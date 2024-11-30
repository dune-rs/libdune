use std::any::Any;
use std::arch::asm;
use std::ffi::{c_int, c_void};
use std::mem::{self, offset_of};
use std::sync::Arc;
use std::fmt;
use x86_64::registers::model_specific::{FsBase, GsBase};
use x86_64::VirtAddr;
use x86_64::PhysAddr;

use dune_sys::{funcs, funcs_vec, BaseDevice, BaseSystem, Device, DuneConfig, DuneLayout, DuneRetCode, DuneTrapRegs, IdtDescriptor, Result, Error, Tptr, Tss, WithInterrupt, TSS_IOPB};
use dune_sys::dune_get_layout;
use crate::mm::vm::AddressMapping;
use crate::WithAddressTranslation;
use crate::globals::{GD_TSS, GD_TSS2, NR_GDT_ENTRIES, SEG_A, SEG_P, SEG_TSSA};
use crate::{dune_vm_init, get_fs_base, DuneSyscall, FxSaveArea, WithDuneFpu, DUNE_VM, PGSIZE};
use crate::__dune_ret;
use crate::__dune_enter;
use crate::dune_die;
use crate::globals::GD_KD;
use crate::globals::GD_KT;
use crate::core::WithDuneAPIC;
use super::cpuset::WithCpuset;
use super::{DuneDebug, DuneInterrupt, DuneMapping, DuneRoutine, Percpu, __dune_go_dune, GDT_TEMPLATE, IDT_ENTRIES, LPERCPU};
use super::DuneSignal;

pub struct DunePercpu {
    percpu_ptr: u64,
    tmp: u64,
    kfs_base: VirtAddr,
    ufs_base: VirtAddr,
    in_usermode: u64,
    pub tss: Tss,
    gdt: [u64; NR_GDT_ENTRIES],
    vcpu_fd: BaseDevice,
    system: Arc<DuneSystem>,
}

/*
 * Supervisor Private Area Format
 */
pub const TMP : usize = offset_of!(DunePercpu, tmp);
pub const KFS_BASE: usize = offset_of!(DunePercpu, kfs_base);
pub const UFS_BASE: usize = offset_of!(DunePercpu, ufs_base);
pub const IN_USERMODE: usize = offset_of!(DunePercpu, in_usermode);
pub const TRAP_STACK: usize = offset_of!(DunePercpu, tss.tss_rsp);

impl DunePercpu {
    funcs!(percpu_ptr, u64);
    funcs!(tmp, u64);
    funcs!(kfs_base, VirtAddr);
    funcs!(ufs_base, VirtAddr);
    funcs!(in_usermode, u64);
    funcs!(vcpu_fd, BaseDevice);
    funcs_vec!(gdt, u64);

    fn get_user_fs() -> u64 {
        let ptr: u64;
        unsafe {
            asm!(
                "mov gs:{ufs_base}, {ptr}",
                ufs_base = const offset_of!(DunePercpu, ufs_base),
                ptr = out(reg) ptr,
                options(nostack, preserves_flags)
            );
        }
        ptr
    }

    fn set_user_fs(fs_base: u64) {
        unsafe {
            asm!(
                "mov {fs_base}, gs:{ufs_base}",
                fs_base = in(reg) fs_base,
                ufs_base = const offset_of!(DunePercpu, ufs_base),
                options(nostack, preserves_flags)
            );
        }
    }
}

impl Device for DunePercpu {

    fn fd(&self) -> c_int {
        self.vcpu_fd.fd()
    }

    fn open(&mut self, path: &str) -> Result<i32> {
        self.vcpu_fd.open(path)
    }

    fn close(&self) -> Result<i32> {
        self.vcpu_fd.close()
    }

    fn ioctl<T>(&self, request: i32, arg: *mut T) -> Result<i32> {
        self.vcpu_fd.ioctl(request, arg)
    }
}

impl Percpu for DunePercpu {

    type SystemType = DuneSystem;

    fn setup_gdt(&mut self) {
        let gdt = &mut self.gdt;
        let tss = &self.tss;
        gdt.copy_from_slice(&GDT_TEMPLATE);
        gdt[GD_TSS >> 3] = SEG_TSSA | SEG_P | SEG_A | SEG_BASELO!(tss) | SEG_LIM!(mem::size_of::<Tss>() as u64 - 1);
        gdt[GD_TSS2 >> 3] = SEG_BASEHI!(tss);
    }

    fn gdtr(&self) -> Tptr {
        let mut gdtr = Tptr::default();
        unsafe {
            let gdt_ptr = std::ptr::addr_of!(self.gdt);
            let size = (*gdt_ptr).len() * mem::size_of::<u64>() - 1;
            gdtr.set_base(gdt_ptr as u64)
                .set_limit(size as u16);
        }
        gdtr
    }

    fn idtr(&mut self) -> Tptr {
        let idt = self.system().get_idt();
        let mut idtr = Tptr::default();
        idtr.set_base(idt.as_ptr() as u64)
            .set_limit((idt.len() * mem::size_of::<IdtDescriptor>() - 1) as u16);
        idtr
    }

    fn system(&self) -> &Arc<Self::SystemType> {
        todo!()
    }

    fn set_system(&mut self, system: &Arc<Self::SystemType>) {
        todo!()
    }

    fn setup_safe_stack(&mut self) -> Result<()> {
        let safe_stack: *mut c_void = Self::map_safe_stack()?;
        self.tss.set_tss_iomb(TSS_IOPB as u16);

        for idx in 1..8 {
            // self.tss.tss_ist[i] = safe_stack as u64;
            self.tss.set_tss_ist(idx, safe_stack as u64);
        }

        self.tss.tss_rsp[0] = safe_stack as u64;

        Ok(())
    }

    fn prepare(&mut self) -> Result<()> {
        let fs_base = get_fs_base()?;
        self.set_kfs_base(fs_base)
            .set_ufs_base(fs_base)
            .set_in_usermode(0)
            .setup_safe_stack()?;
        Ok(())
    }

    fn dune_boot(&mut self) -> Result<()> {
        self.setup_gdt();
        let gdtr = self.gdtr();
        let idtr = self.idtr();

        unsafe {
            asm!(
                // STEP 1: load the new GDT
                "lgdt ({0})",

                // STEP 2: initialize data segments
                "mov {1:x}, %ax",
                "mov %ax, %ds",
                "mov %ax, %es",
                "mov %ax, %ss",

                // STEP 3: long jump into the new code segment
                "mov {2:r}, %rax",
                "pushq %rax",
                "leaq 2f(%rip), %rax",
                "pushq %rax",
                "lretq",
                "2:",
                "nop",

                // STEP 4: load the task register (for safe stack switching)
                "mov {3:x}, %ax",
                "ltr %ax",

                // STEP 5: load the new IDT and enable interrupts
                "lidt ({4})",
                "sti",

                in(reg) &gdtr,
                in(reg) GD_KD,
                in(reg) GD_KT,
                in(reg) GD_TSS,
                in(reg) &idtr,
                options(nostack, preserves_flags, att_syntax)
            );
        }

        // STEP 6: FS and GS require special initialization on 64-bit
        FsBase::write(self.kfs_base);
        GsBase::write(VirtAddr::new(self as *const _ as u64));

        Ok(())
    }

    fn do_dune_enter(&mut self) -> Result<()> {
        let mut dune_vm = DUNE_VM.lock().unwrap();
        let root = dune_vm.get_mut_root();

        let mut conf = DuneConfig::default();
        conf.set_vcpu(0)
            .set_rip(&__dune_ret as *const _ as u64)
            .set_rsp(0)
            .set_cr3(root as *const _ as u64)
            .set_rflags(0x2);

        // NOTE: We don't setup the general purpose registers because __dune_ret
        // will restore them as they were before the __dune_enter call
        let dune_fd = self.fd();
        let ret = unsafe { __dune_enter(dune_fd, &conf) };
        if ret != 0 {
            println!("dune: entry to Dune mode failed, ret is {}", ret);
            return Err(Error::Unknown);
        }

        self.dune_boot().map_err(|e|{
            println!("dune: failed to boot Dune mode: {:?}", e);
            unsafe { dune_die() };
            e
        })
    }

    fn dune_enter_ex(&mut self) -> Result<()> {
        self.prepare()?;
        self.do_dune_enter()
    }
}

pub fn dune_get_user_fs() -> u64 {
    DunePercpu::get_user_fs()
}

pub fn dune_set_user_fs(fs_base: u64) {
    DunePercpu::set_user_fs(fs_base)
}

#[derive(Debug, Copy, Clone)]
pub struct DuneSystem {
    system: BaseSystem,
    layout: DuneLayout,
    dune_fd: i32,
}

impl DuneSystem {
    funcs!(system, BaseSystem);
    funcs!(layout, DuneLayout);
    funcs!(dune_fd, i32);

    pub fn new() -> Self {
        DuneSystem {
            system: BaseSystem::new(),
            layout: DuneLayout::default(),
            dune_fd: -1,
        }
    }
}

impl Device for DuneSystem {

    fn fd(&self) -> c_int {
        self.dune_fd()
    }

    fn open(&mut self, path: &str) -> Result<i32> {
        self.system.open(path)
    }

    fn close(&self) -> Result<i32> {
        self.system.close()
    }

    fn ioctl<T>(&self, request: i32, arg: *mut T) -> Result<i32> {
        self.system.ioctl(request, arg)
    }
}

impl WithInterrupt for DuneSystem {

    fn get_idt<'a>(&self) -> &[IdtDescriptor; IDT_ENTRIES] {
        self.system.get_idt()
    }

    fn get_idt_mut<'a>(&mut self) -> &mut [IdtDescriptor; IDT_ENTRIES] {
        self.system.get_idt_mut()
    }

    fn get_trap_regs_mut<'a>(&mut self) -> &mut DuneTrapRegs {
        self.system.get_trap_regs_mut()
    }
}

impl DuneRoutine for DuneSystem {

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn dune_init(&mut self, map_full: bool) -> Result<()> {
        self.open("/dev/dune\0")?;
        // Initialize the Dune VM
        dune_vm_init()?;

        #[cfg(feature = "apic")]
        self.apic_setup()?;
        self.setup_mappings(map_full)?;
        self.setup_syscall()?;

        self.setup_signals()?;

        self.setup_idt();

        Ok(())
    }

    fn dune_enter(&mut self) -> Result<()> {
        let system = Arc::new(*self);
        // Check if this process already entered Dune before a fork...
        LPERCPU.with(|lpercpu| {
            let mut lpercpu = lpercpu.borrow_mut();
            // if not none, enter Dune mode
            match lpercpu.as_mut() {
                Some(percpu) => {
                    percpu.do_dune_enter()
                },
                None => {
                    let percpu = DunePercpu::create();
                    percpu.and_then(|percpu_ptr| {
                        let percpu = unsafe { &mut *percpu_ptr };
                        self.map_ptr(VirtAddr::from_ptr(percpu_ptr), mem::size_of::<DunePercpu>())?;
                        match percpu.prepare() {
                            Ok(()) => {
                                percpu.set_system(&system);
                                Ok(percpu)
                            },
                            Err(e) => {
                                DunePercpu::free(percpu_ptr);
                                Err(e)
                            },
                        }
                    }).and_then(|percpu| {
                        // map the stack into the Dune address space
                        let _ = self.map_stack();
                        percpu.do_dune_enter().map_err(|e|{
                            DunePercpu::free(percpu);
                            e
                        })
                    })
                },
            }
        })
    }

    fn on_dune_exit(&mut self, conf_: *mut DuneConfig) -> ! {
        let conf = unsafe { &*conf_ };
        let ret: DuneRetCode = conf.ret().into();
        match ret {
            DuneRetCode::Exit => {
                unsafe { libc::syscall(libc::SYS_exit, conf.status()) };
            },
            DuneRetCode::EptViolation => {
                println!("dune: exit due to EPT violation");
            },
            DuneRetCode::Interrupt => {
                #[cfg(feature = "debug")]
                self.handle_int(conf_);
                println!("dune: exit due to interrupt {}", conf.status());
            },
            DuneRetCode::Signal => {
                unsafe { __dune_go_dune(self.fd(), conf_) };
            },
            DuneRetCode::UnhandledVmexit => {
                println!("dune: exit due to unhandled VM exit");
            },
            DuneRetCode::NoEnter => {
                println!("dune: re-entry to Dune mode failed, status is {}", conf.status());
            },
            _ => {
                println!("dune: unknown exit from Dune, ret={}, status={}", conf.ret(), conf.status());
            },
        }

        unsafe { libc::exit(libc::EXIT_FAILURE) };
    }
}

#[cfg(feature = "apic")]
impl WithDuneAPIC for DuneSystem { }
impl DuneInterrupt for DuneSystem { }
impl DuneSignal for DuneSystem { }
#[cfg(feature = "debug")]
impl DuneDebug for DuneSystem { }

impl WithAddressTranslation for DuneSystem {

    fn setup_address_translation(&mut self) -> Result<()> {
        let fd = self.fd();
        let mut layout = &mut self.layout;
        let ret = unsafe { dune_get_layout(fd, layout as *mut DuneLayout) };
        match ret {
            Ok(_) => Ok(()),
            Err(e) => Err(Error::LibcError(e)),
        }
    }

    fn va_to_pa(&self, va: VirtAddr) -> Result<PhysAddr> {
        self.layout.va_to_pa(va)
    }

    fn pa_to_va(&self, pa: PhysAddr) -> Result<VirtAddr> {
        self.layout.pa_to_va(pa)
    }
}

impl DuneMapping for DuneSystem {

    fn get_layout(&self) -> Result<DuneLayout> {
        Ok(self.layout)
    }
}
impl DuneSyscall for DuneSystem { }

impl WithCpuset for DunePercpu { }
impl WithDuneFpu for DunePercpu {

    fn get_fpu(&self) -> *mut FxSaveArea {
        todo!()
    }
}