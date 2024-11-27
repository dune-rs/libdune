use std::any::Any;
use std::arch::asm;
use std::ffi::{c_int, c_void};
use std::mem::{self, offset_of};
use std::sync::Arc;
use x86_64::registers::model_specific::{FsBase, GsBase};
use x86_64::VirtAddr;

use dune_sys::{funcs, funcs_vec, BaseDevice, BaseSystem, Device, DuneConfig, DuneRetCode, DuneTrapRegs, IdtDescriptor, Result, Tptr, Tss, WithInterrupt, TSS_IOPB};

use crate::globals::{GD_TSS, GD_TSS2, NR_GDT_ENTRIES, SEG_A, SEG_P, SEG_TSSA};
use crate::{dune_vm_init, get_fs_base, DuneSyscall, FxSaveArea, WithDuneFpu, DUNE_VM, PGSIZE};

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

    fn ioctl<T>(&self, request: u64, arg: *mut T) -> Result<i32> {
        self.vcpu_fd.ioctl(request, arg)
    }
}

impl Percpu for DunePercpu {

    type SelfType = DunePercpu;
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
        let safe_stack: *mut c_void = self.map_safe_stack()?;
        let safe_stack = unsafe { safe_stack.add(PGSIZE) };
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

    fn post_dune_boot(&mut self) {
        // STEP 6: FS and GS require special initialization on 64-bit
        FsBase::write(self.kfs_base);
        GsBase::write(VirtAddr::new(self as *const _ as u64));
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
}

impl DuneSystem {
    funcs!(system, BaseSystem);

    pub fn new() -> Self {
        DuneSystem {
            system: BaseSystem::new(),
        }
    }
}

impl Device for DuneSystem {

    fn fd(&self) -> c_int {
        self.system.fd()
    }

    fn open(&mut self, path: &str) -> Result<i32> {
        self.system.open(path)
    }

    fn close(&self) -> Result<i32> {
        self.system.close()
    }

    fn ioctl<T>(&self, request: u64, arg: *mut T) -> Result<i32> {
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
        self.open("/dev/dune")?;
        // Initialize the Dune VM
        dune_vm_init()?;

        let mut dune_vm = DUNE_VM.lock().unwrap();
        dune_vm.set_layout(self.get_layout()?);

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
                        percpu.map_ptr(percpu_ptr)?;
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

impl DuneInterrupt for DuneSystem { }
impl DuneSignal for DuneSystem { }
#[cfg(feature = "debug")]
impl DuneDebug for DuneSystem { }
impl DuneMapping for DuneSystem { }
impl DuneSyscall for DuneSystem { }

impl WithCpuset for DunePercpu { }
impl WithDuneFpu for DunePercpu {

    fn get_fpu(&self) -> *mut FxSaveArea {
        todo!()
    }
}