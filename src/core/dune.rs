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
    kfs_base: u64,
    ufs_base: u64,
    in_usermode: u64,
    pub tss: Tss,
    gdt: [u64; NR_GDT_ENTRIES],
    vcpu_fd: BaseDevice,
    system: Arc<dyn WithInterrupt>,
}

/*
 * Supervisor Private Area Format
 */
#[cfg(feature = "dune")]
pub mod offsets {
    use std::mem::offset_of;

    pub const TMP : usize = offset_of!(DunePercpu, tmp);
    pub const KFS_BASE: usize = offset_of!(DunePercpu, kfs_base);
    pub const UFS_BASE: usize = offset_of!(DunePercpu, ufs_base);
    pub const IN_USERMODE: usize = offset_of!(DunePercpu, in_usermode);
    pub const TRAP_STACK: usize = offset_of!(DunePercpu, tss.tss_rsp);
}

impl DunePercpu {
    funcs!(percpu_ptr, u64);
    funcs!(tmp, u64);
    funcs!(kfs_base, u64);
    funcs!(ufs_base, u64);
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

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn system(&self) -> &Arc<dyn WithInterrupt> {
        &self.system
    }

    fn set_system(&mut self, system: &Arc<dyn WithInterrupt>) {
        self.system = Arc::clone(system);
    }

    fn get_gdt(&mut self) -> &mut [u64; NR_GDT_ENTRIES] {
        &mut self.gdt
    }

    fn get_tss(&self) -> &Tss {
        &self.tss
    }

    fn get_tss_mut(&mut self) -> &mut Tss {
        &mut self.tss
    }

    fn prepare(&mut self) -> Result<()> {
        let fs_base = get_fs_base()?;
        self.set_kfs_base(fs_base)
            .set_ufs_base(fs_base)
            .set_in_usermode(0)
            .setup_safe_stack()?;
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
}

pub fn dune_get_user_fs() -> u64 {
    if let Some(percpu) = get_percpu::<DunePercpu>() {
        percpu.get_user_fs()
    } else {
        0
    }
}

pub fn dune_set_user_fs(fs_base: u64) {
    if let Some(percpu) = get_percpu::<DunePercpu>() {
        percpu.set_user_fs(fs_base);
    }
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
        // dune_vm_init(0)?;

        #[cfg(feature = "apic")]
        self.apic_setup()?;
        self.setup_mappings(map_full)?;
        self.setup_syscall()?;

        self.setup_signals()?;

        self.setup_idt();

        Ok(())
    }

    fn dune_enter(&mut self) -> Result<()> {
        // Check if this process already entered Dune before a fork...
        let percpu = get_percpu::<DunePercpu>();
        if let Some(percpu) = percpu {
            // if not none, enter Dune mode
            log::debug!("dune: already entered Dune mode");
            return percpu.do_dune_enter();
        }

        let percpu = DunePercpu::create(Arc::new(self))?;
        percpu.and_then(|percpu_ptr| {
            let percpu = unsafe { &mut *percpu_ptr };
            self.map_ptr(VirtAddr::from_ptr(percpu_ptr), mem::size_of::<DunePercpu>())?;
            percpu.prepare().map_err(|e| {
                log::error!("dune: failed to prepare percpu");
                DunePercpu::free(percpu_ptr);
                e
            })?;
            let _ = self.map_stack();
            percpu.do_dune_enter().map_err(|e| {
                log::error!("dune: failed to enter Dune mode");
                DunePercpu::free(percpu_ptr);
                e
            })?;
            set_percpu(percpu);
            Ok(())
        }).map_err(|e| {
            log::error!("dune: failed to create percpu");
            e
        })?;
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
impl WithPageTable for DuneSystem {

    fn get_root(&self) -> &PageTable {
        self.system.get_root()
    }

    fn get_root_mut(&mut self) -> &mut PageTable {
        self.system.get_root_mut()
    }
}
impl WithDuneMemory for DuneSystem { }
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