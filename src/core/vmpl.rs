use std::ffi::{c_int, c_void};
use std::mem::{self};
use std::sync::Arc;
use libc::munmap;
use x86_64::VirtAddr;

use dune_sys::{funcs, funcs_vec, BaseSystem, Device, DuneTrapRegs, Tss, Tptr, IdtDescriptor, Result, WithInterrupt, DuneConfig, DuneRetCode};

use crate::globals::{GD_TSS, GD_TSS2, NR_GDT_ENTRIES, SEG_A, SEG_P, SEG_TSSA};
use crate::{DuneDebug, DuneInterrupt, DuneSignal, PGSIZE};
use crate::__dune_go_dune;

use super::{DuneRoutine, Percpu, GDT_TEMPLATE, IDT_ENTRIES};

pub struct VmplPercpu {
    percpu_ptr: u64,
    tmp: u64,
    kfs_base: VirtAddr,
    ufs_base: VirtAddr,
    in_usermode: u64,
    system: Arc<VmplSystem>,
    pub tss: Tss,
    gdt: [u64; NR_GDT_ENTRIES],
}

impl VmplPercpu {
    funcs!(percpu_ptr, u64);
    funcs!(tmp, u64);
    funcs!(kfs_base, VirtAddr);
    funcs!(ufs_base, VirtAddr);
    funcs!(in_usermode, u64);
    funcs_vec!(gdt, u64);

    pub fn free(ptr: *mut VmplPercpu) {
        // XXX free stack
        unsafe { munmap(ptr as *const _ as *mut c_void, PGSIZE as usize) };
    }
}

impl Percpu for VmplPercpu {

    type SelfType = VmplPercpu;
    type SystemType = VmplSystem;

    // fn init(&self) -> Result<&mut Self::SelfType>;

    fn prepare(&mut self) -> Result<()> {
        // Implement the prepare function
        todo!()
    }

    fn setup_safe_stack(&mut self) -> Result<()> {
        // Implement the setup_safe_stack function
        todo!()
    }

    fn gdtr(&self) -> Tptr {
        // Implement the gdtr function
        Tptr::default()
    }

    fn idtr(&mut self) -> Tptr {
        // Implement the idtr function
        Tptr::default()
    }

    fn system(&self) -> &Arc<Self::SystemType> {
        &self.system
    }

    fn set_system(&mut self, system: &Arc<Self::SystemType>) {
        self.system = Arc::clone(system);
    }

    fn post_dune_boot(&mut self) {
        // Implement the post_dune_boot function
        todo!()
    }

    fn setup_gdt(&mut self) {
        let gdt = &mut self.gdt;
        let tss = &self.tss;
        gdt.copy_from_slice(&GDT_TEMPLATE);
        gdt[GD_TSS >> 3] = SEG_TSSA | SEG_P | SEG_A | SEG_BASELO!(tss) | SEG_LIM!(mem::size_of::<Tss>() as u64 - 1);
        gdt[GD_TSS2 >> 3] = SEG_BASEHI!(tss);
    }
}

#[derive(Debug, Copy, Clone)]
pub struct VmplSystem {
    system: BaseSystem,
}

impl VmplSystem {
    funcs!(system, BaseSystem);

    #[allow(dead_code)]
    pub fn new() -> Self {
        VmplSystem {
            system: BaseSystem::new(),
        }
    }

    fn on_dune_syscall(&self, conf: &mut DuneConfig) {
        conf.set_rax(unsafe {
            libc::syscall(
                conf.status() as libc::c_long,
                conf.rdi(),
                conf.rsi(),
                conf.rdx(),
                conf.r10(),
                conf.r8(),
                conf.r9(),
            )
        });

        unsafe {
            __dune_go_dune(self.fd(), conf as *mut DuneConfig)
        };
    }
}

impl Device for VmplSystem {

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

impl WithInterrupt for VmplSystem {

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

impl DuneRoutine for VmplSystem {

    fn dune_init(&mut self, map_full: bool) -> Result<()> {
        // Implement the dune_init function
        todo!()
    }

    fn dune_enter(&mut self) -> Result<()> {
        // Implement the dune_enter function
        todo!()
    }

    fn on_dune_exit(&mut self, conf_: *mut DuneConfig) -> ! {
        let conf = unsafe { &mut *conf_ };
        let ret: DuneRetCode = conf.ret().into();
        match ret {
            DuneRetCode::Exit => {
                unsafe { libc::syscall(libc::SYS_exit, conf.status()) };
            }
            DuneRetCode::Syscall => {
                self.on_dune_syscall(conf);
            }
            DuneRetCode::Interrupt => {
                #[cfg(feature = "debug")]
                self.handle_int(conf_);
                println!("dune: exit due to interrupt {}", conf.status());
            }
            DuneRetCode::Signal => {
                unsafe { __dune_go_dune(self.fd(), conf_) };
            }
            DuneRetCode::NoEnter => {
                log::warn!("dune: re-entry to Dune mode failed, status is {}", conf.status());
            }
            _ => {
                log::warn!("dune: unknown exit from Dune, ret={}, status={}", conf.ret(), conf.status());
            }
        }

        std::process::exit(libc::EXIT_FAILURE);
    }
}


impl DuneInterrupt for VmplSystem { }
impl DuneSignal for VmplSystem { }
#[cfg(feature = "debug")]
impl DuneDebug for VmplSystem { }