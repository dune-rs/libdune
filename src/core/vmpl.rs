use std::ffi::{c_int, c_void};
use std::mem::{self};
use std::sync::Arc;
use libc::munmap;
use x86_64::VirtAddr;

use dune_sys::{funcs, funcs_vec, funcs_ref, BaseSystem, Device, DuneTrapRegs, Tss, Tptr, IdtDescriptor, Result, WithInterrupt, DuneConfig};

use crate::globals::{GD_TSS, GD_TSS2, NR_GDT_ENTRIES, SEG_A, SEG_P, SEG_TSSA};
use crate::{DuneDebug, DuneInterrupt, DuneSignal, PGSIZE};

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
    funcs_ref!(system, Arc<VmplSystem>);
    funcs_vec!(gdt, u64);

    pub fn free(ptr: *mut VmplPercpu) {
        // XXX free stack
        unsafe { munmap(ptr as *const _ as *mut c_void, PGSIZE as usize) };
    }
}

impl Percpu for VmplPercpu {

    type SelfType = VmplPercpu;
    type SystemType = VmplSystem;

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

    fn idtr(&self) -> Tptr {
        // Implement the idtr function
        Tptr::default()
    }

    fn system(&self) -> &Arc<VmplSystem> {
        &self.system
    }

    fn set_system(&mut self, system: Arc<VmplSystem>) {
        self.system = system;
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
        // Implement the on_dune_exit function
        todo!()
    }
}


impl DuneInterrupt for VmplSystem { }
impl DuneSignal for VmplSystem { }
impl DuneDebug for VmplSystem { }