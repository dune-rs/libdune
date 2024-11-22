// #[macro_use]
use std::os::raw::{c_void};
use std::mem;
use libc::{ioctl};

use crate::globals::{X86_EFLAGS_TF};
use crate::dune::{DuneConfig, DuneTrapRegs, dune_fd, __dune_go_dune, __dune_go_linux};
use crate::funcs;
const DUNE_TRAP_ENABLE: u64 = 0x4008_0000;
const DUNE_TRAP_DISABLE: u64 = 0x4008_0001;

#[repr(C)]
#[derive(Debug, Default)]
struct DuneTrapConfig {
    trigger_rip: u64,
    delay: u8,
    notify_func: extern "C" fn(*mut DuneTrapRegs, *mut c_void),
    regs: *mut DuneTrapRegs,
    regs_size: usize,
    priv_data: *mut c_void,
}

impl DuneTrapConfig {
    funcs!(trigger_rip, u64);
    funcs!(delay, u8);
    funcs!(notify_func, extern "C" fn(*mut DuneTrapRegs, *mut c_void));
    funcs!(regs, *mut DuneTrapRegs);
    funcs!(regs_size, usize);
    funcs!(priv_data, *mut c_void);
}

static mut TRAP_REGS: DuneTrapRegs = DuneTrapRegs::default();

fn dune_trap_enable(trigger_rip: u64, delay: u8, func: fn(*mut DuneTrapRegs, *mut c_void), priv_data: *mut c_void) {
    let trap_conf = DuneTrapConfig::default();
    trap_conf.set_trigger_rip(trigger_rip)
            .set_delay(delay)
            .set_notify_func(func)
            .set_regs(&mut TRAP_REGS)
            .set_regs_size(mem::size_of::<DuneTrapRegs>())
            .set_priv_data(priv_data);

    { ioctl(dune_fd, DUNE_TRAP_ENABLE, &trap_conf); }
}

fn dune_trap_disable() {
    unsafe { ioctl(dune_fd, DUNE_TRAP_DISABLE); }
}

fn notify_on_resume(regs: *mut DuneTrapRegs, priv_data: *mut c_void) -> ! {
    unsafe {
        let dune_conf = &mut *(priv_data as *mut DuneConfig);

        // We don't need the preemption trap anymore.
        dune_trap_disable();

        // Copy the TF bit from Linux mode to Dune mode. This way, the program
        // will either single-step or continue depending on what the debugger
        // wants the program to do.
        // dune_conf.rflags &= !X86_EFLAGS_TF;
        // dune_conf.rflags |= (*regs).rflags & X86_EFLAGS_TF;
        dune_conf.set_rflags(dune_conf.rflags() & !X86_EFLAGS_TF);
        dune_conf.set_rflags(dune_conf.rflags() | (*regs).rflags() & X86_EFLAGS_TF);

        // Continue in Dune mode.
        __dune_go_dune(dune_fd, dune_conf);
        // It doesn't return.
    }
}

#[no_mangle]
pub fn dune_debug_handle_int(conf: *mut DuneConfig) {
    unsafe {
        match (*conf).status() {
            1 => {
                dune_trap_enable((*conf).rip(), 0, notify_on_resume, conf as *mut c_void);
                (*conf).set_rflags((*conf).rflags() | X86_EFLAGS_TF);
                __dune_go_linux(conf);
            }
            3 => {
                dune_trap_enable((*conf).rip(), 0, notify_on_resume, conf as *mut c_void);
                __dune_go_linux(conf);
            }
            _ => {}
        }
    }
}
