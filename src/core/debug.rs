// #[macro_use]
use std::os::raw::c_void;
use std::mem;
use libc::ioctl;
use dune_sys::*;

use crate::globals::*;
use crate::core::dune::*;

static mut TRAP_REGS: DuneTrapRegs = DuneTrapRegs::default();

unsafe extern "C" fn dune_trap_enable(trigger_rip: u64, delay: u8, func: DuneTrapNotifyFunc, priv_data: *mut c_void) {
    let trap_conf = DuneTrapConfig::default();
    trap_conf.set_trigger_rip(trigger_rip)
            .set_delay(delay)
            .set_notify_func(func)
            .set_regs(&mut TRAP_REGS)
            .set_regs_size(mem::size_of::<DuneTrapRegs>())
            .set_priv_data(priv_data);

    { ioctl(DUNE_FD, DUNE_TRAP_ENABLE, &trap_conf); }
}

fn dune_trap_disable() {
    unsafe { ioctl(DUNE_FD, DUNE_TRAP_DISABLE); }
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
        __dune_go_dune(DUNE_FD, dune_conf);
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
