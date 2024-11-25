// #[macro_use]
use std::{ops::Deref, os::raw::c_void};
use std::mem;
use libc::ioctl;
use lazy_static::lazy_static;
use dune_sys::*;

use crate::globals::*;

use super::{__dune_go_dune, __dune_go_linux, DUNE_FD};

lazy_static! {
    pub static ref TRAP_REGS: DuneTrapRegs = DuneTrapRegs::default();
}

unsafe extern "C" fn dune_trap_enable(trigger_rip: u64, delay: u8, func: DuneTrapNotifyFunc, priv_data: *mut c_void) {
    let mut trap_conf = DuneTrapConfig::default();
    trap_conf.set_trigger_rip(trigger_rip)
            .set_delay(delay)
            .set_notify_func(func)
            .set_regs(TRAP_REGS.deref() as *const DuneTrapRegs as *mut DuneTrapRegs)
            .set_regs_size(mem::size_of::<DuneTrapRegs>() as u64)
            .set_priv_data(priv_data);

    let dune_fd = *DUNE_FD.lock().unwrap();
    ioctl(dune_fd, DUNE_TRAP_ENABLE, &trap_conf);
}

fn dune_trap_disable() {
    let dune_fd = *DUNE_FD.lock().unwrap();
    unsafe { ioctl(dune_fd, DUNE_TRAP_DISABLE) };
}

#[no_mangle]
extern "C" fn notify_on_resume(regs: *mut DuneTrapRegs, priv_data: *mut c_void) -> ! {
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
        let dune_fd = *DUNE_FD.lock().unwrap();
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
