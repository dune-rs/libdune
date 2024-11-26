// #[macro_use]
use std::os::raw::c_void;
use std::mem;
use libc::ioctl;
use dune_sys::*;

use crate::globals::*;

use super::{__dune_go_dune, __dune_go_linux, DUNE_DEVICE};

#[no_mangle]
extern "C" fn notify_on_resume(regs: *mut DuneTrapRegs, priv_data: *mut c_void) -> ! {
    unsafe {
        let dune_conf = &mut *(priv_data as *mut DuneConfig);

        // We don't need the preemption trap anymore.
        let device = DUNE_DEVICE.lock().unwrap();
        dune_trap_disable(device.fd());

        // Copy the TF bit from Linux mode to Dune mode. This way, the program
        // will either single-step or continue depending on what the debugger
        // wants the program to do.
        dune_conf.set_rflags(dune_conf.rflags() & !X86_EFLAGS_TF);
        dune_conf.set_rflags(dune_conf.rflags() | (*regs).rflags() & X86_EFLAGS_TF);

        // Continue in Dune mode.
        __dune_go_dune(device.fd(), dune_conf);
        // It doesn't return.
    }
}

pub trait DuneDebug {
    fn trap_enable(&mut self, trigger_rip: u64, delay: u8, func: DuneTrapNotifyFunc, priv_data: *mut c_void);
    fn trap_disable(&self);
    fn handle_int(&mut self, conf: *mut DuneConfig);
}

impl DuneDebug for DuneDevice {

    fn trap_enable(&mut self, trigger_rip: u64, delay: u8, func: DuneTrapNotifyFunc, priv_data: *mut c_void) {
        let trap_regs = self.get_trap_regs_mut();
        let mut trap_conf = DuneTrapConfig::default();
        trap_conf.set_trigger_rip(trigger_rip)
                .set_delay(delay)
                .set_notify_func(func)
                .set_regs(trap_regs as *mut _)
                .set_regs_size(mem::size_of::<DuneTrapRegs>() as u64)
                .set_priv_data(priv_data);

        unsafe { ioctl(self.fd(), DUNE_TRAP_ENABLE, &trap_conf) };
    }

    fn trap_disable(&self) {
        unsafe { ioctl(self.fd(), DUNE_TRAP_DISABLE) };
    }

    fn handle_int(&mut self, conf: *mut DuneConfig) {
        unsafe {
            match (*conf).status() {
                1 => {
                    self.trap_enable( (*conf).rip(), 0, notify_on_resume, conf as *mut c_void);
                    (*conf).set_rflags((*conf).rflags() | X86_EFLAGS_TF);
                    __dune_go_linux(conf);
                }
                3 => {
                    self.trap_enable( (*conf).rip(), 0, notify_on_resume, conf as *mut c_void);
                    __dune_go_linux(conf);
                }
                _ => {}
            }
        }
    }
}