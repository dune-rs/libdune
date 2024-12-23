use std::{any::Any, mem, os::raw::c_void};
use dune_sys::*;

use crate::globals::*;

use super::{DuneSystem, __dune_go_dune, __dune_go_linux, DEVICE};

#[no_mangle]
extern "C" fn notify_on_resume(regs: *mut DuneTrapRegs, priv_data: *mut c_void) -> ! {
    unsafe {
        let dune_conf = &mut *(priv_data as *mut DuneConfig);

        // We don't need the preemption trap anymore.
        let device = DEVICE.lock().unwrap();
        if let Some(device) = device.as_ref() {
            // if the device has DuneDebug trait, then next
            let device = device.as_any().downcast_ref::<DuneSystem>();
            if let Some(device) = device {
                if device.trap_disable().is_err() {
                    panic!("failed to disable trap");
                }

                // Copy the TF bit from Linux mode to Dune mode. This way, the program
                // will either single-step or continue depending on what the debugger
                // wants the program to do.
                dune_conf.set_rflags(dune_conf.rflags() & !X86_EFLAGS_TF);
                dune_conf.set_rflags(dune_conf.rflags() | (*regs).rflags() & X86_EFLAGS_TF);

                // Continue in Dune mode.
                __dune_go_dune(device.fd(), dune_conf);
                // It doesn't return.
            } else {
                panic!("device does not implement DuneDebug trait");
            }
        } else {
            panic!("device is None");
        }
    }
}

pub trait DuneDebug: Device + WithInterrupt + Any {

    fn trap_enable(&mut self, trigger_rip: u64, delay: u8, func: DuneTrapNotifyFunc, priv_data: *mut c_void) -> Result<i32> {
        let trap_regs = self.get_trap_regs_mut();
        let trap_conf = &mut DuneTrapConfig::default();
        trap_conf.set_trigger_rip(trigger_rip)
                .set_delay(delay)
                .set_notify_func(func)
                .set_regs(trap_regs as *mut _)
                .set_regs_size(mem::size_of::<DuneTrapRegs>() as u64)
                .set_priv_data(priv_data);

        // self.ioctl(DUNE_TRAP_ENABLE, trap_conf)
        match unsafe { dune_trap_enable(self.fd(), trap_conf) } {
            Ok(_) => Ok(0),
            Err(e) => Err(Error::LibcError(e)),
        }
    }

    fn trap_disable(&self) -> Result<i32> {
        // self.ioctl(DUNE_TRAP_DISABLE, ptr::null_mut::<c_void>())
        match unsafe { dune_trap_disable(self.fd()) } {
            Ok(_) => Ok(0),
            Err(e) => Err(Error::LibcError(e)),
        }
    }

    fn handle_int(&mut self, conf: *mut DuneConfig) {
        unsafe {
            match (*conf).status() {
                1 => {
                    let _ = self.trap_enable( (*conf).rip(), 0, notify_on_resume, conf as *mut c_void);
                    (*conf).set_rflags((*conf).rflags() | X86_EFLAGS_TF);
                    __dune_go_linux(conf);
                }
                3 => {
                    let _ = self.trap_enable( (*conf).rip(), 0, notify_on_resume, conf as *mut c_void);
                    __dune_go_linux(conf);
                }
                _ => {}
            }
        }
    }
}