use std::{io::{self, ErrorKind}, mem, ptr};

use dune_sys::Device;
use libc::{sigaction, SIG_IGN, SIGTSTP, SIGSTOP, SIGKILL, SIGCHLD, SIGINT, SIGTERM};

pub trait DuneSignal : Device {
    fn setup_signals(&self) -> io::Result<()> {
        log::info!("Setting up signals");
        for i in 1..32 {
            match i {
                SIGTSTP | SIGSTOP | SIGKILL | SIGCHLD | SIGINT | SIGTERM => continue,
                _ => unsafe {
                    let mut sa: sigaction = mem::zeroed();
                    sa.sa_sigaction = SIG_IGN;
                    if sigaction(i, &sa, ptr::null_mut()) == -1 {
                        libc::close(self.fd());
                        return Err(io::Error::new(ErrorKind::Other, format!("sigaction() {}", i)));
                    }
                }
            }
        }
        Ok(())
    }
}