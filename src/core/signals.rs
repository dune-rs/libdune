use std::{io::{self, ErrorKind}, mem, ptr};

use libc::{sigaction, SIG_IGN, SIGTSTP, SIGSTOP, SIGKILL, SIGCHLD, SIGINT, SIGTERM};

use super::DUNE_FD;

pub fn setup_signals() -> io::Result<()> {
    for i in 1..32 {
        match i {
            SIGTSTP | SIGSTOP | SIGKILL | SIGCHLD | SIGINT | SIGTERM => continue,
            _ => {
                let mut sa: sigaction = unsafe { mem::zeroed() };
                sa.sa_sigaction = SIG_IGN;
                if unsafe { sigaction(i, &sa, ptr::null_mut()) } == -1 {
                    unsafe { libc::close(DUNE_FD) };
                    return Err(io::Error::new(ErrorKind::Other, format!("sigaction() {}", i)));
                }
            }
        }
    }
    Ok(())
}