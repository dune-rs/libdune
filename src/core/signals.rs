use std::{io::{self, ErrorKind}, mem, ptr};

use libc::{sigaction, SIG_IGN, SIGTSTP, SIGSTOP, SIGKILL, SIGCHLD, SIGINT, SIGTERM};

use super::DUNE_FD;

pub fn setup_signals() -> io::Result<()> {
    for i in 1..32 {
        match i {
            SIGTSTP | SIGSTOP | SIGKILL | SIGCHLD | SIGINT | SIGTERM => continue,
            _ => unsafe {
                let mut sa: sigaction = mem::zeroed();
                sa.sa_sigaction = SIG_IGN;
                if sigaction(i, &sa, ptr::null_mut()) == -1 {
                    let dune_fd = *DUNE_FD.lock().unwrap();
                    libc::close(dune_fd);
                    return Err(io::Error::new(ErrorKind::Other, format!("sigaction() {}", i)));
                }
            }
        }
    }
    Ok(())
}