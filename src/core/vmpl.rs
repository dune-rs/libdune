use std::io;

use libc::{open, O_RDWR};

use crate::Error;
use crate::Result;



struct VmplDevice {
    fd: i32,
}

impl VmplDevice {
    pub fn new() -> Result<Self> {
        let fd = unsafe { open("/dev/vmpl".as_ptr() as *const i8,
         O_RDWR) };
        if fd < 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }

        Ok(Self {
            fd,
        })
    }

    pub fn fd(&self) -> i32 {
        self.fd
    }

    pub fn close(&self) {
        unsafe { libc::close(self.fd) };
    }
}
