use std::ptr;
use std::ffi::CString;
use std::os::raw::c_int;
use std::os::unix::io::RawFd;
use libc::{mmap, munmap, MAP_ANONYMOUS, MAP_FAILED, MAP_SHARED, PROT_READ, PROT_WRITE};
use dune_sys::result::{Error, Result};
use dune_sys::vmpl_set_seimi;
use dune_sys::{Device, VmplSeimi, SEIMI_PGD_USER, SEIMI_PGD_SUPER, SEIMI_MMAP_BASE_USER, SEIMI_MMAP_BASE_SUPER};

fn setup_seimi(dune_fd: RawFd) -> Result<c_int> {
    let mut seimi = VmplSeimi::new(SEIMI_PGD_USER, SEIMI_PGD_SUPER);
    log::info!("Setting up SEIMI");
    let rc = unsafe {vmpl_set_seimi(dune_fd, &mut seimi).map_err(|e| {
        log::error!("Failed to setup SEIMI: {:?}", e);
        Error::Io(std::io::Error::last_os_error())
    })}?;
    if rc < 0 {
        log::error!("Failed to setup SEIMI: {}", std::io::Error::last_os_error());
        return Err(Error::Io(std::io::Error::last_os_error()));
    }

    Ok(rc)
}

pub fn sa_alloc(length: usize, need_ro: bool, offset: &mut isize) -> Result<*mut libc::c_void> {
    let seimi_user = unsafe {
        mmap(
            SEIMI_MMAP_BASE_USER as *mut libc::c_void,
            length,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if seimi_user == MAP_FAILED {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }

    if !need_ro {
        return Ok(seimi_user);
    }

    let seimi_super = unsafe {
        mmap(
            SEIMI_MMAP_BASE_SUPER as *mut libc::c_void,
            length,
            PROT_READ,
            MAP_SHARED | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if seimi_super == MAP_FAILED {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }

    *offset = (seimi_super as isize) - (seimi_user as isize);

    Ok(seimi_user)
}

pub fn sa_free(addr: *mut libc::c_void, length: usize) -> Result<()> {
    if unsafe { munmap(addr, length) } == 0 {
        Ok(())
    } else {
        Err(Error::Io(std::io::Error::last_os_error()))
    }
}

pub trait WithSeimi : Device {

    fn setup_seimi(&self, dune_fd: RawFd) -> Result<i32> {
        setup_seimi(dune_fd)
    }
}