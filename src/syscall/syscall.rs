use std::ptr;
use libc::mmap;
use libc::MAP_ANON;
use libc::MAP_FAILED;
use libc::MAP_PRIVATE;
use libc::PROT_EXEC;
use libc::PROT_READ;
use libc::PROT_WRITE;
use x86_64::structures::paging::PageTable;

use crate::PGSIZE;
use crate::globals::PERM_R;
use crate::core::{*};
use crate::mm::MmapArgs;
use dune_sys::result::{Error, Result};

#[cfg(all(feature = "dune", feature = "syscall"))]
pub fn setup_syscall() -> Result<()> {
    let page = unsafe { mmap(ptr::null_mut(),
                                (PGSIZE * 2) as usize,
                                PROT_READ | PROT_WRITE | PROT_EXEC,
                                MAP_PRIVATE | MAP_ANON,
                                -1,
                                0) };

    if page == MAP_FAILED {
        return Err(Error::Unknown);
    }

    // calculate the page-aligned address
    let dune_vm = DUNE_VM.lock().unwrap();
    let lstar = dune_vm.lstar();
    let lstara = lstar.align_down(align_of::<PageTable>() as u64);
    let off = lstar - lstara;

    unsafe {
        ptr::copy_nonoverlapping(
            __dune_syscall as *const u8,
            (page as *mut u8).add(off as usize),
            __dune_syscall_end as usize - __dune_syscall as usize,
        );
    }

    MmapArgs::default()
            .set_va(lstara)
            .set_len((PGSIZE * 2) as u64)
            .set_perm(PERM_R)
            .map()
}

#[cfg(not(feature = "syscall"))]
pub fn setup_syscall() -> Result<()> {
    log::warn!("No syscall support");
    Ok(())
}

pub trait DuneSyscall {
    fn setup_syscall(&self) -> Result<()>;
}

impl DuneSyscall for DuneSystem {

    fn setup_syscall(&self) -> Result<()> {
        setup_syscall()
    }
}
