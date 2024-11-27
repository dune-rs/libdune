use std::ptr;
use dune_sys::Device;
use dune_sys::DUNE_GET_SYSCALL;
use libc::mmap;
use libc::MAP_ANON;
use libc::MAP_FAILED;
use libc::MAP_PRIVATE;
use libc::PROT_EXEC;
use libc::PROT_READ;
use libc::PROT_WRITE;
use x86_64::structures::paging::PageTable;
use x86_64::VirtAddr;

use crate::PGSIZE;
use crate::globals::PERM_R;
use crate::core::{*};
use crate::mm::MmapArgs;
use dune_sys::result::{Error, Result};

pub trait DuneSyscall : Device {

    fn get_syscall(&self) -> Result<VirtAddr> {
        let arg: u64 = 0;
        self.ioctl(DUNE_GET_SYSCALL, &arg as *const u64 as *mut u64)
            .and_then(|e| Ok(VirtAddr::new(e as u64)))
    }

    fn setup_syscall(&self) -> Result<()> {
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
        let lstar = self.get_syscall()?;
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
}