use std::io::{self, ErrorKind};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use dune_sys::{DuneDevice, UintptrT};
use libc::open;
use x86_64::structures::paging::page_table::PageTableEntry;

use crate::globals::*;
use crate::mm::*;
use crate::syscall::*;
use crate::core::*;

use std::cell::RefCell;

extern "C" {
    pub fn arch_prctl(code: c_int, addr: *mut c_void) -> c_int;
    // assembly routines from dune.S
    pub fn __dune_enter(fd: i32, config: *const DuneConfig) -> i32;
    pub fn __dune_ret() -> i32;
    pub fn __dune_syscall();
    pub fn __dune_syscall_end();
    pub fn __dune_intr();
    pub fn __dune_go_dune(dune_fd: c_int, conf: *mut DuneConfig) -> !;
    pub fn __dune_go_linux(conf: *mut DuneConfig);

    // assembly routine for handling vsyscalls
    pub static __dune_vsyscall_page: u8;
}

thread_local! {
    static LPERCPU: RefCell<Option<DunePercpu>> = RefCell::new(None);
}

pub static mut PGROOT: *mut PageTableEntry = ptr::null_mut();
pub static mut PHYS_LIMIT: UintptrT = ptr::null_mut();
pub static mut MMAP_BASE: UintptrT = ptr::null_mut();
pub static mut STACK_BASE: UintptrT = ptr::null_mut();
pub static mut DUNE_FD: i32 = -1;
pub static mut DUNE_DEVICE: Option<DuneDevice> = None;

/**
 * dune_enter - transitions a process to "Dune mode"
 *
 * Can only be called after dune_init().
 *
 * Use this function in each forked child and/or each new thread
 * if you want to re-enter "Dune mode".
 *
 * Returns 0 on success, otherwise failure.
 */
#[no_mangle]
pub unsafe extern "C" fn dune_enter() -> io::Result<()> {
    // Check if this process already entered Dune before a fork...
    LPERCPU.with(|percpu| {
        let mut percpu = percpu.borrow_mut();
        // if not none then enter
        if percpu.is_none() {
            *percpu = create_percpu();
            // if still none, return error
            if let None = *percpu {
                return Err(io::Error::new(ErrorKind::Other, "Failed to create percpu"));
            }
        }

        let percpu = percpu.as_mut().unwrap();
        if let Err(e) = do_dune_enter(percpu) {
            free_percpu(percpu);
            return Err(e);
        } else {
            Ok(())
        }
    });

    Ok(())
}

 /**
  * dune_init - initializes libdune
  *
  * @map_full: determines if the full process address space should be mapped
  *
  * Call this function once before using libdune.
  *
  * Dune supports two memory modes. If map_full is true, then every possible
  * address in the process address space is mapped. Otherwise, only addresses
  * that are used (e.g. set up through mmap) are mapped. Full mapping consumes
  * a lot of memory when enabled, but disabling it incurs slight overhead
  * since pages will occasionally need to be faulted in.
  *
  * Returns 0 on success, otherwise failure.
  */
static DUNE_INITIALIZED: AtomicBool = AtomicBool::new(false);

#[no_mangle]
pub unsafe extern "C" fn dune_init(map_full: bool) -> io::Result<()> {
    if DUNE_INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }

    DUNE_FD = unsafe { open("/dev/dune\0".as_ptr() as *const i8, O_RDWR) };
    if DUNE_FD <= 0 {
        return Err(io::Error::new(ErrorKind::Other, "Failed to open Dune device"));
    }

    PGROOT = unsafe { libc::memalign(PGSIZE, PGSIZE) as *mut PageTableEntry };
    if PGROOT.is_null() {
        unsafe { libc::close(DUNE_FD) };
        return Err(io::Error::new(ErrorKind::Other, "Failed to allocate pgroot"));
    }
    unsafe { ptr::write_bytes(PGROOT, 0, PGSIZE) };

    if dune_page_init().is_err() {
        unsafe { libc::close(DUNE_FD) };
        return Err(io::Error::new(ErrorKind::Other, "Unable to initialize page manager"));
    }

    if setup_mappings(map_full).is_err() {
        unsafe { libc::close(DUNE_FD) };
        return Err(io::Error::new(ErrorKind::Other, "Unable to setup memory layout"));
    }

    if setup_syscall().is_err() {
        unsafe { libc::close(DUNE_FD) };
        return Err(io::Error::new(ErrorKind::Other, "Unable to setup system calls"));
    }

    setup_signals()?;

    setup_idt();

    DUNE_INITIALIZED.store(true, Ordering::SeqCst);
    Ok(())
}

/**
 * dune_init_and_enter - initializes libdune and enters "Dune mode"
 * 
 * This is a simple initialization routine that handles everything
 * in one go. Note that you still need to call dune_enter() in
 * each new forked child or thread.
 * 
 * Returns 0 on success, otherwise failure.
 */
#[no_mangle]
pub unsafe extern "C" fn dune_init_and_enter() -> io::Result<()> {
    if dune_init(true).is_err() {
        return Err(io::Error::new(ErrorKind::Other, "Failed to initialize Dune"));
    }

    dune_enter()
}