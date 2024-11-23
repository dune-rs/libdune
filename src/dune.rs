use std::ptr;
use libc::*;
use lazy_static::lazy_static;
use std::sync::Mutex;
use x86_64::structures::gdt::{GlobalDescriptorTable, Descriptor};
use dune_sys::*;
use dune_sys::dev::DuneDevice;

use crate::globals::*;

lazy_static! {
    static ref PAGE_MUTEX: Mutex<()> = Mutex::new(());
}

extern "C" {
    pub fn arch_prctl(code: c_int, addr: *mut c_void) -> c_int;
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct Tss {
    pub tss_rsp: [u64; 3],
    pub tss_ist: [u64; 8],
    pub tss_iomb: u16,
}

extern "C" {
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

use x86_64::structures::paging::page_table::PageTableEntry;

pub static mut PGROOT: *mut PageTableEntry = ptr::null_mut();
pub static mut DUNE_FD: i32 = -1;
pub static mut DUNE_DEVICE: Option<DuneDevice> = None;