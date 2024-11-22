// use std::ffi::CString;
// use std::io::Error;
use std::ptr;
// use std::sync::Mutex;
// use std::fs::File;
// use std::os::unix::io::AsRawFd;
// use std::mem::size_of;
use libc::*;
use lazy_static::lazy_static;
use std::sync::Mutex;

use crate::globals::*;

lazy_static! {
    static ref PAGE_MUTEX: Mutex<()> = Mutex::new(());
}

extern "C" {
    pub fn arch_prctl(code: c_int, addr: *mut c_void) -> c_int;
}

#[repr(C)]
pub struct DunePercpu {
    kfs_base: u64,
    ufs_base: u64,
    in_usermode: u64,
    tss: Tss,
    gdt: [u64; NR_GDT_ENTRIES],
}

#[repr(C)]
pub struct Tss {
    tss_rsp: [u64; 3],
    tss_ist: [u64; 8],
    tss_iomb: u16,
}

impl Default for Tss {
    fn default() -> Self {
        Tss {
            tss_rsp: [0; 3],
            tss_ist: [0; 8],
            tss_iomb: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct DuneConfig {
    ret: i64,
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rsp: u64,
    rbp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    rflags: u64,
    cr3: u64,
    status: i64,
    vcpu: u64,
}

/// Generate set/get methods for a given struct field and type
#[macro_export]
macro_rules! funcs {
    ($name: ident, $T: ty) => {
        paste::paste! {
            pub fn [<$name>](&self) -> $T {
                self.$name
            }
            pub fn [<set_ $name>](&mut self, value: $T) {
                self.$name = value;
            }
        }
    };
}

impl DuneConfig {
    funcs!(ret, i64);
    funcs!(rip, u64);
    funcs!(rsp, u64);
    funcs!(rflags, u64);
    funcs!(cr3, u64);
    funcs!(status, i64);
    funcs!(vcpu, u64);
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct DuneLayout {
    phys_limit: u64,
    base_map: u64,
    base_stack: u64,
}

impl DuneLayout {
    funcs!(phys_limit, u64);
    funcs!(base_map, u64);
    funcs!(base_stack, u64);
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
pub struct DuneTf {
    /* manually saved, arguments */
    rdi: u64,
    rsi: u64,
    rdx: u64,
    rcx: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,

    /* saved by C calling conventions */
    rbx: u64,
    rbp: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,

    /* system call number, ret */
    rax: u64,

    /* exception frame */
    err: u32,
    pad1: u32,
    rip: u64,
    cs: u16,
    pad2: [u16; 3],
    rflags: u64,
    rsp: u64,
    ss: u16,
    pad3: [u16; 3],
}

impl DuneTf {
    funcs!(rdi, u64);
    funcs!(rsi, u64);
    funcs!(rdx, u64);
    funcs!(rcx, u64);
    funcs!(r8, u64);
    funcs!(r9, u64);
    funcs!(r10, u64);
    funcs!(r11, u64);
    funcs!(rbx, u64);
    funcs!(rbp, u64);
    funcs!(r12, u64);
    funcs!(r13, u64);
    funcs!(r14, u64);
    funcs!(r15, u64);
    funcs!(rax, u64);
    funcs!(err, u32);
    funcs!(rip, u64);
    funcs!(cs, u16);
    funcs!(rflags, u64);
    funcs!(rsp, u64);
    funcs!(ss, u16);
}


#[repr(C, packed)]
#[derive(Debug, Default)]
pub struct DuneTrapRegs {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rsp: u64,
    rbp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    rflags: u64,
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

pub static mut pgroot: *mut c_void = ptr::null_mut();
pub static mut dune_fd: i32 = -1;
