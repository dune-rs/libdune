use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use std::{ptr, str};
use libc::{sighandler_t, SIG_ERR};
use libc::strlen;
use libc::signal;
use std::arch::asm;
use dune_sys::DuneTf;

use crate::core::*;

type SigHandler = extern "C" fn(c_int);

#[inline(always)]
unsafe fn dune_puts(buf: *const c_char) -> i64 {
    let ret: i64;
    asm!(
        "movq $1, %rax", // SYS_write
        "movq $1, %rdi", // STDOUT
        "movq {0}, %rsi", // string
        "movq {1}, %rdx", // string len
        "vmcall",
        "movq %rax, {2}",
        in(reg) buf,
        in(reg) strlen(buf),
        out(reg) ret
    );
    ret
}

/**
 * dune_printf - a raw low-level printf request that uses a hypercall directly
 * 
 * This is intended for working around libc syscall issues.
 */
#[no_mangle]
pub unsafe extern "C" fn dune_printf(fmt: &str, args: ...) -> i64 {
    let mut buf = [0u8; 1024];
    let fmt = CString::new(fmt).unwrap();
    let fmt = fmt.as_ptr();
    let len = libc::snprintf(buf.as_mut_ptr() as *mut c_char, buf.len(), fmt, args);
    if len < 0 {
        return -1;
    }
    dune_puts(buf.as_ptr() as *const c_char)
}

#[no_mangle]
pub unsafe extern "C" fn dune_mmap(
    addr: *mut c_void,
    length: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: isize,
) -> *mut c_void {
    let ret_addr: *mut c_void;
    asm!(
        "movq $9, %rax", // SYS_mmap
        "movq {0}, %rdi",
        "movq {1}, %rsi",
        "movl {2}, %edx",
        "movq {3}, %r10",
        "movq {4}, %r8",
        "movq {5}, %r9",
        "vmcall",
        "movq %rax, {6}",
        in(reg) addr,
        in(reg) length,
        in(reg) prot,
        in(reg) flags,
        in(reg) fd,
        in(reg) offset,
        out(reg) ret_addr,
    );
    ret_addr
}

#[no_mangle]
pub unsafe extern "C" fn dune_die() {
    asm!(
        "movq $60, %rax", // exit
        "vmcall",
        out("rax") _,
    );
}

#[no_mangle]
pub unsafe extern "C" fn dune_passthrough_syscall(tf: &mut DuneTf) {
    let mut rax = tf.rax();
    asm!(
        "movq {0}, %rdi",
        "movq {1}, %rsi",
        "movq {2}, %rdx",
        "movq {3}, %r10",
        "movq {4}, %r8",
        "movq {5}, %r9",
        "vmcall",
        "movq %rax, {6}",
        in(reg) tf.rdi(),
        in(reg) tf.rsi(),
        in(reg) tf.rdx(),
        in(reg) tf.rcx(),
        in(reg) tf.r8(),
        in(reg) tf.r9(),
        inout(reg) rax,
    );
    tf.set_rax(rax);
}

#[no_mangle]
pub unsafe extern "C" fn dune_signal(sig: c_int, cb: *const SigHandler) -> *const sighandler_t {
    let x: *const DuneIntrCb = cb as *const DuneIntrCb;

    let ret = signal(sig, cb as sighandler_t);
    if ret == SIG_ERR {
        return SIG_ERR as *const sighandler_t;
    }

    dune_register_intr_handler(DUNE_SIGNAL_INTR_BASE + sig as usize, *x);

    ptr::null_mut() as *const sighandler_t
}
