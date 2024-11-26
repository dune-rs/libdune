use std::arch::asm;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use std::{ptr, str};
use libc::{sighandler_t, SIG_ERR};
use libc::{strlen,signal};
use nix::errno::Errno;
use x86_64::VirtAddr;
use dune_sys::DuneTf;
use std::fmt::Write;

use crate::{core::*, Error};
use crate::globals::{ARCH_GET_FS, ARCH_SET_FS};
use crate::result::Result;

type SigHandler = extern "C" fn(c_int);

#[inline(always)]
pub unsafe fn dune_get_ticks() -> u64 {
    let a: u32;
    let d: u32;
    asm!(
        "rdtsc",
        out("eax") a,
        out("edx") d,
    );
    (a as u64) | ((d as u64) << 32)
}

#[inline(always)]
pub fn dune_flush_tlb_one(addr: u64) {
    unsafe {
        asm!(
            "invlpg ({0})",
            in(reg) addr,
            options(nostack, preserves_flags, att_syntax)
        );
    }
}

#[inline(always)]
pub fn dune_flush_tlb() {
    unsafe {
        asm!(
            "mov rax, cr3",
            "mov cr3, rax",
            options(nostack, preserves_flags)
        );
    }
}

pub fn load_cr3(cr3: u64) {
    unsafe {
        asm!("mov {0}, %cr3", in(reg) cr3, options(att_syntax, nostack, preserves_flags));
    }
}

pub fn rd_rsp() -> u64 {
    let esp: u64;
    unsafe {
        asm!("mov %rsp, {}", out(reg) esp, options(att_syntax));
    }
    esp
}

#[inline(always)]
pub fn get_fs_base() -> Result<VirtAddr> {
    let mut fs_base: u64 = 0;
    unsafe {
        let ret = arch_prctl(ARCH_GET_FS, &mut fs_base as *mut u64 as *mut c_void);
        if ret == -1 {
            eprintln!("dune: failed to get FS register");
            return Err(Error::LibcError(Errno::EIO));
        }
    }

    Ok(VirtAddr::new(fs_base))
}

#[inline(always)]
pub fn set_fs_base(fs_base: VirtAddr) -> Result<()> {
    unsafe {
        let ret = arch_prctl(ARCH_SET_FS, fs_base.as_u64() as *mut c_void);
        if ret == -1 {
            eprintln!("dune: failed to set FS register");
            return Err(Error::Unknown);
        }
    }

    Ok(())
}

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
        out(reg) ret,
        options(nostack,att_syntax),
    );
    ret
}

pub fn __dune_printf(fmt: &str, args: std::fmt::Arguments) -> i64 {
    let mut buffer = String::new();
    write!(&mut buffer, "{}", args).unwrap();
    let c_string = CString::new(buffer).unwrap();
    unsafe { dune_puts(c_string.as_ptr()) }
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! dune_printf {
    ($($arg:tt)*) => {
        __dune_printf("%s", format_args!($($arg)*))
    };
    () => {
        __dune_printf(format_args!(""))
    };
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
        "movl {2:e}, %edx",
        "movl {3:e}, %r10d",
        "movl {4:e}, %r8d",
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
        options(nostack, att_syntax),
    );
    ret_addr
}

#[no_mangle]
pub unsafe extern "C" fn dune_die() {
    asm!(
        "movq $60, %rax", // exit
        "vmcall",
        out("rax") _,
        options(nostack, att_syntax),
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
        options(nostack, att_syntax),
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

    let _ = dune_register_intr_handler(DUNE_SIGNAL_INTR_BASE + sig as usize, *x);

    ptr::null_mut() as *const sighandler_t
}
