use std::env;
use std::fs::File;
use std::io::{self, BufRead};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::process::{self, exit};
use std::ptr;
use std::ffi::CString;
use std::panic;
use std::arch::asm;
use nix::errno::Errno;
use dune_sys::DuneTf;
use dune_sys::Result;
use dune_sys::Error;
use crate::DuneRoutine;

// Constants
const MAX_SYSCALLS: usize = 512; // Replace with actual value of __NR_syscalls

// A simple bitmap to store hotcalls (in this case, a vector of u64).
static HOTCALLS_BITMAP: AtomicU64 = AtomicU64::new(0);

#[repr(C)]
#[derive(Debug)]
pub struct HotcallArgs {
    pub sysnr: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub r10: u64,
    pub r8: u64,
    pub r9: u64,
}

pub fn register_hotcall(syscall: i64) {
    if syscall >= 0 && syscall < MAX_SYSCALLS as i64 {
        let mask = 1u64 << (syscall as usize % 64);
        HOTCALLS_BITMAP.fetch_or(mask, Ordering::SeqCst);
    }
}

pub fn unregister_hotcall(syscall: i64) {
    if syscall >= 0 && syscall < MAX_SYSCALLS as i64 {
        let mask = !(1u64 << (syscall as usize % 64));
        HOTCALLS_BITMAP.fetch_and(mask, Ordering::SeqCst);
    }
}

pub fn is_hotcall(syscall: u64) -> bool {
    if syscall >= 0 && syscall < MAX_SYSCALLS as u64 {
        let mask = 1u64 << (syscall as usize % 64);
        return (HOTCALLS_BITMAP.load(Ordering::SeqCst) & mask) != 0;
    }
    false
}

pub fn need_hotcalls(sysnr: u64) -> bool {
    let cs: u16;
    unsafe {
        asm!("mov %cs, {0:x}", out(reg) cs, options(att_syntax));
    }
    ((cs & 0x3) == 0) && is_hotcall(sysnr)
}

pub fn vmpl_hotcalls_call(tf: &DuneTf) -> i64 {
    if !is_hotcall(tf.rax()) {
        return Errno::ENOSYS as i64;
    }

    let args = HotcallArgs {
        sysnr: tf.rax(),
        rdi: tf.rdi(),
        rsi: tf.rsi(),
        rdx: tf.rdx(),
        r10: tf.rcx(),
        r8: tf.r8(),
        r9: tf.r9(),
    };

    unsafe { hotcalls_call(&args) }
}

pub fn exec_hotcall(nr: u64, rdi: u64, rsi: u64, rdx: u64, r10: u64, r8: u64, r9: u64) -> Result<i64> {
    if !need_hotcalls(nr) {
        return Err(Error::LibcError(Errno::ENOSYS));
    }

    let args = HotcallArgs {
        sysnr: nr,
        rdi,
        rsi,
        rdx,
        r10,
        r8,
        r9,
    };

    let ret = unsafe {hotcalls_call(&args)};
    Ok(ret)
}

pub fn load_hotcalls(hotcalls_conf: &str) -> usize {
    let file = File::open(hotcalls_conf).unwrap_or_else(|_| {
        eprintln!("Failed to open hotcalls config file");
        exit(1);
    });

    let mut nr_hotcalls = 0;
    for line in io::BufReader::new(file).lines() {
        let line = line.unwrap();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() == 2 {
            if let Ok(syscall) = parts[1].parse::<i64>() {
                register_hotcall(syscall);
                nr_hotcalls += 1;
                println!("Registering hotcall syscall: {}", syscall);
            }
        }
    }

    nr_hotcalls
}

extern "C" {
    pub fn hotcalls_cleanup();
    pub fn hotcalls_setup(enabled: bool);
    pub fn hotcalls_call(args: *const HotcallArgs) -> i64;
}

pub fn setup_hotcalls() {
    let hotcalls_conf = env::var("HOTCALLS_CONFIG_FILE").unwrap_or_else(|_| {
        eprintln!("HOTCALLS_CONFIG_FILE not set");
        exit(1);
    });

    let nr_hotcalls = load_hotcalls(&hotcalls_conf);
    if nr_hotcalls > 0 {
        // Initialize hotcalls system (equivalent of hotcalls_setup(1))
        unsafe { hotcalls_setup(true) };

        // Register cleanup function (equivalent of atexit in C)
        panic::set_hook(Box::new(|_info| {
            unsafe { hotcalls_cleanup() };
        }));

        println!("Hotcalls enabled with {} registered hotcalls", nr_hotcalls);
    } else {
        println!("Hotcalls not enabled");
    }
}

pub trait WithHotCalls : DuneRoutine {

    fn setup_hotcalls() {
        setup_hotcalls();
    }
}

#[test]
fn main() {
    setup_hotcalls();

    // Example usage
    let tf = Default::default();
    // Call openat(0, "/proc/cpuinfo", 0)
    tf.set_rax(257)
        .set_rdi(0)
        .set_rsi(CString::new("/proc/cpuinfo").unwrap().as_ptr() as u64)
        .set_rdx(0);
    let _result = vmpl_hotcalls_call(&tf);

    // Simulate panic to trigger cleanup
    panic!("Simulating panic to trigger cleanup.");
}