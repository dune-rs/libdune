use std::ffi::{c_int, c_void};
use std::sync::Mutex;
use lazy_static::lazy_static;
use libc::EXIT_SUCCESS;
use nix::errno::Errno;
use core::arch::global_asm;
use dune_sys::{DuneConfig, *};
use crate::core::*;
use crate::core::percpu::{get_percpu, set_percpu};
use dune_sys::result::Result;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::any::Any;
use std::sync::Arc;
use std::mem::offset_of;

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

    pub fn dune_pop_trap_frame(tf: *mut dune_sys::DuneTf);
    pub fn dune_jump_to_user(tf: *mut dune_sys::DuneTf) -> c_int;
    pub fn dune_ret_from_user(ret: c_int) -> !;

    // assembly routine for handling vsyscalls
    pub static __dune_vsyscall_page: u64;
}

#[cfg(feature = "dune")]
use crate::core::dune::offsets::*;
#[cfg(feature = "vmpl")]
use crate::core::vmpl::offsets::*;

global_asm!(
    include_str!("dune.S"),
    options(att_syntax),
    TMP = const TMP,
    KFS_BASE = const KFS_BASE,  // 使用 offset
    UFS_BASE = const UFS_BASE,  // 使用 offset
    IN_USERMODE = const IN_USERMODE,
    TRAP_STACK = const TRAP_STACK,
    IOCTL_DUNE_ENTER = const IOCTL_DUNE_ENTER,
    DUNE_CFG_RET = const DUNE_CFG_RET,
    DUNE_CFG_RAX = const DUNE_CFG_RAX,
    DUNE_CFG_RBX = const DUNE_CFG_RBX,
    DUNE_CFG_RCX = const DUNE_CFG_RCX,
    DUNE_CFG_RDX = const DUNE_CFG_RDX,
    DUNE_CFG_RSI = const DUNE_CFG_RSI,
    DUNE_CFG_RDI = const DUNE_CFG_RDI,
    DUNE_CFG_RSP = const DUNE_CFG_RSP,
    DUNE_CFG_RBP = const DUNE_CFG_RBP,
    DUNE_CFG_R8 = const DUNE_CFG_R8,
    DUNE_CFG_R9 = const DUNE_CFG_R9,
    DUNE_CFG_R10 = const DUNE_CFG_R10,
    DUNE_CFG_R11 = const DUNE_CFG_R11,
    DUNE_CFG_R12 = const DUNE_CFG_R12,
    DUNE_CFG_R13 = const DUNE_CFG_R13,
    DUNE_CFG_R14 = const DUNE_CFG_R14,
    DUNE_CFG_R15 = const DUNE_CFG_R15,
    DUNE_CFG_RIP = const DUNE_CFG_RIP,
    DUNE_CFG_RFLAGS = const DUNE_CFG_RFLAGS,
    DUNE_CFG_STATUS = const DUNE_CFG_STATUS,
    DUNE_RET_NOENTER = const DUNE_RET_NOENTER,
);

global_asm!(
    include_str!("vsyscall.S"),
    options(att_syntax),
    __NR_gettimeofday = const libc::SYS_gettimeofday,
    __NR_time = const libc::SYS_time,
    __NR_getcpu = const libc::SYS_getcpu,
);

pub trait DuneRoutine : Any + Send + Sync {
    fn dune_init(&mut self, map_full: bool) -> Result<()>;
    fn dune_enter(&mut self) -> Result<()>;
    fn on_dune_exit(&mut self, conf: *mut DuneConfig) -> !;
}

lazy_static! {
    pub static ref DEVICE: Mutex<Option<Box<dyn DuneRoutine>>> = Mutex::new(None);
}

pub fn get_system<T: 'static>() -> Option<&'static mut T> {
    let device = DEVICE.lock().unwrap();
    if let Some(device) = device.as_mut() {
        device.as_any().downcast_mut::<T>()
    } else {
        None
    }
}

pub fn set_system<T: 'static>(system: Box<T>) {
    let mut device = DEVICE.lock().unwrap();
    if let Some(device) = device.as_mut() {
        *device = Some(system);
    }
}

fn check_cpu_features() -> Result<()> {
    let path = Path::new("/proc/cpuinfo");
    let file = File::open(&path)
                    .map_err(|_| Error::LibcError(Errno::ENOENT))?;
    let reader = io::BufReader::new(file);

    let mut has_vmx = false;
    let mut has_sev_snp = false;

    for line in reader.lines() {
        let line = line.map_err(|_| Error::LibcError(Errno::ENOENT))?;
        if line.contains("vmx") {
            log::info!("Intel VT-x found");
            has_vmx = true;
            break;
        }
        if line.contains("svm") {
            log::info!("AMD SVM found");
            has_sev_snp = true;
            break;
        }
    }

    if has_vmx {
        set_system(Box::new(DuneSystem::new()));
        Ok(())
    } else if has_sev_snp {
        set_system(Box::new(VmplSystem::new()));
        Ok(())
    } else {
        Err(Error::LibcError(Errno::ENOTSUP))
    }
}

#[no_mangle]
pub extern "C" fn dune_init(map_full: bool) -> c_int {
    lazy_static::initialize(&DEVICE);
    if let Err(e) = check_cpu_features() {
        log::error!("dune_init() {}", e);
        return libc::EXIT_FAILURE;
    }

    let device = get_system::<dyn DuneRoutine>();
    device.and_then(|device| {
        match device.dune_init(map_full) {
            Ok(_) => 0,
            Err(e) => {
                log::error!("dune_init() {}", e);
                libc::EXIT_FAILURE
            }
        }
    }).unwrap_or(libc::EXIT_FAILURE)
}

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
pub extern "C" fn dune_enter() -> c_int {
    let mut device = get_system::<dyn DuneRoutine>();
    device.and_then(|device| {
        match device.dune_enter() {
            Ok(_) => 0,
            Err(e) => {
                log::error!("dune_enter() {}", e);
                libc::EXIT_FAILURE
            }
        }
    }).unwrap_or(libc::EXIT_FAILURE)
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
pub extern "C" fn dune_init_and_enter() -> c_int {
    let device = get_system::<dyn DuneRoutine>();
    device.and_then(|device| {
        match device.dune_init(true) {
            Ok(_) => dune_enter(),
            Err(e) => {
                log::error!("dune_init_and_enter() {}", e);
                libc::EXIT_FAILURE
            }
        }
    }).unwrap_or(libc::EXIT_FAILURE)
}

/**
 * on_dune_exit - handle Dune exits
 *
 * This function must not return. It can either exit(), __dune_go_dune() or
 * __dune_go_linux().
 */
#[no_mangle]
pub unsafe extern "C" fn on_dune_exit(conf: *mut DuneConfig) -> ! {
    let device = get_system::<dyn DuneRoutine>();
    device.and_then(|device| {
        device.on_dune_exit(conf)
    });
}