use std::ffi::{c_int, c_void};
use std::io::{self, ErrorKind};
use std::sync::Mutex;
use std::cell::RefCell;
use libc::{open, O_RDWR};
use x86_64::structures::paging::PageTable;
use lazy_static::lazy_static;
use core::arch::global_asm;
use dune_sys::{DuneConfig, DuneDevice, DuneRetCode, *};
use crate::{core::*, dune_page_init};
use crate::result::{Result, Error};

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
    pub static __dune_vsyscall_page: u64;
}

global_asm!(
    include_str!("dune.S"),
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
    DUNE_CFG_CR3 = const DUNE_CFG_CR3,
    DUNE_CFG_STATUS = const DUNE_CFG_STATUS,
    DUNE_CFG_VCPU = const DUNE_CFG_VCPU,
    DUNE_RET_NOENTER = const DUNE_RET_NOENTER,
);

global_asm!(
    include_str!("vsyscall.S"),
    __NR_gettimeofday = const libc::SYS_gettimeofday,
    __NR_time = const libc::SYS_time,
    __NR_getcpu = const libc::SYS_getcpu,
);

thread_local! {
    static LPERCPU: RefCell<Option<DunePercpu>> = RefCell::new(None);
}

lazy_static! {
    pub static ref PGROOT: Mutex<PageTable> = Mutex::new(PageTable::new());
    pub static ref DUNE_FD: Mutex<i32> = Mutex::new(0);
    pub static ref LAYOUT: Mutex<DuneLayout> = Mutex::new(DuneLayout::default());
}

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
pub unsafe extern "C" fn dune_enter() -> Result<()> {
    // Check if this process already entered Dune before a fork...
    LPERCPU.with(|percpu| {
        let mut percpu = percpu.borrow_mut();
        // if not none then enter
        if percpu.is_none() {
            *percpu = DunePercpu::create().ok();
            // if still none, return error
            if let None = *percpu {
                return Err(Error::Unknown);
            }
        }

        let percpu = percpu.as_mut().unwrap();
        do_dune_enter(percpu).map_err(|e|{
            percpu.free();
            e
        })
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
#[no_mangle]
pub extern "C" fn dune_init(map_full: bool) -> Result<()> {
    let dune_fd = &mut *DUNE_FD.lock().unwrap();
    *dune_fd = unsafe { open("/dev/dune\0".as_ptr() as *const i8, O_RDWR) };
    if *dune_fd <= 0 {
        return Err(Error::Unknown);
    }

    // Initialize the root page table
    lazy_static::initialize(&PGROOT);

    // Zero out the root page table
    PGROOT.lock().as_deref_mut().and_then(|pgroot|{
        pgroot.zero();
        Ok(())
    });

    if dune_page_init().is_err() {
        return Err(Error::Unknown);
    }
    
    if setup_mappings(map_full).is_err() {
        return Err(Error::Unknown);
    }

    if setup_syscall().is_err() {
        return Err(Error::Unknown);
    }

    setup_signals()?;

    setup_idt();

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
pub unsafe extern "C" fn dune_init_and_enter() -> Result<()> {
    if dune_init(true).is_err() {
        return Err(Error::Unknown);
    }

    dune_enter()
}

/**
 * on_dune_exit - handle Dune exits
 *
 * This function must not return. It can either exit(), __dune_go_dune() or
 * __dune_go_linux().
 */
#[no_mangle]
pub unsafe extern "C" fn on_dune_exit(conf_: *mut DuneConfig) -> ! {
    let conf = unsafe { &*conf_ };
    let ret: DuneRetCode = conf.ret().into();
    match ret {
        DuneRetCode::Exit => {
            unsafe { libc::syscall(libc::SYS_exit, conf.status()) };
        },
        DuneRetCode::EptViolation => {
            println!("dune: exit due to EPT violation");
        },
        DuneRetCode::Interrupt => {
            #[cfg(feature = "debug")]
            dune_debug_handle_int(conf_);
            println!("dune: exit due to interrupt {}", conf.status());
        },
        DuneRetCode::Signal => {
            let dune_fd = *DUNE_FD.lock().unwrap();
            __dune_go_dune(dune_fd, conf_);
        },
        DuneRetCode::UnhandledVmexit => {
            println!("dune: exit due to unhandled VM exit");
        },
        DuneRetCode::NoEnter => {
            println!("dune: re-entry to Dune mode failed, status is {}", conf.status());
        },
        _ => {
            println!("dune: unknown exit from Dune, ret={}, status={}", conf.ret(), conf.status());
        },
    }

    std::process::exit(libc::EXIT_FAILURE);
}
