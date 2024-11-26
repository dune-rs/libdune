use std::ffi::{c_int, c_void};
use std::sync::{Arc, Mutex};
use std::cell::RefCell;
use lazy_static::lazy_static;
use core::arch::global_asm;
use dune_sys::{DuneConfig, DuneDevice, DuneRetCode, *};
use crate::{core::*, dune_page_init, Error};
use crate::syscall::DuneSyscall;
use crate::result::Result;

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

global_asm!(
    include_str!("dune.S"),
    options(att_syntax),
    TMP = const TMP,
    KFS_BASE = const KFS_BASE,
    UFS_BASE = const UFS_BASE,
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

thread_local! {
    static LPERCPU: RefCell<Option<DunePercpu>> = RefCell::new(None);
}

use crate::mm::DuneVm;

lazy_static! {
    pub static ref DUNE_VM : Mutex<DuneVm> = Mutex::new(DuneVm::new());
    pub static ref DUNE_DEVICE: Mutex<DuneDevice> = Mutex::new(DuneDevice::new().unwrap());
}

pub trait DuneRoutine {
    fn dune_init(&mut self, map_full: bool) -> Result<()>;
    fn dune_enter(&mut self) -> Result<()>;
    fn on_dune_exit(&mut self, conf: *mut DuneConfig) -> !;
}

impl DuneRoutine for DuneDevice {
    fn dune_init(&mut self, map_full: bool) -> Result<()> {
        self.open().map_err(|e| Error::LibcError(e))?;
        // Initialize the Dune VM
        lazy_static::initialize(&DUNE_VM);

        let mut dune_vm = DUNE_VM.lock().unwrap();
        dune_vm.init(self.fd())?;

        dune_page_init()?;
        self.setup_mappings(map_full)?;
        self.setup_syscall()?;

        self.setup_signals()?;

        self.setup_idt();

        Ok(())
    }

    fn dune_enter(&mut self) -> Result<()> {
        let mut device = Arc::new(*self);
        // Check if this process already entered Dune before a fork...
        LPERCPU.with(|lpercpu| {
            let mut lpercpu = lpercpu.borrow_mut();
            // if not none, enter Dune mode
            match lpercpu.as_mut() {
                Some(percpu) => {
                    percpu.do_dune_enter()
                },
                None => {
                    match DunePercpu::create(&mut device) {
                        Ok(percpu) => {
                            percpu.do_dune_enter().map_err(|e|{
                                DunePercpu::free(percpu);
                                e
                            })?;
                            // if successful, set lpercpu to Some(percpu)
                            // let a = *lpercpu;
                            // a.replace(percpu);
                            Ok(())
                        },
                        Err(e) => {
                            // if still none, return error
                            Err(e)
                        }
                    }
                },
            }
        })
    }

    fn on_dune_exit(&mut self, conf_: *mut DuneConfig) -> ! {
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
                self.handle_int(conf_);
                println!("dune: exit due to interrupt {}", conf.status());
            },
            DuneRetCode::Signal => {
                unsafe { __dune_go_dune(self.fd(), conf_) };
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

        unsafe { libc::exit(libc::EXIT_FAILURE) };
    }
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
pub extern "C" fn dune_init(map_full: bool) -> c_int {
    lazy_static::initialize(&DUNE_DEVICE);
    let mut dune_device = DUNE_DEVICE.lock().unwrap();
    match dune_device.dune_init(map_full) {
        Ok(_) => 0,
        Err(e) => {
            log::error!("dune_init() {}", e);
            let _ = dune_device.close();
            libc::EXIT_FAILURE
        }
    }
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
    let mut dune_device = DUNE_DEVICE.lock().unwrap();
    match dune_device.dune_enter() {
        Ok(_) => 0,
        Err(_) => -1,
    }
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
    let ret= dune_init(true);
    if ret != 0 {
        return ret;
    }

	return dune_enter();
}

/**
 * on_dune_exit - handle Dune exits
 *
 * This function must not return. It can either exit(), __dune_go_dune() or
 * __dune_go_linux().
 */
#[no_mangle]
pub unsafe extern "C" fn on_dune_exit(conf: *mut DuneConfig) -> ! {
    let mut dune_device = DUNE_DEVICE.lock().unwrap();
    dune_device.on_dune_exit(conf);
}