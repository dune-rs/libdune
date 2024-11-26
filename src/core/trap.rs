/*
 * trap.c - x86 fault handling
 */
use dune_sys::trap::DuneTf;
use x86_64::VirtAddr;
use crate::core::*;
use crate::mm::*;
use crate::utils::*;
use crate::globals::*;
use crate::dune_printf;

use std::arch::asm;
use std::sync::atomic::Ordering;
use std::sync::atomic::AtomicPtr;
use x86_64::structures::paging::page_table::PageTableFlags;
use std::ptr;

pub const IDT_ENTRIES: usize = 256;
pub const DUNE_SIGNAL_INTR_BASE: usize = 32;
pub const STACK_DEPTH: u64 = 12;

pub type DuneSyscallCb = extern "C" fn(&mut DuneTf);
pub type DunePgfltCb = extern "C" fn(u64, u64, &mut DuneTf);
pub type DuneIntrCb = extern "C" fn(&mut DuneTf);

static SYSCALL_CB: AtomicPtr<DuneSyscallCb> = AtomicPtr::new(ptr::null_mut());
static PGFLT_CB: AtomicPtr<DunePgfltCb> = AtomicPtr::new(ptr::null_mut());
static INTR_CBS: [AtomicPtr<DuneIntrCb>; IDT_ENTRIES] = [const { AtomicPtr::new(ptr::null_mut()) }; IDT_ENTRIES];

#[inline(always)]
fn read_cr2() -> u64 {
    let val: u64;
    unsafe {
        asm!("mov {}, cr2", out(reg) val);
    }
    val
}

pub fn dune_register_intr_handler(vec: usize, cb: DuneIntrCb) -> Result<(), i32> {
    if vec >= IDT_ENTRIES {
        return Err(-libc::EINVAL);
    }
    INTR_CBS[vec].store(Box::into_raw(Box::new(cb)), Ordering::SeqCst);
    Ok(())
}

pub fn dune_register_signal_handler(signum: usize, cb: DuneIntrCb) -> Result<(), i32> {
    dune_register_intr_handler(DUNE_SIGNAL_INTR_BASE + signum, cb)
}

pub fn dune_register_syscall_handler(cb: DuneSyscallCb) {
    SYSCALL_CB.store(Box::into_raw(Box::new(cb)), Ordering::SeqCst);
}

pub fn dune_register_pgflt_handler(cb: DunePgfltCb) {
    PGFLT_CB.store(Box::into_raw(Box::new(cb)), Ordering::SeqCst);
}

unsafe fn addr_is_mapped(va_start: VirtAddr) -> bool {
    let mut dune_vm = DUNE_VM.lock().unwrap();
    let root = dune_vm.get_mut_root();
    match DuneVm::lookup(root, va_start, CreateType::None) {
        Ok(pte) => {
            if pte.flags().contains(PageTableFlags::PRESENT) {
                return true;
            }
            return false;
        }
        Err(_) => {
            return false;
        }
    }
}

#[no_mangle]
unsafe extern "C" fn dune_dump_stack(tf: &DuneTf) {
    let sp = tf.rsp() ;
    let va_start = VirtAddr::new(sp);
    dune_printf!("dune: Dumping Stack Contents...");
    for i in 0..STACK_DEPTH {
        if !addr_is_mapped(va_start) {
            dune_printf!("dune: reached unmapped addr");
            break;
        }
        let offset = i * std::mem::size_of::<u64>() as u64;
        let addr: *const u64 = (va_start + offset).as_ptr();
        dune_printf!("dune: RSP{:+3} 0x{:016x}", offset, unsafe { *addr });
    }
}

#[no_mangle]
unsafe extern "C" fn dune_hexdump(x: *const u8, len: usize) {
    let mut p = x;
    for _ in 0..len {
        print!("{:02x} ", unsafe { *p });
        p = unsafe { p.add(1) };
    }
    dune_printf!("\n");
}

#[no_mangle]
unsafe extern "C" fn dump_ip(tf: &DuneTf) {
    let p = tf.rip() as *const u8;
    let len = 20;
    dune_printf!("dune: code before IP\t");
    dune_hexdump(unsafe { p.sub(len) }, len);
    dune_printf!("dune: code at IP\t");
    dune_hexdump(p, len);
}

#[no_mangle]
pub unsafe extern "C" fn dune_dump_trap_frame(tf: &DuneTf) {
    dune_printf!("dune: --- Begin Trap Dump ---");
    dune_printf!("dune: RIP 0x{:016x}", tf.rip());
    dune_printf!("dune: CS 0x{:02x} SS 0x{:02x}", tf.cs() as u64, tf.ss() as u64);
    dune_printf!("dune: ERR 0x{:08x} RFLAGS 0x{:08x}", tf.err(), tf.rflags());
    dune_printf!("dune: RAX 0x{:016x} RCX 0x{:016x}", tf.rax(), tf.rcx());
    dune_printf!("dune: RDX 0x{:016x} RBX 0x{:016x}", tf.rdx(), tf.rbx());
    dune_printf!("dune: RSP 0x{:016x} RBP 0x{:016x}", tf.rsp(), tf.rbp());
    dune_printf!("dune: RSI 0x{:016x} RDI 0x{:016x}", tf.rsi(), tf.rdi());
    dune_printf!("dune: R8  0x{:016x} R9  0x{:016x}", tf.r8(), tf.r9());
    dune_printf!("dune: R10 0x{:016x} R11 0x{:016x}", tf.r10(), tf.r11());
    dune_printf!("\n");
}

#[allow(dead_code)]
#[no_mangle]
unsafe extern "C" fn dune_syscall_handler(tf: &mut DuneTf) {
    let syscall_cb = SYSCALL_CB.load(Ordering::SeqCst);
    if !syscall_cb.is_null() {
        unsafe { (*syscall_cb)(tf) };
    } else {
        dune_printf!("missing handler for system call - #{}", tf.rax());
        dune_dump_trap_frame(tf);
        dune_die();
    }
}

#[no_mangle]
pub unsafe extern "C" fn dune_trap_handler(num: usize, tf: &mut DuneTf) {
    let intr_cb = INTR_CBS[num].load(Ordering::SeqCst);
    if !intr_cb.is_null() {
        unsafe { (*intr_cb)(tf) };
        return;
    }

    match num {
        T_PGFLT => {
            let pgflt_cb = PGFLT_CB.load(Ordering::SeqCst);
            if !pgflt_cb.is_null() {
                unsafe { (*pgflt_cb)(read_cr2(), tf.err() as u64, tf) };
            } else {
                dune_printf!("unhandled page fault {:x} {:x}", read_cr2(), tf.err());
                dune_dump_trap_frame(tf);
                let _ = dune_procmap_dump();
                dune_die();
            }
        }
        T_NMI | T_DBLFLT | T_GPFLT => {
            dune_printf!("fatal exception {}, code {:x} - dying...", num, tf.err());
            dune_dump_trap_frame(tf);
            dune_die();
        }
        _ => {
            dune_printf!("unhandled exception {}", num);
            dune_dump_trap_frame(tf);
            dune_die();
        }
    }
}
