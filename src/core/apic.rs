use std::alloc::{alloc, dealloc, Layout};
use std::arch::asm;
use std::ptr;
use std::sync::atomic::{fence, Ordering};
use std::mem::MaybeUninit;
use x86_64::registers::model_specific::Msr;
use libc::sched_getcpu;
use libc::{sysconf, _SC_NPROCESSORS_CONF};
use std::ffi::c_void;
use nix::errno::Errno;
use log;
use dune_sys::{Result, Error};
use crate::core::DuneRoutine;

const APIC_DM_FIXED: u32 = 0x00000;
const NMI_VECTOR: i32 = 0x02;
const APIC_DM_NMI: u32 = 0x00400;
const APIC_DEST_PHYSICAL: u32 = 0x00000;
const EOI_ACK: u32 = 0x0;

static mut APIC_ROUTING: *mut i32 = ptr::null_mut();
static mut NUM_RT_ENTRIES: i64 = 0;

fn dune_apic_get_id() -> u64 {
    let msr = Msr::new(0x802);
    unsafe {msr.read()}
}

pub fn dune_apic_setup() -> Result<()> {
    log::info!("setup apic");
    unsafe {
        NUM_RT_ENTRIES = sysconf(_SC_NPROCESSORS_CONF);
        let num_rt_entries = NUM_RT_ENTRIES; // 将值复制到局部变量
        log::debug!("num rt entries: {}", num_rt_entries);
        let layout = Layout::array::<i32>(num_rt_entries as usize).unwrap();
        APIC_ROUTING = alloc(layout) as *mut i32;

        if APIC_ROUTING.is_null() {
            log::error!("apic routing table allocation failed");
            return Err(Error::LibcError(Errno::ENOMEM));
        }

        NUM_RT_ENTRIES = NUM_RT_ENTRIES - 1;
        ptr::write_bytes(APIC_ROUTING, u8::MAX, NUM_RT_ENTRIES as usize);
        fence(Ordering::SeqCst);
    }
    Ok(())
}

pub fn dune_apic_cleanup() {
    unsafe {
        if !APIC_ROUTING.is_null() {
            let layout = Layout::array::<i32>(NUM_RT_ENTRIES as usize).unwrap();
            dealloc(APIC_ROUTING as *mut u8, layout);
        }
    }
}

pub fn dune_apic_init_rt_entry() {
    unsafe {
        let core_id = sched_getcpu();
        *APIC_ROUTING.add(core_id as usize) = dune_apic_get_id() as i32;
        fence(Ordering::SeqCst);
    }
}

pub fn dune_apic_get_id_for_cpu(cpu: u32, error: &mut bool) -> u32 {
    unsafe {
        if cpu >= NUM_RT_ENTRIES as u32 {
            *error = true;
            return 0;
        }
        *APIC_ROUTING.add(cpu as usize) as u32
    }
}

fn __prepare_icr(shortcut: u32, vector: i32, dest: u32) -> u32 {
    let mut icr = shortcut | dest;
    match vector {
        NMI_VECTOR => icr |= APIC_DM_NMI,
        _ => icr |= APIC_DM_FIXED | vector as u32,
    }
    icr
}

pub fn dune_apic_send_ipi(vector: u8, dest_apic_id: u64) {
    let low = __prepare_icr(0, vector as i32, APIC_DEST_PHYSICAL);
    unsafe {
        let mut msr = Msr::new(0x83F);
        msr.write(dest_apic_id << 32 | low as u64);
    }
}

pub fn dune_apic_eoi() {
    let mut msr = Msr::new(0x80B);
    unsafe {msr.write(EOI_ACK as u64)}
}

pub trait WithDuneAPIC : DuneRoutine {

    fn apic_setup(&self) -> Result<()> {
        dune_apic_setup()
    }

    fn apic_cleanup(&self) {
        dune_apic_cleanup()
    }
}