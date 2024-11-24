use std::alloc::{alloc, dealloc, Layout};
use std::arch::asm;
use std::ptr;
use std::sync::atomic::{fence, Ordering};
use std::mem::MaybeUninit;
use libc::{sched_getcpu, get_nprocs_conf};
use std::ffi::c_void;
use log;

const APIC_DM_FIXED: u32 = 0x00000;
const NMI_VECTOR: u32 = 0x02;
const APIC_DM_NMI: u32 = 0x00400;
const APIC_DEST_PHYSICAL: u32 = 0x00000;
const EOI_ACK: u32 = 0x0;

static mut APIC_ROUTING: *mut i32 = ptr::null_mut();
static mut NUM_RT_ENTRIES: i32 = 0;

fn dune_apic_get_id() -> u32 {
    let mut apic_id: u64 = 0;
    unsafe {
        asm!("rdmsr", in("ecx") 0x802, out("eax") apic_id, out("edx") _);
    }
    apic_id as u32
}

pub fn dune_apic_setup() -> Result<(), i32> {
    log::info!("setup apic");
    unsafe {
        NUM_RT_ENTRIES = get_nprocs_conf();
        log::debug!("num rt entries: {}", NUM_RT_ENTRIES);
        let layout = Layout::array::<i32>(NUM_RT_ENTRIES as usize).unwrap();
        APIC_ROUTING = alloc(layout) as *mut i32;

        if APIC_ROUTING.is_null() {
            log::error!("apic routing table allocation failed");
            return Err(libc::ENOMEM);
        }

        NUM_RT_ENTRIES = get_nprocs_conf();
        ptr::write_bytes(APIC_ROUTING, -1, NUM_RT_ENTRIES as usize);
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
        *APIC_ROUTING.add(core_id as usize) = apic_get_id() as i32;
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

pub fn dune_apic_send_ipi(vector: u8, dest_apic_id: u32) {
    let low = __prepare_icr(0, vector as i32, APIC_DEST_PHYSICAL);
    unsafe {
        asm!("wrmsr", in("ecx") 0x830, in("eax") low, in("edx") dest_apic_id);
    }
}

pub fn dune_apic_eoi() {
    unsafe {
        asm!("wrmsr", in("ecx") 0x80B, in("eax") EOI_ACK, in("edx") 0);
    }
}
