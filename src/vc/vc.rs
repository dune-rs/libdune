/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use core::arch::asm;
use libc::{mmap, MAP_FAILED, MAP_FIXED, MAP_POPULATE, MAP_SHARED, PROT_READ, PROT_WRITE};
use x86_64::VirtAddr;
use x86_64::PhysAddr;
use x86_64::structures::paging::PageTableFlags;
use x86::msr::{rdmsr,wrmsr};
use nix::errno::Errno;
use dune_sys::result::Result;
use x86_64::structures::paging::page_table::PageTableEntry;

use crate::Error;
use crate::pgtable_lookup;
use crate::pgtable_va_to_pa;
use crate::pgtable_pa_to_va;
use crate::WithPageTable;
use crate::vc::sys::pvalidate;
use crate::vc::MSR_AMD64_SEV_ES_GHCB;
use crate::globals::PTE_W;
use crate::dune_flush_tlb_one;
use crate::vc::sys::PVALIDATE_RET_MAX;
use crate::vc::sys::PVALIDATE_RET_ERR;
use crate::vc::sys::PVALIDATE_CF_SET;
use crate::vc::sys::PVALIDATE_FAIL_SIZE_MISMATCH;
use crate::vc::Ghcb;
use crate::vc::SHARED_BUFFER_SIZE;
use crate::globals::{wrmsrl,rdmsrl};
use crate::vc::WithGHCB;
use crate::vc::GHCB_USAGE;
use crate::vc::GHCB_VERSION_1;
use libc::syscall;

// GHCB standard termination constants
/// 0
pub const GHCB_REASON_CODE_SET: u64 = 0;
/// 0
pub const GHCB_TERM_GENERAL: u64 = 0;
/// 1
pub const GHCB_TERM_UNSUPPORTED_PROTOCOL: u64 = 1;
/// 2
pub const GHCB_TERM_FEATURE_SUPPORT: u64 = 2;

// SVSM termination constants
/// 15
pub const SVSM_REASON_CODE_SET: u64 = 15;
/// 0
pub const SVSM_TERM_GENERAL: u64 = 0;
/// 1
pub const SVSM_TERM_ENOMEM: u64 = 1;
/// 2
pub const SVSM_TERM_UNHANDLED_VC: u64 = 2;
/// 3
pub const SVSM_TERM_PSC_ERROR: u64 = 3;
/// 4
pub const SVSM_TERM_SET_PAGE_ERROR: u64 = 4;
/// 5
pub const SVSM_TERM_NO_GHCB: u64 = 5;
/// 6
pub const SVSM_TERM_GHCB_RESP_INVALID: u64 = 6;
/// 7
pub const SVSM_TERM_FW_CFG_ERROR: u64 = 7;
/// 8
pub const SVSM_TERM_BIOS_FORMAT: u64 = 8;
/// 9
pub const SVSM_TERM_NOT_VMPL0: u64 = 9;
/// 10
pub const SVSM_TERM_VMPL0_SEV_FEATURES: u64 = 10;
/// 11
pub const SVSM_TERM_INCORRECT_VMPL: u64 = 11;
/// 12
pub const SVSM_TERM_VMPL1_SEV_FEATURES: u64 = 12;

/// 12
pub const PAGE_SHIFT: u64 = 12;
/// BIT 12
pub const PAGE_SIZE: u64 = BIT!(PAGE_SHIFT);
/// Page Mask (the opposite of page size minus 1)
pub const PAGE_MASK: u64 = !(PAGE_SIZE - 1);

/// 21
pub const PAGE_2MB_SHIFT: u64 = 21;
/// Bit 21
pub const PAGE_2MB_SIZE: u64 = BIT!(PAGE_2MB_SHIFT);
/// Page Mask for 2MB (the opposite of 2MB page size minus 1)
pub const PAGE_2MB_MASK: u64 = !(PAGE_2MB_SIZE - 1);

// CPUID
/// 0x0
pub const CPUID_VENDOR_INFO: u32 = 0x00000000;
/// 0xb
pub const CPUID_EXTENDED_TOPO: u32 = 0x0000000b;
/// 0xd
pub const CPUID_EXTENDED_STATE: u32 = 0x0000000d;

// MSRs
/// 0xc0000101
pub const MSR_GS_BASE: u32 = 0xc0000101;
/// 0xc0010130
pub const MSR_GHCB: u32 = 0xc0010130;
/// 0xc0010131
pub const MSR_SEV_STATUS: u32 = 0xc0010131;

// PVALIDATE and RMPADJUST related
/// 0
pub const RMP_4K: u32 = 0;
/// 1
pub const RMP_2M: u32 = 1;

/// Bit 8
pub const VMPL_R: u64 = BIT!(8);
/// Bit 9
pub const VMPL_W: u64 = BIT!(9);
/// Bit 10
pub const VMPL_X_USER: u64 = BIT!(10);
/// Bit 11
pub const VMPL_X_SUPER: u64 = BIT!(11);
/// Bit 16
pub const VMSA_PAGE: u64 = BIT!(16);

/// VMPL_R | VMPL_W | VMPL_X_USER | VMPL_X_SUPER
pub const VMPL_RWX: u64 = VMPL_R | VMPL_W | VMPL_X_USER | VMPL_X_SUPER;
/// VMPL_R | VMSA_PAGE
pub const VMPL_VMSA: u64 = VMPL_R | VMSA_PAGE;

#[derive(Copy, Clone, Debug)]
/// Vmpl levels
pub enum VMPL {
    Vmpl0,
    Vmpl1,
    Vmpl2,
    Vmpl3,

    VmplMax,
}

/// 8
pub const CAA_MAP_SIZE: u64 = 8;

/// PAGE_SIZE
pub const VMSA_MAP_SIZE: u64 = PAGE_SIZE;

fn is_aligned(pa: PhysAddr, alignment: u64) -> bool {
    false
}

fn read_xcr0() -> u64 {
    0
}

#[test]
fn main() {
    let va: u64 = 0x1000; // Example virtual address
    let page_size: u32 = 4096; // Example page size
    let validation: u32 = 0; // Example validation

    let pvalidate_result = pvalidate(va.as_u64(), page_size, validation);
    println!("pvalidate result: {}", pvalidate_result);

    let attrs: u64 = 0; // Example attributes
    let rmpadjust_result = rmpadjust(va.as_u64(), page_size, attrs);
    println!("rmpadjust result: {}", rmpadjust_result);
}


/// 2
const GHCB_PROTOCOL_MIN: u64 = 2;
/// 2
const GHCB_PROTOCOL_MAX: u64 = 2;

/// Bits zero, one and four
const GHCB_SVSM_FEATURES: u64 = BIT!(0) | BIT!(1) | BIT!(4);

/// 0xfff
const GHCB_MSR_INFO_MASK: u64 = 0xfff;

macro_rules! GHCB_MSR_INFO {
    ($x: expr) => {
        $x & GHCB_MSR_INFO_MASK
    };
}

macro_rules! GHCB_MSR_DATA {
    ($x: expr) => {
        $x & !GHCB_MSR_INFO_MASK
    };
}

// MSR protocol: SEV Information
/// 0x2
const GHCB_MSR_SEV_INFO_REQ: u64 = 0x002;
/// 0x1
const GHCB_MSR_SEV_INFO_RES: u64 = 0x001;
macro_rules! GHCB_MSR_PROTOCOL_MIN {
    ($x: expr) => {
        (($x) >> 32) & 0xffff
    };
}
macro_rules! GHCB_MSR_PROTOCOL_MAX {
    ($x: expr) => {
        (($x) >> 48) & 0xffff
    };
}

// MSR protocol: GHCB registration
/// 0x12
const GHCB_MSR_REGISTER_GHCB_REQ: u64 = 0x12;
macro_rules! GHCB_MSR_REGISTER_GHCB {
    ($x: expr) => {
        (($x) | GHCB_MSR_REGISTER_GHCB_REQ)
    };
}
/// 0x13
const GHCB_MSR_REGISTER_GHCB_RES: u64 = 0x13;

// MSR protocol: Hypervisor feature support
/// 0x80
const GHCB_MSR_HV_FEATURE_REQ: u64 = 0x080;
/// 0x81
const GHCB_MSR_HV_FEATURE_RES: u64 = 0x081;
macro_rules! GHCB_MSR_HV_FEATURES {
    ($x: expr) => {
        (GHCB_MSR_DATA!($x) >> 12)
    };
}

// MSR protocol: Termination request
/// 0x100
const GHCB_MSR_TERMINATE_REQ: u64 = 0x100;

/// 0
const RESCIND: u32 = 0;
/// 1
const VALIDATE: u32 = 1;

// VMGEXIT exit codes
/// 0x27
const GHCB_NAE_DR7_READ: u64 = 0x27;
/// 0x37
const GHCB_NAE_DR7_WRITE: u64 = 0x37;
/// 0x6e
const GHCB_NAE_RDTSC: u64 = 0x6e;
/// 0x6f
const GHCB_NAE_RDPMC: u64 = 0x6f;
/// 0x72
const GHCB_NAE_CPUID: u64 = 0x72;
/// 0x76
const GHCB_NAE_INVD: u64 = 0x76;
/// 0x7b
const GHCB_NAE_IOIO: u64 = 0x7b;
/// 0x7c
const GHCB_NAE_MSR_PROT: u64 = 0x7c;
/// 0x81
const GHCB_NAE_VMMCALL: u64 = 0x81;
/// 0x87
const GHCB_NAE_RDTSCP: u64 = 0x87;
/// 0x89
const GHCB_NAE_WBINVD: u64 = 0x89;
/// 0x80000010
const GHCB_NAE_PSC: u64 = 0x80000010;
/// 0x80000011
const GHCB_NAE_SNP_GUEST_REQUEST: u64 = 0x80000011;
/// 0x800000112
const GHCB_NAE_SNP_EXTENDED_GUEST_REQUEST: u64 = 0x80000012;
/// 0x80000013
const GHCB_NAE_SNP_AP_CREATION: u64 = 0x80000013;
/// 1
const SNP_AP_CREATE_IMMEDIATE: u64 = 1;
/// 0x80000017
const GHCB_NAE_GET_APIC_IDS: u64 = 0x80000017;
/// 0x80000018
const GHCB_NAE_RUN_VMPL: u64 = 0x80000018;

macro_rules! GHCB_NAE_SNP_AP_CREATION_REQ {
    ($op: expr, $vmpl: expr, $apic: expr) => {
        (($op) | ((($vmpl) as u64) << 16) | ((($apic) as u64) << 32))
    };
}

// GHCB IN/OUT instruction constants
/// Bit 9
const IOIO_ADDR_64: u64 = BIT!(9);
/// Bit 6
const IOIO_SIZE_32: u64 = BIT!(6);
/// Bit 5
const IOIO_SIZE_16: u64 = BIT!(5);
/// Bit 4
const IOIO_SIZE_8: u64 = BIT!(4);
/// Bit 0
const IOIO_TYPE_IN: u64 = BIT!(0);

static mut HV_FEATURES: u64 = 0;

fn vc_vmgexit() {
    unsafe {
        asm!("rep vmmcall");
    }
}

// Macro for extracting MSR info (same as ghcb_msr_info function)
macro_rules! GHCB_MSR_INFO {
    ($x:expr) => {
        $x & GHCB_MSR_INFO_MASK
    };
}

// Macro for extracting MSR data (same as ghcb_msr_data function)
macro_rules! GHCB_MSR_DATA {
    ($x:expr) => {
        $x & !GHCB_MSR_INFO_MASK
    };
}

// Macro for extracting the minimum protocol value (same as ghcb_msr_protocol_min function)
macro_rules! GHCB_MSR_PROTOCOL_MIN {
    ($x:expr) => {
        ($x >> 32) & 0xffff
    };
}

// Macro for extracting the maximum protocol value (same as ghcb_msr_protocol_max function)
macro_rules! GHCB_MSR_PROTOCOL_MAX {
    ($x:expr) => {
        ($x >> 48) & 0xffff
    };
}

// Macro for extracting the CPUID result value (same as ghcb_msr_cpuid_res_val function)
macro_rules! GHCB_MSR_CPUID_RES_VAL {
    ($v:expr) => {
        GHCB_MSR_DATA!($v) >> 32
    };
}

// Macro for extracting the preferred GHCB value (same as ghcb_msr_preferred_ghcb_val function)
macro_rules! GHCB_MSR_PREFERRED_GHCB_VAL {
    ($v:expr) => {
        GHCB_MSR_DATA!($v) >> 12
    };
}

// Macro for extracting SNP PSC value (same as ghcb_msr_snp_psc_val function)
macro_rules! GHCB_MSR_SNP_PSC_VAL {
    ($v:expr) => {
        $v >> 32
    };
}

// Macro for extracting VMPL response value (same as ghcb_msr_vmpl_resp_val function)
macro_rules! GHCB_MSR_VMPL_RESP_VAL {
    ($v:expr) => {
        $v >> 32
    };
}

// Macro for extracting HV features (same as ghcb_msr_hv_features function)
macro_rules! GHCB_MSR_HV_FEATURES {
    ($x:expr) => {
        GHCB_MSR_DATA!($x) >> 12
    };
}

// Macro for generating NAE SNP AP creation request (same as ghcb_nae_snp_ap_creation_req function)
macro_rules! GHCB_NAE_SNP_AP_CREATION_REQ {
    ($op:expr, $vmpl:expr, $apic:expr) => {
        ($op) | (($vmpl) << 16) | (($apic) << 32)
    };
}

fn main() {
    let x: u64 = 0x1234567890abcdef;
    let op: u64 = 0x1;
    let vmpl: u64 = 0x2;
    let apic: u64 = 0x3;

    // Example usage of macros:
    println!("GHCB_MSR_INFO: {:#x}", GHCB_MSR_INFO!(x));
    println!("GHCB_MSR_DATA: {:#x}", GHCB_MSR_DATA!(x));
    println!("GHCB_MSR_PROTOCOL_MIN: {:#x}", GHCB_MSR_PROTOCOL_MIN!(x));
    println!("GHCB_MSR_PROTOCOL_MAX: {:#x}", GHCB_MSR_PROTOCOL_MAX!(x));
    println!("GHCB_MSR_CPUID_RES_VAL: {:#x}", GHCB_MSR_CPUID_RES_VAL!(x));
    println!("GHCB_MSR_PREFERRED_GHCB_VAL: {:#x}", GHCB_MSR_PREFERRED_GHCB_VAL!(x));
    println!("GHCB_MSR_SNP_PSC_VAL: {:#x}", GHCB_MSR_SNP_PSC_VAL!(x));
    println!("GHCB_MSR_VMPL_RESP_VAL: {:#x}", GHCB_MSR_VMPL_RESP_VAL!(x));
    println!("GHCB_MSR_HV_FEATURES: {:#x}", GHCB_MSR_HV_FEATURES!(x));
    println!("GHCB_NAE_SNP_AP_CREATION_REQ: {:#x}", GHCB_NAE_SNP_AP_CREATION_REQ!(op, vmpl, apic));
}

fn sev_es_rd_ghcb_msr() -> u64 {
    rdmsrl(MSR_AMD64_SEV_ES_GHCB)
}

fn sev_es_wr_ghcb_msr(val: u64) {
    wrmsrl(MSR_AMD64_SEV_ES_GHCB, val)
}

// static HV_FEATURES: AtomicU64 = AtomicU64::new(0);

pub const GHCB_MSR_VMPL_REQ_LEVEL: u64 = 0x1;
pub const VMPL_REASON_CODE_SET: u64 = 0x3;
pub const VMPL_TERM_GENERAL: u64 = 0x4;
pub const VMPL_TERM_ENOMEM: u64 = 0x5;
pub const VMPL_TERM_GHCB_RESP_INVALID: u64 = 0x6;
pub const VMPL_TERM_SET_PAGE_ERROR: u64 = 0x7;
pub const VMPL_TERM_PSC_ERROR: u64 = 0x8;
pub const VMPL_TERM_UNHANDLED_VC: u64 = 0x9;
pub const VMPL_TERM_VMPL1_SEV_FEATURES: u64 = 0xE;
pub const VMPL_TERM_VMPL0_SEV_FEATURES: u64 = 0xF;

pub const PSC_SHARED: u64 = 2 << 52;
pub const PSC_PRIVATE: u64 = 1 << 52;
pub const PSC_ENTRIES: usize = (SHARED_BUFFER_SIZE - std::mem::size_of::<PscOpHeader>()) / 8;

#[repr(C)]
#[derive(Copy, Clone)]
struct PscOpHeader {
    cur_entry: u16,
    end_entry: u16,
    reserved: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct PscOpData {
    data: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct PscOp {
    header: PscOpHeader,
    entries: [PscOpData; PSC_ENTRIES],
}

macro_rules! GHCB_2MB_PSC_ENTRY {
    ($x: expr, $y: expr) => {
        ((($x) | ($y) | (1 << 56)) as u64)
    };
}

macro_rules! GHCB_4KB_PSC_ENTRY {
    ($x: expr, $y: expr) => {
        ((($x) | ($y)) as u64)
    };
}

macro_rules! GHCB_PSC_GPA {
    ($x: expr) => {
        ((($x) & ((1 << 52) - 1)) as u64)
    };
}

macro_rules! GHCB_PSC_SIZE {
    ($x: expr) => {
        (((($x) >> 56) & 1) as u32)
    };
}

fn vc_terminate(reason_set: u64, reason_code: u64) {
    unsafe {
        wrmsrl(MSR_AMD64_SEV_ES_GHCB, GHCB_MSR_VMPL_REQ_LEVEL);
        let mut value = GHCB_MSR_TERMINATE_REQ;
        value |= reason_set << 12;
        value |= reason_code << 16;
        syscall(libc::SYS_exit as i64, value);
    }
}

macro_rules! vc_terminate_fn {
    ($name:ident, $reason_code:expr) => {
        fn $name() {
            vc_terminate(VMPL_REASON_CODE_SET, $reason_code);
        }
    };
}

vc_terminate_fn!(vc_terminate_vmpl_general, VMPL_TERM_GENERAL);
vc_terminate_fn!(vc_terminate_vmpl_enomem, VMPL_TERM_ENOMEM);
vc_terminate_fn!(vc_terminate_vmpl_resp_invalid, VMPL_TERM_GHCB_RESP_INVALID);
vc_terminate_fn!(vc_terminate_vmpl_page_err, VMPL_TERM_SET_PAGE_ERROR);
vc_terminate_fn!(vc_terminate_vmpl_psc, VMPL_TERM_PSC_ERROR);
vc_terminate_fn!(vc_terminate_unhandled_vc, VMPL_TERM_UNHANDLED_VC);
vc_terminate_fn!(vc_terminate_ghcb_general, GHCB_TERM_GENERAL);
vc_terminate_fn!(vc_terminate_ghcb_unsupported_protocol, GHCB_TERM_UNSUPPORTED_PROTOCOL);
vc_terminate_fn!(vc_terminate_ghcb_feature, GHCB_TERM_FEATURE_SUPPORT);
vc_terminate_fn!(vc_terminate_vmpl1_sev_features, VMPL_TERM_VMPL1_SEV_FEATURES);
vc_terminate_fn!(vc_terminate_vmpl0_sev_features, VMPL_TERM_VMPL0_SEV_FEATURES);

fn print_stack(stack: &[u64]) {
    todo!();
}

fn vc_handler(rip: u64, error_code: u64, cr2: u64, stack: &[u64; 5]) {
    println!("Unhandled #VC exception: {:x}", error_code);
    #[cfg(feature = "debug")]
    print_stack(stack);
    println!("RIP={:x}, CR2={:x}", rip, cr2);
    vc_terminate_unhandled_vc();
}

fn vc_msr_protocol(request: u64) -> u64 {
    let response: u64;
    let value: u64;

    value = rdmsrl(MSR_AMD64_SEV_ES_GHCB);
    wrmsrl(MSR_AMD64_SEV_ES_GHCB, request);
    vc_vmgexit();
    response = rdmsrl(MSR_AMD64_SEV_ES_GHCB);
    wrmsrl(MSR_AMD64_SEV_ES_GHCB, value);

    response
}

fn vc_establish_protocol() -> u64 {
    let mut response = vc_msr_protocol(GHCB_MSR_SEV_INFO_REQ);

    if GHCB_MSR_INFO!(response) != GHCB_MSR_SEV_INFO_RES {
        vc_terminate_ghcb_general();
    }

    if GHCB_MSR_PROTOCOL_MIN!(response) > GHCB_PROTOCOL_MAX
        || GHCB_MSR_PROTOCOL_MAX!(response) < GHCB_PROTOCOL_MIN
    {
        vc_terminate_ghcb_unsupported_protocol();
    }

    response = vc_msr_protocol(GHCB_MSR_HV_FEATURE_REQ);

    if GHCB_MSR_INFO!(response) != GHCB_MSR_HV_FEATURE_RES {
        vc_terminate_ghcb_general();
    }

    if (GHCB_MSR_HV_FEATURES!(response) & GHCB_SVSM_FEATURES) != GHCB_SVSM_FEATURES {
        vc_terminate_ghcb_feature();
    }

    unsafe {
        HV_FEATURES = GHCB_MSR_HV_FEATURES!(response);
    }

    response
}

thread_local! {
    static THIS_GHCB: std::cell::RefCell<Option<*mut Ghcb>> = std::cell::RefCell::new(None);
}

fn get_mut_ghcb() -> Option<&'static mut Ghcb> {
    THIS_GHCB.with(|ghcb_ref| {
        // 获取并解引用 Option<*mut Ghcb>，然后返回可变引用
        if let Some(ptr) = *ghcb_ref.borrow_mut() {
            unsafe { Some(&mut *ptr) }
        } else {
            None
        }
    })
}

fn get_early_ghcb() -> Option<&'static mut Ghcb> {
    get_mut_ghcb()
}

fn vc_get_ghcb() -> Option<&'static mut Ghcb> {
    get_mut_ghcb()
}

fn vc_set_ghcb(ghcb: *mut Ghcb) {
    THIS_GHCB.with(|this_ghcb| *this_ghcb.borrow_mut() = Some(ghcb));
}

fn vc_perform_vmgexit(ghcb: &mut Ghcb, code: u64, info1: u64, info2: u64) {
    unsafe {
        ghcb.set_version(GHCB_VERSION_1);
        ghcb.set_usage(GHCB_USAGE);

        ghcb.set_sw_exit_code(code);
        ghcb.set_sw_exit_info_1(info1);
        ghcb.set_sw_exit_info_2(info2);

        vc_vmgexit();

        if !ghcb.is_sw_exit_info_1_valid() {
            vc_terminate_vmpl_resp_invalid();
        }

        let info1_new = ghcb.sw_exit_info_1();
        if LOWER_32BITS!(info1_new) != 0 {
            vc_terminate_ghcb_general();
        }
    }
}

fn vc_run_vmpl(vmpl: VMPL) {
    let ghcb = vc_get_ghcb().unwrap();

    vc_perform_vmgexit(ghcb, GHCB_NAE_RUN_VMPL, vmpl as u64, 0);

    ghcb.clear();
}

fn vc_cpuid_vmgexit(leaf: u32, subleaf: u32, eax: &mut u32, ebx: &mut u32, ecx: &mut u32, edx: &mut u32) {
    let ghcb = vc_get_ghcb().unwrap();

    ghcb.set_rax(leaf as u64);
    ghcb.set_rcx(subleaf as u64);
    if leaf == CPUID_EXTENDED_STATE {
        if read_xcr0() & 0x6 != 0 {
            ghcb.set_xcr0(read_xcr0());
        } else {
            ghcb.set_xcr0(1);
        }
    }
    
    vc_perform_vmgexit(ghcb, GHCB_NAE_CPUID, 0, 0);
    
    if !ghcb.is_rax_valid()
    || !ghcb.is_rbx_valid()
    || !ghcb.is_rcx_valid()
    || !ghcb.is_rdx_valid()
    {
        vc_terminate_vmpl_resp_invalid();
    }
    
    unsafe {
        *eax = ghcb.rax() as u32;
        *ebx = ghcb.rbx() as u32;
        *ecx = ghcb.rcx() as u32;
        *edx = ghcb.rdx() as u32;
    }
        
    ghcb.clear();
}

fn vc_outl(port: u16, value: u32) {
    let ghcb = vc_get_ghcb().unwrap();

    let mut ioio = (port as u64) << 16;
    ioio |= IOIO_ADDR_64;
    ioio |= IOIO_SIZE_32;

    ghcb.set_rax(value as u64);
    vc_perform_vmgexit(ghcb, GHCB_NAE_IOIO, ioio, 0);
    ghcb.clear();
}

fn vc_inl(port: u16) -> u32 {
    let ghcb = vc_get_ghcb().unwrap();

    let mut ioio = (port as u64) << 16;
    ioio |= IOIO_ADDR_64;
    ioio |= IOIO_SIZE_32;
    ioio |= IOIO_TYPE_IN;

    ghcb.set_rax(0);
    vc_perform_vmgexit(ghcb, GHCB_NAE_IOIO, ioio, 0);
    
    if !ghcb.is_rax_valid() {
        vc_terminate_vmpl_resp_invalid();
    }
    
    let value = ghcb.rax() as u32;
    ghcb.clear();
    value
}

fn vc_outw(port: u16, value: u16) {
    let ghcb = vc_get_ghcb().unwrap();

    let mut ioio = (port as u64) << 16;
    ioio |= IOIO_ADDR_64;
    ioio |= IOIO_SIZE_16;

    ghcb.set_rax(value as u64);
    vc_perform_vmgexit(ghcb, GHCB_NAE_IOIO, ioio, 0);
    ghcb.clear();
}

fn vc_inw(port: u16) -> u16 {
    let ghcb = vc_get_ghcb().unwrap();

    let mut ioio = (port as u64) << 16;
    ioio |= IOIO_ADDR_64;
    ioio |= IOIO_SIZE_16;
    ioio |= IOIO_TYPE_IN;

    ghcb.set_rax(0);
    vc_perform_vmgexit(ghcb, GHCB_NAE_IOIO, ioio, 0);
    
    if !ghcb.is_rax_valid() {
        vc_terminate_vmpl_resp_invalid();
    }
    
    let value = ghcb.rax() as u16;
    ghcb.clear();
    value
}

fn vc_outb(port: u16, value: u8) {
    let ghcb = vc_get_ghcb().unwrap();

    let mut ioio = (port as u64) << 16;
    ioio |= IOIO_ADDR_64;
    ioio |= IOIO_SIZE_8;

    ghcb.set_rax(value as u64);
    vc_perform_vmgexit(ghcb, GHCB_NAE_IOIO, ioio, 0);
    ghcb.clear();
}

fn vc_inb(port: u16) -> u8 {
    let ghcb = vc_get_ghcb().unwrap();

    let mut ioio = (port as u64) << 16;
    ioio |= IOIO_ADDR_64;
    ioio |= IOIO_SIZE_8;
    ioio |= IOIO_TYPE_IN;

    ghcb.set_rax(0);
    vc_perform_vmgexit(ghcb, GHCB_NAE_IOIO, ioio, 0);

    if !ghcb.is_rax_valid() {
        vc_terminate_vmpl_resp_invalid();
    }

    let value = ghcb.rax() as u8;
    ghcb.clear();
    value
}

fn vc_register_ghcb(pa: PhysAddr) {
    let response = vc_msr_protocol(GHCB_MSR_REGISTER_GHCB!(pa.as_u64()));

    if GHCB_MSR_INFO!(response) != GHCB_MSR_REGISTER_GHCB_RES {
        vc_terminate_vmpl_general();
    }

    if GHCB_MSR_DATA!(response) != pa.as_u64() {
        vc_terminate_vmpl_general();
    }

    wrmsrl(MSR_AMD64_SEV_ES_GHCB, pa.as_u64());
}

#[cfg(feature = "msr_protocol")]
fn vc_snp_page_state_change(pa: PhysAddr, op: u64) {
    let response = vc_msr_protocol(GHCB_MSR_SNP_PSC(pa, op));

    if GHCB_MSR_INFO(response) != GHCB_MSR_SNP_PSC_RES {
        vc_terminate_vmpl_general();
    }

    if GHCB_MSR_SNP_PSC_VAL(response) != pa {
        vc_terminate_vmpl_general();
    }
}

#[cfg(feature = "msr_protocol")]
fn vc_make_page_private(pa: PhysAddr) {
    vc_snp_page_state_change(pa, SNP_PSC_OP_ASSIGN_PRIVATE);
}

#[cfg(feature = "msr_protocol")]
fn vc_make_page_shared(pa: PhysAddr) {
    vc_snp_page_state_change(pa, SNP_PSC_OP_ASSIGN_SHARED);
}

fn pvalidate_psc_entries(op: &mut PscOp, pvalidate_op: u32) {
    let first_entry = op.header.cur_entry as usize;
    let last_entry = op.header.end_entry as usize + 1;

    for i in first_entry..last_entry {
        let gpa = GHCB_PSC_GPA!(op.entries[i].data);
        let size = GHCB_PSC_SIZE!(op.entries[i].data);

        let mut va = pgtable_pa_to_va(PhysAddr::new(gpa));
        let mut ret = pvalidate(va.as_u64(), size, pvalidate_op);
        if ret == PVALIDATE_FAIL_SIZE_MISMATCH && size > 0 {
            let va_end = va + PAGE_2MB_SIZE;

            while va < va_end {
                ret = pvalidate(va.as_u64(), 0, pvalidate_op);
                if ret != 0 {
                    break;
                }

                va += PAGE_SIZE as u64;
            }
        }

        if ret != 0 {
            vc_terminate_vmpl_psc();
        }
    }
}

fn build_psc_entries(op: &mut PscOp, begin: PhysAddr, end: PhysAddr, page_op: u64) {
    let mut pa = begin;
    let mut i = 0;

    while pa < end && i < PSC_ENTRIES {
        if is_aligned(pa, PAGE_2MB_SIZE) && (end - pa) >= PAGE_2MB_SIZE {
            op.entries[i].data = GHCB_2MB_PSC_ENTRY!(pa.as_u64(), page_op);
            pa += PAGE_2MB_SIZE;
        } else {
            op.entries[i].data = GHCB_4KB_PSC_ENTRY!(pa.as_u64(), page_op);
            pa += PAGE_SIZE as u64;
        }
        op.header.end_entry = i as u16;

        i += 1;
    }
}

fn perform_page_state_change(ghcb: &mut Ghcb, begin: PhysAddr, end: PhysAddr, page_op: u64) {
    let mut op = PscOp {
        header: PscOpHeader {
            cur_entry: 0,
            end_entry: 0,
            reserved: 0,
        },
        entries: [PscOpData { data: 0 }; PSC_ENTRIES],
    };

    let mut pa = begin;
    let pa_end = end;

    while pa < pa_end {
        op.header.cur_entry = 0;
        build_psc_entries(&mut op, pa, pa_end, page_op);

        let last_entry = op.header.end_entry;

        if page_op == PSC_SHARED {
            pvalidate_psc_entries(&mut op, RESCIND);
        }

        let size = std::mem::size_of::<PscOpHeader>() + std::mem::size_of::<PscOpData>() * (last_entry as usize + 1);
        // let set_bytes = &op as &mut[u8];
        // let get_bytes = &mut op as &mut[u8];

        unsafe {
            let set_bytes: *const u8 = &op as *const PscOp as *const u8;
            let get_bytes: *mut u8 = &mut op as *mut PscOp as *mut u8;
            ghcb.clear();
            ghcb.set_shared_buffer(set_bytes, size);

            while op.header.cur_entry <= last_entry {
                vc_perform_vmgexit(ghcb, GHCB_NAE_PSC, 0, 0);
                if !ghcb.is_sw_exit_info_2_valid() || ghcb.sw_exit_info_2() != 0 {
                    vc_terminate_vmpl_psc();
                }

                ghcb.shared_buffer(get_bytes, size);
            }

            if page_op == PSC_PRIVATE {
                op.header.cur_entry = 0;
                op.header.end_entry = last_entry;
                pvalidate_psc_entries(&mut op, VALIDATE);
            }
        }

        pa += PAGE_SIZE as u64;
    }
}

fn vc_make_pages_shared(begin: PhysAddr, end: PhysAddr) {
    let ghcb = vc_get_ghcb().unwrap();
    perform_page_state_change(ghcb, begin, end, PSC_SHARED);
}

#[cfg(not(feature = "msr_protocol"))]
fn vc_make_page_shared(frame: PhysAddr) {
    vc_make_pages_shared(frame, frame + PAGE_SIZE as u64);
}

fn vc_make_pages_private(begin: PhysAddr, end: PhysAddr) {
    let ghcb = vc_get_ghcb().unwrap();
    perform_page_state_change(ghcb, begin, end, PSC_PRIVATE);
}

#[cfg(not(feature = "msr_protocol"))]
fn vc_make_page_private(frame: PhysAddr) {
    vc_make_pages_private(frame, frame + PAGE_SIZE as u64);
}

fn vc_early_make_pages_private(begin: PhysAddr, end: PhysAddr) {
    let ghcb = get_early_ghcb().unwrap();
    perform_page_state_change(ghcb, begin, end, PSC_PRIVATE);
}

pub trait WithVC : WithGHCB + WithPageTable {

    fn vc_init(&mut self) -> Result<i32> {
        let ghcb_va = self.map_ghcb().ok_or(Error::LibcError(Errno::ENOMEM))?;

        println!("setup VC");

        let ghcb_pa = pgtable_va_to_pa(VirtAddr::from_ptr(ghcb_va));
        println!("ghcb_pa: {:x}", ghcb_pa);

        vc_establish_protocol();
        vc_register_ghcb(ghcb_pa);
        vc_set_ghcb(ghcb_va);

        self.set_ghcb(VirtAddr::from_ptr(ghcb_va));
        Ok(0)
    }

    fn vc_init_percpu(&mut self) -> Result<i32> {
        let ghcb_va = self.ghcb();
        self.set_ghcb(VirtAddr::new(0));

        let pte: &mut PageTableEntry = pgtable_lookup(ghcb_va);

        let ghcb_pa = pte.addr();
        let mut value = 0;
        value = rdmsrl(MSR_AMD64_SEV_ES_GHCB);

        if value == ghcb_pa.as_u64() {
            self.set_ghcb(ghcb_va);
            return Ok(0);
        }

        vc_register_ghcb(ghcb_pa);
        unsafe {
            pte.set_flags(pte.flags() | PageTableFlags::WRITABLE);
            dune_flush_tlb_one(ghcb_va.as_u64());
        }

        self.set_ghcb(ghcb_va);
        Ok(0)
    }
}