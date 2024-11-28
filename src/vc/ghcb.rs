/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */
use std::mem::size_of;
use std::mem::offset_of;
use paste::paste;
use x86_64::VirtAddr;
use x86_64::PhysAddr;
use libc::mmap;
use crate::PAGE_SIZE;
use libc::PROT_READ;
use libc::PROT_WRITE;
use libc::MAP_SHARED;
use libc::MAP_FIXED;
use std::ptr::copy_nonoverlapping;
use dune_sys::result::Result;
use dune_sys::Device;
use crate::Percpu;
use libc::MAP_POPULATE;
use libc::MAP_FAILED;
use crate::CreateType;
use crate::mm::pgtable_va_to_pa;

pub const MSR_AMD64_SEV_ES_GHCB: u64 = 0xc0010130;
pub const GHCB_MMAP_BASE: VirtAddr = VirtAddr::new(0);

/// 1
pub const GHCB_VERSION_1: u16 = 1;
/// 0
pub const GHCB_USAGE: u32 = 0;

/// 2032
pub const SHARED_BUFFER_SIZE: usize = 2032;

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct Ghcb {
    reserved1: [u8; 203],
    cpl: u8,
    reserved2: [u8; 300],
    rax: u64,
    reserved3: [u8; 264],
    rcx: u64,
    rdx: u64,
    rbx: u64,
    reserved4: [u8; 112],
    sw_exit_code: u64,
    sw_exit_info_1: u64,
    sw_exit_info_2: u64,
    sw_scratch: u64,
    reserved5: [u8; 56],
    xcr0: u64,
    valid_bitmap: [u8; 16],
    reserved6: [u8; 1024],
    shared_buffer: [u8; SHARED_BUFFER_SIZE],
    reserved7: [u8; 10],
    version: u16,
    usage: u32,
}

#[macro_export]
macro_rules! ghcb_fns {
    ($name: ident) => {
        paste! {
            pub fn [<$name>](&self) -> u64 {
                self.$name
            }
            pub fn [<set_ $name>](&mut self, value: u64) {
                self.$name = value;
                self.set_offset_valid(offset_of!(Ghcb, $name));
            }
            pub fn [<is_ $name _valid>](&self) -> bool {
                self.is_offset_valid(offset_of!(Ghcb, $name))
            }
        }
    };
}

impl Ghcb {
    ghcb_fns!(rax);
    ghcb_fns!(rbx);
    ghcb_fns!(rcx);
    ghcb_fns!(rdx);
    ghcb_fns!(xcr0);
    // ghcb_fns!(cpl);
    ghcb_fns!(sw_exit_code);
    ghcb_fns!(sw_exit_info_1);
    ghcb_fns!(sw_exit_info_2);
    ghcb_fns!(sw_scratch);

    pub fn shared_buffer(&mut self, data: *mut u8, len: usize) {
        assert!(len <= SHARED_BUFFER_SIZE);

        unsafe {
            copy_nonoverlapping(&self.shared_buffer as *const u8, data, len);
        }
    }

    pub fn set_shared_buffer(&mut self, data: *const u8, len: usize) {
        assert!(len <= SHARED_BUFFER_SIZE);

        unsafe {
            copy_nonoverlapping(data, &mut self.shared_buffer as *mut u8, len);
        }

        let va: VirtAddr = VirtAddr::new_truncate(&self.shared_buffer as *const u8 as u64);
        self.set_sw_scratch(pgtable_va_to_pa(va).as_u64());
    }

    pub fn version(&mut self) -> u16 {
        self.version
    }

    pub fn set_version(&mut self, version: u16) {
        self.version = version;
    }

    pub fn usage(&mut self) -> u32 {
        self.usage
    }

    pub fn set_usage(&mut self, usage: u32) {
        self.usage = usage;
    }

    pub fn clear(&mut self) {
        self.sw_exit_code = 0;
        self.valid_bitmap.iter_mut().for_each(|i| *i = 0);
    }

    fn set_offset_valid(&mut self, offset: usize) {
        let idx: usize = (offset / 8) / 8;
        let bit: usize = (offset / 8) % 8;

        self.valid_bitmap[idx] |= BIT!(bit);
    }

    fn is_offset_valid(&self, offset: usize) -> bool {
        let idx: usize = (offset / 8) / 8;
        let bit: usize = (offset / 8) % 8;

        (self.valid_bitmap[idx] & BIT!(bit)) != 0
    }
}

pub trait WithGHCB : Device + Percpu {

    fn ghcb(&self) -> VirtAddr;

    fn set_ghcb(&mut self, ghcb_va: VirtAddr);

    fn map_ghcb(&mut self) -> Option<*mut Ghcb> {
        println!("setup GHCB");
        let dune_fd = self.fd();
        let ghcb = unsafe {
            mmap(
                GHCB_MMAP_BASE.as_ptr::<u64>() as *mut libc::c_void,
                PAGE_SIZE,
                PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_FIXED | MAP_POPULATE,
                dune_fd,
                0,
            )
        };

        if ghcb == MAP_FAILED {
            eprintln!("dune: failed to map GHCB");
            return None;
        }

        let ghcb = ghcb as *mut Ghcb;

        Some(ghcb)
    }

}

#[cfg(feature = "vc")]
pub fn dump_ghcb(ghcb: Option<&mut Ghcb>) {
    if let Some(ghcb) = ghcb {
        log::debug!("GHCB dump:");
        // log::debug!("  cpl: {}", ghcb.cpl());
        log::debug!("  rax: 0x{:x}", ghcb.rax());
        log::debug!("  rcx: 0x{:x}", ghcb.rcx());
        log::debug!("  rdx: 0x{:x}", ghcb.rdx());
        log::debug!("  rbx: 0x{:x}", ghcb.rbx());
        log::debug!("  sw_exit_code: 0x{:x}", ghcb.sw_exit_code());
        log::debug!("  sw_exit_info_1: 0x{:x}", ghcb.sw_exit_info_1());
        log::debug!("  sw_exit_info_2: 0x{:x}", ghcb.sw_exit_info_2());
        log::debug!("  sw_scratch: 0x{:x}", ghcb.sw_scratch());
        log::debug!("  xcr0: 0x{:x}", ghcb.xcr0());
        log::debug!("  version: {}", ghcb.version());
        log::debug!("  usage: {}", ghcb.usage());
    } else {
        log::warn!("GHCB is NULL");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ghcb_size() {
        assert_eq!(size_of::<Ghcb>(), 4096);
    }
}