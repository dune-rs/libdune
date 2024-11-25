
use std::arch::x86_64::{_fxsave, _fxrstor, _xsave, _xrstor, _xsaveopt};

#[repr(C, align(16))]
pub struct FxSaveArea {
    pub fcw: u16,
    pub fsw: u16,
    pub ftw: u8,
    pub reserved1: u8,
    pub fop: u16,
    pub fip: u32,
    pub fcs: u16,
    pub reserved2: u16,
    pub fdp: u32,
    pub fds: u16,
    pub reserved3: u16,
    pub mxcsr: u32,
    pub mxcsr_mask: u32,
    pub st_space: [u32; 32],
    pub xmm_space: [u32; 64],
    pub reserved4: [u32; 24],
}

impl FxSaveArea {
    pub fn new() -> Self {
        FxSaveArea {
            fcw: 0,
            fsw: 0,
            ftw: 0,
            reserved1: 0,
            fop: 0,
            fip: 0,
            fcs: 0,
            reserved2: 0,
            fdp: 0,
            fds: 0,
            reserved3: 0,
            mxcsr: 0,
            mxcsr_mask: 0,
            st_space: [0; 32],
            xmm_space: [0; 64],
            reserved4: [0; 24],
        }
    }

    pub fn save(&mut self) {
        unsafe {
            _fxsave(self as *mut _ as *mut u8);
        }
    }

    pub fn restore(&self) {
        unsafe {
            _fxrstor(self as *const _ as *const u8);
        }
    }
}

#[repr(C, align(64))]
pub struct XSaveArea {
    pub header: [u8; 512],
    pub ymm_space: [u8; 256],
}

impl XSaveArea {
    pub fn new() -> Self {
        XSaveArea {
            header: [0; 512],
            ymm_space: [0; 256],
        }
    }

    pub fn save(&mut self, mask: u64) {
        unsafe {
            _xsave(self as *mut _ as *mut u8, mask);
        }
    }

    pub fn restore(&self, mask: u64) {
        unsafe {
            _xrstor(self as *const _ as *const u8, mask);
        }
    }

    pub fn save_opt(&mut self, mask: u64) {
        unsafe {
            _xsaveopt(self as *mut _ as *mut u8, mask);
        }
    }
}

pub fn dune_fpu_init(fp: *mut FxSaveArea) {
    unsafe {
        *fp = FxSaveArea::new();
        (*fp).fcw = 0x37f;
        (*fp).mxcsr = 0x1f80;
    }
}

pub fn dune_fpu_load(fp: *const FxSaveArea) {
    unsafe {
        (*fp).restore();
    }
}

pub fn dune_fpu_save(fp: *mut FxSaveArea) {
    unsafe {
        (*fp).save();
    }
}

pub fn dune_fpu_save_safe(fp: *mut FxSaveArea) {
    unsafe {
        (*fp).save();
    }
}
