
use std::arch::x86_64::{_fxsave, _fxrstor, _xsave, _xrstor, _xsaveopt};
use xsave::XSave;

use crate::Percpu;

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
#[derive(Debug, Copy, Clone, Default)]
pub struct XSaveArea {
    xsave: XSave,
}

impl XSaveArea {
    pub fn new() -> Self {
        XSaveArea {
            xsave: XSave::default(),
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

pub trait WithDuneFpu : Percpu {

    fn fpu_init(&self) {
        let fp = self.get_fpu();
        dune_fpu_init(fp);
    }

    fn fpu_load(&self) {
        let fp = self.get_fpu();
        dune_fpu_load(fp);
    }

    fn fpu_save(&self) {
        let fp = self.get_fpu();
        dune_fpu_save(fp);
    }

    fn fpu_save_safe(&self) {
        let fp = self.get_fpu();
        dune_fpu_save_safe(fp);
    }

    fn get_fpu(&self) -> *mut FxSaveArea;
}

pub trait WithVmplFpu : Percpu {

    fn xsave_begin(&self) {
        let xs = self.get_xsaves_area();
        let xsave = &mut (unsafe { *xs }).xsave;
        xsave.save();
    }

    fn xsave_end(&self) {
        let xs = self.get_xsaves_area();
        let xsave = &(unsafe { *xs }).xsave;
        xsave.load();
    }

    fn get_xsaves_area(&self) -> *mut XSaveArea;
}