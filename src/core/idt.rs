use std::ptr;
use x86_64::registers::model_specific::GsBase;

use dune_sys::*;
use crate::globals::*;

use super::__dune_intr;
#[repr(packed)]
#[derive(Debug, Copy, Clone, Default)]
pub struct IdtDescriptor {
    low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    middle: u16,
    high: u32,
    zero: u32,
}

impl From<usize> for IdtDescriptor {
    fn from(val: usize) -> Self {
        let mut id = IdtDescriptor::default();
        id.low = (val & 0xFFFF) as u16;
        id.middle = ((val >> 16) & 0xFFFF) as u16;
        id.high = ((val >> 32) & 0xFFFFFFFF) as u32;
        id
    }
}

pub static mut IDT: [IdtDescriptor; IDT_ENTRIES] = [IdtDescriptor::default(); IDT_ENTRIES];

const ISR_LEN: usize = 16;

pub fn setup_idt() {
    for i in 0..IDT_ENTRIES {
        let id = unsafe { &mut IDT[i] };
        let mut isr = __dune_intr as usize;

        isr += ISR_LEN * i;
        ptr::write_bytes(id as *mut IdtDescriptor, 0, 1);

        id.selector = GD_KT as u16;
        id.type_attr = IDTD_P | IDTD_TRAP_GATE;

        match i {
            T_BRKPT => {
                id.type_attr |= IDTD_CPL3;
                id.ist = 1;
            }
            T_DBLFLT | T_NMI | T_MCHK => {
                id.ist = 1;
            }
            _ => {}
        }

        id = isr.into();
    }
}