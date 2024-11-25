use std::sync::Mutex;
use lazy_static::lazy_static;

use dune_sys::funcs;

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

impl IdtDescriptor {
    funcs!(low, u16);
    funcs!(selector, u16);
    funcs!(ist, u8);
    funcs!(type_attr, u8);
    funcs!(middle, u16);
    funcs!(high, u32);
    funcs!(zero, u32);

    pub fn new() -> Self {
        IdtDescriptor::default()
    }

    pub fn clear(&mut self) -> &mut Self {
        self.low = 0;
        self.selector = 0;
        self.ist = 0;
        self.type_attr = 0;
        self.middle = 0;
        self.high = 0;
        self.zero = 0;
        self
    }

    pub fn set_idt_addr(&mut self, addr: usize) -> &mut Self {
        self.low = (addr & 0xFFFF) as u16;
        self.middle = ((addr >> 16) & 0xFFFF) as u16;
        self.high = ((addr >> 32) & 0xFFFFFFFF) as u32;
        self
    }
}

lazy_static! {
    pub static ref IDT: Mutex<[IdtDescriptor; IDT_ENTRIES]> = Mutex::new([IdtDescriptor::default(); IDT_ENTRIES]);
}

const ISR_LEN: usize = 16;

pub fn setup_idt() {
    let mut isr = __dune_intr as usize;
    lazy_static::initialize(&IDT);
    for i in 0..IDT_ENTRIES {
        let mut idt = IDT.lock().unwrap();
        let id = &mut idt[i];

        id.clear()
            .set_selector(GD_KT as u16)
            .set_type_attr(IDTD_P | IDTD_TRAP_GATE);

        match i {
            T_BRKPT => {
                id.type_attr |= IDTD_CPL3;
                id.set_ist(1);
            }
            T_DBLFLT | T_NMI | T_MCHK => {
                id.set_ist(1);
            }
            _ => {}
        }

        id.set_idt_addr(isr);
        isr += ISR_LEN;
    }
}