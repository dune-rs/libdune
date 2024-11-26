use std::sync::Mutex;
use lazy_static::lazy_static;

use dune_sys::{DuneDevice, IdtDescriptor};

use crate::globals::*;

use super::__dune_intr;

lazy_static! {
    pub static ref IDT: Mutex<[IdtDescriptor; IDT_ENTRIES]> = Mutex::new([IdtDescriptor::default(); IDT_ENTRIES]);
}

const ISR_LEN: usize = 16;

pub fn __setup_idt(idt: &mut [IdtDescriptor]) {
    let mut isr = __dune_intr as usize;
    for i in 0..IDT_ENTRIES {
        let id = &mut idt[i];

        id.clear()
            .set_selector(GD_KT as u16)
            .set_type_attr(IDTD_P | IDTD_TRAP_GATE);

        match i {
            T_BRKPT => {
                id.set_type_attr(id.type_attr() | IDTD_CPL3);
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

pub fn setup_idt() {
    lazy_static::initialize(&IDT);
    __setup_idt(&mut *IDT.lock().unwrap());
}

pub trait DuneInterrupt {
    fn setup_idt(&mut self);
}

impl DuneInterrupt for DuneDevice {
    fn setup_idt(&mut self) {
        __setup_idt(self.get_idt_mut());
    }
}