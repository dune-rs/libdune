use std::sync::atomic::{AtomicBool, Ordering};
use std::ptr;

/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */


const TTYS0: u16 = 0x3f8;
const DIV_BASE: u32 = 115200;
const DLAB_BIT: u8 = 1 << 7;

const IER: u16 = 1;
const FCR: u16 = 2;
const LCR: u16 = 3;
const MCR: u16 = 4;

const DLL: u16 = 0;
const DLM: u16 = 1;

static PORT: u16 = TTYS0;
static SERIAL_READY: AtomicBool = AtomicBool::new(false);

fn vc_outb(port: u16, value: u8) {
    unsafe {
        ptr::write_volatile(port as *mut u8, value);
    }
}

fn vc_inb(port: u16) -> u8 {
    unsafe {
        ptr::read_volatile(port as *mut u8)
    }
}

pub fn serial_out(string: &str) {
    if !SERIAL_READY.load(Ordering::SeqCst) {
        return;
    }

    for &byte in string.as_bytes() {
        vc_outb(PORT, byte);
    }
}

pub fn serial_in(buffer: &mut String) {
    if !SERIAL_READY.load(Ordering::SeqCst) {
        return;
    }

    loop {
        let byte = vc_inb(PORT);
        buffer.push(byte as char);

        if byte == b'\n' {
            break;
        }
    }
}

#[cfg(feature = "serial")]
pub fn serial_init() {
    vc_outb(PORT + IER, 0); // Disable all interrupts
    vc_outb(PORT + FCR, 0); // Disable all FIFOs
    vc_outb(PORT + LCR, 3); // 8n1
    vc_outb(PORT + MCR, 3); // DTR and RTS

    let div = (DIV_BASE / 115200) as u16;
    let div_lo = (div & 0xFF) as u8;
    let div_hi = (div >> 8) as u8;

    let c = vc_inb(PORT + LCR);
    vc_outb(PORT + LCR, c | DLAB_BIT);
    vc_outb(PORT + DLL, div_lo);
    vc_outb(PORT + DLM, div_hi);
    vc_outb(PORT + LCR, c);

    SERIAL_READY.store(true, Ordering::SeqCst);
}