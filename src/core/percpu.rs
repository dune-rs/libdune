use std::arch::asm;
use std::ffi::c_void;
use std::sync::Arc;
use std::ptr;
use dune_sys::{Device, DuneConfig, Tptr};
use libc::{mmap, munmap, MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE, PROT_READ, PROT_WRITE};
use nix::errno::Errno;
use x86_64::VirtAddr;
use crate::{dune_die, get_fs_base, globals::*, DUNE_VM, PGSIZE};
use crate::core::*;
use dune_sys::result::{Result, Error};
use std::any::Any;
use std::cell::RefCell;
use std::mem;
use x86_64::structures::DescriptorTablePointer;

pub static GDT_TEMPLATE: [u64; NR_GDT_ENTRIES] = [
    0,
    0,
    SEG64!(SEG_X | SEG_R, 0),
    SEG64!(SEG_W, 0),
    0,
    SEG64!(SEG_W, 3),
    SEG64!(SEG_X | SEG_R, 3),
    0,
    0,
];

const SAFE_STACK_SIZE: usize = PGSIZE;


pub trait Percpu: Any + Send {

    fn as_any(&self) -> &dyn Any;

    fn as_any_mut(&mut self) -> &mut dyn Any;

    fn create() -> Result<*mut Self>
        where Self: Sized
    {
        unsafe {
            let ret = mmap(
                ptr::null_mut(),
                PGSIZE as usize,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            );
            if ret == MAP_FAILED {
                log::error!("dune: failed to mmap percpu");
                return Err(Error::LibcError(Errno::last()));
            }

            Ok(&mut *(ret as *mut Self))
        }
    }

    fn free(ptr: *mut Self)
        where Self: Sized
    {
        log::debug!("free percpu");
        unsafe { munmap(ptr as *const _ as *mut c_void, PGSIZE as usize) };
    }

    fn setup_safe_stack(&mut self, tss: &mut Tss) -> Result<()>
        where Self: Sized
    {
        log::info!("setup safe stack");
        let safe_stack: *mut c_void = unsafe {mmap(
            std::ptr::null_mut(),
            SAFE_STACK_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )};
        if safe_stack == MAP_FAILED {
            return Err(Error::LibcError(Errno::last()));
        }

        let safe_stack = unsafe { safe_stack.add(SAFE_STACK_SIZE) };
                
        // 设置 TSS 的 IOMB
        tss.set_tss_iomb(std::mem::size_of::<Tss>() as u16);

        // 设置所有 IST 入口
        for i in 0..7 {
            tss.set_tss_ist(i, safe_stack as u64);
        }

        // 设置 RSP0
        tss.tss_rsp[0] = safe_stack as u64;

        Ok(())
    }

    fn gdtr(gdt: &[u64]) -> Tptr {
        let mut gdtr = Tptr::default();
        unsafe {
            let gdt_ptr = std::ptr::addr_of!(gdt);
            let size = gdt.len() * mem::size_of::<u64>() - 1;
            gdtr.set_base(gdt_ptr as u64)
                .set_limit(size as u16);
        }
        gdtr
    }

    fn idtr(idt: &[IdtDescriptor]) -> Tptr {
        let mut idtr = Tptr::default();
        idtr.set_base(idt.as_ptr() as u64)
            .set_limit((idt.len() * mem::size_of::<IdtDescriptor>() - 1) as u16);
        idtr
    }

    fn setup_gdt(gdt: &mut [u64], tss: &mut Tss) {
        log::info!("setup gdt");
        
        // 复制 GDT 模板
        gdt.copy_from_slice(&GDT_TEMPLATE);
        
        // 设置 TSS 描述符
        gdt[GD_TSS >> 3] = SEG_TSSA | SEG_P | SEG_A | 
            SEG_BASELO!(tss) | 
            SEG_LIM!(mem::size_of::<Tss>() as u64 - 1);
        gdt[GD_TSS2 >> 3] = SEG_BASEHI!(tss);
    }

    fn init(&mut self) -> Result<()>;

    fn enter(&mut self) -> Result<()>;

    fn boot(&mut self) -> Result<()>;
}

thread_local! {
    pub static LPERCPU: RefCell<Option<Box<dyn Percpu>>> = RefCell::new(None);
}

pub fn get_percpu<T: 'static>() -> Option<&'static mut T> {
    LPERCPU.with(|lpercpu| {
        let percpu = lpercpu.borrow();
        if let Some(p) = percpu.as_ref() {
            if let Some(concrete) = p.as_any().downcast_ref::<T>() {
                Some(unsafe { &mut *(concrete as *const T as *mut T) })
            } else {
                None
            }
        } else {
            None
        }
    })
}

pub fn set_percpu(percpu: Box<dyn Percpu>) {
    LPERCPU.with(|lpercpu| {
        *lpercpu.borrow_mut() = Some(percpu);
    });
}