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

pub trait Percpu {

    type SystemType: Device;

    fn create() -> Result<*mut Self>
        where Self: Sized
    {
        let fs_base = get_fs_base()?;
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
                return Err(Error::LibcError(Errno::last()));
            }
            Ok(ret as *mut Self)
        }
    }

    fn free(ptr: *mut Self)
        where Self: Sized
    {
        // XXX free stack
        unsafe { munmap(ptr as *const _ as *mut c_void, PGSIZE as usize) };
    }

    fn prepare(&mut self) -> Result<()>;

    fn map_safe_stack() -> Result<*mut c_void>
        where Self: Sized
    {
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
        Ok(safe_stack as *mut c_void)
    }

    fn setup_safe_stack(&mut self) -> Result<()>;

    fn gdtr(&self) -> Tptr;

    fn idtr(&mut self) -> Tptr;

    fn setup_gdt(&mut self);

    fn system(&self) -> &Arc<Self::SystemType>;

    fn set_system(&mut self, system: &Arc<Self::SystemType>);

    /**
     * dune_boot - Brings the user-level OS online
     * @percpu: the thread-local data
     */
    fn dune_boot(&mut self) -> Result<()>;

    fn do_dune_enter(&mut self) -> Result<()>;

    fn dune_enter_ex(&mut self) -> Result<()>;
}
