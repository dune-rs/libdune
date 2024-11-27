use std::arch::asm;
use std::ffi::c_void;
use std::sync::Arc;
use std::ptr;
use dune_sys::{Device, DuneConfig, Tptr};
use libc::{mmap, PROT_READ, PROT_WRITE, MAP_PRIVATE, MAP_ANONYMOUS, MAP_FAILED};
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

pub trait Percpu {

    type SelfType: Percpu;
    type SystemType: Device;

    fn map_ptr(&self, ret: *mut Self::SelfType) -> Result<()> {
        let ptr = VirtAddr::from_ptr(ret);
        let ret = map_ptr(ptr, size_of::<Self::SelfType>());
        if ret.is_err() {
            return ret;
        }

        Ok(())
    }

    fn create() -> Result<*mut Self::SelfType> {
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
            Ok(ret as *mut Self::SelfType)
        }
    }

    fn prepare(&mut self) -> Result<()>;

    fn map_safe_stack<T>(&mut self) -> Result<*mut T> {
        let safe_stack: *mut c_void = unsafe { mmap(ptr::null_mut(), PGSIZE, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) };
        if safe_stack == MAP_FAILED {
            return Err(Error::LibcError(Errno::last()));
        }

        let safe_stack = unsafe { safe_stack.add(PGSIZE) };
        Ok(safe_stack as *mut T)
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
    fn dune_boot(&mut self) -> Result<()> {
        self.setup_gdt();
        let gdtr = self.gdtr();
        let idtr = self.idtr();

        unsafe {
            asm!(
                // STEP 1: load the new GDT
                "lgdt [{0}]",
                // STEP 2: initialize data segments
                "mov ax, {1:x}",
                "mov ds, ax",
                "mov es, ax",
                "mov ss, ax",
                // STEP 3: long jump into the new code segment
                "mov rax, {2}",
                "push rax",
                "push 2f",
                "retfq",
                "2:",
                "nop",
                // STEP 4: load the task register (for safe stack switching)
                "mov ax, {3:x}",
                "ltr ax",
                // STEP 5: load the new IDT and enable interrupts
                "lidt [{4}]",
                "sti",
                in(reg) &gdtr,
                in(reg) GD_KD,
                in(reg) GD_KT,
                in(reg) GD_TSS,
                in(reg) &idtr
            );
        }

        self.post_dune_boot();

        Ok(())
    }

    fn post_dune_boot(&mut self);

    fn do_dune_enter(&mut self) -> Result<()> {
        let mut dune_vm = DUNE_VM.lock().unwrap();
        let root = dune_vm.get_mut_root();

        // map the stack into the Dune address space
        let _ = map_stack();

        let mut conf = DuneConfig::default();
        conf.set_vcpu(0)
            .set_rip(&__dune_ret as *const _ as u64)
            .set_rsp(0)
            .set_cr3(root as *const _ as u64)
            .set_rflags(0x2);

        // NOTE: We don't setup the general purpose registers because __dune_ret
        // will restore them as they were before the __dune_enter call

        let dune_fd = self.system().fd();
        let ret = unsafe { __dune_enter(dune_fd, &conf) };
        if ret != 0 {
            println!("dune: entry to Dune mode failed, ret is {}", ret);
            return Err(Error::Unknown);
        }

        self.dune_boot().map_err(|e|{
            println!("dune: failed to boot Dune mode: {:?}", e);
            unsafe { dune_die() };
            e
        })
    }

    fn dune_enter_ex(&mut self) -> Result<()> {
        self.prepare()?;
        self.do_dune_enter()
    }
}
