use std::ffi::c_void;
use std::io::ErrorKind;
use std::{io, mem, ptr};
use std::{arch::asm, mem::offset_of};
use libc::{mmap, PROT_READ, PROT_WRITE, MAP_PRIVATE, MAP_ANONYMOUS, munmap, MAP_FAILED};
use x86_64::registers::model_specific::{FsBase, GsBase};
use dune_sys::dune::DuneConfig;
use dune_sys::{funcs, funcs_vec};
use x86_64::VirtAddr;
use crate::{globals::*, PGSIZE};
use crate::core::*;
use super::arch_prctl;

pub type PhysaddrT = u64;

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
struct Tptr {
    limit: u16,
    base: u64,
}

impl Tptr {
    funcs!(limit, u16);
    funcs!(base, u64);
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
struct Tss {
    reserved0: u32,
    pub tss_rsp: [u64; 3], // Stack pointer for CPL 0, 1, 2
    reserved1: u64,
    tss_ist: [u64; 7], // Note: tss_ist[0] is ignored
    reserved2: u64,
    reserved3: u16,
    tss_iomb: u16, // I/O map base
    tss_iopb: [u8; 0],
}



impl Tss {

    funcs!(tss_iomb, u16);
    funcs_vec!(tss_rsp, u64);
    funcs_vec!(tss_ist, u64);
}

static GDT_TEMPLATE: [u64; NR_GDT_ENTRIES] = [
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

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct DunePercpu {
    percpu_ptr: u64,
    tmp: u64,
    kfs_base: u64,
    ufs_base: u64,
    in_usermode: u64,
    pub tss: Tss,
    gdt: [u64; NR_GDT_ENTRIES],
}

impl DunePercpu {
    funcs!(percpu_ptr, u64);
    funcs!(tmp, u64);
    funcs!(kfs_base, u64);
    funcs!(ufs_base, u64);
    funcs!(in_usermode, u64);
    funcs_vec!(gdt, u64);

    pub fn create() -> Option<DunePercpu> {
        let mut fs_base: u64 = 0;
        if unsafe { arch_prctl(ARCH_GET_FS, &mut fs_base as *mut u64 as *mut c_void) } == -1 {
            eprintln!("dune: failed to get FS register");
            return None;
        }

        let percpu = unsafe {
            let ret = mmap(
                ptr::null_mut(),
                PGSIZE as usize,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            );
            if ret == MAP_FAILED {
                None
            } else {
                Some(ret)
            }
        };
        percpu.and_then(|ret| {
            let percpu_ptr = ret as *mut DunePercpu;
            let percpu = unsafe { &mut *percpu_ptr };
            percpu.set_kfs_base(fs_base)
                .set_ufs_base(fs_base)
                .set_in_usermode(0)
                .setup_safe_stack()
                .ok()?;

            Some(unsafe { ptr::read(percpu) })
        })
    }

    pub fn free(&self) {
        // XXX free stack
        unsafe { munmap(self as *const _ as *mut c_void, PGSIZE as usize) };
    }

    fn setup_gdt(&mut self) {
        self.gdt = GDT_TEMPLATE;
        self.gdt[GD_TSS >> 3] = SEG_TSSA | SEG_P | SEG_A | SEG_BASELO!(&self.tss) | SEG_LIM!(mem::size_of::<Tss>() as u64 - 1);
        self.gdt[GD_TSS2 >> 3] = SEG_BASEHI!(&self.tss);
    }

    fn setup_safe_stack(&mut self) -> io::Result<()> {
        let safe_stack = unsafe { mmap(ptr::null_mut(), PGSIZE, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) };
        if safe_stack == MAP_FAILED {
            return Err(io::Error::new(ErrorKind::Other, "Failed to allocate safe stack"));
        }

        let safe_stack = unsafe { safe_stack.add(PGSIZE) };
        self.tss.set_tss_iomb(offset_of!(Tss, tss_iopb) as u16);

        for i in 1..8 {
            self.tss.tss_ist[i] = safe_stack as u64;
        }

        self.tss.tss_rsp[0] = safe_stack as u64;

        Ok(())
    }

    /**
     * dune_boot - Brings the user-level OS online
     * @percpu: the thread-local data
     */
    fn dune_boot(&self) {
        let mut gdtr = Tptr::default();
        gdtr.set_base(self.gdt.as_ptr() as u64)
            .set_limit((self.gdt.len() * mem::size_of::<u64>() - 1) as u16);

        let idt = IDT.lock().unwrap();
        let mut idtr = Tptr::default();
        idtr.set_base(idt.as_ptr() as u64)
            .set_limit((idt.len() * mem::size_of::<IdtDescriptor>() - 1) as u16);

        unsafe {
            asm!(
                // STEP 1: load the new GDT
                "lgdt [{0}]",
                // STEP 2: initialize data segments
                "mov {1:x}, %ax",
                "mov %ax, %ds",
                "mov %ax, %es",
                "mov %ax, %ss",
                // STEP 3: long jump into the new code segment
                "mov {2:x}, %rax",
                "pushq %rax",
                "pushq $1f",
                "lretq",
                "1:",
                "nop",
                // STEP 4: load the task register (for safe stack switching)
                "mov {3:x}, %ax",
                "ltr %ax",
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

        // STEP 6: FS and GS require special initialization on 64-bit
        FsBase::write(VirtAddr::new(self.kfs_base));
        GsBase::write(VirtAddr::new(self as *const _ as u64));
    }
}

pub fn dune_get_user_fs() -> u64 {
    let ptr: u64;
    unsafe {
        asm!(
            "movq %gs:{ufs_base}, {ptr}",
            ufs_base = const offset_of!(DunePercpu, ufs_base),
            ptr = out(reg) ptr,
            options(nostack, preserves_flags)
        );
    }
    ptr
}

pub fn dune_set_user_fs(fs_base: u64) {
    unsafe {
        asm!(
            "movq {fs_base}, %gs:{ufs_base}",
            fs_base = in(reg) fs_base,
            ufs_base = const offset_of!(DunePercpu, ufs_base),
            options(nostack, preserves_flags)
        );
    }
}

pub unsafe fn do_dune_enter(percpu: &mut DunePercpu) -> io::Result<()> {
    let root = &mut *PGROOT.lock().unwrap();
    let mut conf = DuneConfig::default();
    conf.set_vcpu(0)
        .set_rip(&__dune_ret as *const _ as u64)
        .set_rsp(0)
        .set_cr3(root as *const _ as u64)
        .set_rflags(0x2);

    percpu.setup_gdt();
    // percpu.pre_enter(percpu)?;
    // NOTE: We don't setup the general purpose registers because __dune_ret
    // will restore them as they were before the __dune_enter call

    let ret = __dune_enter(DUNE_FD, &conf);
    if ret != 0 {
        println!("dune: entry to Dune mode failed, ret is {}", ret);
        return Err(io::Error::new(ErrorKind::Other, "Entry to Dune mode failed"));
    }

    // percpu.post_exit(percpu)?;

    Ok(())
}

pub unsafe fn dune_enter_ex(percpu_ptr: *mut DunePercpu) -> io::Result<()> {
    let mut fs_base: u64 = 0;
    if arch_prctl(ARCH_GET_FS, &mut fs_base as *mut u64 as *mut c_void) == -1 {
        return Err(io::Error::new(ErrorKind::Other, "Failed to get FS register"));
    }

    let percpu = &mut *percpu_ptr;
    percpu.set_kfs_base(fs_base)
        .set_ufs_base(fs_base)
        .set_in_usermode(0)
        .setup_safe_stack()?;

    do_dune_enter(percpu)
}