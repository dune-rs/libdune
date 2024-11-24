use std::{arch::asm, mem::offset_of};
use x86_64::registers::model_specific::{FsBase, GsBase};
use dune_sys::dune::{DuneConfig, DuneRetCode};
use dune_sys::funcs;
use crate::globals::*;
use crate::core::*;
use super::arch_prctl;

pub type PhysaddrT = u64;

#[repr(C, packed)]
struct Tptr {
    limit: u16,
    base: u64,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
struct Tss {
    reserved0: u32,
    tss_rsp: [u64; 3], // Stack pointer for CPL 0, 1, 2
    reserved1: u64,
    tss_ist: [u64; 7], // Note: tss_ist[0] is ignored
    reserved2: u64,
    reserved3: u16,
    tss_iomb: u16, // I/O map base
    tss_iopb: [u8; 0],
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct DunePercpu {
    percpu_ptr: u64,
    tmp: u64,
    kfs_base: u64,
    ufs_base: u64,
    in_usermode: u64,
    tss: Tss,
    gdt: [u64; NR_GDT_ENTRIES],
}

impl DunePercpu {
    funcs!(percpu_ptr, u64);
    funcs!(tmp, u64);
    funcs!(kfs_base, u64);
    funcs!(ufs_base, u64);
    funcs!(in_usermode, u64);
}

pub trait DuneHook {
    fn pre_enter(&self, percpu: &mut DunePercpu) -> io::Result<()>;
    fn post_exit(&self, percpu: &mut DunePercpu) -> io::Result<()>;
}

// dune-spesicifc routines
impl DuneHook for DunePercpu {
    fn pre_enter(&self, _percpu: &mut DunePercpu) -> io::Result<()> {
        let safe_stack= _percpu.tss.tss_rsp[0] as *mut c_void;
        unsafe { map_ptr(safe_stack, PGSIZE as usize) };

        setup_gdt(_percpu);
        Ok(())
    }

    fn post_exit(&self, _percpu: &mut DunePercpu) -> io::Result<()> {
        dune_boot(percpu);
        Ok(())
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

fn setup_gdt(percpu: &mut DunePercpu) {
    percpu.gdt.copy_from_slice(&GDT_TEMPLATE);

    percpu.gdt[GD_TSS >> 3] = SEG_TSSA | SEG_P | SEG_A | SEG_BASELO!(&percpu.tss) | SEG_LIM!(mem::size_of::<Tss>() as u64 - 1);
    percpu.gdt[GD_TSS2 >> 3] = SEG_BASEHI!(&percpu.tss);
}

fn setup_safe_stack(percpu: &mut DunePercpu) -> io::Result<()> {
    let safe_stack = mmap(ptr::null_mut(), PGSIZE, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if safe_stack == MAP_FAILED {
        return Err(io::Error::new(ErrorKind::Other, "Failed to allocate safe stack"));
    }

    let safe_stack: u64 = unsafe { safe_stack.add(PGSIZE) };
    percpu.tss.tss_iomb = offset_of!(Tss, tss_iopb) as u16;

    for i in 1..8 {
        percpu.tss.tss_ist[i] = safe_stack as u64;
    }

    percpu.tss.tss_rsp[0] = safe_stack as u64;

    Ok(())
}

fn create_percpu() -> Option<DunePercpu> {
    let mut fs_base: u64 = 0;
    if unsafe { arch_prctl(ARCH_GET_FS, &mut fs_base as *mut u64 as *mut c_void) } == -1 {
        eprintln!("dune: failed to get FS register");
        return None;
    }

    use libc::{mmap, PROT_READ, PROT_WRITE, MAP_PRIVATE, MAP_ANONYMOUS, munmap, c_void, MAP_FAILED};
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
            .set_in_usermode(0);
        if let Err(e) = setup_safe_stack(percpu) {
            eprintln!("dune: failed to setup safe stack: {}", e);
            return None;
        }

        Some(ptr::read(percpu))
    })
}

fn free_percpu(percpu: &DunePercpu) {
    // XXX free stack
    unsafe { munmap(percpu as *const _ as *mut c_void, PGSIZE as usize) };
}

/**
 * dune_boot - Brings the user-level OS online
 * @percpu: the thread-local data
 */
fn dune_boot(percpu: &mut DunePercpu) {
    let gdtr = Tptr {
        base: percpu.gdt.as_ptr() as u64,
        limit: (percpu.gdt.len() * mem::size_of::<u64>() - 1) as u16,
    };

    let idtr = Tptr {
        base: IDT.as_ptr() as u64,
        limit: (IDT.len() * mem::size_of::<IdtDescriptor>() - 1) as u16,
    };

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

    // STEP 6: FS and GS require special initialization on 64-bit
    FsBase::write(VirtAddr::new(percpu.kfs_base));
    GsBase::write(VirtAddr::new(percpu as *const _ as u64));
}

#[no_mangle]
pub unsafe extern "C" fn do_dune_enter(percpu: &mut DunePercpu) -> io::Result<()> {
    map_stack();

    let mut conf = DuneConfig::default();
    conf.set_vcpu(0)
        .set_rip(&__dune_ret as *const _ as u64)
        .set_rsp(0)
        .set_cr3(PGROOT as u64)
        .set_rflags(0x2);

    percpu.pre_enter(percpu)?;
    // NOTE: We don't setup the general purpose registers because __dune_ret
    // will restore them as they were before the __dune_enter call

    let ret = __dune_enter(DUNE_FD, &conf);
    if ret != 0 {
        println!("dune: entry to Dune mode failed, ret is {}", ret);
        return Err(io::Error::new(ErrorKind::Other, "Entry to Dune mode failed"));
    }

    percpu.post_exit(percpu)?;

    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn dune_enter_ex(percpu_ptr: *mut DunePercpu) -> io::Result<()> {
    let mut fs_base: u64 = 0;
    if arch_prctl(ARCH_GET_FS, &mut fs_base as *mut u64 as *mut c_void) == -1 {
        return Err(io::Error::new(ErrorKind::Other, "Failed to get FS register"));
    }

    let percpu = &mut *percpu_ptr;
    percpu.set_kfs_base(fs_base)
        .set_ufs_base(fs_base)
        .set_in_usermode(0);

    if let Err(e) = setup_safe_stack(percpu) {
        return Err(e);
    }

    do_dune_enter(percpu)
}

 /**
  * on_dune_exit - handle Dune exits
  *
  * This function must not return. It can either exit(), __dune_go_dune() or
  * __dune_go_linux().
  */
#[no_mangle]
pub unsafe extern "C" fn on_dune_exit(conf_: *mut DuneConfig) -> ! {
    let conf = unsafe { &*conf_ };
    let ret: DuneRetCode = conf.ret().into();
    match ret {
        DuneRetCode::Exit => {
            unsafe { libc::syscall(libc::SYS_exit, conf.status()) };
        },
        DuneRetCode::EptViolation => {
            println!("dune: exit due to EPT violation");
        },
        DuneRetCode::Interrupt => {
            dune_debug_handle_int(conf_);
            println!("dune: exit due to interrupt {}", conf.status());
        },
        DuneRetCode::Signal => {
            __dune_go_dune(DUNE_FD, conf_);
        },
        DuneRetCode::UnhandledVmexit => {
            println!("dune: exit due to unhandled VM exit");
        },
        DuneRetCode::NoEnter => {
            println!("dune: re-entry to Dune mode failed, status is {}", conf.status());
        },
        _ => {
            println!("dune: unknown exit from Dune, ret={}, status={}", conf.ret(), conf.status());
        },
    }

    std::process::exit(libc::EXIT_FAILURE);
}
