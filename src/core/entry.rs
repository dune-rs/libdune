use std::io::{self, ErrorKind};
use std::mem;
use std::ops::{BitAnd, Sub, SubAssign};
use std::ptr;
use std::arch::asm;
use std::sync::atomic::{AtomicBool, Ordering};
use dune_sys::funcs;
use libc::{c_void, mmap, munmap, open, O_RDWR, PROT_READ, PROT_WRITE, MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE, sigaction, SIG_IGN, SIGTSTP, SIGSTOP, SIGKILL, SIGCHLD, SIGINT, SIGTERM};
use x86_64::structures::paging::PageTableFlags;
use std::mem::offset_of;
use libc::ioctl;
use libc::{PROT_EXEC, MAP_ANON};
use x86_64::structures::gdt::{GlobalDescriptorTable, Descriptor};
use x86_64::structures::paging::page_table::PageTableEntry;
use x86_64::{PhysAddr,VirtAddr};
use x86_64::registers::model_specific::{FsBase, GsBase};
use dune_sys::dune::{DuneConfig, DuneRetCode,DuneLayout};
use dune_sys::dev::{DuneDevice,DUNE_ENTER,DUNE_GET_SYSCALL,DUNE_GET_LAYOUT,DUNE_TRAP_ENABLE,DUNE_TRAP_DISABLE};

use crate::globals::*;
use crate::mm::*;
use crate::utils::*;
use crate::syscall::*;
use crate::core::*;

// static mut pgroot: *mut PageTableEntry = ptr::null_mut();
// pub static mut phys_limit: UintptrT = 0;
// pub static mut mmap_base: UintptrT = 0;
// pub static mut stack_base: UintptrT = 0;

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
struct DunePercpu {
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

use std::cell::RefCell;

thread_local! {
    static LPERCPU: RefCell<Option<DunePercpu>> = RefCell::new(None);
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

unsafe fn map_ptr(p: *mut c_void, len: usize) {
    // Align the pointer to the page size
    let page = (p as usize & !(PGSIZE - 1)) as *mut c_void;
    let page_end = p.add(len + PGSIZE - 1).mask(!(PGSIZE - 1));
    let len = page_end.sub(page);
    let ptr = page as *mut c_void;
    let pa = dune_va_to_pa(ptr) as *mut c_void;

    dune_vm_map_phys(PGROOT, pg, len, pa, PERM_R | PERM_W);
}

unsafe fn setup_safe_stack(percpu: &mut DunePercpu) -> io::Result<()> {
    let safe_stack = mmap(ptr::null_mut(), PGSIZE, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if safe_stack == MAP_FAILED {
        return Err(io::Error::new(ErrorKind::Other, "Failed to allocate safe stack"));
    }

    map_ptr(safe_stack, PGSIZE);

    let safe_stack = safe_stack.add(PGSIZE);
    percpu.tss.tss_iomb = offset_of!(Tss, tss_iopb) as u16;

    for i in 1..8 {
        percpu.tss.tss_ist[i] = safe_stack as u64;
    }

    percpu.tss.tss_rsp[0] = safe_stack as u64;

    Ok(())
}

fn setup_gdt(percpu: &mut DunePercpu) {
    percpu.gdt.copy_from_slice(&GDT_TEMPLATE);

    percpu.gdt[GD_TSS >> 3] = SEG_TSSA | SEG_P | SEG_A | SEG_BASELO!(&percpu.tss) | SEG_LIM!(mem::size_of::<Tss>() as u64 - 1);
    percpu.gdt[GD_TSS2 >> 3] = SEG_BASEHI!(&percpu.tss);
}

#[repr(C, packed)]
struct Tptr {
    limit: u16,
    base: u64,
}

 /**
  * dune_boot - Brings the user-level OS online
  * @percpu: the thread-local data
  */
unsafe fn dune_boot(_percpu: *mut DunePercpu) {
    let percpu = &mut *_percpu;
    setup_gdt(percpu);

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
    FsBase::write!(VirtAddr::new(percpu.kfs_base));
    GsBase::write!(VirtAddr::new(percpu as *const _ as u64));
}

fn __setup_mappings_cb(ent: &DuneProcmapEntry) {
    let mut perm = PERM_NONE;

    // page region already mapped
    if ent.begin == PAGEBASE.as_u64() {
        return;
    }

    if ent.begin == VSYSCALL_ADDR as u64 {
        setup_vsyscall();
        return;
    }

    if ent.type_ == ProcMapType::Vdso {
        unsafe {
            let pa = dune_va_to_pa(ent.begin as *mut c_void);
            dune_vm_map_phys(
                PGROOT,
                ent.begin as *mut c_void,
                ent.len(),
                pa as *mut c_void,
                PERM_U | PERM_R | PERM_X,
            );
        }
        return;
    }

    if ent.type_ == ProcMapType::Vvar {
        unsafe {
            let pa = dune_va_to_pa(ent.begin as *mut c_void);
            dune_vm_map_phys(
                PGROOT,
                ent.begin as *mut c_void,
                ent.len(),
                pa as *mut c_void,
                PERM_U | PERM_R,
            );
        }
        return;
    }

    if ent.r {
        perm |= PERM_R;
    }
    if ent.w {
        perm |= PERM_W;
    }
    if ent.x {
        perm |= PERM_X;
    }

    let ret = unsafe {
        let pa_start = dune_va_to_pa(ent.begin as *mut c_void);
        dune_vm_map_phys(
            PGROOT,
            ent.begin as *mut c_void,
            ent.len(),
            pa_start as *mut c_void,
            perm,
        )
    };
    assert!(ret == 0);
}

fn __setup_mappings_precise() -> io::Result<()> {
    let ret = unsafe {
        let va_start = PAGEBASE.as_u64() as *mut c_void;
        let len = MAX_PAGES as u64 * PGSIZE;
        let pa_start = dune_va_to_pa(PAGEBASE.as_u64() as *mut c_void) as *mut c_void;
        dune_vm_map_phys(PGROOT, va_start, len, pa_start, PERM_R | PERM_W | PERM_BIG)
    };
    if ret != 0 {
        return Err(io::Error::from_raw_os_error(ret));
    }

    dune_procmap_iterate(__setup_mappings_cb);

    Ok(())
}

fn setup_vdso_cb(ent: &DuneProcmapEntry) {
    let pa = unsafe { dune_va_to_pa(ent.begin as *mut c_void) };
    let perm = match ent.type_ {
        ProcMapType::Vdso => Ok(PERM_U | PERM_R | PERM_X),
        ProcMapType::Vvar => Ok(PERM_U | PERM_R),
        _ => Err(PERM_NONE),
    };

    if let Ok(perm) = perm {
        unsafe {
            dune_vm_map_phys(PGROOT, ent.begin as *mut c_void, ent.len(), pa as *mut c_void, perm);
        }
    }
}

// use dune_sys::dune::DuneLayout;

unsafe fn __setup_mappings_full(layout: &DuneLayout) -> io::Result<()> {
    // Map the entire address space
    let va = 0 as *mut c_void;
    let pa = 0 as *mut c_void;
    let len = 1 << 32; // 4GB
    let perm = PERM_R | PERM_W | PERM_X | PERM_U;
    dune_vm_map_phys(PGROOT, va, len, pa, perm);

    // Map the base_map region
    let va = layout.base_map();
    let pa = dune_mmap_addr_to_pa(va);
    let len = GPA_MAP_SIZE as u64;
    let perm = PERM_R | PERM_W | PERM_X | PERM_U;
    dune_vm_map_phys(PGROOT, va, len, pa, perm);

    // Map the base_stack region
    let va = layout.base_stack();
    let pa = dune_stack_addr_to_pa(va);
    let len = GPA_STACK_SIZE as u64;
    let perm = PERM_R | PERM_W | PERM_X | PERM_U;
    dune_vm_map_phys(PGROOT, layout.base_stack(), len, pa, perm);

    // Map the page table region
    let va = PAGEBASE.as_u64() as *mut c_void;
    let pa = dune_va_to_pa(va);
    let len = MAX_PAGES as u64 * PGSIZE;
    let perm = PERM_R | PERM_W | PERM_BIG;
    dune_vm_map_phys(PGROOT, va, len, pa, perm);

    dune_procmap_iterate(setup_vdso_cb);
    setup_vsyscall();

    Ok(())
}

pub unsafe fn setup_mappings(full: bool) -> io::Result<()> {
    let mut layout: DuneLayout = mem::zeroed();
    let ret = ioctl(DUNE_FD, DUNE_GET_LAYOUT, &mut layout);
    if ret != 0 {
        return Err(io::Error::from_raw_os_error(ret));
    }

    unsafe {
        PHYS_LIMIT = layout.phys_limit();
        MMAP_BASE = layout.base_map();
        STACK_BASE = layout.base_stack();
    }

    if full {
        __setup_mappings_full(&layout)
    } else {
        __setup_mappings_precise()
    }
}

fn create_percpu() -> Option<DunePercpu> {
    let mut fs_base: u64 = 0;
    if unsafe { arch_prctl(ARCH_GET_FS, &mut fs_base as *mut u64 as *mut c_void) } == -1 {
        eprintln!("dune: failed to get FS register");
        return None;
    }

    let percpu = unsafe {
        mmap(
            ptr::null_mut(),
            PGSIZE as usize,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        ) as *mut DunePercpu
    };

    if percpu == MAP_FAILED as *mut DunePercpu {
        return None;
    }

    unsafe { map_ptr(percpu as *mut c_void, mem::size_of::<DunePercpu>()) };

    unsafe {
        (*percpu).kfs_base = fs_base;
        (*percpu).ufs_base = fs_base;
        (*percpu).in_usermode = 0;
    }

    if let Err(_) = unsafe { setup_safe_stack(&mut *percpu) } {
        unsafe { munmap(percpu as *mut c_void, PGSIZE as usize) };
        return None;
    }

    Some(unsafe { ptr::read(percpu) })
}

fn free_percpu(percpu: &DunePercpu) {
    // XXX free stack
    unsafe { munmap(percpu as *const _ as *mut c_void, PGSIZE as usize) };
}

fn map_stack_cb(e: &DuneProcmapEntry) {
    let esp: u64;
    unsafe {
        asm!("mov %rsp, {}", out(reg) esp);
    }

    if esp >= e.begin && esp < e.end {
        unsafe { map_ptr(e.begin as *mut c_void, (e.end - e.begin) as usize) };
    }
}

fn map_stack() {
    dune_procmap_iterate(map_stack_cb);
}

pub type PhysaddrT = u64;

#[no_mangle]
unsafe extern "C" fn do_dune_enter(percpu: &mut DunePercpu) -> io::Result<()> {
    map_stack();

    let mut conf = DuneConfig::default();
    conf.set_vcpu(0)
        .set_rip(&__dune_ret as *const _ as u64)
        .set_rsp(0)
        .set_cr3(PGROOT as u64)
        .set_rflags(0x2);

    // NOTE: We don't setup the general purpose registers because __dune_ret
    // will restore them as they were before the __dune_enter call

    let ret = __dune_enter(DUNE_FD, &conf);
    if ret != 0 {
        println!("dune: entry to Dune mode failed, ret is {}", ret);
        return Err(io::Error::new(ErrorKind::Other, "Entry to Dune mode failed"));
    }

    dune_boot(percpu);

    Ok(())
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

 /**
  * dune_enter - transitions a process to "Dune mode"
  *
  * Can only be called after dune_init().
  *
  * Use this function in each forked child and/or each new thread
  * if you want to re-enter "Dune mode".
  *
  * Returns 0 on success, otherwise failure.
  */
#[no_mangle]
pub unsafe extern "C" fn dune_enter() -> io::Result<()> {
    // Check if this process already entered Dune before a fork...
    LPERCPU.with(|percpu| {
        let mut percpu = percpu.borrow_mut();
        // if not none then enter
        if percpu.is_none() {
            *percpu = create_percpu();
            // if still none, return error
            if let None = *percpu {
                return Err(io::Error::new(ErrorKind::Other, "Failed to create percpu"));
            }
        }

        let percpu = percpu.as_mut().unwrap();
        if let Err(e) = do_dune_enter(percpu) {
            free_percpu(percpu);
            return Err(e);
        } else {
            Ok(())
        }
    });

    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn dune_enter_ex(percpu_ptr: *mut DunePercpu) -> io::Result<()> {
    let mut fs_base: u64 = 0;
    if arch_prctl(ARCH_GET_FS, &mut fs_base) == -1 {
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
  * dune_init - initializes libdune
  *
  * @map_full: determines if the full process address space should be mapped
  *
  * Call this function once before using libdune.
  *
  * Dune supports two memory modes. If map_full is true, then every possible
  * address in the process address space is mapped. Otherwise, only addresses
  * that are used (e.g. set up through mmap) are mapped. Full mapping consumes
  * a lot of memory when enabled, but disabling it incurs slight overhead
  * since pages will occasionally need to be faulted in.
  *
  * Returns 0 on success, otherwise failure.
  */
static DUNE_INITIALIZED: AtomicBool = AtomicBool::new(false);

#[no_mangle]
pub unsafe extern "C" fn dune_init(map_full: bool) -> io::Result<()> {
    if DUNE_INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }

    DUNE_FD = unsafe { open("/dev/dune\0".as_ptr() as *const i8, O_RDWR) };
    if DUNE_FD <= 0 {
        return Err(io::Error::new(ErrorKind::Other, "Failed to open Dune device"));
    }

    PGROOT = unsafe { libc::memalign(PGSIZE, PGSIZE) as *mut PageTableEntry };
    if PGROOT.is_null() {
        unsafe { libc::close(DUNE_FD) };
        return Err(io::Error::new(ErrorKind::Other, "Failed to allocate pgroot"));
    }
    unsafe { ptr::write_bytes(PGROOT, 0, PGSIZE) };

    if dune_page_init().is_err() {
        unsafe { libc::close(DUNE_FD) };
        return Err(io::Error::new(ErrorKind::Other, "Unable to initialize page manager"));
    }

    if setup_mappings(map_full).is_err() {
        unsafe { libc::close(DUNE_FD) };
        return Err(io::Error::new(ErrorKind::Other, "Unable to setup memory layout"));
    }

    if setup_syscall().is_err() {
        unsafe { libc::close(DUNE_FD) };
        return Err(io::Error::new(ErrorKind::Other, "Unable to setup system calls"));
    }

    for i in 1..32 {
        match i {
            SIGTSTP | SIGSTOP | SIGKILL | SIGCHLD | SIGINT | SIGTERM => continue,
            _ => {
                let mut sa: sigaction = unsafe { mem::zeroed() };
                sa.sa_handler = SIG_IGN;
                if unsafe { sigaction(i, &sa, ptr::null_mut()) } == -1 {
                    unsafe { libc::close(DUNE_FD) };
                    return Err(io::Error::new(ErrorKind::Other, format!("sigaction() {}", i)));
                }
            }
        }
    }

    setup_idt();

    DUNE_INITIALIZED.store(true, Ordering::SeqCst);
    Ok(())
}