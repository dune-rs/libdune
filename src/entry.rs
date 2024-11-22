use std::io::{self, ErrorKind};
use std::mem;
use std::ptr;
use std::arch::asm;
use std::sync::atomic::{AtomicBool, Ordering};
use libc::{c_void, mmap, munmap, open, O_RDWR, PROT_READ, PROT_WRITE, MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE, sigaction, SIG_IGN, SIGTSTP, SIGSTOP, SIGKILL, SIGCHLD, SIGINT, SIGTERM};
use std::mem::offset_of;
use libc::ioctl;
// use PROT_EXEC, MAP_ANON, DUNE_GET_SYSCALL
use libc::{PROT_EXEC, MAP_ANON};

use crate::globals::*;
use crate::page::*;
use crate::procmaps::*;
use crate::dune::*;
use crate::debug::*;
use crate::util::*;
use crate::vm::*;
// use crate::{phys_limit,mmap_base,stack_base};

// static mut pgroot: *mut PteEntry = ptr::null_mut();
// pub static mut phys_limit: UintptrT = 0;
// pub static mut mmap_base: UintptrT = 0;
// pub static mut stack_base: UintptrT = 0;

#[repr(packed)]
#[derive(Debug, Copy, Clone, Default)]
struct IdtDescriptor {
    low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    middle: u16,
    high: u32,
    zero: u32,
}

static mut idt: [IdtDescriptor; IDT_ENTRIES] = [IdtDescriptor::default(); IDT_ENTRIES];

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

thread_local! {
    static lpercpu: std::cell::RefCell<Option<DunePercpu>> = std::cell::RefCell::new(None);
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

fn map_ptr(p: *mut c_void, len: usize) {
    let page = p as usize & !(PGSIZE - 1);
    let page_end = (p as usize + len + PGSIZE - 1) & !(PGSIZE - 1);
    let l = page_end - page;
    let pg = page as *mut c_void;

    unsafe {
        dune_vm_map_phys(pgroot, pg, l, dune_va_to_pa(pg) as *mut c_void, PERM_R | PERM_W);
    }
}

fn setup_safe_stack(percpu: &mut DunePercpu) -> io::Result<()> {
    let safe_stack = unsafe {
        mmap(
            ptr::null_mut(),
            PGSIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };

    if safe_stack == MAP_FAILED {
        return Err(io::Error::new(ErrorKind::Other, "Failed to allocate safe stack"));
    }

    map_ptr(safe_stack, PGSIZE);

    let safe_stack = unsafe { safe_stack.add(PGSIZE) };
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
fn dune_boot(percpu: &mut DunePercpu) -> io::Result<()> {
    setup_gdt(percpu);

    let gdtr = Tptr {
        base: percpu.gdt.as_ptr() as u64,
        limit: (percpu.gdt.len() * mem::size_of::<u64>() - 1) as u16,
    };

    let idtr = Tptr {
        base: idt.as_ptr() as u64,
        limit: (idt.len() * mem::size_of::<IdtDescriptor>() - 1) as u16,
    };

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
    unsafe {
        wrmsrl(MSR_FS_BASE, percpu.kfs_base);
        wrmsrl(MSR_GS_BASE, percpu as *const _ as u64);
    }

    Ok(())
}
 
const ISR_LEN: usize = 16;

fn set_idt_addr(id: &mut IdtDescriptor, addr: u64) {
    id.low = (addr & 0xFFFF) as u16;
    id.middle = ((addr >> 16) & 0xFFFF) as u16;
    id.high = ((addr >> 32) & 0xFFFFFFFF) as u32;
}

fn setup_idt() {
    for i in 0..IDT_ENTRIES {
        let id = &mut idt[i];
        let mut isr = __dune_intr as usize;

        isr += ISR_LEN * i;
        unsafe { ptr::write_bytes(id as *mut IdtDescriptor, 0, 1) };

        id.selector = GD_KT;
        id.type_attr = IDTD_P | IDTD_TRAP_GATE;

        match i {
            T_BRKPT => {
                id.type_attr |= IDTD_CPL3;
                // fallthrough
            }
            T_DBLFLT | T_NMI | T_MCHK => {
                id.ist = 1;
            }
            _ => {}
        }

        set_idt_addr(id, isr as u64);
    }
}

fn setup_syscall() -> io::Result<()> {
    let lstar = unsafe { ioctl(dune_fd, DUNE_GET_SYSCALL) };
    if lstar == -1 {
        return Err(io::Error::last_os_error());
    }

    let page = unsafe {
        mmap(
            ptr::null_mut(),
            PGSIZE * 2,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_ANON,
            -1,
            0,
        )
    };

    if page == MAP_FAILED {
        return Err(io::Error::last_os_error());
    }

    let lstara = lstar & !(PGSIZE as u64 - 1);
    let off = lstar - lstara;

    unsafe {
        ptr::copy_nonoverlapping(
            __dune_syscall as *const u8,
            (page as *mut u8).add(off as usize),
            __dune_syscall_end as usize - __dune_syscall as usize,
        );
    }

    for i in (0..=PGSIZE).step_by(PGSIZE) {
        let pa = dune_mmap_addr_to_pa(unsafe { page.add(i) });
        let mut pte: *mut PteEntry = ptr::null_mut();
        unsafe {
            dune_vm_lookup(pgroot, (lstara + i as u64) as *mut c_void, 1, &mut pte);
            *pte = PTE_ADDR!(pa) | PTE_P;
        }
    }

    Ok(())
}

const VSYSCALL_ADDR: u64 = 0xffffffffff600000;
 
fn setup_vsyscall() {
    let mut pte: *mut PteEntry = ptr::null_mut();
    unsafe {
        dune_vm_lookup(pgroot, VSYSCALL_ADDR as *mut c_void, 1, &mut pte);
        *pte = PTE_ADDR!(dune_va_to_pa(&__dune_vsyscall_page as *const _ as *mut c_void)) | PTE_P | PTE_U;
    }
}

fn __setup_mappings_cb(ent: &DuneProcmapEntry) {
    let mut perm = PERM_NONE;

    // page region already mapped
    if ent.begin == PAGEBASE as u64 {
        return;
    }

    if ent.begin == VSYSCALL_ADDR as u64 {
        setup_vsyscall();
        return;
    }

    if ent.type_ == ProcMapType::Vdso {
        unsafe {
            dune_vm_map_phys(
                pgroot,
                ent.begin as *mut c_void,
                (ent.end - ent.begin) as usize,
                dune_va_to_pa(ent.begin as *mut c_void),
                PERM_U | PERM_R | PERM_X,
            );
        }
        return;
    }

    if ent.type_ == ProcMapType::Vvar {
        unsafe {
            dune_vm_map_phys(
                pgroot,
                ent.begin as *mut c_void,
                (ent.end - ent.begin) as usize,
                dune_va_to_pa(ent.begin as *mut c_void),
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
        dune_vm_map_phys(
            pgroot,
            ent.begin as *mut c_void,
            (ent.end - ent.begin) as usize,
            dune_va_to_pa(ent.begin as *mut c_void),
            perm,
        )
    };
    assert!(ret == 0);
}

fn __setup_mappings_precise() -> io::Result<()> {
    let ret = unsafe {
        dune_vm_map_phys(
            pgroot,
            PAGEBASE as *mut c_void,
            MAX_PAGES * PGSIZE,
            dune_va_to_pa(PAGEBASE as *mut c_void),
            PERM_R | PERM_W | PERM_BIG,
        )
    };
    if ret != 0 {
        return Err(io::Error::from_raw_os_error(ret));
    }

    dune_procmap_iterate(__setup_mappings_cb);

    Ok(())
}

fn setup_vdso_cb(ent: &DuneProcmapEntry) {
    if ent.type_ == ProcMapType::Vdso {
        unsafe {
            dune_vm_map_phys(
                pgroot,
                ent.begin as *mut c_void,
                (ent.end - ent.begin) as usize,
                dune_va_to_pa(ent.begin as *mut c_void),
                PERM_U | PERM_R | PERM_X,
            );
        }
        return;
    }

    if ent.type_ == ProcMapType::Vvar {
        unsafe {
            dune_vm_map_phys(
                pgroot,
                ent.begin as *mut c_void,
                (ent.end - ent.begin) as usize,
                dune_va_to_pa(ent.begin as *mut c_void),
                PERM_U | PERM_R,
            );
        }
        return;
    }
}
 
fn __setup_mappings_full(layout: &DuneLayout) -> io::Result<()> {
    dune_vm_map_phys(pgroot, 0 as *mut c_void, 1 << 32, 0 as *mut c_void, PERM_R | PERM_W | PERM_X | PERM_U)?;

    dune_vm_map_phys(pgroot, layout.base_map() as *mut c_void, GPA_MAP_SIZE, dune_mmap_addr_to_pa(layout.base_map() as *mut c_void), PERM_R | PERM_W | PERM_X | PERM_U)?;

    dune_vm_map_phys(pgroot, layout.base_stack() as *mut c_void, GPA_STACK_SIZE, dune_stack_addr_to_pa(layout.base_stack() as *mut c_void), PERM_R | PERM_W | PERM_X | PERM_U)?;

    dune_vm_map_phys(pgroot, PAGEBASE as *mut c_void, MAX_PAGES * PGSIZE, dune_va_to_pa(PAGEBASE as *mut c_void), PERM_R | PERM_W | PERM_BIG)?;

    dune_procmap_iterate(setup_vdso_cb);
    setup_vsyscall();

    Ok(())
}

fn setup_mappings(full: bool) -> io::Result<()> {
    let mut layout: DuneLayout = unsafe { mem::zeroed() };
    let ret = unsafe { ioctl(dune_fd, DUNE_GET_LAYOUT, &mut layout) };
    if ret != 0 {
        return Err(io::Error::from_raw_os_error(ret));
    }

    phys_limit = layout.phys_limit();
    mmap_base = layout.base_map();
    stack_base = layout.base_stack();

    if full {
        __setup_mappings_full(&layout)
    } else {
        __setup_mappings_precise()
    }
}

fn create_percpu() -> Option<DunePercpu> {
    let mut fs_base: u64 = 0;
    if unsafe { arch_prctl(ARCH_GET_FS, &mut fs_base) } == -1 {
        eprintln!("dune: failed to get FS register");
        return None;
    }

    let percpu = unsafe {
        mmap(
            ptr::null_mut(),
            PGSIZE,
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
        unsafe { munmap(percpu as *mut c_void, PGSIZE) };
        return None;
    }

    Some(unsafe { ptr::read(percpu) })
}

fn free_percpu(percpu: &DunePercpu) {
    // XXX free stack
    unsafe { munmap(percpu as *const _ as *mut c_void, PGSIZE) };
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

fn do_dune_enter(percpu: &mut DunePercpu) -> io::Result<()> {
    map_stack();

    let mut conf = DuneConfig::default();
    conf.set_vcpu(0);
    conf.set_rip(&__dune_ret as *const _ as u64);
    conf.set_rsp(0);
    conf.set_cr3(pgroot as PhysaddrT);
    conf.set_rflags(0x2);

    // NOTE: We don't setup the general purpose registers because __dune_ret
    // will restore them as they were before the __dune_enter call

    let ret = unsafe { __dune_enter(dune_fd, &conf) };
    if ret != 0 {
        eprintln!("dune: entry to Dune mode failed, ret is {}", ret);
        return Err(io::Error::new(ErrorKind::Other, "Entry to Dune mode failed"));
    }

    let ret = dune_boot(percpu);
    if ret != 0 {
        eprintln!("dune: problem while booting, unrecoverable");
        dune_die();
    }

    Ok(())
}

 /**
  * on_dune_exit - handle Dune exits
  *
  * This function must not return. It can either exit(), __dune_go_dune() or
  * __dune_go_linux().
  */
pub fn on_dune_exit(conf: *const DuneConfig) -> ! {
    let conf = unsafe { &*conf };
    match conf.ret() {
        DUNE_RET_EXIT => {
            unsafe { libc::syscall(libc::SYS_exit, conf.status()) };
        }
        DUNE_RET_EPT_VIOLATION => {
            println!("dune: exit due to EPT violation");
        }
        DUNE_RET_INTERRUPT => {
            dune_debug_handle_int(conf);
            println!("dune: exit due to interrupt {}", conf.status());
        }
        DUNE_RET_SIGNAL => {
            __dune_go_dune(dune_fd, conf);
        }
        DUNE_RET_UNHANDLED_VMEXIT => {
            println!("dune: exit due to unhandled VM exit");
        }
        DUNE_RET_NOENTER => {
            println!(
                "dune: re-entry to Dune mode failed, status is {}",
                conf.status()
            );
        }
        _ => {
            println!(
                "dune: unknown exit from Dune, ret={}, status={}",
                conf.ret(), conf.status()
            );
        }
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
pub fn dune_enter() -> io::Result<()> {
    // Check if this process already entered Dune before a fork...
    if lpercpu.is_some() {
        return do_dune_enter(lpercpu.as_ref().unwrap());
    }

    let percpu = create_percpu().ok_or_else(|| io::Error::new(ErrorKind::Other, "Failed to create percpu"))?;
    if let Err(e) = do_dune_enter(&percpu) {
        free_percpu(&percpu);
        return Err(e);
    }

    lpercpu = Some(percpu);
    Ok(())
}

pub fn dune_enter_ex(percpu: *mut DunePercpu) -> io::Result<()> {
    let fs_base = unsafe {
        let mut fs_base: u64 = 0;
        if arch_prctl(ARCH_GET_FS, &mut fs_base) == -1 {
            return Err(io::Error::new(ErrorKind::Other, "Failed to get FS register"));
        }
        fs_base
    };

    unsafe {
        (*percpu).kfs_base = fs_base;
        (*percpu).ufs_base = fs_base;
        (*percpu).in_usermode = 0;
    }

    if let Err(e) = unsafe { setup_safe_stack(&mut *percpu) } {
        return Err(e);
    }

    do_dune_enter(unsafe { &mut *percpu })
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

pub fn dune_init(map_full: bool) -> io::Result<()> {
    if DUNE_INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }

    dune_fd = unsafe { open("/dev/dune\0".as_ptr() as *const i8, O_RDWR) };
    if dune_fd <= 0 {
        return Err(io::Error::new(ErrorKind::Other, "Failed to open Dune device"));
    }

    pgroot = unsafe { libc::memalign(PGSIZE, PGSIZE) as *mut PteEntry };
    if pgroot.is_null() {
        unsafe { libc::close(dune_fd) };
        return Err(io::Error::new(ErrorKind::Other, "Failed to allocate pgroot"));
    }
    unsafe { ptr::write_bytes(pgroot, 0, PGSIZE) };

    if dune_page_init().is_err() {
        unsafe { libc::close(dune_fd) };
        return Err(io::Error::new(ErrorKind::Other, "Unable to initialize page manager"));
    }

    if setup_mappings(map_full).is_err() {
        unsafe { libc::close(dune_fd) };
        return Err(io::Error::new(ErrorKind::Other, "Unable to setup memory layout"));
    }

    if setup_syscall().is_err() {
        unsafe { libc::close(dune_fd) };
        return Err(io::Error::new(ErrorKind::Other, "Unable to setup system calls"));
    }

    for i in 1..32 {
        match i {
            SIGTSTP | SIGSTOP | SIGKILL | SIGCHLD | SIGINT | SIGTERM => continue,
            _ => {
                let mut sa: sigaction = unsafe { mem::zeroed() };
                sa.sa_handler = SIG_IGN;
                if unsafe { sigaction(i, &sa, ptr::null_mut()) } == -1 {
                    unsafe { libc::close(dune_fd) };
                    return Err(io::Error::new(ErrorKind::Other, format!("sigaction() {}", i)));
                }
            }
        }
    }

    setup_idt();

    DUNE_INITIALIZED.store(true, Ordering::SeqCst);
    Ok(())
}
 