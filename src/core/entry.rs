use std::io::{self, ErrorKind};
use std::mem;
use std::ptr;
use std::arch::asm;
use std::sync::atomic::{AtomicBool, Ordering};
use x86_64::structures::paging::page_table::PageTableEntry;
use dune_sys::dune::DuneLayout;
use dune_sys::dev::DUNE_GET_LAYOUT;

use crate::globals::*;
use crate::mm::*;
use crate::utils::*;
use crate::syscall::*;
use crate::core::*;

use std::cell::RefCell;

thread_local! {
    static LPERCPU: RefCell<Option<DunePercpu>> = RefCell::new(None);
}

pub static mut PHYS_LIMIT: UintptrT = ptr::null_mut();
pub static mut MMAP_BASE: UintptrT = ptr::null_mut();
pub static mut STACK_BASE: UintptrT = ptr::null_mut();

unsafe fn dune_mmap_addr_to_pa(ptr: *mut c_void) -> UintptrT {
    (ptr as UintptrT) - MMAP_BASE + PHYS_LIMIT - GPA_STACK_SIZE - GPA_MAP_SIZE
}

unsafe fn dune_stack_addr_to_pa(ptr: *mut c_void) -> UintptrT {
    (ptr as UintptrT) - STACK_BASE + PHYS_LIMIT - GPA_STACK_SIZE
}

unsafe fn dune_va_to_pa(ptr: *mut c_void) -> UintptrT {
    if (ptr as UintptrT) >= STACK_BASE {
        dune_stack_addr_to_pa(ptr)
    } else if (ptr as UintptrT) >= MMAP_BASE {
        dune_mmap_addr_to_pa(ptr)
    } else {
        ptr as UintptrT
    }
}

pub unsafe fn map_ptr(p: *mut c_void, len: usize) {
    // Align the pointer to the page size
    let page = (p as usize & !(PGSIZE - 1)) as *mut c_void;
    let page_end = p.add(len + PGSIZE - 1).mask(!(PGSIZE - 1));
    let len = page_end.sub(page);
    let ptr = page as *mut c_void;
    let pa = dune_va_to_pa(ptr) as *mut c_void;

    dune_vm_map_phys(PGROOT, pg, len, pa, PERM_R | PERM_W);
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

    setup_signals()?;

    setup_idt();

    DUNE_INITIALIZED.store(true, Ordering::SeqCst);
    Ok(())
}