use std::arch::asm;
use std::{mem, ptr};
use std::{ffi::c_void, io};
use libc::ioctl;
use x86_64::{structures::paging::{page_table::PageTableEntry, PageTableFlags}, PhysAddr};
use dune_sys::*;
use crate::globals::{PERM_BIG, PERM_NONE, PERM_R, PERM_U, PERM_W, PERM_X};
use crate::{dune_procmap_iterate, DuneProcmapEntry, ProcMapType, MAX_PAGES, PAGEBASE};
use crate::{core::*, dune_vm_lookup, dune_vm_map_phys, globals::PGSIZE, CreateType};

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

unsafe fn map_ptr(p: *mut c_void, len: usize) {
    // Align the pointer to the page size
    let page = (p as usize & !(PGSIZE - 1)) as *mut c_void;
    let page_end = p.add(len + PGSIZE - 1).mask(!(PGSIZE - 1));
    let len = page_end.sub(page);
    let ptr = page as *mut c_void;
    let pa = dune_va_to_pa(ptr) as *mut c_void;

    dune_vm_map_phys(PGROOT, page, len, pa, PERM_R | PERM_W);
}

#[cfg(feature = "syscall")]
pub unsafe fn setup_syscall() -> io::Result<()> {
    let lstar = ioctl(DUNE_FD, DUNE_GET_SYSCALL);
    if lstar == -1 {
        return Err(io::Error::last_os_error());
    }

    let page = mmap(ptr::null_mut(),
                                (PGSIZE * 2) as usize,
                                PROT_READ | PROT_WRITE | PROT_EXEC,
                                MAP_PRIVATE | MAP_ANON,
                                -1,
                                0);

    if page == MAP_FAILED {
        return Err(io::Error::last_os_error());
    }

    // calculate the page-aligned address
    let lstara = lstar.bitand(!(PGSIZE - 1));
    let off = lstar.bitand(PGSIZE - 1);

    unsafe {
        ptr::copy_nonoverlapping(
            __dune_syscall as *const u8,
            (page as *mut u8).add(off as usize),
            __dune_syscall_end as usize - __dune_syscall as usize,
        );
    }

    for i in (0..=PGSIZE).step_by(PGSIZE) {
        let pa = dune_mmap_addr_to_pa(unsafe { page.add(i) });
        let mut pte: *mut PageTableEntry = ptr::null_mut();
        unsafe {
            let start = (lstara + i as u64) as *mut c_void;
            dune_vm_lookup(PGROOT, start, CreateType::Normal, &mut pte);
            *pte = PTE_ADDR!(pa) | PTE_P;
        }
    }

    Ok(())
}

#[cfg(not(feature = "syscall"))]
pub unsafe fn setup_syscall() -> io::Result<()> {
    log::warn!("No syscall support");
    Ok(())
}

const VSYSCALL_ADDR: u64 = 0xffffffffff600000;

fn setup_vsyscall() {
    let mut ptep: *mut PageTableEntry = ptr::null_mut();
    unsafe {
        let vsyscall_addr = VSYSCALL_ADDR as *mut c_void;
        let vsyscall_page = &__dune_vsyscall_page as *const _ as *mut c_void;
        let page = dune_va_to_pa(vsyscall_page);
        let addr = PhysAddr::new(page as u64);
        dune_vm_lookup(PGROOT, vsyscall_addr, CreateType::Normal, &mut ptep);
        let pte = &mut *ptep;
        pte.set_addr(addr, PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE);
    }
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
        let len = (MAX_PAGES * PGSIZE) as u64;
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
    let len = (MAX_PAGES * PGSIZE) as u64;
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

pub trait DuneHook {
    fn pre_enter(&self, percpu: &mut DunePercpu) -> io::Result<()>;
    fn post_exit(&self, percpu: &mut DunePercpu) -> io::Result<()>;
}

// dune-spesicifc routines
impl DuneHook for DunePercpu {
    fn pre_enter(&self, _percpu: &mut DunePercpu) -> io::Result<()> {
        let safe_stack= _percpu.tss.tss_rsp[0] as *mut c_void;
        unsafe { map_ptr(safe_stack, PGSIZE as usize) };

        unsafe { setup_syscall()? };
        map_stack();

        Ok(())
    }

    fn post_exit(&self, _percpu: &mut DunePercpu) -> io::Result<()> {
        Ok(())
    }
}