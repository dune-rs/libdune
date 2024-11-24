use std::ptr;
use libc::*;
use lazy_static::lazy_static;
use std::sync::Mutex;
use dune_sys::*;
use dune_sys::dev::DuneDevice;

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