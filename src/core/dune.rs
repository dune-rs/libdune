use std::mem;
use std::io;
use std::ops::BitAnd;
use std::ptr;
use libc::ioctl;
use dune_sys::*;
use libc::mmap;
use libc::MAP_ANON;
use libc::MAP_FAILED;
use libc::MAP_PRIVATE;
use libc::PROT_EXEC;
use libc::PROT_READ;
use libc::PROT_WRITE;
use x86_64::structures::paging::page_table::PageTableEntry;
use x86_64::structures::paging::PageTable;
use x86_64::structures::paging::PageTableFlags;
use x86_64::{PhysAddr, VirtAddr};
use crate::dune_vm_lookup;
use crate::globals::{rd_rsp, PERM_BIG, PERM_NONE, PERM_R, PERM_U, PERM_W, PERM_X};
use crate::CreateType;
use crate::{dune_procmap_iterate, DuneProcmapEntry, ProcMapType, MAX_PAGES, PAGEBASE, PGSIZE};
use crate::{core::{PGROOT, *}, dune_vm_map_phys};
use crate::result::{Result, Error};

// pub static mut PGROOT: *mut PageTable = ptr::null_mut();
static mut PHYS_LIMIT: PhysAddr = PhysAddr::new(0);
static mut MMAP_BASE: VirtAddr = VirtAddr::new(0);
static mut STACK_BASE: VirtAddr = VirtAddr::new(0);

/// The physical address limit of the address space
///  ptr - MMAP_BASE + PHYS_LIMIT - GPA_STACK_SIZE - GPA_MAP_SIZE
///
fn dune_mmap_addr_to_pa(ptr: VirtAddr) -> PhysAddr {
    unsafe {
        PhysAddr::new(ptr.as_u64() - MMAP_BASE.as_u64() + PHYS_LIMIT.as_u64() - GPA_STACK_SIZE - GPA_MAP_SIZE)
    }
}

/// The physical address limit of the address space
/// ptr - STACK_BASE + PHYS_LIMIT - GPA_STACK_SIZE
fn dune_stack_addr_to_pa(ptr: VirtAddr) -> PhysAddr {
    unsafe {
        PhysAddr::new(ptr.as_u64() - STACK_BASE.as_u64() + PHYS_LIMIT.as_u64() - GPA_STACK_SIZE)
    }
}

fn dune_va_to_pa(ptr: VirtAddr) -> PhysAddr {
    unsafe {
        if ptr >= STACK_BASE {
            dune_stack_addr_to_pa(ptr)
        } else if ptr >= MMAP_BASE {
            dune_mmap_addr_to_pa(ptr)
        } else {
            // PA == VA
            PhysAddr::new(ptr.as_u64())
        }
    }
}

unsafe fn map_ptr(page: VirtAddr, len: usize) -> Result<()> {
    // Align the pointer to the page size
    let page_end = page + len as u64;
    let len = page_end - page;
    let pa = dune_va_to_pa(page);
    let perm = PERM_R | PERM_W;
    let root = &mut *PGROOT.lock().unwrap();
    dune_vm_map_phys(root, page, len, pa, perm)
}

#[cfg(feature = "dune")]
pub fn setup_syscall() -> Result<()> {
    let dune_fd = *DUNE_FD.lock().unwrap();
    let lstar = unsafe { ioctl(dune_fd, DUNE_GET_SYSCALL) };
    if lstar == -1 {
        return Err(Error::Unknown);
    }

    let page = unsafe { mmap(ptr::null_mut(),
                                (PGSIZE * 2) as usize,
                                PROT_READ | PROT_WRITE | PROT_EXEC,
                                MAP_PRIVATE | MAP_ANON,
                                -1,
                                0) };

    if page == MAP_FAILED {
        return Err(Error::Unknown);
    }

    // calculate the page-aligned address
    let lstar = VirtAddr::new(lstar as u64);
    let lstara = lstar.align_down(align_of::<PageTable>() as u64);
    let off = lstar - lstara;

    unsafe {
        ptr::copy_nonoverlapping(
            __dune_syscall as *const u8,
            (page as *mut u8).add(off as usize),
            __dune_syscall_end as usize - __dune_syscall as usize,
        );
    }

    let page = VirtAddr::new(page as u64);
    let root = &mut *PGROOT.lock().unwrap();
    for i in (0..=PGSIZE).step_by(PGSIZE) {
        let start = lstara + i as u64;
        let pa = dune_mmap_addr_to_pa(page + i as u64);
        dune_vm_lookup(root, start, CreateType::Normal)
            .and_then(|pte|{
                pte.set_addr(pa, PageTableFlags::PRESENT);
                Ok(())
            })?;
    }

    Ok(())
}

#[cfg(not(feature = "dune"))]
pub fn setup_syscall() -> Result<()> {
    log::warn!("No syscall support");
    Ok(())
}

const VSYSCALL_ADDR: VirtAddr = VirtAddr::new(0xffffffffff600000);

#[cfg(feature = "dune")]
fn setup_vsyscall() -> Result<()> {
    let root = &mut *PGROOT.lock().unwrap();
    let addr = dune_va_to_pa(VSYSCALL_ADDR);
    dune_vm_lookup(root, VSYSCALL_ADDR, CreateType::Normal)
        .and_then(|pte| {
            pte.set_addr(addr, PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE);
            Ok(())
        })
}

#[cfg(not(feature = "dune"))]
fn setup_vsyscall() -> Result<()> {
    log::warn!("No vsyscall support");
    Ok(())
}

fn __setup_mappings_cb(ent: &DuneProcmapEntry) -> Result<()> {
    let root = &mut *PGROOT.lock().unwrap();
    let mut perm = PERM_NONE;

    // page region already mapped
    if ent.begin() == VirtAddr::new(PAGEBASE.as_u64()) {
        return Ok(());
    }

    if ent.begin() == VSYSCALL_ADDR {
        setup_vsyscall();
        return Ok(());
    }

    if ent.type_() == ProcMapType::Vdso {
        let pa = dune_va_to_pa(ent.begin());
        dune_vm_map_phys(root, ent.begin(), ent.len(), pa, PERM_U | PERM_R | PERM_X);
        return Ok(());
    }

    if ent.type_() == ProcMapType::Vvar {
        let pa = dune_va_to_pa(ent.begin());
        dune_vm_map_phys(root, ent.begin(), ent.len(), pa, PERM_U | PERM_R);
        return Ok(());
    }

    if ent.r() {
        perm |= PERM_R;
    }
    if ent.w() {
        perm |= PERM_W;
    }
    if ent.x() {
        perm |= PERM_X;
    }

    let pa_start = dune_va_to_pa(ent.begin());
    dune_vm_map_phys( root, ent.begin(), ent.len(), pa_start, perm)
}

fn __setup_mappings_precise() -> Result<()> {
    let root = &mut *PGROOT.lock().unwrap();
    let va_start = VirtAddr::new(PAGEBASE.as_u64());
    let len = (MAX_PAGES * PGSIZE) as u64;
    let pa_start = PAGEBASE;
    dune_vm_map_phys(root, va_start, len, pa_start, PERM_R | PERM_W | PERM_BIG)
        .and_then(|()| {
            dune_procmap_iterate(__setup_mappings_cb)
        })
}

fn setup_vdso_cb(ent: &DuneProcmapEntry) -> Result<()> {
    let root = &mut *PGROOT.lock().unwrap();
    let pa = dune_va_to_pa(ent.begin());
    let ret = match ent.type_() {
        ProcMapType::Vdso => Ok(PERM_U | PERM_R | PERM_X),
        ProcMapType::Vvar => Ok(PERM_U | PERM_R),
        _ => Err(Error::Unknown),
    }.and_then(|perm|{
        dune_vm_map_phys(root, ent.begin(), ent.len(), pa, perm)
    });
    match ret {
        Ok(_) => Ok(()),
        Err(Error::Unknown) => Ok(()),
        Err(e) => Err(e),
    }
}

fn __setup_mappings_full(layout: &DuneLayout) -> Result<()> {
    let root = &mut *PGROOT.lock().unwrap();
    // Map the entire address space
    let va = VirtAddr::new(0);
    let pa = PhysAddr::new(0);
    let len = 1 << 32; // 4GB
    let perm = PERM_R | PERM_W | PERM_X | PERM_U;
    dune_vm_map_phys(root, va, len, pa, perm)?;

    // Map the base_map region
    let va = layout.base_map();
    let pa = dune_mmap_addr_to_pa(va);
    let len = GPA_MAP_SIZE as u64;
    let perm = PERM_R | PERM_W | PERM_X | PERM_U;
    dune_vm_map_phys(root, va, len, pa, perm)?;

    // Map the base_stack region
    let va = layout.base_stack();
    let pa = dune_stack_addr_to_pa(va);
    let len = GPA_STACK_SIZE as u64;
    let perm = PERM_R | PERM_W | PERM_X | PERM_U;
    dune_vm_map_phys(root, va, len, pa, perm)?;

    // Map the page table region
    let va = VirtAddr::new(PAGEBASE.as_u64());
    let pa = dune_va_to_pa(va);
    let len = (MAX_PAGES * PGSIZE) as u64;
    let perm = PERM_R | PERM_W | PERM_BIG;
    dune_vm_map_phys(root, va, len, pa, perm)?;

    dune_procmap_iterate(setup_vdso_cb)?;
    setup_vsyscall()?;

    Ok(())
}

pub fn setup_mappings(full: bool) -> Result<()> {
    let mut layout: DuneLayout = unsafe { mem::zeroed() };
    let dune_fd = *DUNE_FD.lock().unwrap();
    let ret = unsafe { ioctl(dune_fd, DUNE_GET_LAYOUT, &mut layout) };
    if ret != 0 {
        return Err(Error::Unknown);
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

fn map_stack_cb(e: &DuneProcmapEntry) -> Result<()> {
    let esp: u64 = rd_rsp();
    let addr = VirtAddr::new(esp);
    if addr >= e.begin() && addr < e.end() {
        unsafe { map_ptr(e.begin(), e.len() as usize) };
    }
    Ok(())
}

fn map_stack() -> Result<()> {
    dune_procmap_iterate(map_stack_cb)
}

pub trait DuneHook {
    fn pre_enter(&self, percpu: &mut DunePercpu) -> Result<()>;
    fn post_exit(&self, percpu: &mut DunePercpu) -> Result<()>;
}

// dune-spesicifc routines
impl DuneHook for DunePercpu {
    fn pre_enter(&self, percpu: &mut DunePercpu) -> Result<()> {
        let safe_stack= VirtAddr::new(percpu.tss.tss_rsp[0]);
        unsafe { map_ptr(safe_stack, PGSIZE) };

        setup_syscall()?;
        map_stack()?;

        Ok(())
    }

    fn post_exit(&self, percpu: &mut DunePercpu) -> Result<()> {
        Ok(())
    }
}