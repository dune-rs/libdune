// #[macro_use]
use std::ptr;
use libc::c_void;
use std::arch::asm;
use lazy_static::lazy_static;
use std::sync::Mutex;
use x86_64::structures::paging::page_table::PageTableEntry;
use x86_64::structures::paging::page_table::PageTableFlags;
use crate::globals::*;
use crate::mm::*;

macro_rules! PDADDR {
    ($n:expr, $i:expr) => {
        ($i as u64) << PDSHIFT!($n)
    };
}

pub const PTE_DEF_FLAGS: PageTableFlags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
pub const LGPGSIZE: u64 = 1 << (PGSHIFT + NPTBITS);

#[repr(C)]
#[derive(Debug,PartialEq,Eq)]
pub enum CreateType {
    None = 0,
    Normal = 1,
    Big = 2,
    Big1GB = 3,
}

impl From<i32> for CreateType {
    fn from(item: i32) -> Self {
        match item {
            0 => CreateType::None,
            1 => CreateType::Normal,
            2 => CreateType::Big,
            3 => CreateType::Big1GB,
            _ => CreateType::None,
        }
    }
}

impl From<CreateType> for i32 {
    fn from(item: CreateType) -> Self {
        match item {
            CreateType::None => 0,
            CreateType::Normal => 1,
            CreateType::Big => 2,
            CreateType::Big1GB => 3,
        }
    }
}

pub type PageWalkCb = fn(arg: *const c_void, ptep: *mut PageTableEntry, va: *mut c_void) -> i32;


// static mut pgroot: *mut PageTableEntry;
pub static mut PHYS_LIMIT: UintptrT = ptr::null_mut();
pub static mut MMAP_BASE: UintptrT = ptr::null_mut();
pub static mut STACK_BASE: UintptrT = ptr::null_mut();

lazy_static! {
    static ref PAGE_MUTEX: Mutex<()> = Mutex::new(());
}

fn pte_present(pte: PageTableEntry) -> bool {
    pte.flags().contains(PageTableFlags::PRESENT)
}

fn pte_big(pte: PageTableEntry) -> bool {
    pte.flags().contains(PageTableFlags::HUGE_PAGE)
}

fn alloc_page() -> Result<*mut Page, i32> {

    let pg = dune_page_alloc();

    if let Ok(pg) = pg {
        let pa = dune_page2pa(pg);
        return Ok(pa as *mut Page);
    }

    return Err(-libc::ENOMEM);
}

pub fn put_page(page: *mut c_void) {
    let pg = dune_pa2page(PhysAddr::new(page as u64));
    dune_page_put(pg);
}

pub unsafe fn dune_mmap_addr_to_pa(ptr: *mut c_void) -> UintptrT {
    (ptr as UintptrT) - MMAP_BASE + PHYS_LIMIT - GPA_STACK_SIZE - GPA_MAP_SIZE
}

pub unsafe fn dune_stack_addr_to_pa(ptr: *mut c_void) -> UintptrT {
    (ptr as UintptrT) - STACK_BASE + PHYS_LIMIT - GPA_STACK_SIZE
}

pub unsafe fn dune_va_to_pa(ptr: *mut c_void) -> UintptrT {
    if (ptr as UintptrT) >= STACK_BASE {
        dune_stack_addr_to_pa(ptr)
    } else if (ptr as UintptrT) >= MMAP_BASE {
        dune_mmap_addr_to_pa(ptr)
    } else {
        ptr as UintptrT
    }
}

pub unsafe fn dune_flush_tlb_one(addr: u64) {
    asm!("invlpg ({})", in(reg) addr, options(nostack, preserves_flags));
}

pub unsafe fn dune_flush_tlb() {
    asm!(
        "mov %cr3, %rax",
        "mov %rax, %cr3",
        out("rax") _,
        options(nostack, preserves_flags)
    );
}

pub unsafe fn load_cr3(cr3: u64) {
    asm!("mov {0}, %cr3", in(reg) cr3, options(nostack, preserves_flags));
}

pub fn get_pte_flags(perms: i32) -> PageTableFlags {
    let mut flags = PageTableFlags::empty();
    if perms & PERM_R != 0 {
        flags |= PageTableFlags::PRESENT;
    }

    if perms & PERM_W != 0 {
        flags |= PageTableFlags::WRITABLE;
    }

    if perms & PERM_X == 0 {
        flags |= PageTableFlags::NO_EXECUTE;
    }

    if perms & PERM_U != 0 {
        flags |= PageTableFlags::USER_ACCESSIBLE;
    }

    // bit 9 is the COW bit
    if perms & PERM_COW != 0 {
        flags |= PageTableFlags::BIT_9;
    }

    if perms & PERM_BIG != 0 || perms & PERM_BIG_1GB != 0 {
        flags |= PageTableFlags::HUGE_PAGE;
    }

    flags
}

fn __dune_vm_page_walk(
    dir: *mut PageTableEntry,
    start_va: *const c_void,
    end_va: *const c_void,
    cb: PageWalkCb,
    arg: *const c_void,
    level: i32,
    create: CreateType,
) -> i32 {
    let start_idx = PDX!(level, start_va as u64);
    let end_idx = PDX!(level, end_va as u64);
    let base_va = (start_va as u64 & !(PDADDR!(level + 1, 1) - 1)) as *mut c_void;

    // ptent_t *pte = &dir[i];
    // void *n_start_va, *n_end_va;
    // void *cur_va = base_va + PDADDR(level, i);
    for i in start_idx..=end_idx {
        let cur_va = (base_va as u64 + PDADDR!(level, i)) as *mut c_void;
        let ptep = unsafe { dir.offset(i as isize) as *mut PageTableEntry };
        let pte = &*ptep;

        if level == 0 {
            if create == CreateType::Normal || !pte.is_unused() {
                let ret = cb(arg, ptep, cur_va);
                if ret != 0 {
                    return ret;
                }
            }
            continue;
        }

        if level == 1 {
            if create == CreateType::Big || pte_big(*pte) {
                let ret = cb(arg, ptep, cur_va);
                if ret != 0 {
                    return ret;
                }
                continue;
            }
        }

        if level == 2 {
            if create == CreateType::Big1GB || pte_big(*pte) {
                let ret = cb(arg, ptep, cur_va);
                if ret != 0 {
                    return ret;
                }
                continue;
            }
        }

        if !pte_present(*pte) {
            if create == CreateType::None {
                continue;
            }

            let page = alloc_page();
            match page {
                Ok(page) => {
                    unsafe { ptr::write_bytes(page, 0, PGSIZE as usize) };
                    let addr = PhysAddr::new(page as u64);
                    pte.set_addr(addr, PTE_DEF_FLAGS);
                }
                Err(_) => {
                    return -libc::ENOMEM;
                }
            }
        }

        let n_start_va = if i == start_idx { start_va } else { cur_va };
        let n_end_va = if i == end_idx { end_va } else { (cur_va as u64 + PDADDR!(level, 1) - 1) as *mut c_void };

        let root = pte.addr().as_u64() as *mut PageTableEntry;
        let ret = __dune_vm_page_walk(root,n_start_va,n_end_va, cb, arg, level - 1, create);
        if ret != 0 {
            return ret;
        }
    }

    0
}

pub fn dune_vm_page_walk(
    root: *mut PageTableEntry,
    start_va: *const c_void,
    end_va: *const c_void,
    cb: PageWalkCb,
    arg: *const c_void,
) -> i32 {
    __dune_vm_page_walk(root, start_va, end_va, cb, arg, 3, CreateType::None)
}

pub fn dune_vm_lookup(
    root: *mut PageTableEntry,
    va: *const c_void,
    create: CreateType,
    pte_out: **mut PageTableEntry,
) -> i32 {
    let mut pml4 = root;
    let mut pdpte: *mut [PageTableEntry];
    let mut pde: *mut [PageTableEntry];
    let mut pte: *mut [PageTableEntry];

    let i = PDX!(3, va);
    let j = PDX!(2, va);
    let k = PDX!(1, va);
    let l = PDX!(0, va);

    if !pte_present(pml4[i]) {
        if create == CreateType::None {
            return -libc::ENOENT;
        }

        let page = alloc_page();
        match page {
            Ok(page) => {
                unsafe { ptr::write_bytes(page, 0, PGSIZE as usize) };
                let pte = &mut pml4[i];
                pte.set_addr(page.addr());
                pte.set_flags(PTE_DEF_FLAGS);
            }
            Err(_) => {
                return -libc::ENOMEM;
            }
        }
    } else {
        pdpte = PTE_ADDR!(pml4[i]) as *mut [PageTableEntry];
    }

    if !pte_present(pdpte[j]) {
        if create == CreateType::None {
            return -libc::ENOENT;
        }

        let page = alloc_page();
        match page {
            Ok(page) => {
                unsafe { ptr::write_bytes(page, 0, PGSIZE as usize) };
                let pte = &mut pdpte[j];
                pte.set_addr(pde.addr());
                pte.set_flags(PTE_DEF_FLAGS);
            }
            Err(_) => {
                return -libc::ENOMEM;
            }
        }
    } else if pte_big(pdpte[j]) {
        *pte_out = &mut pdpte[j];
        return 0;
    } else {
        pde = PTE_ADDR!(pdpte[j]) as *mut [PageTableEntry];
    }

    if !pte_present(pde[k]) {
        if create == CreateType::None {
            return -libc::ENOENT;
        }

        let page = alloc_page();
        match page {
            Ok(page) => {
                unsafe { ptr::write_bytes(page, 0, PGSIZE as usize) };
                let _pde = &mut pde[k];
                _pde.set_addr(pte.addr());
                _pde.set_flags(PTE_DEF_FLAGS);
            }
            Err(_) => {
                return -libc::ENOMEM;
            }
        }
    } else if pte_big(pde[k]) {
        *pte_out = &mut pde[k];
        return 0;
    } else {
        pte = PTE_ADDR!(pde[k]) as *mut [PageTableEntry];
    }

    *pte_out = &mut pte[l];
    0
}

pub fn dune_vm_mprotect(
    root: &mut PageTableEntry,
    va: *mut c_void,
    len: u64,
    perm: i32,
) -> i32 {
    if perm & PERM_R == 0 && perm & PERM_W != 0 {
        return -libc::EINVAL;
    }

    let pte_flags = get_pte_flags(perm);

    let ret = __dune_vm_page_walk(
        root,
        va,
        (va as u64 + len - 1) as *mut c_void,
        __dune_vm_mprotect_helper,
        &pte_flags as *const _ as *const c_void,
        3,
        CreateType::None,
    );
    if ret != 0 {
        return ret;
    }

    unsafe { dune_flush_tlb() };
    0
}

unsafe fn __dune_vm_mprotect_helper(arg: *const c_void, ptep: *mut PageTableEntry, _va: *mut c_void) -> i32 {
    let perm: &PageTableEntry = &*(arg as *const PageTableEntry);
    // *pte = PTE_ADDR!(*pte) | (PTE_FLAGS!(*pte) & PTE_PS) | perm;
    let pte = ptep.as_mut().unwrap();
    pte.set_addr(perm.addr(), perm.flags() | (pte.flags() & PageTableFlags::HUGE_PAGE));
    0
}

pub fn dune_vm_map_phys(
    root: *mut PageTableEntry,
    va: *const c_void,
    len: u64,
    pa: *const c_void,
    perm: i32,
) -> i32 {
    let data = MapPhysData {
        perm: get_pte_flags(perm),
        va_base: va as u64,
        pa_base: pa as u64,
    };

    let create = 
    if perm & PERM_BIG != 0 {
        CreateType::Big
    } else if perm & PERM_BIG_1GB != 0 {
        CreateType::Big1GB
    } else {
        CreateType::Normal
    };

    __dune_vm_page_walk(
        root,
        va,
        (va as u64 + len - 1) as *mut c_void,
        __dune_vm_map_phys_helper,
        &data as *const _ as *const c_void,
        3,
        create,
    )
}

struct MapPhysData {
    perm: PageTableFlags,
    va_base: u64,
    pa_base: u64,
}

// import PyhsAddr
use x86_64::PhysAddr;

fn __dune_vm_map_phys_helper(arg: *const c_void, pte: *mut PageTableEntry, va: *mut c_void) -> i32 {
    // *pte = PTE_ADDR!(va as u64 - data.va_base + data.pa_base) | data.perm;
    // convert arg to MapPhysData
    unsafe {
        let data = (arg as *const MapPhysData).as_ref().unwrap();
        let pte = pte.as_mut().unwrap();
        let addr = PhysAddr::new(data.pa_base + (va as u64 - data.va_base));
        pte.set_addr(addr, data.perm);
        0
    }
}

pub fn dune_vm_map_pages(
    root: *mut PageTableEntry,
    va: *mut c_void,
    len: u64,
    perm: i32,
) -> i32 {
    if perm & PERM_R == 0 && perm & !PERM_R != 0 {
        return -libc::EINVAL;
    }

    let pte_flags = get_pte_flags(perm);

    __dune_vm_page_walk(
        root,
        va,
        (va as u64 + len - 1) as *mut c_void,
        __dune_vm_map_pages_helper,
        &pte_flags as *const _ as *const c_void,
        3,
        CreateType::Normal,
    )
}

fn __dune_vm_map_pages_helper(arg: *const c_void, pte: *mut PageTableEntry, _va: *mut c_void) -> i32 {

    let page = dune_page_alloc();
    if let Ok(page) = page {
        let ptep = unsafe { &mut *pte };
        let addr = PhysAddr::new(page as u64);
        let flags = unsafe { *(arg as *const PageTableFlags) };
        ptep.set_addr(addr, flags);
        return 0
    }

    return -libc::ENOMEM;
}

pub fn dune_vm_clone(root: *mut PageTableEntry) -> *mut PageTableEntry {
    let newRoot = alloc_page();
    match newRoot {
        Ok(newRoot) => {
            unsafe { ptr::write_bytes(newRoot, 0, PGSIZE as usize) };
            let ret = __dune_vm_page_walk(
                root,
                VA_START,
                VA_END,
                __dune_vm_clone_helper,
                newRoot as *const c_void,
                3,
                CreateType::None,
            );
            if ret < 0 {
                dune_vm_free(newRoot as *mut PageTableEntry);
                return ptr::null_mut();
            }
            newRoot as *mut PageTableEntry
        }
        Err(_) => {
            return ptr::null_mut();
        }
    }
}

fn __dune_vm_clone_helper(arg: *const c_void, ptep: *mut PageTableEntry, va: *mut c_void) -> i32 {
    let new_root = arg as *mut PageTableEntry;
    let mut new_ptep = ptr::null_mut();
    let pte = unsafe { &mut *ptep };

    let ret = dune_vm_lookup(new_root, va, CreateType::Normal, &mut new_ptep);
    if ret < 0 {
        return ret;
    }

    if dune_page_isfrompool(pte.addr()) {
        dune_page_get(dune_pa2page(pte.addr()));
    }

    let new_pte = unsafe { &mut *new_ptep };
    new_pte.set_addr(pte.addr(), pte.flags());
    0
}

pub fn dune_vm_free(root: *mut PageTableEntry) {
    __dune_vm_page_walk(
        root,
        VA_START,
        VA_END,
        __dune_vm_free_helper,
        ptr::null(),
        2,
        CreateType::None,
    );
    __dune_vm_page_walk(
        root,
        VA_START,
        VA_END,
        __dune_vm_free_helper,
        ptr::null(),
        1,
        CreateType::None,
    );
    put_page(root as *mut c_void);
}

fn __dune_vm_free_helper(_arg: *const c_void, pte: *mut PageTableEntry, _va: *mut c_void) -> i32 {
    let ptep = unsafe { &mut *pte };
    let pg = dune_pa2page(ptep.addr());
    if dune_page_isfrompool(ptep.addr()) {
        dune_page_put(pg);
    }

    ptep.set_unused();
    0
}

pub fn dune_vm_unmap(root: *mut PageTableEntry, va: *mut c_void, len: u64) {
    __dune_vm_page_walk(
        root,        va,        (va as u64 + len - 1) as *mut c_void,
        __dune_vm_free_helper,        ptr::null(),        3,        CreateType::None,
    );
    unsafe { dune_flush_tlb() };
}

pub unsafe extern "C" fn dune_vm_default_pgflt_handler(addr: u64, fec: u64) {
    let pte: *mut PageTableEntry = ptr::null_mut();
    let rc = dune_vm_lookup(PGROOT, addr as *mut c_void, CreateType::None, &pte);
    assert!(rc == 0);

    let pte = unsafe { &mut *pte };
    let flags = pte.flags();
    let cow = flags.contains(PageTableFlags::BIT_9);

    if (fec & FEC_W) != 0 && cow {
        let pg = dune_pa2page((*pte).addr());

        // Compute new permissions, clear the COW bit, and set the writable bit
        let flags = pte.flags() & !PageTableFlags::BIT_9 | PageTableFlags::WRITABLE;
        if dune_page_isfrompool(pte.addr()) && (*pg).ref_count() == 1 {
            pte.set_flags(flags);
            return;
        }

        // Duplicate the page
        let new_page = alloc_page();
        // if alloc_page fails, we should panic
        let new_page = new_page.unwrap();

        unsafe {
            // clear new page
            ptr::write_bytes(new_page, 0, PGSIZE as usize);
        }

        // Map page
        if dune_page_isfrompool(pte.addr()) {
            dune_page_put(pg);
        }

        let addr = PhysAddr::new(new_page as u64);
        pte.set_addr(addr, flags);

        unsafe { dune_flush_tlb_one(new_page as u64) };
    }
}
