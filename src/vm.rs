// #[macro_use]
use std::ptr;
use libc::{c_void};
use std::arch::asm;
use lazy_static::lazy_static;
use std::sync::Mutex;
use crate::globals::*;
use crate::page::*;
use crate::dune::*;

// #define PDADDR(n, i)  (((unsigned long)(i)) << PDSHIFT(n))
macro_rules! PDADDR {
    ($n:expr, $i:expr) => {
        ($i as usize) << PDSHIFT!($n)
    };
}

pub const PTE_DEF_FLAGS: u64 = PTE_P | PTE_W | PTE_U;
pub const LGPGSIZE: usize = 1 << (PGSHIFT + NPTBITS);

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

impl To<i32> for CreateType {
    fn from(item: CreateType) -> Self {
        match item {
            CreateType::None => 0,
            CreateType::Normal => 1,
            CreateType::Big => 2,
            CreateType::Big1GB => 3,
        }
    }
}

pub type PtEnt = u64;
// type PageWalkCb = fn(&c_void, &mut PtEnt, *mut c_void) -> i32;
pub type PageWalkCb = fn(arg: *const c_void, ptep: *mut PteEntry, va: *mut c_void) -> i32;
pub type UintptrT = usize;


// static mut pgroot: *mut PteEntry;
pub static mut phys_limit: UintptrT = 0;
pub static mut mmap_base: UintptrT = 0;
pub static mut stack_base: UintptrT = 0;

lazy_static! {
    static ref PAGE_MUTEX: Mutex<()> = Mutex::new(());
}

pub fn pte_present(pte: PtEnt) -> bool {
    pte & PTE_P != 0
}

pub fn pte_big(pte: PtEnt) -> bool {
    pte & PTE_PS != 0
}

pub fn alloc_page() -> *mut c_void {
    let pg = dune_page_alloc();
    if pg.is_null() {
        return ptr::null_mut();
    }
    dune_page2pa(pg)
}

pub fn put_page(page: *mut c_void) {
    let pg = dune_pa2page(page as usize);
    dune_page_put(pg);
}

pub fn dune_page2pa(pg: *mut Page) -> *mut c_void {
    (PAGEBASE + (pg as usize - pages as usize)) as *mut c_void
}

pub fn dune_pa2page(pa: usize) -> *mut Page {
    (pages as usize + (pa - PAGEBASE)) as *mut Page
}


pub unsafe fn dune_mmap_addr_to_pa(ptr: *mut c_void) -> UintptrT {
    (ptr as UintptrT) - mmap_base + phys_limit - GPA_STACK_SIZE - GPA_MAP_SIZE
}

pub unsafe fn dune_stack_addr_to_pa(ptr: *mut c_void) -> UintptrT {
    (ptr as UintptrT) - stack_base + phys_limit - GPA_STACK_SIZE
}

pub unsafe fn dune_va_to_pa(ptr: *mut c_void) -> UintptrT {
    if (ptr as UintptrT) >= stack_base {
        dune_stack_addr_to_pa(ptr)
    } else if (ptr as UintptrT) >= mmap_base {
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

pub fn get_pte_perm(perm: i32) -> PtEnt {
    let mut pte_perm = 0;
    if perm & PERM_R != 0 {
        pte_perm |= PTE_P;
    }
    if perm & PERM_W != 0 {
        pte_perm |= PTE_W;
    }
    if perm & PERM_X == 0 {
        pte_perm |= PTE_NX;
    }
    if perm & PERM_U != 0 {
        pte_perm |= PTE_U;
    }
    if perm & PERM_COW != 0 {
        pte_perm |= PTE_COW;
    }
    if perm & PERM_BIG != 0 || perm & PERM_BIG_1GB != 0 {
        pte_perm |= PTE_PS;
    }
    pte_perm
}

fn __dune_vm_page_walk(
    dir: &mut [PtEnt],
    start_va: *mut c_void,
    end_va: *mut c_void,
    cb: PageWalkCb,
    arg: &c_void,
    level: i32,
    create: i32,
) -> i32 {
    let start_idx = PDX!(level, start_va);
    let end_idx = PDX!(level, end_va);
    let base_va = (start_va as usize & !(PDADDR!(level + 1, 1) - 1)) as *mut c_void;

    for i in start_idx..=end_idx {
        let cur_va = (base_va as usize + PDADDR!(level, i)) as *mut c_void;
        let pte = &mut dir[i];

        if level == 0 {
            if create == CreateType::Normal || *pte != 0 {
                let ret = cb(arg, pte, cur_va);
                if ret != 0 {
                    return ret;
                }
            }
            continue;
        }

        if level == 1 {
            if create == CreateType::Big || pte_big(*pte) {
                let ret = cb(arg, pte, cur_va);
                if ret != 0 {
                    return ret;
                }
                continue;
            }
        }

        if level == 2 {
            if create == CreateType::Big1GB || pte_big(*pte) {
                let ret = cb(arg, pte, cur_va);
                if ret != 0 {
                    return ret;
                }
                continue;
            }
        }

        if !pte_present(*pte) {
            if create == 0 {
                continue;
            }

            let new_pte = alloc_page();
            if new_pte.is_null() {
                return -libc::ENOMEM;
            }
            unsafe { ptr::write_bytes(new_pte, 0, PGSIZE) };
            *pte = PTE_ADDR!(new_pte) | PTE_DEF_FLAGS;
        }

        let n_start_va = if i == start_idx { start_va } else { cur_va };
        let n_end_va = if i == end_idx { end_va } else { (cur_va as usize + PDADDR!(level, 1) - 1) as *mut c_void };

        let ret = __dune_vm_page_walk(
            unsafe { &mut *(PTE_ADDR!(*pte) as *mut [PtEnt; PGSIZE / size_of::<PtEnt>()]) },
            n_start_va,
            n_end_va,
            cb,
            arg,
            level - 1,
            create,
        );
        if ret != 0 {
            return ret;
        }
    }

    0
}

pub fn dune_vm_page_walk(
    root: &mut [PtEnt],
    start_va: *mut c_void,
    end_va: *mut c_void,
    cb: PageWalkCb,
    arg: &c_void,
) -> i32 {
    __dune_vm_page_walk(root, start_va, end_va, cb, arg, 3, CreateType::None)
}

pub fn dune_vm_lookup(
    root: &mut [PtEnt],
    va: *mut c_void,
    create: i32,
    pte_out: &mut *mut PtEnt,
) -> i32 {
    let mut pml4 = root;
    let mut pdpte;
    let mut pde;
    let mut pte;

    let i = PDX!(3, va);
    let j = PDX!(2, va);
    let k = PDX!(1, va);
    let l = PDX!(0, va);

    if !pte_present(pml4[i]) {
        if create == 0 {
            return -libc::ENOENT;
        }

        pdpte = alloc_page();
        unsafe { ptr::write_bytes(pdpte, 0, PGSIZE) };

        pml4[i] = PTE_ADDR!(pdpte) | PTE_DEF_FLAGS;
    } else {
        pdpte = PTE_ADDR!(pml4[i]) as *mut PtEnt;
    }

    if !pte_present(pdpte[j]) {
        if create == 0 {
            return -libc::ENOENT;
        }

        pde = alloc_page();
        unsafe { ptr::write_bytes(pde, 0, PGSIZE) };

        pdpte[j] = PTE_ADDR!(pde) | PTE_DEF_FLAGS;
    } else if pte_big(pdpte[j]) {
        *pte_out = &mut pdpte[j];
        return 0;
    } else {
        pde = PTE_ADDR!(pdpte[j]) as *mut PtEnt;
    }

    if !pte_present(pde[k]) {
        if create == 0 {
            return -libc::ENOENT;
        }

        pte = alloc_page();
        unsafe { ptr::write_bytes(pte, 0, PGSIZE) };

        pde[k] = PTE_ADDR!(pte) | PTE_DEF_FLAGS;
    } else if pte_big(pde[k]) {
        *pte_out = &mut pde[k];
        return 0;
    } else {
        pte = PTE_ADDR!(pde[k]) as *mut PtEnt;
    }

    *pte_out = &mut pte[l];
    0
}

pub fn dune_vm_mprotect(
    root: &mut [PtEnt],
    va: *mut c_void,
    len: usize,
    perm: i32,
) -> i32 {
    if perm & PERM_R == 0 && perm & PERM_W != 0 {
        return -libc::EINVAL;
    }

    let pte_perm = get_pte_perm(perm);

    let ret = __dune_vm_page_walk(
        root,
        va,
        (va as usize + len - 1) as *mut c_void,
        &__dune_vm_mprotect_helper,
        &pte_perm as *const _ as *const c_void,
        3,
        CreateType::None,
    );
    if ret != 0 {
        return ret;
    }

    dune_flush_tlb();
    0
}

fn __dune_vm_mprotect_helper(arg: &c_void, pte: &mut PtEnt, _va: *mut c_void) -> i32 {
    let perm = arg as *const PtEnt;
    *pte = PTE_ADDR!(*pte) | (PTE_FLAGS!(*pte) & PTE_PS) | *perm;
    0
}

pub fn dune_vm_map_phys(
    root: &mut [PtEnt],
    va: *mut c_void,
    len: usize,
    pa: *mut c_void,
    perm: i32,
) -> i32 {
    let data = MapPhysData {
        perm: get_pte_perm(perm),
        va_base: va as usize,
        pa_base: pa as usize,
    };

    let create = if perm & PERM_BIG != 0 {
        CreateType::Big
    } else if perm & PERM_BIG_1GB != 0 {
        CreateType::Big1GB
    } else {
        CreateType::Normal
    };

    __dune_vm_page_walk(
        root,
        va,
        (va as usize + len - 1) as *mut c_void,
        &__dune_vm_map_phys_helper,
        &data as *const _ as *const c_void,
        3,
        create,
    )
}

struct MapPhysData {
    perm: PtEnt,
    va_base: usize,
    pa_base: usize,
}

fn __dune_vm_map_phys_helper(arg: &c_void, pte: &mut PtEnt, va: *mut c_void) -> i32 {
    let data = arg as *const MapPhysData;
    *pte = PTE_ADDR!(va as usize - data.va_base + data.pa_base) | data.perm;
    0
}

pub fn dune_vm_map_pages(
    root: &mut [PtEnt],
    va: *mut c_void,
    len: usize,
    perm: i32,
) -> i32 {
    if perm & PERM_R == 0 && perm & !PERM_R != 0 {
        return -libc::EINVAL;
    }

    let pte_perm = get_pte_perm(perm);

    __dune_vm_page_walk(
        root,
        va,
        (va as usize + len - 1) as *mut c_void,
        &__dune_vm_map_pages_helper,
        &pte_perm as *const _ as *const c_void,
        3,
        CreateType::Normal,
    )
}

fn __dune_vm_map_pages_helper(arg: &c_void, pte: &mut PtEnt, _va: *mut c_void) -> i32 {
    let perm = arg as *const PtEnt;
    let pg = dune_page_alloc();
    if pg.is_null() {
        return -libc::ENOMEM;
    }
    *pte = PTE_ADDR!(dune_page2pa(pg)) | *perm;
    0
}

pub fn dune_vm_clone(root: &mut [PtEnt]) -> *mut PtEnt {
    let new_root = alloc_page();
    if new_root.is_null() {
        return ptr::null_mut();
    }
    unsafe { ptr::write_bytes(new_root, 0, PGSIZE) };

    let ret = __dune_vm_page_walk(
        root,
        VA_START,
        VA_END,
        &__dune_vm_clone_helper,
        new_root as *const c_void,
        3,
        CreateType::None,
    );
    if ret < 0 {
        dune_vm_free(new_root as *mut PtEnt);
        return ptr::null_mut();
    }

    new_root as *mut PtEnt
}

fn __dune_vm_clone_helper(arg: &c_void, pte: &mut PtEnt, va: *mut c_void) -> i32 {
    let new_root = arg as *mut PtEnt;
    let mut new_pte = ptr::null_mut();

    let ret = dune_vm_lookup(new_root, va, CreateType::Normal, &mut new_pte);
    if ret < 0 {
        return ret;
    }

    if dune_page_isfrompool(PTE_ADDR!(*pte)) {
        dune_page_get(dune_pa2page(PTE_ADDR!(*pte)));
    }
    *new_pte = *pte;
    0
}

pub fn dune_vm_free(root: *mut PtEnt) {
    __dune_vm_page_walk(
        root,
        VA_START,
        VA_END,
        &__dune_vm_free_helper,
        ptr::null(),
        2,
        CreateType::None,
    );
    __dune_vm_page_walk(
        root,
        VA_START,
        VA_END,
        &__dune_vm_free_helper,
        ptr::null(),
        1,
        CreateType::None,
    );
    put_page(root as *mut c_void);
}

fn __dune_vm_free_helper(_arg: &c_void, pte: &mut PtEnt, _va: *mut c_void) -> i32 {
    let pg = dune_pa2page(PTE_ADDR!(*pte));
    if dune_page_isfrompool(PTE_ADDR!(*pte)) {
        dune_page_put(pg);
    }
    *pte = 0;
    0
}

pub fn dune_vm_unmap(root: &mut [PtEnt], va: *mut c_void, len: usize) {
    __dune_vm_page_walk(
        root,
        va,
        (va as usize + len - 1) as *mut c_void,
        &__dune_vm_free_helper,
        ptr::null(),
        3,
        CreateType::None,
    );
    dune_flush_tlb();
}

pub fn dune_vm_default_pgflt_handler(addr: usize, fec: u64) {
    let mut pte = ptr::null_mut();
    let rc = dune_vm_lookup(pgroot, addr as *mut c_void, 0, &mut pte);
    assert!(rc == 0);

    if (fec & FEC_W != 0) && (*pte & PTE_COW != 0) {
        let pg = dune_pa2page(PTE_ADDR!(*pte));
        let perm = PTE_FLAGS!(*pte) & !PTE_COW | PTE_W;

        if dune_page_isfrompool(PTE_ADDR!(*pte)) && (*pg).ref_count() == 1 {
            *pte = PTE_ADDR!(*pte) | perm;
            return;
        }

        let new_page = alloc_page();
        unsafe {
            ptr::copy_nonoverlapping(PGADDR!(addr) as *const u8, new_page as *mut u8, PGSIZE);
        }

        if dune_page_isfrompool(PTE_ADDR!(*pte)) {
            dune_page_put(pg);
        }
        *pte = PTE_ADDR!(new_page) | perm;
        dune_flush_tlb_one(addr);
    }
}
