use std::arch::asm;
use std::ptr;
use libc::c_void;
use x86_64::structures::paging::page_table::PageTableLevel;
use x86_64::structures::paging::PageTable;
use x86_64::structures::paging::PageTableIndex;
use x86_64::VirtAddr;
use x86_64::structures::paging::page_table::PageTableEntry;
use x86_64::structures::paging::page_table::PageTableFlags;
use crate::globals::*;
use crate::mm::*;
use crate::PGROOT;

// i << (12 + 9 * i)
macro_rules! PDADDR {
    ($n:expr, $i:expr) => {
        ($i as u64) << PDSHIFT!($n)
    };
}

pub const PTE_DEF_FLAGS: PageTableFlags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;

#[repr(C)]
#[derive(Debug,Clone,PartialEq,Eq)]
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

pub type PageWalkCb = fn(arg: *const c_void, pte: &mut PageTableEntry, va: VirtAddr) -> i32;

fn pte_present(pte: &PageTableEntry) -> bool {
    pte.flags().contains(PageTableFlags::PRESENT)
}

fn pte_big(pte: &PageTableEntry) -> bool {
    pte.flags().contains(PageTableFlags::HUGE_PAGE)
}

fn pte_big1gb(pte: &PageTableEntry) -> bool {
    pte.flags().contains(PageTableFlags::BIT_9)
}

fn alloc_page() -> Option<PhysAddr> {

    let pg = dune_page_alloc();
    if let Ok(pg) = pg {
        let pa = dune_page2pa(pg);
        return Some(pa);
    }

    return None;
}

pub fn put_page(page: *mut c_void) {
    let pg = dune_pa2page(PhysAddr::new(page as u64));
    dune_page_put(pg);
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
    root: *mut PageTable,
    start_va: VirtAddr,
    end_va: VirtAddr,
    cb: PageWalkCb,
    arg: *const c_void,
    level: PageTableLevel,
    create: CreateType,
) -> i32 {

    let start_idx = start_va.page_table_index(level);
    let end_idx = end_va.page_table_index(level);
    let base_va = start_va.align_down(level.table_address_space_alignment());

    for i in start_idx..=end_idx {
        let cur_va = base_va + level.table_address_space_alignment() * i.into_u64();
        let pte: &mut PageTableEntry = unsafe { &mut (*root)[i] };

        // 4KB page
        if level == PageTableLevel::One {
            if create == CreateType::Normal || !pte.is_unused() {
                cb(arg, pte, cur_va);
            }
            continue;
        }

        // 2MB page
        if level == PageTableLevel::Two && (create == CreateType::Big)
            || pte.flags().contains(PageTableFlags::HUGE_PAGE) {
            cb(arg, pte, cur_va);
            continue;
        }

        // 1GB page
        if level == PageTableLevel::Three && (create == CreateType::Big1GB)
            || pte.flags().contains(PageTableFlags::BIT_9) {
            cb(arg, pte, cur_va);
            continue;
        }

        if !pte.flags().contains(PageTableFlags::PRESENT) {
            if create == CreateType::None {
                continue;
            }

            let new_pte = alloc_page();
            new_pte.map_or(-libc::ENOMEM, |addr|{
                // zero_memory(new_pte as *mut u8, PGSIZE);
                let flags = PTE_DEF_FLAGS;
                pte.set_addr(addr, flags);
                0
            });
        }

        let n_start_va = if i == start_idx { start_va } else { cur_va };
        let pdaddr = level.table_address_space_alignment();
        let n_end_va = if i == end_idx { end_va } else { cur_va + pdaddr - 1 };

        let phys_addr = pte.addr();
        let virt_addr = phys_addr.as_u64();
        let sub_dir: *mut PageTable = virt_addr as *mut PageTable;
        level.next_lower_level().and_then(|level|{
            __dune_vm_page_walk(sub_dir, n_start_va, n_end_va, cb, arg, level, create);
            None
        });
    }

    0
}

pub fn dune_vm_page_walk(
    root: *mut PageTable,
    start_va: VirtAddr,
    end_va: VirtAddr,
    cb: PageWalkCb,
    arg: *const c_void,
) -> i32 {
    __dune_vm_page_walk(root, start_va, end_va, cb, arg, PageTableLevel::Three, CreateType::None)
}

pub fn dune_vm_lookup(
    root: &mut PageTable,
    addr: VirtAddr,
    create: CreateType,
) -> Result<&mut PageTableEntry, i32> {
    let pml4 = root;
    let pdpte: &mut PageTable;
    let pde: &mut PageTable;
    let pte: &mut PageTable;

    let i = addr.p4_index();
    if !pml4[i].flags().contains(PageTableFlags::PRESENT) {
        if create == CreateType::None {
            return Err(-libc::ENOENT);
        }

        let page = alloc_page();
        // None return -ENOMEM

        page.map_or(Err(-libc::ENOMEM), |page|{
            // unsafe { ptr::write_bytes(page, 0, PGSIZE as usize) };
            pml4[i].set_addr(page, PTE_DEF_FLAGS);
            Ok(&mut pml4[i])
        });
    }

    pdpte = unsafe { &mut *(pml4[i].addr().as_u64() as *mut PageTable) };

    let j = addr.p3_index();
    if !pdpte[j].flags().contains(PageTableFlags::PRESENT) {
        if create == CreateType::None {
            return Err(-libc::ENOENT);
        }

        let page = alloc_page();
        page.map_or(-libc::ENOMEM, |page|{
            // unsafe { ptr::write_bytes(page, 0, PGSIZE as usize) };
            pdpte[j].set_addr(page, PTE_DEF_FLAGS);
            0
        });
    } else if pte_big1gb(&pdpte[j]) {
        return Ok(&mut pdpte[j]);
    }

    // VA == PA
    pde = unsafe { &mut *(pdpte[j].addr().as_u64() as *mut PageTable) };

    let k = addr.p2_index();
    if !pte_present(&pde[k]) {
        if create == CreateType::None {
            return Err(-libc::ENOENT);
        }

        let page = alloc_page();
        page.map_or(-libc::ENOMEM, |page|{
            // unsafe { ptr::write_bytes(page, 0, PGSIZE as usize) };
            pde[k].set_addr(page, PTE_DEF_FLAGS);
            0
        });
    } else if pte_big(&pde[k]) {
        return Ok(&mut pde[k]);
    }
    // VA == PA
    pte = unsafe { &mut *(pde[k].addr().as_u64() as *mut PageTable) };

    let l = addr.p1_index();
    Ok(&mut pte[l])
}

pub fn dune_vm_mprotect(
    root: &mut PageTable,
    va: VirtAddr,
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
        va + len - 1,
        __dune_vm_mprotect_helper,
        &pte_flags as *const _ as *const c_void,
        PageTableLevel::Four,
        CreateType::None,
    );
    if ret != 0 {
        return ret;
    }

    unsafe { dune_flush_tlb() };
    0
}

fn __dune_vm_mprotect_helper(arg: *const c_void, pte: &mut PageTableEntry, _va: VirtAddr) -> i32 {
    unsafe{
        let flags = *(arg as *const PageTableFlags);
        pte.set_flags(flags | (pte.flags() & PageTableFlags::HUGE_PAGE));
    }
    0
}

pub fn dune_vm_map_phys(
    root: &mut PageTable,
    va: VirtAddr,
    len: u64,
    pa: PhysAddr,
    perm: i32,
) -> i32 {
    let data = MapPhysData {
        perm: get_pte_flags(perm),
        va_base: va,
        pa_base: pa,
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
        (va) + len - 1,
        __dune_vm_map_phys_helper,
        &data as *const _ as *const c_void,
        PageTableLevel::Four,
        create,
    )
}

struct MapPhysData {
    perm: PageTableFlags,
    va_base: VirtAddr,
    pa_base: PhysAddr,
}

// import PyhsAddr
use x86_64::PhysAddr;

fn __dune_vm_map_phys_helper(arg: *const c_void, pte: &mut PageTableEntry, va: VirtAddr) -> i32 {
    // convert arg to MapPhysData
    unsafe {
        let data = (arg as *const MapPhysData).as_ref().unwrap();
        let addr = PhysAddr::new(va - data.va_base + data.pa_base.as_u64());
        pte.set_addr(addr, data.perm);
        0
    }
}

pub fn dune_vm_map_pages(
    root: *mut PageTable,
    va: VirtAddr,
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
        va + len - 1,
        __dune_vm_map_pages_helper,
        &pte_flags as *const _ as *const c_void,
        PageTableLevel::Four,
        CreateType::Normal,
    )
}

fn __dune_vm_map_pages_helper(arg: *const c_void, pte: &mut PageTableEntry, _va: VirtAddr) -> i32 {
    let page = alloc_page();
    page.and_then(|addr|{
        let dst = addr.as_u64() as u64 as *mut c_void;
        unsafe { ptr::write_bytes(dst as *mut u8, 0, PGSIZE as usize) };
        unsafe {
            let flags = *(arg as *const PageTableFlags);
            pte.set_addr(addr, flags);
        }
        Some(0)
    }
    ).map_or(-libc::ENOMEM, |a| a)
}

pub fn dune_vm_clone(root: *mut PageTable) -> *mut PageTable {
    let pa = alloc_page();
    pa.and_then(|pa|{
        let new_root = pa.as_u64() as *mut PageTable;
        unsafe { ptr::write_bytes(new_root, 0, PGSIZE as usize) };
        let ret = __dune_vm_page_walk(
            root,
            VirtAddr::from_ptr(VA_START),
            VirtAddr::from_ptr(VA_END),
            __dune_vm_clone_helper,
            new_root as *const c_void,
            PageTableLevel::Four,
            CreateType::None,
        );
        if ret < 0 {
            dune_vm_free(new_root as *mut PageTable);
            return None;
        }
        Some(new_root as *mut PageTable)
    }).map_or(ptr::null_mut(), |a| a)
}

fn __dune_vm_clone_helper(arg: *const c_void, pte: &mut PageTableEntry, va: VirtAddr) -> i32 {
    let new_root = unsafe { &mut *(arg as *mut PageTable) };
    let ret = dune_vm_lookup(new_root, va, CreateType::Normal);
    match ret {
        Ok(new_pte) => {
            if dune_page_isfrompool(pte.addr()) {
                dune_page_get(dune_pa2page(pte.addr()));
            }
            new_pte.set_addr(pte.addr(), pte.flags());
            0
        }
        Err(_) => {
            return -libc::ENOMEM;
        }
    }
}

pub fn dune_vm_free(root: *mut PageTable) {
    __dune_vm_page_walk(
        root,
        VirtAddr::from_ptr(VA_START),
        VirtAddr::from_ptr(VA_END),
        __dune_vm_free_helper,
        ptr::null(),
        PageTableLevel::Three,
        CreateType::None,
    );
    __dune_vm_page_walk(
        root,
        VirtAddr::from_ptr(VA_START),
        VirtAddr::from_ptr(VA_END),
        __dune_vm_free_helper,
        ptr::null(),
        PageTableLevel::One,
        CreateType::None,
    );
    put_page(root as *mut c_void);
}

fn __dune_vm_free_helper(_arg: *const c_void, pte: &mut PageTableEntry, _va: VirtAddr) -> i32 {
    let pg = dune_pa2page(pte.addr());
    if dune_page_isfrompool(pte.addr()) {
        dune_page_put(pg);
    }

    pte.set_unused();
    0
}

pub fn dune_vm_unmap(root: *mut PageTable, va: VirtAddr, len: u64) {
    __dune_vm_page_walk(
        root,
        va,va + len - 1,
        __dune_vm_free_helper,
        ptr::null_mut(),
        PageTableLevel::Four,
        CreateType::None,
    );
    unsafe { dune_flush_tlb() };
}

pub unsafe fn dune_vm_default_pgflt_handler(addr: VirtAddr, fec: u64) {
    // let pte: *mut PageTableEntry = ptr::null_mut();
    let pte = dune_vm_lookup(PGROOT, addr, CreateType::None)?;

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
        let addr = alloc_page();
        // if alloc_page fails, we should panic
        addr.and_then(|addr|{
            let new_page = addr.as_u64() as *mut c_void;
            // clear new page
            ptr::write_bytes(new_page, 0, PGSIZE as usize);

            // Copy the old page to the new page
            if dune_page_isfrompool(pte.addr()) {
                dune_page_put(pg);
            }

            // Map page
            pte.set_addr(addr, flags);
            unsafe { dune_flush_tlb_one(new_page as u64) };
            None
        });
    }
}
