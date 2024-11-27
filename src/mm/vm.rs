use std::{default, ptr};
use dune_sys::{funcs, DuneLayout};
use libc::c_void;
use nix::errno::Errno;
use x86_64::structures::paging::page_table::PageTableLevel;
use x86_64::structures::paging::PageTable;
use x86_64::VirtAddr;
use x86_64::{structures::paging::page_table::PageTableEntry, PhysAddr};
use x86_64::structures::paging::page_table::PageTableFlags;
use crate::{dune_flush_tlb, dune_flush_tlb_one, globals::*, DuneProcmapEntry, ProcMapType, DUNE_VM};
use crate::mm::*;
use dune_sys::result::{Result, Error};

// i << (12 + 9 * i)
macro_rules! PDADDR {
    ($n:expr, $i:expr) => {
        ($i as u64) << PDSHIFT!($n)
    };
}

#[repr(C)]
#[derive(Debug,Copy,Clone,PartialEq,Eq)]
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

#[repr(C)]
#[derive(Debug,Clone,PartialEq,Eq)]
struct MapPhysData {
    perm: PageTableFlags,
    va_base: VirtAddr,
    pa_base: PhysAddr,
}

impl MapPhysData {
    funcs!(perm, PageTableFlags);
    funcs!(va_base, VirtAddr);
    funcs!(pa_base, PhysAddr);
}

impl default::Default for MapPhysData {
    fn default() -> Self {
        MapPhysData {
            perm: PageTableFlags::empty(),
            va_base: VirtAddr::zero(),
            pa_base: PhysAddr::zero(),
        }
    }
}

pub type PageWalkCb<T> = fn(arg: *mut T, pte: &mut PageTableEntry, va: VirtAddr) -> Result<()>;

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

pub trait AddressMapping {
    fn mmap_addr_to_pa(&self, ptr: VirtAddr) -> PhysAddr;
    fn stack_addr_to_pa(&self, ptr: VirtAddr) -> PhysAddr;
    fn va_to_pa(&self, ptr: VirtAddr) -> PhysAddr;
}

impl AddressMapping for DuneLayout {
    fn mmap_addr_to_pa(&self, ptr: VirtAddr) -> PhysAddr {
        let base_map = self.base_map();
        let phys_limit = self.phys_limit();
        let addr = ptr.as_u64() - base_map.as_u64() + phys_limit.as_u64() - (GPA_STACK_SIZE + GPA_MAP_SIZE) as u64;
        PhysAddr::new(addr)
    }

    fn stack_addr_to_pa(&self, ptr: VirtAddr) -> PhysAddr {
        let base_stack = self.base_stack();
        let phys_limit = self.phys_limit();
        let addr = ptr.as_u64() - base_stack.as_u64() + phys_limit.as_u64() - GPA_STACK_SIZE as u64;
        PhysAddr::new(addr)
    }

    fn va_to_pa(&self, ptr: VirtAddr) -> PhysAddr {
        let base_map = self.base_map();
        let base_stack = self.base_stack();
        let phys_limit = self.phys_limit();
        if ptr >= base_stack {
            self.stack_addr_to_pa(ptr)
        } else if ptr >= base_map {
            self.mmap_addr_to_pa(ptr)
        } else {
            PhysAddr::new(ptr.as_u64())
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MmapArgs {
    va: VirtAddr,
    len: u64,
    perm: i32,
}

impl MmapArgs {
    funcs!(va, VirtAddr);
    funcs!(len, u64);
    funcs!(perm, i32);

    fn new(va: VirtAddr, len: u64, perm: i32) -> Self {
        Self { va, len, perm }
    }

    pub fn map (&self) -> Result<()> {
        let mut dune_vm = DUNE_VM.lock().unwrap();
        let pa = dune_vm.layout().va_to_pa(self.va);
        dune_vm.map_phys(self.va, self.len, pa, self.perm)
    }
}

impl Default for MmapArgs {
    fn default() -> Self {
        Self {
            va: VirtAddr::new(0),
            len: 0,
            perm: 0,
        }
    }
}

impl From<&DuneProcmapEntry> for MmapArgs {
    fn from(ent: &DuneProcmapEntry) -> Self {
        let mut perm = PERM_NONE;
        perm = match ent.type_() {
            ProcMapType::Vdso => PERM_U | PERM_R | PERM_X,
            ProcMapType::Vvar => PERM_U | PERM_R,
            _ => {
                if ent.r() {
                    perm |= PERM_R;
                }
                if ent.w() {
                    perm |= PERM_W;
                }
                if ent.x() {
                    perm |= PERM_X;
                }
                perm
            },
        };

        Self::new(ent.begin(), ent.len(), perm)
    }
}

pub struct DuneVm {
    root: PageTable,
    layout: DuneLayout,
}

impl DuneVm {

    funcs!(layout, DuneLayout);

    pub fn new() -> Self {
        DuneVm {
            root: PageTable::new(),
            layout: DuneLayout::default(),
        }
    }

    pub fn get_mut_root(&mut self) -> &mut PageTable {
        &mut self.root
    }

    fn __page_walk<T: Sized>(
        root: *mut PageTable,
        start_va: VirtAddr,
        end_va: VirtAddr,
        cb: PageWalkCb<T>,
        arg: *mut T,
        level: PageTableLevel,
        create: CreateType,
    ) -> Result<()>
    {
        let start_idx = start_va.page_table_index(level);
        let end_idx = end_va.page_table_index(level);
        let base_va = start_va.align_down(level.table_address_space_alignment());

        for i in start_idx..=end_idx {
            let idx: u64 = i.into();
            let cur_va = base_va + level.table_address_space_alignment() * idx;
            let pte: &mut PageTableEntry = unsafe { &mut (*root)[i] };

            // 4KB page
            if level == PageTableLevel::One {
                if create == CreateType::Normal || !pte.is_unused() {
                    cb(arg, pte, cur_va)?;
                }
                continue;
            }

            // 2MB page
            if level == PageTableLevel::Two && (create == CreateType::Big)
                || pte.flags().contains(PageTableFlags::HUGE_PAGE) {
                cb(arg, pte, cur_va)?;
                continue;
            }

            // 1GB page
            if level == PageTableLevel::Three && (create == CreateType::Big1GB)
                || pte.flags().contains(PageTableFlags::BIT_9) {
                cb(arg, pte, cur_va)?;
                continue;
            }

            if !pte.flags().contains(PageTableFlags::PRESENT) {
                if create == CreateType::None {
                    continue;
                }

                let ptep = alloc_page()
                    .map_or(Err(libc::ENOMEM), |addr|{
                        // zero_memory(new_pte as *mut u8, PGSIZE);
                        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
                        pte.set_addr(addr, flags);
                        // VA == PA
                        Ok(addr.as_u64() as *mut PageTable)
                    })?;
                // clear page
                unsafe {
                    ptr::write_bytes(ptep, 0, PGSIZE as usize);
                }
            }

            let n_start_va = if i == start_idx { start_va } else { cur_va };
            let pdaddr = level.table_address_space_alignment();
            let n_end_va = if i == end_idx { end_va } else { cur_va + pdaddr - 1 };

            let phys_addr = pte.addr();
            let virt_addr = phys_addr.as_u64();
            let sub_dir: *mut PageTable = virt_addr as *mut PageTable;
            if let Some(level) = level.next_lower_level() {
                DuneVm::__page_walk(sub_dir, n_start_va, n_end_va, cb, arg, level, create)?;
            }
        }

        Ok(())
    }

    pub fn page_walk<T>(
        root: *mut PageTable,
        start_va: VirtAddr,
        end_va: VirtAddr,
        cb: PageWalkCb<T>,
        arg: &mut T,
    ) -> Result<()>
    where
        T: Sized,
    {
        DuneVm::__page_walk(root, start_va, end_va, cb, arg, PageTableLevel::Three, CreateType::None)
    }

    pub fn lookup(
        root: &mut PageTable,
        addr: VirtAddr,
        create: CreateType,
    ) -> Result<&mut PageTableEntry> {
        let i = addr.p4_index(); // P4D
        let j = addr.p3_index(); // PMD
        let k = addr.p2_index(); // PD
        let l = addr.p1_index(); // PT
        let p4de = &mut root[i];
        let pdpt = if !p4de.flags().contains(PageTableFlags::PRESENT) {
            if create == CreateType::None {
                return Err(Error::from(libc::ENOENT))
            }

            let pdptep = alloc_page()
                .map_or(Err(libc::ENOMEM), |addr|{
                    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
                    p4de.set_addr(addr, flags);
                    // VA == PA
                    Ok(addr.as_u64() as *mut PageTable)
                })?;
            unsafe {
                // clear page
                ptr::write_bytes(pdptep, 0, PGSIZE as usize);
                &mut *(pdptep)
            }
        } else {
            unsafe { &mut *(p4de.addr().as_u64() as *mut PageTable) }
        };

        let pdpte = &mut pdpt[j];
        let pd = if !pdpte.flags().contains(PageTableFlags::PRESENT) {
            if create == CreateType::None {
                return Err(Error::LibcError(Errno::ENOENT));
            }

            let pdep = alloc_page()
                .map_or(Err(libc::ENOMEM), |addr|{
                    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
                    pdpte.set_addr(addr, flags);
                    // VA == PA
                    Ok(addr.as_u64() as *mut PageTable)
                })?;
            unsafe {
                // clear page
                ptr::write_bytes(pdep, 0, PGSIZE as usize);
                &mut *pdep
            }
        } else if pte_big1gb(pdpte) {
            return Ok(pdpte);
        } else {
            // VA == PA
            unsafe { &mut *(pdpte.addr().as_u64() as *mut PageTable) }
        };


        let pde = &mut pd[k];
        let pte = if !pte_present(pde) {
            if create == CreateType::None {
                return Err(Error::LibcError(Errno::ENOENT));
            }

            let ptep = alloc_page()
                .map_or(Err(libc::ENOMEM), |addr|{
                    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
                    pde.set_addr(addr, flags);
                    Ok(addr.as_u64() as *mut PageTable)
                })?;

            unsafe {
                ptr::write_bytes(ptep, 0, PGSIZE as usize);
                &mut *(ptep)
            }
        } else if pte_big(&pde) {
            return Ok(pde);
        } else {
            // VA == PA
            unsafe { &mut *(pde.addr().as_u64() as *mut PageTable) }
        };

        Ok(&mut pte[l])
    }

    pub fn mprotect(
        root: &mut PageTable,
        start_va: VirtAddr,
        len: u64,
        perm: i32,
    ) -> Result<()> {
        if perm & PERM_R == 0 && perm & PERM_W != 0 {
            return Err(Error::Unknown);
        }

        let mut pte_flags = get_pte_flags(perm);

        DuneVm::__page_walk(
            root, start_va, start_va + len - 1,
            DuneVm::__mprotect_helper,
            &mut pte_flags,
            PageTableLevel::Four,
            CreateType::None,
        ).and_then(|()| {
            dune_flush_tlb();
            Ok(())
        })
    }

    fn __mprotect_helper(flags: *mut PageTableFlags, pte: &mut PageTableEntry, _va: VirtAddr) -> Result<()> {
        let flags = unsafe { *flags };
        pte.set_flags(flags | (pte.flags() & PageTableFlags::HUGE_PAGE));
        Ok(())
    }

    pub fn map_phys(
        self: &mut DuneVm,
        va: VirtAddr,
        len: u64,
        pa: PhysAddr,
        perm: i32,
    ) -> Result<()> {
        let mut data = MapPhysData::default();
        data.set_perm(get_pte_flags(perm))
            .set_va_base(va)
            .set_pa_base(pa);

        let create = 
        if perm & PERM_BIG != 0 {
            CreateType::Big
        } else if perm & PERM_BIG_1GB != 0 {
            CreateType::Big1GB
        } else {
            CreateType::Normal
        };

        DuneVm::__page_walk(
            &mut self.root, va, (va) + len - 1,
            DuneVm::__map_phys_helper,
            &mut data,
            PageTableLevel::Four,
            create,
        )
    }

    fn __map_phys_helper(data: *mut MapPhysData, pte: &mut PageTableEntry, va: VirtAddr) -> Result<()> {
        let data = unsafe { &mut *data };
        let addr = PhysAddr::new(va - data.va_base + data.pa_base.as_u64());
        pte.set_addr(addr, data.perm);
        Ok(())
    }

    pub fn map_page(
        self: &mut DuneVm,
        start: VirtAddr,
        pa: PhysAddr,
        flags: PageTableFlags,
        create: CreateType
    ) -> Result<()> {
        DuneVm::lookup(&mut self.root, start, create)
            .and_then(|pte| {
                pte.set_addr(pa, flags);
                Ok(())
            })
    }

    pub fn map_pages(
        self: &mut DuneVm,
        // root: *mut PageTable,
        start_va: VirtAddr,
        len: u64,
        perm: i32,
    ) -> Result<()> {
        if perm & PERM_R == 0 && perm & !PERM_R != 0 {
            return Err(Error::Unknown);
        }

        let mut pte_flags = get_pte_flags(perm);

        DuneVm::__page_walk(
            &mut self.root, start_va, start_va + len - 1,
            DuneVm::__map_pages_helper,
            &mut pte_flags,
            PageTableLevel::Four,
            CreateType::Normal,
        )
    }

    fn __map_pages_helper(arg: *mut PageTableFlags , pte: &mut PageTableEntry, _va: VirtAddr) -> Result<()> {
        let page = alloc_page();
        page.and_then(|addr|{
            let dst = addr.as_u64() as u64 as *mut PageTable;
            unsafe {
                ptr::write_bytes(dst as *mut u8, 0, PGSIZE as usize);
                let flags = *(arg as *const PageTableFlags);
                pte.set_addr(addr, flags);
            }
            Some(())
        }).ok_or(Error::Unknown)
    }

    pub fn clone(root: *mut PageTable) -> Result<*mut PageTable> {
        let pa = alloc_page();
        pa.and_then(|pa|{
            let new_root = pa.as_u64() as *mut PageTable;
            unsafe { ptr::write_bytes(new_root, 0, PGSIZE as usize) };
            DuneVm::__page_walk(
                root, VA_START, VA_END,
                DuneVm::__clone_helper,
                new_root ,
                PageTableLevel::Four,
                CreateType::None,
            ).map_err(|_a|{
                DuneVm::free(new_root as *mut PageTable)
            }).and_then(|()|{
                Ok(new_root)
            }).ok()
        }).ok_or(Error::Unknown)
    }

    fn __clone_helper(arg: *mut PageTable, pte: &mut PageTableEntry, va: VirtAddr) -> Result<()> {
        let new_root = unsafe { &mut *(arg as *mut PageTable) };
        let ret = DuneVm::lookup(new_root, va, CreateType::Normal);
        ret.and_then(|a|{
            let new_pte = a;
            if dune_page_isfrompool(pte.addr()) {
                dune_page_get(dune_pa2page(pte.addr()));
            }
            new_pte.set_addr(pte.addr(), pte.flags());
            Ok(())
        })
    }

    pub fn free(root: *mut PageTable) -> Result<()>{
        DuneVm::__page_walk(
            root, VA_START, VA_END,
            DuneVm::__free_helper,
            ptr::null_mut() as *mut c_void,
            PageTableLevel::Three,
            CreateType::None,
        )?;
        DuneVm::__page_walk(
            root, VA_START, VA_END,
            DuneVm::__free_helper,
            ptr::null_mut() as *mut c_void,
            PageTableLevel::One,
            CreateType::None,
        )?;
        put_page(root as *mut c_void);
        Ok(())
    }

    fn __free_helper(_arg: *mut c_void, pte: &mut PageTableEntry, _va: VirtAddr) -> Result<()> {
        let pg = dune_pa2page(pte.addr());
        if dune_page_isfrompool(pte.addr()) {
            dune_page_put(pg);
        }

        pte.set_unused();
        Ok(())
    }

    pub fn unmap(root: *mut PageTable, va: VirtAddr, len: u64) -> Result<()> {
        DuneVm::__page_walk(
            root,
            va,va + len - 1,
            DuneVm::__free_helper,
            ptr::null_mut(),
            PageTableLevel::Four,
            CreateType::None,
        )?;
        dune_flush_tlb();
        Ok(())
    }

    pub unsafe fn default_pgflt_handler(self: &mut DuneVm, addr: VirtAddr, fec: u64) {
        let pte = DuneVm::lookup(&mut self.root, addr, CreateType::None).unwrap();

        let cow = pte.flags().contains(PageTableFlags::BIT_9);

        if (fec & FEC_W) != 0 && cow {
            let pg = dune_pa2page(pte.addr());

            // Compute new permissions, clear the COW bit, and set the writable bit
            let flags = pte.flags() & !PageTableFlags::BIT_9 | PageTableFlags::WRITABLE;
            if dune_page_isfrompool(pte.addr()) && (*pg).ref_count() == 1 {
                pte.set_flags(flags);
                return;
            }

            // Duplicate the page
            let addr = alloc_page();
            let _ = addr.map_or(Err(Error::Unknown), |addr|{
                let new_page = addr.as_u64() as *mut PageTable;
                // clear new page
                ptr::write_bytes(new_page, 0, PGSIZE as usize);

                // Copy the old page to the new page
                if dune_page_isfrompool(pte.addr()) {
                    dune_page_put(pg);
                }

                // Map page
                pte.set_addr(addr, flags);
                dune_flush_tlb_one(new_page as u64);
                Ok(())
            });
        }
    }
}
