/// This module provides functions and traits for managing page tables in a virtual memory system.
/// It includes functions for allocating, looking up, and translating virtual and physical addresses,
/// as well as initializing and updating page tables.
///
/// # Constants
///
/// - `MEMORY_POOL_START`: The start address of the memory pool.
/// - `MEMORY_POOL_END`: The end address of the memory pool.
///
/// # Static Variables
///
/// - `PGROOT`: A mutex-protected optional pointer to the root page table.
///
/// # Functions
///
/// - `pte_present`: Checks if a page table entry is present.
/// - `pte_big`: Checks if a page table entry is a huge page.
/// - `pte_big1gb`: Checks if a page table entry is a 1GB huge page.
/// - `pgtable_alloc`: Allocates a new page table and returns its virtual address.
///
/// # Traits
///
/// - `WithPageTable`: A trait for devices that use page tables. It provides methods for initializing,
///   looking up, and updating page tables, as well as translating addresses.
///
/// # Example
///
/// ```rust
/// use x86_64::VirtAddr;
/// use crate::WithPageTable;
///
/// struct MyDevice;
///
/// impl WithPageTable for MyDevice {
///     // Implement required methods...
/// }
///
/// let device = MyDevice;
/// let va = VirtAddr::new(0x1000);
/// let pa = device.pgtable_va_to_pa(va).unwrap();
/// println!("Physical address: {:?}", pa);
/// ```
///
/// # Errors
///
/// Functions in this module may return errors of type `Error`, which include:
///
/// - `Error::NotFound`: Indicates that a page table entry was not found.
/// - `Error::MappingFailed`: Indicates that memory mapping failed.
/// - `Error::AlreadyExists`: Indicates that a page table entry already exists.
/// - `Error::InvalidAddress`: Indicates that an address is invalid.
///
/// # Safety
///
/// Some functions in this module use unsafe code to manipulate raw pointers and perform low-level
/// memory operations. Care should be taken to ensure that these operations are safe and do not
/// cause undefined behavior.
use x86_64::structures::paging::page_table::PageTableEntry;
use x86_64::PhysAddr;
use x86_64::VirtAddr;
use std::arch::asm;
use std::ptr;
use std::sync::Mutex;
use lazy_static::lazy_static;
use x86::controlregs::cr3;
use x86_64::registers::control::Cr3;
use x86_64::registers::control::Cr3Flags;
use x86_64::structures::paging::PhysFrame;
use x86_64::structures::paging::PageTableFlags;
use x86_64::structures::paging::PageTable;
use x86_64::structures::paging::page_table::PageTableLevel;
use dune_sys::PGTABLE_MMAP_BASE;
use dune_sys::PGTABLE_MMAP_END;
use crate::VmplSystem;
use crate::DEVICE;
use crate::CreateType;
use crate::dune_page_init;
use crate::{dune_page_alloc, dune_page_free, dune_page_get, dune_page_put, dune_page_isfrompool, dune_page2pa, dune_pa2page, PAGE_SIZE, PAGEBASE, Result, Error};
use crate::MAX_PAGES;
use crate::WithPageManager;
use crate::AddressMapping;
use std::ptr::null_mut;
use libc::{mmap, MAP_FAILED, MAP_POPULATE, MAP_SHARED, PROT_READ, PROT_WRITE};

const MEMORY_POOL_START: u64 = PGTABLE_MMAP_BASE;
const MEMORY_POOL_END: u64 = PGTABLE_MMAP_END;

const PT_NAMES: [&str; 5] = ["P4D", "PUD", "PMD", "PTE", "Page"];
const PTE_C: u64 = 0x8000000000000000;
const PAGE_FLAG_MAPPED: u32 = 0x1;
const ADDR_MASK: u64 = 0x0000_ffff_ffff_f000;

#[macro_export]
macro_rules! pte_addr {
    ($x:expr) => {
        ($x & ADDR_MASK) as u64
    };
}

macro_rules! err {
    ($($arg:tt)*) => {
        Err(format!($($arg)*).into())
    };
}

fn pte_none(pte: &PageTableEntry) -> bool {
    pte.flags().is_empty()
}

fn pte_bad(pte: &PageTableEntry) -> bool {
    pte.flags().contains(PageTableFlags::WRITABLE)
}

fn pte_present(pte: &PageTableEntry) -> bool {
    pte.flags().contains(PageTableFlags::PRESENT)
}

fn pte_big(pte: &PageTableEntry) -> bool {
    pte.flags().contains(PageTableFlags::HUGE_PAGE)
}

fn pte_big1gb(pte: &PageTableEntry) -> bool {
    pte.flags().contains(PageTableFlags::HUGE_PAGE | PageTableFlags::BIT_9)
}

#[test]
fn pgtable_alloc() {
    dune_page_init();
    let pg = dune_page_alloc().unwrap();
    let pa = dune_page2pa(pg);
    let va = pgtable_pa_to_va(pa);
    assert!(pa >= PAGEBASE);
    assert!(va.as_u64() >= PGTABLE_MMAP_BASE);
    assert!(va.as_u64() < PGTABLE_MMAP_END);
    assert!(pa == PhysAddr::new(va.as_u64() - PGTABLE_MMAP_BASE));
    assert!(pg == unsafe { dune_pa2page(pa) });
    assert!(unsafe { (*pg).flags() } == PAGE_FLAG_MAPPED);
    unsafe { ptr::write_bytes(va.as_mut_ptr::<*mut PageTable>(), 0, PAGE_SIZE) };
    log::debug!("pg = 0x{:x}, pa = 0x{:x}, va = 0x{:x}, ref = {}", pg as u64, pa, va.as_u64(), unsafe { (*pg).ref_count() });
}

pub fn pgtable_lookup(va: VirtAddr) -> Result<&'static mut PageTableEntry> {
    let system = get_system::<dyn WithPageTable>();
    if let Some(system) = system {
        system.pgtable_lookup(va)
    } else {
        log::error!("pgtable_lookup: system does not implement WithPageTable");
        Err(Error::NotFound)
    }
}

pub fn pgtable_va_to_pa(va: VirtAddr) -> Result<PhysAddr> {
    let system = get_system::<dyn WithAddressTranslation>();
    if let Some(system) = system {
        system.va_to_pa(va).map_err(|e| {
            let system = get_system::<dyn WithPageTable>();
            if let Some(system) = system {
                system.pgtable_lookup(va)
            } else {
                log::error!("pgtable_va_to_pa: system does not implement WithPageTable");
                Err(Error::NotFound)
            }
        })
    } else {
        log::error!("pgtable_va_to_pa: system does not implement WithAddressTranslation");
        Err(Error::NotFound)
    }
}

pub fn pgtable_pa_to_va(pa: PhysAddr) -> Result<VirtAddr> {
    let system = get_system::<dyn WithAddressTranslation>();
    if let Some(system) = system {
        system.pa_to_va(pa)
    } else {
        log::error!("pgtable_pa_to_va: system does not implement WithAddressTranslation");
        Err(Error::NotFound)
    }
}

pub fn is_page_maped(pa: PhysAddr) -> bool {
    let pg = dune_pa2page(pa);
    unsafe { (*pg).flags() == PAGE_FLAG_MAPPED }
}

pub trait WithAddressTranslation {

    fn setup_address_translation(&mut self) -> Result<()>;

    fn va_to_pa(&self, va: VirtAddr) -> Result<PhysAddr>;

    fn pa_to_va(&self, pa: PhysAddr) -> Result<VirtAddr>;
}

pub trait WithPageTable : WithPageManager + WithAddressTranslation {

    // 获取当前进程的CR3寄存器值
    fn get_cr3(&self) -> Option<PhysAddr>;

    // 请求Guest OS线性映射一段物理地址
    fn do_mapping(&self, phys: PhysAddr, len: usize) -> Result<*mut PageTable>;

    // 获取当前系统的页表
    fn get_page_table(&self) -> Result<&mut PageTable>;

    // 递归遍历页表，并标记VMPL页面
    unsafe fn walk_page_table(&self, paddr: PhysAddr, level: PageTableLevel) -> Result<()> {
        // 如果是最底层页表，直接返回
        if level == PageTableLevel::One {
            return Ok(());
        }

        // 映射当前页表
        let table: *mut PageTable = self.do_mapping(paddr, PAGE_SIZE)?;
        
        // 只遍历顶层页表的前256项
        let max_entries = if level == PageTableLevel::Four { 256 } else { 512 };
        let next_level = level.next_lower_level().unwrap();

        // 遍历页表项
        for i in 0..max_entries {
            let pte = &(*table)[i];
            if pte_present(pte) {
                if pte_big(pte) || pte_big1gb(pte) {
                    // 大页直接标记
                    mark_vmpl_page(pte.addr());
                } else {
                    // 递归遍历下一级页表
                    self.walk_page_table(pte.addr(), next_level)?;
                }
            }
        }

        Ok(())
    }

    fn pgtable_init(&self) -> Result<()> {
        let paddr = self.get_cr3().unwrap();
        mark_vmpl_page(paddr);
        
        // 递归遍历页表
        unsafe {
            self.walk_page_table(paddr, PageTableLevel::Four)?;
        }
        Ok(())
    }

    fn pgtable_exit(&self) -> Result<()> {
        log::debug!("pgtable exit");
        Ok(())
    }

    fn pgtable_free(&self) -> Result<()> {
        log::debug!("pgtable free");
        Ok(())
    }

    fn pgtable_stats(&self) {
        log::info!("Page Table Stats:");
        println!("Page Table Stats:");
    }

    #[cfg(test)]
    fn pgtable_test(&self) -> Result<()> {
        log::info!("Page Table Test");
        let cr3 = self.get_cr3().unwrap();
        let pgd = self.get_page_table()?;
        let va = VirtAddr::from_ptr(pgd);
        let (pte, level) = self.lookup_address_in_pgd(va)?;
        assert_eq!(level, PageTableLevel::One);
        let (pte, level) = self.lookup_address(va)?;
        assert_eq!(level, PageTableLevel::One);
        let pte = self.pgtable_lookup(va)?;
        assert_eq!(pte.addr(), cr3);
        log::info!("Page Table Test Passed");
        Ok(())
    }

    // Clear the lower 12 bits of CR3
    fn load_cr3(&self, cr3: &mut VirtAddr) {
        let pa = self.va_to_pa(*cr3).unwrap();
        let mut cr3 = cr3.as_u64();
        cr3 &= !ADDR_MASK;
        cr3 |= PTE_C;
        cr3 |= pa.as_u64();
        unsafe {
            Cr3::write(PhysFrame::from_start_address(PhysAddr::new(cr3)).unwrap(), Cr3Flags::empty());
        }
    }

    fn alloc_pgtable(&self) -> Result<PhysAddr> {
        let manager = self.page_manager();
        let mut pm = manager.lock().unwrap();
        // 分配一个新的页
        let page = pm.dune_page_alloc(1).ok_or(Error::OutOfMemory)?;
        // 将页转换为物理地址
        let pa = pm.dune_page2pa(page);
        // 标记页面为VMPL页面
        mark_vmpl_page(pa);
        // 将页转换为虚拟地址
        let va = self.pa_to_va(pa)?;
        // 将页清零
        unsafe {
            ptr::write_bytes(va.as_mut_ptr::<PageTable>(), 0, PAGE_SIZE);
        }
        Ok(pa)
    }

    fn do_mapping_pgtable(&self, phys: PhysAddr) -> Result<&mut PageTable> {
        // Check if the page is already mapped
        if is_page_maped(phys) {
            log::debug!("already mapped {:?}", phys);
            let va = self.pa_to_va(phys)?;
            let addr = va.as_u64() as *mut PageTable;
            let pgd = unsafe { &mut *addr };
            return Ok(pgd);
        }

        // Mark the page as vmpl page
        mark_vmpl_page(phys);

        // Map the page to the virtual address space of the process.
        let va = self.do_mapping(phys, PAGE_SIZE)?;

        log::debug!("newly mapped phys {:x} to {:p}", phys, va);
        // log::debug!("content: {:x}", unsafe { *va });

        let pgd = unsafe { &mut *(va as *mut PageTable) };
        Ok(pgd)
    }

    fn pgtable_lookup(&self, va: VirtAddr) -> Result<&mut PageTableEntry> {
        self.get_page_table().map(|pgd| {
            let mut pgd = pgd;
            let indices = [
                (va.p4_index(), PageTableLevel::Four),
                (va.p3_index(), PageTableLevel::Three),
                (va.p2_index(), PageTableLevel::Two),
                (va.p1_index(), PageTableLevel::One),
            ];

            for &(index, current_level) in &indices {
                let pte = unsafe { &mut pgd[index] };
                if !pte_present(pte) {
                    // 不存在
                    return Err(Error::NotFound);
                } else if current_level < PageTableLevel::Three && pte_big(pte) {
                    // 是2M大页
                    return Ok(pte);
                } else if current_level < PageTableLevel::Two && pte_big1gb(pte) {
                    // 是1GB大页
                    return Ok(pte);
                }

                pgd = self.do_mapping_pgtable(pte.addr())?;
            }

            Ok(unsafe { &mut pgd[va.p1_index()] })
        })?
    }

    fn pgtable_create(&self, va: VirtAddr, create: CreateType) -> Result<&mut PageTableEntry> {
        self.get_page_table().map(|pgd| {
            let mut pgd = pgd;
            let indices = [
                va.p4_index(),
                va.p3_index(),
                va.p2_index(),
                va.p1_index(),
            ];

            for (level, &index) in indices.iter().enumerate() {
                let pte = unsafe { &mut (*pgd)[index] };
                if !pte_present(pte) {
                    if create == CreateType::None {
                        return Err(Error::NotFound);
                    }
                    let new_page = self.alloc_pgtable()?;
                    pte.set_addr(new_page, PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE);
                } else if level < 3 && pte_big(pte) {
                    return Ok(pte);
                } else if level < 2 && pte_big1gb(pte) {
                    return Ok(pte);
                }

                pgd = self.do_mapping_pgtable(pte.addr())?;
            }

            Ok(unsafe { &mut (*pgd)[va.p1_index()] })
        })?
    }

    fn pgtable_update_leaf_pte(&self, va: VirtAddr, pa: PhysAddr) -> Result<()> {
        let pte = self.pgtable_lookup(va)?;
        pte.set_addr(pa, PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE);
        Ok(())
    }

    fn lookup_address_in_pgd(&self, va: VirtAddr) -> Result<(&mut PageTableEntry, PageTableLevel)> {
        let mut pgd = self.get_page_table()?;
        let indices = [
            (va.p4_index(), PageTableLevel::Four),
            (va.p3_index(), PageTableLevel::Three),
            (va.p2_index(), PageTableLevel::Two),
            (va.p1_index(), PageTableLevel::One),
        ];

        for &(index, current_level) in &indices {
            let pte = unsafe { &mut (*pgd)[index] };
            if !pte_present(pte) {
                return Err(Error::NotFound);
            }
            if pte_big(pte) && current_level == PageTableLevel::Two {
                return Ok((pte, current_level));
            }
            if pte_big1gb(pte) && current_level == PageTableLevel::Three {
                return Ok((pte, current_level));
            }
            if current_level == PageTableLevel::One {
                return Ok((pte, current_level));
            }
            // 先看页表页是否存在线性映射
            pgd = self.do_mapping_pgtable(pte.addr())?;
        }

        Err(Error::NotFound)
    }

    fn lookup_address(&self, va: VirtAddr) -> Result<(&mut PageTableEntry, PageTableLevel)> {
        self.lookup_address_in_pgd(va)
    }

    fn remap_pfn_range(&self, vstart: VirtAddr, vend: VirtAddr, pstart: PhysAddr) -> Result<usize> {
        let mut num_pages = 0;
        let mut va = vstart;
        let mut pa = pstart;

        while va < vend {
            let (pte, _) = self.lookup_address(va)?;
            if pte_present(pte) {
                return Err(Error::AlreadyExists);
            }
            pte.set_addr(pa, PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE);
            va += PAGE_SIZE as u64;
            pa += PAGE_SIZE as u64;
            num_pages += 1;
        }

        Ok(num_pages)
    }

    fn remap_va_to_pa(&self, vstart: VirtAddr, vend: VirtAddr, pstart: PhysAddr) -> Result<()> {
        let mut va = vstart;
        while va < vend {
            // let pa = self.va_to_pa(va)?;
            self.pgtable_update_leaf_pte(va, pstart + (va - vstart))?;
            va += PAGE_SIZE as u64;
        }
        Ok(())
    }
}