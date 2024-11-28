use x86_64::structures::paging::page_table::PageTableEntry;
use x86_64::PhysAddr;
use x86_64::VirtAddr;

use crate::Error;

pub fn pgtable_lookup(va: VirtAddr) -> &'static mut PageTableEntry {
    todo!();
}

pub fn pgtable_va_to_pa(va: VirtAddr) -> PhysAddr {
    todo!();
}

pub fn pgtable_pa_to_va(pa: PhysAddr)  -> VirtAddr {
    todo!();
}

pub trait WithPageTable {

    fn pgtable_va_to_pa(&self, va: VirtAddr) -> PhysAddr;

    fn pgtable_pa_to_va(&self, pa: PhysAddr) -> VirtAddr;
}
