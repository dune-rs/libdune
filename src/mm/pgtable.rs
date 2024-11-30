use x86_64::structures::paging::page_table::PageTableEntry;
use x86_64::PhysAddr;
use x86_64::VirtAddr;
use crate::{Result, Error};

pub fn pgtable_lookup(va: VirtAddr) -> Result<&'static mut PageTableEntry> {
    panic!("pgtable_lookup not implemented");
}

pub fn pgtable_va_to_pa(va: VirtAddr) -> PhysAddr {
    panic!("pgtable_va_to_pa not implemented");
}

pub fn pgtable_pa_to_va(pa: PhysAddr)  -> VirtAddr {
    panic!("pgtable_pa_to_va not implemented");
}

pub trait WithAddressTranslation {

    fn setup_address_translation(&mut self) -> Result<()>;

    fn va_to_pa(&self, va: VirtAddr) -> Result<PhysAddr>;

    fn pa_to_va(&self, pa: PhysAddr) -> Result<VirtAddr>;
}

pub trait WithPageTable {

    fn pgtable_va_to_pa(&self, va: VirtAddr) -> PhysAddr;

    fn pgtable_pa_to_va(&self, pa: PhysAddr) -> VirtAddr;
}
