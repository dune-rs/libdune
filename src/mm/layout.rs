use x86_64::{VirtAddr, PhysAddr};
use dune_sys::result::{Result, Error};
use dune_sys::{GPA_STACK_SIZE, GPA_MAP_SIZE, DuneLayout, VmplLayout};
use crate::mm::AddressMapping;

// 分段线性映射虚拟页
impl AddressMapping for DuneLayout {

    fn va_to_pa(&self, ptr: VirtAddr) -> Result<PhysAddr> {
        let base_map = self.base_map();
        let base_stack = self.base_stack();
        let phys_limit = self.phys_limit();
        let pa = if ptr >= base_stack {
            PhysAddr::new(ptr.as_u64() - base_stack.as_u64() + phys_limit.as_u64() - GPA_STACK_SIZE as u64)
        } else if ptr >= base_map {
            PhysAddr::new(ptr.as_u64() - base_map.as_u64() + phys_limit.as_u64() - (GPA_STACK_SIZE + GPA_MAP_SIZE) as u64)
        } else {
            PhysAddr::new(ptr.as_u64())
        };
        Ok(pa)
    }

    fn pa_to_va(&self, ptr: PhysAddr) -> Result<VirtAddr> {
        let base_map = self.base_map();
        let base_stack = self.base_stack();
        let phys_limit = self.phys_limit();
        let addr = ptr.as_u64();
        let va = if addr >= phys_limit.as_u64() - GPA_STACK_SIZE as u64 {
            VirtAddr::new(addr + base_stack.as_u64() - phys_limit.as_u64() + GPA_STACK_SIZE as u64)
        } else if addr >= phys_limit.as_u64() - (GPA_STACK_SIZE + GPA_MAP_SIZE) as u64 {
            VirtAddr::new(addr + base_map.as_u64() - phys_limit.as_u64() + (GPA_STACK_SIZE + GPA_MAP_SIZE) as u64)
        } else {
            VirtAddr::new(addr)
        };
        Ok(va)
    }
}

// 仅线性映射页表页
impl AddressMapping for VmplLayout {

    fn va_to_pa(&self, va: VirtAddr) -> Result<PhysAddr> {
        if va > self.mmap_base() && va < self.mmap_end() {
            Ok(PhysAddr::new(va.as_u64() - self.mmap_base().as_u64() + self.phys_base().as_u64()))
        } else {
            // 需要查询页表
            Err(Error::InvalidAddress)
        }
    }

    fn pa_to_va(&self, pa: PhysAddr) -> Result<VirtAddr> {
        if pa > self.phys_base() && pa < self.phys_end() {
            Ok(VirtAddr::new(pa.as_u64() - self.phys_base().as_u64() + self.mmap_base().as_u64()))
        } else {
            // 物理地址无效
            Err(Error::InvalidAddress)
        }
    }
}