use dune_sys::*;

use x86_64::VirtAddr;
use crate::mm::Permissions;
use crate::{dune_procmap_iterate, DuneProcmapEntry, ProcMapType, MAX_PAGES, PAGEBASE, PGSIZE};
use crate::mm::MmapArgs;
use crate::utils::rd_rsp;
use x86_64::PhysAddr;
use crate::mm::AddressMapping;
use crate::WithAddressTranslation;
use crate::DUNE_VM;
use dune_sys::result::Result;

const VSYSCALL_ADDR: VirtAddr = VirtAddr::new(0xffffffffff600000);

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

#[cfg(all(feature = "dune", feature = "syscall"))]
fn setup_vsyscall() -> Result<()> {
    MmapArgs::default()
            .set_va(VSYSCALL_ADDR)
            .set_len(PGSIZE as u64)
            .set_perm(Permissions::R | Permissions::U)
            .map()
}

#[cfg(not(feature = "syscall"))]
fn setup_vsyscall() -> Result<()> {
    log::warn!("No vsyscall support");
    Ok(())
}

fn __setup_mappings_precise() -> Result<()> {
    MmapArgs::default()
            .set_va(VirtAddr::new(PAGEBASE.as_u64()))
            .set_len((MAX_PAGES * PGSIZE) as u64)
            .set_perm(Permissions::R | Permissions::W | Permissions::BIG)
            .map()?;

    dune_procmap_iterate(|ent|{
        // page region already mapped
        if ent.begin() == VirtAddr::new(PAGEBASE.as_u64()) {
            return Ok(());
        }

        if ent.begin() == VSYSCALL_ADDR {
            setup_vsyscall()?;
            return Ok(());
        }

        MmapArgs::from(ent).map()
    })
}

fn __setup_mappings_full(layout: &DuneLayout) -> Result<()> {
    MmapArgs::default()
            .set_va(VirtAddr::new(0))
            .set_len(1 << 32)
            .set_perm(Permissions::R | Permissions::W | Permissions::X | Permissions::U)
            .map()?;
    MmapArgs::default()
            .set_va(layout.base_map())
            .set_len(GPA_MAP_SIZE)
            .set_perm(Permissions::R | Permissions::W | Permissions::X | Permissions::U)
            .map()?;
    MmapArgs::default()
            .set_va(layout.base_stack())
            .set_len(GPA_STACK_SIZE)
            .set_perm(Permissions::R | Permissions::W | Permissions::X | Permissions::U)
            .map()?;
    MmapArgs::default()
            .set_va(VirtAddr::new(PAGEBASE.as_u64()))
            .set_len((MAX_PAGES * PGSIZE) as u64)
            .set_perm(Permissions::R | Permissions::W | Permissions::BIG)
            .map()?;

    dune_procmap_iterate(| ent |{
        match ent.type_() {
            ProcMapType::Vdso
            | ProcMapType::Vvar => MmapArgs::from(ent).map(),
            _ => Ok(()),
        }
    })?;
    setup_vsyscall()?;

    Ok(())
}

pub fn map_ptr(p: VirtAddr, len: usize) -> Result<()> {
    // Align the pointer to the page size
    let page = p.align_down(PGSIZE as u64);
    let page_end = (p + len as u64).align_up(PGSIZE as u64);
    MmapArgs::default()
            .set_va(page)
            .set_len(page_end - page)
            .set_perm(Permissions::PERM_STEXT)
            .map()
}

pub fn map_stack() -> Result<()> {
    dune_procmap_iterate(|e|{
        let esp: u64 = rd_rsp();
        let addr = VirtAddr::new(esp);
        if addr >= e.begin() && addr < e.end() {
            let _ = map_ptr(e.begin(), e.len() as usize);
        }
        Ok(())
    })
}

pub trait DuneMapping : WithAddressTranslation {

    fn get_layout(&self) -> Result<DuneLayout>;

    fn setup_mappings(&mut self, full: bool) -> Result<()> {
        self.setup_address_translation()?;
        let layout = self.get_layout()?;
        let mut dune_vm = DUNE_VM.lock().unwrap();
        dune_vm.set_layout(layout);

        if full {
            __setup_mappings_full(&layout)
        } else {
            __setup_mappings_precise()
        }
    }
}