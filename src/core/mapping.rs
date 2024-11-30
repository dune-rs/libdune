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