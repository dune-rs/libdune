use dune_sys::*;

use x86_64::VirtAddr;
use crate::globals::{rd_rsp, PERM_BIG, PERM_R, PERM_U, PERM_W, PERM_X};
use crate::{dune_procmap_iterate, DuneProcmapEntry, ProcMapType, MAX_PAGES, PAGEBASE, PGSIZE};
use crate::core::{*};
use crate::mm::MmapArgs;
use crate::result::Result;

const VSYSCALL_ADDR: VirtAddr = VirtAddr::new(0xffffffffff600000);

#[cfg(all(feature = "dune", feature = "syscall"))]
fn setup_vsyscall() -> Result<()> {
    MmapArgs::default()
            .set_va(VSYSCALL_ADDR)
            .set_len(PGSIZE as u64)
            .set_perm(PERM_R | PERM_U)
            .map()
}

#[cfg(not(feature = "syscall"))]
fn setup_vsyscall() -> Result<()> {
    log::warn!("No vsyscall support");
    Ok(())
}


fn __setup_mappings_cb(ent: &DuneProcmapEntry) -> Result<()> {
    // page region already mapped
    if ent.begin() == VirtAddr::new(PAGEBASE.as_u64()) {
        return Ok(());
    }

    if ent.begin() == VSYSCALL_ADDR {
        setup_vsyscall();
        return Ok(());
    }

    MmapArgs::from(ent).map()
}

fn __setup_mappings_precise() -> Result<()> {
    MmapArgs::default()
            .set_va(VirtAddr::new(PAGEBASE.as_u64()))
            .set_len((MAX_PAGES * PGSIZE) as u64)
            .set_perm(PERM_R | PERM_W | PERM_BIG)
            .map()
            .and_then(|()| {
                dune_procmap_iterate(__setup_mappings_cb)
            })
}

fn setup_vdso_cb(ent: &DuneProcmapEntry) -> Result<()> {
    match ent.type_() {
        ProcMapType::Vdso
        | ProcMapType::Vvar => MmapArgs::from(ent).map(),
        _ => Ok(()),
    }
}

fn __setup_mappings_full(layout: &DuneLayout) -> Result<()> {
    MmapArgs::default()
            .set_va(VirtAddr::new(0))
            .set_len(1 << 32)
            .set_perm(PERM_R | PERM_W | PERM_X | PERM_U)
            .map()?;
    MmapArgs::default()
            .set_va(layout.base_map())
            .set_len(GPA_MAP_SIZE)
            .set_perm(PERM_R | PERM_W | PERM_X | PERM_U)
            .map()?;
    MmapArgs::default()
            .set_va(layout.base_stack())
            .set_len(GPA_STACK_SIZE)
            .set_perm(PERM_R | PERM_W | PERM_X | PERM_U)
            .map();
    MmapArgs::default()
            .set_va(VirtAddr::new(PAGEBASE.as_u64()))
            .set_len((MAX_PAGES * PGSIZE) as u64)
            .set_perm(PERM_R | PERM_W | PERM_BIG)
            .map();

    dune_procmap_iterate(setup_vdso_cb)?;
    setup_vsyscall()?;

    Ok(())
}

#[cfg(feature = "dune")]
pub fn setup_mappings(full: bool) -> Result<()> {
    let dune_vm = DUNE_VM.lock().unwrap();
    let layout = dune_vm.layout();

    if full {
        __setup_mappings_full(&layout)
    } else {
        __setup_mappings_precise()
    }
}

#[cfg(not(feature = "dune"))]
pub fn setup_mappings(full: bool) -> Result<()> {
    log::warn!("No dune support");
    Ok(())
}

pub fn map_ptr(p: VirtAddr, len: usize) -> Result<()> {
    // Align the pointer to the page size
    let page = p.align_down(PGSIZE as u64);
    let page_end = (p + len as u64).align_up(PGSIZE as u64);
    MmapArgs::default()
            .set_va(page)
            .set_len(page_end - page)
            .set_perm(PERM_R | PERM_W)
            .map()
}

fn map_stack_cb(e: &DuneProcmapEntry) -> Result<()> {
    let esp: u64 = rd_rsp();
    let addr = VirtAddr::new(esp);
    if addr >= e.begin() && addr < e.end() {
        map_ptr(e.begin(), e.len() as usize);
    }
    Ok(())
}

pub fn map_stack() -> Result<()> {
    dune_procmap_iterate(map_stack_cb)
}

pub trait DuneMapping {
    fn setup_mappings(&self, full: bool) -> Result<()>;
}

impl DuneMapping for DuneDevice {

    fn setup_mappings(&self, full: bool) -> Result<()> {
        setup_mappings(full)
    }
}