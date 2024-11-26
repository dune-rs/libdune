use std::ptr;
use libc::c_int;
use libc::ioctl;
use dune_sys::*;
use libc::mmap;
use libc::MAP_ANON;
use libc::MAP_FAILED;
use libc::MAP_PRIVATE;
use libc::PROT_EXEC;
use libc::PROT_READ;
use libc::PROT_WRITE;
use x86_64::structures::paging::PageTable;
use x86_64::structures::paging::PageTableFlags;
use x86_64::{PhysAddr, VirtAddr};
use crate::globals::{rd_rsp, PERM_BIG, PERM_NONE, PERM_R, PERM_U, PERM_W, PERM_X};
use crate::CreateType;
use crate::{dune_procmap_iterate, DuneProcmapEntry, ProcMapType, MAX_PAGES, PAGEBASE, PGSIZE};
use crate::core::{*};
use crate::result::{Result, Error};
use crate::mm::DuneLayoutI;

#[derive(Debug, Clone, Copy)]
struct MmapArgs {
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
            pa: PhysAddr::new(0),
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

unsafe fn map_ptr(p: VirtAddr, len: usize) -> Result<()> {
    // Align the pointer to the page size
    let page = p.align_down(PGSIZE as u64);
    let page_end = (p + len as u64).align_down(PGSIZE as u64);
    let len = page_end - page + PGSIZE as u64;
    let dune_vm = DUNE_VM.lock().unwrap();
    MmapArgs::default()
            .set_va(page)
            .set_len(len)
            .set_perm(PERM_R | PERM_W)
            .map()
}

#[cfg(all(feature = "dune", feature = "syscall"))]
pub fn setup_syscall(fd: c_int) -> Result<()> {
    let lstar = unsafe { ioctl(fd, DUNE_GET_SYSCALL) };
    if lstar == -1 {
        return Err(Error::Unknown);
    }

    let page = unsafe { mmap(ptr::null_mut(),
                                (PGSIZE * 2) as usize,
                                PROT_READ | PROT_WRITE | PROT_EXEC,
                                MAP_PRIVATE | MAP_ANON,
                                -1,
                                0) };

    if page == MAP_FAILED {
        return Err(Error::Unknown);
    }

    // calculate the page-aligned address
    let lstar = VirtAddr::new(lstar as u64);
    let lstara = lstar.align_down(align_of::<PageTable>() as u64);
    let off = lstar - lstara;

    unsafe {
        ptr::copy_nonoverlapping(
            __dune_syscall as *const u8,
            (page as *mut u8).add(off as usize),
            __dune_syscall_end as usize - __dune_syscall as usize,
        );
    }

    MmapArgs::default()
            .set_va(lstara)
            .set_len((PGSIZE * 2) as u64)
            .set_perm(PERM_R)
            .map()
}

#[cfg(not(feature = "syscall"))]
pub fn setup_syscall(fd: c_int) -> Result<()> {
    log::warn!("No syscall support");
    Ok(())
}

const VSYSCALL_ADDR: VirtAddr = VirtAddr::new(0xffffffffff600000);

#[cfg(all(feature = "dune", feature = "syscall"))]
fn setup_vsyscall() -> Result<()> {
    let mut dune_vm = DUNE_VM.lock().unwrap();
    let addr = dune_vm.layout().va_to_pa(VSYSCALL_ADDR);
    dune_vm.map_page(VSYSCALL_ADDR, addr,
            PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
            CreateType::Normal)?;
    Ok(())
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
pub fn setup_mappings(fd: c_int, full: bool) -> Result<()> {
    let layout = &mut DuneLayout::default() as *mut DuneLayout;
    let ret = unsafe { ioctl(fd, DUNE_GET_LAYOUT, layout) };
    if ret != 0 {
        return Err(Error::Unknown);
    }

    let mut dune_vm = DUNE_VM.lock().unwrap();
    dune_vm.set_layout(unsafe { *layout });

    if full {
        __setup_mappings_full(unsafe { &*layout })
    } else {
        __setup_mappings_precise()
    }
}

#[cfg(not(feature = "dune"))]
pub fn setup_mappings(fd: c_int, full: bool) -> Result<()> {
    log::warn!("No dune support");
    Ok(())
}

fn map_stack_cb(e: &DuneProcmapEntry) -> Result<()> {
    let esp: u64 = rd_rsp();
    let addr = VirtAddr::new(esp);
    if addr >= e.begin() && addr < e.end() {
        unsafe { map_ptr(e.begin(), e.len() as usize) };
    }
    Ok(())
}

fn map_stack() -> Result<()> {
    dune_procmap_iterate(map_stack_cb)
}

pub trait DuneSyscall {
    fn map_ptr(&self, p: VirtAddr, len: usize) -> Result<()>;
    fn map_stack(&self) -> Result<()>;
    #[cfg(feature = "syscall")]
    fn setup_syscall(&self) -> Result<()>;
    fn setup_vsyscall(&self) -> Result<()>;
    fn setup_mappings(&self, full: bool) -> Result<()>;
}

impl DuneSyscall for DuneDevice {

    fn map_ptr(&self, p: VirtAddr, len: usize) -> Result<()> {
        unsafe { map_ptr(p, len) }
    }

    fn map_stack(&self) -> Result<()> {
        map_stack()
    }

    #[cfg(feature = "syscall")]
    fn setup_syscall(&self) -> Result<()> {
        setup_syscall(self.fd())
    }

    fn setup_vsyscall(&self) -> Result<()> {
        setup_vsyscall()
    }

    fn setup_mappings(&self, full: bool) -> Result<()> {
        setup_mappings(self.fd(), full)
    }
}