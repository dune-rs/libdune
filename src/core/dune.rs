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
use crate::dune_vm_lookup;
use crate::globals::{rd_rsp, PERM_BIG, PERM_NONE, PERM_R, PERM_U, PERM_W, PERM_X};
use crate::CreateType;
use crate::{dune_procmap_iterate, DuneProcmapEntry, ProcMapType, MAX_PAGES, PAGEBASE, PGSIZE};
use crate::{core::{PGROOT, *}, dune_vm_map_phys};
use crate::result::{Result, Error};

trait DuneLayoutI {
    fn mmap_addr_to_pa(&self, ptr: VirtAddr) -> PhysAddr;
    fn stack_addr_to_pa(&self, ptr: VirtAddr) -> PhysAddr;
    fn va_to_pa(&self, ptr: VirtAddr) -> PhysAddr;
}

impl DuneLayoutI for DuneLayout {
    fn mmap_addr_to_pa(&self, ptr: VirtAddr) -> PhysAddr {
        let base_map = self.base_map();
        let phys_limit = self.phys_limit();
        let addr = ptr.as_u64() - base_map.as_u64() + phys_limit.as_u64() - GPA_STACK_SIZE - GPA_MAP_SIZE;
        PhysAddr::new(addr)
    }

    fn stack_addr_to_pa(&self, ptr: VirtAddr) -> PhysAddr {
        let base_stack = self.base_stack();
        let phys_limit = self.phys_limit();
        let addr = ptr.as_u64() - base_stack.as_u64() + phys_limit.as_u64() - GPA_STACK_SIZE;
        PhysAddr::new(addr)
    }

    fn va_to_pa(&self, ptr: VirtAddr) -> PhysAddr {
        let base_map = self.base_map();
        let base_stack = self.base_stack();
        let phys_limit = self.phys_limit();
        if ptr >= base_stack {
            let addr = ptr.as_u64() - base_stack.as_u64() + phys_limit.as_u64() - GPA_STACK_SIZE;
            PhysAddr::new(addr)
        } else if ptr >= base_map {
            let addr = ptr.as_u64() - base_map.as_u64() + phys_limit.as_u64() - GPA_STACK_SIZE - GPA_MAP_SIZE;
            PhysAddr::new(addr)
        } else {
            PhysAddr::new(ptr.as_u64())
        }
    }
}

/// The physical address limit of the address space
///  ptr - MMAP_BASE + PHYS_LIMIT - GPA_STACK_SIZE - GPA_MAP_SIZE
///
fn dune_mmap_addr_to_pa(ptr: VirtAddr) -> PhysAddr {
    match LAYOUT.lock().and_then(|a|{
        let layout = &*a;
        Ok(layout.mmap_addr_to_pa(ptr))
    }) {
        Ok(pa) => pa,
        Err(_) => PhysAddr::new(0),
    }
}

/// The physical address limit of the address space
/// ptr - STACK_BASE + PHYS_LIMIT - GPA_STACK_SIZE
fn dune_stack_addr_to_pa(ptr: VirtAddr) -> PhysAddr {
    match LAYOUT.lock().and_then(|a|{
        let layout = &*a;
        Ok(layout.stack_addr_to_pa(ptr))
    }) {
        Ok(pa) => pa,
        Err(_) => PhysAddr::new(0),
    }
}

fn dune_va_to_pa(ptr: VirtAddr) -> PhysAddr {
    match LAYOUT.lock().and_then(|a|{
        let layout = &*a;
        Ok(layout.va_to_pa(ptr))
    }) {
        Ok(pa) => pa,
        Err(_) => PhysAddr::new(0),
    }
}

#[derive(Debug, Clone, Copy)]
struct MmapArgs {
    va: VirtAddr,
    len: u64,
    pa: PhysAddr,
    perm: i32,
}

impl MmapArgs {
    funcs!(va, VirtAddr);
    funcs!(len, u64);
    funcs!(pa, PhysAddr);
    funcs!(perm, i32);

    fn new(va: VirtAddr, len: u64, pa: PhysAddr, perm: i32) -> Self {
        Self { va, len, pa, perm }
    }

    pub fn map (&self) -> Result<()> {
        let root = &mut *PGROOT.lock().unwrap();
        dune_vm_map_phys(root, self.va, self.len, self.pa, self.perm)
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
        let pa = dune_va_to_pa(ent.begin());

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

        Self::new(ent.begin(), ent.len(), pa, perm)
    }
}

fn dune_vm_create(
    start: VirtAddr,
    pa: PhysAddr,
    flags: PageTableFlags,
    create: CreateType
) -> Result<()> {
    let root = &mut *PGROOT.lock().unwrap();
    dune_vm_lookup(root, start, create)
        .and_then(|pte| {
            pte.set_addr(pa, flags);
            Ok(())
        })
}

unsafe fn map_ptr(p: VirtAddr, len: usize) -> Result<()> {
    // Align the pointer to the page size
    let page = p.align_down(PGSIZE as u64);
    let page_end = (p + len as u64).align_down(PGSIZE as u64);
    let len = page_end - page + PGSIZE as u64;
    MmapArgs::default()
            .set_va(page)
            .set_len(len)
            .set_pa(dune_va_to_pa(page))
            .set_perm(PERM_R | PERM_W)
            .map()
}

#[cfg(feature = "dune")]
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

    let page = VirtAddr::new(page as u64);
    let root = &mut *PGROOT.lock().unwrap();
    for i in (0..=PGSIZE).step_by(PGSIZE) {
        let start = lstara + i as u64;
        let pa = dune_mmap_addr_to_pa(page + i as u64);
        dune_vm_create(start, pa, PageTableFlags::PRESENT, CreateType::Normal)?;
    }

    Ok(())
}

#[cfg(not(feature = "dune"))]
pub fn setup_syscall(fd: c_int) -> Result<()> {
    log::warn!("No syscall support");
    Ok(())
}

const VSYSCALL_ADDR: VirtAddr = VirtAddr::new(0xffffffffff600000);

#[cfg(feature = "dune")]
fn setup_vsyscall() -> Result<()> {
    let addr = dune_va_to_pa(VSYSCALL_ADDR);
    dune_vm_create(VSYSCALL_ADDR, addr,
            PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
            CreateType::Normal)?;
    Ok(())
}

#[cfg(not(feature = "dune"))]
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
            .set_pa(PAGEBASE)
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
            .set_pa(PhysAddr::new(0))
            .set_perm(PERM_R | PERM_W | PERM_X | PERM_U)
            .map()?;
    MmapArgs::default()
            .set_va(layout.base_map())
            .set_len(GPA_MAP_SIZE)
            .set_pa(dune_mmap_addr_to_pa(layout.base_map()))
            .set_perm(PERM_R | PERM_W | PERM_X | PERM_U)
            .map()?;
    MmapArgs::default()
            .set_va(layout.base_stack())
            .set_len(GPA_STACK_SIZE)
            .set_pa(dune_stack_addr_to_pa(layout.base_stack()))
            .set_perm(PERM_R | PERM_W | PERM_X | PERM_U)
            .map();
    MmapArgs::default()
            .set_va(VirtAddr::new(PAGEBASE.as_u64()))
            .set_len((MAX_PAGES * PGSIZE) as u64)
            .set_pa(dune_va_to_pa(VirtAddr::new(PAGEBASE.as_u64())))
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

    let _layout = &mut *LAYOUT.lock().unwrap();
    *_layout = unsafe { *layout };

    if full {
        __setup_mappings_full(_layout)
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