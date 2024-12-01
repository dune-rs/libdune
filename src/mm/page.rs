use std::sync::{Mutex, MutexGuard};
use std::ptr;
use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::collections::LinkedList;
use std::os::unix::io::RawFd;
use std::ffi::c_void;
use std::slice;
use std::sync::Arc;
use std::fmt;
use std::vec::Vec;
use x86_64::PhysAddr;
use nix::errno::Errno;
use lazy_static::lazy_static;

use dune_sys::GetPages;
use dune_sys::result::{Result, Error};
use dune_sys::funcs;
use dune_sys::vmpl_get_pages;

pub const SYSTEM_RAM: u64 = 0x480000000;
pub const PAGEBASE: PhysAddr = PhysAddr::new(0x0);
pub const PAGE_SHIFT: u64 = 12;
pub const MAX_PAGES: usize = (SYSTEM_RAM >> PAGE_SHIFT) as usize;
pub const PAGE_FLAG_MAPPED: u32 = 0x1;
pub const PGSIZE: usize = 1 << PAGE_SHIFT;
pub const PAGE_SIZE: usize = 4096;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct Page {
    link: Option<Box<Page>>,
    ref_count: u64,
    flags: u32,
    vmpl: u64,
}

unsafe impl Send for Page {}

unsafe impl Sync for Page {}

impl Page {

    funcs!(ref_count, u64);
    funcs!(flags, u32);
    funcs!(vmpl, u64);

    fn new() -> Self {
        Page {
            link: None,
            ref_count: 0,
            flags: 0,
            vmpl: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PageManager {
    pages: Vec<Page>,
    num_dune_pages: usize,
    num_vmpl_pages: usize,
    vmpl_pages_free: Mutex<LinkedList<Arc<Mutex<Page>>>>,
    dune_pages_free: Mutex<LinkedList<Arc<Mutex<Page>>>>,
}

impl PageManager {
    pub fn new() -> Self {
        PageManager {
            pages: Vec::with_capacity(MAX_PAGES),
            num_dune_pages: 0,
            num_vmpl_pages: 0,
            vmpl_pages_free: Mutex::new(LinkedList::new()),
            dune_pages_free: Mutex::new(LinkedList::new()),
        }
    }

    fn do_mapping(&self, fd: RawFd, phys: u64, len: usize) -> *mut c_void {
        let addr = unsafe {
            libc::mmap(
                (PAGEBASE.as_u64() + phys) as *mut c_void,
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd,
                phys as libc::off_t,
            )
        };

        if addr == libc::MAP_FAILED {
            eprintln!("dune: failed to map pgtable");
            return ptr::null_mut();
        }

        for i in (0..len).step_by(PGSIZE) {
            let pg = self.vmpl_pa2page(PhysAddr::new(phys + i as u64));
            unsafe { (*pg.lock().unwrap()).flags = PAGE_FLAG_MAPPED };
        }

        addr
    }

    fn grow_pages(&self, fd: RawFd, head: &Mutex<LinkedList<Arc<Mutex<Page>>>>, num_pages: usize, mapping: bool) -> Result<()> {
        let mut param = GetPages::new();
        //  { num_pages, phys: 0 };
        param.set_num_pages(num_pages);
        let rc = unsafe { vmpl_get_pages(fd, &mut param) };
        if rc != Ok(0) {
            eprintln!("Failed to allocate {} pages", num_pages);
            return Err(Error::LibcError(Errno::ENOMEM));
        }

        let begin = self.vmpl_pa2page(PhysAddr::new(param.phys()));
        let end = unsafe { begin.lock().unwrap().add(num_pages) };

        let mut head_guard = head.lock().unwrap();
        for pg in (begin..end).step_by(1) {
            unsafe { (*pg.lock().unwrap()).vmpl = 1 };
            head_guard.push_front(Arc::new(Mutex::new(unsafe { *pg.lock().unwrap() })));
        }

        if !mapping {
            return Ok(());
        }

        let ptr = self.do_mapping(fd, param.phys(), num_pages << PAGE_SHIFT);
        if ptr.is_null() {
            eprintln!("Failed to map pages");
            return Err(Error::LibcError(Errno::ENOMEM));
        }

        Ok(())
    }

    fn vmpl_grow_pages(&mut self, fd: RawFd) -> Result<()> {
        let num_pages = CONFIG_VMPL_PAGE_GROW_SIZE;
        self.grow_pages(fd, &self.vmpl_pages_free, num_pages, false)?;
        self.num_vmpl_pages += num_pages;
        Ok(())
    }

    fn vmpl_page_init(&mut self, fd: RawFd) -> Result<()> {
        if self.vmpl_grow_pages(fd).is_err() {
            return Err(Error::LibcError(Errno::ENOMEM));
        }

        Ok(())
    }

    pub fn vmpl_page_alloc(&mut self, fd: RawFd) -> Option<Arc<Mutex<Page>>> {
        let mut head_guard = self.vmpl_pages_free.lock().unwrap();
        if head_guard.is_empty() {
            drop(head_guard);
            if self.vmpl_grow_pages(fd).is_err() {
                return None;
            }
            head_guard = self.vmpl_pages_free.lock().unwrap();
        }

        let pg = head_guard.pop_front().unwrap();
        self.vmpl_page_get(&pg);
        self.num_vmpl_pages -= 1;
        Some(pg)
    }

    pub fn vmpl_page_free(&mut self, pg: Arc<Mutex<Page>>) {
        let mut head_guard = self.vmpl_pages_free.lock().unwrap();
        head_guard.push_front(pg);
        self.num_vmpl_pages += 1;
    }

    fn vmpl_page_stats(&self) {
        println!("VMPL Pages Stats:");
        println!("VMPL Pages: {}/{}", self.num_vmpl_pages, MAX_PAGES);
    }

    pub fn vmpl_page_is_from_pool(&self, pa: PhysAddr) -> bool {
        if pa.as_u64() < PAGEBASE.as_u64() {
            return false;
        }

        let pg = self.vmpl_pa2page(pa);
        unsafe { let x = (*pg.lock().unwrap()).vmpl == 1; x }
    }

    pub fn vmpl_page_is_mapped(&self, pa: PhysAddr) -> bool {
        if pa.as_u64() < PAGEBASE.as_u64() {
            return false;
        }

        let pg = self.vmpl_pa2page(pa);
        unsafe { let x = (*pg.lock().unwrap()).flags == PAGE_FLAG_MAPPED; x }
    }

    pub fn vmpl_page_get(&self, pg: &Arc<Mutex<Page>>) {
        let mut pg_guard = pg.lock().unwrap();
        pg_guard.ref_count += 1;
    }

    pub fn vmpl_page_put(&mut self, pg: Arc<Mutex<Page>>) {
        let mut pg_guard = pg.lock().unwrap();
        pg_guard.ref_count -= 1;
        if pg_guard.ref_count == 0 {
            drop(pg_guard);
            self.vmpl_page_free(pg);
        }
    }

    pub fn vmpl_pa2page(&self, pa: PhysAddr) -> Arc<Mutex<Page>> {
        assert!(pa >= PAGEBASE);
        assert!(pa < PAGEBASE + (MAX_PAGES << PAGE_SHIFT) as u64);
        let pg_ptr = self.pages.as_ptr().wrapping_add((pa.as_u64() - PAGEBASE.as_u64()) as usize >> PAGE_SHIFT) as *mut Page;
        Arc::new(Mutex::new(unsafe { (*pg_ptr).clone() }))
    }

    pub fn vmpl_page2pa(&self, pg: Arc<Mutex<Page>>) -> PhysAddr {
        let pg_guard = pg.lock().unwrap();
        let pg_ptr = &*pg_guard as *const Page as usize;
        let pg_index = (pg_ptr - self.pages.as_ptr() as usize) / std::mem::size_of::<Page>();
        PAGEBASE + (pg_index << PAGE_SHIFT) as u64
    }

    fn dune_grow_pages(&mut self, fd: RawFd) -> Result<()> {
        let num_pages = CONFIG_DUNE_PAGE_GROW_SIZE;
        self.grow_pages(fd, &self.dune_pages_free, num_pages, true)?;
        self.num_dune_pages += num_pages;
        Ok(())
    }

    fn dune_page_init(&mut self, fd: RawFd) -> Result<()> {
        if self.dune_grow_pages(fd).is_err() {
            return Err(Error::LibcError(Errno::ENOMEM));
        }

        Ok(())
    }

    pub fn dune_page_alloc(&mut self, fd: RawFd) -> Option<Arc<Mutex<Page>>> {
        let mut head_guard = self.dune_pages_free.lock().unwrap();
        if head_guard.is_empty() {
            drop(head_guard);
            if self.dune_grow_pages(fd).is_err() {
                return None;
            }
            head_guard = self.dune_pages_free.lock().unwrap();
        }

        let pg = head_guard.pop_front().unwrap();
        self.vmpl_page_get(&pg);
        self.num_dune_pages -= 1;
        Some(pg)
    }

    pub fn dune_page_free(&mut self, pg: Arc<Mutex<Page>>) {
        let mut head_guard = self.dune_pages_free.lock().unwrap();
        head_guard.push_front(pg);
        self.num_dune_pages += 1;
    }

    fn dune_page_stats(&self) {
        println!("Dune Pages Stats:");
        println!("Dune Pages: {}/{}", self.num_dune_pages, MAX_PAGES);
    }

    pub fn dune_page2pa(&self, pg: Arc<Mutex<Page>>) -> PhysAddr {
        self.vmpl_page2pa(pg)
    }

    pub fn dune_pa2page(&self, pa: PhysAddr) -> Arc<Mutex<Page>> {
        self.vmpl_pa2page(pa)
    }

    pub fn dune_page_get(&self, pg: &Arc<Mutex<Page>>) {
        self.vmpl_page_get(pg)
    }

    pub fn dune_page_put(&mut self, pg: Arc<Mutex<Page>>) {
        self.vmpl_page_put(pg)
    }


    pub fn page_init(&mut self, fd: RawFd) -> Result<()> {
        // 申请MAX_PAGES个Page结构体
        let layout = Layout::array::<Page>(MAX_PAGES).unwrap();
        let pages_ptr = unsafe { alloc_zeroed(layout) as *mut Page };

        // 将pages_ptr转换为Vec
        self.pages = unsafe {
            Vec::from_raw_parts(pages_ptr, MAX_PAGES, MAX_PAGES)
        };

        self.vmpl_page_init(fd)?;
        self.dune_page_init(fd)?;

        Ok(())
    }

    pub fn page_exit(&mut self) {
        // Vec会自动处理内存释放，因此不需要手动调用dealloc
        self.pages.clear();
    }

    pub fn page_stats(&self) {
        println!("Page Stats:");
        self.vmpl_page_stats();
        self.dune_page_stats();
    }
}


lazy_static! {
    pub static ref PAGE_MANAGER: Arc<Mutex<PageManager>> = {
        Arc::new(Mutex::new(PageManager::new()))
    };
}

#[no_mangle]
pub fn dune_page_isfrompool(pa: PhysAddr) -> bool {
    let pm = PAGE_MANAGER.lock().unwrap();
    pm.vmpl_page_is_from_pool(pa)
}

#[no_mangle]
pub fn dune_page_alloc(fd: i32) -> Result<Arc<Mutex<Page>>> {
    let mut pm = PAGE_MANAGER.lock().unwrap();
    let a = pm.dune_page_alloc(fd).unwrap();
    Ok(a)
}

#[no_mangle]
pub fn dune_page_free(pg: Arc<Mutex<Page>>) {
    let mut pm = PAGE_MANAGER.lock().unwrap();
    pm.dune_page_free(pg)
}

#[no_mangle]
pub fn dune_page_get(pg: Arc<Mutex<Page>>) {
    let pm = PAGE_MANAGER.lock().unwrap();
    pm.dune_page_get(&pg)
}

#[no_mangle]
pub fn dune_page_put(pg: Arc<Mutex<Page>>) {
    let mut pm = PAGE_MANAGER.lock().unwrap();
    pm.dune_page_put(pg)
}

#[no_mangle]
pub fn dune_pa2page(pa: PhysAddr) -> Arc<Mutex<Page>> {
    let pm = PAGE_MANAGER.lock().unwrap();
    pm.dune_pa2page(pa)
}

#[no_mangle]
pub fn dune_page2pa(page: Arc<Mutex<Page>>) -> PhysAddr {
    let pm = PAGE_MANAGER.lock().unwrap();
    pm.dune_page2pa(page)
}

pub fn dune_page_init(fd: i32) -> Result<()> {
    lazy_static::initialize(&PAGE_MANAGER);
    let mut pm = PAGE_MANAGER.lock().unwrap();
    pm.dune_page_init(fd)
}

#[no_mangle]
pub fn dune_page_stats() {
    let pm = PAGE_MANAGER.lock().unwrap();
    pm.dune_page_stats()
}

pub trait WithPageManager {

    // 获取页管理器的引用
    fn page_manager(&self) -> Arc<Mutex<PageManager>>;

    // 向Guest OS申请num_pages个物理页
    fn get_pages(&self, num_pages: usize) -> Result<PhysAddr>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_page() {
        let mut pm = PageManager::new();
        pm.page_init().unwrap();
        pm.page_stats();
        let page = pm.vmpl_page_alloc(0).unwrap();
        let pa = pm.vmpl_page2pa(page);
        assert!(pm.vmpl_page_is_from_pool(pa));
        println!("pa: {:x}", pa);
        for _ in 0..10 {
            let page = pm.vmpl_page_alloc(0).unwrap();
            let pa = pm.vmpl_page2pa(page);
            println!("pa: {:x}", pa);
            pm.vmpl_page_free(page);
        }
        pm.page_stats();
        pm.vmpl_page_free(page);
        pm.page_stats();
    }

    #[test]
    fn test_alloc() {
        let mut manager = PageManager::new();
        manager.page_init(0).unwrap();
        let page1 = manager.vmpl_page_alloc(0);
        let page2 = manager.vmpl_page_alloc(0);
        assert_eq!(page1.is_some(), true);
        assert_eq!(page2.is_some(), true);
        if let Some(page1) = page1 {
            assert_eq!(manager.vmpl_page2pa(page1), PAGEBASE.as_u64() + (PGSIZE * (CONFIG_VMPL_PAGE_GROW_SIZE - 1)) as u64);
            manager.vmpl_page_free(page1);
        }
        if let Some(page2) = page2 {
            assert_eq!(manager.vmpl_page2pa(page2), PAGEBASE.as_u64() + (PGSIZE * (CONFIG_VMPL_PAGE_GROW_SIZE - 2)) as u64);
            manager.vmpl_page_free(page2);
        }
    }

    #[test]
    fn test_free() {
        let mut manager = PageManager::new();
        manager.page_init(0).unwrap();
        let page1 = manager.vmpl_page_alloc(0);
        let page2 = manager.vmpl_page_alloc(0);
        assert_eq!(page1.is_some(), true);
        assert_eq!(page2.is_some(), true);
        if let Some(page1) = page1 {
            assert_eq!(manager.vmpl_page2pa(page1), PAGEBASE.as_u64() + (PGSIZE * (CONFIG_VMPL_PAGE_GROW_SIZE - 1)) as u64);
            manager.vmpl_page_free(page1);
        }
        if let Some(page2) = page2 {
            assert_eq!(manager.vmpl_page2pa(page2), PAGEBASE.as_u64() + (PGSIZE * (CONFIG_VMPL_PAGE_GROW_SIZE - 2)) as u64);
            manager.vmpl_page_free(page2);
        }
        let page3 = manager.vmpl_page_alloc(0);
        assert_eq!(page3.is_some(), true);
        if let Some(page3) = page3 {
            assert_eq!(manager.vmpl_page2pa(page3), PAGEBASE.as_u64() + (PGSIZE * (CONFIG_VMPL_PAGE_GROW_SIZE - 2)) as u64);
            manager.vmpl_page_free(page3);
        }
    }

    #[test]
    fn test_dune_page_alloc() {
        let mut pm = PageManager::new();
        pm.page_init(0).unwrap();
        pm.page_stats();
        let page = pm.dune_page_alloc(0).unwrap();
        let pa = pm.vmpl_page2pa(page);
        assert!(pm.vmpl_page_is_from_pool(pa));
        println!("pa: {:x}", pa);
        for _ in 0..10 {
            let page = pm.dune_page_alloc(0).unwrap();
            let pa = pm.vmpl_page2pa(page);
            println!("pa: {:x}", pa);
            pm.dune_page_free(page);
        }
        pm.page_stats();
        pm.dune_page_free(page);
        pm.page_stats();
    }
}

#[repr(C)]
struct get_pages_t {
    num_pages: usize,
    phys: u64,
}

extern "C" {
    fn vmpl_ioctl_get_pages(fd: RawFd, param: *mut get_pages_t) -> i32;
}

const CONFIG_VMPL_PAGE_GROW_SIZE: usize = 1024;
const CONFIG_DUNE_PAGE_GROW_SIZE: usize = 1024;