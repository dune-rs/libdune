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
pub const PAGE_FLAG_MAPPED: u64 = 0x1;
pub const PAGE_FLAG_VMPL: u64 = 0x2;
pub const PGSIZE: usize = 1 << PAGE_SHIFT;
pub const PAGE_SIZE: usize = 4096;

// 使用环境变量,如果没有设置则使用 feature 指定的默认值
#[allow(non_upper_case_globals)]
const CONFIG_VMPL_PAGE_GROW_SIZE: usize = 
    env!("VMPL_PAGE_GROW_SIZE").parse().unwrap();

#[allow(non_upper_case_globals)]
const CONFIG_DUNE_PAGE_GROW_SIZE: usize = 
    env!("DUNE_PAGE_GROW_SIZE").parse().unwrap();

#[repr(C)]
#[derive(Debug, Clone)]
pub struct Page {
    link: Option<Box<Page>>,
    ref_count: u64,
    flags: u64,
}

unsafe impl Send for Page {}

unsafe impl Sync for Page {}

impl Page {

    funcs!(ref_count, u64);
    funcs!(flags, u64);

    fn new() -> Self {
        Page {
            link: None,
            ref_count: 0,
            flags: 0,
        }
    }

    pub fn is_mapped(&self) -> bool {
        self.flags & PAGE_FLAG_MAPPED != 0
    }

    pub fn is_vmpl(&self) -> bool {
        self.flags & PAGE_FLAG_VMPL != 0
    }

    pub fn set_mapped(&mut self) {
        self.flags |= PAGE_FLAG_MAPPED;
    }

    pub fn set_vmpl(&mut self) {
        self.flags |= PAGE_FLAG_VMPL;
    }

    pub fn clear_mapped(&mut self) {
        self.flags &= !PAGE_FLAG_MAPPED;
    }

    pub fn clear_vmpl(&mut self) {
        self.flags &= !PAGE_FLAG_VMPL;
    }
}

trait VmplPageManager {
    fn vmpl_page_init(&mut self) -> Result<()>;
    fn vmpl_page_alloc(&mut self) -> Option<Arc<Mutex<Page>>>;
    fn vmpl_page_free(&mut self, pg: Arc<Mutex<Page>>);
    fn vmpl_page_is_from_pool(&self, pa: PhysAddr) -> bool;
    fn vmpl_page_is_mapped(&self, pa: PhysAddr) -> bool;
    fn vmpl_page_get(&self, pg: &Arc<Mutex<Page>>);
    fn vmpl_page_put(&mut self, pg: Arc<Mutex<Page>>);
    fn vmpl_pa2page(&self, pa: PhysAddr) -> Arc<Mutex<Page>>;
    fn vmpl_page2pa(&self, pg: Arc<Mutex<Page>>) -> PhysAddr;
    fn vmpl_grow_pages(&mut self) -> Result<()>;
    fn vmpl_page_stats(&self);
}

trait DunePageManager {
    fn dune_page_init(&mut self) -> Result<()>;
    fn dune_page_alloc(&mut self) -> Option<Arc<Mutex<Page>>>;
    fn dune_page_free(&mut self, pg: Arc<Mutex<Page>>);
    fn dune_page_is_from_pool(&self, pa: PhysAddr) -> bool;
    fn dune_page_is_mapped(&self, pa: PhysAddr) -> bool;
    fn dune_page_get(&self, pg: &Arc<Mutex<Page>>);
    fn dune_page_put(&mut self, pg: Arc<Mutex<Page>>);
    fn dune_pa2page(&self, pa: PhysAddr) -> Arc<Mutex<Page>>;
    fn dune_page2pa(&self, pg: Arc<Mutex<Page>>) -> PhysAddr;
    fn dune_grow_pages(&mut self) -> Result<()>;
    fn dune_page_stats(&self);
}

#[derive(Debug, Clone)]
pub struct PageManager {
    fd: RawFd,
    pagebase: PhysAddr,
    pages: Vec<Page>,
    num_dune_pages: usize,
    num_vmpl_pages: usize,
    vmpl_pages_free: Mutex<LinkedList<Arc<Mutex<Page>>>>,
    dune_pages_free: Mutex<LinkedList<Arc<Mutex<Page>>>>,
}

impl PageManager {

    funcs!(fd, RawFd);
    funcs!(pagebase, PhysAddr);

    pub fn new(fd: RawFd) -> Self {
        PageManager {
            fd,
            pagebase: PAGEBASE,
            pages: Vec::with_capacity(MAX_PAGES),
            num_dune_pages: 0,
            num_vmpl_pages: 0,
            vmpl_pages_free: Mutex::new(LinkedList::new()),
            dune_pages_free: Mutex::new(LinkedList::new()),
        }
    }

    pub fn with_pagebase(fd: RawFd, pagebase: PhysAddr) -> Self {
        PageManager {
            fd,
            pagebase,
            pages: Vec::with_capacity(MAX_PAGES),
            num_dune_pages: 0,
            num_vmpl_pages: 0,
            vmpl_pages_free: Mutex::new(LinkedList::new()),
            dune_pages_free: Mutex::new(LinkedList::new()),
        }
    }

    fn do_mapping(&self, phys: u64, len: usize) -> *mut c_void {
        let addr = unsafe {
            libc::mmap(
                (self.pagebase.as_u64() + phys) as *mut c_void,
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                self.fd,
                phys as libc::off_t,
            )
        };

        if addr == libc::MAP_FAILED {
            eprintln!("dune: failed to map pgtable");
            return ptr::null_mut();
        }

        for i in (0..len).step_by(PGSIZE) {
            let pg = self.vmpl_pa2page(PhysAddr::new(phys + i as u64));
            pg.lock().unwrap().set_mapped();
        }

        addr
    }

    fn grow_pages(&self, head: &Mutex<LinkedList<Arc<Mutex<Page>>>>, num_pages: usize, mapping: bool) -> Result<()> {
        let mut param = GetPages::new();
        param.set_num_pages(num_pages);
        let rc = unsafe { vmpl_get_pages(self.fd, &mut param) };
        if rc != Ok(0) {
            eprintln!("Failed to allocate {} pages", num_pages);
            return Err(Error::LibcError(Errno::ENOMEM));
        }

        let begin = self.vmpl_pa2page(PhysAddr::new(param.phys()));
        let end = unsafe { begin.lock().unwrap().add(num_pages) };

        let mut head_guard = head.lock().unwrap();
        for pg in (begin..end).step_by(1) {
            pg.lock().unwrap().set_vmpl();
            head_guard.push_front(Arc::new(Mutex::new(unsafe { *pg.lock().unwrap() })));
        }

        if !mapping {
            return Ok(());
        }

        let ptr = self.do_mapping(param.phys(), num_pages << PAGE_SHIFT);
        if ptr.is_null() {
            eprintln!("Failed to map pages");
            return Err(Error::LibcError(Errno::ENOMEM));
        }

        Ok(())
    }
}

impl VmplPageManager for PageManager {

    fn vmpl_grow_pages(&mut self) -> Result<()> {
        let num_pages = CONFIG_VMPL_PAGE_GROW_SIZE;
        self.grow_pages(&self.vmpl_pages_free, num_pages, false)?;
        self.num_vmpl_pages += num_pages;
        Ok(())
    }

    fn vmpl_page_init(&mut self) -> Result<()> {
        if self.vmpl_grow_pages().is_err() {
            return Err(Error::LibcError(Errno::ENOMEM));
        }

        Ok(())
    }

    fn vmpl_page_alloc(&mut self) -> Option<Arc<Mutex<Page>>> {
        let mut head_guard = self.vmpl_pages_free.lock().unwrap();
        if head_guard.is_empty() {
            drop(head_guard);
            if self.vmpl_grow_pages().is_err() {
                return None;
            }
            head_guard = self.vmpl_pages_free.lock().unwrap();
        }

        let pg = head_guard.pop_front().unwrap();
        self.vmpl_page_get(&pg);
        self.num_vmpl_pages -= 1;
        Some(pg)
    }

    fn vmpl_page_free(&mut self, pg: Arc<Mutex<Page>>) {
        let mut head_guard = self.vmpl_pages_free.lock().unwrap();
        head_guard.push_front(pg);
        self.num_vmpl_pages += 1;
    }

    fn vmpl_page_stats(&self) {
        println!("VMPL Pages Stats:");
        println!("VMPL Pages: {}/{}", self.num_vmpl_pages, MAX_PAGES);
        println!("VMPL Pages Free: {}", self.vmpl_pages_free.lock().unwrap().len());
    }

    fn vmpl_page_is_from_pool(&self, pa: PhysAddr) -> bool {
        if pa < self.pagebase {
            return false;
        }

        let pg = self.vmpl_pa2page(pa);
        pg.lock().unwrap().is_vmpl()
    }

    fn vmpl_page_is_mapped(&self, pa: PhysAddr) -> bool {
        if pa < self.pagebase {
            return false;
        }

        let pg = self.vmpl_pa2page(pa);
        pg.lock().unwrap().is_mapped()
    }

    fn vmpl_page_get(&self, pg: &Arc<Mutex<Page>>) {
        let mut pg_guard = pg.lock().unwrap();
        pg_guard.ref_count += 1;
    }

    fn vmpl_page_put(&mut self, pg: Arc<Mutex<Page>>) {
        let mut pg_guard = pg.lock().unwrap();
        pg_guard.ref_count -= 1;
        if pg_guard.ref_count == 0 {
            drop(pg_guard);
            self.vmpl_page_free(pg);
        }
    }

    fn vmpl_pa2page(&self, pa: PhysAddr) -> Arc<Mutex<Page>> {
        assert!(pa >= self.pagebase);
        assert!(pa < self.pagebase + (MAX_PAGES << PAGE_SHIFT) as u64);
        let pg_ptr = self.pages.as_ptr().wrapping_add(
            (pa.as_u64() - self.pagebase.as_u64()) as usize >> PAGE_SHIFT
        ) as *mut Page;
        Arc::new(Mutex::new(unsafe { (*pg_ptr).clone() }))
    }

    fn vmpl_page2pa(&self, pg: Arc<Mutex<Page>>) -> PhysAddr {
        let pg_guard = pg.lock().unwrap();
        let pg_ptr = &*pg_guard as *const Page as usize;
        let pg_index = (pg_ptr - self.pages.as_ptr() as usize) / std::mem::size_of::<Page>();
        self.pagebase + (pg_index << PAGE_SHIFT) as u64
    }
}

impl DunePageManager for PageManager {
    fn dune_grow_pages(&mut self) -> Result<()> {
        let num_pages = CONFIG_DUNE_PAGE_GROW_SIZE;
        self.grow_pages(&self.dune_pages_free, num_pages, true)?;
        self.num_dune_pages += num_pages;
        Ok(())
    }

    fn dune_page_init(&mut self) -> Result<()> {
        if self.dune_grow_pages().is_err() {
            return Err(Error::LibcError(Errno::ENOMEM));
        }
        Ok(())
    }

    fn dune_page_alloc(&mut self) -> Option<Arc<Mutex<Page>>> {
        let mut head_guard = self.dune_pages_free.lock().unwrap();
        if head_guard.is_empty() {
            drop(head_guard);
            if self.dune_grow_pages().is_err() {
                return None;
            }
            head_guard = self.dune_pages_free.lock().unwrap();
        }

        let pg = head_guard.pop_front().unwrap();
        self.vmpl_page_get(&pg);
        self.num_dune_pages -= 1;
        Some(pg)
    }

    fn dune_page_free(&mut self, pg: Arc<Mutex<Page>>) {
        let mut head_guard = self.dune_pages_free.lock().unwrap();
        head_guard.push_front(pg);
        self.num_dune_pages += 1;
    }

    fn dune_page_stats(&self) {
        println!("Dune Pages Stats:");
        println!("Dune Pages: {}/{}", self.num_dune_pages, MAX_PAGES);
        println!("Dune Pages Free: {}", self.dune_pages_free.lock().unwrap().len());
    }

    fn dune_page2pa(&self, pg: Arc<Mutex<Page>>) -> PhysAddr {
        self.vmpl_page2pa(pg)
    }

    fn dune_pa2page(&self, pa: PhysAddr) -> Arc<Mutex<Page>> {
        self.vmpl_pa2page(pa)
    }

    fn dune_page_get(&self, pg: &Arc<Mutex<Page>>) {
        self.vmpl_page_get(pg)
    }

    fn dune_page_put(&mut self, pg: Arc<Mutex<Page>>) {
        self.vmpl_page_put(pg)
    }

    fn dune_page_is_from_pool(&self, pa: PhysAddr) -> bool {
        self.vmpl_page_is_from_pool(pa)
    }

    fn dune_page_is_mapped(&self, pa: PhysAddr) -> bool {
        self.vmpl_page_is_mapped(pa)
    }
}

impl PageManager {

    pub fn page_init(&mut self) -> Result<()> {
        // 申请MAX_PAGES个Page结构体
        let layout = Layout::array::<Page>(MAX_PAGES).unwrap();
        let pages_ptr = unsafe { alloc_zeroed(layout) as *mut Page };

        // 将pages_ptr转换为Vec
        self.pages = unsafe {
            Vec::from_raw_parts(pages_ptr, MAX_PAGES, MAX_PAGES)
        };

        self.vmpl_page_init()?;
        self.dune_page_init()?;

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

    pub fn mark_page_mapped(&self, pa: PhysAddr) {
        log::debug!("Marking page {:x} as mapped", pa);
        let pg = self.vmpl_pa2page(pa);
        let mut pg_guard = pg.lock().unwrap();
        pg_guard.flags = PAGE_FLAG_MAPPED;
    }

    pub fn mark_pages_mapped(&self, phys: PhysAddr, len: usize) {
        log::debug!("Marking pages {:x}-{:x} as mapped", phys, phys + len as u64);
        for i in (0..len).step_by(PAGE_SIZE) {
            self.mark_page_mapped(phys + i as u64);
        }
    }

    pub fn mark_vmpl_page(&self, pa: PhysAddr) {
        self.mark_page_mapped(pa);
    }

    pub fn mark_vmpl_pages(&self, phys: PhysAddr, len: usize) {
        self.mark_pages_mapped(phys, len);
    }
}

// 定义统一的宏来生成全局 helper 函数
macro_rules! define_page_helpers {
    ($(($name:ident, $ret:ty, $fn_name:ident $(, $arg:ident: $type:ty)*)),* $(,)?) => {
        $(
            #[no_mangle]
            pub fn $name($($arg: $type),*) -> $ret {
                let system = get_system::<dyn WithPageManager>();
                if let Some(system) = system {
                    let pm = system.page_manager().lock().unwrap();
                    pm.$fn_name($($arg),*)
                } else {
                    log::error!(concat!(stringify!($name), ": system does not implement WithPageManager"));
                    panic!();
                }
            }
        )*
    };
}

// 使用新宏一次性定义所有helper函数
define_page_helpers!(
    // Dune page helpers
    (dune_page_isfrompool, bool, page_is_from_pool, pa: PhysAddr),
    (dune_page_ismapped, bool, page_is_mapped, pa: PhysAddr),
    (dune_page_alloc, Result<Arc<Mutex<Page>>>, page_alloc),
    (dune_page_init, Result<()>, page_init, fd: i32, pagebase: PhysAddr),
    (dune_page_exit, (), page_exit),
    (dune_page_free, (), page_free, pg: Arc<Mutex<Page>>),
    (dune_page_get, (), page_get, pg: &Arc<Mutex<Page>>),
    (dune_page_put, (), page_put, pg: Arc<Mutex<Page>>),
    (dune_pa2page, Arc<Mutex<Page>>, pa2page, pa: PhysAddr),
    (dune_page2pa, PhysAddr, page2pa, page: Arc<Mutex<Page>>),
    (dune_page_stats, (), page_stats),

    // VMPL page helpers
    (vmpl_page_isfrompool, bool, page_is_from_pool, pa: PhysAddr),
    (vmpl_page_ismapped, bool, page_is_mapped, pa: PhysAddr),
    (vmpl_page_alloc, Result<Arc<Mutex<Page>>>, page_alloc),
    (vmpl_page_init, Result<()>, page_init, fd: i32, pagebase: PhysAddr),
    (vmpl_page_exit, (), page_exit),
    (vmpl_page_free, (), page_free, pg: Arc<Mutex<Page>>),
    (vmpl_page_get, (), page_get, pg: &Arc<Mutex<Page>>),
    (vmpl_page_put, (), page_put, pg: Arc<Mutex<Page>>),
    (vmpl_pa2page, Arc<Mutex<Page>>, pa2page, pa: PhysAddr),
    (vmpl_page2pa, PhysAddr, page2pa, page: Arc<Mutex<Page>>),
    (vmpl_page_stats, (), page_stats),

    // Mark page helpers
    (mark_page_mapped, (), mark_page_mapped, pa: PhysAddr),
    (mark_pages_mapped, (), mark_pages_mapped, phys: PhysAddr, len: usize),
    (mark_vmpl_page, (), mark_page_mapped, pa: PhysAddr),
    (mark_vmpl_pages, (), mark_pages_mapped, phys: PhysAddr, len: usize),

    // Page init helper
    (page_init, Result<()>, page_init, fd: i32, pagebase: PhysAddr),
);

pub trait WithPageManager {

    fn page_manager(&self) -> Arc<Mutex<PageManager>>;

    // 初始化页管理器
    fn page_init(&self, fd: i32, pagebase: PhysAddr) -> Result<()> {
        let pm = self.page_manager().lock().unwrap();
        pm.page_init(fd, pagebase)
    }

    fn page_exit(&self) {
        let pm = self.page_manager().lock().unwrap();
        pm.page_exit()
    }

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
        let page = pm.dune_page_alloc().unwrap();
        let pa = pm.vmpl_page2pa(page);
        assert!(pm.vmpl_page_is_from_pool(pa));
        println!("pa: {:x}", pa);
        for _ in 0..10 {
            let page = pm.dune_page_alloc().unwrap();
            let pa = pm.vmpl_page2pa(page);
            println!("pa: {:x}", pa);
            pm.dune_page_free(page);
        }
        pm.page_stats();
        pm.dune_page_free(page);
        pm.page_stats();
    }
}