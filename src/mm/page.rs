use std::ptr;
use std::mem;
use std::sync::Arc;
use std::sync::Mutex;
use libc::{mmap, MAP_ANONYMOUS, MAP_FIXED, MAP_PRIVATE, MAP_HUGETLB, PROT_READ, PROT_WRITE};
use x86_64::PhysAddr;
use lazy_static::lazy_static;
use dune_sys::*;

pub const PAGEBASE: PhysAddr = PhysAddr::new(0x200000000);
pub const PGSIZE: usize = 4096;
pub const GROW_SIZE: usize = 512;
pub const MAX_PAGES: usize = 1 << 20;
pub const PAGE_SIZE: usize = 4096;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Page {
    next: *mut Page,
    ref_count: usize,
}

impl Page {
    funcs!(next, *mut Page);
    funcs!(ref_count, usize);
}

impl Page {
    fn new() -> Self {
        Page {
            next: ptr::null_mut(),
            ref_count: 0,
        }
    }
}

#[derive(Debug)]
struct PageManager {
    pages: *mut Page,
    free_list: *mut Page,
    page_base: PhysAddr,
    num_pages: usize,
}

unsafe impl Sync for PageManager {}

unsafe impl Send for PageManager {}

impl PageManager {

    fn new() -> Arc<Mutex<Self>> {
        let page_base = PAGEBASE;
        let mut pm = PageManager {
            pages: ptr::null_mut(),
            free_list: ptr::null_mut(),
            page_base,
            num_pages: 0,
        };
        pm.page_init().unwrap();
        Arc::new(Mutex::new(pm))
    }

    fn do_mapping(&self, base: *mut libc::c_void, len: usize) -> Result<*mut libc::c_void> {
        let mem = unsafe {
            mmap(base, len, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_HUGETLB | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
        };
        if mem == libc::MAP_FAILED {
            let mem = unsafe {
                mmap(base, len, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
            };
            if mem == libc::MAP_FAILED {
                return Err(Error::LibcError(libc::ENOMEM));
            }
        }
        Ok(mem)
    }

    fn page_init(&mut self) -> Result<()> {
        self.free_list = ptr::null_mut();
        self.num_pages = GROW_SIZE;

        let base = self.page_base.as_u64() as *mut libc::c_void;
        self.do_mapping(base, self.num_pages * PGSIZE)?;

        self.pages = unsafe {
            let pages = libc::malloc(mem::size_of::<Page>() * MAX_PAGES) as *mut Page;
            if pages.is_null() {
                libc::munmap(base, self.num_pages * PGSIZE);
                return Err(Error::LibcError(libc::ENOMEM));
            }
            pages
        };

        for i in 0..self.num_pages {
            unsafe {
                let page = self.pages.add(i);
                *page = Page::new();
                (*page).next = self.free_list;
                self.free_list = page;
            }
        }

        Ok(())
    }

    fn grow_size(&mut self) -> Result<()> {
        let new_num_pages: usize = self.num_pages + GROW_SIZE;
        let base = (self.page_base + (self.num_pages * PGSIZE) as u64).as_u64() as *mut libc::c_void;
        self.do_mapping(base, GROW_SIZE * PGSIZE)?;

        for i in self.num_pages..new_num_pages {
            unsafe {
                let page = self.pages.add(i);
                *page = Page::new();
                (*page).next = self.free_list;
                self.free_list = page;
            }
        }

        self.num_pages = new_num_pages;
        Ok(())
    }

    fn page_alloc(&mut self) -> Option<*mut Page> {
        if !self.free_list.is_null() {
            let page = self.free_list;
            unsafe {
                self.free_list = (*page).next;
                (*page).ref_count = 1;
            }
            Some(page)
        } else {
            None
        }
    }

    fn page_free(&mut self, page: *mut Page) {
        unsafe {
            if (*page).ref_count > 0 {
                (*page).ref_count -= 1;
                if (*page).ref_count == 0 {
                    (*page).next = self.free_list;
                    self.free_list = page;
                }
            }
        }
    }

    fn page_stats(&self) {
        let num_alloc = (0..self.num_pages)
            .filter(|&i| unsafe { (*self.pages.add(i)).ref_count != 0 })
            .count();

        println!(
            "DUNE Page Allocator: Alloc {}, Free {}, Total {}",
            num_alloc,
            self.num_pages - num_alloc,
            self.num_pages
        );
    }

    fn page_isfrompool(&self, pa: PhysAddr) -> bool {
        pa >= self.page_base && pa < self.page_base + (self.num_pages * PGSIZE) as u64
    }

    fn page_get(&self, pg: *mut Page) -> *mut Page {
        unsafe {
            assert!(pg >= self.pages);
            assert!(pg < self.pages.add(self.num_pages));

            (*pg).ref_count += 1;

            pg
        }
    }

    fn page_put(&mut self, pg: *mut Page) {
        unsafe {
            assert!(pg >= self.pages);
            assert!(pg < self.pages.add(self.num_pages));

            (*pg).ref_count -= 1;

            if (*pg).ref_count == 0 {
                self.page_free(pg);
            }
        }
    }

    fn page2pa(&self, page: *mut Page) -> usize {
        println!("sizeof Page: {}", std::mem::size_of::<Page>());
        (unsafe {
            page.offset_from(self.pages)
        }) as usize * PAGE_SIZE
    }

    fn pa2page(&self, pa: PhysAddr) -> *mut Page {
        if pa < self.page_base {
            return ptr::null_mut();
        }
        let offset = pa - self.page_base;
        let pgoff = offset as usize / PGSIZE;
        unsafe { self.pages.add(pgoff) }
    }
}

lazy_static! {
    pub static ref PAGE_MANAGER: Arc<Mutex<PageManager>> = PageManager::new();
}

pub fn dune_page_isfrompool(pa: PhysAddr) -> bool {
    let pm = PAGE_MANAGER.lock().unwrap();
    pm.page_isfrompool(pa)
}

use crate::Error;
use crate::Result;

pub fn dune_page_alloc() -> Result<*mut Page> {
    let mut pm = PAGE_MANAGER.lock().unwrap();
    let a= pm.page_alloc().unwrap();
    Ok(a)
}

pub fn dune_page_get(pg: *mut Page) -> *mut Page {
    let pm = PAGE_MANAGER.lock().unwrap();
    pm.page_get(pg)
}

pub fn dune_page_put(pg: *mut Page) {
    let mut pm = PAGE_MANAGER.lock().unwrap();
    pm.page_put(pg)
}

pub fn dune_pa2page(pa: PhysAddr) -> *mut Page {
    let pm = PAGE_MANAGER.lock().unwrap();
    pm.pa2page(pa)
}

pub fn dune_page2pa(page: *mut Page) -> PhysAddr {
    let pm = PAGE_MANAGER.lock().unwrap();
    let addr = pm.page2pa(page);
    PhysAddr::new(addr as u64)
}

pub fn dune_page_init() -> Result<()> {
    lazy_static::initialize(&PAGE_MANAGER);
    let mut pm = PAGE_MANAGER.lock().unwrap();
    pm.page_init()
}