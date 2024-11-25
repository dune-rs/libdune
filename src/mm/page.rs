use std::ptr;
use std::mem;
use libc::{mmap, MAP_ANONYMOUS, MAP_FIXED, MAP_PRIVATE, MAP_HUGETLB, PROT_READ, PROT_WRITE};
use x86_64::PhysAddr;
use dune_sys::*;

pub const PAGEBASE: PhysAddr = PhysAddr::new(0x200000000);
pub const PGSIZE: usize = 4096;
pub const GROW_SIZE: usize = 512;
pub const MAX_PAGES: usize = 1 << 20;

#[repr(C)]
#[derive(Debug)]
pub struct Page {
    link: Option<Box<Page>>,
    ref_count: u64,
}

impl Page {
    funcs!(link, Option<Box<Page>>);
    funcs!(ref_count, u64);
}

impl Page {
    fn new() -> Self {
        Page {
            link: None,
            ref_count: 0,
        }
    }
}

pub struct PageList {
    head: Option<Box<Page>>,
}

impl PageList {
    pub fn new() -> Self {
        PageList { head: None }
    }

    pub fn push_front(&mut self, page: Box<Page>) {
        let mut new_node = page;
        new_node.link = self.head.take();
        self.head = Some(new_node);
    }

    pub fn pop_front(&mut self) -> Option<Box<Page>> {
        self.head.take().map(|mut node| {
            self.head = node.link.take();
            node
        })
    }

    pub fn is_empty(&self) -> bool {
        self.head.is_none()
    }
}

pub static mut PAGES: *mut Page = ptr::null_mut();
pub static mut NUM_PAGES: usize = 0;
pub static mut PAGES_FREE: PageList = PageList::new();

fn do_mapping(base: *mut libc::c_void, len: usize) -> Result<*mut libc::c_void, i32> {
    let mem = unsafe {
        mmap(base, len, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_HUGETLB | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
    };
    if mem == libc::MAP_FAILED {
        let mem = unsafe {
            mmap(base, len, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
        };
        if mem == libc::MAP_FAILED {
            return Err(-libc::ENOMEM);
        }
    }
    Ok(mem)
}

fn grow_size() -> Result<(), i32> {
    unsafe {
        let new_num_pages = NUM_PAGES + GROW_SIZE;
        let base = (PAGEBASE + (NUM_PAGES * PGSIZE) as u64).as_u64() as *mut libc::c_void;
        do_mapping(base, GROW_SIZE * PGSIZE)?;

        for i in NUM_PAGES..new_num_pages {
            let page = (PAGEBASE + (i * PGSIZE) as u64).as_u64() as *mut Page;
            ptr::write(page, Page::new());
            PAGES_FREE.push_front(Box::from_raw(page));
        }

        NUM_PAGES = new_num_pages;
    }
    Ok(())
}

pub fn dune_page_alloc() -> Result<*mut Page, i32> {
    unsafe {
        if PAGES_FREE.is_empty() {
            grow_size()?;
        }

        let mut page = PAGES_FREE.pop_front().unwrap();
        (*page).ref_count = 1;
        Ok(Box::into_raw(page))
    }
}

pub fn dune_page_free(page: *mut Page) {
    unsafe {
        (*page).ref_count = 0;
        PAGES_FREE.push_front(Box::from_raw(page));
    }
}

pub fn dune_page_stats() {
    unsafe {
        let num_alloc = NUM_PAGES - PAGES_FREE.head.as_ref().map_or(0, |head| {
            let mut count = 0;
            let mut current = Some(head);
            while let Some(node) = current {
                count += 1;
                current = node.link.as_ref().map(|link| &**link);
            }
            count
        });
        println!("DUNE Page Allocator: Alloc {}, Free {}, Total {}", num_alloc, NUM_PAGES - num_alloc, NUM_PAGES);
    }
}

pub fn dune_pa2page(pa: PhysAddr) -> *mut Page {
    unsafe {
        if pa < PAGEBASE {
            return ptr::null_mut();
        }
        let offset = pa - PAGEBASE;
        let pgoff = offset as usize / PGSIZE;
        PAGES.add(pgoff)
    }
}

pub fn dune_page2pa(pg: *mut Page) -> PhysAddr {
    unsafe {
        if pg < PAGES || pg >= PAGES.add(NUM_PAGES) {
            return PhysAddr::new(0);
        }
        let pgoff = pg.offset_from(PAGES) as usize;
        PAGEBASE + (pgoff * PGSIZE) as u64
    }
}

pub fn dune_page_isfrompool(pa: PhysAddr) -> bool {
    pa >= PAGEBASE && pa < PAGEBASE + unsafe { (NUM_PAGES * PGSIZE) as u64 }
}

pub fn dune_page_get(pg: *mut Page) -> *mut Page {
    unsafe {
        assert!(pg >= PAGES);
        assert!(pg < PAGES.add(NUM_PAGES));

        (*pg).ref_count += 1;

        pg
    }
}

pub fn dune_page_put(pg: *mut Page) -> Result<(), ()>{
    unsafe {
        if pg < PAGES || pg >= PAGES.add(NUM_PAGES) {
            return Err(());
        }

        (*pg).ref_count -= 1;

        if (*pg).ref_count == 0 {
            dune_page_free(pg);
        }
    }
    Ok(())
}

pub fn dune_page_init() -> Result<(), i32> {
    unsafe {
        let base = PAGEBASE.as_u64() as *mut libc::c_void;
        do_mapping(base, GROW_SIZE * PGSIZE as usize)?;

        PAGES = libc::malloc(mem::size_of::<Page>() * MAX_PAGES) as *mut Page;
        if PAGES.is_null() {
            return Err(-libc::ENOMEM);
        }

        for i in 0..GROW_SIZE {
            let page = (PAGEBASE + (i * PGSIZE) as u64).as_u64() as *mut libc::c_void as *mut Page;
            ptr::write(page, Page::new());
            PAGES_FREE.push_front(Box::from_raw(page));
        }

        NUM_PAGES = GROW_SIZE;
    }
    Ok(())
}
