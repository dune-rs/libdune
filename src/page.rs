use std::ptr;
use std::mem;
// use std::slice;
// use std::os::unix::io::AsRawFd;
use libc::{mmap, MAP_ANONYMOUS, MAP_FIXED, MAP_PRIVATE, MAP_HUGETLB, PROT_READ, PROT_WRITE};
// use crate::globals::*;
use crate::globals::*;
use crate::funcs;
// const PAGEBASE: usize = 0x200000000;
// const PGSIZE: usize = 4096;
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

pub static mut pages: *mut Page = ptr::null_mut();
pub static mut num_pages: usize = 0;
pub static mut pages_free: PageList = PageList::new();

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
        let new_num_pages = num_pages + GROW_SIZE;
        let base = (PAGEBASE + num_pages * PGSIZE) as *mut libc::c_void;
        do_mapping(base, GROW_SIZE * PGSIZE)?;

        for i in num_pages..new_num_pages {
            let page = (PAGEBASE + i * PGSIZE) as *mut Page;
            ptr::write(page, Page::new());
            pages_free.push_front(Box::from_raw(page));
        }

        num_pages = new_num_pages;
    }
    Ok(())
}

pub fn dune_page_put(page: *mut Page) {
    unsafe {
        (*page).ref_count += 1;
    }
}

pub fn dune_page_get(page: *mut Page) {
    unsafe {
        (*page).ref_count -= 1;
        if (*page).ref_count == 0 {
            dune_page_free(page);
        }
    }
}

pub fn dune_page_alloc() -> Result<*mut Page, i32> {
    unsafe {
        if pages_free.is_empty() {
            grow_size()?;
        }

        let mut page = pages_free.pop_front().unwrap();
        (*page).ref_count = 1;
        Ok(Box::into_raw(page))
    }
}

pub fn dune_page_free(page: *mut Page) {
    unsafe {
        (*page).ref_count = 0;
        pages_free.push_front(Box::from_raw(page));
    }
}

pub fn dune_page_stats() {
    unsafe {
        let num_alloc = num_pages - pages_free.head.as_ref().map_or(0, |head| {
            let mut count = 0;
            let mut current = Some(head);
            while let Some(node) = current {
                count += 1;
                current = node.link.as_ref().map(|link| &**link);
            }
            count
        });
        println!("DUNE Page Allocator: Alloc {}, Free {}, Total {}", num_alloc, num_pages - num_alloc, num_pages);
    }
}

pub fn dune_page_isfrompool(pa: usize) -> bool {
    pa >= PAGEBASE && pa < PAGEBASE + unsafe { num_pages } * PGSIZE
}

pub fn dune_page_init() -> Result<(), i32> {
    unsafe {
        let base = PAGEBASE as *mut libc::c_void;
        do_mapping(base, GROW_SIZE * PGSIZE)?;

        pages = libc::malloc(mem::size_of::<Page>() * MAX_PAGES) as *mut Page;
        if pages.is_null() {
            return Err(-libc::ENOMEM);
        }

        for i in 0..GROW_SIZE {
            let page = (PAGEBASE + i * PGSIZE) as *mut Page;
            ptr::write(page, Page::new());
            pages_free.push_front(Box::from_raw(page));
        }

        num_pages = GROW_SIZE;
    }
    Ok(())
}
