use dune_sys::*;
use crate::core::*;

const VSYSCALL_ADDR: u64 = 0xffffffffff600000;

pub unsafe fn setup_syscall() -> io::Result<()> {
    let lstar = ioctl(DUNE_FD, DUNE_GET_SYSCALL);
    if lstar == -1 {
        return Err(io::Error::last_os_error());
    }

    let page = mmap(ptr::null_mut(),
                                (PGSIZE * 2) as usize,
                                PROT_READ | PROT_WRITE | PROT_EXEC,
                                MAP_PRIVATE | MAP_ANON,
                                -1,
                                0);

    if page == MAP_FAILED {
        return Err(io::Error::last_os_error());
    }

    // calculate the page-aligned address
    let lstara = lstar.bitand(!(PGSIZE - 1));
    let off = lstar.bitand(PGSIZE - 1);

    unsafe {
        ptr::copy_nonoverlapping(
            __dune_syscall as *const u8,
            (page as *mut u8).add(off as usize),
            __dune_syscall_end as usize - __dune_syscall as usize,
        );
    }

    for i in (0..=PGSIZE).step_by(PGSIZE) {
        let pa = dune_mmap_addr_to_pa(unsafe { page.add(i) });
        let mut pte: *mut PageTableEntry = ptr::null_mut();
        unsafe {
            let start = (lstara + i as u64) as *mut c_void;
            dune_vm_lookup(PGROOT, start, CreateType::Normal, &mut pte);
            *pte = PTE_ADDR!(pa) | PTE_P;
        }
    }

    Ok(())
}

pub fn setup_vsyscall() {
    let mut ptep: *mut PageTableEntry = ptr::null_mut();
    unsafe {
        let vsyscall_addr = VSYSCALL_ADDR as *mut c_void;
        let vsyscall_page = &__dune_vsyscall_page as *const _ as *mut c_void;
        let page = dune_va_to_pa(vsyscall_page);
        let addr = PhysAddr::new(page as u64);
        dune_vm_lookup(PGROOT, vsyscall_addr, CreateType::Normal, &mut ptep);
        let pte = &mut *ptep;
        pte.set_addr(addr, PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE);
    }
}