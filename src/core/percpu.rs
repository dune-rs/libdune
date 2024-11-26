use std::ffi::c_void;
use std::sync::Arc;
use std::{mem, ptr};
use std::{arch::asm, mem::offset_of};
use libc::{mmap, PROT_READ, PROT_WRITE, MAP_PRIVATE, MAP_ANONYMOUS, munmap, MAP_FAILED};
use x86_64::registers::model_specific::{FsBase, GsBase};
use dune_sys::dune::DuneConfig;
use dune_sys::{funcs, funcs_vec, DuneDevice, IdtDescriptor};
use x86_64::VirtAddr;
use crate::{dune_die, get_fs_base, globals::*, PGSIZE};
use crate::core::*;
use crate::result::{Result, Error};

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
struct Tptr {
    limit: u16,
    base: u64,
}

impl Tptr {
    funcs!(limit, u16);
    funcs!(base, u64);
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
struct Tss {
    reserved0: u32,
    pub tss_rsp: [u64; 3], // Stack pointer for CPL 0, 1, 2
    reserved1: u64,
    tss_ist: [u64; 7], // Note: tss_ist[0] is ignored
    reserved2: u64,
    reserved3: u16,
    tss_iomb: u16, // I/O map base
    tss_iopb: [u8; 0],
}

impl Tss {

    funcs!(tss_iomb, u16);
    funcs_vec!(tss_rsp, u64);
    funcs_vec!(tss_ist, u64);
}

static GDT_TEMPLATE: [u64; NR_GDT_ENTRIES] = [
    0,
    0,
    SEG64!(SEG_X | SEG_R, 0),
    SEG64!(SEG_W, 0),
    0,
    SEG64!(SEG_W, 3),
    SEG64!(SEG_X | SEG_R, 3),
    0,
    0,
];

pub struct DunePercpu {
    percpu_ptr: u64,
    tmp: u64,
    kfs_base: VirtAddr,
    ufs_base: VirtAddr,
    in_usermode: u64,
    device: Arc<DuneDevice>,
    pub tss: Tss,
    gdt: [u64; NR_GDT_ENTRIES],
}

/*
 * Supervisor Private Area Format
 */
pub const TMP : usize = offset_of!(DunePercpu, tmp);
pub const KFS_BASE: usize = offset_of!(DunePercpu, kfs_base);
pub const UFS_BASE: usize = offset_of!(DunePercpu, ufs_base);
pub const IN_USERMODE: usize = offset_of!(DunePercpu, in_usermode);
pub const TRAP_STACK: usize = offset_of!(DunePercpu, tss.tss_rsp);

impl DunePercpu {
    funcs!(percpu_ptr, u64);
    funcs!(tmp, u64);
    funcs!(kfs_base, VirtAddr);
    funcs!(ufs_base, VirtAddr);
    funcs!(in_usermode, u64);
    funcs_vec!(gdt, u64);

    pub fn create(device: &Arc<DuneDevice>) -> Result<&mut DunePercpu> {
        let fs_base = get_fs_base()?;
        let percpu = unsafe {
            let ret = mmap(
                ptr::null_mut(),
                PGSIZE as usize,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            );
            if ret == MAP_FAILED {
                return Err(Error::Unknown);
            }
            Ok(ret)
        };

        percpu.and_then(|ret| {
            let percpu_ptr = ret as *mut DunePercpu;

            // map_ptr
            map_ptr(VirtAddr::from_ptr(percpu_ptr), size_of::<DunePercpu>());

            let percpu = unsafe { &mut *percpu_ptr };
            percpu.set_kfs_base(fs_base)
                .set_ufs_base(fs_base)
                .set_in_usermode(0);

            match percpu.setup_safe_stack() {
                Ok(()) => {
                    percpu.device = Arc::clone(device);
                    Ok(percpu)
                },
                Err(e) => {
                    unsafe { munmap(percpu_ptr as *mut c_void, PGSIZE as usize) };
                    return Err(e);
                },
            }
        })
    }

    pub fn free(ptr: *mut DunePercpu) {
        // XXX free stack
        unsafe { munmap(ptr as *const _ as *mut c_void, PGSIZE as usize) };
    }

    fn setup_gdt(&mut self) {
        self.gdt = GDT_TEMPLATE;
        self.gdt[GD_TSS >> 3] = SEG_TSSA | SEG_P | SEG_A | SEG_BASELO!(&self.tss) | SEG_LIM!(mem::size_of::<Tss>() as u64 - 1);
        self.gdt[GD_TSS2 >> 3] = SEG_BASEHI!(&self.tss);
    }

    fn setup_safe_stack(&mut self) -> Result<()> {
        let safe_stack: *mut c_void = unsafe { mmap(ptr::null_mut(), PGSIZE, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) };
        if safe_stack == MAP_FAILED {
            return Err(Error::Unknown);
        }

        let safe_stack = unsafe { safe_stack.add(PGSIZE) };
        self.tss.set_tss_iomb(offset_of!(Tss, tss_iopb) as u16);

        for i in 1..8 {
            self.tss.tss_ist[i] = safe_stack as u64;
        }

        self.tss.tss_rsp[0] = safe_stack as u64;

        Ok(())
    }

    /**
     * dune_boot - Brings the user-level OS online
     * @percpu: the thread-local data
     */
    fn dune_boot(&mut self) -> Result<()> {
        self.setup_gdt();

        let mut gdtr = Tptr::default();
        let gdt_ptr = std::ptr::addr_of!(self.gdt);
        unsafe {
            let size = (*gdt_ptr).len() * mem::size_of::<u64>() - 1;
            gdtr.set_base(gdt_ptr as u64)
                .set_limit(size as u16);
        }

        let idt = IDT.lock().unwrap();
        let mut idtr = Tptr::default();
        idtr.set_base(idt.as_ptr() as u64)
            .set_limit((idt.len() * mem::size_of::<IdtDescriptor>() - 1) as u16);

        unsafe {
            asm!(
                // STEP 1: load the new GDT
                "lgdt [{0}]",
                // STEP 2: initialize data segments
                "mov {1:x}, %ax",
                "mov %ax, %ds",
                "mov %ax, %es",
                "mov %ax, %ss",
                // STEP 3: long jump into the new code segment
                "mov {2:x}, %rax",
                "pushq %rax",
                "pushq $1f",
                "lretq",
                "1:",
                "nop",
                // STEP 4: load the task register (for safe stack switching)
                "mov {3:x}, %ax",
                "ltr %ax",
                // STEP 5: load the new IDT and enable interrupts
                "lidt [{4}]",
                "sti",
                in(reg) &gdtr,
                in(reg) GD_KD,
                in(reg) GD_KT,
                in(reg) GD_TSS,
                in(reg) &idtr
            );
        }

        // STEP 6: FS and GS require special initialization on 64-bit
        FsBase::write(self.kfs_base);
        GsBase::write(VirtAddr::new(self as *const _ as u64));

        Ok(())
    }

    pub fn do_dune_enter(&mut self) -> Result<()> {
        let mut dune_vm = DUNE_VM.lock().unwrap();
        let root = dune_vm.get_mut_root();

        // map the stack into the Dune address space
        map_stack();

        let mut conf = DuneConfig::default();
        conf.set_vcpu(0)
            .set_rip(&__dune_ret as *const _ as u64)
            .set_rsp(0)
            .set_cr3(root as *const _ as u64)
            .set_rflags(0x2);

        // NOTE: We don't setup the general purpose registers because __dune_ret
        // will restore them as they were before the __dune_enter call

        let dune_fd = self.device.fd();
        let ret = unsafe { __dune_enter(dune_fd, &conf) };
        if ret != 0 {
            println!("dune: entry to Dune mode failed, ret is {}", ret);
            return Err(Error::Unknown);
        }

        self.dune_boot().map_err(|e|{
            println!("dune: failed to boot Dune mode: {:?}", e);
            unsafe { dune_die() };
            e
        })
    }

    pub fn dune_enter_ex(&mut self) -> Result<()> {
        let fs_base = get_fs_base()?;
        // let percpu = unsafe { &mut *percpu_ptr };
        self.set_kfs_base(fs_base)
            .set_ufs_base(fs_base)
            .set_in_usermode(0)
            .setup_safe_stack()?;

        self.do_dune_enter()
    }
}

pub fn dune_get_user_fs() -> u64 {
    let ptr: u64;
    unsafe {
        asm!(
            "movq %gs:{ufs_base}, {ptr}",
            ufs_base = const offset_of!(DunePercpu, ufs_base),
            ptr = out(reg) ptr,
            options(nostack, preserves_flags)
        );
    }
    ptr
}

pub fn dune_set_user_fs(fs_base: u64) {
    unsafe {
        asm!(
            "movq {fs_base}, %gs:{ufs_base}",
            fs_base = in(reg) fs_base,
            ufs_base = const offset_of!(DunePercpu, ufs_base),
            options(nostack, preserves_flags)
        );
    }
}