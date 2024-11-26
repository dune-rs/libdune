use std::{arch::asm, u64};
use x86_64::VirtAddr;

pub const NPTBITS: i32 = 9; // log2(NPageTableEntryRIES)
pub const NPTLVLS: usize = 3; // page table depth -1
pub const PD_SKIP: usize = 6; // Offset of pd_lim in Pseudodesc

pub const CR3_NOFLUSH: u64 = 1 << 63;

// ---------------------------------------------------------------------

pub const NR_GDT_ENTRIES: usize = 9;

pub const IDTD_P: u8 = 1 << 7;
pub const IDTD_CPL3: u8 = 3 << 5;
pub const IDTD_TRAP_GATE: u8 = 0xF;
pub const IDTD_INTERRUPT_GATE: u8 = 0xE;

pub const IDT_ENTRIES: usize = 256;

// pub const PGSIZE: usize = 4096;
// pub const PAGEBASE: usize = 0x200000000;
// pub const MAX_PAGES: usize = 1 << 20;
/*
 *
 * Part 1.  Paging data structures and control registers
 *
 */

/* index into:
 *   n = 0 => page table
 *   n = 1 => page directory
 *   n = 2 => page directory pointer
 *   n = 3 => page map level 4
 */
pub const PDXMASK: u64 = (1 << NPTBITS) - 1;

macro_rules! PDSHIFT {
    ($n:expr) => {
        12 + NPTBITS * $n
    };
}

macro_rules! PDX {
    ($n:expr, $la:expr) => {
        ($la >> PDSHIFT!($n)) & PDXMASK
    };
}

pub const NPAGE_TABLE_ENTRY_RIES: usize = 1 << NPTBITS;

/* big page size */
pub const BIG_PGSHIFT: usize = 21;
pub const BIG_PGSIZE: usize = 1 << BIG_PGSHIFT;
pub const BIG_PGMASK: usize = BIG_PGSIZE - 1;

/* offset in big page */
#[allow(unused_macros)]
macro_rules! BIG_PGOFF {
    ($la:expr) => {
        ($la & BIG_PGMASK)
    };
}

#[allow(unused_macros)]
macro_rules! BIG_PGADDR {
    ($la:expr) => {
        ($la & !BIG_PGMASK)
    };
}

/* Page table/directory entry flags. */
pub const PTE_P: u64 = 0x0001; /* Present */
pub const PTE_W: u64 = 0x0002; /* Writeable */
pub const PTE_U: u64 = 0x0004; /* User */
pub const PTE_PWT: u64 = 0x0008; /* Write-Through */
pub const PTE_PCD: u64 = 0x0010; /* Cache-Disable */
pub const PTE_A: u64 = 0x0020; /* Accessed */
pub const PTE_D: u64 = 0x0040; /* Dirty */
pub const PTE_PS: u64 = 0x0080; /* Page size, in PD/PDP/PML4 */
pub const PTE_PAT: u64 = 0x0080; /* Page attribute table, in 4KB PTE */
pub const PTE_G: u64 = 0x0100; /* Global */
pub const PTE_AVAIL: u64 = 0x0E00; /* 3 bits not used by hardware */
pub const PTE_PAT_PS: u64 = 0x1000; /* Page attribute table, in 2MB PTE */
pub const PTE_AVAIL2: u64 = 0x7FF0000000000000; /* 11 bits not used by hardware */
pub const PTE_NX: u64 = 0x8000000000000000; /* No execute */

/* DUNE Specific Flags - Using available bits in PTE */
pub const PTE_COW: u64 = 0x0200; /* Copy-on-write - must also be read-only */
pub const PTE_USR1: u64 = 0x4000000000000000; /* Reserved for user software */
pub const PTE_USR2: u64 = 0x2000000000000000; /* Reserved for user software */
pub const PTE_USR3: u64 = 0x1000000000000000; /* Reserved for user software */

/* Control Register flags */
pub const CR0_PE: u64 = 0x1; /* Protected mode enable */
pub const CR0_MP: u64 = 0x2; /* Monitor coProcessor */
pub const CR0_EM: u64 = 0x4; /* Emulation */
pub const CR0_TS: u64 = 0x8; /* Task Switched */
pub const CR0_ET: u64 = 0x10; /* Extension Type */
pub const CR0_NE: u64 = 0x20; /* Numeric Error */
pub const CR0_WP: u64 = 0x10000; /* Write Protect */
pub const CR0_AM: u64 = 0x40000; /* Alignment Mask */
pub const CR0_NW: u64 = 0x20000000; /* Not Writethrough */
pub const CR0_CD: u64 = 0x40000000; /* Cache Disable */
pub const CR0_PG: u64 = 0x80000000; /* Paging */

pub const CR3_PWT: u64 = 0x8; /* Page-level writethrough */
pub const CR3_PCD: u64 = 0x10; /* Page-level cache disable */

pub const CR4_VME: u64 = 0x1; /* V86 Mode Extensions */
pub const CR4_PVI: u64 = 0x2; /* Protected-Mode Virtual Interrupts */
pub const CR4_TSD: u64 = 0x4; /* Time Stamp Disable */
pub const CR4_DE: u64 = 0x8; /* Debugging Extensions */
pub const CR4_PSE: u64 = 0x10; /* Page Size Extensions */
pub const CR4_PAE: u64 = 0x20; /* Page address extension */
pub const CR4_MCE: u64 = 0x40; /* Machine Check Enable */
pub const CR4_PGE: u64 = 0x80; /* Page-global enable */
pub const CR4_PCE: u64 = 0x100; /* Performance counter enable */
pub const CR4_OSFXSR: u64 = 0x200; /* FXSAVE/FXRSTOR support */
pub const CR4_OSX: u64 = 0x400; /* OS unmasked exception support */

/* EFER Register */
pub const EFER: u32 = 0xc0000080; /* MSR number */
pub const EFER_SCE: u64 = 0x1; /* System-call extension */
pub const EFER_LME: u64 = 0x100; /* Long mode enable */
pub const EFER_LMA: u64 = 0x400; /* Long mode active */
pub const EFER_NXE: u64 = 0x800; /* No-execute enable */
pub const EFER_FFXSR: u64 = 0x4000; /* Fast FXSAVE/FXRSTOR */

/* FS/GS base registers */
pub const MSR_FS_BASE: u32 = 0xc0000100;
pub const MSR_GS_BASE: u32 = 0xc0000101;

/* Debug registers */
pub const MSR_DEBUG_CTL: u32 = 0x1d9; /* MSR number */
pub const DEBUG_CTL_LBR: u64 = 1 << 0; /* Last-Branch Record */

pub const MSR_LBR_FROM_IP: u32 = 0x1db; /* Last branch from IP */
pub const MSR_LBR_TO_IP: u32 = 0x1dc; /* Last branch to IP */
pub const MSR_LEX_FROM_IP: u32 = 0x1dd; /* Last exception from IP */
pub const MSR_LEX_TO_IP: u32 = 0x1de; /* Last exception to IP */

pub const DR7_L: fn(usize) -> u64 = |n| 1 << (n * 2); /* Local breakpoint enable */
pub const DR7_G: fn(usize) -> u64 = |n| 1 << (n * 2 + 1); /* Global breakpoint enable */
pub const DR7_LE: u64 = 1 << 8; /* Local enable */
pub const DR7_GE: u64 = 1 << 9; /* Global enable */
pub const DR7_GD: u64 = 1 << 13; /* General-detect enable */
pub const DR7_RW_SHIFT: fn(usize) -> usize = |n| n * 4 + 16; /* Breakpoint access mode */
pub const DR7_LEN_SHIFT: fn(usize) -> usize = |n| n * 4 + 18; /* Breakpoint addr length */

pub const DR7_RW_EXEC: u64 = 0x0;
pub const DR7_RW_WRITE: u64 = 0x1;
pub const DR7_RW_IO: u64 = 0x2;
pub const DR7_RW_RW: u64 = 0x3;

pub const DR7_LEN_1: u64 = 0x0;
pub const DR7_LEN_2: u64 = 0x1;
pub const DR7_LEN_8: u64 = 0x2;
pub const DR7_LEN_4: u64 = 0x3;

/* Rflags register */
pub const FL_CF: u64 = 0x00000001; /* Carry Flag */
pub const FL_PF: u64 = 0x00000004; /* Parity Flag */
pub const FL_AF: u64 = 0x00000010; /* Auxiliary carry Flag */
pub const FL_ZF: u64 = 0x00000040; /* Zero Flag */
pub const FL_SF: u64 = 0x00000080; /* Sign Flag */
pub const FL_TF: u64 = 0x00000100; /* Trap Flag */
pub const FL_IF: u64 = 0x00000200; /* Interrupt Flag */
pub const FL_DF: u64 = 0x00000400; /* Direction Flag */
pub const FL_OF: u64 = 0x00000800; /* Overflow Flag */
pub const FL_IOPL_MASK: u64 = 0x00003000; /* I/O Privilege Level bitmask */
pub const FL_IOPL_0: u64 = 0x00000000; /*   IOPL == 0 */
pub const FL_IOPL_1: u64 = 0x00001000; /*   IOPL == 1 */
pub const FL_IOPL_2: u64 = 0x00002000; /*   IOPL == 2 */
pub const FL_IOPL_3: u64 = 0x00003000; /*   IOPL == 3 */
pub const FL_NT: u64 = 0x00004000; /* Nested Task */
pub const FL_RF: u64 = 0x00010000; /* Resume Flag */
pub const FL_VM: u64 = 0x00020000; /* Virtual 8086 mode */
pub const FL_AC: u64 = 0x00040000; /* Alignment Check */
pub const FL_VIF: u64 = 0x00080000; /* Virtual Interrupt Flag */
pub const FL_VIP: u64 = 0x00100000; /* Virtual Interrupt Pending */
pub const FL_ID: u64 = 0x00200000; /* ID flag */

/* Page fault error codes */
pub const FEC_P: u64 = 0x1; /* Fault caused by protection violation */
pub const FEC_W: u64 = 0x2; /* Fault caused by a write */
pub const FEC_U: u64 = 0x4; /* Fault occurred in user mode */
pub const FEC_RSV: u64 = 0x8; /* Fault caused by reserved PTE bit */
pub const FEC_I: u64 = 0x10; /* Fault caused by instruction fetch */

/*
 *
 * Part 2.  Segmentation data structures and constants.
 *
 */

 /* STA_ macros are for segment type values */
pub const STA_A: u64 = 1 << 0; /* Accessed */
pub const STA_W: u64 = 1 << 1; /* Writable (for data segments) */
pub const STA_E: u64 = 1 << 2; /* Expand down (for data segments) */
pub const STA_X: u64 = 1 << 3; /* 1 = Code segment (executable) */
pub const STA_R: u64 = 1 << 1; /* Readable (for code segments) */
pub const STA_C: u64 = 1 << 2; /* Conforming (for code segments) */

/* SEG_ macros specify segment type values shifted into place */
pub const SEG_A: u64 = STA_A << 40; /* Accessed */
pub const SEG_W: u64 = STA_W << 40; /* Writable (for data segments) */
pub const SEG_E: u64 = STA_E << 40; /* Expand down (for data segments) */
pub const SEG_X: u64 = STA_X << 40; /* 1 = Code segment (executable) */
pub const SEG_R: u64 = STA_R << 40; /* Readable (for code segments) */
pub const SEG_C: u64 = STA_C << 40; /* Conforming (for code segments) */

pub const SEG_S: u64 = 1 << 44; /* 1 = non-system, 0 = system segment */

pub const SEG_LDT: u64 = 0x2 << 40; /* 64-bit local descriptor segment */
pub const SEG_TSSA: u64 = 0x9 << 40; /* Available 64-bit TSS */
pub const SEG_TSSB: u64 = 0xa << 40; /* Busy 64-bit TSS */
pub const SEG_CG: u64 = 0xc << 40; /* 64-bit Call Gate */
pub const SEG_IG: u64 = 0xe << 40; /* 64-bit Interrupt Gate */
pub const SEG_TG: u64 = 0xf << 40; /* 64-bit Trap Gate */

macro_rules! SEG_DPL {
    ($x:expr) => {
        ($x & 3) << 45
    };
}
pub const SEG_P: u64 = 1 << 47; /* Present */
pub const SEG_L: u64 = 1 << 53; /* Long mode */
pub const SEG_D: u64 = 1 << 54; /* 1 = 32-bit in legacy, 0 in long mode */
pub const SEG_G: u64 = 1 << 55; /* Granularity: 1 = scale limit by 4K */

/* Base and limit for 32-bit or low half of 64-bit segments */
// warn unused macro
#[allow(unused_macros)]
macro_rules! SEG_LIM {
    ($limit:expr) => {
        ($limit & 0xFFFF) as u64 | (($limit >> 16) as u64 & 0xF) << 48
    };
}

#[allow(unused_macros)]
macro_rules! SEG_BASELO {
    ($base:expr) => {
        ($base as *const _ as u64 & 0xFFFFFF) << 16
    };
}

#[allow(unused_macros)]
macro_rules! SEG_BASEHI {
    ($base:expr) => {
        ($base as *const _ as u64 >> 24) & 0xFFFFFFFF
    };
}

#[allow(unused_macros)]
macro_rules! SEG32_ASM {
    ($type:expr, $base:expr, $lim:expr) => {
        ((($lim >> 12) & 0xffff) as u16, ($base & 0xffff) as u16, 
        (($base >> 16) & 0xff) as u8, (0x90 | $type) as u8, 
        (0xC0 | (($lim >> 28) & 0xf)) as u8, (($base >> 24) & 0xff) as u8)
    };
}

#[allow(unused_macros)]
macro_rules! SEG32 {
    ($type:expr, $base:expr, $lim:expr, $dpl:expr) => {
        ($type | SEG_S | SEG_P | SEG_D | SEG_G | SEG_A | SEG_DPL!($dpl) | 
        SEG_BASELO!($base) | SEG_LIM!($lim >> 12))
    };
}

#[allow(unused_macros)]
macro_rules! SEG64 {
    ($type:expr, $dpl:expr) => {
        ($type | SEG_S | SEG_P | SEG_G | SEG_L | SEG_A | SEG_DPL!($dpl) | 
        SEG_LIM!(0xffffffffu32))
    };
}

/* Target and segment selector for trap/interrupt gates */
#[allow(unused_macros)]
macro_rules! SEG_SEL {
    ($x:expr) => {
        (($x & 0xffff) << 16)
    };
}

#[allow(unused_macros)]
macro_rules! SEG_TARGETLO {
    ($x:expr) => {
        ((($x as u64) & 0xffff) | ((($x as u64) & 0xffff0000) << 32))
    };
}

#[allow(unused_macros)]
macro_rules! SEG_TARGETHI {
    ($x:expr) => {
        ($x as u64 >> 32)
    };
}

#[allow(unused_macros)]
macro_rules! GATE32 {
    ($type:expr, $sel:expr, $target:expr, $dpl:expr) => {
        ($type | SEG_DPL!($dpl) | SEG_P | SEG_SEL!($sel) | SEG_TARGETLO!($target))
    };
}

#[allow(unused_macros)]
macro_rules! SETGATE {
    ($gate:expr, $type:expr, $sel:expr, $target:expr, $dpl:expr) => {
        $gate.gd_lo = GATE32!($type, $sel, $target, $dpl);
        $gate.gd_hi = SEG_TARGETHI!($target);
    };
}

/*
 * We use the same general GDT layout as Linux so that can we use
 * the same syscall MSR values. In practice only code segments
 * matter, since ia-32e mode ignores most of segment values anyway,
 * but just to be extra careful we match data as well.
 */
pub const GD_KT: usize = 0x10;
pub const GD_KD: usize = 0x18;
pub const GD_UD: usize = 0x28;
pub const GD_UT: usize = 0x30;
pub const GD_TSS: usize = 0x38;
pub const GD_TSS2: usize = 0x40;

pub const ARCH_GET_FS: i32 = 0x1003;
pub const ARCH_SET_FS: i32 = 0x1004;

// pub const SEG_X: u64 = 0x8;
// pub const SEG_R: u64 = 0x2;
// pub const SEG_W: u64 = 0x2;
// pub const SEG_P: u64 = 0x80;
// pub const SEG_A: u64 = 0x1;
// pub const SEG_TSSA: u64 = 0x89;

pub const VSYSCALL_ADDR: usize = 0xffffffffff600000;

// pub const CREATE_NONE: i32 = 0;
// pub const CREATE_NORMAL: i32 = 1;
// pub const CREATE_BIG: i32 = 2;
// pub const CREATE_BIG_1GB: i32 = 3;

pub const PERM_NONE: i32 = 0;
pub const PERM_R: i32 = 0x0001;
pub const PERM_W: i32 = 0x0002;
pub const PERM_X: i32 = 0x0004;
pub const PERM_U: i32 = 0x0008;
pub const PERM_UC: i32 = 0x0010;
pub const PERM_COW: i32 = 0x0020;
pub const PERM_USR1: i32 = 0x1000;
pub const PERM_USR2: i32 = 0x2000;
pub const PERM_USR3: i32 = 0x3000;
pub const PERM_BIG: i32 = 0x0100;
pub const PERM_BIG_1GB: i32 = 0x0200;

// Helper Macros
pub const VA_START: VirtAddr = VirtAddr::new(u64::MIN);
pub const VA_END: VirtAddr = VirtAddr::new(u64::MAX);

pub const PERM_SCODE: i32 = PERM_R | PERM_X;
pub const PERM_STEXT: i32 = PERM_R | PERM_W;
pub const PERM_SSTACK: i32 = PERM_STEXT;
pub const PERM_UCODE: i32 = PERM_R | PERM_U | PERM_X;
pub const PERM_UTEXT: i32 = PERM_R | PERM_U | PERM_W;
pub const PERM_USTACK: i32 = PERM_UTEXT;

pub const X86_EFLAGS_CF: u64 = 0x1;
pub const X86_EFLAGS_PF: u64 = 0x4;
pub const X86_EFLAGS_AF: u64 = 0x10;
pub const X86_EFLAGS_ZF: u64 = 0x40;
pub const X86_EFLAGS_SF: u64 = 0x80;
pub const X86_EFLAGS_DF: u64 = 0x400;
pub const X86_EFLAGS_OF: u64 = 0x800;
pub const X86_EFLAGS_TF: u64 = 0x100;
pub const X86_EFLAGS_IF: u64 = 0x200;
pub const X86_EFLAGS_IOPL: u64 = 0x3000;
pub const X86_EFLAGS_NT: u64 = 0x4000;


/* x86 trap codes */
pub const T_DIVIDE: usize = 0; // divide error
pub const T_DEBUG: usize = 1; // debug exception
pub const T_NMI: usize = 2; // non-maskable interrupt
pub const T_BRKPT: usize = 3; // breakpoint
pub const T_OFLOW: usize = 4; // overflow
pub const T_BOUND: usize = 5; // bounds check
pub const T_ILLOP: usize = 6; // illegal opcode
pub const T_DEVICE: usize = 7; // device not available
pub const T_DBLFLT: usize = 8; // double fault
// pub const T_COPROC: usize = 9; // reserved (not generated by recent processors)
pub const T_TSS: usize = 10; // invalid task switch segment
pub const T_SEGNP: usize = 11; // segment not present
pub const T_STACK: usize = 12; // stack exception
pub const T_GPFLT: usize = 13; // general protection fault
pub const T_PGFLT: usize = 14; // page fault
// pub const T_RES: usize = 15; // reserved
pub const T_FPERR: usize = 16; // floating point error
pub const T_ALIGN: usize = 17; // alignment check
pub const T_MCHK: usize = 18; // machine check
pub const T_SIMDERR: usize = 19; // SIMD floating point error

// These are arbitrarily chosen, but with care not to overlap
// processor defined exceptions or interrupt vectors.
pub const T_SYSCALL: usize = 48; // system call
pub const GPA_STACK_SIZE: usize = 0x1000;
pub const GPA_MAP_SIZE: usize = 0x1000;

// pub const MSR_FS_BASE: u32 = 0xc0000100;
// pub const MSR_GS_BASE: u32 = 0xc0000101;
pub const MSR_KERNEL_GS_BASE: u32 = 0xc0000102;
pub const MSR_LSTAR: u32 = 0xc0000082; // long mode SYSCALL target

pub fn wrmsrl(msr: u32, value: u64) {
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") (value as u32),
            in("edx") (value >> 32),
            options(nostack, preserves_flags)
        );
    }
}

pub fn rdmsrl(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nostack, preserves_flags)
        );
    }
    ((high as u64) << 32) | (low as u64)
}
