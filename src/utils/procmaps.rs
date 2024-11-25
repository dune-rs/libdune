use std::fs::File;
use std::io::{self, BufRead};
use std::fmt::Display;
use std::str::FromStr;

use dune_sys::funcs;
use x86_64::VirtAddr;
// use std::path::Path;

/*
 * procmap.c - Parse linux process map information.
 */

/*
 * Format:
 * start addr-end addr perms offset dev(xx:yy) inode path
 *
 * Permsissions:
 *                     rwxp
 *                     ||||
 *   Readable ---------+|||
 *   (r or -)           |||
 *   Writable ----------+||
 *   (w or -)            ||
 *   Executable ---------+|
 *   (X or -)             |
 *   Private/Shared ------+
 *   (p or s)
 *
 * Special Paths:
 *  - <filename>
 *  - anonymous
 *  - [heap]
 *  - [stack]
 *  - [vsyscall]
 *  - [vdso]
 *
 * Example /proc/self/maps:
 * 00400000-0040b000 r-xp 00000000 fe:00 917797                             /bin/cat
 * 0060a000-0060b000 r--p 0000a000 fe:00 917797                             /bin/cat
 * 0060b000-0060c000 rw-p 0000b000 fe:00 917797                             /bin/cat
 * 022cf000-022f0000 rw-p 00000000 00:00 0                                  [heap]
 * 7fe598687000-7fe59881e000 r-xp 00000000 fe:00 917523                     /lib/libc-2.15.so
 * 7fe59881e000-7fe598a1e000 ---p 00197000 fe:00 917523                     /lib/libc-2.15.so
 * 7fe598a1e000-7fe598a22000 r--p 00197000 fe:00 917523                     /lib/libc-2.15.so
 * 7fe598a22000-7fe598a24000 rw-p 0019b000 fe:00 917523                     /lib/libc-2.15.so
 * 7fe598a24000-7fe598a28000 rw-p 00000000 00:00 0 
 * 7fe598a28000-7fe598a49000 r-xp 00000000 fe:00 917531                     /lib/ld-2.15.so
 * 7fe598c37000-7fe598c3a000 rw-p 00000000 00:00 0 
 * 7fe598c47000-7fe598c48000 rw-p 00000000 00:00 0 
 * 7fe598c48000-7fe598c49000 r--p 00020000 fe:00 917531                     /lib/ld-2.15.so
 * 7fe598c49000-7fe598c4a000 rw-p 00021000 fe:00 917531                     /lib/ld-2.15.so
 * 7fe598c4a000-7fe598c4b000 rw-p 00000000 00:00 0 
 * 7fff601ca000-7fff601eb000 rw-p 00000000 00:00 0                          [stack]
 * 7fff601ff000-7fff60200000 r-xp 00000000 00:00 0                          [vdso]
 * ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
 */

#[derive(Debug, Default, PartialEq)]
pub enum ProcMapType {
    File,
    Anonymous,
    Heap,
    Stack,
    Vsyscall,
    Vdso,
    Vvar,
    #[default]
    Unknown,
}

impl From<String> for ProcMapType {
    fn from(s: String) -> Self {
        if s.starts_with('/') {
            ProcMapType::File
        } else if s.is_empty() {
            ProcMapType::Anonymous
        } else if s == "[heap]" {
            ProcMapType::Heap
        } else if s.starts_with("[stack") {
            ProcMapType::Stack
        } else if s == "[vsyscall]" {
            ProcMapType::Vsyscall
        } else if s == "[vdso]" {
            ProcMapType::Vdso
        } else if s == "[vvar]" {
            ProcMapType::Vvar
        } else {
            ProcMapType::Unknown
        }
    }
}

#[derive(Debug)]
pub struct DuneProcmapEntry {
    pub begin: VirtAddr,
    pub end: VirtAddr,
    pub r: bool,
    pub w: bool,
    pub x: bool,
    pub p: bool,
    pub offset: u64,
    pub path: String,
    pub type_: ProcMapType,
}

impl DuneProcmapEntry {

    funcs!(begin, VirtAddr);
    funcs!(end, VirtAddr);
    funcs!(r, bool);
    funcs!(w, bool);
    funcs!(x, bool);
    funcs!(p, bool);
    funcs!(offset, u64);

    pub fn len(&self) -> u64 {
        self.end - self.begin
    }
}

impl Display for DuneProcmapEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "0x{:016x}-0x{:016x} {}{}{}{} {:08x} {}",
            self.begin,
            self.end,
            if self.r { 'R' } else { '-' },
            if self.w { 'W' } else { '-' },
            if self.x { 'X' } else { '-' },
            if self.p { 'P' } else { 'S' },
            self.offset,
            self.path
        )
    }
}

impl From<String> for DuneProcmapEntry {
    fn from(s: String) -> Self {
        let mut parts = s.split_whitespace();
        let range = parts.next().unwrap();
        let perms = parts.next().unwrap();
        let offset = parts.next().unwrap();
        let _dev = parts.next().unwrap();
        let _inode = parts.next().unwrap();
        let path = parts.next().unwrap_or("");

        let mut range_parts = range.split('-');
        let begin = u64::from_str_radix(range_parts.next().unwrap(), 16).unwrap();
        let end = u64::from_str_radix(range_parts.next().unwrap(), 16).unwrap();

        let r = perms.contains('r');
        let w = perms.contains('w');
        let x = perms.contains('x');
        let p = perms.contains('p');

        let offset = u64::from_str_radix(offset, 16).unwrap();

        let entry = DuneProcmapEntry {
            begin: VirtAddr::new(begin),
            end: VirtAddr::new(end),
            r, w, x, p,
            offset,
            path: path.to_string(),
            type_: path.to_string().into(),
        };

        entry
    }
}

pub fn dune_procmap_iterate<F>(mut cb: F) -> io::Result<()>
where
    F: FnMut(&DuneProcmapEntry) -> Result<(), i32>,
{
    let file = File::open("/proc/self/maps")?;
    let reader = io::BufReader::new(file);
    reader.lines().map(|line| {
        if let Ok(line) = line {
            let entry = DuneProcmapEntry::from(line);
            cb(&entry);
        }
    });

    Ok(())
}

fn dune_procmap_dump_helper(e: &DuneProcmapEntry) -> Result<(), i32> {
    println!("{}", e);
    Ok(())
}

pub fn dune_procmap_dump() -> io::Result<()> {
    println!("--- Process Map Dump ---");
    dune_procmap_iterate(dune_procmap_dump_helper)
}
