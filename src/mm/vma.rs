use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufRead};
use std::ptr;
use std::str::FromStr;
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::sync::Mutex;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Vma {
    pub start: u64,
    pub end: u64,
    pub prot: u64,
    pub flags: u64,
    pub minor: u32,
    pub major: u32,
    pub inode: u64,
    pub offset: u64,
    pub vm_file: Option<String>,
}

impl Vma {
    pub fn new(path: &str) -> Self {
        Self {
            start: 0,
            end: 0,
            prot: 0,
            flags: 0,
            minor: 0,
            major: 0,
            inode: 0,
            offset: 0,
            vm_file: Some(path.to_string()),
        }
    }

    pub fn create(va_start: u64, len: usize, prot: u64, flags: u64, offset: u64) -> Self {
        Self {
            start: va_start,
            end: va_start + len as u64,
            prot,
            flags,
            minor: 0,
            major: 0,
            inode: 0,
            offset,
            vm_file: None,
        }
    }

    pub fn clone(&self) -> Self {
        Self {
            start: self.start,
            end: self.end,
            prot: self.prot,
            flags: self.flags,
            minor: self.minor,
            major: self.major,
            inode: self.inode,
            offset: self.offset,
            vm_file: self.vm_file.clone(),
        }
    }

    pub fn overlap(&self, other: &Self) -> bool {
        self.start < other.end && other.start < self.end
    }

    pub fn are_adjacent(&self, other: &Self) -> bool {
        self.end == other.start || other.end == self.start
    }

    pub fn merge(&self, other: &Self) -> Option<Self> {
        if !self.are_adjacent(other) || self.prot != other.prot {
            return None;
        }

        Some(Self {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
            prot: self.prot,
            flags: self.flags,
            minor: self.minor,
            major: self.major,
            inode: self.inode,
            offset: self.offset.min(other.offset),
            vm_file: None,
        })
    }

    pub fn split(&mut self, addr: u64) -> Option<Self> {
        if addr <= self.start || addr >= self.end {
            return None;
        }

        let split_vma = Self {
            start: self.start,
            end: addr,
            prot: self.prot,
            flags: self.flags,
            minor: self.minor,
            major: self.major,
            inode: self.inode,
            offset: self.offset,
            vm_file: None,
        };

        self.start = addr;

        Some(split_vma)
    }
}

pub fn parse_procmaps<F>(callback: F) -> io::Result<()>
where
    F: Fn(&Vma),
{
    let file = File::open("/proc/self/maps")?;
    let reader = io::BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        let mut parts = line.split_whitespace();
        let range = parts.next().unwrap();
        let perms = parts.next().unwrap();
        let offset = parts.next().unwrap();
        let dev = parts.next().unwrap();
        let inode = parts.next().unwrap();
        let path = parts.next().unwrap_or("");

        let mut range_parts = range.split('-');
        let start = u64::from_str_radix(range_parts.next().unwrap(), 16).unwrap();
        let end = u64::from_str_radix(range_parts.next().unwrap(), 16).unwrap();

        let mut perms_chars = perms.chars();
        let read = perms_chars.next().unwrap() == 'r';
        let write = perms_chars.next().unwrap() == 'w';
        let execute = perms_chars.next().unwrap() == 'x';
        let private = perms_chars.next().unwrap() == 'p';

        let offset = u64::from_str_radix(offset, 16).unwrap();
        let mut dev_parts = dev.split(':');
        let major = u32::from_str_radix(dev_parts.next().unwrap(), 16).unwrap();
        let minor = u32::from_str_radix(dev_parts.next().unwrap(), 16).unwrap();
        let inode = u64::from_str(inode).unwrap();

        let vma = Vma {
            start,
            end,
            prot: (read as u64) << 2 | (write as u64) << 1 | (execute as u64),
            flags: private as u64,
            minor,
            major,
            inode,
            offset,
            vm_file: if path.is_empty() { None } else { Some(path.to_string()) },
        };

        callback(&vma);
    }

    Ok(())
}

#[test]
fn test_vma() {
    parse_procmaps(|vma| {
        println!("{:?}", vma);
    }).unwrap();
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FreeBlock {
    start: u64,
    size: usize,
}

impl FreeBlock {
    fn new(start: u64, size: usize) -> Self {
        Self { start, size }
    }
}

fn find_free_blocks(vma_map: &VmaMap, va_start: u64, va_end: u64) -> Vec<FreeBlock> {
    // finr free block between va_start and va_end in the VMA map
    let mut free_blocks = Vec::new();
    let mut last_end = va_start;

    for vma in vma_map.values() {
        if vma.start >= last_end && vma.start < va_end {
            let free_size = (vma.start - last_end) as usize;
            if free_size > 0 {
                free_blocks.push(FreeBlock::new(last_end, free_size));
            }
            last_end = vma.end;
        }
    }

    if last_end < va_end {
        free_blocks.push(FreeBlock::new(last_end, (va_end - last_end) as usize));
    }

    free_blocks
}

fn first_fit(vma_map: &VmaMap, size: usize, va_start: u64, va_end: u64) -> Option<u64> {
    let mut last_end = va_start;

    for vma in vma_map.values() {
        if vma.start >= last_end {
            if vma.start < va_end {
                let free_size = (vma.start - last_end) as usize;
                if free_size >= size && last_end + size as u64 <= va_end {
                    return Some(last_end);
                }
            } else {
                break;
            }
            last_end = vma.end;
        }
    }

    if last_end + size as u64 <= va_end {
        return Some(last_end);
    }

    None
}

#[allow(dead_code)]
fn next_fit(vma_map: &VmaMap, size: usize, va_start: u64, va_end: u64, last_end: &mut u64) -> Option<u64> {
    if *last_end < va_start || *last_end >= va_end {
        *last_end = va_start;
    }
    let original_last_end = *last_end;

    for vma in vma_map.values() {
        if vma.start > *last_end && vma.start <= va_end {
            let free_size = (vma.start - *last_end) as usize;
            if free_size >= size && *last_end + size as u64 <= va_end {
                let result = *last_end;
                *last_end += size as u64;
                return Some(result);
            }
        }
        if vma.end > *last_end && vma.end < va_end {
            *last_end = vma.end;
        }
        if *last_end >= va_end {
            *last_end = va_start;
        }
        if *last_end == original_last_end {
            break;
        }
    }

    if *last_end == original_last_end && va_end - *last_end >= size as u64 {
        let result = *last_end;
        *last_end += size as u64;
        return Some(result);
    }

    None
}

#[allow(dead_code)]
fn best_fit(vma_map: &VmaMap, size: usize, va_start: u64, va_end: u64) -> Option<u64> {
    let mut best_start = None;
    let mut best_size = usize::MAX;

    let mut current_start = va_start;

    for vma in vma_map.values() {
        if vma.start >= current_start && vma.end < va_end {
            let free_size = (vma.start - current_start) as usize;
            if free_size >= size && free_size < best_size {
                best_size = free_size;
                best_start = Some(current_start);
            }
            current_start = vma.end;
        }
    }

    if va_end - current_start >= size as u64 && ((va_end - current_start) as usize) < best_size {
        best_start = Some(current_start);
    }

    best_start
}

#[allow(dead_code)]
fn worst_fit(vma_map: &VmaMap, size: usize, va_start: u64, va_end: u64) -> Option<u64> {
    let mut worst_start = None;
    let mut worst_size = 0;

    let mut current_start = va_start;

    for vma in vma_map.values() {
        if vma.start >= current_start && vma.end < va_end {
            let free_size = (vma.start - current_start) as usize;
            if free_size >= size && free_size > worst_size {
                worst_size = free_size;
                worst_start = Some(current_start);
            }
            current_start = vma.end;
        }
    }

    if va_end - current_start >= size as u64 && (va_end - current_start) as usize > worst_size {
        worst_start = Some(current_start);
    }

    worst_start
}

#[allow(dead_code)]
fn random_fit(vma_map: &VmaMap, size: usize, va_start: u64, va_end: u64) -> Option<u64> {
    let mut free_blocks = find_free_blocks(vma_map, va_start, va_end);
    free_blocks.retain(|block| block.size >= size);

    if let Some(block) = free_blocks.choose(&mut thread_rng()) {
        Some(block.start)
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy)]
enum FitAlgorithm {
    FirstFit,
    NextFit,
    BestFit,
    WorstFit,
    RandomFit,
}

impl From<&str> for FitAlgorithm {
    fn from(fit_algorithm: &str) -> Self {
        match fit_algorithm {
            "first_fit" => FitAlgorithm::FirstFit,
            "next_fit" => FitAlgorithm::NextFit,
            "best_fit" => FitAlgorithm::BestFit,
            "worst_fit" => FitAlgorithm::WorstFit,
            "random_fit" => FitAlgorithm::RandomFit,
            _ => FitAlgorithm::FirstFit,
        }
    }
}

type FitAlgorithmFn = fn(&VmaMap, usize, u64, u64) -> Option<u64>;

#[allow(dead_code)]
fn get_fit_algorithm(fit_algorithm: FitAlgorithm) -> FitAlgorithmFn {
    match fit_algorithm {
        FitAlgorithm::FirstFit => first_fit,
        FitAlgorithm::NextFit => first_fit,
        FitAlgorithm::BestFit => best_fit,
        FitAlgorithm::WorstFit => worst_fit,
        FitAlgorithm::RandomFit => random_fit,
    }
}

#[derive(Debug)]
struct VmaMap {
    map: BTreeMap<u64, Vma>,
}

impl VmaMap {
    fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }

    fn insert(&mut self, vma: Vma) -> bool {
        self.map.insert(vma.start, vma).is_none()
    }

    fn find(&self, end_addr: u64) -> Option<Vma> {
        self.map.values().find(|&vma| end_addr <= vma.end).cloned()
    }

    fn find_exact(&self, addr: u64) -> Option<Vma> {
        self.map.values().find(|&vma| addr >= vma.start && addr < vma.end).cloned()
    }

    fn remove(&mut self, start: &u64) -> Option<Vma> {
        self.map.remove(start)
    }

    fn clear(&mut self) {
        self.map.clear()
    }

    fn values(&self) -> impl Iterator<Item = &Vma> {
        self.map.values()
    }

    fn len(&self) -> usize {
        self.map.len()
    }
}

#[derive(Debug)]
pub struct VmplVm {
    vma_map: Mutex<VmaMap>,
    va_start: u64,
    va_end: u64,
    fit_algorithm: FitAlgorithmFn,
    pkey: u64,
}

impl Default for VmplVm {
    fn default() -> Self {
        Self {
            vma_map: Mutex::new(VmaMap::new()),
            va_start: 0,
            va_end: 0,
            fit_algorithm: first_fit,
            pkey: 0,
        }
    }
}

impl VmplVm {
    #[allow(dead_code)]
    fn new(va_start: u64, va_end: u64) -> Self {
        Self {
            vma_map: Mutex::new(VmaMap::new()),
            va_start,
            va_end,
            fit_algorithm: first_fit,
            pkey: 0,
        }
    }

    fn insert_vma(&self, vma: Vma) -> bool {
        if vma.start < self.va_start || vma.end > self.va_end {
            return false;
        }
        let mut vma_map = self.vma_map.lock().unwrap();
        vma_map.insert(vma)
    }

    fn find_vma(&self, end_addr: u64) -> Option<Vma> {
        if end_addr > self.va_end || end_addr < self.va_start {
            return None;
        }
        let vma_map = self.vma_map.lock().unwrap();
        vma_map.find(end_addr)
    }

    #[allow(dead_code)]
    fn find_vma_exact(&self, addr: u64) -> Option<Vma> {
        if addr < self.va_start || addr >= self.va_end {
            return None;
        }
        let vma_map = self.vma_map.lock().unwrap();
        vma_map.find_exact(addr)
    }

    #[allow(dead_code)]
    fn expand_vma(&self, start: u64, new_end: u64) -> bool {
        if new_end > self.va_end {
            return false;
        }
        let mut vma_map = self.vma_map.lock().unwrap();
        if let Some(mut vma) = vma_map.remove(&start) {
            vma.end = new_end;
            vma_map.insert(vma.clone());
            if let Some(next_vma) = vma_map.remove(&vma.end) {
                vma.end = next_vma.end;
                vma_map.insert(vma);
            }
            true
        } else {
            false
        }
    }

    /**
     * @brief Lookup the first VMA that intersects with the given range.
     * @note VMPL-VM Low Level API
     * @param start_addr The start address of the intersection.
     * @param end_addr The end address of the intersection.
     * @return The VMA if found, None otherwise.
     */
    fn find_vma_intersection(&self, start_addr: u64, end_addr: u64) -> Option<Vma> {
        let vma = self.find_vma(end_addr);
        if let Some(vma) = vma {
            if vma.start < end_addr {
                return Some(vma);
            }
        }
        None
    }

    /**
     * @param vma The VMA to remove.
     * @return None.
     */
    fn remove_vma(&self, vma: &Vma) -> bool {
        let mut vma_map = self.vma_map.lock().unwrap();
        vma_map.remove(&vma.start).is_some()
    }

    /**
     * @brief Allocate a VMA from the VMPL-VM.
     * @note VMPL-VM Low Level API
     * @param vm The VMPL-VM to allocate from.
     * @param va_start The start address of the VMA to allocate.
     * @param size The size of the VMA to allocate.
     * @return The allocated VMA if successful, None otherwise.
     */
    #[allow(dead_code)]
    fn alloc_vma_range(&self, va_start: u64, size: usize) -> Option<Vma> {
        let vma_map = self.vma_map.lock().unwrap();

        let va_end = va_start + size as u64;
        if va_start < self.va_start || va_start >= self.va_end || va_end as u64 > self.va_end {
            return None;
        }

        log::trace!("va_start = 0x{:x}, va_end = 0x{:x}, size = 0x{:x}", va_start, va_end, size);
        let va_start = (self.fit_algorithm)(&vma_map, size, va_start, self.va_end)?;
        log::trace!("Allocated VMA at va_start = 0x{:x}", va_start);

        let vma = Vma {
            start: va_start,
            end: va_start + size as u64,
            prot: 0,
            offset: 0,
            vm_file: None,
            ..Default::default()
        };

        Some(vma)
    }
}

fn insert_vma_callback(entry: &Vma, vm: &VmplVm) {
    let new_vma = Vma {
        start: entry.start,
        end: entry.end,
        prot: entry.prot,
        offset: entry.offset,
        vm_file: entry.vm_file.clone(),
        ..Default::default()
    };
    let inserted = vm.insert_vma(new_vma);
    log::trace!("inserted = {}", inserted);
}

fn touch_vma_callback(vma: &Vma) {
    if vma.prot as i32 & (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) != 0 {
        for addr in (vma.start..vma.end).step_by(4096) {
            unsafe {
                ptr::read_volatile(addr as *const u8);
            }
        }
    }
}

#[allow(dead_code)]
fn associate_pkey_callback(vma: &Vma, pkey: &u64) {
    if vma.prot as i32 & (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) != 0 {
        let ret = unsafe {
            libc::syscall(
                libc::SYS_pkey_mprotect,
                vma.start as usize,
                (vma.end - vma.start) as usize,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                *pkey as usize,
            )
        };
        if ret != 0 {
            eprintln!("pkey_mprotect failed: {}", io::Error::last_os_error());
        }
    }
}

impl VmplVm {
    #[allow(dead_code)]
    pub fn init(&mut self, va_start: u64, va_size: usize) -> Result<(), io::Error> {
        let va_end = va_start + va_size as u64;

        // VMPL Preserve Kernel Mapping
        log::debug!("va_start = 0x{:x}, size = 0x{:x}", va_start, va_size);

        // Allocate the Protection Key
        let pkey = unsafe { libc::syscall( libc::SYS_pkey_alloc, 0, 0) };
        if pkey == -1 {
            return Err(io::Error::last_os_error());
        }

        // VMPL VMA Management
        self.pkey = pkey as u64;
        self.va_start = va_start;
        self.va_end = va_end;
        self.fit_algorithm = get_fit_algorithm(FitAlgorithm::FirstFit);

        Ok(())
    }

    #[allow(dead_code)]
    pub fn init_procmaps(&self) -> Result<(), io::Error> {
        // Touch each VMA in the VMA dictionary
        parse_procmaps(touch_vma_callback)?;

        // VMPL VMA Initialization
        parse_procmaps(|vma| insert_vma_callback(vma, self))?;

        // Remove the preserved mapping from the VMA dictionary
        if let Some(vma) = self.find_vma_intersection(self.va_start, self.va_end) {
            assert_eq!(vma.start, self.va_start);
            assert_eq!(vma.end, self.va_end);
            self.remove_vma(&vma);
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn exit(&self) {
        // VMPL VMA Management
        let mut vma_map = self.vma_map.lock().unwrap();
        vma_map.clear();
    }

    #[allow(dead_code)]
    pub fn dump(&self) {
        let vma_map = self.vma_map.lock().unwrap();
        for vma in vma_map.values() {
            if let Some(vm_file) = &vma.vm_file {
                if vm_file == "[vmpl]" {
                    println!("{:?}", vma);
                }
            }
        }
    }

    #[allow(dead_code)]
    pub fn print(&self) {
        println!("VMPL-VM:");
        println!("va_start = 0x{:x}, va_end = 0x{:x}", self.va_start, self.va_end);
        let vma_map = self.vma_map.lock().unwrap();
        for vma in vma_map.values() {
            if let Some(vm_file) = &vma.vm_file {
                if vm_file == "[vmpl]" {
                    println!("{:?}", vma);
                }
            }
        }
    }

    #[allow(dead_code)]
    pub fn stats(&self) {
        println!("VMPL-VM Stats:");
        let vma_map = self.vma_map.lock().unwrap();
        println!("vma_map count = {}", vma_map.len());
        for vma in vma_map.values() {
            println!("{:?}", vma);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vma_creation() {
        let vma = Vma::new("/path/to/file");
        assert_eq!(vma.vm_file, Some("/path/to/file".to_string()));
    }

    #[test]
    fn test_vma_overlap() {
        let vma1 = Vma::create(0, 1000, 0, 0, 0);
        let vma2 = Vma::create(500, 1000, 0, 0, 0);
        assert!(vma1.overlap(&vma2));
    }

    #[test]
    fn test_vma_no_overlap() {
        let vma1 = Vma::create(0, 1000, 0, 0, 0);
        let vma2 = Vma::create(1000, 1000, 0, 0, 0);
        assert!(!vma1.overlap(&vma2));
    }

    #[test]
    fn test_vma_merge() {
        let vma1 = Vma::create(0, 1000, 0, 0, 0);
        let vma2 = Vma::create(1000, 1000, 0, 0, 0);
        let merged_vma = vma1.merge(&vma2).unwrap();
        assert_eq!(merged_vma.start, 0);
        assert_eq!(merged_vma.end, 2000);
    }

    #[test]
    fn test_vma_split() {
        let mut vma = Vma::create(0, 2000, 0, 0, 0);
        let split_vma = vma.split(1000).unwrap();
        assert_eq!(split_vma.start, 0);
        assert_eq!(split_vma.end, 1000);
        assert_eq!(vma.start, 1000);
        assert_eq!(vma.end, 2000);
    }

    #[test]
    fn test_find_free_blocks() {
        let mut vma_map = VmaMap::new();
        vma_map.insert(Vma::create(0, 1000, 0, 0, 0));
        vma_map.insert(Vma::create(2000, 1000, 0, 0, 0));
        let free_blocks = find_free_blocks(&vma_map, 0, 3000);
        assert_eq!(free_blocks.len(), 1);
        assert_eq!(free_blocks[0].start, 1000);
        assert_eq!(free_blocks[0].size, 1000);
    }

    #[test]
    fn test_first_fit() {
        let mut vma_map = VmaMap::new();
        vma_map.insert(Vma::create(0, 1000, 0, 0, 0));
        vma_map.insert(Vma::create(2000, 1000, 0, 0, 0));
        let addr = first_fit(&vma_map, 500, 0, 3000).unwrap();
        assert_eq!(addr, 1000);
    }

    #[test]
    fn test_next_fit() {
        let mut vma_map = VmaMap::new();
        vma_map.insert(Vma::create(0, 1000, 0, 0, 0));
        vma_map.insert(Vma::create(2000, 1000, 0, 0, 0));
        let mut last_end = 0;
        let addr = next_fit(&vma_map, 500, 0, 3000, &mut last_end).unwrap();
        assert_eq!(addr, 1000);
    }

    #[test]
    fn test_best_fit() {
        let mut vma_map = VmaMap::new();
        vma_map.insert(Vma::create(0, 1000, 0, 0, 0));
        vma_map.insert(Vma::create(2000, 1000, 0, 0, 0));
        let addr = best_fit(&vma_map, 500, 0, 3000).unwrap();
        assert_eq!(addr, 1000);
    }

    #[test]
    fn test_worst_fit() {
        let mut vma_map = VmaMap::new();
        vma_map.insert(Vma::create(0, 1000, 0, 0, 0));
        vma_map.insert(Vma::create(2000, 1000, 0, 0, 0));
        let addr = worst_fit(&vma_map, 500, 0, 3000).unwrap();
        assert_eq!(addr, 1000);
    }

    #[test]
    fn test_random_fit() {
        let mut vma_map = VmaMap::new();
        vma_map.insert(Vma::create(0, 1000, 0, 0, 0));
        vma_map.insert(Vma::create(2000, 1000, 0, 0, 0));
        let addr = random_fit(&vma_map, 500, 0, 3000).unwrap();
        assert!(addr == 1000 || addr == 3000);
    }

    #[test]
    fn test_vmpl_vm_insert_vma() {
        let vm = VmplVm::new(0x1000, 0x10000);
        let vma = Vma::create(0x2000, 0x1000, 0, 0, 0);
        assert!(vm.insert_vma(vma));
    }

    #[test]
    fn test_vmpl_vm_find_vma() {
        let vm = VmplVm::new(0x1000, 0x10000);
        let vma = Vma::create(0x2000, 0x1000, 0, 0, 0);
        vm.insert_vma(vma.clone());
        let found_vma = vm.find_vma(0x2000).unwrap();
        assert_eq!(found_vma, vma);
    }

    #[test]
    fn test_vmpl_vm_find_vma_exact() {
        let vm = VmplVm::new(0x1000, 0x10000);
        let vma = Vma::create(0x2000, 0x1000, 0, 0, 0);
        vm.insert_vma(vma.clone());
        let found_vma = vm.find_vma_exact(0x2000).unwrap();
        assert_eq!(found_vma, vma);
    }

    #[test]
    fn test_vmpl_vm_expand_vma() {
        let vm = VmplVm::new(0x1000, 0x10000);
        let vma = Vma::create(0x2000, 0x1000, 0, 0, 0);
        vm.insert_vma(vma.clone());
        assert!(vm.expand_vma(0x2000, 0x3000));
        let expanded_vma = vm.find_vma(0x2000).unwrap();
        assert_eq!(expanded_vma.end, 0x3000);
    }

    #[test]
    fn test_vmpl_vm_find_vma_intersection() {
        let vm = VmplVm::new(0x1000, 0x10000);
        let vma = Vma::create(0x2000, 0x1000, 0, 0, 0);
        vm.insert_vma(vma.clone());
        let found_vma = vm.find_vma_intersection(0x2000, 0x3000).unwrap();
        assert_eq!(found_vma, vma);
    }

    #[test]
    fn test_vmpl_vm_remove_vma() {
        let vm = VmplVm::new(0x1000, 0x10000);
        let vma = Vma::create(0x2000, 0x1000, 0, 0, 0);
        vm.insert_vma(vma.clone());
        assert!(vm.remove_vma(&vma));
        assert!(vm.find_vma(0x2000).is_none());
    }

    #[test]
    fn test_vmpl_vm_alloc_vma_range() {
        let vm = VmplVm::new(0x1000, 0x10000);
        let vma = vm.alloc_vma_range(0x2000, 0x1000).unwrap();
        assert_eq!(vma.start, 0x2000);
        assert_eq!(vma.end, 0x3000);
    }
}