use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use goblin::elf::{Elf, program_header::ProgramHeader, section_header::SectionHeader};

pub struct DuneElf {
    pub fd: File,
    pub mem: Vec<u8>,
    pub len: usize,
    pub hdr: Elf<'static>,
    pub phdr: Vec<ProgramHeader>,
    pub shdr: Vec<SectionHeader>,
    pub shdrstr: String,
    pub priv_data: Option<Box<dyn std::any::Any>>,
}

pub type DuneElfPhCb = fn(&DuneElf, &ProgramHeader) -> io::Result<()>;
pub type DuneElfShCb = fn(&DuneElf, &str, usize, &SectionHeader) -> io::Result<()>;

impl DuneElf {
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let mut file = File::open(path)?;
        let mut mem = Vec::new();
        file.read_to_end(&mut mem)?;
        let elf = Elf::parse(&mem).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(DuneElf { file, elf, mem })
    }

    pub fn open_mem(mem: Vec<u8>) -> io::Result<Self> {
        let elf = Elf::parse(&mem).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(DuneElf { file: File::open("/dev/null")?, elf, mem })
    }

    pub fn close(self) -> io::Result<()> {
        drop(self);
        Ok(())
    }

    pub fn dump(&self) -> io::Result<()> {
        println!("{:#?}", self.elf);
        Ok(())
    }

    pub fn iter_sh(&self, cb: DuneElfShCb) -> io::Result<()> {
        for (i, sh) in self.elf.section_headers.iter().enumerate() {
            let name = self.elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            cb(self, name, i, sh)?;
        }
        Ok(())
    }

    pub fn iter_ph(&self, cb: DuneElfPhCb) -> io::Result<()> {
        for ph in &self.elf.program_headers {
            cb(self, ph)?;
        }
        Ok(())
    }

    pub fn load_ph(&self, ph: &ProgramHeader, offset: u64) -> io::Result<()> {
        let start = ph.p_offset as usize;
        let end = (ph.p_offset + ph.p_filesz) as usize;
        let data = &self.mem[start..end];
        let dest = unsafe { std::slice::from_raw_parts_mut(offset as *mut u8, data.len()) };
        dest.copy_from_slice(data);
        Ok(())
    }
}

// Export functions

pub fn dune_elf_open(path: &str) -> io::Result<DuneElf> {
    DuneElf::open(path)
}

pub fn dune_elf_open_mem(mem: Vec<u8>) -> io::Result<DuneElf> {
    DuneElf::open_mem(mem)
}

pub fn dune_elf_close(elf: DuneElf) -> io::Result<()> {
    elf.close()
}

pub fn dune_elf_dump(elf: &DuneElf) -> io::Result<()> {
    elf.dump()
}

pub fn dune_elf_iter_sh(elf: &DuneElf, cb: DuneElfShCb) -> io::Result<()> {
    elf.iter_sh(cb)
}

pub fn dune_elf_iter_ph(elf: &DuneElf, cb: DuneElfPhCb) -> io::Result<()> {
    elf.iter_ph(cb)
}

pub fn dune_elf_load_ph(elf: &DuneElf, ph: &ProgramHeader, offset: u64) -> io::Result<()> {
    elf.load_ph(ph, offset)
}
