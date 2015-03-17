#![allow(non_camel_case_types)]

// http://refspecs.linuxbase.org/elf/elf.pdf
// http://www.x86-64.org/documentation/abi.pdf

use std::ffi::{CStr, OsStr};
use std::os::unix::OsStrExt;
use std::fs::File;
use std::slice::from_raw_parts_mut;
use std::io::{self, Seek};
use std::mem::{uninitialized, size_of};

use libc;

use util::{FillExact, Section, TraceResult, Error};

// [u8; 16]
#[derive(Debug)]
#[repr(packed)]
pub struct Ident {
    pub mag: [u8; 4],
    pub class: u8,
    pub data: u8,
    pub version: u8,
    pub pad: u8,
    pub nident: [u8; 8],
}

#[cfg(target_arch="i686")]
pub type wxword = u32;
#[cfg(target_arch="i686")]
pub type addr = u32;
#[cfg(target_arch="i686")]
pub type off = u32;

#[cfg(target_arch="x86_64")]
pub type wxword = u64;
#[cfg(target_arch="x86_64")]
pub type addr = u64;
#[cfg(target_arch="x86_64")]
pub type off = u64;

// ELF header
#[derive(Debug)]
#[repr(packed)]
pub struct Ehdr {
    pub ident: Ident,
    pub type_: u16,
    pub machine: u16,
    pub version: u32,
    pub entry: addr,
    // program header table offset
    pub phoff: off,
    // section header table offset
    pub shoff: off,
    pub flags: u32,
    pub ehsize: u16,
    pub phentsize: u16,
    pub phnum: u16,
    pub shentsize: u16,
    pub shnum: u16,
    pub shstrndx: u16,
}

// program header
#[derive(Debug)]
#[repr(packed)]
pub struct Phdr {
   // segment type
   pub type_: u32,
   // segment file offset
   pub offset: off,
   // segment virtual address
   pub vaddr: addr,
   // segment physical address
   pub paddr: addr,
   // segment size in file
   pub filesz: u32,
   // segment size in memory
   pub memsz: u32,
   // segment flags
   pub flags: u32,
   // segment alignment
   pub align: u32,
}

// section header
#[derive(Debug)]
#[repr(packed)]
pub struct Shdr {
    // string index of section name
    pub name: u32,
    pub type_: u32,
    pub flags: wxword,
    pub addr: addr,
    pub offset: off,
    pub size: wxword,
    // index of other section header (interpretation depends on type_)
    pub link: u32,
    pub info: u32,
    pub addralign: wxword,
    pub entsize: wxword,
}

// Elf32_Sym
#[cfg(target_arch = "i686")]
#[derive(Debug)]
#[repr(packed)]
pub struct Sym {
    pub name: u32,
    pub value: addr,
    pub size: u32,
    pub info: u8,
    pub other: u8,
    pub shndx: u16,
}
// Elf64_Sym
// http://refspecs.linuxbase.org/elf/gabi4+/ch4.symtab.html
#[cfg(target_arch = "x86_64")]
#[derive(Debug)]
#[repr(packed)]
pub struct Sym {
    pub name: u32,
    pub info: u8,
    pub other: u8,
    pub shndx: u16,
    pub value: addr,
    pub size: u64,
}

macro_rules! read_struct {
    ($name:ident, $t:ty) => (
        pub fn $name<R: FillExact>(reader: &mut R) -> TraceResult<$t> {
            unsafe {
                let mut value: $t = uninitialized();
                {
                    let ptr = &mut value as *mut $t as *mut u8;
                    let buf = from_raw_parts_mut(ptr, size_of::<$t>());
                    try!(reader.fill_exact(buf));
                }
                Ok(value)
            }
        }
    )
}

read_struct!(read_ehdr, Ehdr);
read_struct!(read_shdr, Shdr);
read_struct!(read_sym, Sym);

// TODO move Section to here
fn shdr_to_section(file: &File, shdr: &Shdr) -> TraceResult<Section> {
    Section::new(file, shdr.offset as usize, shdr.size as usize)
}

macro_rules! try_opt {
    ($e:expr) => (
        match $e {
            Some(e) => e,
            None => return Err(Error::ElfParseError),
        }
    )
}

#[derive(Debug)]
#[allow(raw_pointer_derive)]
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct dl_phdr_info {
    // base address of object
    pub addr: usize,
    // null-terminated name of obj
    pub name: *const u8,
    // array of ELF headers for the object
    pub phdr: *const Phdr,
    // length of `phdr`
    pub phnum: u16,
}

pub type phdr_callback = extern fn(info: *mut dl_phdr_info,
                                   size: libc::size_t,
                                   data: *mut libc::c_void) -> libc::c_int;

extern {
    pub fn dl_iterate_phdr(callback: phdr_callback, data: *mut libc::c_void) -> libc::c_int;
}

// current process object and/or shared object.
// TODO better name!
pub struct Elf {
    pub file: File,
    pub base_address: usize,
    pub symtab: Section,
    pub strtab: Section,
    pub debug_info: Option<Section>,
    pub debug_line: Option<Section>,
    pub debug_abbrev: Option<Section>,
    pub debug_ranges: Option<Section>,
    pub debug_str: Option<Section>,
}

impl Elf {
    // NOTE: this does not set `base_address` correctly. it must be fixed by caller
    // FIXME: get path rather than file?
    // file should be seeked at 0
    fn new(mut file: File) -> TraceResult<Elf> {
        let ehdr = try!(read_ehdr(&mut file));
        // TODO: basic sanity check e.g. ehdr.e_ident.mag == b"\x7fELF"

        // we read all section headers here because finding some headers require several lookups.
        let mut shdrs: Vec<Shdr> = Vec::with_capacity(ehdr.shnum as usize);
        for i in 0 .. ehdr.shnum {
            let str_off = ehdr.shoff + (i as u64) * (size_of::<Shdr>() as u64);
            try!(file.seek(io::SeekFrom::Start(str_off)));
            let shdr = try!(read_shdr(&mut file));
            shdrs.push(shdr);
        }

        // section header string table index is given by ehdr.
        let shstr_shdr = try_opt!(shdrs.get(ehdr.shstrndx as usize));
        // shstr = "\0name\0name...name\0";
        let shstr = {
            try!(file.seek(io::SeekFrom::Start(shstr_shdr.offset as u64)));
            let mut shstr = vec![0u8; shstr_shdr.size as usize];
            try!(file.fill_exact(&mut shstr));
            shstr
        };

        // debug sections
        let mut debug_info: Option<Section> = None;
        let mut debug_line: Option<Section> = None;
        let mut debug_abbrev: Option<Section> = None;
        let mut debug_ranges: Option<Section> = None;
        let mut debug_str: Option<Section> = None;

        // symbol table!
        let mut symtab: Option<Section> = None;
        let mut strtab: Option<Section> = None;

        for shdr in &shdrs {
            const SHT_SYMTAB: u32 = 2;
            // TODO const: SHT_DYNSYM: u32 = 11;
            if shdr.type_ == SHT_SYMTAB {
                // symbol table.
                symtab = Some(try!(shdr_to_section(&file, shdr)));
                // `link` has index of symbol name table.
                let strtab_shdr = try_opt!(shdrs.get(shdr.link as usize));
                strtab = Some(try!(shdr_to_section(&file, &strtab_shdr)));
                continue;
            }

            // shdr.name indicates start offset (> 0).
            let name_off = shdr.name as usize;
            let name_len = shstr[name_off..].iter().position(|s| *s == 0).unwrap_or(0);
            let name = &shstr[name_off..(name_off + name_len)];

            match name {
                b".debug_info" | b".debug_line" | b".debug_abbrev" |
                b".debug_ranges" | b".debug_str" => {
                    let section = try!(shdr_to_section(&file, shdr));
                    let section = Some(section);
                    match name {
                        b".debug_info" => debug_info = section,
                        b".debug_line" => debug_line = section,
                        b".debug_abbrev" => debug_abbrev = section,
                        b".debug_ranges" => debug_ranges = section,
                        b".debug_str" => debug_str = section,
                        _ => unreachable!(),
                    }
                }
                _ => {}
            }
        }

        let elf = Elf {
            file: file,
            base_address: 0,
            symtab: try_opt!(symtab),
            strtab: try_opt!(strtab),
            debug_info: debug_info,
            debug_line: debug_line,
            debug_abbrev: debug_abbrev,
            debug_ranges: debug_ranges,
            debug_str: debug_str,
        };

        Ok(elf)
    }
}

fn load_modules() -> TraceResult<Vec<Elf>> {
    // we want to open all objects (main executable and shared libraries).
    // main executable file is accessible via `/proc/self/exe`.
    let f = try!(File::open("/proc/self/exe"));
    // for pie/aslr executables, we don't know base address right now.
    // (`elf.base_address` is `0` but it's wrong.)
    // it will be fixed by `phdr_callback` via `dl_iterate_phdr`.
    let elf = try!(Elf::new(f));

    // open all shared objects. also fix `elf.base_address`.
    let mut modules: Vec<Elf> = vec![elf];
    unsafe {
        let callback_data = &mut modules as *mut _ as *mut libc::c_void;
        let _ret = dl_iterate_phdr(phdr_callback, callback_data);
        // TODO ret check
    }

    Ok(modules)
}

// called by `dl_iterate_phdr` in `Elf::load_modules()`
extern fn phdr_callback(info: *mut dl_phdr_info,
                        _size: libc::size_t,
                        callback_data: *mut libc::c_void) -> libc::c_int {
    println!("info: {:?} / {:?}", unsafe{&*info}, unsafe{&*((*info).phdr)});
    let modules = unsafe { &mut *(callback_data as *mut Vec<Elf>) };
    let info = unsafe { &mut *info };

    if info.name.is_null() || unsafe { *info.name } == 0 {
        // this is (presumely) the main executable. we get base address here.
        if modules[0].base_address == 0 {
            modules[0].base_address = info.addr;
        }
        return 0;
    }

    match phdr_callback_inner(info) {
        Ok(elf) => modules.push(elf),
        // we may fail to load module, e.g. `linux-vdso.so`
        Err(_err) => return 0,
    }

    return 0;

    fn phdr_callback_inner(info: &mut dl_phdr_info) -> TraceResult<Elf> {
        let name = unsafe { CStr::from_ptr(info.name as *const _) };
        println!("name: {}", ::std::str::from_utf8(name.to_bytes()).unwrap());
        let path: &OsStr = OsStr::from_bytes(name.to_bytes());
        let f = try!(File::open(path));
        let mut elf = try!(Elf::new(f));
        elf.base_address = info.addr;
        Ok(elf)
    }
}

// FIXME: this is far from effient:
// right now, "symbol table" is not constructed but we'll do linear search for each request.
pub struct SymbolTable {
    modules: Vec<Elf>,
}

impl SymbolTable {
    pub fn new() -> TraceResult<SymbolTable> {
        let modules = try!(load_modules());
        Ok(SymbolTable {
            modules: modules,
        })
    }

    pub fn symbol_name(&mut self, symaddr: usize) -> TraceResult<Option<&[u8]>> {
        // I know this is very inefficient.. let's just see if this works.
        for e in &mut self.modules {
            try!(e.symtab.seek_at(0));
            loop {
                match read_sym(&mut e.symtab) {
                    Ok(sym) => {
                        // 1: STT_OBJECT
                        // 2: STT_FUNC
                        if sym.info & 0xf != 1 && sym.info & 0xf != 2 {
                            continue;
                        }
                        let start_addr = sym.value as usize + e.base_address;
                        let end_addr = start_addr + (sym.size as usize);

                        if start_addr <= symaddr && symaddr < end_addr {
                            if sym.size == 0 {
                                continue;
                            }
                            let name = try!(e.strtab.c_str_at(sym.name as usize));
                            return Ok(Some(name));
                        }
                    }
                    Err(Error::Eof) => break,
                    Err(e) => return Err(e),
                }
            }
        }

        Ok(None)
    }
}
