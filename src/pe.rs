use libc;
use std::io::prelude::*;
use std::io;
use std::fs::File;
use std::ffi::OsString;
use std::ffi::CStr;
use std::os::windows::prelude::OsStringExt;
use std::mem::{size_of, transmute};

use util::{TraceResult, FillExact, Section};

const MAX_MODULE_NAME32: usize = 255;
const MAX_PATH: usize = 260;

extern "system" {
    fn GetModuleFileNameW(hModule: libc::HMODULE,
                          lpFileName: libc::LPWSTR,
                          nSize: libc::DWORD) -> libc::DWORD;
    fn CreateToolhelp32Snapshot(dwFlags: libc::DWORD,
                                th32ProcessID: libc::DWORD) -> libc::HANDLE;
    fn Module32FirstW(hSnapshot: libc::HANDLE, lpme: *mut MODULEENTRY32) -> libc::BOOL;
    fn Module32NextW(hSnapshot: libc::HANDLE, lpme: *mut MODULEENTRY32) -> libc::BOOL;
}

#[packed(C)]
struct MODULEENTRY32 {
  dwSize: libc::DWORD,
  th32ModuleID: libc::DWORD,
  th32ProcessID: libc::DWORD,
  GlblcntUsage: libc::DWORD,
  ProccntUsage: libc::DWORD,
  modBaseAddr: *const libc::BYTE,
  modBaseSize: libc::DWORD,
  hModule: libc::HMODULE,
  szModule: [u16; MAX_MODULE_NAME32 + 1],
  szExePath: [u16; MAX_PATH],
}

macro_rules! pe_assert {
    ($e:expr) => ({
        let result: bool = $e;
        if !result {
            return Err($crate::util::Error::PeParseError);
        }
    })
}

// COFF symbol table entry
// 4.4 "COFF Symbol Table"
// http://wiki.osdev.org/COFF#Symbol_Table
#[derive(Debug)]
#[repr(packed)]
pub struct Symbol {
    // symbol name.
    // if name[..4] is all zero, it is offset of string table.
    // if not, it is string.
    name: [u8; 8],
    // (usually) section offset of symbol. actual meaning depends on other fields.
    value: u32,
    section_number: u16,
    // 0x20: function, 0x0: not a function.
    type_: u16,
    storage_class: u8,
    // the number of auxiliary symbols after this symbol.
    num_aux_symbols: u8,
}
read_struct!(read_symbol, Symbol);

fn open_module_file(module: libc::HMODULE) -> TraceResult<File> {
    let mut buf = [0u16; MAX_PATH];
    let len = buf.len();
    let result = unsafe {
        GetModuleFileNameW(module, buf.as_mut_ptr(), len as libc::DWORD)
    };
    pe_assert!(result != 0);
    let filename = OsString::from_wide(&buf[..(result as usize)]);
    let file = try!(File::open(&filename));
    Ok(file)
}

pub fn doit() -> TraceResult<()> {
    // test routine #1: read symbol table of main executable

    let mut f = try!(open_module_file(0 as libc::HMODULE));

    // image file starts with ms-dos stub. the location of pe header is at 0x3c.
    let pos = try!(f.seek(io::SeekFrom::Start(0x3c)));
    pe_assert!(pos == 0x3c);
    let pe_header_pos = try!(f.read_u32());
    println!("header pos: {}", pe_header_pos);

    let pos = try!(f.seek(io::SeekFrom::Start(pe_header_pos as u64)));
    pe_assert!(pos == (pe_header_pos as u64));
    // pe signature: b"PE\0\0"
    let pe_signature = try!(f.read_u32());
    pe_assert!(pe_signature == 0x4550);

    // coff header (20 bytes)
    let machine = try!(f.read_u16());
    pe_assert!(machine == 0x8664); // TODO: x86_64 only for now
    let num_sections = try!(f.read_u16());
    let _timedate = try!(f.read_u32());
    // pecoff_v83 says that this and the next value "should be zero",
    // but in practice they are still used by gcc.
    let symbol_table_offset = try!(f.read_u32()) as usize;
    let num_symbol = try!(f.read_u32());

    println!("sections: {} symbol offset {} numsymbols {}", num_sections, symbol_table_offset, num_symbol);

    let symbol_table_size = (num_symbol as usize) * size_of::<Symbol>();
    let mut symbol_table = try!(Section::new(&f, symbol_table_offset, symbol_table_size));

    // string table is immediately after symbol table.
    let string_table_pos = symbol_table_offset + symbol_table_size;
    let pos = try!(f.seek(io::SeekFrom::Start(string_table_pos as u64)));
    pe_assert!(pos == (string_table_pos as u64));
    let string_table_size = try!(f.read_u32()) as usize;
    let mut string_table = try!(Section::new(&f, string_table_pos, string_table_size));

    for _ in 0..30 {
        let symbol = try!(read_symbol(&mut symbol_table));
        println!("symbol {:?}", symbol);
        if &symbol.name[..4] == &[0; 4] {
            // offset
            let offset: u32 = unsafe { *(symbol.name[4..].as_ptr() as *const u32) };
            let ptr = try!(string_table.ptr_at(offset as usize));
            if ptr.is_null() {
                continue;
            }
            let name = unsafe { CStr::from_ptr(ptr as *const _) };
            println!("symbolname: {}", ::std::str::from_utf8(name.to_bytes()).unwrap_or("???"));
        } else {
            println!("symbolname: {}", ::std::str::from_utf8(&symbol.name).unwrap_or("???"));
        }
        for _ in 0..symbol.num_aux_symbols {
            let aux_symbol = try!(read_symbol(&mut symbol_table));
            println!("aux_symbol {:?}", aux_symbol);
        }
    }

    // test routine #2: get list of modules

    let mut mod_entry = MODULEENTRY32 {
        dwSize: size_of::<MODULEENTRY32>() as libc::DWORD,
        th32ModuleID: 0,
        th32ProcessID: 0,
        GlblcntUsage: 0,
        ProccntUsage: 0,
        modBaseAddr: 0 as *const _,
        modBaseSize: 0,
        hModule: 0 as libc::HMODULE,
        szModule: [0; MAX_MODULE_NAME32 + 1],
        szExePath: [0; MAX_PATH],
    };

    let snapshot = unsafe {
        // TODO: TH32CS_SNAPMODULE32 0x10 (include 32-bit modules)
        // it is not enabled right now since we can't parse 32-bit pe yet (can we?)
        CreateToolhelp32Snapshot(0x8, 0)
    };

    unsafe {
        let ret = Module32FirstW(snapshot, &mut mod_entry);
        pe_assert!(ret == 1);
        let module_name = OsString::from_wide(&mod_entry.szExePath);
        println!("module_name: {:?}", module_name);
        loop {
            let ret = Module32NextW(snapshot, &mut mod_entry);
            if ret == 0 {
                break;
            }
            let module_name = OsString::from_wide(&mod_entry.szExePath);
            println!("module_name: {:?}", module_name);
        }
    }

    Ok(())
}

// pub struct SymbolTable {
//     modules: Vec<Pe>,
// }
