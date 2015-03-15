#![feature(io, core, libc, os, std_misc)]

// # on Linux
//
// (libstd story for now)
//
// We rely on libgcc error handling APIs, specified at [LSB][LSB-unwind].
// (see libgcc/unwind.inc and libgcc/unwind-dw2.c for implementation.)
// `_Unwind_Backtrace()` performs stack backtrace and calls callback function
// for each stack frame. In the callback function, we want start address of
// current stack to determine function name. It is provided by `_Unwind_GetIPInfo()`.
// Then, we call `backtrace_syminfo()` to get function name and
// `backtrace_pcinfo()` to get filename and line number.
// (it calls `elf_syminfo` for elf)
//
// [LSB-unwind]: http://refspecs.linuxbase.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/libgcc-sman.html
//
// ## impl strategy
//
// To print extensive information e.g. line number, we need to access several
// sections like `.debug_info`. However, they are not accessible at runtime
// since they are not mapped into memory.
//
// Therefore, we read the executable file itself and parse it! Well, we need
// to read all dynamic libaries in use too.
//
// # on Windows
//
// (TODO :p)
// (see libgcc/unwind-seh.c)

extern crate libc;
#[macro_use]
extern crate log;

use std::io::{self, Write};
use std::mem;
use std::str;

pub mod uw;
#[macro_use] pub mod util;
#[cfg(not(windows))]
pub mod elf;
#[cfg(windows)]
pub mod pe;

#[cfg(not(windows))]
use util::TraceResult;
#[cfg(not(windows))]
use elf::SymbolTable;

#[cfg(not(windows))]
struct Context<'a> {
    writer: &'a mut Write,
    depth: usize,
    depth_limit: usize,
    symbol_table: SymbolTable,
}

#[cfg(not(windows))]
pub fn print_traceback() -> TraceResult<()> {
    let mut writer = io::stderr();
    let mut cx = Context {
        writer: &mut writer,
        depth: 0,
        depth_limit: 10,
        symbol_table: try!(SymbolTable::new()),
    };

    let _backtrace_ret = unsafe {
        uw::_Unwind_Backtrace(trace_callback,
                              &mut cx as *mut Context as *mut libc::c_void)
    };

    // TODO error handling
    // match backtarce_ret {
    //     uw::_URC_NO_REASON => {
    //         match cx.last_error {
    //             Some(err) => Err(err),
    //             None => Ok(())
    //         }
    //     }
    //     _ => Ok(()),
    // };

    Ok(())
}

// some portion stolen from libstd/sys/unix/backtrace.rs
#[cfg(not(windows))]
extern fn trace_callback(ctx: *mut uw::_Unwind_Context,
                         arg: *mut libc::c_void) -> uw::_Unwind_Reason_Code {
    let cx: &mut Context = unsafe { mem::transmute(arg) };
    let mut ip_before_insn = 0;
    let mut ip = unsafe {
        uw::_Unwind_GetIPInfo(ctx, &mut ip_before_insn) as *mut libc::c_void
    };
    if !ip.is_null() && ip_before_insn == 0 {
        // this is a non-signaling frame, so `ip` refers to the address
        // after the calling instruction. account for that.
        ip = (ip as usize - 1) as *mut _;
    }

    // dladdr() on osx gets whiny when we use FindEnclosingFunction, and
    // it appears to work fine without it, so we only use
    // FindEnclosingFunction on non-osx platforms. In doing so, we get a
    // slightly more accurate stack trace in the process.
    //
    // This is often because panic involves the last instruction of a
    // function being "call std::rt::begin_unwind", with no ret
    // instructions after it. This means that the return instruction
    // pointer points *outside* of the calling function, and by
    // unwinding it we go back to the original function.
    let symaddr = if cfg!(target_os = "macos") || cfg!(target_os = "ios") {
        ip
    } else {
        unsafe { uw::_Unwind_FindEnclosingFunction(ip) }
    };

    if cx.depth == cx.depth_limit {
        return uw::_URC_FAILURE;
    }

    match print_trace_info(cx, ip as usize, symaddr as usize) {
        Ok(()) => {}
        Err(e) => {
            let _ = writeln!(cx.writer, "error during print_trace_info: {:?}", e);
            return uw::_URC_FAILURE;
        }
    }

    cx.depth += 1;
    return uw::_URC_NO_REASON;
}

#[cfg(not(windows))]
fn print_trace_info(cx: &mut Context, ip: usize, symaddr: usize) -> TraceResult<()> {
    if symaddr == 0 {
        return Ok(());
    }

    debug!("depth {} ip: {:x} / symaddr: {:x}:", cx.depth, ip as usize, symaddr as usize);
    try!(write!(cx.writer, "[depth {}/{}] ", cx.depth, cx.depth_limit));
    match try!(cx.symbol_table.symbol_name(symaddr)) {
        Some(name) => {
            match str::from_utf8(name) {
                Ok(name) => try!(write!(cx.writer, "`{}`", name)),
                _ => {}
            }
        }
        None => try!(write!(cx.writer, "(???)")),
    }
    try!(writeln!(cx.writer, ""));

    Ok(())
}
