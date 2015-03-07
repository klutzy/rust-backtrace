use std::error::FromError;
use std::fs::File;
use std::io::{self, Read};
use std::mem::transmute;
use std::os::{self, MemoryMap, MapOption};
use std::ptr;

use libc;

#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
    MmapError(os::MapError),
    ElfParseError,
    Eof,
}

impl FromError<io::Error> for Error {
    fn from_error(err: io::Error) -> Error {
        Error::IoError(err)
    }
}

impl FromError<os::MapError> for Error {
    fn from_error(err: os::MapError) -> Error {
        Error::MmapError(err)
    }
}

pub type TraceResult<T> = Result<T, Error>;

pub trait FillExact: Read {
    #[inline]
    fn fill_exact(&mut self, buf: &mut [u8]) -> TraceResult<()> {
        let len = buf.len();
        let mut pos = 0;
        while pos < len {
            let num_bytes = try!(self.read(&mut buf[pos..]));
            debug_assert!(pos + num_bytes <= len);
            if num_bytes == 0 {
                return Err(Error::Eof);
            }
            pos += num_bytes;
        }
        Ok(())
    }

    #[inline(always)]
    fn read_u8(&mut self) -> TraceResult<u8> {
        let mut buf = [0u8];
        try!(self.fill_exact(&mut buf));
        Ok(buf[0])
    }

    // NOTE: assumes native endian.
    #[inline(always)]
    fn read_u16(&mut self) -> TraceResult<u16> {
        let mut buf = [0u8; 2];
        try!(self.fill_exact(&mut buf));
        Ok(unsafe { transmute(buf) })
    }
    #[inline(always)]
    fn read_u32(&mut self) -> TraceResult<u32> {
        let mut buf = [0u8; 4];
        try!(self.fill_exact(&mut buf));
        Ok(unsafe { transmute(buf) })
    }
    #[inline(always)]
    fn read_u64(&mut self) -> TraceResult<u64> {
        let mut buf = [0u8; 8];
        try!(self.fill_exact(&mut buf));
        Ok(unsafe { transmute(buf) })
    }
}

impl<R: Read> FillExact for R {}

#[cfg(not(windows))]
fn get_fd(file: &File) -> libc::c_int {
    use std::os::unix::AsRawFd;
    file.as_raw_fd()
}
#[cfg(windows)]
fn get_fd(file: &File) -> libc::HANDLE {
    use std::os::windows::AsRawHandle;
    file.as_raw_handle()
}

// TODO: add lifetime?
// TODO: rather than directly implementing Read, provide a view/reader which accepts `start` pos
// (so you will always `seek_at` automatically)
pub struct Section {
    // TODO this just maps all section area into memory. definitely not efficient?
    map: MemoryMap,
    // due to aligning issue, there may be some gap before actual data we want.
    align_size: usize,
    cur: usize,
}

impl Section {
    pub fn new(file: &File, offset: usize, len: usize) -> TraceResult<Section> {
        let fd = get_fd(&file);

        let align_size = offset % MemoryMap::granularity();
        let aligned_offset = offset - align_size;

        let map_args = [
            MapOption::MapReadable,
            MapOption::MapFd(fd),
            MapOption::MapOffset(aligned_offset),
        ];
        let map = try!(MemoryMap::new(len + align_size, &map_args));

        Ok(Section {
            map: map,
            align_size: align_size,
            cur: 0,
        })
    }

    pub fn ptr_at(&self, pos: usize) -> TraceResult<*const u8> {
        let section_len = self.map.len() - self.align_size;
        if pos >= section_len {
            return Err(Error::Eof);
        }
        let ptr = unsafe {
            (self.map.data() as *const u8).offset((self.align_size + pos) as isize)
        };
        Ok(ptr)
    }

    // TODO implement `Seek`?
    pub fn seek_at(&mut self, new_pos: usize) -> TraceResult<usize> {
        let len = self.map.len();
        if new_pos as usize > len {
            // eof
            self.cur = len as usize;
        } else {
            self.cur = new_pos as usize;
        }
        Ok(self.cur)
    }
}

impl Read for Section {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let section_len = self.map.len() - self.align_size;
        debug_assert!(self.cur <= section_len);

        if self.cur == section_len {
            return Ok(0);
        }

        let buflen = buf.len();
        let section_available = section_len - self.cur;
        let len = if buflen > section_available { section_available } else { buflen };
        unsafe {
            let pos = (self.map.data() as *const u8).offset((self.align_size + self.cur) as isize);
            ptr::copy(buf.as_mut_ptr(), pos, len);
        }
        self.cur += len;

        Ok(len)
    }
}
