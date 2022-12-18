use libc::{EINVAL, EROFS};
use std::collections::Bound;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::ops::RangeBounds;
use std::os::unix::fs::FileExt;

pub struct FileSliceCursor<'a, F: FileExt> {
    inner: &'a F,
    begin: u64,
    end: u64,
    offset: u64,
}

impl<'a, F: FileExt> FileSliceCursor<'a, F> {
    pub fn new(file: &'a F, begin: u64, end: u64) -> Self {
        Self {
            inner: file,
            begin,
            end,
            offset: begin,
        }
    }

    pub fn slice(&self, range: impl RangeBounds<u64>) -> Self {
        let end = match range.end_bound() {
            Bound::Included(bound) => (self.begin + *bound + 1).min(self.end),
            Bound::Excluded(bound) => (self.begin + *bound).min(self.end),
            Bound::Unbounded => self.end,
        };
        let begin = match range.start_bound() {
            Bound::Included(bound) => (self.begin + *bound).min(end),
            Bound::Excluded(bound) => (self.begin + *bound + 1).min(end),
            Bound::Unbounded => self.begin,
        };
        Self {
            inner: self.inner,
            begin,
            end,
            offset: self.offset,
        }
    }

    pub fn with_buffering<R>(
        &mut self,
        f: impl FnOnce(&mut BufReader<Self>) -> anyhow::Result<R>,
    ) -> anyhow::Result<R> {
        let mut reader = BufReader::new(self.slice(..));
        let res = f(&mut reader)?;
        let new_pos = reader.stream_position()?;
        self.seek(SeekFrom::Start(new_pos))?;
        Ok(res)
    }

    pub fn len(&self) -> u64 {
        self.end - self.begin
    }
}

impl<'a> FileSliceCursor<'a, File> {
    pub fn from_file(file: &'a mut File) -> Self {
        let file_len = file.seek(SeekFrom::End(0)).unwrap();
        Self::new(file, 0, file_len)
    }
}

impl<'a, F: FileExt> Read for FileSliceCursor<'a, F> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.offset > self.end {
            return Ok(0);
        }
        let read_wanted = buf.len().min((self.end - self.offset) as usize);
        let count = self.inner.read_at(&mut buf[..read_wanted], self.offset)?;
        self.offset += count as u64;
        Ok(count)
    }
}

impl<'a, F: FileExt> Seek for FileSliceCursor<'a, F> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match pos {
            SeekFrom::Start(off) => {
                self.offset = self.begin + off;
            }
            SeekFrom::End(off) => {
                let new_off = self.end as i64 + off;
                if new_off < self.begin as i64 {
                    return Err(std::io::Error::from_raw_os_error(EINVAL));
                }
                self.offset = new_off as u64;
            }
            SeekFrom::Current(off) => {
                let new_off = self.offset as i64 + off;
                if new_off < self.begin as i64 {
                    return Err(std::io::Error::from_raw_os_error(EINVAL));
                }
                self.offset = new_off as u64;
            }
        }
        Ok(self.offset - self.begin)
    }

    fn stream_len(&mut self) -> std::io::Result<u64> {
        Ok(self.end - self.begin)
    }

    fn stream_position(&mut self) -> std::io::Result<u64> {
        Ok(self.offset - self.begin)
    }
}

impl<'a, F: FileExt> FileExt for FileSliceCursor<'a, F> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
        let read_begin = self.begin.checked_add(offset).unwrap();
        let read_end = read_begin
            .checked_add(buf.len() as u64)
            .unwrap()
            .min(self.end);
        self.inner
            .read_at(&mut buf[..(read_end - read_begin) as usize], read_begin)
    }

    fn write_at(&self, _buf: &[u8], _offset: u64) -> std::io::Result<usize> {
        Err(std::io::Error::from_raw_os_error(EROFS))
    }
}
