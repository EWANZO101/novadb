//! Data-file page I/O with checksum and self-id verification.

use crate::error::{Error, Result};
use crate::page::{self, PAGE_SIZE, PageId, PageType};
use crate::vfs::VfsFile;
use std::io;

/// Reads and writes whole pages of the data file.
pub struct Pager {
    file: Box<dyn VfsFile>,
}

impl Pager {
    /// Wrap a data file.
    pub fn new(file: Box<dyn VfsFile>) -> Self {
        Pager { file }
    }

    fn offset(id: PageId) -> Result<u64> {
        if id > page::MAX_PAGE_ID {
            return Err(Error::corrupt(format!("page id {id} out of range")));
        }
        Ok(id * PAGE_SIZE as u64)
    }

    /// Read and verify page `id` into `buf`.
    pub fn read(&mut self, id: PageId, buf: &mut [u8; PAGE_SIZE]) -> Result<PageType> {
        let off = Self::offset(id)?;
        match self.file.read_exact_at(&mut buf[..], off) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(Error::corrupt(format!(
                    "page {id} is beyond the end of the data file"
                )));
            }
            Err(e) => return Err(e.into()),
        }
        page::verify(buf, id)
    }

    /// Seal (checksum) and write page `id`. Not durable until [`Pager::sync`].
    pub fn write(&mut self, id: PageId, buf: &mut [u8; PAGE_SIZE]) -> Result<()> {
        if page::page_id(buf) != id {
            return Err(Error::corrupt(format!(
                "refusing to write page {id}: header says {}",
                page::page_id(buf)
            )));
        }
        let off = Self::offset(id)?;
        page::seal(buf);
        self.file.write_all_at(&buf[..], off)?;
        Ok(())
    }

    /// fsync the data file.
    pub fn sync(&mut self) -> Result<()> {
        self.file.sync()?;
        Ok(())
    }

    /// Number of whole pages in the file.
    pub fn file_pages(&mut self) -> Result<u64> {
        Ok(self.file.size()? / PAGE_SIZE as u64)
    }
}
