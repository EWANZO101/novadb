//! Buffer pool with a hard frame cap and CLOCK eviction.
//!
//! Frames dirtied by the running transaction are *pinned* (no-steal) and never evicted, so
//! uncommitted data never reaches the data file. Committed dirty frames may be evicted; their
//! contents are already durable in the WAL (fsynced at commit), so writing them is safe.

use crate::error::Result;
use crate::page::{PAGE_SIZE, PageBuf, PageId, PageType};
use crate::pager::Pager;
use std::collections::HashMap;

struct Frame {
    id: PageId,
    buf: PageBuf,
    dirty: bool,
    pinned: bool,
    referenced: bool,
}

/// Fixed-capacity page cache.
pub struct BufferPool {
    frames: Vec<Frame>,
    map: HashMap<PageId, usize>,
    cap: usize,
    hand: usize,
    /// Pages read from disk (stats).
    pub reads: u64,
    /// Pages written by eviction/flush (stats).
    pub writes: u64,
}

/// Returned when every frame is pinned by the current transaction.
#[derive(Debug)]
pub struct PoolFull;

impl BufferPool {
    /// Pool holding at most `cap` pages.
    pub fn new(cap: usize) -> Self {
        BufferPool {
            frames: Vec::with_capacity(cap.min(4096)),
            map: HashMap::new(),
            cap,
            hand: 0,
            reads: 0,
            writes: 0,
        }
    }

    /// Capacity in frames.
    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// Whether page `id` is resident.
    pub fn contains(&self, id: PageId) -> bool {
        self.map.contains_key(&id)
    }

    /// Get a free frame index, evicting if necessary. Write errors propagate (caller poisons).
    fn free_slot(&mut self, pager: &mut Pager) -> Result<Result<usize, PoolFull>> {
        if self.frames.len() < self.cap {
            return Ok(Ok(self.frames.len()));
        }
        // Two full sweeps are enough for CLOCK to find an unpinned frame if one exists.
        for _ in 0..2 * self.frames.len() {
            let i = self.hand;
            self.hand = (self.hand + 1) % self.frames.len();
            let f = &mut self.frames[i];
            if f.pinned {
                continue;
            }
            if f.referenced {
                f.referenced = false;
                continue;
            }
            if f.dirty {
                pager.write(f.id, &mut f.buf)?;
                self.writes += 1;
                f.dirty = false;
            }
            self.map.remove(&f.id);
            return Ok(Ok(i));
        }
        Ok(Err(PoolFull))
    }

    fn place(&mut self, slot: usize, id: PageId, buf: PageBuf) {
        let f = Frame {
            id,
            buf,
            dirty: false,
            pinned: false,
            referenced: true,
        };
        if slot == self.frames.len() {
            self.frames.push(f);
        } else {
            self.frames[slot] = f;
        }
        self.map.insert(id, slot);
    }

    /// Ensure `id` is resident; returns its frame index.
    pub fn fetch(&mut self, pager: &mut Pager, id: PageId) -> Result<Result<usize, PoolFull>> {
        if let Some(&i) = self.map.get(&id) {
            self.frames[i].referenced = true;
            return Ok(Ok(i));
        }
        let mut buf = crate::page::new_page_buf();
        pager.read(id, &mut buf)?;
        self.reads += 1;
        let slot = match self.free_slot(pager)? {
            Ok(s) => s,
            Err(full) => return Ok(Err(full)),
        };
        self.place(slot, id, buf);
        Ok(Ok(slot))
    }

    /// Install a brand-new page (not yet on disk).
    pub fn install(
        &mut self,
        pager: &mut Pager,
        id: PageId,
        buf: PageBuf,
    ) -> Result<Result<usize, PoolFull>> {
        if let Some(&i) = self.map.get(&id) {
            self.frames[i].buf = buf;
            return Ok(Ok(i));
        }
        let slot = match self.free_slot(pager)? {
            Ok(s) => s,
            Err(full) => return Ok(Err(full)),
        };
        self.place(slot, id, buf);
        Ok(Ok(slot))
    }

    /// Page bytes of a resident frame.
    pub fn page(&self, slot: usize) -> &[u8; PAGE_SIZE] {
        &self.frames[slot].buf
    }

    /// Mutable page bytes; marks the frame dirty and pinned.
    pub fn page_mut(&mut self, slot: usize) -> &mut [u8; PAGE_SIZE] {
        let f = &mut self.frames[slot];
        f.dirty = true;
        f.pinned = true;
        &mut f.buf
    }

    /// Frame index for a resident page.
    pub fn slot_of(&self, id: PageId) -> Option<usize> {
        self.map.get(&id).copied()
    }

    /// Dirty flag of a frame.
    pub fn is_dirty(&self, slot: usize) -> bool {
        self.frames[slot].dirty
    }

    /// Unpin after commit (contents now durable in the WAL).
    /// Keep a resident frame in memory (it holds uncommitted changes).
    pub fn pin(&mut self, id: PageId) {
        if let Some(&i) = self.map.get(&id) {
            self.frames[i].pinned = true;
        }
    }

    pub fn unpin(&mut self, id: PageId) {
        if let Some(&i) = self.map.get(&id) {
            self.frames[i].pinned = false;
        }
    }

    /// Roll back a frame to `before` (or drop it if it was created by the transaction).
    pub fn restore(&mut self, id: PageId, before: Option<(PageBuf, bool)>) {
        let Some(&i) = self.map.get(&id) else { return };
        match before {
            Some((buf, dirty)) => {
                let f = &mut self.frames[i];
                f.buf = buf;
                f.dirty = dirty;
                f.pinned = false;
            }
            None => {
                // Page did not exist before the transaction: forget it. The frame gets a
                // sentinel id that is never looked up; CLOCK reclaims it.
                self.map.remove(&id);
                let f = &mut self.frames[i];
                f.dirty = false;
                f.pinned = false;
                f.referenced = false;
                f.id = u64::MAX;
            }
        }
    }

    /// Write every dirty frame (checkpoint). Pinned frames must not exist at this point.
    pub fn flush_all(&mut self, pager: &mut Pager) -> Result<()> {
        for f in &mut self.frames {
            if f.dirty && f.id != u64::MAX {
                debug_assert!(!f.pinned);
                pager.write(f.id, &mut f.buf)?;
                self.writes += 1;
                f.dirty = false;
            }
        }
        Ok(())
    }

    /// Type byte of a resident page (debug helper).
    pub fn page_type(&self, slot: usize) -> Option<PageType> {
        PageType::from_u8(self.frames[slot].buf[4])
    }
}
