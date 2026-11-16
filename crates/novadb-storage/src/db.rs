//! Database handle, transactions, catalog, checkpoints and integrity checking.

use crate::btree::{self, Node, NodeStore};
use crate::bufpool::BufferPool;
use crate::error::{Error, Result};
use crate::page::{
    self, BODY_SIZE, HEADER_SIZE, MAX_PAGE_ID, PAGE_SIZE, PageBuf, PageId, PageType, get_u32,
    get_u64, new_page_buf, put_u32, put_u64,
};
use crate::pager::Pager;
use crate::recovery::{self, RecoveryReport};
use crate::vfs::{StdVfs, Vfs, VfsFile};
use crate::wal::{self, RecordKind, WalHeader, WalScanner, WalWriter};
use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::ops::{Bound, RangeBounds};
use std::path::Path;

/// Data file name.
pub const DATA_FILE: &str = "data.ndb";
/// WAL file name.
pub const WAL_FILE: &str = "wal.ndb";
const DATA_TMP: &str = "data.ndb.tmp";
const WAL_TMP: &str = "wal.ndb.tmp";

const META_MAGIC: [u8; 8] = *b"NOVADB\0\x01";
const FORMAT_VERSION: u32 = 1;
const CATALOG_ROOT: PageId = 1;
const CATALOG_TREE_ID: u64 = 1;
/// Longest tree name.
pub const MAX_TREE_NAME: usize = 255;
/// Frames kept unpinned so lookups can always proceed during a large transaction.
const POOL_RESERVE: usize = 8;
/// Smallest accepted buffer pool.
pub const MIN_CACHE_PAGES: usize = 32;
/// Catalog key prefix of dropped trees awaiting page reclamation (user names can't contain
/// control characters, so this never collides).
const DROPPED_PREFIX: &[u8] = b"\0dropped\0";
/// Reclamation transactions run per commit/open while dropped trees are pending (bounds the
/// latency a drop adds to unrelated commits).
const PURGE_STEPS_PER_CALL: usize = 8;

/// Tuning options.
#[derive(Debug, Clone)]
pub struct Options {
    /// Buffer pool capacity in pages (16 KiB each). Hard memory cap for cached pages.
    pub cache_pages: usize,
    /// Checkpoint once the WAL grows past this many bytes.
    pub checkpoint_wal_bytes: u64,
    /// Create the database if the directory is empty.
    pub create_if_missing: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            cache_pages: 2048,
            checkpoint_wal_bytes: 64 << 20,
            create_if_missing: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Meta {
    page_count: u64,
    freelist_head: PageId,
    free_count: u64,
    next_tree_id: u64,
    db_id: u64,
}

impl Meta {
    fn encode(&self, p: &mut [u8; PAGE_SIZE]) {
        let b = &mut p[HEADER_SIZE..];
        b[..8].copy_from_slice(&META_MAGIC);
        put_u32(b, 8, FORMAT_VERSION);
        put_u32(b, 12, PAGE_SIZE as u32);
        put_u64(b, 16, self.page_count);
        put_u64(b, 24, self.freelist_head);
        put_u64(b, 32, self.free_count);
        put_u64(b, 40, self.next_tree_id);
        put_u64(&mut p[..], page::META_DB_ID_OFFSET, self.db_id);
    }

    fn decode(p: &[u8; PAGE_SIZE]) -> Result<Meta> {
        let b = &p[HEADER_SIZE..];
        if b[..8] != META_MAGIC {
            return Err(Error::corrupt(
                "meta page: bad magic (not a NovaDB data file?)",
            ));
        }
        let v = get_u32(b, 8);
        if v != FORMAT_VERSION {
            return Err(Error::corrupt(format!(
                "meta page: unsupported format version {v}"
            )));
        }
        if get_u32(b, 12) != PAGE_SIZE as u32 {
            return Err(Error::corrupt("meta page: page size mismatch"));
        }
        let m = Meta {
            page_count: get_u64(b, 16),
            freelist_head: get_u64(b, 24),
            free_count: get_u64(b, 32),
            next_tree_id: get_u64(b, 40),
            db_id: page::meta_db_id(p),
        };
        if m.page_count < 2
            || m.page_count > MAX_PAGE_ID + 1
            || m.freelist_head >= m.page_count
            || m.freelist_head == 1
            || m.free_count >= m.page_count
            || m.next_tree_id <= CATALOG_TREE_ID
            || m.next_tree_id >= 1 << 62
        {
            return Err(Error::corrupt(format!(
                "meta page: inconsistent values {m:?}"
            )));
        }
        Ok(m)
    }
}

/// Handle to a named B+Tree. Only valid for the database it came from; stale handles (after
/// `drop_tree`) are detected via the page owner field and return an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tree {
    id: u64,
    root: PageId,
    /// Random id of the `Db` instance that produced this handle.
    instance: u64,
}

impl Tree {
    /// Internal tree id (never reused while the `Db` handle is open).
    pub fn id(&self) -> u64 {
        self.id
    }
}

/// Engine statistics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    /// Pages in the data file (incl. free).
    pub page_count: u64,
    /// Pages on the free list.
    pub free_pages: u64,
    /// Current WAL size.
    pub wal_bytes: u64,
    /// Buffer pool capacity.
    pub cache_pages: usize,
    /// Pages read from disk.
    pub page_reads: u64,
    /// Pages written to the data file.
    pub page_writes: u64,
    /// Checkpoints taken by this handle.
    pub checkpoints: u64,
    /// Last error while reclaiming dropped trees, if any.
    pub purge_error: Option<String>,
}

/// Result of [`Db::verify`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifyReport {
    /// Number of user trees.
    pub trees: u64,
    /// Total user entries.
    pub entries: u64,
    /// Pages in use (incl. meta + catalog).
    pub used_pages: u64,
    /// Free pages.
    pub free_pages: u64,
    /// Dropped trees whose pages are not reclaimed yet.
    pub dropped_pending: u64,
}

/// An open database. Single writer: all access goes through `&mut self`.
pub struct Db {
    vfs: Box<dyn Vfs>,
    _lock: Box<dyn Any + Send>,
    pager: Pager,
    wal: WalWriter,
    wal_salt: u32,
    pool: BufferPool,
    meta: Meta,
    /// Pages that have a full image in the current WAL generation.
    logged: HashSet<PageId>,
    poisoned: Option<String>,
    opts: Options,
    recovery: RecoveryReport,
    checkpoints: u64,
    /// Random per-open id stamped into `Tree` handles.
    instance: u64,
    /// Tree ids handed out so far; survives rollbacks so ids are never reused in this handle.
    tree_id_floor: u64,
    /// Last error from reclaiming dropped trees (non-fatal; retried on next open/drop).
    purge_error: Option<String>,
    /// Dropped trees may still hold pages.
    purge_pending: bool,
    purging: bool,
}

fn new_salt(avoid: u32) -> u32 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    if let Ok(d) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        h.write_u128(d.as_nanos());
    }
    h.write_u32(std::process::id());
    let s = h.finish() as u32;
    if s == avoid { s ^ 1 } else { s }
}

fn new_db_id() -> u64 {
    let id = (u64::from(new_salt(0)) << 32) | u64::from(new_salt(1));
    if id == 0 { 1 } else { id }
}

/// Atomically install a fresh WAL generation (tmp file + fsync + rename + dir fsync).
fn install_wal(vfs: &dyn Vfs, h: WalHeader) -> Result<Box<dyn VfsFile>> {
    vfs.remove(WAL_TMP)?;
    let mut f = vfs.open(WAL_TMP, true)?;
    f.set_len(0)?;
    f.write_all_at(&h.encode(), 0)?;
    f.sync()?;
    drop(f);
    vfs.rename(WAL_TMP, WAL_FILE)?;
    vfs.sync_dir()?;
    Ok(vfs.open(WAL_FILE, false)?)
}

/// Create a fresh data file atomically.
fn create_data(vfs: &dyn Vfs, db_id: u64) -> Result<()> {
    vfs.remove(DATA_TMP)?;
    let mut pager = Pager::new(vfs.open(DATA_TMP, true)?);
    let mut p0 = new_page_buf();
    page::init_page(&mut p0, 0, PageType::Meta);
    Meta {
        page_count: 2,
        freelist_head: 0,
        free_count: 0,
        next_tree_id: CATALOG_TREE_ID + 1,
        db_id,
    }
    .encode(&mut p0);
    pager.write(0, &mut p0)?;
    let mut p1 = new_page_buf();
    page::init_page(&mut p1, CATALOG_ROOT, PageType::Leaf);
    page::set_page_owner(&mut p1, CATALOG_TREE_ID);
    Node::empty_leaf().encode_into(&mut p1)?;
    pager.write(CATALOG_ROOT, &mut p1)?;
    pager.sync()?;
    drop(pager);
    vfs.rename(DATA_TMP, DATA_FILE)?;
    vfs.sync_dir()?;
    Ok(())
}

fn wal_has_commits(f: &mut dyn VfsFile) -> Result<bool> {
    let (mut sc, _) = WalScanner::open(f)?;
    while let Some(r) = sc.next_record()? {
        if r.kind == RecordKind::Commit {
            return Ok(true);
        }
    }
    Ok(false)
}

impl Db {
    /// Open (or create) a database in directory `dir`.
    pub fn open(dir: impl AsRef<Path>, opts: Options) -> Result<Db> {
        Self::open_vfs(Box::new(StdVfs::new(dir)?), opts)
    }

    /// Open using a custom [`Vfs`] (e.g. [`crate::SimVfs`] for crash testing).
    pub fn open_vfs(vfs: Box<dyn Vfs>, opts: Options) -> Result<Db> {
        if !(MIN_CACHE_PAGES..=1 << 22).contains(&opts.cache_pages) {
            return Err(Error::InvalidArgument(format!(
                "cache_pages must be in {}..={}",
                MIN_CACHE_PAGES,
                1 << 22
            )));
        }
        if opts.checkpoint_wal_bytes < 64 * 1024 {
            return Err(Error::InvalidArgument(
                "checkpoint_wal_bytes must be >= 64 KiB".into(),
            ));
        }
        let lock = vfs.lock()?.ok_or(Error::Locked)?;
        vfs.remove(DATA_TMP)?;
        vfs.remove(WAL_TMP)?;
        match (vfs.exists(DATA_FILE)?, vfs.exists(WAL_FILE)?) {
            (false, false) => {
                if !opts.create_if_missing {
                    return Err(Error::NotFound);
                }
                let db_id = new_db_id();
                install_wal(
                    &*vfs,
                    WalHeader {
                        salt: new_salt(0),
                        start_lsn: 1,
                        db_id,
                    },
                )?;
                create_data(&*vfs, db_id)?;
            }
            (false, true) => {
                // Crash during creation leaves a WAL without commits; anything else means the
                // data file was lost and we must not silently start over.
                let mut w = vfs.open(WAL_FILE, false)?;
                let (_, h0) = WalScanner::open(&mut *w)?;
                // start_lsn 1 + no commits = a WAL from creation that never logged anything.
                // A checkpointed WAL also has no commits, so it must not count as "new".
                if h0.start_lsn != 1 || wal_has_commits(&mut *w)? || !opts.create_if_missing {
                    return Err(Error::corrupt(
                        "data file missing but WAL has committed records",
                    ));
                }
                let (_, h) = WalScanner::open(&mut *w)?;
                drop(w);
                create_data(&*vfs, h.db_id)?;
            }
            (true, false) => {
                return Err(Error::corrupt(
                    "WAL file missing; refusing to open (data file may be inconsistent)",
                ));
            }
            (true, true) => {}
        }

        let mut pager = Pager::new(vfs.open(DATA_FILE, false)?);
        let (report, old) = {
            let mut w = vfs.open(WAL_FILE, false)?;
            let rep = recovery::recover(&mut *w, &mut pager)?;
            let (_, h) = WalScanner::open(&mut *w)?;
            (rep, h)
        };
        let mut p0 = new_page_buf();
        if pager.read(0, &mut p0)? != PageType::Meta {
            return Err(Error::corrupt("page 0 is not a meta page"));
        }
        let meta = Meta::decode(&p0)?;
        if meta.db_id != old.db_id {
            return Err(Error::corrupt(
                "WAL and data file belong to different databases",
            ));
        }
        // Start a new WAL generation; the old one has been fully applied and synced.
        let salt = new_salt(old.salt);
        let header = WalHeader {
            salt,
            start_lsn: report.next_lsn,
            db_id: meta.db_id,
        };
        let wal_file = install_wal(&*vfs, header)?;
        let file_pages = pager.file_pages()?;
        if file_pages < meta.page_count {
            return Err(Error::corrupt(format!(
                "data file has {file_pages} pages, meta says {}",
                meta.page_count
            )));
        }
        Ok(Db {
            vfs,
            _lock: lock,
            pager,
            wal: WalWriter::new(wal_file, header),
            wal_salt: salt,
            pool: BufferPool::new(opts.cache_pages),
            meta,
            logged: HashSet::new(),
            poisoned: None,
            opts,
            recovery: report,
            checkpoints: 0,
            instance: new_db_id(),
            tree_id_floor: meta.next_tree_id,
            purge_error: None,
            purge_pending: true,
            purging: false,
        })
        .map(|mut db| {
            db.purge_dropped();
            db
        })
    }

    /// Reclaim pages of dropped trees, at most `max_steps` bounded transactions. Returns
    /// whether work remains. Runs automatically (with a small budget) after every commit while
    /// work is pending and on open; call it explicitly for maintenance.
    pub fn reclaim_dropped(&mut self, max_steps: usize) -> Result<bool> {
        self.purging = true;
        let r = self.reclaim_inner(max_steps);
        self.purging = false;
        r
    }

    fn reclaim_inner(&mut self, max_steps: usize) -> Result<bool> {
        for _ in 0..max_steps {
            match self.update(|tx| tx.purge_step()) {
                Ok(true) => continue,
                Ok(false) => {
                    self.purge_pending = false;
                    self.purge_error = None;
                    return Ok(false);
                }
                Err(e) => {
                    // Stop automatic retries until reopen; the error is visible in stats.
                    self.purge_pending = false;
                    self.purge_error = Some(e.to_string());
                    return Err(e);
                }
            }
        }
        Ok(true)
    }

    fn purge_dropped(&mut self) {
        // `purging`: the reclamation steps commit too; don't recurse from those commits.
        if self.purge_pending && !self.purging && self.poisoned.is_none() {
            let _ = self.reclaim_dropped(PURGE_STEPS_PER_CALL);
        }
    }

    /// What crash recovery did when this handle was opened.
    pub fn recovery_report(&self) -> &RecoveryReport {
        &self.recovery
    }

    /// Engine statistics.
    pub fn stats(&self) -> Stats {
        Stats {
            page_count: self.meta.page_count,
            free_pages: self.meta.free_count,
            wal_bytes: self.wal.size(),
            cache_pages: self.pool.capacity(),
            page_reads: self.pool.reads,
            page_writes: self.pool.writes,
            checkpoints: self.checkpoints,
            purge_error: self.purge_error.clone(),
        }
    }

    fn ensure_ok(&self) -> Result<()> {
        match &self.poisoned {
            Some(m) => Err(Error::Poisoned(m.clone())),
            None => Ok(()),
        }
    }

    fn poison(&mut self, e: &Error) {
        if self.poisoned.is_none() {
            self.poisoned = Some(e.to_string());
        }
    }

    /// Start a transaction. Dropping it without [`Tx::commit`] rolls back.
    pub fn begin(&mut self) -> Result<Tx<'_>> {
        self.ensure_ok()?;
        let meta = self.meta;
        Ok(Tx {
            db: self,
            before: HashMap::new(),
            meta_before: meta,
            failed: false,
            done: false,
            dropped: false,
        })
    }

    /// Run `f` in a transaction and commit if it returns `Ok`.
    pub fn update<R>(&mut self, f: impl FnOnce(&mut Tx<'_>) -> Result<R>) -> Result<R> {
        let mut tx = self.begin()?;
        let r = f(&mut tx)?;
        tx.commit()?;
        Ok(r)
    }

    /// Run `f` in a transaction that is always rolled back.
    pub fn view<R>(&mut self, f: impl FnOnce(&mut Tx<'_>) -> Result<R>) -> Result<R> {
        let mut tx = self.begin()?;
        f(&mut tx)
    }

    /// Flush all dirty pages, fsync the data file and start a new (empty) WAL generation.
    pub fn checkpoint(&mut self) -> Result<()> {
        self.ensure_ok()?;
        let r = self.checkpoint_inner();
        if let Err(e) = &r {
            self.poison(e);
        }
        r
    }

    fn checkpoint_inner(&mut self) -> Result<()> {
        self.pool.flush_all(&mut self.pager)?;
        self.pager.sync()?;
        let salt = new_salt(self.wal_salt);
        let h = WalHeader {
            salt,
            start_lsn: self.wal.next_lsn(),
            db_id: self.meta.db_id,
        };
        let f = install_wal(&*self.vfs, h)?;
        self.wal = WalWriter::new(f, h);
        self.wal_salt = salt;
        self.logged.clear();
        self.checkpoints += 1;
        Ok(())
    }

    /// Checkpoint and close.
    pub fn close(mut self) -> Result<()> {
        self.checkpoint()
    }

    /// Full integrity check of every tree, the catalog and the free list.
    pub fn verify(&mut self) -> Result<VerifyReport> {
        let mut tx = self.begin()?;
        tx.run(|tx| tx.verify())
    }
}

/// A write transaction (also used for reads). Changes become durable on [`Tx::commit`].
pub struct Tx<'a> {
    db: &'a mut Db,
    /// Before-images of pages modified by this transaction (`None` = newly created page).
    before: HashMap<PageId, Option<(PageBuf, bool)>>,
    meta_before: Meta,
    failed: bool,
    done: bool,
    /// A tree was dropped: reclaim its pages after commit.
    dropped: bool,
}

impl Drop for Tx<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.rollback_inner();
        }
    }
}

struct TreeCtx<'t, 'a> {
    tx: &'t mut Tx<'a>,
    owner: u64,
}

impl NodeStore for TreeCtx<'_, '_> {
    fn read_node(&mut self, id: PageId) -> Result<Node> {
        let owner = self.owner;
        let p = self.tx.page(id)?;
        if page::page_owner(p) != owner {
            return Err(Error::corrupt(format!(
                "page {id} belongs to tree {}, expected tree {owner} (stale handle or corruption)",
                page::page_owner(p)
            )));
        }
        Node::decode(p)
    }
    fn write_node(&mut self, id: PageId, node: &Node) -> Result<()> {
        let owner = self.owner;
        let p = self.tx.page_mut(id)?;
        if page::page_owner(p) != owner {
            return Err(Error::corrupt(format!(
                "write to page {id} not owned by tree {owner}"
            )));
        }
        node.encode_into(p)
    }
    fn alloc_page(&mut self) -> Result<PageId> {
        self.tx.alloc(self.owner)
    }
    fn free_page(&mut self, id: PageId) -> Result<()> {
        self.tx.free(id, self.owner)
    }
}

fn bound_owned(b: Bound<&[u8]>) -> Bound<Vec<u8>> {
    match b {
        Bound::Included(k) => Bound::Included(k.to_vec()),
        Bound::Excluded(k) => Bound::Excluded(k.to_vec()),
        Bound::Unbounded => Bound::Unbounded,
    }
}

impl<'a> Tx<'a> {
    // ----- page access ------------------------------------------------------------------

    fn pin_limit(&self) -> usize {
        self.db.pool.capacity() - POOL_RESERVE
    }

    fn check_id(&self, id: PageId) -> Result<()> {
        if id >= self.db.meta.page_count {
            return Err(Error::corrupt(format!(
                "page {id} out of range (page_count {})",
                self.db.meta.page_count
            )));
        }
        Ok(())
    }

    fn slot(&mut self, id: PageId) -> Result<usize> {
        self.check_id(id)?;
        let db = &mut *self.db;
        match db.pool.fetch(&mut db.pager, id)? {
            Ok(s) => Ok(s),
            Err(_) => Err(Error::TxnTooLarge {
                pages: self.before.len(),
                limit: self.pin_limit(),
            }),
        }
    }

    fn page(&mut self, id: PageId) -> Result<&[u8; PAGE_SIZE]> {
        let s = self.slot(id)?;
        Ok(self.db.pool.page(s))
    }

    fn page_mut(&mut self, id: PageId) -> Result<&mut [u8; PAGE_SIZE]> {
        let s = self.slot(id)?;
        if !self.before.contains_key(&id) {
            if self.before.len() >= self.pin_limit() {
                return Err(Error::TxnTooLarge {
                    pages: self.before.len() + 1,
                    limit: self.pin_limit(),
                });
            }
            let copy: PageBuf = Box::new(*self.db.pool.page(s));
            let dirty = self.db.pool.is_dirty(s);
            self.before.insert(id, Some((copy, dirty)));
        }
        Ok(self.db.pool.page_mut(s))
    }

    fn write_meta(&mut self) -> Result<()> {
        let m = self.db.meta;
        let p = self.page_mut(0)?;
        m.encode(p);
        Ok(())
    }

    fn alloc(&mut self, owner: u64) -> Result<PageId> {
        let head = self.db.meta.freelist_head;
        let id = if head != 0 {
            let p = self.page(head)?;
            if page::page_type(p) != Some(PageType::Free) {
                return Err(Error::corrupt(format!("free-list page {head} is not free")));
            }
            let next = get_u64(p, HEADER_SIZE);
            if next >= self.db.meta.page_count || next == head {
                return Err(Error::corrupt(format!(
                    "free-list page {head}: bad next {next}"
                )));
            }
            let p = self.page_mut(head)?;
            page::init_page(p, head, PageType::Free);
            page::set_page_owner(p, owner);
            self.db.meta.freelist_head = next;
            self.db.meta.free_count = self.db.meta.free_count.saturating_sub(1);
            head
        } else {
            let id = self.db.meta.page_count;
            if id > MAX_PAGE_ID {
                return Err(Error::InvalidArgument("database is full".into()));
            }
            if self.before.len() >= self.pin_limit() {
                return Err(Error::TxnTooLarge {
                    pages: self.before.len() + 1,
                    limit: self.pin_limit(),
                });
            }
            let mut buf = new_page_buf();
            page::init_page(&mut buf, id, PageType::Free);
            page::set_page_owner(&mut buf, owner);
            let db = &mut *self.db;
            let slot = match db.pool.install(&mut db.pager, id, buf)? {
                Ok(s) => s,
                Err(_) => {
                    return Err(Error::TxnTooLarge {
                        pages: self.before.len(),
                        limit: self.pin_limit(),
                    });
                }
            };
            self.before.insert(id, None);
            self.db.pool.page_mut(slot);
            self.db.meta.page_count += 1;
            id
        };
        self.write_meta()?;
        Ok(id)
    }

    fn free(&mut self, id: PageId, owner: u64) -> Result<()> {
        if id <= CATALOG_ROOT {
            return Err(Error::corrupt(format!(
                "attempt to free reserved page {id}"
            )));
        }
        let head = self.db.meta.freelist_head;
        let p = self.page_mut(id)?;
        match page::page_type(p) {
            Some(PageType::Leaf | PageType::Internal) if page::page_owner(p) == owner => {}
            _ => {
                return Err(Error::corrupt(format!(
                    "free of page {id}: not a node of tree {owner}"
                )));
            }
        }
        page::init_page(p, id, PageType::Free);
        put_u64(&mut p[..], HEADER_SIZE, head);
        self.db.meta.freelist_head = id;
        self.db.meta.free_count += 1;
        self.write_meta()
    }

    /// Run a fallible operation; any error after which tree state may be partially modified
    /// fails the transaction (it can only roll back), and I/O errors poison the database.
    fn run<R>(&mut self, f: impl FnOnce(&mut Self) -> Result<R>) -> Result<R> {
        if self.failed {
            return Err(Error::InvalidArgument(
                "transaction failed earlier and can only be rolled back".into(),
            ));
        }
        self.db.ensure_ok()?;
        let r = f(self);
        if let Err(e) = &r {
            if matches!(e, Error::Io(_)) {
                self.db.poison(e);
            }
            self.failed = true;
        }
        r
    }

    fn ctx(&mut self, owner: u64) -> TreeCtx<'_, 'a> {
        TreeCtx { tx: self, owner }
    }

    // ----- catalog ------------------------------------------------------------------------

    fn check_name(name: &str) -> Result<()> {
        if name.is_empty() || name.len() > MAX_TREE_NAME || name.chars().any(char::is_control) {
            return Err(Error::InvalidArgument(format!(
                "tree name must be 1..={MAX_TREE_NAME} bytes without control characters"
            )));
        }
        Ok(())
    }

    fn check_handle(&self, t: &Tree) -> Result<()> {
        if t.instance != self.db.instance {
            return Err(Error::InvalidArgument(
                "tree handle belongs to a different database handle".into(),
            ));
        }
        Ok(())
    }

    fn catalog_tree(&self) -> Tree {
        Tree {
            id: CATALOG_TREE_ID,
            root: CATALOG_ROOT,
            instance: self.db.instance,
        }
    }

    fn parse_catalog_value(&self, key: &[u8], v: &[u8]) -> Result<Tree> {
        if v.len() != 16 {
            return Err(Error::corrupt(format!("catalog entry {key:?}: bad length")));
        }
        let t = Tree {
            id: get_u64(v, 0),
            root: get_u64(v, 8),
            instance: self.db.instance,
        };
        if t.id <= CATALOG_TREE_ID
            || t.id >= self.db.meta.next_tree_id
            || t.root <= CATALOG_ROOT
            || t.root >= self.db.meta.page_count
        {
            return Err(Error::corrupt(format!("catalog entry {key:?}: bad values")));
        }
        Ok(t)
    }

    /// All catalog entries (including dropped trees awaiting reclamation).
    fn catalog_entries(&mut self) -> Result<Vec<(Vec<u8>, Tree)>> {
        let cat = self.catalog_tree();
        let raw: Vec<(Vec<u8>, Vec<u8>)> = self
            .range_inner(cat, (Bound::Unbounded, Bound::Unbounded))?
            .collect::<Result<_>>()?;
        raw.into_iter()
            .map(|(k, v)| {
                let t = self.parse_catalog_value(&k, &v)?;
                Ok((k, t))
            })
            .collect()
    }

    /// One bounded step of reclaiming a dropped tree. Returns whether work remains.
    fn purge_step(&mut self) -> Result<bool> {
        self.run(|tx| {
            let cat = tx.catalog_tree();
            let first = tx
                .range_inner(
                    cat,
                    (Bound::Included(DROPPED_PREFIX.to_vec()), Bound::Unbounded),
                )?
                .next()
                .transpose()?;
            let Some((key, val)) = first else {
                return Ok(false);
            };
            if !key.starts_with(DROPPED_PREFIX) {
                return Ok(false);
            }
            let t = tx.parse_catalog_value(&key, &val)?;
            if let Node::Leaf { .. } = tx.ctx(t.id).read_node(t.root)? {
                tx.free(t.root, t.id)?;
                btree::delete(&mut tx.ctx(CATALOG_TREE_ID), CATALOG_ROOT, &key)?;
                return Ok(true);
            }
            // Shrink the tree by deleting keys (keeps it a valid tree at every commit, so
            // `verify` and crash recovery never see a half-freed structure).
            let budget = tx.pin_limit() / 2;
            let keys: Vec<Vec<u8>> = tx
                .range_inner(t, (Bound::Unbounded, Bound::Unbounded))?
                .take(512)
                .map(|r| r.map(|(k, _)| k))
                .collect::<Result<_>>()?;
            let mut deleted = 0;
            for k in keys {
                if deleted > 0 && tx.before.len() >= budget {
                    break;
                }
                // A key returned by the scan but not found by search means the tree is corrupt;
                // treating it as progress would loop forever (on every open).
                if btree::delete(&mut tx.ctx(t.id), t.root, &k)?.is_none() {
                    return Err(Error::corrupt(format!(
                        "dropped tree {}: scanned key not reachable by search",
                        t.id
                    )));
                }
                deleted += 1;
            }
            if deleted == 0 {
                // Internal root but no entries (only possible after corruption): free directly.
                let mut pages = Vec::new();
                btree::collect_pages(&mut tx.ctx(t.id), t.root, &mut pages)?;
                for p in pages {
                    tx.free(p, t.id)?;
                }
                btree::delete(&mut tx.ctx(CATALOG_TREE_ID), CATALOG_ROOT, &key)?;
            }
            Ok(true)
        })
    }

    fn catalog_get(&mut self, name: &str) -> Result<Option<Tree>> {
        let v = btree::get(
            &mut self.ctx(CATALOG_TREE_ID),
            CATALOG_ROOT,
            name.as_bytes(),
        )?;
        v.map(|v| self.parse_catalog_value(name.as_bytes(), &v))
            .transpose()
    }

    /// Create a new, empty tree.
    pub fn create_tree(&mut self, name: &str) -> Result<Tree> {
        Self::check_name(name)?;
        if self.run(|tx| tx.catalog_get(name))?.is_some() {
            return Err(Error::TreeExists(name.to_string()));
        }
        self.run(|tx| {
            let id = tx.db.meta.next_tree_id.max(tx.db.tree_id_floor);
            if id >= (1 << 62) - 1 {
                return Err(Error::InvalidArgument("tree ids exhausted".into()));
            }
            tx.db.meta.next_tree_id = id + 1;
            tx.db.tree_id_floor = id + 1;
            let root = tx.alloc(id)?;
            let mut c = tx.ctx(id);
            c.write_node(root, &Node::empty_leaf())?;
            let mut v = Vec::with_capacity(16);
            v.extend_from_slice(&id.to_le_bytes());
            v.extend_from_slice(&root.to_le_bytes());
            btree::insert(
                &mut tx.ctx(CATALOG_TREE_ID),
                CATALOG_ROOT,
                name.as_bytes(),
                &v,
            )?;
            Ok(Tree {
                id,
                root,
                instance: tx.db.instance,
            })
        })
    }

    /// Look up an existing tree.
    pub fn open_tree(&mut self, name: &str) -> Result<Tree> {
        Self::check_name(name)?;
        self.run(|tx| tx.catalog_get(name))?
            .ok_or_else(|| Error::TreeNotFound(name.to_string()))
    }

    /// Open a tree, creating it if missing.
    pub fn open_or_create_tree(&mut self, name: &str) -> Result<Tree> {
        match self.open_tree(name) {
            Err(Error::TreeNotFound(_)) => self.create_tree(name),
            r => r,
        }
    }

    /// Delete a tree and free all its pages.
    pub fn drop_tree(&mut self, name: &str) -> Result<()> {
        let t = self.open_tree(name)?;
        self.run(|tx| {
            // Atomically move the tree out of the namespace; its pages are reclaimed after
            // commit in bounded transactions (so trees larger than the cache can be dropped).
            let mut key = DROPPED_PREFIX.to_vec();
            key.extend_from_slice(&t.id.to_be_bytes());
            let mut v = Vec::with_capacity(16);
            v.extend_from_slice(&t.id.to_le_bytes());
            v.extend_from_slice(&t.root.to_le_bytes());
            btree::delete(&mut tx.ctx(CATALOG_TREE_ID), CATALOG_ROOT, name.as_bytes())?;
            btree::insert(&mut tx.ctx(CATALOG_TREE_ID), CATALOG_ROOT, &key, &v)?;
            tx.dropped = true;
            Ok(())
        })
    }

    /// Names of all trees, sorted.
    pub fn list_trees(&mut self) -> Result<Vec<String>> {
        self.catalog_entries()?
            .into_iter()
            .filter(|(k, _)| !k.starts_with(DROPPED_PREFIX))
            .map(|(k, _)| {
                String::from_utf8(k).map_err(|_| Error::corrupt("catalog: non-UTF-8 name"))
            })
            .collect()
    }

    // ----- data ---------------------------------------------------------------------------

    /// Point lookup.
    pub fn get(&mut self, t: &Tree, key: &[u8]) -> Result<Option<Vec<u8>>> {
        btree::check_kv(key, None)?;
        self.check_handle(t)?;
        let t = *t;
        self.run(|tx| btree::get(&mut tx.ctx(t.id), t.root, key))
    }

    /// Insert or overwrite; returns the previous value.
    pub fn put(&mut self, t: &Tree, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        btree::check_kv(key, Some(value))?;
        self.check_handle(t)?;
        let t = *t;
        self.run(|tx| btree::insert(&mut tx.ctx(t.id), t.root, key, value))
    }

    /// Delete; returns the removed value.
    pub fn delete(&mut self, t: &Tree, key: &[u8]) -> Result<Option<Vec<u8>>> {
        btree::check_kv(key, None)?;
        self.check_handle(t)?;
        let t = *t;
        self.run(|tx| btree::delete(&mut tx.ctx(t.id), t.root, key))
    }

    /// Ordered iteration over `range`.
    pub fn range<'t>(
        &'t mut self,
        t: &Tree,
        range: impl RangeBounds<[u8]>,
    ) -> Result<RangeIter<'t, 'a>> {
        self.check_handle(t)?;
        let b = (
            bound_owned(range.start_bound()),
            bound_owned(range.end_bound()),
        );
        self.range_inner(*t, b)
    }

    fn range_inner<'t>(
        &'t mut self,
        t: Tree,
        (start, end): (Bound<Vec<u8>>, Bound<Vec<u8>>),
    ) -> Result<RangeIter<'t, 'a>> {
        let seek: Vec<u8> = match &start {
            Bound::Included(k) | Bound::Excluded(k) => k.clone(),
            Bound::Unbounded => Vec::new(),
        };
        let (_, node) = self.run(|tx| btree::seek_leaf(&mut tx.ctx(t.id), t.root, &seek))?;
        let Node::Leaf { next, entries } = node else {
            return Err(Error::corrupt("seek did not end at a leaf"));
        };
        let steps = self.db.meta.page_count;
        let mut it = RangeIter {
            tx: self,
            tree: t,
            entries: entries.into_iter(),
            next,
            end,
            last: None,
            steps,
            finished: false,
        };
        // Skip entries before the start bound in the first leaf.
        let mut skipped = Vec::new();
        for e in it.entries.by_ref() {
            let keep = match &start {
                Bound::Included(k) => e.0 >= *k,
                Bound::Excluded(k) => e.0 > *k,
                Bound::Unbounded => true,
            };
            if keep {
                skipped.push(e);
                skipped.extend(it.entries.by_ref());
                break;
            }
        }
        it.entries = skipped.into_iter();
        Ok(it)
    }

    // ----- commit / rollback --------------------------------------------------------------

    /// Make all changes durable (WAL fsync) and visible.
    pub fn commit(mut self) -> Result<()> {
        if self.failed {
            self.rollback_inner();
            return Err(Error::InvalidArgument(
                "transaction failed earlier and was rolled back".into(),
            ));
        }
        if let Err(e) = self.db.ensure_ok() {
            self.rollback_inner();
            return Err(e);
        }
        self.done = true;
        if self.before.is_empty() {
            return Ok(());
        }
        let r = self.commit_inner();
        if let Err(e) = &r {
            // The WAL may or may not contain the commit; memory state can't be trusted.
            // Reopening the database recovers to a consistent state.
            self.db.poison(e);
        }
        if r.is_ok() {
            if self.dropped {
                self.db.purge_pending = true;
                self.db.purge_error = None;
            }
            self.db.purge_dropped();
        }
        r
    }

    fn commit_inner(&mut self) -> Result<()> {
        let mut ids: Vec<PageId> = self.before.keys().copied().collect();
        ids.sort_unstable();
        let db = &mut *self.db;
        let mut newly_logged = Vec::new();
        let mut payload = Vec::with_capacity(8 + PAGE_SIZE);
        for &id in &ids {
            let slot = db
                .pool
                .slot_of(id)
                .ok_or_else(|| Error::corrupt(format!("internal: dirty page {id} not resident")))?;
            let prev = self
                .before
                .get(&id)
                .and_then(|b| b.as_ref())
                .map(|(p, _)| p);
            if let Some(prev) = prev
                && wal::diff_pages(prev, db.pool.page(slot)).is_empty()
            {
                continue; // touched but unchanged
            }
            let lsn = db.wal.next_lsn();
            page::set_page_lsn(db.pool.page_mut(slot), lsn);
            let after = db.pool.page(slot);
            let delta = match prev {
                Some(prev) if db.logged.contains(&id) => {
                    wal::encode_delta(id, &wal::diff_pages(prev, after), after)
                }
                _ => None,
            };
            match delta {
                Some(d) => {
                    db.wal.append(RecordKind::PageDelta, &d);
                }
                None => {
                    payload.clear();
                    payload.extend_from_slice(&id.to_le_bytes());
                    payload.extend_from_slice(&after[..]);
                    payload[8..12].fill(0); // checksum field is not logged
                    db.wal.append(RecordKind::PageImage, &payload);
                    newly_logged.push(id);
                }
            }
        }
        db.wal.append(RecordKind::Commit, &[]);
        db.wal.flush_sync()?;
        db.logged.extend(newly_logged);
        for id in ids {
            db.pool.unpin(id);
        }
        self.before.clear();
        if db.wal.size() >= db.opts.checkpoint_wal_bytes
            && let Err(e) = db.checkpoint_inner()
        {
            // The transaction is already durable (WAL fsynced), so commit succeeded; the
            // handle is poisoned and the next operation reports the checkpoint failure.
            db.poison(&e);
        }
        Ok(())
    }

    /// Discard all changes.
    pub fn rollback(mut self) {
        self.rollback_inner();
    }

    fn rollback_inner(&mut self) {
        for (id, b) in self.before.drain() {
            self.db.pool.restore(id, b);
        }
        self.db.meta = self.meta_before;
        self.done = true;
    }

    // ----- verification -------------------------------------------------------------------

    fn verify(&mut self) -> Result<VerifyReport> {
        let n = self.db.meta.page_count;
        let words = usize::try_from(n.div_ceil(64)).map_err(|_| Error::corrupt("page count"))?;
        let mut seen = vec![0u64; words];
        let mut mark = |id: PageId| -> Result<()> {
            if id >= n {
                return Err(Error::corrupt(format!("verify: page {id} out of range")));
            }
            let (w, b) = ((id / 64) as usize, id % 64);
            if seen[w] & (1 << b) != 0 {
                return Err(Error::corrupt(format!(
                    "verify: page {id} referenced twice"
                )));
            }
            seen[w] |= 1 << b;
            Ok(())
        };
        mark(0)?;
        let mut rep = VerifyReport::default();
        let entries = self.catalog_entries()?;
        btree::check(&mut self.ctx(CATALOG_TREE_ID), CATALOG_ROOT, &mut mark)?;
        let mut ids = HashSet::new();
        for (name, t) in entries {
            if !ids.insert(t.id) {
                return Err(Error::corrupt(format!(
                    "verify: duplicate tree id for {name:?}"
                )));
            }
            let st = btree::check(&mut self.ctx(t.id), t.root, &mut mark)?;
            if name.starts_with(DROPPED_PREFIX) {
                rep.dropped_pending += 1;
            } else {
                rep.trees += 1;
                rep.entries += st.entries;
            }
        }
        let mut cur = self.db.meta.freelist_head;
        while cur != 0 {
            mark(cur)?;
            let p = self.page(cur)?;
            if page::page_type(p) != Some(PageType::Free) {
                return Err(Error::corrupt(format!(
                    "verify: free-list page {cur} not free"
                )));
            }
            cur = get_u64(p, HEADER_SIZE);
            rep.free_pages += 1;
        }
        if rep.free_pages != self.db.meta.free_count {
            return Err(Error::corrupt("verify: free count mismatch"));
        }
        let used: u64 = seen.iter().map(|w| w.count_ones() as u64).sum();
        if used != n {
            return Err(Error::corrupt(format!(
                "verify: {} of {n} pages leaked",
                n - used
            )));
        }
        rep.used_pages = n - rep.free_pages;
        Ok(rep)
    }
}

/// Iterator returned by [`Tx::range`]. Yields entries in key order.
pub struct RangeIter<'t, 'a> {
    tx: &'t mut Tx<'a>,
    tree: Tree,
    entries: std::vec::IntoIter<(Vec<u8>, Vec<u8>)>,
    next: PageId,
    end: Bound<Vec<u8>>,
    last: Option<Vec<u8>>,
    steps: u64,
    finished: bool,
}

impl Iterator for RangeIter<'_, '_> {
    type Item = Result<(Vec<u8>, Vec<u8>)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        loop {
            if let Some((k, v)) = self.entries.next() {
                let in_range = match &self.end {
                    Bound::Included(e) => k <= *e,
                    Bound::Excluded(e) => k < *e,
                    Bound::Unbounded => true,
                };
                if !in_range {
                    self.finished = true;
                    return None;
                }
                if self.last.as_ref().is_some_and(|l| *l >= k) {
                    self.finished = true;
                    self.tx.failed = true;
                    return Some(Err(Error::corrupt("leaf chain out of order")));
                }
                self.last = Some(k.clone());
                return Some(Ok((k, v)));
            }
            if self.next == 0 {
                self.finished = true;
                return None;
            }
            if self.steps == 0 {
                self.finished = true;
                return Some(Err(Error::corrupt(
                    "leaf chain longer than the file (cycle?)",
                )));
            }
            self.steps -= 1;
            let (id, owner) = (self.next, self.tree.id);
            match self.tx.run(|tx| tx.ctx(owner).read_node(id)) {
                Ok(Node::Leaf { next, entries }) => {
                    self.next = next;
                    self.entries = entries.into_iter();
                }
                Ok(Node::Internal { .. }) => {
                    self.finished = true;
                    return Some(Err(Error::corrupt(format!(
                        "leaf chain reaches internal page {id}"
                    ))));
                }
                Err(e) => {
                    self.finished = true;
                    return Some(Err(e));
                }
            }
        }
    }
}

const _: () = assert!(BODY_SIZE > 48);
