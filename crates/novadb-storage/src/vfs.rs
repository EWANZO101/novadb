//! File-system abstraction.
//!
//! [`StdVfs`] is the real implementation (one directory per database). [`SimVfs`] is an
//! in-memory simulation that models **power loss**: writes are volatile until `sync`, directory
//! changes (create/rename/remove) are volatile until `sync_dir`, and [`SimVfs::crash`] keeps a
//! random subset of un-synced writes, tearing them at 512-byte sector granularity. It also
//! supports fault injection (I/O errors after N operations) for deterministic crash testing.

use std::any::Any;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

/// A random-access file.
pub trait VfsFile: Send {
    /// Read exactly `buf.len()` bytes at `off`; `UnexpectedEof` if the file is too short.
    fn read_exact_at(&mut self, buf: &mut [u8], off: u64) -> io::Result<()>;
    /// Write all of `buf` at `off`, extending the file if needed.
    fn write_all_at(&mut self, buf: &[u8], off: u64) -> io::Result<()>;
    /// Current length in bytes.
    fn size(&mut self) -> io::Result<u64>;
    /// Truncate or extend.
    fn set_len(&mut self, len: u64) -> io::Result<()>;
    /// Make all previous writes durable (fsync).
    fn sync(&mut self) -> io::Result<()>;
}

/// A directory holding one database.
pub trait Vfs: Send {
    /// Open a file, creating it if `create` is set. Creation is durable only after `sync_dir`.
    fn open(&self, name: &str, create: bool) -> io::Result<Box<dyn VfsFile>>;
    /// Whether a file exists.
    fn exists(&self, name: &str) -> io::Result<bool>;
    /// Atomically replace `to` with `from`. Durable only after `sync_dir`.
    fn rename(&self, from: &str, to: &str) -> io::Result<()>;
    /// Remove a file (no error if missing).
    fn remove(&self, name: &str) -> io::Result<()>;
    /// fsync the directory itself.
    fn sync_dir(&self) -> io::Result<()>;
    /// Take an exclusive lock on the directory. The lock is held while the returned guard lives.
    fn lock(&self) -> io::Result<Option<Box<dyn Any + Send>>>;
}

fn check_name(name: &str) -> io::Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid file name",
        ))
    }
}

// ---------------------------------------------------------------------------------------------
// Real file system
// ---------------------------------------------------------------------------------------------

/// Real directory on disk.
#[derive(Debug, Clone)]
pub struct StdVfs {
    dir: PathBuf,
}

impl StdVfs {
    /// Use `dir` (created with mode 0700 on Unix if missing).
    pub fn new(dir: impl AsRef<Path>) -> io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        if !dir.exists() {
            let mut b = std::fs::DirBuilder::new();
            b.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                b.mode(0o700);
            }
            b.create(&dir)?;
        }
        Ok(StdVfs { dir })
    }

    fn path(&self, name: &str) -> io::Result<PathBuf> {
        check_name(name)?;
        Ok(self.dir.join(name))
    }
}

struct StdFile(File);

impl VfsFile for StdFile {
    #[cfg(unix)]
    fn read_exact_at(&mut self, buf: &mut [u8], off: u64) -> io::Result<()> {
        std::os::unix::fs::FileExt::read_exact_at(&self.0, buf, off)
    }
    #[cfg(unix)]
    fn write_all_at(&mut self, buf: &[u8], off: u64) -> io::Result<()> {
        std::os::unix::fs::FileExt::write_all_at(&self.0, buf, off)
    }
    #[cfg(windows)]
    fn read_exact_at(&mut self, mut buf: &mut [u8], mut off: u64) -> io::Result<()> {
        use std::os::windows::fs::FileExt;
        while !buf.is_empty() {
            let n = self.0.seek_read(buf, off)?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            buf = &mut buf[n..];
            off += n as u64;
        }
        Ok(())
    }
    #[cfg(windows)]
    fn write_all_at(&mut self, mut buf: &[u8], mut off: u64) -> io::Result<()> {
        use std::os::windows::fs::FileExt;
        while !buf.is_empty() {
            let n = self.0.seek_write(buf, off)?;
            if n == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            buf = &buf[n..];
            off += n as u64;
        }
        Ok(())
    }
    fn size(&mut self) -> io::Result<u64> {
        Ok(self.0.metadata()?.len())
    }
    fn set_len(&mut self, len: u64) -> io::Result<()> {
        self.0.set_len(len)
    }
    fn sync(&mut self) -> io::Result<()> {
        // fsync (not fdatasync) so size changes are durable too. On error the caller must
        // treat the handle as poisoned: Linux may already have dropped the dirty pages.
        self.0.sync_all()
    }
}

impl Vfs for StdVfs {
    fn open(&self, name: &str, create: bool) -> io::Result<Box<dyn VfsFile>> {
        let mut o = OpenOptions::new();
        o.read(true).write(true).create(create);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        Ok(Box::new(StdFile(o.open(self.path(name)?)?)))
    }
    fn exists(&self, name: &str) -> io::Result<bool> {
        self.path(name)?.try_exists()
    }
    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        std::fs::rename(self.path(from)?, self.path(to)?)
    }
    fn remove(&self, name: &str) -> io::Result<()> {
        match std::fs::remove_file(self.path(name)?) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            r => r,
        }
    }
    fn sync_dir(&self) -> io::Result<()> {
        #[cfg(unix)]
        {
            File::open(&self.dir)?.sync_all()
        }
        #[cfg(not(unix))]
        {
            Ok(())
        }
    }
    fn lock(&self) -> io::Result<Option<Box<dyn Any + Send>>> {
        let f = self.open("LOCK", true)?;
        drop(f);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.path("LOCK")?)?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Box::new(file))),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(e)) => Err(e),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// In-memory file (fuzzing, tests)
// ---------------------------------------------------------------------------------------------

/// Simple growable in-memory file with no durability semantics.
#[derive(Debug, Default, Clone)]
pub struct MemFile(pub Vec<u8>);

impl VfsFile for MemFile {
    fn read_exact_at(&mut self, buf: &mut [u8], off: u64) -> io::Result<()> {
        let off =
            usize::try_from(off).map_err(|_| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        let end = off
            .checked_add(buf.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        let src = self.0.get(off..end).ok_or(io::ErrorKind::UnexpectedEof)?;
        buf.copy_from_slice(src);
        Ok(())
    }
    fn write_all_at(&mut self, buf: &[u8], off: u64) -> io::Result<()> {
        write_vec(&mut self.0, buf, off)
    }
    fn size(&mut self) -> io::Result<u64> {
        Ok(self.0.len() as u64)
    }
    fn set_len(&mut self, len: u64) -> io::Result<()> {
        self.0.resize(to_usize(len)?, 0);
        Ok(())
    }
    fn sync(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn to_usize(v: u64) -> io::Result<usize> {
    // Cap simulated files at 1 GiB so hostile inputs can't make tests allocate unbounded memory.
    if v > (1 << 30) {
        return Err(io::Error::other("simulated file too large"));
    }
    usize::try_from(v).map_err(io::Error::other)
}

fn write_vec(v: &mut Vec<u8>, buf: &[u8], off: u64) -> io::Result<()> {
    let off = to_usize(off)?;
    let end = off
        .checked_add(buf.len())
        .ok_or_else(|| io::Error::other("overflow"))?;
    to_usize(end as u64)?;
    if v.len() < end {
        v.resize(end, 0);
    }
    v[off..end].copy_from_slice(buf);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Power-loss simulation
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum PendingOp {
    Write { off: u64, data: Vec<u8> },
    SetLen(u64),
}

#[derive(Debug, Default)]
struct SimInode {
    durable: Vec<u8>,
    current: Vec<u8>,
    pending: Vec<PendingOp>,
}

#[derive(Debug, Default)]
struct SimState {
    inodes: HashMap<u64, SimInode>,
    dir_current: HashMap<String, u64>,
    dir_durable: HashMap<String, u64>,
    next_inode: u64,
    /// Number of mutating operations (write/set_len/sync/rename/sync_dir) performed.
    ops: u64,
    /// If set, every mutating operation with index >= this fails with an I/O error.
    fail_at: Option<u64>,
    /// Make only `sync` calls fail (models fsync EIO).
    fail_syncs: bool,
    locked: bool,
}

impl SimState {
    fn tick(&mut self, is_sync: bool) -> io::Result<()> {
        let n = self.ops;
        self.ops += 1;
        if self.fail_at.is_some_and(|f| n >= f) || (is_sync && self.fail_syncs) {
            return Err(io::Error::other("injected I/O fault"));
        }
        Ok(())
    }
}

/// Deterministic power-loss simulator. Cloning shares the same underlying "disk".
#[derive(Debug, Clone, Default)]
pub struct SimVfs {
    st: Arc<Mutex<SimState>>,
}

fn lock_state(st: &Mutex<SimState>) -> MutexGuard<'_, SimState> {
    // A panic while holding the lock can only come from a test assertion; keep going.
    st.lock().unwrap_or_else(|p| p.into_inner())
}

/// Tiny deterministic PRNG (SplitMix64) used for crash simulation.
#[derive(Debug, Clone)]
pub struct SimRng(u64);

impl SimRng {
    /// Seeded generator.
    pub fn new(seed: u64) -> Self {
        SimRng(seed)
    }
    /// Next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// Uniform in `0..n` (n > 0).
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next_u64() % n }
    }
    /// True with probability `num/den`.
    pub fn chance(&mut self, num: u64, den: u64) -> bool {
        self.below(den) < num
    }
}

impl SimVfs {
    /// Empty simulated disk.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fail every mutating op from the `n`-th one on (counted from the start of the sim).
    pub fn fail_after(&self, n: Option<u64>) {
        lock_state(&self.st).fail_at = n;
    }

    /// Make every `sync` fail (fsync EIO).
    pub fn fail_syncs(&self, on: bool) {
        lock_state(&self.st).fail_syncs = on;
    }

    /// Mutating operations performed so far.
    pub fn op_count(&self) -> u64 {
        lock_state(&self.st).ops
    }

    /// Simulate power loss. Each un-synced write survives with probability 1/2 and surviving
    /// writes may be torn (each 512-byte sector kept independently). Un-synced directory
    /// operations are lost. Clears fault injection and the lock.
    pub fn crash(&self, rng: &mut SimRng) {
        let mut st = lock_state(&self.st);
        for ino in st.inodes.values_mut() {
            let mut img = std::mem::take(&mut ino.durable);
            for op in std::mem::take(&mut ino.pending) {
                if !rng.chance(1, 2) {
                    continue;
                }
                match op {
                    PendingOp::SetLen(l) => img.resize(l as usize, 0),
                    PendingOp::Write { off, data } => {
                        let torn = rng.chance(1, 3);
                        for (i, sector) in data.chunks(512).enumerate() {
                            if torn && rng.chance(1, 2) {
                                continue;
                            }
                            let o = off + (i * 512) as u64;
                            // Ignore errors: sizes were validated on the original write.
                            let _ = write_vec(&mut img, sector, o);
                        }
                    }
                }
            }
            ino.current = img.clone();
            ino.durable = img;
        }
        st.dir_current = st.dir_durable.clone();
        let live: std::collections::HashSet<u64> = st.dir_durable.values().copied().collect();
        st.inodes.retain(|k, _| live.contains(k));
        st.fail_at = None;
        st.fail_syncs = false;
        st.locked = false;
        st.ops = 0;
    }

    /// Replace the full contents of `name` (durably), creating it if needed. Test helper.
    pub fn put_file(&self, name: &str, data: &[u8]) {
        let mut st = lock_state(&self.st);
        let ino = match st.dir_current.get(name) {
            Some(&i) => i,
            None => {
                let i = st.next_inode;
                st.next_inode += 1;
                st.dir_current.insert(name.to_string(), i);
                st.dir_durable.insert(name.to_string(), i);
                i
            }
        };
        let e = st.inodes.entry(ino).or_default();
        e.durable = data.to_vec();
        e.current = data.to_vec();
        e.pending.clear();
    }

    /// Current (possibly volatile) contents of `name`. Test helper.
    pub fn get_file(&self, name: &str) -> Option<Vec<u8>> {
        let st = lock_state(&self.st);
        let ino = st.dir_current.get(name)?;
        st.inodes.get(ino).map(|i| i.current.clone())
    }

    /// Release the directory lock (simulates the owning process dying without a crash).
    pub fn force_unlock(&self) {
        lock_state(&self.st).locked = false;
    }
}

struct SimFile {
    st: Arc<Mutex<SimState>>,
    ino: u64,
}

impl SimFile {
    fn with<R>(
        &self,
        tick: Option<bool>,
        f: impl FnOnce(&mut SimInode) -> io::Result<R>,
    ) -> io::Result<R> {
        let mut st = lock_state(&self.st);
        if let Some(is_sync) = tick {
            st.tick(is_sync)?;
        }
        let ino = st
            .inodes
            .get_mut(&self.ino)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "stale file"))?;
        f(ino)
    }
}

impl VfsFile for SimFile {
    fn read_exact_at(&mut self, buf: &mut [u8], off: u64) -> io::Result<()> {
        self.with(None, |i| {
            let off = usize::try_from(off).map_err(io::Error::other)?;
            let end = off
                .checked_add(buf.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?;
            let src = i
                .current
                .get(off..end)
                .ok_or(io::ErrorKind::UnexpectedEof)?;
            buf.copy_from_slice(src);
            Ok(())
        })
    }
    fn write_all_at(&mut self, buf: &[u8], off: u64) -> io::Result<()> {
        self.with(Some(false), |i| {
            write_vec(&mut i.current, buf, off)?;
            i.pending.push(PendingOp::Write {
                off,
                data: buf.to_vec(),
            });
            Ok(())
        })
    }
    fn size(&mut self) -> io::Result<u64> {
        self.with(None, |i| Ok(i.current.len() as u64))
    }
    fn set_len(&mut self, len: u64) -> io::Result<()> {
        self.with(Some(false), |i| {
            i.current.resize(to_usize(len)?, 0);
            i.pending.push(PendingOp::SetLen(len));
            Ok(())
        })
    }
    fn sync(&mut self) -> io::Result<()> {
        self.with(Some(true), |i| {
            i.durable = i.current.clone();
            i.pending.clear();
            Ok(())
        })
    }
}

impl Vfs for SimVfs {
    fn open(&self, name: &str, create: bool) -> io::Result<Box<dyn VfsFile>> {
        check_name(name)?;
        let mut st = lock_state(&self.st);
        let ino = match st.dir_current.get(name) {
            Some(&i) => i,
            None if create => {
                st.tick(false)?;
                let i = st.next_inode;
                st.next_inode += 1;
                st.inodes.insert(i, SimInode::default());
                st.dir_current.insert(name.to_string(), i);
                i
            }
            None => return Err(io::ErrorKind::NotFound.into()),
        };
        Ok(Box::new(SimFile {
            st: self.st.clone(),
            ino,
        }))
    }
    fn exists(&self, name: &str) -> io::Result<bool> {
        check_name(name)?;
        Ok(lock_state(&self.st).dir_current.contains_key(name))
    }
    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        check_name(from)?;
        check_name(to)?;
        let mut st = lock_state(&self.st);
        st.tick(false)?;
        let ino = st.dir_current.remove(from).ok_or(io::ErrorKind::NotFound)?;
        st.dir_current.insert(to.to_string(), ino);
        Ok(())
    }
    fn remove(&self, name: &str) -> io::Result<()> {
        check_name(name)?;
        let mut st = lock_state(&self.st);
        if st.dir_current.contains_key(name) {
            st.tick(false)?;
            st.dir_current.remove(name);
        }
        Ok(())
    }
    fn sync_dir(&self) -> io::Result<()> {
        let mut st = lock_state(&self.st);
        st.tick(true)?;
        st.dir_durable = st.dir_current.clone();
        Ok(())
    }
    fn lock(&self) -> io::Result<Option<Box<dyn Any + Send>>> {
        let mut st = lock_state(&self.st);
        if st.locked {
            return Ok(None);
        }
        st.locked = true;
        Ok(Some(Box::new(SimLockGuard(self.st.clone()))))
    }
}

struct SimLockGuard(Arc<Mutex<SimState>>);

impl Drop for SimLockGuard {
    fn drop(&mut self) {
        lock_state(&self.0).locked = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sim_unsynced_dir_entries_vanish() {
        let v = SimVfs::new();
        let mut f = v.open("a", true).unwrap();
        f.write_all_at(b"hello", 0).unwrap();
        f.sync().unwrap();
        v.crash(&mut SimRng::new(1));
        assert!(
            !v.exists("a").unwrap(),
            "file created without sync_dir must vanish"
        );
    }

    #[test]
    fn sim_synced_data_survives_and_unsynced_may_not() {
        let v = SimVfs::new();
        let mut f = v.open("a", true).unwrap();
        v.sync_dir().unwrap();
        f.write_all_at(&[1u8; 1024], 0).unwrap();
        f.sync().unwrap();
        f.write_all_at(&[2u8; 1024], 0).unwrap();
        drop(f);
        let mut saw_old = false;
        let mut saw_torn = false;
        for seed in 0..64 {
            let v2 = SimVfs::new();
            v2.put_file("a", &[1u8; 1024]);
            let mut g = v2.open("a", false).unwrap();
            g.write_all_at(&[2u8; 1024], 0).unwrap();
            v2.crash(&mut SimRng::new(seed));
            let d = v2.get_file("a").unwrap();
            assert_eq!(d.len(), 1024);
            if d.iter().all(|&b| b == 1) {
                saw_old = true;
            }
            if d.contains(&1) && d.contains(&2) {
                saw_torn = true;
            }
        }
        assert!(saw_old && saw_torn);
        assert!(v.exists("a").unwrap());
    }

    #[test]
    fn sim_fault_injection() {
        let v = SimVfs::new();
        let mut f = v.open("a", true).unwrap();
        v.fail_after(Some(v.op_count()));
        assert!(f.write_all_at(b"x", 0).is_err());
        v.fail_after(None);
        v.fail_syncs(true);
        f.write_all_at(b"x", 0).unwrap();
        assert!(f.sync().is_err());
    }

    #[test]
    fn rejects_path_traversal() {
        let v = SimVfs::new();
        for bad in ["../x", "a/b", "", ".hidden", "a\0b"] {
            assert!(v.open(bad, true).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn sim_lock_is_exclusive() {
        let v = SimVfs::new();
        let g = v.lock().unwrap();
        assert!(g.is_some());
        assert!(v.lock().unwrap().is_none());
        drop(g);
        assert!(v.lock().unwrap().is_some());
    }
}
