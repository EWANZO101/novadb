//! NovaDB storage engine (Stage 2).
//!
//! * 16 KiB checksummed pages ([`page`]), page I/O ([`pager`])
//! * bounded buffer pool with CLOCK eviction and no-steal pinning ([`bufpool`])
//! * B+Tree with merge/rebalance and stable root ids ([`btree`])
//! * redo-only physical WAL with full-page images + deltas ([`wal`]) and crash recovery
//!   ([`recovery`])
//! * a power-loss simulating VFS for deterministic crash tests ([`vfs::SimVfs`])
//!
//! Concurrency model for now: one writer, `&mut` access. MVCC arrives in Stage 5.
#![forbid(unsafe_code)]

pub mod btree;
pub mod bufpool;
pub mod crc32c;
mod db;
pub mod error;
pub mod page;
pub mod pager;
pub mod recovery;
pub mod vfs;
pub mod wal;

pub use btree::{MAX_KEY_LEN, MAX_VALUE_LEN};
pub use db::{DATA_FILE, Db, MAX_TREE_NAME, Options, RangeIter, Stats, Tree, Tx, VerifyReport, WAL_FILE};
pub use error::{Error, Result};
pub use recovery::RecoveryReport;
pub use vfs::{SimRng, SimVfs, StdVfs, Vfs, VfsFile};
