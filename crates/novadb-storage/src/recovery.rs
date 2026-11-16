//! Crash recovery: redo committed WAL records into the data file.

use crate::error::{Error, Result};
use crate::page::{self, MAX_PAGE_ID, PAGE_SIZE, PageId, PageType, get_u64, new_page_buf};
use crate::pager::Pager;
use crate::vfs::VfsFile;
use crate::wal::{self, RecordKind, WalScanner};

/// Outcome of a recovery run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    /// LSN to start the next WAL generation at.
    pub next_lsn: u64,
    /// Committed transactions replayed.
    pub commits: u64,
    /// Page records (images + deltas) applied.
    pub pages_applied: u64,
    /// Records after the last commit that were discarded (incomplete transaction).
    pub discarded_records: u64,
    /// The scan stopped at a torn/invalid record before end of file.
    pub torn_tail: bool,
    /// Highest page id written.
    pub max_page: Option<PageId>,
}

/// Replay `wal` into `pager` and fsync the data file. Idempotent: running it again (e.g. after
/// crashing during recovery) gives the same result.
pub fn recover(wal: &mut dyn VfsFile, pager: &mut Pager) -> Result<RecoveryReport> {
    // Pass 1: find the end of the last committed transaction.
    let (mut commit_end, mut next_lsn, mut commits, mut total, mut committed_records, torn);
    let mut image_db_id = None;
    let wal_db_id;
    {
        let (mut sc, hdr) = WalScanner::open(wal)?;
        wal_db_id = hdr.db_id;
        commit_end = None;
        next_lsn = hdr.start_lsn;
        commits = 0u64;
        total = 0u64;
        committed_records = 0u64;
        while let Some(r) = sc.next_record()? {
            total += 1;
            if r.kind == RecordKind::PageImage
                && r.payload.len() == 8 + PAGE_SIZE
                && get_u64(r.payload, 0) == 0
            {
                image_db_id = Some(get_u64(r.payload, 8 + page::META_DB_ID_OFFSET));
            }
            if r.kind == RecordKind::Commit {
                if !r.payload.is_empty() {
                    return Err(Error::corrupt(format!(
                        "WAL record {}: commit with payload",
                        r.lsn
                    )));
                }
                commit_end = Some(r.end);
                next_lsn = r.lsn + 1;
                commits += 1;
                committed_records = total;
            }
        }
        torn = sc.stopped_early;
    }
    let mut rep = RecoveryReport {
        next_lsn,
        commits,
        discarded_records: total - committed_records,
        torn_tail: torn,
        ..Default::default()
    };
    let Some(commit_end) = commit_end else {
        return Ok(rep);
    };

    // Refuse to replay a WAL that belongs to a different database. The data file's meta page
    // may itself be torn; then the WAL must carry an image of it.
    let mut buf = new_page_buf();
    let data_db_id = match pager.read(0, &mut buf) {
        Ok(PageType::Meta) => Some(page::meta_db_id(&buf)),
        _ => image_db_id,
    };
    if data_db_id != Some(wal_db_id) {
        return Err(Error::corrupt(format!(
            "WAL belongs to database {wal_db_id:#018x}, data file is {data_db_id:#x?}"
        )));
    }

    // Pass 2: apply page records up to and including the last commit.
    let (mut sc, _) = WalScanner::open(wal)?;
    while let Some(r) = sc.next_record()? {
        if r.end > commit_end {
            break;
        }
        let id = match r.kind {
            RecordKind::Commit => continue,
            RecordKind::PageImage => {
                if r.payload.len() != 8 + PAGE_SIZE {
                    return Err(Error::corrupt(format!(
                        "WAL record {}: bad image size",
                        r.lsn
                    )));
                }
                let id = get_u64(r.payload, 0);
                buf.copy_from_slice(&r.payload[8..]);
                id
            }
            RecordKind::PageDelta => {
                if r.payload.len() < 8 {
                    return Err(Error::corrupt(format!("WAL record {}: short delta", r.lsn)));
                }
                let id = get_u64(r.payload, 0);
                if id > MAX_PAGE_ID {
                    return Err(Error::corrupt(format!(
                        "WAL record {}: page id {id}",
                        r.lsn
                    )));
                }
                // The base must have been restored from an image earlier in this WAL.
                pager.read(id, &mut buf).map_err(|e| {
                    Error::corrupt(format!(
                        "WAL record {}: delta base for page {id}: {e}",
                        r.lsn
                    ))
                })?;
                wal::apply_delta(r.payload, &mut buf)?;
                id
            }
        };
        if id > MAX_PAGE_ID {
            return Err(Error::corrupt(format!(
                "WAL record {}: page id {id} out of range",
                r.lsn
            )));
        }
        if page::page_id(&buf) != id {
            return Err(Error::corrupt(format!(
                "WAL record {}: page header id mismatch",
                r.lsn
            )));
        }
        if page::page_type(&buf).is_none()
            || (id == 0) != (page::page_type(&buf) == Some(PageType::Meta))
        {
            return Err(Error::corrupt(format!(
                "WAL record {}: invalid page type",
                r.lsn
            )));
        }
        pager.write(id, &mut buf)?;
        rep.pages_applied += 1;
        rep.max_page = Some(rep.max_page.map_or(id, |m| m.max(id)));
    }
    pager.sync()?;
    Ok(rep)
}
