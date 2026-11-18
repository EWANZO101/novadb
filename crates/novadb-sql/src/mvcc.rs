//! Multi-version concurrency control (Stage 5): snapshot isolation on top of the
//! single-writer storage engine.
//!
//! * Every data-tree entry is versioned: physical key = logical key ‖ !commit_ts (big-endian,
//!   so newer versions sort first). Value = `0x00 payload` (live) or `0x01` (deleted).
//! * A transaction reads at a snapshot `snap` (newest version with ts ≤ snap) overlaid with
//!   its private write set; nothing is written to storage before COMMIT.
//! * COMMIT (first committer wins): if any written key has a committed version newer than
//!   `snap`, the transaction aborts with ER_LOCK_DEADLOCK (1213, SQLSTATE 40001 — what
//!   drivers/ORMs retry on). Otherwise all versions are written with a new timestamp in one
//!   storage transaction (atomic + durable).
//! * Old versions are pruned as soon as no active snapshot can see them.
//!
//! Logical keys inside one tree are prefix-free (self-delimiting encodings), which the
//! version lookup relies on.

use std::collections::{BTreeMap, HashSet};
use std::ops::Bound;

use novadb_storage::{Tree, Tx};

use crate::error::{Result, SqlError};

const LIVE: u8 = 0;
const DEAD: u8 = 1;
pub const TS_LEN: usize = 8;
/// Catalog key of the last committed timestamp.
pub const TS_KEY: &[u8] = b"ts";
/// Max bytes buffered by one transaction (keys + values).
pub const MAX_WRITESET_BYTES: usize = 256 << 20;

fn phys(lk: &[u8], ts: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(lk.len() + TS_LEN);
    k.extend_from_slice(lk);
    k.extend_from_slice(&(!ts).to_be_bytes());
    k
}

/// Split a physical key into (logical key, commit ts).
fn split(pk: &[u8]) -> Result<(&[u8], u64)> {
    if pk.len() < TS_LEN {
        return Err(SqlError::corrupt("mvcc: physical key too short"));
    }
    let (lk, s) = pk.split_at(pk.len() - TS_LEN);
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Ok((lk, !u64::from_be_bytes(a)))
}

fn decode_val(v: &[u8]) -> Result<Option<&[u8]>> {
    match v.split_first() {
        Some((&LIVE, rest)) => Ok(Some(rest)),
        Some((&DEAD, [])) => Ok(None),
        _ => Err(SqlError::corrupt("mvcc: bad version value")),
    }
}

pub fn conflict() -> SqlError {
    let mut e = SqlError::internal(
        "Deadlock found when trying to get lock; try restarting transaction (another transaction changed this row after your snapshot)",
    );
    e.code = 1213;
    e.state = "40001";
    e
}

/// Logical key → new value (None = delete).
type KeyWrites = BTreeMap<Vec<u8>, Option<Vec<u8>>>;

/// Buffered writes of one transaction: tree id → (handle, writes).
#[derive(Clone, Default)]
pub struct WriteSet {
    trees: BTreeMap<u64, (Tree, KeyWrites)>,
    bytes: usize,
    /// Logical changes for the binary log (undone together with the writes).
    pub(crate) log: Vec<crate::binlog::LogOp>,
}

impl WriteSet {
    pub fn is_empty(&self) -> bool {
        self.trees.values().all(|(_, m)| m.is_empty()) && self.log.is_empty()
    }
    pub fn len(&self) -> usize {
        self.trees.values().map(|(_, m)| m.len()).sum()
    }
    fn get(&self, t: &Tree, k: &[u8]) -> Option<&Option<Vec<u8>>> {
        self.trees.get(&t.id()).and_then(|(_, m)| m.get(k))
    }
    fn set(&mut self, t: &Tree, k: &[u8], v: Option<Vec<u8>>) -> Result<()> {
        self.bytes += k.len() + v.as_ref().map_or(0, Vec::len) + 32;
        if self.bytes > MAX_WRITESET_BYTES {
            return Err(SqlError::resource(
                "Transaction is too large (over 256 MiB of changes); commit in smaller pieces",
            ));
        }
        self.trees
            .entry(t.id())
            .or_insert_with(|| (*t, BTreeMap::new()))
            .1
            .insert(k.to_vec(), v);
        Ok(())
    }
}

/// Newest committed version of `lk`: (ts, live?) — None if never written.
fn newest(tx: &mut Tx<'_>, t: &Tree, lk: &[u8]) -> Result<Option<(u64, bool)>> {
    let lo = lk.to_vec();
    let hi = phys(lk, 0);
    let first = tx
        .range(
            t,
            (
                Bound::Included(lo.as_slice()),
                Bound::Included(hi.as_slice()),
            ),
        )?
        .find(|r| {
            r.as_ref()
                .map_or(true, |(k, _)| k.len() == lk.len() + TS_LEN)
        })
        .transpose()?;
    match first {
        None => Ok(None),
        Some((k, v)) => Ok(Some((split(&k)?.1, decode_val(&v)?.is_some()))),
    }
}

/// Snapshot view used by the executor for every data-tree access.
pub struct Mv<'t, 'a> {
    pub tx: &'t mut Tx<'a>,
    pub snap: u64,
    pub ws: &'t mut WriteSet,
}

impl Mv<'_, '_> {
    /// Visible value of logical key `lk`.
    pub fn get(&mut self, t: &Tree, lk: &[u8]) -> Result<Option<Vec<u8>>> {
        if let Some(v) = self.ws.get(t, lk) {
            return Ok(v.clone());
        }
        let lo = phys(lk, self.snap);
        let hi = phys(lk, 0);
        let hit = self
            .tx
            .range(
                t,
                (
                    Bound::Included(lo.as_slice()),
                    Bound::Included(hi.as_slice()),
                ),
            )?
            .find(|r| {
                r.as_ref()
                    .map_or(true, |(k, _)| k.len() == lk.len() + TS_LEN)
            })
            .transpose()?;
        match hit {
            None => Ok(None),
            Some((_, v)) => Ok(decode_val(&v)?.map(<[u8]>::to_vec)),
        }
    }

    fn check_write(&mut self, t: &Tree, lk: &[u8]) -> Result<()> {
        if self.ws.get(t, lk).is_none()
            && let Some((ts, _)) = newest(self.tx, t, lk)?
            && ts > self.snap
        {
            return Err(conflict());
        }
        Ok(())
    }

    pub fn put(&mut self, t: &Tree, lk: &[u8], v: &[u8]) -> Result<()> {
        self.check_write(t, lk)?;
        self.ws.set(t, lk, Some(v.to_vec()))
    }

    pub fn delete(&mut self, t: &Tree, lk: &[u8]) -> Result<()> {
        self.check_write(t, lk)?;
        self.ws.set(t, lk, None)
    }

    /// Up to `n` visible (logical key, value) pairs within (`lo`, `hi`), in key order.
    pub fn scan(
        &mut self,
        t: &Tree,
        lo: &Bound<Vec<u8>>,
        hi: &Bound<Vec<u8>>,
        n: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        if let (Bound::Included(l) | Bound::Excluded(l), Bound::Included(h) | Bound::Excluded(h)) =
            (lo, hi)
            && l > h
        {
            return Ok(Vec::new());
        }
        let in_hi = |k: &[u8]| match hi {
            Bound::Unbounded => true,
            Bound::Included(h) => k <= h.as_slice(),
            Bound::Excluded(h) => k < h.as_slice(),
        };
        let in_lo = |k: &[u8]| match lo {
            Bound::Unbounded => true,
            Bound::Included(l) => k >= l.as_slice(),
            Bound::Excluded(l) => k > l.as_slice(),
        };
        // Storage side: walk physical entries, keep the visible version of each logical key.
        let mut out: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let mut plo: Bound<Vec<u8>> = match lo {
            Bound::Unbounded => Bound::Unbounded,
            Bound::Included(l) => Bound::Included(l.clone()),
            Bound::Excluded(l) => Bound::Excluded(phys(l, 0)),
        };
        let phi: Bound<Vec<u8>> = match hi {
            Bound::Unbounded => Bound::Unbounded,
            Bound::Included(h) => Bound::Included(phys(h, 0)),
            Bound::Excluded(h) => Bound::Excluded(h.clone()),
        };
        let ws_entries: Vec<(Vec<u8>, Option<Vec<u8>>)> = self
            .ws
            .trees
            .get(&t.id())
            .map(|(_, m)| {
                m.range::<[u8], _>((
                    lo.as_ref().map(Vec::as_slice),
                    hi.as_ref().map(Vec::as_slice),
                ))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
            })
            .unwrap_or_default();
        let want = n.saturating_add(ws_entries.len());
        let mut last_lk: Option<Vec<u8>> = None;
        let mut done = false;
        while !done && out.len() < want {
            let chunk: Vec<(Vec<u8>, Vec<u8>)> = self
                .tx
                .range(
                    t,
                    (
                        plo.as_ref().map(Vec::as_slice),
                        phi.as_ref().map(Vec::as_slice),
                    ),
                )?
                .take(512)
                .collect::<std::result::Result<_, _>>()?;
            if chunk.len() < 512 {
                done = true;
            }
            let Some((lastk, _)) = chunk.last() else {
                break;
            };
            plo = Bound::Excluded(lastk.clone());
            for (pk, v) in chunk {
                let (lk, ts) = split(&pk)?;
                if !in_lo(lk) || !in_hi(lk) {
                    continue;
                }
                if last_lk.as_deref() == Some(lk) {
                    continue; // already decided for this logical key
                }
                if ts > self.snap {
                    continue; // too new for this snapshot; an older version may follow
                }
                last_lk = Some(lk.to_vec());
                if let Some(val) = decode_val(&v)? {
                    out.push((lk.to_vec(), val.to_vec()));
                    if out.len() >= want {
                        break;
                    }
                }
            }
        }
        // Overlay the write set.
        if !ws_entries.is_empty() {
            let mut merged: BTreeMap<Vec<u8>, Vec<u8>> = out.into_iter().collect();
            let storage_max = merged.keys().next_back().cloned();
            for (k, v) in ws_entries {
                // Only trust the merge up to what storage covered (unless storage is exhausted).
                if !done && storage_max.as_ref().is_some_and(|m| &k > m) {
                    continue;
                }
                match v {
                    Some(v) => {
                        merged.insert(k, v);
                    }
                    None => {
                        merged.remove(&k);
                    }
                }
            }
            out = merged.into_iter().collect();
        }
        out.truncate(n);
        Ok(out)
    }
}

/// Last committed timestamp.
pub fn last_ts(tx: &mut Tx<'_>, catalog: &Tree) -> Result<u64> {
    Ok(match tx.get(catalog, TS_KEY)? {
        Some(b) => u64::from_le_bytes(
            b.as_slice()
                .try_into()
                .map_err(|_| SqlError::corrupt("bad ts"))?,
        ),
        None => 0,
    })
}

/// Apply a write set at a new timestamp. `snaps` = snapshots of the *other* active
/// transactions. Keys whose old versions must be kept for those snapshots are remembered in
/// `pending` for later pruning.
pub fn commit(
    tx: &mut Tx<'_>,
    catalog: &Tree,
    ws: &WriteSet,
    snap: u64,
    snaps: &[u64],
    pending: &mut HashSet<(Tree, Vec<u8>)>,
) -> Result<u64> {
    // First committer wins.
    for (t, m) in ws.trees.values() {
        for k in m.keys() {
            if let Some((ts, _)) = newest(tx, t, k)?
                && ts > snap
            {
                return Err(conflict());
            }
        }
    }
    let ts = last_ts(tx, catalog)? + 1;
    tx.put(catalog, TS_KEY, &ts.to_le_bytes())?;
    for (t, m) in ws.trees.values() {
        for (k, v) in m {
            let val = match v {
                Some(v) => {
                    let mut b = Vec::with_capacity(v.len() + 1);
                    b.push(LIVE);
                    b.extend_from_slice(v);
                    b
                }
                None => vec![DEAD],
            };
            tx.put(t, &phys(k, ts), &val)?;
            if !prune(tx, t, k, snaps)? {
                pending.insert((*t, k.clone()));
            }
        }
    }
    Ok(ts)
}

/// Remove versions of `lk` that nobody can see: keep the newest (for new readers) and, for
/// each active snapshot in `snaps`, the newest version at or below it. A deletion marker that
/// nobody needs is removed too. Returns true when nothing is retained for old snapshots.
pub fn prune(tx: &mut Tx<'_>, t: &Tree, lk: &[u8], snaps: &[u64]) -> Result<bool> {
    let lo = lk.to_vec();
    let hi = phys(lk, 0);
    let versions: Vec<(Vec<u8>, u64, bool)> = tx
        .range(
            t,
            (
                Bound::Included(lo.as_slice()),
                Bound::Included(hi.as_slice()),
            ),
        )?
        .filter(|r| {
            r.as_ref()
                .map_or(true, |(k, _)| k.len() == lk.len() + TS_LEN)
        })
        .map(|r| {
            let (k, v) = r?;
            Ok((k, v))
        })
        .collect::<std::result::Result<Vec<_>, novadb_storage::Error>>()?
        .into_iter()
        .map(|(k, v)| Ok((split(&k)?.1, decode_val(&v)?.is_some(), k)))
        .collect::<Result<Vec<(u64, bool, Vec<u8>)>>>()?
        .into_iter()
        .map(|(ts, live, k)| (k, ts, live))
        .collect();
    if versions.is_empty() {
        return Ok(true);
    }
    // versions are newest first
    let mut keep = vec![false; versions.len()];
    keep[0] = true;
    for &s in snaps {
        if let Some(i) = versions.iter().position(|(_, ts, _)| *ts <= s) {
            keep[i] = true;
        }
    }
    let kept_old = keep.iter().skip(1).filter(|k| **k).count();
    // The newest is a deletion: drop it only if no snapshot needs an older version AND no
    // snapshot predates it (those transactions need it to detect the write-write conflict).
    let newest_ts = versions[0].1;
    if kept_old == 0 && !versions[0].2 && snaps.iter().all(|&s| s >= newest_ts) {
        keep[0] = false;
    }
    for (i, (k, _, _)) in versions.iter().enumerate() {
        if !keep[i] {
            tx.delete(t, k)?;
        }
    }
    Ok(kept_old == 0 && (keep[0] == versions[0].2 || snaps.iter().all(|&s| s >= newest_ts)))
}

/// Number of stored versions of `lk` (tests / diagnostics).
pub fn version_count(tx: &mut Tx<'_>, t: &Tree, lk: &[u8]) -> Result<usize> {
    let lo = lk.to_vec();
    let hi = phys(lk, 0);
    Ok(tx
        .range(
            t,
            (
                Bound::Included(lo.as_slice()),
                Bound::Included(hi.as_slice()),
            ),
        )?
        .filter(|r| {
            r.as_ref()
                .map_or(true, |(k, _)| k.len() == lk.len() + TS_LEN)
        })
        .count())
}
