//! Binary log (Stage 7): every committed change, for point-in-time recovery.
//!
//! Records are written and fsynced *before* the storage commit. After a crash the log may hold
//! a record whose storage commit never happened; `open` trims every record newer than the
//! storage's last committed timestamp, so the log never claims more than the database has.
//!
//! File layout (`<dir>/NNNNNN.binlog`): magic `NOVADBL1` (plain) or `NOVADBE1` (encrypted),
//! then records `u32 len | u32 crc32c(stored) | stored`. `stored` is the payload, or for
//! encrypted logs `nonce(24) | XChaCha20-Poly1305(payload)`, so a stolen log file reveals
//! nothing and any tampering fails authentication. Payload: `u64 ts | i64 wall_us | u32 n | op*`.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use novadb_storage::crc32c::crc32c;

use crate::codec::{R, W, row_decode, row_encode};
use crate::error::{Result, SqlError};
use crate::value::Value;

const MAGIC: &[u8; 8] = b"NOVADBL1";
const MAGIC_ENC: &[u8; 8] = b"NOVADBE1";

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

fn seal(key: &[u8; 32], plain: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut nonce).map_err(|e| SqlError::internal(format!("rng: {e}")))?;
    let c = XChaCha20Poly1305::new(key.into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plain,
                aad: MAGIC_ENC,
            },
        )
        .map_err(|_| SqlError::internal("binlog encryption failed"))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&c);
    Ok(out)
}

fn open_sealed(key: &[u8; 32], stored: &[u8]) -> Result<Vec<u8>> {
    if stored.len() < 24 + 16 {
        return Err(SqlError::corrupt("binlog: sealed record too short"));
    }
    let (nonce, c) = stored.split_at(24);
    XChaCha20Poly1305::new(key.into())
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: c,
                aad: MAGIC_ENC,
            },
        )
        .map_err(|_| {
            SqlError::corrupt("binlog: record failed authentication (wrong key or tampered)")
        })
}
/// Start a new file after this many bytes.
const ROTATE_BYTES: u64 = 64 << 20;
const MAX_RECORD: usize = 512 << 20;

/// One logged change.
#[derive(Debug, Clone, PartialEq)]
pub enum LogOp {
    /// Row stored under its primary key (insert or update).
    Put {
        table: String,
        key: Vec<u8>,
        row: Vec<Value>,
    },
    /// Row removed.
    Del { table: String, key: Vec<u8> },
    /// Schema change, as re-executable SQL.
    Ddl(String),
    /// User created / password changed (hash) or dropped (None).
    User { name: String, hash: Option<String> },
    /// AUTO_INCREMENT (`rowid` = false) or hidden row-id counter of a table moved, so a
    /// replay never hands out an id twice.
    Counter {
        table: String,
        rowid: bool,
        value: u64,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub ts: u64,
    pub wall_us: i64,
    pub ops: Vec<LogOp>,
}

fn io(e: std::io::Error) -> SqlError {
    SqlError::corrupt(format!("binlog: {e}"))
}

fn encode(r: &Record) -> Result<Vec<u8>> {
    let mut w = W(Vec::new());
    w.u64(r.ts);
    w.u64(r.wall_us as u64);
    w.u32(r.ops.len() as u32);
    for op in &r.ops {
        match op {
            LogOp::Put { table, key, row } => {
                w.u8(1);
                w.str(table);
                w.bytes(key);
                w.bytes(&row_encode(row)?);
            }
            LogOp::Del { table, key } => {
                w.u8(2);
                w.str(table);
                w.bytes(key);
            }
            LogOp::Ddl(sql) => {
                w.u8(3);
                w.str(sql);
            }
            LogOp::User { name, hash } => {
                w.u8(4);
                w.str(name);
                match hash {
                    Some(h) => {
                        w.u8(1);
                        w.str(h);
                    }
                    None => w.u8(0),
                }
            }
            LogOp::Counter {
                table,
                rowid,
                value,
            } => {
                w.u8(5);
                w.str(table);
                w.u8(u8::from(*rowid));
                w.u64(*value);
            }
        }
    }
    Ok(w.0)
}

fn decode(b: &[u8]) -> Result<Record> {
    let mut r = R::new(b);
    let ts = r.u64()?;
    let wall_us = r.u64()? as i64;
    let n = r.u32()? as usize;
    if n > b.len() {
        return Err(SqlError::corrupt("binlog: bad op count"));
    }
    let mut ops = Vec::with_capacity(n);
    for _ in 0..n {
        ops.push(match r.u8()? {
            1 => {
                let table = r.str()?;
                let key = r.bytes()?;
                let raw = r.bytes()?;
                let ncols = raw
                    .get(1..3)
                    .map_or(0, |c| usize::from(u16::from_le_bytes([c[0], c[1]])));
                LogOp::Put {
                    table,
                    key,
                    row: row_decode(&raw, ncols)?,
                }
            }
            2 => LogOp::Del {
                table: r.str()?,
                key: r.bytes()?,
            },
            3 => LogOp::Ddl(r.str()?),
            4 => {
                let name = r.str()?;
                let hash = if r.u8()? == 1 { Some(r.str()?) } else { None };
                LogOp::User { name, hash }
            }
            5 => LogOp::Counter {
                table: r.str()?,
                rowid: r.u8()? == 1,
                value: r.u64()?,
            },
            _ => return Err(SqlError::corrupt("binlog: unknown op")),
        });
    }
    if !r.done() {
        return Err(SqlError::corrupt("binlog: trailing bytes"));
    }
    Ok(Record { ts, wall_us, ops })
}

fn file_name(n: u64) -> String {
    format!("{n:06}.binlog")
}

/// Sorted binlog files in `dir`.
pub fn files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut v: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "binlog"))
            .collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(io(e)),
    };
    v.sort();
    Ok(v)
}

/// Read every valid record of one file; returns them with the byte offset after each.
fn read_file(path: &Path, key: Option<&[u8; 32]>) -> Result<(Vec<(Record, u64)>, bool)> {
    let mut f = File::open(path).map_err(io)?;
    let mut magic = [0u8; 8];
    if f.read_exact(&mut magic).is_err() {
        return Ok((Vec::new(), false));
    }
    let encrypted = match &magic {
        m if m == MAGIC => false,
        m if m == MAGIC_ENC => true,
        _ => return Ok((Vec::new(), false)),
    };
    if encrypted && key.is_none() {
        return Err(SqlError::corrupt(format!(
            "binlog {} is encrypted: a key is required",
            path.display()
        )));
    }
    let mut out = Vec::new();
    let mut pos = 8u64;
    let mut clean = true;
    loop {
        let mut h = [0u8; 8];
        match f.read_exact(&mut h) {
            Ok(()) => {}
            Err(_) => break,
        }
        let len = u32::from_le_bytes([h[0], h[1], h[2], h[3]]) as usize;
        let crc = u32::from_le_bytes([h[4], h[5], h[6], h[7]]);
        if len > MAX_RECORD {
            clean = false;
            break;
        }
        let mut p = vec![0u8; len];
        if f.read_exact(&mut p).is_err() || crc32c(&p) != crc {
            clean = false;
            break;
        }
        let plain = match (encrypted, key) {
            (true, Some(k)) => open_sealed(k, &p)?,
            _ => p,
        };
        match decode(&plain) {
            Ok(rec) => {
                pos += 8 + len as u64;
                out.push((rec, pos));
            }
            Err(_) => {
                clean = false;
                break;
            }
        }
    }
    Ok((out, clean))
}

/// Every valid record in `dir`, in log order.
pub fn read_all(dir: &Path, key: Option<&[u8; 32]>) -> Result<Vec<Record>> {
    let mut out = Vec::new();
    for f in files(dir)? {
        let (recs, _) = read_file(&f, key)?;
        out.extend(recs.into_iter().map(|(r, _)| r));
    }
    Ok(out)
}

pub struct Binlog {
    dir: PathBuf,
    file: File,
    num: u64,
    size: u64,
    key: Option<[u8; 32]>,
}

impl Binlog {
    /// Open (creating) the log in `dir`, trimming records newer than `committed_ts` and any
    /// torn tail left by a crash.
    pub fn open(dir: &Path, committed_ts: u64, key: Option<[u8; 32]>) -> Result<Binlog> {
        std::fs::create_dir_all(dir).map_err(io)?;
        let all = files(dir)?;
        let mut last: Option<(PathBuf, u64)> = None;
        let mut drop_rest = false;
        for f in &all {
            if drop_rest {
                std::fs::remove_file(f).map_err(io)?;
                continue;
            }
            let (recs, _clean) = read_file(f, key.as_ref())?;
            let mut keep_to = 8u64;
            for (r, end) in &recs {
                if r.ts > committed_ts {
                    drop_rest = true;
                    break;
                }
                keep_to = *end;
            }
            let fh = OpenOptions::new().write(true).open(f).map_err(io)?;
            fh.set_len(keep_to).map_err(io)?;
            fh.sync_all().map_err(io)?;
            last = Some((f.clone(), keep_to));
        }
        let (num, path, size) = match last {
            Some((p, size)) => {
                let num = p
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(1);
                (num, p, size)
            }
            None => (1, dir.join(file_name(1)), 0),
        };
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)
            .map_err(io)?;
        let want: &[u8; 8] = if key.is_some() { MAGIC_ENC } else { MAGIC };
        let size = if size < 8 {
            file.set_len(0).map_err(io)?;
            file.write_all(want).map_err(io)?;
            file.sync_all().map_err(io)?;
            8
        } else {
            size
        };
        file.seek(SeekFrom::End(0)).map_err(io)?;
        let mut b = Binlog {
            dir: dir.to_path_buf(),
            file,
            num,
            size,
            key,
        };
        // Encryption switched on or off: continue in a new file of the right kind.
        let mut magic = [0u8; 8];
        if let Ok(mut f) = File::open(&path)
            && f.read_exact(&mut magic).is_ok()
            && &magic != want
        {
            b.rotate()?;
        }
        Ok(b)
    }

    /// Append one record durably.
    pub fn append(&mut self, rec: &Record) -> Result<()> {
        if rec.ops.is_empty() {
            return Ok(());
        }
        if self.size >= ROTATE_BYTES {
            self.rotate()?;
        }
        let plain = encode(rec)?;
        let p = match &self.key {
            Some(k) => seal(k, &plain)?,
            None => plain,
        };
        if p.len() > MAX_RECORD {
            return Err(SqlError::resource(
                "transaction too large for the binary log",
            ));
        }
        let mut buf = Vec::with_capacity(p.len() + 8);
        buf.extend_from_slice(&(p.len() as u32).to_le_bytes());
        buf.extend_from_slice(&crc32c(&p).to_le_bytes());
        buf.extend_from_slice(&p);
        self.file.write_all(&buf).map_err(io)?;
        self.file.sync_data().map_err(io)?;
        self.size += buf.len() as u64;
        Ok(())
    }

    /// Close the current file and start the next one (e.g. at a backup).
    pub fn rotate(&mut self) -> Result<()> {
        self.num += 1;
        let path = self.dir.join(file_name(self.num));
        let mut f = OpenOptions::new()
            .create_new(true)
            .append(true)
            .mode(0o600)
            .open(&path)
            .map_err(io)?;
        f.write_all(if self.key.is_some() { MAGIC_ENC } else { MAGIC })
            .map_err(io)?;
        f.sync_all().map_err(io)?;
        if let Ok(d) = File::open(&self.dir) {
            let _ = d.sync_all();
        }
        self.file = f;
        self.size = 8;
        Ok(())
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "novadb-binlog-{}-{}",
            std::process::id(),
            crate::exec::hex(&rand8())
        ));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn rand8() -> [u8; 8] {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        (n as u64).to_le_bytes()
    }

    fn rec(ts: u64) -> Record {
        Record {
            ts,
            wall_us: ts as i64 * 1000,
            ops: vec![
                LogOp::Put {
                    table: "t".into(),
                    key: vec![1, 2],
                    row: vec![Value::Int(ts as i64), Value::Str("x".into()), Value::Null],
                },
                LogOp::Del {
                    table: "t".into(),
                    key: vec![9],
                },
                LogOp::Ddl("CREATE TABLE z (a INT)".into()),
                LogOp::User {
                    name: "u".into(),
                    hash: Some("h".into()),
                },
                LogOp::Counter {
                    table: "t".into(),
                    rowid: false,
                    value: 7,
                },
            ],
        }
    }

    #[test]
    fn roundtrip_trim_and_torn_tail() {
        let d = tmp();
        {
            let mut b = Binlog::open(&d, 0, None).unwrap();
            for ts in 1..=5 {
                b.append(&rec(ts)).unwrap();
            }
        }
        assert_eq!(
            read_all(&d, None).unwrap(),
            (1..=5).map(rec).collect::<Vec<_>>()
        );
        // Storage only committed up to ts 3: records 4 and 5 are trimmed.
        drop(Binlog::open(&d, 3, None).unwrap());
        assert_eq!(read_all(&d, None).unwrap().len(), 3);
        // Torn tail: garbage after the last record is cut off.
        {
            let f = files(&d).unwrap().pop().unwrap();
            let mut fh = OpenOptions::new().append(true).open(&f).unwrap();
            fh.write_all(&[200, 0, 0, 0, 1, 2, 3, 4, 5]).unwrap();
        }
        let mut b = Binlog::open(&d, 10, None).unwrap();
        b.append(&rec(4)).unwrap();
        b.rotate().unwrap();
        b.append(&rec(5)).unwrap();
        drop(b);
        let all = read_all(&d, None).unwrap();
        assert_eq!(
            all.iter().map(|r| r.ts).collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5]
        );
        assert_eq!(files(&d).unwrap().len(), 2);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn encrypted_log() {
        let d = tmp();
        let key = [7u8; 32];
        {
            let mut b = Binlog::open(&d, 0, Some(key)).unwrap();
            b.append(&rec(1)).unwrap();
            b.append(&rec(2)).unwrap();
        }
        let raw = std::fs::read(files(&d).unwrap().pop().unwrap()).unwrap();
        assert!(raw.starts_with(MAGIC_ENC));
        assert!(
            !raw.windows(22).any(|w| w == b"CREATE TABLE z (a INT)"),
            "DDL text must not appear in clear"
        );
        assert_eq!(read_all(&d, Some(&key)).unwrap().len(), 2);
        assert!(read_all(&d, None).is_err(), "no key");
        assert!(read_all(&d, Some(&[8u8; 32])).is_err(), "wrong key");
        std::fs::remove_dir_all(&d).unwrap();
    }
}
