//! Backups and point-in-time recovery (Stage 7).
//!
//! A backup is a consistent logical dump at one MVCC snapshot (writers keep working while it
//! runs). Content: framed statements — `~<len>\n<payload>\n` — of CREATE TABLE / INSERT plus
//! `-- novadb:` directives for users (password hashes), counters and the snapshot timestamp.
//!
//! Encrypted file (always used by the server): `NOVADBB1`, then chunks
//! `u32 len | nonce(24) | XChaCha20-Poly1305(≤64 KiB)`; the associated data binds each chunk to
//! its index and marks the final chunk, so truncation, reordering and tampering are detected.
//! Plain files (`NOVADBP1`) exist only for tests and local tooling.

use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::error::{Result, SqlError};
use crate::exec::{Engine, sql_ident, sql_value};
use crate::value::Value;

const MAGIC_ENC: &[u8; 8] = b"NOVADBB1";
const MAGIC_PLAIN: &[u8; 8] = b"NOVADBP1";
const CHUNK: usize = 64 * 1024;
/// Rows per INSERT statement in a dump.
pub const ROWS_PER_INSERT: usize = 200;

fn io(e: std::io::Error) -> SqlError {
    SqlError::corrupt(format!("backup: {e}"))
}

fn aad(i: u64, last: bool) -> [u8; 17] {
    let mut a = [0u8; 17];
    a[..8].copy_from_slice(b"NOVADBB1");
    a[8..16].copy_from_slice(&i.to_le_bytes());
    a[16] = u8::from(last);
    a
}

/// Parse a 32-byte key written as 64 hex characters.
pub fn parse_key(text: &str) -> Result<[u8; 32]> {
    let t = text.trim();
    if t.len() != 64 {
        return Err(SqlError::internal(
            "backup key must be 64 hex characters (32 bytes)",
        ));
    }
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = u8::from_str_radix(t.get(i * 2..i * 2 + 2).unwrap_or("zz"), 16)
            .map_err(|_| SqlError::internal("backup key is not hex"))?;
    }
    Ok(k)
}

pub fn new_key() -> Result<[u8; 32]> {
    let mut k = [0u8; 32];
    getrandom::getrandom(&mut k).map_err(|e| SqlError::internal(format!("rng: {e}")))?;
    Ok(k)
}

/// Writes a backup file (encrypted when a key is given).
pub struct BackupWriter {
    f: File,
    key: Option<[u8; 32]>,
    buf: Vec<u8>,
    chunk: u64,
}

impl BackupWriter {
    pub fn create(path: &Path, key: Option<[u8; 32]>) -> Result<Self> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(io)?;
        f.write_all(if key.is_some() {
            MAGIC_ENC
        } else {
            MAGIC_PLAIN
        })
        .map_err(io)?;
        Ok(BackupWriter {
            f,
            key,
            buf: Vec::with_capacity(CHUNK * 2),
            chunk: 0,
        })
    }

    fn emit(&mut self, data: &[u8], last: bool) -> Result<()> {
        match &self.key {
            None => self.f.write_all(data).map_err(io),
            Some(k) => {
                let mut nonce = [0u8; 24];
                getrandom::getrandom(&mut nonce)
                    .map_err(|e| SqlError::internal(format!("rng: {e}")))?;
                let c = XChaCha20Poly1305::new(k.into())
                    .encrypt(
                        XNonce::from_slice(&nonce),
                        Payload {
                            msg: data,
                            aad: &aad(self.chunk, last),
                        },
                    )
                    .map_err(|_| SqlError::internal("backup encryption failed"))?;
                self.chunk += 1;
                self.f
                    .write_all(&(c.len() as u32).to_le_bytes())
                    .map_err(io)?;
                self.f.write_all(&nonce).map_err(io)?;
                self.f.write_all(&c).map_err(io)
            }
        }
    }

    /// Append one framed item (a SQL statement or a `-- novadb:` directive).
    pub fn item(&mut self, payload: &str) -> Result<()> {
        self.buf
            .extend_from_slice(format!("~{}\n", payload.len()).as_bytes());
        self.buf.extend_from_slice(payload.as_bytes());
        self.buf.push(b'\n');
        while self.buf.len() > CHUNK {
            let rest = self.buf.split_off(CHUNK);
            let chunk = std::mem::replace(&mut self.buf, rest);
            self.emit(&chunk, false)?;
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<()> {
        let rest = std::mem::take(&mut self.buf);
        self.emit(&rest, true)?;
        self.f.sync_all().map_err(io)
    }
}

/// Decrypt / read a whole backup into its framed items.
pub fn read_items(path: &Path, key: Option<&[u8; 32]>) -> Result<Vec<String>> {
    let mut r = BufReader::new(File::open(path).map_err(io)?);
    let mut magic = [0u8; 8];
    r.read_exact(&mut magic).map_err(io)?;
    let mut plain = Vec::new();
    if &magic == MAGIC_PLAIN {
        r.read_to_end(&mut plain).map_err(io)?;
    } else if &magic == MAGIC_ENC {
        let Some(k) = key else {
            return Err(SqlError::internal(
                "this backup is encrypted: give the backup key",
            ));
        };
        let cipher = XChaCha20Poly1305::new(k.into());
        let mut i = 0u64;
        let mut saw_last = false;
        loop {
            let mut lb = [0u8; 4];
            match r.read_exact(&mut lb) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(io(e)),
            }
            if saw_last {
                return Err(SqlError::corrupt("backup: data after the final chunk"));
            }
            let len = u32::from_le_bytes(lb) as usize;
            if len > CHUNK + 64 {
                return Err(SqlError::corrupt("backup: chunk too large"));
            }
            let mut nonce = [0u8; 24];
            r.read_exact(&mut nonce).map_err(io)?;
            let mut c = vec![0u8; len];
            r.read_exact(&mut c).map_err(io)?;
            // Try as a middle chunk, then as the final one.
            let n = XNonce::from_slice(&nonce);
            let p = match cipher.decrypt(
                n,
                Payload {
                    msg: &c,
                    aad: &aad(i, false),
                },
            ) {
                Ok(p) => p,
                Err(_) => {
                    let p = cipher
                        .decrypt(n, Payload { msg: &c, aad: &aad(i, true) })
                        .map_err(|_| SqlError::corrupt("backup: chunk failed authentication (wrong key, tampered or reordered)"))?;
                    saw_last = true;
                    p
                }
            };
            plain.extend_from_slice(&p);
            i += 1;
        }
        if !saw_last {
            return Err(SqlError::corrupt("backup: truncated (final chunk missing)"));
        }
    } else {
        return Err(SqlError::corrupt("backup: not a NovaDB backup file"));
    }
    // Unframe.
    let mut items = Vec::new();
    let mut pos = 0usize;
    while pos < plain.len() {
        let nl = plain[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .ok_or_else(|| SqlError::corrupt("backup: bad frame"))?
            + pos;
        let header = std::str::from_utf8(&plain[pos..nl])
            .map_err(|_| SqlError::corrupt("backup: bad frame"))?;
        let len: usize = header
            .strip_prefix('~')
            .and_then(|n| n.parse().ok())
            .ok_or_else(|| SqlError::corrupt("backup: bad frame"))?;
        let start = nl + 1;
        let end = start
            .checked_add(len)
            .filter(|&e| e < plain.len() + 1)
            .ok_or_else(|| SqlError::corrupt("backup: truncated frame"))?;
        items.push(
            String::from_utf8(plain[start..end].to_vec())
                .map_err(|_| SqlError::corrupt("backup: invalid UTF-8"))?,
        );
        pos = end + 1;
    }
    Ok(items)
}

/// Header + users + table definitions (rows are added by the caller, in batches).
pub fn write_header(
    w: &mut BackupWriter,
    snapshot: u64,
    wall_us: i64,
    users: &[(String, String)],
) -> Result<()> {
    w.item(&format!("-- novadb:backup 1 {snapshot} {wall_us}"))?;
    for (u, h) in users {
        w.item(&format!("-- novadb:user {h} {u}"))?;
    }
    Ok(())
}

pub fn insert_stmt(table: &str, rows: &[Vec<Value>]) -> String {
    let vals: Vec<String> = rows
        .iter()
        .map(|r| {
            format!(
                "({})",
                r.iter().map(sql_value).collect::<Vec<_>>().join(",")
            )
        })
        .collect();
    format!("INSERT INTO {} VALUES {}", sql_ident(table), vals.join(","))
}

/// One-shot dump (CLI / tests). The server runs the same steps but releases its lock between
/// row batches.
pub fn dump(
    e: &mut Engine,
    conn: u32,
    path: &Path,
    key: Option<[u8; 32]>,
    wall_us: i64,
) -> Result<u64> {
    let snap = e.dump_begin(conn)?;
    let r = (|| {
        let mut w = BackupWriter::create(path, key)?;
        let users: Vec<(String, String)> = e
            .users()?
            .into_iter()
            .filter_map(|u| e.user_hash(&u).ok().flatten().map(|h| (u, h)))
            .collect();
        write_header(&mut w, snap, wall_us, &users)?;
        for (u, scope, mask) in e.grants()? {
            w.item(&format!("-- novadb:grant {mask} {scope} {u}"))?;
        }
        for (name, ddl, ai) in e.dump_tables()? {
            w.item(&ddl)?;
            let mut after: Option<Vec<u8>> = None;
            loop {
                let (rows, last) = e.dump_rows(conn, &name, after.as_deref(), ROWS_PER_INSERT)?;
                if rows.is_empty() {
                    break;
                }
                w.item(&insert_stmt(&name, &rows))?;
                after = last;
            }
            if ai > 1 {
                w.item(&format!("-- novadb:autoinc {ai} {name}"))?;
            }
        }
        w.finish()?;
        Ok(snap)
    })();
    e.end_session(conn);
    r
}

/// Load a backup into an empty database. Returns the backup's snapshot timestamp.
pub fn restore(e: &mut Engine, path: &Path, key: Option<&[u8; 32]>) -> Result<u64> {
    if !e.dump_tables()?.is_empty() {
        return Err(SqlError::internal("restore needs an empty database"));
    }
    let mut snap = None;
    for item in read_items(path, key)? {
        if let Some(d) = item.strip_prefix("-- novadb:") {
            let mut parts = d.splitn(3, ' ');
            match (parts.next(), parts.next(), parts.next()) {
                (Some("backup"), Some("1"), Some(rest)) => {
                    snap = rest.split(' ').next().and_then(|t| t.parse().ok());
                }
                (Some("user"), Some(hash), Some(name)) => e.set_user_hash(name, hash)?,
                (Some("grant"), Some(mask), Some(rest)) => {
                    let mask: u64 = mask
                        .parse()
                        .map_err(|_| SqlError::corrupt("backup: bad grant"))?;
                    let (scope, user) = rest
                        .split_once(' ')
                        .ok_or_else(|| SqlError::corrupt("backup: bad grant"))?;
                    e.set_grant(user, scope, mask)?;
                }
                (Some("autoinc"), Some(n), Some(table)) => {
                    let n: u64 = n
                        .parse()
                        .map_err(|_| SqlError::corrupt("backup: bad autoinc"))?;
                    e.set_counter(table, false, n)?;
                }
                _ => return Err(SqlError::corrupt(format!("backup: unknown directive {d}"))),
            }
            continue;
        }
        e.execute(&item)?;
    }
    snap.ok_or_else(|| SqlError::corrupt("backup: header missing"))
}

/// Point-in-time recovery: apply binlog records newer than `after_ts` and not later than
/// `until_wall_us`. Returns the number of records applied.
pub fn replay(
    e: &mut Engine,
    dir: &Path,
    key: Option<&[u8; 32]>,
    after_ts: u64,
    until_wall_us: Option<i64>,
) -> Result<usize> {
    let mut n = 0;
    for rec in crate::binlog::read_all(dir, key)? {
        if rec.ts <= after_ts {
            continue;
        }
        if until_wall_us.is_some_and(|u| rec.wall_us > u) {
            break;
        }
        e.apply_record(&rec)?;
        n += 1;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn keys_and_framing() {
        let k = new_key().unwrap();
        let hex: String = k.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(parse_key(&hex).unwrap(), k);
        assert!(parse_key("abc").is_err());
        let d = std::env::temp_dir().join(format!("novadb-bk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("x.nbk");
        let mut w = BackupWriter::create(&p, Some(k)).unwrap();
        let big = "y".repeat(150_000);
        w.item("first\nline").unwrap();
        w.item(&big).unwrap();
        w.item("").unwrap();
        w.finish().unwrap();
        assert_eq!(
            read_items(&p, Some(&k)).unwrap(),
            vec!["first\nline".to_string(), big, String::new()]
        );
        assert!(read_items(&p, None).is_err());
        assert!(read_items(&p, Some(&[0u8; 32])).is_err());
        // truncation is detected
        let raw = std::fs::read(&p).unwrap();
        let cut = d.join("cut.nbk");
        std::fs::write(&cut, &raw[..raw.len() - 1000]).unwrap();
        assert!(read_items(&cut, Some(&k)).is_err());
        // tampering is detected
        let mut bad = raw.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 1;
        let badp = d.join("bad.nbk");
        std::fs::write(&badp, &bad).unwrap();
        assert!(read_items(&badp, Some(&k)).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }
}
