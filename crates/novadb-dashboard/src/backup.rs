//! Backup files for the SQL workspace: `<data>/backups/workspace-<UTC stamp>-<kind>.sql`.
//!
//! Each file is a logical dump with a small header and a trailing `-- sha256: <hex>` line that
//! covers everything before it, so corruption or editing is detected before a restore.
//! Files are created with `create_new` and mode 0600 inside a 0700 directory.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::auth;
use crate::sqlws::DumpInfo;

/// Automatic backups kept (older ones are deleted).
pub const KEEP_AUTO: usize = 14;
/// Hard cap on stored backups of all kinds.
pub const MAX_FILES: usize = 60;
/// Age after which a new automatic backup is due.
pub const AUTO_EVERY: u64 = 24 * 3600;

const MAGIC: &str = "-- NovaDB workspace dump v1";
const SUM: &str = "-- sha256: ";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupKind {
    Auto,
    Manual,
    PreRestore,
}

impl BackupKind {
    pub fn id(self) -> &'static str {
        match self {
            BackupKind::Auto => "auto",
            BackupKind::Manual => "manual",
            BackupKind::PreRestore => "prerestore",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            BackupKind::Auto => "Automatic",
            BackupKind::Manual => "Manual",
            BackupKind::PreRestore => "Before restore",
        }
    }
    fn parse(s: &str) -> Option<BackupKind> {
        [BackupKind::Auto, BackupKind::Manual, BackupKind::PreRestore]
            .into_iter()
            .find(|k| k.id() == s)
    }
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub kind: BackupKind,
    pub created: u64,
    pub size: u64,
    pub info: DumpInfo,
}

/// Only names we generate ourselves are ever accepted (no paths, no traversal).
pub fn name_ok(n: &str) -> bool {
    n.len() <= 80
        && n.starts_with("workspace-")
        && n.ends_with(".sql")
        && n.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'.')
        && !n.contains("..")
}

pub struct Backups {
    dir: PathBuf,
}

fn stamp(secs: u64) -> String {
    crate::html::ts(secs)
        .replace(['-', ':'], "")
        .replace(' ', "-")
}

impl Backups {
    pub fn new(dir: PathBuf) -> Result<Backups, String> {
        if !dir.exists() {
            std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("chmod {}: {e}", dir.display()))?;
        Ok(Backups { dir })
    }

    /// Write a new backup file; returns its name.
    pub fn write(
        &self,
        kind: BackupKind,
        now: u64,
        body: &str,
        info: DumpInfo,
    ) -> Result<String, String> {
        if self.list()?.len() >= MAX_FILES {
            return Err(format!(
                "There are already {MAX_FILES} backups. Delete some first."
            ));
        }
        let mut content = format!(
            "{MAGIC}\n-- created: {} UTC\n-- kind: {}\n-- tables: {} rows: {}\n-- restore: replaces every table in the workspace\n{body}",
            crate::html::ts(now),
            kind.id(),
            info.tables,
            info.rows
        );
        if !content.ends_with('\n') {
            content.push('\n');
        }
        let sum = auth::sha256_hex(content.as_bytes());
        content.push_str(&format!("{SUM}{sum}\n"));
        // Same second twice (e.g. pre-restore right after a manual one): add a counter.
        for n in 0..100 {
            let name = if n == 0 {
                format!("workspace-{}-{}.sql", stamp(now), kind.id())
            } else {
                format!("workspace-{}-{}-{n}.sql", stamp(now), kind.id())
            };
            let path = self.dir.join(&name);
            let f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path);
            match f {
                Ok(mut f) => {
                    f.write_all(content.as_bytes())
                        .and_then(|_| f.sync_all())
                        .map_err(|e| format!("write {name}: {e}"))?;
                    return Ok(name);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("create {name}: {e}")),
            }
        }
        Err("could not pick a file name".into())
    }

    /// Newest first.
    pub fn list(&self) -> Result<Vec<Entry>, String> {
        let rd = std::fs::read_dir(&self.dir).map_err(|e| format!("read backups: {e}"))?;
        let mut out = Vec::new();
        for ent in rd.flatten() {
            let name = ent.file_name().to_string_lossy().into_owned();
            if !name_ok(&name) {
                continue;
            }
            let Ok(meta) = ent.metadata() else { continue };
            let (kind, created, info) = read_header(&ent.path()).unwrap_or((
                BackupKind::Manual,
                meta.modified()
                    .ok()
                    .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                DumpInfo::default(),
            ));
            out.push(Entry {
                name,
                kind,
                created,
                size: meta.len(),
                info,
            });
        }
        out.sort_by(|a, b| b.created.cmp(&a.created).then(b.name.cmp(&a.name)));
        Ok(out)
    }

    pub fn read(&self, name: &str) -> Result<String, String> {
        if !name_ok(name) {
            return Err("bad backup name".into());
        }
        std::fs::read_to_string(self.dir.join(name)).map_err(|e| format!("read {name}: {e}"))
    }

    pub fn delete(&self, name: &str) -> Result<(), String> {
        if !name_ok(name) {
            return Err("bad backup name".into());
        }
        std::fs::remove_file(self.dir.join(name)).map_err(|e| format!("delete {name}: {e}"))
    }

    /// Delete automatic backups beyond the newest `keep`. Returns how many were removed.
    pub fn prune_auto(&self, keep: usize) -> Result<usize, String> {
        let mut n = 0;
        for e in self
            .list()?
            .into_iter()
            .filter(|e| e.kind == BackupKind::Auto)
            .skip(keep)
        {
            self.delete(&e.name)?;
            n += 1;
        }
        Ok(n)
    }

    /// Newest automatic backup time (0 if none).
    pub fn last_auto(&self) -> u64 {
        self.list()
            .ok()
            .and_then(|l| l.into_iter().find(|e| e.kind == BackupKind::Auto))
            .map(|e| e.created)
            .unwrap_or(0)
    }
}

fn read_header(p: &Path) -> Option<(BackupKind, u64, DumpInfo)> {
    use std::io::{BufRead, BufReader};
    let f = std::fs::File::open(p).ok()?;
    let mut lines = BufReader::new(f).lines();
    if lines.next()?.ok()? != MAGIC {
        return None;
    }
    let created = lines.next()?.ok()?;
    let kind = lines.next()?.ok()?;
    let counts = lines.next()?.ok()?;
    let created =
        crate::html::parse_ts(created.strip_prefix("-- created: ")?.strip_suffix(" UTC")?)?;
    let kind = BackupKind::parse(kind.strip_prefix("-- kind: ")?)?;
    let mut it = counts.strip_prefix("-- tables: ")?.split(" rows: ");
    let tables = it.next()?.parse().ok()?;
    let rows = it.next()?.parse().ok()?;
    Some((kind, created, DumpInfo { tables, rows }))
}

/// Check the checksum line and that the SQL parses. Returns the number of statements.
pub fn verify(content: &str) -> Result<usize, String> {
    if !content.starts_with(MAGIC) {
        return Err("not a NovaDB workspace dump".into());
    }
    let body = content.trim_end_matches('\n');
    let cut = body.rfind('\n').ok_or("file is truncated")?;
    let (head, last) = (&body[..=cut], &body[cut + 1..]);
    let want = last
        .strip_prefix(SUM)
        .ok_or("checksum line missing (file truncated?)")?;
    if auth::sha256_hex(head.as_bytes()) != want {
        return Err("checksum mismatch: the file was changed or damaged".into());
    }
    let n = novadb_sql::parse(head).map_err(|e| format!("SQL does not parse: {e}"))?;
    Ok(n.len())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn names_are_strict() {
        assert!(name_ok("workspace-20261118-020000-auto.sql"));
        assert!(!name_ok("../workspace-x.sql"));
        assert!(!name_ok("workspace-/etc/passwd.sql"));
        assert!(!name_ok("workspace-a..b.sql"));
        assert!(!name_ok("other.sql"));
        assert!(!name_ok("workspace-X.sql"));
    }

    #[test]
    fn write_list_verify_prune() {
        let d = std::env::temp_dir().join(format!("novadb-bk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let b = Backups::new(d.clone()).unwrap();
        let info = DumpInfo { tables: 1, rows: 2 };
        let body = "CREATE TABLE t (a INT);\nINSERT INTO t (`a`) VALUES (1), (2);\n";
        let mut names = Vec::new();
        for i in 0..4 {
            names.push(
                b.write(BackupKind::Auto, 1_800_000_000 + i * 60, body, info)
                    .unwrap(),
            );
        }
        let m = b
            .write(BackupKind::Manual, 1_800_000_000, body, info)
            .unwrap();
        let l = b.list().unwrap();
        assert_eq!(l.len(), 5);
        assert_eq!(l[0].created, 1_800_000_180);
        assert_eq!(l[0].info, info);
        let c = b.read(&m).unwrap();
        assert_eq!(verify(&c).unwrap(), 2);
        assert!(
            verify(&c.replace("(2)", "(3)"))
                .unwrap_err()
                .contains("checksum")
        );
        assert!(verify(&c[..c.len() - 20]).is_err());
        let mode = std::fs::metadata(d.join(&m)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(b.prune_auto(2).unwrap(), 2);
        assert_eq!(b.list().unwrap().len(), 3);
        assert_eq!(b.last_auto(), 1_800_000_180);
        assert!(b.read("../x").is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }
}
