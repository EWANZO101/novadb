//! Dashboard state kept in NovaDB's own storage engine (dogfooding): users, sessions, OAuth
//! links and an append-only, hash-chained audit log (PLAN.md §4.18).

use std::path::Path;
use std::sync::{Arc, Mutex};

use novadb_storage::{Db, Options, Stats, Tree, VerifyReport};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::auth;

pub type R<T> = Result<T, String>;

fn se(e: novadb_storage::Error) -> String {
    format!("storage: {e}")
}

/// Access level, ordered.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Viewer,
    Operator,
    Admin,
}

impl Role {
    pub fn name(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Operator => "operator",
            Role::Admin => "admin",
        }
    }
    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "viewer" => Some(Role::Viewer),
            "operator" => Some(Role::Operator),
            "admin" => Some(Role::Admin),
            _ => None,
        }
    }
}

/// An external identity linked to a user (provider user **id**, never e-mail; PLAN.md §4.9).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Link {
    pub provider: String,
    pub id: String,
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct User {
    pub name: String,
    pub role: Role,
    /// Argon2id PHC string.
    pub pw: String,
    pub must_change: bool,
    /// Base32 TOTP secret once enrolled.
    pub totp: Option<String>,
    /// Last accepted TOTP step (replay protection).
    pub totp_last: u64,
    pub disabled: bool,
    pub failed: u32,
    pub locked_until: u64,
    pub created: u64,
    pub last_login: u64,
    #[serde(default)]
    pub links: Vec<Link>,
    /// SHA-256 hashes of unused recovery codes (single use).
    #[serde(default)]
    pub recovery: Vec<String>,
}

/// Where a session is in the login flow.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Stage {
    /// Password (or OAuth) ok, TOTP still required.
    Mfa,
    /// Must change password and/or enrol TOTP before anything else.
    Setup,
    /// Fully authenticated.
    Full,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Session {
    pub user: String,
    pub stage: Stage,
    pub created: u64,
    pub last_seen: u64,
    pub csrf: String,
    pub ip: String,
    pub ua: String,
    /// TOTP secret shown during enrolment, not yet confirmed.
    pub pending_totp: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuditEntry {
    pub seq: u64,
    pub ts: u64,
    pub actor: String,
    pub ip: String,
    pub action: String,
    pub detail: String,
    pub prev: String,
    pub hash: String,
}

impl AuditEntry {
    fn compute_hash(&self) -> String {
        let body = format!(
            "{}\x1f{}\x1f{}\x1f{}\x1f{}\x1f{}\x1f{}",
            self.prev, self.seq, self.ts, self.actor, self.ip, self.action, self.detail
        );
        auth::sha256_hex(body.as_bytes())
    }
}

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub struct Store {
    db: Db,
    users: Tree,
    sessions: Tree,
    audit: Tree,
    links: Tree,
    meta: Tree,
}

fn get_json<T: DeserializeOwned>(db: &mut Db, t: Tree, key: &[u8]) -> R<Option<T>> {
    let v = db.view(|tx| tx.get(&t, key)).map_err(se)?;
    match v {
        None => Ok(None),
        Some(b) => serde_json::from_slice(&b)
            .map(Some)
            .map_err(|e| format!("decode: {e}")),
    }
}

fn put_json<T: Serialize>(db: &mut Db, t: Tree, key: &[u8], v: &T) -> R<()> {
    let b = serde_json::to_vec(v).map_err(|e| e.to_string())?;
    db.update(|tx| tx.put(&t, key, &b).map(|_| ())).map_err(se)
}

fn del(db: &mut Db, t: Tree, key: &[u8]) -> R<()> {
    db.update(|tx| tx.delete(&t, key).map(|_| ())).map_err(se)
}

fn all_json<T: DeserializeOwned>(db: &mut Db, t: Tree) -> R<Vec<(Vec<u8>, T)>> {
    let rows = db
        .view(|tx| tx.range(&t, ..)?.collect::<Result<Vec<_>, _>>())
        .map_err(se)?;
    rows.into_iter()
        .map(|(k, v)| {
            serde_json::from_slice(&v)
                .map(|x| (k, x))
                .map_err(|e| format!("decode: {e}"))
        })
        .collect()
}

/// Truncate to at most `n` chars.
pub fn clip(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

impl Store {
    pub fn open(dir: &Path) -> R<Store> {
        let opts = Options {
            cache_pages: 256,
            checkpoint_wal_bytes: 8 << 20,
            create_if_missing: true,
        };
        let mut db = Db::open(dir, opts).map_err(se)?;
        let (users, sessions, audit, links, meta) = db
            .update(|tx| {
                Ok((
                    tx.open_or_create_tree("dash_users")?,
                    tx.open_or_create_tree("dash_sessions")?,
                    tx.open_or_create_tree("dash_audit")?,
                    tx.open_or_create_tree("dash_links")?,
                    tx.open_or_create_tree("dash_meta")?,
                ))
            })
            .map_err(se)?;
        Ok(Store {
            db,
            users,
            sessions,
            audit,
            links,
            meta,
        })
    }

    pub fn close(self) -> R<()> {
        self.db.close().map_err(se)
    }

    // ----- users ---------------------------------------------------------------------------

    pub fn get_user(&mut self, name: &str) -> R<Option<User>> {
        get_json(&mut self.db, self.users, name.as_bytes())
    }
    pub fn put_user(&mut self, u: &User) -> R<()> {
        put_json(&mut self.db, self.users, u.name.as_bytes(), u)
    }
    pub fn delete_user(&mut self, name: &str) -> R<()> {
        if let Some(u) = self.get_user(name)? {
            for l in &u.links {
                self.unlink(&l.provider, &l.id)?;
            }
        }
        self.delete_sessions_for(name, None)?;
        del(&mut self.db, self.users, name.as_bytes())
    }
    pub fn list_users(&mut self) -> R<Vec<User>> {
        Ok(all_json(&mut self.db, self.users)?
            .into_iter()
            .map(|(_, u)| u)
            .collect())
    }

    // ----- sessions (keyed by SHA-256 of the cookie token) -----------------------------------

    pub fn get_session(&mut self, key: &str) -> R<Option<Session>> {
        get_json(&mut self.db, self.sessions, key.as_bytes())
    }
    pub fn put_session(&mut self, key: &str, s: &Session) -> R<()> {
        put_json(&mut self.db, self.sessions, key.as_bytes(), s)
    }
    pub fn delete_session(&mut self, key: &str) -> R<()> {
        del(&mut self.db, self.sessions, key.as_bytes())
    }
    pub fn sessions_for(&mut self, user: &str) -> R<Vec<(String, Session)>> {
        Ok(all_json::<Session>(&mut self.db, self.sessions)?
            .into_iter()
            .filter(|(_, s)| s.user == user)
            .map(|(k, s)| (String::from_utf8_lossy(&k).into_owned(), s))
            .collect())
    }
    /// Revoke all sessions of `user` except `keep`.
    pub fn delete_sessions_for(&mut self, user: &str, keep: Option<&str>) -> R<usize> {
        let mut n = 0;
        for (k, _) in self.sessions_for(user)? {
            if Some(k.as_str()) != keep {
                self.delete_session(&k)?;
                n += 1;
            }
        }
        Ok(n)
    }
    /// Drop expired sessions.
    pub fn prune_sessions(&mut self, now: u64, idle: u64, absolute: u64) -> R<usize> {
        let mut n = 0;
        for (k, s) in all_json::<Session>(&mut self.db, self.sessions)? {
            if now.saturating_sub(s.last_seen) > idle || now.saturating_sub(s.created) > absolute {
                del(&mut self.db, self.sessions, &k)?;
                n += 1;
            }
        }
        Ok(n)
    }
    /// Every session (key, session).
    pub fn all_sessions(&mut self) -> R<Vec<(String, Session)>> {
        Ok(all_json::<Session>(&mut self.db, self.sessions)?
            .into_iter()
            .map(|(k, s)| (String::from_utf8_lossy(&k).into_owned(), s))
            .collect())
    }
    pub fn session_count(&mut self) -> R<usize> {
        Ok(all_json::<Session>(&mut self.db, self.sessions)?.len())
    }

    // ----- OAuth links ---------------------------------------------------------------------

    fn link_key(provider: &str, id: &str) -> Vec<u8> {
        format!("{provider}:{id}").into_bytes()
    }
    pub fn linked_user(&mut self, provider: &str, id: &str) -> R<Option<String>> {
        get_json(&mut self.db, self.links, &Self::link_key(provider, id))
    }
    pub fn link(&mut self, provider: &str, id: &str, user: &str) -> R<()> {
        put_json(
            &mut self.db,
            self.links,
            &Self::link_key(provider, id),
            &user,
        )
    }
    pub fn unlink(&mut self, provider: &str, id: &str) -> R<()> {
        del(&mut self.db, self.links, &Self::link_key(provider, id))
    }

    // ----- audit ---------------------------------------------------------------------------

    fn audit_head(&mut self) -> R<(u64, String)> {
        let v: Option<(u64, String)> = get_json(&mut self.db, self.meta, b"audit_head")?;
        Ok(v.unwrap_or((0, GENESIS.to_string())))
    }

    /// Append one entry. Detail must never contain secrets.
    pub fn audit(&mut self, ts: u64, actor: &str, ip: &str, action: &str, detail: &str) -> R<()> {
        let (seq, prev) = self.audit_head()?;
        let mut e = AuditEntry {
            seq: seq + 1,
            ts,
            actor: clip(actor, 64),
            ip: clip(ip, 64),
            action: clip(action, 64),
            detail: clip(detail, 400),
            prev,
            hash: String::new(),
        };
        e.hash = e.compute_hash();
        let ev = serde_json::to_vec(&e).map_err(|x| x.to_string())?;
        let hv = serde_json::to_vec(&(e.seq, e.hash.clone())).map_err(|x| x.to_string())?;
        let (a, m) = (self.audit, self.meta);
        // Entry and head move together in one transaction.
        self.db
            .update(|tx| {
                tx.put(&a, &e.seq.to_be_bytes(), &ev)?;
                tx.put(&m, b"audit_head", &hv)?;
                Ok(())
            })
            .map_err(se)
    }

    /// Newest `limit` entries, newest first.
    pub fn audit_recent(&mut self, limit: u64) -> R<Vec<AuditEntry>> {
        let (head, _) = self.audit_head()?;
        let from = head.saturating_sub(limit) + 1;
        let a = self.audit;
        let start = from.to_be_bytes();
        let rows = self
            .db
            .view(|tx| {
                tx.range(
                    &a,
                    (
                        std::ops::Bound::Included(&start[..]),
                        std::ops::Bound::Unbounded,
                    ),
                )?
                .collect::<Result<Vec<_>, _>>()
            })
            .map_err(se)?;
        let mut out = rows
            .into_iter()
            .map(|(_, v)| serde_json::from_slice(&v).map_err(|e| format!("decode: {e}")))
            .collect::<R<Vec<AuditEntry>>>()?;
        out.reverse();
        Ok(out)
    }

    /// Walks the whole chain. Ok(entries) or Err(first problem).
    /// Every audit entry, newest first.
    pub fn audit_all(&mut self) -> R<Vec<AuditEntry>> {
        let mut v: Vec<AuditEntry> = all_json::<AuditEntry>(&mut self.db, self.audit)?
            .into_iter()
            .map(|(_, e)| e)
            .collect();
        v.reverse();
        Ok(v)
    }

    pub fn audit_verify(&mut self) -> R<u64> {
        let (head_seq, head_hash) = self.audit_head()?;
        let mut prev = GENESIS.to_string();
        let mut n = 0u64;
        for (k, e) in all_json::<AuditEntry>(&mut self.db, self.audit)? {
            n += 1;
            if k != e.seq.to_be_bytes() || e.seq != n {
                return Err(format!("entry {n}: sequence gap or key mismatch"));
            }
            if e.prev != prev {
                return Err(format!("entry {n}: prev hash does not match"));
            }
            if e.compute_hash() != e.hash {
                return Err(format!("entry {n}: content was modified"));
            }
            prev = e.hash;
        }
        if n != head_seq || prev != head_hash {
            return Err("head does not match last entry (entries removed?)".into());
        }
        Ok(n)
    }

    // ----- engine info ---------------------------------------------------------------------

    pub fn stats(&self) -> Stats {
        self.db.stats()
    }
    pub fn verify_db(&mut self) -> R<VerifyReport> {
        self.db.verify().map_err(se)
    }
    /// Flush dirty pages and truncate the WAL now.
    pub fn checkpoint(&mut self) -> R<()> {
        self.db.checkpoint().map_err(se)
    }
    /// Trees in the system database with their entry counts.
    pub fn tree_sizes(&mut self) -> R<Vec<(String, u64)>> {
        let names = self.db.view(|tx| tx.list_trees()).map_err(se)?;
        let mut out = Vec::with_capacity(names.len());
        for n in names {
            let c = self
                .db
                .view(|tx| {
                    let t = tx.open_tree(&n)?;
                    let mut c = 0u64;
                    for r in tx.range(&t, ..)? {
                        r?;
                        c += 1;
                    }
                    Ok(c)
                })
                .map_err(se)?;
            out.push((n, c));
        }
        Ok(out)
    }
    /// What crash recovery did when this database was opened.
    pub fn recovery_report(&self) -> novadb_storage::recovery::RecoveryReport {
        self.db.recovery_report().clone()
    }
}

/// Shared handle; storage calls run on the blocking pool (each commit fsyncs).
#[derive(Clone)]
pub struct Shared(Arc<Mutex<Store>>);

impl Shared {
    pub fn new(s: Store) -> Self {
        Shared(Arc::new(Mutex::new(s)))
    }

    pub async fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Store) -> R<T> + Send + 'static,
    ) -> R<T> {
        let s = self.0.clone();
        tokio::task::spawn_blocking(move || {
            let mut g = s.lock().map_err(|_| "store lock poisoned".to_string())?;
            f(&mut g)
        })
        .await
        .map_err(|e| format!("task: {e}"))?
    }

    /// Close the database (end of process).
    pub fn close(self) -> R<()> {
        match Arc::try_unwrap(self.0) {
            Ok(m) => m
                .into_inner()
                .map_err(|_| "store lock poisoned".to_string())?
                .close(),
            Err(_) => Err("store still in use".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn tmp() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "novadb-dash-test-{}",
            auth::hex(&auth::random_bytes::<8>().unwrap())
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn audit_chain_detects_tampering() {
        let d = tmp();
        {
            let mut s = Store::open(&d).unwrap();
            for i in 0..50 {
                s.audit(i, "admin", "127.0.0.1", "test", &format!("n={i}"))
                    .unwrap();
            }
            assert_eq!(s.audit_verify().unwrap(), 50);
            let recent = s.audit_recent(5).unwrap();
            assert_eq!(recent.len(), 5);
            assert_eq!(recent[0].seq, 50);
            // Tamper with entry 7.
            let a = s.audit;
            let mut e: AuditEntry = get_json(&mut s.db, a, &7u64.to_be_bytes())
                .unwrap()
                .unwrap();
            e.detail = "forged".into();
            put_json(&mut s.db, a, &7u64.to_be_bytes(), &e).unwrap();
            assert!(s.audit_verify().unwrap_err().contains("entry 7"));
            // Remove the last entry instead.
            put_json(&mut s.db, a, &7u64.to_be_bytes(), &{
                e.detail = "n=6".into();
                e
            })
            .unwrap();
            assert_eq!(s.audit_verify().unwrap(), 50);
            del(&mut s.db, a, &50u64.to_be_bytes()).unwrap();
            assert!(s.audit_verify().is_err());
            s.close().unwrap();
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn users_sessions_links_persist() {
        let d = tmp();
        {
            let mut s = Store::open(&d).unwrap();
            let u = User {
                name: "alice".into(),
                role: Role::Admin,
                pw: "x".into(),
                must_change: false,
                totp: None,
                totp_last: 0,
                disabled: false,
                failed: 0,
                locked_until: 0,
                created: 1,
                last_login: 0,
                links: vec![Link {
                    provider: "discord".into(),
                    id: "42".into(),
                    name: "al".into(),
                }],
                recovery: vec![],
            };
            s.put_user(&u).unwrap();
            s.link("discord", "42", "alice").unwrap();
            let sess = Session {
                user: "alice".into(),
                stage: Stage::Full,
                created: 100,
                last_seen: 100,
                csrf: "c".into(),
                ip: "1.2.3.4".into(),
                ua: "t".into(),
                pending_totp: None,
            };
            s.put_session("k1", &sess).unwrap();
            s.put_session("k2", &sess).unwrap();
            s.close().unwrap();
        }
        let mut s = Store::open(&d).unwrap();
        assert_eq!(s.get_user("alice").unwrap().unwrap().role, Role::Admin);
        assert_eq!(
            s.linked_user("discord", "42").unwrap().as_deref(),
            Some("alice")
        );
        assert_eq!(s.delete_sessions_for("alice", Some("k1")).unwrap(), 1);
        assert_eq!(s.prune_sessions(100 + 10_000, 1800, 43_200).unwrap(), 1);
        s.delete_user("alice").unwrap();
        assert!(s.linked_user("discord", "42").unwrap().is_none());
        assert!(s.list_users().unwrap().is_empty());
        s.close().unwrap();
        std::fs::remove_dir_all(&d).unwrap();
    }
}
