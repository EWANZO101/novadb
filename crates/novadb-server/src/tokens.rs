//! REST/WebSocket API tokens and saved queries (Stage 10).
//!
//! * `<data>/rest-tokens.json` (0600): one entry per token — id, label, SQL user it acts as,
//!   scopes, optional table allow-list, expiry, rate limit and the SHA-256 of the secret. The
//!   secret itself (`nvdb_<id>_<secret>`) is shown once at creation and never stored.
//! * `<data>/rest-queries.json` (0600): named, parameterised statements (`?` placeholders) that
//!   tokens with the `query` scope may run — the "allow-listed operations" of PLAN.md §4.8.
//!
//! Both files are re-read when they change, so `novadb-server token …` / `query …` take effect
//! without a restart.

use std::collections::BTreeMap;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const TOKENS_FILE: &str = "rest-tokens.json";
pub const QUERIES_FILE: &str = "rest-queries.json";
pub const SCOPES: [&str; 3] = ["rows", "query", "sql"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Token {
    pub id: String,
    pub name: String,
    /// SQL user whose GRANTs apply.
    pub user: String,
    pub scopes: Vec<String>,
    /// `rows` scope only: tables this token may touch (None = any the user may).
    #[serde(default)]
    pub tables: Option<Vec<String>>,
    /// hex SHA-256 of the secret part
    pub hash: String,
    pub created: u64,
    #[serde(default)]
    pub expires: Option<u64>,
    /// requests per minute (default 600)
    #[serde(default)]
    pub rate: Option<u32>,
}

impl Token {
    pub fn has(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
    pub fn table_ok(&self, t: &str) -> bool {
        self.tables
            .as_ref()
            .is_none_or(|l| l.iter().any(|x| x.eq_ignore_ascii_case(t)))
    }
    pub fn per_minute(&self) -> u32 {
        self.rate.unwrap_or(600).clamp(1, 100_000)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SavedQuery {
    pub sql: String,
    /// Names of the `?` parameters, in order (callers may pass an object by name or an array).
    #[serde(default)]
    pub params: Vec<String>,
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sha_hex(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

fn read_json<T: for<'de> Deserialize<'de> + Default>(p: &Path) -> Result<T, String> {
    match std::fs::read(p) {
        Ok(b) => serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", p.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(format!("{}: {e}", p.display())),
    }
}

/// Atomic 0600 write (temp file + rename).
fn write_json<T: Serialize>(p: &Path, v: &T) -> Result<(), String> {
    use std::io::Write;
    let tmp = p.with_extension("json.tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    let b = serde_json::to_vec_pretty(v).map_err(|e| e.to_string())?;
    f.write_all(&b).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, p).map_err(|e| e.to_string())
}

fn mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

/// Cached view of both files, refreshed when their mtime changes.
pub struct Store {
    tokens_path: PathBuf,
    queries_path: PathBuf,
    cache: Mutex<Cache>,
}

#[derive(Default)]
struct Cache {
    tok_m: Option<SystemTime>,
    tokens: Vec<Token>,
    q_m: Option<SystemTime>,
    queries: BTreeMap<String, SavedQuery>,
}

impl Store {
    pub fn new(dir: &Path) -> Self {
        Store {
            tokens_path: dir.join(TOKENS_FILE),
            queries_path: dir.join(QUERIES_FILE),
            cache: Mutex::new(Cache::default()),
        }
    }

    fn refresh(&self, c: &mut Cache) {
        let m = mtime(&self.tokens_path);
        if m != c.tok_m || m.is_none() {
            match read_json::<Vec<Token>>(&self.tokens_path) {
                Ok(t) => c.tokens = t,
                Err(e) => eprintln!("[novadb] rest tokens: {e} (keeping previous)"),
            }
            c.tok_m = m;
        }
        let m = mtime(&self.queries_path);
        if m != c.q_m || m.is_none() {
            match read_json::<BTreeMap<String, SavedQuery>>(&self.queries_path) {
                Ok(q) => c.queries = q,
                Err(e) => eprintln!("[novadb] rest queries: {e} (keeping previous)"),
            }
            c.q_m = m;
        }
    }

    /// Check a bearer token; returns the token entry if valid and not expired.
    pub fn verify(&self, bearer: &str) -> Option<Token> {
        let rest = bearer.strip_prefix("nvdb_")?;
        let (id, secret) = rest.split_once('_')?;
        if id.len() != 12 || secret.len() != 64 {
            return None;
        }
        let want = sha_hex(secret.as_bytes());
        let mut c = self.cache.lock().ok()?;
        self.refresh(&mut c);
        let t = c.tokens.iter().find(|t| t.id == id)?;
        if !bool::from(t.hash.as_bytes().ct_eq(want.as_bytes())) {
            return None;
        }
        if t.expires.is_some_and(|e| now() >= e) {
            return None;
        }
        Some(t.clone())
    }

    pub fn query(&self, name: &str) -> Option<SavedQuery> {
        let mut c = self.cache.lock().ok()?;
        self.refresh(&mut c);
        c.queries.get(name).cloned()
    }
}

/// Parsed `--flag value` options after a subcommand.
fn opts(args: &[String]) -> Result<(BTreeMap<String, String>, Vec<String>), String> {
    let mut m = BTreeMap::new();
    let mut pos = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if let Some(k) = args[i].strip_prefix("--") {
            let v = args
                .get(i + 1)
                .ok_or_else(|| format!("--{k} needs a value"))?;
            m.insert(k.to_string(), v.clone());
            i += 2;
        } else {
            pos.push(args[i].clone());
            i += 1;
        }
    }
    Ok((m, pos))
}

fn hex_random<const N: usize>() -> Result<String, String> {
    Ok(crate::auth::random_bytes::<N>()?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

const CLI_USAGE: &str = "usage:
  novadb-server token create --data-dir DIR --user SQLUSER [--scopes rows,query,sql] [--tables t1,t2]
                             [--days N] [--name LABEL] [--rate PER_MINUTE]
  novadb-server token list   --data-dir DIR
  novadb-server token revoke --data-dir DIR ID
  novadb-server query add    --data-dir DIR NAME 'SELECT … WHERE id = ?' [--params id]
  novadb-server query list   --data-dir DIR
  novadb-server query remove --data-dir DIR NAME";

/// `novadb-server token …` / `novadb-server query …`. Returns the text to print.
pub fn cli(kind: &str, args: &[String]) -> Result<String, String> {
    let sub = args.first().ok_or(CLI_USAGE)?.as_str();
    let (o, pos) = opts(&args[1..])?;
    let dir = PathBuf::from(o.get("data-dir").ok_or("--data-dir DIR is required")?);
    let tpath = dir.join(TOKENS_FILE);
    let qpath = dir.join(QUERIES_FILE);
    match (kind, sub) {
        ("token", "create") => {
            let user = o.get("user").ok_or("--user SQLUSER is required")?.clone();
            let scopes: Vec<String> = o
                .get("scopes")
                .map_or("rows,query", String::as_str)
                .split(',')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
            for s in &scopes {
                if !SCOPES.contains(&s.as_str()) {
                    return Err(format!("unknown scope {s:?} (rows, query, sql)"));
                }
            }
            let tables = o.get("tables").map(|t| {
                t.split(',')
                    .map(|x| x.trim().to_string())
                    .filter(|x| !x.is_empty())
                    .collect()
            });
            let days: Option<u64> = match o.get("days") {
                Some(d) => Some(d.parse().map_err(|_| "--days: number")?),
                None => None,
            };
            let rate: Option<u32> = match o.get("rate") {
                Some(d) => Some(d.parse().map_err(|_| "--rate: number")?),
                None => None,
            };
            let id = hex_random::<6>()?;
            let secret = hex_random::<32>()?;
            let mut all: Vec<Token> = read_json(&tpath)?;
            all.push(Token {
                id: id.clone(),
                name: o.get("name").cloned().unwrap_or_default(),
                user: user.clone(),
                scopes: scopes.clone(),
                tables,
                hash: sha_hex(secret.as_bytes()),
                created: now(),
                expires: days.map(|d| now() + d * 86_400),
                rate,
            });
            write_json(&tpath, &all)?;
            let mut out = format!(
                "token (shown once, store it safely):\n\nnvdb_{id}_{secret}\n\nid {id}, acts as SQL user '{user}', scopes {}",
                scopes.join(",")
            );
            if user.eq_ignore_ascii_case("root") {
                out.push_str("\nwarning: root can do everything — prefer a dedicated user with only the GRANTs the API needs");
            }
            if scopes.iter().any(|s| s == "sql") {
                out.push_str(
                    "\nwarning: the sql scope runs arbitrary SQL with this user's privileges",
                );
            }
            Ok(out)
        }
        ("token", "list") => {
            let all: Vec<Token> = read_json(&tpath)?;
            let mut out =
                String::from("ID           USER             SCOPES           EXPIRES     NAME\n");
            for t in all {
                let exp = t.expires.map_or("never".to_string(), |e| {
                    if e <= now() {
                        "expired".into()
                    } else {
                        format!("in {}d", (e - now()) / 86_400)
                    }
                });
                out.push_str(&format!(
                    "{:<12} {:<16} {:<16} {:<11} {}\n",
                    t.id,
                    t.user,
                    t.scopes.join(","),
                    exp,
                    t.name
                ));
            }
            Ok(out)
        }
        ("token", "revoke") => {
            let id = pos.first().ok_or("token revoke needs an ID")?;
            let mut all: Vec<Token> = read_json(&tpath)?;
            let n = all.len();
            all.retain(|t| &t.id != id);
            if all.len() == n {
                return Err(format!("no token {id}"));
            }
            write_json(&tpath, &all)?;
            Ok(format!("revoked {id}"))
        }
        ("query", "add") => {
            let name = pos.first().ok_or("query add needs NAME and SQL")?;
            let sql = pos.get(1).ok_or("query add needs NAME and SQL")?;
            if name.is_empty()
                || name.len() > 64
                || !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                return Err("query names: 1-64 of a-z A-Z 0-9 _ -".into());
            }
            let (stmts, nparams) = novadb_sql::parse_prepared(sql).map_err(|e| e.to_string())?;
            if stmts.len() != 1 {
                return Err("a saved query must be exactly one statement".into());
            }
            let params: Vec<String> = match o.get("params") {
                Some(p) => p.split(',').map(|x| x.trim().to_string()).collect(),
                None => (1..=nparams).map(|i| format!("p{i}")).collect(),
            };
            if params.len() != nparams {
                return Err(format!(
                    "the statement has {nparams} '?' placeholders but {} parameter names were given",
                    params.len()
                ));
            }
            let mut all: BTreeMap<String, SavedQuery> = read_json(&qpath)?;
            all.insert(
                name.clone(),
                SavedQuery {
                    sql: sql.clone(),
                    params: params.clone(),
                },
            );
            write_json(&qpath, &all)?;
            Ok(format!(
                "saved query {name} (params: {})",
                params.join(", ")
            ))
        }
        ("query", "list") => {
            let all: BTreeMap<String, SavedQuery> = read_json(&qpath)?;
            Ok(all
                .iter()
                .map(|(n, q)| format!("{n}({}): {}\n", q.params.join(", "), q.sql))
                .collect())
        }
        ("query", "remove") => {
            let name = pos.first().ok_or("query remove needs NAME")?;
            let mut all: BTreeMap<String, SavedQuery> = read_json(&qpath)?;
            if all.remove(name).is_none() {
                return Err(format!("no query {name}"));
            }
            write_json(&qpath, &all)?;
            Ok(format!("removed {name}"))
        }
        _ => Err(CLI_USAGE.into()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn create_verify_revoke() {
        let d = std::env::temp_dir().join(format!("novadb-tok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let ds = d.to_str().unwrap();
        let out = cli(
            "token",
            &s(&[
                "create",
                "--data-dir",
                ds,
                "--user",
                "app",
                "--tables",
                "a,b",
                "--days",
                "1",
            ]),
        )
        .unwrap();
        let tok = out
            .lines()
            .find(|l| l.starts_with("nvdb_"))
            .unwrap()
            .to_string();
        let st = Store::new(&d);
        let t = st.verify(&tok).unwrap();
        assert_eq!(t.user, "app");
        assert!(t.has("rows") && t.has("query") && !t.has("sql"));
        assert!(t.table_ok("A") && !t.table_ok("c"));
        // wrong secret / malformed
        let mut bad = tok.clone();
        bad.pop();
        bad.push(if tok.ends_with('0') { '1' } else { '0' });
        assert!(st.verify(&bad).is_none());
        assert!(st.verify("nvdb_x_y").is_none());
        assert!(st.verify("Bearer").is_none());
        // the secret is not stored
        let file = std::fs::read_to_string(d.join(TOKENS_FILE)).unwrap();
        assert!(!file.contains(tok.rsplit('_').next().unwrap()));
        let meta = std::fs::metadata(d.join(TOKENS_FILE)).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert!(
            cli(
                "token",
                &s(&[
                    "create",
                    "--data-dir",
                    ds,
                    "--user",
                    "x",
                    "--scopes",
                    "admin"
                ])
            )
            .is_err()
        );
        cli("token", &s(&["revoke", "--data-dir", ds, &t.id])).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(st.verify(&tok).is_none(), "revocation is picked up");
        // saved queries
        cli(
            "query",
            &s(&[
                "add",
                "--data-dir",
                ds,
                "by_id",
                "SELECT * FROM a WHERE id = ?",
                "--params",
                "id",
            ]),
        )
        .unwrap();
        assert_eq!(st.query("by_id").unwrap().params, vec!["id"]);
        assert!(
            cli(
                "query",
                &s(&["add", "--data-dir", ds, "two", "SELECT 1; SELECT 2"])
            )
            .is_err()
        );
        assert!(
            cli(
                "query",
                &s(&["add", "--data-dir", ds, "bad name", "SELECT 1"])
            )
            .is_err()
        );
        assert!(
            cli(
                "query",
                &s(&["add", "--data-dir", ds, "n", "SELECT ?", "--params", "a,b"])
            )
            .is_err()
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
