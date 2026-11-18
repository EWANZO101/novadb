//! SQL workspace: an embedded NovaDB SQL engine (`<data>/sql`) behind the Databases screen.
//!
//! Every web request runs as its own connection id; an open transaction left at the end of a
//! request is rolled back. Statements are classified before they run: operators may only read,
//! admins may also write, and SQL-account statements (which carry passwords) are refused here so
//! a password can never reach the audit log.

use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use novadb_sql::ast::Stmt;
use novadb_sql::{Engine, QueryResult, Session};

/// Rows kept per result set for display (the engine may produce more).
pub const MAX_ROWS: usize = 1000;
/// Longest SQL text accepted from the console.
pub const MAX_SQL: usize = 64 * 1024;
/// Most statements per console run.
pub const MAX_STMTS: usize = 50;
/// Default SELECT time limit per statement (ms). Only admins may change it.
pub const MAX_EXEC_MS: u64 = 10_000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// Reads data or metadata only.
    Read,
    /// Changes data or schema.
    Write,
    /// Connection housekeeping (BEGIN/COMMIT/SET/USE): allowed for anyone who may read.
    Control,
    /// Never allowed from the dashboard.
    Forbidden,
}

pub fn classify(s: &Stmt) -> Kind {
    match s {
        Stmt::Select(_)
        | Stmt::ShowTables
        | Stmt::ShowDatabases
        | Stmt::ShowVariables { .. }
        | Stmt::ShowWarnings
        | Stmt::Describe(_)
        | Stmt::ShowCreateTable(_) => Kind::Read,
        Stmt::Explain(inner) => match classify(inner) {
            Kind::Forbidden => Kind::Forbidden,
            _ => Kind::Read,
        },
        // Lifting the time limit is a privileged change (it can tie up the workspace).
        Stmt::Set(v) if v.iter().any(|(n, _)| n == "max_execution_time") => Kind::Write,
        Stmt::Txn(_) | Stmt::Set(_) | Stmt::Use(_) => Kind::Control,
        Stmt::CreateUser { .. } | Stmt::AlterUser { .. } | Stmt::DropUser { .. } => Kind::Forbidden,
        _ => Kind::Write,
    }
}

/// One statement's outcome, already trimmed for display.
pub struct Outcome {
    pub sql: String,
    pub result: Result<QueryResult, String>,
    pub truncated: bool,
    pub micros: u128,
}

#[derive(Clone)]
pub struct SqlShared {
    eng: Arc<Mutex<Option<Engine>>>,
    next_conn: Arc<AtomicU32>,
}

impl SqlShared {
    pub fn open(dir: &Path) -> Result<SqlShared, String> {
        if !dir.exists() {
            std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                    .map_err(|e| format!("chmod {}: {e}", dir.display()))?;
            }
        }
        let e = Engine::open(dir).map_err(|e| e.to_string())?;
        Ok(SqlShared {
            eng: Arc::new(Mutex::new(Some(e))),
            next_conn: Arc::new(AtomicU32::new(1_000_000)),
        })
    }

    /// Run `f` with the engine and a fresh connection on the blocking pool.
    pub async fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Engine, &mut Session) -> Result<T, String> + Send + 'static,
    ) -> Result<T, String> {
        let eng = self.eng.clone();
        let conn = self.next_conn.fetch_add(1, Ordering::Relaxed);
        tokio::task::spawn_blocking(move || {
            let mut g = eng.lock().map_err(|_| "sql lock poisoned".to_string())?;
            let e = g.as_mut().ok_or("sql workspace closed")?;
            let mut sess = Session {
                user: "dashboard".into(),
                conn_id: conn,
                last_insert_id: 0,
                max_execution_ms: MAX_EXEC_MS,
            };
            let r = f(e, &mut sess);
            e.end_session(conn);
            r
        })
        .await
        .map_err(|e| format!("task: {e}"))?
    }

    pub fn close(&self) -> Result<(), String> {
        let mut g = self
            .eng
            .lock()
            .map_err(|_| "sql lock poisoned".to_string())?;
        match g.take() {
            Some(e) => e.close().map_err(|e| e.to_string()),
            None => Ok(()),
        }
    }
}

/// Run parsed statements in order; stops at the first error (like a script).
pub fn run_all(e: &mut Engine, sess: &mut Session, stmts: &[(String, Stmt)]) -> Vec<Outcome> {
    let mut out = Vec::new();
    for (text, s) in stmts {
        let t0 = std::time::Instant::now();
        let r = e.run_in(s, sess).map_err(|x| x.to_string());
        let micros = t0.elapsed().as_micros();
        let failed = r.is_err();
        let (result, truncated) = match r {
            Ok(mut q) => {
                let t = q.rows.len() > MAX_ROWS;
                q.rows.truncate(MAX_ROWS);
                (Ok(q), t)
            }
            Err(x) => (Err(x), false),
        };
        out.push(Outcome {
            sql: text.clone(),
            result,
            truncated,
            micros,
        });
        if failed {
            break;
        }
    }
    out
}

/// Split a script into statements with their source text (for display + audit).
/// Each piece is re-parsed alone so the text shown next to a result is exactly what ran.
pub fn parse_script(sql: &str) -> Result<Vec<(String, Stmt)>, String> {
    if sql.len() > MAX_SQL {
        return Err(format!("SQL is longer than {} KiB.", MAX_SQL / 1024));
    }
    let all = novadb_sql::parse(sql).map_err(|e| e.to_string())?;
    if all.len() > MAX_STMTS {
        return Err(format!("At most {MAX_STMTS} statements per run."));
    }
    let pieces = split_statements(sql);
    if pieces.len() == all.len() {
        Ok(pieces.into_iter().zip(all).collect())
    } else {
        // Splitter disagreed with the parser (exotic quoting): show the whole script per stmt.
        Ok(all
            .into_iter()
            .map(|s| (sql.trim().to_string(), s))
            .collect())
    }
}

/// Split on `;` outside quotes, backticks and comments.
fn split_statements(sql: &str) -> Vec<String> {
    let b = sql.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            q @ (b'\'' | b'"' | b'`') => {
                i += 1;
                while i < b.len() {
                    if b[i] == b'\\' && q != b'`' {
                        i += 2;
                        continue;
                    }
                    if b[i] == q {
                        if b.get(i + 1) == Some(&q) {
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    i += 1;
                }
            }
            b'-' if b.get(i + 1) == Some(&b'-') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'#' => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    i += 1;
                }
                i += 1;
            }
            b';' => {
                let piece = sql.get(start..i).unwrap_or("").trim();
                if !piece.is_empty() {
                    out.push(piece.to_string());
                }
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    let tail = sql.get(start.min(sql.len())..).unwrap_or("").trim();
    if !tail.is_empty() {
        out.push(tail.to_string());
    }
    out
}

/// Plain identifier (letters, digits, `_`, `$`) — the only table names the browser links to.
pub fn plain_ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'$')
}

/// Demo schema for an empty workspace.
pub const DEMO_SQL: &str = "CREATE TABLE IF NOT EXISTS customers (id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(80) NOT NULL, email VARCHAR(120) UNIQUE, city VARCHAR(60), created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS orders (id INT PRIMARY KEY AUTO_INCREMENT, customer_id INT NOT NULL, total DECIMAL(10,2) NOT NULL, status VARCHAR(20) NOT NULL DEFAULT 'pending', placed_at DATETIME DEFAULT CURRENT_TIMESTAMP, KEY idx_customer (customer_id));
INSERT INTO customers (name, email, city) VALUES ('Thandi Mokoena', 'thandi@example.com', 'Johannesburg'), ('Pieter van Wyk', 'pieter@example.com', 'Cape Town'), ('Aisha Patel', 'aisha@example.com', 'Durban'), ('Sipho Dlamini', 'sipho@example.com', 'Pretoria');
INSERT INTO orders (customer_id, total, status) VALUES (1, 499.99, 'paid'), (1, 120.00, 'pending'), (2, 2450.50, 'paid'), (3, 89.95, 'refunded'), (4, 1310.00, 'paid')";

// ----- logical dump / restore ---------------------------------------------------------------

/// What a dump contains.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DumpInfo {
    pub tables: usize,
    pub rows: usize,
}

/// Rows per INSERT statement in a dump.
const DUMP_BATCH: usize = 100;

fn quote_ident(n: &str) -> String {
    format!("`{}`", n.replace('`', "``"))
}

/// SQL literal that the NovaDB lexer reads back to the same value.
pub fn sql_literal(v: &novadb_sql::Value) -> String {
    use novadb_sql::Value;
    match v {
        Value::Null => "NULL".into(),
        Value::Int(_) | Value::Dec { .. } => v.text().unwrap_or_default(),
        Value::Bytes(b) => {
            if b.is_empty() {
                "''".into()
            } else {
                format!(
                    "X'{}'",
                    b.iter().map(|x| format!("{x:02X}")).collect::<String>()
                )
            }
        }
        other => format!(
            "'{}'",
            other
                .text()
                .unwrap_or_default()
                .replace('\\', "\\\\")
                .replace('\'', "''")
        ),
    }
}

fn run1(e: &mut Engine, s: &mut Session, q: &str) -> Result<QueryResult, String> {
    let st = novadb_sql::parse(q).map_err(|x| x.to_string())?;
    let first = st.first().ok_or("empty statement")?;
    e.run_in(first, s).map_err(|x| x.to_string())
}

fn table_names(e: &mut Engine, s: &mut Session) -> Result<Vec<String>, String> {
    let r = run1(e, s, "SHOW TABLES")?;
    Ok((0..r.rows.len()).filter_map(|i| r.text(i, 0)).collect())
}

/// Consistent logical dump (one snapshot) of every table: CREATE TABLE + batched INSERTs.
/// Returns the statements only; the caller adds the header and checksum.
pub fn dump(e: &mut Engine, s: &mut Session) -> Result<(String, DumpInfo), String> {
    let saved = s.max_execution_ms;
    s.max_execution_ms = 0; // internal job: no per-SELECT limit
    let r = (|| {
        run1(e, s, "BEGIN")?;
        let mut out = String::new();
        let mut info = DumpInfo::default();
        for t in table_names(e, s)? {
            let q = quote_ident(&t);
            let create = run1(e, s, &format!("SHOW CREATE TABLE {q}"))?
                .text(0, 1)
                .ok_or_else(|| format!("no CREATE statement for {t}"))?;
            out.push_str(&format!(
                "\n-- table {t}\nDROP TABLE IF EXISTS {q};\n{create};\n"
            ));
            let rows = run1(e, s, &format!("SELECT * FROM {q}"))?;
            let cols = rows
                .columns
                .iter()
                .map(|c| quote_ident(&c.name))
                .collect::<Vec<_>>()
                .join(", ");
            for chunk in rows.rows.chunks(DUMP_BATCH) {
                let vals: Vec<String> = chunk
                    .iter()
                    .map(|r| {
                        format!(
                            "({})",
                            r.iter().map(sql_literal).collect::<Vec<_>>().join(", ")
                        )
                    })
                    .collect();
                out.push_str(&format!(
                    "INSERT INTO {q} ({cols}) VALUES\n  {};\n",
                    vals.join(",\n  ")
                ));
            }
            info.tables += 1;
            info.rows += rows.rows.len();
        }
        run1(e, s, "COMMIT")?;
        Ok((out, info))
    })();
    s.max_execution_ms = saved;
    r
}

/// Drop every table in the workspace. Returns how many were dropped.
pub fn drop_all(e: &mut Engine, s: &mut Session) -> Result<usize, String> {
    let names = table_names(e, s)?;
    for t in &names {
        run1(e, s, &format!("DROP TABLE IF EXISTS {}", quote_ident(t)))?;
    }
    Ok(names.len())
}

/// Replace the workspace with a dump. Stops at the first failing statement.
pub fn load(e: &mut Engine, s: &mut Session, script: &str) -> Result<usize, String> {
    let stmts = novadb_sql::parse(script).map_err(|x| x.to_string())?;
    if stmts.iter().any(|st| classify(st) == Kind::Forbidden) {
        return Err("dump contains SQL account statements".into());
    }
    drop_all(e, s)?;
    for (i, st) in stmts.iter().enumerate() {
        e.run_in(st, s)
            .map_err(|x| format!("statement {}: {x}", i + 1))?;
    }
    Ok(stmts.len())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn splits_outside_quotes_and_comments() {
        let v = split_statements("SELECT 'a;b'; -- x;y\nSELECT `c;d` /* ; */ ;  ; SELECT 1");
        assert_eq!(v.len(), 3);
        assert_eq!(v[0], "SELECT 'a;b'");
        assert_eq!(v[2], "SELECT 1");
    }

    #[test]
    fn classification() {
        let k = |s: &str| classify(&novadb_sql::parse(s).unwrap()[0]);
        assert_eq!(k("SELECT 1"), Kind::Read);
        assert_eq!(k("SHOW TABLES"), Kind::Read);
        assert_eq!(k("EXPLAIN SELECT 1"), Kind::Read);
        assert_eq!(k("DELETE FROM t"), Kind::Write);
        assert_eq!(k("CREATE TABLE t (a INT)"), Kind::Write);
        assert_eq!(k("BEGIN"), Kind::Control);
        assert_eq!(k("SET autocommit = 0"), Kind::Control);
        assert_eq!(k("SET max_execution_time = 0"), Kind::Write);
        assert_eq!(
            k("CREATE USER x IDENTIFIED BY 'long-password-123'"),
            Kind::Forbidden
        );
        assert!(plain_ident("orders_2026"));
        assert!(!plain_ident("a`b"));
        assert!(parse_script(&"x".repeat(MAX_SQL + 1)).is_err());
    }

    #[test]
    fn demo_runs_and_txn_rolls_back() {
        let d = std::env::temp_dir().join(format!("novadb-sqlws-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let mut e = Engine::open(&d).unwrap();
        let mut s = Session {
            conn_id: 7,
            ..Session::default()
        };
        let out = run_all(&mut e, &mut s, &parse_script(DEMO_SQL).unwrap());
        assert!(out.iter().all(|o| o.result.is_ok()));
        let out = run_all(
            &mut e,
            &mut s,
            &parse_script("BEGIN; DELETE FROM orders; SELECT * FROM orders").unwrap(),
        );
        assert_eq!(out[2].result.as_ref().unwrap().rows.len(), 0);
        e.end_session(7);
        let r = e.query("SELECT * FROM orders").unwrap();
        assert_eq!(r.rows.len(), 5, "uncommitted delete must roll back");
        e.close().unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn dump_round_trip() {
        let d = std::env::temp_dir().join(format!("novadb-sqlws-dump-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let mut e = Engine::open(&d).unwrap();
        let mut s = Session {
            conn_id: 9,
            ..Session::default()
        };
        run_all(&mut e, &mut s, &parse_script(DEMO_SQL).unwrap());
        run_all(
            &mut e,
            &mut s,
            &parse_script("CREATE TABLE odd (k INT PRIMARY KEY, t TEXT, b BLOB, d DATETIME(3)); INSERT INTO odd VALUES (1, 'it''s a \\\\ back; slash -- not comment', X'00FF', '2026-01-02 03:04:05.678'), (2, NULL, NULL, NULL)").unwrap(),
        );
        let before: Vec<String> = ["customers", "orders", "odd"]
            .iter()
            .map(|t| format!("{:?}", e.query(&format!("SELECT * FROM {t}")).unwrap().rows))
            .collect();
        let (sql, info) = dump(&mut e, &mut s).unwrap();
        assert_eq!(
            info,
            DumpInfo {
                tables: 3,
                rows: 11
            }
        );
        run1(&mut e, &mut s, "DELETE FROM orders").unwrap();
        run1(&mut e, &mut s, "CREATE TABLE extra (a INT)").unwrap();
        load(&mut e, &mut s, &sql).unwrap();
        let after: Vec<String> = ["customers", "orders", "odd"]
            .iter()
            .map(|t| format!("{:?}", e.query(&format!("SELECT * FROM {t}")).unwrap().rows))
            .collect();
        assert_eq!(before, after);
        assert!(
            e.query("SELECT * FROM extra").is_err(),
            "tables not in the dump are dropped"
        );
        // AUTO_INCREMENT continues after the restored ids.
        let r = e
            .execute("INSERT INTO orders (customer_id, total) VALUES (1, 1.00)")
            .unwrap();
        assert_eq!(r[0].last_insert_id, 6);
        e.close().unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }
}
