//! Stage 7 server operations: encryption key, online backups, restore / PITR, metrics.

use std::io::Read;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use novadb_sql::backup::{self, BackupWriter};
use novadb_sql::{Engine, QueryResult, SqlError};

use crate::Server;

/// Counters exported on /metrics.
#[derive(Default)]
pub struct Metrics {
    pub connections_total: AtomicU64,
    pub auth_failures: AtomicU64,
    pub auth_rate_limited: AtomicU64,
    pub queries: AtomicU64,
    pub query_errors: AtomicU64,
    pub conflicts: AtomicU64,
    pub interrupted: AtomicU64,
    pub backups: AtomicU64,
    pub query_micros: AtomicU64,
}

impl Metrics {
    pub fn inc(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }
}

/// Load the 32-byte backup/binlog key, creating `<data>/keys/backup.key` (0600) if needed.
pub fn load_or_create_key(data_dir: &Path, explicit: Option<&Path>) -> Result<[u8; 32], String> {
    if let Some(p) = explicit {
        let t = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
        return backup::parse_key(&t).map_err(|e| e.msg);
    }
    let dir = data_dir.join("keys");
    std::fs::create_dir_all(&dir).map_err(|e| format!("keys dir: {e}"))?;
    let _ = std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700));
    let p = dir.join("backup.key");
    if p.exists() {
        let t = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        return backup::parse_key(&t).map_err(|e| e.msg);
    }
    let k = backup::new_key().map_err(|e| e.msg)?;
    let hex: String = k.iter().map(|b| format!("{b:02x}")).collect();
    crate::write_private(&p, format!("{hex}\n").as_bytes())?;
    println!(
        "[novadb] generated backup/binlog encryption key {} — copy it somewhere safe and OFF this server: \
         without it backups and binary logs cannot be read",
        p.display()
    );
    Ok(k)
}

pub fn write_key_file(path: &Path) -> Result<(), String> {
    let k = backup::new_key().map_err(|e| e.msg)?;
    let hex: String = k.iter().map(|b| format!("{b:02x}")).collect();
    crate::write_private(path, format!("{hex}\n").as_bytes())
}

fn lock(srv: &Server) -> Result<std::sync::MutexGuard<'_, Engine>, SqlError> {
    srv.engine
        .lock()
        .map_err(|_| SqlError::internal("engine lock poisoned"))
}

fn valid_backup_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 64
        && !n.starts_with('.')
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

/// BACKUP DATABASE TO 'name': consistent snapshot, written in batches so the engine lock is
/// released between them (writers keep working). Root only; files live in <data>/backups.
pub async fn backup(server: &Arc<Server>, user: &str, name: &str) -> Result<QueryResult, SqlError> {
    if !user.eq_ignore_ascii_case("root") {
        let mut e = SqlError::internal("Access denied; you need root to run BACKUP");
        e.code = 1227;
        e.state = "42000";
        return Err(e);
    }
    if !valid_backup_name(name) {
        return Err(SqlError::internal(
            "backup name: 1-64 characters a-z A-Z 0-9 . _ - (written to <data>/backups/)",
        ));
    }
    let dir = server.data_dir.join("backups");
    std::fs::create_dir_all(&dir).map_err(|e| SqlError::internal(format!("backups dir: {e}")))?;
    let path = dir.join(format!("{name}.nbk"));
    if path.exists() {
        return Err(SqlError::internal(format!(
            "backup '{name}' already exists"
        )));
    }
    let srv = server.clone();
    let p2 = path.clone();
    let res = tokio::task::spawn_blocking(move || -> Result<u64, SqlError> {
        // A connection id no client can have.
        let conn = u32::MAX - 1;
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as i64)
            .unwrap_or(0);
        let (snap, users, tables) = {
            let mut e = lock(&srv)?;
            let snap = e.dump_begin(conn)?;
            let users: Vec<(String, String)> = e
                .users()?
                .into_iter()
                .filter_map(|u| e.user_hash(&u).ok().flatten().map(|h| (u, h)))
                .collect();
            let tables = e.dump_tables()?;
            (snap, users, tables)
        };
        let out = (|| {
            let mut w = BackupWriter::create(&p2, Some(srv.backup_key))?;
            backup::write_header(&mut w, snap, wall, &users)?;
            for (name, ddl, ai) in &tables {
                w.item(ddl)?;
                let mut after: Option<Vec<u8>> = None;
                loop {
                    let (rows, last) = lock(&srv)?.dump_rows(
                        conn,
                        name,
                        after.as_deref(),
                        backup::ROWS_PER_INSERT,
                    )?;
                    if rows.is_empty() {
                        break;
                    }
                    w.item(&backup::insert_stmt(name, &rows))?;
                    after = last;
                }
                if *ai > 1 {
                    w.item(&format!("-- novadb:autoinc {ai} {name}"))?;
                }
            }
            w.finish()?;
            lock(&srv)?.rotate_binlog()?;
            Ok(snap)
        })();
        if let Ok(mut e) = lock(&srv) {
            e.end_session(conn);
        }
        if out.is_err() {
            let _ = std::fs::remove_file(&p2);
        }
        out
    })
    .await
    .map_err(|e| SqlError::internal(format!("backup task: {e}")))?;
    let snap = res?;
    Metrics::inc(&server.metrics.backups);
    Ok(QueryResult {
        info: Some(format!(
            "backup written to {} (snapshot {snap}, encrypted)",
            path.display()
        )),
        ..Default::default()
    })
}

/// `--restore FILE --data-dir NEW [--binlog-dir DIR] [--until 'YYYY-MM-DD HH:MM:SS']`
pub fn restore(
    data_dir: &Path,
    file: &Path,
    key: &[u8; 32],
    binlog_dir: Option<&Path>,
    until: Option<&str>,
) -> Result<(), String> {
    if data_dir.join("db").exists() {
        return Err(format!(
            "{} already holds a database; restore into a new directory",
            data_dir.display()
        ));
    }
    let until_us = match until {
        Some(t) => Some(
            novadb_sql::value::parse_datetime(t)
                .ok_or("--until: use 'YYYY-MM-DD HH:MM:SS[.ffffff]' (UTC)")?,
        ),
        None => None,
    };
    std::fs::create_dir_all(data_dir).map_err(|e| e.to_string())?;
    let _ = std::fs::set_permissions(
        data_dir,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    );
    let mut e = Engine::open(data_dir.join("db")).map_err(|e| e.to_string())?;
    let snap = backup::restore(&mut e, file, Some(key)).map_err(|e| e.to_string())?;
    println!(
        "[novadb] restored backup {} (snapshot {snap})",
        file.display()
    );
    if let Some(dir) = binlog_dir {
        let n =
            backup::replay(&mut e, dir, Some(key), snap, until_us).map_err(|e| e.to_string())?;
        println!(
            "[novadb] replayed {n} binary-log record(s) from {}{}",
            dir.display(),
            until.map(|u| format!(" up to {u} UTC")).unwrap_or_default()
        );
    }
    e.close().map_err(|e| e.to_string())
}

/// Minimal Prometheus endpoint (GET /metrics). Bind to loopback; optional bearer token.
pub async fn serve_metrics(server: Arc<Server>, addr: SocketAddr, token: Option<String>) {
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[novadb] metrics: bind {addr}: {e}");
            return;
        }
    };
    println!("[novadb] metrics on http://{addr}/metrics");
    loop {
        let Ok((mut s, _)) = listener.accept().await else {
            continue;
        };
        let srv = server.clone();
        let token = token.clone();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = vec![0u8; 4096];
            let n = match tokio::time::timeout(std::time::Duration::from_secs(5), s.read(&mut buf))
                .await
            {
                Ok(Ok(n)) => n,
                _ => return,
            };
            let req = String::from_utf8_lossy(&buf[..n]);
            let authed = token.as_ref().is_none_or(|t| {
                req.lines()
                    .any(|l| l.eq_ignore_ascii_case(&format!("authorization: bearer {t}")))
            });
            let (status, body) = if !req.starts_with("GET /metrics") {
                ("404 Not Found", "not found\n".to_string())
            } else if !authed {
                ("401 Unauthorized", "unauthorized\n".to_string())
            } else {
                ("200 OK", render(&srv).await)
            };
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes()).await;
        });
    }
}

async fn render(srv: &Arc<Server>) -> String {
    let m = &srv.metrics;
    let g = |c: &AtomicU64| c.load(Ordering::Relaxed);
    let eng = srv.engine.clone();
    let (stats, txns) = tokio::task::spawn_blocking(move || {
        eng.lock()
            .map(|mut e| (e.db().stats(), e.open_transactions()))
            .ok()
    })
    .await
    .ok()
    .flatten()
    .unwrap_or_default();
    let mut o = String::new();
    let mut put = |name: &str, kind: &str, help: &str, v: u64| {
        o.push_str(&format!(
            "# HELP novadb_{name} {help}\n# TYPE novadb_{name} {kind}\nnovadb_{name} {v}\n"
        ));
    };
    put(
        "uptime_seconds",
        "gauge",
        "Seconds since start",
        srv.started.elapsed().as_secs(),
    );
    put(
        "connections_active",
        "gauge",
        "Open client connections",
        srv.active() as u64,
    );
    put(
        "connections_total",
        "counter",
        "Authenticated connections",
        g(&m.connections_total),
    );
    put(
        "auth_failures_total",
        "counter",
        "Failed logins",
        g(&m.auth_failures),
    );
    put(
        "auth_rate_limited_total",
        "counter",
        "Logins refused by the rate limiter",
        g(&m.auth_rate_limited),
    );
    put(
        "queries_total",
        "counter",
        "Statements executed",
        g(&m.queries),
    );
    put(
        "query_errors_total",
        "counter",
        "Statements that returned an error",
        g(&m.query_errors),
    );
    put(
        "query_seconds_total",
        "counter",
        "Time spent executing statements (seconds)",
        g(&m.query_micros) / 1_000_000,
    );
    put(
        "txn_conflicts_total",
        "counter",
        "Transactions aborted by write conflicts (1213)",
        g(&m.conflicts),
    );
    put(
        "queries_interrupted_total",
        "counter",
        "Statements stopped by KILL or max_execution_time",
        g(&m.interrupted),
    );
    put("backups_total", "counter", "Backups written", g(&m.backups));
    put(
        "transactions_open",
        "gauge",
        "Open multi-statement transactions",
        txns as u64,
    );
    put(
        "storage_pages",
        "gauge",
        "Pages in the data file",
        stats.page_count,
    );
    put(
        "storage_free_pages",
        "gauge",
        "Free pages",
        stats.free_pages,
    );
    put(
        "storage_wal_bytes",
        "gauge",
        "Write-ahead log size",
        stats.wal_bytes,
    );
    put(
        "storage_page_reads_total",
        "counter",
        "Pages read from disk",
        stats.page_reads,
    );
    put(
        "storage_page_writes_total",
        "counter",
        "Pages written",
        stats.page_writes,
    );
    put(
        "storage_checkpoints_total",
        "counter",
        "Checkpoints",
        stats.checkpoints,
    );
    o
}

/// Used by `--restore`: read a key file or fail with a clear message.
pub fn read_key(path: &Path) -> Result<[u8; 32], String> {
    let mut t = String::new();
    std::fs::File::open(path)
        .and_then(|mut f| f.read_to_string(&mut t))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    backup::parse_key(&t).map_err(|e| e.msg)
}
