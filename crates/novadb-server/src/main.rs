//! `novadb-server` — Stage 4: MySQL wire protocol over TLS.
//!
//! * Binds `127.0.0.1:3307` by default (never 3306, never a wildcard address unless `--listen` asks).
//! * TLS is mandatory. Certificate from `--tls-cert/--tls-key` (PEM) or a self-signed one
//!   generated at first start in `<data>/tls/` (key 0600).
//! * Users authenticate with `caching_sha2_password` *full* authentication: the password
//!   travels inside TLS and is checked against an Argon2id hash. First start creates `root`
//!   with a random password in `<data>/initial-root-password.txt` (0600). No defaults.
//! * Pre-auth limits (PLAN.md §4.5/4.6): 64 KiB packets, 10 s handshake, 32 connections per
//!   IP, 256 total, auth attempts rate-limited per IP and per user *before* hashing, at most 2
//!   concurrent Argon2 verifications.
#![forbid(unsafe_code)]

mod auth;
mod conn;
mod ops;

use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use novadb_sql::ast::Stmt;
use novadb_sql::{Engine, QueryResult, Session, SqlError};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub const INITIAL_PW_FILE: &str = "initial-root-password.txt";
const MAX_CONNECTIONS: usize = 256;
const MAX_PER_IP: usize = 32;

/// A live, authenticated connection (for KILL / SHOW PROCESSLIST).
pub struct ConnInfo {
    pub user: String,
    pub host: String,
    pub since: Instant,
    pub cancel: Arc<std::sync::atomic::AtomicBool>,
    pub closing: Arc<std::sync::atomic::AtomicBool>,
    pub info: Mutex<Option<String>>,
}

pub struct Server {
    engine: Arc<Mutex<Engine>>,
    data_dir: PathBuf,
    backup_key: [u8; 32],
    metrics: ops::Metrics,
    conns: Mutex<HashMap<u32, Arc<ConnInfo>>>,
    tls: TlsAcceptor,
    limiter: auth::RateLimiter,
    hash_sem: tokio::sync::Semaphore,
    dummy_hash: String,
    version: String,
    max_packet: usize,
    started: Instant,
    active: AtomicUsize,
}

impl Server {
    /// Execute one statement on the blocking pool (single writer engine). Returns the result
    /// and the connection's server status bits (IN_TRANS / AUTOCOMMIT).
    async fn run(&self, st: Stmt, sess: &mut Session) -> (Result<QueryResult, SqlError>, u16) {
        let eng = self.engine.clone();
        let mut s = sess.clone();
        let cancel = self.conn(sess.conn_id).map(|c| {
            c.cancel.store(false, Ordering::Relaxed);
            c.cancel.clone()
        });
        let started = Instant::now();
        let joined = tokio::task::spawn_blocking(move || {
            novadb_sql::set_cancel_flag(cancel);
            let (mut r, mut status) = match eng.lock() {
                Ok(mut e) => {
                    let r = e.run_in_start(&st, &mut s);
                    (r, e.status(s.conn_id))
                }
                Err(_) => (Err(SqlError::internal("engine lock poisoned")), 2),
            };
            // Online ALTER TABLE: one batch per lock hold, so other sessions keep running.
            if r.is_ok() && matches!(st, Stmt::AlterTable { .. }) {
                loop {
                    let step = match eng.lock() {
                        Ok(mut e) if e.alter_owner() == Some(s.conn_id) => {
                            let x = e.alter_step();
                            status = e.status(s.conn_id);
                            x
                        }
                        Ok(_) => break,
                        Err(_) => Err(SqlError::internal("engine lock poisoned")),
                    };
                    match step {
                        Ok(None) => std::thread::sleep(std::time::Duration::from_millis(1)),
                        Ok(Some(done)) => {
                            r = Ok(done);
                            break;
                        }
                        Err(e) => {
                            r = Err(e);
                            break;
                        }
                    }
                }
            }
            novadb_sql::set_cancel_flag(None);
            (r, status, s)
        })
        .await;
        let m = &self.metrics;
        ops::Metrics::inc(&m.queries);
        m.query_micros
            .fetch_add(started.elapsed().as_micros() as u64, Ordering::Relaxed);
        if let Ok((Err(e), _, _)) = &joined {
            ops::Metrics::inc(&m.query_errors);
            match e.code {
                1213 => ops::Metrics::inc(&m.conflicts),
                1317 | 3024 => ops::Metrics::inc(&m.interrupted),
                _ => {}
            }
        }
        match joined {
            Ok((r, status, s)) => {
                *sess = s;
                (r, status)
            }
            Err(e) => (Err(SqlError::internal(format!("task: {e}"))), 2),
        }
    }

    /// Roll back whatever the connection left open.
    async fn end_session(&self, conn_id: u32) {
        let eng = self.engine.clone();
        let _ = tokio::task::spawn_blocking(move || {
            if let Ok(mut e) = eng.lock() {
                e.end_session(conn_id);
            }
        })
        .await;
    }

    /// Verify a password. Unknown users are checked against a dummy hash so timing does not
    /// reveal which names exist.
    async fn verify(&self, user: &str, password: String) -> bool {
        let Ok(_permit) = self.hash_sem.acquire().await else {
            return false;
        };
        let eng = self.engine.clone();
        let user = user.to_string();
        let dummy = self.dummy_hash.clone();
        tokio::task::spawn_blocking(move || {
            let stored = eng
                .lock()
                .ok()
                .and_then(|mut e| e.user_hash(&user).ok().flatten());
            let ok = auth::verify_password(&password, stored.as_deref().unwrap_or(&dummy));
            ok && stored.is_some()
        })
        .await
        .unwrap_or(false)
    }

    /// Global privilege check (blocking engine lock; used for KILL / PROCESSLIST).
    fn has_global(&self, user: &str, p: u64) -> bool {
        novadb_sql::privs::is_root(user)
            || self
                .engine
                .lock()
                .ok()
                .and_then(|mut e| e.has_global(user, p).ok())
                .unwrap_or(false)
    }

    fn conn(&self, id: u32) -> Option<Arc<ConnInfo>> {
        self.conns.lock().ok().and_then(|m| m.get(&id).cloned())
    }

    fn register(&self, id: u32, c: Arc<ConnInfo>) {
        if let Ok(mut m) = self.conns.lock() {
            m.insert(id, c);
        }
    }

    fn unregister(&self, id: u32) {
        if let Ok(mut m) = self.conns.lock() {
            m.remove(&id);
        }
    }

    /// KILL: users may kill their own connections, root any.
    fn kill(&self, by: &str, id: u64, query_only: bool) -> Result<(), SqlError> {
        let target = u32::try_from(id).ok().and_then(|i| self.conn(i));
        let Some(t) = target else {
            let mut e = SqlError::internal(format!("Unknown thread id: {id}"));
            e.code = 1094;
            return Err(e);
        };
        if !t.user.eq_ignore_ascii_case(by) && !self.has_global(by, novadb_sql::privs::SUPER) {
            let mut e = SqlError::internal(format!("You are not owner of thread {id}"));
            e.code = 1095;
            return Err(e);
        }
        t.cancel.store(true, Ordering::Relaxed);
        if !query_only {
            t.closing.store(true, Ordering::Relaxed);
        }
        Ok(())
    }

    fn processlist(&self, by: &str) -> QueryResult {
        let see_all = self.has_global(by, novadb_sql::privs::PROCESS);
        let mut rows = Vec::new();
        if let Ok(m) = self.conns.lock() {
            let mut ids: Vec<&u32> = m.keys().collect();
            ids.sort();
            for id in ids {
                let c = &m[id];
                if !see_all && !c.user.eq_ignore_ascii_case(by) {
                    continue;
                }
                let info = c.info.lock().ok().and_then(|i| i.clone());
                rows.push(vec![
                    novadb_sql::Value::Int(i64::from(*id)),
                    novadb_sql::Value::Str(c.user.clone()),
                    novadb_sql::Value::Str(c.host.clone()),
                    novadb_sql::Value::Str("novadb".into()),
                    novadb_sql::Value::Str(if info.is_some() { "Query" } else { "Sleep" }.into()),
                    novadb_sql::Value::Int(c.since.elapsed().as_secs() as i64),
                    info.map_or(novadb_sql::Value::Null, novadb_sql::Value::Str),
                ]);
            }
        }
        let names = ["Id", "User", "Host", "db", "Command", "Time", "Info"];
        QueryResult {
            columns: names
                .iter()
                .map(|n| novadb_sql::ColumnMeta {
                    name: (*n).into(),
                    ty: None,
                })
                .collect(),
            rows,
            ..Default::default()
        }
    }

    fn active(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }
}

struct Config {
    data_dir: PathBuf,
    listen: SocketAddr,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    backup_key: Option<PathBuf>,
    metrics: Option<SocketAddr>,
    metrics_token: Option<String>,
    no_binlog: bool,
}

const USAGE: &str = "usage:
  novadb-server --data-dir DIR [--listen 127.0.0.1:3307] [--tls-cert FILE --tls-key FILE]
                [--backup-key FILE] [--metrics 127.0.0.1:9104] [--metrics-token-file FILE] [--no-binlog]
  novadb-server --restore BACKUP.nbk --data-dir NEW_DIR --backup-key FILE [--binlog-dir DIR] [--until 'YYYY-MM-DD HH:MM:SS']
  novadb-server --gen-backup-key FILE
  novadb-server --version";

fn parse_args() -> Result<Option<Config>, String> {
    let mut args = std::env::args().skip(1);
    let (mut dir, mut listen, mut cert, mut key) = (None, None, None, None);
    let (mut bkey, mut metrics, mut mtoken, mut no_binlog) = (None, None, None, false);
    let (mut restore, mut binlog_dir, mut until) = (None, None, None);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--version" => {
                println!("novadb-server {}", env!("CARGO_PKG_VERSION"));
                return Ok(None);
            }
            "--gen-backup-key" => {
                let p = args.next().ok_or(USAGE)?;
                ops::write_key_file(Path::new(&p))?;
                println!("wrote a new 256-bit key to {p} (0600)");
                return Ok(None);
            }
            "--data-dir" => dir = args.next(),
            "--listen" => listen = args.next(),
            "--tls-cert" => cert = args.next(),
            "--tls-key" => key = args.next(),
            "--backup-key" => bkey = args.next(),
            "--metrics" => metrics = args.next(),
            "--metrics-token-file" => mtoken = args.next(),
            "--no-binlog" => no_binlog = true,
            "--restore" => restore = args.next(),
            "--binlog-dir" => binlog_dir = args.next(),
            "--until" => until = args.next(),
            _ => return Err(USAGE.into()),
        }
    }
    if let Some(file) = restore {
        let dir = PathBuf::from(dir.ok_or(USAGE)?);
        let kp = bkey.ok_or("--restore needs --backup-key FILE")?;
        let k = ops::read_key(Path::new(&kp))?;
        ops::restore(
            &dir,
            Path::new(&file),
            &k,
            binlog_dir.as_deref().map(Path::new),
            until.as_deref(),
        )?;
        return Ok(None);
    }
    let data_dir = PathBuf::from(dir.ok_or(USAGE)?);
    let listen: SocketAddr = listen
        .as_deref()
        .unwrap_or(novadb_protocol::DEFAULT_LISTEN)
        .parse()
        .map_err(|e| format!("--listen: {e}"))?;
    if cert.is_some() != key.is_some() {
        return Err("--tls-cert and --tls-key go together".into());
    }
    let metrics: Option<SocketAddr> = match metrics {
        Some(m) => Some(m.parse().map_err(|e| format!("--metrics: {e}"))?),
        None => None,
    };
    let metrics_token = match mtoken {
        Some(p) => Some(
            std::fs::read_to_string(&p)
                .map_err(|e| format!("{p}: {e}"))?
                .trim()
                .to_string(),
        ),
        None => None,
    };
    Ok(Some(Config {
        data_dir,
        listen,
        tls_cert: cert.map(PathBuf::from),
        tls_key: key.map(PathBuf::from),
        backup_key: bkey.map(PathBuf::from),
        metrics,
        metrics_token,
        no_binlog,
    }))
}

pub(crate) fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("create {}: {e}", path.display()))?;
    f.write_all(data).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())
}

/// Load the TLS identity, generating a self-signed one on first start.
fn tls_config(cfg: &Config) -> Result<rustls::ServerConfig, String> {
    let (cert_path, key_path) = match (&cfg.tls_cert, &cfg.tls_key) {
        (Some(c), Some(k)) => (c.clone(), k.clone()),
        _ => {
            let dir = cfg.data_dir.join("tls");
            std::fs::create_dir_all(&dir).map_err(|e| format!("tls dir: {e}"))?;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| e.to_string())?;
            let (c, k) = (dir.join("server.crt"), dir.join("server.key"));
            if !c.exists() || !k.exists() {
                let ck = rcgen::generate_simple_self_signed(vec![
                    "localhost".into(),
                    "127.0.0.1".into(),
                    "::1".into(),
                ])
                .map_err(|e| format!("generate certificate: {e}"))?;
                let _ = std::fs::remove_file(&c);
                let _ = std::fs::remove_file(&k);
                write_private(&k, ck.key_pair.serialize_pem().as_bytes())?;
                std::fs::write(&c, ck.cert.pem()).map_err(|e| e.to_string())?;
                println!(
                    "[novadb] generated self-signed TLS certificate {} (give clients --ssl-ca={0})",
                    c.display()
                );
            }
            (c, k)
        }
    };
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&cert_path)
        .map_err(|e| format!("{}: {e}", cert_path.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{}: {e}", cert_path.display()))?;
    let key = PrivateKeyDer::from_pem_file(&key_path)
        .map_err(|e| format!("{}: {e}", key_path.display()))?;
    rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("TLS certificate/key: {e}"))
}

/// First start: create `root` with a random one-time password (PLAN.md §4.1).
fn bootstrap(eng: &mut Engine, dir: &Path) -> Result<(), String> {
    if !eng.users().map_err(|e| e.to_string())?.is_empty() {
        return Ok(());
    }
    let pw = auth::random_password(24)?;
    let path = dir.join(INITIAL_PW_FILE);
    write_private(&path, format!("user: root\npassword: {pw}\n\nChange it: ALTER USER root IDENTIFIED BY '...';\nThen delete this file.\n").as_bytes())?;
    eng.set_user_hash("root", &auth::hash_password(&pw)?)
        .map_err(|e| e.to_string())?;
    println!(
        "[novadb] first start: created user 'root'; one-time password is in {} (0600)",
        path.display()
    );
    Ok(())
}

/// Counts connections per IP; released on drop.
struct ConnGuard {
    server: Arc<Server>,
    per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
    ip: IpAddr,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.server.active.fetch_sub(1, Ordering::Relaxed);
        if let Ok(mut m) = self.per_ip.lock()
            && let Some(n) = m.get_mut(&self.ip)
        {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.ip);
            }
        }
    }
}

async fn serve(server: Arc<Server>, listen: SocketAddr) -> Result<(), String> {
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|e| format!("bind {listen}: {e}"))?;
    println!(
        "[novadb] listening on {listen} (TLS required, MySQL protocol, user auth: caching_sha2_password + Argon2id)"
    );
    let per_ip: Arc<Mutex<HashMap<IpAddr, usize>>> = Arc::new(Mutex::new(HashMap::new()));
    let ids = AtomicU32::new(1);
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| e.to_string())?;
    loop {
        let (tcp, peer) = tokio::select! {
            r = listener.accept() => match r {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[novadb] accept: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            _ = tokio::signal::ctrl_c() => break,
            _ = term.recv() => break,
        };
        let ip = peer.ip();
        let allowed = {
            let mut m = per_ip.lock().map_err(|_| "lock")?;
            let n = m.entry(ip).or_insert(0);
            if *n >= MAX_PER_IP || server.active() >= MAX_CONNECTIONS {
                false
            } else {
                *n += 1;
                server.active.fetch_add(1, Ordering::Relaxed);
                true
            }
        };
        if !allowed {
            // MySQL sends ER_CON_COUNT_ERROR as the very first packet.
            let mut tcp = tcp;
            tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                let mut out = Vec::new();
                novadb_protocol::frame(
                    &mut out,
                    &novadb_protocol::packets::err(1040, "08004", "Too many connections"),
                    0,
                );
                let _ = tcp.write_all(&out).await;
            });
            continue;
        }
        let _ = tcp.set_nodelay(true);
        let guard = ConnGuard {
            server: server.clone(),
            per_ip: per_ip.clone(),
            ip,
        };
        let id = ids.fetch_add(1, Ordering::Relaxed);
        let srv = server.clone();
        tokio::spawn(async move {
            let _g = guard;
            conn::handle(srv, tcp, peer, id).await;
        });
    }
    println!("[novadb] shutting down");
    Ok(())
}

fn run(cfg: Config) -> Result<(), String> {
    std::fs::create_dir_all(&cfg.data_dir).map_err(|e| format!("data dir: {e}"))?;
    std::fs::set_permissions(&cfg.data_dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| e.to_string())?;
    let backup_key = ops::load_or_create_key(&cfg.data_dir, cfg.backup_key.as_deref())?;
    let mut engine = Engine::open(cfg.data_dir.join("db"))
        .map_err(|e| e.to_string())?
        .with_password_hasher(auth::hash_password)
        .with_privileges();
    if !cfg.no_binlog {
        // Encrypted binary log for point-in-time recovery.
        engine = engine
            .with_binlog(&cfg.data_dir.join("binlog"), Some(backup_key))
            .map_err(|e| e.to_string())?;
    }
    bootstrap(&mut engine, &cfg.data_dir)?;
    let tls = tls_config(&cfg)?;
    let server = Arc::new(Server {
        engine: Arc::new(Mutex::new(engine)),
        data_dir: cfg.data_dir.clone(),
        backup_key,
        metrics: ops::Metrics::default(),
        conns: Mutex::new(HashMap::new()),
        tls: TlsAcceptor::from(Arc::new(tls)),
        limiter: auth::RateLimiter::new(),
        hash_sem: tokio::sync::Semaphore::new(2),
        dummy_hash: auth::hash_password("timing-equalisation-dummy")?,
        version: format!("8.0.0-NovaDB-{}", env!("CARGO_PKG_VERSION")),
        max_packet: novadb_protocol::DEFAULT_MAX_ALLOWED_PACKET,
        started: Instant::now(),
        active: AtomicUsize::new(0),
    });
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(16)
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    if let Some(addr) = cfg.metrics {
        if !addr.ip().is_loopback() && cfg.metrics_token.is_none() {
            return Err("--metrics on a non-loopback address needs --metrics-token-file".into());
        }
        rt.spawn(ops::serve_metrics(
            server.clone(),
            addr,
            cfg.metrics_token.clone(),
        ));
    }
    rt.block_on(serve(server.clone(), cfg.listen))?;
    rt.shutdown_timeout(Duration::from_secs(5));
    // Close the engine cleanly if no connection still holds it (otherwise WAL recovery on
    // the next start covers it).
    match Arc::try_unwrap(server)
        .ok()
        .and_then(|s| Arc::try_unwrap(s.engine).ok())
        .and_then(|m| m.into_inner().ok())
    {
        Some(e) => e.close().map_err(|e| e.to_string()),
        None => Ok(()),
    }
}

fn main() -> ExitCode {
    match parse_args() {
        Ok(None) => ExitCode::SUCCESS,
        Ok(Some(cfg)) => match run(cfg) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("[novadb] fatal: {e}");
                ExitCode::FAILURE
            }
        },
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(2)
        }
    }
}
