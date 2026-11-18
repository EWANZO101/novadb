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

pub struct Server {
    engine: Arc<Mutex<Engine>>,
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
    /// Execute one statement on the blocking pool (single writer engine).
    async fn run(&self, st: Stmt, sess: &mut Session) -> Result<QueryResult, SqlError> {
        let eng = self.engine.clone();
        let mut s = sess.clone();
        let (r, s) = tokio::task::spawn_blocking(move || {
            let r = match eng.lock() {
                Ok(mut e) => e.run_in(&st, &mut s),
                Err(_) => Err(SqlError::internal("engine lock poisoned")),
            };
            (r, s)
        })
        .await
        .map_err(|e| SqlError::internal(format!("task: {e}")))?;
        *sess = s;
        r
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

    fn active(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }
}

struct Config {
    data_dir: PathBuf,
    listen: SocketAddr,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
}

const USAGE: &str = "usage: novadb-server --data-dir DIR [--listen 127.0.0.1:3307] [--tls-cert FILE --tls-key FILE] | --version";

fn parse_args() -> Result<Option<Config>, String> {
    let mut args = std::env::args().skip(1);
    let (mut dir, mut listen, mut cert, mut key) = (None, None, None, None);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--version" => {
                println!("novadb-server {}", env!("CARGO_PKG_VERSION"));
                return Ok(None);
            }
            "--data-dir" => dir = args.next(),
            "--listen" => listen = args.next(),
            "--tls-cert" => cert = args.next(),
            "--tls-key" => key = args.next(),
            _ => return Err(USAGE.into()),
        }
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
    Ok(Some(Config {
        data_dir,
        listen,
        tls_cert: cert.map(PathBuf::from),
        tls_key: key.map(PathBuf::from),
    }))
}

fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
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
    let mut engine = Engine::open(cfg.data_dir.join("db"))
        .map_err(|e| e.to_string())?
        .with_password_hasher(auth::hash_password);
    bootstrap(&mut engine, &cfg.data_dir)?;
    let tls = tls_config(&cfg)?;
    let server = Arc::new(Server {
        engine: Arc::new(Mutex::new(engine)),
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
