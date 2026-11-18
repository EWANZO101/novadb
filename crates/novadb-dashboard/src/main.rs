//! `novadb-dashboard` — Stage 9 control dashboard + identity.
//!
//! * Users, sessions, OAuth links and the audit log live in NovaDB's own storage engine.
//! * No default credentials: the first run creates `admin` with a random password written to
//!   `<data>/initial-admin-password.txt` (0600). It must be changed and TOTP enrolled before
//!   anything else is reachable (PLAN.md §4.1).
//! * Binds 127.0.0.1 only; meant to sit behind nginx/TLS.
//!
//! Configuration (environment):
//! `NOVADB_DASH_DATA` (default `./dashboard-data`), `NOVADB_DASH_LISTEN` (default
//! `127.0.0.1:9620`), `NOVADB_DASH_PUBLIC_URL` (e.g. `https://novadb.example.com`),
//! `NOVADB_DASH_TRUSTED_PROXY` (default `127.0.0.1`; the only peer whose X-Real-IP is used),
//! `NOVADB_DISCORD_CLIENT_ID` / `_SECRET`, `NOVADB_GITHUB_CLIENT_ID` / `_SECRET` (optional).
#![forbid(unsafe_code)]

mod auth;
mod backup;
mod html;
mod oauth;
mod sqlws;
mod store;
mod totp;
mod web;

use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use store::{Role, Shared, Store, User};

pub const INITIAL_PW_FILE: &str = "initial-admin-password.txt";

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.trim().is_empty())
}

fn provider(kind: oauth::Kind, prefix: &str) -> Option<oauth::Provider> {
    Some(oauth::Provider {
        kind,
        client_id: env(&format!("{prefix}_CLIENT_ID"))?,
        client_secret: env(&format!("{prefix}_CLIENT_SECRET"))?,
    })
}

/// Create the first admin if there are no users. Returns true when created.
fn bootstrap(s: &mut Store, dir: &Path) -> Result<bool, String> {
    if !s.list_users()?.is_empty() {
        return Ok(false);
    }
    let pw = auth::random_password(24)?;
    let user = User {
        name: "admin".into(),
        role: Role::Admin,
        pw: auth::hash_password(&pw)?,
        must_change: true,
        totp: None,
        totp_last: 0,
        disabled: false,
        failed: 0,
        locked_until: 0,
        created: web::now(),
        last_login: 0,
        links: vec![],
        recovery: vec![],
    };
    let path = dir.join(INITIAL_PW_FILE);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    writeln!(f, "username: admin\npassword: {pw}\n\nOne-time password. You must change it and set up 2FA at first sign-in.\nThis file is deleted automatically once the password is changed.")
        .map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    s.put_user(&user)?;
    s.audit(
        web::now(),
        "system",
        "-",
        "bootstrap",
        "created admin with one-time password",
    )?;
    Ok(true)
}

fn run() -> Result<(), String> {
    let data_dir =
        PathBuf::from(env("NOVADB_DASH_DATA").unwrap_or_else(|| "dashboard-data".into()));
    let listen: SocketAddr = env("NOVADB_DASH_LISTEN")
        .unwrap_or_else(|| "127.0.0.1:9620".into())
        .parse()
        .map_err(|e| format!("NOVADB_DASH_LISTEN: {e}"))?;
    let public_url = env("NOVADB_DASH_PUBLIC_URL").unwrap_or_else(|| format!("http://{listen}"));
    let trusted_proxy: Option<IpAddr> = match env("NOVADB_DASH_TRUSTED_PROXY").as_deref() {
        Some("none") => None,
        Some(v) => Some(
            v.parse()
                .map_err(|e| format!("NOVADB_DASH_TRUSTED_PROXY: {e}"))?,
        ),
        None => Some(IpAddr::from([127, 0, 0, 1])),
    };
    if !public_url.starts_with("https://") && !listen.ip().is_loopback() {
        return Err(
            "refusing to listen on a non-loopback address without an https public URL".into(),
        );
    }

    std::fs::create_dir_all(&data_dir).map_err(|e| format!("data dir: {e}"))?;
    std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("data dir perms: {e}"))?;
    let db_dir = data_dir.join("system");
    std::fs::create_dir_all(&db_dir).map_err(|e| format!("db dir: {e}"))?;

    let mut st = Store::open(&db_dir)?;
    if bootstrap(&mut st, &data_dir)? {
        println!(
            "[dashboard] first run: created user 'admin'; one-time password is in {} (0600)",
            data_dir.join(INITIAL_PW_FILE).display()
        );
    }
    let store = Shared::new(st);
    // The SQL workspace is optional: if it cannot open, the rest of the dashboard still works.
    let sql = match sqlws::SqlShared::open(&data_dir.join("sql")) {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("[dashboard] SQL workspace unavailable: {e}");
            None
        }
    };
    let sql_close = sql.clone();
    let backups = match backup::Backups::new(data_dir.join("backups")) {
        Ok(b) => Some(Arc::new(b)),
        Err(e) => {
            eprintln!("[dashboard] backups unavailable: {e}");
            None
        }
    };

    let cfg = web::Config {
        public_url,
        trusted_proxy,
        data_dir: data_dir.clone(),
        discord: provider(oauth::Kind::Discord, "NOVADB_DISCORD"),
        github: provider(oauth::Kind::Github, "NOVADB_GITHUB"),
    };
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("novadb-dashboard/", env!("CARGO_PKG_VERSION")))
        .https_only(true)
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    let app = Arc::new(web::App {
        store: store.clone(),
        dummy_hash: auth::hash_password("dummy password for timing equalisation")?,
        cfg,
        limiter: auth::RateLimiter::new(),
        hash_sem: tokio::sync::Semaphore::new(2),
        flows: oauth::Flows::new(),
        http,
        started: web::now(),
        sql,
        backups,
    });

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(8)
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    let pruner = store.clone();
    let bk_app = app.clone();
    rt.block_on(async move {
        tokio::spawn(async move {
            // First check shortly after start, then hourly; a backup is taken when the last
            // automatic one is older than a day.
            tokio::time::sleep(Duration::from_secs(120)).await;
            let mut iv = tokio::time::interval(Duration::from_secs(3600));
            loop {
                iv.tick().await;
                web::auto_backup(&bk_app).await;
            }
        });
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(300));
            loop {
                iv.tick().await;
                let t = web::now();
                if let Err(e) = pruner
                    .run(move |s| s.prune_sessions(t, web::IDLE, web::ABSOLUTE))
                    .await
                {
                    eprintln!("[dashboard] session prune failed: {e}");
                }
            }
        });
        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .map_err(|e| format!("bind {listen}: {e}"))?;
        println!(
            "[dashboard] listening on http://{listen} (public {}); discord={} github={}",
            app.cfg.public_url,
            app.cfg.discord.is_some(),
            app.cfg.github.is_some()
        );
        axum::serve(
            listener,
            web::router(app).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            // docker stop / systemd send SIGTERM; Ctrl-C sends SIGINT.
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut term) => {
                    tokio::select! {
                        _ = term.recv() => {}
                        _ = tokio::signal::ctrl_c() => {}
                    }
                }
                Err(_) => {
                    let _ = tokio::signal::ctrl_c().await;
                }
            }
        })
        .await
        .map_err(|e| format!("serve: {e}"))
    })?;
    drop(rt);
    if let Some(Err(e)) = sql_close.map(|s| s.close()) {
        eprintln!("[dashboard] SQL workspace close failed: {e}");
    }
    // All handler clones are gone once the runtime is dropped.
    store.close()
}

fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("novadb-dashboard {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[dashboard] fatal: {e}");
            ExitCode::FAILURE
        }
    }
}
