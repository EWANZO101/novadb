//! HTTP routes. Every state-changing request is a POST with a per-session CSRF token and an
//! Origin check; the session cookie is `__Host-`, Secure, HttpOnly, SameSite=Lax.

// Handlers return `Result<Response, Response>` (early-return redirects/error pages); boxing every
// Response would only add allocations, so the size lint is silenced for this module.
#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Form, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;

use crate::html::{self, Flash, Nav, csrf, esc};
use crate::oauth::{self, Flows, Kind, Mode, Provider};
use crate::store::{Link, Role, Session, Shared, Stage, User, clip};
use crate::{auth, totp};

mod more;

pub const SESSION_COOKIE: &str = "__Host-novadb_session";
const OAUTH_COOKIE: &str = "__Host-novadb_oauth";
/// Idle timeout.
pub const IDLE: u64 = 30 * 60;
/// Absolute session lifetime.
pub const ABSOLUTE: u64 = 12 * 3600;
const MAX_FAILED: u32 = 10;
const LOCK_SECS: u64 = 15 * 60;
pub const CSS: &str = include_str!("../static/app.css");

pub struct Config {
    pub public_url: String,
    pub trusted_proxy: Option<IpAddr>,
    pub data_dir: std::path::PathBuf,
    pub discord: Option<Provider>,
    pub github: Option<Provider>,
}

pub struct App {
    pub store: Shared,
    pub cfg: Config,
    pub limiter: auth::RateLimiter,
    /// Caps concurrent Argon2id work (PLAN.md §4.5).
    pub hash_sem: Semaphore,
    pub flows: Flows,
    pub http: reqwest::Client,
    /// Hash verified for unknown users so timing does not reveal which names exist.
    pub dummy_hash: String,
    pub started: u64,
}

type S = Arc<App>;
type Res = Result<Response, Response>;

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn router(app: S) -> Router {
    Router::new()
        .route("/", get(overview))
        .route("/healthz", get(|| async { "ok" }))
        .route("/static/app.css", get(css))
        .route("/login", get(login_page).post(login_post))
        .route("/login/totp", get(mfa_page).post(mfa_post))
        .route("/logout", post(logout))
        .route("/setup/password", get(setpw_page).post(setpw_post))
        .route("/setup/totp", get(enrol_page).post(enrol_post))
        .route("/account", get(account_page))
        .route("/account/password", post(account_password))
        .route("/account/totp/reset", post(account_totp_reset))
        .route("/account/sessions/revoke", post(account_revoke))
        .route("/account/unlink", post(account_unlink))
        .route("/users", get(users_page))
        .route("/users/create", post(users_create))
        .route("/users/action", post(users_action))
        .route("/audit", get(more::audit_page))
        .route("/audit/export.csv", get(more::audit_export))
        .route("/sessions", get(more::sessions_page))
        .route("/sessions/revoke", post(more::sessions_revoke))
        .route("/sessions/revoke_all", post(more::sessions_revoke_all))
        .route("/system", get(more::system_page))
        .route("/system/checkpoint", post(more::system_checkpoint))
        .route("/account/recovery", post(more::recovery_generate))
        .route(
            "/account/sessions/revoke_all",
            post(more::account_revoke_all),
        )
        .route("/login/recovery", post(more::login_recovery))
        .route("/oauth/{provider}/start", get(oauth_start_login))
        .route("/oauth/{provider}/link", post(oauth_start_link))
        .route("/oauth/{provider}/callback", get(oauth_callback))
        .fallback(|| async { (StatusCode::NOT_FOUND, "not found") })
        .layer(middleware::from_fn(security_headers))
        .with_state(app)
}

async fn security_headers(req: Request<Body>, next: Next) -> Response {
    let mut r = next.run(req).await;
    let h = r.headers_mut();
    let set = |h: &mut HeaderMap, k: &'static str, v: &'static str| {
        h.insert(k, HeaderValue::from_static(v));
    };
    set(
        h,
        "content-security-policy",
        "default-src 'none'; object-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self' https://discord.com https://github.com; frame-ancestors 'none'; base-uri 'none'",
    );
    set(h, "x-frame-options", "DENY");
    set(h, "x-content-type-options", "nosniff");
    // same-origin (not no-referrer): no-referrer makes browsers send `Origin: null` on form POSTs.
    set(h, "referrer-policy", "same-origin");
    set(h, "cache-control", "no-store");
    set(
        h,
        "permissions-policy",
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    );
    set(h, "cross-origin-opener-policy", "same-origin");
    r
}

async fn css() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        CSS,
    )
        .into_response()
}

// ----- helpers -------------------------------------------------------------------------------

fn client_ip(app: &App, peer: &SocketAddr, h: &HeaderMap) -> String {
    // X-Real-IP is trusted only from the configured reverse proxy (PLAN.md §4.13).
    if Some(peer.ip()) == app.cfg.trusted_proxy
        && let Some(ip) = h
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<IpAddr>().ok())
    {
        return ip.to_string();
    }
    peer.ip().to_string()
}

fn cookie(h: &HeaderMap, name: &str) -> Option<String> {
    h.get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

fn set_cookie(name: &str, value: &str, max_age: u64) -> (header::HeaderName, String) {
    (
        header::SET_COOKIE,
        format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}"),
    )
}

fn ua(h: &HeaderMap) -> String {
    clip(
        h.get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-"),
        160,
    )
}

fn redirect(to: &str) -> Response {
    Redirect::to(to).into_response()
}

fn err_page(code: StatusCode, msg: &str) -> Response {
    (
        code,
        Html(html::page(
            "Error",
            None,
            Flash::Err(msg),
            r#"<h1>Something went wrong</h1><p class="sub">The request could not be completed.</p><p><a class="btn ghost" href="/">&larr; Back to dashboard</a></p>"#,
        )),
    )
        .into_response()
}

fn internal(e: String) -> Response {
    eprintln!("[dashboard] internal error: {e}");
    err_page(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Something went wrong. Details are in the server log.",
    )
}

/// Reject cross-site POSTs (defence in depth next to CSRF tokens + SameSite).
fn origin_ok(app: &App, h: &HeaderMap) -> bool {
    let fetch_site = h.get("sec-fetch-site").and_then(|v| v.to_str().ok());
    match h.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        // Browsers send `Origin: null` for privacy-sensitive contexts (e.g. a no-referrer
        // policy); then only an explicit same-origin Sec-Fetch-Site is accepted.
        Some("null") => fetch_site == Some("same-origin"),
        Some(o) => o == app.cfg.public_url.trim_end_matches('/'),
        // Some clients omit Origin on same-origin POSTs; fall back to Sec-Fetch-Site.
        None => !matches!(fetch_site, Some("cross-site") | Some("same-site")),
    }
}

fn csrf_ok(sess: &Session, form: &HashMap<String, String>) -> bool {
    let got = form.get("csrf").map(String::as_str).unwrap_or("");
    !got.is_empty() && bool::from(got.as_bytes().ct_eq(sess.csrf.as_bytes()))
}

fn field<'a>(f: &'a HashMap<String, String>, k: &str) -> &'a str {
    f.get(k).map(String::as_str).unwrap_or("")
}

fn valid_username(s: &str) -> bool {
    (3..=32).contains(&s.len())
        && s.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-' || b == b'.'
        })
}

struct Ctx {
    key: String,
    sess: Session,
    user: User,
}

impl Ctx {
    fn nav<'a>(&'a self, active: &'a str) -> Nav<'a> {
        Nav {
            user: &self.user.name,
            role: self.user.role,
            csrf: &self.sess.csrf,
            active,
        }
    }
}

/// Load the session from the cookie (expiring it if needed).
async fn load(app: &App, h: &HeaderMap, _ip: String) -> Result<Option<Ctx>, String> {
    let Some(tok) = cookie(h, SESSION_COOKIE) else {
        return Ok(None);
    };
    if tok.len() > 64 {
        return Ok(None);
    }
    let key = auth::sha256_hex(tok.as_bytes());
    let t = now();
    app.store
        .run(move |s| {
            let Some(mut sess) = s.get_session(&key)? else {
                return Ok(None);
            };
            if t.saturating_sub(sess.last_seen) > IDLE || t.saturating_sub(sess.created) > ABSOLUTE
            {
                s.delete_session(&key)?;
                return Ok(None);
            }
            let Some(user) = s.get_user(&sess.user)? else {
                s.delete_session(&key)?;
                return Ok(None);
            };
            if user.disabled {
                s.delete_session(&key)?;
                return Ok(None);
            }
            if t.saturating_sub(sess.last_seen) >= 60 {
                sess.last_seen = t;
                s.put_session(&key, &sess)?;
            }
            Ok(Some(Ctx { key, sess, user }))
        })
        .await
}

/// Fully authenticated user with at least `min` role.
async fn guard(app: &App, h: &HeaderMap, ip: String, min: Role) -> Result<Ctx, Response> {
    let Some(c) = load(app, h, ip).await.map_err(internal)? else {
        return Err(redirect("/login"));
    };
    match c.sess.stage {
        Stage::Mfa => return Err(redirect("/login/totp")),
        Stage::Setup => return Err(redirect(next_setup(&c.user))),
        Stage::Full => {}
    }
    if c.user.role < min {
        return Err(err_page(
            StatusCode::FORBIDDEN,
            "Your role does not allow this page.",
        ));
    }
    Ok(c)
}

fn next_setup(u: &User) -> &'static str {
    if u.must_change {
        "/setup/password"
    } else if u.totp.is_none() {
        "/setup/totp"
    } else {
        "/"
    }
}

/// Guard for POSTs: session + CSRF + Origin.
async fn guard_post(
    app: &App,
    h: &HeaderMap,
    ip: String,
    min: Role,
    form: &HashMap<String, String>,
) -> Result<Ctx, Response> {
    if !origin_ok(app, h) {
        return Err(err_page(
            StatusCode::FORBIDDEN,
            "Cross-site request blocked.",
        ));
    }
    let c = guard(app, h, ip, min).await?;
    if !csrf_ok(&c.sess, form) {
        return Err(err_page(
            StatusCode::FORBIDDEN,
            "Form expired. Go back, reload the page and try again.",
        ));
    }
    Ok(c)
}

async fn audit(app: &App, actor: &str, ip: &str, action: &str, detail: &str) {
    let (a, i, ac, d, t) = (
        actor.to_string(),
        ip.to_string(),
        action.to_string(),
        detail.to_string(),
        now(),
    );
    if let Err(e) = app.store.run(move |s| s.audit(t, &a, &i, &ac, &d)).await {
        eprintln!("[dashboard] audit write failed: {e}");
    }
}

/// Create a session and return the Set-Cookie header pair.
async fn new_session(
    app: &App,
    user: &str,
    stage: Stage,
    ip: &str,
    ua: String,
    replace: Option<String>,
) -> Result<(header::HeaderName, String), String> {
    let tok = auth::token()?;
    let key = auth::sha256_hex(tok.as_bytes());
    let t = now();
    let sess = Session {
        user: user.to_string(),
        stage,
        created: t,
        last_seen: t,
        csrf: auth::token()?,
        ip: ip.to_string(),
        ua,
        pending_totp: None,
    };
    app.store
        .run(move |s| {
            if let Some(old) = replace {
                s.delete_session(&old)?;
            }
            s.put_session(&key, &sess)
        })
        .await?;
    Ok(set_cookie(SESSION_COOKIE, &tok, ABSOLUTE))
}

async fn verify_pw(app: &App, pw: String, phc: Option<String>) -> Result<bool, String> {
    let _permit = app
        .hash_sem
        .acquire()
        .await
        .map_err(|_| "semaphore closed".to_string())?;
    let dummy = app.dummy_hash.clone();
    tokio::task::spawn_blocking(move || {
        let ok = auth::verify_password(&pw, phc.as_deref().unwrap_or(&dummy));
        ok && phc.is_some()
    })
    .await
    .map_err(|e| e.to_string())
}

async fn hash_pw(app: &App, pw: String) -> Result<String, String> {
    let _permit = app
        .hash_sem
        .acquire()
        .await
        .map_err(|_| "semaphore closed".to_string())?;
    tokio::task::spawn_blocking(move || auth::hash_password(&pw))
        .await
        .map_err(|e| e.to_string())?
}

fn providers(app: &App) -> Vec<&Provider> {
    [app.cfg.discord.as_ref(), app.cfg.github.as_ref()]
        .into_iter()
        .flatten()
        .collect()
}

fn provider(app: &App, name: &str) -> Option<Provider> {
    match Kind::parse(name)? {
        Kind::Discord => app.cfg.discord.clone(),
        Kind::Github => app.cfg.github.clone(),
    }
}

fn redirect_uri(app: &App, k: Kind) -> String {
    format!(
        "{}/oauth/{}/callback",
        app.cfg.public_url.trim_end_matches('/'),
        k.id()
    )
}

#[derive(serde::Deserialize)]
struct MsgQuery {
    ok: Option<String>,
    err: Option<String>,
}

fn flash_of(q: &MsgQuery) -> Flash<'_> {
    // Messages are fixed keys mapped to fixed text; never reflected raw.
    fn text(k: &str) -> &'static str {
        match k {
            "pw" => "Password changed.",
            "mfa" => "Two-factor authentication is set up.",
            "linked" => "Account linked.",
            "unlinked" => "Account unlinked.",
            "revoked" => "Session signed out.",
            "revoked_all" => "All other sessions were signed out.",
            "checkpoint" => "Checkpoint done: cached pages written, WAL emptied.",
            "slow" => "Too many checkpoints in a short time. Try again in a minute.",
            "recovery" => {
                "Signed in with a recovery code. That code is now used up; create new codes under Account if you are running low."
            }
            "created" => "User created.",
            "done" => "Done.",
            "loggedout" => "You have been signed out.",
            "expired" => "Your session expired. Please sign in again.",
            "oauth" => "That sign-in did not work. Please try again.",
            "nolink" => {
                "No NovaDB account is linked to that login. Sign in with your password, then link it under Account."
            }
            "taken" => "That login is already linked to another NovaDB user.",
            "notsetup" => "Finish setting up your account with your password first.",
            _ => "",
        }
    }
    match (&q.ok, &q.err) {
        (_, Some(e)) if !text(e).is_empty() => Flash::Err(text(e)),
        (Some(o), _) if !text(o).is_empty() => Flash::Ok(text(o)),
        _ => Flash::None,
    }
}

// ----- login ---------------------------------------------------------------------------------

async fn login_page(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Query(q): Query<MsgQuery>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    if let Some(c) = load(&app, &h, ip).await.map_err(internal)? {
        return Ok(redirect(match c.sess.stage {
            Stage::Full => "/",
            Stage::Mfa => "/login/totp",
            Stage::Setup => next_setup(&c.user),
        }));
    }
    Ok(Html(login_html(&app, flash_of(&q))).into_response())
}

fn login_html(app: &App, flash: Flash<'_>) -> String {
    let oauth: String = providers(app)
        .iter()
        .map(|p| {
            format!(
                r#"<a href="/oauth/{}/start">{}Continue with {}</a>"#,
                p.kind.id(),
                html::icon("link"),
                p.kind.label()
            )
        })
        .collect();
    let oauth = if oauth.is_empty() {
        String::new()
    } else {
        format!(
            r#"<div class="divider">or</div><div class="oauth">{oauth}</div><p class="hint">Works only for logins linked under Account. Your 2FA code is still required.</p>"#
        )
    };
    html::page(
        "Sign in",
        None,
        flash,
        &format!(
            r#"<h1>Sign in</h1><p class="sub">Welcome back. Sign in to the NovaDB control plane.</p>
<div class="card"><form method="post" action="/login">
<label for="u">Username</label><input id="u" type="text" name="username" autocomplete="username" required maxlength="32" autofocus>
<label for="p">Password</label><input id="p" type="password" name="password" autocomplete="current-password" required maxlength="128">
<button class="block">Sign in</button></form>{oauth}</div>"#
        ),
    )
}

async fn login_post(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    if !origin_ok(&app, &h) {
        return Err(err_page(
            StatusCode::FORBIDDEN,
            "Cross-site request blocked.",
        ));
    }
    let name = field(&f, "username").trim().to_lowercase();
    let pw = field(&f, "password").to_string();
    let fail = |m: &str| Html(login_html(&app, Flash::Err(m))).into_response();
    // Rate limits run before any hashing (PLAN.md §4.5).
    if !app
        .limiter
        .hit(&format!("login-ip:{ip}"), 10, Duration::from_secs(300))
        || !app
            .limiter
            .hit(&format!("login-user:{name}"), 20, Duration::from_secs(300))
    {
        audit(&app, &name, &ip, "login.rate_limited", "").await;
        return Ok((
            StatusCode::TOO_MANY_REQUESTS,
            fail("Too many attempts. Wait a few minutes and try again."),
        )
            .into_response());
    }
    if name.is_empty() || pw.is_empty() || pw.len() > 512 || !valid_username(&name) {
        return Ok(fail("Wrong username or password."));
    }
    let n2 = name.clone();
    let user = app
        .store
        .run(move |s| s.get_user(&n2))
        .await
        .map_err(internal)?;
    let t = now();
    let ok = verify_pw(&app, pw, user.as_ref().map(|u| u.pw.clone()))
        .await
        .map_err(internal)?;
    let Some(mut user) = user else {
        audit(&app, &name, &ip, "login.fail", "unknown user").await;
        return Ok(fail("Wrong username or password."));
    };
    if user.disabled || user.locked_until > t {
        audit(
            &app,
            &name,
            &ip,
            "login.blocked",
            if user.disabled { "disabled" } else { "locked" },
        )
        .await;
        return Ok(fail(
            "Wrong username or password, or the account is locked. Try again later.",
        ));
    }
    if !ok {
        user.failed += 1;
        let locked = user.failed >= MAX_FAILED;
        if locked {
            user.locked_until = t + LOCK_SECS;
            user.failed = 0;
        }
        let u2 = user.clone();
        app.store
            .run(move |s| s.put_user(&u2))
            .await
            .map_err(internal)?;
        audit(
            &app,
            &name,
            &ip,
            if locked { "login.locked" } else { "login.fail" },
            "bad password",
        )
        .await;
        return Ok(fail("Wrong username or password."));
    }
    user.failed = 0;
    let stage = if user.totp.is_some() {
        Stage::Mfa
    } else {
        Stage::Setup
    };
    let u2 = user.clone();
    app.store
        .run(move |s| s.put_user(&u2))
        .await
        .map_err(internal)?;
    let old = cookie(&h, SESSION_COOKIE).map(|t| auth::sha256_hex(t.as_bytes()));
    let c = new_session(&app, &name, stage, &ip, ua(&h), old)
        .await
        .map_err(internal)?;
    audit(&app, &name, &ip, "login.password_ok", "").await;
    let to = if stage == Stage::Mfa {
        "/login/totp"
    } else {
        next_setup(&user)
    };
    Ok(([c], redirect(to)).into_response())
}

async fn mfa_page(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    let Some(c) = load(&app, &h, ip).await.map_err(internal)? else {
        return Ok(redirect("/login"));
    };
    if c.sess.stage != Stage::Mfa {
        return Ok(redirect("/"));
    }
    Ok(Html(mfa_html(&c, Flash::None)).into_response())
}

fn mfa_html(c: &Ctx, flash: Flash<'_>) -> String {
    html::page(
        "Two-factor",
        None,
        flash,
        &format!(
            r#"<h1>Two-factor check</h1><p class="sub">Enter the 6-digit code from your authenticator app for <b>{}</b>.</p>
<div class="card"><form method="post" action="/login/totp">{}<label for="c">Authentication code</label>
<input id="c" class="code" type="text" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{{6,7}}" maxlength="7" placeholder="000000" required autofocus>
<button class="block">Verify</button></form>
<details class="alt"><summary>Lost your device? Use a recovery code</summary>
<form method="post" action="/login/recovery">{}<label for="r">Recovery code</label>
<input id="r" type="text" name="recovery" autocomplete="off" spellcheck="false" maxlength="24" placeholder="XXXX-XXXX-XXXX-XXXX" required>
<button class="ghost block">Use recovery code</button></form></details>
<form method="post" action="/logout">{}<button class="link">&larr; Use a different account</button></form></div>"#,
            esc(&c.user.name),
            csrf(&c.sess.csrf),
            csrf(&c.sess.csrf),
            csrf(&c.sess.csrf)
        ),
    )
}

async fn mfa_post(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    if !origin_ok(&app, &h) {
        return Err(err_page(
            StatusCode::FORBIDDEN,
            "Cross-site request blocked.",
        ));
    }
    let Some(c) = load(&app, &h, ip.clone()).await.map_err(internal)? else {
        return Ok(redirect("/login?err=expired"));
    };
    if c.sess.stage != Stage::Mfa || !csrf_ok(&c.sess, &f) {
        return Ok(redirect("/login"));
    }
    if !app
        .limiter
        .hit(&format!("mfa:{}", c.user.name), 6, Duration::from_secs(300))
    {
        // Too many wrong codes: kill the half-authenticated session.
        let k = c.key.clone();
        app.store
            .run(move |s| s.delete_session(&k))
            .await
            .map_err(internal)?;
        audit(&app, &c.user.name, &ip, "mfa.rate_limited", "").await;
        return Ok(redirect("/login?err=expired"));
    }
    let secret = c
        .user
        .totp
        .as_deref()
        .and_then(totp::base32_decode)
        .unwrap_or_default();
    let Some(step) = totp::verify(&secret, field(&f, "code"), now(), c.user.totp_last) else {
        audit(&app, &c.user.name, &ip, "mfa.fail", "").await;
        return Ok(Html(mfa_html(
            &c,
            Flash::Err("That code is not right (or was already used). Try the next one."),
        ))
        .into_response());
    };
    let mut user = c.user.clone();
    user.totp_last = step;
    user.last_login = now();
    let stage = if user.must_change {
        Stage::Setup
    } else {
        Stage::Full
    };
    let u2 = user.clone();
    app.store
        .run(move |s| s.put_user(&u2))
        .await
        .map_err(internal)?;
    // Rotate the session id at the privilege change.
    let ck = new_session(&app, &user.name, stage, &ip, ua(&h), Some(c.key))
        .await
        .map_err(internal)?;
    audit(&app, &user.name, &ip, "login.ok", "").await;
    Ok((
        [ck],
        redirect(if stage == Stage::Full {
            "/"
        } else {
            next_setup(&user)
        }),
    )
        .into_response())
}

async fn logout(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    if let Some(c) = load(&app, &h, ip.clone()).await.map_err(internal)?
        && csrf_ok(&c.sess, &f)
        && origin_ok(&app, &h)
    {
        let k = c.key.clone();
        app.store
            .run(move |s| s.delete_session(&k))
            .await
            .map_err(internal)?;
        audit(&app, &c.user.name, &ip, "logout", "").await;
    }
    Ok((
        [set_cookie(SESSION_COOKIE, "", 0)],
        redirect("/login?ok=loggedout"),
    )
        .into_response())
}

// ----- first-run / forced setup ----------------------------------------------------------

async fn setup_ctx(app: &App, h: &HeaderMap, ip: String) -> Result<Ctx, Response> {
    let Some(c) = load(app, h, ip).await.map_err(internal)? else {
        return Err(redirect("/login"));
    };
    if c.sess.stage == Stage::Mfa {
        return Err(redirect("/login/totp"));
    }
    Ok(c)
}

fn setpw_html(c: &Ctx, flash: Flash<'_>) -> String {
    html::page(
        "Choose a password",
        None,
        flash,
        &format!(
            r#"<div class="steps-auth" aria-label="Step 1 of 2"><i class="on"></i><i></i></div><h1>Choose a new password</h1><p class="sub">Step 1 of 2. At least 12 characters; a few random words works well.</p>
<div class="card"><form method="post" action="/setup/password">{}
<label for="a">New password</label><input id="a" type="password" name="new" autocomplete="new-password" required minlength="12" maxlength="128" autofocus>
<label for="b">Repeat it</label><input id="b" type="password" name="again" autocomplete="new-password" required minlength="12" maxlength="128">
<button class="block">Save and continue</button></form></div>"#,
            csrf(&c.sess.csrf)
        ),
    )
}

async fn setpw_page(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
) -> Res {
    let c = setup_ctx(&app, &h, client_ip(&app, &peer, &h)).await?;
    if !c.user.must_change {
        return Ok(redirect(next_setup(&c.user)));
    }
    Ok(Html(setpw_html(&c, Flash::None)).into_response())
}

/// Validates + stores a new password. Returns a user-facing error.
async fn change_password(
    app: &App,
    user: &User,
    new: &str,
    again: &str,
) -> Result<Option<&'static str>, String> {
    if new != again {
        return Ok(Some("The two passwords do not match."));
    }
    if let Some(p) = auth::password_problem(new, &user.name) {
        return Ok(Some(p));
    }
    if verify_pw(app, new.to_string(), Some(user.pw.clone())).await? {
        return Ok(Some("Pick a password you have not used here before."));
    }
    let phc = hash_pw(app, new.to_string()).await?;
    let mut u = user.clone();
    u.pw = phc;
    u.must_change = false;
    let initial = app.cfg.data_dir.join(crate::INITIAL_PW_FILE);
    app.store.run(move |s| s.put_user(&u)).await?;
    // The one-time admin password file is no longer valid once any password was set.
    if initial.exists() {
        let _ = std::fs::remove_file(initial);
    }
    Ok(None)
}

async fn setpw_post(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    if !origin_ok(&app, &h) {
        return Err(err_page(
            StatusCode::FORBIDDEN,
            "Cross-site request blocked.",
        ));
    }
    let c = setup_ctx(&app, &h, ip.clone()).await?;
    if !csrf_ok(&c.sess, &f) || !c.user.must_change {
        return Ok(redirect(next_setup(&c.user)));
    }
    if let Some(msg) = change_password(&app, &c.user, field(&f, "new"), field(&f, "again"))
        .await
        .map_err(internal)?
    {
        return Ok(Html(setpw_html(&c, Flash::Err(msg))).into_response());
    }
    audit(&app, &c.user.name, &ip, "password.changed", "forced change").await;
    let mut u = c.user.clone();
    u.must_change = false;
    let stage = if u.totp.is_some() {
        Stage::Full
    } else {
        Stage::Setup
    };
    let ck = new_session(&app, &u.name, stage, &ip, ua(&h), Some(c.key))
        .await
        .map_err(internal)?;
    Ok((
        [ck],
        redirect(if stage == Stage::Full {
            "/?ok=pw"
        } else {
            "/setup/totp"
        }),
    )
        .into_response())
}

fn qr_svg(data: &str) -> String {
    match qrcode::QrCode::new(data.as_bytes()) {
        Ok(q) => q
            .render::<qrcode::render::svg::Color<'_>>()
            .min_dimensions(200, 200)
            .quiet_zone(false)
            .build(),
        Err(_) => String::new(),
    }
}

async fn enrol_page(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
) -> Res {
    let c = setup_ctx(&app, &h, client_ip(&app, &peer, &h)).await?;
    if c.user.must_change {
        return Ok(redirect("/setup/password"));
    }
    if c.user.totp.is_some() {
        return Ok(redirect("/"));
    }
    let mut sess = c.sess.clone();
    let secret = match &sess.pending_totp {
        Some(s) => s.clone(),
        None => {
            let s = totp::base32_encode(&auth::random_bytes::<20>().map_err(internal)?);
            sess.pending_totp = Some(s.clone());
            let (k, s2) = (c.key.clone(), sess.clone());
            app.store
                .run(move |st| st.put_session(&k, &s2))
                .await
                .map_err(internal)?;
            s
        }
    };
    Ok(Html(enrol_html(&c, &secret, Flash::None)).into_response())
}

fn enrol_html(c: &Ctx, secret: &str, flash: Flash<'_>) -> String {
    let uri = totp::otpauth_uri("NovaDB", &c.user.name, secret);
    let grouped: Vec<String> = secret
        .as_bytes()
        .chunks(4)
        .map(|ch| String::from_utf8_lossy(ch).into_owned())
        .collect();
    html::page(
        "Set up two-factor",
        None,
        flash,
        &format!(
            r#"<div class="steps-auth" aria-label="Step 2 of 2"><i class="on"></i><i class="on"></i></div><h1>Set up two-factor sign-in</h1><p class="sub">Step 2 of 2. Scan with an authenticator app (1Password, Bitwarden, Authy, Google Authenticator).</p>
<div class="card"><div class="qrwrap"><div class="qr">{}</div></div><label>Or enter this key manually</label><div class="secret">{}</div>
<form method="post" action="/setup/totp">{}<label for="c">6-digit code from the app</label>
<input id="c" class="code" type="text" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="7" placeholder="000000" required autofocus><button class="block">Turn on 2FA</button></form></div>"#,
            qr_svg(&uri),
            esc(&grouped.join(" ")),
            csrf(&c.sess.csrf)
        ),
    )
}

async fn enrol_post(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    if !origin_ok(&app, &h) {
        return Err(err_page(
            StatusCode::FORBIDDEN,
            "Cross-site request blocked.",
        ));
    }
    let c = setup_ctx(&app, &h, ip.clone()).await?;
    if !csrf_ok(&c.sess, &f) || c.user.totp.is_some() || c.user.must_change {
        return Ok(redirect(next_setup(&c.user)));
    }
    let Some(secret_b32) = c.sess.pending_totp.clone() else {
        return Ok(redirect("/setup/totp"));
    };
    if !app.limiter.hit(
        &format!("enrol:{}", c.user.name),
        10,
        Duration::from_secs(300),
    ) {
        return Ok(Html(enrol_html(
            &c,
            &secret_b32,
            Flash::Err("Too many tries. Wait a few minutes."),
        ))
        .into_response());
    }
    let secret = totp::base32_decode(&secret_b32).unwrap_or_default();
    let Some(step) = totp::verify(&secret, field(&f, "code"), now(), 0) else {
        return Ok(Html(enrol_html(
            &c,
            &secret_b32,
            Flash::Err("That code is not right. Check the time on your phone and try again."),
        ))
        .into_response());
    };
    let mut u = c.user.clone();
    u.totp = Some(secret_b32);
    u.totp_last = step;
    u.last_login = now();
    let u2 = u.clone();
    app.store
        .run(move |s| s.put_user(&u2))
        .await
        .map_err(internal)?;
    audit(&app, &u.name, &ip, "mfa.enrolled", "totp").await;
    let ck = new_session(&app, &u.name, Stage::Full, &ip, ua(&h), Some(c.key))
        .await
        .map_err(internal)?;
    Ok(([ck], redirect("/?ok=mfa")).into_response())
}

// ----- overview ------------------------------------------------------------------------------

async fn overview(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Query(q): Query<MsgQuery>,
) -> Res {
    let c = guard(&app, &h, client_ip(&app, &peer, &h), Role::Viewer).await?;
    let (stats, verify, user_list, sessions, chain, recent) = app
        .store
        .run(|s| {
            let st = s.stats();
            let v = s.verify_db();
            let users = s.list_users()?;
            let sessions = s.session_count()?;
            let chain = s.audit_verify();
            let recent = s.audit_recent(8)?;
            Ok((st, v, users, sessions, chain, recent))
        })
        .await
        .map_err(internal)?;
    let t = now();
    let users = user_list.len();
    // Things worth a human look, most urgent first.
    let mut warn: Vec<(String, &str)> = Vec::new();
    if c.user.recovery.is_empty() {
        warn.push((
            "You have no recovery codes. If you lose your phone you cannot sign in.".into(),
            r#"<a class="btn ghost sm" href="/account">Create codes</a>"#,
        ));
    }
    if c.user.role >= Role::Admin {
        let locked = user_list.iter().filter(|u| u.locked_until > t).count();
        if locked > 0 {
            warn.push((
                format!("{locked} account(s) locked after too many wrong passwords."),
                r#"<a class="btn ghost sm" href="/users">Review</a>"#,
            ));
        }
        let pending = user_list
            .iter()
            .filter(|u| !u.disabled && u.totp.is_none())
            .count();
        if pending > 0 {
            warn.push((
                format!("{pending} user(s) have not finished setting up 2FA yet."),
                r#"<a class="btn ghost sm" href="/users">Review</a>"#,
            ));
        }
    }
    let fails = recent
        .iter()
        .filter(|e| html::event_class(&e.action) == "bad")
        .count();
    if fails >= 3 && c.user.role >= Role::Operator {
        warn.push((
            format!("{fails} failed or blocked sign-ins among the latest events."),
            r#"<a class="btn ghost sm" href="/audit?cat=login">Look</a>"#,
        ));
    }
    let warn_html: String = warn
        .iter()
        .map(|(m, a)| {
            format!(
                r#"<div class="notice">{}<span>{}</span>{a}</div>"#,
                html::icon("alert"),
                esc(m)
            )
        })
        .collect();
    let feed_link = if c.user.role >= Role::Operator {
        r#"<a class="r hint" href="/audit">View all &rarr;</a>"#
    } else {
        r#"<span class="r hint">latest events</span>"#
    };
    let (vpill, vtext) = match &verify {
        Ok(r) => (
            "ok",
            format!(
                "{} trees, {} entries, {} used / {} free pages",
                r.trees, r.entries, r.used_pages, r.free_pages
            ),
        ),
        Err(e) => ("bad", e.clone()),
    };
    let (cpill, ctext) = match &chain {
        Ok(n) => ("ok", format!("intact ({n} entries)")),
        Err(e) => ("bad", format!("BROKEN: {e}")),
    };
    let stages = [
        (
            "1",
            "Skeleton: workspace, CI, lint + supply-chain gates",
            "done",
        ),
        (
            "2",
            "Storage: pager, buffer pool, B+Tree, WAL, crash recovery",
            "done",
        ),
        (
            "3",
            "SQL single-node: tables, indexes, planner, CLI shell",
            "done",
        ),
        ("4", "MySQL wire protocol over TLS (127.0.0.1:3307)", "done"),
        ("5", "Transactions: MVCC, snapshot isolation", "done"),
        ("6", "Joins, aggregates, planner", "planned"),
        ("7", "Ops: backups, PITR, metrics", "planned"),
        ("8", "Replication / Raft cluster", "planned"),
        (
            "9",
            "Control dashboard + identity (this page)",
            "in progress",
        ),
        ("10", "REST / WebSocket + SDKs", "planned"),
    ];
    let done = stages.iter().filter(|(_, _, st)| *st == "done").count();
    let pct = (done * 100 / stages.len()).div_ceil(10) * 10;
    let stage_rows: String = stages
        .iter()
        .map(|(n, d, st)| {
            let (cls, badge, num) = match *st {
                "done" => ("done", r#"<span class="badge ok">Done</span>"#.to_string(), html::icon("check")),
                "in progress" => ("now", r#"<span class="badge warn">In progress</span>"#.to_string(), (*n).to_string()),
                _ => ("planned", r#"<span class="badge">Planned</span>"#.to_string(), (*n).to_string()),
            };
            format!(
                r#"<li class="{cls}"><span class="n" title="Stage {n}">{num}</span><span class="d">{d}</span>{badge}</li>"#
            )
        })
        .collect();
    let healthy = vpill == "ok" && cpill == "ok";
    let status_badge = if healthy {
        r#"<span class="badge ok"><span class="pulse"></span>All systems healthy</span>"#
    } else {
        r#"<span class="badge bad"><span class="pulse"></span>Attention needed</span>"#
    };
    let check_row = |ok: bool, title: &str, detail: &str| {
        format!(
            r#"<li><span class="st {}">{}</span><span class="t"><b>{title}</b><span>{}</span></span><span class="v">{}</span></li>"#,
            if ok { "ok" } else { "bad" },
            html::icon(if ok { "check" } else { "x" }),
            esc(detail),
            if ok {
                r#"<span class="pill ok">Passing</span>"#
            } else {
                r#"<span class="pill bad">Failing</span>"#
            }
        )
    };
    let kpi = |ic: &str, label: &str, value: String, note: &str| {
        format!(
            r#"<div class="kpi"><div class="kpi-h"><span>{label}</span><span class="ic">{}</span></div><b>{value}</b><small>{note}</small></div>"#,
            html::icon(ic)
        )
    };
    let body = format!(
        r#"{head}{warn_html}
<div class="kpis">{k1}{k2}{k3}{k4}{k5}</div>
<div class="cols cols-32"><div class="card"><div class="card-h">{iact}<h2>System health</h2><span class="r hint">2 checks</span></div>
<ul class="checks">{c1}{c2}</ul>
<div class="metrics"><div><span>Pages read / written</span><b>{pr} / {pw}</b></div><div><span>Checkpoints</span><b>{cp}</b></div><div><span>Buffer pool</span><b>{bp} pages</b> <small class="hint">{bpb}</small></div></div>
<div class="card-f">The dashboard keeps its own users, sessions and audit log in NovaDB's storage engine.</div></div>
<div class="card"><div class="card-h">{iflag}<h2>Engine roadmap</h2><span class="r hint">{done} of {total} stages</span></div>
<div class="card-b"><div class="progress" role="progressbar" aria-valuenow="{done}" aria-valuemin="0" aria-valuemax="{total}"><i class="p{pct}"></i></div></div>
<ol class="steps">{stage_rows}</ol>
<div class="card-f">SQL works through the <code>novadb</code> shell and any MySQL client over TLS on 127.0.0.1:3307. Database screens here come next.</div></div></div>
<div class="card"><div class="card-h">{iact}<h2>Recent activity</h2>{feed_link}</div>{feed}</div>"#,
        head = html::header(
            "Overview",
            &format!(
                "Signed in as <b>{}</b> · last sign-in {}",
                esc(&c.user.name),
                html::ago(t, c.user.last_login)
            ),
            status_badge
        ),
        k1 = kpi(
            "clock",
            "Uptime",
            html::ago(t, app.started).replace(" ago", ""),
            "dashboard process"
        ),
        k2 = kpi("users", "Users", users.to_string(), "accounts with access"),
        k3 = kpi(
            "monitor",
            "Active sessions",
            sessions.to_string(),
            "signed-in devices"
        ),
        k4 = kpi(
            "drive",
            "System DB",
            html::bytes(stats.page_count * novadb_storage::page::PAGE_SIZE as u64),
            "on-disk size"
        ),
        k5 = kpi(
            "file",
            "WAL",
            html::bytes(stats.wal_bytes),
            "write-ahead log"
        ),
        iact = html::icon("activity"),
        iflag = html::icon("flag"),
        feed = more::activity_list(&recent, t, true),
        c1 = check_row(vpill == "ok", "Integrity (full verify)", &vtext),
        c2 = check_row(cpill == "ok", "Audit hash chain", &ctext),
        pr = stats.page_reads,
        pw = stats.page_writes,
        cp = stats.checkpoints,
        bp = stats.cache_pages,
        bpb = html::bytes(stats.cache_pages as u64 * novadb_storage::page::PAGE_SIZE as u64),
        total = stages.len(),
    );
    Ok(Html(html::page(
        "Overview",
        Some(&c.nav("/")),
        flash_of(&q),
        &body,
    ))
    .into_response())
}

// ----- account ---------------------------------------------------------------------------

async fn account_page(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Query(q): Query<MsgQuery>,
) -> Res {
    let c = guard(&app, &h, client_ip(&app, &peer, &h), Role::Viewer).await?;
    account_render(&app, &c, flash_of(&q)).await
}

async fn account_render(app: &App, c: &Ctx, flash: Flash<'_>) -> Res {
    account_render_full(app, c, flash, None).await
}

/// Account page; `codes` = freshly generated recovery codes to show exactly once.
async fn account_render_full(
    app: &App,
    c: &Ctx,
    flash: Flash<'_>,
    codes: Option<&[String]>,
) -> Res {
    let name = c.user.name.clone();
    let (sessions, mine) = app
        .store
        .run(move |s| {
            let sess = s.sessions_for(&name)?;
            let mine: Vec<_> = s
                .audit_all()?
                .into_iter()
                .filter(|e| e.actor == name)
                .take(12)
                .collect();
            Ok((sess, mine))
        })
        .await
        .map_err(internal)?;
    let t = now();
    let srows: String = sessions
        .iter()
        .map(|(k, s)| {
            let me = *k == c.key;
            let action = if me {
                r#"<span class="badge acc">This device</span>"#.to_string()
            } else {
                format!(
                    r#"<form method="post" action="/account/sessions/revoke">{}<input type="hidden" name="id" value="{}"><button class="ghost sm">Sign out</button></form>"#,
                    csrf(&c.sess.csrf),
                    esc(&k[..12.min(k.len())])
                )
            };
            format!(
                "<tr><td class=mono>{}</td><td>{}</td><td class=nw>{}</td><td class=nw>{}</td><td class=r>{action}</td></tr>",
                esc(&s.ip),
                esc(&clip(&s.ua, 60)),
                html::ago(t, s.created),
                html::ago(t, s.last_seen)
            )
        })
        .collect();
    let mut lrows = String::new();
    for p in providers(app) {
        let linked = c.user.links.iter().find(|l| l.provider == p.kind.id());
        let cell = match linked {
            Some(l) => format!(
                r#"<td><span class="pill ok">Linked</span> {} <span class="hint">id {}</span></td><td class="r"><form method="post" action="/account/unlink">{}<input type="hidden" name="provider" value="{}"><button class="ghost sm">Unlink</button></form></td>"#,
                esc(&l.name),
                esc(&l.id),
                csrf(&c.sess.csrf),
                p.kind.id()
            ),
            None => format!(
                r#"<td><span class="pill plain">Not linked</span></td><td class="r"><form method="post" action="/oauth/{}/link">{}<button class="ghost sm">Link {}</button></form></td>"#,
                p.kind.id(),
                csrf(&c.sess.csrf),
                p.kind.label()
            ),
        };
        lrows.push_str(&format!(
            "<tr><td><b>{}</b></td>{cell}</tr>",
            p.kind.label()
        ));
    }
    let links = if lrows.is_empty() {
        r#"<div class="empty">Discord / GitHub sign-in is not configured on this server yet.</div>"#
            .to_string()
    } else {
        format!(
            r#"<div class="tbl"><table><tbody>{lrows}</tbody></table></div><div class="card-f">Linked logins let you skip the password, never the 2FA code.</div>"#
        )
    };
    let body = format!(
        r#"{head}
{reveal}<div class="cols"><div class="card"><div class="card-h">{ikey}<h2>Change password</h2></div><div class="card-b"><form method="post" action="/account/password">{}
<label>Current password</label><input type="password" name="current" autocomplete="current-password" required maxlength="128">
<label>New password</label><input type="password" name="new" autocomplete="new-password" required minlength="12" maxlength="128">
<label>Repeat new password</label><input type="password" name="again" autocomplete="new-password" required minlength="12" maxlength="128">
<button>Update password</button></form></div><div class="card-f">Changing it signs out your other devices.</div></div>
<div class="card"><div class="card-h">{iphone}<h2>Two-factor authentication</h2><span class="r badge ok">{icheck}Enabled</span></div><div class="card-b"><p class="sub">TOTP is required for every account. To move it to a new phone, confirm with your password and a current code.</p>
<form method="post" action="/account/totp/reset">{}<label>Current password</label><input type="password" name="current" required maxlength="128">
<label>Current 6-digit code</label><input type="text" name="code" inputmode="numeric" required maxlength="7" placeholder="000000">
<button class="ghost">Move 2FA to a new device</button></form></div></div></div>
<div class="card"><div class="card-h">{ilb}<h2>Recovery codes</h2><span class="r">{rc_badge}</span></div><div class="card-b"><p class="sub">Single-use codes that replace the 2FA code if you lose your phone. Creating new codes cancels the old ones.</p>
<form method="post" action="/account/recovery" class="addform three">{csrf_r}<div><label>Current password</label><input type="password" name="current" autocomplete="current-password" required maxlength="128"></div>
<div><label>Current 6-digit code</label><input type="text" name="code" inputmode="numeric" required maxlength="7" placeholder="000000"></div>
<button class="ghost">{rc_btn}</button></form></div></div>
<div class="card"><div class="card-h">{ilink}<h2>Linked logins</h2></div>{links}</div>
<div class="card"><div class="card-h">{imon}<h2>Active sessions</h2><span class="r hint">{nsess} signed in</span></div><div class="tbl"><table><thead><tr><th>IP</th><th>Device</th><th>Started</th><th>Last seen</th><th></th></tr></thead><tbody>{srows}</tbody></table></div>
<div class="card-f between"><span>Don't recognise a device? Sign it out and change your password.</span><form method="post" action="/account/sessions/revoke_all">{csrf_r}<button class="danger sm"{others_dis}>Sign out all other devices</button></form></div></div>
<div class="card"><div class="card-h">{iact}<h2>Your recent security activity</h2><span class="r hint">from the audit log</span></div>{activity}</div>"#,
        csrf(&c.sess.csrf),
        csrf(&c.sess.csrf),
        head = html::header(
            "Account",
            &format!(
                "{} · <span class=\"role\">{}</span>",
                esc(&c.user.name),
                c.user.role.name()
            ),
            ""
        ),
        ikey = html::icon("key"),
        iphone = html::icon("phone"),
        icheck = html::icon("check"),
        ilink = html::icon("link"),
        imon = html::icon("monitor"),
        nsess = sessions.len(),
        ilb = html::icon("life-buoy"),
        iact = html::icon("activity"),
        csrf_r = csrf(&c.sess.csrf),
        others_dis = if sessions.len() <= 1 { " disabled" } else { "" },
        activity = more::activity_list(&mine, now(), false),
        rc_badge = match c.user.recovery.len() {
            0 => r#"<span class="badge warn">None yet</span>"#.to_string(),
            1..=3 => format!(
                r#"<span class="badge warn">{} left</span>"#,
                c.user.recovery.len()
            ),
            n => format!(
                r#"<span class="badge ok">{n} of {} left</span>"#,
                auth::RECOVERY_CODES
            ),
        },
        rc_btn = if c.user.recovery.is_empty() {
            "Create recovery codes"
        } else {
            "Create new codes"
        },
        reveal = match codes {
            None => String::new(),
            Some(list) => format!(
                r#"<div class="card reveal"><div class="card-h">{}<h2>Save your recovery codes now</h2></div><div class="card-b"><p class="sub">They are shown only this once. Store them in your password manager or print them. Each code works one time.</p><ol class="codes">{}</ol></div></div>"#,
                html::icon("key"),
                list.iter()
                    .map(|x| format!("<li><code>{}</code></li>", esc(x)))
                    .collect::<String>()
            ),
        },
    );
    Ok(Html(html::page(
        "Account",
        Some(&c.nav("/account")),
        flash,
        &body,
    ))
    .into_response())
}

async fn account_password(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    let c = guard_post(&app, &h, ip.clone(), Role::Viewer, &f).await?;
    if !app.limiter.hit(
        &format!("pwchange:{}", c.user.name),
        10,
        Duration::from_secs(900),
    ) {
        return account_render(&app, &c, Flash::Err("Too many tries. Wait a while.")).await;
    }
    if !verify_pw(
        &app,
        field(&f, "current").to_string(),
        Some(c.user.pw.clone()),
    )
    .await
    .map_err(internal)?
    {
        audit(
            &app,
            &c.user.name,
            &ip,
            "password.change_fail",
            "wrong current",
        )
        .await;
        return account_render(&app, &c, Flash::Err("Current password is wrong.")).await;
    }
    if let Some(msg) = change_password(&app, &c.user, field(&f, "new"), field(&f, "again"))
        .await
        .map_err(internal)?
    {
        return account_render(&app, &c, Flash::Err(msg)).await;
    }
    let (n, k) = (c.user.name.clone(), c.key.clone());
    let revoked = app
        .store
        .run(move |s| s.delete_sessions_for(&n, Some(&k)))
        .await
        .map_err(internal)?;
    audit(
        &app,
        &c.user.name,
        &ip,
        "password.changed",
        &format!("revoked {revoked} other sessions"),
    )
    .await;
    Ok(redirect("/account?ok=pw"))
}

async fn account_totp_reset(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    let c = guard_post(&app, &h, ip.clone(), Role::Viewer, &f).await?;
    if !app
        .limiter
        .hit(&format!("mfa:{}", c.user.name), 6, Duration::from_secs(300))
    {
        return account_render(&app, &c, Flash::Err("Too many tries. Wait a few minutes.")).await;
    }
    let pw_ok = verify_pw(
        &app,
        field(&f, "current").to_string(),
        Some(c.user.pw.clone()),
    )
    .await
    .map_err(internal)?;
    let secret = c
        .user
        .totp
        .as_deref()
        .and_then(totp::base32_decode)
        .unwrap_or_default();
    let step = totp::verify(&secret, field(&f, "code"), now(), c.user.totp_last);
    let (true, Some(_)) = (pw_ok, step) else {
        audit(&app, &c.user.name, &ip, "mfa.reset_fail", "").await;
        return account_render(&app, &c, Flash::Err("Password or code is wrong.")).await;
    };
    let mut u = c.user.clone();
    u.totp = None;
    u.totp_last = 0;
    let (k, mut sess) = (c.key.clone(), c.sess.clone());
    sess.stage = Stage::Setup;
    sess.pending_totp = None;
    app.store
        .run(move |s| {
            s.put_user(&u)?;
            s.delete_sessions_for(&u.name, Some(&k))?;
            s.put_session(&k, &sess)
        })
        .await
        .map_err(internal)?;
    audit(&app, &c.user.name, &ip, "mfa.reset", "self").await;
    Ok(redirect("/setup/totp"))
}

async fn account_revoke(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    let c = guard_post(&app, &h, ip.clone(), Role::Viewer, &f).await?;
    let id = field(&f, "id").to_string();
    if id.len() != 12 {
        return Ok(redirect("/account"));
    }
    let (n, me) = (c.user.name.clone(), c.key.clone());
    let done = app
        .store
        .run(move |s| {
            for (k, _) in s.sessions_for(&n)? {
                if k.starts_with(&id) && k != me {
                    s.delete_session(&k)?;
                    return Ok(true);
                }
            }
            Ok(false)
        })
        .await
        .map_err(internal)?;
    if done {
        audit(&app, &c.user.name, &ip, "session.revoked", "").await;
    }
    Ok(redirect("/account?ok=revoked"))
}

async fn account_unlink(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    let c = guard_post(&app, &h, ip.clone(), Role::Viewer, &f).await?;
    let prov = field(&f, "provider").to_string();
    let mut u = c.user.clone();
    let Some(pos) = u.links.iter().position(|l| l.provider == prov) else {
        return Ok(redirect("/account"));
    };
    let l = u.links.remove(pos);
    let lid = l.id.clone();
    app.store
        .run(move |s| {
            s.unlink(&l.provider, &l.id)?;
            s.put_user(&u)
        })
        .await
        .map_err(internal)?;
    audit(
        &app,
        &c.user.name,
        &ip,
        "oauth.unlinked",
        &format!("{prov}:{lid}"),
    )
    .await;
    Ok(redirect("/account?ok=unlinked"))
}

// ----- users (admin) ---------------------------------------------------------------------

async fn users_page(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Query(q): Query<MsgQuery>,
) -> Res {
    let c = guard(&app, &h, client_ip(&app, &peer, &h), Role::Admin).await?;
    users_render(&app, &c, flash_of(&q), None).await
}

async fn users_render(app: &App, c: &Ctx, flash: Flash<'_>, reveal: Option<(&str, &str)>) -> Res {
    let users = app.store.run(|s| s.list_users()).await.map_err(internal)?;
    let t = now();
    let rows: String = users
        .iter()
        .map(|u| {
            let mut status = Vec::new();
            if u.disabled {
                status.push(r#"<span class="pill bad">Disabled</span>"#.to_string());
            }
            if u.locked_until > t {
                status.push(r#"<span class="pill warn">Locked</span>"#.to_string());
            }
            if u.must_change {
                status.push(r#"<span class="pill warn">Must change password</span>"#.to_string());
            }
            status.push(if u.totp.is_some() {
                r#"<span class="pill ok">2FA on</span>"#.to_string()
            } else {
                r#"<span class="pill warn">2FA pending</span>"#.to_string()
            });
            for l in &u.links {
                status.push(format!(r#"<span class="pill plain">{}</span>"#, esc(&l.provider)));
            }
            let me = u.name == c.user.name;
            let btn = |action: &str, label: &str, cls: &str| {
                format!(
                    r#"<form method="post" action="/users/action">{}<input type="hidden" name="user" value="{}"><input type="hidden" name="action" value="{action}"><button class="{cls}">{label}</button></form>"#,
                    csrf(&c.sess.csrf),
                    esc(&u.name)
                )
            };
            let actions = if me {
                r#"<a class="hint" href="/account">You · manage in Account</a>"#.to_string()
            } else {
                let mut a = vec![
                    if u.disabled { btn("enable", "Enable", "") } else { btn("disable", "Disable", "") },
                    btn("reset_pw", "Reset password", ""),
                    btn("reset_mfa", "Reset 2FA", ""),
                ];
                if u.locked_until > t {
                    a.push(btn("unlock", "Unlock", ""));
                }
                a.push(r#"<hr><div class="lbl">Change role</div>"#.to_string());
                for r in [Role::Viewer, Role::Operator, Role::Admin] {
                    if r != u.role {
                        a.push(btn(&format!("role_{}", r.name()), &format!("Make {}", r.name()), ""));
                    }
                }
                a.push("<hr>".to_string());
                a.push(btn("delete", "Delete user", "danger"));
                format!(
                    r#"<details class="menu"><summary title="Manage {}" aria-label="Manage {}">{}</summary><div class="pop">{}</div></details>"#,
                    esc(&u.name),
                    esc(&u.name),
                    html::icon("more"),
                    a.concat()
                )
            };
            format!(
                "<tr><td><span class=ucell>{}<b>{}</b></span></td><td><span class=\"role {}\">{}</span></td><td>{}</td><td class=nw>{}</td><td class=r>{actions}</td></tr>",
                html::avatar(&u.name),
                esc(&u.name),
                u.role.name(),
                u.role.name(),
                status.concat(),
                html::ago(t, u.last_login)
            )
        })
        .collect();
    let reveal_html = match reveal {
        Some((who, pw)) => format!(
            r#"<div class="card reveal"><div class="card-h">{}<h2>One-time password for {}</h2></div><div class="card-b"><p class="sub">Send it over a private channel. It is shown only once; they must change it at first sign-in.</p><div class="secret">{}</div></div></div>"#,
            html::icon("key"),
            esc(who),
            esc(pw)
        ),
        None => String::new(),
    };
    let body = format!(
        r#"{head}{reveal_html}
<div class="card"><div class="card-h">{iusers}<h2>Members</h2><span class="r hint">{n} accounts</span></div><div class="tbl"><table><thead><tr><th>User</th><th>Role</th><th>Status</th><th>Last sign-in</th><th class="r">Actions</th></tr></thead><tbody>{rows}</tbody></table></div></div>
<div class="card"><div class="card-h">{iadd}<h2>Invite a user</h2></div><div class="card-b"><form method="post" action="/users/create" class="addform">{}
<div><label for="nu">Username</label><input id="nu" type="text" name="username" placeholder="a-z 0-9 . _ -" required maxlength="32"></div>
<div><label for="nr">Role</label><select id="nr" name="role"><option value="viewer">Viewer</option><option value="operator">Operator</option><option value="admin">Admin</option></select></div>
<button>{iadd}Create user</button></form></div><div class="card-f"><b>Viewer</b>: overview · <b>Operator</b>: + audit log · <b>Admin</b>: + user management</div></div>"#,
        csrf(&c.sess.csrf),
        head = html::header(
            "Users",
            "Every account needs a password and TOTP. New users get a one-time password.",
            ""
        ),
        iusers = html::icon("users"),
        iadd = html::icon("user-plus"),
        n = users.len(),
    );
    Ok(Html(html::page("Users", Some(&c.nav("/users")), flash, &body)).into_response())
}

async fn users_create(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    let c = guard_post(&app, &h, ip.clone(), Role::Admin, &f).await?;
    let name = field(&f, "username").trim().to_lowercase();
    let Some(role) = Role::parse(field(&f, "role")) else {
        return users_render(&app, &c, Flash::Err("Pick a role."), None).await;
    };
    if !valid_username(&name) {
        return users_render(
            &app,
            &c,
            Flash::Err("Username: 3-32 characters, a-z 0-9 . _ -"),
            None,
        )
        .await;
    }
    let pw = auth::random_password(20).map_err(internal)?;
    let phc = hash_pw(&app, pw.clone()).await.map_err(internal)?;
    let n2 = name.clone();
    let created = app
        .store
        .run(move |s| {
            if s.get_user(&n2)?.is_some() {
                return Ok(false);
            }
            s.put_user(&User {
                name: n2,
                role,
                pw: phc,
                must_change: true,
                totp: None,
                totp_last: 0,
                disabled: false,
                failed: 0,
                locked_until: 0,
                created: now(),
                last_login: 0,
                links: vec![],
                recovery: vec![],
            })?;
            Ok(true)
        })
        .await
        .map_err(internal)?;
    if !created {
        return users_render(&app, &c, Flash::Err("That username already exists."), None).await;
    }
    audit(
        &app,
        &c.user.name,
        &ip,
        "user.created",
        &format!("{name} as {}", role.name()),
    )
    .await;
    users_render(&app, &c, Flash::Ok("User created."), Some((&name, &pw))).await
}

async fn users_action(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    let c = guard_post(&app, &h, ip.clone(), Role::Admin, &f).await?;
    let target = field(&f, "user").to_string();
    let action = field(&f, "action").to_string();
    if target == c.user.name {
        return users_render(
            &app,
            &c,
            Flash::Err("Use the Account page for your own account."),
            None,
        )
        .await;
    }
    let new_pw = if action == "reset_pw" {
        let pw = auth::random_password(20).map_err(internal)?;
        Some((pw.clone(), hash_pw(&app, pw).await.map_err(internal)?))
    } else {
        None
    };
    let (t2, a2, phc) = (
        target.clone(),
        action.clone(),
        new_pw.as_ref().map(|p| p.1.clone()),
    );
    let outcome: Result<&'static str, &'static str> = app
        .store
        .run(move |s| {
            let Some(mut u) = s.get_user(&t2)? else {
                return Ok(Err("No such user."));
            };
            let admins = s
                .list_users()?
                .iter()
                .filter(|x| x.role == Role::Admin && !x.disabled)
                .count();
            let losing_admin = u.role == Role::Admin && !u.disabled;
            match a2.as_str() {
                "disable" | "delete" | "role_viewer" | "role_operator"
                    if losing_admin && admins <= 1 =>
                {
                    return Ok(Err("There must always be at least one active admin."));
                }
                _ => {}
            }
            match a2.as_str() {
                "disable" => {
                    u.disabled = true;
                    s.delete_sessions_for(&u.name, None)?;
                }
                "enable" => u.disabled = false,
                "unlock" => {
                    u.locked_until = 0;
                    u.failed = 0;
                }
                "reset_pw" => {
                    let Some(p) = phc else {
                        return Ok(Err("internal"));
                    };
                    u.pw = p;
                    u.must_change = true;
                    s.delete_sessions_for(&u.name, None)?;
                }
                "reset_mfa" => {
                    u.totp = None;
                    u.totp_last = 0;
                    u.recovery.clear();
                    s.delete_sessions_for(&u.name, None)?;
                }
                "role_viewer" | "role_operator" | "role_admin" => {
                    let Some(r) = Role::parse(a2.trim_start_matches("role_")) else {
                        return Ok(Err("Unknown role."));
                    };
                    u.role = r;
                }
                "delete" => {
                    s.delete_user(&u.name)?;
                    return Ok(Ok("deleted"));
                }
                _ => return Ok(Err("Unknown action.")),
            }
            s.put_user(&u)?;
            Ok(Ok("done"))
        })
        .await
        .map_err(internal)?;
    match outcome {
        Err(m) => users_render(&app, &c, Flash::Err(m), None).await,
        Ok(_) => {
            audit(&app, &c.user.name, &ip, &format!("user.{action}"), &target).await;
            match new_pw {
                Some((pw, _)) => {
                    users_render(&app, &c, Flash::Ok("Password reset."), Some((&target, &pw))).await
                }
                None => Ok(redirect("/users?ok=done")),
            }
        }
    }
}

// ----- audit -----------------------------------------------------------------------------

// ----- OAuth -----------------------------------------------------------------------------

async fn oauth_start_login(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Path(name): Path<String>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    let Some(p) = provider(&app, &name) else {
        return Err(err_page(
            StatusCode::NOT_FOUND,
            "That sign-in method is not configured.",
        ));
    };
    if !app
        .limiter
        .hit(&format!("oauth-ip:{ip}"), 20, Duration::from_secs(300))
    {
        return Err(err_page(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts. Wait a few minutes.",
        ));
    }
    let (state, challenge, bind) = app
        .flows
        .start(p.kind, Mode::Login, None)
        .map_err(internal)?;
    let url = oauth::authorize_url(&p, &redirect_uri(&app, p.kind), &state, &challenge);
    Ok(([set_cookie(OAUTH_COOKIE, &bind, 600)], redirect(&url)).into_response())
}

async fn oauth_start_link(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Path(name): Path<String>,
    Form(f): Form<HashMap<String, String>>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    let c = guard_post(&app, &h, ip, Role::Viewer, &f).await?;
    let Some(p) = provider(&app, &name) else {
        return Err(err_page(
            StatusCode::NOT_FOUND,
            "That sign-in method is not configured.",
        ));
    };
    let (state, challenge, bind) = app
        .flows
        .start(p.kind, Mode::Link, Some(c.key.clone()))
        .map_err(internal)?;
    let url = oauth::authorize_url(&p, &redirect_uri(&app, p.kind), &state, &challenge);
    Ok(([set_cookie(OAUTH_COOKIE, &bind, 600)], redirect(&url)).into_response())
}

#[derive(serde::Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
}

async fn oauth_callback(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Path(name): Path<String>,
    Query(q): Query<CallbackQuery>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    let clear = set_cookie(OAUTH_COOKIE, "", 0);
    let back = |to: &str| Ok(([clear.clone()], redirect(to)).into_response());
    let Some(p) = provider(&app, &name) else {
        return Err(err_page(
            StatusCode::NOT_FOUND,
            "That sign-in method is not configured.",
        ));
    };
    let (Some(code), Some(state)) = (q.code, q.state) else {
        return back("/login?err=oauth");
    };
    let Some(pending) = app.flows.take(&state) else {
        return back("/login?err=oauth");
    };
    let bind = cookie(&h, OAUTH_COOKIE).unwrap_or_default();
    if pending.kind != p.kind
        || bind.is_empty()
        || !bool::from(bind.as_bytes().ct_eq(pending.bind.as_bytes()))
    {
        audit(&app, "-", &ip, "oauth.state_mismatch", p.kind.id()).await;
        return back("/login?err=oauth");
    }
    let (pid, pname) = match oauth::finish(
        &app.http,
        &p,
        &code,
        &pending.verifier,
        &redirect_uri(&app, p.kind),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[dashboard] oauth {}: {e}", p.kind.id());
            audit(&app, "-", &ip, "oauth.fail", p.kind.id()).await;
            return back(if pending.mode == Mode::Link {
                "/account?err=oauth"
            } else {
                "/login?err=oauth"
            });
        }
    };
    let prov = p.kind.id().to_string();
    match pending.mode {
        Mode::Link => {
            // The flow must finish in the same, still fully authenticated session.
            let Some(c) = load(&app, &h, ip.clone()).await.map_err(internal)? else {
                return back("/login?err=expired");
            };
            if Some(&c.key) != pending.session_key.as_ref() || c.sess.stage != Stage::Full {
                return back("/login?err=oauth");
            }
            let (pr, id, nm, uname) = (
                prov.clone(),
                pid.clone(),
                clip(&pname, 64),
                c.user.name.clone(),
            );
            let res = app
                .store
                .run(move |s| {
                    if let Some(owner) = s.linked_user(&pr, &id)?
                        && owner != uname
                    {
                        return Ok(false);
                    }
                    let Some(mut u) = s.get_user(&uname)? else {
                        return Ok(false);
                    };
                    // Replace any previous link for this provider.
                    if let Some(old) = u.links.iter().find(|l| l.provider == pr).cloned() {
                        s.unlink(&old.provider, &old.id)?;
                    }
                    u.links.retain(|l| l.provider != pr);
                    u.links.push(Link {
                        provider: pr.clone(),
                        id: id.clone(),
                        name: nm,
                    });
                    s.link(&pr, &id, &uname)?;
                    s.put_user(&u)?;
                    Ok(true)
                })
                .await
                .map_err(internal)?;
            if !res {
                audit(
                    &app,
                    &c.user.name,
                    &ip,
                    "oauth.link_refused",
                    &format!("{prov}:{pid} owned by another user"),
                )
                .await;
                return back("/account?err=taken");
            }
            audit(
                &app,
                &c.user.name,
                &ip,
                "oauth.linked",
                &format!("{prov}:{pid}"),
            )
            .await;
            back("/account?ok=linked")
        }
        Mode::Login => {
            let (pr, id) = (prov.clone(), pid.clone());
            let user = app
                .store
                .run(move |s| match s.linked_user(&pr, &id)? {
                    Some(n) => s.get_user(&n),
                    None => Ok(None),
                })
                .await
                .map_err(internal)?;
            let Some(user) = user else {
                audit(
                    &app,
                    "-",
                    &ip,
                    "login.oauth_unlinked",
                    &format!("{prov}:{pid}"),
                )
                .await;
                return back("/login?err=nolink");
            };
            if user.disabled || user.locked_until > now() {
                audit(&app, &user.name, &ip, "login.blocked", "oauth").await;
                return back("/login?err=oauth");
            }
            if user.totp.is_none() {
                return back("/login?err=notsetup");
            }
            let old = cookie(&h, SESSION_COOKIE).map(|t| auth::sha256_hex(t.as_bytes()));
            let ck = new_session(&app, &user.name, Stage::Mfa, &ip, ua(&h), old)
                .await
                .map_err(internal)?;
            audit(&app, &user.name, &ip, "login.oauth_ok", &prov).await;
            Ok(([ck, clear], redirect("/login/totp")).into_response())
        }
    }
}
