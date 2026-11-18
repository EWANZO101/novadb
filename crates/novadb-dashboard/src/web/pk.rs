//! Passkeys: register on the Account page, sign in without password + TOTP.
//!
//! A passkey with user verification (PIN / biometrics on the device) is phishing-resistant
//! multi-factor on its own, so a passkey login skips the password and the TOTP step. JSON
//! endpoints, driven by `/static/passkey.js` (the only script; CSP `script-src 'self'`). State
//! changes need the session's CSRF token (`X-CSRF` header) plus the usual Origin check; every
//! outcome goes to the audit log.

use std::sync::{LazyLock, Mutex};

use axum::Json;
use serde_json::{Value as J, json};

use super::*;
use crate::store::Passkey;
use crate::webauthn::{self, Rp, b64url, unb64url};

pub const JS: &str = include_str!("../../static/passkey.js");
const MAX_PASSKEYS: usize = 10;
const CHALLENGE_SECS: u64 = 180;

enum Purpose {
    /// registration for this user (session key bound)
    Register(String),
    Login,
}

struct Pending {
    challenge: String,
    purpose: Purpose,
    expires: u64,
}

/// Outstanding challenges (single use, 3 minutes).
static PENDING: LazyLock<Mutex<HashMap<String, Pending>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn put_challenge(key: String, purpose: Purpose) -> Result<String, String> {
    let challenge = b64url(&auth::random_bytes::<32>()?);
    let t = now();
    let mut m = PENDING.lock().map_err(|_| "lock")?;
    m.retain(|_, p| p.expires > t);
    if m.len() > 10_000 {
        return Err("too many pending passkey requests".into());
    }
    m.insert(
        key,
        Pending {
            challenge: challenge.clone(),
            purpose,
            expires: t + CHALLENGE_SECS,
        },
    );
    Ok(challenge)
}

fn take_challenge(key: &str) -> Option<Pending> {
    let mut m = PENDING.lock().ok()?;
    let p = m.remove(key)?;
    (p.expires > now()).then_some(p)
}

fn rp_id(app: &App) -> String {
    let u = app.cfg.public_url.trim_end_matches('/');
    let host = u.split("://").nth(1).unwrap_or(u);
    host.split(['/', ':']).next().unwrap_or(host).to_string()
}

fn origin(app: &App) -> String {
    app.cfg.public_url.trim_end_matches('/').to_string()
}

fn jerr(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({"ok": false, "error": msg}))).into_response()
}

/// Session + Origin + `X-CSRF` for JSON requests.
async fn guard_json(app: &App, h: &HeaderMap, ip: String) -> Result<Ctx, Response> {
    if !origin_ok(app, h) {
        return Err(jerr(StatusCode::FORBIDDEN, "Cross-site request blocked."));
    }
    let c = guard(app, h, ip, Role::Viewer)
        .await
        .map_err(|_| jerr(StatusCode::UNAUTHORIZED, "Sign in first."))?;
    let got = h.get("x-csrf").and_then(|v| v.to_str().ok()).unwrap_or("");
    if got.is_empty() || !bool::from(got.as_bytes().ct_eq(c.sess.csrf.as_bytes())) {
        return Err(jerr(
            StatusCode::FORBIDDEN,
            "Form expired. Reload the page.",
        ));
    }
    Ok(c)
}

fn s<'a>(v: &'a J, path: &[&str]) -> Result<&'a str, Response> {
    let mut cur = v;
    for p in path {
        cur = cur
            .get(p)
            .ok_or_else(|| jerr(StatusCode::BAD_REQUEST, "malformed passkey response"))?;
    }
    cur.as_str()
        .ok_or_else(|| jerr(StatusCode::BAD_REQUEST, "malformed passkey response"))
}

fn b(v: &J, path: &[&str]) -> Result<Vec<u8>, Response> {
    unb64url(s(v, path)?).map_err(|_| jerr(StatusCode::BAD_REQUEST, "malformed passkey response"))
}

pub(super) async fn script() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=300"),
        ],
        JS,
    )
        .into_response()
}

// ----- registration ----------------------------------------------------------------------

pub(super) async fn register_begin(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Json(body): Json<J>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    let c = guard_json(&app, &h, ip.clone()).await?;
    if c.user.passkeys.len() >= MAX_PASSKEYS {
        return Err(jerr(
            StatusCode::BAD_REQUEST,
            "At most 10 passkeys per account.",
        ));
    }
    // A passkey is a full sign-in method, so adding one needs the password and a fresh 2FA
    // code (same rule as recovery codes): a stolen session cookie alone must not be able to
    // plant a permanent backdoor. Own rate-limit bucket so it cannot lock the user out.
    if !app.limiter.hit(
        &format!("passkey-add:{}", c.user.name),
        6,
        Duration::from_secs(300),
    ) {
        return Err(jerr(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many tries. Wait a few minutes.",
        ));
    }
    let current = body
        .get("current")
        .and_then(J::as_str)
        .unwrap_or("")
        .to_string();
    let code = body.get("code").and_then(J::as_str).unwrap_or("");
    let pw_ok = verify_pw(&app, current, Some(c.user.pw.clone()))
        .await
        .map_err(internal)?;
    let secret = c
        .user
        .totp
        .as_deref()
        .and_then(totp::base32_decode)
        .unwrap_or_default();
    let step = totp::verify(&secret, code, now(), c.user.totp_last);
    let (true, Some(step)) = (pw_ok, step) else {
        audit(
            &app,
            &c.user.name,
            &ip,
            "passkey.add_fail",
            "password or code wrong",
        )
        .await;
        return Err(jerr(StatusCode::FORBIDDEN, "Password or code is wrong."));
    };
    let uname = c.user.name.clone();
    app.store
        .run(move |s| {
            let Some(mut u) = s.get_user(&uname)? else {
                return Err("user vanished".into());
            };
            u.totp_last = step; // the code cannot be replayed
            s.put_user(&u)
        })
        .await
        .map_err(internal)?;
    let challenge =
        put_challenge(c.key.clone(), Purpose::Register(c.user.name.clone())).map_err(internal)?;
    let exclude: Vec<J> = c
        .user
        .passkeys
        .iter()
        .map(|p| json!({"type": "public-key", "id": p.id}))
        .collect();
    Ok(Json(json!({
        "challenge": challenge,
        "rp": {"id": rp_id(&app), "name": "NovaDB"},
        "user": {"id": b64url(c.user.name.as_bytes()), "name": c.user.name, "displayName": c.user.name},
        "pubKeyCredParams": [
            {"type": "public-key", "alg": webauthn::ES256},
            {"type": "public-key", "alg": webauthn::EDDSA},
            {"type": "public-key", "alg": webauthn::RS256}
        ],
        "authenticatorSelection": {"residentKey": "required", "requireResidentKey": true, "userVerification": "required"},
        "attestation": "none",
        "excludeCredentials": exclude,
        "timeout": CHALLENGE_SECS * 1000 - 10_000
    }))
    .into_response())
}

pub(super) async fn register_finish(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Json(body): Json<J>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    let c = guard_json(&app, &h, ip.clone()).await?;
    let Some(p) = take_challenge(&c.key) else {
        return Err(jerr(
            StatusCode::BAD_REQUEST,
            "The request expired. Try again.",
        ));
    };
    let Purpose::Register(for_user) = p.purpose else {
        return Err(jerr(StatusCode::BAD_REQUEST, "Wrong request."));
    };
    if for_user != c.user.name {
        return Err(jerr(StatusCode::BAD_REQUEST, "Wrong request."));
    }
    let att = b(&body, &["response", "attestationObject"])?;
    let cd = b(&body, &["response", "clientDataJSON"])?;
    let (rid, org) = (rp_id(&app), origin(&app));
    let cred = match webauthn::verify_registration(
        &att,
        &cd,
        &p.challenge,
        &Rp {
            id: &rid,
            origin: &org,
        },
    ) {
        Ok(c) => c,
        Err(e) => {
            audit(&app, &c.user.name, &ip, "passkey.add_fail", &e).await;
            return Err(jerr(
                StatusCode::BAD_REQUEST,
                &format!("Passkey not accepted: {e}"),
            ));
        }
    };
    let id = b64url(&cred.id);
    let name: String = body
        .get("name")
        .and_then(J::as_str)
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .take(40)
        .collect();
    let name = if name.trim().is_empty() {
        "Passkey".to_string()
    } else {
        name.trim().to_string()
    };
    let user = c.user.name.clone();
    let pk = Passkey {
        id: id.clone(),
        cose: b64url(&cred.cose),
        alg: cred.alg,
        count: cred.count,
        name: name.clone(),
        created: now(),
        last_used: 0,
    };
    let added = app
        .store
        .run(move |s| {
            // a credential id may belong to one account only
            for u in s.list_users()? {
                if u.passkeys.iter().any(|p| p.id == pk.id) {
                    return Ok(false);
                }
            }
            let Some(mut u) = s.get_user(&user)? else {
                return Ok(false);
            };
            if u.passkeys.len() >= MAX_PASSKEYS {
                return Ok(false);
            }
            u.passkeys.push(pk);
            s.put_user(&u)?;
            Ok(true)
        })
        .await
        .map_err(internal)?;
    if !added {
        return Err(jerr(
            StatusCode::CONFLICT,
            "This passkey is already registered (or the limit is reached).",
        ));
    }
    audit(
        &app,
        &c.user.name,
        &ip,
        "passkey.add",
        &format!("{name} ({})", alg_name(cred.alg)),
    )
    .await;
    Ok(Json(json!({"ok": true})).into_response())
}

fn alg_name(a: i64) -> &'static str {
    match a {
        webauthn::ES256 => "ES256",
        webauthn::EDDSA => "Ed25519",
        webauthn::RS256 => "RS256",
        _ => "?",
    }
}

pub(super) async fn delete(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    let c = guard_post(&app, &h, ip.clone(), Role::Viewer, &f).await?;
    let id = field(&f, "id").to_string();
    let user = c.user.name.clone();
    let id2 = id.clone();
    let removed = app
        .store
        .run(move |s| {
            let Some(mut u) = s.get_user(&user)? else {
                return Ok(None);
            };
            let pos = u.passkeys.iter().position(|p| p.id == id2);
            let r = pos.map(|i| u.passkeys.remove(i).name);
            if r.is_some() {
                s.put_user(&u)?;
            }
            Ok(r)
        })
        .await
        .map_err(internal)?;
    match removed {
        Some(n) => {
            audit(&app, &c.user.name, &ip, "passkey.remove", &n).await;
            Ok(redirect("/account?ok=passkey_removed"))
        }
        None => Ok(redirect("/account")),
    }
}

/// The Account page card.
pub(super) fn account_card(u: &User, token: &str, t: u64) -> String {
    let rows: String = u
        .passkeys
        .iter()
        .map(|p| {
            format!(
                r#"<tr><td><b>{}</b><div class="hint">{}</div></td><td>{}</td><td>{}</td><td class="r"><form method="post" action="/account/passkeys/delete">{}<input type="hidden" name="id" value="{}"><button class="danger sm">Remove</button></form></td></tr>"#,
                esc(&p.name),
                alg_name(p.alg),
                html::ago(t, p.created),
                if p.last_used == 0 { "never".to_string() } else { html::ago(t, p.last_used) },
                csrf(token),
                esc(&p.id),
            )
        })
        .collect();
    let list = if u.passkeys.is_empty() {
        r#"<div class="empty">No passkeys yet.</div>"#.to_string()
    } else {
        format!(
            r#"<div class="tbl"><table><thead><tr><th>Name</th><th>Added</th><th>Last used</th><th></th></tr></thead><tbody>{rows}</tbody></table></div>"#
        )
    };
    format!(
        r#"<div class="card"><div class="card-h">{icon}<h2>Passkeys</h2><span class="r hint">{n} of {MAX_PASSKEYS}</span></div><div class="card-b"><p class="sub">Sign in with your phone, security key or computer (Face ID, fingerprint, PIN) — no password or 2FA code needed, and it can't be phished.</p>
<div class="pkform"><div><label for="pk-name">Name</label><input id="pk-name" type="text" maxlength="40" placeholder="e.g. My phone"></div><div><label for="pk-pw">Current password</label><input id="pk-pw" type="password" autocomplete="current-password" maxlength="128"></div><div><label for="pk-code">Current 6-digit code</label><input id="pk-code" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="7" placeholder="000000"></div><button type="button" id="pk-add" data-csrf="{tok}">Add a passkey</button></div><p id="pk-msg" class="hint" role="status"></p></div>{list}</div>
<script src="/static/passkey.js" defer></script>"#,
        icon = html::icon("key"),
        n = u.passkeys.len(),
        tok = esc(token),
    )
}

// ----- login -------------------------------------------------------------------------------

pub(super) async fn login_begin(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    if !origin_ok(&app, &h) {
        return Err(jerr(StatusCode::FORBIDDEN, "Cross-site request blocked."));
    }
    if !app
        .limiter
        .hit(&format!("pk-ip:{ip}"), 30, Duration::from_secs(300))
    {
        return Err(jerr(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts. Wait a few minutes.",
        ));
    }
    let flow = auth::token().map_err(internal)?;
    let challenge = put_challenge(format!("login:{flow}"), Purpose::Login).map_err(internal)?;
    Ok(Json(json!({
        "flow": flow,
        "publicKey": {
            "challenge": challenge,
            "rpId": rp_id(&app),
            "userVerification": "required",
            "allowCredentials": [],
            "timeout": CHALLENGE_SECS * 1000 - 10_000
        }
    }))
    .into_response())
}

pub(super) async fn login_finish(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Json(body): Json<J>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    if !origin_ok(&app, &h) {
        return Err(jerr(StatusCode::FORBIDDEN, "Cross-site request blocked."));
    }
    let generic = || {
        jerr(
            StatusCode::UNAUTHORIZED,
            "That passkey can't sign you in here.",
        )
    };
    let flow = s(&body, &["flow"])?.to_string();
    let Some(p) = take_challenge(&format!("login:{flow}")) else {
        return Err(jerr(
            StatusCode::BAD_REQUEST,
            "The request expired. Try again.",
        ));
    };
    if !matches!(p.purpose, Purpose::Login) {
        return Err(generic());
    }
    let cred_id = s(&body, &["id"])?.to_string();
    let ad = b(&body, &["response", "authenticatorData"])?;
    let cd = b(&body, &["response", "clientDataJSON"])?;
    let sig = b(&body, &["response", "signature"])?;
    let handle = body
        .get("response")
        .and_then(|r| r.get("userHandle"))
        .and_then(J::as_str)
        .and_then(|h| unb64url(h).ok())
        .and_then(|h| String::from_utf8(h).ok());
    let cid = cred_id.clone();
    let found = app
        .store
        .run(move |s| {
            let candidates: Vec<User> = match handle {
                Some(n) => s.get_user(n.as_str())?.into_iter().collect(),
                None => s.list_users()?,
            };
            Ok(candidates
                .into_iter()
                .find(|u| u.passkeys.iter().any(|p| p.id == cid)))
        })
        .await
        .map_err(internal)?;
    let Some(mut user) = found else {
        audit(&app, "-", &ip, "login.passkey_fail", "unknown passkey").await;
        return Err(generic());
    };
    let t = now();
    if user.disabled || user.locked_until > t {
        audit(&app, &user.name, &ip, "login.blocked", "passkey").await;
        return Err(generic());
    }
    let Some(pi) = user.passkeys.iter().position(|p| p.id == cred_id) else {
        return Err(generic());
    };
    let cose = unb64url(&user.passkeys[pi].cose).map_err(internal)?;
    let (rid, org) = (rp_id(&app), origin(&app));
    match webauthn::verify_assertion(
        &cose,
        user.passkeys[pi].count,
        &ad,
        &cd,
        &sig,
        &p.challenge,
        &Rp {
            id: &rid,
            origin: &org,
        },
    ) {
        Ok(count) => {
            user.passkeys[pi].count = count;
            user.passkeys[pi].last_used = t;
        }
        Err(e) => {
            audit(&app, &user.name, &ip, "login.passkey_fail", &e).await;
            return Err(generic());
        }
    }
    user.failed = 0;
    user.last_login = t;
    let stage = if user.must_change || user.totp.is_none() {
        Stage::Setup
    } else {
        Stage::Full
    };
    let pk_name = user.passkeys[pi].name.clone();
    let u2 = user.clone();
    app.store
        .run(move |s| s.put_user(&u2))
        .await
        .map_err(internal)?;
    let old = cookie(&h, SESSION_COOKIE).map(|t| auth::sha256_hex(t.as_bytes()));
    let c = new_session(&app, &user.name, stage, &ip, ua(&h), old)
        .await
        .map_err(internal)?;
    audit(&app, &user.name, &ip, "login.passkey_ok", &pk_name).await;
    let to = if stage == Stage::Full {
        "/"
    } else {
        next_setup(&user)
    };
    Ok(([c], Json(json!({"ok": true, "redirect": to}))).into_response())
}
