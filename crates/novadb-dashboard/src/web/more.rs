//! Second batch of pages: audit search + CSV export, all-sessions admin view, system page,
//! recovery codes and activity feeds. Same rules as the parent module: every state change is a
//! POST through `guard_post` (session + CSRF + Origin) and is written to the audit log.

use super::*;
use crate::store::AuditEntry;

const PAGE: usize = 50;

// ----- small helpers -----------------------------------------------------------------------

/// Percent-encode a query-string value.
fn qenc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            o.push(char::from(b));
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

fn category(action: &str) -> &str {
    action.split('.').next().unwrap_or(action)
}

/// Compact "recent activity" list used on Overview and Account.
pub(super) fn activity_list(entries: &[AuditEntry], t: u64, show_actor: bool) -> String {
    if entries.is_empty() {
        return r#"<div class="empty">No activity yet.</div>"#.into();
    }
    let rows: String = entries
        .iter()
        .map(|e| {
            let who = if show_actor {
                format!("<b>{}</b> ", esc(&e.actor))
            } else {
                String::new()
            };
            let detail = if e.detail.is_empty() {
                String::new()
            } else {
                format!(r#"<span class="feed-d">{}</span>"#, esc(&clip(&e.detail, 80)))
            };
            format!(
                r#"<li><span class="feed-dot {cls}"></span><span class="feed-t">{who}<span class="pill {cls}">{act}</span>{detail}</span><span class="feed-m" title="{ts} UTC">{ago}<small>{ip}</small></span></li>"#,
                cls = html::event_class(&e.action),
                act = esc(&e.action),
                ts = html::ts(e.ts),
                ago = html::ago(t, e.ts),
                ip = esc(&e.ip),
            )
        })
        .collect();
    format!(r#"<ul class="feed">{rows}</ul>"#)
}

// ----- audit log: filters, pagination, CSV ---------------------------------------------------

#[derive(serde::Deserialize, Default)]
pub(super) struct AuditQ {
    q: Option<String>,
    cat: Option<String>,
    who: Option<String>,
    page: Option<usize>,
}

impl AuditQ {
    fn norm(&self) -> (String, String, String) {
        let t = |o: &Option<String>| clip(o.as_deref().unwrap_or("").trim(), 64);
        (t(&self.q), t(&self.cat), t(&self.who))
    }
    fn matches(&self, e: &AuditEntry) -> bool {
        let (q, cat, who) = self.norm();
        if !cat.is_empty() && category(&e.action) != cat {
            return false;
        }
        if !who.is_empty() && e.actor != who {
            return false;
        }
        if !q.is_empty() {
            let q = q.to_lowercase();
            let hay = format!("{} {} {} {}", e.actor, e.ip, e.action, e.detail).to_lowercase();
            if !hay.contains(&q) {
                return false;
            }
        }
        true
    }
    fn query_string(&self, page: Option<usize>) -> String {
        let (q, cat, who) = self.norm();
        let mut parts = Vec::new();
        for (k, v) in [("q", q), ("cat", cat), ("who", who)] {
            if !v.is_empty() {
                parts.push(format!("{k}={}", qenc(&v)));
            }
        }
        if let Some(p) = page {
            parts.push(format!("page={p}"));
        }
        if parts.is_empty() {
            String::new()
        } else {
            format!("?{}", parts.join("&amp;"))
        }
    }
}

pub(super) async fn audit_page(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Query(aq): Query<AuditQ>,
) -> Res {
    let c = guard(&app, &h, client_ip(&app, &peer, &h), Role::Operator).await?;
    let (all, chain) = app
        .store
        .run(|s| Ok((s.audit_all()?, s.audit_verify())))
        .await
        .map_err(internal)?;
    let chain_html = match chain {
        Ok(n) => format!(
            r#"<span class="badge ok"><span class="pulse"></span>Chain intact</span><span class="r hint">{n} entries, each hashed into the next</span>"#
        ),
        Err(e) => format!(
            r#"<span class="badge bad"><span class="pulse"></span>Chain broken</span><span class="r hint">{}</span>"#,
            esc(&e)
        ),
    };
    let mut cats: Vec<&str> = all.iter().map(|e| category(&e.action)).collect();
    cats.sort_unstable();
    cats.dedup();
    let mut actors: Vec<&str> = all.iter().map(|e| e.actor.as_str()).collect();
    actors.sort_unstable();
    actors.dedup();
    let (q, cat, who) = aq.norm();
    let hits: Vec<&AuditEntry> = all.iter().filter(|e| aq.matches(e)).collect();
    let pages = hits.len().div_ceil(PAGE).max(1);
    let page = aq.page.unwrap_or(1).clamp(1, pages);
    let trs: String = hits
        .iter()
        .skip((page - 1) * PAGE)
        .take(PAGE)
        .map(|e| {
            format!(
                r#"<tr><td class="num">{}</td><td class="mono nw">{}</td><td><b>{}</b></td><td class="mono">{}</td><td><span class="pill {}">{}</span></td><td>{}</td><td class="mono" title="{}">{}</td></tr>"#,
                e.seq,
                html::ts(e.ts),
                esc(&e.actor),
                esc(&e.ip),
                html::event_class(&e.action),
                esc(&e.action),
                esc(&e.detail),
                esc(&e.hash),
                esc(&e.hash[..10.min(e.hash.len())])
            )
        })
        .collect();
    let trs = if trs.is_empty() {
        r#"<tr><td colspan="7"><div class="empty">No events match these filters.</div></td></tr>"#
            .to_string()
    } else {
        trs
    };
    let opt = |v: &str, cur: &str, label: &str| {
        format!(
            r#"<option value="{}"{}>{}</option>"#,
            esc(v),
            if v == cur { " selected" } else { "" },
            esc(label)
        )
    };
    let cat_opts: String = std::iter::once(opt("", &cat, "All events"))
        .chain(cats.iter().map(|x| opt(x, &cat, x)))
        .collect();
    let who_opts: String = std::iter::once(opt("", &who, "Everyone"))
        .chain(actors.iter().map(|x| opt(x, &who, x)))
        .collect();
    let filtered = !(q.is_empty() && cat.is_empty() && who.is_empty());
    let pager = if pages > 1 {
        let prev = if page > 1 {
            format!(
                r#"<a class="btn ghost sm" href="/audit{}">&larr; Newer</a>"#,
                aq.query_string(Some(page - 1))
            )
        } else {
            r#"<span class="btn ghost sm dis">&larr; Newer</span>"#.into()
        };
        let next = if page < pages {
            format!(
                r#"<a class="btn ghost sm" href="/audit{}">Older &rarr;</a>"#,
                aq.query_string(Some(page + 1))
            )
        } else {
            r#"<span class="btn ghost sm dis">Older &rarr;</span>"#.into()
        };
        format!(
            r#"<div class="pager"><span class="hint">Page {page} of {pages}</span><span class="row">{prev}{next}</span></div>"#
        )
    } else {
        String::new()
    };
    let body = format!(
        r#"{head}
<form method="get" action="/audit" class="filters card">
<div class="f-search">{isearch}<input type="text" name="q" value="{qv}" placeholder="Search user, IP, event or detail" maxlength="64" aria-label="Search"></div>
<select name="cat" aria-label="Event type">{cat_opts}</select>
<select name="who" aria-label="User">{who_opts}</select>
<button class="sm">Apply</button>{clear}</form>
<div class="card"><div class="card-h">{ic}{chain_html}</div>
<div class="tbl"><table><thead><tr><th>#</th><th>Time (UTC)</th><th>Who</th><th>IP</th><th>Event</th><th>Detail</th><th>Hash</th></tr></thead><tbody>{trs}</tbody></table></div>
<div class="card-f between"><span>{shown}</span>{pager}</div></div>"#,
        head = html::header(
            "Audit log",
            "Append-only and tamper-evident. Every sign-in, change and export is recorded.",
            &format!(
                r#"<a class="btn ghost" href="/audit/export.csv{}">{}Export CSV</a>"#,
                aq.query_string(None),
                html::icon("download")
            )
        ),
        isearch = html::icon("search"),
        qv = esc(&q),
        clear = if filtered {
            r#"<a class="hint" href="/audit">Clear</a>"#
        } else {
            ""
        },
        ic = html::icon("audit"),
        shown = if filtered {
            format!("{} of {} events match", hits.len(), all.len())
        } else {
            format!("{} events", all.len())
        },
    );
    Ok(Html(html::page(
        "Audit log",
        Some(&c.nav("/audit")),
        Flash::None,
        &body,
    ))
    .into_response())
}

/// One CSV cell: quoted, quotes doubled, and spreadsheet formula triggers neutralised.
fn csv_cell(s: &str) -> String {
    let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{s}")
    } else {
        s.to_string()
    };
    format!("\"{}\"", s.replace('"', "\"\""))
}

pub(super) async fn audit_export(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Query(aq): Query<AuditQ>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    let c = guard(&app, &h, ip.clone(), Role::Operator).await?;
    let all = app.store.run(|s| s.audit_all()).await.map_err(internal)?;
    let mut out = String::from("seq,time_utc,actor,ip,action,detail,hash\r\n");
    let mut n = 0usize;
    for e in all.iter().filter(|e| aq.matches(e)) {
        n += 1;
        out.push_str(&format!(
            "{},{},{},{},{},{},{}\r\n",
            e.seq,
            csv_cell(&html::ts(e.ts)),
            csv_cell(&e.actor),
            csv_cell(&e.ip),
            csv_cell(&e.action),
            csv_cell(&e.detail),
            csv_cell(&e.hash)
        ));
    }
    let (q, cat, who) = aq.norm();
    audit(
        &app,
        &c.user.name,
        &ip,
        "audit.exported",
        &format!("{n} rows; q={q} cat={cat} who={who}"),
    )
    .await;
    let fname = format!(
        "attachment; filename=\"novadb-audit-{}.csv\"",
        html::ts(now()).replace([' ', ':'], "-")
    );
    let mut r = ([(header::CONTENT_TYPE, "text/csv; charset=utf-8")], out).into_response();
    if let Ok(v) = HeaderValue::from_str(&fname) {
        r.headers_mut().insert(header::CONTENT_DISPOSITION, v);
    }
    Ok(r)
}

// ----- all sessions (admin) ----------------------------------------------------------------

pub(super) async fn sessions_page(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Query(q): Query<MsgQuery>,
) -> Res {
    let c = guard(&app, &h, client_ip(&app, &peer, &h), Role::Admin).await?;
    sessions_render(&app, &c, flash_of(&q)).await
}

async fn sessions_render(app: &App, c: &Ctx, flash: Flash<'_>) -> Res {
    let mut all = app
        .store
        .run(|s| s.all_sessions())
        .await
        .map_err(internal)?;
    all.sort_by_key(|(_, s)| std::cmp::Reverse(s.last_seen));
    let t = now();
    let mut users: Vec<&str> = all.iter().map(|(_, s)| s.user.as_str()).collect();
    users.sort_unstable();
    users.dedup();
    let half = all.iter().filter(|(_, s)| s.stage != Stage::Full).count();
    let rows: String = all
        .iter()
        .map(|(k, s)| {
            let stage = match s.stage {
                Stage::Full => r#"<span class="pill ok">Signed in</span>"#,
                Stage::Mfa => r#"<span class="pill warn">Waiting for 2FA</span>"#,
                Stage::Setup => r#"<span class="pill warn">Setting up</span>"#,
            };
            let left = IDLE
                .saturating_sub(t.saturating_sub(s.last_seen))
                .min(ABSOLUTE.saturating_sub(t.saturating_sub(s.created)));
            let action = if *k == c.key {
                r#"<span class="badge acc">This device</span>"#.to_string()
            } else {
                format!(
                    r#"<form method="post" action="/sessions/revoke">{}<input type="hidden" name="id" value="{}"><button class="ghost sm">Revoke</button></form>"#,
                    csrf(&c.sess.csrf),
                    esc(&k[..12.min(k.len())])
                )
            };
            format!(
                r#"<tr><td><span class="ucell">{}<b>{}</b></span></td><td>{stage}</td><td class="mono">{}</td><td>{}</td><td class="nw">{}</td><td class="nw">{}</td><td class="nw num">{}m</td><td class="r">{action}</td></tr>"#,
                html::avatar(&s.user),
                esc(&s.user),
                esc(&s.ip),
                esc(&clip(&s.ua, 48)),
                html::ago(t, s.created),
                html::ago(t, s.last_seen),
                left / 60,
            )
        })
        .collect();
    let others = all.len().saturating_sub(1);
    let body = format!(
        r#"{head}
<div class="kpis">
<div class="kpi"><div class="kpi-h"><span>Active sessions</span><span class="ic">{imon}</span></div><b>{n}</b><small>across all users</small></div>
<div class="kpi"><div class="kpi-h"><span>Users online</span><span class="ic">{iusers}</span></div><b>{nu}</b><small>distinct accounts</small></div>
<div class="kpi"><div class="kpi-h"><span>Half signed in</span><span class="ic">{ilock}</span></div><b>{half}</b><small>waiting for 2FA or setup</small></div>
<div class="kpi"><div class="kpi-h"><span>Idle timeout</span><span class="ic">{iclock}</span></div><b>{idle}m</b><small>{abs}h absolute limit</small></div></div>
<div class="card"><div class="card-h">{imon}<h2>All sessions</h2><span class="r hint">newest activity first</span></div>
<div class="tbl"><table><thead><tr><th>User</th><th>State</th><th>IP</th><th>Device</th><th>Started</th><th>Last seen</th><th>Expires in</th><th></th></tr></thead><tbody>{rows}</tbody></table></div>
<div class="card-f between"><span>Revoking a session signs that device out immediately.</span>
<form method="post" action="/sessions/revoke_all">{csrf}<button class="danger sm"{dis}>Sign out everyone else ({others})</button></form></div></div>"#,
        head = html::header(
            "Sessions",
            "Every signed-in device, for every user. Only hashes of session tokens are stored.",
            ""
        ),
        imon = html::icon("monitor"),
        iusers = html::icon("users"),
        ilock = html::icon("lock"),
        iclock = html::icon("clock"),
        n = all.len(),
        nu = users.len(),
        idle = IDLE / 60,
        abs = ABSOLUTE / 3600,
        csrf = csrf(&c.sess.csrf),
        dis = if others == 0 { " disabled" } else { "" },
    );
    Ok(Html(html::page(
        "Sessions",
        Some(&c.nav("/sessions")),
        flash,
        &body,
    ))
    .into_response())
}

pub(super) async fn sessions_revoke(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    let c = guard_post(&app, &h, ip.clone(), Role::Admin, &f).await?;
    let id = field(&f, "id").to_string();
    if id.len() != 12 {
        return Ok(redirect("/sessions"));
    }
    let me = c.key.clone();
    let who = app
        .store
        .run(move |s| {
            let hits: Vec<(String, Session)> = s
                .all_sessions()?
                .into_iter()
                .filter(|(k, _)| k.starts_with(&id) && *k != me)
                .collect();
            // Ambiguous prefixes are refused rather than guessed.
            if let [(k, sess)] = hits.as_slice() {
                s.delete_session(k)?;
                return Ok(Some(sess.user.clone()));
            }
            Ok(None)
        })
        .await
        .map_err(internal)?;
    match who {
        Some(u) => {
            audit(
                &app,
                &c.user.name,
                &ip,
                "session.revoked",
                &format!("user {u}"),
            )
            .await;
            Ok(redirect("/sessions?ok=revoked"))
        }
        None => Ok(redirect("/sessions")),
    }
}

pub(super) async fn sessions_revoke_all(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    let c = guard_post(&app, &h, ip.clone(), Role::Admin, &f).await?;
    let me = c.key.clone();
    let n = app
        .store
        .run(move |s| {
            let mut n = 0;
            for (k, _) in s.all_sessions()? {
                if k != me {
                    s.delete_session(&k)?;
                    n += 1;
                }
            }
            Ok(n)
        })
        .await
        .map_err(internal)?;
    audit(
        &app,
        &c.user.name,
        &ip,
        "session.revoked_all",
        &format!("{n} sessions"),
    )
    .await;
    Ok(redirect("/sessions?ok=revoked_all"))
}

/// Account: sign out all of *my* other devices.
pub(super) async fn account_revoke_all(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    let c = guard_post(&app, &h, ip.clone(), Role::Viewer, &f).await?;
    let (n, me) = (c.user.name.clone(), c.key.clone());
    let cnt = app
        .store
        .run(move |s| s.delete_sessions_for(&n, Some(&me)))
        .await
        .map_err(internal)?;
    audit(
        &app,
        &c.user.name,
        &ip,
        "session.revoked_others",
        &format!("{cnt} sessions"),
    )
    .await;
    Ok(redirect("/account?ok=revoked_all"))
}

// ----- system ------------------------------------------------------------------------------

fn proc_status() -> (String, String) {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let get = |k: &str| {
        s.lines()
            .find(|l| l.starts_with(k))
            .map(|l| l[k.len()..].trim().to_string())
            .unwrap_or_else(|| "n/a".into())
    };
    let rss = get("VmRSS:");
    let rss = rss
        .strip_suffix(" kB")
        .and_then(|k| k.trim().parse::<u64>().ok())
        .map(|k| html::bytes(k * 1024))
        .unwrap_or(rss);
    (rss, get("Threads:"))
}

fn dir_size(p: &std::path::Path) -> u64 {
    std::fs::read_dir(p)
        .map(|rd| {
            rd.flatten()
                .map(|e| match e.metadata() {
                    Ok(m) if m.is_dir() => dir_size(&e.path()),
                    Ok(m) => m.len(),
                    Err(_) => 0,
                })
                .sum()
        })
        .unwrap_or(0)
}

pub(super) async fn system_page(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Query(q): Query<MsgQuery>,
) -> Res {
    let c = guard(&app, &h, client_ip(&app, &peer, &h), Role::Operator).await?;
    let (stats, verify, trees, rec) = app
        .store
        .run(|s| {
            Ok((
                s.stats(),
                s.verify_db(),
                s.tree_sizes()?,
                s.recovery_report(),
            ))
        })
        .await
        .map_err(internal)?;
    let t = now();
    let (rss, threads) = proc_status();
    let fds = std::fs::read_dir("/proc/self/fd")
        .map(|d| d.count().to_string())
        .unwrap_or_else(|_| "n/a".into());
    let disk = dir_size(&app.cfg.data_dir);
    let ps = novadb_storage::page::PAGE_SIZE as u64;
    let kv = |rows: &[(&str, String)]| -> String {
        rows.iter()
            .map(|(k, v)| format!("<tr><td>{k}</td><td class=\"r\">{v}</td></tr>"))
            .collect()
    };
    let runtime = kv(&[
        (
            "Version",
            format!("<code>v{}</code>", env!("CARGO_PKG_VERSION")),
        ),
        ("Started", format!("{} UTC", html::ts(app.started))),
        ("Uptime", html::ago(t, app.started).replace(" ago", "")),
        ("Process ID", std::process::id().to_string()),
        ("Memory (RSS)", esc(&rss)),
        ("Threads", esc(&threads)),
        ("Open files", fds),
    ]);
    let (vbadge, vrows) = match &verify {
        Ok(r) => (
            r#"<span class="badge ok">Verified</span>"#,
            kv(&[
                ("Trees", r.trees.to_string()),
                ("Entries", r.entries.to_string()),
                (
                    "Used / free pages",
                    format!("{} / {}", r.used_pages, r.free_pages),
                ),
                ("Dropped, not yet reclaimed", r.dropped_pending.to_string()),
            ]),
        ),
        Err(e) => (
            r#"<span class="badge bad">Verify failed</span>"#,
            format!(r#"<tr><td colspan="2" class="mono">{}</td></tr>"#, esc(e)),
        ),
    };
    let storage = kv(&[
        ("Data directory on disk", html::bytes(disk)),
        (
            "Data file",
            format!(
                "{} pages · {}",
                stats.page_count,
                html::bytes(stats.page_count * ps)
            ),
        ),
        ("Page size", html::bytes(ps)),
        ("Write-ahead log", html::bytes(stats.wal_bytes)),
        (
            "Buffer pool",
            format!(
                "{} pages · {}",
                stats.cache_pages,
                html::bytes(stats.cache_pages as u64 * ps)
            ),
        ),
        (
            "Pages read / written",
            format!("{} / {}", stats.page_reads, stats.page_writes),
        ),
        ("Checkpoints (this run)", stats.checkpoints.to_string()),
    ]);
    let recovery = kv(&[
        ("Transactions replayed", rec.commits.to_string()),
        ("Page records applied", rec.pages_applied.to_string()),
        (
            "Incomplete records discarded",
            rec.discarded_records.to_string(),
        ),
        (
            "Torn WAL tail",
            if rec.torn_tail {
                r#"<span class="pill warn">yes, cut off safely</span>"#.into()
            } else {
                r#"<span class="pill ok">no</span>"#.into()
            },
        ),
    ]);
    let tree_rows: String = trees
        .iter()
        .map(|(n, cnt)| {
            let what = match n.as_str() {
                "dash_users" => "user accounts",
                "dash_sessions" => "session token hashes",
                "dash_audit" => "audit log entries",
                "dash_links" => "linked Discord / GitHub ids",
                "dash_meta" => "audit chain head",
                _ => "",
            };
            format!(
                r#"<tr><td><code>{}</code></td><td class="hint">{what}</td><td class="r num">{cnt}</td></tr>"#,
                esc(n)
            )
        })
        .collect();
    let on = |b: bool, yes: &str| {
        if b {
            format!(r#"<span class="pill ok">{yes}</span>"#)
        } else {
            r#"<span class="pill plain">not configured</span>"#.to_string()
        }
    };
    let policy = kv(&[
        ("Password hashing", "Argon2id · 19 MiB · t=2 · p=1".into()),
        ("Password length", "12 – 128 characters".into()),
        (
            "Two-factor",
            r#"<span class="pill ok">required for everyone</span>"#.into(),
        ),
        (
            "Recovery codes",
            format!("{} per batch · single use", auth::RECOVERY_CODES),
        ),
        (
            "Lockout",
            format!("{MAX_FAILED} wrong passwords → {} min", LOCK_SECS / 60),
        ),
        (
            "Sign-in rate limit",
            "10 / IP and 20 / user per 5 min".into(),
        ),
        (
            "Session timeout",
            format!("{} min idle · {} h absolute", IDLE / 60, ABSOLUTE / 3600),
        ),
        ("Discord sign-in", on(app.cfg.discord.is_some(), "enabled")),
        ("GitHub sign-in", on(app.cfg.github.is_some(), "enabled")),
        (
            "Public URL",
            format!("<code>{}</code>", esc(&app.cfg.public_url)),
        ),
        (
            "Trusted proxy",
            app.cfg
                .trusted_proxy
                .map(|p| format!("<code>{p}</code>"))
                .unwrap_or_else(|| "none".into()),
        ),
    ]);
    let checkpoint = if c.user.role >= Role::Admin {
        format!(
            r#"<form method="post" action="/system/checkpoint">{}<button class="ghost sm">Checkpoint now</button></form>"#,
            csrf(&c.sess.csrf)
        )
    } else {
        String::new()
    };
    let body = format!(
        r#"{head}
<div class="cols">
<div class="card"><div class="card-h">{icpu}<h2>Runtime</h2></div><table class="kv"><tbody>{runtime}</tbody></table></div>
<div class="card"><div class="card-h">{idb}<h2>Storage engine</h2><span class="r">{checkpoint}</span></div><table class="kv"><tbody>{storage}</tbody></table>
<div class="card-f">A checkpoint writes cached pages to the data file and empties the WAL.</div></div>
<div class="card"><div class="card-h">{iok}<h2>Integrity</h2><span class="r">{vbadge}</span></div><table class="kv"><tbody>{vrows}</tbody></table>
<div class="card-h sub2">{ilb}<h2>Crash recovery at startup</h2></div><table class="kv"><tbody>{recovery}</tbody></table></div>
<div class="card"><div class="card-h">{ilock}<h2>Security policy</h2></div><table class="kv"><tbody>{policy}</tbody></table></div>
</div>
<div class="card"><div class="card-h">{idrive}<h2>System trees</h2><span class="r hint">B+Trees inside the dashboard's own NovaDB database</span></div>
<div class="tbl"><table><thead><tr><th>Tree</th><th>Holds</th><th class="r">Entries</th></tr></thead><tbody>{tree_rows}</tbody></table></div></div>"#,
        head = html::header(
            "System",
            "Process, storage engine and security settings of this dashboard instance.",
            ""
        ),
        icpu = html::icon("cpu"),
        idb = html::icon("database"),
        iok = html::icon("check-circle"),
        ilb = html::icon("life-buoy"),
        ilock = html::icon("lock"),
        idrive = html::icon("drive"),
    );
    Ok(Html(html::page(
        "System",
        Some(&c.nav("/system")),
        flash_of(&q),
        &body,
    ))
    .into_response())
}

pub(super) async fn system_checkpoint(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    let c = guard_post(&app, &h, ip.clone(), Role::Admin, &f).await?;
    if !app.limiter.hit("checkpoint", 6, Duration::from_secs(60)) {
        return Ok(redirect("/system?err=slow"));
    }
    app.store.run(|s| s.checkpoint()).await.map_err(internal)?;
    audit(&app, &c.user.name, &ip, "system.checkpoint", "").await;
    Ok(redirect("/system?ok=checkpoint"))
}

// ----- recovery codes ----------------------------------------------------------------------

/// Account: (re)generate recovery codes. Needs password + a fresh TOTP code.
pub(super) async fn recovery_generate(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    let c = guard_post(&app, &h, ip.clone(), Role::Viewer, &f).await?;
    // Own bucket (it also needs the password), so it cannot lock the user out of signing in.
    if !app.limiter.hit(
        &format!("recovery-gen:{}", c.user.name),
        6,
        Duration::from_secs(300),
    ) {
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
    let (true, Some(step)) = (pw_ok, step) else {
        audit(&app, &c.user.name, &ip, "recovery.generate_fail", "").await;
        return account_render(&app, &c, Flash::Err("Password or code is wrong.")).await;
    };
    let codes = auth::recovery_codes().map_err(internal)?;
    let hashes: Vec<String> = codes
        .iter()
        .filter_map(|x| auth::recovery_hash(x))
        .collect();
    let name = c.user.name.clone();
    app.store
        .run(move |s| {
            let Some(mut u) = s.get_user(&name)? else {
                return Err("user vanished".into());
            };
            u.recovery = hashes;
            u.totp_last = step;
            s.put_user(&u)
        })
        .await
        .map_err(internal)?;
    audit(
        &app,
        &c.user.name,
        &ip,
        "recovery.generated",
        &format!("{} codes", codes.len()),
    )
    .await;
    // Re-load so the page shows the new count.
    let mut c2 = c;
    if let Some(u) = app
        .store
        .run({
            let n = c2.user.name.clone();
            move |s| s.get_user(&n)
        })
        .await
        .map_err(internal)?
    {
        c2.user = u;
    }
    account_render_full(
        &app,
        &c2,
        Flash::Ok("New recovery codes created. Your old codes no longer work."),
        Some(&codes),
    )
    .await
}

/// Second factor via a recovery code instead of TOTP. Each code works once.
pub(super) async fn login_recovery(
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
    // Shares the TOTP attempt budget: 6 wrong second factors kill the half session.
    if !app
        .limiter
        .hit(&format!("mfa:{}", c.user.name), 6, Duration::from_secs(300))
    {
        let k = c.key.clone();
        app.store
            .run(move |s| s.delete_session(&k))
            .await
            .map_err(internal)?;
        audit(&app, &c.user.name, &ip, "mfa.rate_limited", "recovery").await;
        return Ok(redirect("/login?err=expired"));
    }
    let given = auth::recovery_hash(field(&f, "recovery"));
    let name = c.user.name.clone();
    let t = now();
    let used = app
        .store
        .run(move |s| {
            let Some(mut u) = s.get_user(&name)? else {
                return Ok(None);
            };
            let Some(g) = given else { return Ok(None) };
            let pos = u
                .recovery
                .iter()
                .position(|h| bool::from(h.as_bytes().ct_eq(g.as_bytes())));
            let Some(i) = pos else { return Ok(None) };
            u.recovery.remove(i);
            u.last_login = t;
            s.put_user(&u)?;
            Ok(Some(u))
        })
        .await
        .map_err(internal)?;
    let Some(user) = used else {
        audit(&app, &c.user.name, &ip, "mfa.fail", "recovery code").await;
        return Ok(Html(mfa_html(
            &c,
            Flash::Err("That recovery code is not valid or was already used."),
        ))
        .into_response());
    };
    let stage = if user.must_change {
        Stage::Setup
    } else {
        Stage::Full
    };
    let ck = new_session(&app, &user.name, stage, &ip, ua(&h), Some(c.key))
        .await
        .map_err(internal)?;
    audit(
        &app,
        &user.name,
        &ip,
        "login.ok",
        &format!("recovery code, {} left", user.recovery.len()),
    )
    .await;
    Ok((
        [ck],
        redirect(if stage == Stage::Full {
            "/?ok=recovery"
        } else {
            next_setup(&user)
        }),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_and_query_encoding() {
        assert_eq!(csv_cell("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_cell("=cmd()"), "\"'=cmd()\"");
        assert_eq!(csv_cell("-1"), "\"'-1\"");
        assert_eq!(qenc("a b&c=<"), "a%20b%26c%3D%3C");
        let q = AuditQ {
            q: Some("x y".into()),
            cat: Some("login".into()),
            who: None,
            page: None,
        };
        assert_eq!(q.query_string(Some(2)), "?q=x%20y&amp;cat=login&amp;page=2");
        assert_eq!(category("login.fail"), "login");
    }
}
