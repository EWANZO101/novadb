//! Backups screen (admin): logical dumps of the SQL workspace, automatic daily backups,
//! download, verify, delete and restore (password + typed confirmation, safety backup first,
//! automatic roll-back if the restore fails).
//!
//! The dashboard's own system database (password hashes, TOTP secrets) is never offered for
//! download.

use std::sync::Arc;

use super::*;
use crate::backup::{self, BackupKind, Backups};
use crate::sqlws::{self, DumpInfo};

fn store(app: &App) -> Result<(&crate::sqlws::SqlShared, Arc<Backups>), Response> {
    match (&app.sql, &app.backups) {
        (Some(s), Some(b)) => Ok((s, b.clone())),
        _ => Err(err_page(
            StatusCode::SERVICE_UNAVAILABLE,
            "Backups are unavailable: the SQL workspace or backup folder could not be opened.",
        )),
    }
}

/// Dump the workspace and write a backup file (SQL lock held for both: consistent with restores).
pub(super) async fn take(app: &App, kind: BackupKind) -> Result<(String, DumpInfo), String> {
    let (Some(sql), Some(bk)) = (&app.sql, &app.backups) else {
        return Err("backups unavailable".into());
    };
    let bk = bk.clone();
    let t = now();
    sql.run(move |e, s| {
        let (body, info) = sqlws::dump(e, s)?;
        let name = bk.write(kind, t, &body, info)?;
        Ok((name, info))
    })
    .await
}

/// Background job: take an automatic backup when the last one is older than a day.
pub async fn auto_tick(app: &App) {
    let Some(bk) = app.backups.clone() else {
        return;
    };
    let last = tokio::task::spawn_blocking({
        let bk = bk.clone();
        move || bk.last_auto()
    })
    .await
    .unwrap_or(0);
    if now().saturating_sub(last) < backup::AUTO_EVERY {
        return;
    }
    match take(app, BackupKind::Auto).await {
        Ok((name, info)) => {
            let pruned = tokio::task::spawn_blocking(move || bk.prune_auto(backup::KEEP_AUTO))
                .await
                .map_err(|e| e.to_string())
                .and_then(|r| r);
            audit(
                app,
                "system",
                "-",
                "backup.auto",
                &format!(
                    "{name}: {} tables, {} rows; pruned {}",
                    info.tables,
                    info.rows,
                    pruned.unwrap_or(0)
                ),
            )
            .await;
        }
        Err(e) => {
            eprintln!("[dashboard] automatic backup failed: {e}");
            audit(app, "system", "-", "backup.auto_failed", &clip(&e, 200)).await;
        }
    }
}

pub(super) async fn backups_page(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Query(q): Query<MsgQuery>,
) -> Res {
    let c = guard(&app, &h, client_ip(&app, &peer, &h), Role::Admin).await?;
    render(&app, &c, flash_of(&q)).await
}

async fn render(app: &App, c: &Ctx, flash: Flash<'_>) -> Res {
    let (_, bk) = store(app)?;
    let list = tokio::task::spawn_blocking(move || bk.list())
        .await
        .map_err(|e| internal(e.to_string()))?
        .map_err(internal)?;
    let t = now();
    let total: u64 = list.iter().map(|e| e.size).sum();
    let last_auto = list
        .iter()
        .find(|e| e.kind == BackupKind::Auto)
        .map(|e| e.created)
        .unwrap_or(0);
    let next = if last_auto == 0 {
        "within the hour".to_string()
    } else {
        let due = last_auto + backup::AUTO_EVERY;
        if due <= t {
            "within the hour".into()
        } else {
            let left = due - t;
            format!("in {}h {}m", left / 3600, (left % 3600) / 60)
        }
    };
    let tok = csrf(&c.sess.csrf);
    let rows: String = list
        .iter()
        .map(|e| {
            let kind_cls = match e.kind {
                BackupKind::Auto => "",
                BackupKind::Manual => "ok",
                BackupKind::PreRestore => "warn",
            };
            let n = esc(&e.name);
            format!(
                r#"<tr><td class="mono">{n}</td><td><span class="pill {kind_cls}">{kind}</span></td><td class="nw" title="{full} UTC">{ago}</td><td class="num">{tables} tables · {rows} rows</td><td class="num nw">{size}</td><td class="r"><div class="row end">
<a class="btn ghost sm" href="/backups/download/{n}" title="Download">{idl}</a>
<details class="menu"><summary title="More" aria-label="More actions for {n}">{imore}</summary><div class="pop">
<form method="post" action="/backups/verify">{tok}<input type="hidden" name="name" value="{n}"><button>Verify checksum</button></form>
<form method="get" action="/backups/restore/{n}"><button>Restore…</button></form><hr>
<form method="post" action="/backups/delete">{tok}<input type="hidden" name="name" value="{n}"><button class="danger">Delete</button></form>
</div></details></div></td></tr>"#,
                kind = e.kind.label(),
                full = html::ts(e.created),
                ago = html::ago(t, e.created),
                tables = e.info.tables,
                rows = e.info.rows,
                size = html::bytes(e.size),
                idl = html::icon("download"),
                imore = html::icon("more"),
            )
        })
        .collect();
    let rows = if rows.is_empty() {
        r#"<tr><td colspan="6"><div class="empty">No backups yet. Take the first one with <b>Back up now</b>.</div></td></tr>"#.to_string()
    } else {
        rows
    };
    let kpi = |ic: &str, label: &str, value: String, note: &str| {
        format!(
            r#"<div class="kpi"><div class="kpi-h"><span>{label}</span><span class="ic">{}</span></div><b>{value}</b><small>{note}</small></div>"#,
            html::icon(ic)
        )
    };
    let body = format!(
        r#"{head}
<div class="kpis">{k1}{k2}{k3}{k4}</div>
<div class="card menus"><div class="card-h">{iar}<h2>Workspace backups</h2><span class="r hint">newest first</span></div>
<div class="tbl stack"><table><thead><tr><th>File</th><th>Type</th><th>Created</th><th>Contents</th><th>Size</th><th class="r">Actions</th></tr></thead><tbody>{rows}</tbody></table></div>
<div class="card-f">Logical SQL dumps taken from one consistent snapshot. Each ends with a SHA-256 line that is checked before any restore. The newest {keep} automatic backups are kept; manual ones stay until you delete them.</div></div>
<div class="card"><div class="card-h">{ilock}<h2>What is not in here</h2></div><div class="card-b"><p class="sub">The dashboard's own system database (accounts, password hashes, 2FA secrets, audit log) is deliberately not downloadable. Back up the <code>novadb-dash-data</code> Docker volume on the server for that.</p></div></div>"#,
        head = html::header(
            "Backups",
            "Point-in-time copies of the SQL workspace. Restore replaces every table.",
            &format!(
                r#"<form method="post" action="/backups/create">{tok}<button>{}Back up now</button></form>"#,
                html::icon("archive")
            )
        ),
        k1 = kpi(
            "archive",
            "Backups",
            list.len().to_string(),
            "stored on the server"
        ),
        k2 = kpi(
            "clock",
            "Latest",
            list.first()
                .map(|e| html::ago(t, e.created))
                .unwrap_or_else(|| "never".into()),
            "most recent of any type"
        ),
        k3 = kpi("zap", "Next automatic", next, "once a day"),
        k4 = kpi(
            "drive",
            "Space used",
            html::bytes(total),
            &format!("max {} files", backup::MAX_FILES)
        ),
        iar = html::icon("archive"),
        ilock = html::icon("lock"),
        keep = backup::KEEP_AUTO,
    );
    Ok(Html(html::page(
        "Backups",
        Some(&c.nav("/backups")),
        flash,
        &body,
    ))
    .into_response())
}

pub(super) async fn backups_create(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    let c = guard_post(&app, &h, ip.clone(), Role::Admin, &f).await?;
    store(&app)?;
    if !app
        .limiter
        .hit("backup:create", 10, Duration::from_secs(600))
    {
        return render(
            &app,
            &c,
            Flash::Err("Too many backups in a short time. Try again in a few minutes."),
        )
        .await;
    }
    match take(&app, BackupKind::Manual).await {
        Ok((name, info)) => {
            audit(
                &app,
                &c.user.name,
                &ip,
                "backup.created",
                &format!("{name}: {} tables, {} rows", info.tables, info.rows),
            )
            .await;
            render(
                &app,
                &c,
                Flash::Ok(&format!(
                    "Backup created: {} tables, {} rows.",
                    info.tables, info.rows
                )),
            )
            .await
        }
        Err(e) => render(&app, &c, Flash::Err(&format!("Backup failed: {e}"))).await,
    }
}

pub(super) async fn backups_download(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Path(name): Path<String>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    let c = guard(&app, &h, ip.clone(), Role::Admin).await?;
    let (_, bk) = store(&app)?;
    if !backup::name_ok(&name) {
        return Err(err_page(StatusCode::NOT_FOUND, "No such backup."));
    }
    let n2 = name.clone();
    let Ok(Ok(content)) = tokio::task::spawn_blocking(move || bk.read(&n2)).await else {
        return Err(err_page(StatusCode::NOT_FOUND, "No such backup."));
    };
    audit(&app, &c.user.name, &ip, "backup.downloaded", &name).await;
    let mut r = (
        [(header::CONTENT_TYPE, "application/sql; charset=utf-8")],
        content,
    )
        .into_response();
    // name_ok guarantees a plain ASCII file name.
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")) {
        r.headers_mut().insert(header::CONTENT_DISPOSITION, v);
    }
    Ok(r)
}

pub(super) async fn backups_verify(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    let c = guard_post(&app, &h, ip.clone(), Role::Admin, &f).await?;
    let (_, bk) = store(&app)?;
    let name = field(&f, "name").to_string();
    let n2 = name.clone();
    let res = tokio::task::spawn_blocking(move || bk.read(&n2).and_then(|c| backup::verify(&c)))
        .await
        .map_err(|e| internal(e.to_string()))?;
    match res {
        Ok(n) => {
            audit(&app, &c.user.name, &ip, "backup.verified", &name).await;
            render(
                &app,
                &c,
                Flash::Ok(&format!(
                    "{name}: checksum OK, {n} SQL statements parse cleanly."
                )),
            )
            .await
        }
        Err(e) => {
            audit(
                &app,
                &c.user.name,
                &ip,
                "backup.verify_failed",
                &format!("{name}: {e}"),
            )
            .await;
            render(&app, &c, Flash::Err(&format!("{name}: {e}"))).await
        }
    }
}

pub(super) async fn backups_delete(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    let c = guard_post(&app, &h, ip.clone(), Role::Admin, &f).await?;
    let (_, bk) = store(&app)?;
    let name = field(&f, "name").to_string();
    let n2 = name.clone();
    let res = tokio::task::spawn_blocking(move || bk.delete(&n2))
        .await
        .map_err(|e| internal(e.to_string()))?;
    match res {
        Ok(()) => {
            audit(&app, &c.user.name, &ip, "backup.deleted", &name).await;
            render(&app, &c, Flash::Ok("Backup deleted.")).await
        }
        Err(_) => render(&app, &c, Flash::Err("That backup does not exist.")).await,
    }
}

fn confirm_html(c: &Ctx, name: &str, info: &str, flash: Flash<'_>) -> String {
    let body = format!(
        r#"<p class="crumbs"><a href="/backups">&larr; Backups</a></p>{head}
<div class="card danger-zone"><div class="card-h">{ialert}<h2>This replaces the whole workspace</h2></div><div class="card-b">
<p class="sub">Every current table is dropped and the tables from <code>{n}</code> ({info}) are loaded. A safety backup of the current state is taken first, and if loading fails the workspace is put back automatically.</p>
<form method="post" action="/backups/restore" class="formgrid narrow">{tok}<input type="hidden" name="name" value="{n}">
<label for="pw">Your password</label><input id="pw" type="password" name="current" autocomplete="current-password" required maxlength="128">
<label for="cf">Type <b>RESTORE</b> to confirm</label><input id="cf" type="text" name="confirm" autocomplete="off" required maxlength="16" placeholder="RESTORE">
<div class="row"><button class="danger-solid">Restore this backup</button><a class="btn ghost" href="/backups">Cancel</a></div></form></div></div>"#,
        head = html::header(
            "Restore backup",
            "Check the file name before you continue.",
            ""
        ),
        ialert = html::icon("alert"),
        n = esc(name),
        info = esc(info),
        tok = csrf(&c.sess.csrf),
    );
    html::page("Restore backup", Some(&c.nav("/backups")), flash, &body)
}

pub(super) async fn backups_restore_page(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Path(name): Path<String>,
) -> Res {
    let c = guard(&app, &h, client_ip(&app, &peer, &h), Role::Admin).await?;
    let (_, bk) = store(&app)?;
    let n2 = name.clone();
    let entry = tokio::task::spawn_blocking(move || {
        bk.list().map(|l| l.into_iter().find(|e| e.name == n2))
    })
    .await
    .map_err(|e| internal(e.to_string()))?
    .map_err(internal)?;
    let Some(e) = entry else {
        return Err(err_page(StatusCode::NOT_FOUND, "No such backup."));
    };
    let info = format!(
        "{} tables, {} rows, taken {} UTC",
        e.info.tables,
        e.info.rows,
        html::ts(e.created)
    );
    Ok(Html(confirm_html(&c, &name, &info, Flash::None)).into_response())
}

pub(super) async fn backups_restore(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    let c = guard_post(&app, &h, ip.clone(), Role::Admin, &f).await?;
    let (sql, bk) = store(&app)?;
    let name = field(&f, "name").to_string();
    if !backup::name_ok(&name) {
        return Err(err_page(StatusCode::NOT_FOUND, "No such backup."));
    }
    let again = |msg: &str| {
        Html(confirm_html(
            &c,
            &name,
            "see the backup list",
            Flash::Err(msg),
        ))
        .into_response()
    };
    if !app.limiter.hit(
        &format!("restore:{}", c.user.name),
        5,
        Duration::from_secs(600),
    ) {
        return Ok(again("Too many restore attempts. Wait a few minutes."));
    }
    if field(&f, "confirm") != "RESTORE" {
        return Ok(again("Type RESTORE (capital letters) to confirm."));
    }
    let pw_ok = verify_pw(
        &app,
        field(&f, "current").to_string(),
        Some(c.user.pw.clone()),
    )
    .await
    .map_err(internal)?;
    if !pw_ok {
        audit(
            &app,
            &c.user.name,
            &ip,
            "backup.restore_denied",
            &format!("{name}: wrong password"),
        )
        .await;
        return Ok(again("Wrong password."));
    }
    let t = now();
    let n2 = name.clone();
    let res = sql
        .run(move |e, s| {
            let content = bk.read(&n2)?;
            backup::verify(&content)?;
            // Safety net first.
            let (cur, cur_info) = sqlws::dump(e, s)?;
            let safety = bk.write(BackupKind::PreRestore, t, &cur, cur_info)?;
            match sqlws::load(e, s, &content) {
                Ok(n) => Ok((safety, n)),
                Err(err) => {
                    let back = sqlws::load(e, s, &cur);
                    Err(match back {
                        Ok(_) => format!("{err}. The workspace was put back as it was (safety backup {safety})."),
                        Err(e2) => format!("{err}. Putting the old state back ALSO failed ({e2}); restore {safety} manually."),
                    })
                }
            }
        })
        .await;
    match res {
        Ok((safety, n)) => {
            audit(
                &app,
                &c.user.name,
                &ip,
                "backup.restored",
                &format!("{name} ({n} statements); safety backup {safety}"),
            )
            .await;
            render(
                &app,
                &c,
                Flash::Ok(&format!(
                    "Restored {name}. The previous state was saved as {safety}."
                )),
            )
            .await
        }
        Err(e) => {
            audit(
                &app,
                &c.user.name,
                &ip,
                "backup.restore_failed",
                &format!("{name}: {}", clip(&e, 300)),
            )
            .await;
            render(&app, &c, Flash::Err(&format!("Restore failed: {e}"))).await
        }
    }
}
