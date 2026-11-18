//! Databases screen: table browser + SQL console over the embedded workspace engine.
//! Operators read, admins also write; every run and every browse is audited.

use super::*;
use crate::sqlws::{self, Kind, Outcome, SqlShared};

const BROWSE_PAGE: usize = 50;
const COUNT_CAP: usize = 100_000;

fn ws(app: &App) -> Result<&SqlShared, Response> {
    app.sql.as_ref().ok_or_else(|| {
        err_page(
            StatusCode::SERVICE_UNAVAILABLE,
            "The SQL workspace could not be opened. See the dashboard log.",
        )
    })
}

/// Cell as HTML: NULL as a muted pill, long values clipped with the full text in a tooltip.
fn cell(v: Option<String>) -> String {
    match v {
        None => r#"<span class="null">NULL</span>"#.into(),
        Some(s) if s.chars().count() > 120 => format!(
            r#"<span title="{}">{}…</span>"#,
            esc(&clip(&s, 2000)),
            esc(&clip(&s, 120))
        ),
        Some(s) => esc(&s),
    }
}

fn result_table(q: &novadb_sql::QueryResult) -> String {
    let head: String = q
        .columns
        .iter()
        .map(|c| format!("<th>{}</th>", esc(&c.name)))
        .collect();
    let body: String = (0..q.rows.len())
        .map(|i| {
            let tds: String = (0..q.columns.len())
                .map(|c| format!("<td>{}</td>", cell(q.text(i, c))))
                .collect();
            format!("<tr>{tds}</tr>")
        })
        .collect();
    let body = if body.is_empty() {
        format!(
            r#"<tr><td colspan="{}"><div class="empty">Empty set</div></td></tr>"#,
            q.columns.len().max(1)
        )
    } else {
        body
    };
    format!(
        r#"<div class="tbl rs"><table class="data"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"#
    )
}

fn outcome_card(o: &Outcome) -> String {
    let ms = format!("{:.2} ms", o.micros as f64 / 1000.0);
    match &o.result {
        Err(e) => format!(
            r#"<div class="card res err"><div class="card-h">{}<code class="stmt">{}</code><span class="r badge bad">Error</span></div><div class="card-b"><p class="sqlerr">{}</p></div></div>"#,
            html::icon("x"),
            esc(&clip(&o.sql, 300)),
            esc(e)
        ),
        Ok(q) if q.is_rows() => format!(
            r#"<div class="card res"><div class="card-h">{}<code class="stmt">{}</code><span class="r hint">{} row{} · {ms}</span></div>{}{}</div>"#,
            html::icon("check"),
            esc(&clip(&o.sql, 300)),
            q.rows.len(),
            if q.rows.len() == 1 { "" } else { "s" },
            result_table(q),
            if o.truncated {
                format!(
                    r#"<div class="card-f">Showing the first {} rows. Add a LIMIT, or export to CSV for everything shown here.</div>"#,
                    sqlws::MAX_ROWS
                )
            } else {
                String::new()
            }
        ),
        Ok(q) => format!(
            r#"<div class="card res"><div class="card-h">{}<code class="stmt">{}</code><span class="r hint">{ms}</span></div><div class="card-b ok-line">Query OK, {} row{} affected{}{}</div></div>"#,
            html::icon("check"),
            esc(&clip(&o.sql, 300)),
            q.affected,
            if q.affected == 1 { "" } else { "s" },
            if q.last_insert_id > 0 {
                format!(" · last insert id {}", q.last_insert_id)
            } else {
                String::new()
            },
            q.info
                .as_deref()
                .map(|i| format!(" · {}", esc(i)))
                .unwrap_or_default()
        ),
    }
}

struct TableInfo {
    name: String,
    cols: usize,
    rows: usize,
}

/// Tables with column + (capped) row counts.
async fn table_list(sql: &SqlShared) -> Result<Vec<TableInfo>, String> {
    sql.run(|e, s| {
        let st = novadb_sql::parse("SHOW TABLES").map_err(|x| x.to_string())?;
        let names = e.run_in(&st[0], s).map_err(|x| x.to_string())?;
        let mut out = Vec::new();
        for i in 0..names.rows.len().min(200) {
            let Some(n) = names.text(i, 0) else { continue };
            if !sqlws::plain_ident(&n) {
                out.push(TableInfo {
                    name: n,
                    cols: 0,
                    rows: 0,
                });
                continue;
            }
            let run = |e: &mut novadb_sql::Engine, s: &mut novadb_sql::Session, q: &str| {
                novadb_sql::parse(q)
                    .map_err(|x| x.to_string())
                    .and_then(|v| e.run_in(&v[0], s).map_err(|x| x.to_string()))
            };
            let cols = run(e, s, &format!("DESCRIBE `{n}`"))?.rows.len();
            let rows = run(
                e,
                s,
                &format!("SELECT * FROM `{n}` LIMIT {}", COUNT_CAP + 1),
            )?
            .rows
            .len();
            out.push(TableInfo {
                name: n,
                cols,
                rows,
            });
        }
        Ok(out)
    })
    .await
}

fn count_txt(n: usize) -> String {
    if n > COUNT_CAP {
        format!("{}k+", COUNT_CAP / 1000)
    } else {
        n.to_string()
    }
}

#[derive(serde::Deserialize, Default)]
pub(super) struct DbQ {
    sql: Option<String>,
}

pub(super) async fn databases_page(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Query(q): Query<DbQ>,
) -> Res {
    let c = guard(&app, &h, client_ip(&app, &peer, &h), Role::Operator).await?;
    let pre = clip(q.sql.as_deref().unwrap_or(""), sqlws::MAX_SQL);
    db_render(&app, &c, Flash::None, &pre, None).await
}

async fn db_render(
    app: &App,
    c: &Ctx,
    flash: Flash<'_>,
    sql_text: &str,
    outcomes: Option<&[Outcome]>,
) -> Res {
    let sql = ws(app)?;
    let tables = table_list(sql).await.map_err(internal)?;
    let name = c.user.name.clone();
    let recent = app
        .store
        .run(move |s| {
            Ok(s.audit_all()?
                .into_iter()
                .filter(|e| e.actor == name && (e.action == "sql.read" || e.action == "sql.write"))
                .take(8)
                .collect::<Vec<_>>())
        })
        .await
        .map_err(internal)?;
    let admin = c.user.role >= Role::Admin;
    let t_rows: String = tables
        .iter()
        .map(|t| {
            let link = if sqlws::plain_ident(&t.name) {
                format!(
                    r#"<a href="/databases/t/{0}">{1}{0}</a>"#,
                    esc(&t.name),
                    html::icon("table")
                )
            } else {
                esc(&t.name)
            };
            format!(
                r#"<li>{link}<span class="hint">{} col · {} rows</span></li>"#,
                t.cols,
                count_txt(t.rows)
            )
        })
        .collect();
    let tables_html = if tables.is_empty() {
        let demo = if admin {
            format!(
                r#"<form method="post" action="/databases/demo">{}<button class="ghost sm">Create demo tables</button></form>"#,
                csrf(&c.sess.csrf)
            )
        } else {
            String::new()
        };
        format!(
            r#"<div class="empty">No tables yet.<br><span class="hint">Create one with <code>CREATE TABLE</code>.</span>{demo}</div>"#
        )
    } else {
        format!(r#"<ul class="tlist">{t_rows}</ul>"#)
    };
    let snippets: String = [
        ("Show tables", "SHOW TABLES"),
        ("Server version", "SELECT VERSION(), NOW()"),
        (
            "New table",
            "CREATE TABLE notes (\n  id INT PRIMARY KEY AUTO_INCREMENT,\n  body TEXT NOT NULL,\n  created_at DATETIME DEFAULT CURRENT_TIMESTAMP\n)",
        ),
    ]
    .iter()
    .filter(|(l, _)| admin || *l != "New table")
    .map(|(l, s)| {
        format!(
            r#"<a class="chip" href="/databases?sql={}">{}</a>"#,
            more::qenc(s),
            esc(l)
        )
    })
    .collect();
    let recent_html = if recent.is_empty() {
        r#"<div class="empty">Queries you run show up here.</div>"#.to_string()
    } else {
        let t = now();
        let items: String = recent
            .iter()
            .map(|e| {
                format!(
                    r#"<li><a href="/databases?sql={}" title="Load into the editor"><code>{}</code></a><span class="hint">{}</span></li>"#,
                    more::qenc(&e.detail),
                    esc(&clip(&e.detail, 90)),
                    html::ago(t, e.ts)
                )
            })
            .collect();
        format!(r#"<ul class="qlist">{items}</ul>"#)
    };
    let results: String = outcomes
        .map(|o| o.iter().map(outcome_card).collect())
        .unwrap_or_default();
    let body = format!(
        r#"{head}
<div class="cols cols-13">
<div><div class="card"><div class="card-h">{idb}<h2>Tables</h2><span class="r hint">{nt}</span></div>{tables_html}</div>
<div class="card"><div class="card-h">{iclock}<h2>Your recent queries</h2></div>{recent_html}</div></div>
<div><div class="card"><div class="card-h">{iterm}<h2>SQL console</h2><span class="r">{perm}</span></div>
<form method="post" action="/databases/query" class="console">{csrf}
<textarea name="sql" rows="9" spellcheck="false" autocapitalize="off" maxlength="{max}" placeholder="SELECT * FROM customers LIMIT 10;" aria-label="SQL" required autofocus>{pre}</textarea>
<div class="between"><div class="chips">{snippets}</div><div class="row"><button name="format" value="csv" class="ghost sm">{idl}CSV</button><button class="sm">{iplay}Run</button></div></div></form>
<div class="card-f">Separate statements with <code>;</code>. Each run is its own connection: an unfinished <code>BEGIN</code> is rolled back. Results show the first {maxrows} rows. Every query is written to the audit log.</div></div>
{results}</div></div>"#,
        head = html::header(
            "Databases",
            "The embedded NovaDB SQL workspace. Same engine, parser and MVCC as the server on port 3307.",
            r#"<span class="badge acc">workspace</span>"#
        ),
        idb = html::icon("database"),
        iclock = html::icon("clock"),
        iterm = html::icon("terminal"),
        idl = html::icon("download"),
        iplay = html::icon("play"),
        nt = tables.len(),
        perm = if admin {
            r#"<span class="badge ok">Read &amp; write</span>"#
        } else {
            r#"<span class="badge warn">Read only</span>"#
        },
        csrf = csrf(&c.sess.csrf),
        max = sqlws::MAX_SQL,
        maxrows = sqlws::MAX_ROWS,
        pre = esc(sql_text),
    );
    Ok(Html(html::page(
        "Databases",
        Some(&c.nav("/databases")),
        flash,
        &body,
    ))
    .into_response())
}

pub(super) async fn databases_query(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    let c = guard_post(&app, &h, ip.clone(), Role::Operator, &f).await?;
    let text = field(&f, "sql").to_string();
    if !app
        .limiter
        .hit(&format!("sql:{}", c.user.name), 60, Duration::from_secs(60))
    {
        return db_render(
            &app,
            &c,
            Flash::Err("Too many queries. Wait a minute."),
            &text,
            None,
        )
        .await;
    }
    let stmts = match sqlws::parse_script(&text) {
        Ok(v) if v.is_empty() => {
            return db_render(&app, &c, Flash::Err("Nothing to run."), &text, None).await;
        }
        Ok(v) => v,
        Err(e) => {
            return db_render(&app, &c, Flash::Err(&e), &text, None).await;
        }
    };
    let kinds: Vec<Kind> = stmts.iter().map(|(_, s)| sqlws::classify(s)).collect();
    if kinds.contains(&Kind::Forbidden) {
        audit(
            &app,
            &c.user.name,
            &ip,
            "sql.denied",
            "SQL account statement",
        )
        .await;
        return db_render(
            &app,
            &c,
            Flash::Err("SQL accounts (CREATE / ALTER / DROP USER) are managed with the server CLI, not from the dashboard."),
            "",
            None,
        )
        .await;
    }
    let writes = kinds.contains(&Kind::Write);
    if writes && c.user.role < Role::Admin {
        audit(&app, &c.user.name, &ip, "sql.denied", &clip(&text, 380)).await;
        return db_render(
            &app,
            &c,
            Flash::Err("Your role can run read-only statements (SELECT, SHOW, DESCRIBE, EXPLAIN). Ask an admin for changes."),
            &text,
            None,
        )
        .await;
    }
    audit(
        &app,
        &c.user.name,
        &ip,
        if writes { "sql.write" } else { "sql.read" },
        &clip(text.trim(), 380),
    )
    .await;
    let sql = ws(&app)?;
    let outs = sql
        .run(move |e, s| Ok(sqlws::run_all(e, s, &stmts)))
        .await
        .map_err(internal)?;
    if field(&f, "format") == "csv" {
        if let Some(q) = outs
            .iter()
            .rev()
            .find_map(|o| o.result.as_ref().ok().filter(|q| q.is_rows()))
        {
            let mut out = q
                .columns
                .iter()
                .map(|c| more::csv_cell(&c.name))
                .collect::<Vec<_>>()
                .join(",");
            out.push_str("\r\n");
            for i in 0..q.rows.len() {
                let line: Vec<String> = (0..q.columns.len())
                    .map(|c| q.text(i, c).map(|v| more::csv_cell(&v)).unwrap_or_default())
                    .collect();
                out.push_str(&line.join(","));
                out.push_str("\r\n");
            }
            let mut r = ([(header::CONTENT_TYPE, "text/csv; charset=utf-8")], out).into_response();
            let fname = format!(
                "attachment; filename=\"novadb-query-{}.csv\"",
                html::ts(now()).replace([' ', ':'], "-")
            );
            if let Ok(v) = HeaderValue::from_str(&fname) {
                r.headers_mut().insert(header::CONTENT_DISPOSITION, v);
            }
            return Ok(r);
        }
        return db_render(
            &app,
            &c,
            Flash::Err("No result set to export: the last statement must return rows."),
            &text,
            Some(&outs),
        )
        .await;
    }
    let failed = outs.iter().any(|o| o.result.is_err());
    let flash = if failed {
        Flash::Err("A statement failed; statements after it were not run.")
    } else {
        Flash::None
    };
    db_render(&app, &c, flash, &text, Some(&outs)).await
}

pub(super) async fn databases_demo(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    let c = guard_post(&app, &h, ip.clone(), Role::Admin, &f).await?;
    let sql = ws(&app)?;
    let outs = sql
        .run(|e, s| {
            let stmts = sqlws::parse_script(sqlws::DEMO_SQL)?;
            Ok(sqlws::run_all(e, s, &stmts))
        })
        .await
        .map_err(internal)?;
    audit(
        &app,
        &c.user.name,
        &ip,
        "sql.demo",
        "demo tables: customers, orders",
    )
    .await;
    if outs.iter().any(|o| o.result.is_err()) {
        return db_render(
            &app,
            &c,
            Flash::Err("Creating the demo tables failed."),
            "",
            Some(&outs),
        )
        .await;
    }
    Ok(redirect("/databases?sql=SELECT%20*%20FROM%20orders"))
}

#[derive(serde::Deserialize, Default)]
pub(super) struct PageQ {
    page: Option<usize>,
}

pub(super) async fn table_page(
    State(app): State<S>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Path(name): Path<String>,
    Query(pq): Query<PageQ>,
) -> Res {
    let ip = client_ip(&app, &peer, &h);
    let c = guard(&app, &h, ip.clone(), Role::Operator).await?;
    let sql = ws(&app)?;
    if !sqlws::plain_ident(&name) {
        return Err(err_page(StatusCode::NOT_FOUND, "No such table."));
    }
    let page = pq.page.unwrap_or(1).clamp(1, 1_000_000);
    let n2 = name.clone();
    let got = sql
        .run(move |e, s| {
            let run = |e: &mut novadb_sql::Engine, s: &mut novadb_sql::Session, q: &str| {
                novadb_sql::parse(q)
                    .map_err(|x| x.to_string())
                    .and_then(|v| e.run_in(&v[0], s).map_err(|x| x.to_string()))
            };
            let tables = run(e, s, "SHOW TABLES")?;
            let Some(real) = (0..tables.rows.len())
                .filter_map(|i| tables.text(i, 0))
                .find(|t| t.eq_ignore_ascii_case(&n2))
            else {
                return Ok(None);
            };
            let desc = run(e, s, &format!("DESCRIBE `{real}`"))?;
            let create = run(e, s, &format!("SHOW CREATE TABLE `{real}`"))?;
            let rows = run(
                e,
                s,
                &format!(
                    "SELECT * FROM `{real}` LIMIT {} OFFSET {}",
                    BROWSE_PAGE + 1,
                    (page - 1) * BROWSE_PAGE
                ),
            )?;
            Ok(Some((real, desc, create, rows)))
        })
        .await
        .map_err(internal)?;
    let Some((real, desc, create, mut rows)) = got else {
        return Err(err_page(StatusCode::NOT_FOUND, "No such table."));
    };
    audit(
        &app,
        &c.user.name,
        &ip,
        "sql.browse",
        &format!("{real} page {page}"),
    )
    .await;
    let more_rows = rows.rows.len() > BROWSE_PAGE;
    rows.rows.truncate(BROWSE_PAGE);
    let create_sql = create.text(0, 1).unwrap_or_default();
    let pager = format!(
        r#"<div class="pager"><span class="hint">Page {page} · rows {} – {}</span><span class="row">{}{}</span></div>"#,
        if rows.rows.is_empty() {
            0
        } else {
            (page - 1) * BROWSE_PAGE + 1
        },
        (page - 1) * BROWSE_PAGE + rows.rows.len(),
        if page > 1 {
            format!(
                r#"<a class="btn ghost sm" href="/databases/t/{}?page={}">&larr; Previous</a>"#,
                esc(&real),
                page - 1
            )
        } else {
            r#"<span class="btn ghost sm dis">&larr; Previous</span>"#.into()
        },
        if more_rows {
            format!(
                r#"<a class="btn ghost sm" href="/databases/t/{}?page={}">Next &rarr;</a>"#,
                esc(&real),
                page + 1
            )
        } else {
            r#"<span class="btn ghost sm dis">Next &rarr;</span>"#.into()
        },
    );
    let body = format!(
        r#"<p class="crumbs"><a href="/databases">&larr; Databases</a></p>{head}
<div class="card"><div class="card-h">{itab}<h2>Rows</h2><span class="r hint">{nc} columns</span></div>{rows_html}<div class="card-f between"><span></span>{pager}</div></div>
<div class="cols">
<div class="card"><div class="card-h">{ilist}<h2>Structure</h2></div>{desc_html}</div>
<div class="card"><div class="card-h">{icode}<h2>CREATE statement</h2></div><pre class="ddl"><code>{ddl}</code></pre></div></div>"#,
        head = html::header(
            &real,
            "Browse rows, structure and definition.",
            &format!(
                r#"<a class="btn ghost" href="/databases?sql={}">{}Query this table</a>"#,
                more::qenc(&format!("SELECT * FROM {real} LIMIT 100")),
                html::icon("terminal")
            )
        ),
        itab = html::icon("table"),
        ilist = html::icon("list"),
        icode = html::icon("code"),
        nc = desc.rows.len(),
        rows_html = result_table(&rows),
        desc_html = result_table(&desc),
        ddl = esc(&create_sql),
    );
    Ok(Html(html::page(
        &real,
        Some(&c.nav("/databases")),
        Flash::None,
        &body,
    ))
    .into_response())
}
