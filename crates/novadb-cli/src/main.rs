//! `novadb` — developer CLI: SQL (Stage 3) plus raw storage-engine commands (Stage 2).
#![forbid(unsafe_code)]

use novadb_storage::{Db, Options};
use std::io::Write;
use std::ops::Bound;
use std::process::ExitCode;

const USAGE: &str = "usage:
  novadb DIR sql \"STATEMENTS\"      run SQL (several statements separated by ;)
  novadb DIR shell                 interactive SQL (reads stdin; end statements with ;)
  novadb DIR put TREE KEY VALUE
  novadb DIR get TREE KEY
  novadb DIR del TREE KEY
  novadb DIR scan TREE [START [END]]
  novadb DIR trees
  novadb DIR drop TREE
  novadb DIR verify
  novadb DIR stats";

fn run(args: &[String]) -> Result<(), String> {
    let [dir, cmd, rest @ ..] = args else {
        return Err(USAGE.into());
    };
    match (cmd.as_str(), rest) {
        ("sql", [stmts]) => return sql_once(dir, stmts),
        ("shell", []) => return sql_shell(dir),
        _ => {}
    }
    let mut db = Db::open(dir, Options::default()).map_err(|e| e.to_string())?;
    let e = |e: novadb_storage::Error| e.to_string();
    let mut out = std::io::stdout().lock();
    let w = |out: &mut std::io::StdoutLock<'_>, s: String| {
        writeln!(out, "{s}").map_err(|e| e.to_string())
    };
    match (cmd.as_str(), rest) {
        ("put", [t, k, v]) => {
            db.update(|tx| {
                let t = tx.open_or_create_tree(t)?;
                tx.put(&t, k.as_bytes(), v.as_bytes())
            })
            .map_err(e)?;
        }
        ("get", [t, k]) => {
            let v = db.view(|tx| {
                let t = tx.open_tree(t)?;
                tx.get(&t, k.as_bytes())
            });
            match v.map_err(e)? {
                Some(v) => w(&mut out, String::from_utf8_lossy(&v).into_owned())?,
                None => return Err("not found".into()),
            }
        }
        ("del", [t, k]) => {
            db.update(|tx| {
                let t = tx.open_tree(t)?;
                tx.delete(&t, k.as_bytes())
            })
            .map_err(e)?;
        }
        ("scan", [t, bounds @ ..]) if bounds.len() <= 2 => {
            let rows = db
                .view(|tx| {
                    let t = tx.open_tree(t)?;
                    let start = bounds
                        .first()
                        .map(|s| s.as_bytes().to_vec())
                        .unwrap_or_default();
                    let end = match bounds.get(1) {
                        Some(e) => Bound::Excluded(e.as_bytes()),
                        None => Bound::Unbounded,
                    };
                    tx.range(&t, (Bound::Included(start.as_slice()), end))?
                        .collect::<novadb_storage::Result<Vec<_>>>()
                })
                .map_err(e)?;
            for (k, v) in rows {
                w(
                    &mut out,
                    format!(
                        "{}\t{}",
                        String::from_utf8_lossy(&k),
                        String::from_utf8_lossy(&v)
                    ),
                )?;
            }
        }
        ("trees", []) => {
            for t in db.view(|tx| tx.list_trees()).map_err(e)? {
                w(&mut out, t)?;
            }
        }
        ("drop", [t]) => db.update(|tx| tx.drop_tree(t)).map_err(e)?,
        ("verify", []) => {
            let r = db.verify().map_err(e)?;
            w(&mut out, format!("ok: {r:?}"))?;
        }
        ("stats", []) => w(&mut out, format!("{:?}", db.stats()))?,
        _ => return Err(USAGE.into()),
    }
    db.close().map_err(e)
}

/// Render a result like the mysql client.
fn print_result(r: &novadb_sql::QueryResult, out: &mut impl Write) -> std::io::Result<()> {
    if !r.is_rows() {
        writeln!(out, "Query OK, {} row(s) affected", r.affected)?;
        if r.last_insert_id > 0 {
            writeln!(out, "last insert id: {}", r.last_insert_id)?;
        }
        if let Some(i) = &r.info {
            writeln!(out, "{i}")?;
        }
        return Ok(());
    }
    let cells: Vec<Vec<String>> = (0..r.rows.len())
        .map(|i| {
            (0..r.columns.len())
                .map(|c| {
                    r.text(i, c)
                        .unwrap_or_else(|| "NULL".into())
                        .replace('\n', "\\n")
                })
                .collect()
        })
        .collect();
    let mut w: Vec<usize> = r.columns.iter().map(|c| c.name.chars().count()).collect();
    for row in &cells {
        for (i, c) in row.iter().enumerate() {
            w[i] = w[i].max(c.chars().count()).min(80);
        }
    }
    let line = format!(
        "+{}+",
        w.iter()
            .map(|n| "-".repeat(n + 2))
            .collect::<Vec<_>>()
            .join("+")
    );
    let fmt_row = |vals: &[String]| {
        let parts: Vec<String> = vals
            .iter()
            .zip(&w)
            .map(|(v, n)| {
                let v: String = v.chars().take(*n).collect();
                format!(" {v}{} ", " ".repeat(n - v.chars().count()))
            })
            .collect();
        format!("|{}|", parts.join("|"))
    };
    writeln!(out, "{line}")?;
    writeln!(
        out,
        "{}",
        fmt_row(&r.columns.iter().map(|c| c.name.clone()).collect::<Vec<_>>())
    )?;
    writeln!(out, "{line}")?;
    for row in &cells {
        writeln!(out, "{}", fmt_row(row))?;
    }
    if !cells.is_empty() {
        writeln!(out, "{line}")?;
    }
    writeln!(out, "{} row(s) in set", cells.len())
}

fn sql_once(dir: &str, stmts: &str) -> Result<(), String> {
    let mut db = novadb_sql::Engine::open(dir).map_err(|e| e.to_string())?;
    let mut out = std::io::stdout().lock();
    let res = (|| {
        for stmt in novadb_sql::parse(stmts).map_err(|e| e.to_string())? {
            let r = db.run(&stmt).map_err(|e| e.to_string())?;
            print_result(&r, &mut out).map_err(|e| e.to_string())?;
        }
        Ok(())
    })();
    db.close().map_err(|e| e.to_string())?;
    res
}

fn sql_shell(dir: &str) -> Result<(), String> {
    use std::io::BufRead;
    let mut db = novadb_sql::Engine::open(dir).map_err(|e| e.to_string())?;
    let mut out = std::io::stdout().lock();
    let mut buf = String::new();
    let _ = write!(out, "novadb> ");
    let _ = out.flush();
    for line in std::io::stdin().lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        let t = line.trim();
        if buf.is_empty()
            && (t.eq_ignore_ascii_case("exit") || t.eq_ignore_ascii_case("quit") || t == "\\q")
        {
            break;
        }
        buf.push_str(&line);
        buf.push('\n');
        if t.ends_with(';') {
            match novadb_sql::parse(&buf) {
                Err(e) => {
                    let _ = writeln!(out, "{e}");
                }
                Ok(stmts) => {
                    for s in stmts {
                        match db.run(&s) {
                            Ok(r) => print_result(&r, &mut out).map_err(|e| e.to_string())?,
                            Err(e) => {
                                let _ = writeln!(out, "{e}");
                            }
                        }
                    }
                }
            }
            buf.clear();
            let _ = write!(out, "novadb> ");
        } else {
            let _ = write!(out, "     -> ");
        }
        let _ = out.flush();
    }
    let _ = writeln!(out);
    db.close().map_err(|e| e.to_string())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(m) => {
            eprintln!("{m}");
            ExitCode::FAILURE
        }
    }
}
