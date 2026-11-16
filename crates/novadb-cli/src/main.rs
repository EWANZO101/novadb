//! `novadb` — developer CLI for the storage engine (Stage 2). SQL shell arrives later.
#![forbid(unsafe_code)]

use novadb_storage::{Db, Options};
use std::io::Write;
use std::ops::Bound;
use std::process::ExitCode;

const USAGE: &str = "usage:
  novadb DIR put TREE KEY VALUE
  novadb DIR get TREE KEY
  novadb DIR del TREE KEY
  novadb DIR scan TREE [START [END]]
  novadb DIR trees
  novadb DIR drop TREE
  novadb DIR verify
  novadb DIR stats";

fn run(args: &[String]) -> Result<(), String> {
    let [dir, cmd, rest @ ..] = args else { return Err(USAGE.into()) };
    let mut db = Db::open(dir, Options::default()).map_err(|e| e.to_string())?;
    let e = |e: novadb_storage::Error| e.to_string();
    let mut out = std::io::stdout().lock();
    let w = |out: &mut std::io::StdoutLock<'_>, s: String| writeln!(out, "{s}").map_err(|e| e.to_string());
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
                    let start = bounds.first().map(|s| s.as_bytes().to_vec()).unwrap_or_default();
                    let end = match bounds.get(1) {
                        Some(e) => Bound::Excluded(e.as_bytes()),
                        None => Bound::Unbounded,
                    };
                    tx.range(&t, (Bound::Included(start.as_slice()), end))?
                        .collect::<novadb_storage::Result<Vec<_>>>()
                })
                .map_err(e)?;
            for (k, v) in rows {
                w(&mut out, format!("{}\t{}", String::from_utf8_lossy(&k), String::from_utf8_lossy(&v)))?;
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
