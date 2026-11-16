//! `novadb-server` — Stage 1 placeholder. Opens (and recovers) the storage engine and exits.
//! Networking arrives in Stage 4; it will bind `novadb_protocol::DEFAULT_LISTEN` (127.0.0.1:3307).
#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mut dir = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--data-dir" => dir = args.next(),
            "--version" => {
                println!("novadb-server {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            _ => {
                eprintln!("usage: novadb-server --data-dir DIR | --version");
                return ExitCode::from(2);
            }
        }
    }
    let Some(dir) = dir else {
        eprintln!("usage: novadb-server --data-dir DIR | --version");
        return ExitCode::from(2);
    };
    match novadb_storage::Db::open(&dir, novadb_storage::Options::default()) {
        Ok(db) => {
            let r = db.recovery_report().clone();
            println!(
                "storage ok: recovered {} commits ({} page records); network listener not \
                 implemented yet (Stage 4, will use {})",
                r.commits,
                r.pages_applied,
                novadb_protocol::DEFAULT_LISTEN
            );
            match db.close() {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("close failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Err(e) => {
            eprintln!("open failed: {e}");
            ExitCode::FAILURE
        }
    }
}
