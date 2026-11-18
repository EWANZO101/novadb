//! Privileges (GRANT / REVOKE). Least privilege by default: a new user can log in and nothing
//! else. `root` is always all-powerful (so the server can never be locked out).
//!
//! Stored in tree `sql:grants`: key `user ‖ 0x00 ‖ scope` (scope `*` = global, else lower-case
//! table name) → u64 bit mask.

use novadb_storage::Db;

use crate::error::{Result, SqlError};

pub const SELECT: u64 = 1;
pub const INSERT: u64 = 1 << 1;
pub const UPDATE: u64 = 1 << 2;
pub const DELETE: u64 = 1 << 3;
pub const CREATE: u64 = 1 << 4;
pub const DROP: u64 = 1 << 5;
pub const INDEX: u64 = 1 << 6;
pub const ALTER: u64 = 1 << 7;
pub const CREATE_USER: u64 = 1 << 8;
pub const PROCESS: u64 = 1 << 9;
pub const SUPER: u64 = 1 << 10;
pub const GRANT_OPTION: u64 = 1 << 11;

/// Privileges that make sense on one table.
pub const TABLE_ALL: u64 = SELECT | INSERT | UPDATE | DELETE | CREATE | DROP | INDEX | ALTER;
/// ALL PRIVILEGES at global level (GRANT OPTION is separate, like MySQL).
pub const GLOBAL_ALL: u64 = TABLE_ALL | CREATE_USER | PROCESS | SUPER;

pub const GRANTS_TREE: &str = "sql:grants";

pub const NAMES: &[(&str, u64)] = &[
    ("SELECT", SELECT),
    ("INSERT", INSERT),
    ("UPDATE", UPDATE),
    ("DELETE", DELETE),
    ("CREATE", CREATE),
    ("DROP", DROP),
    ("INDEX", INDEX),
    ("ALTER", ALTER),
    ("CREATE USER", CREATE_USER),
    ("PROCESS", PROCESS),
    ("SUPER", SUPER),
];

pub fn is_root(user: &str) -> bool {
    user.eq_ignore_ascii_case("root")
}

fn key(user: &str, scope: &str) -> Vec<u8> {
    let mut k = user.to_lowercase().into_bytes();
    k.push(0);
    k.extend_from_slice(scope.to_lowercase().as_bytes());
    k
}

fn scope_of(table: Option<&str>) -> String {
    table.map_or_else(|| "*".to_string(), str::to_lowercase)
}

pub fn get(db: &mut Db, user: &str, table: Option<&str>) -> Result<u64> {
    let k = key(user, &scope_of(table));
    let v = db.view(|tx| match tx.open_tree(GRANTS_TREE) {
        Ok(t) => tx.get(&t, &k),
        Err(novadb_storage::Error::TreeNotFound(_)) => Ok(None),
        Err(e) => Err(e),
    })?;
    Ok(v.and_then(|b| b.as_slice().try_into().ok())
        .map_or(0, u64::from_le_bytes))
}

pub fn set(db: &mut Db, user: &str, table: Option<&str>, mask: u64) -> Result<()> {
    let k = key(user, &scope_of(table));
    db.update(|tx| {
        let t = tx.open_or_create_tree(GRANTS_TREE)?;
        if mask == 0 {
            tx.delete(&t, &k).map(|_| ())
        } else {
            tx.put(&t, &k, &mask.to_le_bytes()).map(|_| ())
        }
    })?;
    Ok(())
}

/// Effective privileges of `user` on `table` (global ∪ table), or global only.
pub fn effective(db: &mut Db, user: &str, table: Option<&str>) -> Result<u64> {
    if is_root(user) {
        return Ok(GLOBAL_ALL | GRANT_OPTION);
    }
    let g = get(db, user, None)?;
    Ok(match table {
        Some(t) => g | get(db, user, Some(t))?,
        None => g,
    })
}

/// All grants: (user, scope, mask).
pub fn all(db: &mut Db) -> Result<Vec<(String, String, u64)>> {
    let rows = db.view(|tx| match tx.open_tree(GRANTS_TREE) {
        Ok(t) => tx
            .range(&t, ..)?
            .collect::<novadb_storage::Result<Vec<_>>>(),
        Err(novadb_storage::Error::TreeNotFound(_)) => Ok(Vec::new()),
        Err(e) => Err(e),
    })?;
    let mut out = Vec::new();
    for (k, v) in rows {
        let Some(i) = k.iter().position(|&b| b == 0) else {
            continue;
        };
        let user = String::from_utf8_lossy(&k[..i]).into_owned();
        let scope = String::from_utf8_lossy(&k[i + 1..]).into_owned();
        let mask = v
            .as_slice()
            .try_into()
            .map(u64::from_le_bytes)
            .map_err(|_| SqlError::corrupt("bad grant"))?;
        out.push((user, scope, mask));
    }
    Ok(out)
}

/// Remove every grant of a user (DROP USER).
pub fn drop_user(db: &mut Db, user: &str) -> Result<()> {
    for (u, scope, _) in all(db)? {
        if u.eq_ignore_ascii_case(user) {
            let t = if scope == "*" {
                None
            } else {
                Some(scope.as_str())
            };
            set(db, &u, t, 0)?;
        }
    }
    Ok(())
}

/// Human-readable privilege list (for SHOW GRANTS).
pub fn names(mask: u64, global: bool) -> String {
    let full = if global { GLOBAL_ALL } else { TABLE_ALL };
    if mask & full == full {
        return "ALL PRIVILEGES".into();
    }
    let v: Vec<&str> = NAMES
        .iter()
        .filter(|(_, b)| mask & b != 0)
        .map(|(n, _)| *n)
        .collect();
    if v.is_empty() {
        "USAGE".into()
    } else {
        v.join(", ")
    }
}

fn priv_name(p: u64) -> &'static str {
    NAMES
        .iter()
        .find(|(_, b)| *b == p)
        .map_or("required", |(n, _)| n)
}

pub fn denied_table(p: u64, user: &str, table: &str) -> SqlError {
    let mut e = SqlError::internal(format!(
        "{} command denied to user '{user}'@'localhost' for table '{table}'",
        priv_name(p)
    ));
    e.code = 1142;
    e.state = "42000";
    e
}

pub fn denied_global(p: u64) -> SqlError {
    let mut e = SqlError::internal(format!(
        "Access denied; you need (at least one of) the {} privilege(s) for this operation",
        priv_name(p)
    ));
    e.code = 1227;
    e.state = "42000";
    e
}
