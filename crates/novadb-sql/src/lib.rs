//! NovaDB SQL (Stage 3): hand-written lexer + recursive-descent parser and a single-node
//! executor on top of `novadb-storage`.
//!
//! ```
//! # fn main() -> Result<(), novadb_sql::SqlError> {
//! # let dir = std::env::temp_dir().join(format!("novadb-doc-{}", std::process::id()));
//! let mut db = novadb_sql::Engine::open(&dir)?;
//! db.execute("CREATE TABLE t (id INT PRIMARY KEY, name VARCHAR(20)); INSERT INTO t VALUES (1, 'a')")?;
//! let r = db.query("SELECT name FROM t WHERE id = 1")?;
//! assert_eq!(r.rows[0][0], novadb_sql::Value::Str("a".into()));
//! # db.close()?; let _ = std::fs::remove_dir_all(&dir);
//! # Ok(()) }
//! ```
//!
//! Hard limits (PLAN.md §4.7, §4.16) live here so the parser, executor and fuzz targets share them.
#![forbid(unsafe_code)]

pub mod ast;
pub mod catalog;
pub mod codec;
pub mod error;
pub mod exec;
pub mod lexer;
pub mod mvcc;
pub mod parser;
pub mod value;

pub use ast::bind_params;
pub use error::{Result, SqlError};
pub use exec::{ColumnMeta, Engine, QueryResult, Session};
pub use parser::{parse, parse_prepared};
pub use value::{ColType, Value};

/// Maximum nesting depth of expressions before the parser returns an error
/// (prevents stack exhaustion on hostile input).
pub const MAX_PARSE_DEPTH: usize = 128;

/// Maximum SQL statement length in bytes accepted by the parser.
pub const MAX_STATEMENT_BYTES: usize = 16 << 20;

#[cfg(test)]
mod tests {
    #[test]
    fn limits_are_sane() {
        const { assert!(super::MAX_PARSE_DEPTH >= 32 && super::MAX_PARSE_DEPTH <= 1024) };
        const { assert!(super::MAX_STATEMENT_BYTES <= 64 << 20) };
    }
}
