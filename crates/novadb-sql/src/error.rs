//! SQL errors carry MySQL error numbers + SQLSTATE so the wire protocol (Stage 4) can return
//! them unchanged.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlError {
    /// MySQL error number (e.g. 1064).
    pub code: u16,
    /// Five-character SQLSTATE.
    pub state: &'static str,
    pub msg: String,
}

pub type Result<T, E = SqlError> = std::result::Result<T, E>;

impl SqlError {
    fn new(code: u16, state: &'static str, msg: impl Into<String>) -> Self {
        SqlError {
            code,
            state,
            msg: msg.into(),
        }
    }
    /// Syntax error near `near` (a snippet of the input) at byte offset `pos`.
    pub fn syntax(pos: usize, near: &str, msg: &str) -> Self {
        let snippet: String = near.chars().take(40).collect();
        Self::new(
            1064,
            "42000",
            format!(
                "You have an error in your SQL syntax: {msg} near '{snippet}' at position {pos}"
            ),
        )
    }
    pub fn no_table(t: &str) -> Self {
        Self::new(1146, "42S02", format!("Table '{t}' doesn't exist"))
    }
    pub fn table_exists(t: &str) -> Self {
        Self::new(1050, "42S01", format!("Table '{t}' already exists"))
    }
    pub fn bad_column(c: &str) -> Self {
        Self::new(
            1054,
            "42S22",
            format!("Unknown column '{c}' in 'field list'"),
        )
    }
    pub fn dup_column(c: &str) -> Self {
        Self::new(1060, "42S21", format!("Duplicate column name '{c}'"))
    }
    pub fn dup_key_name(k: &str) -> Self {
        Self::new(1061, "42000", format!("Duplicate key name '{k}'"))
    }
    pub fn no_key(k: &str) -> Self {
        Self::new(
            1091,
            "42000",
            format!("Can't DROP '{k}'; check that column/key exists"),
        )
    }
    pub fn multiple_pk() -> Self {
        Self::new(1068, "42000", "Multiple primary key defined")
    }
    pub fn dup_entry(v: &str, key: &str) -> Self {
        Self::new(
            1062,
            "23000",
            format!("Duplicate entry '{v}' for key '{key}'"),
        )
    }
    pub fn not_null(c: &str) -> Self {
        Self::new(1048, "23000", format!("Column '{c}' cannot be null"))
    }
    pub fn no_default(c: &str) -> Self {
        Self::new(
            1364,
            "HY000",
            format!("Field '{c}' doesn't have a default value"),
        )
    }
    pub fn too_long(c: &str) -> Self {
        Self::new(1406, "22001", format!("Data too long for column '{c}'"))
    }
    pub fn out_of_range(c: &str) -> Self {
        Self::new(
            1264,
            "22003",
            format!("Out of range value for column '{c}'"),
        )
    }
    pub fn value_out_of_range(what: &str) -> Self {
        Self::new(1690, "22003", format!("Value is out of range in '{what}'"))
    }
    pub fn bad_value(ty: &str, v: &str, c: &str) -> Self {
        Self::new(
            1366,
            "HY000",
            format!("Incorrect {ty} value: '{v}' for column '{c}'"),
        )
    }
    pub fn bad_datetime(v: &str, c: &str) -> Self {
        Self::new(
            1292,
            "22007",
            format!("Incorrect datetime value: '{v}' for column '{c}'"),
        )
    }
    pub fn column_count() -> Self {
        Self::new(1136, "21S01", "Column count doesn't match value count")
    }
    pub fn unsupported(what: &str) -> Self {
        Self::new(
            1235,
            "42000",
            format!("This version of NovaDB doesn't yet support '{what}'"),
        )
    }
    pub fn key_too_long() -> Self {
        Self::new(1071, "42000", "Specified key was too long")
    }
    pub fn blob_key(c: &str) -> Self {
        Self::new(
            1170,
            "42000",
            format!("BLOB/TEXT column '{c}' used in key specification without a key length"),
        )
    }
    pub fn row_too_big() -> Self {
        Self::new(1118, "42000", "Row size too large")
    }
    pub fn wrong_func(f: &str) -> Self {
        Self::new(
            1582,
            "42000",
            format!("Incorrect parameter count or unknown function '{f}'"),
        )
    }
    pub fn resource(msg: &str) -> Self {
        Self::new(1038, "HY001", msg)
    }
    pub fn bad_ident(name: &str) -> Self {
        Self::new(1103, "42000", format!("Incorrect name '{name}'"))
    }
    pub fn invalid_default(c: &str) -> Self {
        Self::new(1067, "42000", format!("Invalid default value for '{c}'"))
    }
    pub fn auto_inc() -> Self {
        Self::new(
            1075,
            "42000",
            "Incorrect table definition; there can be only one auto column and it must be defined as a key",
        )
    }
    pub fn param_count() -> Self {
        Self::new(1210, "HY000", "Incorrect arguments to mysqld_stmt_execute")
    }
    pub fn unknown_db(d: &str) -> Self {
        Self::new(1049, "42000", format!("Unknown database '{d}'"))
    }
    pub fn unknown_sysvar(v: &str) -> Self {
        Self::new(1193, "HY000", format!("Unknown system variable '{v}'"))
    }
    pub fn user_op(op: &str, u: &str) -> Self {
        Self::new(
            1396,
            "HY000",
            format!("Operation {op} failed for '{u}'@'%'"),
        )
    }
    pub fn weak_password() -> Self {
        Self::new(
            1819,
            "HY000",
            "Your password does not satisfy the current policy requirements (12-128 characters)",
        )
    }
    pub fn access_denied(u: &str) -> Self {
        Self::new(
            1045,
            "28000",
            format!("Access denied for user '{u}'@'localhost' (using password: YES)"),
        )
    }
    pub fn corrupt(msg: impl Into<String>) -> Self {
        Self::new(
            1030,
            "HY000",
            format!("Got error from storage engine: {}", msg.into()),
        )
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(1105, "HY000", msg)
    }
}

impl fmt::Display for SqlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ERROR {} ({}): {}", self.code, self.state, self.msg)
    }
}

impl std::error::Error for SqlError {}

impl From<novadb_storage::Error> for SqlError {
    fn from(e: novadb_storage::Error) -> Self {
        match e {
            novadb_storage::Error::TxnTooLarge { .. } => SqlError::resource(
                "Statement touches too many pages for one transaction; split it into smaller statements",
            ),
            other => SqlError::corrupt(other.to_string()),
        }
    }
}
