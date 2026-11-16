//! Storage error type.

use std::fmt;
use std::io;

/// Result alias for the storage engine.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Errors returned by the storage engine. Malformed on-disk data always surfaces as
/// [`Error::Corruption`]; it must never cause a panic.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Underlying I/O failure.
    Io(io::Error),
    /// On-disk data failed validation (checksum, structure, bounds).
    Corruption(String),
    /// A previous fatal error (e.g. failed fsync) poisoned this handle. The database must be
    /// closed and reopened, which runs crash recovery from the WAL (PLAN.md §4.12).
    Poisoned(String),
    /// The database directory is locked by another process/handle.
    Locked,
    /// The transaction modified more pages than the buffer pool may pin.
    TxnTooLarge {
        /// Pages the transaction tried to pin.
        pages: usize,
        /// Maximum allowed.
        limit: usize,
    },
    /// Key length is 0 or exceeds [`crate::MAX_KEY_LEN`].
    KeyTooLarge(usize),
    /// Value exceeds [`crate::MAX_VALUE_LEN`].
    ValueTooLarge(usize),
    /// Named tree does not exist.
    TreeNotFound(String),
    /// Named tree already exists.
    TreeExists(String),
    /// Database does not exist and `create_if_missing` is false.
    NotFound,
    /// Caller error (bad option, bad name, ...).
    InvalidArgument(String),
}

impl Error {
    pub(crate) fn corrupt(msg: impl Into<String>) -> Self {
        Error::Corruption(msg.into())
    }

    /// True if the handle can no longer be used and must be reopened.
    pub fn is_fatal(&self) -> bool {
        matches!(self, Error::Poisoned(_) | Error::Io(_))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::Corruption(m) => write!(f, "data corruption: {m}"),
            Error::Poisoned(m) => write!(f, "database handle poisoned by earlier fatal error: {m}"),
            Error::Locked => write!(f, "database is locked by another process"),
            Error::TxnTooLarge { pages, limit } => {
                write!(f, "transaction too large: {pages} pages (limit {limit})")
            }
            Error::KeyTooLarge(n) => write!(f, "invalid key length {n}"),
            Error::ValueTooLarge(n) => write!(f, "value too large: {n} bytes"),
            Error::TreeNotFound(n) => write!(f, "tree not found: {n}"),
            Error::TreeExists(n) => write!(f, "tree already exists: {n}"),
            Error::NotFound => write!(f, "database not found"),
            Error::InvalidArgument(m) => write!(f, "invalid argument: {m}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}
