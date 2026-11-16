//! NovaDB SQL front end (Stage 3): hand-written lexer + recursive-descent parser.
//!
//! Not implemented yet. Hard limits that the parser must enforce (PLAN.md §4.7, §4.16) are
//! fixed here so later code and fuzz targets share them.
#![forbid(unsafe_code)]

/// Maximum nesting depth of expressions/subqueries before the parser returns an error
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
