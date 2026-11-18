//! The SQL lexer + parser must reject any input with an error, never panic or recurse
//! without bound (PLAN.md §4.16).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = novadb_sql::parse(s);
    }
});
