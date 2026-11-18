//! Client-controlled protocol messages must never panic the decoder (PLAN.md §4.16).
#![no_main]
use libfuzzer_sys::fuzz_target;
use novadb_protocol::packets as pk;
use novadb_protocol::wire::Reader;

fuzz_target!(|data: &[u8]| {
    let _ = pk::parse_ssl_request(data);
    let _ = pk::parse_handshake_response(data);
    let _ = pk::parse_cleartext_password(data);
    let _ = pk::parse_stmt_id(data);
    if let Some((&n, rest)) = data.split_first() {
        let mut ld = std::collections::HashMap::new();
        if n & 0x80 != 0 {
            ld.insert(0u16, b"long".to_vec());
        }
        if let Ok(e) = pk::parse_execute(rest, usize::from(n & 0x1f), &[], &ld) {
            for p in &e.params {
                let _ = pk::param_value(p);
            }
            // Types are reused on the next execute.
            let _ = pk::parse_execute(rest, e.types.len(), &e.types, &ld);
        }
    }
    let mut r = Reader::new(data);
    while r.lenenc_bytes().is_ok() {}
});
