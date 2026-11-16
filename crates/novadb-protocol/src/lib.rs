//! NovaDB MySQL wire protocol (Stage 4). Own implementation; must be fuzzed.
//!
//! Not implemented yet. Pre-auth limits (PLAN.md §4.6) live here so the decoder, server and
//! fuzz targets agree on them.
#![forbid(unsafe_code)]

/// Default listen address. 3306 belongs to MariaDB on the dev host; never default to it.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:3307";

/// Largest packet accepted before authentication completes.
pub const MAX_PREAUTH_PACKET: usize = 64 * 1024;

/// Default `max_allowed_packet` after authentication.
pub const DEFAULT_MAX_ALLOWED_PACKET: usize = 64 << 20;

/// Seconds a client may take to finish the handshake.
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 10;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_defaults_to_mariadb_port() {
        assert!(!DEFAULT_LISTEN.ends_with(":3306"));
        assert!(DEFAULT_LISTEN.starts_with("127.0.0.1:"));
        const { assert!(MAX_PREAUTH_PACKET < DEFAULT_MAX_ALLOWED_PACKET) };
    }
}
