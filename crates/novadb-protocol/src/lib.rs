//! NovaDB MySQL wire protocol (Stage 4): own implementation, no I/O. The server crate does
//! the networking; everything here is pure encode/decode so it can be fuzzed.
//!
//! Pre-auth limits (PLAN.md §4.6) live here so the decoder, server and fuzz targets agree.
#![forbid(unsafe_code)]

pub mod packets;
pub mod wire;

/// Default listen address. 3306 belongs to MariaDB on the dev host; never default to it.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:3307";

/// Largest packet accepted before authentication completes.
pub const MAX_PREAUTH_PACKET: usize = 64 * 1024;

/// Default `max_allowed_packet` after authentication.
pub const DEFAULT_MAX_ALLOWED_PACKET: usize = 64 << 20;

/// Seconds a client may take to finish the handshake.
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 10;

/// Largest payload of a single wire packet; bigger messages are split.
pub const MAX_PAYLOAD: usize = 0xFF_FFFF;

/// Split `payload` into wire packets starting at sequence `seq`; returns the next sequence id.
pub fn frame(out: &mut Vec<u8>, payload: &[u8], mut seq: u8) -> u8 {
    let mut rest = payload;
    loop {
        let n = rest.len().min(MAX_PAYLOAD);
        out.extend_from_slice(&(n as u32).to_le_bytes()[..3]);
        out.push(seq);
        out.extend_from_slice(&rest[..n]);
        seq = seq.wrapping_add(1);
        rest = &rest[n..];
        // A payload of exactly MAX_PAYLOAD bytes is followed by an empty packet.
        if n < MAX_PAYLOAD {
            return seq;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_defaults_to_mariadb_port() {
        assert!(!DEFAULT_LISTEN.ends_with(":3306"));
        assert!(DEFAULT_LISTEN.starts_with("127.0.0.1:"));
        const { assert!(MAX_PREAUTH_PACKET < DEFAULT_MAX_ALLOWED_PACKET) };
    }

    #[test]
    fn framing() {
        let mut out = Vec::new();
        assert_eq!(frame(&mut out, b"abc", 3), 4);
        assert_eq!(out, vec![3, 0, 0, 3, b'a', b'b', b'c']);
        let big = vec![1u8; MAX_PAYLOAD];
        let mut out = Vec::new();
        assert_eq!(frame(&mut out, &big, 0), 2);
        assert_eq!(out.len(), MAX_PAYLOAD + 8);
        assert_eq!(&out[MAX_PAYLOAD + 4..], &[0, 0, 0, 1]);
    }
}
