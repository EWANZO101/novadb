//! RFC 6238 TOTP (SHA-1, 6 digits, 30 s) + RFC 4648 base32. Codes are single-use: a step that
//! was already accepted (or any earlier step) is rejected, which stops replay inside the window.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

/// Seconds per TOTP step.
pub const STEP: u64 = 30;
const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Six-digit code for a counter value.
pub fn code_at(secret: &[u8], counter: u64) -> u32 {
    // HMAC accepts keys of any length, so this cannot fail; fall back to an impossible code.
    let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(secret) else {
        return u32::MAX;
    };
    mac.update(&counter.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = usize::from(h[19] & 0x0f);
    let bin = ((u32::from(h[off]) & 0x7f) << 24)
        | (u32::from(h[off + 1]) << 16)
        | (u32::from(h[off + 2]) << 8)
        | u32::from(h[off + 3]);
    bin % 1_000_000
}

/// Checks `code` against the steps around `now` (±1). Returns the matched step if it is newer
/// than `last_used`.
pub fn verify(secret: &[u8], code: &str, now: u64, last_used: u64) -> Option<u64> {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let want: u32 = code.parse().ok()?;
    let cur = now / STEP;
    let mut hit = None;
    // Check every candidate (no early exit) so timing does not reveal which step matched.
    for c in [cur.saturating_sub(1), cur, cur + 1] {
        let ok: bool = code_at(secret, c)
            .to_be_bytes()
            .ct_eq(&want.to_be_bytes())
            .into();
        if ok && c > last_used && hit.is_none() {
            hit = Some(c);
        }
    }
    hit
}

/// Base32 without padding.
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(B32[((buf >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(B32[((buf << (5 - bits)) & 31) as usize]));
    }
    out
}

/// Base32 decode (case-insensitive, ignores padding/spaces).
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        if c == b'=' || c == b' ' {
            continue;
        }
        let v = B32.iter().position(|&x| x == c.to_ascii_uppercase())? as u32;
        buf = ((buf << 5) | v) & 0xffff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

fn pct(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            o.push(char::from(b));
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

/// `otpauth://` URI for authenticator apps.
pub fn otpauth_uri(issuer: &str, account: &str, secret_b32: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period={}",
        pct(issuer),
        pct(account),
        secret_b32,
        pct(issuer),
        STEP
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn rfc6238_vectors() {
        let k = b"12345678901234567890";
        // RFC 6238 appendix B (8-digit values, last 6 digits).
        assert_eq!(code_at(k, 59 / 30), 287_082);
        assert_eq!(code_at(k, 1_111_111_109 / 30), 81_804);
        assert_eq!(code_at(k, 1_234_567_890 / 30), 5_924);
        assert_eq!(code_at(k, 2_000_000_000 / 30), 279_037);
    }

    #[test]
    fn verify_window_and_replay() {
        let k = b"12345678901234567890";
        let now = 1_234_567_890;
        let code = format!("{:06}", code_at(k, now / 30));
        let step = verify(k, &code, now, 0).unwrap();
        assert_eq!(step, now / 30);
        assert_eq!(verify(k, &code, now, step), None, "replay must fail");
        let prev = format!("{:06}", code_at(k, now / 30 - 1));
        assert!(verify(k, &prev, now, 0).is_some());
        let old = format!("{:06}", code_at(k, now / 30 - 2));
        assert_eq!(verify(k, &old, now, 0), None);
        assert_eq!(verify(k, "12345", now, 0), None);
        assert_eq!(verify(k, "abcdef", now, 0), None);
    }

    #[test]
    fn base32_roundtrip() {
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        for n in 0..40u8 {
            let d: Vec<u8> = (0..n).map(|i| i.wrapping_mul(37)).collect();
            assert_eq!(base32_decode(&base32_encode(&d)).unwrap(), d);
        }
        assert!(base32_decode("not!valid").is_none());
    }
}
