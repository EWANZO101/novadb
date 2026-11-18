//! Passwords (Argon2id), random tokens, rate limiting.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

/// Minimum / maximum password length (characters).
pub const PW_MIN: usize = 12;
pub const PW_MAX: usize = 128;

fn argon() -> Argon2<'static> {
    // OWASP 2024 baseline for Argon2id: 19 MiB, 2 passes, 1 lane.
    let p = Params::new(19_456, 2, 1, None).unwrap_or_default();
    Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
}

/// Argon2id PHC string.
pub fn hash_password(pw: &str) -> Result<String, String> {
    let salt_bytes: [u8; 16] = random_bytes()?;
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|e| e.to_string())?;
    argon()
        .hash_password(pw.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

/// Constant-time verify against a PHC string. Malformed hashes never match.
pub fn verify_password(pw: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(h) => argon().verify_password(pw.as_bytes(), &h).is_ok(),
        Err(_) => false,
    }
}

/// Returns a user-facing reason when the password is not acceptable.
pub fn password_problem(pw: &str, username: &str) -> Option<&'static str> {
    let n = pw.chars().count();
    if n < PW_MIN {
        return Some("Password must be at least 12 characters.");
    }
    if n > PW_MAX {
        return Some("Password must be at most 128 characters.");
    }
    let lower = pw.to_lowercase();
    if lower.contains(&username.to_lowercase()) {
        return Some("Password must not contain the username.");
    }
    const WEAK: [&str; 8] = [
        "password", "admin", "novadb", "123456", "qwerty", "letmein", "welcome", "changeme",
    ];
    if WEAK.iter().any(|w| lower.contains(w)) && n < 20 {
        return Some("Password is too easy to guess.");
    }
    if pw.chars().all(|c| c == pw.chars().next().unwrap_or(' ')) {
        return Some("Password is too easy to guess.");
    }
    None
}

/// OS random bytes.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], String> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|e| format!("os rng: {e}"))?;
    Ok(b)
}

/// 256-bit URL-safe token.
pub fn token() -> Result<String, String> {
    Ok(URL_SAFE_NO_PAD.encode(random_bytes::<32>()?))
}

/// Human-friendly random password (no look-alike characters), uniform via rejection sampling.
pub fn random_password(len: usize) -> Result<String, String> {
    const A: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut out = String::with_capacity(len);
    while out.len() < len {
        for b in random_bytes::<64>()? {
            // 57 symbols; 228 = 4*57 keeps the distribution uniform.
            if b < 228 && out.len() < len {
                out.push(char::from(A[usize::from(b) % A.len()]));
            }
        }
    }
    Ok(out)
}

/// Lowercase hex SHA-256.
pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// Lowercase hex.
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// PKCE S256 challenge for a verifier.
pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Fixed-window counter per key. Checked before any expensive work (PLAN.md §4.5).
pub struct RateLimiter {
    map: Mutex<HashMap<String, (Instant, u32)>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            map: Mutex::new(HashMap::new()),
        }
    }

    /// Counts one hit; returns false when `key` exceeded `max` hits in `window`.
    pub fn hit(&self, key: &str, max: u32, window: Duration) -> bool {
        let Ok(mut m) = self.map.lock() else {
            return false;
        };
        let now = Instant::now();
        if m.len() > 50_000 {
            m.retain(|_, (t, _)| now.duration_since(*t) < Duration::from_secs(3600));
        }
        let e = m.entry(key.to_string()).or_insert((now, 0));
        if now.duration_since(e.0) >= window {
            *e = (now, 0);
        }
        e.1 = e.1.saturating_add(1);
        e.1 <= max
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn hash_and_verify() {
        let h = hash_password("correct horse battery").unwrap();
        assert!(h.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(verify_password("correct horse battery", &h));
        assert!(!verify_password("correct horse batterz", &h));
        assert!(!verify_password("x", "not-a-phc"));
        assert_ne!(h, hash_password("correct horse battery").unwrap(), "salted");
    }

    #[test]
    fn policy() {
        assert!(password_problem("short", "bob").is_some());
        assert!(password_problem("bobbobbobbobbob1", "bob").is_some());
        assert!(password_problem("password12345", "x").is_some());
        assert!(password_problem("aaaaaaaaaaaaaaaa", "x").is_some());
        assert!(password_problem("tangerine-violin-42", "bob").is_none());
    }

    #[test]
    fn random_password_alphabet() {
        let p = random_password(24).unwrap();
        assert_eq!(p.len(), 24);
        assert!(!p.contains(['0', 'O', 'l', '1', 'I']));
    }

    #[test]
    fn limiter() {
        let r = RateLimiter::new();
        for _ in 0..3 {
            assert!(r.hit("k", 3, Duration::from_secs(60)));
        }
        assert!(!r.hit("k", 3, Duration::from_secs(60)));
        assert!(r.hit("other", 3, Duration::from_secs(60)));
    }

    #[test]
    fn pkce() {
        // RFC 7636 appendix B.
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }
}
