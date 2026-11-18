//! Password hashing (Argon2id), random secrets and pre-hash rate limiting (PLAN.md §4.4, §4.5).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

fn argon() -> Argon2<'static> {
    let p = Params::new(19_456, 2, 1, None).unwrap_or_default();
    Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
}

pub fn random_bytes<const N: usize>() -> Result<[u8; N], String> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|e| format!("os rng: {e}"))?;
    Ok(b)
}

pub fn hash_password(pw: &str) -> Result<String, String> {
    let salt = SaltString::encode_b64(&random_bytes::<16>()?).map_err(|e| e.to_string())?;
    argon()
        .hash_password(pw.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

pub fn verify_password(pw: &str, phc: &str) -> bool {
    PasswordHash::new(phc).is_ok_and(|h| argon().verify_password(pw.as_bytes(), &h).is_ok())
}

/// Random password without look-alike characters (uniform via rejection sampling).
pub fn random_password(len: usize) -> Result<String, String> {
    const A: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut out = String::with_capacity(len);
    while out.len() < len {
        for b in random_bytes::<64>()? {
            if b < 228 && out.len() < len {
                out.push(char::from(A[usize::from(b) % A.len()]));
            }
        }
    }
    Ok(out)
}

/// MySQL scramble: 20 bytes, no NUL, no '$' issues — printable ASCII is the safest.
pub fn scramble() -> Result<[u8; 20], String> {
    let mut s = random_bytes::<20>()?;
    for b in &mut s {
        *b = 0x21 + (*b % 94);
    }
    Ok(s)
}

/// Fixed-window counter per key, consulted before any hashing.
pub struct RateLimiter {
    map: Mutex<HashMap<String, (Instant, u32)>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            map: Mutex::new(HashMap::new()),
        }
    }

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
    fn argon2id_roundtrip() {
        let h = hash_password("a long enough password").unwrap();
        assert!(h.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(verify_password("a long enough password", &h));
        assert!(!verify_password("a long enough passwore", &h));
        assert!(!verify_password("x", "garbage"));
    }

    #[test]
    fn scramble_is_printable() {
        let s = scramble().unwrap();
        assert!(s.iter().all(|b| (0x21..0x7f).contains(b)));
    }

    #[test]
    fn limiter_blocks() {
        let r = RateLimiter::new();
        assert!(r.hit("a", 2, Duration::from_secs(60)));
        assert!(r.hit("a", 2, Duration::from_secs(60)));
        assert!(!r.hit("a", 2, Duration::from_secs(60)));
    }
}
