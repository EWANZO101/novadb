//! Passkeys (WebAuthn level 2, "none" attestation) — server-side verification.
//!
//! Registration: client data type/challenge/origin, RP id hash, user present + user verified,
//! attested credential (id + COSE public key: ES256, EdDSA or RS256). Attestation statements
//! are not evaluated (we ask for `attestation: "none"`; passkeys are about phishing-resistant
//! login, not device vetting).
//! Login: same checks plus the signature over `authenticatorData ‖ SHA-256(clientDataJSON)` and
//! the signature counter (a non-zero counter that does not increase means a cloned key).
//! All input is untrusted: the CBOR decoder is bounded (depth, lengths) and never panics.

use ring::signature;
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq)]
pub enum Cbor {
    Uint(u64),
    Nint(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
    Bool(bool),
    Null,
}

impl Cbor {
    fn int(&self) -> Option<i128> {
        match self {
            Cbor::Uint(u) => Some(i128::from(*u)),
            Cbor::Nint(n) => Some(*n),
            _ => None,
        }
    }
    fn get_int(&self, k: i128) -> Option<&Cbor> {
        match self {
            Cbor::Map(m) => m.iter().find(|(a, _)| a.int() == Some(k)).map(|(_, v)| v),
            _ => None,
        }
    }
    fn get_text(&self, k: &str) -> Option<&Cbor> {
        match self {
            Cbor::Map(m) => m
                .iter()
                .find(|(a, _)| matches!(a, Cbor::Text(t) if t == k))
                .map(|(_, v)| v),
            _ => None,
        }
    }
    fn bytes(&self) -> Option<&[u8]> {
        match self {
            Cbor::Bytes(b) => Some(b),
            _ => None,
        }
    }
}

const MAX_DEPTH: usize = 16;
const MAX_ITEMS: u64 = 1024;

/// Decode one CBOR item; returns it and the number of bytes used.
pub fn cbor(b: &[u8]) -> Result<(Cbor, usize), String> {
    let mut i = 0;
    let v = item(b, &mut i, 0)?;
    Ok((v, i))
}

fn take<'a>(b: &'a [u8], i: &mut usize, n: usize) -> Result<&'a [u8], String> {
    let end = i.checked_add(n).ok_or("cbor: overflow")?;
    let s = b.get(*i..end).ok_or("cbor: truncated")?;
    *i = end;
    Ok(s)
}

fn arg(b: &[u8], i: &mut usize, info: u8) -> Result<u64, String> {
    Ok(match info {
        0..=23 => u64::from(info),
        24 => u64::from(take(b, i, 1)?[0]),
        25 => u64::from(u16::from_be_bytes(
            take(b, i, 2)?.try_into().map_err(|_| "cbor")?,
        )),
        26 => u64::from(u32::from_be_bytes(
            take(b, i, 4)?.try_into().map_err(|_| "cbor")?,
        )),
        27 => u64::from_be_bytes(take(b, i, 8)?.try_into().map_err(|_| "cbor")?),
        _ => return Err("cbor: indefinite lengths not supported".into()),
    })
}

fn item(b: &[u8], i: &mut usize, depth: usize) -> Result<Cbor, String> {
    if depth > MAX_DEPTH {
        return Err("cbor: too deep".into());
    }
    let ib = take(b, i, 1)?[0];
    let (major, info) = (ib >> 5, ib & 0x1f);
    Ok(match major {
        0 => Cbor::Uint(arg(b, i, info)?),
        1 => Cbor::Nint(-1 - i128::from(arg(b, i, info)?)),
        2 => {
            let n = usize::try_from(arg(b, i, info)?).map_err(|_| "cbor: len")?;
            Cbor::Bytes(take(b, i, n)?.to_vec())
        }
        3 => {
            let n = usize::try_from(arg(b, i, info)?).map_err(|_| "cbor: len")?;
            Cbor::Text(String::from_utf8(take(b, i, n)?.to_vec()).map_err(|_| "cbor: utf8")?)
        }
        4 => {
            let n = arg(b, i, info)?;
            if n > MAX_ITEMS {
                return Err("cbor: array too long".into());
            }
            let mut v = Vec::new();
            for _ in 0..n {
                v.push(item(b, i, depth + 1)?);
            }
            Cbor::Array(v)
        }
        5 => {
            let n = arg(b, i, info)?;
            if n > MAX_ITEMS {
                return Err("cbor: map too long".into());
            }
            let mut v = Vec::new();
            for _ in 0..n {
                let k = item(b, i, depth + 1)?;
                let val = item(b, i, depth + 1)?;
                v.push((k, val));
            }
            Cbor::Map(v)
        }
        6 => {
            // tag: skip it, keep the content
            arg(b, i, info)?;
            item(b, i, depth + 1)?
        }
        7 => match info {
            20 => Cbor::Bool(false),
            21 => Cbor::Bool(true),
            22 | 23 => Cbor::Null,
            _ => return Err("cbor: unsupported simple/float value".into()),
        },
        _ => return Err("cbor: bad major type".into()),
    })
}

// ----- public keys ---------------------------------------------------------------------------

pub const ES256: i64 = -7;
pub const EDDSA: i64 = -8;
pub const RS256: i64 = -257;

/// Algorithm of a COSE public key we can verify with.
pub fn cose_alg(cose: &[u8]) -> Result<i64, String> {
    let (k, _) = cbor(cose)?;
    let alg = k.get_int(3).and_then(Cbor::int).ok_or("COSE key: no alg")?;
    let kty = k.get_int(1).and_then(Cbor::int).ok_or("COSE key: no kty")?;
    match (kty, alg) {
        (2, -7) => {
            let crv = k.get_int(-1).and_then(Cbor::int);
            let x = k.get_int(-2).and_then(Cbor::bytes).map_or(0, <[u8]>::len);
            let y = k.get_int(-3).and_then(Cbor::bytes).map_or(0, <[u8]>::len);
            if crv != Some(1) || x != 32 || y != 32 {
                return Err("COSE key: ES256 needs P-256 x/y".into());
            }
            Ok(ES256)
        }
        (1, -8) => {
            let crv = k.get_int(-1).and_then(Cbor::int);
            let x = k.get_int(-2).and_then(Cbor::bytes).map_or(0, <[u8]>::len);
            if crv != Some(6) || x != 32 {
                return Err("COSE key: EdDSA needs Ed25519".into());
            }
            Ok(EDDSA)
        }
        (3, -257) => {
            let n = k.get_int(-1).and_then(Cbor::bytes).map_or(0, <[u8]>::len);
            if !(256..=1024).contains(&n) || k.get_int(-2).and_then(Cbor::bytes).is_none() {
                return Err("COSE key: RSA 2048-8192 bits".into());
            }
            Ok(RS256)
        }
        _ => Err(format!("unsupported key type {kty} / algorithm {alg}")),
    }
}

fn verify_sig(cose: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), String> {
    let (k, _) = cbor(cose)?;
    let bad = || "signature does not verify".to_string();
    match cose_alg(cose)? {
        ES256 => {
            let x = k.get_int(-2).and_then(Cbor::bytes).ok_or("x")?;
            let y = k.get_int(-3).and_then(Cbor::bytes).ok_or("y")?;
            let mut pt = vec![4u8];
            pt.extend_from_slice(x);
            pt.extend_from_slice(y);
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, pt)
                .verify(msg, sig)
                .map_err(|_| bad())
        }
        EDDSA => {
            let x = k.get_int(-2).and_then(Cbor::bytes).ok_or("x")?;
            signature::UnparsedPublicKey::new(&signature::ED25519, x)
                .verify(msg, sig)
                .map_err(|_| bad())
        }
        RS256 => {
            let n = k.get_int(-1).and_then(Cbor::bytes).ok_or("n")?;
            let e = k.get_int(-2).and_then(Cbor::bytes).ok_or("e")?;
            signature::RsaPublicKeyComponents { n, e }
                .verify(&signature::RSA_PKCS1_2048_8192_SHA256, msg, sig)
                .map_err(|_| bad())
        }
        _ => Err("unsupported algorithm".into()),
    }
}

// ----- ceremony checks -----------------------------------------------------------------------

pub struct Rp<'a> {
    pub id: &'a str,
    pub origin: &'a str,
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    ty: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: bool,
}

fn check_client_data(raw: &[u8], ty: &str, challenge: &str, rp: &Rp<'_>) -> Result<(), String> {
    let c: ClientData = serde_json::from_slice(raw).map_err(|_| "clientDataJSON: invalid")?;
    if c.ty != ty {
        return Err(format!("clientDataJSON: expected type {ty}"));
    }
    if !bool::from(subtle::ConstantTimeEq::ct_eq(
        c.challenge.as_bytes(),
        challenge.as_bytes(),
    )) {
        return Err("challenge does not match (expired or replayed?)".into());
    }
    if c.origin != rp.origin || c.cross_origin {
        return Err(format!("wrong origin {}", c.origin));
    }
    Ok(())
}

const UP: u8 = 0x01;
const UV: u8 = 0x04;
const AT: u8 = 0x40;

struct AuthData<'a> {
    flags: u8,
    count: u32,
    cred: Option<(Vec<u8>, &'a [u8])>,
}

fn auth_data<'a>(b: &'a [u8], rp: &Rp<'_>) -> Result<AuthData<'a>, String> {
    if b.len() < 37 {
        return Err("authenticatorData too short".into());
    }
    let want = Sha256::digest(rp.id.as_bytes());
    if b[..32] != want[..] {
        return Err("authenticator used a different RP id".into());
    }
    let flags = b[32];
    if flags & UP == 0 || flags & UV == 0 {
        return Err("user presence and verification (PIN / biometrics) are required".into());
    }
    let count = u32::from_be_bytes([b[33], b[34], b[35], b[36]]);
    let cred = if flags & AT != 0 {
        let rest = &b[37..];
        if rest.len() < 18 {
            return Err("attested credential data truncated".into());
        }
        let n = usize::from(u16::from_be_bytes([rest[16], rest[17]]));
        if n == 0 || n > 1023 || rest.len() < 18 + n {
            return Err("credential id length".into());
        }
        let id = rest[18..18 + n].to_vec();
        let key_bytes = &rest[18 + n..];
        let (_, used) = cbor(key_bytes)?;
        Some((id, &key_bytes[..used]))
    } else {
        None
    };
    Ok(AuthData { flags, count, cred })
}

#[derive(Debug, Clone, PartialEq)]
pub struct NewCredential {
    pub id: Vec<u8>,
    pub cose: Vec<u8>,
    pub alg: i64,
    pub count: u32,
}

pub fn verify_registration(
    attestation_object: &[u8],
    client_data_json: &[u8],
    challenge: &str,
    rp: &Rp<'_>,
) -> Result<NewCredential, String> {
    check_client_data(client_data_json, "webauthn.create", challenge, rp)?;
    let (att, _) = cbor(attestation_object)?;
    let ad = att
        .get_text("authData")
        .and_then(Cbor::bytes)
        .ok_or("attestationObject: no authData")?;
    let a = auth_data(ad, rp)?;
    let (id, cose) = a.cred.ok_or("no credential in registration")?;
    let alg = cose_alg(cose)?;
    let _ = a.flags;
    Ok(NewCredential {
        id,
        cose: cose.to_vec(),
        alg,
        count: a.count,
    })
}

/// Verify a login assertion; returns the new signature counter.
pub fn verify_assertion(
    cose: &[u8],
    stored_count: u32,
    authenticator_data: &[u8],
    client_data_json: &[u8],
    sig: &[u8],
    challenge: &str,
    rp: &Rp<'_>,
) -> Result<u32, String> {
    check_client_data(client_data_json, "webauthn.get", challenge, rp)?;
    let a = auth_data(authenticator_data, rp)?;
    let mut msg = authenticator_data.to_vec();
    msg.extend_from_slice(&Sha256::digest(client_data_json));
    verify_sig(cose, &msg, sig)?;
    if (a.count != 0 || stored_count != 0) && a.count <= stored_count {
        return Err("signature counter went backwards: this passkey may have been cloned".into());
    }
    Ok(a.count)
}

pub fn b64url(b: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

pub fn unb64url(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .map_err(|_| "bad base64url".to_string())
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair};

    /// Minimal CBOR encoder for the test authenticator.
    fn enc(c: &Cbor, out: &mut Vec<u8>) {
        fn head(major: u8, n: u64, out: &mut Vec<u8>) {
            let m = major << 5;
            if n < 24 {
                out.push(m | n as u8);
            } else if n < 256 {
                out.push(m | 24);
                out.push(n as u8);
            } else if n < 65536 {
                out.push(m | 25);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            } else {
                out.push(m | 26);
                out.extend_from_slice(&(n as u32).to_be_bytes());
            }
        }
        match c {
            Cbor::Uint(u) => head(0, *u, out),
            Cbor::Nint(n) => head(1, (-1 - n) as u64, out),
            Cbor::Bytes(b) => {
                head(2, b.len() as u64, out);
                out.extend_from_slice(b);
            }
            Cbor::Text(t) => {
                head(3, t.len() as u64, out);
                out.extend_from_slice(t.as_bytes());
            }
            Cbor::Array(a) => {
                head(4, a.len() as u64, out);
                for x in a {
                    enc(x, out);
                }
            }
            Cbor::Map(m) => {
                head(5, m.len() as u64, out);
                for (k, v) in m {
                    enc(k, out);
                    enc(v, out);
                }
            }
            Cbor::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
            Cbor::Null => out.push(0xf6),
        }
    }

    pub(crate) enum Key {
        P256(EcdsaKeyPair),
        Ed(Ed25519KeyPair),
    }

    /// A software authenticator.
    pub(crate) struct Authn {
        pub key: Key,
        pub id: Vec<u8>,
        pub count: u32,
        pub rp_id: String,
        pub flags: u8,
    }

    impl Authn {
        pub(crate) fn new(rp_id: &str, ed: bool) -> Authn {
            let rng = SystemRandom::new();
            let key = if ed {
                let p = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
                Key::Ed(Ed25519KeyPair::from_pkcs8(p.as_ref()).unwrap())
            } else {
                let p =
                    EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
                        .unwrap();
                Key::P256(
                    EcdsaKeyPair::from_pkcs8(
                        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                        p.as_ref(),
                        &rng,
                    )
                    .unwrap(),
                )
            };
            Authn {
                key,
                id: vec![7u8; 16],
                count: 0,
                rp_id: rp_id.into(),
                flags: UP | UV,
            }
        }
        fn cose(&self) -> Vec<u8> {
            let m = match &self.key {
                Key::P256(k) => {
                    let p = k.public_key().as_ref();
                    Cbor::Map(vec![
                        (Cbor::Uint(1), Cbor::Uint(2)),
                        (Cbor::Uint(3), Cbor::Nint(-7)),
                        (Cbor::Nint(-1), Cbor::Uint(1)),
                        (Cbor::Nint(-2), Cbor::Bytes(p[1..33].to_vec())),
                        (Cbor::Nint(-3), Cbor::Bytes(p[33..65].to_vec())),
                    ])
                }
                Key::Ed(k) => Cbor::Map(vec![
                    (Cbor::Uint(1), Cbor::Uint(1)),
                    (Cbor::Uint(3), Cbor::Nint(-8)),
                    (Cbor::Nint(-1), Cbor::Uint(6)),
                    (
                        Cbor::Nint(-2),
                        Cbor::Bytes(k.public_key().as_ref().to_vec()),
                    ),
                ]),
            };
            let mut o = Vec::new();
            enc(&m, &mut o);
            o
        }
        fn ad(&self, attested: bool) -> Vec<u8> {
            let mut a = Sha256::digest(self.rp_id.as_bytes()).to_vec();
            a.push(self.flags | if attested { AT } else { 0 });
            a.extend_from_slice(&self.count.to_be_bytes());
            if attested {
                a.extend_from_slice(&[0u8; 16]);
                a.extend_from_slice(&(self.id.len() as u16).to_be_bytes());
                a.extend_from_slice(&self.id);
                a.extend_from_slice(&self.cose());
            }
            a
        }
        pub(crate) fn client_data(ty: &str, challenge: &str, origin: &str) -> Vec<u8> {
            format!(r#"{{"type":"{ty}","challenge":"{challenge}","origin":"{origin}","crossOrigin":false}}"#).into_bytes()
        }
        /// (attestationObject, clientDataJSON)
        pub(crate) fn register(&self, challenge: &str, origin: &str) -> (Vec<u8>, Vec<u8>) {
            let att = Cbor::Map(vec![
                (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
                (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
                (Cbor::Text("authData".into()), Cbor::Bytes(self.ad(true))),
            ]);
            let mut o = Vec::new();
            enc(&att, &mut o);
            (o, Self::client_data("webauthn.create", challenge, origin))
        }
        /// (authenticatorData, clientDataJSON, signature)
        pub(crate) fn assert(
            &mut self,
            challenge: &str,
            origin: &str,
        ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
            self.count += 1;
            let ad = self.ad(false);
            let cd = Self::client_data("webauthn.get", challenge, origin);
            let mut msg = ad.clone();
            msg.extend_from_slice(&Sha256::digest(&cd));
            let sig = match &self.key {
                Key::P256(k) => k
                    .sign(&SystemRandom::new(), &msg)
                    .unwrap()
                    .as_ref()
                    .to_vec(),
                Key::Ed(k) => k.sign(&msg).as_ref().to_vec(),
            };
            (ad, cd, sig)
        }
    }

    const RP: Rp<'static> = Rp {
        id: "db.example.com",
        origin: "https://db.example.com",
    };

    #[test]
    fn register_and_login_es256_and_ed25519() {
        for ed in [false, true] {
            let mut a = Authn::new(RP.id, ed);
            let (att, cd) = a.register("chal1", RP.origin);
            let c = verify_registration(&att, &cd, "chal1", &RP).unwrap();
            assert_eq!(c.id, a.id);
            assert_eq!(c.alg, if ed { EDDSA } else { ES256 });
            let (ad, cd, sig) = a.assert("chal2", RP.origin);
            let n = verify_assertion(&c.cose, c.count, &ad, &cd, &sig, "chal2", &RP).unwrap();
            assert_eq!(n, 1);
            // replaying the same assertion (counter not increasing) fails
            assert!(verify_assertion(&c.cose, n, &ad, &cd, &sig, "chal2", &RP).is_err());
        }
    }

    #[test]
    fn every_check_rejects() {
        let mut a = Authn::new(RP.id, false);
        let (att, cd) = a.register("c", RP.origin);
        assert!(
            verify_registration(&att, &cd, "other", &RP)
                .unwrap_err()
                .contains("challenge")
        );
        let (att2, cd2) = a.register("c", "https://evil.example");
        assert!(
            verify_registration(&att2, &cd2, "c", &RP)
                .unwrap_err()
                .contains("origin")
        );
        let other_rp = Authn::new("evil.example", false);
        let (att3, cd3) = other_rp.register("c", RP.origin);
        assert!(
            verify_registration(&att3, &cd3, "c", &RP)
                .unwrap_err()
                .contains("RP id")
        );
        let mut no_uv = Authn::new(RP.id, false);
        no_uv.flags = UP;
        let (att4, cd4) = no_uv.register("c", RP.origin);
        assert!(
            verify_registration(&att4, &cd4, "c", &RP)
                .unwrap_err()
                .contains("verification")
        );
        let c = verify_registration(&att, &cd, "c", &RP).unwrap();
        // wrong type: a create response used for login
        let (ad, _, sig) = a.assert("x", RP.origin);
        let wrong = Authn::client_data("webauthn.create", "x", RP.origin);
        assert!(verify_assertion(&c.cose, 0, &ad, &wrong, &sig, "x", &RP).is_err());
        // tampered signature / data
        let (ad, cd, mut sig) = a.assert("y", RP.origin);
        let last = sig.len() - 1;
        sig[last] ^= 1;
        assert!(verify_assertion(&c.cose, 0, &ad, &cd, &sig, "y", &RP).is_err());
        let (mut ad, cd, sig) = a.assert("z", RP.origin);
        ad[36] ^= 1; // counter byte
        assert!(verify_assertion(&c.cose, 0, &ad, &cd, &sig, "z", &RP).is_err());
        // another key's signature
        let mut b = Authn::new(RP.id, false);
        let (ad, cd, sig) = b.assert("w", RP.origin);
        assert!(verify_assertion(&c.cose, 0, &ad, &cd, &sig, "w", &RP).is_err());
    }

    #[test]
    fn cbor_garbage_never_panics() {
        let mut s = 99u64;
        for _ in 0..50_000 {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            let n = (s % 48) as usize;
            let b: Vec<u8> = (0..n)
                .map(|i| (s.rotate_left(i as u32 * 7)) as u8)
                .collect();
            let _ = cbor(&b);
            let _ = cose_alg(&b);
            let rp = Rp {
                id: "a",
                origin: "b",
            };
            let _ = verify_registration(&b, b"{}", "c", &rp);
        }
        // deep nesting is refused
        let deep = vec![0x81u8; 100];
        assert!(cbor(&deep).is_err());
        // huge declared lengths are refused without allocating
        assert!(cbor(&[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).is_err());
        assert!(cbor(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0]).is_err());
    }
}
