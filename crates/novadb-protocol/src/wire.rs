//! Byte-level helpers: length-encoded integers/strings and a bounds-checked reader.
//! Every decoder returns `Err(ProtoError)` on malformed input; nothing here can panic.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtoError(pub &'static str);

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed packet: {}", self.0)
    }
}

impl std::error::Error for ProtoError {}

pub type PResult<T> = Result<T, ProtoError>;

/// Append a length-encoded integer.
pub fn put_lenenc_int(out: &mut Vec<u8>, v: u64) {
    if v < 251 {
        out.push(v as u8);
    } else if v < 1 << 16 {
        out.push(0xFC);
        out.extend_from_slice(&(v as u16).to_le_bytes());
    } else if v < 1 << 24 {
        out.push(0xFD);
        out.extend_from_slice(&(v as u32).to_le_bytes()[..3]);
    } else {
        out.push(0xFE);
        out.extend_from_slice(&v.to_le_bytes());
    }
}

/// Append a length-encoded string.
pub fn put_lenenc_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_lenenc_int(out, b.len() as u64);
    out.extend_from_slice(b);
}

pub struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Reader { b, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.pos)
    }
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }
    pub fn take(&mut self, n: usize) -> PResult<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(ProtoError("length overflow"))?;
        let s = self.b.get(self.pos..end).ok_or(ProtoError("truncated"))?;
        self.pos = end;
        Ok(s)
    }
    pub fn rest(&mut self) -> &'a [u8] {
        let s = self.b.get(self.pos..).unwrap_or(&[]);
        self.pos = self.b.len();
        s
    }
    pub fn u8(&mut self) -> PResult<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> PResult<u16> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }
    pub fn u32(&mut self) -> PResult<u32> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    pub fn u64(&mut self) -> PResult<u64> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_le_bytes(a))
    }
    pub fn lenenc_int(&mut self) -> PResult<u64> {
        match self.u8()? {
            x @ 0..=250 => Ok(u64::from(x)),
            0xFC => Ok(u64::from(self.u16()?)),
            0xFD => {
                let s = self.take(3)?;
                Ok(u64::from(s[0]) | u64::from(s[1]) << 8 | u64::from(s[2]) << 16)
            }
            0xFE => self.u64(),
            _ => Err(ProtoError("invalid length-encoded integer")),
        }
    }
    pub fn lenenc_bytes(&mut self) -> PResult<&'a [u8]> {
        let n = self.lenenc_int()?;
        let n = usize::try_from(n).map_err(|_| ProtoError("length too large"))?;
        self.take(n)
    }
    /// NUL-terminated string (terminator consumed). Missing terminator at end of packet is
    /// accepted (some clients omit it on the last field).
    pub fn cstr(&mut self) -> PResult<&'a [u8]> {
        let rest = self.b.get(self.pos..).unwrap_or(&[]);
        match rest.iter().position(|&c| c == 0) {
            Some(i) => {
                let s = &rest[..i];
                self.pos += i + 1;
                Ok(s)
            }
            None => Ok(self.rest()),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn lenenc_roundtrip() {
        for v in [
            0u64,
            250,
            251,
            65_535,
            65_536,
            (1 << 24) - 1,
            1 << 24,
            u64::MAX,
        ] {
            let mut b = Vec::new();
            put_lenenc_int(&mut b, v);
            let mut r = Reader::new(&b);
            assert_eq!(r.lenenc_int().unwrap(), v);
            assert!(r.is_empty());
            for cut in 0..b.len() {
                assert!(Reader::new(&b[..cut]).lenenc_int().is_err());
            }
        }
        assert!(Reader::new(&[0xFF]).lenenc_int().is_err());
        assert!(
            Reader::new(&[0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
                .lenenc_bytes()
                .is_err()
        );
    }
}
