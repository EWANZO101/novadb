//! Byte encodings.
//!
//! * **Key encoding** is order-preserving ("memcomparable"): comparing encoded bytes gives the
//!   same order as comparing values, and every encoding is self-delimiting, so composite keys
//!   are plain concatenations and prefix scans work.
//! * **Row encoding** is a compact tagged format. Decoders treat input as untrusted and return
//!   `SqlError` (never panic) on malformed bytes.

use crate::error::{Result, SqlError};
use crate::value::{ColType, Value};

const K_NULL: u8 = 0x00;
const K_VAL: u8 = 0x01;

fn flip64(i: i64) -> [u8; 8] {
    ((i as u64) ^ (1 << 63)).to_be_bytes()
}

fn flip128(i: i128) -> [u8; 16] {
    ((i as u128) ^ (1 << 127)).to_be_bytes()
}

/// Append the key encoding of `v` (already coerced to `ty`).
pub fn key_encode(out: &mut Vec<u8>, v: &Value, ty: ColType) -> Result<()> {
    if v.is_null() {
        out.push(K_NULL);
        return Ok(());
    }
    out.push(K_VAL);
    match (ty, v) {
        (ColType::Int | ColType::BigInt, Value::Int(i)) => out.extend_from_slice(&flip64(*i)),
        (ColType::DateTime(_), Value::DateTime(us)) => out.extend_from_slice(&flip64(*us)),
        (ColType::Decimal { s, .. }, Value::Dec { v, s: vs }) if *vs == s => {
            out.extend_from_slice(&flip128(*v))
        }
        (ColType::Varchar(_) | ColType::Text, Value::Str(t)) => escape_bytes(out, t.as_bytes()),
        (ColType::Blob, Value::Bytes(b)) => escape_bytes(out, b),
        _ => {
            return Err(SqlError::internal(format!(
                "key encode: value {v:?} does not match {ty:?}"
            )));
        }
    }
    Ok(())
}

/// 0x00 → 0x00 0xFF, terminated by 0x00 0x01 (sorts before any continuation).
fn escape_bytes(out: &mut Vec<u8>, b: &[u8]) {
    for &x in b {
        out.push(x);
        if x == 0 {
            out.push(0xFF);
        }
    }
    out.extend_from_slice(&[0x00, 0x01]);
}

/// Smallest byte string greater than every string that starts with `prefix`.
/// None if no such bound exists (prefix is all 0xFF).
pub fn prefix_end(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut p = prefix.to_vec();
    while let Some(last) = p.pop() {
        if last != 0xFF {
            p.push(last + 1);
            return Some(p);
        }
    }
    None
}

// ----- rows ----------------------------------------------------------------------------------

const R_NULL: u8 = 0;
const R_INT: u8 = 1;
const R_DEC: u8 = 2;
const R_STR: u8 = 3;
const R_BYTES: u8 = 4;
const R_DT: u8 = 5;
const ROW_VERSION: u8 = 1;

pub fn row_encode(row: &[Value]) -> Result<Vec<u8>> {
    let n = u16::try_from(row.len()).map_err(|_| SqlError::row_too_big())?;
    let mut out = Vec::with_capacity(16 + row.len() * 9);
    out.push(ROW_VERSION);
    out.extend_from_slice(&n.to_le_bytes());
    for v in row {
        match v {
            Value::Null => out.push(R_NULL),
            Value::Int(i) => {
                out.push(R_INT);
                out.extend_from_slice(&i.to_le_bytes());
            }
            Value::Dec { v, s } => {
                out.push(R_DEC);
                out.push(*s);
                out.extend_from_slice(&v.to_le_bytes());
            }
            Value::Str(t) => {
                out.push(R_STR);
                let l = u32::try_from(t.len()).map_err(|_| SqlError::row_too_big())?;
                out.extend_from_slice(&l.to_le_bytes());
                out.extend_from_slice(t.as_bytes());
            }
            Value::Bytes(b) => {
                out.push(R_BYTES);
                let l = u32::try_from(b.len()).map_err(|_| SqlError::row_too_big())?;
                out.extend_from_slice(&l.to_le_bytes());
                out.extend_from_slice(b);
            }
            Value::DateTime(us) => {
                out.push(R_DT);
                out.extend_from_slice(&us.to_le_bytes());
            }
        }
    }
    Ok(out)
}

struct Rd<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .i
            .checked_add(n)
            .ok_or_else(|| SqlError::corrupt("row: length overflow"))?;
        let s = self
            .b
            .get(self.i..end)
            .ok_or_else(|| SqlError::corrupt("row: truncated"))?;
        self.i = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| SqlError::corrupt("row: truncated"))
    }
}

/// Decode a row; `expect` = number of columns in the schema.
pub fn row_decode(b: &[u8], expect: usize) -> Result<Vec<Value>> {
    let mut r = Rd { b, i: 0 };
    if r.u8()? != ROW_VERSION {
        return Err(SqlError::corrupt("row: unknown format version"));
    }
    let n = usize::from(u16::from_le_bytes(r.arr()?));
    if n != expect {
        return Err(SqlError::corrupt(format!(
            "row: {n} columns, schema has {expect}"
        )));
    }
    let mut row = Vec::with_capacity(n);
    for _ in 0..n {
        row.push(match r.u8()? {
            R_NULL => Value::Null,
            R_INT => Value::Int(i64::from_le_bytes(r.arr()?)),
            R_DEC => {
                let s = r.u8()?;
                if s > 38 {
                    return Err(SqlError::corrupt("row: bad decimal scale"));
                }
                Value::Dec {
                    v: i128::from_le_bytes(r.arr()?),
                    s,
                }
            }
            R_STR => {
                let l = u32::from_le_bytes(r.arr()?) as usize;
                let t = std::str::from_utf8(r.take(l)?)
                    .map_err(|_| SqlError::corrupt("row: invalid UTF-8"))?;
                Value::Str(t.to_string())
            }
            R_BYTES => {
                let l = u32::from_le_bytes(r.arr()?) as usize;
                Value::Bytes(r.take(l)?.to_vec())
            }
            R_DT => Value::DateTime(i64::from_le_bytes(r.arr()?)),
            _ => return Err(SqlError::corrupt("row: unknown value tag")),
        });
    }
    if r.i != b.len() {
        return Err(SqlError::corrupt("row: trailing bytes"));
    }
    Ok(row)
}

/// Minimal reader/writer helpers for the catalog encoding.
pub struct W(pub Vec<u8>);

impl W {
    pub fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    pub fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn str(&mut self, s: &str) {
        self.u32(s.len() as u32);
        self.0.extend_from_slice(s.as_bytes());
    }
    pub fn bytes(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.0.extend_from_slice(b);
    }
}

pub struct R<'a> {
    rd: Rd<'a>,
}

impl<'a> R<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        R { rd: Rd { b, i: 0 } }
    }
    pub fn u8(&mut self) -> Result<u8> {
        self.rd.u8()
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.rd.arr()?))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.rd.arr()?))
    }
    pub fn str(&mut self) -> Result<String> {
        let l = self.u32()? as usize;
        std::str::from_utf8(self.rd.take(l)?)
            .map(str::to_string)
            .map_err(|_| SqlError::corrupt("catalog: invalid UTF-8"))
    }
    pub fn bytes(&mut self) -> Result<Vec<u8>> {
        let l = self.u32()? as usize;
        Ok(self.rd.take(l)?.to_vec())
    }
    pub fn done(&self) -> bool {
        self.rd.i == self.rd.b.len()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn k(v: Value, ty: ColType) -> Vec<u8> {
        let mut o = Vec::new();
        key_encode(&mut o, &v, ty).unwrap();
        o
    }

    #[test]
    fn key_order_ints() {
        let vals = [i64::MIN, -5, -1, 0, 1, 7, i64::MAX];
        for w in vals.windows(2) {
            assert!(k(Value::Int(w[0]), ColType::BigInt) < k(Value::Int(w[1]), ColType::BigInt));
        }
        assert!(k(Value::Null, ColType::BigInt) < k(Value::Int(i64::MIN), ColType::BigInt));
    }

    #[test]
    fn key_order_strings_and_composites() {
        let ty = ColType::Varchar(10);
        let words = ["", "\0", "\0\0", "a", "a\0", "a\0b", "ab", "b"];
        for w in words.windows(2) {
            assert!(
                k(Value::Str(w[0].into()), ty) < k(Value::Str(w[1].into()), ty),
                "{:?} < {:?}",
                w[0],
                w[1]
            );
        }
        // Composite (a, 2) < (a, 10) < (ab, 1): concatenation preserves order.
        let c = |s: &str, i: i64| {
            let mut o = k(Value::Str(s.into()), ty);
            o.extend(k(Value::Int(i), ColType::Int));
            o
        };
        assert!(c("a", 2) < c("a", 10));
        assert!(c("a", 10) < c("ab", 1));
        let p = k(Value::Str("a".into()), ty);
        assert!(c("a", 99).starts_with(&p) && !c("ab", 1).starts_with(&p));
    }

    #[test]
    fn key_order_decimal() {
        let ty = ColType::Decimal { p: 10, s: 2 };
        let vals = [-100_000, -1, 0, 1, 250, 99_999_999];
        for w in vals.windows(2) {
            assert!(k(Value::Dec { v: w[0], s: 2 }, ty) < k(Value::Dec { v: w[1], s: 2 }, ty));
        }
        assert!(key_encode(&mut Vec::new(), &Value::Dec { v: 1, s: 1 }, ty).is_err());
    }

    #[test]
    fn prefix_end_works() {
        assert_eq!(prefix_end(&[1, 2]), Some(vec![1, 3]));
        assert_eq!(prefix_end(&[1, 0xFF]), Some(vec![2]));
        assert_eq!(prefix_end(&[0xFF, 0xFF]), None);
    }

    #[test]
    fn row_roundtrip_and_corruption() {
        let row = vec![
            Value::Null,
            Value::Int(-7),
            Value::Dec { v: -12345, s: 2 },
            Value::Str("héllo".into()),
            Value::Bytes(vec![0, 1, 255]),
            Value::DateTime(123_456_789),
        ];
        let b = row_encode(&row).unwrap();
        assert_eq!(row_decode(&b, 6).unwrap(), row);
        assert!(row_decode(&b, 5).is_err());
        for cut in 0..b.len() {
            assert!(row_decode(&b[..cut], 6).is_err());
        }
        let mut extra = b.clone();
        extra.push(0);
        assert!(row_decode(&extra, 6).is_err());
        let mut bad = b;
        bad[3] = 99;
        assert!(row_decode(&bad, 6).is_err());
    }
}
