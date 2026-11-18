//! Binary encoding of Raft messages and log entries (bounds-checked decoding: input comes from
//! the network / disk).

use crate::{Entry, EntryKind, HardState, Msg, Snapshot};
use std::sync::Arc;

/// Largest frame accepted (snapshots are sent in one message).
pub const MAX_FRAME: usize = 512 << 20;

#[derive(Debug, PartialEq, Eq)]
pub struct DecodeError(pub &'static str);

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "raft decode: {}", self.0)
    }
}
impl std::error::Error for DecodeError {}

type R<T> = Result<T, DecodeError>;

struct W(Vec<u8>);
impl W {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.u64(b.len() as u64);
        self.0.extend_from_slice(b);
    }
}

struct Rd<'a> {
    b: &'a [u8],
    i: usize,
}
impl Rd<'_> {
    fn u8(&mut self) -> R<u8> {
        let v = *self.b.get(self.i).ok_or(DecodeError("truncated"))?;
        self.i += 1;
        Ok(v)
    }
    fn u64(&mut self) -> R<u64> {
        let s = self
            .b
            .get(self.i..self.i + 8)
            .ok_or(DecodeError("truncated"))?;
        self.i += 8;
        Ok(u64::from_le_bytes(
            s.try_into().map_err(|_| DecodeError("truncated"))?,
        ))
    }
    fn len(&mut self) -> R<usize> {
        let n = self.u64()?;
        if n > (self.b.len() - self.i) as u64 {
            return Err(DecodeError("length beyond input"));
        }
        Ok(n as usize)
    }
    fn bytes(&mut self) -> R<Vec<u8>> {
        let n = self.len()?;
        let v = self.b[self.i..self.i + n].to_vec();
        self.i += n;
        Ok(v)
    }
    fn done(&self) -> R<()> {
        if self.i == self.b.len() {
            Ok(())
        } else {
            Err(DecodeError("trailing bytes"))
        }
    }
}

fn put_entry(w: &mut W, e: &Entry) {
    w.u64(e.term);
    w.u64(e.index);
    match &e.kind {
        EntryKind::Noop => w.u8(0),
        EntryKind::Data(d) => {
            w.u8(1);
            w.bytes(d);
        }
        EntryKind::Config(v) => {
            w.u8(2);
            w.u64(v.len() as u64);
            for x in v {
                w.u64(*x);
            }
        }
    }
}

fn get_entry(r: &mut Rd<'_>) -> R<Entry> {
    let term = r.u64()?;
    let index = r.u64()?;
    let kind = match r.u8()? {
        0 => EntryKind::Noop,
        1 => EntryKind::Data(r.bytes()?),
        2 => {
            let n = r.len()?;
            if n > 1024 {
                return Err(DecodeError("too many voters"));
            }
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                v.push(r.u64()?);
            }
            EntryKind::Config(v)
        }
        _ => return Err(DecodeError("entry kind")),
    };
    Ok(Entry { term, index, kind })
}

fn put_snapshot(w: &mut W, s: &Snapshot) {
    w.u64(s.index);
    w.u64(s.term);
    w.u64(s.voters.len() as u64);
    for v in &s.voters {
        w.u64(*v);
    }
    w.bytes(&s.data);
}

fn get_snapshot(r: &mut Rd<'_>) -> R<Snapshot> {
    let index = r.u64()?;
    let term = r.u64()?;
    let n = r.len()?;
    if n > 1024 {
        return Err(DecodeError("too many voters"));
    }
    let mut voters = Vec::with_capacity(n);
    for _ in 0..n {
        voters.push(r.u64()?);
    }
    Ok(Snapshot {
        index,
        term,
        voters,
        data: Arc::new(r.bytes()?),
    })
}

pub fn encode_entry(e: &Entry) -> Vec<u8> {
    let mut w = W(Vec::new());
    put_entry(&mut w, e);
    w.0
}

pub fn decode_entry(b: &[u8]) -> R<Entry> {
    let mut r = Rd { b, i: 0 };
    let e = get_entry(&mut r)?;
    r.done()?;
    Ok(e)
}

pub fn encode_hard_state(h: &HardState) -> Vec<u8> {
    let mut w = W(Vec::new());
    w.u64(h.term);
    w.u64(h.voted_for.map_or(0, |v| v + 1));
    w.0
}

pub fn decode_hard_state(b: &[u8]) -> R<HardState> {
    let mut r = Rd { b, i: 0 };
    let term = r.u64()?;
    let v = r.u64()?;
    r.done()?;
    Ok(HardState {
        term,
        voted_for: v.checked_sub(1),
    })
}

pub fn encode_snapshot(s: &Snapshot) -> Vec<u8> {
    let mut w = W(Vec::new());
    put_snapshot(&mut w, s);
    w.0
}

pub fn decode_snapshot(b: &[u8]) -> R<Snapshot> {
    let mut r = Rd { b, i: 0 };
    let s = get_snapshot(&mut r)?;
    r.done()?;
    Ok(s)
}

pub fn encode_msg(m: &Msg) -> Vec<u8> {
    let mut w = W(Vec::new());
    match m {
        Msg::Vote {
            term,
            last_index,
            last_term,
            pre,
        } => {
            w.u8(1);
            w.u64(*term);
            w.u64(*last_index);
            w.u64(*last_term);
            w.u8(u8::from(*pre));
        }
        Msg::VoteResp { term, granted, pre } => {
            w.u8(2);
            w.u64(*term);
            w.u8(u8::from(*granted));
            w.u8(u8::from(*pre));
        }
        Msg::Append {
            term,
            prev_index,
            prev_term,
            entries,
            commit,
            seq,
        } => {
            w.u8(3);
            w.u64(*term);
            w.u64(*prev_index);
            w.u64(*prev_term);
            w.u64(*commit);
            w.u64(*seq);
            w.u64(entries.len() as u64);
            for e in entries {
                put_entry(&mut w, e);
            }
        }
        Msg::AppendResp {
            term,
            success,
            index,
            seq,
        } => {
            w.u8(4);
            w.u64(*term);
            w.u8(u8::from(*success));
            w.u64(*index);
            w.u64(*seq);
        }
        Msg::InstallSnapshot {
            term,
            snapshot,
            seq,
        } => {
            w.u8(5);
            w.u64(*term);
            w.u64(*seq);
            put_snapshot(&mut w, snapshot);
        }
    }
    w.0
}

fn bool8(v: u8) -> R<bool> {
    match v {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(DecodeError("bool")),
    }
}

pub fn decode_msg(b: &[u8]) -> R<Msg> {
    if b.len() > MAX_FRAME {
        return Err(DecodeError("message too large"));
    }
    let mut r = Rd { b, i: 0 };
    let m = match r.u8()? {
        1 => Msg::Vote {
            term: r.u64()?,
            last_index: r.u64()?,
            last_term: r.u64()?,
            pre: bool8(r.u8()?)?,
        },
        2 => Msg::VoteResp {
            term: r.u64()?,
            granted: bool8(r.u8()?)?,
            pre: bool8(r.u8()?)?,
        },
        3 => {
            let term = r.u64()?;
            let prev_index = r.u64()?;
            let prev_term = r.u64()?;
            let commit = r.u64()?;
            let seq = r.u64()?;
            let n = r.len()?;
            let mut entries = Vec::with_capacity(n.min(4096));
            for _ in 0..n {
                entries.push(get_entry(&mut r)?);
            }
            Msg::Append {
                term,
                prev_index,
                prev_term,
                entries,
                commit,
                seq,
            }
        }
        4 => Msg::AppendResp {
            term: r.u64()?,
            success: bool8(r.u8()?)?,
            index: r.u64()?,
            seq: r.u64()?,
        },
        5 => {
            let term = r.u64()?;
            let seq = r.u64()?;
            Msg::InstallSnapshot {
                term,
                seq,
                snapshot: get_snapshot(&mut r)?,
            }
        }
        _ => return Err(DecodeError("message kind")),
    };
    r.done()?;
    Ok(m)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn roundtrip_and_garbage() {
        let msgs = vec![
            Msg::Vote {
                term: 3,
                last_index: 9,
                last_term: 2,
                pre: true,
            },
            Msg::VoteResp {
                term: 3,
                granted: false,
                pre: false,
            },
            Msg::Append {
                term: 4,
                prev_index: 7,
                prev_term: 3,
                commit: 6,
                seq: 11,
                entries: vec![
                    Entry {
                        term: 4,
                        index: 8,
                        kind: EntryKind::Noop,
                    },
                    Entry {
                        term: 4,
                        index: 9,
                        kind: EntryKind::Data(b"hello".to_vec()),
                    },
                    Entry {
                        term: 4,
                        index: 10,
                        kind: EntryKind::Config(vec![1, 2, 3]),
                    },
                ],
            },
            Msg::AppendResp {
                term: 4,
                success: true,
                index: 10,
                seq: 11,
            },
            Msg::InstallSnapshot {
                term: 5,
                seq: 1,
                snapshot: Snapshot {
                    index: 10,
                    term: 4,
                    voters: vec![1, 2],
                    data: Arc::new(vec![9; 100]),
                },
            },
        ];
        for m in msgs {
            let b = encode_msg(&m);
            assert_eq!(decode_msg(&b).unwrap(), m);
            // every truncation and a trailing byte are rejected, never panic
            for n in 0..b.len() {
                assert!(decode_msg(&b[..n]).is_err());
            }
            let mut x = b.clone();
            x.push(0);
            assert!(decode_msg(&x).is_err());
        }
        // random garbage never panics
        let mut s = 12345u64;
        for _ in 0..20_000 {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            let n = (s % 64) as usize;
            let b: Vec<u8> = (0..n).map(|i| (s >> (i % 8 * 8)) as u8).collect();
            let _ = decode_msg(&b);
            let _ = decode_entry(&b);
            let _ = decode_snapshot(&b);
        }
        let h = HardState {
            term: 7,
            voted_for: Some(0),
        };
        assert_eq!(decode_hard_state(&encode_hard_state(&h)).unwrap(), h);
        let h = HardState {
            term: 7,
            voted_for: None,
        };
        assert_eq!(decode_hard_state(&encode_hard_state(&h)).unwrap(), h);
    }
}
