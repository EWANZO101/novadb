//! MySQL client/server protocol messages (protocol 41). Encoders build payloads (without the
//! 4-byte packet header); decoders parse untrusted client payloads.

use novadb_sql::{ColType, Value};

use crate::wire::{PResult, ProtoError, Reader, put_lenenc_bytes, put_lenenc_int};

// ----- capability / status flags -------------------------------------------------------------

pub const CLIENT_LONG_PASSWORD: u32 = 1;
pub const CLIENT_FOUND_ROWS: u32 = 2;
pub const CLIENT_LONG_FLAG: u32 = 4;
pub const CLIENT_CONNECT_WITH_DB: u32 = 8;
pub const CLIENT_PROTOCOL_41: u32 = 0x200;
pub const CLIENT_INTERACTIVE: u32 = 0x400;
pub const CLIENT_SSL: u32 = 0x800;
pub const CLIENT_TRANSACTIONS: u32 = 0x2000;
pub const CLIENT_SECURE_CONNECTION: u32 = 0x8000;
pub const CLIENT_MULTI_STATEMENTS: u32 = 0x1_0000;
pub const CLIENT_MULTI_RESULTS: u32 = 0x2_0000;
pub const CLIENT_PS_MULTI_RESULTS: u32 = 0x4_0000;
pub const CLIENT_PLUGIN_AUTH: u32 = 0x8_0000;
pub const CLIENT_CONNECT_ATTRS: u32 = 0x10_0000;
pub const CLIENT_PLUGIN_AUTH_LENENC_DATA: u32 = 0x20_0000;
pub const CLIENT_DEPRECATE_EOF: u32 = 0x100_0000;

/// What the server offers.
pub const SERVER_CAPS: u32 = CLIENT_LONG_PASSWORD
    | CLIENT_FOUND_ROWS
    | CLIENT_LONG_FLAG
    | CLIENT_CONNECT_WITH_DB
    | CLIENT_PROTOCOL_41
    | CLIENT_INTERACTIVE
    | CLIENT_SSL
    | CLIENT_TRANSACTIONS
    | CLIENT_SECURE_CONNECTION
    | CLIENT_MULTI_STATEMENTS
    | CLIENT_MULTI_RESULTS
    | CLIENT_PS_MULTI_RESULTS
    | CLIENT_PLUGIN_AUTH
    | CLIENT_CONNECT_ATTRS
    | CLIENT_PLUGIN_AUTH_LENENC_DATA
    | CLIENT_DEPRECATE_EOF;

pub const SERVER_STATUS_AUTOCOMMIT: u16 = 0x0002;
pub const SERVER_MORE_RESULTS_EXISTS: u16 = 0x0008;

pub const AUTH_PLUGIN: &str = "caching_sha2_password";
/// utf8mb4_bin
pub const CHARSET_UTF8MB4: u16 = 46;
pub const CHARSET_BINARY: u16 = 63;

// column types
pub const T_LONG: u8 = 3;
pub const T_NULL: u8 = 6;
pub const T_LONGLONG: u8 = 8;
pub const T_DATETIME: u8 = 12;
pub const T_NEWDECIMAL: u8 = 246;
pub const T_BLOB: u8 = 252;
pub const T_VAR_STRING: u8 = 253;

// column flags
pub const F_NOT_NULL: u16 = 1;
pub const F_BLOB: u16 = 16;
pub const F_BINARY: u16 = 128;
pub const F_NUM: u16 = 32768;

// commands
pub const COM_QUIT: u8 = 0x01;
pub const COM_INIT_DB: u8 = 0x02;
pub const COM_QUERY: u8 = 0x03;
pub const COM_FIELD_LIST: u8 = 0x04;
pub const COM_STATISTICS: u8 = 0x09;
pub const COM_PING: u8 = 0x0e;
pub const COM_STMT_PREPARE: u8 = 0x16;
pub const COM_STMT_EXECUTE: u8 = 0x17;
pub const COM_STMT_SEND_LONG_DATA: u8 = 0x18;
pub const COM_STMT_CLOSE: u8 = 0x19;
pub const COM_STMT_RESET: u8 = 0x1a;
pub const COM_SET_OPTION: u8 = 0x1b;
pub const COM_RESET_CONNECTION: u8 = 0x1f;

// ----- handshake -----------------------------------------------------------------------------

/// Initial Handshake v10. `scramble` must be 20 bytes without NUL.
pub fn handshake_v10(version: &str, conn_id: u32, scramble: &[u8; 20]) -> Vec<u8> {
    let mut p = Vec::with_capacity(128);
    p.push(10);
    p.extend_from_slice(version.as_bytes());
    p.push(0);
    p.extend_from_slice(&conn_id.to_le_bytes());
    p.extend_from_slice(&scramble[..8]);
    p.push(0);
    p.extend_from_slice(&(SERVER_CAPS as u16).to_le_bytes());
    p.push(CHARSET_UTF8MB4 as u8);
    p.extend_from_slice(&SERVER_STATUS_AUTOCOMMIT.to_le_bytes());
    p.extend_from_slice(&((SERVER_CAPS >> 16) as u16).to_le_bytes());
    p.push(21);
    p.extend_from_slice(&[0; 10]);
    p.extend_from_slice(&scramble[8..]);
    p.push(0);
    p.extend_from_slice(AUTH_PLUGIN.as_bytes());
    p.push(0);
    p
}

/// SSLRequest: exactly 32 bytes with CLIENT_SSL set.
pub fn parse_ssl_request(p: &[u8]) -> Option<u32> {
    if p.len() != 32 {
        return None;
    }
    let caps = u32::from_le_bytes([p[0], p[1], p[2], p[3]]);
    (caps & CLIENT_SSL != 0).then_some(caps)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeResponse {
    pub caps: u32,
    pub max_packet: u32,
    pub charset: u8,
    pub user: String,
    pub auth_response: Vec<u8>,
    pub database: Option<String>,
    pub plugin: Option<String>,
}

pub fn parse_handshake_response(p: &[u8]) -> PResult<HandshakeResponse> {
    let mut r = Reader::new(p);
    let caps = r.u32()?;
    if caps & CLIENT_PROTOCOL_41 == 0 {
        return Err(ProtoError("client does not support protocol 41"));
    }
    let max_packet = r.u32()?;
    let charset = r.u8()?;
    r.take(23)?;
    let user =
        String::from_utf8(r.cstr()?.to_vec()).map_err(|_| ProtoError("user name not UTF-8"))?;
    if user.len() > 128 {
        return Err(ProtoError("user name too long"));
    }
    let auth_response = if caps & CLIENT_PLUGIN_AUTH_LENENC_DATA != 0 {
        r.lenenc_bytes()?.to_vec()
    } else if caps & CLIENT_SECURE_CONNECTION != 0 {
        let n = r.u8()?;
        r.take(usize::from(n))?.to_vec()
    } else {
        r.cstr()?.to_vec()
    };
    if auth_response.len() > 1024 {
        return Err(ProtoError("auth response too long"));
    }
    let database = if caps & CLIENT_CONNECT_WITH_DB != 0 && !r.is_empty() {
        let d = r.cstr()?;
        (!d.is_empty()).then(|| String::from_utf8_lossy(d).into_owned())
    } else {
        None
    };
    let plugin = if caps & CLIENT_PLUGIN_AUTH != 0 && !r.is_empty() {
        Some(String::from_utf8_lossy(r.cstr()?).into_owned())
    } else {
        None
    };
    // Connection attributes (if any) are ignored.
    Ok(HandshakeResponse {
        caps,
        max_packet,
        charset,
        user,
        auth_response,
        database,
        plugin,
    })
}

/// AuthSwitchRequest to caching_sha2_password.
pub fn auth_switch(scramble: &[u8; 20]) -> Vec<u8> {
    let mut p = vec![0xFE];
    p.extend_from_slice(AUTH_PLUGIN.as_bytes());
    p.push(0);
    p.extend_from_slice(scramble);
    p.push(0);
    p
}

/// caching_sha2_password "perform full authentication" (client then sends the cleartext
/// password over TLS).
pub fn auth_full_request() -> Vec<u8> {
    vec![0x01, 0x04]
}

/// Password packet after a full-auth request: cleartext, NUL-terminated.
pub fn parse_cleartext_password(p: &[u8]) -> PResult<String> {
    let pw = match p.iter().position(|&c| c == 0) {
        Some(i) => &p[..i],
        None => p,
    };
    if pw.len() > 512 {
        return Err(ProtoError("password too long"));
    }
    String::from_utf8(pw.to_vec()).map_err(|_| ProtoError("password not UTF-8"))
}

// ----- generic responses ---------------------------------------------------------------------

pub fn ok(
    affected: u64,
    last_insert_id: u64,
    status: u16,
    info: &str,
    eof_header: bool,
) -> Vec<u8> {
    let mut p = vec![if eof_header { 0xFE } else { 0x00 }];
    put_lenenc_int(&mut p, affected);
    put_lenenc_int(&mut p, last_insert_id);
    p.extend_from_slice(&status.to_le_bytes());
    p.extend_from_slice(&0u16.to_le_bytes());
    // Real servers length-prefix the info string and libmysql/libmariadb read it that way.
    if !info.is_empty() {
        put_lenenc_bytes(&mut p, info.as_bytes());
    }
    p
}

pub fn err(code: u16, state: &str, msg: &str) -> Vec<u8> {
    let mut p = vec![0xFF];
    p.extend_from_slice(&code.to_le_bytes());
    p.push(b'#');
    let st = state.as_bytes();
    let mut s5 = *b"HY000";
    if st.len() == 5 {
        s5.copy_from_slice(st);
    }
    p.extend_from_slice(&s5);
    let m: String = msg.chars().take(512).collect();
    p.extend_from_slice(m.as_bytes());
    p
}

pub fn eof(status: u16) -> Vec<u8> {
    let mut p = vec![0xFE, 0, 0];
    p.extend_from_slice(&status.to_le_bytes());
    p
}

// ----- result sets ---------------------------------------------------------------------------

/// Wire description of one result column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireCol {
    pub name: String,
    pub ty: u8,
    pub charset: u16,
    pub length: u32,
    pub flags: u16,
    pub decimals: u8,
}

/// Map a column (declared type, or inferred from values for expressions) to wire metadata.
pub fn wire_col(
    name: &str,
    ty: Option<ColType>,
    values: &mut dyn Iterator<Item = &Value>,
) -> WireCol {
    let mk = |ty, charset, length, flags, decimals| WireCol {
        name: name.to_string(),
        ty,
        charset,
        length,
        flags,
        decimals,
    };
    match ty {
        Some(ColType::Int) => mk(T_LONG, CHARSET_BINARY, 11, F_NUM, 0),
        Some(ColType::BigInt) => mk(T_LONGLONG, CHARSET_BINARY, 20, F_NUM, 0),
        Some(ColType::Decimal { p, s }) => {
            mk(T_NEWDECIMAL, CHARSET_BINARY, u32::from(p) + 2, F_NUM, s)
        }
        Some(ColType::Varchar(n)) => mk(T_VAR_STRING, CHARSET_UTF8MB4, n.saturating_mul(4), 0, 0),
        Some(ColType::Text) => mk(T_BLOB, CHARSET_UTF8MB4, 262_140, F_BLOB, 0),
        Some(ColType::Blob) => mk(T_BLOB, CHARSET_BINARY, 65_535, F_BLOB | F_BINARY, 0),
        Some(ColType::DateTime(f)) => mk(
            T_DATETIME,
            CHARSET_BINARY,
            19 + if f > 0 { u32::from(f) + 1 } else { 0 },
            F_BINARY,
            f,
        ),
        None => {
            // Expressions: one consistent type if all non-NULL values agree, else text.
            let mut kind: Option<u8> = None;
            let mut max_scale = 0u8;
            let mut mixed = false;
            for v in values {
                let k = match v {
                    Value::Null => continue,
                    Value::Int(_) => T_LONGLONG,
                    Value::Dec { s, .. } => {
                        max_scale = max_scale.max(*s);
                        T_NEWDECIMAL
                    }
                    Value::Str(_) => T_VAR_STRING,
                    Value::Bytes(_) => T_BLOB,
                    Value::DateTime(_) => T_VAR_STRING,
                };
                match kind {
                    None => kind = Some(k),
                    Some(x) if x != k => mixed = true,
                    _ => {}
                }
            }
            match (kind, mixed) {
                (Some(T_LONGLONG), false) => mk(T_LONGLONG, CHARSET_BINARY, 21, F_NUM, 0),
                (Some(T_NEWDECIMAL), false) => {
                    mk(T_NEWDECIMAL, CHARSET_BINARY, 67, F_NUM, max_scale)
                }
                (Some(T_BLOB), false) => mk(T_BLOB, CHARSET_BINARY, 65_535, F_BLOB | F_BINARY, 0),
                (None, _) => mk(T_NULL, CHARSET_BINARY, 0, F_BINARY, 0),
                _ => mk(T_VAR_STRING, CHARSET_UTF8MB4, 1024, 0, 0x1f),
            }
        }
    }
}

pub fn column_count(n: usize) -> Vec<u8> {
    let mut p = Vec::new();
    put_lenenc_int(&mut p, n as u64);
    p
}

pub fn column_def(c: &WireCol) -> Vec<u8> {
    let mut p = Vec::with_capacity(48 + c.name.len());
    put_lenenc_bytes(&mut p, b"def");
    put_lenenc_bytes(&mut p, b"novadb");
    put_lenenc_bytes(&mut p, b"");
    put_lenenc_bytes(&mut p, b"");
    put_lenenc_bytes(&mut p, c.name.as_bytes());
    put_lenenc_bytes(&mut p, c.name.as_bytes());
    p.push(0x0c);
    p.extend_from_slice(&c.charset.to_le_bytes());
    p.extend_from_slice(&c.length.to_le_bytes());
    p.push(c.ty);
    p.extend_from_slice(&c.flags.to_le_bytes());
    p.push(c.decimals);
    p.extend_from_slice(&[0, 0]);
    p
}

/// Text value as sent on the wire, formatted for the column's declared type.
fn text_bytes(v: &Value, ty: Option<ColType>) -> Option<Vec<u8>> {
    match v {
        Value::Null => None,
        Value::Bytes(b) => Some(b.clone()),
        other => other.text_as(ty).map(String::into_bytes),
    }
}

pub fn text_row(row: &[Value], types: &[Option<ColType>]) -> Vec<u8> {
    let mut p = Vec::new();
    for (i, v) in row.iter().enumerate() {
        match text_bytes(v, types.get(i).copied().flatten()) {
            None => p.push(0xFB),
            Some(b) => put_lenenc_bytes(&mut p, &b),
        }
    }
    p
}

/// Split "YYYY-MM-DD HH:MM:SS[.ffffff]" into fields.
fn dt_fields(s: &str) -> Option<(u16, u8, u8, u8, u8, u8, u32)> {
    let n = |a: usize, b: usize| s.get(a..b).and_then(|x| x.parse::<u32>().ok());
    let us = match s.get(20..) {
        Some(f) if !f.is_empty() => format!("{f:0<6}").get(..6)?.parse().ok()?,
        _ => 0,
    };
    Some((
        n(0, 4)? as u16,
        n(5, 7)? as u8,
        n(8, 10)? as u8,
        n(11, 13)? as u8,
        n(14, 16)? as u8,
        n(17, 19)? as u8,
        us,
    ))
}

/// Binary-protocol row (COM_STMT_EXECUTE results).
pub fn binary_row(row: &[Value], cols: &[WireCol], types: &[Option<ColType>]) -> Vec<u8> {
    let n = row.len();
    let mut p = vec![0x00];
    let mut bitmap = vec![0u8; (n + 7 + 2) / 8];
    let mut body = Vec::new();
    for (i, v) in row.iter().enumerate() {
        let ty = cols.get(i).map_or(T_VAR_STRING, |c| c.ty);
        if v.is_null() || ty == T_NULL {
            bitmap[(i + 2) / 8] |= 1 << ((i + 2) % 8);
            continue;
        }
        match ty {
            T_LONG => {
                let x = match v {
                    Value::Int(x) => *x as i32,
                    _ => 0,
                };
                body.extend_from_slice(&x.to_le_bytes());
            }
            T_LONGLONG => {
                let x = match v {
                    Value::Int(x) => *x,
                    _ => 0,
                };
                body.extend_from_slice(&x.to_le_bytes());
            }
            T_DATETIME => {
                let s = v.text_as(Some(ColType::DateTime(6))).unwrap_or_default();
                match dt_fields(&s) {
                    Some((y, mo, d, h, mi, se, us)) => {
                        let len: u8 = if us != 0 {
                            11
                        } else if h != 0 || mi != 0 || se != 0 {
                            7
                        } else {
                            4
                        };
                        body.push(len);
                        body.extend_from_slice(&y.to_le_bytes());
                        body.extend_from_slice(&[mo, d]);
                        if len >= 7 {
                            body.extend_from_slice(&[h, mi, se]);
                        }
                        if len == 11 {
                            body.extend_from_slice(&us.to_le_bytes());
                        }
                    }
                    None => body.push(0),
                }
            }
            _ => {
                let b = text_bytes(v, types.get(i).copied().flatten()).unwrap_or_default();
                put_lenenc_bytes(&mut body, &b);
            }
        }
    }
    p.extend_from_slice(&bitmap);
    p.extend_from_slice(&body);
    p
}

// ----- prepared statements -------------------------------------------------------------------

pub fn stmt_prepare_ok(stmt_id: u32, columns: u16, params: u16) -> Vec<u8> {
    let mut p = vec![0x00];
    p.extend_from_slice(&stmt_id.to_le_bytes());
    p.extend_from_slice(&columns.to_le_bytes());
    p.extend_from_slice(&params.to_le_bytes());
    p.push(0);
    p.extend_from_slice(&0u16.to_le_bytes());
    p
}

/// A bound parameter value as sent by the client.
#[derive(Debug, Clone, PartialEq)]
pub enum Param {
    Null,
    Int(i64),
    UInt(u64),
    Double(f64),
    Bytes(Vec<u8>),
    /// Text form "YYYY-MM-DD HH:MM:SS[.ffffff]" (also for DATE / TIMESTAMP).
    DateTime(String),
    Time(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Execute {
    pub stmt_id: u32,
    pub params: Vec<Param>,
    /// Parameter types (sent once, reused on later executes).
    pub types: Vec<u16>,
}

pub fn parse_stmt_id(p: &[u8]) -> PResult<u32> {
    Reader::new(p).u32()
}

/// COM_STMT_EXECUTE payload (after the command byte). `num_params` comes from PREPARE,
/// `prev_types` from an earlier execute, `long_data` from COM_STMT_SEND_LONG_DATA.
pub fn parse_execute(
    p: &[u8],
    num_params: usize,
    prev_types: &[u16],
    long_data: &std::collections::HashMap<u16, Vec<u8>>,
) -> PResult<Execute> {
    let mut r = Reader::new(p);
    let stmt_id = r.u32()?;
    let _flags = r.u8()?;
    let _iterations = r.u32()?;
    if num_params == 0 {
        return Ok(Execute {
            stmt_id,
            params: vec![],
            types: vec![],
        });
    }
    let bitmap = r.take(num_params.div_ceil(8))?;
    let new_bound = r.u8()?;
    let types: Vec<u16> = if new_bound == 1 {
        (0..num_params).map(|_| r.u16()).collect::<PResult<_>>()?
    } else if prev_types.len() == num_params {
        prev_types.to_vec()
    } else {
        return Err(ProtoError("parameter types were never sent"));
    };
    let mut params = Vec::with_capacity(num_params);
    for (i, &t) in types.iter().enumerate() {
        if bitmap[i / 8] & (1 << (i % 8)) != 0 {
            params.push(Param::Null);
            continue;
        }
        if let Some(d) = long_data.get(&(i as u16)) {
            params.push(Param::Bytes(d.clone()));
            continue;
        }
        let unsigned = t & 0x8000 != 0;
        let ty = (t & 0xFF) as u8;
        let v = match ty {
            1 => {
                let b = r.u8()?;
                if unsigned {
                    Param::UInt(u64::from(b))
                } else {
                    Param::Int(i64::from(b as i8))
                }
            }
            2 | 13 => {
                let x = r.u16()?;
                if unsigned {
                    Param::UInt(u64::from(x))
                } else {
                    Param::Int(i64::from(x as i16))
                }
            }
            3 | 9 => {
                let x = r.u32()?;
                if unsigned {
                    Param::UInt(u64::from(x))
                } else {
                    Param::Int(i64::from(x as i32))
                }
            }
            8 => {
                let x = r.u64()?;
                if unsigned {
                    Param::UInt(x)
                } else {
                    Param::Int(x as i64)
                }
            }
            4 => {
                let s = r.take(4)?;
                Param::Double(f64::from(f32::from_le_bytes([s[0], s[1], s[2], s[3]])))
            }
            5 => Param::Double(f64::from_bits(r.u64()?)),
            6 => Param::Null,
            7 | 10 | 12 => {
                let n = r.u8()?;
                let mut f = Reader::new(r.take(usize::from(n))?);
                let (y, mo, d) = if n >= 4 {
                    (f.u16()?, f.u8()?, f.u8()?)
                } else {
                    (0, 0, 0)
                };
                let (h, mi, se) = if n >= 7 {
                    (f.u8()?, f.u8()?, f.u8()?)
                } else {
                    (0, 0, 0)
                };
                let us = if n >= 11 { f.u32()? } else { 0 };
                Param::DateTime(format!(
                    "{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{se:02}.{us:06}"
                ))
            }
            11 => {
                let n = r.u8()?;
                let mut f = Reader::new(r.take(usize::from(n))?);
                if n >= 8 {
                    let neg = f.u8()? == 1;
                    let days = f.u32()?;
                    let (h, mi, se) = (f.u8()?, f.u8()?, f.u8()?);
                    let hours = u64::from(days) * 24 + u64::from(h);
                    Param::Time(format!(
                        "{}{hours:02}:{mi:02}:{se:02}",
                        if neg { "-" } else { "" }
                    ))
                } else {
                    Param::Time("00:00:00".into())
                }
            }
            // DECIMAL, VARCHAR, ENUM, SET, *BLOB, VAR_STRING, STRING, GEOMETRY, JSON, BIT
            0 | 15 | 16 | 245..=255 => Param::Bytes(r.lenenc_bytes()?.to_vec()),
            _ => return Err(ProtoError("unsupported parameter type")),
        };
        params.push(v);
    }
    Ok(Execute {
        stmt_id,
        params,
        types,
    })
}

/// Convert a bound parameter into a SQL value.
pub fn param_value(p: &Param) -> Result<Value, &'static str> {
    Ok(match p {
        Param::Null => Value::Null,
        Param::Int(i) => Value::Int(*i),
        Param::UInt(u) => match i64::try_from(*u) {
            Ok(i) => Value::Int(i),
            Err(_) => Value::Dec {
                v: i128::from(*u),
                s: 0,
            },
        },
        Param::Double(d) => {
            if !d.is_finite() {
                return Err("NaN/Infinity cannot be stored");
            }
            let s = format!("{d}");
            match novadb_sql::value::parse_decimal(&s) {
                Some((v, 0)) => i64::try_from(v)
                    .map(Value::Int)
                    .unwrap_or(Value::Dec { v, s: 0 }),
                Some((v, sc)) => Value::Dec { v, s: sc },
                None => return Err("number out of range"),
            }
        }
        Param::Bytes(b) => match std::str::from_utf8(b) {
            Ok(t) => Value::Str(t.to_string()),
            Err(_) => Value::Bytes(b.clone()),
        },
        Param::DateTime(s) | Param::Time(s) => Value::Str(s.clone()),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn handshake_layout() {
        let s = [7u8; 20];
        let h = handshake_v10("8.0.0-NovaDB", 42, &s);
        assert_eq!(h[0], 10);
        assert!(h.ends_with(b"caching_sha2_password\0"));
        let v_end = 1 + "8.0.0-NovaDB".len();
        assert_eq!(h[v_end], 0);
        assert_eq!(
            u32::from_le_bytes(h[v_end + 1..v_end + 5].try_into().unwrap()),
            42
        );
    }

    fn sample_response(caps: u32, db: bool) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&caps.to_le_bytes());
        p.extend_from_slice(&(16u32 << 20).to_le_bytes());
        p.push(45);
        p.extend_from_slice(&[0; 23]);
        p.extend_from_slice(b"root\0");
        p.push(3);
        p.extend_from_slice(b"abc");
        if db {
            p.extend_from_slice(b"novadb\0");
        }
        p.extend_from_slice(b"client_ed25519\0");
        p
    }

    #[test]
    fn parse_response() {
        let caps = CLIENT_PROTOCOL_41
            | CLIENT_SECURE_CONNECTION
            | CLIENT_PLUGIN_AUTH
            | CLIENT_CONNECT_WITH_DB;
        let p = sample_response(caps, true);
        let r = parse_handshake_response(&p).unwrap();
        assert_eq!(r.user, "root");
        assert_eq!(r.auth_response, b"abc");
        assert_eq!(r.database.as_deref(), Some("novadb"));
        assert_eq!(r.plugin.as_deref(), Some("client_ed25519"));
        for cut in 0..37 {
            assert!(parse_handshake_response(&p[..cut]).is_err(), "cut {cut}");
        }
        assert!(
            parse_handshake_response(&sample_response(CLIENT_SECURE_CONNECTION, false)).is_err()
        );
    }

    #[test]
    fn execute_params() {
        let mut p = Vec::new();
        p.extend_from_slice(&5u32.to_le_bytes());
        p.push(0);
        p.extend_from_slice(&1u32.to_le_bytes());
        p.push(0b0000_0100); // param 2 is NULL
        p.push(1);
        for t in [8u16, 253, 6, 12] {
            p.extend_from_slice(&t.to_le_bytes());
        }
        p.extend_from_slice(&(-7i64).to_le_bytes());
        p.extend_from_slice(&[3, b'x', b'y', b'z']);
        p.extend_from_slice(&[7, 0xEA, 0x07, 11, 18, 1, 2, 3]);
        let e = parse_execute(&p, 4, &[], &Default::default()).unwrap();
        assert_eq!(e.stmt_id, 5);
        assert_eq!(
            e.params,
            vec![
                Param::Int(-7),
                Param::Bytes(b"xyz".to_vec()),
                Param::Null,
                Param::DateTime("2026-11-18 01:02:03.000000".into())
            ]
        );
        for cut in 0..p.len() {
            assert!(
                parse_execute(&p[..cut], 4, &[], &Default::default()).is_err(),
                "cut {cut}"
            );
        }
        // types reused from a previous execute
        let mut q = p[..10].to_vec();
        q.push(0);
        q.push(0);
        q[9] = 0b1111;
        assert_eq!(
            parse_execute(&q, 4, &e.types, &Default::default())
                .unwrap()
                .params,
            vec![Param::Null; 4]
        );
    }

    #[test]
    fn binary_rows() {
        let cols = vec![
            WireCol {
                name: "a".into(),
                ty: T_LONG,
                charset: 63,
                length: 11,
                flags: 0,
                decimals: 0,
            },
            WireCol {
                name: "b".into(),
                ty: T_VAR_STRING,
                charset: 46,
                length: 4,
                flags: 0,
                decimals: 0,
            },
            WireCol {
                name: "c".into(),
                ty: T_DATETIME,
                charset: 63,
                length: 19,
                flags: 0,
                decimals: 0,
            },
        ];
        let t = novadb_sql::value::parse_datetime("2026-11-18 01:02:03").unwrap();
        let r = binary_row(
            &[Value::Int(5), Value::Null, Value::DateTime(t)],
            &cols,
            &[Some(ColType::Int), None, Some(ColType::DateTime(0))],
        );
        assert_eq!(
            r,
            vec![0, 0b0000_1000, 5, 0, 0, 0, 7, 0xEA, 0x07, 11, 18, 1, 2, 3]
        );
    }

    #[test]
    fn ok_info_is_lenenc() {
        assert_eq!(ok(1, 0, 2, "", false), vec![0, 1, 0, 2, 0, 0, 0]);
        assert_eq!(
            ok(1, 0, 2, "hi", false),
            vec![0, 1, 0, 2, 0, 0, 0, 2, b'h', b'i']
        );
    }

    #[test]
    fn err_packet() {
        let e = err(1064, "42000", "bad");
        assert_eq!(
            e,
            vec![
                0xFF, 0x28, 0x04, b'#', b'4', b'2', b'0', b'0', b'0', b'b', b'a', b'd'
            ]
        );
    }
}
