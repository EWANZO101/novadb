//! Column types, values, coercion, comparison and arithmetic.
//!
//! DECIMAL is exact (i128 + scale, max precision 38). DATETIME is microseconds since
//! 1970-01-01 00:00:00 (no time zone, like MySQL DATETIME). Strings compare byte-wise
//! (binary collation) — see docs/sql.md.

use std::cmp::Ordering;
use std::fmt;

use crate::error::{Result, SqlError};

pub const MAX_DECIMAL_PRECISION: u8 = 38;
/// Max scale kept for intermediate results.
pub const MAX_SCALE: u8 = 30;
pub const MAX_VARCHAR: u32 = 65_535;
/// TEXT / BLOB maximum length in bytes (MySQL TEXT/BLOB).
pub const MAX_LOB: usize = 65_535;
/// Extra scale added by `/` (MySQL div_precision_increment).
pub const DIV_SCALE_INCREMENT: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColType {
    Int,
    BigInt,
    Decimal {
        p: u8,
        s: u8,
    },
    Varchar(u32),
    Text,
    Blob,
    /// Fractional-second precision 0..=6.
    DateTime(u8),
}

impl ColType {
    pub fn sql(&self) -> String {
        match self {
            ColType::Int => "int".into(),
            ColType::BigInt => "bigint".into(),
            ColType::Decimal { p, s } => format!("decimal({p},{s})"),
            ColType::Varchar(n) => format!("varchar({n})"),
            ColType::Text => "text".into(),
            ColType::Blob => "blob".into(),
            ColType::DateTime(0) => "datetime".into(),
            ColType::DateTime(f) => format!("datetime({f})"),
        }
    }
    pub fn is_lob(&self) -> bool {
        matches!(self, ColType::Text | ColType::Blob)
    }
    pub fn is_numeric(&self) -> bool {
        matches!(
            self,
            ColType::Int | ColType::BigInt | ColType::Decimal { .. }
        )
    }
    pub fn is_string(&self) -> bool {
        matches!(self, ColType::Varchar(_) | ColType::Text | ColType::Blob)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Null,
    Int(i64),
    /// value = v / 10^s
    Dec {
        v: i128,
        s: u8,
    },
    Str(String),
    Bytes(Vec<u8>),
    /// Microseconds since 1970-01-01 00:00:00.
    DateTime(i64),
}

pub fn pow10(n: u8) -> Option<i128> {
    10i128.checked_pow(u32::from(n))
}

/// Round `v` (scale `from`) to scale `to`, half away from zero.
pub fn rescale(v: i128, from: u8, to: u8) -> Option<i128> {
    match to.cmp(&from) {
        Ordering::Equal => Some(v),
        Ordering::Greater => v.checked_mul(pow10(to - from)?),
        Ordering::Less => {
            let d = pow10(from - to)?;
            let q = v / d;
            let r = v % d;
            if r.unsigned_abs() * 2 >= d.unsigned_abs() {
                q.checked_add(v.signum())
            } else {
                Some(q)
            }
        }
    }
}

fn digits(v: i128) -> u32 {
    let mut n = v.unsigned_abs();
    let mut d = 1;
    while n >= 10 {
        n /= 10;
        d += 1;
    }
    d
}

/// Parse a decimal string (`-12.50`, `1e3`, ` 7 `). Returns (value, scale).
pub fn parse_decimal(s: &str) -> Option<(i128, u8)> {
    let s = s.trim();
    let (neg, body) = match s.as_bytes().first()? {
        b'-' => (true, &s[1..]),
        b'+' => (false, &s[1..]),
        _ => (false, s),
    };
    let (mant, exp) = match body.find(['e', 'E']) {
        Some(i) => (&body[..i], body[i + 1..].parse::<i32>().ok()?),
        None => (body, 0),
    };
    let (ip, fp) = match mant.find('.') {
        Some(i) => (&mant[..i], &mant[i + 1..]),
        None => (mant, ""),
    };
    if (ip.is_empty() && fp.is_empty())
        || !ip.bytes().all(|b| b.is_ascii_digit())
        || !fp.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    // Strip leading zeros so long zero-padded inputs don't overflow.
    let ip = ip.trim_start_matches('0');
    let all = format!("{ip}{fp}");
    let all = all.trim_start_matches('0');
    if all.len() > 60 {
        return None;
    }
    let mut v: i128 = 0;
    for b in all.bytes() {
        v = v.checked_mul(10)?.checked_add(i128::from(b - b'0'))?;
    }
    let mut scale = i32::try_from(fp.len()).ok()? - exp;
    if scale < 0 {
        v = v.checked_mul(10i128.checked_pow(u32::try_from(-scale).ok()?)?)?;
        scale = 0;
    }
    let mut scale = u8::try_from(scale).ok()?;
    if scale > MAX_SCALE {
        v = rescale(v, scale, MAX_SCALE)?;
        scale = MAX_SCALE;
    }
    Some((if neg { -v } else { v }, scale))
}

pub fn format_decimal(v: i128, s: u8) -> String {
    let neg = v < 0;
    let a = v.unsigned_abs().to_string();
    let s = usize::from(s);
    let body = if s == 0 {
        a
    } else if a.len() <= s {
        format!("0.{}{a}", "0".repeat(s - a.len()))
    } else {
        format!("{}.{}", &a[..a.len() - s], &a[a.len() - s..])
    };
    if neg { format!("-{body}") } else { body }
}

// ----- DATETIME ------------------------------------------------------------------------------

const MICROS_PER_SEC: i64 = 1_000_000;
const MICROS_PER_DAY: i64 = 86_400 * MICROS_PER_SEC;
/// 1000-01-01 00:00:00 and 9999-12-31 23:59:59.999999
pub const DT_MIN: i64 = -30_610_224_000 * MICROS_PER_SEC;
pub const DT_MAX: i64 = 253_402_300_799 * MICROS_PER_SEC + 999_999;

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        _ => 28,
    }
}

/// `YYYY-MM-DD[( |T)HH:MM:SS[.ffffff]]`
pub fn parse_datetime(s: &str) -> Option<i64> {
    let s = s.trim();
    let b = s.as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let t = s.get(r)?;
        if t.is_empty() || !t.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        t.parse().ok()
    };
    if b.len() < 10 || b.get(4) != Some(&b'-') || b.get(7) != Some(&b'-') {
        return None;
    }
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (mut h, mut mi, mut se, mut us) = (0, 0, 0, 0);
    if b.len() > 10 {
        if !matches!(b[10], b' ' | b'T')
            || b.len() < 19
            || b.get(13) != Some(&b':')
            || b.get(16) != Some(&b':')
        {
            return None;
        }
        h = num(11..13)?;
        mi = num(14..16)?;
        se = num(17..19)?;
        if b.len() > 19 {
            if b[19] != b'.' || b.len() > 26 || b.len() == 20 {
                return None;
            }
            let f = s.get(20..)?;
            if !f.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            us = format!("{f:0<6}").parse().ok()?;
        }
    }
    if !(1000..=9999).contains(&y)
        || !(1..=12).contains(&mo)
        || d < 1
        || d > days_in_month(y, mo)
        || h > 23
        || mi > 59
        || se > 59
    {
        return None;
    }
    let days = days_from_civil(y, mo, d);
    Some(days * MICROS_PER_DAY + ((h * 60 + mi) * 60 + se) * MICROS_PER_SEC + us)
}

pub fn format_datetime(us: i64, fsp: u8) -> String {
    let days = us.div_euclid(MICROS_PER_DAY);
    let rem = us.rem_euclid(MICROS_PER_DAY);
    let (y, m, d) = civil_from_days(days);
    let secs = rem / MICROS_PER_SEC;
    let frac = rem % MICROS_PER_SEC;
    let base = format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    );
    if fsp == 0 {
        base
    } else {
        let f = format!("{frac:06}");
        format!("{base}.{}", &f[..usize::from(fsp.min(6))])
    }
}

/// Round micros to `fsp` digits (half up), as MySQL does on insert.
pub fn round_fsp(us: i64, fsp: u8) -> i64 {
    let unit = 10i64.pow(u32::from(6 - fsp.min(6)));
    if unit == 1 {
        return us;
    }
    let r = us.rem_euclid(unit);
    let down = us - r;
    if r * 2 >= unit {
        down.saturating_add(unit)
    } else {
        down
    }
}

// ----- Value ---------------------------------------------------------------------------------

impl Value {
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    pub fn bool(b: bool) -> Value {
        Value::Int(i64::from(b))
    }

    /// Numeric view: (value, scale). Strings are parsed leniently (non-numeric → 0), as in
    /// MySQL expression context.
    pub fn to_num(&self) -> Option<(i128, u8)> {
        match self {
            Value::Null => None,
            Value::Int(i) => Some((i128::from(*i), 0)),
            Value::Dec { v, s } => Some((*v, *s)),
            Value::Str(s) => Some(parse_decimal(s).unwrap_or((0, 0))),
            Value::Bytes(b) => Some(
                std::str::from_utf8(b)
                    .ok()
                    .and_then(parse_decimal)
                    .unwrap_or((0, 0)),
            ),
            Value::DateTime(us) => {
                // YYYYMMDDhhmmss as a number (MySQL numeric context).
                let s = format_datetime(*us, 0);
                let digits: String = s.chars().filter(char::is_ascii_digit).collect();
                Some((digits.parse().unwrap_or(0), 0))
            }
        }
    }

    /// Truth value: None = UNKNOWN.
    pub fn truth(&self) -> Option<bool> {
        self.to_num().map(|(v, _)| v != 0)
    }

    /// Text form used for results and string conversion.
    pub fn render(&self, fsp: u8) -> Option<String> {
        match self {
            Value::Null => None,
            Value::Int(i) => Some(i.to_string()),
            Value::Dec { v, s } => Some(format_decimal(*v, *s)),
            Value::Str(s) => Some(s.clone()),
            Value::Bytes(b) => Some(String::from_utf8_lossy(b).into_owned()),
            Value::DateTime(us) => Some(format_datetime(*us, fsp)),
        }
    }

    fn render_bytes(&self) -> Option<Vec<u8>> {
        match self {
            Value::Bytes(b) => Some(b.clone()),
            // Without a column type the precision is unknown: show only significant digits.
            Value::DateTime(us) => {
                let s = format_datetime(*us, 6);
                Some(
                    if us.rem_euclid(MICROS_PER_SEC) == 0 {
                        format_datetime(*us, 0)
                    } else {
                        s.trim_end_matches('0').to_string()
                    }
                    .into_bytes(),
                )
            }
            other => other.render(0).map(String::into_bytes),
        }
    }

    /// Text form for a result column of type `ty` (DATETIME(n) always shows n digits).
    pub fn text_as(&self, ty: Option<ColType>) -> Option<String> {
        match (self, ty) {
            (Value::DateTime(us), Some(ColType::DateTime(f))) => Some(format_datetime(*us, f)),
            _ => self.text(),
        }
    }

    pub fn text(&self) -> Option<String> {
        self.render_bytes()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.text() {
            None => write!(f, "NULL"),
            Some(s) => write!(f, "{s}"),
        }
    }
}

/// Compare two decimals exactly.
pub fn cmp_dec(a: (i128, u8), b: (i128, u8)) -> Ordering {
    let (av, as_) = a;
    let (bv, bs) = b;
    if as_ == bs {
        return av.cmp(&bv);
    }
    if as_ < bs {
        match pow10(bs - as_).and_then(|p| av.checked_mul(p)) {
            Some(x) => x.cmp(&bv),
            // Overflow means |a| exceeds anything representable at b's scale.
            None => {
                if av < 0 {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            }
        }
    } else {
        cmp_dec(b, a).reverse()
    }
}

fn is_numeric(v: &Value) -> bool {
    matches!(v, Value::Int(_) | Value::Dec { .. })
}

/// SQL comparison; None if either side is NULL.
pub fn compare(a: &Value, b: &Value) -> Option<Ordering> {
    use Value::*;
    match (a, b) {
        (Null, _) | (_, Null) => None,
        (Int(x), Int(y)) => Some(x.cmp(y)),
        (DateTime(x), DateTime(y)) => Some(x.cmp(y)),
        (DateTime(x), Str(s)) => Some(match parse_datetime(s) {
            Some(y) => x.cmp(&y),
            None => format_datetime(*x, 6).as_str().cmp(s.as_str()),
        }),
        (Str(_), DateTime(_)) => compare(b, a).map(Ordering::reverse),
        (Str(x), Str(y)) => Some(x.as_bytes().cmp(y.as_bytes())),
        (Bytes(x), Bytes(y)) => Some(x.cmp(y)),
        (Bytes(x), Str(y)) => Some(x.as_slice().cmp(y.as_bytes())),
        (Str(x), Bytes(y)) => Some(x.as_bytes().cmp(y.as_slice())),
        _ if is_numeric(a) || is_numeric(b) => Some(cmp_dec(a.to_num()?, b.to_num()?)),
        _ => Some(a.render_bytes()?.cmp(&b.render_bytes()?)),
    }
}

/// Total order for ORDER BY / DISTINCT: NULL first (MySQL ASC).
pub fn sort_cmp(a: &Value, b: &Value) -> Ordering {
    match (a.is_null(), b.is_null()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        _ => compare(a, b).unwrap_or(Ordering::Equal),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithOp {
    Add,
    Sub,
    Mul,
    Div,
    IntDiv,
    Mod,
}

fn mk(v: i128, s: u8, what: &str) -> Result<Value> {
    if s == 0 {
        return i64::try_from(v)
            .map(Value::Int)
            .map_err(|_| SqlError::value_out_of_range(what));
    }
    if digits(v) > u32::from(MAX_DECIMAL_PRECISION) + 10 {
        return Err(SqlError::value_out_of_range(what));
    }
    Ok(Value::Dec { v, s })
}

pub fn arith(op: ArithOp, a: &Value, b: &Value) -> Result<Value> {
    let (Some((av, as_)), Some((bv, bs))) = (a.to_num(), b.to_num()) else {
        return Ok(Value::Null);
    };
    let what = "expression";
    let oor = || SqlError::value_out_of_range(what);
    let s = as_.max(bs);
    let (x, y) = (
        rescale(av, as_, s).ok_or_else(oor)?,
        rescale(bv, bs, s).ok_or_else(oor)?,
    );
    match op {
        ArithOp::Add => mk(x.checked_add(y).ok_or_else(oor)?, s, what),
        ArithOp::Sub => mk(x.checked_sub(y).ok_or_else(oor)?, s, what),
        ArithOp::Mul => {
            let mut v = av.checked_mul(bv).ok_or_else(oor)?;
            let mut sc = as_.checked_add(bs).ok_or_else(oor)?;
            if sc > MAX_SCALE {
                v = rescale(v, sc, MAX_SCALE).ok_or_else(oor)?;
                sc = MAX_SCALE;
            }
            mk(v, sc, what)
        }
        ArithOp::Div => {
            if bv == 0 {
                return Ok(Value::Null);
            }
            let rs = as_.saturating_add(DIV_SCALE_INCREMENT).min(MAX_SCALE);
            // a/b at scale rs = (av * 10^(rs + bs - as)) / bv, rounded half away from zero.
            let shift = (u32::from(rs) + u32::from(bs))
                .checked_sub(u32::from(as_))
                .ok_or_else(oor)?;
            let num = av
                .checked_mul(10i128.checked_pow(shift).ok_or_else(oor)?)
                .ok_or_else(oor)?;
            let q = num / bv;
            let r = num % bv;
            let q = if r.unsigned_abs() * 2 >= bv.unsigned_abs() {
                q + if (num < 0) != (bv < 0) { -1 } else { 1 }
            } else {
                q
            };
            mk(q, rs, what)
        }
        ArithOp::IntDiv => {
            if y == 0 {
                return Ok(Value::Null);
            }
            mk(x / y, 0, what)
        }
        ArithOp::Mod => {
            if y == 0 {
                return Ok(Value::Null);
            }
            mk(x % y, s, what)
        }
    }
}

/// Convert a value for storage in a column of type `ty` (strict mode: bad data is an error).
pub fn coerce(v: Value, ty: ColType, col: &str) -> Result<Value> {
    if v.is_null() {
        return Ok(Value::Null);
    }
    match ty {
        ColType::Int | ColType::BigInt => {
            let (n, s) = match &v {
                Value::Int(i) => (i128::from(*i), 0),
                Value::Dec { v, s } => (*v, *s),
                Value::Str(t) => {
                    parse_decimal(t).ok_or_else(|| SqlError::bad_value("integer", t, col))?
                }
                Value::Bytes(b) => {
                    let t = String::from_utf8_lossy(b);
                    parse_decimal(&t).ok_or_else(|| SqlError::bad_value("integer", &t, col))?
                }
                Value::DateTime(_) => {
                    return Err(SqlError::bad_value("integer", &v.to_string(), col));
                }
                Value::Null => return Ok(Value::Null),
            };
            let n = rescale(n, s, 0).ok_or_else(|| SqlError::out_of_range(col))?;
            let ok = match ty {
                ColType::Int => i32::try_from(n).is_ok(),
                _ => i64::try_from(n).is_ok(),
            };
            if !ok {
                return Err(SqlError::out_of_range(col));
            }
            i64::try_from(n)
                .map(Value::Int)
                .map_err(|_| SqlError::out_of_range(col))
        }
        ColType::Decimal { p, s } => {
            let (n, ns) = match &v {
                Value::Int(i) => (i128::from(*i), 0),
                Value::Dec { v, s } => (*v, *s),
                Value::Str(t) => {
                    parse_decimal(t).ok_or_else(|| SqlError::bad_value("decimal", t, col))?
                }
                Value::Bytes(b) => {
                    let t = String::from_utf8_lossy(b);
                    parse_decimal(&t).ok_or_else(|| SqlError::bad_value("decimal", &t, col))?
                }
                Value::DateTime(_) => {
                    return Err(SqlError::bad_value("decimal", &v.to_string(), col));
                }
                Value::Null => return Ok(Value::Null),
            };
            let r = rescale(n, ns, s).ok_or_else(|| SqlError::out_of_range(col))?;
            if r != 0 && digits(r) > u32::from(p) {
                return Err(SqlError::out_of_range(col));
            }
            Ok(Value::Dec { v: r, s })
        }
        ColType::Varchar(n) => {
            let t = match v {
                Value::Str(t) => t,
                Value::Bytes(b) => String::from_utf8(b)
                    .map_err(|_| SqlError::bad_value("string", "<binary>", col))?,
                other => other.text().unwrap_or_default(),
            };
            if t.chars().count() > n as usize {
                return Err(SqlError::too_long(col));
            }
            Ok(Value::Str(t))
        }
        ColType::Text => {
            let t = match v {
                Value::Str(t) => t,
                Value::Bytes(b) => String::from_utf8(b)
                    .map_err(|_| SqlError::bad_value("string", "<binary>", col))?,
                other => other.text().unwrap_or_default(),
            };
            if t.len() > MAX_LOB {
                return Err(SqlError::too_long(col));
            }
            Ok(Value::Str(t))
        }
        ColType::Blob => {
            let b = match v {
                Value::Bytes(b) => b,
                Value::Str(t) => t.into_bytes(),
                other => other.text().unwrap_or_default().into_bytes(),
            };
            if b.len() > MAX_LOB {
                return Err(SqlError::too_long(col));
            }
            Ok(Value::Bytes(b))
        }
        ColType::DateTime(fsp) => {
            let us = match &v {
                Value::DateTime(us) => *us,
                Value::Str(t) => parse_datetime(t).ok_or_else(|| SqlError::bad_datetime(t, col))?,
                other => return Err(SqlError::bad_datetime(&other.to_string(), col)),
            };
            let us = round_fsp(us, fsp);
            if !(DT_MIN..=DT_MAX).contains(&us) {
                return Err(SqlError::bad_datetime(&v.to_string(), col));
            }
            Ok(Value::DateTime(us))
        }
    }
}

/// `LIKE` with `%`, `_` and `\` escape; binary, O(n·m) (no exponential backtracking).
pub fn like(text: &str, pat: &str) -> bool {
    let t: Vec<char> = text.chars().collect();
    // Tokenise the pattern: Some(c) literal, None '_' (any one), '%' handled separately.
    #[derive(Clone, Copy)]
    enum P {
        Lit(char),
        One,
        Any,
    }
    let mut p = Vec::new();
    let mut it = pat.chars();
    while let Some(c) = it.next() {
        p.push(match c {
            '%' => P::Any,
            '_' => P::One,
            '\\' => P::Lit(it.next().unwrap_or('\\')),
            c => P::Lit(c),
        });
    }
    // dp[j] = pattern[..i] matches text[..j]
    let mut dp = vec![false; t.len() + 1];
    dp[0] = true;
    for tok in &p {
        let mut next = vec![false; t.len() + 1];
        match tok {
            P::Any => {
                let mut seen = false;
                for j in 0..=t.len() {
                    seen |= dp[j];
                    next[j] = seen;
                }
            }
            P::One => next[1..].copy_from_slice(&dp[..t.len()]),
            P::Lit(c) => {
                for j in 1..=t.len() {
                    next[j] = dp[j - 1] && t[j - 1] == *c;
                }
            }
        }
        dp = next;
    }
    dp[t.len()]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn decimals() {
        assert_eq!(parse_decimal("-12.50"), Some((-1250, 2)));
        assert_eq!(parse_decimal("1.5e2"), Some((150, 0)));
        assert_eq!(parse_decimal("1.25e-1"), Some((125, 3)));
        assert_eq!(parse_decimal(".5"), Some((5, 1)));
        assert_eq!(parse_decimal("abc"), None);
        assert_eq!(parse_decimal("1.2.3"), None);
        assert_eq!(parse_decimal(""), None);
        assert_eq!(format_decimal(-5, 3), "-0.005");
        assert_eq!(format_decimal(12345, 2), "123.45");
        assert_eq!(rescale(125, 2, 1), Some(13));
        assert_eq!(rescale(-125, 2, 1), Some(-13));
        assert_eq!(rescale(124, 2, 1), Some(12));
        assert_eq!(cmp_dec((10, 1), (1, 0)), Ordering::Equal);
        assert_eq!(cmp_dec((i128::MAX, 0), (1, 30)), Ordering::Greater);
    }

    #[test]
    fn arithmetic() {
        let d = |s: &str| {
            let (v, s) = parse_decimal(s).unwrap();
            Value::Dec { v, s }
        };
        assert_eq!(
            arith(ArithOp::Add, &Value::Int(1), &d("0.25")).unwrap(),
            d("1.25")
        );
        assert_eq!(
            arith(ArithOp::Div, &Value::Int(1), &Value::Int(3)).unwrap(),
            d("0.3333")
        );
        assert_eq!(
            arith(ArithOp::Div, &Value::Int(2), &Value::Int(3)).unwrap(),
            d("0.6667")
        );
        assert_eq!(
            arith(ArithOp::Div, &Value::Int(-2), &Value::Int(3)).unwrap(),
            d("-0.6667")
        );
        assert_eq!(
            arith(ArithOp::Div, &Value::Int(1), &Value::Int(0)).unwrap(),
            Value::Null
        );
        assert_eq!(
            arith(ArithOp::Mod, &Value::Int(7), &Value::Int(3)).unwrap(),
            Value::Int(1)
        );
        assert_eq!(
            arith(ArithOp::IntDiv, &Value::Int(7), &Value::Int(2)).unwrap(),
            Value::Int(3)
        );
        assert_eq!(
            arith(ArithOp::Mul, &d("1.5"), &d("2.25")).unwrap(),
            d("3.375")
        );
        assert!(arith(ArithOp::Add, &Value::Int(i64::MAX), &Value::Int(1)).is_err());
        assert_eq!(
            arith(ArithOp::Add, &Value::Null, &Value::Int(1)).unwrap(),
            Value::Null
        );
    }

    #[test]
    fn datetimes() {
        let t = parse_datetime("2026-11-18 01:02:03.5").unwrap();
        assert_eq!(format_datetime(t, 1), "2026-11-18 01:02:03.5");
        assert_eq!(format_datetime(t, 0), "2026-11-18 01:02:03");
        assert_eq!(format_datetime(round_fsp(t, 0), 0), "2026-11-18 01:02:04");
        assert_eq!(
            parse_datetime("2024-02-29"),
            Some(days_from_civil(2024, 2, 29) * MICROS_PER_DAY)
        );
        assert!(parse_datetime("2023-02-29").is_none());
        assert!(parse_datetime("0000-00-00").is_none());
        assert!(parse_datetime("2026-13-01").is_none());
        assert!(parse_datetime("2026-01-01 24:00:00").is_none());
        assert_eq!(parse_datetime("1000-01-01 00:00:00"), Some(DT_MIN));
        assert_eq!(parse_datetime("9999-12-31 23:59:59.999999"), Some(DT_MAX));
        assert_eq!(format_datetime(DT_MIN, 0), "1000-01-01 00:00:00");
    }

    #[test]
    fn coercion() {
        assert_eq!(
            coerce(Value::Str("42".into()), ColType::Int, "c").unwrap(),
            Value::Int(42)
        );
        assert_eq!(
            coerce(Value::Dec { v: 25, s: 1 }, ColType::Int, "c").unwrap(),
            Value::Int(3)
        );
        assert_eq!(
            coerce(Value::Int(2_147_483_648), ColType::Int, "c")
                .unwrap_err()
                .code,
            1264
        );
        assert_eq!(
            coerce(Value::Str("x".into()), ColType::Int, "c")
                .unwrap_err()
                .code,
            1366
        );
        assert_eq!(
            coerce(
                Value::Str("12.345".into()),
                ColType::Decimal { p: 5, s: 2 },
                "c"
            )
            .unwrap(),
            Value::Dec { v: 1235, s: 2 }
        );
        assert_eq!(
            coerce(Value::Int(1000), ColType::Decimal { p: 5, s: 2 }, "c")
                .unwrap_err()
                .code,
            1264
        );
        assert_eq!(
            coerce(Value::Str("héllo".into()), ColType::Varchar(5), "c").unwrap(),
            Value::Str("héllo".into())
        );
        assert_eq!(
            coerce(Value::Str("hello!".into()), ColType::Varchar(5), "c")
                .unwrap_err()
                .code,
            1406
        );
        assert_eq!(
            coerce(Value::Str("nope".into()), ColType::DateTime(0), "c")
                .unwrap_err()
                .code,
            1292
        );
    }

    #[test]
    fn compare_rules() {
        assert_eq!(
            compare(&Value::Int(5), &Value::Str("05".into())),
            Some(Ordering::Equal)
        );
        assert_eq!(
            compare(&Value::Str("a".into()), &Value::Str("b".into())),
            Some(Ordering::Less)
        );
        assert_eq!(compare(&Value::Null, &Value::Int(1)), None);
        let t = parse_datetime("2026-01-01").unwrap();
        assert_eq!(
            compare(
                &Value::DateTime(t),
                &Value::Str("2026-01-01 00:00:00".into())
            ),
            Some(Ordering::Equal)
        );
    }

    #[test]
    fn like_patterns() {
        assert!(like("hello", "h%o"));
        assert!(like("hello", "_ell_"));
        assert!(!like("hello", "h_o"));
        assert!(like("50%", "50\\%"));
        assert!(!like("500", "50\\%"));
        assert!(like("", "%"));
        assert!(like(&"a".repeat(2000), &"%a".repeat(200)));
    }
}
