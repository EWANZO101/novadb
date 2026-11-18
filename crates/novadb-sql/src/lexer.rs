//! Hand-written lexer. Byte-offset positions are kept for error messages and for naming
//! SELECT columns after their source text.

use crate::error::{Result, SqlError};

/// Upper bound on tokens per input (memory guard on top of `MAX_STATEMENT_BYTES`).
pub const MAX_TOKENS: usize = 4_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok {
    /// Unquoted identifier or keyword (original spelling).
    Ident(String),
    /// `backtick` quoted identifier.
    QIdent(String),
    /// Integer literal digits.
    Int(String),
    /// Decimal literal (`1.5`, `.5`, `1e3`), original text.
    Num(String),
    /// String literal (escapes resolved).
    Str(String),
    /// `X'..'` / `0x..` literal.
    Hex(Vec<u8>),
    /// Punctuation / operator.
    Sym(&'static str),
    Eof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub tok: Tok,
    /// Byte offset of the first character.
    pub pos: usize,
    /// Byte offset one past the last character.
    pub end: usize,
}

const SYMS: [&str; 24] = [
    "<=>", "<=", ">=", "<>", "!=", "||", "&&", "<<", ">>", "(", ")", ",", ";", ".", "*", "+", "-",
    "/", "%", "=", "<", ">", "!", "?",
];

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn decode_hex(s: &[u8], pos: usize, sql: &str) -> Result<Vec<u8>> {
    let padded: Vec<u8> = if s.len() % 2 == 1 {
        std::iter::once(b'0').chain(s.iter().copied()).collect()
    } else {
        s.to_vec()
    };
    padded
        .chunks(2)
        .map(|c| {
            match (
                c.first().and_then(|&b| hex_val(b)),
                c.get(1).and_then(|&b| hex_val(b)),
            ) {
                (Some(h), Some(l)) => Ok(h << 4 | l),
                _ => Err(SqlError::syntax(pos, &sql[pos..], "invalid hex literal")),
            }
        })
        .collect()
}

pub fn lex(sql: &str) -> Result<Vec<Token>> {
    let b = sql.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    let err = |p: usize, m: &str| SqlError::syntax(p, sql.get(p..).unwrap_or(""), m);
    while i < b.len() {
        if out.len() >= MAX_TOKENS {
            return Err(SqlError::resource("statement has too many tokens"));
        }
        let c = b[i];
        // whitespace
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        // comments: -- (followed by space/control/end), #, /* */
        if c == b'#'
            || (c == b'-'
                && b.get(i + 1) == Some(&b'-')
                && b.get(i + 2)
                    .is_none_or(|x| x.is_ascii_whitespace() || x.is_ascii_control()))
        {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if c == b'/' && b.get(i + 1) == Some(&b'*') {
            let start = i;
            i += 2;
            loop {
                if i + 1 >= b.len() {
                    return Err(err(start, "unterminated comment"));
                }
                if b[i] == b'*' && b[i + 1] == b'/' {
                    i += 2;
                    break;
                }
                i += 1;
            }
            continue;
        }
        let start = i;
        // hex literals X'ab' / 0xab
        if (c == b'x' || c == b'X') && b.get(i + 1) == Some(&b'\'') {
            let s = i + 2;
            let mut j = s;
            while j < b.len() && b[j] != b'\'' {
                j += 1;
            }
            if j >= b.len() {
                return Err(err(start, "unterminated hex literal"));
            }
            if (j - s) % 2 == 1 {
                return Err(err(start, "hex literal needs an even number of digits"));
            }
            out.push(Token {
                tok: Tok::Hex(decode_hex(&b[s..j], start, sql)?),
                pos: start,
                end: j + 1,
            });
            i = j + 1;
            continue;
        }
        if c == b'0'
            && matches!(b.get(i + 1), Some(b'x' | b'X'))
            && b.get(i + 2).is_some_and(|x| hex_val(*x).is_some())
        {
            let s = i + 2;
            let mut j = s;
            while j < b.len() && hex_val(b[j]).is_some() {
                j += 1;
            }
            if j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
                return Err(err(start, "invalid hex literal"));
            }
            out.push(Token {
                tok: Tok::Hex(decode_hex(&b[s..j], start, sql)?),
                pos: start,
                end: j,
            });
            i = j;
            continue;
        }
        // numbers
        if c.is_ascii_digit() || (c == b'.' && b.get(i + 1).is_some_and(u8::is_ascii_digit)) {
            let mut j = i;
            let mut is_dec = false;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            if j < b.len() && b[j] == b'.' {
                is_dec = true;
                j += 1;
                while j < b.len() && b[j].is_ascii_digit() {
                    j += 1;
                }
            }
            if j < b.len() && (b[j] == b'e' || b[j] == b'E') {
                let mut k = j + 1;
                if k < b.len() && (b[k] == b'+' || b[k] == b'-') {
                    k += 1;
                }
                if k < b.len() && b[k].is_ascii_digit() {
                    while k < b.len() && b[k].is_ascii_digit() {
                        k += 1;
                    }
                    is_dec = true;
                    j = k;
                }
            }
            // `1abc` is an identifier in MySQL; we keep it simple and reject it.
            if j < b.len() && (b[j].is_ascii_alphabetic() || b[j] == b'_') {
                return Err(err(start, "invalid number"));
            }
            let text = sql[i..j].to_string();
            out.push(Token {
                tok: if is_dec {
                    Tok::Num(text)
                } else {
                    Tok::Int(text)
                },
                pos: start,
                end: j,
            });
            i = j;
            continue;
        }
        // strings
        if c == b'\'' || c == b'"' {
            let q = c;
            let mut s: Vec<u8> = Vec::new();
            let mut j = i + 1;
            loop {
                let Some(&ch) = b.get(j) else {
                    return Err(err(start, "unterminated string"));
                };
                if ch == q {
                    if b.get(j + 1) == Some(&q) {
                        s.push(q);
                        j += 2;
                        continue;
                    }
                    j += 1;
                    break;
                }
                if ch == b'\\' {
                    let Some(&e) = b.get(j + 1) else {
                        return Err(err(start, "unterminated string"));
                    };
                    s.push(match e {
                        b'0' => 0,
                        b'n' => b'\n',
                        b'r' => b'\r',
                        b't' => b'\t',
                        b'b' => 8,
                        b'Z' => 26,
                        other => other,
                    });
                    j += 2;
                    continue;
                }
                s.push(ch);
                j += 1;
            }
            let s = String::from_utf8(s).map_err(|_| err(start, "string is not valid UTF-8"))?;
            out.push(Token {
                tok: Tok::Str(s),
                pos: start,
                end: j,
            });
            i = j;
            continue;
        }
        // quoted identifiers
        if c == b'`' {
            let mut s = Vec::new();
            let mut j = i + 1;
            loop {
                let Some(&ch) = b.get(j) else {
                    return Err(err(start, "unterminated quoted identifier"));
                };
                if ch == b'`' {
                    if b.get(j + 1) == Some(&b'`') {
                        s.push(b'`');
                        j += 2;
                        continue;
                    }
                    j += 1;
                    break;
                }
                s.push(ch);
                j += 1;
            }
            let s =
                String::from_utf8(s).map_err(|_| err(start, "identifier is not valid UTF-8"))?;
            out.push(Token {
                tok: Tok::QIdent(s),
                pos: start,
                end: j,
            });
            i = j;
            continue;
        }
        // identifiers / keywords (ASCII letters, digits, _, $ and any non-ASCII char)
        if c.is_ascii_alphabetic() || c == b'_' || c == b'$' || c >= 0x80 {
            let mut j = i;
            while j < b.len()
                && (b[j].is_ascii_alphanumeric() || b[j] == b'_' || b[j] == b'$' || b[j] >= 0x80)
            {
                j += 1;
            }
            // j always lands on a char boundary: we only stop on ASCII bytes or the end.
            out.push(Token {
                tok: Tok::Ident(sql[i..j].to_string()),
                pos: start,
                end: j,
            });
            i = j;
            continue;
        }
        let rest = &sql[i..];
        match SYMS.iter().find(|s| rest.starts_with(**s)) {
            Some(s) => {
                out.push(Token {
                    tok: Tok::Sym(s),
                    pos: start,
                    end: i + s.len(),
                });
                i += s.len();
            }
            None => return Err(err(start, "unexpected character")),
        }
    }
    out.push(Token {
        tok: Tok::Eof,
        pos: b.len(),
        end: b.len(),
    });
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn toks(s: &str) -> Vec<Tok> {
        lex(s).unwrap().into_iter().map(|t| t.tok).collect()
    }

    #[test]
    fn basics() {
        assert_eq!(
            toks("SELECT a,`b c`,'x''y\\n' FROM t -- c\n WHERE x<=>1.5e2 # z"),
            vec![
                Tok::Ident("SELECT".into()),
                Tok::Ident("a".into()),
                Tok::Sym(","),
                Tok::QIdent("b c".into()),
                Tok::Sym(","),
                Tok::Str("x'y\n".into()),
                Tok::Ident("FROM".into()),
                Tok::Ident("t".into()),
                Tok::Ident("WHERE".into()),
                Tok::Ident("x".into()),
                Tok::Sym("<=>"),
                Tok::Num("1.5e2".into()),
                Tok::Eof
            ]
        );
        assert_eq!(
            toks("X'0aff' 0x1"),
            vec![Tok::Hex(vec![10, 255]), Tok::Hex(vec![1]), Tok::Eof]
        );
        assert_eq!(toks("1-- x"), vec![Tok::Int("1".into()), Tok::Eof]);
        assert_eq!(
            toks("1--2"),
            vec![
                Tok::Int("1".into()),
                Tok::Sym("-"),
                Tok::Sym("-"),
                Tok::Int("2".into()),
                Tok::Eof
            ]
        );
        assert_eq!(
            toks("/* a */ ñame"),
            vec![Tok::Ident("ñame".into()), Tok::Eof]
        );
    }

    #[test]
    fn errors() {
        for bad in ["'abc", "`abc", "/* x", "X'abc'", "1abc", "@", "\"\\"] {
            assert!(lex(bad).is_err(), "{bad}");
        }
    }
}
