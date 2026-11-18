//! Recursive-descent parser. Depth-limited (`MAX_PARSE_DEPTH`) so hostile input cannot
//! exhaust the stack; every failure is a `SqlError` (1064), never a panic.

use crate::ast::*;
use crate::error::{Result, SqlError};
use crate::lexer::{Tok, Token, lex};
use crate::value::{ColType, MAX_DECIMAL_PRECISION, MAX_VARCHAR, Value, parse_decimal};
use crate::{MAX_PARSE_DEPTH, MAX_STATEMENT_BYTES};

/// Max identifier length (MySQL: 64).
pub const MAX_IDENT: usize = 64;

/// Words that cannot be used as bare identifiers.
const RESERVED: &[&str] = &[
    "join",
    "inner",
    "left",
    "right",
    "cross",
    "outer",
    "using",
    "natural",
    "group",
    "having",
    "union",
    "select",
    "from",
    "where",
    "insert",
    "into",
    "values",
    "update",
    "set",
    "delete",
    "create",
    "drop",
    "table",
    "index",
    "key",
    "primary",
    "unique",
    "not",
    "null",
    "and",
    "or",
    "xor",
    "order",
    "by",
    "limit",
    "offset",
    "asc",
    "desc",
    "is",
    "in",
    "between",
    "like",
    "on",
    "default",
    "distinct",
    "as",
    "true",
    "false",
    "div",
    "mod",
    "exists",
    "if",
    "explain",
    "describe",
    "show",
    "auto_increment",
    "constraint",
];

pub fn parse(sql: &str) -> Result<Vec<Stmt>> {
    parse_prepared(sql).map(|(s, _)| s)
}

/// Parse and also return the number of `?` placeholders (prepared statements).
pub fn parse_prepared(sql: &str) -> Result<(Vec<Stmt>, usize)> {
    if sql.len() > MAX_STATEMENT_BYTES {
        return Err(SqlError::resource("statement too large"));
    }
    let toks = lex(sql)?;
    let mut p = Parser {
        sql,
        toks,
        i: 0,
        depth: 0,
        params: 0,
    };
    let mut out = Vec::new();
    loop {
        while p.eat_sym(";") {}
        if p.at_eof() {
            break;
        }
        out.push(p.statement()?);
        if !p.at_eof() && !p.eat_sym(";") {
            return Err(p.err("expected ';' or end of statement"));
        }
    }
    Ok((out, p.params))
}

struct Parser<'a> {
    sql: &'a str,
    toks: Vec<Token>,
    i: usize,
    depth: usize,
    /// Number of `?` placeholders seen so far.
    params: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> &Tok {
        self.toks.get(self.i).map_or(&Tok::Eof, |t| &t.tok)
    }
    fn peek_at(&self, n: usize) -> &Tok {
        self.toks.get(self.i + n).map_or(&Tok::Eof, |t| &t.tok)
    }
    fn pos(&self) -> usize {
        self.toks.get(self.i).map_or(self.sql.len(), |t| t.pos)
    }
    fn prev_end(&self) -> usize {
        self.i
            .checked_sub(1)
            .and_then(|j| self.toks.get(j))
            .map_or(0, |t| t.end)
    }
    fn at_eof(&self) -> bool {
        matches!(self.peek(), Tok::Eof)
    }
    fn bump(&mut self) -> Tok {
        let t = self.peek().clone();
        if !matches!(t, Tok::Eof) {
            self.i += 1;
        }
        t
    }
    fn err(&self, msg: &str) -> SqlError {
        let p = self.pos();
        SqlError::syntax(p, self.sql.get(p..).unwrap_or(""), msg)
    }
    fn is_kw(&self, kw: &str) -> bool {
        matches!(self.peek(), Tok::Ident(s) if s.eq_ignore_ascii_case(kw))
    }
    fn is_kw_at(&self, n: usize, kw: &str) -> bool {
        matches!(self.peek_at(n), Tok::Ident(s) if s.eq_ignore_ascii_case(kw))
    }
    fn eat_kw(&mut self, kw: &str) -> bool {
        if self.is_kw(kw) {
            self.i += 1;
            true
        } else {
            false
        }
    }
    fn kw(&mut self, kw: &str) -> Result<()> {
        if self.eat_kw(kw) {
            Ok(())
        } else {
            Err(self.err(&format!("expected {}", kw.to_uppercase())))
        }
    }
    fn eat_sym(&mut self, s: &str) -> bool {
        if matches!(self.peek(), Tok::Sym(x) if *x == s) {
            self.i += 1;
            true
        } else {
            false
        }
    }
    fn sym(&mut self, s: &str) -> Result<()> {
        if self.eat_sym(s) {
            Ok(())
        } else {
            Err(self.err(&format!("expected '{s}'")))
        }
    }
    fn ident(&mut self) -> Result<String> {
        let name = match self.peek().clone() {
            Tok::Ident(s) if !RESERVED.iter().any(|r| s.eq_ignore_ascii_case(r)) => s,
            Tok::QIdent(s) => s,
            _ => return Err(self.err("expected an identifier")),
        };
        if name.is_empty()
            || name.chars().count() > MAX_IDENT
            || name.chars().any(char::is_control)
            || name.ends_with(' ')
        {
            return Err(SqlError::bad_ident(&name));
        }
        self.i += 1;
        Ok(name)
    }
    fn uint(&mut self) -> Result<u64> {
        match self.bump() {
            Tok::Int(s) => s.parse().map_err(|_| self.err("number too large")),
            _ => {
                self.i -= 1;
                Err(self.err("expected a number"))
            }
        }
    }
    fn ident_list(&mut self) -> Result<Vec<String>> {
        self.sym("(")?;
        let mut v = vec![self.ident()?];
        while self.eat_sym(",") {
            v.push(self.ident()?);
        }
        self.sym(")")?;
        Ok(v)
    }

    // ----- statements --------------------------------------------------------------------

    fn user_spec(&mut self) -> Result<String> {
        let name = match self.bump() {
            Tok::Str(s) | Tok::QIdent(s) | Tok::Ident(s) => s,
            _ => {
                self.i -= 1;
                return Err(self.err("expected a user name"));
            }
        };
        if self.eat_sym("@") {
            match self.bump() {
                Tok::Str(_) | Tok::QIdent(_) | Tok::Ident(_) => {}
                _ => {
                    self.i -= 1;
                    return Err(self.err("expected a host name"));
                }
            }
        }
        if name.is_empty() || name.chars().count() > 32 || name.chars().any(char::is_control) {
            return Err(SqlError::bad_ident(&name));
        }
        Ok(name)
    }

    fn password_clause(&mut self) -> Result<String> {
        self.kw("identified")?;
        if self.eat_kw("with") {
            // IDENTIFIED WITH caching_sha2_password BY '...': plugin name accepted, ignored.
            self.bump();
        }
        self.kw("by")?;
        match self.bump() {
            Tok::Str(s) => Ok(s),
            _ => {
                self.i -= 1;
                Err(self.err("expected a password string"))
            }
        }
    }

    fn set_stmt(&mut self) -> Result<Stmt> {
        if self.eat_kw("names") {
            let cs = match self.bump() {
                Tok::Str(s) | Tok::Ident(s) | Tok::QIdent(s) => s,
                _ => return Err(self.err("expected a character set")),
            };
            if self.eat_kw("collate") {
                self.bump();
            }
            return Ok(Stmt::Set(vec![(
                "character_set_client".into(),
                Expr::Lit(Value::Str(cs)),
            )]));
        }
        if self.eat_kw("character") || self.eat_kw("charset") {
            let _ = self.eat_kw("set");
            let cs = match self.bump() {
                Tok::Str(s) | Tok::Ident(s) | Tok::QIdent(s) => s,
                _ => return Err(self.err("expected a character set")),
            };
            return Ok(Stmt::Set(vec![(
                "character_set_client".into(),
                Expr::Lit(Value::Str(cs)),
            )]));
        }
        let _ = self.eat_kw("session") || self.eat_kw("local") || self.eat_kw("global");
        if self.eat_kw("transaction") {
            while !self.at_eof() && !matches!(self.peek(), Tok::Sym(";")) {
                self.bump();
            }
            return Ok(Stmt::Set(vec![]));
        }
        let mut v = Vec::new();
        loop {
            let _ = self.eat_kw("session") || self.eat_kw("local") || self.eat_kw("global");
            let name = match self.bump() {
                Tok::SysVar(n) => n,
                Tok::Ident(n) | Tok::QIdent(n) => n.to_ascii_lowercase(),
                Tok::Sym("@") => return Err(SqlError::unsupported("user variables")),
                _ => {
                    self.i -= 1;
                    return Err(self.err("expected a variable name"));
                }
            };
            self.sym("=")?;
            let e = if self.is_kw("on") || self.is_kw("default") || self.is_kw("off") {
                let k = match self.bump() {
                    Tok::Ident(k) => k.to_ascii_lowercase(),
                    _ => String::new(),
                };
                Expr::Lit(match k.as_str() {
                    "on" => Value::Int(1),
                    "off" => Value::Int(0),
                    _ => Value::Null,
                })
            } else {
                self.expr()?
            };
            v.push((name, e));
            if !self.eat_sym(",") {
                break;
            }
        }
        Ok(Stmt::Set(v))
    }

    /// Features that give SQL access to files or native code are not implemented on purpose
    /// (MySQL: LOAD DATA [LOCAL] INFILE, SELECT … INTO OUTFILE/DUMPFILE, LOAD_FILE(), UDFs via
    /// CREATE FUNCTION … SONAME, INSTALL PLUGIN). Refuse them with a clear message.
    fn refuse_file_and_code_features(&self) -> Result<()> {
        let kw = |i: usize, w: &str| self.is_kw_at(i, w);
        let reason = if kw(0, "load") && (kw(1, "data") || kw(1, "xml")) {
            Some("LOAD DATA / LOAD XML (NovaDB never reads server or client files from SQL)")
        } else if kw(0, "install") || kw(0, "uninstall") {
            Some("INSTALL/UNINSTALL PLUGIN (no native-code loading)")
        } else if kw(0, "create")
            && (kw(1, "function") || kw(1, "aggregate") || kw(1, "procedure") || kw(1, "trigger"))
        {
            Some("CREATE FUNCTION / PROCEDURE / TRIGGER (no user-defined native code)")
        } else {
            None
        };
        match reason {
            Some(r) => Err(SqlError::unsupported(r)),
            None => Ok(()),
        }
    }

    /// Privilege list of GRANT/REVOKE. Returns (mask, saw GRANT OPTION).
    fn priv_list(&mut self) -> Result<(u64, bool)> {
        let mut mask = 0u64;
        let mut grant_opt = false;
        loop {
            let word = match self.bump() {
                Tok::Ident(w) => w.to_ascii_lowercase(),
                _ => {
                    self.i -= 1;
                    return Err(self.err("expected a privilege name"));
                }
            };
            match word.as_str() {
                "all" => {
                    let _ = self.eat_kw("privileges");
                    mask = u64::MAX;
                }
                "usage" => {}
                "select" => mask |= crate::privs::SELECT,
                "insert" => mask |= crate::privs::INSERT,
                "update" => mask |= crate::privs::UPDATE,
                "delete" => mask |= crate::privs::DELETE,
                "drop" => mask |= crate::privs::DROP,
                "index" => mask |= crate::privs::INDEX,
                "alter" => mask |= crate::privs::ALTER,
                "process" => mask |= crate::privs::PROCESS,
                "super" | "backup_admin" | "connection_admin" => mask |= crate::privs::SUPER,
                "create" => {
                    if self.eat_kw("user") {
                        mask |= crate::privs::CREATE_USER;
                    } else {
                        mask |= crate::privs::CREATE;
                    }
                }
                "grant" => {
                    self.kw("option")?;
                    grant_opt = true;
                }
                other => {
                    return Err(SqlError::unsupported(&format!(
                        "privilege {}",
                        other.to_uppercase()
                    )));
                }
            }
            if !self.eat_sym(",") {
                break;
            }
        }
        Ok((mask, grant_opt))
    }

    /// `*.*` | `*` | `novadb.*` | `[novadb.]table` → None (global) or Some(table).
    fn grant_target(&mut self) -> Result<Option<String>> {
        if self.eat_sym("*") {
            if self.eat_sym(".") {
                self.sym("*")?;
            }
            return Ok(None);
        }
        let first = self.ident()?;
        if self.eat_sym(".") {
            if !first.eq_ignore_ascii_case("novadb") {
                return Err(SqlError::unknown_db(&first));
            }
            if self.eat_sym("*") {
                return Ok(None);
            }
            return Ok(Some(self.ident()?));
        }
        Ok(Some(first))
    }

    fn statement(&mut self) -> Result<Stmt> {
        self.refuse_file_and_code_features()?;
        if self.eat_kw("grant") {
            let (privs, _) = self.priv_list()?;
            self.kw("on")?;
            let _ = self.eat_kw("table");
            let table = self.grant_target()?;
            self.kw("to")?;
            let mut users = vec![self.user_spec()?];
            while self.eat_sym(",") {
                users.push(self.user_spec()?);
            }
            let grant_option = if self.eat_kw("with") {
                self.kw("grant")?;
                self.kw("option")?;
                true
            } else {
                false
            };
            return Ok(Stmt::Grant {
                privs,
                table,
                users,
                grant_option,
            });
        }
        if self.eat_kw("revoke") {
            let (privs, grant_option) = self.priv_list()?;
            self.kw("on")?;
            let _ = self.eat_kw("table");
            let table = self.grant_target()?;
            if !self.eat_kw("from") {
                return Err(self.err("expected FROM"));
            }
            let mut users = vec![self.user_spec()?];
            while self.eat_sym(",") {
                users.push(self.user_spec()?);
            }
            return Ok(Stmt::Revoke {
                privs,
                table,
                users,
                grant_option,
            });
        }
        if self.eat_kw("backup") {
            let _ = self.eat_kw("database");
            self.kw("to")?;
            return match self.bump() {
                Tok::Str(name) => Ok(Stmt::Backup(name)),
                _ => Err(self.err("expected a backup name string")),
            };
        }
        if self.eat_kw("kill") {
            let query_only = if self.eat_kw("query") {
                true
            } else {
                let _ = self.eat_kw("connection");
                false
            };
            let id = self.uint()?;
            return Ok(Stmt::Kill { id, query_only });
        }
        if self.eat_kw("set") {
            return self.set_stmt();
        }
        if self.eat_kw("use") {
            return Ok(Stmt::Use(self.ident()?));
        }
        if self.eat_kw("begin") {
            let _ = self.eat_kw("work");
            return Ok(Stmt::Txn(TxnKind::Begin));
        }
        if self.eat_kw("start") {
            self.kw("transaction")?;
            while !self.at_eof() && !matches!(self.peek(), Tok::Sym(";")) {
                self.bump();
            }
            return Ok(Stmt::Txn(TxnKind::Begin));
        }
        if self.eat_kw("commit") {
            let _ = self.eat_kw("work");
            return Ok(Stmt::Txn(TxnKind::Commit));
        }
        if self.eat_kw("rollback") {
            let _ = self.eat_kw("work");
            return Ok(Stmt::Txn(TxnKind::Rollback));
        }
        if self.is_kw("create") && self.is_kw_at(1, "user") {
            self.i += 2;
            let if_not_exists = if self.eat_kw("if") {
                self.kw("not")?;
                self.kw("exists")?;
                true
            } else {
                false
            };
            let name = self.user_spec()?;
            let password = self.password_clause()?;
            return Ok(Stmt::CreateUser {
                name,
                password,
                if_not_exists,
            });
        }
        if self.is_kw("alter") && self.is_kw_at(1, "table") {
            self.i += 2;
            return self.alter_table();
        }
        if self.is_kw("alter") && self.is_kw_at(1, "user") {
            self.i += 2;
            let if_exists = if self.eat_kw("if") {
                self.kw("exists")?;
                true
            } else {
                false
            };
            let name = self.user_spec()?;
            let password = self.password_clause()?;
            return Ok(Stmt::AlterUser {
                name,
                password,
                if_exists,
            });
        }
        if self.is_kw("drop") && self.is_kw_at(1, "user") {
            self.i += 2;
            let if_exists = if self.eat_kw("if") {
                self.kw("exists")?;
                true
            } else {
                false
            };
            let mut names = vec![self.user_spec()?];
            while self.eat_sym(",") {
                names.push(self.user_spec()?);
            }
            return Ok(Stmt::DropUser { names, if_exists });
        }
        if self.is_kw("show") {
            let save = self.i;
            self.i += 1;
            let _ = self.eat_kw("session") || self.eat_kw("global") || self.eat_kw("full");
            if self.eat_kw("databases") || self.eat_kw("schemas") {
                return Ok(Stmt::ShowDatabases);
            }
            if self.eat_kw("processlist") {
                return Ok(Stmt::ShowProcesslist);
            }
            if self.eat_kw("grants") {
                if self.eat_kw("for") {
                    if self.is_kw("current_user") {
                        self.i += 1;
                        if self.eat_sym("(") {
                            self.sym(")")?;
                        }
                        return Ok(Stmt::ShowGrants(None));
                    }
                    return Ok(Stmt::ShowGrants(Some(self.user_spec()?)));
                }
                return Ok(Stmt::ShowGrants(None));
            }
            if self.eat_kw("warnings") || self.eat_kw("errors") {
                return Ok(Stmt::ShowWarnings);
            }
            let status = self.is_kw("status");
            if self.eat_kw("variables") || self.eat_kw("status") {
                let like = if self.eat_kw("like") {
                    match self.bump() {
                        Tok::Str(s) => Some(s),
                        _ => return Err(self.err("expected a pattern string")),
                    }
                } else {
                    None
                };
                return Ok(Stmt::ShowVariables { like, status });
            }
            self.i = save;
        }
        if self.eat_kw("select") {
            return Ok(Stmt::Select(self.select()?));
        }
        if self.eat_kw("insert") {
            return self.insert();
        }
        if self.eat_kw("update") {
            return self.update();
        }
        if self.eat_kw("delete") {
            return self.delete();
        }
        if self.eat_kw("create") {
            if self.eat_kw("table") {
                return self.create_table();
            }
            let unique = self.eat_kw("unique");
            if self.eat_kw("index") || self.eat_kw("key") {
                let name = self.ident()?;
                self.kw("on")?;
                let table = self.ident()?;
                let cols = self.ident_list()?;
                return Ok(Stmt::CreateIndex {
                    name,
                    table,
                    cols,
                    unique,
                });
            }
            return Err(self.err("expected TABLE or INDEX"));
        }
        if self.eat_kw("drop") {
            if self.eat_kw("table") {
                let if_exists = if self.eat_kw("if") {
                    self.kw("exists")?;
                    true
                } else {
                    false
                };
                let mut names = vec![self.ident()?];
                while self.eat_sym(",") {
                    names.push(self.ident()?);
                }
                return Ok(Stmt::DropTable { names, if_exists });
            }
            if self.eat_kw("index") {
                let name = self.ident()?;
                self.kw("on")?;
                let table = self.ident()?;
                return Ok(Stmt::DropIndex { name, table });
            }
            return Err(self.err("expected TABLE or INDEX"));
        }
        if self.eat_kw("show") {
            if self.eat_kw("tables") {
                return Ok(Stmt::ShowTables);
            }
            if self.eat_kw("create") {
                self.kw("table")?;
                return Ok(Stmt::ShowCreateTable(self.ident()?));
            }
            if self.eat_kw("columns") || self.eat_kw("fields") {
                if !self.eat_kw("from") {
                    self.kw("in")?;
                }
                return Ok(Stmt::Describe(self.ident()?));
            }
            return Err(self.err("expected TABLES, COLUMNS or CREATE TABLE"));
        }
        if self.eat_kw("describe") || self.eat_kw("desc") {
            return Ok(Stmt::Describe(self.ident()?));
        }
        if self.eat_kw("explain") {
            if !(self.is_kw("select") || self.is_kw("update") || self.is_kw("delete")) {
                return Ok(Stmt::Describe(self.ident()?));
            }
            return Ok(Stmt::Explain(Box::new(self.statement()?)));
        }
        Err(self.err("unknown statement"))
    }

    fn col_type(&mut self) -> Result<ColType> {
        let name = match self.bump() {
            Tok::Ident(s) => s.to_ascii_lowercase(),
            _ => {
                self.i -= 1;
                return Err(self.err("expected a column type"));
            }
        };
        let args = |p: &mut Self| -> Result<Vec<u64>> {
            let mut v = Vec::new();
            if p.eat_sym("(") {
                v.push(p.uint()?);
                while p.eat_sym(",") {
                    v.push(p.uint()?);
                }
                p.sym(")")?;
            }
            Ok(v)
        };
        let ty = match name.as_str() {
            "int" | "integer" => {
                let _display_width = args(self)?;
                ColType::Int
            }
            "bigint" => {
                let _ = args(self)?;
                ColType::BigInt
            }
            "decimal" | "numeric" | "dec" => {
                let a = args(self)?;
                let (p, s) = match a.as_slice() {
                    [] => (10, 0),
                    [p] => (*p, 0),
                    [p, s] => (*p, *s),
                    _ => return Err(self.err("DECIMAL takes (precision[, scale])")),
                };
                if p == 0 || p > u64::from(MAX_DECIMAL_PRECISION) || s > p || s > 30 {
                    return Err(SqlError::unsupported(
                        "DECIMAL precision > 38 or scale > precision",
                    ));
                }
                ColType::Decimal {
                    p: p as u8,
                    s: s as u8,
                }
            }
            "varchar" | "char" => {
                let a = args(self)?;
                let n = match a.as_slice() {
                    [n] => *n,
                    [] if name == "char" => 1,
                    _ => return Err(self.err("VARCHAR needs a length")),
                };
                if n > u64::from(MAX_VARCHAR) {
                    return Err(SqlError::unsupported("VARCHAR longer than 65535"));
                }
                ColType::Varchar(n as u32)
            }
            "text" => ColType::Text,
            "blob" => ColType::Blob,
            "datetime" => {
                let a = args(self)?;
                let f = a.first().copied().unwrap_or(0);
                if a.len() > 1 || f > 6 {
                    return Err(self.err("DATETIME precision must be 0-6"));
                }
                ColType::DateTime(f as u8)
            }
            other => return Err(SqlError::unsupported(&format!("column type {other}"))),
        };
        // Accept and ignore CHARACTER SET / COLLATE clauses on string types (binary for now).
        loop {
            if self.eat_kw("character") {
                self.kw("set")?;
                self.ident()?;
            } else if self.eat_kw("charset") || self.eat_kw("collate") {
                self.ident()?;
            } else {
                break;
            }
        }
        Ok(ty)
    }

    fn default_value(&mut self) -> Result<DefaultExpr> {
        if self.eat_kw("current_timestamp") || self.eat_kw("now") {
            if self.eat_sym("(") {
                self.sym(")")?;
            }
            return Ok(DefaultExpr::Now);
        }
        let neg = self.eat_sym("-");
        let v = match self.bump() {
            Tok::Int(s) | Tok::Num(s) => {
                let (v, sc) = parse_decimal(&s).ok_or_else(|| self.err("bad number"))?;
                let v = if neg { -v } else { v };
                if sc == 0 {
                    i64::try_from(v)
                        .map(Value::Int)
                        .unwrap_or(Value::Dec { v, s: 0 })
                } else {
                    Value::Dec { v, s: sc }
                }
            }
            Tok::Str(s) if !neg => Value::Str(s),
            Tok::Hex(b) if !neg => Value::Bytes(b),
            Tok::Ident(k) if !neg && k.eq_ignore_ascii_case("null") => Value::Null,
            Tok::Ident(k) if !neg && k.eq_ignore_ascii_case("true") => Value::Int(1),
            Tok::Ident(k) if !neg && k.eq_ignore_ascii_case("false") => Value::Int(0),
            _ => {
                self.i -= 1;
                return Err(self.err("DEFAULT must be a literal"));
            }
        };
        Ok(DefaultExpr::Value(v))
    }

    fn column_def(&mut self) -> Result<ColumnDef> {
        let cname = self.ident()?;
        let ty = self.col_type()?;
        let mut c = ColumnDef {
            name: cname,
            ty,
            nullable: true,
            default: None,
            auto_inc: false,
            primary: false,
            unique: false,
        };
        let mut saw_null = false;
        loop {
            if self.eat_kw("not") {
                self.kw("null")?;
                c.nullable = false;
                saw_null = true;
            } else if self.eat_kw("null") {
                c.nullable = true;
                saw_null = true;
            } else if self.eat_kw("default") {
                c.default = Some(self.default_value()?);
            } else if self.eat_kw("auto_increment") {
                c.auto_inc = true;
            } else if self.eat_kw("primary") {
                self.kw("key")?;
                c.primary = true;
            } else if self.eat_kw("unique") {
                let _ = self.eat_kw("key");
                c.unique = true;
            } else if self.eat_kw("comment") {
                match self.bump() {
                    Tok::Str(_) => {}
                    _ => return Err(self.err("expected comment string")),
                }
            } else {
                break;
            }
        }
        if c.primary && !saw_null {
            c.nullable = false;
        }
        Ok(c)
    }

    fn col_pos(&mut self) -> Result<ColPos> {
        if self.eat_kw("first") {
            Ok(ColPos::First)
        } else if self.eat_kw("after") {
            Ok(ColPos::After(self.ident()?))
        } else {
            Ok(ColPos::Keep)
        }
    }

    fn alter_table(&mut self) -> Result<Stmt> {
        let name = self.ident()?;
        let mut actions = Vec::new();
        loop {
            if self.eat_kw("algorithm") || self.eat_kw("lock") {
                // ALGORITHM=INPLACE/INSTANT/COPY, LOCK=NONE/…: accepted; NovaDB always picks
                // instant or online when it can.
                let _ = self.eat_sym("=");
                self.bump();
            } else if self.eat_kw("add") {
                let _ = self.eat_kw("constraint")
                    && !self.is_kw("primary")
                    && !self.is_kw("unique")
                    && self.ident().is_ok();
                if self.eat_kw("primary") {
                    self.kw("key")?;
                    actions.push(AlterAction::AddPrimaryKey(self.ident_list()?));
                } else if self.is_kw("unique") || self.is_kw("index") || self.is_kw("key") {
                    let unique = self.eat_kw("unique");
                    let _ = self.eat_kw("key") || self.eat_kw("index");
                    let iname = if matches!(self.peek(), Tok::Sym("(")) {
                        None
                    } else {
                        Some(self.ident()?)
                    };
                    actions.push(AlterAction::AddIndex(IndexDef {
                        name: iname,
                        cols: self.ident_list()?,
                        unique,
                    }));
                } else {
                    let _ = self.eat_kw("column");
                    let def = self.column_def()?;
                    let pos = self.col_pos()?;
                    actions.push(AlterAction::AddColumn { def, pos });
                }
            } else if self.eat_kw("drop") {
                if self.eat_kw("primary") {
                    self.kw("key")?;
                    actions.push(AlterAction::DropPrimaryKey);
                } else if self.eat_kw("index") || self.eat_kw("key") {
                    actions.push(AlterAction::DropIndex(self.ident()?));
                } else {
                    let _ = self.eat_kw("column");
                    actions.push(AlterAction::DropColumn(self.ident()?));
                }
            } else if self.eat_kw("modify") {
                let _ = self.eat_kw("column");
                let def = self.column_def()?;
                let pos = self.col_pos()?;
                actions.push(AlterAction::ModifyColumn {
                    old: def.name.clone(),
                    def,
                    pos,
                });
            } else if self.eat_kw("change") {
                let _ = self.eat_kw("column");
                let old = self.ident()?;
                let def = self.column_def()?;
                let pos = self.col_pos()?;
                actions.push(AlterAction::ModifyColumn { old, def, pos });
            } else if self.eat_kw("rename") {
                if self.eat_kw("column") {
                    let old = self.ident()?;
                    self.kw("to")?;
                    let new = self.ident()?;
                    actions.push(AlterAction::RenameColumn { old, new });
                } else if self.eat_kw("index") || self.eat_kw("key") {
                    let old = self.ident()?;
                    self.kw("to")?;
                    let new = self.ident()?;
                    actions.push(AlterAction::RenameIndex { old, new });
                } else {
                    let _ = self.eat_kw("to") || self.eat_kw("as");
                    actions.push(AlterAction::RenameTable(self.ident()?));
                }
            } else if self.eat_kw("alter") {
                let _ = self.eat_kw("column");
                let col = self.ident()?;
                if self.eat_kw("set") {
                    self.kw("default")?;
                    let d = self.default_value()?;
                    actions.push(AlterAction::SetDefault {
                        col,
                        default: Some(d),
                    });
                } else {
                    self.kw("drop")?;
                    self.kw("default")?;
                    actions.push(AlterAction::SetDefault { col, default: None });
                }
            } else {
                return Err(self.err("expected ADD, DROP, MODIFY, CHANGE, RENAME or ALTER"));
            }
            if !self.eat_sym(",") {
                break;
            }
        }
        if actions.is_empty() {
            return Err(self.err("nothing to alter"));
        }
        Ok(Stmt::AlterTable { name, actions })
    }

    fn create_table(&mut self) -> Result<Stmt> {
        let if_not_exists = if self.eat_kw("if") {
            self.kw("not")?;
            self.kw("exists")?;
            true
        } else {
            false
        };
        let name = self.ident()?;
        self.sym("(")?;
        let mut cols = Vec::new();
        let mut pk: Option<Vec<String>> = None;
        let mut indexes = Vec::new();
        loop {
            if self.eat_kw("constraint") && !self.is_kw("primary") && !self.is_kw("unique") {
                self.ident()?;
            }
            if self.eat_kw("primary") {
                self.kw("key")?;
                if pk.is_some() {
                    return Err(SqlError::multiple_pk());
                }
                pk = Some(self.ident_list()?);
            } else if self.is_kw("unique") || self.is_kw("key") || self.is_kw("index") {
                let unique = self.eat_kw("unique");
                let _ = self.eat_kw("key") || self.eat_kw("index");
                let iname = if matches!(self.peek(), Tok::Sym("(")) {
                    None
                } else {
                    Some(self.ident()?)
                };
                indexes.push(IndexDef {
                    name: iname,
                    cols: self.ident_list()?,
                    unique,
                });
            } else {
                let c = self.column_def()?;
                cols.push(c);
            }
            if self.eat_sym(",") {
                continue;
            }
            self.sym(")")?;
            break;
        }
        // Table options (ENGINE=..., DEFAULT CHARSET=...) are accepted and ignored.
        while !self.at_eof() && !matches!(self.peek(), Tok::Sym(";")) {
            self.bump();
        }
        Ok(Stmt::CreateTable(CreateTable {
            name,
            if_not_exists,
            cols,
            pk,
            indexes,
        }))
    }

    fn insert(&mut self) -> Result<Stmt> {
        let _ = self.eat_kw("into");
        let table = self.ident()?;
        let cols =
            if matches!(self.peek(), Tok::Sym("(")) && matches!(self.peek_at(1), Tok::Sym(")")) {
                self.i += 2;
                Some(Vec::new())
            } else if matches!(self.peek(), Tok::Sym("(")) {
                Some(self.ident_list()?)
            } else {
                None
            };
        if self.eat_kw("select") {
            let sel = self.select()?;
            return Ok(Stmt::Insert {
                table,
                cols,
                rows: Vec::new(),
                select: Some(Box::new(sel)),
            });
        }
        if !self.eat_kw("values") {
            self.kw("value")?;
        }
        let mut rows = Vec::new();
        loop {
            self.sym("(")?;
            let mut row = Vec::new();
            if !self.eat_sym(")") {
                row.push(self.expr()?);
                while self.eat_sym(",") {
                    row.push(self.expr()?);
                }
                self.sym(")")?;
            }
            rows.push(row);
            if !self.eat_sym(",") {
                break;
            }
        }
        Ok(Stmt::Insert {
            table,
            cols,
            rows,
            select: None,
        })
    }

    fn order_by(&mut self) -> Result<Vec<OrderBy>> {
        let mut v = Vec::new();
        if self.is_kw("order") && self.is_kw_at(1, "by") {
            self.i += 2;
            loop {
                let expr = self.expr()?;
                let desc = if self.eat_kw("desc") {
                    true
                } else {
                    let _ = self.eat_kw("asc");
                    false
                };
                v.push(OrderBy { expr, desc });
                if !self.eat_sym(",") {
                    break;
                }
            }
        }
        Ok(v)
    }

    fn select(&mut self) -> Result<Select> {
        let distinct = self.eat_kw("distinct");
        if !distinct {
            let _ = self.eat_kw("all");
        }
        let mut items = Vec::new();
        loop {
            if self.eat_sym("*") {
                items.push(SelectItem::Star);
            } else if matches!(self.peek(), Tok::Ident(_) | Tok::QIdent(_))
                && matches!(self.peek_at(1), Tok::Sym("."))
                && matches!(self.peek_at(2), Tok::Sym("*"))
            {
                let t = self.ident()?;
                self.i += 2;
                items.push(SelectItem::TableStar(t));
            } else {
                let start = self.pos();
                let expr = self.expr()?;
                let text = self
                    .sql
                    .get(start..self.prev_end())
                    .unwrap_or("")
                    .to_string();
                let alias = if self.eat_kw("as") {
                    Some(match self.bump() {
                        Tok::Str(s) => s,
                        _ => {
                            self.i -= 1;
                            self.ident()?
                        }
                    })
                } else if matches!(self.peek(), Tok::QIdent(_))
                    || matches!(self.peek(), Tok::Ident(s) if !RESERVED.iter().any(|r| s.eq_ignore_ascii_case(r)))
                {
                    Some(self.ident()?)
                } else {
                    None
                };
                items.push(SelectItem::Expr { expr, alias, text });
            }
            if !self.eat_sym(",") {
                break;
            }
        }
        let (mut from, mut alias, mut joins) = (None, None, Vec::new());
        if self.eat_kw("from") {
            from = Some(self.ident()?);
            alias = self.table_alias()?;
            loop {
                let kind = if self.eat_sym(",") {
                    JoinKind::Cross
                } else if self.eat_kw("join") {
                    JoinKind::Inner
                } else if self.is_kw("inner") || self.is_kw("cross") {
                    let k = if self.eat_kw("inner") {
                        JoinKind::Inner
                    } else {
                        self.i += 1;
                        JoinKind::Cross
                    };
                    self.kw("join")?;
                    k
                } else if self.is_kw("left") || self.is_kw("right") {
                    let k = if self.eat_kw("left") {
                        JoinKind::Left
                    } else {
                        self.i += 1;
                        JoinKind::Right
                    };
                    let _ = self.eat_kw("outer");
                    self.kw("join")?;
                    k
                } else if self.is_kw("natural") {
                    return Err(SqlError::unsupported("NATURAL JOIN"));
                } else {
                    break;
                };
                let table = self.ident()?;
                let jalias = self.table_alias()?;
                let (mut on, mut using) = (None, Vec::new());
                if kind != JoinKind::Cross || self.is_kw("on") || self.is_kw("using") {
                    if self.eat_kw("on") {
                        on = Some(self.expr()?);
                    } else if self.eat_kw("using") {
                        using = self.ident_list()?;
                    } else if kind != JoinKind::Cross && kind != JoinKind::Inner {
                        return Err(self.err("expected ON or USING"));
                    }
                }
                joins.push(Join {
                    kind,
                    table,
                    alias: jalias,
                    on,
                    using,
                });
                if joins.len() > 60 {
                    return Err(SqlError::unsupported("more than 61 tables in a join"));
                }
            }
        }
        let filter = if self.eat_kw("where") {
            Some(self.expr()?)
        } else {
            None
        };
        let mut group_by = Vec::new();
        if self.is_kw("group") && self.is_kw_at(1, "by") {
            self.i += 2;
            loop {
                group_by.push(self.expr()?);
                if !self.eat_sym(",") {
                    break;
                }
            }
        }
        let having = if self.eat_kw("having") {
            Some(self.expr()?)
        } else {
            None
        };
        let order = self.order_by()?;
        let (limit, offset) = self.limit_offset(true)?;
        if self.is_kw("union") {
            return Err(SqlError::unsupported("UNION"));
        }
        if self.is_kw("into") {
            return Err(SqlError::unsupported(
                "SELECT ... INTO OUTFILE/DUMPFILE/@var (NovaDB never writes files from SQL)",
            ));
        }
        if self.is_kw("for") || self.is_kw("lock") {
            return Err(SqlError::unsupported(
                "SELECT ... FOR UPDATE / LOCK IN SHARE MODE",
            ));
        }
        Ok(Select {
            distinct,
            items,
            from,
            alias,
            joins,
            filter,
            group_by,
            having,
            order,
            limit,
            offset,
        })
    }

    /// `[AS] alias` after a table name.
    fn table_alias(&mut self) -> Result<Option<String>> {
        if self.eat_kw("as") {
            return self.ident().map(Some);
        }
        match self.peek() {
            Tok::QIdent(_) => self.ident().map(Some),
            Tok::Ident(s)
                if !RESERVED.iter().any(|r| s.eq_ignore_ascii_case(r))
                    && !["on", "where", "limit", "order", "set", "for", "lock"]
                        .iter()
                        .any(|r| s.eq_ignore_ascii_case(r)) =>
            {
                self.ident().map(Some)
            }
            _ => Ok(None),
        }
    }

    fn limit_offset(&mut self, allow_offset: bool) -> Result<(Option<u64>, u64)> {
        if !self.eat_kw("limit") {
            return Ok((None, 0));
        }
        let a = self.uint()?;
        if allow_offset && self.eat_sym(",") {
            let b = self.uint()?;
            return Ok((Some(b), a));
        }
        if allow_offset && self.eat_kw("offset") {
            let o = self.uint()?;
            return Ok((Some(a), o));
        }
        Ok((Some(a), 0))
    }

    fn update(&mut self) -> Result<Stmt> {
        let table = self.ident()?;
        self.kw("set")?;
        let mut sets = Vec::new();
        loop {
            let c = self.ident()?;
            self.sym("=")?;
            sets.push((c, self.expr()?));
            if !self.eat_sym(",") {
                break;
            }
        }
        let filter = if self.eat_kw("where") {
            Some(self.expr()?)
        } else {
            None
        };
        let order = self.order_by()?;
        let (limit, _) = self.limit_offset(false)?;
        Ok(Stmt::Update {
            table,
            sets,
            filter,
            order,
            limit,
        })
    }

    fn delete(&mut self) -> Result<Stmt> {
        self.kw("from")?;
        let table = self.ident()?;
        let filter = if self.eat_kw("where") {
            Some(self.expr()?)
        } else {
            None
        };
        let order = self.order_by()?;
        let (limit, _) = self.limit_offset(false)?;
        Ok(Stmt::Delete {
            table,
            filter,
            order,
            limit,
        })
    }

    // ----- expressions (lowest → highest precedence) --------------------------------------

    fn expr(&mut self) -> Result<Expr> {
        self.depth += 1;
        if self.depth > MAX_PARSE_DEPTH {
            return Err(SqlError::syntax(
                self.pos(),
                "",
                "expression nested too deeply",
            ));
        }
        let r = self.or_expr();
        self.depth -= 1;
        r
    }

    fn bin(op: BinOp, l: Expr, r: Expr) -> Expr {
        Expr::Binary {
            op,
            l: Box::new(l),
            r: Box::new(r),
        }
    }

    fn or_expr(&mut self) -> Result<Expr> {
        let mut l = self.xor_expr()?;
        while self.eat_kw("or") || self.eat_sym("||") {
            let r = self.xor_expr()?;
            l = Self::bin(BinOp::Or, l, r);
        }
        Ok(l)
    }

    fn xor_expr(&mut self) -> Result<Expr> {
        let mut l = self.and_expr()?;
        while self.eat_kw("xor") {
            let r = self.and_expr()?;
            l = Self::bin(BinOp::Xor, l, r);
        }
        Ok(l)
    }

    fn and_expr(&mut self) -> Result<Expr> {
        let mut l = self.not_expr()?;
        while self.eat_kw("and") || self.eat_sym("&&") {
            let r = self.not_expr()?;
            l = Self::bin(BinOp::And, l, r);
        }
        Ok(l)
    }

    fn not_expr(&mut self) -> Result<Expr> {
        if self.eat_kw("not") {
            self.depth += 1;
            if self.depth > MAX_PARSE_DEPTH {
                return Err(SqlError::syntax(
                    self.pos(),
                    "",
                    "expression nested too deeply",
                ));
            }
            let e = self.not_expr();
            self.depth -= 1;
            return Ok(Expr::Unary {
                op: UnOp::Not,
                e: Box::new(e?),
            });
        }
        self.cmp_expr()
    }

    fn cmp_expr(&mut self) -> Result<Expr> {
        let mut l = self.add_expr()?;
        loop {
            let op = match self.peek() {
                Tok::Sym("=") => Some(BinOp::Eq),
                Tok::Sym("<=>") => Some(BinOp::NullSafeEq),
                Tok::Sym("!=") | Tok::Sym("<>") => Some(BinOp::Ne),
                Tok::Sym("<") => Some(BinOp::Lt),
                Tok::Sym("<=") => Some(BinOp::Le),
                Tok::Sym(">") => Some(BinOp::Gt),
                Tok::Sym(">=") => Some(BinOp::Ge),
                _ => None,
            };
            if let Some(op) = op {
                self.i += 1;
                let r = self.add_expr()?;
                l = Self::bin(op, l, r);
                continue;
            }
            if self.eat_kw("is") {
                let neg = self.eat_kw("not");
                if self.eat_kw("null") {
                    l = Expr::IsNull {
                        e: Box::new(l),
                        neg,
                    };
                } else if self.eat_kw("true") || self.eat_kw("false") {
                    let want_true = matches!(&self.toks[self.i - 1].tok, Tok::Ident(s) if s.eq_ignore_ascii_case("true"));
                    // x IS TRUE  ==  COALESCE(x <> 0, 0); expressed via functions.
                    let t = Expr::Func {
                        name: "__is_true".into(),
                        args: vec![l],
                    };
                    let t = if want_true {
                        t
                    } else {
                        Expr::Func {
                            name: "__is_false".into(),
                            args: vec![match t {
                                Expr::Func { args, .. } => {
                                    args.into_iter().next().unwrap_or(Expr::Lit(Value::Null))
                                }
                                other => other,
                            }],
                        }
                    };
                    l = if neg {
                        Expr::Unary {
                            op: UnOp::Not,
                            e: Box::new(t),
                        }
                    } else {
                        t
                    };
                } else {
                    return Err(self.err("expected NULL, TRUE or FALSE after IS"));
                }
                continue;
            }
            let neg = self.is_kw("not")
                && (self.is_kw_at(1, "in")
                    || self.is_kw_at(1, "between")
                    || self.is_kw_at(1, "like"));
            if neg {
                self.i += 1;
            }
            if self.eat_kw("in") {
                self.sym("(")?;
                if self.eat_kw("select") {
                    let sub = self.select()?;
                    self.sym(")")?;
                    l = Expr::InSubquery {
                        e: Box::new(l),
                        sub: Box::new(sub),
                        neg,
                    };
                    continue;
                }
                let mut list = vec![self.expr()?];
                while self.eat_sym(",") {
                    list.push(self.expr()?);
                }
                self.sym(")")?;
                l = Expr::InList {
                    e: Box::new(l),
                    list,
                    neg,
                };
                continue;
            }
            if self.eat_kw("between") {
                let lo = self.add_expr()?;
                self.kw("and")?;
                let hi = self.add_expr()?;
                l = Expr::Between {
                    e: Box::new(l),
                    lo: Box::new(lo),
                    hi: Box::new(hi),
                    neg,
                };
                continue;
            }
            if self.eat_kw("like") {
                let pat = self.add_expr()?;
                l = Expr::Like {
                    e: Box::new(l),
                    pat: Box::new(pat),
                    neg,
                };
                continue;
            }
            if neg {
                return Err(self.err("expected IN, BETWEEN or LIKE after NOT"));
            }
            return Ok(l);
        }
    }

    fn add_expr(&mut self) -> Result<Expr> {
        let mut l = self.mul_expr()?;
        loop {
            let op = if self.eat_sym("+") {
                BinOp::Add
            } else if self.eat_sym("-") {
                BinOp::Sub
            } else {
                return Ok(l);
            };
            let r = self.mul_expr()?;
            l = Self::bin(op, l, r);
        }
    }

    fn mul_expr(&mut self) -> Result<Expr> {
        let mut l = self.unary()?;
        loop {
            let op = if self.eat_sym("*") {
                BinOp::Mul
            } else if self.eat_sym("/") {
                BinOp::Div
            } else if self.eat_sym("%") || self.eat_kw("mod") {
                BinOp::Mod
            } else if self.eat_kw("div") {
                BinOp::IntDiv
            } else {
                return Ok(l);
            };
            let r = self.unary()?;
            l = Self::bin(op, l, r);
        }
    }

    fn unary(&mut self) -> Result<Expr> {
        self.depth += 1;
        if self.depth > MAX_PARSE_DEPTH {
            return Err(SqlError::syntax(
                self.pos(),
                "",
                "expression nested too deeply",
            ));
        }
        let r = if self.eat_sym("-") {
            match self.unary()? {
                // Fold -literal so i64::MIN can be written.
                Expr::Lit(Value::Int(i)) => Ok(Expr::Lit(Value::Int(-i))),
                Expr::Lit(Value::Dec { v, s }) => Ok(match i64::try_from(-v) {
                    Ok(i) if s == 0 => Expr::Lit(Value::Int(i)),
                    _ => Expr::Lit(Value::Dec { v: -v, s }),
                }),
                e => Ok(Expr::Unary {
                    op: UnOp::Neg,
                    e: Box::new(e),
                }),
            }
        } else if self.eat_sym("+") {
            self.unary()
        } else if self.eat_sym("!") {
            self.unary().map(|e| Expr::Unary {
                op: UnOp::Not,
                e: Box::new(e),
            })
        } else {
            self.primary()
        };
        self.depth -= 1;
        r
    }

    fn primary(&mut self) -> Result<Expr> {
        match self.peek().clone() {
            Tok::Int(s) => {
                self.i += 1;
                let (v, _) = parse_decimal(&s).ok_or_else(|| self.err("bad number"))?;
                Ok(Expr::Lit(match i64::try_from(v) {
                    Ok(i) => Value::Int(i),
                    Err(_) => Value::Dec { v, s: 0 },
                }))
            }
            Tok::Num(s) => {
                self.i += 1;
                let (v, sc) = parse_decimal(&s).ok_or_else(|| self.err("bad number"))?;
                Ok(Expr::Lit(Value::Dec { v, s: sc }))
            }
            Tok::Str(s) => {
                self.i += 1;
                Ok(Expr::Lit(Value::Str(s)))
            }
            Tok::Hex(b) => {
                self.i += 1;
                Ok(Expr::Lit(Value::Bytes(b)))
            }
            Tok::Sym("?") => {
                self.i += 1;
                self.params += 1;
                if self.params > u16::MAX as usize {
                    return Err(self.err("too many placeholders"));
                }
                Ok(Expr::Param(self.params - 1))
            }
            Tok::SysVar(n) => {
                self.i += 1;
                Ok(Expr::Func {
                    name: "__sysvar".into(),
                    args: vec![Expr::Lit(Value::Str(n))],
                })
            }
            Tok::Sym("(") => {
                self.i += 1;
                if self.eat_kw("select") {
                    let sub = self.select()?;
                    self.sym(")")?;
                    return Ok(Expr::Subquery(Box::new(sub)));
                }
                let e = self.expr()?;
                self.sym(")")?;
                Ok(e)
            }
            Tok::Ident(s)
                if s.eq_ignore_ascii_case("exists") && matches!(self.peek_at(1), Tok::Sym("(")) =>
            {
                self.i += 2;
                self.kw("select")?;
                let sub = self.select()?;
                self.sym(")")?;
                Ok(Expr::Exists {
                    sub: Box::new(sub),
                    neg: false,
                })
            }
            Tok::Ident(s) if s.eq_ignore_ascii_case("null") => {
                self.i += 1;
                Ok(Expr::Lit(Value::Null))
            }
            Tok::Ident(s) if s.eq_ignore_ascii_case("true") => {
                self.i += 1;
                Ok(Expr::Lit(Value::Int(1)))
            }
            Tok::Ident(s) if s.eq_ignore_ascii_case("false") => {
                self.i += 1;
                Ok(Expr::Lit(Value::Int(0)))
            }
            Tok::Ident(s)
                if (s.eq_ignore_ascii_case("current_timestamp")
                    || s.eq_ignore_ascii_case("localtimestamp"))
                    && !matches!(self.peek_at(1), Tok::Sym("(")) =>
            {
                self.i += 1;
                Ok(Expr::Func {
                    name: "now".into(),
                    args: vec![],
                })
            }
            Tok::Ident(s)
                if matches!(self.peek_at(1), Tok::Sym("("))
                    && !RESERVED.iter().any(|r| s.eq_ignore_ascii_case(r))
                    || (matches!(self.peek_at(1), Tok::Sym("("))
                        && (s.eq_ignore_ascii_case("if") || s.eq_ignore_ascii_case("mod"))) =>
            {
                self.i += 2;
                let mut name = s.to_ascii_lowercase();
                let mut args = Vec::new();
                if name == "count" && matches!(self.peek(), Tok::Sym("*")) {
                    // COUNT(*) counts rows: same as COUNT(1).
                    self.i += 1;
                    self.sym(")")?;
                    return Ok(Expr::Func {
                        name,
                        args: vec![Expr::Lit(Value::Int(1))],
                    });
                }
                if crate::query::is_aggregate(&name) && self.eat_kw("distinct") {
                    name = format!("{name}_distinct");
                }
                if !self.eat_sym(")") {
                    args.push(self.expr()?);
                    while self.eat_sym(",") {
                        args.push(self.expr()?);
                    }
                    if name.starts_with("group_concat") && self.eat_kw("separator") {
                        match self.bump() {
                            Tok::Str(sep) => args.push(Expr::Lit(Value::Str(sep))),
                            _ => return Err(self.err("expected a separator string")),
                        }
                        if !name.ends_with("_sep") {
                            name.push_str("_sep");
                        }
                    }
                    self.sym(")")?;
                }
                Ok(Expr::Func { name, args })
            }
            Tok::Ident(_) | Tok::QIdent(_) => {
                let mut name = self.ident()?;
                // table.column is kept as "table.column" and resolved by the executor.
                if self.eat_sym(".") {
                    name = format!("{name}.{}", self.ident()?);
                }
                Ok(Expr::Col(name))
            }
            _ => Err(self.err("expected an expression")),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    fn one(s: &str) -> Stmt {
        let mut v = parse(s).unwrap();
        assert_eq!(v.len(), 1);
        v.remove(0)
    }

    #[test]
    fn create_table() {
        let Stmt::CreateTable(c) = one(
            "CREATE TABLE IF NOT EXISTS `users` (id BIGINT NOT NULL AUTO_INCREMENT, name VARCHAR(32) NOT NULL DEFAULT 'x', \
             bal DECIMAL(12,2) DEFAULT -1.5, born DATETIME(3) DEFAULT CURRENT_TIMESTAMP, bio TEXT, PRIMARY KEY (id), UNIQUE KEY u_name (name), KEY (bal)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
        ) else {
            panic!()
        };
        assert!(c.if_not_exists);
        assert_eq!(c.cols.len(), 5);
        assert_eq!(c.cols[2].ty, ColType::Decimal { p: 12, s: 2 });
        assert_eq!(
            c.cols[2].default,
            Some(DefaultExpr::Value(Value::Dec { v: -15, s: 1 }))
        );
        assert_eq!(c.cols[3].default, Some(DefaultExpr::Now));
        assert_eq!(c.pk, Some(vec!["id".into()]));
        assert_eq!(c.indexes.len(), 2);
        assert!(c.indexes[0].unique);
    }

    #[test]
    fn select_shapes() {
        let Stmt::Select(s) = one(
            "select a, b+1 AS x, `c` y from t where a = 1 and not b in (1,2) or c like 'x%' order by a desc, b limit 5, 10",
        ) else {
            panic!()
        };
        assert_eq!(s.items.len(), 3);
        assert_eq!(s.limit, Some(10));
        assert_eq!(s.offset, 5);
        assert_eq!(s.order.len(), 2);
        assert!(s.order[0].desc);
        match &s.items[1] {
            SelectItem::Expr { alias, text, .. } => {
                assert_eq!(alias.as_deref(), Some("x"));
                assert_eq!(text, "b+1");
            }
            _ => panic!(),
        }
        let Stmt::Select(s) = one("SELECT 1 + 2 * 3") else {
            panic!()
        };
        assert_eq!(
            s.items[0],
            SelectItem::Expr {
                expr: Expr::Binary {
                    op: BinOp::Add,
                    l: Box::new(Expr::Lit(Value::Int(1))),
                    r: Box::new(Expr::Binary {
                        op: BinOp::Mul,
                        l: Box::new(Expr::Lit(Value::Int(2))),
                        r: Box::new(Expr::Lit(Value::Int(3)))
                    })
                },
                alias: None,
                text: "1 + 2 * 3".into()
            }
        );
        assert_eq!(parse("SELECT -9223372036854775808").unwrap().len(), 1);
    }

    #[test]
    fn multi_and_errors() {
        assert_eq!(parse("select 1; select 2;").unwrap().len(), 2);
        assert_eq!(parse("  ;; ").unwrap().len(), 0);
        for bad in [
            "select",
            "select 1 2",
            "insert t values (1",
            "create table t (a nosuchtype)",
            "select * from select",
            "delete t",
            "update t set",
            "select 1 from t where",
        ] {
            let e = parse(bad).unwrap_err();
            assert!(e.code == 1064 || e.code == 1235, "{bad}: {e}");
        }
        let deep = format!("select {}1{}", "(".repeat(5000), ")".repeat(5000));
        assert_eq!(parse(&deep).unwrap_err().code, 1064);
        let deep_not = format!("select {}1", "not ".repeat(5000));
        assert_eq!(parse(&deep_not).unwrap_err().code, 1064);
        let deep_neg = format!("select {}1", "- ".repeat(5000));
        assert_eq!(parse(&deep_neg).unwrap_err().code, 1064);
    }

    #[test]
    fn client_statements() {
        let (v, n) = parse_prepared("SELECT * FROM t WHERE a = ? AND b IN (?, ?)").unwrap();
        assert_eq!((v.len(), n), (1, 3));
        assert!(
            matches!(one("SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci"), Stmt::Set(v) if v.len() == 1)
        );
        assert!(
            matches!(one("SET autocommit=0, @@session.sql_mode = 'STRICT_ALL_TABLES', SESSION wait_timeout = 10"), Stmt::Set(v) if v.len() == 3 && v[0].0 == "autocommit" && v[1].0 == "sql_mode")
        );
        assert!(
            matches!(one("SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED"), Stmt::Set(v) if v.is_empty())
        );
        assert_eq!(parse("SET @x = 1").unwrap_err().code, 1235);
        assert!(matches!(one("USE `novadb`"), Stmt::Use(d) if d == "novadb"));
        assert!(matches!(
            one("START TRANSACTION READ WRITE"),
            Stmt::Txn(TxnKind::Begin)
        ));
        assert!(matches!(one("rollback"), Stmt::Txn(TxnKind::Rollback)));
        assert!(
            matches!(one("CREATE USER IF NOT EXISTS 'app'@'%' IDENTIFIED BY 'pw'"), Stmt::CreateUser { name, password, if_not_exists: true } if name == "app" && password == "pw")
        );
        assert!(matches!(
            one("ALTER USER app@localhost IDENTIFIED WITH caching_sha2_password BY 'x'"),
            Stmt::AlterUser { .. }
        ));
        assert!(
            matches!(one("DROP USER 'a', 'b'@'h'"), Stmt::DropUser { names, .. } if names.len() == 2)
        );
        assert!(matches!(
            one("SHOW SESSION VARIABLES LIKE 'version%'"),
            Stmt::ShowVariables {
                like: Some(_),
                status: false
            }
        ));
        assert!(matches!(one("SHOW DATABASES"), Stmt::ShowDatabases));
        assert!(matches!(
            one("SELECT @@version_comment LIMIT 1"),
            Stmt::Select(_)
        ));
    }

    #[test]
    fn file_and_native_code_features_are_refused() {
        for sql in [
            "LOAD DATA INFILE '/etc/passwd' INTO TABLE t",
            "LOAD DATA LOCAL INFILE '/home/u/.ssh/id_rsa' INTO TABLE t",
            "LOAD XML INFILE 'x' INTO TABLE t",
            "SELECT * FROM t INTO OUTFILE '/var/www/shell.php'",
            "SELECT 1 INTO DUMPFILE '/tmp/x'",
            "CREATE FUNCTION sys_exec RETURNS INT SONAME 'lib_mysqludf_sys.so'",
            "CREATE AGGREGATE FUNCTION f RETURNS INT SONAME 'x.so'",
            "INSTALL PLUGIN x SONAME 'x.so'",
            "CREATE TRIGGER t BEFORE INSERT ON x FOR EACH ROW SET @a = 1",
            "CREATE PROCEDURE p() SELECT 1",
        ] {
            let e = parse(sql).unwrap_err();
            assert_eq!(e.code, 1235, "{sql}: {e}");
        }
        // LOAD_FILE() is simply an unknown function.
        assert!(matches!(
            one("SELECT LOAD_FILE('/etc/passwd')"),
            Stmt::Select(_)
        ));
    }

    #[test]
    fn dml() {
        assert!(
            matches!(one("INSERT INTO t (a,b) VALUES (1,'x'),(2,NULL)"), Stmt::Insert { rows, .. } if rows.len() == 2)
        );
        assert!(matches!(
            one("UPDATE t SET a = a + 1, b = 'y' WHERE id BETWEEN 1 AND 5 LIMIT 3"),
            Stmt::Update { limit: Some(3), .. }
        ));
        assert!(matches!(
            one("DELETE FROM t WHERE x IS NOT NULL"),
            Stmt::Delete { .. }
        ));
        assert!(matches!(one("explain select * from t"), Stmt::Explain(_)));
        assert!(matches!(one("show tables"), Stmt::ShowTables));
        assert!(matches!(
            one("create unique index i on t (a, b)"),
            Stmt::CreateIndex { unique: true, .. }
        ));
    }
}
