//! Statement and expression trees.

use crate::value::{ColType, Value};

#[derive(Debug, Clone, PartialEq)]
pub enum Stmt {
    CreateTable(CreateTable),
    DropTable {
        names: Vec<String>,
        if_exists: bool,
    },
    CreateIndex {
        name: String,
        table: String,
        cols: Vec<String>,
        unique: bool,
    },
    DropIndex {
        name: String,
        table: String,
    },
    Insert {
        table: String,
        cols: Option<Vec<String>>,
        rows: Vec<Vec<Expr>>,
        /// INSERT … SELECT
        select: Option<Box<Select>>,
    },
    Select(Select),
    Update {
        table: String,
        sets: Vec<(String, Expr)>,
        filter: Option<Expr>,
        order: Vec<OrderBy>,
        limit: Option<u64>,
    },
    Delete {
        table: String,
        filter: Option<Expr>,
        order: Vec<OrderBy>,
        limit: Option<u64>,
    },
    ShowTables,
    /// GRANT privs ON scope TO users [WITH GRANT OPTION]; `table` None = global (*.*).
    /// `privs` == u64::MAX means ALL PRIVILEGES (resolved by scope).
    Grant {
        privs: u64,
        table: Option<String>,
        users: Vec<String>,
        grant_option: bool,
    },
    /// REVOKE privs [, GRANT OPTION] ON scope FROM users.
    Revoke {
        privs: u64,
        table: Option<String>,
        users: Vec<String>,
        grant_option: bool,
    },
    ShowGrants(Option<String>),
    /// BACKUP DATABASE TO 'name' — handled by the server (root only, into <data>/backups).
    Backup(String),
    /// SHOW [FULL] PROCESSLIST — handled by the server.
    ShowProcesslist,
    /// KILL [CONNECTION | QUERY] id — handled by the server.
    Kill {
        id: u64,
        query_only: bool,
    },
    ShowDatabases,
    /// SHOW [SESSION|GLOBAL] VARIABLES / STATUS [LIKE 'pattern']
    ShowVariables {
        like: Option<String>,
        status: bool,
    },
    ShowWarnings,
    /// SET var = expr, ... (names lowercased; NAMES / CHARACTER SET map to character_set_client)
    Set(Vec<(String, Expr)>),
    Use(String),
    Txn(TxnKind),
    CreateUser {
        name: String,
        password: String,
        if_not_exists: bool,
    },
    AlterUser {
        name: String,
        password: String,
        if_exists: bool,
    },
    DropUser {
        names: Vec<String>,
        if_exists: bool,
    },
    Describe(String),
    ShowCreateTable(String),
    Explain(Box<Stmt>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxnKind {
    Begin,
    Commit,
    Rollback,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DefaultExpr {
    Value(Value),
    /// CURRENT_TIMESTAMP / NOW() (DATETIME only).
    Now,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ColumnDef {
    pub name: String,
    pub ty: ColType,
    pub nullable: bool,
    pub default: Option<DefaultExpr>,
    pub auto_inc: bool,
    pub primary: bool,
    pub unique: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IndexDef {
    pub name: Option<String>,
    pub cols: Vec<String>,
    pub unique: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CreateTable {
    pub name: String,
    pub if_not_exists: bool,
    pub cols: Vec<ColumnDef>,
    pub pk: Option<Vec<String>>,
    pub indexes: Vec<IndexDef>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SelectItem {
    Star,
    /// `alias.*`
    TableStar(String),
    Expr {
        expr: Expr,
        alias: Option<String>,
        text: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinKind {
    Inner,
    Left,
    Right,
    Cross,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Join {
    pub kind: JoinKind,
    pub table: String,
    pub alias: Option<String>,
    pub on: Option<Expr>,
    pub using: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OrderBy {
    pub expr: Expr,
    pub desc: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Select {
    pub distinct: bool,
    pub items: Vec<SelectItem>,
    pub from: Option<String>,
    /// Alias of the first FROM table.
    pub alias: Option<String>,
    pub joins: Vec<Join>,
    pub filter: Option<Expr>,
    pub group_by: Vec<Expr>,
    pub having: Option<Expr>,
    pub order: Vec<OrderBy>,
    pub limit: Option<u64>,
    pub offset: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Or,
    And,
    Xor,
    Eq,
    NullSafeEq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Add,
    Sub,
    Mul,
    Div,
    IntDiv,
    Mod,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnOp {
    Neg,
    Not,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Lit(Value),
    /// `?` placeholder (0-based, in order of appearance); replaced by `bind_params`.
    Param(usize),
    Col(String),
    Unary {
        op: UnOp,
        e: Box<Expr>,
    },
    Binary {
        op: BinOp,
        l: Box<Expr>,
        r: Box<Expr>,
    },
    IsNull {
        e: Box<Expr>,
        neg: bool,
    },
    InList {
        e: Box<Expr>,
        list: Vec<Expr>,
        neg: bool,
    },
    Between {
        e: Box<Expr>,
        lo: Box<Expr>,
        hi: Box<Expr>,
        neg: bool,
    },
    Like {
        e: Box<Expr>,
        pat: Box<Expr>,
        neg: bool,
    },
    Func {
        name: String,
        args: Vec<Expr>,
    },
    /// Scalar subquery `(SELECT …)`.
    Subquery(Box<Select>),
    InSubquery {
        e: Box<Expr>,
        sub: Box<Select>,
        neg: bool,
    },
    Exists {
        sub: Box<Select>,
        neg: bool,
    },
}

impl Expr {
    /// Visit every column reference.
    pub fn columns<'a>(&'a self, out: &mut Vec<&'a str>) {
        match self {
            Expr::Lit(_) | Expr::Param(_) => {}
            Expr::Col(c) => out.push(c),
            Expr::Unary { e, .. } | Expr::IsNull { e, .. } => e.columns(out),
            Expr::Binary { l, r, .. } => {
                l.columns(out);
                r.columns(out);
            }
            Expr::InList { e, list, .. } => {
                e.columns(out);
                for x in list {
                    x.columns(out);
                }
            }
            Expr::Between { e, lo, hi, .. } => {
                e.columns(out);
                lo.columns(out);
                hi.columns(out);
            }
            Expr::Like { e, pat, .. } => {
                e.columns(out);
                pat.columns(out);
            }
            Expr::Func { args, .. } => {
                for a in args {
                    a.columns(out);
                }
            }
            // Subqueries have their own scope (only uncorrelated ones are supported).
            Expr::Subquery(_) | Expr::Exists { .. } => {}
            Expr::InSubquery { e, .. } => e.columns(out),
        }
    }
}

/// Apply `f` to every expression in `e` (pre-order, mutable).
pub fn walk_expr_mut(e: &mut Expr, f: &mut dyn FnMut(&mut Expr)) {
    f(e);
    match e {
        Expr::Lit(_) | Expr::Param(_) | Expr::Col(_) => {}
        Expr::Unary { e, .. } | Expr::IsNull { e, .. } => walk_expr_mut(e, f),
        Expr::Binary { l, r, .. } => {
            walk_expr_mut(l, f);
            walk_expr_mut(r, f);
        }
        Expr::InList { e, list, .. } => {
            walk_expr_mut(e, f);
            for x in list {
                walk_expr_mut(x, f);
            }
        }
        Expr::Between { e, lo, hi, .. } => {
            walk_expr_mut(e, f);
            walk_expr_mut(lo, f);
            walk_expr_mut(hi, f);
        }
        Expr::Like { e, pat, .. } => {
            walk_expr_mut(e, f);
            walk_expr_mut(pat, f);
        }
        Expr::Func { args, .. } => {
            for a in args {
                walk_expr_mut(a, f);
            }
        }
        Expr::Subquery(sub) | Expr::Exists { sub, .. } => walk_select_mut(sub, f),
        Expr::InSubquery { e, sub, .. } => {
            walk_expr_mut(e, f);
            walk_select_mut(sub, f);
        }
    }
}

pub fn walk_select_mut(sel: &mut Select, f: &mut dyn FnMut(&mut Expr)) {
    for it in &mut sel.items {
        if let SelectItem::Expr { expr, .. } = it {
            walk_expr_mut(expr, f);
        }
    }
    for j in &mut sel.joins {
        if let Some(on) = &mut j.on {
            walk_expr_mut(on, f);
        }
    }
    if let Some(w) = &mut sel.filter {
        walk_expr_mut(w, f);
    }
    for g in &mut sel.group_by {
        walk_expr_mut(g, f);
    }
    if let Some(h) = &mut sel.having {
        walk_expr_mut(h, f);
    }
    for o in &mut sel.order {
        walk_expr_mut(&mut o.expr, f);
    }
}

/// Apply `f` to every expression of a statement.
pub fn walk_stmt_mut(s: &mut Stmt, f: &mut dyn FnMut(&mut Expr)) {
    let order = |o: &mut Vec<OrderBy>, f: &mut dyn FnMut(&mut Expr)| {
        for x in o {
            walk_expr_mut(&mut x.expr, f);
        }
    };
    match s {
        Stmt::Insert { rows, select, .. } => {
            for r in rows {
                for e in r {
                    walk_expr_mut(e, f);
                }
            }
            if let Some(sel) = select {
                walk_select_mut(sel, f);
            }
        }
        Stmt::Select(sel) => walk_select_mut(sel, f),
        Stmt::Update {
            sets,
            filter,
            order: o,
            ..
        } => {
            for (_, e) in sets {
                walk_expr_mut(e, f);
            }
            if let Some(w) = filter {
                walk_expr_mut(w, f);
            }
            order(o, f);
        }
        Stmt::Delete {
            filter, order: o, ..
        } => {
            if let Some(w) = filter {
                walk_expr_mut(w, f);
            }
            order(o, f);
        }
        Stmt::Set(v) => {
            for (_, e) in v {
                walk_expr_mut(e, f);
            }
        }
        Stmt::Explain(inner) => walk_stmt_mut(inner, f),
        _ => {}
    }
}

/// Replace `?` placeholders with values. Errors if the count does not match.
pub fn bind_params(s: &mut Stmt, vals: &[Value]) -> Result<(), crate::SqlError> {
    let mut bad = None;
    walk_stmt_mut(s, &mut |e| {
        if let Expr::Param(i) = e {
            match vals.get(*i) {
                Some(v) => *e = Expr::Lit(v.clone()),
                None => bad = Some(*i),
            }
        }
    });
    match bad {
        Some(_) => Err(crate::SqlError::param_count()),
        None => Ok(()),
    }
}
