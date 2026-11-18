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
    Describe(String),
    ShowCreateTable(String),
    Explain(Box<Stmt>),
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
    Expr {
        expr: Expr,
        alias: Option<String>,
        text: String,
    },
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
    pub filter: Option<Expr>,
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
}

impl Expr {
    /// Visit every column reference.
    pub fn columns<'a>(&'a self, out: &mut Vec<&'a str>) {
        match self {
            Expr::Lit(_) => {}
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
        }
    }
}
