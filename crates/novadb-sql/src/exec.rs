//! Single-node executor (Stage 3). Every statement runs in one storage transaction, so a
//! statement is atomic: on any error nothing it did is kept.

use std::cmp::Ordering;
use std::collections::HashSet;
use std::ops::Bound;
use std::path::Path;

use novadb_storage::{Db, MAX_KEY_LEN, MAX_VALUE_LEN, Options, Tree, Tx, Vfs};

use crate::ast::*;
use crate::catalog::{
    CATALOG_TREE, Column, Index, MAX_COLUMNS, MAX_INDEXES, Table, counter_key, table_key,
};
use crate::codec::{key_encode, prefix_end, row_decode, row_encode};
use crate::error::{Result, SqlError};
use crate::parser::parse;
use crate::value::{ArithOp, ColType, Value, arith, coerce, compare, like, sort_cmp};

/// Max rows a statement may hold in memory (sorting, UPDATE/DELETE candidate sets, results).
/// Disk spill for sorts arrives with the planner (Stage 6); until then this is a hard cap.
pub const MAX_ROWS_IN_MEMORY: usize = 1_000_000;
/// Max encoded row size (rows above `INLINE_MAX` are chunked into the overflow tree).
pub const MAX_ROW_BYTES: usize = 4 << 20;
const INLINE_MAX: usize = MAX_VALUE_LEN - 1;
const CHUNK: usize = 4000;
const SCAN_BATCH: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnMeta {
    pub name: String,
    /// Source column type when the item is a plain column reference.
    pub ty: Option<ColType>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct QueryResult {
    pub columns: Vec<ColumnMeta>,
    pub rows: Vec<Vec<Value>>,
    pub affected: u64,
    pub last_insert_id: u64,
    pub info: Option<String>,
}

impl QueryResult {
    fn ok(affected: u64) -> Self {
        QueryResult {
            affected,
            ..Default::default()
        }
    }
    /// Cell `col` of `row` as text (None = NULL), using the column type for formatting.
    pub fn text(&self, row: usize, col: usize) -> Option<String> {
        let v = self.rows.get(row)?.get(col)?;
        v.text_as(self.columns.get(col).and_then(|c| c.ty))
    }

    /// True for statements that return a result set.
    pub fn is_rows(&self) -> bool {
        !self.columns.is_empty()
    }
}

type Clock = Box<dyn Fn() -> i64 + Send>;

pub struct Engine {
    db: Db,
    clock: Clock,
}

fn system_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_micros()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

impl Engine {
    pub fn open(dir: impl AsRef<Path>) -> Result<Engine> {
        Ok(Engine {
            db: Db::open(dir, Options::default())?,
            clock: Box::new(system_now),
        })
    }
    pub fn open_vfs(vfs: Box<dyn Vfs>, opts: Options) -> Result<Engine> {
        Ok(Engine {
            db: Db::open_vfs(vfs, opts)?,
            clock: Box::new(system_now),
        })
    }
    /// Replace the clock used by NOW()/CURRENT_TIMESTAMP (tests).
    pub fn with_clock(mut self, f: impl Fn() -> i64 + Send + 'static) -> Self {
        self.clock = Box::new(f);
        self
    }
    pub fn db(&mut self) -> &mut Db {
        &mut self.db
    }
    pub fn close(self) -> Result<()> {
        Ok(self.db.close()?)
    }

    /// Parse and run every statement in `sql`; stops at the first error.
    pub fn execute(&mut self, sql: &str) -> Result<Vec<QueryResult>> {
        let stmts = parse(sql)?;
        let mut out = Vec::with_capacity(stmts.len());
        for s in &stmts {
            out.push(self.run(s)?);
        }
        Ok(out)
    }

    /// Convenience: run exactly one statement.
    pub fn query(&mut self, sql: &str) -> Result<QueryResult> {
        let mut v = self.execute(sql)?;
        if v.len() != 1 {
            return Err(SqlError::internal("expected exactly one statement"));
        }
        Ok(v.remove(0))
    }

    pub fn run(&mut self, s: &Stmt) -> Result<QueryResult> {
        let now = (self.clock)();
        let mut tx = self.db.begin()?;
        let r = run_stmt(&mut tx, s, now);
        match (&r, s) {
            // Reads never commit.
            (
                Ok(_),
                Stmt::Select(_)
                | Stmt::ShowTables
                | Stmt::Describe(_)
                | Stmt::ShowCreateTable(_)
                | Stmt::Explain(_),
            ) => tx.rollback(),
            (Ok(_), _) => tx.commit()?,
            (Err(_), _) => tx.rollback(),
        }
        r
    }
}

fn run_stmt(tx: &mut Tx<'_>, s: &Stmt, now: i64) -> Result<QueryResult> {
    match s {
        Stmt::CreateTable(c) => create_table(tx, c),
        Stmt::DropTable { names, if_exists } => drop_table(tx, names, *if_exists),
        Stmt::CreateIndex {
            name,
            table,
            cols,
            unique,
        } => create_index(tx, name, table, cols, *unique),
        Stmt::DropIndex { name, table } => drop_index(tx, name, table),
        Stmt::Insert { table, cols, rows } => insert(tx, table, cols.as_deref(), rows, now),
        Stmt::Select(sel) => select(tx, sel, now),
        Stmt::Update {
            table,
            sets,
            filter,
            order,
            limit,
        } => update(tx, table, sets, filter.as_ref(), order, *limit, now),
        Stmt::Delete {
            table,
            filter,
            order,
            limit,
        } => delete(tx, table, filter.as_ref(), order, *limit, now),
        Stmt::ShowTables => show_tables(tx),
        Stmt::Describe(t) => describe(tx, t),
        Stmt::ShowCreateTable(t) => show_create(tx, t),
        Stmt::Explain(inner) => explain(tx, inner, now),
    }
}

// ----- catalog access ------------------------------------------------------------------------

fn catalog(tx: &mut Tx<'_>) -> Result<Tree> {
    Ok(tx.open_or_create_tree(CATALOG_TREE)?)
}

fn find_table(tx: &mut Tx<'_>, name: &str) -> Result<Option<Table>> {
    let c = catalog(tx)?;
    match tx.get(&c, &table_key(name))? {
        Some(b) => Table::decode(&b).map(Some),
        None => Ok(None),
    }
}

fn load_table(tx: &mut Tx<'_>, name: &str) -> Result<Table> {
    find_table(tx, name)?.ok_or_else(|| SqlError::no_table(name))
}

fn save_table(tx: &mut Tx<'_>, t: &Table) -> Result<()> {
    let c = catalog(tx)?;
    let b = t.encode();
    if b.len() > MAX_VALUE_LEN {
        return Err(SqlError::unsupported(
            "table definition this large (too many columns/indexes)",
        ));
    }
    tx.put(&c, &table_key(&t.name), &b)?;
    Ok(())
}

fn read_counter(tx: &mut Tx<'_>, key: &[u8], default: u64) -> Result<u64> {
    let c = catalog(tx)?;
    Ok(match tx.get(&c, key)? {
        Some(b) => u64::from_le_bytes(
            b.as_slice()
                .try_into()
                .map_err(|_| SqlError::corrupt("bad counter"))?,
        ),
        None => default,
    })
}

fn write_counter(tx: &mut Tx<'_>, key: &[u8], v: u64) -> Result<()> {
    let c = catalog(tx)?;
    tx.put(&c, key, &v.to_le_bytes())?;
    Ok(())
}

fn rowid_key(id: u64) -> Vec<u8> {
    let mut k = b"r\0".to_vec();
    k.extend_from_slice(&id.to_be_bytes());
    k
}

struct Trees {
    rows: Tree,
    ovf: Tree,
    idx: Vec<Tree>,
}

fn open_trees(tx: &mut Tx<'_>, t: &Table) -> Result<Trees> {
    let rows = tx.open_tree(&t.rows_tree())?;
    let ovf = tx.open_tree(&t.overflow_tree())?;
    let mut idx = Vec::with_capacity(t.indexes.len());
    for ix in &t.indexes {
        idx.push(tx.open_tree(&t.index_tree(ix))?);
    }
    Ok(Trees { rows, ovf, idx })
}

// ----- row storage ---------------------------------------------------------------------------

fn chunk_key(pk: &[u8], i: u32) -> Vec<u8> {
    let mut k = pk.to_vec();
    k.extend_from_slice(&i.to_be_bytes());
    k
}

fn stored_chunks(stored: &[u8]) -> Result<Option<(usize, u32)>> {
    match stored.first() {
        Some(0) => Ok(None),
        Some(1) if stored.len() == 9 => {
            let len = u32::from_le_bytes(
                stored[1..5]
                    .try_into()
                    .map_err(|_| SqlError::corrupt("overflow header"))?,
            ) as usize;
            let n = u32::from_le_bytes(
                stored[5..9]
                    .try_into()
                    .map_err(|_| SqlError::corrupt("overflow header"))?,
            );
            Ok(Some((len, n)))
        }
        _ => Err(SqlError::corrupt("row: bad storage header")),
    }
}

fn decode_stored(
    tx: &mut Tx<'_>,
    tr: &Trees,
    pk: &[u8],
    stored: &[u8],
    ncols: usize,
) -> Result<Vec<Value>> {
    match stored_chunks(stored)? {
        None => row_decode(&stored[1..], ncols),
        Some((len, n)) => {
            if len > MAX_ROW_BYTES || n as usize > MAX_ROW_BYTES / CHUNK + 1 {
                return Err(SqlError::corrupt("row: overflow too large"));
            }
            let mut buf = Vec::with_capacity(len);
            for i in 0..n {
                let c = tx
                    .get(&tr.ovf, &chunk_key(pk, i))?
                    .ok_or_else(|| SqlError::corrupt("row: overflow chunk missing"))?;
                buf.extend_from_slice(&c);
            }
            if buf.len() != len {
                return Err(SqlError::corrupt("row: overflow length mismatch"));
            }
            row_decode(&buf, ncols)
        }
    }
}

fn get_row(tx: &mut Tx<'_>, tr: &Trees, pk: &[u8], ncols: usize) -> Result<Option<Vec<Value>>> {
    match tx.get(&tr.rows, pk)? {
        Some(s) => decode_stored(tx, tr, pk, &s, ncols).map(Some),
        None => Ok(None),
    }
}

fn delete_chunks(tx: &mut Tx<'_>, tr: &Trees, pk: &[u8]) -> Result<()> {
    if let Some(old) = tx.get(&tr.rows, pk)?
        && let Some((_, n)) = stored_chunks(&old)?
    {
        for i in 0..n {
            tx.delete(&tr.ovf, &chunk_key(pk, i))?;
        }
    }
    Ok(())
}

fn put_row(tx: &mut Tx<'_>, tr: &Trees, pk: &[u8], row: &[Value]) -> Result<()> {
    let enc = row_encode(row)?;
    if enc.len() > MAX_ROW_BYTES {
        return Err(SqlError::row_too_big());
    }
    delete_chunks(tx, tr, pk)?;
    if enc.len() <= INLINE_MAX {
        let mut v = Vec::with_capacity(enc.len() + 1);
        v.push(0);
        v.extend_from_slice(&enc);
        tx.put(&tr.rows, pk, &v)?;
    } else {
        let mut n = 0u32;
        for (i, c) in enc.chunks(CHUNK).enumerate() {
            tx.put(&tr.ovf, &chunk_key(pk, i as u32), c)?;
            n += 1;
        }
        let mut h = vec![1u8];
        h.extend_from_slice(&(enc.len() as u32).to_le_bytes());
        h.extend_from_slice(&n.to_le_bytes());
        tx.put(&tr.rows, pk, &h)?;
    }
    Ok(())
}

fn del_row(tx: &mut Tx<'_>, tr: &Trees, pk: &[u8]) -> Result<()> {
    delete_chunks(tx, tr, pk)?;
    tx.delete(&tr.rows, pk)?;
    Ok(())
}

fn pk_key(t: &Table, row: &[Value]) -> Result<Vec<u8>> {
    let mut k = Vec::new();
    for &c in &t.pk {
        key_encode(&mut k, &row[c], t.cols[c].ty)?;
    }
    if k.len() > MAX_KEY_LEN - 4 {
        return Err(SqlError::key_too_long());
    }
    Ok(k)
}

fn hidden_key(rowid: u64) -> Result<Vec<u8>> {
    let mut k = Vec::new();
    key_encode(&mut k, &Value::Int(rowid as i64), ColType::BigInt)?;
    Ok(k)
}

/// (full index key, length of the indexed-columns prefix)
fn index_key(t: &Table, ix: &Index, row: &[Value], pk: &[u8]) -> Result<(Vec<u8>, usize)> {
    let mut k = Vec::new();
    for &c in &ix.cols {
        key_encode(&mut k, &row[c], t.cols[c].ty)?;
    }
    let pl = k.len();
    k.extend_from_slice(pk);
    if k.len() > MAX_KEY_LEN {
        return Err(SqlError::key_too_long());
    }
    Ok((k, pl))
}

fn render_key(cols: &[usize], row: &[Value]) -> String {
    cols.iter()
        .map(|&c| row[c].text().unwrap_or_else(|| "NULL".into()))
        .collect::<Vec<_>>()
        .join("-")
}

fn index_insert(tx: &mut Tx<'_>, t: &Table, tr: &Trees, row: &[Value], pk: &[u8]) -> Result<()> {
    for (i, ix) in t.indexes.iter().enumerate() {
        let (k, pl) = index_key(t, ix, row, pk)?;
        if ix.unique && ix.cols.iter().all(|&c| !row[c].is_null()) {
            let prefix = k[..pl].to_vec();
            let hi = prefix_end(&prefix).map_or(Bound::Unbounded, Bound::Excluded);
            let clash = tx
                .range(
                    &tr.idx[i],
                    (
                        Bound::Included(prefix.as_slice()),
                        hi.as_ref().map(Vec::as_slice),
                    ),
                )?
                .next()
                .transpose()?
                .is_some_and(|(_, other_pk)| other_pk != pk);
            if clash {
                return Err(SqlError::dup_entry(&render_key(&ix.cols, row), &ix.name));
            }
        }
        tx.put(&tr.idx[i], &k, pk)?;
    }
    Ok(())
}

fn index_delete(tx: &mut Tx<'_>, t: &Table, tr: &Trees, row: &[Value], pk: &[u8]) -> Result<()> {
    for (i, ix) in t.indexes.iter().enumerate() {
        let (k, _) = index_key(t, ix, row, pk)?;
        tx.delete(&tr.idx[i], &k)?;
    }
    Ok(())
}

/// Collect up to `n` entries of `tree` within (`lo`, `hi`).
fn batch(
    tx: &mut Tx<'_>,
    tree: &Tree,
    lo: &Bound<Vec<u8>>,
    hi: &Bound<Vec<u8>>,
    n: usize,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let b = (
        lo.as_ref().map(Vec::as_slice),
        hi.as_ref().map(Vec::as_slice),
    );
    if let (Bound::Included(l) | Bound::Excluded(l), Bound::Included(h) | Bound::Excluded(h)) = b
        && l > h
    {
        return Ok(Vec::new());
    }
    Ok(tx.range(tree, b)?.take(n).collect::<Result<Vec<_>, _>>()?)
}

// ----- expressions ---------------------------------------------------------------------------

struct Env<'a> {
    t: Option<&'a Table>,
    row: &'a [Value],
    now: i64,
}

fn check_cols(e: &Expr, t: Option<&Table>) -> Result<()> {
    let mut cols = Vec::new();
    e.columns(&mut cols);
    for c in cols {
        if t.and_then(|t| t.col(c)).is_none() {
            return Err(SqlError::bad_column(c));
        }
    }
    Ok(())
}

fn tv(b: Option<bool>) -> Value {
    b.map_or(Value::Null, Value::bool)
}

fn eval(e: &Expr, env: &Env<'_>) -> Result<Value> {
    Ok(match e {
        Expr::Lit(v) => v.clone(),
        Expr::Col(c) => {
            let i = env
                .t
                .and_then(|t| t.col(c))
                .ok_or_else(|| SqlError::bad_column(c))?;
            env.row.get(i).cloned().unwrap_or(Value::Null)
        }
        Expr::Unary { op: UnOp::Not, e } => tv(eval(e, env)?.truth().map(|b| !b)),
        Expr::Unary { op: UnOp::Neg, e } => arith(ArithOp::Sub, &Value::Int(0), &eval(e, env)?)?,
        Expr::Binary { op, l, r } => {
            match op {
                BinOp::And => {
                    let a = eval(l, env)?.truth();
                    if a == Some(false) {
                        return Ok(Value::Int(0));
                    }
                    let b = eval(r, env)?.truth();
                    return Ok(match (a, b) {
                        (_, Some(false)) => Value::Int(0),
                        (Some(true), Some(true)) => Value::Int(1),
                        _ => Value::Null,
                    });
                }
                BinOp::Or => {
                    let a = eval(l, env)?.truth();
                    if a == Some(true) {
                        return Ok(Value::Int(1));
                    }
                    let b = eval(r, env)?.truth();
                    return Ok(match (a, b) {
                        (_, Some(true)) => Value::Int(1),
                        (Some(false), Some(false)) => Value::Int(0),
                        _ => Value::Null,
                    });
                }
                _ => {}
            }
            let a = eval(l, env)?;
            let b = eval(r, env)?;
            match op {
                BinOp::Xor => tv(match (a.truth(), b.truth()) {
                    (Some(x), Some(y)) => Some(x ^ y),
                    _ => None,
                }),
                BinOp::Eq => tv(compare(&a, &b).map(|o| o == Ordering::Equal)),
                BinOp::Ne => tv(compare(&a, &b).map(|o| o != Ordering::Equal)),
                BinOp::Lt => tv(compare(&a, &b).map(|o| o == Ordering::Less)),
                BinOp::Le => tv(compare(&a, &b).map(|o| o != Ordering::Greater)),
                BinOp::Gt => tv(compare(&a, &b).map(|o| o == Ordering::Greater)),
                BinOp::Ge => tv(compare(&a, &b).map(|o| o != Ordering::Less)),
                BinOp::NullSafeEq => Value::bool(match (a.is_null(), b.is_null()) {
                    (true, true) => true,
                    (false, false) => compare(&a, &b) == Some(Ordering::Equal),
                    _ => false,
                }),
                BinOp::Add => arith(ArithOp::Add, &a, &b)?,
                BinOp::Sub => arith(ArithOp::Sub, &a, &b)?,
                BinOp::Mul => arith(ArithOp::Mul, &a, &b)?,
                BinOp::Div => arith(ArithOp::Div, &a, &b)?,
                BinOp::IntDiv => arith(ArithOp::IntDiv, &a, &b)?,
                BinOp::Mod => arith(ArithOp::Mod, &a, &b)?,
                BinOp::And | BinOp::Or => Value::Null,
            }
        }
        Expr::IsNull { e, neg } => Value::bool(eval(e, env)?.is_null() != *neg),
        Expr::InList { e, list, neg } => {
            let v = eval(e, env)?;
            if v.is_null() {
                return Ok(Value::Null);
            }
            let mut saw_null = false;
            let mut hit = false;
            for x in list {
                match compare(&v, &eval(x, env)?) {
                    Some(Ordering::Equal) => {
                        hit = true;
                        break;
                    }
                    None => saw_null = true,
                    _ => {}
                }
            }
            if hit {
                Value::bool(!neg)
            } else if saw_null {
                Value::Null
            } else {
                Value::bool(*neg)
            }
        }
        Expr::Between { e, lo, hi, neg } => {
            let v = eval(e, env)?;
            let a = compare(&v, &eval(lo, env)?).map(|o| o != Ordering::Less);
            let b = compare(&v, &eval(hi, env)?).map(|o| o != Ordering::Greater);
            let r = match (a, b) {
                (Some(false), _) | (_, Some(false)) => Some(false),
                (Some(true), Some(true)) => Some(true),
                _ => None,
            };
            tv(if *neg { r.map(|x| !x) } else { r })
        }
        Expr::Like { e, pat, neg } => {
            let (v, p) = (eval(e, env)?, eval(pat, env)?);
            match (v.text(), p.text()) {
                (Some(v), Some(p)) => Value::bool(like(&v, &p) != *neg),
                _ => Value::Null,
            }
        }
        Expr::Func { name, args } => func(name, args, env)?,
    })
}

fn func(name: &str, args: &[Expr], env: &Env<'_>) -> Result<Value> {
    let n = args.len();
    let arg = |i: usize| -> Result<Value> { args.get(i).map_or(Ok(Value::Null), |a| eval(a, env)) };
    let need = |ok: bool| {
        if ok {
            Ok(())
        } else {
            Err(SqlError::wrong_func(name))
        }
    };
    Ok(match name {
        "now" | "current_timestamp" | "localtimestamp" | "sysdate" => {
            need(n <= 1)?;
            let fsp = match arg(0)? {
                Value::Null => 0,
                v => v
                    .to_num()
                    .map_or(0, |(x, s)| crate::value::rescale(x, s, 0).unwrap_or(0))
                    .clamp(0, 6) as u8,
            };
            Value::DateTime(trunc_fsp(env.now, fsp))
        }
        "lower" | "lcase" | "upper" | "ucase" => {
            need(n == 1)?;
            let up = name.starts_with('u');
            match arg(0)? {
                Value::Null => Value::Null,
                Value::Bytes(b) => Value::Bytes(if up {
                    b.to_ascii_uppercase()
                } else {
                    b.to_ascii_lowercase()
                }),
                v => {
                    let s = v.text().unwrap_or_default();
                    Value::Str(if up {
                        s.to_uppercase()
                    } else {
                        s.to_lowercase()
                    })
                }
            }
        }
        "length" | "octet_length" => {
            need(n == 1)?;
            match arg(0)? {
                Value::Null => Value::Null,
                Value::Bytes(b) => Value::Int(b.len() as i64),
                v => Value::Int(v.text().unwrap_or_default().len() as i64),
            }
        }
        "char_length" | "character_length" => {
            need(n == 1)?;
            match arg(0)? {
                Value::Null => Value::Null,
                Value::Bytes(b) => Value::Int(b.len() as i64),
                v => Value::Int(v.text().unwrap_or_default().chars().count() as i64),
            }
        }
        "concat" => {
            need(n >= 1)?;
            let mut bin = false;
            let mut out: Vec<u8> = Vec::new();
            for i in 0..n {
                let v = arg(i)?;
                match v {
                    Value::Null => return Ok(Value::Null),
                    Value::Bytes(b) => {
                        bin = true;
                        out.extend_from_slice(&b);
                    }
                    v => out.extend_from_slice(v.text().unwrap_or_default().as_bytes()),
                }
                if out.len() > crate::MAX_STATEMENT_BYTES {
                    return Err(SqlError::resource("CONCAT result too large"));
                }
            }
            if bin {
                Value::Bytes(out)
            } else {
                Value::Str(String::from_utf8_lossy(&out).into_owned())
            }
        }
        "coalesce" => {
            need(n >= 1)?;
            for i in 0..n {
                let v = arg(i)?;
                if !v.is_null() {
                    return Ok(v);
                }
            }
            Value::Null
        }
        "ifnull" => {
            need(n == 2)?;
            let a = arg(0)?;
            if a.is_null() { arg(1)? } else { a }
        }
        "nullif" => {
            need(n == 2)?;
            let (a, b) = (arg(0)?, arg(1)?);
            if compare(&a, &b) == Some(Ordering::Equal) {
                Value::Null
            } else {
                a
            }
        }
        "if" => {
            need(n == 3)?;
            if arg(0)?.truth() == Some(true) {
                arg(1)?
            } else {
                arg(2)?
            }
        }
        "abs" => {
            need(n == 1)?;
            let v = arg(0)?;
            match v.to_num() {
                None => Value::Null,
                Some((x, _)) if x < 0 => arith(ArithOp::Sub, &Value::Int(0), &v)?,
                Some(_) => match v {
                    Value::Int(_) | Value::Dec { .. } => v,
                    other => {
                        let (x, s) = other.to_num().unwrap_or((0, 0));
                        if s == 0 {
                            i64::try_from(x)
                                .map(Value::Int)
                                .unwrap_or(Value::Dec { v: x, s })
                        } else {
                            Value::Dec { v: x, s }
                        }
                    }
                },
            }
        }
        "round" => {
            need(n == 1 || n == 2)?;
            let v = arg(0)?;
            let d = if n == 2 {
                match arg(1)?.to_num() {
                    None => return Ok(Value::Null),
                    Some((x, s)) => {
                        crate::value::rescale(x, s, 0).unwrap_or(0).clamp(-38, 30) as i32
                    }
                }
            } else {
                0
            };
            let Some((x, s)) = v.to_num() else {
                return Ok(Value::Null);
            };
            let oor = || SqlError::value_out_of_range("round");
            if d >= 0 {
                let d = d as u8;
                if d >= s {
                    return Ok(match v {
                        Value::Int(_) | Value::Dec { .. } => v,
                        _ => Value::Dec { v: x, s },
                    });
                }
                let r = crate::value::rescale(x, s, d).ok_or_else(oor)?;
                if d == 0 {
                    i64::try_from(r)
                        .map(Value::Int)
                        .unwrap_or(Value::Dec { v: r, s: 0 })
                } else {
                    Value::Dec { v: r, s: d }
                }
            } else {
                let whole = crate::value::rescale(x, s, 0).ok_or_else(oor)?;
                let p = crate::value::pow10((-d) as u8).ok_or_else(oor)?;
                let q = crate::value::rescale(whole, (-d) as u8, 0).ok_or_else(oor)?;
                let r = q.checked_mul(p).ok_or_else(oor)?;
                i64::try_from(r)
                    .map(Value::Int)
                    .unwrap_or(Value::Dec { v: r, s: 0 })
            }
        }
        "substring" | "substr" => {
            need(n == 2 || n == 3)?;
            let s = arg(0)?;
            let Some(text) = s.text() else {
                return Ok(Value::Null);
            };
            let Some((p, ps)) = arg(1)?.to_num() else {
                return Ok(Value::Null);
            };
            let p = crate::value::rescale(p, ps, 0).unwrap_or(0);
            let chars: Vec<char> = text.chars().collect();
            let len = chars.len() as i128;
            let start = if p > 0 {
                p - 1
            } else if p < 0 {
                len + p
            } else {
                return Ok(Value::Str(String::new()));
            };
            if start < 0 || start >= len {
                return Ok(Value::Str(String::new()));
            }
            let take = if n == 3 {
                match arg(2)?.to_num() {
                    None => return Ok(Value::Null),
                    Some((l, ls)) => crate::value::rescale(l, ls, 0).unwrap_or(0).max(0),
                }
            } else {
                len
            };
            let end = (start + take).min(len);
            Value::Str(chars[start as usize..end as usize].iter().collect())
        }
        "__is_true" => Value::bool(arg(0)?.truth() == Some(true)),
        "__is_false" => Value::bool(arg(0)?.truth() == Some(false)),
        "version" => {
            need(n == 0)?;
            Value::Str(concat!("8.0.0-NovaDB-", env!("CARGO_PKG_VERSION")).into())
        }
        "database" | "schema" => {
            need(n == 0)?;
            Value::Str("novadb".into())
        }
        _ => return Err(SqlError::wrong_func(name)),
    })
}

/// Current time cut to `fsp` fractional digits (NOW(), DEFAULT CURRENT_TIMESTAMP).
fn trunc_fsp(now: i64, fsp: u8) -> i64 {
    now - now.rem_euclid(10i64.pow(u32::from(6 - fsp.min(6))))
}

fn matches(filter: Option<&Expr>, env: &Env<'_>) -> Result<bool> {
    match filter {
        None => Ok(true),
        Some(f) => Ok(eval(f, env)?.truth() == Some(true)),
    }
}

// ----- planner -------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Access {
    Full,
    /// Primary-key range (point when lo == hi on the full key).
    Pk {
        lo: Bound<Vec<u8>>,
        hi: Bound<Vec<u8>>,
        point: bool,
    },
    /// Secondary index range; entries map to primary keys.
    Idx {
        ix: usize,
        lo: Bound<Vec<u8>>,
        hi: Bound<Vec<u8>>,
        point: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Op {
    Eq,
    Lt,
    Le,
    Gt,
    Ge,
}

fn conjuncts<'a>(e: &'a Expr, out: &mut Vec<&'a Expr>) {
    match e {
        Expr::Binary {
            op: BinOp::And,
            l,
            r,
        } => {
            conjuncts(l, out);
            conjuncts(r, out);
        }
        other => out.push(other),
    }
}

fn is_const(e: &Expr) -> bool {
    let mut c = Vec::new();
    e.columns(&mut c);
    c.is_empty()
}

/// A literal is usable as an index bound only if it converts to the column type without
/// changing value and compares the same way the WHERE clause will (so no rows are missed).
fn key_value(t: &Table, col: usize, lit: &Value) -> Option<Value> {
    let ty = t.cols[col].ty;
    let family_ok = match lit {
        Value::Int(_) | Value::Dec { .. } => ty.is_numeric(),
        Value::Str(_) => matches!(ty, ColType::Varchar(_) | ColType::DateTime(_)),
        Value::DateTime(_) => matches!(ty, ColType::DateTime(_)),
        _ => false,
    };
    if !family_ok || ty.is_lob() {
        return None;
    }
    let c = coerce(lit.clone(), ty, "").ok()?;
    (compare(&c, lit) == Some(Ordering::Equal)).then_some(c)
}

fn simple_preds(t: &Table, filter: &Expr, now: i64) -> Vec<(usize, Op, Value)> {
    let mut cs = Vec::new();
    conjuncts(filter, &mut cs);
    let mut out = Vec::new();
    let env = Env {
        t: None,
        row: &[],
        now,
    };
    let lit = |e: &Expr| -> Option<Value> {
        if is_const(e) {
            eval(e, &env).ok()
        } else {
            None
        }
    };
    for c in cs {
        match c {
            Expr::Binary { op, l, r } => {
                let op = match op {
                    BinOp::Eq => Op::Eq,
                    BinOp::Lt => Op::Lt,
                    BinOp::Le => Op::Le,
                    BinOp::Gt => Op::Gt,
                    BinOp::Ge => Op::Ge,
                    _ => continue,
                };
                let (col, v, op) = match (&**l, &**r) {
                    (Expr::Col(n), e) => match (t.col(n), lit(e)) {
                        (Some(c), Some(v)) => (c, v, op),
                        _ => continue,
                    },
                    (e, Expr::Col(n)) => match (t.col(n), lit(e)) {
                        (Some(c), Some(v)) => (
                            c,
                            v,
                            match op {
                                Op::Lt => Op::Gt,
                                Op::Le => Op::Ge,
                                Op::Gt => Op::Lt,
                                Op::Ge => Op::Le,
                                Op::Eq => Op::Eq,
                            },
                        ),
                        _ => continue,
                    },
                    _ => continue,
                };
                if let Some(kv) = key_value(t, col, &v) {
                    out.push((col, op, kv));
                }
            }
            Expr::Between {
                e,
                lo,
                hi,
                neg: false,
            } => {
                if let Expr::Col(n) = &**e
                    && let Some(col) = t.col(n)
                {
                    if let Some(v) = lit(lo).and_then(|v| key_value(t, col, &v)) {
                        out.push((col, Op::Ge, v));
                    }
                    if let Some(v) = lit(hi).and_then(|v| key_value(t, col, &v)) {
                        out.push((col, Op::Le, v));
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn enc1(t: &Table, col: usize, v: &Value) -> Option<Vec<u8>> {
    let mut k = Vec::new();
    key_encode(&mut k, v, t.cols[col].ty).ok()?;
    Some(k)
}

/// (lower bound, upper bound, is an equality prefix)
type KeyRange = (Bound<Vec<u8>>, Bound<Vec<u8>>, bool);

/// Bounds on keys whose first component is column `col`, given `preds`.
fn first_col_bounds(t: &Table, col: usize, preds: &[(usize, Op, Value)]) -> Option<KeyRange> {
    let mine: Vec<&(usize, Op, Value)> = preds.iter().filter(|p| p.0 == col).collect();
    if let Some((_, _, v)) = mine.iter().find(|p| p.1 == Op::Eq) {
        let p = enc1(t, col, v)?;
        let hi = prefix_end(&p).map_or(Bound::Unbounded, Bound::Excluded);
        return Some((Bound::Included(p), hi, true));
    }
    let mut lo = Bound::Unbounded;
    let mut hi = Bound::Unbounded;
    for (_, op, v) in &mine {
        let k = enc1(t, col, v)?;
        match op {
            Op::Ge if lo == Bound::Unbounded => lo = Bound::Included(k),
            Op::Gt if lo == Bound::Unbounded => {
                lo =
                    prefix_end(&k).map_or(Bound::Excluded(vec![0xFF; MAX_KEY_LEN]), Bound::Included)
            }
            Op::Le if hi == Bound::Unbounded => {
                hi = prefix_end(&k).map_or(Bound::Unbounded, Bound::Excluded)
            }
            Op::Lt if hi == Bound::Unbounded => hi = Bound::Excluded(k),
            _ => {}
        }
    }
    if lo == Bound::Unbounded && hi == Bound::Unbounded {
        return None;
    }
    // Exclude NULLs (encoded as 0x00) from upper-only ranges: comparisons never match NULL.
    if lo == Bound::Unbounded {
        lo = Bound::Included(vec![0x01]);
    }
    Some((lo, hi, false))
}

fn plan(t: &Table, filter: Option<&Expr>, now: i64) -> Access {
    let Some(f) = filter else { return Access::Full };
    let preds = simple_preds(t, f, now);
    if preds.is_empty() {
        return Access::Full;
    }
    let eq = |c: usize| {
        preds
            .iter()
            .find(|p| p.0 == c && p.1 == Op::Eq)
            .map(|p| &p.2)
    };
    // 1. full primary key equality
    if !t.pk.is_empty() && t.pk.iter().all(|&c| eq(c).is_some()) {
        let mut k = Vec::new();
        let ok =
            t.pk.iter()
                .all(|&c| eq(c).is_some_and(|v| key_encode(&mut k, v, t.cols[c].ty).is_ok()));
        if ok {
            return Access::Pk {
                lo: Bound::Included(k.clone()),
                hi: Bound::Included(k),
                point: true,
            };
        }
    }
    // 2. unique index with full equality
    for (i, ix) in t.indexes.iter().enumerate() {
        if ix.unique && ix.cols.iter().all(|&c| eq(c).is_some()) {
            let mut k = Vec::new();
            if ix
                .cols
                .iter()
                .all(|&c| eq(c).is_some_and(|v| key_encode(&mut k, v, t.cols[c].ty).is_ok()))
            {
                let hi = prefix_end(&k).map_or(Bound::Unbounded, Bound::Excluded);
                return Access::Idx {
                    ix: i,
                    lo: Bound::Included(k),
                    hi,
                    point: true,
                };
            }
        }
    }
    // 3. primary key prefix / range on its first column
    if let Some(&c0) = t.pk.first()
        && let Some((lo, hi, _)) = first_col_bounds(t, c0, &preds)
    {
        return Access::Pk {
            lo,
            hi,
            point: false,
        };
    }
    // 4. any index: full equality prefix, else range on its first column
    for (i, ix) in t.indexes.iter().enumerate() {
        let mut k = Vec::new();
        let mut n = 0;
        for &c in &ix.cols {
            match eq(c) {
                Some(v) if key_encode(&mut k, v, t.cols[c].ty).is_ok() => n += 1,
                _ => break,
            }
        }
        if n > 0 {
            let hi = prefix_end(&k).map_or(Bound::Unbounded, Bound::Excluded);
            return Access::Idx {
                ix: i,
                lo: Bound::Included(k),
                hi,
                point: true,
            };
        }
    }
    for (i, ix) in t.indexes.iter().enumerate() {
        if let Some(&c0) = ix.cols.first()
            && let Some((lo, hi, _)) = first_col_bounds(t, c0, &preds)
        {
            return Access::Idx {
                ix: i,
                lo,
                hi,
                point: false,
            };
        }
    }
    Access::Full
}

/// Visit matching rows in access order; `visit` returns false to stop early.
fn scan(
    tx: &mut Tx<'_>,
    t: &Table,
    tr: &Trees,
    access: &Access,
    filter: Option<&Expr>,
    now: i64,
    mut visit: impl FnMut(Vec<u8>, Vec<Value>) -> Result<bool>,
) -> Result<()> {
    let ncols = t.cols.len();
    let test = |row: &[Value]| {
        matches(
            filter,
            &Env {
                t: Some(t),
                row,
                now,
            },
        )
    };
    match access {
        Access::Full | Access::Pk { .. } => {
            let (mut lo, hi) = match access {
                Access::Pk { lo, hi, .. } => (lo.clone(), hi.clone()),
                _ => (Bound::Unbounded, Bound::Unbounded),
            };
            loop {
                let b = batch(tx, &tr.rows, &lo, &hi, SCAN_BATCH)?;
                let Some((last, _)) = b.last() else { break };
                lo = Bound::Excluded(last.clone());
                for (k, stored) in b {
                    let row = decode_stored(tx, tr, &k, &stored, ncols)?;
                    if test(&row)? && !visit(k, row)? {
                        return Ok(());
                    }
                }
            }
        }
        Access::Idx { ix, lo, hi, .. } => {
            let tree = tr
                .idx
                .get(*ix)
                .ok_or_else(|| SqlError::internal("index handle"))?;
            let mut lo = lo.clone();
            loop {
                let b = batch(tx, tree, &lo, hi, SCAN_BATCH)?;
                let Some((last, _)) = b.last() else { break };
                lo = Bound::Excluded(last.clone());
                for (_, pk) in b {
                    let row = get_row(tx, tr, &pk, ncols)?
                        .ok_or_else(|| SqlError::corrupt("index entry points to a missing row"))?;
                    if test(&row)? && !visit(pk, row)? {
                        return Ok(());
                    }
                }
            }
        }
    }
    Ok(())
}

fn access_desc(t: &Table, a: &Access) -> (&'static str, Option<String>) {
    match a {
        Access::Full => ("ALL", None),
        Access::Pk { point: true, .. } => ("const", Some("PRIMARY".into())),
        Access::Pk { .. } => ("range", Some("PRIMARY".into())),
        Access::Idx { ix, point, .. } => {
            let index = t.indexes.get(*ix);
            let kind = match (point, index.is_some_and(|i| i.unique)) {
                (true, true) => "const",
                (true, false) => "ref",
                _ => "range",
            };
            (kind, index.map(|i| i.name.clone()))
        }
    }
}

// ----- DDL -----------------------------------------------------------------------------------

fn valid_name(n: &str) -> Result<()> {
    if n.is_empty() || n.chars().count() > crate::parser::MAX_IDENT {
        return Err(SqlError::bad_ident(n));
    }
    Ok(())
}

fn col_pos(cols: &[Column], n: &str) -> Result<usize> {
    cols.iter()
        .position(|x| x.name.eq_ignore_ascii_case(n))
        .ok_or_else(|| SqlError::bad_column(n))
}

fn create_table(tx: &mut Tx<'_>, c: &CreateTable) -> Result<QueryResult> {
    valid_name(&c.name)?;
    if find_table(tx, &c.name)?.is_some() {
        if c.if_not_exists {
            return Ok(QueryResult {
                info: Some(format!("Table '{}' already exists", c.name)),
                ..Default::default()
            });
        }
        return Err(SqlError::table_exists(&c.name));
    }
    if c.cols.is_empty() || c.cols.len() > MAX_COLUMNS {
        return Err(SqlError::unsupported(
            "tables without columns or with more than 1024 columns",
        ));
    }
    let mut cols: Vec<Column> = Vec::with_capacity(c.cols.len());
    let mut seen = HashSet::new();
    for d in &c.cols {
        valid_name(&d.name)?;
        if !seen.insert(d.name.to_lowercase()) {
            return Err(SqlError::dup_column(&d.name));
        }
        let default = match &d.default {
            None => None,
            Some(DefaultExpr::Now) if matches!(d.ty, ColType::DateTime(_)) => {
                Some(DefaultExpr::Now)
            }
            Some(DefaultExpr::Now) => return Err(SqlError::invalid_default(&d.name)),
            Some(DefaultExpr::Value(Value::Null)) if !d.nullable || d.primary => {
                return Err(SqlError::invalid_default(&d.name));
            }
            Some(DefaultExpr::Value(v)) if d.ty.is_lob() && !v.is_null() => {
                return Err(SqlError::invalid_default(&d.name));
            }
            Some(DefaultExpr::Value(v)) => Some(DefaultExpr::Value(
                coerce(v.clone(), d.ty, &d.name).map_err(|_| SqlError::invalid_default(&d.name))?,
            )),
        };
        if d.auto_inc && !matches!(d.ty, ColType::Int | ColType::BigInt) {
            return Err(SqlError::auto_inc());
        }
        cols.push(Column {
            name: d.name.clone(),
            ty: d.ty,
            nullable: d.nullable,
            default,
            auto_inc: d.auto_inc,
        });
    }
    // primary key
    let col_pk: Vec<usize> = c
        .cols
        .iter()
        .enumerate()
        .filter(|(_, d)| d.primary)
        .map(|(i, _)| i)
        .collect();
    let pk: Vec<usize> = match (&c.pk, col_pk.len()) {
        (Some(_), n) if n > 0 => return Err(SqlError::multiple_pk()),
        (_, n) if n > 1 => return Err(SqlError::multiple_pk()),
        (Some(names), _) => names
            .iter()
            .map(|n| col_pos(&cols, n))
            .collect::<Result<_>>()?,
        (None, _) => col_pk,
    };
    if pk.iter().collect::<HashSet<_>>().len() != pk.len() {
        return Err(SqlError::dup_column("primary key"));
    }
    for &p in &pk {
        if cols[p].ty.is_lob() {
            return Err(SqlError::blob_key(&cols[p].name));
        }
        cols[p].nullable = false;
    }
    // indexes
    let mut indexes: Vec<Index> = Vec::new();
    let mut next_index_id = 1u32;
    let mut defs: Vec<IndexDef> = c
        .cols
        .iter()
        .filter(|d| d.unique)
        .map(|d| IndexDef {
            name: Some(d.name.clone()),
            cols: vec![d.name.clone()],
            unique: true,
        })
        .collect();
    defs.extend(c.indexes.iter().cloned());
    for d in defs {
        let ic: Vec<usize> = d
            .cols
            .iter()
            .map(|n| col_pos(&cols, n))
            .collect::<Result<_>>()?;
        if ic.iter().collect::<HashSet<_>>().len() != ic.len() {
            return Err(SqlError::dup_column(&d.cols.join(",")));
        }
        for &x in &ic {
            if cols[x].ty.is_lob() {
                return Err(SqlError::blob_key(&cols[x].name));
            }
        }
        let name = match d.name {
            Some(n) => n,
            None => {
                let base = cols[ic[0]].name.clone();
                let mut n = base.clone();
                let mut k = 2;
                while indexes.iter().any(|i| i.name.eq_ignore_ascii_case(&n)) {
                    n = format!("{base}_{k}");
                    k += 1;
                }
                n
            }
        };
        valid_name(&name)?;
        if name.eq_ignore_ascii_case("primary")
            || indexes.iter().any(|i| i.name.eq_ignore_ascii_case(&name))
        {
            return Err(SqlError::dup_key_name(&name));
        }
        indexes.push(Index {
            id: next_index_id,
            name,
            cols: ic,
            unique: d.unique,
        });
        next_index_id += 1;
    }
    if indexes.len() > MAX_INDEXES {
        return Err(SqlError::unsupported("more than 64 indexes"));
    }
    // AUTO_INCREMENT: at most one, and it must lead a key.
    let ai: Vec<usize> = cols
        .iter()
        .enumerate()
        .filter(|(_, x)| x.auto_inc)
        .map(|(i, _)| i)
        .collect();
    if ai.len() > 1 {
        return Err(SqlError::auto_inc());
    }
    if let Some(&a) = ai.first()
        && pk.first() != Some(&a)
        && !indexes.iter().any(|i| i.cols.first() == Some(&a))
    {
        return Err(SqlError::auto_inc());
    }
    let id = read_counter(tx, b"n", 1)?;
    write_counter(tx, b"n", id + 1)?;
    let t = Table {
        id,
        name: c.name.clone(),
        cols,
        pk,
        indexes,
        next_index_id,
    };
    tx.create_tree(&t.rows_tree())?;
    tx.create_tree(&t.overflow_tree())?;
    for ix in &t.indexes {
        tx.create_tree(&t.index_tree(ix))?;
    }
    save_table(tx, &t)?;
    Ok(QueryResult::ok(0))
}

fn drop_table(tx: &mut Tx<'_>, names: &[String], if_exists: bool) -> Result<QueryResult> {
    let mut missing = Vec::new();
    for n in names {
        match find_table(tx, n)? {
            None => missing.push(n.clone()),
            Some(t) => {
                tx.drop_tree(&t.rows_tree())?;
                tx.drop_tree(&t.overflow_tree())?;
                for ix in &t.indexes {
                    tx.drop_tree(&t.index_tree(ix))?;
                }
                let c = catalog(tx)?;
                tx.delete(&c, &table_key(&t.name))?;
                tx.delete(&c, &counter_key(t.id))?;
                tx.delete(&c, &rowid_key(t.id))?;
            }
        }
    }
    if !missing.is_empty() && !if_exists {
        return Err(SqlError::new_unknown_tables(&missing));
    }
    Ok(QueryResult::ok(0))
}

fn create_index(
    tx: &mut Tx<'_>,
    name: &str,
    table: &str,
    cols: &[String],
    unique: bool,
) -> Result<QueryResult> {
    valid_name(name)?;
    let mut t = load_table(tx, table)?;
    if name.eq_ignore_ascii_case("primary")
        || t.indexes.iter().any(|i| i.name.eq_ignore_ascii_case(name))
    {
        return Err(SqlError::dup_key_name(name));
    }
    if t.indexes.len() >= MAX_INDEXES {
        return Err(SqlError::unsupported("more than 64 indexes"));
    }
    let ic: Vec<usize> = cols
        .iter()
        .map(|n| t.col(n).ok_or_else(|| SqlError::bad_column(n)))
        .collect::<Result<_>>()?;
    if ic.iter().collect::<HashSet<_>>().len() != ic.len() {
        return Err(SqlError::dup_column(&cols.join(",")));
    }
    for &x in &ic {
        if t.cols[x].ty.is_lob() {
            return Err(SqlError::blob_key(&t.cols[x].name));
        }
    }
    let ix = Index {
        id: t.next_index_id,
        name: name.to_string(),
        cols: ic,
        unique,
    };
    t.next_index_id += 1;
    let tree_name = t.index_tree(&ix);
    let itree = tx.create_tree(&tree_name)?;
    // Build from existing rows (unique violations abort the whole statement).
    let base = open_trees(tx, &t)?;
    let one = Table {
        indexes: vec![ix.clone()],
        ..t.clone()
    };
    let tr = Trees {
        rows: base.rows,
        ovf: base.ovf,
        idx: vec![itree],
    };
    let mut rows = Vec::new();
    scan(tx, &t, &tr, &Access::Full, None, 0, |pk, row| {
        rows.push((pk, row));
        if rows.len() > MAX_ROWS_IN_MEMORY {
            return Err(SqlError::resource(
                "table too large to index in one statement",
            ));
        }
        Ok(true)
    })?;
    for (pk, row) in &rows {
        index_insert(tx, &one, &tr, row, pk)?;
    }
    t.indexes.push(ix);
    save_table(tx, &t)?;
    Ok(QueryResult::ok(0))
}

fn drop_index(tx: &mut Tx<'_>, name: &str, table: &str) -> Result<QueryResult> {
    let mut t = load_table(tx, table)?;
    let Some(pos) = t
        .indexes
        .iter()
        .position(|i| i.name.eq_ignore_ascii_case(name))
    else {
        return Err(SqlError::no_key(name));
    };
    let ix = t.indexes.remove(pos);
    if let Some(a) = t.auto_inc_col()
        && t.pk.first() != Some(&a)
        && !t.indexes.iter().any(|i| i.cols.first() == Some(&a))
    {
        return Err(SqlError::auto_inc());
    }
    tx.drop_tree(&t.index_tree(&ix))?;
    save_table(tx, &t)?;
    Ok(QueryResult::ok(0))
}

// ----- DML -----------------------------------------------------------------------------------

/// Store `row` as a new row (PK / unique checks, indexes). Returns the primary key.
fn insert_row(tx: &mut Tx<'_>, t: &Table, tr: &Trees, row: &[Value]) -> Result<Vec<u8>> {
    let pk = if t.pk.is_empty() {
        let id = read_counter(tx, &rowid_key(t.id), 1)?;
        write_counter(tx, &rowid_key(t.id), id + 1)?;
        hidden_key(id)?
    } else {
        let k = pk_key(t, row)?;
        if tx.get(&tr.rows, &k)?.is_some() {
            return Err(SqlError::dup_entry(&render_key(&t.pk, row), "PRIMARY"));
        }
        k
    };
    index_insert(tx, t, tr, row, &pk)?;
    put_row(tx, tr, &pk, row)?;
    Ok(pk)
}

fn finish_row(t: &Table, row: &mut [Value]) -> Result<()> {
    for (i, c) in t.cols.iter().enumerate() {
        if row[i].is_null() && !c.nullable {
            return Err(SqlError::not_null(&c.name));
        }
    }
    Ok(())
}

fn insert(
    tx: &mut Tx<'_>,
    table: &str,
    cols: Option<&[String]>,
    rows: &[Vec<Expr>],
    now: i64,
) -> Result<QueryResult> {
    let t = load_table(tx, table)?;
    let tr = open_trees(tx, &t)?;
    let targets: Vec<usize> = match cols {
        None => (0..t.cols.len()).collect(),
        Some(names) => {
            let mut v = Vec::with_capacity(names.len());
            for n in names {
                let c = t.col(n).ok_or_else(|| SqlError::bad_column(n))?;
                if v.contains(&c) {
                    return Err(SqlError::dup_column(n));
                }
                v.push(c);
            }
            v
        }
    };
    let ai = t.auto_inc_col();
    let mut counter = match ai {
        Some(_) => Some(read_counter(tx, &counter_key(t.id), 1)?),
        None => None,
    };
    let mut first_id = 0u64;
    let mut n = 0u64;
    let env = Env {
        t: None,
        row: &[],
        now,
    };
    for exprs in rows {
        if exprs.len() != targets.len() {
            return Err(SqlError::column_count());
        }
        let mut row = vec![Value::Null; t.cols.len()];
        let mut given = vec![false; t.cols.len()];
        for (e, &c) in exprs.iter().zip(&targets) {
            let v = eval(e, &env)?;
            row[c] = coerce(v, t.cols[c].ty, &t.cols[c].name)?;
            given[c] = true;
        }
        for (i, c) in t.cols.iter().enumerate() {
            if given[i] || c.auto_inc {
                continue;
            }
            row[i] = match &c.default {
                Some(DefaultExpr::Value(v)) => v.clone(),
                Some(DefaultExpr::Now) => Value::DateTime(trunc_fsp(
                    now,
                    match c.ty {
                        ColType::DateTime(f) => f,
                        _ => 0,
                    },
                )),
                None if c.nullable => Value::Null,
                None => return Err(SqlError::no_default(&c.name)),
            };
        }
        if let (Some(a), Some(ctr)) = (ai, counter.as_mut()) {
            let explicit = match &row[a] {
                Value::Int(v) if *v != 0 => Some(*v),
                _ => None,
            };
            match explicit {
                Some(v) => {
                    if v > 0 && (v as u64) >= *ctr {
                        *ctr = (v as u64).saturating_add(1);
                    }
                }
                None => {
                    let id = *ctr;
                    let limit = if t.cols[a].ty == ColType::Int {
                        i32::MAX as u64
                    } else {
                        i64::MAX as u64
                    };
                    if id > limit {
                        return Err(SqlError::out_of_range(&t.cols[a].name));
                    }
                    row[a] = Value::Int(id as i64);
                    *ctr = id + 1;
                    if first_id == 0 {
                        first_id = id;
                    }
                }
            }
        }
        finish_row(&t, &mut row)?;
        insert_row(tx, &t, &tr, &row)?;
        n += 1;
    }
    if let (Some(_), Some(ctr)) = (ai, counter) {
        write_counter(tx, &counter_key(t.id), ctr)?;
    }
    Ok(QueryResult {
        affected: n,
        last_insert_id: first_id,
        ..Default::default()
    })
}

fn order_rows(
    t: &Table,
    rows: &mut [(Vec<u8>, Vec<Value>)],
    order: &[OrderBy],
    now: i64,
) -> Result<()> {
    if order.is_empty() {
        return Ok(());
    }
    let mut keyed: Vec<(Vec<Value>, usize)> = Vec::with_capacity(rows.len());
    for (i, (_, row)) in rows.iter().enumerate() {
        let env = Env {
            t: Some(t),
            row,
            now,
        };
        keyed.push((
            order
                .iter()
                .map(|o| eval(&o.expr, &env))
                .collect::<Result<_>>()?,
            i,
        ));
    }
    keyed.sort_by(|a, b| cmp_keys(&a.0, &b.0, order));
    let perm: Vec<usize> = keyed.into_iter().map(|(_, i)| i).collect();
    let mut sorted: Vec<(Vec<u8>, Vec<Value>)> =
        perm.iter().map(|&i| std::mem::take(&mut rows[i])).collect();
    rows.swap_with_slice(&mut sorted);
    Ok(())
}

fn cmp_keys(a: &[Value], b: &[Value], order: &[OrderBy]) -> Ordering {
    for (i, o) in order.iter().enumerate() {
        let c = sort_cmp(&a[i], &b[i]);
        let c = if o.desc { c.reverse() } else { c };
        if c != Ordering::Equal {
            return c;
        }
    }
    Ordering::Equal
}

fn collect(
    tx: &mut Tx<'_>,
    t: &Table,
    tr: &Trees,
    filter: Option<&Expr>,
    order: &[OrderBy],
    limit: Option<u64>,
    now: i64,
) -> Result<Vec<(Vec<u8>, Vec<Value>)>> {
    if let Some(f) = filter {
        check_cols(f, Some(t))?;
    }
    for o in order {
        check_cols(&o.expr, Some(t))?;
    }
    let access = plan(t, filter, now);
    let cap = if order.is_empty() {
        limit.map(|l| l as usize)
    } else {
        None
    };
    let mut rows = Vec::new();
    if cap == Some(0) {
        return Ok(rows);
    }
    scan(tx, t, tr, &access, filter, now, |pk, row| {
        rows.push((pk, row));
        if rows.len() > MAX_ROWS_IN_MEMORY {
            return Err(SqlError::resource(
                "statement matches too many rows to process at once; add a LIMIT or a narrower WHERE",
            ));
        }
        Ok(cap.is_none_or(|c| rows.len() < c))
    })?;
    order_rows(t, &mut rows, order, now)?;
    if let Some(l) = limit {
        rows.truncate(l as usize);
    }
    Ok(rows)
}

fn update(
    tx: &mut Tx<'_>,
    table: &str,
    sets: &[(String, Expr)],
    filter: Option<&Expr>,
    order: &[OrderBy],
    limit: Option<u64>,
    now: i64,
) -> Result<QueryResult> {
    let t = load_table(tx, table)?;
    let tr = open_trees(tx, &t)?;
    let mut targets = Vec::with_capacity(sets.len());
    for (c, e) in sets {
        let i = t.col(c).ok_or_else(|| SqlError::bad_column(c))?;
        check_cols(e, Some(&t))?;
        targets.push((i, e));
    }
    let rows = collect(tx, &t, &tr, filter, order, limit, now)?;
    let mut changed = 0u64;
    let matched = rows.len();
    for (pk, old) in rows {
        let mut new = old.clone();
        for &(i, e) in &targets {
            let v = eval(
                e,
                &Env {
                    t: Some(&t),
                    row: &new,
                    now,
                },
            )?;
            new[i] = coerce(v, t.cols[i].ty, &t.cols[i].name)?;
        }
        finish_row(&t, &mut new)?;
        if new == old {
            continue;
        }
        let new_pk = if t.pk.is_empty() {
            pk.clone()
        } else {
            pk_key(&t, &new)?
        };
        index_delete(tx, &t, &tr, &old, &pk)?;
        if new_pk != pk {
            if tx.get(&tr.rows, &new_pk)?.is_some() {
                return Err(SqlError::dup_entry(&render_key(&t.pk, &new), "PRIMARY"));
            }
            del_row(tx, &tr, &pk)?;
        }
        index_insert(tx, &t, &tr, &new, &new_pk)?;
        put_row(tx, &tr, &new_pk, &new)?;
        changed += 1;
    }
    Ok(QueryResult {
        affected: changed,
        info: Some(format!(
            "Rows matched: {matched}  Changed: {changed}  Warnings: 0"
        )),
        ..Default::default()
    })
}

fn delete(
    tx: &mut Tx<'_>,
    table: &str,
    filter: Option<&Expr>,
    order: &[OrderBy],
    limit: Option<u64>,
    now: i64,
) -> Result<QueryResult> {
    let t = load_table(tx, table)?;
    let tr = open_trees(tx, &t)?;
    let rows = collect(tx, &t, &tr, filter, order, limit, now)?;
    let n = rows.len() as u64;
    for (pk, row) in rows {
        index_delete(tx, &t, &tr, &row, &pk)?;
        del_row(tx, &tr, &pk)?;
    }
    Ok(QueryResult::ok(n))
}

// ----- SELECT --------------------------------------------------------------------------------

enum Item<'a> {
    Col(usize),
    Expr(&'a Expr),
}

fn select(tx: &mut Tx<'_>, s: &Select, now: i64) -> Result<QueryResult> {
    let t = match &s.from {
        Some(name) => Some(load_table(tx, name)?),
        None => None,
    };
    // Resolve select list.
    let mut items: Vec<Item<'_>> = Vec::new();
    let mut columns = Vec::new();
    for it in &s.items {
        match it {
            SelectItem::Star => {
                let Some(t) = &t else {
                    return Err(SqlError::syntax(0, "*", "SELECT * needs a FROM clause"));
                };
                for (i, c) in t.cols.iter().enumerate() {
                    items.push(Item::Col(i));
                    columns.push(ColumnMeta {
                        name: c.name.clone(),
                        ty: Some(c.ty),
                    });
                }
            }
            SelectItem::Expr { expr, alias, text } => {
                check_cols(expr, t.as_ref())?;
                match (expr, &t) {
                    (Expr::Col(c), Some(t)) => {
                        let i = t.col(c).ok_or_else(|| SqlError::bad_column(c))?;
                        items.push(Item::Col(i));
                        columns.push(ColumnMeta {
                            name: alias.clone().unwrap_or_else(|| t.cols[i].name.clone()),
                            ty: Some(t.cols[i].ty),
                        });
                    }
                    _ => {
                        items.push(Item::Expr(expr));
                        columns.push(ColumnMeta {
                            name: alias.clone().unwrap_or_else(|| text.clone()),
                            ty: None,
                        });
                    }
                }
            }
        }
    }
    // ORDER BY may name a select alias or a 1-based position.
    let order: Vec<OrderBy> = s
        .order
        .iter()
        .map(|o| match &o.expr {
            Expr::Lit(Value::Int(n)) if *n >= 1 && (*n as usize) <= s.items.len() => {
                let idx = *n as usize - 1;
                match s.items.get(idx) {
                    Some(SelectItem::Expr { expr, .. }) => Ok(OrderBy {
                        expr: expr.clone(),
                        desc: o.desc,
                    }),
                    _ => Err(SqlError::unsupported("ORDER BY position of *")),
                }
            }
            Expr::Col(name) if t.as_ref().is_none_or(|t| t.col(name).is_none()) => {
                let hit = s.items.iter().find_map(|it| match it {
                    SelectItem::Expr {
                        expr,
                        alias: Some(a),
                        ..
                    } if a.eq_ignore_ascii_case(name) => Some(expr.clone()),
                    _ => None,
                });
                hit.map(|expr| OrderBy { expr, desc: o.desc })
                    .ok_or_else(|| SqlError::bad_column(name))
            }
            _ => Ok(o.clone()),
        })
        .collect::<Result<_>>()?;

    let project = |row: &[Value], t: Option<&Table>| -> Result<Vec<Value>> {
        let env = Env { t, row, now };
        items
            .iter()
            .map(|it| match it {
                Item::Col(i) => Ok(row.get(*i).cloned().unwrap_or(Value::Null)),
                Item::Expr(e) => eval(e, &env),
            })
            .collect()
    };

    let mut out: Vec<Vec<Value>> = match &t {
        None => {
            if let Some(f) = &s.filter {
                check_cols(f, None)?;
                if !matches(
                    Some(f),
                    &Env {
                        t: None,
                        row: &[],
                        now,
                    },
                )? {
                    return Ok(QueryResult {
                        columns,
                        ..Default::default()
                    });
                }
            }
            vec![project(&[], None)?]
        }
        Some(t) => {
            let tr = open_trees(tx, t)?;
            let need = if s.distinct {
                None
            } else {
                s.limit.map(|l| l.saturating_add(s.offset))
            };
            let rows = collect(tx, t, &tr, s.filter.as_ref(), &order, need, now)?;
            rows.iter()
                .map(|(_, r)| project(r, Some(t)))
                .collect::<Result<_>>()?
        }
    };
    if s.distinct {
        let mut seen: Vec<Vec<Value>> = Vec::new();
        out.retain(|r| {
            let dup = seen.iter().any(|x| {
                x.len() == r.len()
                    && x.iter()
                        .zip(r)
                        .all(|(a, b)| sort_cmp(a, b) == Ordering::Equal)
            });
            if !dup {
                seen.push(r.clone());
            }
            !dup
        });
    }
    let off = usize::try_from(s.offset).unwrap_or(usize::MAX);
    out = out.into_iter().skip(off).collect();
    if let Some(l) = s.limit {
        out.truncate(usize::try_from(l).unwrap_or(usize::MAX));
    }
    Ok(QueryResult {
        columns,
        rows: out,
        ..Default::default()
    })
}

// ----- introspection -------------------------------------------------------------------------

fn meta(names: &[&str]) -> Vec<ColumnMeta> {
    names
        .iter()
        .map(|n| ColumnMeta {
            name: (*n).into(),
            ty: None,
        })
        .collect()
}

fn show_tables(tx: &mut Tx<'_>) -> Result<QueryResult> {
    let c = catalog(tx)?;
    let entries = tx
        .range(
            &c,
            (Bound::Included(&b"t\0"[..]), Bound::Excluded(&b"t\x01"[..])),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    let mut rows = Vec::new();
    for (_, v) in entries {
        rows.push(vec![Value::Str(Table::decode(&v)?.name)]);
    }
    Ok(QueryResult {
        columns: meta(&["Tables_in_novadb"]),
        rows,
        ..Default::default()
    })
}

fn describe(tx: &mut Tx<'_>, name: &str) -> Result<QueryResult> {
    let t = load_table(tx, name)?;
    let mut rows = Vec::new();
    for (i, c) in t.cols.iter().enumerate() {
        let key = if t.pk.contains(&i) {
            "PRI"
        } else if t
            .indexes
            .iter()
            .any(|x| x.unique && x.cols.len() == 1 && x.cols[0] == i)
        {
            "UNI"
        } else if t.indexes.iter().any(|x| x.cols.first() == Some(&i)) {
            "MUL"
        } else {
            ""
        };
        let default = match &c.default {
            None => Value::Null,
            Some(DefaultExpr::Now) => Value::Str("CURRENT_TIMESTAMP".into()),
            Some(DefaultExpr::Value(v)) => v.text().map_or(Value::Null, Value::Str),
        };
        rows.push(vec![
            Value::Str(c.name.clone()),
            Value::Str(c.ty.sql()),
            Value::Str(if c.nullable { "YES" } else { "NO" }.into()),
            Value::Str(key.into()),
            default,
            Value::Str(if c.auto_inc { "auto_increment" } else { "" }.into()),
        ]);
    }
    Ok(QueryResult {
        columns: meta(&["Field", "Type", "Null", "Key", "Default", "Extra"]),
        rows,
        ..Default::default()
    })
}

fn quote(n: &str) -> String {
    format!("`{}`", n.replace('`', "``"))
}

fn sql_literal(v: &Value) -> String {
    match v {
        Value::Null => "NULL".into(),
        Value::Int(_) | Value::Dec { .. } => v.text().unwrap_or_default(),
        Value::Bytes(b) => format!(
            "X'{}'",
            b.iter().map(|x| format!("{x:02X}")).collect::<String>()
        ),
        other => format!(
            "'{}'",
            other
                .text()
                .unwrap_or_default()
                .replace('\\', "\\\\")
                .replace('\'', "''")
        ),
    }
}

fn show_create(tx: &mut Tx<'_>, name: &str) -> Result<QueryResult> {
    let t = load_table(tx, name)?;
    let mut lines = Vec::new();
    for c in &t.cols {
        let mut l = format!("  {} {}", quote(&c.name), c.ty.sql());
        if !c.nullable {
            l.push_str(" NOT NULL");
        }
        match &c.default {
            Some(DefaultExpr::Now) => l.push_str(" DEFAULT CURRENT_TIMESTAMP"),
            Some(DefaultExpr::Value(v)) => l.push_str(&format!(" DEFAULT {}", sql_literal(v))),
            None if c.nullable && !c.ty.is_lob() => l.push_str(" DEFAULT NULL"),
            None => {}
        }
        if c.auto_inc {
            l.push_str(" AUTO_INCREMENT");
        }
        lines.push(l);
    }
    let names = |cols: &[usize]| {
        cols.iter()
            .map(|&i| quote(&t.cols[i].name))
            .collect::<Vec<_>>()
            .join(",")
    };
    if !t.pk.is_empty() {
        lines.push(format!("  PRIMARY KEY ({})", names(&t.pk)));
    }
    for ix in &t.indexes {
        lines.push(format!(
            "  {}KEY {} ({})",
            if ix.unique { "UNIQUE " } else { "" },
            quote(&ix.name),
            names(&ix.cols)
        ));
    }
    let ddl = format!(
        "CREATE TABLE {} (\n{}\n) ENGINE=NovaDB",
        quote(&t.name),
        lines.join(",\n")
    );
    Ok(QueryResult {
        columns: meta(&["Table", "Create Table"]),
        rows: vec![vec![Value::Str(t.name.clone()), Value::Str(ddl)]],
        ..Default::default()
    })
}

fn explain(tx: &mut Tx<'_>, s: &Stmt, now: i64) -> Result<QueryResult> {
    let (table, filter) = match s {
        Stmt::Select(sel) => (sel.from.as_deref(), sel.filter.as_ref()),
        Stmt::Update { table, filter, .. } | Stmt::Delete { table, filter, .. } => {
            (Some(table.as_str()), filter.as_ref())
        }
        _ => return Err(SqlError::unsupported("EXPLAIN for this statement")),
    };
    let row = match table {
        None => vec![
            Value::Null,
            Value::Str("No tables used".into()),
            Value::Null,
        ],
        Some(name) => {
            let t = load_table(tx, name)?;
            if let Some(f) = filter {
                check_cols(f, Some(&t))?;
            }
            let (ty, key) = access_desc(&t, &plan(&t, filter, now));
            vec![
                Value::Str(t.name.clone()),
                Value::Str(ty.into()),
                key.map_or(Value::Null, Value::Str),
            ]
        }
    };
    Ok(QueryResult {
        columns: meta(&["table", "type", "key"]),
        rows: vec![row],
        ..Default::default()
    })
}

impl SqlError {
    fn new_unknown_tables(names: &[String]) -> SqlError {
        let mut e = SqlError::no_table(&names.join(","));
        e.code = 1051;
        e.msg = format!("Unknown table '{}'", names.join(","));
        e
    }
}
