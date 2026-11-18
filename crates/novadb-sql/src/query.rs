//! Stage 6: joins, GROUP BY / aggregates, HAVING and subqueries.
//!
//! Approach: every column reference of a multi-table query is resolved once to a canonical name
//! `#<n>` = position in the combined row (ambiguity and unknown names are reported here), and
//! aggregates are replaced by `#a<k>` slots. The ordinary expression evaluator then runs on
//! combined rows through a synthetic table whose columns are named `#0, #1, …`.
//!
//! Joins are nested loops in FROM order (RIGHT JOIN of two tables is run as the mirrored LEFT
//! JOIN). For each row of the tables bound so far, the inner table is scanned with its ON
//! condition and every WHERE conjunct that only needs bound tables, with the bound values
//! substituted as literals — so the regular single-table planner picks the inner table's primary
//! key or an index whenever the join condition allows it (index nested-loop join).

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use crate::ast::*;
use crate::catalog::{Column, Table};
use crate::error::{Result, SqlError};
use crate::exec::{
    ColumnMeta, Env, MAX_ROWS_IN_MEMORY, QueryResult, Trees, check_interrupt, eval, load_table,
    matches, open_trees, plan, scan,
};
use crate::mvcc::Mv;
use crate::value::{ArithOp, ColType, Value, arith, compare, sort_cmp};

/// Aggregate function names (with `_distinct` / `_sep` suffixes stripped).
pub fn is_aggregate(name: &str) -> bool {
    matches!(
        base_agg(name),
        "count" | "sum" | "avg" | "min" | "max" | "group_concat"
    )
}

fn base_agg(name: &str) -> &str {
    name.trim_end_matches("_sep").trim_end_matches("_distinct")
}

fn has_agg(e: &Expr) -> bool {
    let mut found = false;
    let mut e = e.clone();
    walk_expr_mut(&mut e, &mut |x| {
        if let Expr::Func { name, .. } = x
            && is_aggregate(name)
        {
            found = true;
        }
    });
    found
}

/// Does this SELECT need the general (join / aggregate) path?
pub fn needs_general(s: &Select) -> bool {
    !s.joins.is_empty()
        || !s.group_by.is_empty()
        || s.having.is_some()
        || s.items.iter().any(|i| match i {
            SelectItem::TableStar(_) => true,
            SelectItem::Expr { expr, .. } => has_agg(expr),
            SelectItem::Star => false,
        })
        || s.order.iter().any(|o| has_agg(&o.expr))
}

fn too_many_cols() -> SqlError {
    let mut e = SqlError::internal("Operand should contain 1 column(s)");
    e.code = 1241;
    e.state = "21000";
    e
}

fn subquery_rows() -> SqlError {
    let mut e = SqlError::internal("Subquery returns more than 1 row");
    e.code = 1242;
    e.state = "21000";
    e
}

fn run_sub(mv: &mut Mv<'_, '_>, sub: &Select, now: i64) -> Result<QueryResult> {
    match crate::exec::select(mv, sub, now) {
        Err(e) if e.code == 1054 => Err(SqlError::unsupported(&format!(
            "correlated subqueries (the subquery refers to an outer column; {})",
            e.msg
        ))),
        r => r,
    }
}

/// Replace uncorrelated subqueries in `s` by their results.
pub fn materialize_select(mv: &mut Mv<'_, '_>, s: &mut Select, now: i64) -> Result<()> {
    let mut err = None;
    walk_select_mut(s, &mut |e| materialize_one(mv, e, now, &mut err));
    err.map_or(Ok(()), Err)
}

/// Same for a free expression (UPDATE/DELETE WHERE, SET values, INSERT VALUES).
pub fn materialize_expr(mv: &mut Mv<'_, '_>, e: &mut Expr, now: i64) -> Result<()> {
    let mut err = None;
    walk_expr_mut(e, &mut |x| materialize_one(mv, x, now, &mut err));
    err.map_or(Ok(()), Err)
}

fn materialize_one(mv: &mut Mv<'_, '_>, e: &mut Expr, now: i64, err: &mut Option<SqlError>) {
    if err.is_some() {
        return;
    }
    let r: Result<Option<Expr>> = (|| {
        Ok(match e {
            Expr::Subquery(sub) => {
                let q = run_sub(mv, sub, now)?;
                if q.columns.len() != 1 {
                    return Err(too_many_cols());
                }
                if q.rows.len() > 1 {
                    return Err(subquery_rows());
                }
                Some(Expr::Lit(
                    q.rows
                        .into_iter()
                        .next()
                        .and_then(|r| r.into_iter().next())
                        .unwrap_or(Value::Null),
                ))
            }
            Expr::InSubquery { e: inner, sub, neg } => {
                let q = run_sub(mv, sub, now)?;
                if q.columns.len() != 1 {
                    return Err(too_many_cols());
                }
                let list: Vec<Expr> = q
                    .rows
                    .into_iter()
                    .filter_map(|r| r.into_iter().next())
                    .map(Expr::Lit)
                    .collect();
                if list.is_empty() {
                    Some(Expr::Lit(Value::bool(*neg)))
                } else {
                    Some(Expr::InList {
                        e: inner.clone(),
                        list,
                        neg: *neg,
                    })
                }
            }
            Expr::Exists { sub, neg } => {
                let mut s1 = (**sub).clone();
                s1.limit = Some(1);
                let q = run_sub(mv, &s1, now)?;
                Some(Expr::Lit(Value::bool(q.rows.is_empty() == *neg)))
            }
            _ => None,
        })
    })();
    match r {
        Ok(Some(x)) => *e = x,
        Ok(None) => {}
        Err(x) => *err = Some(x),
    }
}

/// For single-table statements: `t.col` / `alias.col` → `col` (checking the qualifier).
pub fn strip_qualifiers(e: &mut Expr, table: &str, alias: Option<&str>) -> Result<()> {
    let mut bad = None;
    walk_expr_mut(e, &mut |x| {
        if let Expr::Col(n) = x
            && let Some((q, c)) = n.split_once('.')
        {
            let ok =
                q.eq_ignore_ascii_case(table) || alias.is_some_and(|a| q.eq_ignore_ascii_case(a));
            if ok {
                *n = c.to_string();
            } else if bad.is_none() {
                bad = Some(n.clone());
            }
        }
    });
    match bad {
        Some(n) => Err(SqlError::bad_column(&n)),
        None => Ok(()),
    }
}

struct Src {
    alias: String,
    t: Table,
    tr: Trees,
    offset: usize,
    kind: JoinKind,
    on: Option<Expr>,
}

fn ambiguous(c: &str) -> SqlError {
    let mut e = SqlError::bad_column(c);
    e.code = 1052;
    e.state = "23000";
    e.msg = format!("Column '{c}' in field list is ambiguous");
    e
}

fn resolve_name(srcs: &[Src], name: &str) -> Result<usize> {
    if let Some((a, c)) = name.split_once('.') {
        let s = srcs
            .iter()
            .find(|s| s.alias.eq_ignore_ascii_case(a))
            .ok_or_else(|| SqlError::bad_column(name))?;
        return s
            .t
            .col(c)
            .map(|i| s.offset + i)
            .ok_or_else(|| SqlError::bad_column(name));
    }
    let hits: Vec<usize> = srcs
        .iter()
        .filter_map(|s| s.t.col(name).map(|i| s.offset + i))
        .collect();
    match hits.as_slice() {
        [one] => Ok(*one),
        [] => Err(SqlError::bad_column(name)),
        _ => Err(ambiguous(name)),
    }
}

fn resolve(e: &mut Expr, srcs: &[Src]) -> Result<()> {
    let mut err = None;
    walk_expr_mut(e, &mut |x| {
        if let Expr::Col(n) = x
            && !n.starts_with('#')
        {
            match resolve_name(srcs, n) {
                Ok(i) => *n = format!("#{i}"),
                Err(e) => {
                    if err.is_none() {
                        err = Some(e);
                    }
                }
            }
        }
    });
    err.map_or(Ok(()), Err)
}

fn global_cols(e: &Expr) -> Vec<usize> {
    let mut cols = Vec::new();
    e.columns(&mut cols);
    cols.iter()
        .filter_map(|c| c.strip_prefix('#').and_then(|n| n.parse().ok()))
        .collect()
}

fn src_of(srcs: &[Src], g: usize) -> usize {
    srcs.iter().rposition(|s| s.offset <= g).unwrap_or(0)
}

/// Inner-table filter for one outer row: bound columns become literals, the inner table's own
/// columns get their real names back (so the single-table planner can use its indexes).
fn bind_for(e: &Expr, row: &[Value], src: &Src, bound: &[bool]) -> Result<Expr> {
    let mut e = e.clone();
    let mut bad = None;
    walk_expr_mut(&mut e, &mut |x| {
        if let Expr::Col(n) = x
            && let Some(g) = n.strip_prefix('#').and_then(|v| v.parse::<usize>().ok())
        {
            if g >= src.offset && g < src.offset + src.t.cols.len() {
                *x = Expr::Col(src.t.cols[g - src.offset].name.clone());
            } else if bound.get(g).copied().unwrap_or(false) {
                *x = Expr::Lit(row.get(g).cloned().unwrap_or(Value::Null));
            } else if bad.is_none() {
                bad = Some(g);
            }
        }
    });
    match bad {
        Some(_) => Err(SqlError::unsupported(
            "ON condition referring to a table joined later",
        )),
        None => Ok(e),
    }
}

fn and_all(parts: Vec<Expr>) -> Option<Expr> {
    parts.into_iter().reduce(|l, r| Expr::Binary {
        op: BinOp::And,
        l: Box::new(l),
        r: Box::new(r),
    })
}

fn conjuncts(e: Expr, out: &mut Vec<Expr>) {
    match e {
        Expr::Binary {
            op: BinOp::And,
            l,
            r,
        } => {
            conjuncts(*l, out);
            conjuncts(*r, out);
        }
        other => out.push(other),
    }
}

// ----- aggregates ----------------------------------------------------------------------------

#[derive(Clone)]
struct AggSpec {
    kind: String,
    distinct: bool,
    arg: Option<Expr>,
    sep: String,
}

/// One group: its first input row, aggregate states, DISTINCT seen-sets.
type Group = (Vec<Value>, Vec<AggState>, Vec<HashSet<String>>);

enum AggState {
    Count(u64),
    Sum(Value, bool),
    Avg(Value, u64),
    Min(Value),
    Max(Value),
    Concat(Vec<String>, usize),
}

/// Canonical text for grouping / DISTINCT (1 = 1.0, binary strings).
fn canon(v: &Value) -> String {
    match v {
        Value::Null => "n".into(),
        Value::Int(_) | Value::Dec { .. } => {
            let (x, s) = v.to_num().unwrap_or((0, 0));
            let mut t = crate::value::format_decimal(x, s);
            if t.contains('.') {
                t = t.trim_end_matches('0').trim_end_matches('.').to_string();
            }
            if t == "-0" {
                t = "0".into();
            }
            format!("#{t}")
        }
        Value::Str(s) => format!("s{s}"),
        Value::Bytes(b) => format!("b{}", crate::exec::hex(b)),
        Value::DateTime(us) => format!("d{us}"),
    }
}

fn extract_aggs(e: &mut Expr, specs: &mut Vec<AggSpec>, base: usize) -> Result<()> {
    let mut err = None;
    walk_expr_mut(e, &mut |x| {
        if let Expr::Func { name, args } = x
            && is_aggregate(name)
        {
            if args.iter().any(has_agg) && err.is_none() {
                let mut e = SqlError::internal("Invalid use of group function");
                e.code = 1111;
                err = Some(e);
                return;
            }
            let kind = base_agg(name).to_string();
            let distinct = name.contains("_distinct");
            let mut args = args.clone();
            let sep = if name.ends_with("_sep") {
                match args.pop() {
                    Some(Expr::Lit(Value::Str(s))) => s,
                    _ => ",".into(),
                }
            } else {
                ",".into()
            };
            let ok_arity = match kind.as_str() {
                "group_concat" => !args.is_empty(),
                _ => args.len() == 1,
            };
            if !ok_arity && err.is_none() {
                err = Some(SqlError::wrong_func(&kind));
                return;
            }
            let arg = if kind == "group_concat" && args.len() > 1 {
                Some(Expr::Func {
                    name: "concat".into(),
                    args,
                })
            } else {
                args.into_iter().next()
            };
            specs.push(AggSpec {
                kind,
                distinct,
                arg,
                sep,
            });
            *x = Expr::Col(format!("#a{}", base + specs.len() - 1));
        }
    });
    err.map_or(Ok(()), Err)
}

fn new_state(s: &AggSpec) -> AggState {
    match s.kind.as_str() {
        "count" => AggState::Count(0),
        "sum" => AggState::Sum(Value::Int(0), false),
        "avg" => AggState::Avg(Value::Int(0), 0),
        "min" => AggState::Min(Value::Null),
        "max" => AggState::Max(Value::Null),
        _ => AggState::Concat(Vec::new(), 0),
    }
}

fn agg_update(st: &mut AggState, v: Value) -> Result<()> {
    if v.is_null() {
        return Ok(());
    }
    match st {
        AggState::Count(n) => *n += 1,
        AggState::Sum(acc, any) => {
            *acc = arith(ArithOp::Add, acc, &v)?;
            *any = true;
        }
        AggState::Avg(acc, n) => {
            *acc = arith(ArithOp::Add, acc, &v)?;
            *n += 1;
        }
        AggState::Min(m) => {
            if m.is_null() || compare(&v, m) == Some(Ordering::Less) {
                *m = v;
            }
        }
        AggState::Max(m) => {
            if m.is_null() || compare(&v, m) == Some(Ordering::Greater) {
                *m = v;
            }
        }
        AggState::Concat(parts, bytes) => {
            let t = v.text().unwrap_or_default();
            *bytes += t.len();
            // group_concat_max_len default (1024) is far too small for real use; cap at 1 MiB.
            if *bytes <= 1 << 20 {
                parts.push(t);
            }
        }
    }
    Ok(())
}

fn agg_final(st: AggState, spec: &AggSpec) -> Result<Value> {
    Ok(match st {
        AggState::Count(n) => Value::Int(n as i64),
        AggState::Sum(acc, any) => {
            if any {
                acc
            } else {
                Value::Null
            }
        }
        AggState::Avg(acc, n) => {
            if n == 0 {
                Value::Null
            } else {
                arith(ArithOp::Div, &acc, &Value::Int(n as i64))?
            }
        }
        AggState::Min(m) | AggState::Max(m) => m,
        AggState::Concat(parts, _) => {
            if parts.is_empty() {
                Value::Null
            } else {
                Value::Str(parts.join(&spec.sep))
            }
        }
    })
}

fn synthetic(cols: Vec<Column>) -> Table {
    Table {
        id: 0,
        name: String::new(),
        cols,
        pk: vec![],
        indexes: vec![],
        next_index_id: 0,
    }
}

fn col_named(name: String, ty: ColType) -> Column {
    Column {
        name,
        ty,
        nullable: true,
        default: None,
        auto_inc: false,
    }
}

// ----- the general SELECT --------------------------------------------------------------------

pub fn select_general(mv: &mut Mv<'_, '_>, s: &Select, now: i64) -> Result<QueryResult> {
    let Some(first) = &s.from else {
        // Aggregates without FROM: one implicit row.
        return select_no_from(s, now);
    };
    // Sources in FROM order (= combined row layout).
    let mut srcs: Vec<Src> = Vec::new();
    let add = |mv: &mut Mv<'_, '_>,
               name: &str,
               alias: Option<&String>,
               kind: JoinKind,
               on: Option<Expr>,
               srcs: &mut Vec<Src>|
     -> Result<()> {
        let t = load_table(mv.tx, name)?;
        let tr = open_trees(mv.tx, &t)?;
        let alias = alias.cloned().unwrap_or_else(|| t.name.clone());
        if srcs.iter().any(|x| x.alias.eq_ignore_ascii_case(&alias)) {
            let mut e = SqlError::internal(format!("Not unique table/alias: '{alias}'"));
            e.code = 1066;
            e.state = "42000";
            return Err(e);
        }
        let offset = srcs.last().map_or(0, |l| l.offset + l.t.cols.len());
        srcs.push(Src {
            alias,
            t,
            tr,
            offset,
            kind,
            on,
        });
        Ok(())
    };
    add(
        mv,
        first,
        s.alias.as_ref(),
        JoinKind::Inner,
        None,
        &mut srcs,
    )?;
    for j in &s.joins {
        add(
            mv,
            &j.table,
            j.alias.as_ref(),
            j.kind,
            j.on.clone(),
            &mut srcs,
        )?;
    }
    let width = srcs.last().map_or(0, |l| l.offset + l.t.cols.len());
    if width > 4096 {
        return Err(SqlError::unsupported(
            "joins producing more than 4096 columns",
        ));
    }
    // USING(cols) → ON left.c = right.c
    for (k, j) in s.joins.iter().enumerate() {
        if j.using.is_empty() {
            continue;
        }
        let mut parts = Vec::new();
        for c in &j.using {
            let right = srcs[k + 1]
                .t
                .col(c)
                .map(|i| srcs[k + 1].offset + i)
                .ok_or_else(|| SqlError::bad_column(c))?;
            let left = resolve_name(&srcs[..=k], c)?;
            parts.push(Expr::Binary {
                op: BinOp::Eq,
                l: Box::new(Expr::Col(format!("#{left}"))),
                r: Box::new(Expr::Col(format!("#{right}"))),
            });
        }
        srcs[k + 1].on = and_all(parts);
    }
    // Resolve ON conditions.
    for k in 0..srcs.len() {
        if let Some(mut on) = srcs[k].on.take() {
            resolve(&mut on, &srcs[..=k])?;
            srcs[k].on = Some(on);
        }
    }
    // Execution order: RIGHT JOIN of two tables runs mirrored as LEFT JOIN.
    let mut order: Vec<usize> = (0..srcs.len()).collect();
    if srcs.iter().any(|x| x.kind == JoinKind::Right) {
        if srcs.len() != 2 {
            return Err(SqlError::unsupported(
                "RIGHT JOIN with more than two tables (rewrite as LEFT JOIN)",
            ));
        }
        order = vec![1, 0];
        srcs[0].kind = JoinKind::Left;
        srcs[0].on = srcs[1].on.take();
        srcs[1].kind = JoinKind::Inner;
    }
    let pos_of: Vec<usize> = {
        let mut p = vec![0; srcs.len()];
        for (i, &si) in order.iter().enumerate() {
            p[si] = i;
        }
        p
    };
    let names: Vec<(String, ColType)> = srcs
        .iter()
        .flat_map(|x| x.t.cols.iter().map(|c| (c.name.clone(), c.ty)))
        .collect();

    // Resolve the rest of the query.
    let mut items = s.items.clone();
    let mut filter = s.filter.clone();
    let mut group_by = s.group_by.clone();
    let mut having = s.having.clone();
    // ORDER BY alias / position → the select expression.
    let mut order_by: Vec<OrderBy> = Vec::with_capacity(s.order.len());
    for o in &s.order {
        let expr = match &o.expr {
            Expr::Lit(Value::Int(n)) if *n >= 1 && (*n as usize) <= items.len() => {
                match &items[*n as usize - 1] {
                    SelectItem::Expr { expr, .. } => expr.clone(),
                    _ => return Err(SqlError::unsupported("ORDER BY position of *")),
                }
            }
            Expr::Col(n) if !n.contains('.') && resolve_name(&srcs, n).is_err() => items
                .iter()
                .find_map(|it| match it {
                    SelectItem::Expr {
                        expr,
                        alias: Some(a),
                        ..
                    } if a.eq_ignore_ascii_case(n) => Some(expr.clone()),
                    _ => None,
                })
                .ok_or_else(|| SqlError::bad_column(n))?,
            e => e.clone(),
        };
        order_by.push(OrderBy { expr, desc: o.desc });
    }
    // HAVING may use select aliases too.
    if let Some(h) = &mut having {
        let aliases: Vec<(String, Expr)> = items
            .iter()
            .filter_map(|it| match it {
                SelectItem::Expr {
                    expr,
                    alias: Some(a),
                    ..
                } => Some((a.clone(), expr.clone())),
                _ => None,
            })
            .collect();
        walk_expr_mut(h, &mut |x| {
            if let Expr::Col(n) = x
                && resolve_name(&srcs, n).is_err()
                && let Some((_, e)) = aliases.iter().find(|(a, _)| a.eq_ignore_ascii_case(n))
            {
                *x = e.clone();
            }
        });
    }
    for it in &mut items {
        if let SelectItem::Expr { expr, .. } = it {
            resolve(expr, &srcs)?;
        }
    }
    if let Some(f) = &mut filter {
        if has_agg(f) {
            let mut e = SqlError::internal("Invalid use of group function");
            e.code = 1111;
            return Err(e);
        }
        resolve(f, &srcs)?;
    }
    for g in &mut group_by {
        resolve(g, &srcs)?;
    }
    if let Some(h) = &mut having {
        resolve(h, &srcs)?;
    }
    for o in &mut order_by {
        resolve(&mut o.expr, &srcs)?;
    }

    // Place WHERE conjuncts at the earliest join level that binds all their tables. Conjuncts
    // touching a LEFT-joined table are applied after the join (they filter NULL-extended rows).
    let mut placed: Vec<Vec<Expr>> = vec![Vec::new(); srcs.len()];
    let mut post: Vec<Expr> = Vec::new();
    if let Some(f) = filter.take() {
        let mut cs = Vec::new();
        conjuncts(f, &mut cs);
        for c in cs {
            let used: HashSet<usize> = global_cols(&c)
                .into_iter()
                .map(|g| src_of(&srcs, g))
                .collect();
            if used.iter().any(|&u| srcs[u].kind == JoinKind::Left) {
                post.push(c);
            } else {
                let at = used.iter().map(|&u| pos_of[u]).max().unwrap_or(0);
                placed[at].push(c);
            }
        }
    }

    // Nested-loop join.
    let mut rows: Vec<Vec<Value>> = vec![vec![Value::Null; width]];
    let mut bound = vec![false; width];
    for (pos, &si) in order.iter().enumerate() {
        let src = &srcs[si];
        let mut parts: Vec<Expr> = placed[pos].clone();
        if pos > 0
            && let Some(on) = &src.on
        {
            parts.push(on.clone());
        }
        let cond = and_all(parts);
        let mut next: Vec<Vec<Value>> = Vec::new();
        let n = src.t.cols.len();
        for partial in &rows {
            check_interrupt()?;
            let f = match &cond {
                Some(c) => Some(bind_for(c, partial, src, &bound)?),
                None => None,
            };
            let access = plan(&src.t, f.as_ref(), now);
            let mut matched = false;
            scan(mv, &src.t, &src.tr, &access, f.as_ref(), now, |_, r| {
                let mut row = partial.clone();
                row[src.offset..src.offset + n].clone_from_slice(&r);
                next.push(row);
                matched = true;
                if next.len() > MAX_ROWS_IN_MEMORY {
                    return Err(SqlError::resource(
                        "join produces too many rows to process at once; add join conditions or a narrower WHERE",
                    ));
                }
                Ok(true)
            })?;
            if !matched && pos > 0 && src.kind == JoinKind::Left {
                next.push(partial.clone());
            }
        }
        for b in bound.iter_mut().skip(src.offset).take(n) {
            *b = true;
        }
        rows = next;
    }
    let comb = synthetic(
        names
            .iter()
            .enumerate()
            .map(|(i, (_, ty))| col_named(format!("#{i}"), *ty))
            .collect(),
    );
    if !post.is_empty() {
        let f = and_all(post);
        let mut kept = Vec::with_capacity(rows.len());
        for r in rows {
            if matches(
                f.as_ref(),
                &Env {
                    t: Some(&comb),
                    row: &r,
                    now,
                },
            )? {
                kept.push(r);
            }
        }
        rows = kept;
    }
    finish(
        rows, comb, &names, &srcs, items, group_by, having, order_by, s, now,
    )
}

/// SELECT with aggregates but no FROM (e.g. `SELECT COUNT(*)`).
fn select_no_from(s: &Select, now: i64) -> Result<QueryResult> {
    let comb = synthetic(Vec::new());
    let items = s.items.clone();
    if items.iter().any(|i| !matches!(i, SelectItem::Expr { .. })) {
        return Err(SqlError::syntax(0, "*", "SELECT * needs a FROM clause"));
    }
    let rows = match &s.filter {
        Some(f)
            if !matches(
                Some(f),
                &Env {
                    t: None,
                    row: &[],
                    now,
                },
            )? =>
        {
            vec![]
        }
        _ => vec![vec![]],
    };
    finish(
        rows,
        comb,
        &[],
        &[],
        items,
        s.group_by.clone(),
        s.having.clone(),
        s.order.clone(),
        s,
        now,
    )
}

#[allow(clippy::too_many_arguments)]
fn finish(
    rows: Vec<Vec<Value>>,
    comb: Table,
    names: &[(String, ColType)],
    srcs: &[Src],
    mut items: Vec<SelectItem>,
    group_by: Vec<Expr>,
    mut having: Option<Expr>,
    mut order_by: Vec<OrderBy>,
    s: &Select,
    now: i64,
) -> Result<QueryResult> {
    let width = comb.cols.len();
    // Aggregates → slots.
    let mut specs: Vec<AggSpec> = Vec::new();
    for it in &mut items {
        if let SelectItem::Expr { expr, .. } = it {
            extract_aggs(expr, &mut specs, 0)?;
        }
    }
    if let Some(h) = &mut having {
        extract_aggs(h, &mut specs, 0)?;
    }
    for o in &mut order_by {
        extract_aggs(&mut o.expr, &mut specs, 0)?;
    }
    for g in &group_by {
        if has_agg(g) {
            let mut e = SqlError::internal("Can't group on an aggregate");
            e.code = 1056;
            return Err(e);
        }
    }
    let grouped = !specs.is_empty() || !group_by.is_empty();
    let (rows, table) = if grouped {
        let env_t = &comb;
        let mut index: HashMap<Vec<String>, usize> = HashMap::new();
        let mut groups: Vec<Group> = Vec::new();
        for r in rows {
            check_interrupt()?;
            let env = Env {
                t: Some(env_t),
                row: &r,
                now,
            };
            let key: Vec<String> = group_by
                .iter()
                .map(|g| eval(g, &env).map(|v| canon(&v)))
                .collect::<Result<_>>()?;
            let gi = match index.get(&key) {
                Some(&i) => i,
                None => {
                    if groups.len() >= MAX_ROWS_IN_MEMORY {
                        return Err(SqlError::resource("too many groups"));
                    }
                    groups.push((
                        r.clone(),
                        specs.iter().map(new_state).collect(),
                        vec![HashSet::new(); specs.len()],
                    ));
                    index.insert(key, groups.len() - 1);
                    groups.len() - 1
                }
            };
            let g = &mut groups[gi];
            for (k, spec) in specs.iter().enumerate() {
                let v = match &spec.arg {
                    Some(a) => eval(a, &env)?,
                    None => Value::Null,
                };
                if spec.distinct && !v.is_null() && !g.2[k].insert(canon(&v)) {
                    continue;
                }
                agg_update(&mut g.1[k], v)?;
            }
        }
        if groups.is_empty() && group_by.is_empty() {
            // Aggregates over an empty input still produce one row (COUNT = 0, SUM = NULL).
            groups.push((
                vec![Value::Null; width],
                specs.iter().map(new_state).collect(),
                vec![],
            ));
        }
        let mut cols = comb.cols.clone();
        for k in 0..specs.len() {
            cols.push(col_named(format!("#a{k}"), ColType::Text));
        }
        let ext = synthetic(cols);
        let mut out = Vec::with_capacity(groups.len());
        for (first, states, _) in groups {
            let mut row = first;
            for (st, spec) in states.into_iter().zip(&specs) {
                row.push(agg_final(st, spec)?);
            }
            out.push(row);
        }
        if let Some(h) = &having {
            let mut kept = Vec::with_capacity(out.len());
            for r in out {
                if matches(
                    Some(h),
                    &Env {
                        t: Some(&ext),
                        row: &r,
                        now,
                    },
                )? {
                    kept.push(r);
                }
            }
            out = kept;
        }
        (out, ext)
    } else {
        if having.is_some() {
            let mut e = SqlError::internal("HAVING needs GROUP BY or an aggregate");
            e.code = 1463;
            return Err(e);
        }
        (rows, comb)
    };
    // Projection plan + metadata.
    enum P {
        Col(usize),
        Expr(Expr),
    }
    let mut proj: Vec<P> = Vec::new();
    let mut columns: Vec<ColumnMeta> = Vec::new();
    for it in &items {
        match it {
            SelectItem::Star => {
                for (i, (n, ty)) in names.iter().enumerate() {
                    proj.push(P::Col(i));
                    columns.push(ColumnMeta {
                        name: n.clone(),
                        ty: Some(*ty),
                    });
                }
            }
            SelectItem::TableStar(a) => {
                let src = srcs
                    .iter()
                    .find(|x| x.alias.eq_ignore_ascii_case(a))
                    .ok_or_else(|| SqlError::bad_column(&format!("{a}.*")))?;
                for (i, c) in src.t.cols.iter().enumerate() {
                    proj.push(P::Col(src.offset + i));
                    columns.push(ColumnMeta {
                        name: c.name.clone(),
                        ty: Some(c.ty),
                    });
                }
            }
            SelectItem::Expr { expr, alias, text } => {
                let direct = match expr {
                    Expr::Col(n) => n.strip_prefix('#').and_then(|v| v.parse::<usize>().ok()),
                    _ => None,
                };
                match direct {
                    Some(g) if g < names.len() => {
                        proj.push(P::Col(g));
                        columns.push(ColumnMeta {
                            name: alias.clone().unwrap_or_else(|| names[g].0.clone()),
                            ty: Some(names[g].1),
                        });
                    }
                    _ => {
                        proj.push(P::Expr(expr.clone()));
                        columns.push(ColumnMeta {
                            name: alias.clone().unwrap_or_else(|| text.clone()),
                            ty: None,
                        });
                    }
                }
            }
        }
    }
    // ORDER BY on the (extended) rows, then project.
    let mut keyed: Vec<(Vec<Value>, Vec<Value>)> = Vec::with_capacity(rows.len());
    for r in rows {
        let env = Env {
            t: Some(&table),
            row: &r,
            now,
        };
        let k: Vec<Value> = order_by
            .iter()
            .map(|o| eval(&o.expr, &env))
            .collect::<Result<_>>()?;
        let p: Vec<Value> = proj
            .iter()
            .map(|x| match x {
                P::Col(i) => Ok(r.get(*i).cloned().unwrap_or(Value::Null)),
                P::Expr(e) => eval(e, &env),
            })
            .collect::<Result<_>>()?;
        keyed.push((k, p));
    }
    if !order_by.is_empty() {
        keyed.sort_by(|a, b| {
            for (i, o) in order_by.iter().enumerate() {
                let c = sort_cmp(&a.0[i], &b.0[i]);
                let c = if o.desc { c.reverse() } else { c };
                if c != Ordering::Equal {
                    return c;
                }
            }
            Ordering::Equal
        });
    }
    let mut out: Vec<Vec<Value>> = keyed.into_iter().map(|(_, p)| p).collect();
    if s.distinct {
        let mut seen = HashSet::new();
        out.retain(|r| seen.insert(r.iter().map(canon).collect::<Vec<_>>()));
    }
    let off = usize::try_from(s.offset).unwrap_or(usize::MAX);
    let mut out: Vec<Vec<Value>> = out.into_iter().skip(off).collect();
    if let Some(l) = s.limit {
        out.truncate(usize::try_from(l).unwrap_or(usize::MAX));
    }
    Ok(QueryResult {
        columns,
        rows: out,
        ..Default::default()
    })
}
