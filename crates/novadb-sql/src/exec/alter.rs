//! ALTER TABLE.
//!
//! * **Instant** (catalog only, O(1)): rename table/column/index, SET/DROP DEFAULT, DROP INDEX,
//!   ADD a nullable column without default at the end, relax NOT NULL, widen VARCHAR / INT→BIGINT
//!   on columns that are not part of a key.
//! * **Online rebuild** (everything else, primary key unchanged): rows are copied in batches
//!   into a hidden shadow table; changes committed meanwhile are recorded (by primary key) and
//!   re-applied; a short final step re-applies the last changes and swaps the catalog entry.
//!   Between steps the engine lock is released (see `Engine::alter_step`), so readers and
//!   writers keep working. The swap needs a moment with no open transactions (≤ 50 s wait).
//! * **Blocking rebuild**: when the primary key changes, or inside a transaction (transactional
//!   DDL), the copy happens in one storage transaction.
//!
//! Shadow tables live under catalog key `s\0<id>`; a crash mid-ALTER leaves one behind, which
//! `Engine::cleanup_shadows` removes at open.

use std::collections::BTreeSet;
use std::ops::Bound;
use std::time::{Duration, Instant};

use super::*;

/// Rows copied / changes re-applied per online step.
const STEP_ROWS: usize = 1000;
/// How long the final swap waits for open transactions to finish.
const SWAP_WAIT: Duration = Duration::from_secs(50);

pub(super) fn shadow_key(id: u64) -> Vec<u8> {
    let mut k = b"s\0".to_vec();
    k.extend_from_slice(&id.to_be_bytes());
    k
}

/// Where a column of the new table gets its value.
#[derive(Debug, Clone)]
enum Src {
    Old(usize),
    Default,
}

#[derive(Debug, Clone)]
struct DraftCol {
    def: ColumnDef,
    src: Option<usize>,
}

/// Result of planning an ALTER.
pub(super) enum Plan {
    /// New schema replaces the old one in place (same id, same trees).
    Instant {
        new: Table,
        dropped: Vec<Index>,
    },
    Rebuild(Box<Rebuild>),
}

pub(super) struct Rebuild {
    old: Table,
    /// New schema (id assigned when the shadow is created).
    new: Table,
    map: Vec<Src>,
    /// Primary key unchanged: shadow rows keep their keys (needed for online mode).
    same_pk: bool,
    now: i64,
}

/// A running online ALTER.
pub(super) struct Job {
    pub(super) conn: u32,
    /// Old table name (changes are recorded under it).
    pub(super) table: String,
    rb: Rebuild,
    shadow: Table,
    /// Last primary key copied; None = not started; Some(empty) never happens.
    cursor: Option<Vec<u8>>,
    copied_all: bool,
    pub(super) dirty: BTreeSet<Vec<u8>>,
    swap_wait_since: Option<Instant>,
    stmt_text: Option<String>,
    rows: u64,
}

fn col_type_widens(old: ColType, new: ColType) -> bool {
    old == new
        || matches!((old, new), (ColType::Varchar(a), ColType::Varchar(b)) if b >= a)
        || matches!((old, new), (ColType::Int, ColType::BigInt))
}

fn find_col(cols: &[DraftCol], n: &str) -> Result<usize> {
    cols.iter()
        .position(|c| c.def.name.eq_ignore_ascii_case(n))
        .ok_or_else(|| SqlError::bad_column(n))
}

fn rename_refs(pk: &mut [String], ixs: &mut [IndexDef], old: &str, new: &str) {
    for c in pk
        .iter_mut()
        .chain(ixs.iter_mut().flat_map(|i| i.cols.iter_mut()))
    {
        if c.eq_ignore_ascii_case(old) {
            *c = new.to_string();
        }
    }
}

fn place(cols: &mut Vec<DraftCol>, c: DraftCol, pos: &ColPos, at: usize) -> Result<()> {
    let i = match pos {
        ColPos::Keep => at.min(cols.len()),
        ColPos::First => 0,
        ColPos::After(a) => find_col(cols, a)? + 1,
    };
    cols.insert(i, c);
    Ok(())
}

/// Apply `actions` to `old` and decide how to carry them out.
pub(super) fn plan(
    tx: &mut Tx<'_>,
    old: &Table,
    actions: &[AlterAction],
    now: i64,
) -> Result<Plan> {
    let mut name = old.name.clone();
    let mut cols: Vec<DraftCol> = old
        .cols
        .iter()
        .enumerate()
        .map(|(i, c)| DraftCol {
            def: ColumnDef {
                name: c.name.clone(),
                ty: c.ty,
                nullable: c.nullable,
                default: c.default.clone(),
                auto_inc: c.auto_inc,
                primary: false,
                unique: false,
            },
            src: Some(i),
        })
        .collect();
    let mut pk: Vec<String> = old.pk.iter().map(|&i| old.cols[i].name.clone()).collect();
    // (index def, id of the old index it came from)
    let mut ixs: Vec<IndexDef> = Vec::new();
    let mut ix_src: Vec<Option<u32>> = Vec::new();
    for ix in &old.indexes {
        ixs.push(IndexDef {
            name: Some(ix.name.clone()),
            cols: ix.cols.iter().map(|&i| old.cols[i].name.clone()).collect(),
            unique: ix.unique,
        });
        ix_src.push(Some(ix.id));
    }
    let auto_ix_name = |ixs: &[IndexDef], base: &str| {
        let mut n = base.to_string();
        let mut k = 2;
        while ixs.iter().any(|i| {
            i.name
                .as_deref()
                .is_some_and(|x| x.eq_ignore_ascii_case(&n))
        }) {
            n = format!("{base}_{k}");
            k += 1;
        }
        n
    };
    for a in actions {
        match a {
            AlterAction::AddColumn { def, pos } => {
                if find_col(&cols, &def.name).is_ok() {
                    return Err(SqlError::dup_column(&def.name));
                }
                if def.auto_inc {
                    return Err(SqlError::unsupported(
                        "adding an AUTO_INCREMENT column with ALTER TABLE (create a new table and INSERT … SELECT)",
                    ));
                }
                let mut d = def.clone();
                if d.primary {
                    if !pk.is_empty() {
                        return Err(SqlError::multiple_pk());
                    }
                    pk = vec![d.name.clone()];
                }
                if d.unique {
                    let n = auto_ix_name(&ixs, &d.name);
                    ixs.push(IndexDef {
                        name: Some(n),
                        cols: vec![d.name.clone()],
                        unique: true,
                    });
                    ix_src.push(None);
                }
                d.primary = false;
                d.unique = false;
                let at = cols.len();
                place(&mut cols, DraftCol { def: d, src: None }, pos, at)?;
            }
            AlterAction::DropColumn(c) => {
                let i = find_col(&cols, c)?;
                if cols.len() == 1 {
                    return Err(SqlError::unsupported(
                        "dropping the only column (use DROP TABLE)",
                    ));
                }
                cols.remove(i);
                pk.retain(|x| !x.eq_ignore_ascii_case(c));
                for ix in &mut ixs {
                    ix.cols.retain(|x| !x.eq_ignore_ascii_case(c));
                }
                let mut k = 0;
                while k < ixs.len() {
                    if ixs[k].cols.is_empty() {
                        ixs.remove(k);
                        ix_src.remove(k);
                    } else {
                        k += 1;
                    }
                }
            }
            AlterAction::ModifyColumn { old: o, def, pos } => {
                let i = find_col(&cols, o)?;
                if !def.name.eq_ignore_ascii_case(o) && find_col(&cols, &def.name).is_ok() {
                    return Err(SqlError::dup_column(&def.name));
                }
                let mut c = cols.remove(i);
                let was_ai = c.def.auto_inc;
                c.def = def.clone();
                if def.auto_inc && !was_ai {
                    return Err(SqlError::unsupported(
                        "making an existing column AUTO_INCREMENT",
                    ));
                }
                if def.primary {
                    if !pk.is_empty() {
                        return Err(SqlError::multiple_pk());
                    }
                    pk = vec![def.name.clone()];
                }
                if def.unique {
                    let n = auto_ix_name(&ixs, &def.name);
                    ixs.push(IndexDef {
                        name: Some(n),
                        cols: vec![def.name.clone()],
                        unique: true,
                    });
                    ix_src.push(None);
                }
                c.def.primary = false;
                c.def.unique = false;
                rename_refs(&mut pk, &mut ixs, o, &def.name);
                place(&mut cols, c, pos, i)?;
            }
            AlterAction::RenameColumn { old: o, new } => {
                let i = find_col(&cols, o)?;
                if !new.eq_ignore_ascii_case(o) && find_col(&cols, new).is_ok() {
                    return Err(SqlError::dup_column(new));
                }
                cols[i].def.name = new.clone();
                rename_refs(&mut pk, &mut ixs, o, new);
            }
            AlterAction::SetDefault { col, default } => {
                let i = find_col(&cols, col)?;
                cols[i].def.default = default.clone();
            }
            AlterAction::AddIndex(d) => {
                let mut d = d.clone();
                if d.name.is_none() {
                    let base = d.cols.first().cloned().unwrap_or_default();
                    d.name = Some(auto_ix_name(&ixs, &base));
                }
                ixs.push(d);
                ix_src.push(None);
            }
            AlterAction::DropIndex(n) if n.eq_ignore_ascii_case("primary") => {
                if pk.is_empty() {
                    return Err(SqlError::no_key("PRIMARY"));
                }
                pk.clear();
            }
            AlterAction::DropIndex(n) => {
                let k = ixs
                    .iter()
                    .position(|i| i.name.as_deref().is_some_and(|x| x.eq_ignore_ascii_case(n)))
                    .ok_or_else(|| SqlError::no_key(n))?;
                ixs.remove(k);
                ix_src.remove(k);
            }
            AlterAction::RenameIndex { old: o, new } => {
                let k = ixs
                    .iter()
                    .position(|i| i.name.as_deref().is_some_and(|x| x.eq_ignore_ascii_case(o)))
                    .ok_or_else(|| SqlError::no_key(o))?;
                ixs[k].name = Some(new.clone());
            }
            AlterAction::AddPrimaryKey(c) => {
                if !pk.is_empty() {
                    return Err(SqlError::multiple_pk());
                }
                pk = c.clone();
            }
            AlterAction::DropPrimaryKey => {
                if pk.is_empty() {
                    return Err(SqlError::no_key("PRIMARY"));
                }
                pk.clear();
            }
            AlterAction::RenameTable(n) => {
                valid_name(n)?;
                if !n.eq_ignore_ascii_case(&old.name) && find_table(tx, n)?.is_some() {
                    return Err(SqlError::table_exists(n));
                }
                name = n.clone();
            }
        }
    }
    // Validate the result exactly like CREATE TABLE would.
    let ct = CreateTable {
        name: name.clone(),
        if_not_exists: false,
        cols: cols.iter().map(|c| c.def.clone()).collect(),
        pk: if pk.is_empty() { None } else { Some(pk) },
        indexes: ixs.clone(),
    };
    let mut new = build_table(&ct)?;
    let map: Vec<Src> = cols
        .iter()
        .map(|c| c.src.map_or(Src::Default, Src::Old))
        .collect();
    let same_pk = new.pk.len() == old.pk.len()
        && new.pk.iter().zip(&old.pk).all(|(&n, &o)| {
            matches!(map[n], Src::Old(x) if x == o) && new.cols[n].ty == old.cols[o].ty
        });

    // ---- instant? ----
    let in_key =
        |t: &Table, c: usize| t.pk.contains(&c) || t.indexes.iter().any(|i| i.cols.contains(&c));
    let mut instant = same_pk && new.cols.len() >= old.cols.len();
    if instant {
        for (i, oc) in old.cols.iter().enumerate() {
            let nc = &new.cols[i];
            let ok = matches!(map[i], Src::Old(x) if x == i)
                && nc.auto_inc == oc.auto_inc
                && (nc.nullable || !oc.nullable)
                && (nc.ty == oc.ty || (col_type_widens(oc.ty, nc.ty) && !in_key(old, i)));
            if !ok {
                instant = false;
                break;
            }
        }
        for nc in &new.cols[old.cols.len()..] {
            if !nc.nullable || !matches!(nc.default, None | Some(DefaultExpr::Value(Value::Null))) {
                instant = false;
            }
        }
    }
    // Every new index must be an old one (same columns + uniqueness), possibly renamed.
    let mut kept_ids = Vec::new();
    if instant {
        for (k, nix) in new.indexes.iter_mut().enumerate() {
            let Some(oid) = ix_src[k] else {
                instant = false;
                break;
            };
            let Some(oix) = old.indexes.iter().find(|i| i.id == oid) else {
                instant = false;
                break;
            };
            if oix.cols != nix.cols || oix.unique != nix.unique {
                instant = false;
                break;
            }
            nix.id = oid;
            kept_ids.push(oid);
        }
    }
    if instant {
        new.id = old.id;
        new.next_index_id = old.next_index_id;
        let dropped = old
            .indexes
            .iter()
            .filter(|i| !kept_ids.contains(&i.id))
            .cloned()
            .collect();
        return Ok(Plan::Instant { new, dropped });
    }
    Ok(Plan::Rebuild(Box::new(Rebuild {
        old: old.clone(),
        new,
        map,
        same_pk,
        now,
    })))
}

/// Carry out an instant plan.
pub(super) fn apply_instant(
    tx: &mut Tx<'_>,
    old: &Table,
    new: &Table,
    dropped: &[Index],
) -> Result<()> {
    for ix in dropped {
        tx.drop_tree(&old.index_tree(ix))?;
    }
    let c = catalog(tx)?;
    tx.delete(&c, &table_key(&old.name))?;
    save_table(tx, new)?;
    Ok(())
}

impl Rebuild {
    /// Row of the new table from a row of the old one.
    fn convert(&self, row: &[Value]) -> Result<Vec<Value>> {
        let mut out = Vec::with_capacity(self.new.cols.len());
        for (i, c) in self.new.cols.iter().enumerate() {
            let v = match &self.map[i] {
                Src::Old(o) => {
                    let v = row.get(*o).cloned().unwrap_or(Value::Null);
                    if self.old.cols[*o].ty == c.ty {
                        v
                    } else {
                        coerce(v, c.ty, &c.name)?
                    }
                }
                Src::Default => match &c.default {
                    Some(DefaultExpr::Value(v)) => v.clone(),
                    Some(DefaultExpr::Now) => Value::DateTime(trunc_fsp(
                        self.now,
                        match c.ty {
                            ColType::DateTime(f) => f,
                            _ => 0,
                        },
                    )),
                    None if c.nullable => Value::Null,
                    None => default_for(c.ty),
                },
            };
            if v.is_null() && !c.nullable {
                return Err(SqlError::not_null(&c.name));
            }
            out.push(v);
        }
        Ok(out)
    }
}

/// MySQL's implicit default for a NOT NULL column without DEFAULT added to existing rows.
fn default_for(ty: ColType) -> Value {
    match ty {
        ColType::Int | ColType::BigInt => Value::Int(0),
        ColType::Decimal { s, .. } => Value::Dec { v: 0, s },
        ColType::DateTime(_) => Value::DateTime(0),
        _ => Value::Str(String::new()),
    }
}

/// Create the hidden shadow table (new id, empty trees).
fn create_shadow(tx: &mut Tx<'_>, rb: &Rebuild) -> Result<Table> {
    let mut sh = rb.new.clone();
    sh.id = read_counter(tx, b"n", 1)?;
    write_counter(tx, b"n", sh.id + 1)?;
    tx.create_tree(&sh.rows_tree())?;
    tx.create_tree(&sh.overflow_tree())?;
    for ix in &sh.indexes {
        tx.create_tree(&sh.index_tree(ix))?;
    }
    let c = catalog(tx)?;
    tx.put(&c, &shadow_key(sh.id), &sh.encode())?;
    Ok(sh)
}

fn drop_trees(tx: &mut Tx<'_>, t: &Table) -> Result<()> {
    for n in std::iter::once(t.rows_tree())
        .chain(std::iter::once(t.overflow_tree()))
        .chain(t.indexes.iter().map(|i| t.index_tree(i)))
    {
        match tx.drop_tree(&n) {
            Ok(()) | Err(novadb_storage::Error::TreeNotFound(_)) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Remove a shadow table (abort / crash cleanup).
pub(super) fn drop_shadow(tx: &mut Tx<'_>, sh: &Table) -> Result<()> {
    drop_trees(tx, sh)?;
    let c = catalog(tx)?;
    tx.delete(&c, &shadow_key(sh.id))?;
    tx.delete(&c, &counter_key(sh.id))?;
    tx.delete(&c, &rowid_key(sh.id))?;
    Ok(())
}

/// Make the shadow row for old primary key `pk` match the old table's current row.
fn sync_key(
    mv: &mut Mv<'_, '_>,
    rb: &Rebuild,
    otr: &Trees,
    sh: &Table,
    str_: &Trees,
    pk: &[u8],
) -> Result<()> {
    let cur = get_row(mv, otr, pk, rb.old.cols.len())?;
    if let Some(prev) = get_row(mv, str_, pk, sh.cols.len())? {
        index_delete(mv, sh, str_, &prev, pk)?;
        if cur.is_none() {
            del_row(mv, str_, pk)?;
        }
    }
    if let Some(row) = cur {
        let new = rb.convert(&row)?;
        index_insert(mv, sh, str_, &new, pk)?;
        put_row(mv, str_, pk, &new)?;
    }
    Ok(())
}

/// Copy every row in one go (blocking mode; primary key may change).
fn copy_all(mv: &mut Mv<'_, '_>, rb: &Rebuild, sh: &Table) -> Result<u64> {
    let otr = open_trees(mv.tx, &rb.old)?;
    let str_ = open_trees(mv.tx, sh)?;
    let mut rows = Vec::new();
    scan(mv, &rb.old, &otr, &Access::Full, None, 0, |pk, row| {
        rows.push((pk, row));
        if rows.len() > MAX_ROWS_IN_MEMORY {
            return Err(SqlError::resource(
                "table too large to rebuild inside a transaction / while changing the primary key",
            ));
        }
        Ok(true)
    })?;
    let n = rows.len() as u64;
    for (pk, row) in rows {
        let new = rb.convert(&row)?;
        if rb.same_pk {
            index_insert(mv, sh, &str_, &new, &pk)?;
            put_row(mv, &str_, &pk, &new)?;
        } else {
            insert_row(mv, sh, &str_, &new)?;
        }
    }
    Ok(n)
}

/// Swap the shadow in: catalog entry, counters, old trees dropped.
fn swap(tx: &mut Tx<'_>, rb: &Rebuild, sh: &Table) -> Result<()> {
    let c = catalog(tx)?;
    let old = &rb.old;
    // AUTO_INCREMENT counter follows the column; hidden row ids keep counting.
    if let Some(v) = tx.get(&c, &counter_key(old.id))?
        && sh.auto_inc_col().is_some()
    {
        tx.put(&c, &counter_key(sh.id), &v)?;
    }
    if rb.same_pk
        && sh.pk.is_empty()
        && let Some(v) = tx.get(&c, &rowid_key(old.id))?
    {
        tx.put(&c, &rowid_key(sh.id), &v)?;
    }
    drop_trees(tx, old)?;
    tx.delete(&c, &table_key(&old.name))?;
    tx.delete(&c, &counter_key(old.id))?;
    tx.delete(&c, &rowid_key(old.id))?;
    tx.delete(&c, &shadow_key(sh.id))?;
    save_table(tx, sh)?;
    Ok(())
}

/// Re-executable text of an ALTER (binlog).
pub(super) fn alter_text(name: &str, actions: &[AlterAction]) -> String {
    let coldef = |d: &ColumnDef| {
        let mut l = format!("{} {}", quote(&d.name), d.ty.sql());
        if !d.nullable {
            l.push_str(" NOT NULL");
        }
        match &d.default {
            Some(DefaultExpr::Now) => l.push_str(" DEFAULT CURRENT_TIMESTAMP"),
            Some(DefaultExpr::Value(v)) => l.push_str(&format!(" DEFAULT {}", sql_literal(v))),
            None => {}
        }
        if d.auto_inc {
            l.push_str(" AUTO_INCREMENT");
        }
        if d.primary {
            l.push_str(" PRIMARY KEY");
        }
        if d.unique {
            l.push_str(" UNIQUE");
        }
        l
    };
    let pos = |p: &ColPos| match p {
        ColPos::Keep => String::new(),
        ColPos::First => " FIRST".into(),
        ColPos::After(a) => format!(" AFTER {}", quote(a)),
    };
    let list = |v: &[String]| v.iter().map(|c| quote(c)).collect::<Vec<_>>().join(", ");
    let parts: Vec<String> = actions
        .iter()
        .map(|a| match a {
            AlterAction::AddColumn { def, pos: p } => {
                format!("ADD COLUMN {}{}", coldef(def), pos(p))
            }
            AlterAction::DropColumn(c) => format!("DROP COLUMN {}", quote(c)),
            AlterAction::ModifyColumn { old, def, pos: p } => {
                format!("CHANGE COLUMN {} {}{}", quote(old), coldef(def), pos(p))
            }
            AlterAction::RenameColumn { old, new } => {
                format!("RENAME COLUMN {} TO {}", quote(old), quote(new))
            }
            AlterAction::SetDefault { col, default } => match default {
                None => format!("ALTER COLUMN {} DROP DEFAULT", quote(col)),
                Some(DefaultExpr::Now) => {
                    format!("ALTER COLUMN {} SET DEFAULT CURRENT_TIMESTAMP", quote(col))
                }
                Some(DefaultExpr::Value(v)) => {
                    format!("ALTER COLUMN {} SET DEFAULT {}", quote(col), sql_literal(v))
                }
            },
            AlterAction::AddIndex(d) => format!(
                "ADD {}INDEX {}({})",
                if d.unique { "UNIQUE " } else { "" },
                d.name
                    .as_deref()
                    .map(|n| format!("{} ", quote(n)))
                    .unwrap_or_default(),
                list(&d.cols)
            ),
            AlterAction::DropIndex(n) => format!("DROP INDEX {}", quote(n)),
            AlterAction::RenameIndex { old, new } => {
                format!("RENAME INDEX {} TO {}", quote(old), quote(new))
            }
            AlterAction::AddPrimaryKey(c) => format!("ADD PRIMARY KEY ({})", list(c)),
            AlterAction::DropPrimaryKey => "DROP PRIMARY KEY".into(),
            AlterAction::RenameTable(n) => format!("RENAME TO {}", quote(n)),
        })
        .collect();
    format!("ALTER TABLE {} {}", quote(name), parts.join(", "))
}

/// Record changed primary keys of the table being altered.
pub(super) fn note(j: &mut Job, log: &[LogOp]) {
    for op in log {
        match op {
            LogOp::Put { table, key, .. } | LogOp::Del { table, key }
                if table.eq_ignore_ascii_case(&j.table) =>
            {
                j.dirty.insert(key.clone());
            }
            _ => {}
        }
    }
}

impl Engine {
    /// Remove shadow tables left by an ALTER that was interrupted by a crash.
    pub(super) fn cleanup_shadows(&mut self) -> Result<()> {
        let mut tx = self.db.begin()?;
        let r = (|| {
            let c = match tx.open_tree(CATALOG_TREE) {
                Ok(c) => c,
                Err(novadb_storage::Error::TreeNotFound(_)) => return Ok(false),
                Err(e) => return Err(e.into()),
            };
            let lo = b"s\0".to_vec();
            let hi = b"s\x01".to_vec();
            let found: Vec<Vec<u8>> = tx
                .range(
                    &c,
                    (
                        Bound::Included(lo.as_slice()),
                        Bound::Excluded(hi.as_slice()),
                    ),
                )?
                .map(|kv| kv.map(|(_, v)| v))
                .collect::<std::result::Result<_, _>>()?;
            for v in &found {
                let sh = Table::decode(v)?;
                drop_shadow(&mut tx, &sh)?;
            }
            Ok(!found.is_empty())
        })();
        match r {
            Ok(true) => Ok(tx.commit()?),
            Ok(false) => {
                tx.rollback();
                Ok(())
            }
            Err(e) => {
                tx.rollback();
                Err(e)
            }
        }
    }

    /// Is an online ALTER TABLE in progress?
    pub fn alter_running(&self) -> bool {
        self.alter.is_some()
    }

    /// Connection whose online ALTER TABLE is in progress.
    pub fn alter_owner(&self) -> Option<u32> {
        self.alter.as_ref().map(|j| j.conn)
    }

    /// Execute ALTER TABLE. `online`: a rebuild may run as a background job driven by
    /// `alter_step` (returns Ok with `alter_running() == true`).
    pub(super) fn alter_exec(&mut self, s: &Stmt, conn: u32, online: bool) -> Result<QueryResult> {
        let Stmt::AlterTable { name, actions } = s else {
            return Err(SqlError::internal("not ALTER TABLE"));
        };
        let now = (self.clock)();
        let mut tx = self.db.begin()?;
        let planned = (|| {
            let old = load_table(&mut tx, name)?;
            plan(&mut tx, &old, actions, now).map(|p| (old, p))
        })();
        let (old, p) = match planned {
            Ok(x) => x,
            Err(e) => {
                tx.rollback();
                return Err(e);
            }
        };
        match p {
            Plan::Instant { new, dropped } => match apply_instant(&mut tx, &old, &new, &dropped) {
                Ok(()) => {
                    tx.commit()?;
                    self.pending.clear();
                    self.log_alter(name, actions)?;
                    Ok(QueryResult {
                        info: Some("Records: 0  Duplicates: 0  Warnings: 0 (instant)".into()),
                        ..Default::default()
                    })
                }
                Err(e) => {
                    tx.rollback();
                    Err(e)
                }
            },
            Plan::Rebuild(rb) if !online || !rb.same_pk => {
                // One storage transaction: atomic, but holds the engine for the whole copy.
                let mut ws = WriteSet::default();
                let r = (|| {
                    let sh = create_shadow(&mut tx, &rb)?;
                    let cat0 = catalog(&mut tx)?;
                    let snap = mvcc::last_ts(&mut tx, &cat0)?;
                    let n = {
                        let mut mv = Mv {
                            tx: &mut tx,
                            snap,
                            ws: &mut ws,
                        };
                        copy_all(&mut mv, &rb, &sh)?
                    };
                    ws.log.clear();
                    let cat = catalog(&mut tx)?;
                    let snaps: Vec<u64> = self.txns.values().map(|t| t.snap).collect();
                    if !ws.is_empty() {
                        mvcc::commit(&mut tx, &cat, &ws, snap, &snaps, &mut self.pending)?;
                    }
                    swap(&mut tx, &rb, &sh)?;
                    Ok(n)
                })();
                match r {
                    Ok(n) => {
                        tx.commit()?;
                        self.pending.clear();
                        self.log_alter(name, actions)?;
                        Ok(QueryResult {
                            affected: n,
                            info: Some(format!("Records: {n}  Duplicates: 0  Warnings: 0")),
                            ..Default::default()
                        })
                    }
                    Err(e) => {
                        tx.rollback();
                        Err(e)
                    }
                }
            }
            Plan::Rebuild(rb) => {
                let sh = match create_shadow(&mut tx, &rb) {
                    Ok(sh) => sh,
                    Err(e) => {
                        tx.rollback();
                        return Err(e);
                    }
                };
                tx.commit()?;
                self.alter = Some(Job {
                    conn,
                    table: old.name.clone(),
                    rb: *rb,
                    shadow: sh,
                    cursor: None,
                    copied_all: false,
                    dirty: BTreeSet::new(),
                    swap_wait_since: None,
                    stmt_text: Some(alter_text(name, actions)),
                    rows: 0,
                });
                Ok(QueryResult::ok(0))
            }
        }
    }

    fn log_alter(&mut self, name: &str, actions: &[AlterAction]) -> Result<()> {
        if self.binlog.is_some() {
            self.log_now(vec![LogOp::Ddl(alter_text(name, actions))])?;
        }
        Ok(())
    }

    /// Abort the running ALTER (drops the shadow table).
    pub(super) fn alter_abort(&mut self) {
        if let Some(j) = self.alter.take() {
            let _ = self.db.update(|tx| {
                drop_shadow(tx, &j.shadow)
                    .map_err(|e| novadb_storage::Error::Corruption(e.to_string()))
            });
            self.pending.clear();
        }
    }

    /// Run one step of the online ALTER. `Ok(None)` = call again (release the engine lock in
    /// between so other sessions run); `Ok(Some(result))` = finished. On error the ALTER is
    /// rolled back (shadow dropped) and the table is unchanged.
    pub fn alter_step(&mut self) -> Result<Option<QueryResult>> {
        if self.alter.is_none() {
            return Err(SqlError::internal("no ALTER TABLE is running"));
        }
        let r = self.alter_step_inner();
        if r.is_err() {
            self.alter_abort();
        }
        r
    }

    fn alter_step_inner(&mut self) -> Result<Option<QueryResult>> {
        check_interrupt()?;
        let mut job = self
            .alter
            .take()
            .ok_or_else(|| SqlError::internal("no ALTER"))?;
        let r = self.alter_work(&mut job);
        let done = matches!(r, Ok(Some(_)));
        if !done {
            // keep the job (also on error, so alter_abort can drop the shadow)
            self.alter = Some(job);
        }
        r
    }

    fn alter_work(&mut self, job: &mut Job) -> Result<Option<QueryResult>> {
        // Ready to swap? Needs the copy done, few pending changes and no open transaction
        // (their write sets point at the old trees).
        let ready = job.copied_all && job.dirty.len() <= STEP_ROWS;
        if ready && !self.txns.is_empty() {
            let since = *job.swap_wait_since.get_or_insert_with(Instant::now);
            if since.elapsed() > SWAP_WAIT {
                let mut e = SqlError::internal(
                    "Lock wait timeout exceeded; ALTER TABLE waited 50 s for open transactions to finish (table unchanged)",
                );
                e.code = 1205;
                return Err(e);
            }
            return Ok(None);
        }
        let snaps: Vec<u64> = self.txns.values().map(|t| t.snap).collect();
        let mut tx = self.db.begin()?;
        let mut ws = WriteSet::default();
        let r = (|| {
            let cat = catalog(&mut tx)?;
            let snap = mvcc::last_ts(&mut tx, &cat)?;
            let otr = open_trees(&mut tx, &job.rb.old)?;
            let str_ = open_trees(&mut tx, &job.shadow)?;
            {
                let mut mv = Mv {
                    tx: &mut tx,
                    snap,
                    ws: &mut ws,
                };
                if !job.copied_all {
                    let lo = match &job.cursor {
                        None => Bound::Unbounded,
                        Some(k) => Bound::Excluded(k.clone()),
                    };
                    let batch = mv.scan(&otr.rows, &lo, &Bound::Unbounded, STEP_ROWS)?;
                    if batch.len() < STEP_ROWS {
                        job.copied_all = true;
                    }
                    for (pk, _) in &batch {
                        sync_key(&mut mv, &job.rb, &otr, &job.shadow, &str_, pk)?;
                        job.rows += 1;
                    }
                    if let Some((k, _)) = batch.last() {
                        job.cursor = Some(k.clone());
                    }
                } else {
                    let keys: Vec<Vec<u8>> = job.dirty.iter().take(STEP_ROWS).cloned().collect();
                    for k in &keys {
                        job.dirty.remove(k);
                        sync_key(&mut mv, &job.rb, &otr, &job.shadow, &str_, k)?;
                    }
                }
            }
            ws.log.clear();
            if !ws.is_empty() {
                mvcc::commit(&mut tx, &cat, &ws, snap, &snaps, &mut self.pending)?;
            }
            let finish = ready && job.dirty.is_empty();
            if finish {
                swap(&mut tx, &job.rb, &job.shadow)?;
            }
            Ok(finish)
        })();
        match r {
            Ok(finish) => {
                tx.commit()?;
                if !finish {
                    return Ok(None);
                }
                self.pending.clear();
                if let Some(text) = job.stmt_text.take()
                    && self.binlog.is_some()
                {
                    self.log_now(vec![LogOp::Ddl(text)])?;
                }
                let n = job.rows;
                Ok(Some(QueryResult {
                    affected: n,
                    info: Some(format!("Records: {n}  Duplicates: 0  Warnings: 0 (online)")),
                    ..Default::default()
                }))
            }
            Err(e) => {
                tx.rollback();
                Err(e)
            }
        }
    }
}
