//! Table schemas, stored in the `sql:catalog` tree.
//!
//! Keys: `t\0<lowercase name>` → schema, `n` → next table id, `a\0<id>` → auto-increment /
//! hidden row-id counter. Table data lives in trees named by table id, so names never need
//! escaping: `sql:t:<id>` rows, `sql:o:<id>` row overflow chunks, `sql:i:<id>:<index id>`.

use crate::ast::DefaultExpr;
use crate::codec::{R, W};
use crate::error::{Result, SqlError};
use crate::value::{ColType, MAX_DECIMAL_PRECISION, Value};

pub const CATALOG_TREE: &str = "sql:catalog";
pub const MAX_COLUMNS: usize = 1024;
pub const MAX_INDEXES: usize = 64;
const SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq)]
pub struct Column {
    pub name: String,
    pub ty: ColType,
    pub nullable: bool,
    pub default: Option<DefaultExpr>,
    pub auto_inc: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Index {
    pub id: u32,
    pub name: String,
    pub cols: Vec<usize>,
    pub unique: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Table {
    pub id: u64,
    pub name: String,
    pub cols: Vec<Column>,
    /// Primary key column positions; empty = hidden row id.
    pub pk: Vec<usize>,
    pub indexes: Vec<Index>,
    pub next_index_id: u32,
}

pub fn table_key(name: &str) -> Vec<u8> {
    let mut k = b"t\0".to_vec();
    k.extend_from_slice(name.to_lowercase().as_bytes());
    k
}

pub fn counter_key(id: u64) -> Vec<u8> {
    let mut k = b"a\0".to_vec();
    k.extend_from_slice(&id.to_be_bytes());
    k
}

impl Table {
    pub fn rows_tree(&self) -> String {
        format!("sql:t:{}", self.id)
    }
    pub fn overflow_tree(&self) -> String {
        format!("sql:o:{}", self.id)
    }
    pub fn index_tree(&self, ix: &Index) -> String {
        format!("sql:i:{}:{}", self.id, ix.id)
    }
    pub fn col(&self, name: &str) -> Option<usize> {
        self.cols
            .iter()
            .position(|c| c.name.eq_ignore_ascii_case(name))
    }
    pub fn auto_inc_col(&self) -> Option<usize> {
        self.cols.iter().position(|c| c.auto_inc)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = W(Vec::new());
        w.u8(SCHEMA_VERSION);
        w.u64(self.id);
        w.str(&self.name);
        w.u32(self.cols.len() as u32);
        for c in &self.cols {
            w.str(&c.name);
            encode_type(&mut w, c.ty);
            w.u8(u8::from(c.nullable) | (u8::from(c.auto_inc) << 1));
            match &c.default {
                None => w.u8(0),
                Some(DefaultExpr::Now) => w.u8(1),
                Some(DefaultExpr::Value(v)) => {
                    w.u8(2);
                    w.bytes(&crate::codec::row_encode(std::slice::from_ref(v)).unwrap_or_default());
                }
            }
        }
        w.u32(self.pk.len() as u32);
        for &p in &self.pk {
            w.u32(p as u32);
        }
        w.u32(self.indexes.len() as u32);
        for ix in &self.indexes {
            w.u32(ix.id);
            w.str(&ix.name);
            w.u8(u8::from(ix.unique));
            w.u32(ix.cols.len() as u32);
            for &c in &ix.cols {
                w.u32(c as u32);
            }
        }
        w.u32(self.next_index_id);
        w.0
    }

    pub fn decode(b: &[u8]) -> Result<Table> {
        let mut r = R::new(b);
        if r.u8()? != SCHEMA_VERSION {
            return Err(SqlError::corrupt("catalog: unknown schema version"));
        }
        let id = r.u64()?;
        let name = r.str()?;
        let ncols = r.u32()? as usize;
        if ncols == 0 || ncols > MAX_COLUMNS {
            return Err(SqlError::corrupt("catalog: bad column count"));
        }
        let mut cols = Vec::with_capacity(ncols);
        for _ in 0..ncols {
            let cname = r.str()?;
            let ty = decode_type(&mut r)?;
            let flags = r.u8()?;
            let default = match r.u8()? {
                0 => None,
                1 => Some(DefaultExpr::Now),
                2 => {
                    let b = r.bytes()?;
                    let mut v = crate::codec::row_decode(&b, 1)?;
                    Some(DefaultExpr::Value(v.pop().unwrap_or(Value::Null)))
                }
                _ => return Err(SqlError::corrupt("catalog: bad default tag")),
            };
            cols.push(Column {
                name: cname,
                ty,
                nullable: flags & 1 != 0,
                default,
                auto_inc: flags & 2 != 0,
            });
        }
        let npk = r.u32()? as usize;
        if npk > ncols {
            return Err(SqlError::corrupt("catalog: bad primary key"));
        }
        let mut pk = Vec::with_capacity(npk);
        for _ in 0..npk {
            let p = r.u32()? as usize;
            if p >= ncols {
                return Err(SqlError::corrupt(
                    "catalog: primary key column out of range",
                ));
            }
            pk.push(p);
        }
        let nix = r.u32()? as usize;
        if nix > MAX_INDEXES {
            return Err(SqlError::corrupt("catalog: too many indexes"));
        }
        let mut indexes = Vec::with_capacity(nix);
        for _ in 0..nix {
            let iid = r.u32()?;
            let iname = r.str()?;
            let unique = r.u8()? != 0;
            let n = r.u32()? as usize;
            if n == 0 || n > ncols {
                return Err(SqlError::corrupt("catalog: bad index column count"));
            }
            let mut ic = Vec::with_capacity(n);
            for _ in 0..n {
                let c = r.u32()? as usize;
                if c >= ncols {
                    return Err(SqlError::corrupt("catalog: index column out of range"));
                }
                ic.push(c);
            }
            indexes.push(Index {
                id: iid,
                name: iname,
                cols: ic,
                unique,
            });
        }
        let next_index_id = r.u32()?;
        if !r.done() {
            return Err(SqlError::corrupt("catalog: trailing bytes"));
        }
        Ok(Table {
            id,
            name,
            cols,
            pk,
            indexes,
            next_index_id,
        })
    }
}

fn encode_type(w: &mut W, t: ColType) {
    match t {
        ColType::Int => w.u8(1),
        ColType::BigInt => w.u8(2),
        ColType::Decimal { p, s } => {
            w.u8(3);
            w.u8(p);
            w.u8(s);
        }
        ColType::Varchar(n) => {
            w.u8(4);
            w.u32(n);
        }
        ColType::Text => w.u8(5),
        ColType::Blob => w.u8(6),
        ColType::DateTime(f) => {
            w.u8(7);
            w.u8(f);
        }
    }
}

fn decode_type(r: &mut R<'_>) -> Result<ColType> {
    Ok(match r.u8()? {
        1 => ColType::Int,
        2 => ColType::BigInt,
        3 => {
            let (p, s) = (r.u8()?, r.u8()?);
            if p == 0 || p > MAX_DECIMAL_PRECISION || s > p {
                return Err(SqlError::corrupt("catalog: bad decimal type"));
            }
            ColType::Decimal { p, s }
        }
        4 => ColType::Varchar(r.u32()?),
        5 => ColType::Text,
        6 => ColType::Blob,
        7 => {
            let f = r.u8()?;
            if f > 6 {
                return Err(SqlError::corrupt("catalog: bad datetime precision"));
            }
            ColType::DateTime(f)
        }
        _ => return Err(SqlError::corrupt("catalog: unknown column type")),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn roundtrip_and_truncation() {
        let t = Table {
            id: 7,
            name: "Users".into(),
            cols: vec![
                Column {
                    name: "id".into(),
                    ty: ColType::BigInt,
                    nullable: false,
                    default: None,
                    auto_inc: true,
                },
                Column {
                    name: "bal".into(),
                    ty: ColType::Decimal { p: 12, s: 2 },
                    nullable: true,
                    default: Some(DefaultExpr::Value(Value::Dec { v: 100, s: 2 })),
                    auto_inc: false,
                },
                Column {
                    name: "at".into(),
                    ty: ColType::DateTime(3),
                    nullable: true,
                    default: Some(DefaultExpr::Now),
                    auto_inc: false,
                },
            ],
            pk: vec![0],
            indexes: vec![Index {
                id: 1,
                name: "b".into(),
                cols: vec![1, 2],
                unique: true,
            }],
            next_index_id: 2,
        };
        let b = t.encode();
        assert_eq!(Table::decode(&b).unwrap(), t);
        for cut in 0..b.len() {
            assert!(Table::decode(&b[..cut]).is_err());
        }
    }
}
