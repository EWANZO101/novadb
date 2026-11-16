//! B+Tree over pages.
//!
//! Nodes are decoded into an owned [`Node`], modified, and re-encoded. This keeps split/merge
//! logic simple and makes every page read go through one validating decoder (fuzzed).
//! Root page ids never change (root splits move the old root's contents into a new child), so
//! the catalog can store tree roots without updating them.
//!
//! Leaf body:     `next u64 ‖ count u16 ‖ (klen u16 ‖ vlen u16 ‖ key ‖ value)*`
//! Internal body: `count u16 ‖ child0 u64 ‖ (klen u16 ‖ key ‖ child u64)*`
//! Child `i` holds keys `k` with `keys[i-1] <= k < keys[i]`.

use crate::error::{Error, Result};
use crate::page::{
    self, BODY_SIZE, HEADER_SIZE, MAX_PAGE_ID, PAGE_SIZE, PageId, PageType, get_u16, get_u64,
};

/// Longest key accepted.
pub const MAX_KEY_LEN: usize = 1024;
/// Longest value accepted (larger values need overflow pages; Stage 3).
pub const MAX_VALUE_LEN: usize = 4096;
/// Maximum tree height. Guards against cycles in corrupt pages.
pub const MAX_DEPTH: usize = 48;

const LEAF_FIXED: usize = 10;
const LEAF_ENTRY: usize = 4;
const INT_FIXED: usize = 10;
const INT_ENTRY: usize = 10;
/// Non-root nodes smaller than this (encoded body bytes) are merged or rebalanced.
const UNDERFLOW: usize = BODY_SIZE / 4;

// Splitting must always succeed. Splitting S item bytes at the midpoint gives halves of at most
// S/2 + E (E = largest entry).
// * Overflow after insert/replace: S <= BODY - FIXED + E  =>  need 3E <= BODY - FIXED.
// * Rebalance: underflowing child (< BODY/4) + sibling (<= BODY) + separator:
//   leaves:    S/2 + E + FIXED <= 5/8 BODY + E_leaf + FIXED <= BODY
//   internals: S/2 + E + FIXED <= 5/8 BODY + E_int/2 + E_int + FIXED <= BODY
const MAX_LEAF_ENTRY: usize = LEAF_ENTRY + MAX_KEY_LEN + MAX_VALUE_LEN;
const MAX_INT_ENTRY: usize = INT_ENTRY + MAX_KEY_LEN;
const _: () = assert!(3 * MAX_LEAF_ENTRY <= BODY_SIZE - LEAF_FIXED);
const _: () = assert!(BODY_SIZE * 5 / 8 + MAX_LEAF_ENTRY + LEAF_FIXED <= BODY_SIZE);
const _: () = assert!(BODY_SIZE * 5 / 8 + 2 * MAX_INT_ENTRY + INT_FIXED <= BODY_SIZE);
const _: () = assert!(UNDERFLOW <= BODY_SIZE / 4);
const _: () = assert!(PAGE_SIZE <= u16::MAX as usize + 1);

/// Decoded B+Tree node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// Leaf: sorted unique entries + right-sibling link (0 = none).
    Leaf {
        /// Next leaf in key order (0 = none).
        next: PageId,
        /// Sorted key/value pairs.
        entries: Vec<(Vec<u8>, Vec<u8>)>,
    },
    /// Internal node: `children.len() == keys.len() + 1`.
    Internal {
        /// Separator keys (sorted).
        keys: Vec<Vec<u8>>,
        /// Child page ids.
        children: Vec<PageId>,
    },
}

fn leaf_size(entries: &[(Vec<u8>, Vec<u8>)]) -> usize {
    LEAF_FIXED
        + entries
            .iter()
            .map(|(k, v)| LEAF_ENTRY + k.len() + v.len())
            .sum::<usize>()
}

fn internal_size(keys: &[Vec<u8>]) -> usize {
    INT_FIXED + keys.iter().map(|k| INT_ENTRY + k.len()).sum::<usize>()
}

impl Node {
    /// Empty leaf.
    pub fn empty_leaf() -> Self {
        Node::Leaf {
            next: 0,
            entries: Vec::new(),
        }
    }

    /// Encoded body size in bytes.
    pub fn size(&self) -> usize {
        match self {
            Node::Leaf { entries, .. } => leaf_size(entries),
            Node::Internal { keys, .. } => internal_size(keys),
        }
    }

    /// Encode into `page` (header id/LSN preserved, type byte set, body rewritten).
    pub fn encode_into(&self, p: &mut [u8; PAGE_SIZE]) -> Result<()> {
        if self.size() > BODY_SIZE {
            return Err(Error::corrupt("internal error: node larger than a page"));
        }
        let body = &mut p[HEADER_SIZE..];
        body.fill(0);
        let mut w = 0usize;
        let mut put = |b: &mut [u8], bytes: &[u8]| {
            b[w..w + bytes.len()].copy_from_slice(bytes);
            w += bytes.len();
        };
        match self {
            Node::Leaf { next, entries } => {
                put(body, &next.to_le_bytes());
                put(body, &(entries.len() as u16).to_le_bytes());
                for (k, v) in entries {
                    put(body, &(k.len() as u16).to_le_bytes());
                    put(body, &(v.len() as u16).to_le_bytes());
                    put(body, k);
                    put(body, v);
                }
                p[4] = PageType::Leaf as u8;
            }
            Node::Internal { keys, children } => {
                if children.len() != keys.len() + 1 {
                    return Err(Error::corrupt("internal error: child count mismatch"));
                }
                put(body, &(keys.len() as u16).to_le_bytes());
                put(body, &children[0].to_le_bytes());
                for (k, c) in keys.iter().zip(&children[1..]) {
                    put(body, &(k.len() as u16).to_le_bytes());
                    put(body, k);
                    put(body, &c.to_le_bytes());
                }
                p[4] = PageType::Internal as u8;
            }
        }
        Ok(())
    }

    /// Decode and fully validate a node page. Never panics on arbitrary input.
    pub fn decode(p: &[u8; PAGE_SIZE]) -> Result<Node> {
        let id = page::page_id(p);
        let bad = |m: &str| Error::corrupt(format!("page {id}: {m}"));
        let body = &p[HEADER_SIZE..];
        let mut r = Reader { b: body, pos: 0 };
        match page::page_type(p) {
            Some(PageType::Leaf) => {
                let next = r.u64().ok_or_else(|| bad("truncated leaf header"))?;
                if next > MAX_PAGE_ID || (next != 0 && next == id) {
                    return Err(bad("bad next-leaf pointer"));
                }
                let n = r.u16().ok_or_else(|| bad("truncated leaf header"))? as usize;
                let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(n.min(BODY_SIZE / 4));
                for _ in 0..n {
                    let kl = r.u16().ok_or_else(|| bad("truncated entry"))? as usize;
                    let vl = r.u16().ok_or_else(|| bad("truncated entry"))? as usize;
                    if kl > MAX_KEY_LEN || vl > MAX_VALUE_LEN {
                        return Err(bad("entry too large"));
                    }
                    let k = r.bytes(kl).ok_or_else(|| bad("truncated key"))?;
                    let v = r.bytes(vl).ok_or_else(|| bad("truncated value"))?;
                    if let Some((pk, _)) = entries.last()
                        && pk.as_slice() >= k
                    {
                        return Err(bad("leaf keys not strictly increasing"));
                    }
                    entries.push((k.to_vec(), v.to_vec()));
                }
                Ok(Node::Leaf { next, entries })
            }
            Some(PageType::Internal) => {
                let n = r.u16().ok_or_else(|| bad("truncated internal header"))? as usize;
                let c0 = r.u64().ok_or_else(|| bad("truncated internal header"))?;
                let mut keys: Vec<Vec<u8>> = Vec::with_capacity(n.min(BODY_SIZE / INT_ENTRY));
                let mut children = Vec::with_capacity(n.min(BODY_SIZE / INT_ENTRY) + 1);
                children.push(c0);
                for _ in 0..n {
                    let kl = r.u16().ok_or_else(|| bad("truncated key"))? as usize;
                    if kl > MAX_KEY_LEN {
                        return Err(bad("separator too large"));
                    }
                    let k = r.bytes(kl).ok_or_else(|| bad("truncated key"))?;
                    let c = r.u64().ok_or_else(|| bad("truncated child"))?;
                    if let Some(pk) = keys.last()
                        && pk.as_slice() >= k
                    {
                        return Err(bad("separators not strictly increasing"));
                    }
                    keys.push(k.to_vec());
                    children.push(c);
                }
                if children
                    .iter()
                    .any(|&c| c == 0 || c == id || c > MAX_PAGE_ID)
                {
                    return Err(bad("bad child pointer"));
                }
                Ok(Node::Internal { keys, children })
            }
            _ => Err(bad("not a B+Tree node")),
        }
    }
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.b.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
    fn u16(&mut self) -> Option<u16> {
        self.bytes(2).map(|b| get_u16(b, 0))
    }
    fn u64(&mut self) -> Option<u64> {
        self.bytes(8).map(|b| get_u64(b, 0))
    }
}

/// Page access used by the tree algorithms (implemented by the transaction).
pub(crate) trait NodeStore {
    fn read_node(&mut self, id: PageId) -> Result<Node>;
    fn write_node(&mut self, id: PageId, node: &Node) -> Result<()>;
    fn alloc_page(&mut self) -> Result<PageId>;
    fn free_page(&mut self, id: PageId) -> Result<()>;
}

fn child_index(keys: &[Vec<u8>], key: &[u8]) -> usize {
    keys.partition_point(|k| k.as_slice() <= key)
}

/// Best split of items with sizes `sz` (plus fixed overhead per side) into two non-empty
/// halves that both fit, minimising the larger half. `skip_mid` = internal-node split where
/// the middle item moves up to the parent.
fn best_split(sz: &[usize], fixed: usize, skip_mid: bool) -> Result<usize> {
    let total: usize = sz.iter().sum();
    let mut best: Option<(usize, usize)> = None;
    let mut left = 0usize;
    let (lo, hi) = if skip_mid {
        (0, sz.len())
    } else {
        (1, sz.len())
    };
    for (m, &s) in sz.iter().enumerate().take(hi) {
        if m >= lo {
            let right = total - left - if skip_mid { s } else { 0 };
            let (l, r) = (fixed + left, fixed + right);
            if l <= BODY_SIZE && r <= BODY_SIZE {
                let worst = l.max(r);
                if best.is_none_or(|(_, w)| worst < w) {
                    best = Some((m, worst));
                }
            }
        }
        left += s;
    }
    best.map(|(m, _)| m)
        .ok_or_else(|| Error::corrupt("internal error: node cannot be split"))
}

fn split_leaf_point(entries: &[(Vec<u8>, Vec<u8>)]) -> Result<usize> {
    let sz: Vec<usize> = entries
        .iter()
        .map(|(k, v)| LEAF_ENTRY + k.len() + v.len())
        .collect();
    best_split(&sz, LEAF_FIXED, false)
}

fn split_internal_point(keys: &[Vec<u8>]) -> Result<usize> {
    let sz: Vec<usize> = keys.iter().map(|k| INT_ENTRY + k.len()).collect();
    best_split(&sz, INT_FIXED, true)
}

fn depth_check(depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        Err(Error::corrupt("B+Tree deeper than MAX_DEPTH (cycle?)"))
    } else {
        Ok(())
    }
}

/// Validate key/value sizes.
pub fn check_kv(key: &[u8], val: Option<&[u8]>) -> Result<()> {
    if key.len() > MAX_KEY_LEN {
        return Err(Error::KeyTooLarge(key.len()));
    }
    if let Some(v) = val
        && v.len() > MAX_VALUE_LEN
    {
        return Err(Error::ValueTooLarge(v.len()));
    }
    Ok(())
}

/// Point lookup.
pub(crate) fn get(s: &mut impl NodeStore, root: PageId, key: &[u8]) -> Result<Option<Vec<u8>>> {
    let mut id = root;
    for _ in 0..=MAX_DEPTH {
        match s.read_node(id)? {
            Node::Internal { keys, children } => id = children[child_index(&keys, key)],
            Node::Leaf { mut entries, .. } => {
                return Ok(entries
                    .binary_search_by(|(k, _)| k.as_slice().cmp(key))
                    .ok()
                    .map(|i| entries.swap_remove(i).1));
            }
        }
    }
    Err(Error::corrupt("B+Tree deeper than MAX_DEPTH (cycle?)"))
}

/// Find the leaf that would contain `key`.
pub(crate) fn seek_leaf(
    s: &mut impl NodeStore,
    root: PageId,
    key: &[u8],
) -> Result<(PageId, Node)> {
    let mut id = root;
    for _ in 0..=MAX_DEPTH {
        let n = s.read_node(id)?;
        match n {
            Node::Internal { keys, children } => id = children[child_index(&keys, key)],
            leaf @ Node::Leaf { .. } => return Ok((id, leaf)),
        }
    }
    Err(Error::corrupt("B+Tree deeper than MAX_DEPTH (cycle?)"))
}

type Split = Option<(Vec<u8>, PageId)>;

/// Write internal node `id`, splitting it if it no longer fits. Returns the split (separator +
/// new right sibling) and the encoded size of what was written to `id`.
fn write_internal(
    s: &mut impl NodeStore,
    id: PageId,
    mut keys: Vec<Vec<u8>>,
    mut children: Vec<PageId>,
) -> Result<(Split, usize)> {
    if internal_size(&keys) <= BODY_SIZE {
        let size = internal_size(&keys);
        s.write_node(id, &Node::Internal { keys, children })?;
        return Ok((None, size));
    }
    let m = split_internal_point(&keys)?;
    let rkeys = keys.split_off(m + 1);
    let up = keys
        .pop()
        .ok_or_else(|| Error::corrupt("internal error: empty split"))?;
    let rchildren = children.split_off(m + 1);
    let nid = s.alloc_page()?;
    s.write_node(
        nid,
        &Node::Internal {
            keys: rkeys,
            children: rchildren,
        },
    )?;
    let size = internal_size(&keys);
    s.write_node(id, &Node::Internal { keys, children })?;
    Ok((Some((up, nid)), size))
}

/// The root (which now holds the left half of a split) gets a new level, keeping its page id.
fn split_root(s: &mut impl NodeStore, root: PageId, sep: Vec<u8>, rid: PageId) -> Result<()> {
    let left = s.read_node(root)?;
    let lid = s.alloc_page()?;
    s.write_node(lid, &left)?;
    s.write_node(
        root,
        &Node::Internal {
            keys: vec![sep],
            children: vec![lid, rid],
        },
    )
}

fn insert_rec(
    s: &mut impl NodeStore,
    id: PageId,
    key: &[u8],
    val: &[u8],
    depth: usize,
) -> Result<(Option<Vec<u8>>, Split)> {
    depth_check(depth)?;
    match s.read_node(id)? {
        Node::Leaf { next, mut entries } => {
            let old = match entries.binary_search_by(|(k, _)| k.as_slice().cmp(key)) {
                Ok(i) => Some(std::mem::replace(&mut entries[i].1, val.to_vec())),
                Err(i) => {
                    entries.insert(i, (key.to_vec(), val.to_vec()));
                    None
                }
            };
            if leaf_size(&entries) <= BODY_SIZE {
                s.write_node(id, &Node::Leaf { next, entries })?;
                return Ok((old, None));
            }
            let m = split_leaf_point(&entries)?;
            let right = entries.split_off(m);
            let sep = right[0].0.clone();
            let rid = s.alloc_page()?;
            s.write_node(
                rid,
                &Node::Leaf {
                    next,
                    entries: right,
                },
            )?;
            s.write_node(id, &Node::Leaf { next: rid, entries })?;
            Ok((old, Some((sep, rid))))
        }
        Node::Internal {
            mut keys,
            mut children,
        } => {
            let idx = child_index(&keys, key);
            let (old, split) = insert_rec(s, children[idx], key, val, depth + 1)?;
            let Some((sep, rid)) = split else {
                return Ok((old, None));
            };
            keys.insert(idx, sep);
            children.insert(idx + 1, rid);
            let (split, _) = write_internal(s, id, keys, children)?;
            Ok((old, split))
        }
    }
}

/// Insert or replace; returns the previous value.
pub(crate) fn insert(
    s: &mut impl NodeStore,
    root: PageId,
    key: &[u8],
    val: &[u8],
) -> Result<Option<Vec<u8>>> {
    check_kv(key, Some(val))?;
    let (old, split) = insert_rec(s, root, key, val, 0)?;
    if let Some((sep, rid)) = split {
        split_root(s, root, sep, rid)?;
    }
    Ok(old)
}

/// Merge or rebalance child `idx` (underflowing) with a sibling.
fn rebalance(
    s: &mut impl NodeStore,
    keys: &mut Vec<Vec<u8>>,
    children: &mut Vec<PageId>,
    idx: usize,
) -> Result<()> {
    if children.len() < 2 {
        return Ok(());
    }
    let li = if idx + 1 < children.len() {
        idx
    } else {
        idx - 1
    };
    let ri = li + 1;
    let (lid, rid) = (children[li], children[ri]);
    match (s.read_node(lid)?, s.read_node(rid)?) {
        (
            Node::Leaf {
                entries: mut le, ..
            },
            Node::Leaf {
                next: rnext,
                entries: re,
            },
        ) => {
            le.extend(re);
            if leaf_size(&le) <= BODY_SIZE {
                s.write_node(
                    lid,
                    &Node::Leaf {
                        next: rnext,
                        entries: le,
                    },
                )?;
                s.free_page(rid)?;
                keys.remove(li);
                children.remove(ri);
            } else {
                let m = split_leaf_point(&le)?;
                let right = le.split_off(m);
                keys[li] = right[0].0.clone();
                s.write_node(
                    lid,
                    &Node::Leaf {
                        next: rid,
                        entries: le,
                    },
                )?;
                s.write_node(
                    rid,
                    &Node::Leaf {
                        next: rnext,
                        entries: right,
                    },
                )?;
            }
        }
        (
            Node::Internal {
                keys: mut lk,
                children: mut lc,
            },
            Node::Internal {
                keys: rk,
                children: rc,
            },
        ) => {
            lk.push(keys[li].clone());
            lk.extend(rk);
            lc.extend(rc);
            if internal_size(&lk) <= BODY_SIZE {
                s.write_node(
                    lid,
                    &Node::Internal {
                        keys: lk,
                        children: lc,
                    },
                )?;
                s.free_page(rid)?;
                keys.remove(li);
                children.remove(ri);
            } else {
                let m = split_internal_point(&lk)?;
                let rkeys = lk.split_off(m + 1);
                let up = lk
                    .pop()
                    .ok_or_else(|| Error::corrupt("internal error: empty split"))?;
                let rch = lc.split_off(m + 1);
                keys[li] = up;
                s.write_node(
                    lid,
                    &Node::Internal {
                        keys: lk,
                        children: lc,
                    },
                )?;
                s.write_node(
                    rid,
                    &Node::Internal {
                        keys: rkeys,
                        children: rch,
                    },
                )?;
            }
        }
        _ => {
            return Err(Error::corrupt(format!(
                "pages {lid} and {rid}: sibling kinds differ"
            )));
        }
    }
    Ok(())
}

/// Returns (removed value, encoded size of node `id` afterwards, split of node `id`).
///
/// A delete can *grow* an internal node: rebalancing two children replaces their separator,
/// and the new one may be longer. Such a node is split and the split propagates upwards
/// exactly like on insert.
fn delete_rec(
    s: &mut impl NodeStore,
    id: PageId,
    key: &[u8],
    depth: usize,
) -> Result<Option<(Vec<u8>, usize, Split)>> {
    depth_check(depth)?;
    match s.read_node(id)? {
        Node::Leaf { next, mut entries } => {
            let Ok(i) = entries.binary_search_by(|(k, _)| k.as_slice().cmp(key)) else {
                return Ok(None);
            };
            let (_, v) = entries.remove(i);
            let size = leaf_size(&entries);
            s.write_node(id, &Node::Leaf { next, entries })?;
            Ok(Some((v, size, None)))
        }
        Node::Internal {
            mut keys,
            mut children,
        } => {
            let idx = child_index(&keys, key);
            let Some((v, child_size, child_split)) = delete_rec(s, children[idx], key, depth + 1)?
            else {
                return Ok(None);
            };
            if let Some((sep, rid)) = child_split {
                keys.insert(idx, sep);
                children.insert(idx + 1, rid);
            } else if child_size < UNDERFLOW && children.len() > 1 {
                rebalance(s, &mut keys, &mut children, idx)?;
            } else {
                return Ok(Some((v, internal_size(&keys), None)));
            }
            let (split, size) = write_internal(s, id, keys, children)?;
            Ok(Some((v, size, split)))
        }
    }
}

/// Delete `key`; returns the removed value.
pub(crate) fn delete(s: &mut impl NodeStore, root: PageId, key: &[u8]) -> Result<Option<Vec<u8>>> {
    check_kv(key, None)?;
    let Some((removed, _, split)) = delete_rec(s, root, key, 0)? else {
        return Ok(None);
    };
    if let Some((sep, rid)) = split {
        split_root(s, root, sep, rid)?;
    }
    {
        // Collapse a root that has a single child.
        for _ in 0..=MAX_DEPTH {
            match s.read_node(root)? {
                Node::Internal { keys, children } if keys.is_empty() => {
                    let child = children[0];
                    let c = s.read_node(child)?;
                    s.write_node(root, &c)?;
                    s.free_page(child)?;
                }
                _ => break,
            }
        }
    }
    Ok(Some(removed))
}

/// Collect every page of the tree rooted at `root` (for drop/verify).
pub(crate) fn collect_pages(
    s: &mut impl NodeStore,
    root: PageId,
    out: &mut Vec<PageId>,
) -> Result<()> {
    // `seen` turns DAG-shaped corruption (two parents sharing a child) into an error instead of
    // an exponential walk.
    fn rec(
        s: &mut impl NodeStore,
        id: PageId,
        out: &mut Vec<PageId>,
        seen: &mut std::collections::HashSet<PageId>,
        depth: usize,
    ) -> Result<()> {
        depth_check(depth)?;
        if !seen.insert(id) {
            return Err(Error::corrupt(format!(
                "page {id} is referenced twice in one tree"
            )));
        }
        out.push(id);
        if let Node::Internal { children, .. } = s.read_node(id)? {
            for c in children {
                rec(s, c, out, seen, depth + 1)?;
            }
        }
        Ok(())
    }
    rec(s, root, out, &mut std::collections::HashSet::new(), 0)
}

/// Structural statistics returned by [`check`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TreeStats {
    /// Number of key/value entries.
    pub entries: u64,
    /// Number of leaf pages.
    pub leaves: u64,
    /// Number of internal pages.
    pub internals: u64,
    /// Height (1 = root is a leaf).
    pub height: usize,
}

/// Full invariant check: key ordering and bounds, uniform leaf depth, leaf chain order.
/// `seen` is called for every page (lets the caller detect pages shared between trees).
pub(crate) fn check(
    s: &mut impl NodeStore,
    root: PageId,
    seen: &mut dyn FnMut(PageId) -> Result<()>,
) -> Result<TreeStats> {
    struct Ctx<'a> {
        stats: TreeStats,
        leaves: Vec<(PageId, PageId)>,
        leaf_depth: Option<usize>,
        seen: &'a mut dyn FnMut(PageId) -> Result<()>,
    }
    fn rec(
        s: &mut impl NodeStore,
        c: &mut Ctx<'_>,
        id: PageId,
        lo: Option<&[u8]>,
        hi: Option<&[u8]>,
        depth: usize,
    ) -> Result<()> {
        depth_check(depth)?;
        (c.seen)(id)?;
        let bad = |m: String| Err(Error::corrupt(format!("tree check, page {id}: {m}")));
        let in_range = |k: &[u8]| lo.is_none_or(|l| k >= l) && hi.is_none_or(|h| k < h);
        match s.read_node(id)? {
            Node::Leaf { next, entries } => {
                if entries.iter().any(|(k, _)| !in_range(k)) {
                    return bad("key outside parent bounds".into());
                }
                match c.leaf_depth {
                    None => c.leaf_depth = Some(depth),
                    Some(d) if d != depth => return bad("leaves at different depths".into()),
                    _ => {}
                }
                c.stats.entries += entries.len() as u64;
                c.stats.leaves += 1;
                c.leaves.push((id, next));
            }
            Node::Internal { keys, children } => {
                if keys.iter().any(|k| !in_range(k)) {
                    return bad("separator outside parent bounds".into());
                }
                c.stats.internals += 1;
                for (i, &ch) in children.iter().enumerate() {
                    let l = if i == 0 {
                        lo
                    } else {
                        Some(keys[i - 1].as_slice())
                    };
                    let h = if i == keys.len() {
                        hi
                    } else {
                        Some(keys[i].as_slice())
                    };
                    rec(s, c, ch, l, h, depth + 1)?;
                }
            }
        }
        Ok(())
    }
    let mut c = Ctx {
        stats: TreeStats::default(),
        leaves: Vec::new(),
        leaf_depth: None,
        seen,
    };
    rec(s, &mut c, root, None, None, 0)?;
    for w in c.leaves.windows(2) {
        if w[0].1 != w[1].0 {
            return Err(Error::corrupt(format!(
                "tree check: leaf {} links to {}, expected {}",
                w[0].0, w[0].1, w[1].0
            )));
        }
    }
    if let Some(&(id, next)) = c.leaves.last()
        && next != 0
    {
        return Err(Error::corrupt(format!(
            "tree check: last leaf {id} links to {next}"
        )));
    }
    c.stats.height = c.leaf_depth.unwrap_or(0) + 1;
    Ok(c.stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::page::{init_page, new_page_buf};
    use std::collections::{BTreeMap, HashMap};

    /// In-memory node store that round-trips every node through encode/decode.
    #[derive(Default)]
    struct MemStore {
        pages: HashMap<PageId, Box<[u8; PAGE_SIZE]>>,
        next: PageId,
        free: Vec<PageId>,
    }
    impl MemStore {
        fn new() -> (Self, PageId) {
            let mut s = MemStore {
                next: 1,
                ..Default::default()
            };
            let r = s.alloc_page().unwrap();
            s.write_node(r, &Node::empty_leaf()).unwrap();
            (s, r)
        }
    }
    impl NodeStore for MemStore {
        fn read_node(&mut self, id: PageId) -> Result<Node> {
            Node::decode(
                self.pages
                    .get(&id)
                    .ok_or_else(|| Error::corrupt("missing"))?,
            )
        }
        fn write_node(&mut self, id: PageId, n: &Node) -> Result<()> {
            let p = self
                .pages
                .get_mut(&id)
                .ok_or_else(|| Error::corrupt("missing"))?;
            n.encode_into(p)
        }
        fn alloc_page(&mut self) -> Result<PageId> {
            let id = self.free.pop().unwrap_or_else(|| {
                self.next += 1;
                self.next - 1
            });
            let mut p = new_page_buf();
            init_page(&mut p, id, PageType::Free);
            self.pages.insert(id, p);
            Ok(id)
        }
        fn free_page(&mut self, id: PageId) -> Result<()> {
            assert!(self.pages.remove(&id).is_some(), "double free {id}");
            self.free.push(id);
            Ok(())
        }
    }

    fn check_all(s: &mut MemStore, root: PageId, model: &BTreeMap<Vec<u8>, Vec<u8>>) {
        let mut seen = std::collections::HashSet::new();
        let st = check(s, root, &mut |id| {
            assert!(seen.insert(id), "page {id} reachable twice");
            Ok(())
        })
        .unwrap();
        assert_eq!(st.entries, model.len() as u64);
        assert_eq!(seen.len(), s.pages.len(), "leaked pages");
        // Leaf-chain scan returns the model in order.
        let (_, mut node) = seek_leaf(s, root, &[]).unwrap();
        let mut got = Vec::new();
        loop {
            let Node::Leaf { next, entries } = node else {
                panic!()
            };
            got.extend(entries);
            if next == 0 {
                break;
            }
            node = s.read_node(next).unwrap();
        }
        let want: Vec<_> = model.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        assert_eq!(got, want);
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let mut p = new_page_buf();
        init_page(&mut p, 5, PageType::Leaf);
        let n = Node::Leaf {
            next: 9,
            entries: vec![(b"a".to_vec(), b"1".to_vec()), (b"b".to_vec(), vec![])],
        };
        n.encode_into(&mut p).unwrap();
        assert_eq!(Node::decode(&p).unwrap(), n);
        let i = Node::Internal {
            keys: vec![b"m".to_vec()],
            children: vec![2, 3],
        };
        i.encode_into(&mut p).unwrap();
        assert_eq!(Node::decode(&p).unwrap(), i);
    }

    #[test]
    fn decode_rejects_unsorted_and_bad_pointers() {
        let mut p = new_page_buf();
        init_page(&mut p, 5, PageType::Leaf);
        Node::Leaf {
            next: 0,
            entries: vec![(b"b".to_vec(), vec![]), (b"a".to_vec(), vec![])],
        }
        .encode_into(&mut p)
        .unwrap();
        assert!(Node::decode(&p).is_err());
        Node::Internal {
            keys: vec![b"m".to_vec()],
            children: vec![5, 3],
        }
        .encode_into(&mut p)
        .unwrap();
        assert!(Node::decode(&p).is_err(), "self-pointer");
        Node::Internal {
            keys: vec![b"m".to_vec()],
            children: vec![0, 3],
        }
        .encode_into(&mut p)
        .unwrap();
        assert!(Node::decode(&p).is_err(), "null child");
        // count larger than the body
        init_page(&mut p, 5, PageType::Leaf);
        page::put_u16(&mut p[..], HEADER_SIZE + 8, u16::MAX);
        assert!(Node::decode(&p).is_err());
    }

    #[test]
    fn random_ops_match_model() {
        for seed in 1..=6u64 {
            let (mut s, root) = MemStore::new();
            let mut model = BTreeMap::new();
            let mut rng = Rng(seed * 0x9E37_79B9);
            for step in 0..6000 {
                let k = (rng.next() % 2000).to_be_bytes().to_vec();
                let r = rng.next() % 10;
                if r < 6 {
                    let vlen = (rng.next() % 300) as usize;
                    let v = vec![(step % 251) as u8; vlen];
                    assert_eq!(insert(&mut s, root, &k, &v).unwrap(), model.insert(k, v));
                } else if r < 9 {
                    assert_eq!(delete(&mut s, root, &k).unwrap(), model.remove(&k));
                } else {
                    assert_eq!(get(&mut s, root, &k).unwrap(), model.get(&k).cloned());
                }
                if step % 1000 == 999 {
                    check_all(&mut s, root, &model);
                }
            }
            // Delete everything: tree must shrink back to a single empty root leaf.
            let keys: Vec<_> = model.keys().cloned().collect();
            for k in keys {
                assert!(delete(&mut s, root, &k).unwrap().is_some());
                model.remove(&k);
            }
            check_all(&mut s, root, &model);
            assert_eq!(s.pages.len(), 1);
        }
    }

    #[test]
    fn max_size_entries_split_and_merge() {
        let (mut s, root) = MemStore::new();
        let mut model = BTreeMap::new();
        let mut rng = Rng(42);
        for i in 0..400u32 {
            let mut k = vec![0u8; MAX_KEY_LEN];
            k[..4].copy_from_slice(&(rng.next() as u32).to_be_bytes());
            k[MAX_KEY_LEN - 4..].copy_from_slice(&i.to_be_bytes());
            let v = vec![
                i as u8;
                if i % 3 == 0 {
                    MAX_VALUE_LEN
                } else {
                    (i * 7 % 900) as usize
                }
            ];
            insert(&mut s, root, &k, &v).unwrap();
            model.insert(k, v);
        }
        check_all(&mut s, root, &model);
        let keys: Vec<_> = model.keys().cloned().collect();
        for (i, k) in keys.iter().enumerate() {
            if i % 2 == 0 {
                delete(&mut s, root, k).unwrap();
                model.remove(k);
            }
        }
        check_all(&mut s, root, &model);
        assert!(matches!(
            insert(&mut s, root, &vec![0; MAX_KEY_LEN + 1], b""),
            Err(Error::KeyTooLarge(_))
        ));
        assert!(matches!(
            insert(&mut s, root, b"k", &vec![0; MAX_VALUE_LEN + 1]),
            Err(Error::ValueTooLarge(_))
        ));
    }

    #[test]
    fn sequential_and_reverse_inserts() {
        for rev in [false, true] {
            let (mut s, root) = MemStore::new();
            let mut model = BTreeMap::new();
            for i in 0..20_000u32 {
                let i = if rev { 20_000 - i } else { i };
                let k = i.to_be_bytes().to_vec();
                insert(&mut s, root, &k, b"value-bytes").unwrap();
                model.insert(k, b"value-bytes".to_vec());
            }
            check_all(&mut s, root, &model);
        }
    }

    /// Regression (review finding): rebalancing two leaves replaced a 1-byte separator with a
    /// 1024-byte one in a nearly full parent, which then no longer fit its page.
    #[test]
    fn delete_rebalance_that_grows_parent_splits_it() {
        let (mut s, root) = MemStore::new();
        let long = |c: u8, i: u8| {
            let mut k = vec![c; MAX_KEY_LEN];
            k[MAX_KEY_LEN - 1] = i;
            k
        };
        let mut model = BTreeMap::new();
        // child0: one small entry left after the delete -> underflow
        let c0 = s.alloc_page().unwrap();
        let mut e0 = vec![
            (b"a0".to_vec(), vec![1u8; 100]),
            (b"a1".to_vec(), vec![1u8; 10]),
        ];
        // child1: 15 entries with 1024-byte keys, nearly full -> re-split, not merge
        let c1 = s.alloc_page().unwrap();
        let e1: Vec<_> = (0..15).map(|i| (long(b'b', i), vec![2u8; 60])).collect();
        let mut keys = vec![b"b".to_vec()];
        let mut children = vec![c0, c1];
        let mut leaves = vec![(c0, e0.clone()), (c1, e1)];
        for i in 0..15u8 {
            keys.push(long(b'c', i));
            let c = s.alloc_page().unwrap();
            children.push(c);
            leaves.push((c, vec![(long(b'c', i), b"x".to_vec())]));
        }
        assert!(internal_size(&keys) > BODY_SIZE - 1000 && internal_size(&keys) <= BODY_SIZE);
        for (i, (id, entries)) in leaves.iter().enumerate() {
            let next = leaves.get(i + 1).map_or(0, |l| l.0);
            s.write_node(
                *id,
                &Node::Leaf {
                    next,
                    entries: entries.clone(),
                },
            )
            .unwrap();
            model.extend(entries.iter().cloned());
        }
        s.write_node(root, &Node::Internal { keys, children })
            .unwrap();
        check_all(&mut s, root, &model);
        assert_eq!(delete(&mut s, root, b"a1").unwrap(), Some(vec![1u8; 10]));
        model.remove(b"a1".as_slice());
        e0.pop();
        check_all(&mut s, root, &model);
        let mut seen = std::collections::HashSet::new();
        let st = check(&mut s, root, &mut |id| {
            assert!(seen.insert(id));
            Ok(())
        })
        .unwrap();
        assert_eq!(st.height, 3, "root must have split");
    }

    /// Mixed short/long keys with heavy deletes: exercises separator growth on rebalance.
    #[test]
    fn mixed_key_lengths_random_ops() {
        for seed in 1..=4u64 {
            let (mut s, root) = MemStore::new();
            let mut model = BTreeMap::new();
            let mut rng = Rng(seed * 7919);
            for step in 0..8000 {
                let n = rng.next() % 600;
                let mut k = vec![
                    b'k';
                    if rng.next().is_multiple_of(3) {
                        MAX_KEY_LEN
                    } else {
                        1 + (rng.next() % 8) as usize
                    }
                ];
                k[0] = (n / 3) as u8;
                let l = k.len();
                k[l - 1] = (n % 251) as u8;
                if rng.next().is_multiple_of(3) {
                    assert_eq!(delete(&mut s, root, &k).unwrap(), model.remove(&k));
                } else {
                    let v = vec![1u8; (rng.next() % 2000) as usize];
                    assert_eq!(insert(&mut s, root, &k, &v).unwrap(), model.insert(k, v));
                }
                if step % 2000 == 1999 {
                    check_all(&mut s, root, &model);
                }
            }
            check_all(&mut s, root, &model);
        }
    }

    #[test]
    fn shared_child_is_detected_by_collect_pages() {
        let (mut s, root) = MemStore::new();
        let leaf = s.alloc_page().unwrap();
        s.write_node(leaf, &Node::empty_leaf()).unwrap();
        let mut prev = leaf;
        for _ in 0..40 {
            let n = s.alloc_page().unwrap();
            s.write_node(
                n,
                &Node::Internal {
                    keys: vec![b"m".to_vec()],
                    children: vec![prev, prev],
                },
            )
            .unwrap();
            prev = n;
        }
        s.write_node(
            root,
            &Node::Internal {
                keys: vec![b"m".to_vec()],
                children: vec![prev, prev],
            },
        )
        .unwrap();
        let mut out = Vec::new();
        assert!(collect_pages(&mut s, root, &mut out).is_err());
    }

    #[test]
    fn cycle_is_detected_not_infinite() {
        let (mut s, root) = MemStore::new();
        // Build an internal node pointing at another internal node that points back.
        let a = s.alloc_page().unwrap();
        let b = s.alloc_page().unwrap();
        s.write_node(
            a,
            &Node::Internal {
                keys: vec![b"m".to_vec()],
                children: vec![b, b],
            },
        )
        .unwrap();
        s.write_node(
            b,
            &Node::Internal {
                keys: vec![b"m".to_vec()],
                children: vec![a, a],
            },
        )
        .unwrap();
        s.write_node(
            root,
            &Node::Internal {
                keys: vec![b"m".to_vec()],
                children: vec![a, a],
            },
        )
        .unwrap();
        assert!(get(&mut s, root, b"x").is_err());
        assert!(insert(&mut s, root, b"x", b"y").is_err());
        assert!(delete(&mut s, root, b"x").is_err());
    }
}
