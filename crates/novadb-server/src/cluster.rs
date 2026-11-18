//! Cluster mode (Stage 8): Raft replication of every change, mTLS between nodes, join tokens.
//!
//! Layout under `<data>/cluster/`:
//! * `cluster.json` — cluster id, this node's id and addresses, peer address book;
//! * `ca.crt` (+ `ca.key` 0600 on the node that created the cluster and issues join tokens),
//!   `node.crt`/`node.key` (0600) — node identity, SAN `node-<id>.novadb` + `novadb-node`;
//! * `join-tokens.json` (0600) — SHA-256 of outstanding one-time join secrets + expiry;
//! * `raft/` — hard state, log (CRC-checked records, fsync per batch), snapshot.
//!
//! How writes work: see `novadb_sql::exec::cluster` (capture on the leader → replicate →
//! every node applies) and `Server::run_cluster`.

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use novadb_raft::codec;
use novadb_raft::{
    Config, Entry, EntryKind, HardState, Node, NodeId, Persisted, ProposeError, Snapshot,
};
use novadb_sql::binlog::Record;
use novadb_sql::{Engine, SqlError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

pub const TICK: Duration = Duration::from_millis(100);
/// Take a snapshot (and drop the log before it) every this many applied entries
/// (`NOVADB_SNAPSHOT_EVERY` overrides, for tests).
fn snapshot_every() -> u64 {
    std::env::var("NOVADB_SNAPSHOT_EVERY")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v >= 10)
        .unwrap_or(10_000)
}

// ----- config files --------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Peer {
    pub raft: String,
    #[serde(default)]
    pub sql: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClusterFile {
    pub cluster_id: String,
    pub node_id: NodeId,
    /// address the Raft listener binds
    pub raft_listen: String,
    pub peers: BTreeMap<NodeId, Peer>,
    /// true once this node has been added to the voter set (joiners start false)
    #[serde(default)]
    pub member: bool,
}

pub fn dir(data: &Path) -> PathBuf {
    data.join("cluster")
}

pub fn load(data: &Path) -> Result<Option<ClusterFile>, String> {
    let p = dir(data).join("cluster.json");
    match std::fs::read(&p) {
        Ok(b) => serde_json::from_slice(&b)
            .map(Some)
            .map_err(|e| format!("{}: {e}", p.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", p.display())),
    }
}

pub fn write_atomic(p: &Path, b: &[u8], private: bool) -> Result<(), String> {
    let tmp = p.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(if private { 0o600 } else { 0o644 })
        .open(&tmp)
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    f.write_all(b).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, p).map_err(|e| e.to_string())?;
    if let Some(d) = p.parent()
        && let Ok(df) = std::fs::File::open(d)
    {
        let _ = df.sync_all();
    }
    Ok(())
}

pub fn save(data: &Path, c: &ClusterFile) -> Result<(), String> {
    let b = serde_json::to_vec_pretty(c).map_err(|e| e.to_string())?;
    write_atomic(&dir(data).join("cluster.json"), &b, false)
}

// ----- PKI -----------------------------------------------------------------------------------

fn ca_params(cluster_id: &str) -> Result<rcgen::CertificateParams, String> {
    let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(|e| e.to_string())?;
    p.distinguished_name = rcgen::DistinguishedName::new();
    p.distinguished_name.push(
        rcgen::DnType::CommonName,
        format!("NovaDB cluster CA {cluster_id}"),
    );
    p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    p.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    p.not_before = rcgen::date_time_ymd(2024, 1, 1);
    p.not_after = rcgen::date_time_ymd(2124, 1, 1);
    Ok(p)
}

/// (cert pem, key pem) for node `id`, signed by the cluster CA.
pub fn issue_node_cert(
    cluster_id: &str,
    ca_key_pem: &str,
    id: NodeId,
) -> Result<(String, String), String> {
    let ca_key = rcgen::KeyPair::from_pem(ca_key_pem).map_err(|e| e.to_string())?;
    // Re-creating the CA certificate from the same parameters + key gives the same issuer
    // name and key identifier, so node certificates chain to the stored ca.crt.
    let ca = ca_params(cluster_id)?
        .self_signed(&ca_key)
        .map_err(|e| e.to_string())?;
    let mut p =
        rcgen::CertificateParams::new(vec![format!("node-{id}.novadb"), "novadb-node".to_string()])
            .map_err(|e| e.to_string())?;
    p.distinguished_name = rcgen::DistinguishedName::new();
    p.distinguished_name
        .push(rcgen::DnType::CommonName, format!("novadb node {id}"));
    p.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];
    p.not_before = rcgen::date_time_ymd(2024, 1, 1);
    p.not_after = rcgen::date_time_ymd(2124, 1, 1);
    let key = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
    let cert = p.signed_by(&key, &ca, &ca_key).map_err(|e| e.to_string())?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// Node id from a verified node certificate (SAN `node-<id>.novadb`).
pub fn node_id_from_cert(der: &[u8]) -> Option<NodeId> {
    let pat = b"node-";
    let mut i = 0;
    while i + pat.len() < der.len() {
        if &der[i..i + pat.len()] == pat {
            let mut j = i + pat.len();
            let mut id: u64 = 0;
            let mut digits = 0;
            while j < der.len() && der[j].is_ascii_digit() && digits < 19 {
                id = id * 10 + u64::from(der[j] - b'0');
                j += 1;
                digits += 1;
            }
            if digits > 0 && der[j..].starts_with(b".novadb") {
                return Some(id);
            }
        }
        i += 1;
    }
    None
}

pub fn fingerprint(der: &[u8]) -> String {
    crate::hex(&Sha256::digest(der))
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    use tokio_rustls::rustls::pki_types::CertificateDer;
    use tokio_rustls::rustls::pki_types::pem::PemObject;
    CertificateDer::from_pem_slice(pem.as_bytes())
        .map(|c| c.to_vec())
        .map_err(|e| format!("certificate: {e}"))
}

// ----- join tokens ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JoinToken {
    hash: String,
    expires: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBody {
    /// issuer's Raft address
    pub a: String,
    /// SHA-256 of the cluster CA certificate (DER)
    pub f: String,
    /// one-time secret
    pub s: String,
}

fn now() -> u64 {
    crate::tokens::now()
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

/// Validate and consume a join secret (on the issuing node).
pub fn consume_join_secret(data: &Path, secret: &str) -> bool {
    let p = dir(data).join("join-tokens.json");
    let Ok(b) = std::fs::read(&p) else {
        return false;
    };
    let Ok(mut all) = serde_json::from_slice::<Vec<JoinToken>>(&b) else {
        return false;
    };
    let h = crate::hex(&Sha256::digest(secret.as_bytes()));
    let t = now();
    let before = all.len();
    let mut ok = false;
    all.retain(|x| {
        if x.expires <= t {
            return false;
        }
        if !ok && subtle::ConstantTimeEq::ct_eq(x.hash.as_bytes(), h.as_bytes()).into() {
            ok = true;
            return false; // one-time
        }
        true
    });
    if ok || all.len() != before {
        let _ = serde_json::to_vec(&all).map(|b| write_atomic(&p, &b, true));
    }
    ok
}

// ----- Raft storage --------------------------------------------------------------------------

/// Durable Raft state: hard state, log file of CRC-checked records, snapshot.
pub struct RaftStore {
    dir: PathBuf,
    log: std::fs::File,
    /// stored entries' (index, byte offset) for truncation
    offsets: Vec<(u64, u64)>,
    size: u64,
}

/// Entries, their (index, byte offset), and the length of the valid prefix.
type LogScan = (Vec<Entry>, Vec<(u64, u64)>, u64);

fn read_records(path: &Path) -> Result<LogScan, String> {
    let mut b = Vec::new();
    match std::fs::File::open(path) {
        Ok(mut f) => {
            f.read_to_end(&mut b).map_err(|e| e.to_string())?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.to_string()),
    }
    let mut out = Vec::new();
    let mut offs = Vec::new();
    let mut i = 0usize;
    while i + 8 <= b.len() {
        let n = u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]) as usize;
        let crc = u32::from_le_bytes([b[i + 4], b[i + 5], b[i + 6], b[i + 7]]);
        if i + 8 + n > b.len() {
            break; // torn tail
        }
        let payload = &b[i + 8..i + 8 + n];
        if novadb_storage::crc32c::crc32c(payload) != crc {
            break;
        }
        match codec::decode_entry(payload) {
            Ok(e) => {
                offs.push((e.index, i as u64));
                out.push(e);
            }
            Err(_) => break,
        }
        i += 8 + n;
    }
    Ok((out, offs, i as u64))
}

impl RaftStore {
    pub fn open(dir: &Path) -> Result<(RaftStore, Persisted), String> {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let hard_state = match std::fs::read(dir.join("hardstate")) {
            Ok(b) => codec::decode_hard_state(&b).map_err(|e| e.to_string())?,
            Err(_) => HardState::default(),
        };
        let snapshot = match std::fs::read(dir.join("snapshot")) {
            Ok(b) => Some(codec::decode_snapshot(&b).map_err(|e| e.to_string())?),
            Err(_) => None,
        };
        let lp = dir.join("log");
        let (entries, offsets, good) = read_records(&lp)?;
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&lp)
            .map_err(|e| e.to_string())?;
        // cut a torn tail
        log.set_len(good).map_err(|e| e.to_string())?;
        Ok((
            RaftStore {
                dir: dir.to_path_buf(),
                log,
                offsets,
                size: good,
            },
            Persisted {
                hard_state,
                snapshot,
                entries,
            },
        ))
    }

    pub fn save_hard_state(&mut self, h: &HardState) -> Result<(), String> {
        write_atomic(
            &self.dir.join("hardstate"),
            &codec::encode_hard_state(h),
            true,
        )
    }

    pub fn save_snapshot(&mut self, s: &Snapshot) -> Result<(), String> {
        write_atomic(&self.dir.join("snapshot"), &codec::encode_snapshot(s), true)?;
        // drop log records covered by the snapshot (rewrite the remaining ones)
        let (entries, _, _) = read_records(&self.dir.join("log"))?;
        let keep: Vec<Entry> = entries.into_iter().filter(|e| e.index > s.index).collect();
        self.rewrite(&keep)
    }

    fn rewrite(&mut self, keep: &[Entry]) -> Result<(), String> {
        let mut buf = Vec::new();
        let mut offs = Vec::new();
        for e in keep {
            offs.push((e.index, buf.len() as u64));
            frame(&mut buf, e);
        }
        write_atomic(&self.dir.join("log"), &buf, true)?;
        self.log = std::fs::OpenOptions::new()
            .append(true)
            .open(self.dir.join("log"))
            .map_err(|e| e.to_string())?;
        self.offsets = offs;
        self.size = buf.len() as u64;
        Ok(())
    }

    pub fn truncate_from(&mut self, index: u64) -> Result<(), String> {
        let Some(pos) = self.offsets.iter().position(|(i, _)| *i >= index) else {
            return Ok(());
        };
        let off = self.offsets[pos].1;
        self.log.set_len(off).map_err(|e| e.to_string())?;
        self.offsets.truncate(pos);
        self.size = off;
        Ok(())
    }

    pub fn append(&mut self, entries: &[Entry]) -> Result<(), String> {
        if entries.is_empty() {
            return Ok(());
        }
        let mut buf = Vec::new();
        for e in entries {
            self.offsets.push((e.index, self.size + buf.len() as u64));
            frame(&mut buf, e);
        }
        self.log.write_all(&buf).map_err(|e| e.to_string())?;
        self.size += buf.len() as u64;
        Ok(())
    }

    pub fn sync(&mut self) -> Result<(), String> {
        self.log.sync_data().map_err(|e| e.to_string())
    }
}

fn frame(buf: &mut Vec<u8>, e: &Entry) {
    let p = codec::encode_entry(e);
    buf.extend_from_slice(&(p.len() as u32).to_le_bytes());
    buf.extend_from_slice(&novadb_storage::crc32c::crc32c(&p).to_le_bytes());
    buf.extend_from_slice(&p);
}

// ----- entry payloads ------------------------------------------------------------------------

const PAYLOAD_SQL: u8 = 0;
const PAYLOAD_PEER: u8 = 1;

pub fn encode_sql(recs: &[Record]) -> Result<Vec<u8>, SqlError> {
    let mut b = vec![PAYLOAD_SQL];
    b.extend_from_slice(&(recs.len() as u32).to_le_bytes());
    for r in recs {
        let e = novadb_sql::binlog::encode_record(r)?;
        b.extend_from_slice(&(e.len() as u64).to_le_bytes());
        b.extend_from_slice(&e);
    }
    Ok(b)
}

fn decode_sql(b: &[u8]) -> Result<Vec<Record>, String> {
    let bad = || "bad replicated entry".to_string();
    let n =
        u32::from_le_bytes(b.get(1..5).ok_or_else(bad)?.try_into().map_err(|_| bad())?) as usize;
    let mut i = 5;
    let mut out = Vec::with_capacity(n.min(1024));
    for _ in 0..n {
        let len = u64::from_le_bytes(
            b.get(i..i + 8)
                .ok_or_else(bad)?
                .try_into()
                .map_err(|_| bad())?,
        ) as usize;
        i += 8;
        let s = b
            .get(i..i.checked_add(len).ok_or_else(bad)?)
            .ok_or_else(bad)?;
        out.push(novadb_sql::binlog::decode_record(s).map_err(|e| e.to_string())?);
        i += len;
    }
    Ok(out)
}

fn encode_peer(id: NodeId, p: &Peer) -> Vec<u8> {
    let mut b = vec![PAYLOAD_PEER];
    b.extend_from_slice(&serde_json::to_vec(&(id, p)).unwrap_or_default());
    b
}

// ----- driver --------------------------------------------------------------------------------

pub enum Event {
    Msg(NodeId, novadb_raft::Msg),
    /// Replicate SQL records; reply with the apply outcome.
    Propose(Vec<u8>, oneshot::Sender<Result<(), SqlError>>),
    /// Linearizable read barrier: reply once this node applied the read index.
    Read(oneshot::Sender<Result<(), SqlError>>),
    /// Add a node (its addresses) to the cluster.
    AddNode(NodeId, Peer, oneshot::Sender<Result<(), String>>),
    RemoveNode(NodeId, oneshot::Sender<Result<(), String>>),
}

/// Shared view of the cluster for SQL sessions / REST / metrics.
pub struct Handle {
    pub node_id: NodeId,
    pub events: mpsc::Sender<Event>,
    pub is_leader: AtomicBool,
    /// leader has applied everything committed before its term (may serve writes)
    pub ready: AtomicBool,
    pub leader: AtomicU64,
    pub term: AtomicU64,
    pub commit: AtomicU64,
    pub applied: AtomicU64,
    pub peers: RwLock<BTreeMap<NodeId, Peer>>,
    pub voters: RwLock<Vec<NodeId>>,
    /// serialises captured writes on the leader (capture → replicate → apply)
    pub write_lock: tokio::sync::Mutex<()>,
    pub linearizable_reads: bool,
}

impl Handle {
    pub fn leader_hint(&self) -> String {
        let l = self.leader.load(Ordering::Relaxed);
        if l == 0 {
            return "no leader elected right now".into();
        }
        let sql = self
            .peers
            .read()
            .ok()
            .and_then(|p| p.get(&l).map(|x| x.sql.clone()))
            .unwrap_or_default();
        format!(
            "leader is node {l}{}",
            if sql.is_empty() {
                String::new()
            } else {
                format!(" at {sql}")
            }
        )
    }
    pub fn not_leader(&self) -> SqlError {
        let mut e = SqlError::internal(format!(
            "The NovaDB server is running with the --read-only option so it cannot execute this statement: this node is a cluster follower ({})",
            self.leader_hint()
        ));
        e.code = 1290;
        e.state = "HY000";
        e
    }
    pub fn status_json(&self) -> serde_json::Value {
        serde_json::json!({
            "node_id": self.node_id,
            "role": if self.is_leader.load(Ordering::Relaxed) { "leader" } else { "follower" },
            "leader": self.leader.load(Ordering::Relaxed),
            "term": self.term.load(Ordering::Relaxed),
            "commit_index": self.commit.load(Ordering::Relaxed),
            "applied_index": self.applied.load(Ordering::Relaxed),
            "voters": self.voters.read().map(|v| v.clone()).unwrap_or_default(),
            "peers": self.peers.read().map(|p| p.clone()).unwrap_or_default(),
        })
    }
}

pub fn unknown_outcome() -> SqlError {
    let mut e = SqlError::internal(
        "commit outcome unknown: cluster leadership changed before the write was confirmed (check, then retry if needed)",
    );
    e.code = 1180;
    e
}

/// Opens an engine the way the server does (hasher, GRANTs, change hook).
pub type OpenEngine = Box<dyn Fn(&Path) -> Result<Engine, String> + Send>;
type ReadReply = oneshot::Sender<Result<(), SqlError>>;

/// What the driver needs to replace the engine when installing a snapshot.
pub struct EngineSlot {
    pub engine: Arc<Mutex<Engine>>,
    pub data_dir: PathBuf,
    pub open: OpenEngine,
}

pub struct Driver {
    node: Node,
    store: RaftStore,
    slot: EngineSlot,
    handle: Arc<Handle>,
    net: crate::cluster_net::Outbox,
    waiters: HashMap<u64, (u64, oneshot::Sender<Result<(), SqlError>>)>,
    reads: HashMap<u64, (ReadReply, Option<u64>)>,
    next_ctx: u64,
    conf_waiters: Vec<(u64, oneshot::Sender<Result<(), String>>)>,
    term_start: u64,
    data: PathBuf,
}

impl Driver {
    pub fn new(
        data: &Path,
        cf: &ClusterFile,
        slot: EngineSlot,
        handle: Arc<Handle>,
        net: crate::cluster_net::Outbox,
    ) -> Result<Driver, String> {
        let (store, mut persisted) = RaftStore::open(&dir(data).join("raft"))?;
        if persisted.snapshot.is_none() {
            // first start: the creating node bootstraps a one-node cluster, joiners start empty
            let voters = if cf.member {
                vec![cf.node_id]
            } else {
                Vec::new()
            };
            persisted.snapshot = Some(Snapshot {
                index: 0,
                term: 0,
                voters,
                data: Arc::new(Vec::new()),
            });
        }
        let applied = slot
            .engine
            .lock()
            .map_err(|_| "engine lock")?
            .cluster_applied()
            .map_err(|e| e.to_string())?;
        let cfg = Config {
            election_ticks: 10,
            heartbeat_ticks: 2,
            max_entries_per_msg: 256,
            pre_vote: true,
            check_quorum: true,
        };
        let node = Node::restore(cf.node_id, persisted, applied, cfg);
        handle.applied.store(applied, Ordering::Relaxed);
        Ok(Driver {
            node,
            store,
            slot,
            handle,
            net,
            waiters: HashMap::new(),
            reads: HashMap::new(),
            next_ctx: 1,
            conf_waiters: Vec::new(),
            term_start: 0,
            data: data.to_path_buf(),
        })
    }

    pub fn run(mut self, rx: mpsc::Receiver<Event>) {
        let mut next_tick = Instant::now() + TICK;
        loop {
            let wait = next_tick.saturating_duration_since(Instant::now());
            match rx.recv_timeout(wait) {
                Ok(ev) => self.event(ev),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            }
            // drain whatever else is queued before processing ready (batching)
            while let Ok(ev) = rx.try_recv() {
                self.event(ev);
            }
            if Instant::now() >= next_tick {
                self.node.tick();
                next_tick += TICK;
                if next_tick < Instant::now() {
                    next_tick = Instant::now() + TICK;
                }
            }
            if let Err(e) = self.process_ready() {
                eprintln!("[novadb] cluster: fatal storage error: {e}; exiting");
                std::process::exit(70);
            }
        }
    }

    fn event(&mut self, ev: Event) {
        match ev {
            Event::Msg(from, m) => self.node.step(from, m),
            Event::Propose(data, reply) => {
                if !self.handle.ready.load(Ordering::Relaxed) {
                    let _ = reply.send(Err(self.handle.not_leader()));
                    return;
                }
                match self.node.propose(data) {
                    Ok(i) => {
                        self.waiters.insert(i, (self.node.term(), reply));
                    }
                    Err(_) => {
                        let _ = reply.send(Err(self.handle.not_leader()));
                    }
                }
            }
            Event::Read(reply) => {
                let ctx = self.next_ctx;
                self.next_ctx += 1;
                match self.node.read_index(ctx) {
                    Ok(()) => {
                        self.reads.insert(ctx, (reply, None));
                    }
                    Err(_) => {
                        let _ = reply.send(Err(self.handle.not_leader()));
                    }
                }
            }
            Event::AddNode(id, peer, reply) => {
                if !self.node.is_leader() {
                    let _ = reply.send(Err(format!(
                        "not the leader ({})",
                        self.handle.leader_hint()
                    )));
                    return;
                }
                let mut v = self.node.voters();
                if v.contains(&id) {
                    let _ = reply.send(Ok(()));
                    return;
                }
                // addresses first, then the voter change
                if let Err(e) = self.node.propose(encode_peer(id, &peer)) {
                    let _ = reply.send(Err(format!("{e:?}")));
                    return;
                }
                v.push(id);
                match self.node.propose_config(v) {
                    Ok(i) => self.conf_waiters.push((i, reply)),
                    Err(e) => {
                        let _ = reply.send(Err(format!("{e:?}")));
                    }
                }
            }
            Event::RemoveNode(id, reply) => {
                if !self.node.is_leader() {
                    let _ = reply.send(Err(format!(
                        "not the leader ({})",
                        self.handle.leader_hint()
                    )));
                    return;
                }
                let v: Vec<NodeId> = self
                    .node
                    .voters()
                    .into_iter()
                    .filter(|x| *x != id)
                    .collect();
                match self.node.propose_config(v) {
                    Ok(i) => self.conf_waiters.push((i, reply)),
                    Err(ProposeError::BadConfig(e)) => {
                        let _ = reply.send(Err(e));
                    }
                    Err(e) => {
                        let _ = reply.send(Err(format!("{e:?}")));
                    }
                }
            }
        }
    }

    fn process_ready(&mut self) -> Result<(), String> {
        loop {
            let r = self.node.ready();
            if r.is_empty() {
                break;
            }
            // 1. durable before sending
            if let Some(s) = &r.snapshot {
                if r.install {
                    self.install_snapshot(s)?;
                }
                self.store.save_snapshot(s)?;
            }
            if let Some(h) = &r.hard_state {
                self.store.save_hard_state(h)?;
            }
            if let Some(t) = r.truncate {
                self.store.truncate_from(t)?;
            }
            self.store.append(&r.entries)?;
            if !r.entries.is_empty() || r.truncate.is_some() {
                self.store.sync()?;
            }
            // 2. send
            for m in r.messages {
                self.net.send(m.to, &m.msg);
            }
            // 3. apply
            for e in &r.committed {
                self.apply(e)?;
            }
            for (ctx, idx) in r.reads {
                if let Some((reply, _)) = self.reads.remove(&ctx) {
                    self.reads.insert(ctx, (reply, Some(idx)));
                }
            }
        }
        // reads whose index is applied
        let applied = self.handle.applied.load(Ordering::Relaxed);
        let done: Vec<u64> = self
            .reads
            .iter()
            .filter(|(_, (_, i))| i.is_some_and(|i| i <= applied))
            .map(|(c, _)| *c)
            .collect();
        for c in done {
            if let Some((reply, _)) = self.reads.remove(&c) {
                let _ = reply.send(Ok(()));
            }
        }
        self.publish();
        Ok(())
    }

    fn publish(&mut self) {
        let h = &self.handle;
        let leader = self.node.is_leader();
        let was = h.is_leader.swap(leader, Ordering::Relaxed);
        if leader && !was {
            self.term_start = self.node.last_index();
            println!(
                "[novadb] cluster: node {} is now the leader (term {})",
                self.node.id,
                self.node.term()
            );
        }
        if !leader && was {
            println!(
                "[novadb] cluster: node {} is no longer the leader",
                self.node.id
            );
            // writes in flight: their outcome is unknown to us now
            for (_, (_, w)) in self.waiters.drain() {
                let _ = w.send(Err(unknown_outcome()));
            }
            for (_, (r, _)) in self.reads.drain() {
                let _ = r.send(Err(h.not_leader()));
            }
            for (_, r) in self.conf_waiters.drain(..) {
                let _ = r.send(Err("leadership changed".into()));
            }
        }
        let applied = h.applied.load(Ordering::Relaxed);
        h.ready
            .store(leader && applied >= self.term_start, Ordering::Relaxed);
        h.leader
            .store(self.node.leader().unwrap_or(0), Ordering::Relaxed);
        h.term.store(self.node.term(), Ordering::Relaxed);
        h.commit.store(self.node.commit_index(), Ordering::Relaxed);
        if let Ok(mut v) = h.voters.write() {
            *v = self.node.voters();
        }
    }

    fn apply(&mut self, e: &Entry) -> Result<(), String> {
        let outcome: Result<(), SqlError> = match &e.kind {
            EntryKind::Data(d) if d.first() == Some(&PAYLOAD_SQL) => match decode_sql(d) {
                Ok(recs) => self.apply_engine(&recs, e.index)?,
                Err(m) => Err(SqlError::corrupt(m)),
            },
            EntryKind::Data(d) if d.first() == Some(&PAYLOAD_PEER) => {
                if let Ok((id, p)) = serde_json::from_slice::<(NodeId, Peer)>(&d[1..]) {
                    if let Ok(mut peers) = self.handle.peers.write() {
                        peers.insert(id, p.clone());
                    }
                    self.net.set_peer(id, p.raft.clone());
                    self.save_peers();
                }
                self.apply_engine(&[], e.index)?
            }
            EntryKind::Config(v) => {
                if v.contains(&self.node.id) {
                    if let Ok(Some(mut cf)) = load(&self.data)
                        && !cf.member
                    {
                        cf.member = true;
                        let _ = save(&self.data, &cf);
                    }
                } else {
                    println!(
                        "[novadb] cluster: node {} is not a voter any more",
                        self.node.id
                    );
                }
                self.apply_engine(&[], e.index)?
            }
            _ => self.apply_engine(&[], e.index)?,
        };
        if let Some((term, w)) = self.waiters.remove(&e.index) {
            let _ = w.send(if term == e.term {
                outcome
            } else {
                Err(unknown_outcome())
            });
        }
        let mut k = 0;
        while k < self.conf_waiters.len() {
            if self.conf_waiters[k].0 <= e.index {
                let (_, r) = self.conf_waiters.remove(k);
                let _ = r.send(Ok(()));
            } else {
                k += 1;
            }
        }
        // compaction
        if e.index >= self.node.snapshot_index() + snapshot_every() {
            self.take_snapshot(e.index)?;
        }
        Ok(())
    }

    fn apply_engine(
        &mut self,
        recs: &[Record],
        index: u64,
    ) -> Result<Result<(), SqlError>, String> {
        let mut eng = self
            .slot
            .engine
            .lock()
            .map_err(|_| "engine lock poisoned")?;
        let r = eng
            .apply_cluster(recs, index)
            .map_err(|e| format!("apply {index}: {e}"))?;
        self.handle.applied.store(index, Ordering::Relaxed);
        Ok(r)
    }

    fn save_peers(&self) {
        if let Ok(Some(mut cf)) = load(&self.data)
            && let Ok(p) = self.handle.peers.read()
        {
            cf.peers = p.clone();
            let _ = save(&self.data, &cf);
        }
    }

    fn take_snapshot(&mut self, index: u64) -> Result<(), String> {
        let path = dir(&self.data).join("raft").join("snapshot.nbk.tmp");
        let _ = std::fs::remove_file(&path);
        {
            let mut eng = self
                .slot
                .engine
                .lock()
                .map_err(|_| "engine lock poisoned")?;
            novadb_sql::backup::dump(&mut eng, u32::MAX - 7, &path, None, 0)
                .map_err(|e| format!("snapshot dump: {e}"))?;
        }
        let data = std::fs::read(&path).map_err(|e| e.to_string())?;
        let _ = std::fs::remove_file(&path);
        self.node.compact(index, Arc::new(data));
        Ok(())
    }

    /// Replace the database with the leader's snapshot. (Snapshots are plain dumps: they only travel
    /// inside the cluster's mutual-TLS channel and live in the 0600 raft directory; nodes have
    /// different backup keys.)
    fn install_snapshot(&mut self, s: &Snapshot) -> Result<(), String> {
        println!(
            "[novadb] cluster: installing snapshot at index {} ({} bytes)",
            s.index,
            s.data.len()
        );
        let incoming = self.slot.data_dir.join("db.incoming");
        let _ = std::fs::remove_dir_all(&incoming);
        let file = dir(&self.data).join("raft").join("install.nbk");
        write_atomic(&file, &s.data, true)?;
        {
            // plain engine (no GRANT enforcement) just for loading the dump
            let mut e = Engine::open(&incoming).map_err(|e| e.to_string())?;
            if !s.data.is_empty() {
                novadb_sql::backup::restore(&mut e, &file, None)
                    .map_err(|e| format!("snapshot restore: {e}"))?;
            }
            e.apply_cluster(&[], s.index)
                .map_err(|e| e.to_string())?
                .map_err(|e| e.to_string())?;
            e.close().map_err(|e| e.to_string())?;
        }
        let _ = std::fs::remove_file(&file);
        let live = self.slot.data_dir.join("db");
        let old = self.slot.data_dir.join("db.old");
        let mut g = self
            .slot
            .engine
            .lock()
            .map_err(|_| "engine lock poisoned")?;
        // park a throwaway engine while the directories are swapped
        let parked = self.slot.data_dir.join("db.parked");
        let _ = std::fs::remove_dir_all(&parked);
        let placeholder = (self.slot.open)(&parked)?;
        let prev = std::mem::replace(&mut *g, placeholder);
        let _ = prev.close();
        let _ = std::fs::remove_dir_all(&old);
        std::fs::rename(&live, &old).map_err(|e| e.to_string())?;
        std::fs::rename(&incoming, &live).map_err(|e| e.to_string())?;
        let fresh = (self.slot.open)(&live)?;
        let p = std::mem::replace(&mut *g, fresh);
        let _ = p.close();
        let _ = std::fs::remove_dir_all(&parked);
        let _ = std::fs::remove_dir_all(&old);
        self.handle.applied.store(s.index, Ordering::Relaxed);
        Ok(())
    }
}

// ----- CLI -----------------------------------------------------------------------------------

const USAGE: &str = "usage:
  novadb-server cluster init  --data-dir DIR --node-id 1 --raft 0.0.0.0:7400 --advertise HOST:7400 [--sql HOST:3307]
  novadb-server cluster token --data-dir DIR [--minutes 60]          (on the node that ran init)
  novadb-server cluster join  --data-dir DIR --node-id N --raft 0.0.0.0:7400 --advertise HOST:7400 [--sql HOST:3307] --token TOKEN
  novadb-server cluster status --data-dir DIR
Then start each node as usual (novadb-server --data-dir DIR …); cluster mode is picked up from DIR/cluster.";

fn opts(args: &[String]) -> Result<BTreeMap<String, String>, String> {
    let mut m = BTreeMap::new();
    let mut i = 0;
    while i < args.len() {
        let k = args[i]
            .strip_prefix("--")
            .ok_or_else(|| format!("unexpected {:?}\n{USAGE}", args[i]))?;
        let v = args
            .get(i + 1)
            .ok_or_else(|| format!("--{k} needs a value"))?;
        m.insert(k.to_string(), v.clone());
        i += 2;
    }
    Ok(m)
}

fn need<'a>(o: &'a BTreeMap<String, String>, k: &str) -> Result<&'a String, String> {
    o.get(k)
        .ok_or_else(|| format!("--{k} is required\n{USAGE}"))
}

pub fn cli(args: &[String]) -> Result<String, String> {
    let sub = args.first().map(String::as_str).ok_or(USAGE)?;
    let o = opts(&args[1..])?;
    let data = PathBuf::from(need(&o, "data-dir")?);
    let cdir = dir(&data);
    match sub {
        "init" => {
            if load(&data)?.is_some() {
                return Err(format!(
                    "{} already exists",
                    cdir.join("cluster.json").display()
                ));
            }
            let id: NodeId = need(&o, "node-id")?
                .parse()
                .map_err(|_| "--node-id: number")?;
            if id == 0 {
                return Err("--node-id must be ≥ 1".into());
            }
            std::fs::create_dir_all(&cdir).map_err(|e| e.to_string())?;
            let cluster_id = crate::hex(&crate::auth::random_bytes::<8>()?);
            let ca_key = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
            let ca = ca_params(&cluster_id)?
                .self_signed(&ca_key)
                .map_err(|e| e.to_string())?;
            write_atomic(&cdir.join("ca.crt"), ca.pem().as_bytes(), false)?;
            write_atomic(
                &cdir.join("ca.key"),
                ca_key.serialize_pem().as_bytes(),
                true,
            )?;
            let (cert, key) = issue_node_cert(&cluster_id, &ca_key.serialize_pem(), id)?;
            write_atomic(&cdir.join("node.crt"), cert.as_bytes(), false)?;
            write_atomic(&cdir.join("node.key"), key.as_bytes(), true)?;
            let mut peers = BTreeMap::new();
            peers.insert(
                id,
                Peer {
                    raft: need(&o, "advertise")?.clone(),
                    sql: o.get("sql").cloned().unwrap_or_default(),
                },
            );
            save(
                &data,
                &ClusterFile {
                    cluster_id: cluster_id.clone(),
                    node_id: id,
                    raft_listen: need(&o, "raft")?.clone(),
                    peers,
                    member: true,
                },
            )?;
            Ok(format!(
                "cluster {cluster_id} created; node {id}. Start it, then add nodes with `cluster token` + `cluster join`."
            ))
        }
        "token" => {
            let cf = load(&data)?.ok_or("not a cluster node (run cluster init first)")?;
            if !cdir.join("ca.key").exists() {
                return Err(
                    "join tokens are issued by the node that holds ca.key (the one that ran init)"
                        .into(),
                );
            }
            let minutes: u64 = o
                .get("minutes")
                .map_or(Ok(60), |m| m.parse())
                .map_err(|_| "--minutes: number")?;
            let secret = crate::hex(&crate::auth::random_bytes::<32>()?);
            let p = cdir.join("join-tokens.json");
            let mut all: Vec<JoinToken> = std::fs::read(&p)
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or_default();
            all.retain(|t| t.expires > now());
            all.push(JoinToken {
                hash: crate::hex(&Sha256::digest(secret.as_bytes())),
                expires: now() + minutes.clamp(1, 7 * 24 * 60) * 60,
            });
            write_atomic(
                &p,
                &serde_json::to_vec(&all).map_err(|e| e.to_string())?,
                true,
            )?;
            let ca_pem = std::fs::read_to_string(cdir.join("ca.crt")).map_err(|e| e.to_string())?;
            let body = TokenBody {
                a: cf
                    .peers
                    .get(&cf.node_id)
                    .map(|p| p.raft.clone())
                    .unwrap_or_default(),
                f: fingerprint(&pem_to_der(&ca_pem)?),
                s: secret,
            };
            use base64::Engine as _;
            let t = b64().encode(serde_json::to_vec(&body).map_err(|e| e.to_string())?);
            Ok(format!(
                "one-time join token (valid {minutes} min, pinned to CA {}…):\n\nnvdbjoin_{t}",
                &body.f[..16]
            ))
        }
        "join" => {
            if load(&data)?.is_some() {
                return Err(format!(
                    "{} already exists",
                    cdir.join("cluster.json").display()
                ));
            }
            let id: NodeId = need(&o, "node-id")?
                .parse()
                .map_err(|_| "--node-id: number")?;
            let tok = need(&o, "token")?;
            let raw = tok
                .strip_prefix("nvdbjoin_")
                .ok_or("not a NovaDB join token")?;
            use base64::Engine as _;
            let body: TokenBody =
                serde_json::from_slice(&b64().decode(raw).map_err(|_| "token: bad encoding")?)
                    .map_err(|_| "token: bad content")?;
            let me = Peer {
                raft: need(&o, "advertise")?.clone(),
                sql: o.get("sql").cloned().unwrap_or_default(),
            };
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            let resp = rt.block_on(crate::cluster_net::join_request(&body, id, &me))?;
            std::fs::create_dir_all(&cdir).map_err(|e| e.to_string())?;
            write_atomic(&cdir.join("ca.crt"), resp.ca.as_bytes(), false)?;
            write_atomic(&cdir.join("node.crt"), resp.cert.as_bytes(), false)?;
            write_atomic(&cdir.join("node.key"), resp.key.as_bytes(), true)?;
            let mut peers = resp.peers.clone();
            peers.insert(id, me);
            save(
                &data,
                &ClusterFile {
                    cluster_id: resp.cluster_id.clone(),
                    node_id: id,
                    raft_listen: need(&o, "raft")?.clone(),
                    peers,
                    member: false,
                },
            )?;
            Ok(format!(
                "joined cluster {} as node {id} (certificate issued). Start this node; it asks the leader to add it.",
                resp.cluster_id
            ))
        }
        "status" => {
            let cf = load(&data)?.ok_or("not a cluster node")?;
            Ok(serde_json::to_string_pretty(&cf).map_err(|e| e.to_string())?)
        }
        _ => Err(USAGE.into()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn certs_chain_and_ids() {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca = ca_params("abc").unwrap().self_signed(&ca_key).unwrap();
        let (cert, _key) = issue_node_cert("abc", &ca_key.serialize_pem(), 42).unwrap();
        let der = pem_to_der(&cert).unwrap();
        assert_eq!(node_id_from_cert(&der), Some(42));
        assert_eq!(node_id_from_cert(ca.der()), None);
        // the node cert verifies against the stored CA cert
        use tokio_rustls::rustls;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let v = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap();
        use rustls::client::danger::ServerCertVerifier;
        let ee = rustls::pki_types::CertificateDer::from(der);
        v.verify_server_cert(
            &ee,
            &[],
            &rustls::pki_types::ServerName::try_from("novadb-node").unwrap(),
            &[],
            rustls::pki_types::UnixTime::now(),
        )
        .unwrap();
    }

    #[test]
    fn raft_store_roundtrip_truncate_torn_tail() {
        let d = std::env::temp_dir().join(format!("novadb-raftstore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let e = |i: u64| Entry {
            term: 1,
            index: i,
            kind: EntryKind::Data(vec![i as u8; 10]),
        };
        {
            let (mut s, p) = RaftStore::open(&d).unwrap();
            assert!(p.entries.is_empty());
            s.append(&(1..=10).map(e).collect::<Vec<_>>()).unwrap();
            s.truncate_from(8).unwrap();
            s.append(&[Entry {
                term: 2,
                index: 8,
                kind: EntryKind::Noop,
            }])
            .unwrap();
            s.save_hard_state(&HardState {
                term: 2,
                voted_for: Some(3),
            })
            .unwrap();
            s.sync().unwrap();
        }
        // torn tail
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(d.join("log"))
            .unwrap();
        f.write_all(&[9, 0, 0, 0, 1, 2]).unwrap();
        drop(f);
        let (mut s, p) = RaftStore::open(&d).unwrap();
        assert_eq!(p.entries.len(), 8);
        assert_eq!(p.entries[7].term, 2);
        assert_eq!(p.hard_state.voted_for, Some(3));
        s.save_snapshot(&Snapshot {
            index: 5,
            term: 1,
            voters: vec![1],
            data: Arc::new(vec![1, 2]),
        })
        .unwrap();
        drop(s);
        let (_, p) = RaftStore::open(&d).unwrap();
        assert_eq!(p.entries.first().map(|e| e.index), Some(6));
        assert_eq!(p.snapshot.unwrap().index, 5);
        let _ = std::fs::remove_dir_all(&d);
    }
}
