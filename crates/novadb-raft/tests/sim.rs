#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Deterministic cluster simulation ("Jepsen in a box"): random partitions, message loss,
//! duplication and reordering, crashes with restart from persisted state, membership changes
//! and snapshots — with safety checked after every event:
//! * at most one leader per term (election safety),
//! * every node applies the same entry at a given index (state machine safety),
//! * a write that any client saw committed is never lost and ends up everywhere,
//! * ReadIndex reads never miss a write that was acknowledged before the read started,
//!
//! Liveness is checked once the network heals.

use novadb_raft::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.below(100) < pct
    }
}

/// The replicated state machine: the list of applied (index, command).
#[derive(Clone, Default)]
struct Sm {
    applied: u64,
    cmds: Vec<(u64, Vec<u8>)>,
}

fn sm_encode(sm: &Sm) -> Vec<u8> {
    let mut b = sm.applied.to_le_bytes().to_vec();
    for (i, c) in &sm.cmds {
        b.extend_from_slice(&i.to_le_bytes());
        b.extend_from_slice(&(c.len() as u32).to_le_bytes());
        b.extend_from_slice(c);
    }
    b
}

fn sm_decode(b: &[u8]) -> Sm {
    if b.is_empty() {
        return Sm::default();
    }
    let applied = u64::from_le_bytes(b[..8].try_into().unwrap());
    let mut cmds = Vec::new();
    let mut i = 8;
    while i < b.len() {
        let idx = u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        let n = u32::from_le_bytes(b[i + 8..i + 12].try_into().unwrap()) as usize;
        cmds.push((idx, b[i + 12..i + 12 + n].to_vec()));
        i += 12 + n;
    }
    Sm { applied, cmds }
}

struct SimNode {
    node: Node,
    store: Persisted,
    /// durable state machine (like NovaDB's database)
    sm: Sm,
}

struct Sim {
    cfg: Config,
    nodes: BTreeMap<NodeId, SimNode>,
    down: BTreeMap<NodeId, (Persisted, Sm)>,
    net: Vec<(u64, Envelope)>,
    time: u64,
    rng: Rng,
    /// nodes on side A of a partition (None = no partition)
    side_a: Option<BTreeSet<NodeId>>,
    drop_pct: u64,
    dup_pct: u64,
    max_delay: u64,
    leaders: BTreeMap<u64, NodeId>,
    /// index -> (term, kind) as applied anywhere
    applied_global: BTreeMap<u64, (u64, EntryKind)>,
    /// commands some client saw committed
    acked: BTreeSet<Vec<u8>>,
    next_cmd: u64,
    reads: BTreeMap<u64, u64>, // ctx -> min index it must reflect
    reads_done: u64,
    compact_every: u64,
}

impl Sim {
    fn new(n: u64, seed: u64) -> Sim {
        let ids: Vec<NodeId> = (1..=n).collect();
        let cfg = Config::default();
        let nodes = ids
            .iter()
            .map(|&id| {
                (
                    id,
                    SimNode {
                        node: Node::new(id, &ids, cfg),
                        store: Persisted {
                            snapshot: Some(Snapshot {
                                index: 0,
                                term: 0,
                                voters: ids.clone(),
                                data: Arc::new(Vec::new()),
                            }),
                            ..Default::default()
                        },
                        sm: Sm::default(),
                    },
                )
            })
            .collect();
        Sim {
            cfg,
            nodes,
            down: BTreeMap::new(),
            net: Vec::new(),
            time: 0,
            rng: Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1),
            side_a: None,
            drop_pct: 0,
            dup_pct: 0,
            max_delay: 1,
            leaders: BTreeMap::new(),
            applied_global: BTreeMap::new(),
            acked: BTreeSet::new(),
            next_cmd: 0,
            reads: BTreeMap::new(),
            reads_done: 0,
            compact_every: 0,
        }
    }

    fn connected(&self, a: NodeId, b: NodeId) -> bool {
        match &self.side_a {
            None => true,
            Some(s) => s.contains(&a) == s.contains(&b),
        }
    }

    /// Persist + send + apply what a node produced.
    fn drain(&mut self, id: NodeId) {
        loop {
            let Some(sn) = self.nodes.get_mut(&id) else {
                return;
            };
            let r = sn.node.ready();
            if r.is_empty() {
                return;
            }
            // 1. persist (before sending)
            if let Some(h) = r.hard_state {
                sn.store.hard_state = h;
            }
            if let Some(s) = &r.snapshot {
                sn.store.entries.retain(|e| e.index > s.index);
                sn.store.snapshot = Some(s.clone());
                if r.install {
                    sn.sm = sm_decode(&s.data);
                    assert_eq!(sn.sm.applied, s.index, "snapshot data matches its index");
                }
            }
            if let Some(t) = r.truncate {
                sn.store.entries.retain(|e| e.index < t);
            }
            sn.store.entries.extend(r.entries.iter().cloned());
            // 2. apply
            for e in &r.committed {
                if e.index <= sn.sm.applied {
                    continue; // already in the durable state machine (restart)
                }
                assert_eq!(e.index, sn.sm.applied + 1, "node {id}: apply gap");
                sn.sm.applied = e.index;
                if let EntryKind::Data(d) = &e.kind {
                    sn.sm.cmds.push((e.index, d.clone()));
                }
                match self.applied_global.get(&e.index) {
                    Some((t, k)) => assert!(
                        *t == e.term && *k == e.kind,
                        "STATE MACHINE SAFETY: node {id} applied {:?} at {} but {:?} was applied elsewhere",
                        e,
                        e.index,
                        (t, k)
                    ),
                    None => {
                        self.applied_global
                            .insert(e.index, (e.term, e.kind.clone()));
                    }
                }
                if let EntryKind::Data(d) = &e.kind {
                    self.acked.insert(d.clone());
                }
            }
            // 3. reads
            for (ctx, index) in &r.reads {
                if let Some(min) = self.reads.remove(ctx) {
                    assert!(
                        *index >= min,
                        "LINEARIZABILITY: read {ctx} served at {index} but a write at {min} was acknowledged before it"
                    );
                    self.reads_done += 1;
                }
            }
            // 4. send
            for m in r.messages {
                if self.rng.chance(self.drop_pct) {
                    continue;
                }
                let copies = if self.rng.chance(self.dup_pct) { 2 } else { 1 };
                for _ in 0..copies {
                    let at = self.time + 1 + self.rng.below(self.max_delay);
                    self.net.push((at, m.clone()));
                }
            }
            // snapshots
            let sn = self.nodes.get_mut(&id).unwrap();
            if self.compact_every > 0
                && sn.sm.applied >= sn.node.snapshot_index() + self.compact_every
            {
                let data = Arc::new(sm_encode(&sn.sm));
                sn.node.compact(sn.sm.applied, data);
            }
        }
    }

    fn check_leaders(&mut self) {
        for (id, sn) in &self.nodes {
            if sn.node.is_leader() {
                let t = sn.node.term();
                match self.leaders.get(&t) {
                    Some(o) => assert_eq!(*o, *id, "ELECTION SAFETY: two leaders in term {t}"),
                    None => {
                        self.leaders.insert(t, *id);
                    }
                }
            }
        }
    }

    fn step_time(&mut self) {
        self.time += 1;
        let ids: Vec<NodeId> = self.nodes.keys().copied().collect();
        for id in &ids {
            self.nodes.get_mut(id).unwrap().node.tick();
            self.drain(*id);
        }
        // deliver due messages (in random order among the due ones)
        let now = self.time;
        let mut due: Vec<Envelope> = Vec::new();
        let mut later = Vec::new();
        for (at, m) in std::mem::take(&mut self.net) {
            if at <= now {
                due.push(m);
            } else {
                later.push((at, m));
            }
        }
        self.net = later;
        for i in (1..due.len()).rev() {
            let j = self.rng.below(i as u64 + 1) as usize;
            due.swap(i, j);
        }
        for m in due {
            if !self.connected(m.from, m.to) || !self.nodes.contains_key(&m.to) {
                continue;
            }
            self.nodes.get_mut(&m.to).unwrap().node.step(m.from, m.msg);
            self.drain(m.to);
        }
        self.check_leaders();
    }

    fn leader(&self) -> Option<NodeId> {
        // the leader with the highest term among live nodes
        self.nodes
            .iter()
            .filter(|(_, n)| n.node.is_leader())
            .max_by_key(|(_, n)| n.node.term())
            .map(|(id, _)| *id)
    }

    fn propose(&mut self) {
        if let Some(l) = self.leader() {
            self.next_cmd += 1;
            let cmd = format!("c{}", self.next_cmd).into_bytes();
            let _ = self.nodes.get_mut(&l).unwrap().node.propose(cmd);
            self.drain(l);
        }
    }

    fn read(&mut self) {
        if let Some(l) = self.leader() {
            self.next_cmd += 1;
            let ctx = self.next_cmd;
            // every write acknowledged so far must be visible to this read
            let min = self.applied_global.keys().next_back().copied().unwrap_or(0);
            if self.nodes.get_mut(&l).unwrap().node.read_index(ctx).is_ok() {
                self.reads.insert(ctx, min);
            }
            self.drain(l);
        }
    }

    fn crash(&mut self, id: NodeId) {
        if let Some(sn) = self.nodes.remove(&id) {
            self.down.insert(id, (sn.store, sn.sm));
        }
    }

    fn restart(&mut self, id: NodeId) {
        if let Some((store, sm)) = self.down.remove(&id) {
            let node = Node::restore(id, store.clone(), sm.applied, self.cfg);
            self.nodes.insert(id, SimNode { node, store, sm });
        }
    }

    fn heal(&mut self) {
        self.side_a = None;
        self.drop_pct = 0;
        self.dup_pct = 0;
        self.max_delay = 1;
        let ids: Vec<NodeId> = self.down.keys().copied().collect();
        for id in ids {
            self.restart(id);
        }
    }

    /// After healing: a leader exists, a new write commits everywhere, all logs agree, and
    /// every acknowledged write is in every state machine.
    fn converge(&mut self, ticks: u64) {
        for _ in 0..ticks {
            self.step_time();
        }
        assert!(self.leader().is_some(), "LIVENESS: no leader after healing");
        let marker = format!("final-{}", self.next_cmd).into_bytes();
        let mut done = false;
        for _ in 0..ticks {
            if !done && let Some(l) = self.leader() {
                let n = &mut self.nodes.get_mut(&l).unwrap().node;
                if n.propose(marker.clone()).is_ok() {
                    done = true;
                }
                self.drain(l);
            }
            self.step_time();
        }
        for _ in 0..ticks {
            self.step_time();
        }
        let first = self.nodes.values().next().unwrap().sm.cmds.clone();
        let voters = self.nodes.values().next().unwrap().node.voters();
        for (id, sn) in &self.nodes {
            if !voters.contains(id) {
                continue;
            }
            assert_eq!(
                sn.sm.cmds, first,
                "node {id} state machine differs after convergence"
            );
            assert!(
                sn.sm.cmds.iter().any(|(_, c)| *c == marker),
                "LIVENESS: final write not applied on node {id}"
            );
        }
        let have: BTreeSet<&Vec<u8>> = first.iter().map(|(_, c)| c).collect();
        for a in &self.acked {
            assert!(
                have.contains(a),
                "DURABILITY: acknowledged write {:?} lost",
                String::from_utf8_lossy(a)
            );
        }
    }
}

fn chaos(n: u64, seed: u64, ticks: u64, snapshots: bool) -> Sim {
    let mut s = Sim::new(n, seed);
    if snapshots {
        s.compact_every = 20;
    }
    for _ in 0..ticks {
        let r = s.rng.below(1000);
        match r {
            0..=7 => {
                // new random partition
                let mut a = BTreeSet::new();
                for id in 1..=n {
                    if s.rng.chance(50) {
                        a.insert(id);
                    }
                }
                s.side_a = Some(a);
            }
            8..=15 => s.side_a = None,
            16..=19 => {
                let id = 1 + s.rng.below(n);
                // keep a majority alive most of the time
                if (s.down.len() as u64) < n / 2 {
                    s.crash(id);
                }
            }
            20..=27 => {
                if let Some(&id) = s.down.keys().next() {
                    s.restart(id);
                }
            }
            28..=31 => {
                s.drop_pct = s.rng.below(30);
                s.dup_pct = s.rng.below(10);
                s.max_delay = 1 + s.rng.below(6);
            }
            _ => {}
        }
        if s.rng.chance(30) {
            s.propose();
        }
        if s.rng.chance(10) {
            s.read();
        }
        s.step_time();
    }
    s.heal();
    s.converge(300);
    s
}

#[test]
fn basic_replication() {
    let mut s = Sim::new(3, 1);
    for _ in 0..100 {
        s.step_time();
    }
    let l = s.leader().expect("leader elected");
    for _ in 0..50 {
        s.propose();
        s.step_time();
    }
    s.converge(100);
    assert_eq!(
        s.leader(),
        Some(l),
        "stable network: leader does not change"
    );
    assert!(s.nodes.values().all(|n| n.sm.cmds.len() == 51));
}

#[test]
fn single_node_cluster() {
    let mut s = Sim::new(1, 2);
    for _ in 0..50 {
        s.step_time();
    }
    for _ in 0..10 {
        s.propose();
        s.read();
        s.step_time();
    }
    s.converge(50);
    assert_eq!(s.nodes[&1].sm.cmds.len(), 11);
    assert!(s.reads_done >= 10);
}

#[test]
fn chaos_three_nodes_many_seeds() {
    let mut reads = 0;
    let mut writes = 0;
    for seed in 1..=120 {
        let s = chaos(3, seed, 1500, false);
        reads += s.reads_done;
        writes += s.acked.len();
    }
    assert!(
        writes > 10_000 && reads > 1_000,
        "workload ran: {writes} writes, {reads} reads"
    );
}

#[test]
fn chaos_five_nodes_with_snapshots() {
    for seed in 1..=60 {
        let s = chaos(5, 1000 + seed, 2000, true);
        assert!(
            s.nodes.values().any(|n| n.node.snapshot_index() > 0),
            "snapshots were taken"
        );
    }
}

#[test]
fn isolated_leader_steps_down_and_does_not_disrupt_on_return() {
    let mut s = Sim::new(5, 7);
    for _ in 0..100 {
        s.step_time();
    }
    let old = s.leader().unwrap();
    let rest: BTreeSet<NodeId> = (1..=5).filter(|i| *i != old).collect();
    s.side_a = Some(rest);
    for _ in 0..80 {
        s.propose();
        s.step_time();
    }
    assert!(
        !s.nodes[&old].node.is_leader(),
        "CheckQuorum: isolated leader stepped down"
    );
    let new = s.leader().unwrap();
    assert_ne!(new, old);
    let term = s.nodes[&new].node.term();
    // the old leader kept timing out alone, but PreVote kept its term from inflating
    assert!(s.nodes[&old].node.term() <= term);
    s.side_a = None;
    for _ in 0..100 {
        s.step_time();
    }
    assert_eq!(
        s.leader(),
        Some(new),
        "returning node did not depose the leader"
    );
    assert_eq!(s.nodes[&new].node.term(), term, "no term inflation");
    s.converge(100);
}

#[test]
fn minority_cannot_commit() {
    let mut s = Sim::new(5, 9);
    for _ in 0..100 {
        s.step_time();
    }
    let l = s.leader().unwrap();
    let other = if l == 1 { 2 } else { 1 };
    s.side_a = Some([l, other].into_iter().collect());
    let before = s.applied_global.len();
    // the old leader accepts proposals until it steps down, but can't commit them
    for _ in 0..5 {
        let _ = s
            .nodes
            .get_mut(&l)
            .unwrap()
            .node
            .propose(b"minority".to_vec());
        s.drain(l);
        s.step_time();
    }
    for _ in 0..60 {
        s.step_time();
    }
    assert!(
        s.applied_global
            .values()
            .all(|(_, k)| *k != EntryKind::Data(b"minority".to_vec())),
        "minority-side write committed"
    );
    assert!(s.applied_global.len() >= before);
    s.side_a = None;
    s.converge(200);
    for sn in s.nodes.values() {
        assert!(
            !sn.sm.cmds.iter().any(|(_, c)| c == b"minority"),
            "uncommitted write survived"
        );
    }
}

#[test]
fn membership_changes_under_faults() {
    let mut s = Sim::new(3, 11);
    for _ in 0..100 {
        s.step_time();
    }
    // add node 4 (starts empty, learns everything from the leader)
    s.nodes.insert(
        4,
        SimNode {
            node: Node::new(4, &[], s.cfg),
            store: Persisted::default(),
            sm: Sm::default(),
        },
    );
    let mut changed = false;
    for _ in 0..400 {
        if !changed && let Some(l) = s.leader() {
            changed = s
                .nodes
                .get_mut(&l)
                .unwrap()
                .node
                .propose_config(vec![1, 2, 3, 4])
                .is_ok();
            s.drain(l);
        }
        if s.rng.chance(30) {
            s.propose();
        }
        s.drop_pct = 10;
        s.step_time();
    }
    s.drop_pct = 0;
    for _ in 0..100 {
        s.step_time();
    }
    for sn in s.nodes.values() {
        assert_eq!(sn.node.voters(), vec![1, 2, 3, 4]);
    }
    // two changes at once are refused
    let l = s.leader().unwrap();
    assert!(matches!(
        s.nodes.get_mut(&l).unwrap().node.propose_config(vec![1, 2]),
        Err(ProposeError::BadConfig(_))
    ));
    // remove the current leader
    let rest: Vec<NodeId> = [1, 2, 3, 4].into_iter().filter(|i| *i != l).collect();
    s.nodes
        .get_mut(&l)
        .unwrap()
        .node
        .propose_config(rest.clone())
        .unwrap();
    s.drain(l);
    for _ in 0..300 {
        if s.rng.chance(30) {
            s.propose();
        }
        s.step_time();
    }
    let nl = s.leader().unwrap();
    assert_ne!(nl, l, "removed leader stepped down");
    assert_eq!(s.nodes[&nl].node.voters(), rest);
    s.crash(l); // decommissioned
    s.down.clear();
    s.converge(200);
}

#[test]
fn lagging_node_catches_up_from_snapshot() {
    let mut s = Sim::new(3, 13);
    s.compact_every = 10;
    for _ in 0..100 {
        s.step_time();
    }
    let l = s.leader().unwrap();
    let lag = if l == 3 { 2 } else { 3 };
    s.crash(lag);
    for _ in 0..300 {
        s.propose();
        s.step_time();
    }
    assert!(
        s.nodes[&l].node.snapshot_index() > 50,
        "leader compacted its log"
    );
    s.restart(lag);
    s.converge(200);
    assert!(
        s.nodes[&lag].node.snapshot_index() > 0,
        "follower installed a snapshot"
    );
}

#[test]
fn restart_keeps_votes_and_log() {
    // A node must not vote twice in a term across a crash: hard state is persisted.
    let mut s = Sim::new(3, 17);
    for _ in 0..100 {
        s.step_time();
    }
    for id in 1..=3 {
        s.crash(id);
        s.restart(id);
        for _ in 0..30 {
            s.propose();
            s.step_time();
        }
    }
    s.converge(200);
}

/// Long soak: `NOVADB_RAFT_SEEDS=5000 cargo test --release -p novadb-raft -- --ignored`.
#[test]
#[ignore]
fn chaos_soak() {
    let n: u64 = std::env::var("NOVADB_RAFT_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000);
    for seed in 0..n {
        chaos(3 + 2 * (seed % 2), 50_000 + seed, 2500, seed % 3 == 0);
    }
}
