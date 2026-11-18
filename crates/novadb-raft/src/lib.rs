//! Raft consensus core for NovaDB (Stage 8).
//!
//! Deterministic and free of I/O: the driver feeds it clock ticks ([`Node::tick`]) and
//! messages ([`Node::step`]), and after each call takes a [`Ready`] that says what to persist,
//! what to send and what to apply. Rules for the driver:
//! 1. persist `Ready::hard_state`, `Ready::snapshot` and `Ready::entries` (truncate the stored log
//!    at `entries[0].index` first) **durably before** sending `Ready::messages`;
//! 2. apply `Ready::committed` in order (and install `Ready::snapshot` data first if present);
//! 3. answer linearizable reads in `Ready::reads` once the state machine has applied the index.
//!
//! Implemented: leader election with randomized timeouts, **PreVote** (a partitioned node does
//! not disrupt the cluster when it returns) and **CheckQuorum** (a leader that cannot reach a
//! majority steps down; followers ignore vote requests while they hear from a leader — no
//! split brain without quorum, PLAN.md §4.11), log replication with fast conflict back-off,
//! commit only of current-term entries, **ReadIndex** linearizable reads, snapshots /
//! log compaction with InstallSnapshot, and single-server membership changes.
#![forbid(unsafe_code)]

pub mod codec;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub type NodeId = u64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    /// Appended by every new leader so it can commit earlier terms' entries.
    Noop,
    Data(Vec<u8>),
    /// New voter set (takes effect when appended; one change at a time).
    Config(Vec<NodeId>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub term: u64,
    pub index: u64,
    pub kind: EntryKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HardState {
    pub term: u64,
    pub voted_for: Option<NodeId>,
}

/// Snapshot of the state machine up to and including `index`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub index: u64,
    pub term: u64,
    pub voters: Vec<NodeId>,
    pub data: Arc<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    Vote {
        term: u64,
        last_index: u64,
        last_term: u64,
        pre: bool,
    },
    VoteResp {
        term: u64,
        granted: bool,
        pre: bool,
    },
    Append {
        term: u64,
        prev_index: u64,
        prev_term: u64,
        entries: Vec<Entry>,
        commit: u64,
        /// Heartbeat round (echoed; confirms leadership for ReadIndex).
        seq: u64,
    },
    AppendResp {
        term: u64,
        success: bool,
        /// success: last index known to match; failure: where the leader should retry.
        index: u64,
        seq: u64,
    },
    InstallSnapshot {
        term: u64,
        snapshot: Snapshot,
        seq: u64,
    },
}

impl Msg {
    pub fn term(&self) -> u64 {
        match self {
            Msg::Vote { term, .. }
            | Msg::VoteResp { term, .. }
            | Msg::Append { term, .. }
            | Msg::AppendResp { term, .. }
            | Msg::InstallSnapshot { term, .. } => *term,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub from: NodeId,
    pub to: NodeId,
    pub msg: Msg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Follower,
    PreCandidate,
    Candidate,
    Leader,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposeError {
    /// Not the leader; the known leader (if any) to retry with.
    NotLeader(Option<NodeId>),
    /// A membership change is still in progress.
    ConfigChangePending,
    /// Bad membership change (e.g. empty voter set, more than one node changed).
    BadConfig(String),
}

#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// Election timeout is randomized in [election_ticks, 2*election_ticks).
    pub election_ticks: u32,
    pub heartbeat_ticks: u32,
    pub max_entries_per_msg: usize,
    pub pre_vote: bool,
    pub check_quorum: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            election_ticks: 10,
            heartbeat_ticks: 2,
            max_entries_per_msg: 64,
            pre_vote: true,
            check_quorum: true,
        }
    }
}

/// What the driver must do after `tick`/`step`/`propose`.
#[derive(Debug, Default)]
pub struct Ready {
    pub hard_state: Option<HardState>,
    /// Delete stored entries with index >= this before appending `entries`.
    pub truncate: Option<u64>,
    /// Append to the stored log.
    pub entries: Vec<Entry>,
    /// New snapshot to persist (and, if it came from the leader, to install into the state
    /// machine — `install` is true then).
    pub snapshot: Option<Snapshot>,
    pub install: bool,
    pub messages: Vec<Envelope>,
    /// Newly committed entries to apply, in order.
    pub committed: Vec<Entry>,
    /// Linearizable reads: (ctx, index) — safe once the state machine has applied `index`.
    pub reads: Vec<(u64, u64)>,
}

impl Ready {
    pub fn is_empty(&self) -> bool {
        self.hard_state.is_none()
            && self.entries.is_empty()
            && self.truncate.is_none()
            && self.snapshot.is_none()
            && self.messages.is_empty()
            && self.committed.is_empty()
            && self.reads.is_empty()
    }
}

#[derive(Debug, Clone)]
struct Progress {
    next: u64,
    matched: u64,
    active: bool,
    /// Highest heartbeat round this peer answered in the current term.
    acked_seq: u64,
}

#[derive(Debug, Clone)]
struct ReadReq {
    ctx: u64,
    index: u64,
    seq: u64,
}

pub struct Node {
    pub id: NodeId,
    cfg: Config,
    voters: BTreeSet<NodeId>,
    role: Role,
    term: u64,
    voted_for: Option<NodeId>,
    leader: Option<NodeId>,
    /// Entries after the snapshot.
    log: Vec<Entry>,
    snap: Snapshot,
    commit: u64,
    applied: u64,
    election_elapsed: u32,
    election_timeout: u32,
    heartbeat_elapsed: u32,
    votes: BTreeMap<NodeId, bool>,
    progress: BTreeMap<NodeId, Progress>,
    seq: u64,
    reads: Vec<ReadReq>,
    rng: u64,
    // pending output
    msgs: Vec<Envelope>,
    hs_dirty: bool,
    persist_from: Option<u64>,
    snap_dirty: bool,
    snap_install: bool,
    reads_ready: Vec<(u64, u64)>,
}

/// Durable state the driver gives back after a restart.
#[derive(Debug, Clone, Default)]
pub struct Persisted {
    pub hard_state: HardState,
    pub snapshot: Option<Snapshot>,
    pub entries: Vec<Entry>,
}

fn majority(n: usize) -> usize {
    n / 2 + 1
}

impl Node {
    /// A brand-new node. `voters` is the initial cluster (empty for a node that will be added
    /// by a membership change and learns the configuration from the leader).
    pub fn new(id: NodeId, voters: &[NodeId], cfg: Config) -> Node {
        Self::restore(
            id,
            Persisted {
                hard_state: HardState::default(),
                snapshot: Some(Snapshot {
                    index: 0,
                    term: 0,
                    voters: voters.to_vec(),
                    data: Arc::new(Vec::new()),
                }),
                entries: Vec::new(),
            },
            0,
            cfg,
        )
    }

    /// Restart from persisted state. `applied`: index the state machine durably applied (it is
    /// committed, so the node starts with commit = applied).
    pub fn restore(id: NodeId, p: Persisted, applied: u64, cfg: Config) -> Node {
        let snap = p.snapshot.unwrap_or(Snapshot {
            index: 0,
            term: 0,
            voters: Vec::new(),
            data: Arc::new(Vec::new()),
        });
        let log: Vec<Entry> = p
            .entries
            .into_iter()
            .filter(|e| e.index > snap.index)
            .collect();
        let last = log.last().map_or(snap.index, |e| e.index);
        let applied = applied.max(snap.index).min(last);
        let mut n = Node {
            id,
            cfg,
            voters: BTreeSet::new(),
            role: Role::Follower,
            term: p.hard_state.term,
            voted_for: p.hard_state.voted_for,
            leader: None,
            log,
            snap,
            commit: applied,
            applied,
            election_elapsed: 0,
            election_timeout: cfg.election_ticks,
            heartbeat_elapsed: 0,
            votes: BTreeMap::new(),
            progress: BTreeMap::new(),
            seq: 0,
            reads: Vec::new(),
            rng: 0x9E37_79B9_7F4A_7C15 ^ id.wrapping_mul(0xA24B_AED4_963E_E407),
            msgs: Vec::new(),
            hs_dirty: false,
            persist_from: None,
            snap_dirty: false,
            snap_install: false,
            reads_ready: Vec::new(),
        };
        n.recompute_voters();
        n.reset_election_timeout();
        n
    }

    // ----- accessors ---------------------------------------------------------------------

    pub fn role(&self) -> Role {
        self.role
    }
    pub fn term(&self) -> u64 {
        self.term
    }
    pub fn leader(&self) -> Option<NodeId> {
        self.leader
    }
    pub fn is_leader(&self) -> bool {
        self.role == Role::Leader
    }
    pub fn commit_index(&self) -> u64 {
        self.commit
    }
    pub fn applied_index(&self) -> u64 {
        self.applied
    }
    pub fn last_index(&self) -> u64 {
        self.log.last().map_or(self.snap.index, |e| e.index)
    }
    pub fn voters(&self) -> Vec<NodeId> {
        self.voters.iter().copied().collect()
    }
    pub fn snapshot_index(&self) -> u64 {
        self.snap.index
    }
    /// Entries in the log (after the snapshot).
    pub fn entries(&self) -> &[Entry] {
        &self.log
    }

    fn last_term(&self) -> u64 {
        self.log.last().map_or(self.snap.term, |e| e.term)
    }

    fn term_at(&self, i: u64) -> Option<u64> {
        if i == self.snap.index {
            return Some(self.snap.term);
        }
        if i < self.snap.index {
            return None;
        }
        self.log
            .get((i - self.snap.index - 1) as usize)
            .map(|e| e.term)
    }

    fn entry(&self, i: u64) -> Option<&Entry> {
        if i <= self.snap.index {
            return None;
        }
        self.log.get((i - self.snap.index - 1) as usize)
    }

    fn rand(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn reset_election_timeout(&mut self) {
        let e = u64::from(self.cfg.election_ticks.max(1));
        self.election_timeout = (e + self.rand() % e) as u32;
        self.election_elapsed = 0;
    }

    fn recompute_voters(&mut self) {
        let mut v: BTreeSet<NodeId> = self.snap.voters.iter().copied().collect();
        for e in &self.log {
            if let EntryKind::Config(c) = &e.kind {
                v = c.iter().copied().collect();
            }
        }
        self.voters = v;
    }

    fn send(&mut self, to: NodeId, msg: Msg) {
        self.msgs.push(Envelope {
            from: self.id,
            to,
            msg,
        });
    }

    fn mark_persist(&mut self, from: u64) {
        self.persist_from = Some(self.persist_from.map_or(from, |p| p.min(from)));
    }

    // ----- driver interface ---------------------------------------------------------------

    /// One clock tick.
    pub fn tick(&mut self) {
        if self.role == Role::Leader {
            self.heartbeat_elapsed += 1;
            self.election_elapsed += 1;
            if self.heartbeat_elapsed >= self.cfg.heartbeat_ticks {
                self.heartbeat_elapsed = 0;
                self.broadcast_append(true);
            }
            if self.election_elapsed >= self.cfg.election_ticks {
                self.election_elapsed = 0;
                if self.cfg.check_quorum {
                    let id = self.id;
                    let active = self
                        .voters
                        .iter()
                        .filter(|v| **v == id || self.progress.get(v).is_some_and(|p| p.active))
                        .count();
                    for p in self.progress.values_mut() {
                        p.active = false;
                    }
                    if active < majority(self.voters.len()) {
                        // Cannot reach a majority: stop acting as leader (no split brain).
                        let t = self.term;
                        self.become_follower(t, None);
                    }
                }
            }
            return;
        }
        self.election_elapsed += 1;
        if self.election_elapsed >= self.election_timeout && self.voters.contains(&self.id) {
            if self.cfg.pre_vote {
                self.campaign(true);
            } else {
                self.campaign(false);
            }
        }
    }

    /// Propose a state-machine command. Returns its log index.
    pub fn propose(&mut self, data: Vec<u8>) -> Result<u64, ProposeError> {
        if self.role != Role::Leader {
            return Err(ProposeError::NotLeader(self.leader));
        }
        Ok(self.append_local(EntryKind::Data(data)))
    }

    /// Change the voter set by adding or removing exactly one node.
    pub fn propose_config(&mut self, voters: Vec<NodeId>) -> Result<u64, ProposeError> {
        if self.role != Role::Leader {
            return Err(ProposeError::NotLeader(self.leader));
        }
        let new: BTreeSet<NodeId> = voters.iter().copied().collect();
        if new.is_empty() {
            return Err(ProposeError::BadConfig("empty voter set".into()));
        }
        let diff = new.symmetric_difference(&self.voters).count();
        if diff != 1 {
            return Err(ProposeError::BadConfig(
                "change exactly one voter at a time".into(),
            ));
        }
        // One change at a time: the previous one must be committed.
        let pending = self
            .log
            .iter()
            .any(|e| e.index > self.commit && matches!(e.kind, EntryKind::Config(_)));
        if pending {
            return Err(ProposeError::ConfigChangePending);
        }
        Ok(self.append_local(EntryKind::Config(new.into_iter().collect())))
    }

    /// Request a linearizable read; `ctx` comes back in `Ready::reads` with the read index.
    pub fn read_index(&mut self, ctx: u64) -> Result<(), ProposeError> {
        if self.role != Role::Leader {
            return Err(ProposeError::NotLeader(self.leader));
        }
        self.seq += 1;
        let seq = self.seq;
        self.reads.push(ReadReq {
            ctx,
            index: self.commit,
            seq,
        });
        if self.voters.len() == 1 {
            self.resolve_reads();
        } else {
            self.broadcast_append(true);
        }
        Ok(())
    }

    /// The state machine has a snapshot up to `index` (≤ applied): drop the log before it.
    pub fn compact(&mut self, index: u64, data: Arc<Vec<u8>>) {
        if index <= self.snap.index || index > self.applied {
            return;
        }
        let Some(term) = self.term_at(index) else {
            return;
        };
        // voters as of `index`
        let mut voters: Vec<NodeId> = self.snap.voters.clone();
        for e in &self.log {
            if e.index > index {
                break;
            }
            if let EntryKind::Config(c) = &e.kind {
                voters = c.clone();
            }
        }
        let keep = (index - self.snap.index) as usize;
        self.log.drain(..keep.min(self.log.len()));
        self.snap = Snapshot {
            index,
            term,
            voters,
            data,
        };
        self.snap_dirty = true;
        self.snap_install = false;
    }

    /// Take the pending work.
    pub fn ready(&mut self) -> Ready {
        let mut r = Ready::default();
        if self.hs_dirty {
            r.hard_state = Some(HardState {
                term: self.term,
                voted_for: self.voted_for,
            });
            self.hs_dirty = false;
        }
        if self.snap_dirty {
            r.snapshot = Some(self.snap.clone());
            r.install = self.snap_install;
            self.snap_dirty = false;
            self.snap_install = false;
        }
        if let Some(from) = self.persist_from.take() {
            let from = from.max(self.snap.index + 1);
            r.truncate = Some(from);
            r.entries = self
                .log
                .iter()
                .filter(|e| e.index >= from)
                .cloned()
                .collect();
        }
        r.messages = std::mem::take(&mut self.msgs);
        if self.commit > self.applied {
            let from = self.applied + 1;
            r.committed = (from..=self.commit)
                .filter_map(|i| self.entry(i).cloned())
                .collect();
            self.applied = self.commit;
        }
        r.reads = std::mem::take(&mut self.reads_ready);
        r
    }

    // ----- roles -------------------------------------------------------------------------

    fn become_follower(&mut self, term: u64, leader: Option<NodeId>) {
        if term != self.term {
            self.term = term;
            self.voted_for = None;
            self.hs_dirty = true;
        }
        self.role = Role::Follower;
        self.leader = leader;
        self.votes.clear();
        self.progress.clear();
        self.reads.clear();
        self.reset_election_timeout();
    }

    fn campaign(&mut self, pre: bool) {
        self.votes.clear();
        self.leader = None;
        self.reset_election_timeout();
        let term = if pre {
            self.role = Role::PreCandidate;
            self.term + 1
        } else {
            self.role = Role::Candidate;
            self.term += 1;
            self.voted_for = Some(self.id);
            self.hs_dirty = true;
            self.term
        };
        self.votes.insert(self.id, true);
        if self.votes_won() {
            self.on_votes_won(pre);
            return;
        }
        let (li, lt) = (self.last_index(), self.last_term());
        let peers: Vec<NodeId> = self
            .voters
            .iter()
            .copied()
            .filter(|v| *v != self.id)
            .collect();
        for p in peers {
            self.send(
                p,
                Msg::Vote {
                    term,
                    last_index: li,
                    last_term: lt,
                    pre,
                },
            );
        }
    }

    fn votes_won(&self) -> bool {
        let yes = self
            .voters
            .iter()
            .filter(|v| self.votes.get(v) == Some(&true))
            .count();
        yes >= majority(self.voters.len())
    }

    fn votes_lost(&self) -> bool {
        let no = self
            .voters
            .iter()
            .filter(|v| self.votes.get(v) == Some(&false))
            .count();
        no >= majority(self.voters.len())
    }

    fn on_votes_won(&mut self, pre: bool) {
        if pre {
            self.campaign(false);
        } else {
            self.become_leader();
        }
    }

    fn become_leader(&mut self) {
        self.role = Role::Leader;
        self.leader = Some(self.id);
        self.heartbeat_elapsed = 0;
        self.election_elapsed = 0;
        self.votes.clear();
        let last = self.last_index();
        self.progress = self
            .voters
            .iter()
            .filter(|v| **v != self.id)
            .map(|v| {
                (
                    *v,
                    Progress {
                        next: last + 1,
                        matched: 0,
                        active: true,
                        acked_seq: 0,
                    },
                )
            })
            .collect();
        self.append_local(EntryKind::Noop);
    }

    fn append_local(&mut self, kind: EntryKind) -> u64 {
        let index = self.last_index() + 1;
        let is_conf = matches!(kind, EntryKind::Config(_));
        self.log.push(Entry {
            term: self.term,
            index,
            kind,
        });
        self.mark_persist(index);
        if is_conf {
            self.on_config_changed();
        }
        self.maybe_commit();
        self.broadcast_append(false);
        index
    }

    fn on_config_changed(&mut self) {
        self.recompute_voters();
        if self.role == Role::Leader {
            let last = self.last_index();
            let id = self.id;
            for v in self.voters.clone() {
                if v != id {
                    self.progress.entry(v).or_insert(Progress {
                        next: last,
                        matched: 0,
                        active: true,
                        acked_seq: 0,
                    });
                }
            }
            let voters = self.voters.clone();
            self.progress.retain(|k, _| voters.contains(k));
        }
    }

    // ----- replication -------------------------------------------------------------------

    fn broadcast_append(&mut self, heartbeat: bool) {
        if self.role != Role::Leader {
            return;
        }
        if heartbeat {
            self.seq += 1;
        }
        let peers: Vec<NodeId> = self.progress.keys().copied().collect();
        for p in peers {
            self.send_append(p, heartbeat);
        }
    }

    fn send_append(&mut self, to: NodeId, allow_empty: bool) {
        let Some(pr) = self.progress.get(&to).cloned() else {
            return;
        };
        if pr.next <= self.snap.index {
            let snapshot = self.snap.clone();
            let (term, seq) = (self.term, self.seq);
            self.send(
                to,
                Msg::InstallSnapshot {
                    term,
                    snapshot,
                    seq,
                },
            );
            return;
        }
        let prev_index = pr.next - 1;
        let Some(prev_term) = self.term_at(prev_index) else {
            return;
        };
        let entries: Vec<Entry> = (pr.next..=self.last_index())
            .take(self.cfg.max_entries_per_msg)
            .filter_map(|i| self.entry(i).cloned())
            .collect();
        if entries.is_empty() && !allow_empty {
            return;
        }
        let (term, commit, seq) = (self.term, self.commit, self.seq);
        self.send(
            to,
            Msg::Append {
                term,
                prev_index,
                prev_term,
                entries,
                commit,
                seq,
            },
        );
    }

    fn maybe_commit(&mut self) {
        if self.role != Role::Leader {
            return;
        }
        let mut matched: Vec<u64> = self
            .voters
            .iter()
            .map(|v| {
                if *v == self.id {
                    self.last_index()
                } else {
                    self.progress.get(v).map_or(0, |p| p.matched)
                }
            })
            .collect();
        if matched.is_empty() {
            return;
        }
        matched.sort_unstable_by(|a, b| b.cmp(a));
        let n = matched[majority(self.voters.len()) - 1];
        // Only entries of the current term are committed by counting replicas (Raft §5.4.2).
        if n > self.commit && self.term_at(n) == Some(self.term) {
            self.commit = n;
            // A leader removed from the configuration steps down once that is committed.
            if !self.voters.contains(&self.id) {
                let t = self.term;
                self.broadcast_append(true);
                self.become_follower(t, None);
                return;
            }
            self.broadcast_append(false);
            self.resolve_reads();
        }
    }

    fn resolve_reads(&mut self) {
        if self.role != Role::Leader || self.term_at(self.commit) != Some(self.term) {
            return; // must have committed an entry of this term first
        }
        let id = self.id;
        let quorum = majority(self.voters.len());
        let mut keep = Vec::new();
        for r in std::mem::take(&mut self.reads) {
            let acks = self
                .voters
                .iter()
                .filter(|v| **v == id || self.progress.get(v).is_some_and(|p| p.acked_seq >= r.seq))
                .count();
            if acks >= quorum {
                // The commit index known when leadership is confirmed (≥ the one at request
                // time; a new leader's commit can lag until its own entry commits).
                self.reads_ready.push((r.ctx, r.index.max(self.commit)));
            } else {
                keep.push(r);
            }
        }
        self.reads = keep;
    }

    /// Handle a message.
    pub fn step(&mut self, from: NodeId, msg: Msg) {
        let t = msg.term();
        // Votes for a future term while we still hear from a live leader are ignored
        // (CheckQuorum lease): a partitioned node can't depose a healthy leader.
        if let Msg::Vote { pre, .. } = &msg
            && t > self.term
            && self.cfg.check_quorum
            && self.leader.is_some()
            && self.election_elapsed < self.cfg.election_ticks
        {
            let pre = *pre;
            if pre {
                let term = self.term;
                self.send(
                    from,
                    Msg::VoteResp {
                        term,
                        granted: false,
                        pre: true,
                    },
                );
            }
            return;
        }
        match &msg {
            Msg::Vote { pre: true, .. } | Msg::VoteResp { pre: true, .. } => {}
            _ if t > self.term => {
                let leader = match msg {
                    Msg::Append { .. } | Msg::InstallSnapshot { .. } => Some(from),
                    _ => None,
                };
                self.become_follower(t, leader);
            }
            _ => {}
        }
        if t < self.term {
            // stale: tell the sender our term so it steps down
            match msg {
                Msg::Append { seq, .. } | Msg::InstallSnapshot { seq, .. } => {
                    let term = self.term;
                    self.send(
                        from,
                        Msg::AppendResp {
                            term,
                            success: false,
                            index: 0,
                            seq,
                        },
                    );
                }
                Msg::Vote { pre, .. } => {
                    let term = self.term;
                    self.send(
                        from,
                        Msg::VoteResp {
                            term,
                            granted: false,
                            pre,
                        },
                    );
                }
                _ => {}
            }
            return;
        }
        match msg {
            Msg::Vote {
                term,
                last_index,
                last_term,
                pre,
            } => {
                let up_to_date = last_term > self.last_term()
                    || (last_term == self.last_term() && last_index >= self.last_index());
                let granted = if pre {
                    // grant a pre-vote if we would vote and we don't hear from a leader
                    up_to_date
                        && (self.leader.is_none()
                            || self.election_elapsed >= self.cfg.election_ticks)
                } else {
                    let ok =
                        up_to_date && (self.voted_for.is_none() || self.voted_for == Some(from));
                    if ok {
                        self.voted_for = Some(from);
                        self.hs_dirty = true;
                        self.election_elapsed = 0;
                    }
                    ok
                };
                // pre-vote replies carry the asked-for term so the candidate counts them
                let rterm = if pre { term } else { self.term };
                self.send(
                    from,
                    Msg::VoteResp {
                        term: rterm,
                        granted,
                        pre,
                    },
                );
            }
            Msg::VoteResp { term, granted, pre } => {
                let expected = if pre {
                    Role::PreCandidate
                } else {
                    Role::Candidate
                };
                if self.role != expected {
                    return;
                }
                if pre && term != self.term + 1 {
                    if term > self.term + 1 && !granted {
                        // someone is ahead of us: adopt their term
                        self.become_follower(term, None);
                    }
                    return;
                }
                self.votes.insert(from, granted);
                if self.votes_won() {
                    self.on_votes_won(pre);
                } else if self.votes_lost() {
                    let t = self.term;
                    self.become_follower(t, None);
                }
            }
            Msg::Append {
                prev_index,
                prev_term,
                entries,
                commit,
                seq,
                ..
            } => {
                self.role = Role::Follower;
                self.leader = Some(from);
                self.election_elapsed = 0;
                let resp = self.handle_append(prev_index, prev_term, entries, commit);
                let term = self.term;
                let (success, index) = resp;
                self.send(
                    from,
                    Msg::AppendResp {
                        term,
                        success,
                        index,
                        seq,
                    },
                );
            }
            Msg::AppendResp {
                success,
                index,
                seq,
                ..
            } => {
                if self.role != Role::Leader {
                    return;
                }
                let last = self.last_index();
                let Some(pr) = self.progress.get_mut(&from) else {
                    return;
                };
                pr.active = true;
                pr.acked_seq = pr.acked_seq.max(seq);
                if success {
                    if index > pr.matched {
                        pr.matched = index.min(last);
                    }
                    pr.next = pr.next.max(pr.matched + 1);
                    let more = pr.next <= last;
                    self.maybe_commit();
                    if more {
                        self.send_append(from, false);
                    }
                } else {
                    pr.next = index
                        .max(pr.matched + 1)
                        .max(1)
                        .min(pr.next.saturating_sub(1).max(1));
                    self.send_append(from, true);
                }
                self.resolve_reads();
            }
            Msg::InstallSnapshot { snapshot, seq, .. } => {
                self.role = Role::Follower;
                self.leader = Some(from);
                self.election_elapsed = 0;
                let idx = self.handle_snapshot(snapshot);
                let term = self.term;
                self.send(
                    from,
                    Msg::AppendResp {
                        term,
                        success: true,
                        index: idx,
                        seq,
                    },
                );
            }
        }
    }

    fn handle_append(
        &mut self,
        prev_index: u64,
        prev_term: u64,
        entries: Vec<Entry>,
        leader_commit: u64,
    ) -> (bool, u64) {
        if prev_index < self.commit {
            // Part of it is already committed here; skip that part (it must match).
            let skip = (self.commit - prev_index) as usize;
            if skip >= entries.len() {
                return (true, self.commit);
            }
            let rest = entries[skip..].to_vec();
            let pt = rest
                .first()
                .and_then(|e| self.term_at(e.index - 1))
                .unwrap_or(0);
            return self.handle_append(self.commit, pt, rest, leader_commit);
        }
        if prev_index > self.last_index() {
            return (false, self.last_index() + 1);
        }
        match self.term_at(prev_index) {
            Some(t) if t == prev_term => {}
            Some(t) => {
                // back off to the first index of the conflicting term (but past the commit)
                let mut i = prev_index;
                while i > self.commit + 1 && self.term_at(i - 1) == Some(t) {
                    i -= 1;
                }
                return (false, i);
            }
            None => return (false, self.commit + 1),
        }
        let mut conf = false;
        let n = entries.len() as u64;
        for e in entries {
            match self.term_at(e.index) {
                Some(t) if t == e.term => continue,
                Some(_) => {
                    // conflict: drop this and everything after it (never committed entries)
                    let keep = (e.index - self.snap.index - 1) as usize;
                    if self.log[keep..]
                        .iter()
                        .any(|x| matches!(x.kind, EntryKind::Config(_)))
                    {
                        conf = true;
                    }
                    self.log.truncate(keep);
                    self.mark_persist(e.index);
                }
                None => {}
            }
            if matches!(e.kind, EntryKind::Config(_)) {
                conf = true;
            }
            self.mark_persist(e.index);
            self.log.push(e);
        }
        if conf {
            self.on_config_changed();
        }
        let last_new = prev_index + n;
        if leader_commit > self.commit {
            self.commit = leader_commit
                .min(last_new.max(self.commit))
                .min(self.last_index());
        }
        (true, last_new)
    }

    fn handle_snapshot(&mut self, s: Snapshot) -> u64 {
        if s.index <= self.commit {
            return self.commit;
        }
        if self.term_at(s.index) == Some(s.term) {
            // keep the suffix after the snapshot
            let keep = (s.index - self.snap.index) as usize;
            self.log.drain(..keep.min(self.log.len()));
        } else {
            self.log.clear();
        }
        let idx = s.index;
        self.snap = s;
        self.commit = idx;
        self.applied = idx;
        self.snap_dirty = true;
        self.snap_install = true;
        self.mark_persist(idx + 1);
        self.recompute_voters();
        idx
    }
}
