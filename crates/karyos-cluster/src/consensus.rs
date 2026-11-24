// SPDX-License-Identifier: Apache-2.0

//! The custom Raft core's state machine (ADR-0105, part (b) of
//! quantstratum/karyos#681): terms, votes, roles, pre-vote, randomised
//! election timeouts from a seeded source, log matching and the commit
//! rule, for a static membership of 3 or 5 voters.
//!
//! The core is pure: it does no I/O and allocates nothing after
//! [`Core::new`]. It reads the log through [`LogTerms`], C4's log being
//! the only log (it keeps no copy of written entries), and tells its
//! driver what to do through [`Effects`]:
//!
//! - [`Effects::persist`] the term and vote, and [`Effects::write`] a
//!   follower's log suffix, both before any message passed to
//!   [`Effects::send_after_persist`] in the same call leaves the node
//!   (persist then send). A vote, a vote request and an append
//!   acknowledgement are only ever sent that way.
//! - [`Effects::send`] a message that depends on nothing durable.
//! - [`Effects::append`] a leader's no-op entry, and
//!   [`Effects::commit`] a new commit index.
//!
//! **Model.** The state is [`Role`] plus the persistent term and vote and
//! the volatile commit index; each input ([`Core::tick`], [`Core::step`],
//! [`Core::propose`], [`Core::persisted`]) is one transition. The rules
//! are Raft's (Ongaro, figure 2) with pre-vote (section 9.6): a node
//! asks for pre-votes for `term + 1` without changing its term, and
//! starts a real election only with a majority of them, so a node that
//! was partitioned away does not raise the cluster's term on its return.
//! A leader commits an index only when a majority holds it durably and
//! its entry is from the leader's own term; earlier-term entries commit
//! with it, never directly.
//!
//! **Flow limits** (part (c)). Replication is pipelined: a leader sends
//! from each follower's next index and moves it on, and falls back on a
//! rejection. What it has sent a follower and not yet seen acknowledged
//! is in flight, and [`Limits`] bounds it strictly per follower, in
//! entries and in bytes, whatever is lost or delayed: an entry leaves
//! only when it fits the window, and the window frees only on an
//! acknowledgement, so a lost append or reply holds its share until a
//! heartbeat's answer or a rejection settles it. Each send is recorded
//! (first index, last index, bytes) in a fixed ring per follower, so an
//! acknowledgement frees exactly the sends it covers, and a send it covers
//! only in part stays counted whole. A rejection rewinds the follower's
//! pipeline and starts a new epoch, carried by every append and echoed in
//! its reply: a rejection of an earlier epoch (a duplicate, a delayed
//! reply, an append of an earlier term) changes nothing, so no credit is
//! refunded twice. The one exception to the byte window is an entry larger
//! than the whole window, which [`Core::propose`] never admits but a log
//! written under a larger limit may hold: it is sent alone, into an empty
//! window, so replication cannot stall on it.
//!
//! A leader also bounds the entries clients may add while uncommitted
//! (the request queue): a new leader's no-op and the entries it inherits
//! are not refused, since refusing them would stall the very commits that
//! drain the queue. Per duty it looks up at most [`Limits::reads`] entry
//! sizes, counting every lookup, and sends at most [`Limits::read_bytes`]
//! bytes of entries, which is what its driver reads from the log for
//! that duty (W2's log read bound, in bytes). It refuses a proposal it cannot
//! hold with a typed [`Backpressure`], never by growing anything. The core holds no entry
//! buffer: messages carry positions and counts, and the driver reads the
//! entries from C4's log.
//!
//! **Snapshots** (quantstratum/karyos#682). The core keeps the base of
//! the node's latest snapshot, the last index it includes and that
//! entry's term, and reads the log through it: the base's term comes
//! from the core, entries below it may be gone. [`Core::compacted`]
//! moves the base up to a committed index once the driver has compacted
//! below it. A leader that would send a follower an entry the log no
//! longer holds asks its driver for [`Effects::send_snapshot`] instead,
//! holds that follower's appends to heartbeats at the base, and asks
//! again, for the latest snapshot, when no acknowledgement arrives within
//! the minimum election timeout (a lost snapshot is retried, never
//! awaited forever).
//! The follower's driver installs the snapshot and restarts its log after
//! the base, then calls [`Core::install`], which commits the base and
//! acknowledges it to the leader once durable. The core sees no snapshot
//! bytes: the store and its CRC-32C checks are the driver's, and those
//! checks detect corruption only; they claim no tamper evidence.

use crate::hard_state::HardState;

/// The most voters a static membership has.
pub const MAX_VOTERS: usize = 5;

/// What the core reads of its node's log: C4's [`RaftLog`](crate::RaftLog)
/// or a test log.
pub trait LogTerms {
    /// The last index written, 0 for an empty log.
    fn last_index(&self) -> u64;
    /// The term of the entry at `index`; `Some(0)` for index 0, `None`
    /// past the end.
    fn term(&self, index: u64) -> Option<u64>;
    /// The size in bytes the entry at `index` takes in an append, `None`
    /// past the end or for index 0.
    fn size(&self, index: u64) -> Option<u64>;
    /// What reading the entry at `index` to send it costs a duty, in
    /// bytes ([`Limits::read_bytes`]): its size by default; a driver
    /// whose log reads whole frames, or that holds the entry unwritten,
    /// says so here.
    fn cost(&self, index: u64) -> Option<u64> {
        self.size(index)
    }
}

/// What the core asks its driver to do, in the order of the calls.
pub trait Effects {
    /// Persist the term and vote before any message given to
    /// [`Effects::send_after_persist`] in this call is sent.
    fn persist(&mut self, term_vote: TermVote);
    /// Truncate the log from `index` on and append the entries of the
    /// [`Message::Append`] being stepped from its `skip`th on, at
    /// `index`; durable before any [`Effects::send_after_persist`]
    /// message of this call is sent.
    fn write(&mut self, index: u64, skip: u64);
    /// Append a leader's no-op entry of `term` at `index`.
    fn append(&mut self, index: u64, term: u64);
    /// Send `message` to `to` now.
    fn send(&mut self, to: u64, message: Message);
    /// Send `message` to `to` once this call's persists and writes are
    /// durable.
    fn send_after_persist(&mut self, to: u64, message: Message);
    /// The commit index rose to `index`.
    fn commit(&mut self, index: u64);
    /// Send the node's latest snapshot to `to`: it needs entries the log
    /// no longer holds. The core asks at most once per follower per
    /// minimum election timeout until a base is acknowledged; each request
    /// supersedes the follower's earlier ones, so a driver keeps at most
    /// one transfer per follower, replacing or dropping a queued one. A
    /// transfer is not charged to [`Limits`]: they bound appends.
    fn send_snapshot(&mut self, to: u64);
}

/// The persistent term and vote.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TermVote {
    /// The latest term seen.
    pub term: u64,
    /// The voter voted for in `term`, if any.
    pub voted_for: Option<u64>,
}

impl From<HardState> for TermVote {
    fn from(state: HardState) -> Self {
        Self {
            term: state.current_term,
            voted_for: state.voted_for,
        }
    }
}

/// A node's role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Follows `leader`, when it knows one.
    Follower {
        /// The leader of the current term, if heard from.
        leader: Option<u64>,
    },
    /// Asks for pre-votes for the next term, its term unchanged.
    PreCandidate,
    /// Asks for votes in its term, having voted for itself.
    Candidate,
    /// Leads its term.
    Leader,
}

/// A message between cores. The entries of an [`Message::Append`] are
/// named by position: the driver sends the log's entries
/// `prev_index + 1 ..= prev_index + entries` with it and hands their
/// terms to the receiver's [`Core::step`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Message {
    /// A pre-vote request for `term`, the sender's term plus one.
    PreVote {
        /// The term the sender would stand in.
        term: u64,
        /// The sender's last index.
        last_index: u64,
        /// Its term.
        last_term: u64,
        /// The sender's pre-vote round, echoed in the replies.
        round: u64,
    },
    /// A pre-vote answer.
    PreVoteReply {
        /// The requested term when granted, else the voter's term.
        term: u64,
        /// Whether it is granted.
        granted: bool,
        /// The round of the request it answers.
        round: u64,
    },
    /// A vote request.
    Vote {
        /// The candidate's term.
        term: u64,
        /// Its last index.
        last_index: u64,
        /// Its term.
        last_term: u64,
    },
    /// A vote answer.
    VoteReply {
        /// The voter's term.
        term: u64,
        /// Whether it is granted.
        granted: bool,
    },
    /// Entries, or a heartbeat when `entries` is 0.
    Append {
        /// The leader's term.
        term: u64,
        /// The index before the first entry.
        prev_index: u64,
        /// Its term.
        prev_term: u64,
        /// How many entries follow.
        entries: u64,
        /// The leader's commit index.
        commit: u64,
        /// The leader's pipeline epoch for this follower, echoed in the
        /// reply.
        epoch: u64,
    },
    /// An append answer.
    AppendReply {
        /// The follower's term.
        term: u64,
        /// Whether it matched.
        outcome: AppendOutcome,
        /// The epoch of the append it answers; 0 for the acknowledgement of
        /// an installed snapshot, which answers none.
        epoch: u64,
    },
}

/// A follower's answer to an append.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendOutcome {
    /// Its log matches the leader's up to `index`, durably.
    Accepted {
        /// The last matching index.
        index: u64,
    },
    /// Its log does not hold the previous entry; it has at most `hint`
    /// entries that may match.
    Rejected {
        /// The rejected append's previous index.
        probe: u64,
        /// Where the leader should retry from, plus one.
        hint: u64,
    },
}

/// Why a configuration is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    /// Static membership is 3 or 5 voters.
    VoterCount(usize),
    /// The node is not among the voters.
    NotAVoter,
    /// A voter is named twice, or a voter id is 0.
    BadVoter,
    /// The election timeout range is empty or zero, or the heartbeat is
    /// not shorter than its minimum.
    Timeouts,
    /// The append batch is 0 entries.
    Batch,
    /// A flow limit is 0, or the in-flight entries are fewer than a
    /// batch.
    Limits,
}

/// A leader's flow limits (W2's): what it may have in flight to each
/// follower, how many entries it may hold uncommitted, and how many
/// entries it reads from the log per duty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Entries sent to one follower and not acknowledged.
    pub in_flight_entries: u64,
    /// Bytes of those entries.
    pub in_flight_bytes: u64,
    /// Entries clients may have written and not committed: a proposal
    /// past it is refused. A new leader's no-op is not.
    pub queue: u64,
    /// Entry sizes read from the log per duty ([`Core::replicate`], or
    /// one reply's resend or refill), every read counted.
    pub reads: u64,
    /// Bytes of entries sent per duty, across all followers: what the
    /// driver reads from the log for it (W2's `log_read_bytes`). A
    /// proposal larger than it is refused, since it could never be read.
    pub read_bytes: u64,
}

/// Which limit refused a proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backpressure {
    /// The entry is larger than a follower's whole byte window, so it
    /// could never be sent.
    InFlightBytes,
    /// The leader holds its limit of uncommitted entries.
    Queue,
    /// The entry is larger than a duty's log read, so it could never be
    /// read to be sent.
    LogRead,
}

/// Why a proposal is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposeError {
    /// The node does not lead.
    NotLeader(NotLeader),
    /// A flow limit is reached; retry after commits.
    Backpressure(Backpressure),
}

/// Why a message is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepError {
    /// The sender is not a voter, or is this node.
    UnknownSender,
    /// An append's entry terms do not match its count, or are not
    /// ascending from its previous term.
    Malformed,
    /// An append would truncate a committed entry: the leader broke
    /// Raft's safety.
    CommittedConflict,
}

/// Why [`Core::compacted`] is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactError {
    /// The base is past the commit index: only committed entries may be
    /// compacted.
    Uncommitted,
}

/// Why [`Core::install`] is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallError {
    /// The core already holds the base, or a later commit.
    Stale,
    /// The node leads: a leader's log already holds every committed
    /// entry.
    Leader,
}

/// A proposal refused because the node does not lead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotLeader {
    /// The leader it knows, if any.
    pub leader: Option<u64>,
}

/// A core's configuration.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    id: u64,
    voters: [u64; MAX_VOTERS],
    count: usize,
    election_min: u32,
    election_max: u32,
    heartbeat: u32,
    batch: u64,
    seed: u64,
    limits: Limits,
}

impl Config {
    /// A configuration for node `id` of `voters`, whose election timeout
    /// is drawn from `election_min..election_max` ticks with `seed`,
    /// whose leader heartbeats every `heartbeat` ticks and sends at most
    /// `batch` entries per append. Its flow limits are a batch in flight
    /// per follower and no byte, queue or read limit until
    /// [`Config::with_limits`] declares them.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] for each rule it breaks.
    pub fn new(
        id: u64,
        voters: &[u64],
        election_min: u32,
        election_max: u32,
        heartbeat: u32,
        batch: u64,
        seed: u64,
    ) -> Result<Self, ConfigError> {
        if voters.len() != 3 && voters.len() != 5 {
            return Err(ConfigError::VoterCount(voters.len()));
        }
        let mut array = [0; MAX_VOTERS];
        for (slot, (at, &voter)) in array.iter_mut().zip(voters.iter().enumerate()) {
            if voter == 0 || voters.iter().take(at).any(|&seen| seen == voter) {
                return Err(ConfigError::BadVoter);
            }
            *slot = voter;
        }
        if !voters.contains(&id) {
            return Err(ConfigError::NotAVoter);
        }
        // At least two timeout values, so nodes that time out together
        // draw apart.
        if election_min == 0 || election_max.saturating_sub(election_min) < 2 || heartbeat == 0 {
            return Err(ConfigError::Timeouts);
        }
        if heartbeat >= election_min {
            return Err(ConfigError::Timeouts);
        }
        if batch == 0 {
            return Err(ConfigError::Batch);
        }
        Ok(Self {
            id,
            voters: array,
            count: voters.len(),
            election_min,
            election_max,
            heartbeat,
            batch,
            seed,
            limits: Limits {
                in_flight_entries: batch,
                in_flight_bytes: u64::MAX,
                queue: u64::MAX,
                reads: u64::MAX,
                read_bytes: u64::MAX,
            },
        })
    }

    /// The same configuration with the flow limits `limits`.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Limits`] when a limit is 0, or fewer entries may
    /// be in flight than one batch holds.
    pub const fn with_limits(mut self, limits: Limits) -> Result<Self, ConfigError> {
        if limits.in_flight_entries < self.batch
            || limits.in_flight_bytes == 0
            || limits.queue == 0
            || limits.reads == 0
            || limits.read_bytes == 0
        {
            return Err(ConfigError::Limits);
        }
        self.limits = limits;
        Ok(self)
    }

    /// The flow limits.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// The node's id.
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }

    fn voters(&self) -> impl Iterator<Item = u64> + '_ {
        self.voters.iter().copied().take(self.count)
    }

    const fn quorum(&self) -> usize {
        self.count / 2 + 1
    }
}

/// What a leader knows of one voter.
#[derive(Debug, Clone, Copy, Default)]
struct Peer {
    id: u64,
    /// The next index to send it.
    next: u64,
    /// The highest index known durable on it.
    matched: u64,
    /// The entries of `sends`, in flight.
    flight: u64,
    /// Their bytes.
    bytes: u64,
    /// The sends not yet acknowledged, oldest first.
    sends: Sends,
    /// The current pipeline epoch.
    epoch: u64,
    /// Whether it granted this round's pre-vote or vote.
    granted: bool,
    /// Whether it answered this leader since the last quorum check.
    recent: bool,
    /// A snapshot asked for it: its base index and the ticks since.
    snapshot: Option<(u64, u32)>,
}

/// The most sends in flight to one follower: a window full of one-entry
/// appends.
pub const MAX_SENDS: usize = 64;

/// One append sent: entries `first..=last` and their bytes.
#[derive(Debug, Clone, Copy, Default)]
struct Send {
    first: u64,
    last: u64,
    bytes: u64,
}

/// A fixed ring of sends, oldest first.
#[derive(Debug, Clone, Copy)]
struct Sends {
    ring: [Send; MAX_SENDS],
    head: usize,
    len: usize,
}

impl Default for Sends {
    fn default() -> Self {
        Self {
            ring: [Send::default(); MAX_SENDS],
            head: 0,
            len: 0,
        }
    }
}

impl Sends {
    const fn is_full(&self) -> bool {
        self.len == MAX_SENDS
    }

    fn slot(&self, from_head: usize) -> usize {
        (self.head + from_head) % MAX_SENDS
    }

    fn push(&mut self, send: Send) {
        if self.is_full() {
            return;
        }
        let at = self.slot(self.len);
        if let Some(slot) = self.ring.get_mut(at) {
            *slot = send;
            self.len += 1;
        }
    }

    fn front(&self) -> Option<Send> {
        if self.len == 0 {
            return None;
        }
        self.ring.get(self.head).copied()
    }

    fn pop_front(&mut self) {
        if self.len > 0 {
            self.head = (self.head + 1) % MAX_SENDS;
            self.len -= 1;
        }
    }

    fn back_mut(&mut self) -> Option<&mut Send> {
        if self.len == 0 {
            return None;
        }
        let at = self.slot(self.len - 1);
        self.ring.get_mut(at)
    }

    fn pop_back(&mut self) {
        self.len = self.len.saturating_sub(1);
    }

    fn clear(&mut self) {
        self.len = 0;
    }
}

/// The custom Raft core of one node.
#[derive(Debug, Clone)]
pub struct Core {
    config: Config,
    term_vote: TermVote,
    role: Role,
    commit: u64,
    peers: [Peer; MAX_VOTERS],
    elapsed: u32,
    timeout: u32,
    rng: u64,
    /// The current pre-vote round: replies to another are ignored.
    round: u64,
    /// Ticks since a leader's last quorum check.
    quorum_elapsed: u32,
    /// The last pipeline epoch given to a follower.
    epoch: u64,
    /// The latest snapshot's base: its last index and that entry's term.
    base: (u64, u64),
}

impl Core {
    /// A follower recovered from its stored term and vote and the commit
    /// index it kept (0 when none).
    #[must_use]
    pub fn new(config: Config, term_vote: TermVote, commit: u64) -> Self {
        let mut peers = [Peer::default(); MAX_VOTERS];
        for (peer, id) in peers.iter_mut().zip(config.voters()) {
            peer.id = id;
        }
        let mut core = Self {
            config,
            term_vote,
            role: Role::Follower { leader: None },
            commit,
            peers,
            elapsed: 0,
            timeout: 0,
            rng: config.seed ^ config.id.wrapping_mul(0x9E37_79B9_7F4A_7C15),
            round: 0,
            quorum_elapsed: 0,
            epoch: 0,
            base: (0, 0),
        };
        // A restarted node starts its rounds at a fresh random point, so
        // a reply to a round before the restart is not counted.
        core.round = core.draw();
        // Epochs too, so a reply to an append before the restart is not
        // taken for one of this run.
        core.epoch = core.draw();
        core.reset_timer();
        core
    }

    /// The node's role.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// The persistent term and vote, as last given to
    /// [`Effects::persist`].
    #[must_use]
    pub const fn term_vote(&self) -> TermVote {
        self.term_vote
    }

    /// The commit index.
    #[must_use]
    pub const fn commit(&self) -> u64 {
        self.commit
    }

    /// What a leader has in flight to voter `id`, as (entries, bytes);
    /// `None` unless it leads and `id` is another voter.
    #[must_use]
    pub fn in_flight(&self, id: u64) -> Option<(u64, u64)> {
        if self.role != Role::Leader || id == self.config.id {
            return None;
        }
        let peer = self
            .peers
            .iter()
            .take(self.config.count)
            .find(|peer| peer.id == id)?;
        Some((peer.flight, peer.bytes))
    }

    /// A leader's pipeline epoch for voter `id`, which its appends carry
    /// and their replies echo; `None` unless it leads and `id` is another
    /// voter.
    #[must_use]
    pub fn pipeline_epoch(&self, id: u64) -> Option<u64> {
        if self.role != Role::Leader || id == self.config.id {
            return None;
        }
        self.peers
            .iter()
            .take(self.config.count)
            .find(|peer| peer.id == id)
            .map(|peer| peer.epoch)
    }

    /// The same core recovered over a snapshot whose base is `index`, of
    /// `term`: the base is committed, and the log starts after it.
    #[must_use]
    pub const fn with_snapshot(mut self, index: u64, term: u64) -> Self {
        if index > self.base.0 {
            self.base = (index, term);
        }
        if index > self.commit {
            self.commit = index;
        }
        self
    }

    /// The latest snapshot's base, as (index, term); (0, 0) for none.
    #[must_use]
    pub const fn snapshot_base(&self) -> (u64, u64) {
        self.base
    }

    /// The node compacted its log below a snapshot whose base is
    /// `index`, of `term`: entries up to it may be gone from the log.
    ///
    /// # Errors
    ///
    /// [`CompactError::Uncommitted`] when `index` is past the commit
    /// index; nothing changes.
    pub const fn compacted(&mut self, index: u64, term: u64) -> Result<(), CompactError> {
        if index > self.commit {
            return Err(CompactError::Uncommitted);
        }
        if index > self.base.0 {
            self.base = (index, term);
        }
        Ok(())
    }

    /// Whether [`Core::install`] would take a snapshot whose base is
    /// `index`: the admission a driver checks before it publishes the
    /// snapshot over its service and log, with no other call to the core
    /// in between, so the install it then reports is never refused.
    ///
    /// # Errors
    ///
    /// As [`Core::install`].
    pub fn can_install(&self, index: u64) -> Result<(), InstallError> {
        if self.role == Role::Leader {
            return Err(InstallError::Leader);
        }
        if index <= self.commit {
            return Err(InstallError::Stale);
        }
        Ok(())
    }

    /// The node installed a leader's snapshot whose base is `index`, of
    /// `term`: its service holds the state up to `index` and its log
    /// restarts after it, durably. A log that holds the base's entry keeps
    /// the entries after it, which the leader may already count (Raft's
    /// figure 13, step 6); any other log is emptied. The base is
    /// committed, and it is acknowledged to the leader once durable.
    ///
    /// A snapshot holds only committed entries, which every later leader's
    /// log holds too, so a snapshot sent in an earlier term is still safe
    /// to install, and its acknowledgement goes to the leader the node
    /// follows now, whoever sent it: that leader's log matches it up to
    /// the base. A node that knows no leader acknowledges nothing; the
    /// leader's next heartbeat at its base is acknowledged instead. The
    /// acknowledgement answers no append, so it carries epoch 0: an
    /// accepted reply is never checked against an epoch.
    ///
    /// # Errors
    ///
    /// [`InstallError::Stale`] when the core already committed `index`;
    /// [`InstallError::Leader`] when it leads. Nothing changes.
    pub fn install(
        &mut self,
        index: u64,
        term: u64,
        out: &mut impl Effects,
    ) -> Result<(), InstallError> {
        self.can_install(index)?;
        self.base = (index, term);
        self.commit = index;
        self.elapsed = 0;
        if let Role::Follower {
            leader: Some(leader),
        } = self.role
        {
            out.send_after_persist(
                leader,
                Message::AppendReply {
                    term: self.term_vote.term,
                    outcome: AppendOutcome::Accepted { index },
                    epoch: 0,
                },
            );
        }
        Ok(())
    }

    /// The current election timeout, in ticks.
    #[must_use]
    pub const fn election_timeout(&self) -> u32 {
        self.timeout
    }

    /// One tick: a follower or candidate whose timeout passes asks for
    /// pre-votes; a leader heartbeats, and steps down when a quorum has
    /// not answered it within the minimum election timeout (check
    /// quorum), so followers it still reaches stop refusing pre-votes.
    pub fn tick(&mut self, log: &impl LogTerms, out: &mut impl Effects) {
        let log = &Based::new(log, self.base);
        self.elapsed = self.elapsed.saturating_add(1);
        if self.role == Role::Leader {
            self.quorum_elapsed = self.quorum_elapsed.saturating_add(1);
            if self.quorum_elapsed >= self.config.election_min {
                self.quorum_elapsed = 0;
                let id = self.config.id;
                let heard = self
                    .peers
                    .iter()
                    .take(self.config.count)
                    .filter(|peer| peer.recent || peer.id == id)
                    .count();
                for peer in &mut self.peers {
                    peer.recent = false;
                }
                if heard < self.config.quorum() {
                    self.role = Role::Follower { leader: None };
                    self.reset_timer();
                    return;
                }
            }
            let (retry, base) = (self.config.election_min, self.base.0);
            for peer in &mut self.peers {
                if let Some((_, ticks)) = peer.snapshot.as_mut() {
                    *ticks = ticks.saturating_add(1);
                    if *ticks >= retry {
                        // Unacknowledged: lost, or not yet installed. Ask
                        // again; the driver sends its latest snapshot, and
                        // an acknowledgement of the first base asked still
                        // counts, so a slow install is never outrun by
                        // compaction.
                        *ticks = 0;
                        peer.next = base.saturating_add(1);
                        out.send_snapshot(peer.id);
                    }
                }
            }
            if self.elapsed >= self.config.heartbeat {
                self.elapsed = 0;
                self.replicate(log, out);
            }
        } else if self.elapsed >= self.timeout {
            self.pre_campaign(log, out);
        }
    }

    /// The leader's next entry, of `size` bytes: the driver writes it at
    /// the returned index with the returned term, then calls
    /// [`Core::replicate`].
    ///
    /// # Errors
    ///
    /// [`ProposeError::NotLeader`] unless the node leads, and
    /// [`ProposeError::Backpressure`] when the entry exceeds the byte
    /// window or the leader holds its queue of uncommitted entries.
    pub fn propose(&self, size: u64, log: &impl LogTerms) -> Result<(u64, u64), ProposeError> {
        let log = &Based::new(log, self.base);
        match self.role {
            Role::Leader => {}
            Role::Follower { leader } => {
                return Err(ProposeError::NotLeader(NotLeader { leader }));
            }
            Role::PreCandidate | Role::Candidate => {
                return Err(ProposeError::NotLeader(NotLeader { leader: None }));
            }
        }
        let limits = self.config.limits;
        if size > limits.in_flight_bytes {
            return Err(ProposeError::Backpressure(Backpressure::InFlightBytes));
        }
        if size > limits.read_bytes {
            return Err(ProposeError::Backpressure(Backpressure::LogRead));
        }
        let last = log.last_index();
        if last.saturating_sub(self.commit) >= limits.queue {
            return Err(ProposeError::Backpressure(Backpressure::Queue));
        }
        Ok((last.saturating_add(1), self.term_vote.term))
    }

    /// The leader's own log is durable up to `index`.
    pub fn persisted(&mut self, index: u64, log: &impl LogTerms, out: &mut impl Effects) {
        let log = &Based::new(log, self.base);
        if self.role != Role::Leader {
            return;
        }
        let id = self.config.id;
        if let Some(own) = self.peers.iter_mut().find(|peer| peer.id == id) {
            own.matched = own.matched.max(index);
        }
        self.advance_commit(log, out);
    }

    /// A leader sends each follower the entries from its next index that
    /// fit a batch, its in-flight window and this duty's read budget, or
    /// a heartbeat.
    pub fn replicate(&mut self, log: &impl LogTerms, out: &mut impl Effects) {
        let log = &Based::new(log, self.base);
        if self.role != Role::Leader {
            return;
        }
        let mut budget = Duty::of(self.config.limits);
        for at in 0..self.config.count {
            self.send_append(at, &mut budget, true, log, out);
        }
    }

    /// One message from voter `from`; `terms` are the entry terms of an
    /// [`Message::Append`], empty otherwise.
    ///
    /// # Errors
    ///
    /// [`StepError`] for a message the core refuses; its state is
    /// unchanged by the refused message.
    pub fn step(
        &mut self,
        from: u64,
        message: Message,
        terms: &[u64],
        log: &impl LogTerms,
        out: &mut impl Effects,
    ) -> Result<(), StepError> {
        let log = &Based::new(log, self.base);
        if from == self.config.id || !self.config.voters().any(|voter| voter == from) {
            return Err(StepError::UnknownSender);
        }
        match message {
            Message::PreVote {
                term,
                last_index,
                last_term,
                round,
            } => {
                self.on_pre_vote(from, term, (last_index, last_term), round, log, out);
                Ok(())
            }
            Message::PreVoteReply {
                term,
                granted,
                round,
            } => {
                if round == self.round {
                    self.on_pre_vote_reply(from, term, granted, log, out);
                }
                Ok(())
            }
            Message::Vote {
                term,
                last_index,
                last_term,
            } => {
                self.observe(term, out);
                self.on_vote(from, term, last_index, last_term, log, out);
                Ok(())
            }
            Message::VoteReply { term, granted } => {
                self.observe(term, out);
                self.on_vote_reply(from, term, granted, log, out);
                Ok(())
            }
            Message::Append {
                term,
                prev_index,
                prev_term,
                entries,
                commit,
                epoch,
            } => {
                let append = Append {
                    epoch,
                    term,
                    prev_index,
                    prev_term,
                    entries,
                    commit,
                };
                self.on_append(from, append, terms, log, out)
            }
            Message::AppendReply {
                term,
                outcome,
                epoch,
            } => {
                self.observe(term, out);
                self.on_append_reply(from, term, (outcome, epoch), log, out);
                Ok(())
            }
        }
    }

    /// A higher term seen: follow it, no vote yet.
    fn observe(&mut self, term: u64, out: &mut impl Effects) {
        if term > self.term_vote.term {
            self.term_vote = TermVote {
                term,
                voted_for: None,
            };
            out.persist(self.term_vote);
            self.role = Role::Follower { leader: None };
        }
    }

    fn pre_campaign(&mut self, log: &impl LogTerms, out: &mut impl Effects) {
        self.role = Role::PreCandidate;
        self.reset_timer();
        self.clear_grants();
        self.round = self.round.wrapping_add(1);
        let term = self.term_vote.term.saturating_add(1);
        let (last_index, last_term) = last(log);
        let message = Message::PreVote {
            term,
            last_index,
            last_term,
            round: self.round,
        };
        for voter in self.config.voters().filter(|&v| v != self.config.id) {
            out.send(voter, message);
        }
    }

    fn campaign(&mut self, log: &impl LogTerms, out: &mut impl Effects) {
        self.role = Role::Candidate;
        self.reset_timer();
        self.clear_grants();
        self.term_vote = TermVote {
            term: self.term_vote.term.saturating_add(1),
            voted_for: Some(self.config.id),
        };
        out.persist(self.term_vote);
        let (last_index, last_term) = last(log);
        let message = Message::Vote {
            term: self.term_vote.term,
            last_index,
            last_term,
        };
        for voter in self.config.voters().filter(|&v| v != self.config.id) {
            out.send_after_persist(voter, message);
        }
    }

    fn on_pre_vote(
        &mut self,
        from: u64,
        term: u64,
        (last_index, last_term): (u64, u64),
        round: u64,
        log: &impl LogTerms,
        out: &mut impl Effects,
    ) {
        // A node that hears from a live leader, or leads, refuses: a
        // returning partitioned node must not unseat it.
        let live_leader = match self.role {
            Role::Leader => true,
            Role::Follower { leader } => {
                leader.is_some() && self.elapsed < self.config.election_min
            }
            Role::PreCandidate | Role::Candidate => false,
        };
        let granted =
            term > self.term_vote.term && !live_leader && up_to_date(log, last_index, last_term);
        let reply_term = if granted { term } else { self.term_vote.term };
        out.send(
            from,
            Message::PreVoteReply {
                term: reply_term,
                granted,
                round,
            },
        );
    }

    fn on_pre_vote_reply(
        &mut self,
        from: u64,
        term: u64,
        granted: bool,
        log: &impl LogTerms,
        out: &mut impl Effects,
    ) {
        if !granted {
            // A refusal names the voter's term: a higher one is followed.
            self.observe(term, out);
            return;
        }
        if self.role != Role::PreCandidate || term != self.term_vote.term.saturating_add(1) {
            return;
        }
        if self.grant(from) {
            self.campaign(log, out);
        }
    }

    fn on_vote(
        &mut self,
        from: u64,
        term: u64,
        last_index: u64,
        last_term: u64,
        log: &impl LogTerms,
        out: &mut impl Effects,
    ) {
        let free = self.term_vote.voted_for.is_none_or(|voted| voted == from);
        let granted = term == self.term_vote.term
            && free
            && self.role != Role::Leader
            && up_to_date(log, last_index, last_term);
        if granted {
            if self.term_vote.voted_for.is_none() {
                self.term_vote.voted_for = Some(from);
                out.persist(self.term_vote);
            }
            self.elapsed = 0;
        }
        out.send_after_persist(
            from,
            Message::VoteReply {
                term: self.term_vote.term,
                granted,
            },
        );
    }

    fn on_vote_reply(
        &mut self,
        from: u64,
        term: u64,
        granted: bool,
        log: &impl LogTerms,
        out: &mut impl Effects,
    ) {
        if self.role != Role::Candidate || term != self.term_vote.term || !granted {
            return;
        }
        if self.grant(from) {
            self.lead(log, out);
        }
    }

    fn lead(&mut self, log: &impl LogTerms, out: &mut impl Effects) {
        self.role = Role::Leader;
        self.elapsed = 0;
        self.quorum_elapsed = 0;
        let next = log.last_index().saturating_add(1);
        for peer in self.peers.iter_mut().take(self.config.count) {
            self.epoch = self.epoch.wrapping_add(1);
            peer.next = next;
            peer.matched = 0;
            peer.flight = 0;
            peer.bytes = 0;
            peer.sends.clear();
            peer.epoch = self.epoch;
            peer.recent = false;
            peer.snapshot = None;
        }
        // A no-op of the new term, so earlier-term entries can commit.
        out.append(next, self.term_vote.term);
    }

    fn on_append(
        &mut self,
        from: u64,
        append: Append,
        terms: &[u64],
        log: &impl LogTerms,
        out: &mut impl Effects,
    ) -> Result<(), StepError> {
        let count = u64::try_from(terms.len()).map_err(|_| StepError::Malformed)?;
        if count != append.entries {
            return Err(StepError::Malformed);
        }
        let mut floor = append.prev_term;
        for &term in terms {
            if term < floor || term > append.term {
                return Err(StepError::Malformed);
            }
            floor = term;
        }
        if append.term < self.term_vote.term {
            out.send(
                from,
                Message::AppendReply {
                    term: self.term_vote.term,
                    outcome: AppendOutcome::Rejected {
                        probe: append.prev_index,
                        hint: log.last_index(),
                    },
                    epoch: append.epoch,
                },
            );
            return Ok(());
        }
        // The first conflict, checked before any state changes.
        let mut conflict = None;
        if append.prev_index <= log.last_index()
            && log.term(append.prev_index) == Some(append.prev_term)
        {
            for (skip, &term) in (0..count).zip(terms) {
                let index = append.prev_index.saturating_add(skip).saturating_add(1);
                if log.term(index) != Some(term) {
                    if log.term(index).is_some() && index <= self.commit {
                        return Err(StepError::CommittedConflict);
                    }
                    conflict = Some((index, skip));
                    break;
                }
            }
        }
        self.observe(append.term, out);
        self.role = Role::Follower { leader: Some(from) };
        self.elapsed = 0;
        let outcome = if append.prev_index < self.base.0 {
            // Up to the base the log holds a committed prefix, which
            // matches every leader's: acknowledge it, and the leader
            // resends from after it.
            AppendOutcome::Accepted { index: self.base.0 }
        } else if append.prev_index > log.last_index() {
            AppendOutcome::Rejected {
                probe: append.prev_index,
                hint: log.last_index(),
            }
        } else if log.term(append.prev_index) != Some(append.prev_term) {
            AppendOutcome::Rejected {
                probe: append.prev_index,
                hint: append.prev_index.saturating_sub(1),
            }
        } else {
            if let Some((index, skip)) = conflict {
                out.write(index, skip);
            }
            let matched = append.prev_index.saturating_add(count);
            let commit = append.commit.min(matched);
            if commit > self.commit {
                self.commit = commit;
                out.commit(commit);
            }
            AppendOutcome::Accepted { index: matched }
        };
        out.send_after_persist(
            from,
            Message::AppendReply {
                term: self.term_vote.term,
                outcome,
                epoch: append.epoch,
            },
        );
        Ok(())
    }

    fn on_append_reply(
        &mut self,
        from: u64,
        term: u64,
        (outcome, epoch): (AppendOutcome, u64),
        log: &impl LogTerms,
        out: &mut impl Effects,
    ) {
        if self.role != Role::Leader || term != self.term_vote.term {
            return;
        }
        let Some(at) = self.peers.iter().position(|peer| peer.id == from) else {
            return;
        };
        let Some(peer) = self.peers.get_mut(at) else {
            return;
        };
        peer.recent = true;
        match (peer.snapshot, outcome) {
            (Some((base, _)), AppendOutcome::Accepted { index }) if index >= base => {
                peer.snapshot = None;
            }
            // Until the snapshot is acknowledged, nothing else moves it.
            (Some(_), _) => return,
            (None, _) => {}
        }
        let mut budget = Duty::of(self.config.limits);
        match outcome {
            AppendOutcome::Accepted { index } => {
                if index > peer.matched {
                    // Free the sends the acknowledgement covers whole; one
                    // it covers in part stays counted.
                    while let Some(send) = peer.sends.front() {
                        if send.last > index {
                            break;
                        }
                        peer.flight = peer.flight.saturating_sub(send.last - send.first + 1);
                        peer.bytes = peer.bytes.saturating_sub(send.bytes);
                        peer.sends.pop_front();
                    }
                    peer.matched = index;
                    peer.next = peer.next.max(index.saturating_add(1));
                    self.advance_commit(log, out);
                    // The window opened: refill it.
                    self.send_append(at, &mut budget, false, log, out);
                }
            }
            // A rejection of a prefix since acknowledged, or of an earlier
            // pipeline, is stale: it must not rewind or refund anything.
            AppendOutcome::Rejected { probe, .. }
                if probe <= peer.matched || epoch != peer.epoch => {}
            AppendOutcome::Rejected { hint, .. } => {
                let sent = peer.next.saturating_sub(1);
                let retry = sent.min(hint.saturating_add(1));
                peer.next = retry.max(peer.matched.saturating_add(1)).max(1);
                // What is past the retry point is no longer in flight; a
                // send straddling it keeps its whole bytes.
                let kept = peer.next.saturating_sub(1);
                while let Some(send) = peer.sends.back_mut() {
                    if send.first > kept {
                        let (count, bytes) = (send.last - send.first + 1, send.bytes);
                        peer.sends.pop_back();
                        peer.flight = peer.flight.saturating_sub(count);
                        peer.bytes = peer.bytes.saturating_sub(bytes);
                    } else {
                        if send.last > kept {
                            peer.flight = peer.flight.saturating_sub(send.last - kept);
                            send.last = kept;
                        }
                        break;
                    }
                }
                self.epoch = self.epoch.wrapping_add(1);
                peer.epoch = self.epoch;
                self.send_append(at, &mut budget, true, log, out);
            }
        }
    }

    /// The previous index, and the entries, bytes and reads of what `at`
    /// can be sent now, within what is left of the duty's `budget`.
    fn fit(&self, at: usize, budget: Duty, log: &impl LogTerms) -> (u64, u64, u64, (u64, u64)) {
        let Some(peer) = self.peers.get(at) else {
            return (0, 0, 0, (0, 0));
        };
        let limits = self.config.limits;
        let last = log.last_index();
        let prev_index = peer.next.saturating_sub(1).min(last);
        if peer.sends.is_full() {
            return (prev_index, 0, 0, (0, 0));
        }
        let most = last
            .saturating_sub(prev_index)
            .min(self.config.batch)
            .min(limits.in_flight_entries.saturating_sub(peer.flight));
        let mut entries = 0;
        let mut bytes = 0_u64;
        let mut cost = 0_u64;
        let mut reads = 0;
        while entries < most && reads < budget.reads {
            reads += 1;
            let index = prev_index.saturating_add(entries).saturating_add(1);
            let (Some(size), Some(read)) = (log.size(index), log.cost(index)) else {
                break;
            };
            let total = peer.bytes.saturating_add(bytes).saturating_add(size);
            // An entry larger than the whole window goes alone into an
            // empty one (see the module notes).
            let alone = entries == 0 && peer.flight == 0;
            if total > limits.in_flight_bytes && !alone {
                break;
            }
            // The duty's log read bound has no exception.
            if cost.saturating_add(read) > budget.bytes {
                break;
            }
            cost = cost.saturating_add(read);
            bytes = bytes.saturating_add(size);
            entries += 1;
            if total > limits.in_flight_bytes {
                break;
            }
        }
        (prev_index, entries, bytes, (reads, cost))
    }

    /// Sends `at` what fits, or a heartbeat when nothing does and
    /// `heartbeat` is set.
    fn send_append(
        &mut self,
        at: usize,
        budget: &mut Duty,
        heartbeat: bool,
        log: &impl LogTerms,
        out: &mut impl Effects,
    ) {
        let id = self.config.id;
        if self.peers.get(at).is_none_or(|peer| peer.id == id) {
            return;
        }
        let commit = self.commit;
        let term = self.term_vote.term;
        if self.snapshot_needed(at, budget, log, out) {
            // A heartbeat at the base keeps it following, and its answer
            // acknowledges the snapshot once installed.
            let (base, prev_term) = self.base;
            if heartbeat
                && base > 0
                && let Some(peer) = self.peers.get(at)
                && peer.snapshot.is_some()
            {
                out.send(
                    peer.id,
                    Message::Append {
                        term,
                        prev_index: base,
                        prev_term,
                        entries: 0,
                        commit,
                        epoch: peer.epoch,
                    },
                );
            }
            return;
        }
        let (prev_index, entries, bytes, (reads, cost)) = self.fit(at, *budget, log);
        budget.reads = budget.reads.saturating_sub(reads);
        budget.bytes = budget.bytes.saturating_sub(cost);
        if entries == 0 && !heartbeat {
            return;
        }
        let Some(prev_term) = log.term(prev_index) else {
            return;
        };
        let Some(peer) = self.peers.get_mut(at) else {
            return;
        };
        if entries > 0 {
            peer.sends.push(Send {
                first: prev_index.saturating_add(1),
                last: prev_index.saturating_add(entries),
                bytes,
            });
            peer.flight = peer.flight.saturating_add(entries);
            peer.bytes = peer.bytes.saturating_add(bytes);
        }
        peer.next = prev_index.saturating_add(entries).saturating_add(1);
        out.send(
            peer.id,
            Message::Append {
                term,
                prev_index,
                prev_term,
                entries,
                commit,
                epoch: peer.epoch,
            },
        );
    }

    /// Whether `at` waits for a snapshot: one asked for, or one it needs
    /// now because the log no longer holds what it would be sent, which
    /// is then asked for. A follower waiting for one is sent no entries.
    fn snapshot_needed(
        &mut self,
        at: usize,
        budget: &mut Duty,
        log: &impl LogTerms,
        out: &mut impl Effects,
    ) -> bool {
        let base = self.base.0;
        let Some(peer) = self.peers.get_mut(at) else {
            return true;
        };
        if peer.snapshot.is_some() {
            return true;
        }
        let last = log.last_index();
        let prev = peer.next.saturating_sub(1).min(last);
        if base == 0 {
            return false;
        }
        // Below the base a log may keep terms without entries: the next
        // entry's size says whether it can still be sent. That read is
        // charged to the duty, and with none left nothing is decided.
        let gone = if log.term(prev).is_none() {
            true
        } else if prev < base && prev < last {
            if budget.reads == 0 {
                return false;
            }
            budget.reads -= 1;
            log.size(prev.saturating_add(1)).is_none()
        } else {
            false
        };
        if !gone {
            return false;
        }
        peer.snapshot = Some((base, 0));
        peer.next = base.saturating_add(1);
        peer.sends.clear();
        peer.flight = 0;
        peer.bytes = 0;
        self.epoch = self.epoch.wrapping_add(1);
        peer.epoch = self.epoch;
        out.send_snapshot(peer.id);
        true
    }

    /// The highest index a majority holds durably, committed when its
    /// entry is of this term.
    fn advance_commit(&mut self, log: &impl LogTerms, out: &mut impl Effects) {
        let mut matched = [0_u64; MAX_VOTERS];
        for (slot, peer) in matched
            .iter_mut()
            .zip(self.peers.iter().take(self.config.count))
        {
            *slot = peer.matched;
        }
        let Some(live) = matched.get_mut(..self.config.count) else {
            return;
        };
        live.sort_unstable_by(|a, b| b.cmp(a));
        let Some(&index) = live.get(self.config.quorum().saturating_sub(1)) else {
            return;
        };
        if index > self.commit && log.term(index) == Some(self.term_vote.term) {
            self.commit = index;
            out.commit(index);
        }
    }

    /// Records `from`'s grant; true when the grants first reach a quorum.
    fn grant(&mut self, from: u64) -> bool {
        let before = self.grants();
        if let Some(peer) = self.peers.iter_mut().find(|peer| peer.id == from) {
            peer.granted = true;
        }
        let after = self.grants();
        before < self.config.quorum() && after >= self.config.quorum()
    }

    fn grants(&self) -> usize {
        self.peers
            .iter()
            .take(self.config.count)
            .filter(|peer| peer.granted)
            .count()
    }

    fn clear_grants(&mut self) {
        let id = self.config.id;
        for peer in &mut self.peers {
            peer.granted = peer.id == id;
        }
    }

    /// The next splitmix64 draw: deterministic for a seed and a node.
    const fn draw(&mut self) -> u64 {
        self.rng = self.rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn reset_timer(&mut self) {
        self.elapsed = 0;
        let z = self.draw();
        let span = u64::from(self.config.election_max - self.config.election_min);
        let offset = u32::try_from(z % span).unwrap_or(0);
        self.timeout = self.config.election_min.saturating_add(offset);
    }
}

/// What is left of a duty's reads.
#[derive(Debug, Clone, Copy)]
struct Duty {
    /// Entry size lookups.
    reads: u64,
    /// Bytes of entries sent, read by the driver.
    bytes: u64,
}

impl Duty {
    const fn of(limits: Limits) -> Self {
        Self {
            reads: limits.reads,
            bytes: limits.read_bytes,
        }
    }
}

/// An append's header.
#[derive(Debug, Clone, Copy)]
struct Append {
    epoch: u64,
    term: u64,
    prev_index: u64,
    prev_term: u64,
    entries: u64,
    commit: u64,
}

/// The node's log read through the snapshot base: the base's term is
/// known, and the log ends no earlier than the base.
struct Based<'a, L> {
    log: &'a L,
    base: (u64, u64),
}

impl<'a, L: LogTerms> Based<'a, L> {
    const fn new(log: &'a L, base: (u64, u64)) -> Self {
        Self { log, base }
    }
}

impl<L: LogTerms> LogTerms for Based<'_, L> {
    fn last_index(&self) -> u64 {
        self.log.last_index().max(self.base.0)
    }

    fn term(&self, index: u64) -> Option<u64> {
        if index == self.base.0 {
            return Some(self.base.1);
        }
        self.log.term(index)
    }

    fn size(&self, index: u64) -> Option<u64> {
        self.log.size(index)
    }
}

fn last(log: &impl LogTerms) -> (u64, u64) {
    let index = log.last_index();
    (index, log.term(index).unwrap_or(0))
}

/// Whether a candidate's log is at least as up to date as this one.
fn up_to_date(log: &impl LogTerms, last_index: u64, last_term: u64) -> bool {
    let (index, term) = last(log);
    last_term > term || (last_term == term && last_index >= index)
}
