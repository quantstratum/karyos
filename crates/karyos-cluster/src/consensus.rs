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
//! Replication is pipelined optimistically here: a leader sends from each
//! follower's next index and moves it on, and falls back on a rejection.
//! The strict in-flight limits, the pooled buffers and snapshot install
//! come in later parts of the issue.

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
    },
    /// An append answer.
    AppendReply {
        /// The follower's term.
        term: u64,
        /// Whether it matched.
        outcome: AppendOutcome,
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
}

impl Config {
    /// A configuration for node `id` of `voters`, whose election timeout
    /// is drawn from `election_min..election_max` ticks with `seed`,
    /// whose leader heartbeats every `heartbeat` ticks and sends at most
    /// `batch` entries per append.
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
        })
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
    /// Whether it granted this round's pre-vote or vote.
    granted: bool,
    /// Whether it answered this leader since the last quorum check.
    recent: bool,
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
        };
        // A restarted node starts its rounds at a fresh random point, so
        // a reply to a round before the restart is not counted.
        core.round = core.draw();
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
            if self.elapsed >= self.config.heartbeat {
                self.elapsed = 0;
                self.replicate(log, out);
            }
        } else if self.elapsed >= self.timeout {
            self.pre_campaign(log, out);
        }
    }

    /// The leader's next entry: the driver writes it at the returned
    /// index with the returned term, then calls [`Core::replicate`].
    ///
    /// # Errors
    ///
    /// [`NotLeader`] unless the node leads.
    pub fn propose(&self, log: &impl LogTerms) -> Result<(u64, u64), NotLeader> {
        match self.role {
            Role::Leader => Ok((log.last_index().saturating_add(1), self.term_vote.term)),
            Role::Follower { leader } => Err(NotLeader { leader }),
            Role::PreCandidate | Role::Candidate => Err(NotLeader { leader: None }),
        }
    }

    /// The leader's own log is durable up to `index`.
    pub fn persisted(&mut self, index: u64, log: &impl LogTerms, out: &mut impl Effects) {
        if self.role != Role::Leader {
            return;
        }
        let id = self.config.id;
        if let Some(own) = self.peers.iter_mut().find(|peer| peer.id == id) {
            own.matched = own.matched.max(index);
        }
        self.advance_commit(log, out);
    }

    /// A leader sends each follower the entries from its next index, at
    /// most a batch, or a heartbeat.
    pub fn replicate(&mut self, log: &impl LogTerms, out: &mut impl Effects) {
        if self.role != Role::Leader {
            return;
        }
        for at in 0..self.config.count {
            self.send_append(at, log, out);
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
            } => {
                let append = Append {
                    term,
                    prev_index,
                    prev_term,
                    entries,
                    commit,
                };
                self.on_append(from, append, terms, log, out)
            }
            Message::AppendReply { term, outcome } => {
                self.observe(term, out);
                self.on_append_reply(from, term, outcome, log, out);
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
            peer.next = next;
            peer.matched = 0;
            peer.recent = false;
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
        let outcome = if append.prev_index > log.last_index() {
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
            },
        );
        Ok(())
    }

    fn on_append_reply(
        &mut self,
        from: u64,
        term: u64,
        outcome: AppendOutcome,
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
        match outcome {
            AppendOutcome::Accepted { index } => {
                peer.matched = peer.matched.max(index);
                peer.next = peer.next.max(index.saturating_add(1));
                self.advance_commit(log, out);
            }
            // A rejection of a prefix since acknowledged is stale: it must
            // not rewind the pipeline.
            AppendOutcome::Rejected { probe, .. } if probe <= peer.matched => {}
            AppendOutcome::Rejected { hint, .. } => {
                let retry = peer.next.saturating_sub(1).min(hint.saturating_add(1));
                peer.next = retry.max(peer.matched.saturating_add(1)).max(1);
                self.send_append(at, log, out);
            }
        }
    }

    fn send_append(&mut self, at: usize, log: &impl LogTerms, out: &mut impl Effects) {
        let id = self.config.id;
        let commit = self.commit;
        let term = self.term_vote.term;
        let batch = self.config.batch;
        let Some(peer) = self.peers.get_mut(at) else {
            return;
        };
        if peer.id == id {
            return;
        }
        let last = log.last_index();
        let prev_index = peer.next.saturating_sub(1).min(last);
        let Some(prev_term) = log.term(prev_index) else {
            return;
        };
        let entries = last.saturating_sub(prev_index).min(batch);
        peer.next = prev_index.saturating_add(entries).saturating_add(1);
        out.send(
            peer.id,
            Message::Append {
                term,
                prev_index,
                prev_term,
                entries,
                commit,
            },
        );
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

/// An append's header.
#[derive(Debug, Clone, Copy)]
struct Append {
    term: u64,
    prev_index: u64,
    prev_term: u64,
    entries: u64,
    commit: u64,
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
