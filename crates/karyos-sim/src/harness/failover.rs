// SPDX-License-Identifier: Apache-2.0

//! A harness client driven by the Cluster client's failover state
//! ([`ClusterClient`]; SPEC.md §9; karyos#720): the scripted client of
//! [`super::node::ClientNode`], but every decision of what to send, where,
//! and what an answer means is [`ClusterClient`]'s, the node only carrying
//! its sends over the harness's wire and its answers back by [`Key`].
//!
//! - **The session.** The harness's test service deduplicates a client's
//!   sequence with no session layer, so the harness stands in for the
//!   cluster's registration: the client registers once, on a session of
//!   epoch [`EPOCH`] that a one-session [`SessionTable`] opens with a
//!   window of one request, the harness client's one request at a time.
//!   Its request `s` is the wire's sequence `s + 1` (the wire's start at
//!   1).
//! - **The wire.** An answer is [`Reply::Outcome`] to the current attempt
//!   of the open request (the wire carries no attempt); an expired one is
//!   [`Answer::Duplicate`], applied with its reply gone. A refusal from a
//!   server that does not act names no leader, and the harness client keeps
//!   its server: [`Reply::Redirect`] to that server. Backpressure is
//!   [`Answer::WindowFull`]. A server's redirect is [`Reply::Redirect`]; the
//!   operator's, a promotion's, is a leader change learnt otherwise
//!   ([`ClusterClient::leader_changed`]), in the generation the client has
//!   seen: the redirect carries none.
//! - **The caller.** The node is its [`ClusterClient`]'s caller: once its
//!   request is unknown (a leader change, or no answer within its retry
//!   interval, [`ClusterClient::timed_out`]) it retries it at its next tick
//!   ([`ClusterClient::retry`], recorded as
//!   [`Observation::ClientRetry`]); a busy one, after its retry interval.
//!   [`ClusterClient`] itself never resends an unknown request. Every event
//!   it reports is recorded ([`Observation::ClientEvent`]), and a refused
//!   lower generation as the harness client records it
//!   ([`Observation::StaleGeneration`]).

use karyos_cluster::client::{Answer, ClusterClient, Event, Key, Reply, Send};
use karyos_cluster::dedup::{DedupConfig, SessionTable};

use super::node::{Command, Observation, Op, Ret, Shared, Wire};
use super::standby::FIRST_GENERATION;
use crate::cluster::Outbox;
use crate::net::NodeId;

/// The epoch of the session the harness opens for each Cluster client.
pub const EPOCH: u64 = 1;

/// The request waiting for its outcome.
#[derive(Debug, Clone)]
struct Open {
    command: Command,
    key: Key,
    /// When it was last sent.
    sent: u64,
    /// Reported unknown: the caller retries it.
    unknown: bool,
    /// Refused for now (busy, no leader): the caller retries it after its
    /// retry interval.
    busy: bool,
    /// Every attempt sent: to whom, its key, and the generation the client
    /// had seen when it was sent. The wire carries neither key nor a
    /// refusal's generation, so an answer from a server is the answer to
    /// the last attempt sent to it, in that attempt's generation: a late
    /// refusal from the old primary cannot steer a newer attempt.
    sends: Vec<(NodeId, Key, u64)>,
}

/// A scripted client whose failover is [`ClusterClient`]'s.
#[derive(Debug, Clone)]
pub struct FailoverClient {
    id: NodeId,
    script: Vec<Op>,
    next: usize,
    open: Option<Open>,
    retry_after: u64,
    recorder: Shared,
    client: ClusterClient,
    /// It records each read with a value no one wrote (karyos#1038,
    /// tests): a faulty client.
    #[cfg(feature = "test-hooks")]
    corrupts_reads: bool,
}

impl FailoverClient {
    /// Client `id`, sending `script` to `server` in order, retrying after
    /// `retry_after` ticks.
    #[must_use]
    pub fn new(
        id: NodeId,
        server: NodeId,
        script: Vec<Op>,
        recorder: Shared,
        retry_after: u64,
    ) -> Self {
        let mut client = ClusterClient::new(u64::from(id), Some(u64::from(server)));
        let bounds = DedupConfig::default()
            .with_sessions(1)
            .with_window(1)
            .with_ttl(u64::MAX);
        // A fresh table of one session takes its first registration, and a
        // fresh client its first session, reporting nothing; a client
        // without one sends nothing, which the run's liveness reports.
        if let Ok(mut table) = SessionTable::new(bounds)
            && let Ok(registered) = table.register(u64::from(id), EPOCH, 0)
        {
            let _ = client.registered(registered, FIRST_GENERATION, &mut |_| {});
        }
        Self {
            id,
            script,
            next: 0,
            open: None,
            retry_after,
            recorder,
            client,
            #[cfg(feature = "test-hooks")]
            corrupts_reads: false,
        }
    }

    /// The client recording each read with a value no one wrote: a faulty
    /// client (karyos#1038, tests).
    #[cfg(feature = "test-hooks")]
    pub fn corrupt_reads(&mut self) {
        self.corrupts_reads = true;
    }

    /// Its open request's wire sequence, if one waits for its outcome.
    #[must_use]
    pub fn open(&self) -> Option<u64> {
        self.open.as_ref().map(|open| open.command.sequence)
    }

    /// Whether every request of its script has its outcome.
    #[must_use]
    pub fn done(&self) -> bool {
        self.open.is_none() && self.next == self.script.len()
    }

    /// Its failover state.
    #[must_use]
    pub const fn cluster_client(&self) -> &ClusterClient {
        &self.client
    }

    fn observe(&self, observation: Observation) {
        self.recorder.borrow_mut().observations.push(observation);
    }

    /// Carries `send` to its server.
    fn send<M>(&mut self, send: Send, now: u64, out: &mut Outbox<Wire<M>>) {
        let (Some(open), Ok(to)) = (self.open.as_mut(), NodeId::try_from(send.to)) else {
            return;
        };
        open.key = send.key;
        open.sent = now;
        open.sends.push((to, send.key, self.client.generation()));
        out.push((to, Wire::Request(open.command.clone())));
    }

    /// The key and generation of the last attempt of the open request sent
    /// to `from`, if `sequence` (the wire's) is the open request's.
    fn exchange(&self, from: NodeId, sequence: u64) -> Option<(Key, u64)> {
        self.open
            .as_ref()
            .filter(|open| open.command.sequence == sequence)?
            .sends
            .iter()
            .rev()
            .find(|(to, _, _)| *to == from)
            .map(|&(_, key, generation)| (key, generation))
    }

    /// Acts on `events`; `settled` is the answer, its entry's index and
    /// its server's generation, when `events` answer one.
    fn handle<M>(
        &mut self,
        events: Vec<Event>,
        mut settled: Option<(Ret, u64, u64)>,
        now: u64,
        out: &mut Outbox<Wire<M>>,
    ) {
        for event in events {
            self.observe(Observation::ClientEvent {
                client: self.id,
                event,
            });
            match event {
                Event::Completed { .. } => {
                    let Some((ret, index, generation)) = settled.take() else {
                        continue;
                    };
                    let Some(open) = self.open.take() else {
                        continue;
                    };
                    if ret == Ret::Expired {
                        // As the harness client: the outcome is unknown,
                        // left open in the history, and the client stops.
                        self.next = self.script.len();
                        self.observe(Observation::Expired {
                            client: self.id,
                            sequence: open.command.sequence,
                        });
                        continue;
                    }
                    #[cfg(feature = "test-hooks")]
                    let ret = match ret {
                        Ret::Values(mut values) if self.corrupts_reads => {
                            values.push(b"never written".to_vec());
                            Ret::Values(values)
                        }
                        other => other,
                    };
                    let mut recorder = self.recorder.borrow_mut();
                    let _ = recorder.history.ret(self.id, ret);
                    recorder.observations.push(Observation::Success {
                        client: self.id,
                        index,
                        generation,
                    });
                }
                Event::Resend(send) => self.send(send, now, out),
                Event::Unknown { .. } => {
                    if let Some(open) = self.open.as_mut() {
                        open.unknown = true;
                    }
                }
                Event::StaleGeneration { generation, .. } => {
                    self.observe(Observation::StaleGeneration {
                        client: self.id,
                        generation,
                    });
                }
                Event::Busy { .. } | Event::NoLeader { .. } | Event::OutOfOrder { .. } => {
                    if let Some(open) = self.open.as_mut() {
                        open.busy = true;
                        open.sent = now;
                    }
                }
                Event::Expired { .. } => {
                    self.open = None;
                    self.next = self.script.len();
                }
            }
        }
    }

    fn replied<M>(
        &mut self,
        key: Key,
        generation: u64,
        reply: Reply,
        settled: Option<(Ret, u64, u64)>,
        now: u64,
        out: &mut Outbox<Wire<M>>,
    ) {
        let mut events = Vec::new();
        self.client
            .replied(key, generation, reply, &mut |event| events.push(event));
        self.handle(events, settled, now, out);
    }

    /// One tick at `now`.
    pub fn tick<M>(&mut self, now: u64, out: &mut Outbox<Wire<M>>) {
        if let Some(open) = self.open.as_ref() {
            let (key, unknown, busy) = (open.key, open.unknown, open.busy);
            let waited = now
                .checked_sub(open.sent)
                .is_some_and(|waited| waited >= self.retry_after);
            if unknown || (busy && waited) {
                // The caller's retry: the same request, which the
                // cluster's deduplication answers rather than applies
                // again.
                if let Ok(send) = self.client.retry(key.sequence) {
                    if let Some(open) = self.open.as_mut() {
                        open.unknown = false;
                        open.busy = false;
                    }
                    self.observe(Observation::ClientRetry {
                        client: self.id,
                        sequence: key.sequence,
                    });
                    self.send(send, now, out);
                }
            } else if waited && !busy {
                let mut events = Vec::new();
                self.client.timed_out(key, &mut |event| events.push(event));
                self.handle(events, None, now, out);
            }
            return;
        }
        let Some(op) = self.script.get(self.next).cloned() else {
            return;
        };
        let Ok(send) = self.client.submit() else {
            return;
        };
        let Some(sequence) = send.key.sequence.checked_add(1) else {
            return;
        };
        // `next` indexes the script, so it is below `usize::MAX`.
        self.next += 1;
        let _ = self
            .recorder
            .borrow_mut()
            .history
            .invoke(self.id, op.clone());
        self.open = Some(Open {
            command: Command {
                client: self.id,
                sequence,
                op,
            },
            key: send.key,
            sent: now,
            unknown: false,
            busy: false,
            sends: Vec::new(),
        });
        self.send(send, now, out);
    }

    /// `message` from `from` at `now`.
    pub fn deliver<M>(
        &mut self,
        from: NodeId,
        message: Wire<M>,
        now: u64,
        out: &mut Outbox<Wire<M>>,
    ) {
        match message {
            Wire::Response {
                sequence,
                bytes,
                index,
                generation: answered,
            } => {
                // Bytes that do not decode are no answer: the retry asks
                // again.
                // An answer names its own generation; any attempt's outcome
                // is the request's.
                let key = self
                    .exchange(from, sequence)
                    .map(|(key, _)| key)
                    .or_else(|| {
                        self.open
                            .as_ref()
                            .filter(|open| open.command.sequence == sequence)
                            .map(|open| open.key)
                    });
                let (Some(key), Some(ret)) = (key, Ret::decode(&bytes)) else {
                    return;
                };
                let answer = if ret == Ret::Expired {
                    Answer::Duplicate
                } else {
                    Answer::Applied
                };
                self.replied(
                    key,
                    answered,
                    Reply::Outcome(answer),
                    Some((ret, index, answered)),
                    now,
                    out,
                );
            }
            Wire::Refused { sequence } => {
                if let Some((key, generation)) = self.exchange(from, sequence) {
                    let leader = Some(u64::from(from));
                    self.replied(key, generation, Reply::Redirect { leader }, None, now, out);
                }
            }
            Wire::Busy { sequence } => {
                if let Some((key, generation)) = self.exchange(from, sequence) {
                    let reply = Reply::Outcome(Answer::WindowFull);
                    self.replied(key, generation, reply, None, now, out);
                }
            }
            Wire::Redirect { server } => {
                let leader = Some(u64::from(server));
                let sequence = self.open.as_ref().map(|open| open.command.sequence);
                // A server's redirect answers the last attempt sent to it;
                // the operator's is a leader change.
                match sequence.and_then(|sequence| self.exchange(from, sequence)) {
                    Some((key, generation)) => {
                        self.replied(key, generation, Reply::Redirect { leader }, None, now, out);
                    }
                    None => {
                        let generation = self.client.generation();
                        let mut events = Vec::new();
                        self.client
                            .leader_changed(leader, generation, &mut |event| events.push(event));
                        self.handle(events, None, now, out);
                    }
                }
            }
            _ => {}
        }
    }
}
