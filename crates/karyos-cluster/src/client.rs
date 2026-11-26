// SPDX-License-Identifier: Apache-2.0

//! The Cluster client's failover (quantstratum-docs: karyos/SPEC.md §9,
//! "Cluster clients follow leader changes and generation changes, and
//! resubmit with stable client identity and request sequence, relying on
//! the replicated deduplication above. Requests whose outcome is unknown
//! are reported as unknown"; owner decisions 2026-10-21, items 37 and 44;
//! karyos#720).
//!
//! [`ClusterClient`] is the client's state, transport-neutral: its caller
//! sends what it returns and feeds it what arrives, each answer named by
//! the request's [`Key`] (session epoch, sequence, attempt).
//!
//! - **Bounds.** A client registers ([`ClusterClient::registered`]) with
//!   the session the cluster opened ([`Registered`]): its epoch and the
//!   bounds the cluster advertises (sessions, window `K`, reply bytes,
//!   TTL). It never assumes them: a submit past `K` requests outstanding is
//!   refused ([`SubmitError::WindowFull`]) before anything is sent. A
//!   registration of an older epoch than the one held is refused; the same
//!   epoch again changes nothing; a newer one replaces the session, and
//!   every request still outstanding becomes unknown.
//! - **Identity.** Every request carries the client's stable identity, its
//!   session's epoch and its sequence, from 0 within the session; a resend
//!   is the same request, so the cluster's deduplication answers it with
//!   the reply it kept rather than applying it again. Each send of it is
//!   an attempt, numbered, so an answer to an older attempt cannot steer a
//!   newer one.
//! - **Leader changes.** A redirect ([`Reply::Redirect`]) to the current
//!   attempt of a request whose outcome is not unknown means it was not
//!   taken: the client follows the leader named and resends the same
//!   request there ([`Event::Resend`]), or reports it waiting for a leader
//!   ([`Event::NoLeader`]). A leader change the client learns otherwise
//!   ([`ClusterClient::leader_changed`]), or a request that times out
//!   ([`ClusterClient::timed_out`]), leaves each request still outstanding
//!   **unknown** ([`Event::Unknown`], with the client's identity and the
//!   sequence): it may have been applied. The client never resends an
//!   unknown request on its own (item 44); its caller does, by
//!   [`ClusterClient::retry`], and deduplication makes that safe. An
//!   unknown request keeps its place in the window until it has an
//!   outcome: the lowest unanswered sequence every request carries stays
//!   at it, so the cluster keeps its reply for the retry; giving it up
//!   takes a new session.
//! - **Generations.** The client keeps the highest cluster generation it
//!   has seen, raised only by an answer to one of its outstanding requests
//!   or by [`ClusterClient::leader_changed`]; an answer or an announcement
//!   of a lower one is refused ([`Event::StaleGeneration`]) and changes
//!   nothing.
//! - **Expiry.** A session the cluster no longer holds reaches the caller
//!   as [`Event::Expired`], never as a retry: every request still
//!   outstanding is unknown, and the client registers again.
//! - **Allocation.** The outstanding requests live in a buffer reserved to
//!   the window at registration; nothing after that allocates (the
//!   Cluster's hard gate): events go to a caller's sink, not into a vector.

use crate::dedup::{DedupConfig, Registered, Request};

/// What names one send of a request: its session's epoch, its sequence,
/// and the attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key {
    /// The session's epoch.
    pub epoch: u64,
    /// The request's sequence.
    pub sequence: u64,
    /// The send: 0 for the first, one more for each resend or retry.
    pub attempt: u32,
}

/// A request to send: to whom, what, and the key its answer comes back
/// under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Send {
    /// The server.
    pub to: u64,
    /// The request.
    pub request: Request,
    /// Its key.
    pub key: Key,
}

/// What the cluster answered a request with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reply {
    /// Its outcome, as the deduplication gave it.
    Outcome(Answer),
    /// The server does not lead; `leader` is the one it knows, if any.
    Redirect {
        /// The leader.
        leader: Option<u64>,
    },
}

/// A request's outcome from the cluster's deduplication, without its
/// reply's bytes (the caller keeps those).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Answer {
    /// Applied now.
    Applied,
    /// Applied before: its kept reply.
    Retained,
    /// Applied before; its reply is gone.
    Duplicate,
    /// Applied, once; its reply did not fit the advertised reply bytes.
    ReplyTooLarge,
    /// The session expired.
    SessionExpired,
    /// The session's window is full: not applied, retry later.
    WindowFull,
    /// The identity applied before with another command: not applied, and
    /// not a duplicate; a client's bug.
    PayloadMismatch,
    /// Under a log written by an earlier build, whose sessions take
    /// sequences in order: the sequence is past the one the session
    /// expects; not applied, the earlier one comes first.
    OutOfOrder {
        /// The sequence the session expects.
        expected: u64,
    },
}

/// What the client tells its caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// Request `sequence` has its outcome.
    Completed {
        /// The sequence.
        sequence: u64,
        /// Its outcome.
        answer: Answer,
    },
    /// Send this again: the same request, after a redirect.
    Resend(Send),
    /// Request `sequence` of `client` may or may not have been applied;
    /// it is not sent again unless the caller retries it.
    Unknown {
        /// The client's identity.
        client: u64,
        /// The sequence.
        sequence: u64,
    },
    /// The session expired: every request still outstanding is unknown,
    /// and the client must register again.
    Expired {
        /// The client's identity.
        client: u64,
        /// The epoch that expired.
        epoch: u64,
    },
    /// An answer or an announcement of a generation below one already
    /// seen: refused.
    StaleGeneration {
        /// Its generation.
        generation: u64,
        /// The highest seen.
        highest: u64,
    },
    /// The cluster refused `sequence` for a full window: not applied; the
    /// caller retries it later.
    Busy {
        /// The sequence.
        sequence: u64,
    },
    /// The cluster refused `sequence` for coming before `expected`: not
    /// applied; the caller retries `expected` first.
    OutOfOrder {
        /// The sequence.
        sequence: u64,
        /// The one the session expects.
        expected: u64,
    },
    /// `sequence` was not taken, and no leader is known: the caller
    /// retries it once one is.
    NoLeader {
        /// The sequence.
        sequence: u64,
    },
}

/// Why a submit or a retry was refused, before anything was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SubmitError {
    /// No session: register first.
    #[error("the client has no session")]
    NotRegistered,
    /// `window` requests are outstanding, the advertised bound.
    #[error("{window} requests are outstanding, the window the cluster advertised")]
    WindowFull {
        /// The window.
        window: u32,
    },
    /// No leader is known to send to.
    #[error("no leader is known")]
    NoLeader,
    /// The sequence is not one of the client's outstanding requests.
    #[error("request {sequence} is not outstanding")]
    NotOutstanding {
        /// The sequence.
        sequence: u64,
    },
    /// The session's sequences or a request's attempts ran out: register
    /// again.
    #[error("the session's sequences are exhausted")]
    Exhausted,
}

/// Why a registration was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RegisterError {
    /// Its epoch is below the session held: a stale answer.
    #[error("epoch {epoch} is below the session's {held}")]
    Stale {
        /// Its epoch.
        epoch: u64,
        /// The session held.
        held: u64,
    },
}

/// One outstanding request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Slot {
    sequence: u64,
    attempt: u32,
    unknown: bool,
}

/// The session the client holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Session {
    epoch: u64,
    bounds: DedupConfig,
}

/// A Cluster client's failover state.
#[derive(Debug, Clone)]
pub struct ClusterClient {
    client: u64,
    session: Option<Session>,
    next_sequence: u64,
    leader: Option<u64>,
    generation: u64,
    /// The outstanding requests, oldest first, at most the window.
    outstanding: Vec<Slot>,
}

impl ClusterClient {
    /// Client `client`, with no session yet, sending to `leader` if known.
    #[must_use]
    pub const fn new(client: u64, leader: Option<u64>) -> Self {
        Self {
            client,
            session: None,
            next_sequence: 0,
            leader,
            generation: 0,
            outstanding: Vec::new(),
        }
    }

    /// The session the cluster opened for the client, in `generation`: its
    /// epoch and its advertised bounds, which the client holds to from now
    /// on. A newer session replaces the one held, every request still
    /// outstanding reported unknown to `sink`; the same one again changes
    /// nothing. The outstanding buffer is reserved to the window here, the
    /// last allocation the client makes.
    ///
    /// # Errors
    ///
    /// [`RegisterError::Stale`] for an epoch below the session held,
    /// changing nothing.
    pub fn registered(
        &mut self,
        registered: Registered,
        generation: u64,
        sink: &mut (impl FnMut(Event) + ?Sized),
    ) -> Result<(), RegisterError> {
        if let Some(held) = self.session {
            if registered.epoch < held.epoch {
                return Err(RegisterError::Stale {
                    epoch: registered.epoch,
                    held: held.epoch,
                });
            }
            if registered.epoch == held.epoch {
                return Ok(());
            }
            self.report_unknown(sink);
        }
        self.generation = self.generation.max(generation);
        self.session = Some(Session {
            epoch: registered.epoch,
            bounds: registered.config,
        });
        self.next_sequence = 0;
        self.outstanding.clear();
        // `reserve` counts from the length, 0 after the clear: the whole
        // window.
        let window = usize::try_from(registered.config.window).unwrap_or(usize::MAX);
        self.outstanding.reserve(window);
        Ok(())
    }

    /// The bounds the cluster advertised, once registered.
    #[must_use]
    pub fn bounds(&self) -> Option<DedupConfig> {
        self.session.map(|session| session.bounds)
    }

    /// The leader it sends to.
    #[must_use]
    pub const fn leader(&self) -> Option<u64> {
        self.leader
    }

    /// The highest generation seen.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// The lowest sequence without an outcome: every reply below it may be
    /// dropped by the cluster.
    #[must_use]
    pub fn lowest_unanswered(&self) -> u64 {
        self.outstanding
            .first()
            .map_or(self.next_sequence, |slot| slot.sequence)
    }

    fn send(&self, session: Session, to: u64, slot: Slot) -> Send {
        Send {
            to,
            request: Request::new(
                self.client,
                session.epoch,
                slot.sequence,
                self.lowest_unanswered(),
            ),
            key: Key {
                epoch: session.epoch,
                sequence: slot.sequence,
                attempt: slot.attempt,
            },
        }
    }

    /// The next request, to send to the leader.
    ///
    /// # Errors
    ///
    /// [`SubmitError`], before anything is sent.
    pub fn submit(&mut self) -> Result<Send, SubmitError> {
        let session = self.session.ok_or(SubmitError::NotRegistered)?;
        let window = session.bounds.window;
        if self.outstanding.len() >= usize::try_from(window).unwrap_or(usize::MAX) {
            return Err(SubmitError::WindowFull { window });
        }
        let leader = self.leader.ok_or(SubmitError::NoLeader)?;
        let sequence = self.next_sequence;
        self.next_sequence = sequence.checked_add(1).ok_or(SubmitError::Exhausted)?;
        let slot = Slot {
            sequence,
            attempt: 0,
            unknown: false,
        };
        self.outstanding.push(slot);
        Ok(self.send(session, leader, slot))
    }

    /// The caller retries request `sequence`, outstanding or unknown: the
    /// same request, a new attempt, to the current leader.
    ///
    /// # Errors
    ///
    /// [`SubmitError`].
    pub fn retry(&mut self, sequence: u64) -> Result<Send, SubmitError> {
        let session = self.session.ok_or(SubmitError::NotRegistered)?;
        let leader = self.leader.ok_or(SubmitError::NoLeader)?;
        let slot = self
            .outstanding
            .iter_mut()
            .find(|slot| slot.sequence == sequence)
            .ok_or(SubmitError::NotOutstanding { sequence })?;
        slot.attempt = slot.attempt.checked_add(1).ok_or(SubmitError::Exhausted)?;
        slot.unknown = false;
        let slot = *slot;
        Ok(self.send(session, leader, slot))
    }

    /// The answer to the send named `key` from a server of `generation`.
    pub fn replied(
        &mut self,
        key: Key,
        generation: u64,
        reply: Reply,
        sink: &mut (impl FnMut(Event) + ?Sized),
    ) {
        let Some(session) = self.session.filter(|session| session.epoch == key.epoch) else {
            // An answer of another session: nothing of this one changes.
            return;
        };
        let Some(at) = self
            .outstanding
            .iter()
            .position(|slot| slot.sequence == key.sequence)
        else {
            // An answer to a request already settled: nothing changes.
            return;
        };
        if generation < self.generation {
            return sink(Event::StaleGeneration {
                generation,
                highest: self.generation,
            });
        }
        self.generation = generation;
        let Some(slot) = self.outstanding.get(at).copied() else {
            return;
        };
        // A refusal steers only the current attempt of a request whose
        // outcome is not unknown: an older attempt's, or one after the
        // request became unknown, may answer for a send another attempt
        // overtook.
        let current = slot.attempt == key.attempt && !slot.unknown;
        match reply {
            Reply::Redirect { .. }
            | Reply::Outcome(Answer::WindowFull | Answer::OutOfOrder { .. })
                if !current => {}
            Reply::Redirect { leader } => {
                self.leader = leader;
                match leader {
                    Some(to) => {
                        let slot = self.outstanding.get_mut(at).map(|slot| {
                            slot.attempt = slot.attempt.saturating_add(1);
                            *slot
                        });
                        if let Some(slot) = slot {
                            let send = self.send(session, to, slot);
                            sink(Event::Resend(send));
                        }
                    }
                    None => sink(Event::NoLeader {
                        sequence: key.sequence,
                    }),
                }
            }
            Reply::Outcome(Answer::WindowFull) => sink(Event::Busy {
                sequence: key.sequence,
            }),
            Reply::Outcome(Answer::OutOfOrder { expected }) => sink(Event::OutOfOrder {
                sequence: key.sequence,
                expected,
            }),
            Reply::Outcome(Answer::SessionExpired) => self.expire(session, sink),
            Reply::Outcome(answer) => {
                let _ = self.outstanding.remove(at);
                sink(Event::Completed {
                    sequence: key.sequence,
                    answer,
                });
            }
        }
    }

    /// Every outstanding request not yet reported unknown, reported now.
    fn report_unknown(&mut self, sink: &mut (impl FnMut(Event) + ?Sized)) {
        for slot in &mut self.outstanding {
            if !slot.unknown {
                slot.unknown = true;
                sink(Event::Unknown {
                    client: self.client,
                    sequence: slot.sequence,
                });
            }
        }
    }

    /// The session expired: every outstanding request is unknown, and the
    /// client has no session until it registers again.
    fn expire(&mut self, session: Session, sink: &mut (impl FnMut(Event) + ?Sized)) {
        self.report_unknown(sink);
        self.outstanding.clear();
        self.session = None;
        sink(Event::Expired {
            client: self.client,
            epoch: session.epoch,
        });
    }

    /// The leader changed to `leader` in `generation`, as the client
    /// learned other than by a redirect (a new leader's announcement, a
    /// promoted standby): every request still outstanding may have been
    /// applied by the old one, so each is unknown, and none is resent.
    pub fn leader_changed(
        &mut self,
        leader: Option<u64>,
        generation: u64,
        sink: &mut (impl FnMut(Event) + ?Sized),
    ) {
        if generation < self.generation {
            return sink(Event::StaleGeneration {
                generation,
                highest: self.generation,
            });
        }
        self.generation = generation;
        self.leader = leader;
        self.report_unknown(sink);
    }

    /// The send named `key` got no answer in time: its request's outcome is
    /// unknown, and it is not resent. A timer of an older attempt, or of
    /// another session, changes nothing.
    pub fn timed_out(&mut self, key: Key, sink: &mut (impl FnMut(Event) + ?Sized)) {
        if self
            .session
            .is_none_or(|session| session.epoch != key.epoch)
        {
            return;
        }
        if let Some(slot) = self.outstanding.iter_mut().find(|slot| {
            slot.sequence == key.sequence && slot.attempt == key.attempt && !slot.unknown
        }) {
            slot.unknown = true;
            sink(Event::Unknown {
                client: self.client,
                sequence: key.sequence,
            });
        }
    }
}
