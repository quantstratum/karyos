// SPDX-License-Identifier: Apache-2.0

//! The Cluster client's failover (quantstratum-docs: karyos/SPEC.md §9,
//! "Cluster clients follow leader changes and generation changes, and
//! resubmit with stable client identity and request sequence, relying on
//! the replicated deduplication above. Requests whose outcome is unknown
//! are reported as unknown"; owner decisions 2026-10-21, items 37 and 44;
//! karyos#720).
//!
//! [`ClusterClient`] is the client's state, transport-neutral: its caller
//! sends what it returns and feeds it what arrives.
//!
//! - **Bounds.** A client registers ([`ClusterClient::registered`]) with
//!   the session the cluster opened ([`Registered`]): its epoch and the
//!   bounds the cluster advertises (sessions, window `K`, reply bytes,
//!   TTL). It never assumes them: a submit past `K` requests outstanding is
//!   refused ([`SubmitError::WindowFull`]) before anything is sent.
//! - **Identity.** Every request carries the client's stable identity, its
//!   session's epoch and its sequence, from 0 within the session; a resend
//!   is the same request, so the cluster's deduplication answers it with
//!   the reply it kept rather than applying it again.
//! - **Leader changes.** A redirect ([`Reply::Redirect`]) means the request
//!   was not taken: the client follows the leader it names and resends the
//!   same request there ([`Event::Resend`]). A leader change the client
//!   learns otherwise ([`ClusterClient::leader_changed`]), or a request
//!   that times out ([`ClusterClient::timed_out`]), leaves each request
//!   still outstanding **unknown** ([`Event::Unknown`], with the client's
//!   identity and the sequence): it may have been applied. The client never
//!   resends an unknown request on its own (item 44); its caller does, by
//!   [`ClusterClient::retry`], and deduplication makes that safe.
//! - **Generations.** The client keeps the highest cluster generation it
//!   has seen; a reply of a lower one is refused
//!   ([`Event::StaleGeneration`]) and changes nothing.
//! - **Expiry.** A session the cluster no longer holds
//!   ([`Reply::Outcome`] of `SessionExpired`) reaches the caller as
//!   [`Event::Expired`], never as a retry: every request still outstanding
//!   is unknown, and the client registers again under a new epoch.
//! - **Allocation.** The outstanding requests live in a buffer sized to the
//!   window at registration; nothing after that allocates (the Cluster's
//!   hard gate): events go to a caller's sink, not into a vector.

use crate::dedup::{DedupConfig, Registered, Request};

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
    /// The session's window is full: not applied, try again later.
    WindowFull,
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
    /// Send `request` to `to`: the same request again, after a redirect,
    /// or because the caller asked for it.
    Resend {
        /// The server.
        to: u64,
        /// The request.
        request: Request,
    },
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
    /// A reply of a generation below one already seen: refused.
    StaleGeneration {
        /// Its generation.
        generation: u64,
        /// The highest seen.
        highest: u64,
    },
    /// The cluster refused `sequence` for a full window: not applied; the
    /// caller may retry it later.
    Busy {
        /// The sequence.
        sequence: u64,
    },
}

/// Why a submit was refused, before anything was sent.
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
}

/// One outstanding request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Slot {
    sequence: u64,
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
    /// on. Its outstanding buffer is sized to the window here, the last
    /// allocation it makes.
    pub fn registered(&mut self, registered: Registered, generation: u64) {
        self.generation = self.generation.max(generation);
        self.session = Some(Session {
            epoch: registered.epoch,
            bounds: registered.config,
        });
        self.next_sequence = 0;
        self.outstanding.clear();
        let window = usize::try_from(registered.config.window).unwrap_or(usize::MAX);
        self.outstanding
            .reserve(window.saturating_sub(self.outstanding.capacity()));
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

    fn request(&self, session: Session, sequence: u64) -> Request {
        Request::new(
            self.client,
            session.epoch,
            sequence,
            self.lowest_unanswered(),
        )
    }

    /// The next request, to send to the leader: `(leader, request)`.
    ///
    /// # Errors
    ///
    /// [`SubmitError`], before anything is sent.
    pub fn submit(&mut self) -> Result<(u64, Request), SubmitError> {
        let session = self.session.ok_or(SubmitError::NotRegistered)?;
        let window = session.bounds.window;
        if self.outstanding.len() >= usize::try_from(window).unwrap_or(usize::MAX) {
            return Err(SubmitError::WindowFull { window });
        }
        let leader = self.leader.ok_or(SubmitError::NoLeader)?;
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        self.outstanding.push(Slot {
            sequence,
            unknown: false,
        });
        Ok((leader, self.request(session, sequence)))
    }

    /// The caller retries request `sequence`, outstanding or unknown: the
    /// same request, to the current leader.
    ///
    /// # Errors
    ///
    /// [`SubmitError`].
    pub fn retry(&mut self, sequence: u64) -> Result<(u64, Request), SubmitError> {
        let session = self.session.ok_or(SubmitError::NotRegistered)?;
        let leader = self.leader.ok_or(SubmitError::NoLeader)?;
        let slot = self
            .outstanding
            .iter_mut()
            .find(|slot| slot.sequence == sequence)
            .ok_or(SubmitError::NotOutstanding { sequence })?;
        slot.unknown = false;
        Ok((leader, self.request(session, sequence)))
    }

    /// The caller gives up on request `sequence`, unknown: it leaves the
    /// window, its outcome unknown for good.
    pub fn abandon(&mut self, sequence: u64) {
        self.outstanding.retain(|slot| slot.sequence != sequence);
    }

    /// The reply to request `sequence` from a server of `generation`.
    pub fn replied(
        &mut self,
        sequence: u64,
        generation: u64,
        reply: Reply,
        sink: &mut (impl FnMut(Event) + ?Sized),
    ) {
        if generation < self.generation {
            return sink(Event::StaleGeneration {
                generation,
                highest: self.generation,
            });
        }
        self.generation = generation;
        let Some(session) = self.session else {
            return;
        };
        let Some(at) = self
            .outstanding
            .iter()
            .position(|slot| slot.sequence == sequence)
        else {
            // An answer to a request already settled: nothing changes.
            return;
        };
        match reply {
            Reply::Redirect { leader } => {
                self.leader = leader;
                match leader {
                    // Not taken: the same request, to the leader named.
                    Some(to) => sink(Event::Resend {
                        to,
                        request: self.request(session, sequence),
                    }),
                    // No leader known: not taken either, but nowhere to
                    // send it; the caller retries once one is known.
                    None => sink(Event::Busy { sequence }),
                }
            }
            Reply::Outcome(Answer::WindowFull) => sink(Event::Busy { sequence }),
            Reply::Outcome(Answer::SessionExpired) => self.expire(session, sink),
            Reply::Outcome(answer) => {
                let _ = self.outstanding.remove(at);
                sink(Event::Completed { sequence, answer });
            }
        }
    }

    /// The session expired: every outstanding request is unknown, and the
    /// client has no session until it registers again.
    fn expire(&mut self, session: Session, sink: &mut (impl FnMut(Event) + ?Sized)) {
        for slot in &self.outstanding {
            sink(Event::Unknown {
                client: self.client,
                sequence: slot.sequence,
            });
        }
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

    /// Request `sequence` got no reply in time: its outcome is unknown, and
    /// it is not resent.
    pub fn timed_out(&mut self, sequence: u64, sink: &mut (impl FnMut(Event) + ?Sized)) {
        if let Some(slot) = self
            .outstanding
            .iter_mut()
            .find(|slot| slot.sequence == sequence && !slot.unknown)
        {
            slot.unknown = true;
            sink(Event::Unknown {
                client: self.client,
                sequence,
            });
        }
    }
}
