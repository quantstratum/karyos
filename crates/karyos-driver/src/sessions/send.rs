// SPDX-License-Identifier: Apache-2.0

//! The sender agent's SETUP side (`quantstratum-docs:
//! karyos/design/network-sessions.md` S5 `setup_interval`;
//! `network-control-schemas.md` §6.2 and §6.3).
//!
//! - **Announce.** Each publication incarnation announces SETUP every
//!   `setup_interval` until its first SM, then stops (SPEC §5). When the
//!   publication later has no live receiver (no live member and no
//!   confirmed binding), the caller reports it disconnected and it
//!   announces again until the next accepted SM: SPEC §5's rule applied
//!   per connection episode (coordinator decision, ACS 15933).
//! - **Challenge.** The sender answers an RSP_SETUP CHALLENGE only if its
//!   identity block names a publication it currently sends, with that
//!   stream and alias, on the endpoint where it arrived; otherwise the
//!   challenge is dropped and counted and nothing is sent. The answer
//!   echoes the challenge block and states the current join points.
//! - **Solicit.** An RSP_SETUP SOLICIT has no identity: the sender answers
//!   it only if `(stream_id, session_id)` names a publication it sends on
//!   that endpoint.
//!
//! - **Answer rate.** Answers are limited per source endpoint
//!   (`setup_answer_rate`, 20 per second, network-control-schemas.md 7.4):
//!   a spoofed 56-byte SOLICIT must not make the sender emit unbounded
//!   answers toward the spoofed address. Each source endpoint has a
//!   message bucket ([`karyos_sys::rate_limit::RateLimiter`]) in a bounded
//!   table; an entry idle for a second is full again and may be reused, and
//!   with no reusable entry the control is dropped. IPv4-mapped IPv6
//!   sources count as their IPv4 endpoint. Each drop is counted under its
//!   own reason.
//!
//! A state machine with no I/O: the caller decodes the controls, supplies
//! the join points and sends what it returns, through the channel route,
//! never to an address taken from a payload.

use std::net::SocketAddr;

use karyos_protocol::frame::Lane;
use karyos_protocol::network::{
    Alias, Identity, Lanes, RspChallenge, RspSolicit, SetupAnnounce, SetupAnswer, StatusMessage,
    TermParams,
};
use karyos_sys::host_clock::age_ns;

use super::rate::{EndpointRates, RateRefused};
use crate::agents::EndpointId;

/// One publication incarnation as its SETUPs describe it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Publication {
    /// The endpoint it sends on.
    pub endpoint: EndpointId,
    /// Stream and session alias.
    pub alias: Alias,
    /// The full incarnation identity.
    pub identity: Identity,
    /// Term parameters.
    pub term: TermParams,
    /// Lane count, 1 to 4.
    pub lane_count: u8,
}

/// Why a control was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendIgnored {
    /// No publication of this endpoint has the control's alias.
    UnknownAlias,
    /// The alias is ours but the identity block names another incarnation.
    WrongIdentity,
    /// The join points do not cover the publication's lanes.
    Joins,
    /// The source endpoint exceeded `setup_answer_rate`.
    RateLimited,
    /// The per-source rate table is full of sources active within the last
    /// second.
    RateSources,
}

/// Counters of the sender's SETUP side; checked, sticky on overflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SendCounters {
    /// Announcements due and returned.
    pub announces: u64,
    /// Answers to challenges and solicits.
    pub answers: u64,
    /// Challenges and solicits dropped for their content (alias, identity,
    /// joins).
    pub dropped: u64,
    /// Challenges and solicits dropped by `setup_answer_rate`.
    pub rate_limited: u64,
    /// Challenges and solicits dropped with the rate table full.
    pub rate_sources_full: u64,
    /// Incarnations established by an SM: the first, and the first after
    /// each disconnection.
    pub established: u64,
    /// Established incarnations that lost every receiver and announce
    /// again.
    pub reannounced: u64,
    /// An increment did not apply.
    pub overflowed: bool,
}

impl SendCounters {
    fn bump(&mut self, field: fn(&mut Self) -> &mut u64) {
        let value = field(self);
        match value.checked_add(1) {
            Some(next) => *value = next,
            None => self.overflowed = true,
        }
    }
}

/// `setup_answer_rate` and the size of its per-source table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnswerRate {
    /// Answers per second per source endpoint, also the burst (default 20).
    pub per_second: u64,
    /// Source endpoints tracked at once (default 64).
    pub sources: usize,
}

impl Default for AnswerRate {
    fn default() -> Self {
        Self {
            per_second: 20,
            sources: 64,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Session {
    publication: Publication,
    last_announce: Option<u64>,
    established: bool,
}

/// The sender's SETUP state of every publication incarnation it sends,
/// at most `capacity` (allocated at creation).
#[derive(Debug)]
pub struct SendSessions {
    sessions: Vec<Session>,
    capacity: usize,
    setup_interval: u64,
    rates: EndpointRates,
    counters: SendCounters,
}

/// Why a publication could not be added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SendSessionError {
    /// The table holds `capacity` sessions.
    #[error("the sender session table is full")]
    Full,
    /// The endpoint already has a publication with this alias.
    #[error("the alias is already in use on this endpoint")]
    DuplicateAlias,
    /// A zero capacity or interval, or a lane count outside 1 to 4.
    #[error("invalid sender session configuration")]
    InvalidConfig,
}

impl SendSessions {
    /// A table of at most `capacity` sessions announcing every
    /// `setup_interval` ns (default 100 ms), answering at most `rate` per
    /// source endpoint.
    ///
    /// # Errors
    ///
    /// [`SendSessionError::InvalidConfig`] for a zero capacity, interval,
    /// rate or rate table.
    pub fn new(
        capacity: usize,
        setup_interval: u64,
        rate: AnswerRate,
    ) -> Result<Self, SendSessionError> {
        if capacity == 0 || setup_interval == 0 || rate.per_second == 0 || rate.sources == 0 {
            return Err(SendSessionError::InvalidConfig);
        }
        Ok(Self {
            sessions: Vec::with_capacity(capacity),
            capacity,
            setup_interval,
            rates: EndpointRates::new(rate.per_second, rate.sources)
                .ok_or(SendSessionError::InvalidConfig)?,
            counters: SendCounters::default(),
        })
    }

    /// The counters.
    #[must_use]
    pub fn counters(&self) -> SendCounters {
        self.counters
    }

    /// Starts announcing `publication`; its first SETUP is due at once.
    ///
    /// # Errors
    ///
    /// [`SendSessionError::Full`], [`SendSessionError::DuplicateAlias`],
    /// [`SendSessionError::InvalidConfig`] for a lane count outside 1 to 4.
    pub fn add(&mut self, publication: Publication) -> Result<(), SendSessionError> {
        if !(1..=Lane::COUNT).contains(&publication.lane_count) {
            return Err(SendSessionError::InvalidConfig);
        }
        if self.sessions.iter().any(|session| {
            session.publication.endpoint == publication.endpoint
                && session.publication.alias == publication.alias
        }) {
            return Err(SendSessionError::DuplicateAlias);
        }
        if self.sessions.len() >= self.capacity {
            return Err(SendSessionError::Full);
        }
        self.sessions.push(Session {
            publication,
            last_announce: None,
            established: false,
        });
        Ok(())
    }

    /// Stops a publication's SETUP side. Returns whether it was present.
    /// The table keeps no order (`swap_remove`).
    pub fn remove(&mut self, endpoint: EndpointId, alias: Alias) -> bool {
        let found = self.sessions.iter().position(|session| {
            session.publication.endpoint == endpoint && session.publication.alias == alias
        });
        if let Some(index) = found {
            self.sessions.swap_remove(index);
        }
        found.is_some()
    }

    /// The incarnation identity of the publication `alias` on `endpoint`.
    #[must_use]
    pub fn identity(&self, endpoint: EndpointId, alias: Alias) -> Option<Identity> {
        self.sessions
            .iter()
            .find(|session| {
                session.publication.endpoint == endpoint && session.publication.alias == alias
            })
            .map(|session| session.publication.identity)
    }

    /// Whether the publication received its first SM.
    #[must_use]
    pub fn is_established(&self, endpoint: EndpointId, alias: Alias) -> bool {
        self.find(endpoint, alias)
            .is_some_and(|session| session.established)
    }

    fn find(&self, endpoint: EndpointId, alias: Alias) -> Option<&Session> {
        self.sessions.iter().find(|session| {
            session.publication.endpoint == endpoint && session.publication.alias == alias
        })
    }

    fn find_mut(&mut self, endpoint: EndpointId, alias: Alias) -> Option<&mut Session> {
        self.sessions.iter_mut().find(|session| {
            session.publication.endpoint == endpoint && session.publication.alias == alias
        })
    }

    /// The publication on `endpoint` and `alias` has no live receiver: an
    /// established one announces again from the next call of
    /// [`SendSessions::announce_due`], every `setup_interval`, until an
    /// accepted SM establishes it again. Returns whether it was
    /// established.
    pub fn disconnected(&mut self, endpoint: EndpointId, alias: Alias) -> bool {
        let Some(session) = self.find_mut(endpoint, alias) else {
            return false;
        };
        if !session.established {
            return false;
        }
        session.established = false;
        session.last_announce = None;
        self.counters.bump(|c| &mut c.reannounced);
        true
    }

    /// The announcements due at `now`, each to send on its endpoint;
    /// `emit` is called once per due SETUP.
    pub fn announce_due(&mut self, now: u64, mut emit: impl FnMut(EndpointId, SetupAnnounce)) {
        let interval = self.setup_interval;
        for session in &mut self.sessions {
            let due = !session.established
                && session
                    .last_announce
                    .is_none_or(|last| age_ns(now, last) >= interval);
            if !due {
                continue;
            }
            session.last_announce = Some(now);
            let publication = session.publication;
            match self.counters.announces.checked_add(1) {
                Some(next) => self.counters.announces = next,
                None => self.counters.overflowed = true,
            }
            emit(
                publication.endpoint,
                SetupAnnounce {
                    alias: publication.alias,
                    identity: publication.identity,
                    term: publication.term,
                    lane_count: publication.lane_count,
                },
            );
        }
    }

    /// An RSP_SETUP CHALLENGE that arrived on `endpoint` from `source` at
    /// `now`. `joins` gives the publication's current join point of each
    /// lane. Returns the answer to send, or why it was dropped.
    ///
    /// # Errors
    ///
    /// The [`SendIgnored`] reason; the drop is counted.
    pub fn challenge(
        &mut self,
        endpoint: EndpointId,
        source: SocketAddr,
        now: u64,
        challenge: &RspChallenge,
        joins: impl FnOnce(&Publication) -> Lanes<u64>,
    ) -> Result<SetupAnswer, SendIgnored> {
        let Some(session) = self.find(endpoint, challenge.alias) else {
            return Err(self.ignore(SendIgnored::UnknownAlias));
        };
        if session.publication.identity != challenge.identity {
            return Err(self.ignore(SendIgnored::WrongIdentity));
        }
        let publication = session.publication;
        self.answer(
            &publication,
            source,
            now,
            challenge.challenge,
            joins(&publication),
        )
    }

    /// An RSP_SETUP SOLICIT that arrived on `endpoint` from `source` at
    /// `now`: answered by alias, as [`SendSessions::challenge`].
    ///
    /// # Errors
    ///
    /// The [`SendIgnored`] reason; the drop is counted.
    pub fn solicit(
        &mut self,
        endpoint: EndpointId,
        source: SocketAddr,
        now: u64,
        solicit: &RspSolicit,
        joins: impl FnOnce(&Publication) -> Lanes<u64>,
    ) -> Result<SetupAnswer, SendIgnored> {
        let Some(session) = self.find(endpoint, solicit.alias) else {
            return Err(self.ignore(SendIgnored::UnknownAlias));
        };
        let publication = session.publication;
        self.answer(
            &publication,
            source,
            now,
            solicit.challenge,
            joins(&publication),
        )
    }

    fn answer(
        &mut self,
        publication: &Publication,
        source: SocketAddr,
        now: u64,
        challenge: karyos_protocol::network::ChallengeBlock,
        joins: Lanes<u64>,
    ) -> Result<SetupAnswer, SendIgnored> {
        if joins.count() != publication.lane_count {
            return Err(self.ignore(SendIgnored::Joins));
        }
        self.admit(source, now)?;
        self.counters.bump(|c| &mut c.answers);
        Ok(SetupAnswer {
            alias: publication.alias,
            identity: publication.identity,
            term: publication.term,
            challenge,
            joins,
        })
    }

    /// An SM that arrived on `endpoint`, already validated for its
    /// binding: the first one for the publication's exact identity and
    /// alias ends its announcements. A receiver that joins later binds
    /// through SOLICIT ([`SendSessions::solicit`]). Returns whether it
    /// established the publication now.
    pub fn status(&mut self, endpoint: EndpointId, status: &StatusMessage) -> bool {
        let Some(session) = self.find_mut(endpoint, status.alias) else {
            return false;
        };
        if session.publication.identity != status.identity || session.established {
            return false;
        }
        session.established = true;
        self.counters.bump(|c| &mut c.established);
        true
    }

    /// Charges one answer to `source`'s bucket at `now`.
    fn admit(&mut self, source: SocketAddr, now: u64) -> Result<(), SendIgnored> {
        match self.rates.admit(source, now) {
            Ok(()) => Ok(()),
            Err(RateRefused::Limited) => {
                self.counters.bump(|c| &mut c.rate_limited);
                Err(SendIgnored::RateLimited)
            }
            Err(RateRefused::TableFull) => {
                self.counters.bump(|c| &mut c.rate_sources_full);
                Err(SendIgnored::RateSources)
            }
        }
    }

    fn ignore(&mut self, reason: SendIgnored) -> SendIgnored {
        self.counters.bump(|c| &mut c.dropped);
        reason
    }
}

#[cfg(test)]
mod tests;
