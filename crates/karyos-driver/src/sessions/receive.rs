// SPDX-License-Identifier: Apache-2.0

//! The receiver agent's session table (`quantstratum-docs:
//! karyos/design/network-sessions.md`, "Fresh establishment", "Aliases,
//! retirement and quarantine", S1 and S5).
//!
//! - **Key.** A binding key is the local endpoint, the source endpoint and
//!   the `(stream_id, session_id)` alias. A SETUP for an unbound key gets a
//!   challenge; the answer must come from the same key.
//! - **Challenge.** At most one per key. An identical announcement resends
//!   the current challenge without extending its expiry; any other one, or
//!   one after expiry, replaces it with a fresh nonce. Pending challenges
//!   are bounded globally and per source address; a full table is scanned
//!   for expired entries before an announcement is refused.
//! - **Answer.** It must match the key, the identity, the term parameters,
//!   the lane count, this receiver's boot id and the current nonce, before
//!   `setup_challenge_timeout` (checked here, whatever the timers did). The
//!   caller reserves the conductor command chain first (S1); on success the
//!   challenge is `Answered`: a second answer is ignored, and no timer frees
//!   it until the conductor replies.
//! - **Installation.** `ImageReady` installs the image in one transition
//!   if the challenge is still within its timeout, and bumps the slot's
//!   checked generation; otherwise the image is released. `ImageRefused`
//!   removes the challenge.
//! - **Bound.** A SETUP for the bound identity is ignored and counted; one
//!   for another identity is rejected until the image retires; neither
//!   refreshes liveness.
//! - **Retirement.** The binding goes at once; the full identity stays
//!   quarantined for `alias_quarantine`, and the slot stays charged until
//!   both the quarantine has passed and the conductor reclaimed the
//!   storage. An unexpired tombstone is never evicted.
//!
//! Every deadline is an elapsed time from `host_clock::age_ns`, never an
//! addition. Counters are checked and sticky on overflow.

use std::net::SocketAddr;

use karyos_protocol::network::{
    Alias, ChallengeBlock, Identity, RspChallenge, SetupAnnounce, SetupAnswer, TermParams,
};
use karyos_sys::host_clock::age_ns;

use super::NonceSource;
use crate::agents::EndpointId;

/// A binding key: the local endpoint, the datagram's source and its alias.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BindingKey {
    /// The local endpoint the datagram arrived on.
    pub endpoint: EndpointId,
    /// The datagram's source, from backend metadata.
    pub source: SocketAddr,
    /// Stream and session alias.
    pub alias: Alias,
}

/// The table's limits and timeouts (S5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionConfig {
    /// Entries: images, pending challenges and quarantined tombstones
    /// together (`max_images`, default 64).
    pub max_images: usize,
    /// Pending challenges at once (default 16), at most `max_images`.
    pub max_pending_challenges: usize,
    /// Pending challenges per source address (default 4), at most
    /// `max_pending_challenges`.
    pub max_pending_per_source: usize,
    /// How long a challenge lives, in ns (default 1 s).
    pub setup_challenge_timeout: u64,
    /// How long a retired identity stays quarantined, in ns (default 10 s).
    pub alias_quarantine: u64,
    /// Timer actions per receiver duty (default 64).
    pub timer_actions: u32,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_images: 64,
            max_pending_challenges: 16,
            max_pending_per_source: 4,
            setup_challenge_timeout: 1_000_000_000,
            alias_quarantine: 10_000_000_000,
            timer_actions: 64,
        }
    }
}

/// A configuration the table refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid session configuration: {0}")]
pub struct SessionConfigError(pub &'static str);

impl SessionConfig {
    fn validate(&self) -> Result<(), SessionConfigError> {
        if self.max_images == 0
            || self.max_pending_challenges == 0
            || self.max_pending_per_source == 0
            || self.timer_actions == 0
        {
            return Err(SessionConfigError("a capacity or budget is zero"));
        }
        if self.max_pending_challenges > self.max_images {
            return Err(SessionConfigError(
                "max_pending_challenges above max_images",
            ));
        }
        if self.max_pending_per_source > self.max_pending_challenges {
            return Err(SessionConfigError(
                "max_pending_per_source above max_pending_challenges",
            ));
        }
        if self.setup_challenge_timeout == 0 || self.alias_quarantine == 0 {
            return Err(SessionConfigError("a timeout is zero"));
        }
        Ok(())
    }
}

/// Names one session slot at one generation: a delayed command for a
/// reused slot never matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SlotRef {
    /// The slot index.
    pub slot: u32,
    /// The slot's generation.
    pub generation: u32,
}

/// What the receiver does with an announcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnounceOutcome {
    /// Send this challenge (new or resent).
    Challenge(RspChallenge),
    /// Ignored and counted: the reason.
    Dropped(Ignored),
}

/// What the receiver does with an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerOutcome {
    /// Accepted: post `CreateImage` for this slot with this geometry.
    CreateImage {
        /// The pending slot.
        slot: SlotRef,
        /// The answering incarnation.
        identity: Identity,
        /// Term parameters.
        term: TermParams,
        /// Each lane's join position.
        joins: karyos_protocol::network::Lanes<u64>,
    },
    /// Ignored and counted: the reason.
    Dropped(Ignored),
}

/// What the receiver does with the conductor's `ImageReady`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadyOutcome {
    /// Installed: post `ImageInstalled`; the image is bound and its first SM
    /// is due.
    Installed(SlotRef),
    /// Too late or stale: post `ReleaseImage`; nothing is bound.
    Release(SlotRef),
}

/// Why a control was ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ignored {
    /// The full identity is quarantined after retirement.
    Quarantined,
    /// The key is bound to this identity: a replayed or late SETUP.
    BoundSameIdentity,
    /// The key is bound to another identity.
    BoundOtherIdentity,
    /// The pending challenge tables are full (globally or for the source).
    ChallengeCapacity,
    /// No free session slot.
    TableFull,
    /// The nonce source failed.
    NoNonce,
    /// The key's challenge was answered and awaits the conductor; this
    /// announcement differs from it.
    AwaitingInstallation,
    /// No challenge for the key.
    NoChallenge,
    /// The answer does not match the challenge (identity, parameters, boot
    /// id or nonce).
    Mismatch,
    /// The challenge expired.
    Expired,
    /// The challenge was already answered.
    AlreadyAnswered,
    /// The conductor command chain could not be reserved.
    NoCommandCredit,
}

/// Counters of the table; increments are checked and `overflowed` is
/// sticky.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SessionCounters {
    /// Challenges created.
    pub challenges: u64,
    /// Challenges resent for an identical announcement.
    pub challenge_resends: u64,
    /// Challenges replaced by another announcement or after expiry.
    pub challenges_replaced: u64,
    /// Challenges freed by the timer after expiry.
    pub challenges_expired: u64,
    /// Announcements and answers dropped, all reasons.
    pub dropped: u64,
    /// Images installed.
    pub installed: u64,
    /// Images released at `ImageReady` (too late) or refused.
    pub released: u64,
    /// Images retired.
    pub retired: u64,
    /// Slots retired for good because their generation is exhausted.
    pub slots_exhausted: u64,
    /// An increment did not apply.
    pub overflowed: bool,
}

impl SessionCounters {
    fn bump(&mut self, field: fn(&mut Self) -> &mut u64) {
        let value = field(self);
        match value.checked_add(1) {
            Some(next) => *value = next,
            None => self.overflowed = true,
        }
    }
}

/// A slot's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Free,
    /// A pending challenge; `answered` once the answer was accepted and the
    /// conductor asked to create the image.
    Challenged {
        key: BindingKey,
        identity: Identity,
        term: TermParams,
        lane_count: u8,
        nonce: [u64; 2],
        created_at: u64,
        answered: bool,
    },
    Active {
        key: BindingKey,
        identity: Identity,
    },
    /// Retired: the identity is quarantined; the storage may still be held.
    Retired {
        identity: Identity,
        retired_at: u64,
        reclaimed: bool,
    },
    /// Generation exhausted: never reused.
    Exhausted,
}

#[derive(Debug, Clone, Copy)]
struct Slot {
    generation: u32,
    state: State,
}

/// The receiver agent's session table.
#[derive(Debug)]
pub struct ReceiveSessions {
    config: SessionConfig,
    boot_id: [u64; 2],
    slots: Vec<Slot>,
    counters: SessionCounters,
}

impl ReceiveSessions {
    /// A table for the receiver started with `boot_id` (random, not all
    /// zero); every slot is allocated here.
    ///
    /// # Errors
    ///
    /// [`SessionConfigError`] for a configuration S5 refuses or a zero boot
    /// id.
    pub fn new(config: SessionConfig, boot_id: [u64; 2]) -> Result<Self, SessionConfigError> {
        config.validate()?;
        if boot_id == [0, 0] {
            return Err(SessionConfigError("receiver_boot_id is zero"));
        }
        Ok(Self {
            config,
            boot_id,
            slots: vec![
                Slot {
                    generation: 0,
                    state: State::Free,
                };
                config.max_images
            ],
            counters: SessionCounters::default(),
        })
    }

    /// The counters.
    #[must_use]
    pub fn counters(&self) -> SessionCounters {
        self.counters
    }

    fn ignore(&mut self, reason: Ignored) -> Ignored {
        self.counters.bump(|c| &mut c.dropped);
        reason
    }

    fn slot_ref(index: usize, slot: &Slot) -> Option<SlotRef> {
        Some(SlotRef {
            slot: u32::try_from(index).ok()?,
            generation: slot.generation,
        })
    }

    /// The bound image of `key`, for DATA admission: the slot to recheck
    /// immediately before the receive owner call.
    #[must_use]
    pub fn lookup(&self, key: &BindingKey) -> Option<SlotRef> {
        self.slots
            .iter()
            .enumerate()
            .find_map(|(index, slot)| match slot.state {
                State::Active { key: bound, .. } if bound == *key => Self::slot_ref(index, slot),
                _ => None,
            })
    }

    /// Whether `slot` still names an active image (the admission recheck).
    #[must_use]
    pub fn is_active(&self, slot: SlotRef) -> bool {
        self.get(slot)
            .is_some_and(|entry| matches!(entry.state, State::Active { .. }))
    }

    fn get(&self, slot: SlotRef) -> Option<&Slot> {
        self.slots
            .get(usize::try_from(slot.slot).ok()?)
            .filter(|entry| entry.generation == slot.generation)
    }

    fn get_mut(&mut self, slot: SlotRef) -> Option<&mut Slot> {
        self.slots
            .get_mut(usize::try_from(slot.slot).ok()?)
            .filter(|entry| entry.generation == slot.generation)
    }

    fn quarantined(&self, identity: &Identity, now: u64) -> bool {
        self.slots.iter().any(|slot| match slot.state {
            State::Retired {
                identity: retired,
                retired_at,
                ..
            } => retired == *identity && age_ns(now, retired_at) < self.config.alias_quarantine,
            _ => false,
        })
    }

    fn pending(&self, source: Option<SocketAddr>) -> usize {
        self.slots
            .iter()
            .filter(|slot| match slot.state {
                State::Challenged { key, .. } => {
                    source.is_none_or(|source| key.source.ip() == source.ip())
                }
                _ => false,
            })
            .count()
    }

    /// Frees every expired, unanswered challenge and every tombstone whose
    /// quarantine passed with its storage reclaimed. Returns how many.
    fn sweep(&mut self, now: u64, limit: u32) -> u32 {
        let timeout = self.config.setup_challenge_timeout;
        let quarantine = self.config.alias_quarantine;
        let mut freed = 0u32;
        for slot in &mut self.slots {
            if freed >= limit {
                break;
            }
            let free = match slot.state {
                State::Challenged {
                    created_at,
                    answered: false,
                    ..
                } => {
                    let expired = age_ns(now, created_at) >= timeout;
                    if expired {
                        self.counters.bump(|c| &mut c.challenges_expired);
                    }
                    expired
                }
                State::Retired {
                    retired_at,
                    reclaimed: true,
                    ..
                } => age_ns(now, retired_at) >= quarantine,
                _ => false,
            };
            if free {
                slot.state = State::Free;
                freed += 1;
            }
        }
        freed
    }

    /// Timer duty: frees expired entries, up to the configured
    /// `timer_actions`. Returns how many were freed.
    pub fn timers(&mut self, now: u64) -> u32 {
        self.sweep(now, self.config.timer_actions)
    }

    /// A SETUP ANNOUNCE from `key` at `now`.
    pub fn announce(
        &mut self,
        key: BindingKey,
        announce: &SetupAnnounce,
        now: u64,
        nonces: &mut impl NonceSource,
    ) -> AnnounceOutcome {
        if self.quarantined(&announce.identity, now) {
            return AnnounceOutcome::Dropped(self.ignore(Ignored::Quarantined));
        }
        let timeout = self.config.setup_challenge_timeout;
        let existing = self.slots.iter().position(|slot| match slot.state {
            State::Active { key: bound, .. } | State::Challenged { key: bound, .. } => bound == key,
            _ => false,
        });
        if let Some(index) = existing
            && let Some(slot) = self.slots.get(index)
        {
            match slot.state {
                State::Active { identity, .. } => {
                    let reason = if identity == announce.identity {
                        Ignored::BoundSameIdentity
                    } else {
                        Ignored::BoundOtherIdentity
                    };
                    return AnnounceOutcome::Dropped(self.ignore(reason));
                }
                State::Challenged {
                    identity,
                    term,
                    lane_count,
                    nonce,
                    created_at,
                    answered,
                    ..
                } => {
                    let identical = identity == announce.identity
                        && term == announce.term
                        && lane_count == announce.lane_count;
                    if identical && (answered || age_ns(now, created_at) < timeout) {
                        // The same challenge, its expiry unchanged.
                        self.counters.bump(|c| &mut c.challenge_resends);
                        return AnnounceOutcome::Challenge(self.challenge(key, identity, nonce));
                    }
                    if answered {
                        return AnnounceOutcome::Dropped(
                            self.ignore(Ignored::AwaitingInstallation),
                        );
                    }
                    // Replace: a fresh nonce makes the old answer unusable.
                    let Some(fresh) = nonces.nonce() else {
                        return AnnounceOutcome::Dropped(self.ignore(Ignored::NoNonce));
                    };
                    if let Some(slot) = self.slots.get_mut(index) {
                        slot.state = State::Challenged {
                            key,
                            identity: announce.identity,
                            term: announce.term,
                            lane_count: announce.lane_count,
                            nonce: fresh,
                            created_at: now,
                            answered: false,
                        };
                    }
                    self.counters.bump(|c| &mut c.challenges_replaced);
                    return AnnounceOutcome::Challenge(self.challenge(
                        key,
                        announce.identity,
                        fresh,
                    ));
                }
                _ => {}
            }
        }
        // A new challenge: capacity first, expired entries freed if needed.
        let full = |table: &Self| {
            table.pending(None) >= table.config.max_pending_challenges
                || table.pending(Some(key.source)) >= table.config.max_pending_per_source
                || !table.slots.iter().any(|slot| slot.state == State::Free)
        };
        if full(self) {
            self.sweep(now, u32::MAX);
        }
        if self.pending(None) >= self.config.max_pending_challenges
            || self.pending(Some(key.source)) >= self.config.max_pending_per_source
        {
            return AnnounceOutcome::Dropped(self.ignore(Ignored::ChallengeCapacity));
        }
        let Some(index) = self.slots.iter().position(|slot| slot.state == State::Free) else {
            return AnnounceOutcome::Dropped(self.ignore(Ignored::TableFull));
        };
        let Some(nonce) = nonces.nonce() else {
            return AnnounceOutcome::Dropped(self.ignore(Ignored::NoNonce));
        };
        if let Some(slot) = self.slots.get_mut(index) {
            slot.state = State::Challenged {
                key,
                identity: announce.identity,
                term: announce.term,
                lane_count: announce.lane_count,
                nonce,
                created_at: now,
                answered: false,
            };
        }
        self.counters.bump(|c| &mut c.challenges);
        AnnounceOutcome::Challenge(self.challenge(key, announce.identity, nonce))
    }

    fn challenge(&self, key: BindingKey, identity: Identity, nonce: [u64; 2]) -> RspChallenge {
        RspChallenge {
            alias: key.alias,
            identity,
            challenge: ChallengeBlock {
                receiver_boot_id: self.boot_id,
                nonce,
            },
        }
    }

    /// A SETUP ANSWER from `key` at `now`. `reserve` reserves the conductor
    /// command chain (S1); it runs only after every check passed, and a
    /// `false` leaves the challenge pending.
    pub fn answer(
        &mut self,
        key: BindingKey,
        answer: &SetupAnswer,
        now: u64,
        reserve: impl FnOnce() -> bool,
    ) -> AnswerOutcome {
        let timeout = self.config.setup_challenge_timeout;
        let boot_id = self.boot_id;
        let found = self
            .slots
            .iter()
            .enumerate()
            .find_map(|(index, slot)| match slot.state {
                State::Challenged { key: pending, .. } if pending == key => Some(index),
                _ => None,
            });
        let Some(index) = found else {
            return AnswerOutcome::Dropped(self.ignore(Ignored::NoChallenge));
        };
        let Some(slot) = self.slots.get(index).copied() else {
            return AnswerOutcome::Dropped(self.ignore(Ignored::NoChallenge));
        };
        let State::Challenged {
            identity,
            term,
            lane_count,
            nonce,
            created_at,
            answered,
            ..
        } = slot.state
        else {
            return AnswerOutcome::Dropped(self.ignore(Ignored::NoChallenge));
        };
        if answered {
            return AnswerOutcome::Dropped(self.ignore(Ignored::AlreadyAnswered));
        }
        if answer.identity != identity
            || answer.term != term
            || answer.joins.count() != lane_count
            || answer.challenge.receiver_boot_id != boot_id
            || answer.challenge.nonce != nonce
        {
            return AnswerOutcome::Dropped(self.ignore(Ignored::Mismatch));
        }
        if age_ns(now, created_at) >= timeout {
            return AnswerOutcome::Dropped(self.ignore(Ignored::Expired));
        }
        if !reserve() {
            return AnswerOutcome::Dropped(self.ignore(Ignored::NoCommandCredit));
        }
        let Some(slot_ref) = Self::slot_ref(index, &slot) else {
            return AnswerOutcome::Dropped(self.ignore(Ignored::TableFull));
        };
        if let Some(entry) = self.slots.get_mut(index)
            && let State::Challenged { answered, .. } = &mut entry.state
        {
            *answered = true;
        }
        AnswerOutcome::CreateImage {
            slot: slot_ref,
            identity,
            term,
            joins: answer.joins,
        }
    }

    /// The conductor's `ImageReady` for `slot` at `now`: installs the
    /// image if its challenge is still answered and within its timeout.
    pub fn image_ready(&mut self, slot: SlotRef, now: u64) -> ReadyOutcome {
        let timeout = self.config.setup_challenge_timeout;
        let Some(entry) = self.get_mut(slot) else {
            return ReadyOutcome::Release(slot);
        };
        let State::Challenged {
            key,
            identity,
            created_at,
            answered: true,
            ..
        } = entry.state
        else {
            return ReadyOutcome::Release(slot);
        };
        if age_ns(now, created_at) >= timeout {
            entry.state = State::Free;
            self.counters.bump(|c| &mut c.released);
            return ReadyOutcome::Release(slot);
        }
        // The slot's generation moves with every installed image; an
        // exhausted one is never reused.
        let Some(generation) = entry.generation.checked_add(1) else {
            entry.state = State::Exhausted;
            self.counters.bump(|c| &mut c.slots_exhausted);
            self.counters.bump(|c| &mut c.released);
            return ReadyOutcome::Release(slot);
        };
        entry.generation = generation;
        entry.state = State::Active { key, identity };
        self.counters.bump(|c| &mut c.installed);
        ReadyOutcome::Installed(SlotRef {
            slot: slot.slot,
            generation,
        })
    }

    /// The conductor's `ImageRefused`: the challenge goes, its token with
    /// it.
    pub fn image_refused(&mut self, slot: SlotRef) {
        if let Some(entry) = self.get_mut(slot)
            && matches!(entry.state, State::Challenged { answered: true, .. })
        {
            entry.state = State::Free;
            self.counters.bump(|c| &mut c.released);
        }
    }

    /// Retires an active image at `now`: the binding goes at once and the
    /// identity is quarantined. Returns `false` if `slot` is not active.
    pub fn retire(&mut self, slot: SlotRef, now: u64) -> bool {
        let Some(entry) = self.get_mut(slot) else {
            return false;
        };
        let State::Active { identity, .. } = entry.state else {
            return false;
        };
        entry.state = State::Retired {
            identity,
            retired_at: now,
            reclaimed: false,
        };
        self.counters.bump(|c| &mut c.retired);
        true
    }

    /// The conductor's `StorageReclaimed`: the tombstone may go once its
    /// quarantine has passed.
    pub fn storage_reclaimed(&mut self, slot: SlotRef) {
        if let Some(entry) = self.get_mut(slot)
            && let State::Retired { reclaimed, .. } = &mut entry.state
        {
            *reclaimed = true;
        }
    }
}

#[cfg(test)]
mod tests;
