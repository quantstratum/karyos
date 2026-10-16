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
//! - **One owner per identity.** An identity challenged or answered under
//!   one key is refused under any other. An identity active under one key
//!   may gain a later path under another (`quantstratum-docs:
//!   karyos/design/redundant-paths.md`, RP-1): with the image's term
//!   parameters and lane count and a free path, the announcement gets a
//!   path challenge, whose answer binds the path in [`super::paths`]
//!   ([`AnswerOutcome::PathBound`]) and creates no image; otherwise it is
//!   refused. The quarantine and this uniqueness are checked at the
//!   announcement and again at the answer and at `ImageReady`, so a
//!   challenge created before a retirement or before another key bound the
//!   identity never installs it.
//! - **Retirement.** The binding goes at once; the full identity stays
//!   quarantined for `alias_quarantine`, and the slot stays charged until
//!   both the quarantine has passed and the conductor reclaimed the
//!   storage. An unexpired tombstone is never evicted.
//!
//! Every deadline is an elapsed time from `host_clock::age_ns`, never an
//! addition. Counters are checked and sticky on overflow.

use std::net::SocketAddr;

use karyos_protocol::network::{
    Alias, ChallengeBlock, Identity, Lanes, RspChallenge, SetupAnnounce, SetupAnswer, TermParams,
};
use karyos_sys::host_clock::age_ns;

use super::NonceSource;
use super::paths::{PathBindings, PathBindingsConfig};
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
    /// The least time between two sends of one challenge, in ns
    /// (`challenge_resend_interval`, network-control-schemas.md §7.4,
    /// default 50 ms).
    pub challenge_resend_interval: u64,
    /// Paths of one image (`max_paths`, redundant-paths.md section 5,
    /// default 4), 1 to `super::paths::MAX_PATHS`.
    pub max_paths: u8,
    /// A path with no fresh evidence for this long is lost, in ns
    /// (`path_liveness_timeout`, RP-2; provisional default 10 s, the image
    /// liveness timeout).
    pub path_liveness_timeout: u64,
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
            challenge_resend_interval: 50_000_000,
            max_paths: 4,
            path_liveness_timeout: 10_000_000_000,
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
        if self.setup_challenge_timeout == 0
            || self.alias_quarantine == 0
            || self.path_liveness_timeout == 0
        {
            return Err(SessionConfigError("a timeout is zero"));
        }
        if self.max_paths == 0 || self.max_paths > super::paths::MAX_PATHS {
            return Err(SessionConfigError("max_paths is not in 1..=MAX_PATHS"));
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
    /// Accepted as a later path of the active image (RP-1): bound, no
    /// image created.
    PathBound {
        /// The image's installed slot.
        image: SlotRef,
        /// The path's index in its bindings.
        path: usize,
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
    /// The identity is challenged or answered under another key, or active
    /// under another key with other term parameters or lane count: a second
    /// writer, or a path that does not match its image (one receive owner
    /// per image, ADR-0018).
    DuplicateIdentity,
    /// The identity is active under another key and its image has
    /// `max_paths` paths.
    PathsFull,
    /// A later path's answer was refused by the path bindings (RP-1).
    PathRefused,
    /// The control's alias differs from the key's.
    AliasMismatch,
    /// The challenge was sent less than `challenge_resend_interval` ago.
    ResendHoldoff,
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
    /// Later paths bound to installed images (RP-1).
    pub paths_bound: u64,
    /// Images released at `ImageReady` (too late) or refused.
    pub released: u64,
    /// Images retired.
    pub retired: u64,
    /// Slots retired for good because their generation is exhausted.
    pub slots_exhausted: u64,
    /// Conductor replies naming a slot at another generation or state,
    /// ignored.
    pub stale_commands: u64,
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
        /// When this challenge was last handed out for sending.
        last_sent: u64,
        answered: bool,
        /// A later path's challenge: the image it would add a path to.
        path_of: Option<SlotRef>,
        /// The answer's join points, kept for the first path's binding.
        joins: Option<Lanes<u64>>,
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
    /// The images' path bindings (redundant-paths.md sections 2 and 3).
    paths: PathBindings,
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
        let paths = PathBindings::new(PathBindingsConfig {
            max_images: u32::try_from(config.max_images)
                .map_err(|_| SessionConfigError("max_images above u32"))?,
            max_paths: config.max_paths,
            path_liveness_timeout: config.path_liveness_timeout,
        })
        .map_err(|_| SessionConfigError("a capacity or budget is zero"))?;
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
            paths,
        })
    }

    /// The images' path bindings: the receive owner refreshes a binding on
    /// fresh evidence, PATH_HB intake on its datagram, and the timer duty
    /// removes lost ones (`crate::paths::stats` says what is fresh).
    #[must_use]
    pub fn paths(&self) -> &PathBindings {
        &self.paths
    }

    /// The images' path bindings, for refresh, PATH_HB and timers.
    pub fn paths_mut(&mut self) -> &mut PathBindings {
        &mut self.paths
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

    /// Whether `identity` is active, challenged or answered under a key
    /// other than `key`.
    fn elsewhere(&self, identity: &Identity, key: &BindingKey) -> bool {
        self.slots.iter().any(|slot| match slot.state {
            State::Active {
                key: other,
                identity: held,
            }
            | State::Challenged {
                key: other,
                identity: held,
                ..
            } => held == *identity && other != *key,
            _ => false,
        })
    }

    /// The installed image of `identity` under a key other than `key`.
    fn active_elsewhere(&self, identity: &Identity, key: &BindingKey) -> Option<SlotRef> {
        self.slots
            .iter()
            .enumerate()
            .find_map(|(index, slot)| match slot.state {
                State::Active {
                    key: other,
                    identity: held,
                } if held == *identity && other != *key => Self::slot_ref(index, slot),
                _ => None,
            })
    }

    /// Whether `identity` is challenged or answered under a key other than
    /// `key`: refused, one challenge at a time.
    fn pending_elsewhere(&self, identity: &Identity, key: &BindingKey) -> bool {
        self.slots.iter().any(|slot| match slot.state {
            State::Challenged {
                key: other,
                identity: held,
                ..
            } => held == *identity && other != *key,
            _ => false,
        })
    }

    /// What an announcement of `identity` from `key` may become while the
    /// identity is held under another key (RP-1): nothing held, a later
    /// path of the active image with its term parameters and lane count
    /// and a free path, or a refusal.
    fn path_target(
        &self,
        key: &BindingKey,
        announce: &SetupAnnounce,
    ) -> Result<Option<SlotRef>, Ignored> {
        let identity = &announce.identity;
        if self.pending_elsewhere(identity, key) {
            return Err(Ignored::DuplicateIdentity);
        }
        let Some(image) = self.active_elsewhere(identity, key) else {
            return Ok(None);
        };
        // Every path carries the same session and stream (redundant-paths.md
        // section 1): another alias for the identity is another writer.
        let same_alias = self.get(image).is_some_and(
            |slot| matches!(slot.state, State::Active { key: held, .. } if held.alias == key.alias),
        );
        if !same_alias {
            return Err(Ignored::DuplicateIdentity);
        }
        match self.paths.image(image) {
            Some((held, term, lanes, free))
                if held == *identity && term == announce.term && lanes == announce.lane_count =>
            {
                if free {
                    Ok(Some(image))
                } else {
                    Err(Ignored::PathsFull)
                }
            }
            _ => Err(Ignored::DuplicateIdentity),
        }
    }

    fn pending(&self, source: Option<SocketAddr>) -> usize {
        self.slots
            .iter()
            .filter(|slot| match slot.state {
                State::Challenged { key, .. } => {
                    source.is_none_or(|source| source_ip(key.source) == source_ip(source))
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
        if announce.alias != key.alias {
            return AnnounceOutcome::Dropped(self.ignore(Ignored::AliasMismatch));
        }
        if self.quarantined(&announce.identity, now) {
            return AnnounceOutcome::Dropped(self.ignore(Ignored::Quarantined));
        }
        // A key bound as a later path is bound: a replayed or late SETUP.
        if let Some((image, _)) = self.paths.lookup(key) {
            let same = self
                .paths
                .image(image)
                .is_some_and(|(held, ..)| held == announce.identity);
            let reason = if same {
                Ignored::BoundSameIdentity
            } else {
                Ignored::BoundOtherIdentity
            };
            return AnnounceOutcome::Dropped(self.ignore(reason));
        }
        let path_of = match self.path_target(&key, announce) {
            Ok(path_of) => path_of,
            Err(reason) => return AnnounceOutcome::Dropped(self.ignore(reason)),
        };
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
                    last_sent,
                    answered,
                    ..
                } => {
                    let identical = identity == announce.identity
                        && term == announce.term
                        && lane_count == announce.lane_count;
                    if identical && (answered || age_ns(now, created_at) < timeout) {
                        // At most one resend per `challenge_resend_interval`
                        // (§7.4): a burst of identical announcements does
                        // not multiply the challenges.
                        if age_ns(now, last_sent) < self.config.challenge_resend_interval {
                            return AnnounceOutcome::Dropped(self.ignore(Ignored::ResendHoldoff));
                        }
                        if let Some(entry) = self.slots.get_mut(index)
                            && let State::Challenged { last_sent, .. } = &mut entry.state
                        {
                            *last_sent = now;
                        }
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
                            last_sent: now,
                            answered: false,
                            path_of,
                            joins: None,
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
                last_sent: now,
                answered: false,
                path_of,
                joins: None,
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
            path_of,
            ..
        } = slot.state
        else {
            return AnswerOutcome::Dropped(self.ignore(Ignored::NoChallenge));
        };
        if answered {
            return AnswerOutcome::Dropped(self.ignore(Ignored::AlreadyAnswered));
        }
        if answer.alias != key.alias {
            return AnswerOutcome::Dropped(self.ignore(Ignored::AliasMismatch));
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
        // Rechecked here: the identity may have been retired, or bound under
        // another key, since its announcement was challenged.
        if self.quarantined(&identity, now) {
            return AnswerOutcome::Dropped(self.ignore(Ignored::Quarantined));
        }
        if let Some(image) = path_of {
            return self.answer_path(index, image, key, answer, now);
        }
        if self.elsewhere(&identity, &key) {
            return AnswerOutcome::Dropped(self.ignore(Ignored::DuplicateIdentity));
        }
        if !reserve() {
            return AnswerOutcome::Dropped(self.ignore(Ignored::NoCommandCredit));
        }
        let Some(slot_ref) = Self::slot_ref(index, &slot) else {
            return AnswerOutcome::Dropped(self.ignore(Ignored::TableFull));
        };
        if let Some(entry) = self.slots.get_mut(index)
            && let State::Challenged {
                answered, joins, ..
            } = &mut entry.state
        {
            *answered = true;
            *joins = Some(answer.joins);
        }
        AnswerOutcome::CreateImage {
            slot: slot_ref,
            identity,
            term,
            joins: answer.joins,
        }
    }

    /// A later path's checked answer (RP-1): the image must still be
    /// active under another key; the path is bound with its joins recorded,
    /// never applied, and no image is created, so no conductor chain is
    /// reserved. The challenge is consumed either way.
    fn answer_path(
        &mut self,
        index: usize,
        image: SlotRef,
        key: BindingKey,
        answer: &SetupAnswer,
        now: u64,
    ) -> AnswerOutcome {
        if self.active_elsewhere(&answer.identity, &key) != Some(image) {
            if let Some(entry) = self.slots.get_mut(index) {
                entry.state = State::Free;
            }
            return AnswerOutcome::Dropped(self.ignore(Ignored::DuplicateIdentity));
        }
        let bound =
            self.paths
                .offer_later(image, key, answer.identity, answer.term, answer.joins, now);
        if let Some(entry) = self.slots.get_mut(index) {
            entry.state = State::Free;
        }
        match bound {
            Ok(path) => {
                self.counters.bump(|c| &mut c.paths_bound);
                AnswerOutcome::PathBound { image, path }
            }
            Err(_) => AnswerOutcome::Dropped(self.ignore(Ignored::PathRefused)),
        }
    }

    /// The conductor's `ImageReady` for `slot` at `now`: installs the
    /// image if its challenge is still answered, within its timeout, its
    /// identity not quarantined and not bound under another key.
    ///
    /// `slot` carries the challenge's generation, as `CreateImage` did; on
    /// installation the generation moves, and [`ReadyOutcome::Installed`]
    /// carries the new one, which `ImageInstalled`, `RetireImage` and
    /// `StorageReclaimed` must carry from then on.
    pub fn image_ready(&mut self, slot: SlotRef, now: u64) -> ReadyOutcome {
        let timeout = self.config.setup_challenge_timeout;
        let Some(entry) = self.get(slot).copied() else {
            self.counters.bump(|c| &mut c.stale_commands);
            return ReadyOutcome::Release(slot);
        };
        let State::Challenged {
            key,
            identity,
            term,
            created_at,
            answered: true,
            joins,
            ..
        } = entry.state
        else {
            self.counters.bump(|c| &mut c.stale_commands);
            return ReadyOutcome::Release(slot);
        };
        let refused = age_ns(now, created_at) >= timeout
            || self.quarantined(&identity, now)
            || self.elsewhere(&identity, &key);
        let Some(entry) = self.get_mut(slot) else {
            return ReadyOutcome::Release(slot);
        };
        if refused {
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
        let installed = SlotRef {
            slot: slot.slot,
            generation,
        };
        // The first path, at the image's own joins, keyed by the installed
        // generation.
        if let Some(joins) = joins {
            let _ = self
                .paths
                .bind_first(installed, identity, term, key, joins, now);
        }
        ReadyOutcome::Installed(installed)
    }

    /// The conductor's `ImageRefused`: the challenge goes, its token with
    /// it.
    pub fn image_refused(&mut self, slot: SlotRef) {
        if let Some(entry) = self.get_mut(slot)
            && matches!(entry.state, State::Challenged { answered: true, .. })
        {
            entry.state = State::Free;
            self.counters.bump(|c| &mut c.released);
        } else {
            self.counters.bump(|c| &mut c.stale_commands);
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
        self.paths.image_retired(slot);
        true
    }

    /// The conductor's `StorageReclaimed` for the installed generation of
    /// `slot`: the tombstone may go once its quarantine has passed. A
    /// reply for another generation is ignored and counted
    /// (`stale_commands`).
    pub fn storage_reclaimed(&mut self, slot: SlotRef) {
        if let Some(entry) = self.get_mut(slot)
            && let State::Retired { reclaimed, .. } = &mut entry.state
        {
            *reclaimed = true;
        } else {
            self.counters.bump(|c| &mut c.stale_commands);
        }
    }
}

/// The address a source counts under: an IPv4-mapped IPv6 address is the
/// IPv4 address, so one host cannot double its per-source budget.
fn source_ip(source: SocketAddr) -> std::net::IpAddr {
    super::rate::normalized(source).ip()
}

#[cfg(test)]
mod tests;
