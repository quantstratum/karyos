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
    Alias, ChallengeBlock, Identity, Lanes, RspChallenge, RspSolicit, SetupAnnounce, SetupAnswer,
    TermParams,
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

/// What the receiver does with DATA for an unbound key
/// (network-control-schemas.md §6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SolicitOutcome {
    /// Send this SOLICIT, once: the entry is never resent.
    Solicit(RspSolicit),
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
    /// DATA from a bound key: nothing to solicit.
    KeyBound,
    /// The key has a current challenge or solicit entry: DATA neither
    /// replaces it nor sends another SOLICIT.
    EntryPending,
    /// The key's solicit entry ended without a binding less than
    /// `solicit_holdoff` (`setup_challenge_timeout`) ago.
    SolicitHoldoff,
    /// The holdoff table is full of unexpired keys: no SOLICIT is sent
    /// whose end could not be held off.
    HoldoffFull,
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
    /// SOLICITs sent (an entry whose send was refused is withdrawn and
    /// not counted here).
    pub solicits: u64,
    /// Solicit entries freed by the timer after expiry.
    pub solicits_expired: u64,
    /// Solicited answers accepted (an image created or a path bound).
    pub solicits_answered: u64,
    /// Solicit entries withdrawn: never sent, or answered with no command
    /// chain; freed with no holdoff.
    pub solicits_withdrawn: u64,
    /// Announcements, answers and DATA-driven solicits dropped, all
    /// reasons; DATA for a bound key or a key with an entry counts once
    /// per datagram.
    pub dropped: u64,
    /// Images installed.
    pub installed: u64,
    /// Later paths bound to installed images (RP-1).
    pub paths_bound: u64,
    /// Installed images whose first path could not be bound: a broken
    /// invariant (the path table has a row per slot).
    pub path_bind_failed: u64,
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
        /// It was a solicit entry (§6.3): a refusal at `ImageReady` ends it
        /// without a binding and starts the holdoff.
        solicited: bool,
    },
    /// A pending solicit (§6.3): DATA for an unbound key, no candidate
    /// identity. Its answer supplies identity, term parameters and lanes
    /// and, accepted, makes it an answered challenge.
    Solicited {
        key: BindingKey,
        nonce: [u64; 2],
        created_at: u64,
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
    /// Keys whose solicit entry ended without a binding, and until when no
    /// new SOLICIT goes out for them (`solicit_holdoff`, §7.4): at most
    /// `max_pending_challenges` (allocated at creation).
    holdoffs: Vec<(BindingKey, u64)>,
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
            holdoffs: Vec::with_capacity(config.max_pending_challenges),
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
        self.slots.iter().enumerate().find_map(|(index, slot)| {
            self.bound_here(index, slot, key)
                .then(|| Self::slot_ref(index, slot))
                .flatten()
        })
    }

    /// Whether `key` is a live path of the active image in `slot` (the
    /// path rows are the truth for admission, redundant-paths.md section
    /// 3): a first path lost at its liveness timeout is no longer bound
    /// and returns only through a fresh challenge, as a later path. An
    /// image with no row (its first binding failed, counted) keeps its
    /// installing key.
    fn bound_here(&self, index: usize, slot: &Slot, key: &BindingKey) -> bool {
        let State::Active { key: founding, .. } = slot.state else {
            return false;
        };
        let Some(image) = Self::slot_ref(index, slot) else {
            return false;
        };
        if self.paths.image(image).is_none() {
            return founding == *key;
        }
        self.paths
            .lookup(*key)
            .is_some_and(|(bound, _)| bound == image)
    }

    /// The binding key and identity of the active image at `slot`: where
    /// its SMs go and what they report.
    #[must_use]
    pub fn binding(&self, slot: SlotRef) -> Option<(BindingKey, Identity)> {
        match self.get(slot)?.state {
            State::Active { key, identity } => Some((key, identity)),
            _ => None,
        }
    }

    /// This receiver's boot id, the boot id of its SMs' receiver block.
    #[must_use]
    pub fn boot_id(&self) -> [u64; 2] {
        self.boot_id
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
        self.slots
            .iter()
            .enumerate()
            .any(|(index, slot)| match slot.state {
                State::Active { identity: held, .. } => {
                    held == *identity && !self.bound_here(index, slot, key)
                }
                State::Challenged {
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
                State::Active { identity: held, .. }
                    if held == *identity && !self.bound_here(index, slot, key) =>
                {
                    Self::slot_ref(index, slot)
                }
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
                State::Challenged { key, .. } | State::Solicited { key, .. } => {
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
        for index in 0..self.slots.len() {
            if freed >= limit {
                break;
            }
            let Some(slot) = self.slots.get(index).copied() else {
                break;
            };
            let free = match slot.state {
                State::Solicited {
                    key, created_at, ..
                } => {
                    let expired = age_ns(now, created_at) >= timeout;
                    if expired {
                        self.counters.bump(|c| &mut c.solicits_expired);
                        self.hold_off(key, now);
                    }
                    expired
                }
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
                if let Some(slot) = self.slots.get_mut(index) {
                    slot.state = State::Free;
                }
                // Bounded by `limit`, a u32: it cannot overflow.
                freed = freed.checked_add(1).unwrap_or(freed);
            }
        }
        freed
    }

    /// Starts `key`'s solicit holdoff at `now`: its row is renewed, or an
    /// expired row reused, or a row added below capacity. A full table of
    /// unexpired rows records nothing; [`ReceiveSessions::solicit`] then
    /// refuses new SOLICITs until a row expires.
    fn hold_off(&mut self, key: BindingKey, now: u64) {
        let holdoff = self.config.setup_challenge_timeout;
        let row = self
            .holdoffs
            .iter()
            .position(|(held, _)| *held == key)
            .or_else(|| {
                self.holdoffs
                    .iter()
                    .position(|(_, since)| age_ns(now, *since) >= holdoff)
            });
        let below = self.holdoffs.len() < self.config.max_pending_challenges;
        match row.and_then(|row| self.holdoffs.get_mut(row)) {
            Some(entry) => *entry = (key, now),
            None if below => self.holdoffs.push((key, now)),
            None => {}
        }
    }

    /// Whether `key` is held off at `now`, and whether the holdoff table
    /// has no row free for another key.
    fn held_off(&self, key: &BindingKey, now: u64) -> (bool, bool) {
        let holdoff = self.config.setup_challenge_timeout;
        let held = self
            .holdoffs
            .iter()
            .any(|(held, since)| held == key && age_ns(now, *since) < holdoff);
        let full = self.holdoffs.len() >= self.config.max_pending_challenges
            && self
                .holdoffs
                .iter()
                .all(|(_, since)| age_ns(now, *since) < holdoff);
        (held, full)
    }

    /// The SOLICIT of a new entry was handed to the sender: counted in
    /// `solicits`, which counts only SOLICITs sent.
    pub fn solicit_sent(&mut self) {
        self.counters.bump(|c| &mut c.solicits);
    }

    /// Frees `key`'s solicit entry with no holdoff: its SOLICIT was never
    /// sent (an RSP_SETUP limit or the control ring refused it), and it is
    /// never resent.
    pub fn withdraw_solicit(&mut self, key: &BindingKey) {
        let found = self
            .slots
            .iter_mut()
            .find(|slot| matches!(slot.state, State::Solicited { key: held, .. } if held == *key));
        if let Some(slot) = found {
            slot.state = State::Free;
            self.counters.bump(|c| &mut c.solicits_withdrawn);
        }
    }

    /// DATA, PAD, ABORTED or a heartbeat from `key`, a key with no binding,
    /// on a subscribed stream, at `now` (network-control-schemas.md §6.3):
    /// a solicit entry and one SOLICIT, unless the key is bound, has a
    /// current challenge or solicit entry, or is held off, or the pending
    /// limits of challenges are reached. A SOLICIT is never resent; DATA
    /// never replaces a current entry.
    pub fn solicit(
        &mut self,
        key: BindingKey,
        now: u64,
        nonces: &mut impl NonceSource,
    ) -> SolicitOutcome {
        if self.lookup(&key).is_some() || self.paths.lookup(key).is_some() {
            return SolicitOutcome::Dropped(self.ignore(Ignored::KeyBound));
        }
        let pending = self.slots.iter().any(|slot| {
            matches!(slot.state,
                State::Challenged { key: held, .. } | State::Solicited { key: held, .. }
                    if held == key)
        });
        if pending {
            return SolicitOutcome::Dropped(self.ignore(Ignored::EntryPending));
        }
        match self.held_off(&key, now) {
            (true, _) => return SolicitOutcome::Dropped(self.ignore(Ignored::SolicitHoldoff)),
            (false, true) => return SolicitOutcome::Dropped(self.ignore(Ignored::HoldoffFull)),
            (false, false) => {}
        }
        // DATA comes at line rate: no sweep here, whose scan is not bounded
        // by what it frees. The timer duty frees expired entries.
        if self.pending(None) >= self.config.max_pending_challenges
            || self.pending(Some(key.source)) >= self.config.max_pending_per_source
        {
            return SolicitOutcome::Dropped(self.ignore(Ignored::ChallengeCapacity));
        }
        let Some(index) = self.slots.iter().position(|slot| slot.state == State::Free) else {
            return SolicitOutcome::Dropped(self.ignore(Ignored::TableFull));
        };
        let Some(nonce) = nonces.nonce() else {
            return SolicitOutcome::Dropped(self.ignore(Ignored::NoNonce));
        };
        if let Some(slot) = self.slots.get_mut(index) {
            slot.state = State::Solicited {
                key,
                nonce,
                created_at: now,
            };
        }
        SolicitOutcome::Solicit(RspSolicit {
            alias: key.alias,
            challenge: ChallengeBlock {
                receiver_boot_id: self.boot_id,
                nonce,
            },
        })
    }

    /// Timer duty, up to the configured `timer_actions` in all: frees
    /// expired entries, then removes path bindings with no fresh evidence
    /// for `path_liveness_timeout` (RP-2; an image keeps its other paths,
    /// and with none left its own liveness decides). Returns how many
    /// actions were taken.
    pub fn timers(&mut self, now: u64) -> u32 {
        self.timers_with(now, |_, _, _| {})
    }

    /// [`ReceiveSessions::timers`], reporting each lost path binding to
    /// `lost` (image, path, key), for its owner's path statistics.
    pub fn timers_with(
        &mut self,
        now: u64,
        lost: impl FnMut(SlotRef, usize, super::paths::PathKey),
    ) -> u32 {
        let budget = self.config.timer_actions;
        let freed = self.sweep(now, budget);
        // The sweep frees at most `budget`; whatever is left goes to the
        // paths.
        let lost = match budget.checked_sub(freed) {
            Some(left) if left > 0 => self.paths.timers(now, left, lost),
            _ => 0,
        };
        freed.checked_add(lost).unwrap_or(budget)
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
        let existing = self
            .slots
            .iter()
            .enumerate()
            .position(|(index, slot)| match slot.state {
                State::Active { .. } => self.bound_here(index, slot, &key),
                State::Challenged { key: bound, .. } | State::Solicited { key: bound, .. } => {
                    bound == key
                }
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
                            solicited: false,
                        };
                    }
                    self.counters.bump(|c| &mut c.challenges_replaced);
                    return AnnounceOutcome::Challenge(self.challenge(
                        key,
                        announce.identity,
                        fresh,
                    ));
                }
                // An announcement names the identity a solicit lacks: it
                // replaces the entry, whose nonce stops matching.
                State::Solicited { .. } => {
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
                            solicited: false,
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
                solicited: false,
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
                State::Challenged { key: pending, .. } | State::Solicited { key: pending, .. }
                    if pending == key =>
                {
                    Some(index)
                }
                _ => None,
            });
        let Some(index) = found else {
            return AnswerOutcome::Dropped(self.ignore(Ignored::NoChallenge));
        };
        let Some(slot) = self.slots.get(index).copied() else {
            return AnswerOutcome::Dropped(self.ignore(Ignored::NoChallenge));
        };
        if let State::Solicited {
            nonce, created_at, ..
        } = slot.state
        {
            return self.answer_solicited(
                index,
                &slot,
                key,
                answer,
                (nonce, created_at),
                now,
                reserve,
            );
        }
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

    /// The answer to a solicit entry (§6.3 step 3): its challenge block
    /// must match before expiry; identity, term parameters and lanes come
    /// from the answer. A quarantined or duplicate identity consumes the
    /// entry, binds nothing and starts the holdoff. An identity active
    /// under another key binds a later path of that image (RP-1), as a
    /// challenged later path does; otherwise the entry becomes an answered
    /// challenge and the image is created as for an announcement.
    #[expect(
        clippy::too_many_arguments,
        reason = "the entry's index, copy, key and challenge state, kept together on one cold path"
    )]
    fn answer_solicited(
        &mut self,
        index: usize,
        slot: &Slot,
        key: BindingKey,
        answer: &SetupAnswer,
        (nonce, created_at): ([u64; 2], u64),
        now: u64,
        reserve: impl FnOnce() -> bool,
    ) -> AnswerOutcome {
        // The caller builds the key from the answer's alias.
        debug_assert_eq!(answer.alias, key.alias);
        if answer.challenge.receiver_boot_id != self.boot_id || answer.challenge.nonce != nonce {
            return AnswerOutcome::Dropped(self.ignore(Ignored::Mismatch));
        }
        if age_ns(now, created_at) >= self.config.setup_challenge_timeout {
            return AnswerOutcome::Dropped(self.ignore(Ignored::Expired));
        }
        let identity = answer.identity;
        let consumed = |table: &mut Self, reason| {
            if let Some(entry) = table.slots.get_mut(index) {
                entry.state = State::Free;
            }
            table.hold_off(key, now);
            AnswerOutcome::Dropped(table.ignore(reason))
        };
        if self.quarantined(&identity, now) {
            return consumed(self, Ignored::Quarantined);
        }
        if self.pending_elsewhere(&identity, &key) {
            return consumed(self, Ignored::DuplicateIdentity);
        }
        if let Some(image) = self.active_elsewhere(&identity, &key) {
            let same = self.get(image).is_some_and(
                |held| matches!(held.state, State::Active { key: held, .. } if held.alias == key.alias),
            ) && self.paths.image(image).is_some_and(|(held, term, lanes, _)| {
                held == identity && term == answer.term && lanes == answer.joins.count()
            });
            if !same {
                return consumed(self, Ignored::DuplicateIdentity);
            }
            let outcome = self.answer_path(index, image, key, answer, now);
            match outcome {
                AnswerOutcome::PathBound { .. } => {
                    self.counters.bump(|c| &mut c.solicits_answered);
                }
                _ => self.hold_off(key, now),
            }
            return outcome;
        }
        if !reserve() {
            // The publisher answers a SOLICIT once: keeping the entry would
            // wait for its expiry and a holdoff. It goes, with no holdoff,
            // and the next DATA asks again under the limits.
            if let Some(entry) = self.slots.get_mut(index) {
                entry.state = State::Free;
            }
            self.counters.bump(|c| &mut c.solicits_withdrawn);
            return AnswerOutcome::Dropped(self.ignore(Ignored::NoCommandCredit));
        }
        let Some(slot_ref) = Self::slot_ref(index, slot) else {
            return AnswerOutcome::Dropped(self.ignore(Ignored::TableFull));
        };
        if let Some(entry) = self.slots.get_mut(index) {
            entry.state = State::Challenged {
                key,
                identity,
                term: answer.term,
                lane_count: answer.joins.count(),
                nonce,
                created_at,
                last_sent: created_at,
                answered: true,
                path_of: None,
                joins: Some(answer.joins),
                solicited: true,
            };
        }
        self.counters.bump(|c| &mut c.solicits_answered);
        AnswerOutcome::CreateImage {
            slot: slot_ref,
            identity,
            term: answer.term,
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
            solicited,
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
            // A solicit entry ended without a binding.
            if solicited {
                self.hold_off(key, now);
            }
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
        // generation. Without a row (a slot beyond the path table, or no
        // recorded joins: a broken invariant, counted) the image is still
        // installed and its own liveness is unchanged, but it has no live
        // path binding, so no later path can join it.
        let bound = joins.is_some_and(|joins| {
            self.paths
                .bind_first(installed, identity, term, key, joins, now)
                .is_ok()
        });
        if !bound {
            self.counters.bump(|c| &mut c.path_bind_failed);
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
