// SPDX-License-Identifier: Apache-2.0

//! A guard owned by another driver, as one receiving driver follows it
//! (`quantstratum-docs:
//! karyos/adr/0086-wire-authentication-profile-v1.md` section 7,
//! `karyos/adr/0107-guard-recovery-and-renewal-on-the-wire.md` and
//! `karyos/design/authenticated-control-schemas.md` section 4; part of
//! quantstratum/karyos#648).
//!
//! A [`RemoteGuard`] starts closed and in recovery. Recovery and every
//! grant or extension of an `Open` are an accepted signed STATUS answering
//! the receiver's own unexpired, unconsumed nonce for its current boot id.
//! On it the floor becomes the STATUS epoch, persisted in [`GuardMarks`]
//! before anything opens; a STATUS below the durable mark latches the
//! guard closed for good. After recovery a `Closed` STATE above the floor
//! raises the floor and closes at once; an `Open` STATE above it raises
//! the floor and only starts a confirmation round. An `Open` lapses one
//! lifetime after its last confirmation. The verified datagrams come from
//! [`crate::signed_control::SignedIntake`]; this module is its epoch check
//! and state change. Nothing here allocates after construction.

use karyos_protocol::network::Receiver;
use karyos_protocol::network::authenticated::{GuardState, GuardStatus, StatusChallenge};

use crate::sessions::NonceSource;
use crate::wire_keys::store::{FileError, Files};

/// How long a challenge nonce lives (`setup_challenge_timeout`).
pub const CHALLENGE_TIMEOUT_NS: u64 = 1_000_000_000;
/// The lifetime of an `Open` recovery applies (`guard_lifetime_ms`).
pub const DEFAULT_LIFETIME_NS: u64 = 5_000_000_000;

/// The durable guard epoch marks: one small file per guard, replaced
/// atomically and durably, only ever raised.
pub trait MarkStore: core::fmt::Debug {
    /// The durable mark of `guard_id`: 0 when none was ever stored.
    ///
    /// # Errors
    ///
    /// [`MarkError`] when it exists and cannot be read; the guard then
    /// stays closed.
    fn load(&self, guard_id: u64) -> Result<u64, MarkError>;
    /// Persists `epoch` as `guard_id`'s mark before it is acted on.
    ///
    /// # Errors
    ///
    /// [`MarkError`] when the commit fails; nothing may then open.
    fn persist(&mut self, guard_id: u64, epoch: u64) -> Result<(), MarkError>;
}

/// Why a mark cannot be read or stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkError {
    /// The file is refused or does not parse.
    Unreadable,
    /// The commit failed.
    Commit,
}

const MARK_FORMAT: &str = "karyos-guard-mark-v1";

/// [`MarkStore`] over a state directory ([`Files`]: on Linux a
/// `karyos_sys::secure_dir::SecureDir`), with the commit discipline of
/// the key state: an atomic, durable replace.
pub struct GuardMarks<F: Files> {
    files: F,
}

impl<F: Files> core::fmt::Debug for GuardMarks<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GuardMarks").finish_non_exhaustive()
    }
}

impl<F: Files> GuardMarks<F> {
    /// The marks of `files`.
    pub fn new(files: F) -> Self {
        Self { files }
    }

    fn name(guard_id: u64) -> String {
        format!("guard-{guard_id}")
    }
}

impl<F: Files> MarkStore for GuardMarks<F> {
    fn load(&self, guard_id: u64) -> Result<u64, MarkError> {
        let mut buf = [0u8; 64];
        let len = match self.files.read(&Self::name(guard_id), &mut buf) {
            Ok(len) => len,
            Err(FileError::NotFound) => return Ok(0),
            Err(FileError::Refused) => return Err(MarkError::Unreadable),
        };
        let text = buf
            .get(..len)
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
            .ok_or(MarkError::Unreadable)?;
        let mut lines = text.split('\n');
        if lines.next() != Some(MARK_FORMAT) {
            return Err(MarkError::Unreadable);
        }
        let epoch = lines
            .next()
            .and_then(|line| line.strip_prefix("epoch="))
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(MarkError::Unreadable)?;
        if lines.next() != Some("") || lines.next().is_some() {
            return Err(MarkError::Unreadable);
        }
        Ok(epoch)
    }

    fn persist(&mut self, guard_id: u64, epoch: u64) -> Result<(), MarkError> {
        // Only ever raised: a lower mark is never written.
        if self.load(guard_id).is_ok_and(|held| held >= epoch) {
            return Ok(());
        }
        let text = format!("{MARK_FORMAT}\nepoch={epoch}\n");
        self.files
            .write_atomic(&Self::name(guard_id), text.as_bytes())
            .map_err(|_| MarkError::Commit)
    }
}

/// Where a followed guard is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Closed, waiting for a STATUS (the start).
    Recovering,
    /// Recovered and closed.
    Closed,
    /// Recovered and open at `epoch` until `until` (monotonic ns).
    Open {
        /// The open epoch.
        epoch: u64,
        /// When it lapses without a confirmation.
        until: u64,
    },
    /// A STATUS below the durable mark was seen: closed for good under this
    /// `guard_id` (design section 4.4, step 3).
    Latched,
}

/// Why a STATUS or STATE changed nothing; one counter each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum GuardRefusal {
    /// No round is outstanding, or the nonce was never drawn.
    UnknownNonce = 0,
    /// The nonce expired, or was consumed or replaced.
    StaleNonce,
    /// Another receiver's boot id or id.
    WrongReceiver,
    /// Another guard or authority.
    WrongGuard,
    /// A STATE during recovery: discarded, the floor unchanged.
    Recovering,
    /// At or below the floor.
    Stale,
    /// Latched closed.
    Latched,
    /// The mark could not be persisted: nothing opens.
    Persist,
}

/// Refusal reasons.
pub const GUARD_REFUSALS: usize = GuardRefusal::Persist as usize + 1;

/// What an accepted STATUS or STATE did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardChange {
    /// Recovery completed, or a transition applied; the new phase.
    Applied(Phase),
    /// An `Open` STATE above the floor: the floor rose, and a confirmation
    /// round must start; nothing opened.
    ConfirmationDue,
}

/// One followed guard.
#[derive(Debug)]
pub struct RemoteGuard {
    authority_id: u64,
    guard_id: u64,
    floor: u64,
    phase: Phase,
    /// The outstanding round: its nonce and when it was drawn.
    round: Option<([u64; 2], u64)>,
    /// The last nonce consumed or replaced, for its own reason.
    retired: Option<[u64; 2]>,
    /// The lifetime of the `Open` STATE awaiting confirmation, by epoch.
    pending: Option<(u64, u64)>,
    lifetime_ns: u64,
    refusals: [u64; GUARD_REFUSALS],
}

impl RemoteGuard {
    /// A guard of `authority_id` starting closed and recovering, its floor
    /// the durable mark `mark`.
    #[must_use]
    pub fn new(authority_id: u64, guard_id: u64, mark: u64) -> Self {
        Self {
            authority_id,
            guard_id,
            floor: mark,
            phase: Phase::Recovering,
            round: None,
            retired: None,
            pending: None,
            lifetime_ns: DEFAULT_LIFETIME_NS,
            refusals: [0; GUARD_REFUSALS],
        }
    }

    /// The guard, its marks read from `marks`: unreadable marks leave it
    /// latched closed (fail closed).
    pub fn load(authority_id: u64, guard_id: u64, marks: &dyn MarkStore) -> Self {
        match marks.load(guard_id) {
            Ok(mark) => Self::new(authority_id, guard_id, mark),
            Err(_) => Self {
                phase: Phase::Latched,
                ..Self::new(authority_id, guard_id, u64::MAX)
            },
        }
    }

    /// The guard id.
    #[must_use]
    pub fn guard_id(&self) -> u64 {
        self.guard_id
    }

    /// The floor.
    #[must_use]
    pub fn floor(&self) -> u64 {
        self.floor
    }

    /// The phase at `now`, an `Open` past its lifetime closed.
    #[must_use]
    pub fn phase(&self, now: u64) -> Phase {
        match self.phase {
            Phase::Open { until, .. } if now >= until => Phase::Closed,
            phase => phase,
        }
    }

    /// The guard word a local sender gate reads for this guard at `now`
    /// (`karyos_sys::guard` encoding): `(epoch, Open)` only while open and
    /// confirmed; otherwise a closed word at the floor, or just above an
    /// open floor that lapsed or awaits confirmation, so no gate admits.
    /// A publication it guards is admitted only once this word first
    /// reads `(e, Open)` ([`crate::agents::data::Outbound::guard_remote`]);
    /// its gate then aborts the incarnation for good on any other word,
    /// as for a local guard (guards-and-abort.md, "The sender gate and
    /// applied epoch", step 3).
    #[must_use]
    pub fn word(&self, now: u64) -> u64 {
        let closed = |epoch: u64| {
            let epoch = epoch.max(1);
            let epoch = if epoch.is_multiple_of(2) {
                epoch.saturating_add(1).min(karyos_sys::guard::MAX_EPOCH)
            } else {
                epoch
            };
            karyos_sys::guard::encode(karyos_sys::guard::GuardState { epoch, open: false })
                .unwrap_or(karyos_sys::guard::created())
        };
        match self.phase(now) {
            Phase::Open { epoch, .. } => {
                karyos_sys::guard::encode(karyos_sys::guard::GuardState { epoch, open: true })
                    .unwrap_or_else(|| closed(epoch))
            }
            Phase::Recovering | Phase::Closed | Phase::Latched => closed(self.floor),
        }
    }

    /// Whether the guard is open at `now`.
    #[must_use]
    pub fn is_open(&self, now: u64) -> bool {
        matches!(self.phase(now), Phase::Open { .. })
    }

    /// The refusals for `reason`.
    #[must_use]
    pub fn refusals(&self, reason: GuardRefusal) -> u64 {
        self.refusals.get(reason as usize).copied().unwrap_or(0)
    }

    fn refuse(&mut self, reason: GuardRefusal) -> GuardRefusal {
        if let Some(count) = self.refusals.get_mut(reason as usize) {
            *count = count.saturating_add(1);
        }
        reason
    }

    fn round_live(&self, now: u64) -> bool {
        self.round
            .is_some_and(|(_, at)| now.saturating_sub(at) < CHALLENGE_TIMEOUT_NS)
    }

    /// Whether a new round is due at `now`: while recovering, while an
    /// `Open` STATE awaits confirmation, and from half an `Open`'s lifetime
    /// on; never once latched, and not while a round is live.
    #[must_use]
    pub fn round_due(&self, now: u64) -> bool {
        if self.round_live(now) {
            return false;
        }
        match self.phase(now) {
            Phase::Recovering => true,
            Phase::Closed => self.pending.is_some(),
            Phase::Open { until, .. } => now >= until.saturating_sub(self.lifetime_ns / 2),
            Phase::Latched => false,
        }
    }

    /// Starts a round for `receiver` at `now`: a fresh nonce, which
    /// replaces the previous one. `None` when latched or the nonce source
    /// failed.
    pub fn challenge(
        &mut self,
        receiver: Receiver,
        now: u64,
        nonces: &mut dyn NonceSource,
    ) -> Option<StatusChallenge> {
        if self.phase == Phase::Latched {
            return None;
        }
        let nonce = nonces.nonce()?;
        if let Some((old, _)) = self.round.replace((nonce, now)) {
            self.retired = Some(old);
        }
        Some(StatusChallenge {
            authority_id: self.authority_id,
            guard_id: self.guard_id,
            receiver,
            nonce,
        })
    }

    /// A verified STATUS, for this receiver's current `receiver` block, at
    /// `now`: accepted only for the outstanding, unexpired nonce, which it
    /// consumes. During recovery an epoch at or above the floor completes
    /// it (the floor persisted first); one below latches. After recovery a
    /// higher epoch is a transition, the same open epoch extends the
    /// `Open`, a lower one changes nothing.
    ///
    /// # Errors
    ///
    /// The [`GuardRefusal`], counted.
    pub fn on_status(
        &mut self,
        status: &GuardStatus,
        receiver: Receiver,
        now: u64,
        marks: &mut dyn MarkStore,
    ) -> Result<GuardChange, GuardRefusal> {
        if (status.authority_id, status.guard_id) != (self.authority_id, self.guard_id) {
            return Err(self.refuse(GuardRefusal::WrongGuard));
        }
        if status.receiver != receiver {
            return Err(self.refuse(GuardRefusal::WrongReceiver));
        }
        match self.round {
            Some((nonce, _)) if nonce == status.nonce => {}
            _ if self.retired == Some(status.nonce) => {
                return Err(self.refuse(GuardRefusal::StaleNonce));
            }
            _ => return Err(self.refuse(GuardRefusal::UnknownNonce)),
        }
        let live = self.round_live(now);
        // Consumed either way: a nonce answers once.
        self.retired = self.round.take().map(|(nonce, _)| nonce);
        if !live {
            return Err(self.refuse(GuardRefusal::StaleNonce));
        }
        if self.phase == Phase::Latched {
            return Err(self.refuse(GuardRefusal::Latched));
        }
        let epoch = status.word.epoch();
        let recovering = self.phase == Phase::Recovering;
        if epoch < self.floor {
            if recovering {
                // The authority is behind this receiver: latched closed.
                self.phase = Phase::Latched;
                return Err(self.refuse(GuardRefusal::Latched));
            }
            return Err(self.refuse(GuardRefusal::Stale));
        }
        if marks.persist(self.guard_id, epoch).is_err() {
            self.phase = if recovering {
                Phase::Recovering
            } else {
                Phase::Closed
            };
            return Err(self.refuse(GuardRefusal::Persist));
        }
        self.floor = epoch;
        self.phase = if status.word.is_open() {
            let lifetime = match self.pending {
                Some((pending, lifetime)) if pending == epoch => lifetime,
                _ => self.lifetime_ns,
            };
            Phase::Open {
                epoch,
                until: now.saturating_add(lifetime),
            }
        } else {
            Phase::Closed
        };
        if self.pending.is_some_and(|(pending, _)| pending <= epoch) {
            self.pending = None;
        }
        Ok(GuardChange::Applied(self.phase))
    }

    /// A verified STATE at `now`: discarded during recovery or once
    /// latched; refused at or below the floor; above it, `Closed` raises
    /// the floor (persisted first) and closes, `Open` raises it and only
    /// makes a confirmation round due.
    ///
    /// # Errors
    ///
    /// The [`GuardRefusal`], counted.
    pub fn on_state(
        &mut self,
        state: &GuardState,
        now: u64,
        marks: &mut dyn MarkStore,
    ) -> Result<GuardChange, GuardRefusal> {
        if (state.authority_id, state.guard_id) != (self.authority_id, self.guard_id) {
            return Err(self.refuse(GuardRefusal::WrongGuard));
        }
        match self.phase(now) {
            Phase::Recovering => return Err(self.refuse(GuardRefusal::Recovering)),
            Phase::Latched => return Err(self.refuse(GuardRefusal::Latched)),
            Phase::Closed | Phase::Open { .. } => {}
        }
        let epoch = state.word.epoch();
        if epoch <= self.floor {
            return Err(self.refuse(GuardRefusal::Stale));
        }
        if !state.word.is_open() {
            // Closing is always safe: it closes even if the mark cannot
            // be stored.
            self.phase = Phase::Closed;
            if marks.persist(self.guard_id, epoch).is_err() {
                return Err(self.refuse(GuardRefusal::Persist));
            }
            self.floor = epoch;
            return Ok(GuardChange::Applied(Phase::Closed));
        }
        if marks.persist(self.guard_id, epoch).is_err() {
            return Err(self.refuse(GuardRefusal::Persist));
        }
        self.floor = epoch;
        // An `Open` needs a fresh confirmation: until then it is closed.
        self.phase = Phase::Closed;
        let lifetime = u64::from(state.lifetime_ms).saturating_mul(1_000_000);
        self.pending = Some((epoch, lifetime));
        Ok(GuardChange::ConfirmationDue)
    }
}

#[cfg(test)]
mod tests;
