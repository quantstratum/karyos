// SPDX-License-Identifier: Apache-2.0

//! The receive order of the signed domains, GUARD (2) and SESSION_ABORT
//! (3) (`quantstratum-docs:
//! karyos/adr/0086-wire-authentication-profile-v1.md` sections 2, 6 and 8;
//! `karyos/design/authenticated-control-schemas.md` sections 3 to 5; part
//! of quantstratum/karyos#648).
//!
//! [`SignedIntake::receive`] runs, in order: the verification budget (one
//! per duty cycle, and per-source and per-driver rates; excess is dropped
//! and counted before any verification), the lookup of the SHA-256
//! digest of the complete datagram in a bounded, preallocated cache of
//! verified datagrams (a hit returns what to resend and changes nothing),
//! `verify_strict` under the authority key the envelope names, and the
//! authority checks of the key file's scope (`authority_id`, the guard in
//! `guards`, `abort` for SESSION_ABORT). The epoch check and the state
//! change are the caller's; only after them does the caller insert the
//! digest ([`SignedIntake::applied`]). Nothing here allocates after
//! construction.

use std::net::SocketAddr;

use karyos_protocol::frame::FrameType;
use karyos_protocol::network::authenticated::AuthControl;
use karyos_protocol::protection::Rejection;
use karyos_protocol::protection::hmac_sha256::HEADER_LEN;
use karyos_protocol::protection::signed::{
    MAX_BODY_LEN, SIGNATURE_LEN, SignedBinding, SignedDomain, open_signed,
};
use sha2::{Digest as _, Sha256};

use crate::authority::Ed25519Verifier;
use crate::wire_keys::{KeyFile, Material, Purpose, Scope};

/// Verifications per duty cycle (ADR-0086 section 2: at most one).
pub const VERIFY_PER_CYCLE: u32 = 1;
/// Verifications per second per driver.
pub const DRIVER_RATE: u32 = 256;
/// Verifications per second per source address, with that burst.
pub const SOURCE_RATE: u32 = 4;
/// Source addresses the per-source budget tracks; a source finding no
/// slot is dropped (fail closed).
pub const SOURCE_SLOTS: usize = 64;
/// Verified datagrams the digest cache remembers.
pub const CACHE_ENTRIES: usize = 64;

const NS_PER_S: u128 = 1_000_000_000;

/// A token bucket refilled on the monotonic clock.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Bucket {
    tokens: u32,
    capacity: u32,
    per_second: u32,
    last: u64,
}

impl Bucket {
    pub(crate) const fn full(capacity: u32, per_second: u32, now: u64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            per_second,
            last: now,
        }
    }

    fn refill(&mut self, now: u64) {
        let elapsed = u128::from(now.saturating_sub(self.last));
        let earned = elapsed.saturating_mul(u128::from(self.per_second)) / NS_PER_S;
        if earned == 0 {
            return;
        }
        let earned = u32::try_from(earned).unwrap_or(u32::MAX);
        self.tokens = self.tokens.saturating_add(earned).min(self.capacity);
        let spent =
            u128::from(earned).saturating_mul(NS_PER_S) / u128::from(self.per_second.max(1));
        self.last = self
            .last
            .saturating_add(u64::try_from(spent).unwrap_or(u64::MAX))
            .min(now);
    }

    pub(crate) fn has(&mut self, now: u64) -> bool {
        self.refill(now);
        self.tokens > 0
    }

    pub(crate) fn take(&mut self) {
        self.tokens = self.tokens.saturating_sub(1);
    }
}

/// Why the budget refused a datagram, before any verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetRefusal {
    /// This duty cycle's verification is spent.
    Cycle,
    /// The driver's rate.
    Driver,
    /// The source's rate.
    Source,
    /// No slot is left for a new source.
    Sources,
}

/// The verification budget of the signed domains: allocated once.
#[derive(Debug)]
pub struct VerifyBudget {
    cycle_left: u32,
    driver: Bucket,
    sources: Vec<(SocketAddr, Bucket)>,
}

impl VerifyBudget {
    /// A full budget at `now`.
    #[must_use]
    pub fn new(now: u64) -> Self {
        Self {
            cycle_left: VERIFY_PER_CYCLE,
            driver: Bucket::full(DRIVER_RATE, DRIVER_RATE, now),
            sources: Vec::with_capacity(SOURCE_SLOTS),
        }
    }

    /// A new duty cycle: its verification is available again.
    pub fn new_cycle(&mut self) {
        self.cycle_left = VERIFY_PER_CYCLE;
    }

    /// Takes one verification for `source` at `now`, or says why not;
    /// nothing is taken from any limit on a refusal.
    ///
    /// # Errors
    ///
    /// The [`BudgetRefusal`].
    pub fn admit(&mut self, source: SocketAddr, now: u64) -> Result<(), BudgetRefusal> {
        if self.cycle_left == 0 {
            return Err(BudgetRefusal::Cycle);
        }
        if !self.driver.has(now) {
            return Err(BudgetRefusal::Driver);
        }
        let index = match self.sources.iter().position(|(held, _)| *held == source) {
            Some(index) => index,
            None if self.sources.len() < SOURCE_SLOTS => {
                self.sources
                    .push((source, Bucket::full(SOURCE_RATE, SOURCE_RATE, now)));
                self.sources.len() - 1
            }
            None => return Err(BudgetRefusal::Sources),
        };
        let Some((_, bucket)) = self.sources.get_mut(index) else {
            return Err(BudgetRefusal::Sources);
        };
        if !bucket.has(now) {
            return Err(BudgetRefusal::Source);
        }
        bucket.take();
        self.driver.take();
        self.cycle_left -= 1;
        Ok(())
    }
}

/// The SHA-256 digests of verified, applied datagrams, each with what a
/// hit resends: bounded, preallocated, oldest replaced first.
#[derive(Debug)]
pub struct DigestCache<R: Clone> {
    entries: Vec<([u8; 32], R)>,
    next: usize,
}

impl<R: Clone> DigestCache<R> {
    /// An empty cache of [`CACHE_ENTRIES`], allocated now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::with_capacity(CACHE_ENTRIES),
            next: 0,
        }
    }

    fn find(&self, digest: &[u8; 32]) -> Option<R> {
        self.entries
            .iter()
            .find(|(held, _)| held == digest)
            .map(|(_, resend)| resend.clone())
    }

    fn insert(&mut self, digest: [u8; 32], resend: R) {
        if self.find(&digest).is_some() {
            return;
        }
        if self.entries.len() < CACHE_ENTRIES {
            self.entries.push((digest, resend));
        } else if let Some(slot) = self.entries.get_mut(self.next) {
            *slot = (digest, resend);
            self.next = (self.next + 1) % CACHE_ENTRIES;
        }
    }
}

impl<R: Clone> Default for DigestCache<R> {
    fn default() -> Self {
        Self::new()
    }
}

/// An authority key and the scope its file names.
#[derive(Debug, Clone)]
pub struct Authority {
    key_id: u32,
    verifier: Ed25519Verifier,
    authority_id: u64,
    guards: Vec<u64>,
    abort: bool,
}

/// Why an authority key file cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotAuthority;

impl Authority {
    /// The authority a public key file names.
    ///
    /// # Errors
    ///
    /// [`NotAuthority`] for a file of another purpose or material.
    pub fn from_file(file: &KeyFile) -> Result<Self, NotAuthority> {
        let (Purpose::AuthorityPublic, Material::Public(verifier)) = (file.purpose, &file.material)
        else {
            return Err(NotAuthority);
        };
        let Scope::Authority {
            authority_id,
            guards,
            guard_count,
            abort,
        } = file.scope
        else {
            return Err(NotAuthority);
        };
        Ok(Self {
            key_id: file.key_id,
            verifier: verifier.clone(),
            authority_id,
            guards: guards.get(..guard_count).unwrap_or(&[]).to_vec(),
            abort,
        })
    }

    /// An authority from its parts (tests).
    #[cfg(test)]
    #[must_use]
    pub fn of(
        key_id: u32,
        verifier: Ed25519Verifier,
        authority_id: u64,
        guards: &[u64],
        abort: bool,
    ) -> Self {
        Self {
            key_id,
            verifier,
            authority_id,
            guards: guards.to_vec(),
            abort,
        }
    }

    /// The `key_id` of its key.
    #[must_use]
    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    /// The authority id its key names.
    #[must_use]
    pub fn authority_id(&self) -> u64 {
        self.authority_id
    }
}

/// Why a signed datagram is refused; one counter each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum SignedRefusal {
    /// The duty cycle's verification is spent.
    BudgetCycle = 0,
    /// The driver's rate.
    BudgetDriver,
    /// The source's rate.
    BudgetSource,
    /// No source slot left.
    BudgetSources,
    /// Not a signed-domain envelope, or longer than any.
    NotSigned,
    /// No authority key of the envelope's `key_id`.
    UnknownKey,
    /// A field of the envelope, or the signature.
    Envelope,
    /// The body does not decode, or is not of the envelope's domain.
    Body,
    /// The body names another authority than its key.
    WrongAuthority,
    /// The guard is not one the key serves.
    WrongGuard,
    /// A SESSION_ABORT under a key without the `abort` permission.
    NoAbortPermission,
    /// A SESSION_ABORT whose body alias is not the envelope's.
    Binding,
}

/// Refusal reasons.
pub const SIGNED_REFUSALS: usize = SignedRefusal::Binding as usize + 1;

impl From<BudgetRefusal> for SignedRefusal {
    fn from(refusal: BudgetRefusal) -> Self {
        match refusal {
            BudgetRefusal::Cycle => Self::BudgetCycle,
            BudgetRefusal::Driver => Self::BudgetDriver,
            BudgetRefusal::Source => Self::BudgetSource,
            BudgetRefusal::Sources => Self::BudgetSources,
        }
    }
}

/// A datagram that passed the budget, the cache, the signature and the
/// authority checks: the caller checks its epoch, applies it, and only
/// then records its digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified {
    /// The body.
    pub control: AuthControl,
    /// The SHA-256 digest of the whole datagram.
    pub digest: [u8; 32],
}

/// What a signed datagram is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Received<R> {
    /// New: verified, to be epoch-checked and applied.
    Fresh(Verified),
    /// The identical datagram of one already applied: resend `R` (the
    /// idempotent ACK), change nothing.
    Resend(R),
}

/// The receive order of the signed domains for one driver.
#[derive(Debug)]
pub struct SignedIntake<R: Clone> {
    authorities: Vec<Authority>,
    budget: VerifyBudget,
    cache: DigestCache<R>,
    refusals: [u64; SIGNED_REFUSALS],
    /// Datagrams verified.
    pub verified: u64,
    /// Cache hits.
    pub resends: u64,
}

impl<R: Clone> SignedIntake<R> {
    /// An intake trusting `authorities`, its budget full at `now`.
    #[must_use]
    pub fn new(authorities: Vec<Authority>, now: u64) -> Self {
        Self {
            authorities,
            budget: VerifyBudget::new(now),
            cache: DigestCache::new(),
            refusals: [0; SIGNED_REFUSALS],
            verified: 0,
            resends: 0,
        }
    }

    /// Replaces the trusted authorities after a key reload or expiry (H8
    /// finding 4): a key no longer in `authorities` verifies nothing from
    /// now on, and the digest cache is emptied, so no ACK is resent from
    /// state applied under the old set.
    pub fn replace_authorities(&mut self, authorities: Vec<Authority>) {
        self.authorities = authorities;
        self.cache = DigestCache::new();
    }

    /// A new duty cycle.
    pub fn new_cycle(&mut self) {
        self.budget.new_cycle();
    }

    /// The refusals for `reason`.
    #[must_use]
    pub fn refusals(&self, reason: SignedRefusal) -> u64 {
        self.refusals.get(reason as usize).copied().unwrap_or(0)
    }

    /// Runs the receive order of `datagram` from `source` at `now` (the
    /// monotonic clock, for the budget). Allocates nothing.
    ///
    /// # Errors
    ///
    /// The [`SignedRefusal`], counted; nothing else changes.
    pub fn receive(
        &mut self,
        source: SocketAddr,
        datagram: &[u8],
        now: u64,
    ) -> Result<Received<R>, SignedRefusal> {
        let result = self.receive_uncounted(source, datagram, now);
        if let Err(reason) = result
            && let Some(count) = self.refusals.get_mut(reason as usize)
        {
            *count = count.saturating_add(1);
        }
        result
    }

    fn receive_uncounted(
        &mut self,
        source: SocketAddr,
        datagram: &[u8],
        now: u64,
    ) -> Result<Received<R>, SignedRefusal> {
        let max = HEADER_LEN + MAX_BODY_LEN + SIGNATURE_LEN;
        let domain = match datagram.get(10).copied() {
            Some(2) => SignedDomain::Guard,
            Some(3) => SignedDomain::SessionAbort,
            _ => return Err(SignedRefusal::NotSigned),
        };
        if datagram.len() > max {
            return Err(SignedRefusal::NotSigned);
        }
        // 1. The budget, before anything is hashed or verified.
        self.budget.admit(source, now)?;
        // 2. The digest cache.
        let digest: [u8; 32] = Sha256::digest(datagram).into();
        if let Some(resend) = self.cache.find(&digest) {
            self.resends = self.resends.saturating_add(1);
            return Ok(Received::Resend(resend));
        }
        // 3. `verify_strict` under the key the envelope names.
        let field = |at: usize| -> Option<[u8; 4]> { datagram.get(at..at + 4)?.try_into().ok() };
        let key_id = field(20)
            .map(u32::from_le_bytes)
            .ok_or(SignedRefusal::NotSigned)?;
        let authority = self
            .authorities
            .iter()
            .find(|authority| authority.key_id == key_id)
            .ok_or(SignedRefusal::UnknownKey)?;
        // GUARD names no session; SESSION_ABORT's alias is the envelope's,
        // which the signature covers and the body must repeat.
        let (session_id, stream_id) = match domain {
            SignedDomain::Guard => (0, 0),
            SignedDomain::SessionAbort => (
                field(12)
                    .map(i32::from_le_bytes)
                    .ok_or(SignedRefusal::NotSigned)?,
                field(16)
                    .map(i32::from_le_bytes)
                    .ok_or(SignedRefusal::NotSigned)?,
            ),
        };
        let binding = SignedBinding {
            domain,
            party_epoch: 0,
            session_id,
            stream_id,
            key_id,
        };
        let opened = open_signed(datagram, &binding, &authority.verifier).map_err(
            |rejection: Rejection| {
                let _ = rejection;
                SignedRefusal::Envelope
            },
        )?;
        let body = datagram
            .get(opened.start..)
            .and_then(|rest| rest.get(..opened.body))
            .ok_or(SignedRefusal::Body)?;
        let control = AuthControl::decode(body).map_err(|_| SignedRefusal::Body)?;
        // 4. The authority checks of the key's scope.
        match (domain, control) {
            (SignedDomain::Guard, AuthControl::State(state)) => {
                authority.serves(state.authority_id, state.guard_id)?;
            }
            (SignedDomain::Guard, AuthControl::Status(status)) => {
                authority.serves(status.authority_id, status.guard_id)?;
            }
            (SignedDomain::SessionAbort, AuthControl::Abort(abort)) => {
                if abort.authority_id != authority.authority_id {
                    return Err(SignedRefusal::WrongAuthority);
                }
                if !authority.abort {
                    return Err(SignedRefusal::NoAbortPermission);
                }
                if abort.guard_id != 0 && !authority.guards.contains(&abort.guard_id) {
                    return Err(SignedRefusal::WrongGuard);
                }
                if (abort.alias.session_id, abort.alias.stream_id) != (session_id, stream_id) {
                    return Err(SignedRefusal::Binding);
                }
            }
            _ => return Err(SignedRefusal::Body),
        }
        self.verified = self.verified.saturating_add(1);
        Ok(Received::Fresh(Verified { control, digest }))
    }

    /// Records a verified datagram's digest once its state change is made,
    /// with what a resend of it resends.
    pub fn applied(&mut self, digest: [u8; 32], resend: R) {
        self.cache.insert(digest, resend);
    }
}

impl Authority {
    fn serves(&self, authority_id: u64, guard_id: u64) -> Result<(), SignedRefusal> {
        if authority_id != self.authority_id {
            return Err(SignedRefusal::WrongAuthority);
        }
        if !self.guards.contains(&guard_id) {
            return Err(SignedRefusal::WrongGuard);
        }
        Ok(())
    }
}

/// Whether `bytes` is a frame of a type only the signed or MAC path may
/// decode (GUARD, SESSION_ABORT, SESSION_ABORT_ACK), read from its common
/// word.
#[must_use]
pub fn is_gated(bytes: &[u8]) -> bool {
    bytes
        .get(6..8)
        .and_then(|code| code.try_into().ok())
        .map(u16::from_le_bytes)
        .and_then(|code| FrameType::try_from_code(code).ok())
        .is_some_and(|frame_type| {
            matches!(
                frame_type,
                FrameType::Guard | FrameType::SessionAbort | FrameType::SessionAbortAck
            )
        })
}

#[cfg(test)]
mod tests;
