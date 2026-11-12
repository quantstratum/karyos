// SPDX-License-Identifier: Apache-2.0

//! Bounded admission of dynamic multi-destination registrations
//! (ADR-0056 as amended by ADR-0082; SPEC.md §6, "Multi-destination
//! unicast"; `quantstratum-docs: karyos/design/multi-destination-unicast.md`
//! section 3.2, steps 2, 3 and 5 to 7, and section 9.2).
//!
//! A REGISTER is one unauthenticated datagram. [`Registrations`] decides
//! what it may cause, in the design's order, the first failure deciding:
//!
//! 1. **Source.** A unicast address of the endpoint's family with a
//!    nonzero port (network-control-schemas.md 7.3); otherwise dropped.
//! 2. **Allowlist.** The source must lie in one of the
//!    [`RegistrationAllowlist`]'s ranges; otherwise dropped, no reply.
//! 3. **Rates.** A per-source bucket and a per-driver total; exhaustion
//!    drops with no reply.
//! 4. **Retry.** A pending entry with the same source and receiver block
//!    resends its one ANNOUNCE and takes no new entry.
//! 5. **Pending bounds.** At most `pending` entries in all and
//!    `pending_per_source` per source; exhaustion drops, no reply.
//! 6. **Capacity.** With no free destination slot, one ERR REGISTRATION
//!    `DESTINATIONS_FULL` to the source, at most once per source per
//!    `refusal_interval`; existing destinations are unaffected.
//! 7. **Pending entry.** The source, its receiver block and an expiry at
//!    `join_timeout`; exactly one SETUP ANNOUNCE goes to the source.
//!
//! **Reflection.** Before a receiver's CHALLENGE proves that it receives
//! at its source, a REGISTER causes at most one 72-byte ANNOUNCE or one
//! 40-byte ERR, only to its validated source, within the rates and
//! bounds above (design 9.2). The larger ANSWER follows only a CHALLENGE.
//!
//! **No authentication.** The allowlist restricts admission and supplies
//! no authentication (ADR-0082, decision 1): an admitted registration is
//! as unauthenticated as any other, and every check above stays mandatory
//! whatever the allowlist names. Authenticated registration has its own
//! profile gate (ADR-0076, clause 4) and is not here: SPEC.md §13's case of
//! an unauthenticated registration to an `authenticated` or `encrypted`
//! channel occupying no entry belongs to plan issue 034.
//!
//! Every table is allocated at construction; nothing here allocates
//! afterwards, reads a clock or sends. The caller owns the destination
//! table (step 6 takes its answer as [`Capacity`]) and the step 1 context
//! check of the stream.

use std::net::{IpAddr, SocketAddr};

use karyos_protocol::network::{Receiver, RspRegister};
use karyos_sys::host_clock::age_ns;

use crate::sessions::rate::{EndpointRates, TotalRate, normalized};

/// The most ranges a [`RegistrationAllowlist`] holds.
pub const MAX_ALLOW_RANGES: usize = 64;

/// One address range: a network address and a prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddressRange {
    network: IpAddr,
    prefix: u8,
}

impl AddressRange {
    /// The range of `network` with a `prefix`-bit prefix. An IPv4-mapped
    /// IPv6 network is its IPv4 network, as sources are compared.
    ///
    /// # Errors
    ///
    /// [`RegistrationConfigError::InvalidRange`] for a prefix longer than
    /// the address, or host bits set below it: a range is named exactly,
    /// never rounded.
    pub fn new(network: IpAddr, prefix: u8) -> Result<Self, RegistrationConfigError> {
        let network = network.to_canonical();
        let bits = bits_of(network);
        if prefix > bits {
            return Err(RegistrationConfigError::InvalidRange);
        }
        if masked(network, prefix) != network {
            return Err(RegistrationConfigError::InvalidRange);
        }
        Ok(Self { network, prefix })
    }

    /// The network address.
    #[must_use]
    #[inline]
    pub const fn network(&self) -> IpAddr {
        self.network
    }

    /// The prefix length.
    #[must_use]
    #[inline]
    pub const fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Whether `address` lies in the range: the same family once
    /// IPv4-mapped IPv6 is read as IPv4, and the same prefix.
    #[must_use]
    pub fn contains(&self, address: IpAddr) -> bool {
        let address = address.to_canonical();
        address.is_ipv4() == self.network.is_ipv4() && masked(address, self.prefix) == self.network
    }
}

/// The width of `address` in bits.
const fn bits_of(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// `address` with every bit below its first `prefix` cleared; `prefix` is
/// at most the address width.
fn masked(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(v4) => {
            let mask = u32::MAX.checked_shl(32u32.saturating_sub(u32::from(prefix)));
            IpAddr::V4(std::net::Ipv4Addr::from(u32::from(v4) & mask.unwrap_or(0)))
        }
        IpAddr::V6(v6) => {
            let mask = u128::MAX.checked_shl(128u32.saturating_sub(u32::from(prefix)));
            IpAddr::V6(std::net::Ipv6Addr::from(u128::from(v6) & mask.unwrap_or(0)))
        }
    }
}

/// The registration allowlist of a publication in `control-mode=dynamic`
/// on the trusted profile (ADR-0082, decision 1): non-empty, at most
/// [`MAX_ALLOW_RANGES`] ranges. A deployment that means to admit any
/// source names that broad range (`0.0.0.0/0`, `::/0`) explicitly; there is
/// no permissive default, and no constructor builds an empty list.
///
/// It restricts admission and supplies no authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationAllowlist {
    ranges: Vec<AddressRange>,
}

impl RegistrationAllowlist {
    /// An allowlist of `ranges`.
    ///
    /// # Errors
    ///
    /// [`RegistrationConfigError::EmptyAllowlist`] for no range, and
    /// [`RegistrationConfigError::TooManyRanges`] above
    /// [`MAX_ALLOW_RANGES`].
    pub fn new(ranges: &[AddressRange]) -> Result<Self, RegistrationConfigError> {
        if ranges.is_empty() {
            return Err(RegistrationConfigError::EmptyAllowlist);
        }
        if ranges.len() > MAX_ALLOW_RANGES {
            return Err(RegistrationConfigError::TooManyRanges);
        }
        Ok(Self {
            ranges: ranges.to_vec(),
        })
    }

    /// The ranges, as configured.
    #[must_use]
    pub fn ranges(&self) -> &[AddressRange] {
        &self.ranges
    }

    /// Whether `address` lies in one of the ranges.
    #[must_use]
    pub fn admits(&self, address: IpAddr) -> bool {
        self.ranges.iter().any(|range| range.contains(address))
    }
}

/// Why a registration configuration is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RegistrationConfigError {
    /// No allowlist range: dynamic trusted mode needs an explicit,
    /// non-empty allowlist (ADR-0082, decision 1).
    #[error("dynamic registration needs a non-empty allowlist")]
    EmptyAllowlist,
    /// More than [`MAX_ALLOW_RANGES`] ranges.
    #[error("too many registration allowlist ranges")]
    TooManyRanges,
    /// A prefix longer than its address, or host bits set below it.
    #[error("invalid registration address range")]
    InvalidRange,
    /// A zero rate, bound, interval or timeout, or a per-source bound
    /// above the total.
    #[error("invalid registration limit")]
    InvalidLimit,
}

/// The registration limits of design 3.2 (MD-11: driver and stream
/// configuration, not URI parameters). Every limit is mandatory and
/// nonzero; only the allowlist has no default.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RegistrationConfig {
    /// Which sources may register at all.
    pub allowlist: RegistrationAllowlist,
    /// REGISTERs per second per source endpoint, also the burst (the
    /// `setup_answer_rate` of 20).
    pub per_source_rate: u64,
    /// REGISTERs per second for the driver, also the burst
    /// (`registration_rate`, 256).
    pub rate: u64,
    /// Source endpoints whose rates and refusal times are tracked at once
    /// (64); a new source with no reusable entry is dropped.
    pub sources: usize,
    /// Pending registrations in all (`registration_pending`, 32).
    pub pending: usize,
    /// Pending registrations per source endpoint
    /// (`registration_pending_per_source`, 2).
    pub pending_per_source: usize,
    /// The least time between two ERR REGISTRATIONs to one source
    /// (`registration_refusal_interval`, 1 s), in ns.
    pub refusal_interval: u64,
    /// How long a pending registration waits for its receiver
    /// (`join_timeout`, 5 s, as `MembershipConfig`'s), in ns.
    pub join_timeout: u64,
}

impl RegistrationConfig {
    /// The design's defaults under `allowlist`, which has none.
    #[must_use]
    pub fn new(allowlist: RegistrationAllowlist) -> Self {
        Self {
            allowlist,
            per_source_rate: 20,
            rate: 256,
            sources: 64,
            pending: 32,
            pending_per_source: 2,
            refusal_interval: 1_000_000_000,
            join_timeout: 5_000_000_000,
        }
    }

    /// Checks every limit.
    ///
    /// # Errors
    ///
    /// [`RegistrationConfigError::InvalidLimit`] for a zero limit or a
    /// per-source pending bound above the total.
    pub fn validate(&self) -> Result<(), RegistrationConfigError> {
        let zero = self.per_source_rate == 0
            || self.rate == 0
            || self.sources == 0
            || self.pending == 0
            || self.pending_per_source == 0
            || self.refusal_interval == 0
            || self.join_timeout == 0;
        if zero || self.pending_per_source > self.pending {
            return Err(RegistrationConfigError::InvalidLimit);
        }
        Ok(())
    }
}

/// Whether the publication's destination table has a free slot for an
/// optional registrant (design 3.5), as its owner reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capacity {
    /// A slot is free.
    Free,
    /// Every slot open to an optional registrant is taken.
    Full,
}

/// What a REGISTER causes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum RegisterOutcome {
    /// Send one SETUP ANNOUNCE to `source`: a new pending entry, or a
    /// retry of one.
    Announce {
        /// The validated, normalized source.
        source: SocketAddr,
    },
    /// Send one ERR REGISTRATION `DESTINATIONS_FULL` to `source`.
    Refuse {
        /// The validated, normalized source.
        source: SocketAddr,
    },
    /// Nothing is sent.
    Drop(RegisterDrop),
}

/// Why a REGISTER caused nothing; each is counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegisterDrop {
    /// Not a unicast source of the endpoint's family with a nonzero port.
    Source,
    /// Outside the allowlist.
    NotAllowed,
    /// The source's bucket is empty, or no rate entry is free for it.
    SourceRate,
    /// The driver's total is spent.
    Rate,
    /// `pending` entries are held.
    PendingFull,
    /// `pending_per_source` entries are held by this source.
    SourcePendingFull,
    /// The table is full and this source was refused within
    /// `refusal_interval`, or no refusal entry is free for it.
    RefusalLimited,
}

/// Counters of [`Registrations`], each saturating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct RegistrationCounters {
    /// New pending entries, each with one ANNOUNCE.
    pub registered: u64,
    /// Retries that resent their entry's ANNOUNCE.
    pub retried: u64,
    /// ERR REGISTRATIONs sent.
    pub refused_full: u64,
    /// Dropped: [`RegisterDrop::Source`].
    pub dropped_source: u64,
    /// Dropped: [`RegisterDrop::NotAllowed`].
    pub dropped_not_allowed: u64,
    /// Dropped: [`RegisterDrop::SourceRate`].
    pub dropped_source_rate: u64,
    /// Dropped: [`RegisterDrop::Rate`].
    pub dropped_rate: u64,
    /// Dropped: [`RegisterDrop::PendingFull`].
    pub dropped_pending_full: u64,
    /// Dropped: [`RegisterDrop::SourcePendingFull`].
    pub dropped_source_pending_full: u64,
    /// Dropped: [`RegisterDrop::RefusalLimited`].
    pub dropped_refusal_limited: u64,
    /// Pending entries a CHALLENGE took.
    pub challenged: u64,
    /// Pending entries removed at `join_timeout`.
    pub expired: u64,
}

/// One pending registration (design 3.2 step 7): unverified until its
/// receiver's CHALLENGE takes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingRegistration {
    /// The normalized source.
    pub source: SocketAddr,
    /// The receiver block the REGISTER named.
    pub receiver: Receiver,
    /// Monotonic expiry, in ns.
    pub expires: u64,
}

/// The time of the last ERR REGISTRATION to one source.
#[derive(Debug, Clone, Copy)]
struct Refusal {
    source: SocketAddr,
    at: u64,
}

/// The bounded registration state of one dynamic publication.
#[derive(Debug)]
pub struct Registrations {
    config: RegistrationConfig,
    ipv4: bool,
    source_rates: EndpointRates,
    rate: TotalRate,
    pending: Vec<PendingRegistration>,
    refusals: Vec<Refusal>,
    counters: RegistrationCounters,
}

impl Registrations {
    /// The registrations of a publication whose endpoint is IPv4 when
    /// `ipv4`, under `config`, at `now`; every table is allocated here.
    ///
    /// # Errors
    ///
    /// [`RegistrationConfig::validate`]'s.
    pub fn new(
        config: RegistrationConfig,
        ipv4: bool,
        now: u64,
    ) -> Result<Self, RegistrationConfigError> {
        config.validate()?;
        let source_rates = EndpointRates::new(config.per_source_rate, config.sources)
            .ok_or(RegistrationConfigError::InvalidLimit)?;
        let rate = TotalRate::new(config.rate, now).ok_or(RegistrationConfigError::InvalidLimit)?;
        Ok(Self {
            pending: Vec::with_capacity(config.pending),
            refusals: Vec::with_capacity(config.sources),
            ipv4,
            source_rates,
            rate,
            config,
            counters: RegistrationCounters::default(),
        })
    }

    /// The configuration.
    #[must_use]
    pub const fn config(&self) -> &RegistrationConfig {
        &self.config
    }

    /// The counters.
    #[must_use]
    pub const fn counters(&self) -> RegistrationCounters {
        self.counters
    }

    /// The pending registrations, oldest first.
    #[must_use]
    pub fn pending(&self) -> &[PendingRegistration] {
        &self.pending
    }

    /// Admits or drops `register` from `source` at `now`, with the
    /// destination table's `capacity` (design 3.2; module docs).
    pub fn register(
        &mut self,
        source: SocketAddr,
        register: &RspRegister,
        capacity: Capacity,
        now: u64,
    ) -> RegisterOutcome {
        let outcome = self.decide(source, register, capacity, now);
        let counters = &mut self.counters;
        let counter = match outcome {
            RegisterOutcome::Announce { .. } => return outcome,
            RegisterOutcome::Refuse { .. } => &mut counters.refused_full,
            RegisterOutcome::Drop(reason) => match reason {
                RegisterDrop::Source => &mut counters.dropped_source,
                RegisterDrop::NotAllowed => &mut counters.dropped_not_allowed,
                RegisterDrop::SourceRate => &mut counters.dropped_source_rate,
                RegisterDrop::Rate => &mut counters.dropped_rate,
                RegisterDrop::PendingFull => &mut counters.dropped_pending_full,
                RegisterDrop::SourcePendingFull => &mut counters.dropped_source_pending_full,
                RegisterDrop::RefusalLimited => &mut counters.dropped_refusal_limited,
            },
        };
        *counter = counter.saturating_add(1);
        outcome
    }

    fn decide(
        &mut self,
        source: SocketAddr,
        register: &RspRegister,
        capacity: Capacity,
        now: u64,
    ) -> RegisterOutcome {
        // Step 1: the source.
        let source = normalized(source);
        if !self.valid_source(source) {
            return RegisterOutcome::Drop(RegisterDrop::Source);
        }
        // Step 2: the allowlist, before any state is charged.
        if !self.config.allowlist.admits(source.ip()) {
            return RegisterOutcome::Drop(RegisterDrop::NotAllowed);
        }
        // Step 3: both rates must admit before either is charged.
        if self.source_rates.would_admit(source, now).is_err() {
            return RegisterOutcome::Drop(RegisterDrop::SourceRate);
        }
        if !self.rate.would_admit(now) {
            return RegisterOutcome::Drop(RegisterDrop::Rate);
        }
        if self.source_rates.admit(source, now).is_err() {
            return RegisterOutcome::Drop(RegisterDrop::SourceRate);
        }
        if !self.rate.admit(now) {
            return RegisterOutcome::Drop(RegisterDrop::Rate);
        }
        self.expire(now);
        // Step 4: a retry resends its one ANNOUNCE.
        if self
            .pending
            .iter()
            .any(|entry| entry.source == source && entry.receiver == register.receiver)
        {
            self.counters.retried = self.counters.retried.saturating_add(1);
            return RegisterOutcome::Announce { source };
        }
        // Step 5: pending bounds.
        let held = self
            .pending
            .iter()
            .filter(|entry| entry.source == source)
            .count();
        if held >= self.config.pending_per_source {
            return RegisterOutcome::Drop(RegisterDrop::SourcePendingFull);
        }
        if self.pending.len() >= self.config.pending {
            return RegisterOutcome::Drop(RegisterDrop::PendingFull);
        }
        // Step 6: capacity.
        if capacity == Capacity::Full {
            return self.refuse(source, now);
        }
        // Step 7: the pending entry; its room was checked above.
        self.pending.push(PendingRegistration {
            source,
            receiver: register.receiver,
            expires: now.saturating_add(self.config.join_timeout),
        });
        self.counters.registered = self.counters.registered.saturating_add(1);
        RegisterOutcome::Announce { source }
    }

    /// Step 1: a unicast address of the endpoint's family, nonzero port.
    fn valid_source(&self, source: SocketAddr) -> bool {
        let unicast = match source.ip() {
            IpAddr::V4(v4) => !(v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast()),
            IpAddr::V6(v6) => !(v6.is_unspecified() || v6.is_multicast()),
        };
        unicast && source.port() != 0 && source.is_ipv4() == self.ipv4
    }

    /// Step 6: one ERR per source per `refusal_interval`, in a bounded
    /// table whose entries are reused once their interval has passed.
    fn refuse(&mut self, source: SocketAddr, now: u64) -> RegisterOutcome {
        let interval = self.config.refusal_interval;
        if let Some(entry) = self
            .refusals
            .iter_mut()
            .find(|entry| entry.source == source)
        {
            if age_ns(now, entry.at) < interval {
                return RegisterOutcome::Drop(RegisterDrop::RefusalLimited);
            }
            entry.at = now;
            return RegisterOutcome::Refuse { source };
        }
        let fresh = Refusal { source, at: now };
        if self.refusals.len() < self.config.sources {
            self.refusals.push(fresh);
        } else if let Some(entry) = self
            .refusals
            .iter_mut()
            .find(|entry| age_ns(now, entry.at) >= interval)
        {
            *entry = fresh;
        } else {
            return RegisterOutcome::Drop(RegisterDrop::RefusalLimited);
        }
        RegisterOutcome::Refuse { source }
    }

    /// Takes the pending entry a CHALLENGE from `source` with
    /// `receiver_boot_id` answers (design 3.2: the CHALLENGE moves it into
    /// `Membership`); `None` when none is pending, so a CHALLENGE from a
    /// source that never registered is not answered on this path.
    pub fn challenged(
        &mut self,
        source: SocketAddr,
        receiver_boot_id: [u64; 2],
        now: u64,
    ) -> Option<PendingRegistration> {
        self.expire(now);
        let source = normalized(source);
        let at = self.pending.iter().position(|entry| {
            entry.source == source && entry.receiver.receiver_boot_id == receiver_boot_id
        })?;
        // `at` is in range: `position` found it.
        let taken = (at < self.pending.len()).then(|| self.pending.remove(at))?;
        self.counters.challenged = self.counters.challenged.saturating_add(1);
        Some(taken)
    }

    /// Removes the entries whose `join_timeout` passed by `now` (MC-6).
    pub fn expire(&mut self, now: u64) {
        let before = self.pending.len();
        self.pending.retain(|entry| entry.expires > now);
        let removed = before.saturating_sub(self.pending.len());
        self.counters.expired = self
            .counters
            .expired
            .saturating_add(u64::try_from(removed).unwrap_or(u64::MAX));
    }
}

#[cfg(test)]
mod tests;
