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
            return Err(RegistrationConfigError::InvalidRange { network, prefix });
        }
        if masked(network, prefix) != network {
            return Err(RegistrationConfigError::InvalidRange { network, prefix });
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
            return Err(RegistrationConfigError::TooManyRanges {
                count: ranges.len(),
            });
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

/// What one dynamic publication admits a REGISTER from (design 3.2 steps 1
/// and 2): its allowlist (ADR-0082, decision 1) and its endpoint's address
/// family. The driver's [`Registrations`] are shared by every dynamic
/// publication; each passes its own policy with each REGISTER.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationPolicy {
    allowlist: RegistrationAllowlist,
    ipv4: bool,
}

impl RegistrationPolicy {
    /// The policy of a publication whose endpoint is IPv4 when `ipv4`,
    /// admitting the sources `allowlist` names.
    #[must_use]
    pub const fn new(allowlist: RegistrationAllowlist, ipv4: bool) -> Self {
        Self { allowlist, ipv4 }
    }

    /// The allowlist.
    #[must_use]
    #[inline]
    pub const fn allowlist(&self) -> &RegistrationAllowlist {
        &self.allowlist
    }

    /// Whether the publication's endpoint is IPv4.
    #[must_use]
    #[inline]
    pub const fn ipv4(&self) -> bool {
        self.ipv4
    }
}

/// The most pending registrations, and refusal entries, a driver may be
/// configured to hold: an implementation ceiling far above the design's
/// defaults (32 and 64), so a configured value is refused as a typed
/// error and never reaches an allocation that panics or aborts.
pub const MAX_REGISTRATION_TABLE: usize = 65_536;

/// Why a registration configuration is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RegistrationConfigError {
    /// No allowlist range: dynamic trusted mode needs an explicit,
    /// non-empty allowlist (ADR-0082, decision 1).
    #[error("dynamic registration needs a non-empty allowlist")]
    EmptyAllowlist,
    /// More than [`MAX_ALLOW_RANGES`] ranges.
    #[error("{count} registration allowlist ranges, above the maximum of {MAX_ALLOW_RANGES}")]
    TooManyRanges {
        /// The number of ranges given.
        count: usize,
    },
    /// A prefix longer than its address, or host bits set below it.
    #[error("invalid registration address range {network}/{prefix}")]
    InvalidRange {
        /// The network address given.
        network: IpAddr,
        /// The prefix length given.
        prefix: u8,
    },
    /// A zero rate, bound, interval or timeout, a per-source bound above
    /// the total, or a table above [`MAX_REGISTRATION_TABLE`].
    #[error("invalid registration limit `{field}`")]
    InvalidLimit {
        /// The [`RegistrationConfig`] field at fault.
        field: &'static str,
    },
}

/// The driver's registration limits of design 3.2 (MD-11: driver and
/// stream configuration, not URI parameters). Every limit is mandatory and
/// nonzero. The per-source bucket is not here: it is the sender's existing
/// `setup_answer_rate` table, which [`Registrations::register`] borrows.
/// The allowlist is per publication and passed with each REGISTER.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RegistrationConfig {
    /// REGISTERs per second for the driver, also the burst
    /// (`registration_rate`, 256 per driver).
    pub rate: u64,
    /// Source addresses whose refusal times are tracked at once (64); a
    /// new source with no reusable entry is not refused again.
    pub sources: usize,
    /// Pending registrations in all (`registration_pending`, 32 per
    /// driver).
    pub pending: usize,
    /// Pending registrations per source address
    /// (`registration_pending_per_source`, 2; SPEC.md §6).
    pub pending_per_source: usize,
    /// The least time between two ERR REGISTRATIONs to one source address
    /// (`registration_refusal_interval`, 1 s), in ns.
    pub refusal_interval: u64,
    /// How long a pending registration waits for its receiver
    /// (`join_timeout`, 5 s, as `MembershipConfig`'s), in ns.
    pub join_timeout: u64,
}

impl Default for RegistrationConfig {
    /// The design's defaults.
    fn default() -> Self {
        Self {
            rate: 256,
            sources: 64,
            pending: 32,
            pending_per_source: 2,
            refusal_interval: 1_000_000_000,
            join_timeout: 5_000_000_000,
        }
    }
}

impl RegistrationConfig {
    /// Checks every limit.
    ///
    /// # Errors
    ///
    /// [`RegistrationConfigError::InvalidLimit`], naming the field, for a
    /// zero limit, a per-source pending bound above the total, or a table
    /// above [`MAX_REGISTRATION_TABLE`].
    pub fn validate(&self) -> Result<(), RegistrationConfigError> {
        let bad = |field| Err(RegistrationConfigError::InvalidLimit { field });
        if self.rate == 0 {
            return bad("rate");
        }
        if self.sources == 0 || self.sources > MAX_REGISTRATION_TABLE {
            return bad("sources");
        }
        if self.pending == 0 || self.pending > MAX_REGISTRATION_TABLE {
            return bad("pending");
        }
        if self.pending_per_source == 0 || self.pending_per_source > self.pending {
            return bad("pending_per_source");
        }
        if self.refusal_interval == 0 {
            return bad("refusal_interval");
        }
        if self.join_timeout == 0 {
            return bad("join_timeout");
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
    /// `pending_per_source` entries are held by this source address.
    SourcePendingFull,
    /// The table is full and this source address was refused within
    /// `refusal_interval`, or no refusal entry is free for it.
    RefusalLimited,
}

/// Counters of [`Registrations`]; checked, sticky on overflow (design 7).
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
    /// An increment did not apply.
    pub overflowed: bool,
}

impl RegistrationCounters {
    fn add(&mut self, field: fn(&mut Self) -> &mut u64, amount: u64) {
        let value = field(self);
        match value.checked_add(amount) {
            Some(next) => *value = next,
            None => self.overflowed = true,
        }
    }

    fn bump(&mut self, field: fn(&mut Self) -> &mut u64) {
        self.add(field, 1);
    }
}

/// One pending registration (design 3.2 step 7): unverified until its
/// receiver's CHALLENGE takes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingRegistration {
    /// The stream the REGISTER named.
    pub stream_id: i32,
    /// The normalized source.
    pub source: SocketAddr,
    /// The receiver block the REGISTER named.
    pub receiver: Receiver,
    /// Monotonic expiry, in ns.
    pub expires: u64,
}

/// The time of the last ERR REGISTRATION to one source address.
#[derive(Debug, Clone, Copy)]
struct Refusal {
    source: IpAddr,
    at: u64,
}

/// The bounded registration state of one driver, shared by its dynamic
/// publications: the per-driver rate, the pending table and the refusal
/// table (design 3.2 steps 3, 5 and 6 scope these to the driver). Each
/// publication keeps its own allowlist (ADR-0082, decision 1).
#[derive(Debug)]
pub struct Registrations {
    config: RegistrationConfig,
    rate: TotalRate,
    pending: Vec<PendingRegistration>,
    refusals: Vec<Refusal>,
    counters: RegistrationCounters,
}

/// Step 1: a unicast address of the endpoint's family (IPv4 when `ipv4`),
/// nonzero port.
fn valid_source(source: SocketAddr, ipv4: bool) -> bool {
    let unicast = match source.ip() {
        IpAddr::V4(v4) => !(v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast()),
        IpAddr::V6(v6) => !(v6.is_unspecified() || v6.is_multicast()),
    };
    unicast && source.port() != 0 && source.is_ipv4() == ipv4
}

/// Allocates room for `len` entries, or names `field` at fault.
fn table<T>(len: usize, field: &'static str) -> Result<Vec<T>, RegistrationConfigError> {
    let mut table = Vec::new();
    table
        .try_reserve_exact(len)
        .map_err(|_| RegistrationConfigError::InvalidLimit { field })?;
    Ok(table)
}

impl Registrations {
    /// The registrations of a driver under `config`, at `now`; every table
    /// is allocated here.
    ///
    /// # Errors
    ///
    /// [`RegistrationConfig::validate`]'s.
    pub fn new(config: RegistrationConfig, now: u64) -> Result<Self, RegistrationConfigError> {
        config.validate()?;
        let rate = TotalRate::new(config.rate, now)
            .ok_or(RegistrationConfigError::InvalidLimit { field: "rate" })?;
        Ok(Self {
            pending: table(config.pending, "pending")?,
            refusals: table(config.sources, "sources")?,
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

    /// Admits or drops `register` from `source` at `now`, for the
    /// publication whose policy is `policy` and whose destination
    /// table reports `capacity`, charging the sender's per-source
    /// `setup_answer_rate` table `source_rates` (design 3.2; module docs).
    pub fn register(
        &mut self,
        source_rates: &mut EndpointRates,
        policy: &RegistrationPolicy,
        source: SocketAddr,
        register: &RspRegister,
        capacity: Capacity,
        now: u64,
    ) -> RegisterOutcome {
        let outcome = self.decide(source_rates, policy, source, register, capacity, now);
        let counter: fn(&mut RegistrationCounters) -> &mut u64 = match outcome {
            RegisterOutcome::Announce { .. } => return outcome,
            RegisterOutcome::Refuse { .. } => |c| &mut c.refused_full,
            RegisterOutcome::Drop(reason) => match reason {
                RegisterDrop::Source => |c| &mut c.dropped_source,
                RegisterDrop::NotAllowed => |c| &mut c.dropped_not_allowed,
                RegisterDrop::SourceRate => |c| &mut c.dropped_source_rate,
                RegisterDrop::Rate => |c| &mut c.dropped_rate,
                RegisterDrop::PendingFull => |c| &mut c.dropped_pending_full,
                RegisterDrop::SourcePendingFull => |c| &mut c.dropped_source_pending_full,
                RegisterDrop::RefusalLimited => |c| &mut c.dropped_refusal_limited,
            },
        };
        self.counters.bump(counter);
        outcome
    }

    fn decide(
        &mut self,
        source_rates: &mut EndpointRates,
        policy: &RegistrationPolicy,
        source: SocketAddr,
        register: &RspRegister,
        capacity: Capacity,
        now: u64,
    ) -> RegisterOutcome {
        // Step 1: the source.
        let source = normalized(source);
        if !valid_source(source, policy.ipv4) {
            return RegisterOutcome::Drop(RegisterDrop::Source);
        }
        // Step 2: the allowlist, before any state is charged.
        if !policy.allowlist.admits(source.ip()) {
            return RegisterOutcome::Drop(RegisterDrop::NotAllowed);
        }
        // Step 3: both rates must admit before either is charged.
        if source_rates.would_admit(source, now).is_err() {
            return RegisterOutcome::Drop(RegisterDrop::SourceRate);
        }
        if !self.rate.would_admit(now) {
            return RegisterOutcome::Drop(RegisterDrop::Rate);
        }
        if source_rates.admit(source, now).is_err() {
            return RegisterOutcome::Drop(RegisterDrop::SourceRate);
        }
        if !self.rate.admit(now) {
            return RegisterOutcome::Drop(RegisterDrop::Rate);
        }
        self.expire(now);
        // Step 4: a retry resends its one ANNOUNCE; it matches the source
        // endpoint, the stream and the receiver block.
        if self.pending.iter().any(|entry| {
            entry.source == source
                && entry.stream_id == register.stream_id
                && entry.receiver == register.receiver
        }) {
            self.counters.bump(|c| &mut c.retried);
            return RegisterOutcome::Announce { source };
        }
        // Step 5: pending bounds, per source address (SPEC.md §6): a
        // source varying its port holds no more.
        let held = self
            .pending
            .iter()
            .filter(|entry| entry.source.ip() == source.ip())
            .count();
        if held >= self.config.pending_per_source {
            return RegisterOutcome::Drop(RegisterDrop::SourcePendingFull);
        }
        if self.pending.len() >= self.config.pending {
            return RegisterOutcome::Drop(RegisterDrop::PendingFull);
        }
        // Step 6: capacity.
        if capacity == Capacity::Full {
            return self.refuse(source.ip(), source, now);
        }
        // Step 7: the pending entry; its room was checked above.
        self.pending.push(PendingRegistration {
            stream_id: register.stream_id,
            source,
            receiver: register.receiver,
            expires: now.saturating_add(self.config.join_timeout),
        });
        self.counters.bump(|c| &mut c.registered);
        RegisterOutcome::Announce { source }
    }

    /// Step 6: one ERR per source address per `refusal_interval`, in a
    /// bounded table whose entries are reused once their interval has
    /// passed.
    fn refuse(&mut self, address: IpAddr, source: SocketAddr, now: u64) -> RegisterOutcome {
        let interval = self.config.refusal_interval;
        if let Some(entry) = self
            .refusals
            .iter_mut()
            .find(|entry| entry.source == address)
        {
            if age_ns(now, entry.at) < interval {
                return RegisterOutcome::Drop(RegisterDrop::RefusalLimited);
            }
            entry.at = now;
            return RegisterOutcome::Refuse { source };
        }
        let fresh = Refusal {
            source: address,
            at: now,
        };
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

    /// Takes the pending entry for `stream_id` that a CHALLENGE from
    /// `source` with `receiver_boot_id` answers (design 3.2: the CHALLENGE
    /// moves it into `Membership`); `None` when none is pending, so a
    /// CHALLENGE from a source that never registered is not answered on
    /// this path.
    pub fn challenged(
        &mut self,
        stream_id: i32,
        source: SocketAddr,
        receiver_boot_id: [u64; 2],
        now: u64,
    ) -> Option<PendingRegistration> {
        self.expire(now);
        let source = normalized(source);
        let at = self.pending.iter().position(|entry| {
            entry.stream_id == stream_id
                && entry.source == source
                && entry.receiver.receiver_boot_id == receiver_boot_id
        })?;
        // `at` is in range: `position` found it.
        let taken = (at < self.pending.len()).then(|| self.pending.remove(at))?;
        self.counters.bump(|c| &mut c.challenged);
        Some(taken)
    }

    /// Removes the entries whose `join_timeout` passed by `now` (MC-6).
    pub fn expire(&mut self, now: u64) {
        let before = self.pending.len();
        self.pending.retain(|entry| entry.expires > now);
        let removed = before.saturating_sub(self.pending.len());
        // A `usize` count fits a `u64` on every supported target.
        let removed = u64::try_from(removed).unwrap_or(u64::MAX);
        self.counters.add(|c| &mut c.expired, removed);
    }
}

#[cfg(test)]
mod tests;
