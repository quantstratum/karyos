// SPDX-License-Identifier: Apache-2.0

//! Replicated guards, the replicated side of semantic fencing (C9, part
//! (a) of karyos#683; quantstratum-docs: karyos/design/replicated-guards.md).
//!
//! A [`GuardTable`] is container state, beside the session table and the
//! timers: the guards a cluster decides through its log, their epochs and
//! fences, and the authority lease the leader renews. It applies the
//! schema 6 entries ([`GuardEntry`]) in log order and reports every change
//! as an ordered effect list ([`GuardEffect`]) for the host to hand to its
//! driver. How a driver enforces those changes and fails closed is part
//! (b) (the note's §10), not this module.
//!
//! - **Epoch and fence.** The epoch is the local guard's (odd `Closed`,
//!   even `Open`, one step per state change, at most [`MAX_EPOCH`]). The
//!   fence counts close decisions: every close raises it, even on a closed
//!   guard, and a reopen applies only to the fence it names. A close is
//!   never refused for an epoch or a fence.
//! - **The lease.** A `Renew` grants `issued + lifetime`, anchored to its
//!   own timestamp; a lease is [`Lease::NeverGranted`], [`Lease::Active`]
//!   or [`Lease::Lapsed`]. Before any guard entry applies at or past
//!   `lease_until`, the **lapse rule** closes every open guard and raises
//!   every fence. A reopen applies only while the lease is active.
//! - **Bounds.** [`GuardBounds`], the first in the log, fixes the capacity,
//!   the lifetime, the renewal interval and the durability profile on every
//!   replica; a replica configured otherwise stops.
//! - **The one clock** is the container's log time, the highest event time
//!   applied; all lease arithmetic is checked.

use karyos_codec::{CodecError, Decoder, ENVELOPE_LENGTH, Encoder, Template};

#[cfg(test)]
mod tests;

/// Schema 6, the guard entries.
pub const GUARD_SCHEMA_ID: u16 = 6;
/// The only version of schema 6.
pub const GUARD_VERSION: u16 = 1;
/// The largest epoch: odd, so a guard can always be closed.
pub const MAX_EPOCH: u64 = (1 << 63) - 1;
/// The longest lease a `GuardBounds` may declare, in log time units
/// (nanoseconds): one minute.
pub const MAX_GUARD_LIFETIME: u64 = 60_000_000_000;
/// The reason a lapse records; no operator reason may be it.
pub const LAPSE_REASON: u32 = u32::MAX;

const fn template(template_id: u16, block_length: u16) -> Template {
    Template {
        schema_id: GUARD_SCHEMA_ID,
        template_id,
        version: GUARD_VERSION,
        block_length,
        max_length: ENVELOPE_LENGTH as u32 + block_length as u32,
    }
}

/// `GuardBounds`, template 1: 33 bytes.
pub const GUARD_BOUNDS: Template = template(1, 21);
/// `Define`, template 2: 24 bytes.
pub const DEFINE: Template = template(2, 12);
/// `Close`, template 3: 40 bytes.
pub const CLOSE: Template = template(3, 28);
/// `Reopen`, template 4: 48 bytes.
pub const REOPEN: Template = template(4, 36);
/// `Renew`, template 5: 20 bytes.
pub const RENEW: Template = template(5, 8);

/// The Cluster's durability profile: a reopen applies only under
/// [`Profile::Durable`], where a committed entry is durable on a majority
/// before it applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Profile {
    /// Entries are durable on a majority before they apply.
    Durable,
    /// They are not.
    Volatile,
}

impl Profile {
    const fn code(self) -> u8 {
        match self {
            Self::Durable => 1,
            Self::Volatile => 2,
        }
    }

    fn from_code(code: u8) -> Result<Self, CodecError> {
        match code {
            1 => Ok(Self::Durable),
            2 => Ok(Self::Volatile),
            _ => Err(CodecError::ValueOutOfRange { field: "profile" }),
        }
    }
}

/// The guard table's bounds, replicated: the same on every replica.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct GuardBounds {
    /// Guards at most.
    pub guards: u32,
    /// The lease a renewal grants, in log time units.
    pub lifetime: u64,
    /// How often the leader renews, below `lifetime`.
    pub renew_every: u64,
    /// The durability profile.
    pub profile: Profile,
}

impl GuardBounds {
    /// Bounds of `guards`, `lifetime`, `renew_every` and `profile`.
    ///
    /// # Errors
    ///
    /// [`CodecError::ValueOutOfRange`] for a 0, a renewal interval not
    /// below the lifetime, or a lifetime past [`MAX_GUARD_LIFETIME`].
    pub fn new(
        guards: u32,
        lifetime: u64,
        renew_every: u64,
        profile: Profile,
    ) -> Result<Self, CodecError> {
        let bounds = Self {
            guards,
            lifetime,
            renew_every,
            profile,
        };
        bounds.check()?;
        Ok(bounds)
    }

    fn check(&self) -> Result<(), CodecError> {
        if self.guards == 0 {
            return Err(CodecError::ValueOutOfRange { field: "guards" });
        }
        if self.lifetime == 0 || self.lifetime > MAX_GUARD_LIFETIME {
            return Err(CodecError::ValueOutOfRange { field: "lifetime" });
        }
        if self.renew_every == 0 || self.renew_every >= self.lifetime {
            return Err(CodecError::ValueOutOfRange {
                field: "renew_every",
            });
        }
        Ok(())
    }
}

impl Default for GuardBounds {
    /// 64 guards, a two second lease renewed every half second, durable.
    fn default() -> Self {
        Self {
            guards: 64,
            lifetime: 2_000_000_000,
            renew_every: 500_000_000,
            profile: Profile::Durable,
        }
    }
}

/// A guard entry, schema 6 version 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GuardEntry {
    /// The table's bounds.
    Bounds(GuardBounds),
    /// A guard is defined, closed.
    Define {
        /// The guard.
        guard: u64,
        /// Its policy version.
        policy: u32,
    },
    /// A close decision.
    Close {
        /// The guard.
        guard: u64,
        /// The operation id, for retries and audit.
        operation: u64,
        /// The requester, for audit.
        requester: u64,
        /// The reason, for audit.
        reason: u32,
    },
    /// A reopen of the close whose fence it names.
    Reopen {
        /// The guard.
        guard: u64,
        /// The fence of the close it lifts.
        fence: u64,
        /// The operation id.
        operation: u64,
        /// The requester.
        requester: u64,
        /// The reason.
        reason: u32,
    },
    /// A lease renewal, issued at the proposer's clock.
    Renew {
        /// The proposer's clock at the proposal.
        issued: u64,
    },
}

fn nonzero(field: &'static str, value: u64) -> Result<u64, CodecError> {
    if value == 0 {
        Err(CodecError::ValueOutOfRange { field })
    } else {
        Ok(value)
    }
}

fn nonzero32(field: &'static str, value: u32) -> Result<u32, CodecError> {
    if value == 0 {
        Err(CodecError::ValueOutOfRange { field })
    } else {
        Ok(value)
    }
}

fn reason(value: u32) -> Result<u32, CodecError> {
    if value == 0 || value == LAPSE_REASON {
        Err(CodecError::ValueOutOfRange { field: "reason" })
    } else {
        Ok(value)
    }
}

impl GuardEntry {
    /// Encodes into `out`; returns the message's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] for a short `out`, and
    /// [`CodecError::ValueOutOfRange`] for a field the schema refuses.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        match *self {
            Self::Bounds(bounds) => {
                bounds.check()?;
                let mut e = Encoder::new(out, &GUARD_BOUNDS)?;
                e.u32(0, bounds.guards)?;
                e.u64(4, bounds.lifetime)?;
                e.u64(12, bounds.renew_every)?;
                e.u8(20, bounds.profile.code())?;
                e.finish()
            }
            Self::Define { guard, policy } => {
                let mut e = Encoder::new(out, &DEFINE)?;
                e.u64(0, nonzero("guard", guard)?)?;
                e.u32(8, nonzero32("policy", policy)?)?;
                e.finish()
            }
            Self::Close {
                guard,
                operation,
                requester,
                reason: why,
            } => {
                let mut e = Encoder::new(out, &CLOSE)?;
                e.u64(0, nonzero("guard", guard)?)?;
                e.u64(8, nonzero("operation", operation)?)?;
                e.u64(16, nonzero("requester", requester)?)?;
                e.u32(24, reason(why)?)?;
                e.finish()
            }
            Self::Reopen {
                guard,
                fence,
                operation,
                requester,
                reason: why,
            } => {
                let mut e = Encoder::new(out, &REOPEN)?;
                e.u64(0, nonzero("guard", guard)?)?;
                e.u64(8, nonzero("fence", fence)?)?;
                e.u64(16, nonzero("operation", operation)?)?;
                e.u64(24, nonzero("requester", requester)?)?;
                e.u32(32, reason(why)?)?;
                e.finish()
            }
            Self::Renew { issued } => {
                let mut e = Encoder::new(out, &RENEW)?;
                e.u64(0, nonzero("issued", issued)?)?;
                e.finish()
            }
        }
    }

    /// The message's bytes.
    ///
    /// # Errors
    ///
    /// As [`GuardEntry::encode`], but never `Truncated`.
    pub fn to_vec(&self) -> Result<Vec<u8>, CodecError> {
        let mut out = vec![0; usize::try_from(REOPEN.max_length).unwrap_or(usize::MAX)];
        let length = self.encode(&mut out)?;
        out.truncate(length);
        Ok(out)
    }

    /// Decodes exactly one schema 6 version 1 message.
    ///
    /// # Errors
    ///
    /// [`CodecError::UnsupportedSchema`] for any other tuple,
    /// [`CodecError::ValueOutOfRange`] for a field the schema refuses, and
    /// every other [`CodecError`] the envelope can raise.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let envelope = karyos_codec::Envelope::read(bytes)?;
        let unsupported = CodecError::UnsupportedSchema {
            schema: envelope.schema_id,
            template: envelope.template_id,
            version: envelope.version,
        };
        if envelope.schema_id != GUARD_SCHEMA_ID || envelope.version != GUARD_VERSION {
            return Err(unsupported);
        }
        let template = match envelope.template_id {
            1 => &GUARD_BOUNDS,
            2 => &DEFINE,
            3 => &CLOSE,
            4 => &REOPEN,
            5 => &RENEW,
            _ => return Err(unsupported),
        };
        let (b, decoder) = Decoder::new(bytes, template)?;
        let entry = match envelope.template_id {
            1 => {
                let bounds = GuardBounds {
                    guards: b.u32(0)?,
                    lifetime: b.u64(4)?,
                    renew_every: b.u64(12)?,
                    profile: Profile::from_code(b.u8(20)?)?,
                };
                bounds.check()?;
                Self::Bounds(bounds)
            }
            2 => Self::Define {
                guard: nonzero("guard", b.u64(0)?)?,
                policy: nonzero32("policy", b.u32(8)?)?,
            },
            3 => Self::Close {
                guard: nonzero("guard", b.u64(0)?)?,
                operation: nonzero("operation", b.u64(8)?)?,
                requester: nonzero("requester", b.u64(16)?)?,
                reason: reason(b.u32(24)?)?,
            },
            4 => Self::Reopen {
                guard: nonzero("guard", b.u64(0)?)?,
                fence: nonzero("fence", b.u64(8)?)?,
                operation: nonzero("operation", b.u64(16)?)?,
                requester: nonzero("requester", b.u64(24)?)?,
                reason: reason(b.u32(32)?)?,
            },
            _ => Self::Renew {
                issued: nonzero("issued", b.u64(0)?)?,
            },
        };
        decoder.finish()?;
        Ok(entry)
    }
}

/// The authority lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Lease {
    /// No renewal has granted one yet: no reopen applies.
    NeverGranted,
    /// Granted until `until`, by a renewal `issued` then.
    Active {
        /// The granting renewal's `issued`.
        issued: u64,
        /// `issued + lifetime`.
        until: u64,
    },
    /// Expired at `until`; a later grant ends it.
    Lapsed {
        /// The last grant's `issued`.
        issued: u64,
        /// The time it expired.
        until: u64,
    },
}

/// A transition's audit record.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Audit {
    /// The operation id; 0 for a lapse.
    pub operation: u64,
    /// The requester; 0 for a lapse.
    pub requester: u64,
    /// The reason; [`LAPSE_REASON`] for a lapse.
    pub reason: u32,
    /// The entry's log index.
    pub index: u64,
}

/// One guard of the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Guard {
    /// Its id.
    pub guard: u64,
    /// Its epoch: odd `Closed`, even `Open`.
    pub epoch: u64,
    /// Its close decisions, from 1.
    pub fence: u64,
    /// Its policy version.
    pub policy: u32,
    /// The last operator operation applied to it, for retries; 0 before
    /// the first.
    pub retry: u64,
    /// The last transition's audit record; all zero before the first.
    pub last: Audit,
}

impl Guard {
    /// Whether it is open.
    #[must_use]
    pub const fn open(&self) -> bool {
        self.epoch.is_multiple_of(2)
    }
}

/// Why an entry changed nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// No `GuardBounds` has applied.
    NoBounds,
    /// The guard is not defined.
    Undefined,
    /// The table is full.
    GuardsFull,
    /// A reopen names a fence that is not the guard's, or the guard is
    /// open.
    Stale,
    /// A reopen while the lease is not active.
    NoAuthority,
    /// A reopen under a volatile profile.
    NotDurable,
    /// A reopen that would pass [`MAX_EPOCH`], or names a saturated fence.
    GuardExhausted,
}

/// What a guard entry did, besides its effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GuardOutcome {
    /// The bounds applied, or equalled those already logged.
    Bounds,
    /// The entry changed its guard, or granted the lease.
    Accepted,
    /// A retry of the guard's last operation: nothing changed.
    Retry,
    /// A renewal that grants nothing new.
    NotGranted,
    /// It changed nothing, for this reason.
    Refused(Refusal),
}

/// One change an entry made, in order: the host hands each to its driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum GuardEffect {
    /// A guard's new state.
    Guard {
        /// The guard as it now is.
        guard: Guard,
        /// The entry's log index.
        index: u64,
        /// The log time.
        log_time: u64,
    },
    /// The lease's new state.
    Lease {
        /// The lease as it now is.
        lease: Lease,
        /// The entry's log index.
        index: u64,
        /// The log time.
        log_time: u64,
    },
}

/// A guard entry the table cannot apply: a safety stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum GuardStop {
    /// The logged bounds differ from this replica's configuration.
    #[error("the logged guard bounds {logged:?} differ from this replica's {configured:?}")]
    BoundsDiffer {
        /// The bounds the log carries.
        logged: GuardBounds,
        /// This replica's.
        configured: GuardBounds,
    },
    /// A lease sum overflowed.
    #[error("a lease time overflowed")]
    Overflow,
}

/// The guard table (see the module).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GuardTable {
    configured: GuardBounds,
    logged: bool,
    guards: Vec<Guard>,
    lease: Lease,
    effects: Vec<GuardEffect>,
}

impl GuardTable {
    /// An empty table for this replica's configured `bounds`, every guard
    /// slot and effect slot allocated.
    #[must_use]
    pub fn new(bounds: GuardBounds) -> Self {
        let capacity = usize::try_from(bounds.guards).unwrap_or(0);
        Self {
            configured: bounds,
            logged: false,
            guards: Vec::with_capacity(capacity),
            lease: Lease::NeverGranted,
            effects: Vec::with_capacity(capacity.saturating_add(2)),
        }
    }

    /// The configured bounds.
    #[must_use]
    pub const fn bounds(&self) -> GuardBounds {
        self.configured
    }

    /// Whether the log's `GuardBounds` has applied.
    #[must_use]
    pub const fn bounds_logged(&self) -> bool {
        self.logged
    }

    /// The guards, sorted by id.
    #[must_use]
    pub fn guards(&self) -> &[Guard] {
        &self.guards
    }

    /// The guard `guard`, if defined.
    #[must_use]
    pub fn guard(&self, guard: u64) -> Option<&Guard> {
        self.slot(guard).ok().and_then(|at| self.guards.get(at))
    }

    /// The lease.
    #[must_use]
    pub const fn lease(&self) -> Lease {
        self.lease
    }

    /// The effects of the last applied entry, in order.
    #[must_use]
    pub fn effects(&self) -> &[GuardEffect] {
        &self.effects
    }

    fn slot(&self, guard: u64) -> Result<usize, usize> {
        self.guards.binary_search_by_key(&guard, |g| g.guard)
    }

    fn effect_of(&mut self, at: usize, index: u64, log_time: u64) {
        if let Some(&guard) = self.guards.get(at) {
            self.effects.push(GuardEffect::Guard {
                guard,
                index,
                log_time,
            });
        }
    }

    /// Applies `entry`, the log entry at `index`, at `log_time` (the
    /// container's log time once the entry's event time is observed).
    ///
    /// # Errors
    ///
    /// [`GuardStop`]: a safety stop, nothing changed.
    pub fn apply(
        &mut self,
        entry: GuardEntry,
        index: u64,
        log_time: u64,
    ) -> Result<GuardOutcome, GuardStop> {
        // Every check that can stop, before any change: a stop applies
        // nothing, effects included.
        if let GuardEntry::Bounds(logged) = entry
            && logged != self.configured
        {
            return Err(GuardStop::BoundsDiffer {
                logged,
                configured: self.configured,
            });
        }
        if let GuardEntry::Renew { issued } = entry {
            let _ = issued
                .checked_add(self.configured.lifetime)
                .ok_or(GuardStop::Overflow)?;
        }
        self.effects.clear();
        if !self.logged && !matches!(entry, GuardEntry::Bounds(_)) {
            return Ok(GuardOutcome::Refused(Refusal::NoBounds));
        }
        let lease_before = self.lease;
        self.lapse(index, log_time);
        let outcome = match entry {
            GuardEntry::Bounds(_) => {
                self.logged = true;
                GuardOutcome::Bounds
            }
            GuardEntry::Define { guard, policy } => match self.slot(guard) {
                Ok(_) => GuardOutcome::Retry,
                Err(_)
                    if self.guards.len()
                        >= usize::try_from(self.configured.guards).unwrap_or(0) =>
                {
                    GuardOutcome::Refused(Refusal::GuardsFull)
                }
                Err(at) => {
                    self.guards.insert(
                        at,
                        Guard {
                            guard,
                            epoch: 1,
                            fence: 1,
                            policy,
                            retry: 0,
                            last: Audit::default(),
                        },
                    );
                    self.effect_of(at, index, log_time);
                    GuardOutcome::Accepted
                }
            },
            GuardEntry::Close {
                guard,
                operation,
                requester,
                reason,
            } => match self.slot(guard) {
                Err(_) => GuardOutcome::Refused(Refusal::Undefined),
                Ok(at) => {
                    let Some(g) = self.guards.get_mut(at) else {
                        return Ok(GuardOutcome::Refused(Refusal::Undefined));
                    };
                    if g.retry == operation {
                        GuardOutcome::Retry
                    } else {
                        g.retry = operation;
                        g.fence = g.fence.saturating_add(1);
                        if g.open() {
                            g.epoch += 1;
                        }
                        g.last = Audit {
                            operation,
                            requester,
                            reason,
                            index,
                        };
                        self.effect_of(at, index, log_time);
                        GuardOutcome::Accepted
                    }
                }
            },
            GuardEntry::Reopen {
                guard,
                fence,
                operation,
                requester,
                reason,
            } => {
                let active = matches!(self.lease, Lease::Active { until, .. } if log_time < until);
                let durable = self.configured.profile == Profile::Durable;
                match self.slot(guard) {
                    Err(_) => GuardOutcome::Refused(Refusal::Undefined),
                    Ok(at) => {
                        let Some(g) = self.guards.get_mut(at) else {
                            return Ok(GuardOutcome::Refused(Refusal::Undefined));
                        };
                        if g.retry == operation {
                            GuardOutcome::Retry
                        } else if !durable {
                            GuardOutcome::Refused(Refusal::NotDurable)
                        } else if !active {
                            GuardOutcome::Refused(Refusal::NoAuthority)
                        } else if g.fence == u64::MAX || g.epoch >= MAX_EPOCH {
                            GuardOutcome::Refused(Refusal::GuardExhausted)
                        } else if g.open() || g.fence != fence {
                            GuardOutcome::Refused(Refusal::Stale)
                        } else {
                            g.retry = operation;
                            g.epoch += 1;
                            g.last = Audit {
                                operation,
                                requester,
                                reason,
                                index,
                            };
                            self.effect_of(at, index, log_time);
                            GuardOutcome::Accepted
                        }
                    }
                }
            }
            GuardEntry::Renew { issued } => {
                let grant = issued
                    .checked_add(self.configured.lifetime)
                    .ok_or(GuardStop::Overflow)?;
                let later = match self.lease {
                    Lease::Active { until, .. } => grant > until,
                    Lease::NeverGranted | Lease::Lapsed { .. } => true,
                };
                if grant > log_time && later {
                    self.lease = Lease::Active {
                        issued,
                        until: grant,
                    };
                    GuardOutcome::Accepted
                } else {
                    GuardOutcome::NotGranted
                }
            }
        };
        // One final lease effect, after the lapse's guard changes and the
        // entry's own, when the lease changed (design §7).
        if self.lease != lease_before {
            self.effects.push(GuardEffect::Lease {
                lease: self.lease,
                index,
                log_time,
            });
        }
        Ok(outcome)
    }

    /// The lapse rule: an active lease at or past its `until` lapses,
    /// closing every open guard and raising every fence, one effect per
    /// guard in order; the lease's effect is the entry's final one.
    fn lapse(&mut self, index: u64, log_time: u64) {
        let Lease::Active { issued, until } = self.lease else {
            return;
        };
        if log_time < until {
            return;
        }
        self.lease = Lease::Lapsed { issued, until };
        for at in 0..self.guards.len() {
            if let Some(g) = self.guards.get_mut(at) {
                g.fence = g.fence.saturating_add(1);
                if g.open() {
                    g.epoch += 1;
                }
                g.last = Audit {
                    operation: 0,
                    requester: 0,
                    reason: LAPSE_REASON,
                    index,
                };
            }
            self.effect_of(at, index, log_time);
        }
    }
}

/// The snapshot section's version.
pub const SECTION_VERSION: u64 = 1;
const HEAD: usize = 21 + 1 + 8 + 8 + 4;
const RECORD: usize = 8 + 8 + 8 + 4 + 8 + 8 + 8 + 4 + 8;

/// Why a guard section is refused, whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SectionError {
    /// A section version this replica does not read.
    #[error("guard section version {0} is not read")]
    Version(u64),
    /// Its length is not its count's.
    #[error("the section's length does not match its count")]
    Length,
    /// Its bounds are not valid, or differ from this replica's.
    #[error("the section's bounds are invalid or differ")]
    Bounds,
    /// The lease is not a reachable state.
    #[error("the section's lease is not reachable")]
    Lease,
    /// A guard record is not a reachable state, or out of order.
    #[error("guard record {0} is not reachable")]
    Guard(usize),
}

fn put(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(bytes);
}

impl GuardTable {
    /// The table as a snapshot section's bytes (`SectionKind::Guards`,
    /// version [`SECTION_VERSION`]); `None` before the log's bounds apply.
    #[must_use]
    pub fn section(&self) -> Option<Vec<u8>> {
        // No section before the log's bounds: a restored table would take
        // guard entries the log has not bounded yet.
        if !self.logged {
            return None;
        }
        let mut out = Vec::with_capacity(HEAD + RECORD * self.guards.len());
        let b = self.configured;
        put(&mut out, &b.guards.to_le_bytes());
        put(&mut out, &b.lifetime.to_le_bytes());
        put(&mut out, &b.renew_every.to_le_bytes());
        out.push(b.profile.code());
        let (state, issued, until) = match self.lease {
            Lease::NeverGranted => (0u8, 0, 0),
            Lease::Active { issued, until } => (1, issued, until),
            Lease::Lapsed { issued, until } => (2, issued, until),
        };
        out.push(state);
        put(&mut out, &issued.to_le_bytes());
        put(&mut out, &until.to_le_bytes());
        put(
            &mut out,
            &u32::try_from(self.guards.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        for g in &self.guards {
            put(&mut out, &g.guard.to_le_bytes());
            put(&mut out, &g.epoch.to_le_bytes());
            put(&mut out, &g.fence.to_le_bytes());
            put(&mut out, &g.policy.to_le_bytes());
            put(&mut out, &g.retry.to_le_bytes());
            put(&mut out, &g.last.operation.to_le_bytes());
            put(&mut out, &g.last.requester.to_le_bytes());
            put(&mut out, &g.last.reason.to_le_bytes());
            put(&mut out, &g.last.index.to_le_bytes());
        }
        Some(out)
    }

    /// A table restored from a section of `version` and `bytes`, for this
    /// replica's `bounds`, in a snapshot at `index` whose log time is
    /// `log_time`:
    /// validated whole, then built in one step.
    ///
    /// # Errors
    ///
    /// [`SectionError`]: nothing is restored.
    pub fn restore(
        version: u64,
        bytes: &[u8],
        bounds: GuardBounds,
        index: u64,
        log_time: u64,
    ) -> Result<Self, SectionError> {
        if version != SECTION_VERSION {
            return Err(SectionError::Version(version));
        }
        let mut at = 0usize;
        let mut take = |n: usize| -> Result<&[u8], SectionError> {
            let end = at.checked_add(n).ok_or(SectionError::Length)?;
            let slice = bytes.get(at..end).ok_or(SectionError::Length)?;
            at = end;
            Ok(slice)
        };
        let u64_ = |s: &[u8]| u64::from_le_bytes(s.try_into().unwrap_or([0; 8]));
        let u32_ = |s: &[u8]| u32::from_le_bytes(s.try_into().unwrap_or([0; 4]));
        let logged = GuardBounds {
            guards: u32_(take(4)?),
            lifetime: u64_(take(8)?),
            renew_every: u64_(take(8)?),
            profile: Profile::from_code(take(1)?.first().copied().unwrap_or(0))
                .map_err(|_| SectionError::Bounds)?,
        };
        if logged.check().is_err() || logged != bounds {
            return Err(SectionError::Bounds);
        }
        let state = take(1)?.first().copied().unwrap_or(u8::MAX);
        let issued = u64_(take(8)?);
        let until = u64_(take(8)?);
        let lease = match state {
            0 if issued == 0 && until == 0 => Lease::NeverGranted,
            1 | 2 if issued > 0 && issued.checked_add(bounds.lifetime) == Some(until) => {
                if state == 1 {
                    Lease::Active { issued, until }
                } else if until <= log_time {
                    Lease::Lapsed { issued, until }
                } else {
                    return Err(SectionError::Lease);
                }
            }
            _ => return Err(SectionError::Lease),
        };
        let count = usize::try_from(u32_(take(4)?)).map_err(|_| SectionError::Length)?;
        if count > usize::try_from(bounds.guards).unwrap_or(0) {
            return Err(SectionError::Length);
        }
        if bytes.len() != HEAD + RECORD * count {
            return Err(SectionError::Length);
        }
        let mut table = Self::new(bounds);
        table.logged = true;
        table.lease = lease;
        let mut previous = 0u64;
        for n in 0..count {
            let g = Guard {
                guard: u64_(take(8)?),
                epoch: u64_(take(8)?),
                fence: u64_(take(8)?),
                policy: u32_(take(4)?),
                retry: u64_(take(8)?),
                last: Audit {
                    operation: u64_(take(8)?),
                    requester: u64_(take(8)?),
                    reason: u32_(take(4)?),
                    index: u64_(take(8)?),
                },
            };
            let fresh = g.last == Audit::default();
            let lapse = g.last.reason == LAPSE_REASON;
            let audit = if fresh {
                g.fence == 1 && g.epoch == 1 && g.retry == 0
            } else {
                g.last.reason != 0
                    && g.last.index != 0
                    && g.last.index <= index
                    && if lapse {
                        g.last.operation == 0 && g.last.requester == 0
                    } else {
                        g.last.operation != 0 && g.last.requester != 0
                    }
            };
            let reachable = g.guard > previous
                && (1..=MAX_EPOCH).contains(&g.epoch)
                && g.fence >= 1
                && !(g.open() && (g.fence == u64::MAX || !matches!(lease, Lease::Active { .. })))
                && audit;
            if !reachable {
                return Err(SectionError::Guard(n));
            }
            previous = g.guard;
            table.guards.push(g);
        }
        Ok(table)
    }
}
