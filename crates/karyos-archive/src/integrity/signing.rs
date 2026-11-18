// SPDX-License-Identifier: Apache-2.0

//! Asking for signed heads without ever waiting on the signer
//! (quantstratum-docs: karyos/SPEC.md §8.4, "Signed heads and custody";
//! ADR-0051 item 5; karyos#663).
//!
//! Sealing never calls the signer. The Archive offers each new chain head
//! to [`HeadSigning`], a bounded queue on the control path, and a separate
//! [`HeadSigning::poll`] asks the [`HeadSigner`]. If the signer is
//! unavailable, sealing continues and anchoring falls behind: pending
//! state is bounded by the [`BacklogPolicy`] (coalesce to the latest
//! unsent head, or refuse an offer visibly), the coverage lag is reported
//! even before the first signed head, and [`SigningStatus::alarm`] is set
//! once the oldest record outside signed coverage has waited longer than
//! `anchor_interval`, which is required configuration with no default
//! (X14).
//!
//! A head counts as signed only once a [`HeadStore`] has recorded it
//! durably: the Archive records its signed heads, so a signature that was
//! never stored is never reported as coverage.

use std::collections::VecDeque;
use std::num::{NonZeroU64, NonZeroUsize};

use super::journal::IntegrityError;
use super::ledger::Ledger;
use super::trust::{
    ChainHead, Custody, HeadVerdict, KeyRegistry, SIGNATURE_LENGTH, SIGNED_HEAD_LENGTH, SignedHead,
};
use super::{Digest, SealRecord};
use crate::disk::Disk;

/// The signer is unavailable; the head stays pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the archival signer is unavailable")]
pub struct SignerUnavailable;

/// A signer of chain heads, run by the operator off the Archive host or
/// in a key service. It is only ever asked to sign a [`ChainHead`], so an
/// archival key cannot be made to sign anything else through it.
pub trait HeadSigner {
    /// The id of the key it signs with.
    fn key_id(&self) -> Digest;

    /// The custody it declares.
    fn custody(&self) -> Custody;

    /// Signs `head`'s signed bytes under the custody it declares,
    /// `head.signed_bytes(self.custody())`.
    ///
    /// # Errors
    ///
    /// [`SignerUnavailable`] when it cannot sign now.
    fn sign(&mut self, head: &ChainHead) -> Result<[u8; SIGNATURE_LENGTH], SignerUnavailable>;
}

/// Where signed heads are recorded durably before they count as signed.
pub trait HeadStore {
    /// Records `signed` durably.
    ///
    /// # Errors
    ///
    /// The store's error; the head is not recorded then.
    fn record(&mut self, signed: &SignedHead) -> Result<(), IntegrityError>;
}

impl<D: Disk> HeadStore for Ledger<D, SIGNED_HEAD_LENGTH> {
    fn record(&mut self, signed: &SignedHead) -> Result<(), IntegrityError> {
        self.append(signed.encode())
    }
}

/// Why [`HeadSigning::poll`] stopped with heads still pending.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PollError {
    /// The signed head could not be recorded.
    #[error("recording a signed head: {0}")]
    Store(#[from] IntegrityError),
    /// The pending head is not this journal's: it names another journal
    /// or Archive, or its digest is not the chain's record at its counter.
    /// It is dropped and counted in [`SigningStatus::discarded`].
    #[error("head {counter} is not a head of this journal's chain")]
    NotInChain {
        /// The head's counter.
        counter: u64,
    },
    /// The signer returned a signature the registry does not trust (a key
    /// not registered, retired or revoked, or a signature that does not
    /// verify): it covers nothing.
    #[error("the signer's head {counter} is not trusted under the registry: {verdict:?}")]
    Untrusted {
        /// The head's counter.
        counter: u64,
        /// The registry's verdict.
        verdict: HeadVerdict,
    },
}

/// What happens to a head offered while others are pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BacklogPolicy {
    /// Keep only the latest unsent head: a later head covers every record
    /// an earlier one does.
    Coalesce,
    /// Keep up to `capacity` heads and refuse more, counting each refusal.
    Refuse {
        /// The most heads pending.
        capacity: NonZeroUsize,
    },
}

/// A configuration refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SigningConfigError {
    /// `anchor_interval` is required and has no default (X14).
    #[error("anchor_interval is not configured; it has no default")]
    AnchorIntervalUnset,
    /// `anchor_interval` is zero.
    #[error("anchor_interval must be above zero")]
    AnchorIntervalZero,
}

/// The configuration of head signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigningConfig {
    anchor_interval_ns: NonZeroU64,
    policy: BacklogPolicy,
}

impl SigningConfig {
    /// A configuration from the operator's settings: `anchor_interval_ns`
    /// is `None` when the operator did not set it.
    ///
    /// # Errors
    ///
    /// [`SigningConfigError::AnchorIntervalUnset`] when it is `None`, and
    /// [`SigningConfigError::AnchorIntervalZero`] when it is zero: an
    /// unconfigured deployment is refused, never silently unanchored.
    pub fn new(
        anchor_interval_ns: Option<u64>,
        policy: BacklogPolicy,
    ) -> Result<Self, SigningConfigError> {
        let interval = anchor_interval_ns.ok_or(SigningConfigError::AnchorIntervalUnset)?;
        let anchor_interval_ns =
            NonZeroU64::new(interval).ok_or(SigningConfigError::AnchorIntervalZero)?;
        Ok(Self {
            anchor_interval_ns,
            policy,
        })
    }

    /// The `anchor_interval`, in ns.
    #[must_use]
    #[inline]
    pub const fn anchor_interval_ns(&self) -> NonZeroU64 {
        self.anchor_interval_ns
    }
}

/// What became of an offered head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Offered {
    /// Queued.
    Queued,
    /// It replaced an unsent head.
    Coalesced,
    /// Refused: the backlog is full. Counted in [`SigningStatus::refused`].
    Refused,
}

/// The signing state at a moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigningStatus {
    /// Records sealed past the last signed head.
    pub coverage_lag_records: u64,
    /// How long the oldest record outside signed coverage has waited, in
    /// ns: since the first offer of a head not yet signed, or since the
    /// last signed head (or the start of signing) for records not offered
    /// yet. Signing an older head does not reset it while newer records
    /// remain uncovered.
    pub coverage_lag_ns: u64,
    /// Whether records remain uncovered for longer than `anchor_interval`.
    /// After a restart the age of records left uncovered is unknown, so
    /// they count as overdue until signed coverage advances.
    pub alarm: bool,
    /// Heads waiting for the signer.
    pub pending: u64,
    /// Heads replaced by a later one.
    pub coalesced: u64,
    /// Heads refused because the backlog was full.
    pub refused: u64,
    /// The counter of the last signed head.
    pub last_signed: Option<u64>,
    /// Heads not counted because they did not verify, did not belong to
    /// this journal's chain, or lost trust when the registry changed.
    pub discarded: u64,
}

/// A head waiting for the signer.
#[derive(Debug, Clone, Copy)]
struct Pending {
    head: ChainHead,
    /// When the oldest record this head covers, and no earlier pending
    /// head does, was first offered.
    since_ns: u64,
}

/// The bounded queue of heads to sign.
#[derive(Debug, Clone)]
pub struct HeadSigning {
    config: SigningConfig,
    /// The journal whose heads are signed.
    journal_id: u64,
    /// The registry's next sequence when coverage was last validated.
    registry_sequence: u64,
    pending: VecDeque<Pending>,
    /// When the first head refused since the last queued one was offered:
    /// its records stay uncovered until a later head is signed.
    refused_since_ns: Option<u64>,
    signed: Vec<SignedHead>,
    started_ns: u64,
    last_signed_ns: Option<u64>,
    /// Set on a restart to the chain's record count then: those records'
    /// age was not kept, so any of them still uncovered is overdue until
    /// signed coverage reaches this boundary.
    overdue_until: Option<u64>,
    discarded: u64,
    coalesced: u64,
    refused: u64,
}

impl HeadSigning {
    /// Signing of journal `journal_id` that started at `now_ns`.
    #[must_use]
    pub const fn new(config: SigningConfig, journal_id: u64, now_ns: u64) -> Self {
        Self {
            config,
            journal_id,
            registry_sequence: 0,
            pending: VecDeque::new(),
            refused_since_ns: None,
            signed: Vec::new(),
            started_ns: now_ns,
            last_signed_ns: None,
            overdue_until: None,
            discarded: 0,
            coalesced: 0,
            refused: 0,
        }
    }

    /// Signing resumed at `now_ns` after a restart, with `recorded` the
    /// entries of the store's ledger, oldest first, `records` the chain of
    /// journal `journal_id` and `registry` its key registry.
    ///
    /// A stored head counts as coverage only if it decodes, names this
    /// Archive and journal, matches the chain's record at its counter and
    /// verifies as trusted under `registry`; any other is counted in
    /// [`SigningStatus::discarded`] and covers nothing. Records left
    /// uncovered count as overdue until coverage advances: their age was
    /// not kept, and a restart must not reset an alarm.
    #[must_use]
    pub fn resume(
        config: SigningConfig,
        now_ns: u64,
        recorded: &[[u8; SIGNED_HEAD_LENGTH]],
        registry: &KeyRegistry,
        journal_id: u64,
        records: &[SealRecord],
    ) -> Self {
        let mut signing = Self::new(config, journal_id, now_ns);
        signing.registry_sequence = registry.next_sequence();
        signing.overdue_until = Some(u64::try_from(records.len()).unwrap_or(u64::MAX));
        for bytes in recorded {
            let valid = SignedHead::decode(bytes).ok().filter(|signed| {
                signing.in_chain(&signed.head, records) && trusted(registry, signed)
            });
            match valid {
                Some(signed) => signing.signed.push(signed),
                None => signing.discarded = signing.discarded.saturating_add(1),
            }
        }
        signing
    }

    /// Offers a new head at `now_ns`. Never blocks and never calls the
    /// signer.
    pub fn offer(&mut self, head: ChainHead, now_ns: u64) -> Offered {
        match self.config.policy {
            BacklogPolicy::Coalesce => {
                let replaced = self.pending.pop_back();
                self.pending.clear();
                self.pending.push_back(Pending {
                    head,
                    since_ns: replaced.map_or(now_ns, |old| old.since_ns),
                });
                if replaced.is_some() {
                    self.coalesced = self.coalesced.saturating_add(1);
                    Offered::Coalesced
                } else {
                    Offered::Queued
                }
            }
            BacklogPolicy::Refuse { capacity } => {
                if self.pending.len() >= capacity.get() {
                    self.refused = self.refused.saturating_add(1);
                    let _ = self.refused_since_ns.get_or_insert(now_ns);
                    Offered::Refused
                } else {
                    // The records of heads refused before this one are
                    // covered only by it: they have waited since then.
                    let since_ns = self.refused_since_ns.take().unwrap_or(now_ns);
                    self.pending.push_back(Pending { head, since_ns });
                    Offered::Queued
                }
            }
        }
    }

    /// Asks `signer` for every pending head, oldest first, stopping at the
    /// first that it cannot sign, verifies each signature under
    /// `registry` and records the head in `store` before it counts as
    /// signed. Returns the heads signed.
    ///
    /// # Errors
    ///
    /// [`PollError::Untrusted`] when the registry does not trust a
    /// signature, which is neither recorded nor counted, and
    /// [`PollError::Store`] for the store's error. The head stays pending
    /// either way, with every head after it; those recorded before stay
    /// signed.
    pub fn poll(
        &mut self,
        signer: &mut impl HeadSigner,
        store: &mut impl HeadStore,
        registry: &KeyRegistry,
        records: &[SealRecord],
        now_ns: u64,
    ) -> Result<u64, PollError> {
        if registry.next_sequence() != self.registry_sequence {
            self.revalidate(registry);
        }
        let mut signed = 0u64;
        while let Some(pending) = self.pending.front().copied() {
            if !self.in_chain(&pending.head, records) {
                let _ = self.pending.pop_front();
                self.discarded = self.discarded.saturating_add(1);
                return Err(PollError::NotInChain {
                    counter: pending.head.counter,
                });
            }
            let Ok(signature) = signer.sign(&pending.head) else {
                break;
            };
            let head = SignedHead {
                head: pending.head,
                key_id: signer.key_id(),
                custody: signer.custody(),
                signature,
            };
            let verdict = registry.verify(&head, None);
            if !matches!(verdict, HeadVerdict::Trusted { .. }) {
                return Err(PollError::Untrusted {
                    counter: head.head.counter,
                    verdict,
                });
            }
            store.record(&head)?;
            let _ = self.pending.pop_front();
            self.signed.push(head);
            self.last_signed_ns = Some(now_ns);
            signed = signed.saturating_add(1);
        }
        Ok(signed)
    }

    /// Revalidates the credited heads under `registry` after it changed
    /// (a retirement or a retrospective revocation): a head it no longer
    /// trusts covers nothing and is counted in
    /// [`SigningStatus::discarded`], and the records whose coverage was
    /// lost are overdue until signed coverage reaches them again, as their
    /// age was not kept. [`HeadSigning::poll`] does this itself when the
    /// registry it is given changed.
    pub fn revalidate(&mut self, registry: &KeyRegistry) {
        let before = covered(&self.signed);
        let count = self.signed.len();
        self.signed.retain(|signed| trusted(registry, signed));
        let dropped = count.saturating_sub(self.signed.len());
        self.discarded = self
            .discarded
            .saturating_add(u64::try_from(dropped).unwrap_or(u64::MAX));
        if covered(&self.signed) < before {
            self.overdue_until = Some(self.overdue_until.map_or(before, |until| until.max(before)));
        }
        self.registry_sequence = registry.next_sequence();
    }

    /// Whether `head` is a head of this journal's chain: this journal, the
    /// Archive and the digest of the chain's record at its counter.
    fn in_chain(&self, head: &ChainHead, records: &[SealRecord]) -> bool {
        head.journal_id == self.journal_id
            && usize::try_from(head.counter)
                .ok()
                .and_then(|index| records.get(index))
                .is_some_and(|record| record.digest() == head.digest)
    }

    /// The heads signed, oldest first.
    #[must_use]
    #[inline]
    pub fn signed(&self) -> &[SignedHead] {
        &self.signed
    }

    /// The status at `now_ns`, with `sealed_records` the integrity
    /// journal's record count. Counts saturate rather than wrap: they are
    /// a report, never a position.
    #[must_use]
    pub fn status(
        &self,
        now_ns: u64,
        sealed_records: u64,
        registry: &KeyRegistry,
    ) -> SigningStatus {
        // A registry changed since the last validation is applied here
        // too: a head it no longer trusts is not credited, and the records
        // it covered are overdue.
        let current = registry.next_sequence() == self.registry_sequence;
        let credited = covered(&self.signed);
        let last_signed = self
            .signed
            .iter()
            .filter(|signed| current || trusted(registry, signed))
            .map(|signed| signed.head.counter)
            .max();
        let covered = last_signed.map_or(0, |counter| counter.saturating_add(1));
        let lost = covered < credited;
        let since = self
            .pending
            .front()
            .map(|pending| pending.since_ns)
            .or(self.refused_since_ns)
            .or(self.last_signed_ns)
            .unwrap_or(self.started_ns);
        let coverage_lag_ns = now_ns.saturating_sub(since);
        let coverage_lag_records = sealed_records.saturating_sub(covered);
        SigningStatus {
            coverage_lag_records,
            coverage_lag_ns,
            alarm: coverage_lag_records > 0
                && (lost
                    || self.overdue_until.is_some_and(|until| covered < until)
                    || coverage_lag_ns > self.config.anchor_interval_ns.get()),
            pending: u64::try_from(self.pending.len()).unwrap_or(u64::MAX),
            coalesced: self.coalesced,
            refused: self.refused,
            last_signed,
            discarded: self.discarded,
        }
    }
}

/// The records the heads cover: one past the highest counter.
fn covered(signed: &[SignedHead]) -> u64 {
    signed
        .iter()
        .map(|signed| signed.head.counter.saturating_add(1))
        .max()
        .unwrap_or(0)
}

/// Whether `registry` trusts `signed` (its key, its signature over the
/// head under its custody, the Archive, retirement and revocation).
fn trusted(registry: &KeyRegistry, signed: &SignedHead) -> bool {
    matches!(registry.verify(signed, None), HeadVerdict::Trusted { .. })
}
