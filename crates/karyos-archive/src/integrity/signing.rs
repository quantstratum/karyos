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
//! once it exceeds `anchor_interval`, which is required configuration with
//! no default (X14).

use std::collections::VecDeque;
use std::num::{NonZeroU64, NonZeroUsize};

use super::Digest;
use super::trust::{ChainHead, Custody, SIGNATURE_LENGTH, SignedHead};

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
    /// How long since the last signed head, or since signing started if
    /// none was signed yet, in ns.
    pub coverage_lag_ns: u64,
    /// Whether the lag exceeds `anchor_interval`.
    pub alarm: bool,
    /// Heads waiting for the signer.
    pub pending: u64,
    /// Heads replaced by a later one.
    pub coalesced: u64,
    /// Heads refused because the backlog was full.
    pub refused: u64,
    /// The counter of the last signed head.
    pub last_signed: Option<u64>,
}

/// The bounded queue of heads to sign.
#[derive(Debug, Clone)]
pub struct HeadSigning {
    config: SigningConfig,
    pending: VecDeque<ChainHead>,
    signed: Vec<SignedHead>,
    started_ns: u64,
    last_signed_ns: Option<u64>,
    coalesced: u64,
    refused: u64,
}

impl HeadSigning {
    /// Signing that started at `now_ns`.
    #[must_use]
    pub const fn new(config: SigningConfig, now_ns: u64) -> Self {
        Self {
            config,
            pending: VecDeque::new(),
            signed: Vec::new(),
            started_ns: now_ns,
            last_signed_ns: None,
            coalesced: 0,
            refused: 0,
        }
    }

    /// Offers a new head. Never blocks and never calls the signer.
    pub fn offer(&mut self, head: ChainHead) -> Offered {
        match self.config.policy {
            BacklogPolicy::Coalesce => {
                let replaced = self.pending.pop_back().is_some();
                self.pending.clear();
                self.pending.push_back(head);
                if replaced {
                    self.coalesced = self.coalesced.saturating_add(1);
                    Offered::Coalesced
                } else {
                    Offered::Queued
                }
            }
            BacklogPolicy::Refuse { capacity } => {
                if self.pending.len() >= capacity.get() {
                    self.refused = self.refused.saturating_add(1);
                    Offered::Refused
                } else {
                    self.pending.push_back(head);
                    Offered::Queued
                }
            }
        }
    }

    /// Asks `signer` for every pending head, oldest first, stopping at the
    /// first that it cannot sign. Returns the heads signed.
    pub fn poll(&mut self, signer: &mut impl HeadSigner, now_ns: u64) -> u64 {
        let mut signed = 0u64;
        while let Some(head) = self.pending.front().copied() {
            let Ok(signature) = signer.sign(&head) else {
                break;
            };
            self.pending.pop_front();
            self.signed.push(SignedHead {
                head,
                key_id: signer.key_id(),
                custody: signer.custody(),
                signature,
            });
            self.last_signed_ns = Some(now_ns);
            signed = signed.saturating_add(1);
        }
        signed
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
    pub fn status(&self, now_ns: u64, sealed_records: u64) -> SigningStatus {
        let last_signed = self.signed.last().map(|signed| signed.head.counter);
        let covered = last_signed.map_or(0, |counter| counter.saturating_add(1));
        let since = self.last_signed_ns.unwrap_or(self.started_ns);
        let coverage_lag_ns = now_ns.saturating_sub(since);
        let coverage_lag_records = sealed_records.saturating_sub(covered);
        SigningStatus {
            coverage_lag_records,
            coverage_lag_ns,
            alarm: coverage_lag_records > 0
                && coverage_lag_ns > self.config.anchor_interval_ns.get(),
            pending: u64::try_from(self.pending.len()).unwrap_or(u64::MAX),
            coalesced: self.coalesced,
            refused: self.refused,
            last_signed,
        }
    }
}
