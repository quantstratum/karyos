// SPDX-License-Identifier: Apache-2.0

//! Refresh and snapshot cycles a publication runs on a conflated lane
//! (`quantstratum-docs: karyos/adr/0080-conflation-refresh-cycles-in-band.md`;
//! karyos#634): the begin marker, the refresh values and the end marker,
//! carried in ordinary messages through their reserved value. The
//! application decides when to run a cycle and which keys it carries; a
//! view whose table opts in (`ConflationConfig::refresh`) turns every key a
//! complete cycle carried `Fresh`, and an incomplete cycle restores none.
//!
//! Each step offers one message. A return other than `Accepted` appended
//! nothing: retry the same step. A cycle abandoned before its end has no
//! end marker, and the next begin aborts it at every receiver.

use karyos_sys::conflation::cycle::{self, Marker};
use karyos_sys::log_buffer::AppendOptions;
use karyos_sys::term_bytes::TermBytes;

pub use karyos_sys::conflation::cycle::{CycleId, Scope};

use crate::error::ClientError;
use crate::publication::{ClientPublication, OfferOutcome};

/// Why a cycle step was refused before anything was offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CycleError {
    /// A value or the end before the begin marker was accepted, or a
    /// second begin.
    #[error("the refresh cycle step is out of order")]
    OutOfOrder,
    /// The key is the marker's key field, never a key.
    #[error("key {key} cannot be refreshed")]
    InvalidKey {
        /// The refused key.
        key: u32,
    },
    /// The offer failed.
    #[error(transparent)]
    Client(#[from] ClientError),
}

/// One refresh or snapshot cycle of a publication's conflated lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshCycle {
    id: CycleId,
    scope: Scope,
    /// The begin marker's position, once accepted.
    begin: Option<u64>,
    /// Refresh values accepted.
    values: u64,
    ended: bool,
}

impl RefreshCycle {
    /// A cycle `id` of `scope`. A publisher takes the next id for each
    /// cycle ([`CycleId::next`]); receivers compare ids only for equality.
    #[must_use]
    pub const fn new(id: CycleId, scope: Scope) -> Self {
        Self {
            id,
            scope,
            begin: None,
            values: 0,
            ended: false,
        }
    }

    /// The cycle's id.
    #[must_use]
    pub const fn id(&self) -> CycleId {
        self.id
    }

    /// The begin marker's position, once it was accepted.
    #[must_use]
    pub const fn begin_position(&self) -> Option<u64> {
        self.begin
    }

    /// The refresh values accepted so far.
    #[must_use]
    pub const fn values(&self) -> u64 {
        self.values
    }

    /// Offers the begin marker on `lane`.
    ///
    /// # Errors
    ///
    /// [`CycleError::OutOfOrder`] once the begin was accepted, and the
    /// offer's errors.
    pub fn begin<T: TermBytes>(
        &mut self,
        lane: &mut ClientPublication<T>,
    ) -> Result<OfferOutcome, CycleError> {
        if self.begin.is_some() || self.ended {
            return Err(CycleError::OutOfOrder);
        }
        let marker = Marker::Begin { scope: self.scope }.encode();
        let outcome = lane.offer_with(&marker, Self::options(cycle::marker(self.id)))?;
        if let OfferOutcome::Accepted { position, .. } = outcome {
            self.begin = Some(position);
        }
        Ok(outcome)
    }

    /// Offers the refresh value of `key` on `lane`; an accepted one counts.
    ///
    /// # Errors
    ///
    /// [`CycleError::OutOfOrder`] before the begin or after the end,
    /// [`CycleError::InvalidKey`] for [`cycle::MARKER_KEY`], and the
    /// offer's errors (a key outside the lane's table among them).
    pub fn offer<T: TermBytes>(
        &mut self,
        lane: &mut ClientPublication<T>,
        key: u32,
        value: &[u8],
    ) -> Result<OfferOutcome, CycleError> {
        if self.begin.is_none() || self.ended {
            return Err(CycleError::OutOfOrder);
        }
        let reserved = cycle::value(self.id, key).ok_or(CycleError::InvalidKey { key })?;
        let outcome = lane.offer_with(value, Self::options(reserved))?;
        if matches!(outcome, OfferOutcome::Accepted { .. }) {
            self.values = self.values.saturating_add(1);
        }
        Ok(outcome)
    }

    /// Offers the end marker on `lane`, with the begin's position and the
    /// count of values; once accepted the cycle is over.
    ///
    /// # Errors
    ///
    /// [`CycleError::OutOfOrder`] before the begin or after the end, and
    /// the offer's errors.
    pub fn end<T: TermBytes>(
        &mut self,
        lane: &mut ClientPublication<T>,
    ) -> Result<OfferOutcome, CycleError> {
        let Some(begin) = self.begin.filter(|_| !self.ended) else {
            return Err(CycleError::OutOfOrder);
        };
        let marker = Marker::End {
            scope: self.scope,
            begin,
            values: self.values,
        }
        .encode();
        let outcome = lane.offer_with(&marker, Self::options(cycle::marker(self.id)))?;
        if matches!(outcome, OfferOutcome::Accepted { .. }) {
            self.ended = true;
        }
        Ok(outcome)
    }

    fn options(reserved_value: i64) -> AppendOptions {
        AppendOptions {
            reserved_value,
            ..AppendOptions::default()
        }
    }
}
