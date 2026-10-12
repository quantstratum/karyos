// SPDX-License-Identifier: Apache-2.0

//! The embedded publication (SPEC.md §4 and §10, `offer`).

use std::sync::Arc;

use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{AppendOptions, AppendOutcome, LogBuffer, Publication};

use crate::error::ClientError;
use crate::link::Origin;

/// Result of an offer. Each call performs at most one append attempt:
/// padding, rotation and waiting for the driver are reported to the caller
/// as [`OfferOutcome::AdminAction`] and never retried silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "back pressure and admin actions must be handled"]
pub enum OfferOutcome {
    /// The message was accepted into the local publication log at
    /// `position` in `lane`. Positions are per lane, so the pair identifies
    /// the message. Acceptance is local only: it does not imply backend
    /// submission, wire transmission, receiver delivery, archive durability
    /// or Cluster commitment (SPEC.md §10).
    Accepted {
        /// The lane the message was appended to.
        lane: Lane,
        /// Position of the message in that lane.
        position: u64,
    },
    /// The flow-control limit does not admit the message; retry later.
    BackPressured,
    /// The offer only padded or rotated, or waits for the driver; retry.
    AdminAction,
    /// No subscriber is attached and the publication does not allow
    /// unconnected offers (SPEC.md §4 connection rule).
    NotConnected,
}

/// An exclusive publication on one stream.
#[derive(Debug)]
pub struct ClientPublication {
    inner: Publication<Arc<LogBuffer>>,
    allow_unconnected: bool,
    origin: Option<Origin>,
}

impl ClientPublication {
    /// Wraps the buffer's publication. Connectivity, limits and the lane
    /// are read from the buffer the publication itself appends to.
    #[must_use]
    pub fn new(inner: Publication<Arc<LogBuffer>>, allow_unconnected: bool) -> Self {
        Self {
            inner,
            allow_unconnected,
            origin: None,
        }
    }

    /// Wraps a publication handed over through a client conductor; the
    /// handle keeps the stream's lease until it is dropped.
    #[must_use]
    pub fn from_hand_over(
        inner: Publication<Arc<LogBuffer>>,
        allow_unconnected: bool,
        origin: Origin,
    ) -> Self {
        Self {
            inner,
            allow_unconnected,
            origin: Some(origin),
        }
    }

    /// The owner and registration, for a handle from a client conductor.
    #[must_use]
    pub fn origin(&self) -> Option<&Origin> {
        self.origin.as_ref()
    }

    /// Largest message accepted without a trace extension.
    #[inline]
    #[must_use]
    pub fn max_message_length(&self) -> u32 {
        self.inner.buffer().max_message_length()
    }

    /// Offers one message.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::EmptyMessage`], [`ClientError::MessageTooLarge`]
    /// and lower-layer errors; nothing is published on error.
    pub fn offer(&mut self, payload: &[u8]) -> Result<OfferOutcome, ClientError> {
        self.offer_with(payload, AppendOptions::default())
    }

    /// Offers one message with header options (EOS, reserved value, an
    /// opaque trace extension).
    ///
    /// # Errors
    ///
    /// As [`ClientPublication::offer`].
    pub fn offer_with(
        &mut self,
        payload: &[u8],
        options: AppendOptions,
    ) -> Result<OfferOutcome, ClientError> {
        if !self.allow_unconnected && self.inner.buffer().attached_subscribers() == 0 {
            return Ok(OfferOutcome::NotConnected);
        }
        Ok(match self.inner.append(payload, options)? {
            AppendOutcome::Appended { position } => OfferOutcome::Accepted {
                lane: self.inner.buffer().lane(),
                position,
            },
            AppendOutcome::BackPressured => OfferOutcome::BackPressured,
            AppendOutcome::AdminAction => OfferOutcome::AdminAction,
        })
    }
}
