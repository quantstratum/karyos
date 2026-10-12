// SPDX-License-Identifier: Apache-2.0

//! The embedded subscription with copy delivery (SPEC.md §4 reader roles,
//! §10 `poll`).
//!
//! Each message is copied, under the log buffer's loan, into a private
//! buffer allocated when the subscription is created; the handler then runs
//! on that copy, so a slow handler never pins term memory. For a required
//! subscription the message is acknowledged only after the handler returns:
//! if the handler panics, the panic unwinds before the acknowledgement and
//! the next poll delivers the same message again. An optional subscription's
//! copy is its acknowledgement, so a failed handler is not replayed.

use std::sync::Arc;

use karyos_sys::frame::EXTENSION_LENGTH;
use karyos_sys::log_buffer::{LogBuffer, PollOutcome, Subscription};

use crate::error::ClientError;
use crate::link::{Lease, Origin};

/// Metadata delivered with each message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageInfo {
    /// Stream position of the message.
    pub position: u64,
    /// Reserved value of the first fragment.
    pub reserved_value: i64,
    /// End of stream.
    pub end_of_stream: bool,
    /// The opaque trace extension, if the message carries one.
    pub extension: Option<[u8; EXTENSION_LENGTH as usize]>,
}

/// Upper bound on whole messages delivered by one poll. Counts reassembled
/// messages, never fragments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageLimit(u32);

impl MessageLimit {
    /// A limit of `messages` whole messages; 0 makes a poll do nothing.
    #[inline]
    #[must_use]
    pub const fn new(messages: u32) -> Self {
        Self(messages)
    }

    /// The number of messages.
    #[inline]
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// A lost range reported by an optional subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Overrun {
    /// First position not delivered.
    pub from: u64,
    /// End of the range known lost (below the retention floor).
    pub lost_to: u64,
    /// Position delivery resumed from.
    pub resume: u64,
}

/// What one poll did. A poll stops at the first overrun, so no loss report
/// is ever overwritten.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PollSummary {
    /// Messages delivered to the handler (and acknowledged) before the poll
    /// stopped.
    pub delivered: u32,
    /// The overrun that stopped the poll, if any.
    pub overrun: Option<Overrun>,
}

/// A poll that failed after possibly delivering messages: `summary` reports
/// the deliveries that were handled and acknowledged before `cause`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("poll failed after {} deliveries: {cause}", summary.delivered)]
pub struct PollError {
    /// Progress made before the failure.
    pub summary: PollSummary,
    /// The failure.
    pub cause: ClientError,
}

/// A subscription on one stream.
#[derive(Debug)]
pub struct ClientSubscription {
    inner: Subscription<Arc<LogBuffer>>,
    scratch: Box<[u8]>,
    origin: Option<Origin>,
    /// The stream lease of a handle from the direct driver API, held only
    /// for its drop.
    _lease: Option<Lease>,
}

impl ClientSubscription {
    /// Wraps a log buffer subscription, allocating its private copy buffer
    /// (control path) for the largest message of the buffer it reads.
    #[must_use]
    pub fn new(inner: Subscription<Arc<LogBuffer>>) -> Self {
        let max_message_length = inner.buffer().max_message_length();
        Self {
            inner,
            scratch: vec![0u8; max_message_length as usize].into_boxed_slice(),
            origin: None,
            _lease: None,
        }
    }

    /// Wraps a subscription from the direct driver API; the handle keeps
    /// the stream's lease until it is dropped.
    #[must_use]
    pub fn with_lease(inner: Subscription<Arc<LogBuffer>>, lease: Lease) -> Self {
        let mut subscription = Self::new(inner);
        subscription._lease = Some(lease);
        subscription
    }

    /// Wraps a subscription handed over through a client conductor; the
    /// handle keeps the stream's lease until it is dropped.
    #[must_use]
    pub fn from_hand_over(inner: Subscription<Arc<LogBuffer>>, origin: Origin) -> Self {
        let mut subscription = Self::new(inner);
        subscription.origin = Some(origin);
        subscription
    }

    /// The owner and registration, for a handle from a client conductor.
    #[must_use]
    pub fn origin(&self) -> Option<&Origin> {
        self.origin.as_ref()
    }

    /// Delivers up to `message_limit` messages to `handler`.
    ///
    /// The handler gets a slice of the private copy, valid only for that
    /// call; no loan is held while it runs. A normal return means the message
    /// was handled. Work is bounded: a limit of 0 does nothing; otherwise at
    /// most `message_limit + 1` lower-layer polls run, each copying at most
    /// one message after stepping over at most one PAD. The poll stops when
    /// nothing is published or at the first overrun.
    ///
    /// # Errors
    ///
    /// Returns [`PollError`] carrying the deliveries handled before a
    /// lower-layer failure, such as a required subscription whose data is
    /// gone. A message handed to the handler and not yet acknowledged stays
    /// pending for redelivery; a PAD stepped over before the failure may
    /// still have been acknowledged.
    pub fn poll<H>(
        &mut self,
        mut handler: H,
        message_limit: MessageLimit,
    ) -> Result<PollSummary, PollError>
    where
        H: FnMut(&[u8], MessageInfo),
    {
        let message_limit = message_limit.get();
        let mut summary = PollSummary::default();
        if message_limit == 0 {
            return Ok(summary);
        }
        let attempts = message_limit.checked_add(1).unwrap_or(message_limit);
        for _ in 0..attempts {
            if summary.delivered == message_limit {
                break;
            }
            let outcome = match self.inner.poll(&mut self.scratch) {
                Ok(outcome) => outcome,
                Err(error) => {
                    return Err(PollError {
                        summary,
                        cause: ClientError::from(error),
                    });
                }
            };
            match outcome {
                PollOutcome::Message {
                    position,
                    length,
                    end_of_stream,
                    reserved_value,
                    extension,
                } => {
                    let info = MessageInfo {
                        position,
                        reserved_value,
                        end_of_stream,
                        extension,
                    };
                    let message = self.scratch.get(..length as usize).unwrap_or(&[]);
                    handler(message, info);
                    // Reached only if the handler returned.
                    self.inner.acknowledge();
                    summary.delivered += 1;
                }
                PollOutcome::Overrun {
                    from,
                    lost_to,
                    resume,
                } => {
                    summary.overrun = Some(Overrun {
                        from,
                        lost_to,
                        resume,
                    });
                    break;
                }
                PollOutcome::Pending => break,
            }
        }
        Ok(summary)
    }

    /// The acknowledged stream position.
    #[inline]
    #[must_use]
    pub fn position(&self) -> u64 {
        self.inner.acknowledged_position()
    }
}
