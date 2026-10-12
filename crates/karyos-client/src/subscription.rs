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

/// What one poll did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PollSummary {
    /// Messages delivered to the handler.
    pub delivered: u32,
    /// The last overrun observed in this poll, if any. Earlier overruns in
    /// the same poll are counted in `overruns`.
    pub last_overrun: Option<Overrun>,
    /// Overruns observed in this poll.
    pub overruns: u32,
}

/// A subscription on one stream.
#[derive(Debug)]
pub struct ClientSubscription {
    inner: Subscription<Arc<LogBuffer>>,
    scratch: Box<[u8]>,
}

impl ClientSubscription {
    /// Wraps a log buffer subscription, allocating its private copy buffer
    /// (control path) for the buffer's largest message.
    #[must_use]
    pub fn new(inner: Subscription<Arc<LogBuffer>>, max_message_length: u32) -> Self {
        Self {
            inner,
            scratch: vec![0u8; max_message_length as usize].into_boxed_slice(),
        }
    }

    /// Delivers up to `message_limit` messages to `handler`.
    ///
    /// Work is bounded: at most `2 × message_limit + 2` attempts, each of
    /// which may also step over a PAD or report an overrun. The poll stops
    /// early when nothing is published.
    ///
    /// # Errors
    ///
    /// Lower-layer errors, including a required subscription that finds its
    /// data gone. Messages delivered before the error stay delivered.
    pub fn poll<H>(
        &mut self,
        mut handler: H,
        message_limit: u32,
    ) -> Result<PollSummary, ClientError>
    where
        H: FnMut(&[u8], MessageInfo),
    {
        let mut summary = PollSummary::default();
        let attempts = message_limit
            .checked_mul(2)
            .and_then(|a| a.checked_add(2))
            .unwrap_or(u32::MAX);
        for _ in 0..attempts {
            if summary.delivered == message_limit {
                break;
            }
            match self.inner.poll(&mut self.scratch)? {
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
                    summary.overruns += 1;
                    summary.last_overrun = Some(Overrun {
                        from,
                        lost_to,
                        resume,
                    });
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
