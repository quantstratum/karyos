// SPDX-License-Identifier: Apache-2.0

//! Subscriptions and their poll (F4; quantstratum-docs:
//! karyos/design/ffi-gap-analysis.md §4.4, ADR-0067).
//!
//! A subscription handle wraps the facade's `Subscription` of its client's
//! connection, and records the client, whose handle closes it.
//!
//! The poll hands each message to the caller's handler from a private copy
//! owned by `karyos-ffi`, never from a term or a mapping shared with another
//! process (SPEC.md §10.2). The copy buffer is allocated when the
//! subscription is added, with the largest message it can deliver, and is
//! grown only when that grows: after an image of a larger geometry or a
//! successor mapping was adopted, never per message. Each poll adopts, sizes
//! the buffer and then polls only what it adopted
//! (`Subscription::poll_adopted`), so no message of the poll is larger than
//! the buffer: what arrives meanwhile waits for the next poll. A handle that
//! stopped at a mapping's seal gets one more round in the same call, so a
//! cutover never costs the caller an empty poll. A buffer that cannot grow
//! answers [`Status::System`] before anything of that round is delivered
//! (the count covers earlier rounds), so nothing of it is acknowledged and
//! the next poll tries again.
//!
//! The handler runs while the subscription's slot is held: a handler that
//! polls or closes its own subscription, or closes its client, gets
//! [`Status::Reentrant`]. A binding stops a poll after a failed handler with
//! the bounded poll of ADR-0067: a `limit` of 1 in a loop, and no further
//! call after a failure.

use std::sync::OnceLock;

use karyos_client::{
    ImageChange, MessageInfo, MessageLimit, StreamId, Subscription, SubscriptionError,
    SubscriptionPoll,
};
use karyos_sys::term_bytes::HeapTerms;

use crate::api::client::{AnyClient, clients};
use crate::handles::{Handle, Kind, Table};
use crate::status::{Failure, Status};

/// The most subscriptions open at once (`KARYOS_MAX_SUBSCRIPTIONS`).
pub(crate) const MAX_SUBSCRIPTIONS: u32 = 4096;

/// Rounds of one poll call: one, and one more after a seal.
const ROUNDS: usize = 2;

/// A subscription over either connection.
#[derive(Debug)]
pub(crate) enum Reader {
    /// Of a client attached to a driver in another process.
    #[cfg(target_os = "linux")]
    Remote(Subscription<karyos_sys::term_bytes::SharedTerms>),
    /// Of a client over an embedded driver's conductor.
    Embedded(Subscription<HeapTerms>),
}

/// Runs `$body` on the subscription of either connection.
macro_rules! reader {
    ($reader:expr, $subscription:ident => $body:expr) => {
        match $reader {
            #[cfg(target_os = "linux")]
            Reader::Remote($subscription) => $body,
            Reader::Embedded($subscription) => $body,
        }
    };
}

impl Reader {
    fn adopt(&mut self) {
        reader!(self, subscription => subscription.adopt());
    }

    fn max_message_length(&self) -> u32 {
        reader!(self, subscription => subscription.max_message_length())
    }

    #[expect(
        clippy::result_large_err,
        reason = "the facade's poll result, passed on as it is"
    )]
    fn poll_adopted(
        &mut self,
        handler: impl FnMut(&[u8], MessageInfo),
        limit: MessageLimit,
    ) -> Result<SubscriptionPoll, SubscriptionError> {
        reader!(self, subscription => subscription.poll_adopted(handler, limit))
    }

    fn next_image_change(&mut self) -> Option<ImageChange> {
        reader!(self, subscription => subscription.next_image_change())
    }

    fn image_changes_lost(&self) -> u64 {
        reader!(self, subscription => subscription.image_changes_lost())
    }
}

/// A subscription handle's object.
#[derive(Debug)]
pub(crate) struct Entry {
    /// The client handle it belongs to.
    client: Handle,
    /// Its client's embedded driver's state, if the C ABI created it: the
    /// subscription follows its failure and its close
    /// (`crate::api::driver::DriverState::usable`), with no lock.
    driver: Option<crate::api::driver::DriverState>,
    reader: Reader,
    /// The private copy each message is handed from; its length is the
    /// largest message the subscription delivered or can deliver.
    copy: Vec<u8>,
}

impl Entry {
    /// Releases the subscription to `client`.
    pub(crate) fn release(self, client: &mut AnyClient) {
        client.remove_subscription(self.reader);
    }
}

/// The table of subscriptions, allocated on first use.
pub(crate) fn table() -> &'static Table<Entry> {
    static SUBSCRIPTIONS: OnceLock<Table<Entry>> = OnceLock::new();
    SUBSCRIPTIONS.get_or_init(|| Table::new(Kind::Subscription, MAX_SUBSCRIPTIONS))
}

#[cfg(test)]
thread_local! {
    /// Makes every growth of a copy on this thread fail, as a refused
    /// allocation (tests).
    pub(crate) static REFUSE_GROWTH: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
    /// Makes the poll panic while it hands a message over, with the
    /// subscription held (tests of the poison).
    pub(crate) static PANIC_IN_POLL: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

/// Grows `copy` to `length` bytes without reallocating twice; never
/// shrinks it.
fn fit(copy: &mut Vec<u8>, length: u32) -> Result<(), Status> {
    let length = usize::try_from(length).map_err(|_| Status::System)?;
    let Some(extra) = length.checked_sub(copy.len()).filter(|extra| *extra > 0) else {
        return Ok(());
    };
    #[cfg(test)]
    if REFUSE_GROWTH.with(core::cell::Cell::get) {
        return Err(Status::System);
    }
    copy.try_reserve_exact(extra).map_err(|_| Status::System)?;
    copy.resize(length, 0);
    Ok(())
}

/// Adds the subscription of `stream_id` on `uri` to `client`, with its
/// copy buffer.
///
/// # Errors
///
/// The client's handle and control call failures, [`Status::System`] when
/// the copy buffer cannot be allocated, and [`Status::HandlesExhausted`],
/// with the subscription released.
pub(crate) fn add(client: Handle, uri: &str, stream_id: i32) -> Result<Handle, Failure> {
    clients().with(client, |entry| {
        entry.usable()?;
        let reader = entry
            .client
            .add_subscription(uri, StreamId::new(stream_id))?;
        let mut copy = Vec::new();
        if let Err(status) = fit(&mut copy, reader.max_message_length()) {
            entry.client.remove_subscription(reader);
            return Err(status.into());
        }
        let subscription = Entry {
            client,
            driver: entry.driver.clone(),
            reader,
            copy,
        };
        match table().insert_or_return(subscription) {
            Ok(handle) => {
                entry.subscriptions.push(handle);
                Ok(handle)
            }
            Err((status, subscription)) => {
                subscription.release(&mut entry.client);
                Err(status.into())
            }
        }
    })?
}

/// Delivers at most `limit` messages of `subscription` to `handler`, each
/// from the private copy, and returns how many it delivered.
///
/// # Errors
///
/// The handle's failures, [`Status::System`] when the copy cannot grow
/// (nothing delivered by that round), and a failed poll's status with the
/// messages delivered before it.
pub(crate) fn poll(
    subscription: Handle,
    limit: u32,
    handler: &mut dyn FnMut(&[u8], &MessageInfo),
) -> Result<u32, (Failure, u32)> {
    table()
        .with(subscription, |entry| {
            if let Some(driver) = &entry.driver {
                driver
                    .usable()
                    .map_err(|status| (Failure::from(status), 0))?;
            }
            let Entry { reader, copy, .. } = entry;
            let mut delivered = 0u32;
            for _ in 0..ROUNDS {
                let Some(remaining) = limit.checked_sub(delivered).filter(|left| *left > 0) else {
                    break;
                };
                // What it adopts is what this round may deliver: the copy
                // fits its largest message before anything is delivered.
                reader.adopt();
                fit(copy, reader.max_message_length())
                    .map_err(|status| (Failure::from(status), delivered))?;
                // Messages handed over, and whether one did not fit: the
                // adoption above makes that impossible, so a miss is a
                // broken invariant, reported rather than acknowledged
                // silently.
                let (mut handed, mut missed) = (0u32, false);
                let polled = reader.poll_adopted(
                    |bytes, info| {
                        #[cfg(test)]
                        if PANIC_IN_POLL.with(core::cell::Cell::get) {
                            std::panic::resume_unwind(Box::new("a panic in the poll"));
                        }
                        debug_assert!(bytes.len() <= copy.len(), "a message past the copy");
                        if let Some(copied) = copy.get_mut(..bytes.len()) {
                            copied.copy_from_slice(bytes);
                            handler(copied, &info);
                            // At most `limit` messages: never past a u32.
                            if let Some(next) = handed.checked_add(1) {
                                handed = next;
                            }
                        } else {
                            missed = true;
                        }
                    },
                    MessageLimit::new(remaining),
                );
                if missed {
                    let delivered = delivered.checked_add(handed).unwrap_or(limit);
                    return Err((Failure::from(Status::Internal), delivered));
                }
                match polled {
                    Ok(poll) => {
                        delivered = delivered.checked_add(poll.delivered).unwrap_or(limit);
                        if !poll.stopped_at_seal {
                            break;
                        }
                    }
                    Err(error) => {
                        let before = match &error {
                            SubscriptionError::Poll { delivered, .. } => *delivered,
                            _ => 0,
                        };
                        let delivered = delivered.checked_add(before).unwrap_or(limit);
                        return Err((Failure::from(&error), delivered));
                    }
                }
            }
            Ok(delivered)
        })
        .map_err(|status| (Failure::from(status), 0))?
}

/// The next image change of `subscription`, if one is queued.
///
/// # Errors
///
/// The handle's failures.
pub(crate) fn next_image_change(subscription: Handle) -> Result<Option<ImageChange>, Status> {
    table().with(subscription, |entry| entry.reader.next_image_change())
}

/// The image changes `subscription` dropped from its full queue.
///
/// # Errors
///
/// The handle's failures.
pub(crate) fn image_changes_lost(subscription: Handle) -> Result<u64, Status> {
    table().with(subscription, |entry| entry.reader.image_changes_lost())
}

/// Empties `subscription`'s copy buffer, so its next poll grows it (tests).
#[cfg(test)]
pub(crate) fn empty_copy(subscription: Handle) {
    let _ = table().with(subscription, |entry| {
        entry.copy = Vec::new();
    });
}

/// The length of `subscription`'s copy buffer (tests).
#[cfg(test)]
pub(crate) fn copy_length(subscription: Handle) -> Option<usize> {
    table().with(subscription, |entry| entry.copy.len()).ok()
}

/// Closes `subscription` through its client.
///
/// # Errors
///
/// The handle's failures, its client's included.
pub(crate) fn close(subscription: Handle) -> Result<(), Status> {
    // A poisoned handle is closed too, and released like any other: its client,
    // written at the add and never changed, is read regardless
    // (`Table::read_even_poisoned`); the table hands the poisoned object over,
    // and it is released to the client (`remove_subscription`). What a release
    // touches cannot be left invalid by a panic inside a call: at worst it
    // releases what that call left half-done, as a drop would.
    let client = table().read_even_poisoned(subscription, |entry| entry.client)?;
    clients().with(client, |entry| {
        let removed = table().remove(subscription)?;
        entry.subscriptions.retain(|handle| *handle != subscription);
        removed.release(&mut entry.client);
        Ok(())
    })?
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The copy only grows, and to the exact length asked.
    #[test]
    fn the_copy_grows_to_the_largest_message_and_never_shrinks() {
        let mut copy = Vec::new();
        fit(&mut copy, 16).unwrap();
        assert_eq!(copy.len(), 16);
        fit(&mut copy, 8).unwrap();
        assert_eq!(copy.len(), 16);
        fit(&mut copy, 64).unwrap();
        assert_eq!(copy.len(), 64);
    }
}
