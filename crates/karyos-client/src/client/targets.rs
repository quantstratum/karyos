// SPDX-License-Identifier: Apache-2.0

//! Replay targets subscribed through a facade client without blocking
//! (`quantstratum-docs: karyos/design/ffi-archive.md`, F9b): an Archive's
//! client, polled inside a subscription's poll, holds no `&mut Client`, so
//! it asks a [`ReplayTargetSubscriber`] for the target, and the client's
//! own polls ([`Client::poll`]) submit the request and complete it, as
//! they adopt a network subscription's images.

use std::sync::{Arc, Mutex, Weak};

use karyos_protocol::cnc::{StreamKey, SubscriberRole};
use karyos_sys::term_bytes::TermBytes;

use super::{Client, Connection};
use crate::conductor::Outcome;
use crate::subscription::ClientSubscription;

/// Subscribes replay targets through the [`Client`] that made it
/// ([`Client::replay_targets`]), without blocking: what an Archive's client
/// takes to find the stream a replay is written to.
///
/// [`ReplayTargetSubscriber::subscribe`] asks for a target, and returns
/// its subscription once a later [`Client::poll`] of that client has the
/// grant. The client must therefore be polled while a target is asked for.
///
/// **Withdrawal and release.** One target is asked for at a time. Asking
/// for another withdraws the previous request: a grant for it that comes
/// later, or one granted and never taken, is released by the client on its
/// next poll, so a withdrawn target never holds a driver registration.
/// So is anything left when the subscriber is dropped. A request the
/// driver refuses (the target not there yet) is asked again on the next
/// [`ReplayTargetSubscriber::subscribe`] call; how long to keep asking is
/// the caller's deadline.
pub struct ReplayTargetSubscriber<T: TermBytes> {
    shared: Arc<Mutex<Target<T>>>,
}

impl<T: TermBytes> core::fmt::Debug for ReplayTargetSubscriber<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let target = lock(&self.shared);
        f.debug_struct("ReplayTargetSubscriber")
            .field("wanted", &target.wanted)
            .field("granted", &target.granted.is_some())
            .finish_non_exhaustive()
    }
}

/// What a subscriber and its client share. The client holds it until the
/// subscriber is dropped and nothing of its own is left in flight or to
/// release.
#[derive(Debug)]
pub(super) struct Target<T: TermBytes> {
    /// The target asked for.
    wanted: Option<StreamKey>,
    /// Whether the client is to submit a request for `wanted`.
    ask: bool,
    /// Whether a request of this subscriber is in flight.
    pending: bool,
    /// The grant for `wanted`, not taken yet.
    granted: Option<ClientSubscription<T>>,
    /// Grants withdrawn, for the client to release.
    discarded: Vec<ClientSubscription<T>>,
    /// The subscriber was dropped.
    dropped: bool,
}

/// A request for a target, in flight.
#[derive(Debug)]
pub(super) struct TargetAsk<T: TermBytes> {
    sequence: u64,
    stream: StreamKey,
    target: Weak<Mutex<Target<T>>>,
}

fn lock<T: TermBytes>(target: &Mutex<Target<T>>) -> std::sync::MutexGuard<'_, Target<T>> {
    target
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl<T: TermBytes> ReplayTargetSubscriber<T> {
    /// The subscription of `karyos:ipc` stream `stream_id`, session
    /// `session_id`, as a required reader, once granted: the first call
    /// asks for it and returns `None`, and a call after the client's poll
    /// had the grant returns it. Asking for another target withdraws the
    /// previous one (see the type's documentation). Never blocks.
    pub fn subscribe(&mut self, stream_id: i32, session_id: i32) -> Option<ClientSubscription<T>> {
        let stream = StreamKey {
            stream_id,
            session_id,
        };
        let mut target = lock(&self.shared);
        if target.wanted != Some(stream) {
            if let Some(withdrawn) = target.granted.take() {
                target.discarded.push(withdrawn);
            }
            target.wanted = Some(stream);
        }
        if let Some(granted) = target.granted.take() {
            target.wanted = None;
            return Some(granted);
        }
        if !target.pending {
            target.ask = true;
        }
        None
    }
}

impl<T: TermBytes> Drop for ReplayTargetSubscriber<T> {
    /// Withdraws the target asked for: a grant not taken, or one that
    /// comes later, is released by the client's next poll, which holds
    /// what the two share until then.
    fn drop(&mut self) {
        let mut target = lock(&self.shared);
        target.wanted = None;
        target.dropped = true;
        if let Some(withdrawn) = target.granted.take() {
            target.discarded.push(withdrawn);
        }
    }
}

impl<C: Connection> Client<C> {
    /// A subscriber of replay targets through this client
    /// ([`ReplayTargetSubscriber`]): its requests are submitted and
    /// completed by this client's polls.
    pub fn replay_targets(&mut self) -> ReplayTargetSubscriber<C::Terms> {
        let shared = Arc::new(Mutex::new(Target {
            wanted: None,
            ask: false,
            pending: false,
            granted: None,
            discarded: Vec::new(),
            dropped: false,
        }));
        self.targets.push(Arc::clone(&shared));
        ReplayTargetSubscriber { shared }
    }

    /// Submits the targets asked for and releases those withdrawn; forgets
    /// a dropped subscriber once nothing of its own is left in flight.
    pub(super) fn serve_targets(&mut self) {
        let mut index = 0;
        while let Some(shared) = self.targets.get(index).map(Arc::clone) {
            let (asked, discarded, gone) = {
                let mut target = lock(&shared);
                let asked = match (target.ask, target.wanted) {
                    (true, Some(stream)) => {
                        target.ask = false;
                        Some(stream)
                    }
                    _ => None,
                };
                let gone = target.dropped && !target.pending;
                (asked, std::mem::take(&mut target.discarded), gone)
            };
            for withdrawn in discarded {
                if !self.connection.release_subscription(withdrawn) {
                    super::bump(&mut self.subscription_releases_failed);
                }
            }
            if gone {
                let _ = self.targets.swap_remove(index);
                continue;
            }
            // A request not submitted now (the ring full) is asked again
            // on the subscriber's next call.
            if let Some(stream) = asked
                && let Ok(sequence) = self
                    .connection
                    .add_subscription(stream, SubscriberRole::Required)
            {
                lock(&shared).pending = true;
                self.target_asks.push(TargetAsk {
                    sequence,
                    stream,
                    target: Arc::downgrade(&shared),
                });
            }
            index += 1;
        }
    }

    /// Completes a target's request, if `sequence` is one: its grant goes
    /// to the subscriber still asking for it and holding none, and is
    /// released otherwise. Returns the outcome back when it is no target's.
    pub(super) fn target_completed(&mut self, sequence: u64, outcome: Outcome) -> Option<Outcome> {
        let Some(index) = self
            .target_asks
            .iter()
            .position(|ask| ask.sequence == sequence)
        else {
            return Some(outcome);
        };
        let ask = self.target_asks.swap_remove(index);
        let Some(shared) = ask.target.upgrade() else {
            let _ = self.connection.release(outcome);
            return None;
        };
        // Another request of this subscriber may still be in flight.
        let pending = self
            .target_asks
            .iter()
            .any(|other| Weak::ptr_eq(&other.target, &ask.target));
        let mut target = lock(&shared);
        target.pending = pending;
        if target.wanted != Some(ask.stream) || target.granted.is_some() {
            // Withdrawn, its subscriber dropped, or granted already by an
            // earlier request: released.
            drop(target);
            let _ = self.connection.release(outcome);
            return None;
        }
        // A refusal (the target not there yet) is asked again by the
        // subscriber's next call.
        target.granted = self.connection.subscription(outcome).ok();
        None
    }
}
