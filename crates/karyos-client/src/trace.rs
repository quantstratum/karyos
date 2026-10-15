// SPDX-License-Identifier: Apache-2.0

//! Tracing on the client handles (`quantstratum-docs:
//! karyos/design/trace-data-path.md`, batch p6b): one decision per logical
//! message, reused by every attempt; the `Publish` observation after a
//! commit and the `SubscriberPoll` observation before the handler, through
//! the handle's [`TraceHook`]. Without a hook the data path pays one branch.

use core::fmt;

use karyos_protocol::frame::{Lane, TraceExtension};
use karyos_protocol::trace_hook::{
    Committed, Delivered, PublicationIdentity, PublishContext, SubscriberIdentity, TraceHook,
};
use karyos_sys::frame::EXTENSION_LENGTH;

/// The tracing decision for one logical message: the extension to write in
/// every fragment of every attempt, or none. Taking it consumed the
/// sampler's cadence slot and ids once; retrying with the same decision
/// publishes the same extension and is not sampled again. A decision that
/// is never committed records nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TraceDecision {
    extension: Option<TraceExtension>,
    bytes: Option<[u8; EXTENSION_LENGTH as usize]>,
}

impl TraceDecision {
    /// Publish untraced.
    pub const UNTRACED: Self = Self {
        extension: None,
        bytes: None,
    };

    /// A decision that writes `extension`. An extension that does not
    /// encode (undefined feature bits) publishes untraced.
    #[must_use]
    pub fn traced(extension: TraceExtension) -> Self {
        let mut bytes = [0u8; EXTENSION_LENGTH as usize];
        match extension.encode(&mut bytes) {
            Ok(()) => Self {
                extension: Some(extension),
                bytes: Some(bytes),
            },
            Err(_) => Self::UNTRACED,
        }
    }

    /// The extension, when the message is traced.
    #[must_use]
    pub fn extension(&self) -> Option<TraceExtension> {
        self.extension
    }

    /// Whether the message is traced.
    #[must_use]
    pub fn is_traced(&self) -> bool {
        self.extension.is_some()
    }

    /// The encoded extension for `AppendOptions::extension`.
    pub(crate) fn bytes(&self) -> Option<[u8; EXTENSION_LENGTH as usize]> {
        self.bytes
    }
}

/// The hook and identity of a traced publication handle.
pub(crate) struct PublishTrace {
    hook: Box<dyn TraceHook>,
    identity: PublicationIdentity,
}

impl fmt::Debug for PublishTrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublishTrace")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl PublishTrace {
    pub(crate) fn new(hook: Box<dyn TraceHook>, identity: PublicationIdentity) -> Self {
        Self { hook, identity }
    }

    /// One decision for a message on `lane`, caused by `parent` if any.
    pub(crate) fn decide(&mut self, parent: Option<&TraceExtension>, lane: Lane) -> TraceDecision {
        let context = PublishContext {
            publication: self.identity,
            lane,
        };
        self.hook
            .on_publish(parent, &context)
            .map_or(TraceDecision::UNTRACED, TraceDecision::traced)
    }

    /// The `Publish` observation of a committed traced message.
    pub(crate) fn committed(&mut self, extension: &TraceExtension, lane: Lane, position: u64) {
        self.hook.on_committed(
            extension,
            &Committed {
                publication: self.identity,
                lane,
                position,
            },
        );
    }

    pub(crate) fn maintain(&mut self) {
        self.hook.maintain();
    }
}

/// The hook, identities and delivery boundary of a traced subscription.
pub(crate) struct DeliveryTrace {
    hook: Box<dyn TraceHook>,
    publication: PublicationIdentity,
    subscriber: SubscriberIdentity,
    /// The end of the highest message the subscription attempted to
    /// deliver; 0 before the first. It advances before the observation and
    /// the handler, independently of acknowledgement.
    boundary: u64,
}

impl fmt::Debug for DeliveryTrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeliveryTrace")
            .field("publication", &self.publication)
            .field("subscriber", &self.subscriber)
            .field("boundary", &self.boundary)
            .finish_non_exhaustive()
    }
}

impl DeliveryTrace {
    /// A trace starting at `boundary`: 0 for a new subscription, the
    /// previous boundary when a hook is rebound.
    pub(crate) fn new(
        hook: Box<dyn TraceHook>,
        publication: PublicationIdentity,
        subscriber: SubscriberIdentity,
        boundary: u64,
    ) -> Self {
        Self {
            hook,
            publication,
            subscriber,
            boundary,
        }
    }

    pub(crate) fn boundary(&self) -> u64 {
        self.boundary
    }

    /// A delivery attempt of the message at `position`, ending at `end`,
    /// before its handler runs: advances the boundary and records the
    /// observation of a traced message the first time its position is
    /// attempted, so a redelivery after a handler panic records nothing.
    pub(crate) fn attempt(
        &mut self,
        extension: Option<&TraceExtension>,
        lane: Lane,
        position: u64,
        end: u64,
    ) {
        let first = position >= self.boundary;
        if !first {
            return;
        }
        self.boundary = end;
        if let Some(extension) = extension {
            self.hook.on_delivered(
                extension,
                &Delivered {
                    publication: self.publication,
                    subscriber: self.subscriber,
                    lane,
                    position,
                },
            );
        }
    }

    pub(crate) fn maintain(&mut self) {
        self.hook.maintain();
    }
}

#[cfg(test)]
pub(crate) mod test_hook {
    //! A recording hook for the client's tests.

    use std::sync::{Arc, Mutex};

    use super::*;

    /// What a [`Recording`] hook saw.
    #[derive(Debug, Default)]
    pub(crate) struct Seen {
        pub(crate) decisions: u64,
        pub(crate) committed: Vec<(TraceExtension, Committed)>,
        pub(crate) delivered: Vec<(TraceExtension, Delivered)>,
        pub(crate) maintained: u64,
    }

    /// Traces every message with a fresh id, records every callback.
    pub(crate) struct Recording {
        pub(crate) seen: Arc<Mutex<Seen>>,
        pub(crate) trace_all: bool,
    }

    impl TraceHook for Recording {
        fn on_publish(
            &mut self,
            incoming: Option<&TraceExtension>,
            _message: &PublishContext,
        ) -> Option<TraceExtension> {
            let mut seen = self.seen.lock().unwrap();
            seen.decisions += 1;
            if !self.trace_all {
                return None;
            }
            let id = seen.decisions;
            Some(TraceExtension {
                trace_id: incoming.map_or([id, 1], |parent| parent.trace_id),
                span_id: 100 + id,
                parent_span_id: incoming.map_or(0, |parent| parent.span_id),
                message_id: id,
                ..TraceExtension::default()
            })
        }

        fn on_committed(&mut self, ext: &TraceExtension, at: &Committed) {
            self.seen.lock().unwrap().committed.push((*ext, *at));
        }

        fn on_delivered(&mut self, ext: &TraceExtension, at: &Delivered) {
            self.seen.lock().unwrap().delivered.push((*ext, *at));
        }

        fn maintain(&mut self) {
            self.seen.lock().unwrap().maintained += 1;
        }
    }

    pub(crate) fn recording(trace_all: bool) -> (Box<dyn TraceHook>, Arc<Mutex<Seen>>) {
        let seen = Arc::new(Mutex::new(Seen::default()));
        (
            Box::new(Recording {
                seen: Arc::clone(&seen),
                trace_all,
            }),
            seen,
        )
    }
}

#[cfg(test)]
mod tests;
