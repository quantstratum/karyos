// SPDX-License-Identifier: Apache-2.0

//! The tracing hook of the data path (`quantstratum-docs:
//! karyos/design/trace-data-path.md`, "Crate graph"). A client handle holds
//! an optional hook; `karyos-trace` implements it, so the client depends on
//! `karyos-protocol` only and the SPEC.md §14 crate graph stays unchanged.
//!
//! The data-path callbacks are called outside reservations, never block
//! and never allocate in the implementations Karyos provides;
//! [`TraceHook::maintain`] is the only control-path entry point.

use crate::frame::{Lane, TraceExtension};

/// The publication an observation belongs to: the driver instance, the
/// registration, the wire stream and session, and the incarnation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PublicationIdentity {
    /// The driver's random 128-bit `driver_id` (SPEC.md §4), two words.
    pub driver: [u64; 2],
    /// Publication registration.
    pub registration: u64,
    /// Wire stream id.
    pub stream_id: i32,
    /// Wire session id.
    pub session_id: i32,
    /// Publication incarnation.
    pub incarnation: u64,
}

/// A subscriber registration, scoped by its driver instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubscriberIdentity {
    /// The subscriber's driver instance, two words.
    pub driver: [u64; 2],
    /// Subscriber registration, nonzero.
    pub registration: u64,
    /// Subscriber incarnation.
    pub incarnation: u64,
}

/// What a hook may use to decide whether to trace a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublishContext {
    /// The publishing publication.
    pub publication: PublicationIdentity,
    /// The lane the message is published on.
    pub lane: Lane,
}

/// A traced message committed by a publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Committed {
    /// The publication.
    pub publication: PublicationIdentity,
    /// The lane.
    pub lane: Lane,
    /// Stream position of the message's block in its lane.
    pub position: u64,
}

/// A traced message delivered to a subscriber, before its handler runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Delivered {
    /// The publication that published it.
    pub publication: PublicationIdentity,
    /// The receiving subscription.
    pub subscriber: SubscriberIdentity,
    /// The lane.
    pub lane: Lane,
    /// Stream position of the message's block in its lane.
    pub position: u64,
}

/// Decides and records tracing for one client handle.
pub trait TraceHook: Send {
    /// Decides once per logical message whether to trace it, given the
    /// trace context of the message that caused it, if any. Returns the
    /// extension to write in every fragment of the message, or `None` to
    /// publish it untraced. Every attempt of the message reuses the result.
    fn on_publish(
        &mut self,
        incoming: Option<&TraceExtension>,
        message: &PublishContext,
    ) -> Option<TraceExtension>;

    /// Records the `Publish` observation of a traced message after its
    /// commit. A full journal drops the record; the call never waits.
    fn on_committed(&mut self, ext: &TraceExtension, at: &Committed);

    /// Records the `SubscriberPoll` observation of a traced message before
    /// its handler runs. A full journal drops the record; the call never
    /// waits.
    fn on_delivered(&mut self, ext: &TraceExtension, at: &Delivered);

    /// Control path: refills what the data path consumes (random ids).
    /// Called by the application from the handle's thread, never from the
    /// data-path callbacks.
    fn maintain(&mut self) {}
}
