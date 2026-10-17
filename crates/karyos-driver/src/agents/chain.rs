// SPDX-License-Identifier: Apache-2.0

//! The session command rings between the receiver and the conductor
//! (`quantstratum-docs: karyos/design/network-sessions.md` S1, "commands
//! between receiver and conductor"; driver-network-agents.md §3.2 step 1).
//!
//! One ring per direction, `session_command_capacity` entries each, carries only
//! the commands of image chains, apart from the agents' general rings. The
//! whole chain of one image is reserved at the answer, before the
//! challenge is marked answered:
//!
//! | Unit | Ring |
//! | --- | --- |
//! | `CreateImage` | receiver to conductor |
//! | `ImageReady` or `ImageRefused` ([`SessionCommand`]) | conductor to receiver |
//! | `ImageInstalled` or `ReleaseImage` (its reply) | receiver to conductor |
//! | `RetireImage` | receiver to conductor |
//! | `StorageReclaimed` | conductor to receiver |
//!
//! The receiver reserves the conductor-to-receiver units through its own
//! producer handle of that ring and hands them over in `CreateImage`
//! ([`ImageChain`]), so no later step of the chain can find a ring full.
//! A unit returns to its ring when the consumer takes the command, so each
//! ring holds at most three units per image in flight, and configuration
//! validates `session_command_capacity >= 3 * max_images`. If the credit were ever
//! missing, the answer is dropped and counted and the challenge stays
//! pending until its expiry. `RetireImage` and `StorageReclaimed` are
//! posted at retirement (phase 5b); their units are held until then, and
//! released with an image that is never installed.

use karyos_protocol::network::{Alias, Identity, Lanes, TermParams};
use karyos_sys::log_buffer::ReceiveOwner;
use karyos_sys::term_bytes::HeapTerms;

use super::EndpointId;
use super::ring::{PostError, Reservation, RingReceiver, RingSender};
use crate::embedded::StreamTerms;
use crate::sessions::receive::SlotRef;

/// Conductor to receiver, on the session ring.
#[derive(Debug)]
pub enum SessionCommand<T: StreamTerms = HeapTerms> {
    /// `ImageReady`: install the image of the pending `slot`, receive
    /// owner included. Answered [`SessionEvent::ImageInstalled`] or
    /// [`SessionEvent::ImageReleased`] into `reply`.
    InstallImage {
        /// The reply's unit, reserved at the answer.
        reply: Reservation,
        /// The pending session slot, at its challenge generation.
        slot: SlotRef,
        /// The image's receive owner over its lanes.
        owner: Box<ReceiveOwner<T>>,
    },
    /// `ImageRefused`: the challenge of `slot` goes. Answered
    /// [`SessionEvent::ImageReleased`] into `reply`.
    RefuseImage {
        /// The reply's unit, reserved at the answer.
        reply: Reservation,
        /// The pending session slot.
        slot: SlotRef,
    },
    /// `StorageReclaimed`: every loan on the retired image at `slot` (its
    /// installed slot) is gone and its storage freed; the tombstone may go
    /// once its quarantine passes. No reply.
    StorageReclaimed {
        /// The installed slot.
        slot: SlotRef,
    },
}

/// Receiver to conductor, on the session ring.
#[derive(Debug)]
pub enum SessionEvent {
    /// A SETUP answer was accepted: the conductor charges its storage
    /// budget, allocates every lane and answers with `chain`'s units.
    CreateImage {
        /// The endpoint it arrived on.
        endpoint: EndpointId,
        /// Stream and session alias of the binding.
        alias: Alias,
        /// The pending session slot, at its challenge generation.
        slot: SlotRef,
        /// The answering incarnation.
        identity: Identity,
        /// Term parameters.
        term: TermParams,
        /// Each lane's join point.
        joins: Lanes<u64>,
        /// The conductor's units of the chain.
        chain: ImageChain,
    },
    /// The image of `slot` is installed and bound; its installed slot (the
    /// new generation) names it from now on.
    ImageInstalled {
        /// The pending slot the `InstallImage` named.
        slot: SlotRef,
        /// The installed slot.
        installed: SlotRef,
        /// The conflated lane of its key and the link its seal gate shares
        /// with the lane's view (conflated-network-images.md (b)); `None`
        /// without a conflated view.
        freshness: Option<(
            karyos_sys::frame::Lane,
            karyos_sys::freshness::FreshnessLink,
        )>,
    },
    /// The image of `slot` was not installed (too late, quarantined, bound
    /// elsewhere, or refused): nothing is bound and the conductor frees its
    /// storage (`ReleaseImage`).
    ImageReleased {
        /// The pending slot.
        slot: SlotRef,
    },
    /// The installed image at `slot` is retired: its binding is gone and
    /// no datagram reaches it; the conductor reclaims its storage once
    /// every loan on it is released and answers `StorageReclaimed`.
    RetireImage {
        /// The installed slot.
        slot: SlotRef,
        /// Whether the image ended cleanly: every lane's complete prefix
        /// reached the terminal bound its EOS named (network-sessions.md,
        /// Liveness and terminal transitions). Otherwise it is retired
        /// with its prefix possibly unresolved.
        complete: bool,
    },
}

/// The conductor's units of one image chain, reserved by the receiver at
/// the answer.
#[derive(Debug)]
pub struct ImageChain {
    /// The `InstallImage` or `RefuseImage` slot (conductor to receiver).
    pub(super) command: Reservation,
    /// Its reply's slot (receiver to conductor).
    pub(super) reply: Reservation,
    /// The `StorageReclaimed` slot (conductor to receiver), held until
    /// phase 5 posts it.
    pub(super) reclaimed: Reservation,
}

/// The receiver's end of the session rings.
#[derive(Debug)]
pub(super) struct SessionEnd<T: StreamTerms = HeapTerms> {
    /// Commands from the conductor.
    pub(super) commands: RingReceiver<SessionCommand<T>>,
    /// Events to the conductor.
    pub(super) events: RingSender<SessionEvent>,
    /// A producer handle of the command ring, to reserve the conductor's
    /// units at the answer.
    pub(super) credit: RingSender<SessionCommand<T>>,
}

/// The conductor's end of the session rings.
#[derive(Debug)]
pub struct SessionLink<T: StreamTerms = HeapTerms> {
    commands: RingSender<SessionCommand<T>>,
    events: RingReceiver<SessionEvent>,
}

/// Both ends of the session rings, `capacity` entries each.
pub(super) fn session_rings<T: StreamTerms>(
    capacity: std::num::NonZeroUsize,
) -> (SessionEnd<T>, SessionLink<T>) {
    let (commands, command_receiver) = super::ring::ring(capacity);
    let (events, event_receiver) = super::ring::ring(capacity);
    (
        SessionEnd {
            commands: command_receiver,
            events,
            credit: commands.clone_sender(),
        },
        SessionLink {
            commands,
            events: event_receiver,
        },
    )
}

impl<T: StreamTerms> SessionLink<T> {
    /// Takes the receiver's oldest session event.
    #[must_use]
    pub fn take_event(&self) -> Option<SessionEvent> {
        self.events.try_take().ok().flatten()
    }

    /// Posts `command` into the unit `reservation` holds. `false` when the
    /// receiver is gone (the driver is stopping) or the reservation belongs
    /// to another ring.
    pub fn post(&self, reservation: Reservation, command: SessionCommand<T>) -> bool {
        match self.commands.post(reservation, command) {
            Ok(()) => true,
            Err(PostError::Gone(_) | PostError::Foreign(_) | PostError::Full(_)) => false,
        }
    }
}
