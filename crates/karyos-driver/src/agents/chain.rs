// SPDX-License-Identifier: Apache-2.0

//! The session command rings between the receiver and the conductor
//! (`quantstratum-docs: karyos/design/network-sessions.md` S1, "commands
//! between receiver and conductor"; driver-network-agents.md §3.2 step 1).
//!
//! One ring per direction, `session_capacity` entries each, carries only
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
//! validates `session_capacity >= 3 * max_images`. If the credit were ever
//! missing, the answer is dropped and counted and the challenge stays
//! pending until its expiry. `RetireImage` and `StorageReclaimed` are
//! posted by phase 5; until then their units are held, and released with
//! the image.

use karyos_protocol::network::{Alias, Identity, Lanes, TermParams};
use karyos_sys::log_buffer::ReceiveOwner;

use super::EndpointId;
use super::ring::{PostError, Reservation, RingReceiver, RingSender};
use crate::sessions::receive::SlotRef;

/// Conductor to receiver, on the session ring.
#[derive(Debug)]
pub enum SessionCommand {
    /// `ImageReady`: install the image of the pending `slot`, receive
    /// owner included. Answered [`SessionEvent::ImageInstalled`] or
    /// [`SessionEvent::ImageReleased`] into `reply`.
    InstallImage {
        /// The reply's unit, reserved at the answer.
        reply: Reservation,
        /// The pending session slot, at its challenge generation.
        slot: SlotRef,
        /// The image's receive owner over its lanes.
        owner: Box<ReceiveOwner>,
    },
    /// `ImageRefused`: the challenge of `slot` goes. Answered
    /// [`SessionEvent::ImageReleased`] into `reply`.
    RefuseImage {
        /// The reply's unit, reserved at the answer.
        reply: Reservation,
        /// The pending session slot.
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
    },
    /// The image of `slot` was not installed (too late, quarantined, bound
    /// elsewhere, or refused): nothing is bound and the conductor frees its
    /// storage (`ReleaseImage`).
    ImageReleased {
        /// The pending slot.
        slot: SlotRef,
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
pub(super) struct SessionEnd {
    /// Commands from the conductor.
    pub(super) commands: RingReceiver<SessionCommand>,
    /// Events to the conductor.
    pub(super) events: RingSender<SessionEvent>,
    /// A producer handle of the command ring, to reserve the conductor's
    /// units at the answer.
    pub(super) credit: RingSender<SessionCommand>,
}

/// The conductor's end of the session rings.
#[derive(Debug)]
pub struct SessionLink {
    commands: RingSender<SessionCommand>,
    events: RingReceiver<SessionEvent>,
}

/// Both ends of the session rings, `capacity` entries each.
pub(super) fn session_rings(capacity: std::num::NonZeroUsize) -> (SessionEnd, SessionLink) {
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

impl SessionLink {
    /// Takes the receiver's oldest session event.
    #[must_use]
    pub fn take_event(&self) -> Option<SessionEvent> {
        self.events.try_take().ok().flatten()
    }

    /// Posts `command` into the unit `reservation` holds. `false` when the
    /// receiver is gone (the driver is stopping) or the reservation belongs
    /// to another ring.
    pub fn post(&self, reservation: Reservation, command: SessionCommand) -> bool {
        match self.commands.post(reservation, command) {
            Ok(()) => true,
            Err(PostError::Gone(_) | PostError::Foreign(_) | PostError::Full(_)) => false,
        }
    }
}
