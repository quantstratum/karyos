// SPDX-License-Identifier: Apache-2.0

//! The trait an event loop runs through, under capture and under replay
//! (quantstratum-docs: karyos/design/recording-group-gateway.md, sections
//! 3 to 6).
//!
//! The event loop is written once against [`GroupGateway`]. The live
//! Gateway implements it in A7d-2; `ReplayGateway` implements it in A8.
//! The handler sees an [`Event`] and acts only through [`Effects`]. Each
//! `Effects` call is one observation, in call order: performed and
//! recorded under capture, returned from the recording and checked
//! under replay. `clock` is the exception: it returns the event's
//! `logical_time` and is not recorded.

use thiserror::Error;

use karyos_sys::frame::Lane;

use super::record::{EXTENSION, Freshness, LifecycleKind, Loss, Outcome};

/// A publication added to a Gateway at configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicationId(pub u16);

/// A subscription added to a Gateway at configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubscriptionId(pub u16);

/// A conflated view added to a Gateway at configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConflatedId(pub u16);

/// A slot in a Gateway's timer table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimerId(pub u16);

/// The event a dispatch delivers to the handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event<'a> {
    /// A subscription's message.
    Message {
        /// The subscription.
        source: SubscriptionId,
        /// The message's lane.
        lane: Lane,
        /// Its position.
        position: u64,
        /// The frame's reserved value.
        reserved_value: i64,
        /// Whether it ended its stream.
        end_of_stream: bool,
        /// Its trace extension, if it had one.
        extension: Option<&'a [u8; EXTENSION]>,
        /// Its payload.
        payload: &'a [u8],
    },
    /// What a subscription's poll reported instead of a message: an
    /// overrun, a skipped range or an aborted block (section 5).
    Loss {
        /// The subscription.
        source: SubscriptionId,
        /// What was lost, and how the source resolved it.
        loss: Loss,
        /// The first position not delivered.
        from: u64,
        /// The end known lost.
        lost_to: u64,
        /// Where delivery resumed.
        resume: u64,
    },
    /// A conflated view's value.
    Conflated {
        /// The view.
        source: ConflatedId,
        /// The value's version.
        version: u64,
        /// Its freshness.
        freshness: Freshness,
        /// The value.
        value: &'a [u8],
    },
    /// A timer at its deadline.
    Timer {
        /// The timer.
        timer: TimerId,
    },
    /// A subscription's end, as its poll reported it.
    Lifecycle {
        /// The subscription.
        source: SubscriptionId,
        /// What it announced.
        kind: LifecycleKind,
    },
    /// An input from outside Karyos, delivered by
    /// [`GroupGateway::deliver_external`].
    External {
        /// The application's kind.
        kind: u32,
        /// The value.
        value: &'a [u8],
    },
}

/// A claim the handler writes into, through [`Effects::claim_bytes`],
/// before [`Effects::commit`].
///
/// The Gateway's own type, not the client's: a handle that borrows
/// nothing, so the handler can call other effects between the claim and
/// its commit, as the client allows. Under capture its bytes are the
/// log's reserved bytes; under replay, a scratch buffer of the largest
/// claim, owned by the Gateway and checked at `commit`. Only a Gateway
/// makes one, and a claim not committed is aborted when its event ends.
#[derive(Debug, PartialEq, Eq)]
pub struct Claim {
    publication: PublicationId,
    token: u64,
    length: usize,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the live Gateway (A7d-2a) and ReplayGateway (A8) make claims"
    )
)]
impl Claim {
    /// A claim of `length` bytes on `publication`. `token` is the
    /// implementation's own handle on the reservation.
    pub(crate) fn new(publication: PublicationId, token: u64, length: usize) -> Self {
        Self {
            publication,
            token,
            length,
        }
    }

    /// The implementation's handle on the reservation.
    pub(crate) fn token(&self) -> u64 {
        self.token
    }
}

impl Claim {
    /// The publication it was claimed on.
    #[must_use]
    pub fn publication(&self) -> PublicationId {
        self.publication
    }

    /// The bytes claimed.
    #[must_use]
    pub fn length(&self) -> usize {
        self.length
    }
}

/// The claim's outcome: a claim to write, or what refused it.
#[derive(Debug, PartialEq, Eq)]
pub enum ClaimResult {
    /// The bytes reserved.
    Claimed(Claim),
    /// Any outcome other than a reservation.
    Refused(Outcome),
}

/// The handler's only way to act during an event. Each call but
/// [`clock`](Effects::clock) is one observation.
pub trait Effects {
    /// The event's `logical_time`, however often it is called.
    fn clock(&self) -> u64;

    /// Offers `payload` on `publication`.
    fn offer(&mut self, publication: PublicationId, payload: &[u8]) -> Outcome;

    /// Claims `length` bytes on `publication`.
    fn claim(&mut self, publication: PublicationId, length: usize) -> ClaimResult;

    /// The bytes of `claim`, to write before its commit.
    fn claim_bytes(&mut self, claim: &Claim) -> &mut [u8];

    /// Commits a claim.
    fn commit(&mut self, claim: Claim) -> Outcome;

    /// Presents a guarded publication's next delivery outcomes, at most
    /// `max`, to `each`. Returns how many it presented.
    fn poll_outcomes(
        &mut self,
        publication: PublicationId,
        max: u32,
        each: &mut dyn FnMut(&DeliveryOutcome),
    ) -> u32;

    /// Schedules `timer` at `deadline`, replacing a pending deadline.
    fn schedule(&mut self, timer: TimerId, deadline: u64);

    /// Cancels `timer`, if it is pending. Nothing is returned: template
    /// 12 records the call, not whether the timer was pending.
    fn cancel(&mut self, timer: TimerId);

    /// A value read from outside Karyos: `read` runs under capture and
    /// writes into the buffer, returning its length; under replay the
    /// recorded value is returned without running it.
    fn external(&mut self, kind: u32, read: &mut dyn FnMut(&mut [u8]) -> usize) -> &[u8];
}

/// A delivery outcome as the outcome ring presented it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryOutcome {
    /// The ring's kind code.
    pub kind: u8,
    /// The lane.
    pub lane: Lane,
    /// The receiver index, for range kinds; else 0.
    pub receiver: u16,
    /// The message's start, or a receiver's delivered prefix.
    pub start: u64,
    /// The message's end, or the unresolved range's end.
    pub end: u64,
    /// The guard epoch at the decision.
    pub epoch: u64,
    /// The reason, for the kinds that carry one.
    pub reason: u64,
}

/// The application's code for one event.
pub trait Handler {
    /// Handles `event`, acting only through `effects`.
    fn on_event(&mut self, event: &Event<'_>, effects: &mut dyn Effects);
}

impl<F: FnMut(&Event<'_>, &mut dyn Effects)> Handler for F {
    fn on_event(&mut self, event: &Event<'_>, effects: &mut dyn Effects) {
        self(event, effects)
    }
}

/// What a dispatch did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dispatched {
    /// An event ran, as `group_seq`.
    Event {
        /// Its sequence in the group.
        group_seq: u64,
    },
    /// No event was ready.
    Idle,
    /// Best effort: the event could not be captured; it ran unrecorded
    /// and joins the pending gap.
    Uncaptured,
    /// Replay: the complete prefix has no event left.
    End,
}

/// Where a replay first differed from its recording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Divergence {
    /// The event.
    pub group_seq: u64,
    /// The observation's index within it, or the recorded count for an
    /// event that ended with fewer observations.
    pub index: u32,
    /// What the recording holds there, as its template id (0 for none).
    pub expected: u16,
    /// What the handler did, as the template id it would record (0 for
    /// none).
    pub found: u16,
}

/// Why a Gateway call failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum GatewayError {
    /// The group ended: strict capture could not record an event, or its
    /// journal failed.
    #[error("the recording group ended")]
    Ended,
    /// `deliver_external` under replay: external inputs come from the
    /// recording.
    #[error("external events are not delivered in replay")]
    ExternalInReplay,
    /// A replay's handler diverged from its recording.
    #[error("replay diverged at group_seq {}, observation {}", .0.group_seq, .0.index)]
    Diverged(Divergence),
    /// Replay reached an event it cannot reproduce: an incomplete event, a
    /// gap, or a payload or reference unavailable.
    #[error("event {group_seq} cannot be reproduced")]
    NotReproducible {
        /// The event.
        group_seq: u64,
    },
    /// Replay's manifest differs from the journal's and was not accepted.
    #[error("the manifest differs from the journal's")]
    Manifest,
    /// An external value over `MAX_INLINE` under strict capture.
    #[error("value too large: {0} bytes")]
    TooLarge(usize),
}

/// The trait both the live Gateway and `ReplayGateway` implement.
pub trait GroupGateway {
    /// Takes the next event, if any, and runs `handler` on it.
    fn dispatch(&mut self, handler: &mut dyn Handler) -> Result<Dispatched, GatewayError>;

    /// Dispatches an input from outside Karyos, recorded inline. Replay
    /// refuses it with [`GatewayError::ExternalInReplay`].
    fn deliver_external(
        &mut self,
        kind: u32,
        value: &[u8],
        handler: &mut dyn Handler,
    ) -> Result<Dispatched, GatewayError>;
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::panic,
        reason = "test helpers, as ADR-0007 allows in tests"
    )]

    use super::*;

    /// Effects over one scratch buffer, enough to drive a handler.
    struct Scratch {
        buffer: Vec<u8>,
        committed: Vec<u8>,
    }

    impl Effects for Scratch {
        fn clock(&self) -> u64 {
            7
        }
        fn offer(&mut self, _: PublicationId, _: &[u8]) -> Outcome {
            Outcome::BackPressured
        }
        fn claim(&mut self, publication: PublicationId, length: usize) -> ClaimResult {
            ClaimResult::Claimed(Claim::new(publication, 1, length))
        }
        fn claim_bytes(&mut self, claim: &Claim) -> &mut [u8] {
            assert_eq!(claim.token(), 1);
            &mut self.buffer[..claim.length()]
        }
        fn commit(&mut self, claim: Claim) -> Outcome {
            self.committed = self.buffer[..claim.length()].to_vec();
            Outcome::BackPressured
        }
        fn poll_outcomes(
            &mut self,
            _: PublicationId,
            _: u32,
            _: &mut dyn FnMut(&DeliveryOutcome),
        ) -> u32 {
            0
        }
        fn schedule(&mut self, _: TimerId, _: u64) {}
        fn cancel(&mut self, _: TimerId) {}
        fn external(&mut self, _: u32, _: &mut dyn FnMut(&mut [u8]) -> usize) -> &[u8] {
            &[]
        }
    }

    /// A handler claims, calls another effect, writes and commits: the
    /// claim borrows nothing from the effects.
    #[test]
    fn a_handler_claims_writes_and_commits() {
        let mut handler = |_: &Event<'_>, effects: &mut dyn Effects| {
            let ClaimResult::Claimed(claim) = effects.claim(PublicationId(1), 4) else {
                panic!("refused");
            };
            let _ = effects.offer(PublicationId(2), b"x");
            effects.claim_bytes(&claim).fill(9);
            assert_eq!(claim.publication(), PublicationId(1));
            let _ = effects.commit(claim);
        };
        let mut effects = Scratch {
            buffer: vec![0; 8],
            committed: Vec::new(),
        };
        handler.on_event(&Event::Timer { timer: TimerId(0) }, &mut effects);
        assert_eq!(effects.committed, [9; 4]);
    }
}
