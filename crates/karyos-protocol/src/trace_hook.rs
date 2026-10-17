// SPDX-License-Identifier: Apache-2.0

//! The tracing hook of the data path (`quantstratum-docs:
//! karyos/design/trace-data-path.md`, "Crate graph"). A client handle holds
//! an optional hook; `karyos-trace` implements it, so the client depends on
//! `karyos-protocol` only and the SPEC.md §14 crate graph stays unchanged.
//!
//! The data-path callbacks are called outside reservations, never block
//! and never allocate in the implementations Karyos provides;
//! [`TraceHook::maintain`] is the only control-path entry point.
//!
//! [`NetworkTraceHook`] is its network counterpart (`quantstratum-docs:
//! karyos/design/trace-network.md`, NT-1): the sender and receiver agents
//! of a driver call it per traced frame, and `karyos-trace` implements it,
//! so the driver gains no trace dependency either.

use crate::frame::{Lane, TraceExtension};
use crate::journal::JournalWriter;

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

/// Payload words of a trace journal record: the observation and the
/// writer's collection stamp (`karyos-trace`'s `RECORD_WORDS`). The driver
/// sizes its network journals with it (`trace-network.md`, NT-3).
pub const TRACE_RECORD_WORDS: usize = 25;

/// The clock provenance word of the host's `CLOCK_MONOTONIC` in
/// nanoseconds (`karyos-trace`'s `ClockProvenance::HostMonotonic`): the
/// clock of the driver's network journals (T2).
pub const HOST_MONOTONIC_PROVENANCE: u64 = 2;

/// A traced frame copied into backend TX storage, before submission, for
/// a first send or a retransmission (`SenderPickup`, NT-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetPickup {
    /// The publication.
    pub publication: PublicationIdentity,
    /// The lane.
    pub lane: Lane,
    /// Stream position of the frame in its lane.
    pub position: u64,
    /// The send path, a reusable identity.
    pub path: u32,
    /// 0 for the first send; the repair count for a retransmission.
    pub attempt: u32,
}

/// A traced frame committed into an image by its receive owner
/// (`ReceiverCommit`, NT-2). A receiver cannot know the attempt: DATA
/// carries none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetCommit {
    /// The publication.
    pub publication: PublicationIdentity,
    /// The lane.
    pub lane: Lane,
    /// Stream position of the frame in its lane.
    pub position: u64,
    /// The path whose copy of the frame was committed.
    pub path: u32,
}

/// Where a packet stamp was taken (batch N2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StampPoint {
    /// Kernel software transmit stamp.
    KernelTx,
    /// Kernel software receive stamp.
    KernelRx,
    /// NIC hardware transmit stamp.
    HardwareTx,
    /// NIC hardware receive stamp.
    HardwareRx,
}

/// A kernel or hardware stamp of one packet (batch N2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PacketStamp {
    /// Where it was taken.
    pub point: StampPoint,
    /// Time in the clock's unit.
    pub time: u64,
    /// Clock domain.
    pub clock: u64,
    /// Calibration epoch.
    pub epoch: u64,
    /// Half-width of the uncertainty interval, same unit as `time`.
    pub uncertainty: u64,
}

/// The side of a network journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetSide {
    /// The sender agent's journal of one lane of a publication incarnation.
    Sender,
    /// The receiver agent's journal of one lane of an image.
    Receiver,
}

/// A network journal the driver created for an agent (NT-3): the driver
/// owns its storage, charges it to `max_network_journal_bytes` and drains
/// it into the trace mirror; the agent writes it.
#[derive(Debug)]
pub struct NetJournal {
    /// Its side.
    pub side: NetSide,
    /// The publication it observes.
    pub publication: PublicationIdentity,
    /// The lane it observes.
    pub lane: Lane,
    /// The driver's journal number, never reused.
    pub number: u64,
    /// Its only writer.
    pub writer: JournalWriter,
}

/// Records the network observations of one driver agent (NT-1, completed
/// in ACS 15608). The driver holds one per agent, set on the control path;
/// with none, the data path pays one branch per frame.
///
/// - **Journals (control path).** The driver hands the hook each network
///   journal it creates ([`NetworkTraceHook::open_journal`]) and tells it
///   when one closes ([`NetworkTraceHook::close_journal`]), never from a
///   duty cycle. A refused journal never reaches the hook.
/// - **Observations (data path).** Each call records one frame of a
///   traced message, every fragment included (NT-2). A call whose
///   publication and lane have no open journal on that side, as for a
///   refused journal, is counted and dropped; a full journal drops the
///   record; a call never waits.
pub trait NetworkTraceHook: Send {
    /// Control path: writes `journal` from now on.
    fn open_journal(&mut self, journal: NetJournal);

    /// Control path: the journal of `side`, `publication` and `lane`
    /// closes, since its publication closed or its image retired. The hook
    /// expires its pending stamps (N2) and closes the writer; the driver
    /// then drains the journal to its end.
    fn close_journal(&mut self, side: NetSide, publication: &PublicationIdentity, lane: Lane);

    /// Records the `SenderPickup` of a traced frame, once per path and
    /// attempt.
    fn on_sender_pickup(&mut self, ext: &TraceExtension, at: &NetPickup);

    /// Records the `ReceiverCommit` of a traced frame, once per frame;
    /// duplicates and repairs of a committed frame record nothing.
    fn on_receiver_commit(&mut self, ext: &TraceExtension, at: &NetCommit);

    /// Records a kernel or hardware stamp of the packet `token` (batch N2,
    /// gated on owner decision O-3): no producer calls it yet.
    fn on_packet_stamp(&mut self, _token: u64, _stamp: &PacketStamp) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Counts its calls and holds its journals.
    #[derive(Default)]
    struct Counting {
        journals: Vec<NetJournal>,
        pickups: Vec<NetPickup>,
        commits: Vec<NetCommit>,
    }

    impl NetworkTraceHook for Counting {
        fn open_journal(&mut self, journal: NetJournal) {
            self.journals.push(journal);
        }

        fn close_journal(&mut self, side: NetSide, publication: &PublicationIdentity, lane: Lane) {
            self.journals.retain(|journal| {
                (journal.side, journal.publication, journal.lane) != (side, *publication, lane)
            });
        }

        fn on_sender_pickup(&mut self, _ext: &TraceExtension, at: &NetPickup) {
            self.pickups.push(*at);
        }

        fn on_receiver_commit(&mut self, _ext: &TraceExtension, at: &NetCommit) {
            self.commits.push(*at);
        }
    }

    #[test]
    fn a_network_hook_is_held_as_an_object() {
        let mut counting = Counting::default();
        let hook: &mut dyn NetworkTraceHook = &mut counting;
        let (writer, mut consumer) = crate::journal::record_journal(4, 1, 1).unwrap();
        hook.open_journal(NetJournal {
            side: NetSide::Sender,
            publication: PublicationIdentity::default(),
            lane: Lane::default(),
            number: 1,
            writer,
        });
        let ext = TraceExtension::default();
        let pickup = NetPickup {
            publication: PublicationIdentity::default(),
            lane: Lane::default(),
            position: 64,
            path: 1,
            attempt: 2,
        };
        hook.on_sender_pickup(&ext, &pickup);
        hook.on_receiver_commit(
            &ext,
            &NetCommit {
                publication: PublicationIdentity::default(),
                lane: Lane::default(),
                position: 64,
                path: 1,
            },
        );
        // N2 has no producer: the default stamp call records nothing.
        hook.on_packet_stamp(
            1,
            &PacketStamp {
                point: StampPoint::KernelTx,
                time: 1,
                clock: 0,
                epoch: 0,
                uncertainty: 0,
            },
        );
        assert_eq!(counting.pickups, [pickup]);
        assert_eq!(counting.commits.len(), 1);
        // The hook writes the journal the driver handed it, and closing it
        // ends the journal for the driver's drain.
        counting.journals[0]
            .writer
            .append(
                &[42],
                crate::journal::Stamp {
                    time: 1,
                    clock: 0,
                    epoch: 0,
                },
            )
            .unwrap();
        let hook: &mut dyn NetworkTraceHook = &mut counting;
        hook.close_journal(
            NetSide::Sender,
            &PublicationIdentity::default(),
            Lane::default(),
        );
        assert!(counting.journals.is_empty());
        assert!(matches!(consumer.take(), crate::journal::Taken::Record(_)));
        assert!(matches!(consumer.take(), crate::journal::Taken::Closed));
    }
}
