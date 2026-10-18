// SPDX-License-Identifier: Apache-2.0

//! P2.12 step 3, PR 3a: the conductor hands network trace hooks and
//! journals to the agents over loopback, records the agents' start and
//! close facts in the trace mirror, and closes the journals with their
//! publication or image (`quantstratum-docs: karyos/design/trace-network.md`
//! §4 and §5).

use std::sync::{Arc, Mutex};

use karyos_protocol::frame::TraceExtension;
use karyos_protocol::trace_hook::{
    NetCommit, NetJournal, NetPickup, NetSide, NetworkTraceHook, PublicationIdentity,
};
use karyos_sys::counters::CellRead;
use karyos_sys::trace_mirror::{EntryRead, JournalEntry, JournalState};

use super::{
    ANY_PORT, aggregate, bound, channel, connected, driver, driver_with, fast_driver, pump,
};
use crate::EmbeddedDriver;
use crate::agents::ThreadingMode;
use karyos_client::OfferOutcome;
use karyos_sys::frame::Lane;

/// What a test hook saw.
#[derive(Default)]
struct Seen {
    journals: Vec<NetJournal>,
    opened: Vec<u64>,
    closed: Vec<u64>,
    pickups: Vec<(TraceExtension, NetPickup)>,
    commits: Vec<(TraceExtension, NetCommit)>,
}

/// A hook that keeps its journals and what it was told.
#[derive(Clone, Default)]
struct Hook(Arc<Mutex<Seen>>);

impl Hook {
    fn opened(&self) -> Vec<u64> {
        self.0.lock().unwrap().opened.clone()
    }

    fn closed(&self) -> Vec<u64> {
        self.0.lock().unwrap().closed.clone()
    }

    fn pickups(&self) -> Vec<(TraceExtension, NetPickup)> {
        self.0.lock().unwrap().pickups.clone()
    }

    fn commits(&self) -> Vec<(TraceExtension, NetCommit)> {
        self.0.lock().unwrap().commits.clone()
    }
}

impl NetworkTraceHook for Hook {
    fn open_journal(&mut self, journal: NetJournal) {
        let mut seen = self.0.lock().unwrap();
        seen.opened.push(journal.number);
        seen.journals.push(journal);
    }

    fn close_journal(&mut self, side: NetSide, publication: &PublicationIdentity, lane: Lane) {
        let mut seen = self.0.lock().unwrap();
        if let Some(index) = seen.journals.iter().position(|journal| {
            (journal.side, journal.publication, journal.lane) == (side, *publication, lane)
        }) {
            // Dropping the writer closes the journal.
            let journal = seen.journals.swap_remove(index);
            seen.closed.push(journal.number);
        }
    }

    fn on_sender_pickup(&mut self, ext: &TraceExtension, at: &NetPickup) {
        self.0.lock().unwrap().pickups.push((*ext, *at));
    }

    fn on_receiver_commit(&mut self, ext: &TraceExtension, at: &NetCommit) {
        self.0.lock().unwrap().commits.push((*ext, *at));
    }
}

fn hook(driver: &mut EmbeddedDriver, side: NetSide) -> Hook {
    let hook = Hook::default();
    driver.set_network_trace_hook(side, Some(Box::new(hook.clone())));
    hook
}

/// The mirror's entry of journal `number`, if it is in the table.
fn entry(driver: &EmbeddedDriver, number: u64) -> Option<JournalEntry> {
    let reader = driver.trace_mirror();
    (0..reader.entries()).find_map(|index| match reader.entry(index) {
        EntryRead::Entry(entry) if entry.journal == number => Some(entry),
        _ => None,
    })
}

fn counter(driver: &EmbeddedDriver, label: &str) -> u64 {
    let reader = driver.counters();
    (0..reader.capacity())
        .find_map(|index| match reader.read(index) {
            CellRead::Allocated {
                metadata, value, ..
            } if metadata.label() == label.as_bytes() => Some(value),
            _ => None,
        })
        .unwrap()
}

/// The start the agent answered for journal `number`, once recorded.
fn start(driver: &EmbeddedDriver, number: u64) -> Option<u64> {
    entry(driver, number)?.network?.start
}

fn extension(message_id: u64) -> TraceExtension {
    TraceExtension {
        extension_flags: 0,
        trace_id: [5, 6],
        span_id: 2,
        parent_span_id: 0,
        message_id,
    }
}

/// The client publication of lane 0 of `publication`.
fn lane_zero(
    a: &mut EmbeddedDriver,
    publication: &crate::embedded::AggregateHandle,
) -> karyos_client::ClientPublication<karyos_sys::term_bytes::HeapTerms> {
    a.publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap()
}

/// Offers one traced message on `lane`, pumping both drivers until it is
/// accepted.
fn offer_traced(
    a: &mut EmbeddedDriver,
    b: &mut EmbeddedDriver,
    lane: &mut karyos_client::ClientPublication<karyos_sys::term_bytes::HeapTerms>,
    message_id: u64,
) {
    let mut bytes = [0u8; 64];
    extension(message_id).encode(&mut bytes).unwrap();
    let options = karyos_sys::log_buffer::AppendOptions {
        extension: Some(bytes),
        ..karyos_sys::log_buffer::AppendOptions::default()
    };
    pump(&mut [a, b], |_| {
        matches!(
            lane.offer_with(&[9u8; 100], options).unwrap(),
            OfferOutcome::Accepted { .. }
        )
    });
}

/// PR 3a, end to end: hooks set before the publication and the image get
/// one journal per lane on each side, each with the start its agent
/// answered; a traced message records one `SenderPickup` and one
/// `ReceiverCommit` at the same position; removing the publication closes
/// its sender journal with its pickup boundary.
fn journals_follow_a_publication_and_its_image(threading: ThreadingMode) {
    let (mut a, mut b) = (driver(threading), driver(threading));
    let sender = hook(&mut a, NetSide::Sender);
    let receiver = hook(&mut b, NetSide::Receiver);
    let (publication, _image) = connected(&mut a, &mut b, false, 10);
    pump(&mut [&mut a, &mut b], |drivers| {
        let (sent, received) = (sender.opened(), receiver.opened());
        sent.len() == 1
            && received.len() == 1
            && start(drivers[0], sent[0]).is_some()
            && start(drivers[1], received[0]).is_some()
    });
    let (sent, received) = (sender.opened()[0], receiver.opened()[0]);
    let mut lane = lane_zero(&mut a, &publication);
    offer_traced(&mut a, &mut b, &mut lane, 7);
    drop(lane);
    pump(&mut [&mut a, &mut b], |_| {
        !sender.pickups().is_empty() && !receiver.commits().is_empty()
    });
    let (pickup, commit) = (sender.pickups()[0], receiver.commits()[0]);
    assert_eq!((pickup.0, commit.0), (extension(7), extension(7)));
    assert_eq!(pickup.1.publication, commit.1.publication);
    assert_eq!(pickup.1.position, commit.1.position);
    assert_eq!(receiver.commits().len(), 1, "one commit per frame");
    // Removing the publication closes its sender journal first, with its
    // boundary past the message.
    a.remove_aggregate(&publication).unwrap();
    pump(&mut [&mut a, &mut b], |drivers| {
        entry(drivers[0], sent).is_some_and(|entry| {
            entry.state == JournalState::Closed
                && entry
                    .network
                    .is_some_and(|facts| facts.boundary > Some(pickup.1.position))
        })
    });
    assert_eq!(sender.closed(), [sent]);
    assert_eq!(counter(&a, "network trace journals refused"), 0);
    // The image then ends at its EOS (driver-network-agents.md §7), which
    // closes its receiver journal too.
    pump(&mut [&mut a, &mut b], |drivers| {
        entry(drivers[1], received).is_some_and(|entry| entry.state == JournalState::Closed)
    });
}

#[test]
fn journals_follow_a_publication_and_its_image_shared() {
    journals_follow_a_publication_and_its_image(ThreadingMode::Shared);
}

#[test]
fn journals_follow_a_publication_and_its_image_dedicated() {
    journals_follow_a_publication_and_its_image(ThreadingMode::Dedicated);
}

/// PR 3a: a hook set after the image was installed gets its journals
/// then; removing it closes them without facts, counted as unhooked, not
/// refused.
#[test]
fn a_late_hook_gets_journals_and_its_removal_loses_them() {
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let (_publication, _image) = connected(&mut a, &mut b, false, 10);
    let receiver = hook(&mut b, NetSide::Receiver);
    pump(&mut [&mut a, &mut b], |drivers| {
        receiver
            .opened()
            .first()
            .is_some_and(|number| start(drivers[1], *number).is_some())
    });
    let number = receiver.opened()[0];
    b.set_network_trace_hook(NetSide::Receiver, None);
    assert_eq!(counter(&b, "network trace journals unhooked"), 1);
    pump(&mut [&mut a, &mut b], |drivers| {
        entry(drivers[1], number).is_some_and(|entry| entry.state == JournalState::Closed)
    });
    assert_eq!(receiver.closed(), [number]);
    let facts = entry(&b, number).unwrap().network.unwrap();
    assert_eq!(facts.boundary, None, "Lost: closed without facts");
    assert_eq!(counter(&b, "network trace journals refused"), 0);
}

/// PR 3a: an image that retires closes its receiver journal with its
/// facts: the start, and a commit boundary past the traced message.
#[test]
fn a_retired_image_closes_its_receiver_journal_with_its_facts() {
    let (mut a, mut b) = (
        fast_driver(ThreadingMode::Shared),
        fast_driver(ThreadingMode::Shared),
    );
    let receiver = hook(&mut b, NetSide::Receiver);
    let (publication, _image) = connected(&mut a, &mut b, false, 10);
    pump(&mut [&mut a, &mut b], |drivers| {
        receiver
            .opened()
            .first()
            .is_some_and(|number| start(drivers[1], *number).is_some())
    });
    let number = receiver.opened()[0];
    let joined = start(&b, number).unwrap();
    let mut lane = lane_zero(&mut a, &publication);
    offer_traced(&mut a, &mut b, &mut lane, 3);
    drop(lane);
    pump(&mut [&mut a, &mut b], |_| !receiver.commits().is_empty());
    let position = receiver.commits()[0].1.position;
    a.remove_aggregate(&publication).unwrap();
    pump(&mut [&mut a, &mut b], |drivers| {
        entry(drivers[1], number).is_some_and(|entry| entry.state == JournalState::Closed)
    });
    let facts = entry(&b, number).unwrap().network.unwrap();
    assert_eq!(facts.start, Some(joined));
    assert!(facts.boundary > Some(position), "{facts:?}");
    assert_eq!(receiver.closed(), [number]);
}

/// PR 3b, end to end: a gap sealed on a traced image lane is kept, and the
/// control path returns it with the journal's close.
#[test]
fn a_closed_receiver_journal_returns_its_gaps() {
    let (mut a, mut b) = (
        fast_driver(ThreadingMode::Shared),
        fast_driver(ThreadingMode::Shared),
    );
    let receiver = hook(&mut b, NetSide::Receiver);
    let (publication, _image) = connected(&mut a, &mut b, false, 10);
    pump(&mut [&mut a, &mut b], |drivers| {
        receiver
            .opened()
            .first()
            .is_some_and(|number| start(drivers[1], *number).is_some())
    });
    let number = receiver.opened()[0];
    // The first message is lost; the second arrives: a gap is sealed.
    b.net.as_mut().unwrap().drop_receiver_data(&[0]);
    let mut lane = lane_zero(&mut a, &publication);
    offer_traced(&mut a, &mut b, &mut lane, 1);
    offer_traced(&mut a, &mut b, &mut lane, 2);
    drop(lane);
    pump(&mut [&mut a, &mut b], |drivers| {
        drivers[1]
            .net
            .as_ref()
            .unwrap()
            .receiver_counters()
            .is_some_and(|counters| counters.gaps_sealed >= 1)
    });
    assert_eq!(b.network_journal_gaps(number), None, "still open");
    a.remove_aggregate(&publication).unwrap();
    pump(&mut [&mut a, &mut b], |drivers| {
        drivers[1].network_journal_gaps(number).is_some()
    });
    let gaps = b.network_journal_gaps(number).unwrap();
    let first_gap = entry(&b, number).unwrap().network.unwrap().first_gap;
    assert_eq!(gaps.intervals().len(), 1, "{gaps:?}");
    assert_eq!(Some(gaps.intervals()[0].0), first_gap);
    assert!(!gaps.overflowed());
}

/// #332 review P2-1: a removal whose sender journal closes find the ring
/// full keeps them pending; a second removal adds to them, never drops
/// them, so every lane's journal closes with its boundary.
#[test]
fn a_repeated_removal_keeps_the_pending_closes() {
    let agents = crate::agents::AgentConfig {
        command_capacity: 2,
        ..crate::agents::AgentConfig::default()
    };
    let (mut a, mut b) = (
        driver_with(ThreadingMode::Shared, agents),
        driver(ThreadingMode::Shared),
    );
    let sender = hook(&mut a, NetSide::Sender);
    // The hook's command leaves the small ring first.
    for _ in 0..4 {
        let _ = a.do_work().unwrap();
    }
    let _subscription = b
        .add_network_subscription(10, &channel(ANY_PORT, false))
        .unwrap();
    let address = bound(&b, 10);
    let publication = a
        .add_network_publication(aggregate(10, 3, 2), &channel(address, false))
        .unwrap();
    pump(&mut [&mut a, &mut b], |drivers| {
        let opened = sender.opened();
        opened.len() == 2
            && opened
                .iter()
                .all(|number| start(drivers[0], *number).is_some())
    });
    let journals = sender.opened();
    // One slot of the sender's ring is taken: the first close posts, the
    // second waits.
    a.net.as_ref().unwrap().links().sender.ping(1).unwrap();
    a.remove_aggregate(&publication).unwrap();
    a.remove_aggregate(&publication).unwrap();
    pump(&mut [&mut a, &mut b], |drivers| {
        journals.iter().all(|number| {
            entry(drivers[0], *number).is_some_and(|entry| entry.state == JournalState::Closed)
        })
    });
    for number in journals {
        let facts = entry(&a, number).unwrap().network.unwrap();
        assert!(facts.boundary.is_some(), "journal {number}: {facts:?}");
    }
    assert_eq!(counter(&a, "network trace journals unhooked"), 0);
}

/// #396 review P3: a reincarnation closes the old incarnation's sender
/// journal before its session's removal, as a removal does, rather than
/// leaving it to end lost.
#[test]
fn a_reincarnation_closes_the_old_sender_journal() {
    use karyos_sys::guard::Closed;
    use karyos_sys::log_buffer::SealReason;

    use crate::error::DriverError;
    use crate::net::NetworkGuard;

    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let sender = hook(&mut a, NetSide::Sender);
    let guard = a.add_guard("journal").unwrap();
    assert_eq!(a.reopen_guard(guard, 1, 1).unwrap(), 2);
    let _ = b
        .add_network_subscription(10, &channel(ANY_PORT, false))
        .unwrap();
    let address = bound(&b, 10);
    let mut config = aggregate(10, 3, 1);
    config.stream.buffer.spare_slots = 4;
    let publication = a
        .add_guarded_network_publication(
            config,
            &channel(address, false),
            NetworkGuard {
                guard,
                messages: 2,
                rate: None,
            },
        )
        .unwrap();
    pump(&mut [&mut a, &mut b], |drivers| {
        let sent = sender.opened();
        sent.len() == 1 && start(drivers[0], sent[0]).is_some()
    });
    let sent = sender.opened()[0];
    let lane = publication.lane(Lane::ZERO).unwrap();
    // A traced message picked up on the first incarnation.
    let mut handle = lane_zero(&mut a, &publication);
    offer_traced(&mut a, &mut b, &mut handle, 7);
    pump(&mut [&mut a, &mut b], |_| !sender.pickups().is_empty());
    let pickup = sender.pickups()[0];
    drop(handle);
    let Closed::Now { epoch } = a.close_guard(guard, 2).unwrap() else {
        panic!("not closed");
    };
    pump(&mut [&mut a, &mut b], |drivers| {
        drivers[0].seal_reason(lane) == Ok(Some(SealReason::GuardClosed))
    });
    let _ = a.reopen_guard(guard, epoch, epoch).unwrap();
    pump(&mut [&mut a, &mut b], |drivers| {
        matches!(
            drivers[0].publication(lane),
            Err(DriverError::QuarantinedAlias { .. })
        )
    });
    // Closed with its facts, not lost: its boundary is past the message.
    pump(&mut [&mut a, &mut b], |drivers| {
        entry(drivers[0], sent).is_some_and(|entry| entry.state == JournalState::Closed)
    });
    assert_eq!(sender.closed(), [sent]);
    let facts = entry(&a, sent).unwrap().network.unwrap();
    assert!(facts.boundary > Some(pickup.1.position), "{facts:?}");
}
