// SPDX-License-Identifier: Apache-2.0

//! Timed lanes of a network publication end to end (`quantstratum-docs:
//! karyos/design/timed-tx.md`; P2.11 PR1, the software route): the sender
//! holds each message until its requested time, then sends it, and frees
//! its schedule entry once it left. The clocks are real (the network
//! clock is the host's monotonic clock), so each bound has a margin.

use std::time::{Duration, Instant};

use karyos_client::OfferOutcome;
use karyos_client::schedule::ScheduleOptions;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::Role;

use super::{ANY_PORT, BUDGET, aggregate, bound, channel, driver, pump, shared};
use crate::embedded::{AggregateHandle, EmbeddedDriver};

/// A timed publication of one lane with a ring of `capacity` and the
/// settings `options` on `a`, over a channel `reliable` or not, and B's
/// required reader of its image.
fn timed_pair(
    capacity: u32,
    options: ScheduleOptions,
    reliable: bool,
) -> (
    EmbeddedDriver,
    EmbeddedDriver,
    AggregateHandle,
    karyos_client::aggregate::AggregateSubscription<karyos_sys::term_bytes::HeapTerms>,
) {
    let (mut a, mut b) = (
        driver(crate::agents::ThreadingMode::Shared),
        driver(crate::agents::ThreadingMode::Shared),
    );
    let _ = b
        .add_network_subscription(10, &channel(ANY_PORT, reliable))
        .unwrap();
    let address = bound(&b, 10);
    let mut config = aggregate(10, 3, 1);
    config.stream.buffer.schedule_capacity = capacity;
    let publication = a
        .add_timed_network_publication(config, &channel(address, reliable), None, options)
        .unwrap();
    let mut image = None;
    pump(&mut [&mut a, &mut b], |drivers| {
        image = drivers[1].network_image(10, 3);
        image.is_some()
    });
    let reader = b
        .subscribe_aggregate(&image.unwrap(), Role::Required)
        .unwrap();
    (a, b, publication, reader)
}

/// P2.11 PR1: a timed lane's schedule ring is freed as its messages leave,
/// so it takes more offers than its ring holds, each read once and in
/// order. Before PR1 the network sender read no schedule ring: after
/// `capacity` offers every one was back-pressured, for good.
#[test]
fn a_timed_network_lane_takes_more_offers_than_its_ring() {
    let (mut a, mut b, publication, mut reader) = timed_pair(4, ScheduleOptions::default(), false);
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let (mut sent, mut seen) = (0u32, 0u32);
    pump(&mut [&mut a, &mut b], |_| {
        while sent < 16 {
            // Due at once: a time already past goes immediately.
            let now = karyos_sys::host_clock::host_monotonic_ns();
            match lane.offer_at(&sent.to_le_bytes(), now).unwrap() {
                OfferOutcome::Accepted { .. } => sent += 1,
                _ => break,
            }
        }
        let _ = reader.poll(
            |bytes, _, _| {
                let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                assert_eq!(index, seen, "in order, exactly once");
                seen += 1;
            },
            BUDGET,
        );
        seen == 16
    });
}

/// P2.11 PR1: a message offered for 150 ms from now is not read before
/// its time, and is read within a bounded slack after it (2 s, for a
/// loaded Linux runner). A message offered after it with a past time
/// waits behind it: times on a lane are not reordered.
#[test]
fn a_timed_network_message_is_not_sent_before_its_time() {
    const AHEAD: u64 = 150_000_000;
    const SLACK: Duration = Duration::from_secs(2);
    let (mut a, mut b, publication, mut reader) = timed_pair(4, ScheduleOptions::default(), false);
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let start = karyos_sys::host_clock::host_monotonic_ns();
    let at = start + AHEAD;
    assert!(matches!(
        lane.offer_at(&0u32.to_le_bytes(), at).unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    let issued = Instant::now();
    let mut read = Vec::new();
    pump(&mut [&mut a, &mut b], |_| {
        let _ = reader.poll(
            |bytes, _, _| {
                read.push((
                    u32::from_le_bytes(bytes[..4].try_into().unwrap()),
                    karyos_sys::host_clock::host_monotonic_ns(),
                ));
            },
            BUDGET,
        );
        !read.is_empty()
    });
    let (index, when) = read[0];
    assert_eq!(index, 0);
    assert!(when >= at, "read {} ns before its time", at - when);
    assert!(issued.elapsed() < Duration::from_nanos(AHEAD) + SLACK);
}

/// P2.11 PR1: a timed lane sends one message per datagram, so each waits
/// for its own time only: eight small messages offered at once, all due,
/// take eight datagrams, each a timed head sent once. Sent 20 ms after
/// their time, past the 1 ms tolerance, they are late, counted in the gate
/// and in the lane's counter cells.
#[test]
fn a_timed_lane_sends_one_message_per_datagram_and_counts_late_ones() {
    let (mut a, mut b, publication, mut reader) = timed_pair(16, ScheduleOptions::default(), false);
    let stream = publication.lane(Lane::ZERO).unwrap();
    let mut lane = a.publication(stream).unwrap();
    let now = karyos_sys::host_clock::host_monotonic_ns();
    for index in 0..8u32 {
        assert!(matches!(
            lane.offer_at(&index.to_le_bytes(), now).unwrap(),
            OfferOutcome::Accepted { .. }
        ));
    }
    // No duty yet: they leave late.
    std::thread::sleep(Duration::from_millis(20));
    let mut seen = 0u32;
    pump(&mut [&mut a, &mut b], |_| {
        let _ = reader.poll(
            |bytes, _, _| {
                let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                assert_eq!(index, seen, "in order, exactly once");
                seen += 1;
            },
            BUDGET,
        );
        seen == 8
    });
    let agents = shared(&mut a);
    let staged = agents.sender.outbound_counters(0).unwrap().staged;
    let counts = agents.sender.outbound_timed_counts(0).unwrap();
    assert_eq!((staged, counts.sent), (8, 8), "{counts:?}");
    assert_eq!(counts.late_sends, 8, "{counts:?}");
    let cells = a.timed_counters(stream).unwrap().unwrap();
    let cell = cells.late_sends.as_ref().unwrap();
    // The cell's value, read by adding nothing.
    assert_eq!(cell.increment(0).unwrap(), 8);
}

/// P2.11 PR1: an unreliable lane's reset drops the heads it held for
/// their time, unsent: each counts as dropped, and their schedule
/// entries are done, so the ring takes new offers again (it does not
/// leak) and they are delivered.
#[test]
fn an_unreliable_reset_frees_the_ring_of_held_heads() {
    let options = ScheduleOptions {
        max_horizon: 120_000_000_000,
        ..ScheduleOptions::default()
    };
    let (mut a, mut b, publication, _reader) = timed_pair(4, options, false);
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    // Four heads held for a time far ahead: the ring is full.
    let ahead = karyos_sys::host_clock::host_monotonic_ns() + 60_000_000_000;
    for index in 0..4u32 {
        assert!(matches!(
            lane.offer_at(&index.to_le_bytes(), ahead).unwrap(),
            OfferOutcome::Accepted { .. }
        ));
    }
    assert!(matches!(
        lane.offer_at(&4u32.to_le_bytes(), ahead).unwrap(),
        OfferOutcome::BackPressured
    ));
    pump(&mut [&mut a, &mut b], |drivers| {
        shared(drivers[0])
            .sender
            .outbound_counters(0)
            .unwrap()
            .staged
            == 4
    });
    let (endpoint, alias) = a
        .net
        .as_ref()
        .unwrap()
        .publication_route(publication.registration())
        .unwrap();
    a.net
        .as_ref()
        .unwrap()
        .links()
        .sender
        .post(|_reply| crate::agents::AgentCommand::ForceReset { endpoint, alias })
        .unwrap();
    pump(&mut [&mut a, &mut b], |drivers| {
        drivers[0].net.as_ref().unwrap().reopened() >= 1
    });
    let counts = shared(&mut a).sender.outbound_timed_counts(0).unwrap();
    assert_eq!((counts.dropped, counts.sent), (4, 0), "{counts:?}");
    // The ring has room again; times on the lane do not go back.
    let mut accepted = 0u32;
    pump(&mut [&mut a, &mut b], |_| {
        if let Ok(OfferOutcome::Accepted { .. }) =
            lane.offer_at(&(4 + accepted).to_le_bytes(), ahead)
        {
            accepted += 1;
        }
        accepted == 4
    });
}

/// P2.11 PR1: a message larger than a datagram goes as fragments, each
/// in its own datagram, all held for the message's time: it is read
/// whole, not before its time, and a small one after it follows.
#[test]
fn a_fragmented_timed_message_is_read_whole_at_its_time() {
    const AHEAD: u64 = 100_000_000;
    let (mut a, mut b, publication, mut reader) = timed_pair(4, ScheduleOptions::default(), false);
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let at = karyos_sys::host_clock::host_monotonic_ns() + AHEAD;
    let big = [7u8; 5000];
    assert!(matches!(
        lane.offer_at(&big, at).unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    assert!(matches!(
        lane.offer_at(&[9u8; 10], at).unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    let mut read: Vec<(usize, u64)> = Vec::new();
    pump(&mut [&mut a, &mut b], |_| {
        let _ = reader.poll(
            |bytes, _, _| {
                read.push((bytes.len(), karyos_sys::host_clock::host_monotonic_ns()));
            },
            BUDGET,
        );
        read.len() == 2
    });
    assert_eq!(read[0].0, 5000, "whole, first");
    assert_eq!(read[1].0, 10);
    assert!(read[0].1 >= at, "read before its time");
    let staged = shared(&mut a).sender.outbound_counters(0).unwrap().staged;
    assert!(staged >= 5, "a fragment per datagram: {staged}");
}

/// P2.11 PR1 (E5 for timed lanes): in steady state a network cycle of a
/// timed publication allocates nothing, on either side: the timed gate's
/// record, the probe read and the ring releases reuse what the add
/// allocated.
#[test]
fn a_steady_timed_network_cycle_allocates_nothing() {
    use karyos_sys::alloc_count::count;

    let ((), made) = count(|| drop(std::hint::black_box(vec![0_u8; 8])));
    assert!(made > 0, "the counting allocator counts in this binary");
    let (mut a, mut b, publication, mut reader) = timed_pair(64, ScheduleOptions::default(), false);
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let (mut sent, mut seen, mut work) = (0u32, 0u32, [0u64; 2]);
    let offer = |lane: &mut karyos_client::ClientPublication<_>, sent: &mut u32, until| {
        while *sent < until {
            let now = karyos_sys::host_clock::host_monotonic_ns();
            match lane.offer_at(&sent.to_le_bytes(), now).unwrap() {
                OfferOutcome::Accepted { .. } => *sent += 1,
                _ => break,
            }
        }
    };
    // Warm up: every buffer the path keeps is sized by real traffic.
    pump(&mut [&mut a, &mut b], |_| {
        offer(&mut lane, &mut sent, 128);
        let _ = reader.poll(|_, _, _| seen += 1, BUDGET);
        seen == 128
    });
    for _ in 0..2_000 {
        offer(&mut lane, &mut sent, 384);
        for (side, driver) in [&mut a, &mut b].into_iter().enumerate() {
            let ((units, error), made) = count(|| driver.serve_network());
            assert!(error.is_none());
            assert_eq!(made, 0, "side {side}: {units} units allocated");
            work[side] += u64::from(units);
        }
        let _ = (a.do_work().unwrap(), b.do_work().unwrap());
        let _ = reader.poll(|_, _, _| seen += 1, BUDGET);
        if seen == 384 {
            break;
        }
        std::thread::sleep(Duration::from_micros(50));
    }
    assert_eq!(seen, 384);
    assert!(
        work[0] > 0 && work[1] > 0,
        "counted cycles did work: {work:?}"
    );
}

/// P2.11 PR1: a guarded timed lane whose guard closes while its head waits
/// for its time: the guard gate is asked on every probe, so the close
/// becomes effective at once, the held message never leaves, and its
/// outcome is final.
#[test]
fn a_guard_close_ends_a_timed_head_that_waits() {
    use karyos_sys::guard::Closed;

    use crate::net::NetworkGuard;

    let (mut a, mut b) = (
        driver(crate::agents::ThreadingMode::Shared),
        driver(crate::agents::ThreadingMode::Shared),
    );
    let guard = a.add_guard("timed").unwrap();
    assert_eq!(a.reopen_guard(guard, 1, 1).unwrap(), 2);
    let _ = b
        .add_network_subscription(10, &channel(ANY_PORT, false))
        .unwrap();
    let address = bound(&b, 10);
    let mut config = aggregate(10, 3, 1);
    config.stream.buffer.schedule_capacity = 4;
    config.stream.buffer.spare_slots = 4;
    let publication = a
        .add_timed_network_publication(
            config,
            &channel(address, false),
            Some(NetworkGuard {
                guard,
                messages: 2,
                rate: None,
            }),
            ScheduleOptions::default(),
        )
        .unwrap();
    let mut image = None;
    pump(&mut [&mut a, &mut b], |drivers| {
        image = drivers[1].network_image(10, 3);
        image.is_some()
    });
    let mut reader = b
        .subscribe_aggregate(&image.unwrap(), Role::Required)
        .unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let at = karyos_sys::host_clock::host_monotonic_ns() + 800_000_000;
    assert!(matches!(
        lane.offer_at(&0u32.to_le_bytes(), at).unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    pump(&mut [&mut a, &mut b], |drivers| {
        shared(drivers[0])
            .sender
            .outbound_counters(0)
            .unwrap()
            .staged
            == 1
    });
    let Closed::Now { epoch } = a.close_guard(guard, 2).unwrap() else {
        panic!("not closed");
    };
    let closed = Instant::now();
    pump(&mut [&mut a, &mut b], |drivers| {
        drivers[0]
            .close_guard_ack(guard, epoch)
            .unwrap()
            .effective()
            == Some(true)
    });
    assert!(
        closed.elapsed() < Duration::from_millis(800),
        "before its time"
    );
    // Past its time, still nothing: the held head never left.
    std::thread::sleep(Duration::from_millis(900));
    let mut seen = 0;
    for _ in 0..200 {
        let _ = (a.do_work().unwrap(), b.do_work().unwrap());
        let _ = reader.poll(|_, _, _| seen += 1, BUDGET);
    }
    assert_eq!(seen, 0, "a held head left after the close");
    let counts = shared(&mut a).sender.outbound_timed_counts(0).unwrap();
    assert_eq!(counts.sent, 0, "{counts:?}");
}

/// P2.11 PR1b: a reliable timed lane frees a message's entry once the
/// receivers acknowledged it (its registered position passed it), not when
/// it is sent: the ring holds the unacknowledged window. A ring of 4 below
/// that window back-pressures the offers, and recovers as the subscriber
/// consumes, so 32 messages go through it, each read once and in order.
#[test]
fn a_reliable_timed_lane_holds_its_ring_until_acknowledged() {
    let (mut a, mut b, publication, mut reader) = timed_pair(4, ScheduleOptions::default(), true);
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let (mut sent, mut seen, mut pressured) = (0u32, 0u32, 0u32);
    pump(&mut [&mut a, &mut b], |_| {
        while sent < 32 {
            let now = karyos_sys::host_clock::host_monotonic_ns();
            match lane.offer_at(&sent.to_le_bytes(), now).unwrap() {
                OfferOutcome::Accepted { .. } => sent += 1,
                _ => {
                    pressured += 1;
                    break;
                }
            }
        }
        let _ = reader.poll(
            |bytes, _, _| {
                let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                assert_eq!(index, seen, "in order, exactly once");
                seen += 1;
            },
            BUDGET,
        );
        seen == 32
    });
    assert!(pressured > 0, "the ring held the window");
    let agents = shared(&mut a);
    assert_eq!(
        agents.sender.outbound_counters(0).unwrap().schedule_faults,
        0
    );
    let counts = agents.sender.outbound_timed_counts(0).unwrap();
    assert_eq!((counts.sent, counts.rewound), (32, 0), "{counts:?}");
}

/// P2.11 PR1b: a reliable timed lane's endpoint reset rewinds it to its
/// registered position. The messages above it are read again with their
/// entries, which were held: resent at once, outside the late policy and
/// counted `rewound`, never late; the subscriber reads each once, in
/// order, and the schedule stays consistent (no fault).
#[test]
fn a_reliable_reset_resends_timed_messages_outside_the_policy() {
    let (mut a, mut b, publication, mut reader) = timed_pair(16, ScheduleOptions::default(), true);
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    // The subscriber holds: nothing is acknowledged while 8 are sent.
    let now = karyos_sys::host_clock::host_monotonic_ns();
    for index in 0..8u32 {
        assert!(matches!(
            lane.offer_at(&index.to_le_bytes(), now).unwrap(),
            OfferOutcome::Accepted { .. }
        ));
    }
    pump(&mut [&mut a, &mut b], |drivers| {
        shared(drivers[0])
            .sender
            .outbound_timed_counts(0)
            .unwrap()
            .sent
            == 8
    });
    let late = shared(&mut a)
        .sender
        .outbound_timed_counts(0)
        .unwrap()
        .late_sends;
    let (endpoint, alias) = a
        .net
        .as_ref()
        .unwrap()
        .publication_route(publication.registration())
        .unwrap();
    a.net
        .as_ref()
        .unwrap()
        .links()
        .sender
        .post(|_reply| crate::agents::AgentCommand::ForceReset { endpoint, alias })
        .unwrap();
    pump(&mut [&mut a, &mut b], |drivers| {
        drivers[0].net.as_ref().unwrap().reopened() >= 1
    });
    let mut seen = 0u32;
    pump(&mut [&mut a, &mut b], |_| {
        let _ = reader.poll(
            |bytes, _, _| {
                let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                assert_eq!(index, seen, "in order, exactly once");
                seen += 1;
            },
            BUDGET,
        );
        seen == 8
    });
    let agents = shared(&mut a);
    assert_eq!(
        agents.sender.outbound_counters(0).unwrap().schedule_faults,
        0
    );
    let counts = agents.sender.outbound_timed_counts(0).unwrap();
    assert!(counts.rewound >= 1, "{counts:?}");
    assert_eq!(counts.late_sends, late, "a resend is not late: {counts:?}");
    assert_eq!(counts.dropped, 0, "{counts:?}");
}

/// P2.11 PR1b: a NAK repair of a reliable timed lane goes through the
/// repair path, never the timed gate: it repeats data already sent. The
/// lost datagram is repaired and every message is read once and in order,
/// while the timed gate counts each message sent exactly once.
#[test]
fn a_repair_of_a_timed_lane_bypasses_the_timed_gate() {
    let (mut a, mut b, publication, mut reader) = timed_pair(16, ScheduleOptions::default(), true);
    // The receiver loses the second DATA datagram it sees.
    b.net.as_mut().unwrap().drop_receiver_data(&[1]);
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let now = karyos_sys::host_clock::host_monotonic_ns();
    for index in 0..6u32 {
        assert!(matches!(
            lane.offer_at(&index.to_le_bytes(), now).unwrap(),
            OfferOutcome::Accepted { .. }
        ));
    }
    let mut seen = 0u32;
    pump(&mut [&mut a, &mut b], |_| {
        let _ = reader.poll(
            |bytes, _, _| {
                let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                assert_eq!(index, seen, "in order, exactly once");
                seen += 1;
            },
            BUDGET,
        );
        seen == 6
    });
    let repairs = a.net.as_ref().unwrap().sender_counters().unwrap().repairs;
    assert!(repairs >= 1, "the loss was repaired");
    let counts = shared(&mut a).sender.outbound_timed_counts(0).unwrap();
    assert_eq!((counts.sent, counts.rewound), (6, 0), "{counts:?}");
}
