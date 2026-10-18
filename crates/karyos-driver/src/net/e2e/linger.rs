// SPDX-License-Identifier: Apache-2.0

//! A network publication's removal linger end to end
//! (`quantstratum-docs: karyos/design/driver-network-agents.md` §7,
//! coordinator ACS 16954): the tail is delivered, each lane's EOS names
//! its seal, repair is served through the linger, the receiver's image ends
//! cleanly, and the stream is freed only once the sender's session is
//! removed. A driver stop or a sender failure frees it at once, with no
//! linger.
//!
//! The lingers here are short and real (the network's clock is the host's
//! monotonic clock, whatever the driver clock is): each test bounds what
//! it waits for by the linger it set.

use std::time::{Duration, Instant};

use karyos_client::OfferOutcome;
use karyos_client::aggregate::{AggregateSubscription, LaneEnd, Terminal};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{Role, SealReason};
use karyos_sys::term_bytes::HeapTerms;

use super::{ANY_PORT, BUDGET, aggregate, bound, channel, pump, silent};
use crate::agents::{AgentConfig, ThreadingMode};
use crate::embedded::{AggregateHandle, DriverConfig, EmbeddedDriver, StreamState};
use crate::net::{NetworkConfig, NetworkStreamDefaults};

const MS: u64 = 1_000_000;

/// A driver whose removed publications linger for `linger` ns.
fn lingering(linger: u64) -> EmbeddedDriver {
    EmbeddedDriver::with_config(DriverConfig {
        network: Some(NetworkConfig {
            threading: ThreadingMode::Shared,
            agents: AgentConfig::default(),
            stream_defaults: NetworkStreamDefaults {
                publication_linger: linger,
                ..NetworkStreamDefaults::default()
            },
            ..NetworkConfig::default()
        }),
        ..DriverConfig::default()
    })
    .unwrap()
}

/// A publication of `lanes` lanes on `a` (lingering `linger`) and B's
/// required reader of its image.
fn pair(
    linger: u64,
    lanes: usize,
) -> (
    EmbeddedDriver,
    EmbeddedDriver,
    AggregateHandle,
    AggregateSubscription<HeapTerms>,
) {
    let (mut a, mut b) = (lingering(linger), lingering(linger));
    let _ = b
        .add_network_subscription(10, &channel(ANY_PORT, true))
        .unwrap();
    let address = bound(&b, 10);
    let publication = a
        .add_network_publication(aggregate(10, 3, lanes), &channel(address, true))
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

/// Offers `count` numbered messages on each lane of `publication`, all at
/// once, without reading.
fn offer_all(a: &mut EmbeddedDriver, publication: &AggregateHandle, lanes: u8, count: u32) {
    for lane in 0..lanes {
        let mut handle = a
            .publication(publication.lane(Lane::try_new(lane).unwrap()).unwrap())
            .unwrap();
        for index in 0..count {
            let mut payload = [0u8; 1000];
            payload[..4].copy_from_slice(&index.to_le_bytes());
            assert!(matches!(
                handle.offer(&payload).unwrap(),
                OfferOutcome::Accepted { .. }
            ));
        }
    }
}

/// Reads `reader` until its terminal, checking each lane's messages in
/// order; returns the terminal, each lane's end and its count.
fn read_to_end(
    a: &mut EmbeddedDriver,
    b: &mut EmbeddedDriver,
    reader: &mut AggregateSubscription<HeapTerms>,
) -> (Terminal, Vec<Option<LaneEnd>>, [u32; 2]) {
    let mut seen = [0u32; 2];
    let mut end = None;
    pump(&mut [a, b], |_| {
        let poll = reader.poll(
            |bytes, lane, _| {
                let lane = usize::from(lane.get());
                let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                assert_eq!(index, seen[lane], "lane {lane} in order");
                seen[lane] += 1;
            },
            BUDGET,
        );
        if let Some(terminal) = poll.terminal {
            end = Some((terminal, poll.lanes.iter().map(|lane| lane.end).collect()));
        }
        end.is_some()
    });
    let (terminal, ends) = end.unwrap();
    (terminal, ends, seen)
}

fn closed_at_eos(end: Option<LaneEnd>) -> bool {
    matches!(
        end,
        Some(LaneEnd::Closed {
            reason: SealReason::EndOfStream,
            ..
        })
    )
}

fn eos_sent(driver: &EmbeddedDriver) -> u64 {
    driver
        .net
        .as_ref()
        .and_then(|net| net.sender_counters())
        .map_or(0, |counters| counters.eos_sent)
}

fn stream_state(driver: &EmbeddedDriver, publication: &AggregateHandle, lane: u8) -> StreamState {
    driver
        .stream_state(publication.lane(Lane::try_new(lane).unwrap()).unwrap())
        .unwrap()
}

/// The tail committed after the receiver's last SM is delivered, then
/// each lane's EOS: the image ends cleanly, at `EndOfStream`.
#[test]
fn a_removed_publication_delivers_its_tail_then_ends_at_its_eos() {
    let (mut a, mut b, publication, mut reader) = pair(200 * MS, 1);
    offer_all(&mut a, &publication, 1, 8);
    a.remove_aggregate(&publication).unwrap();
    let (terminal, ends, seen) = read_to_end(&mut a, &mut b, &mut reader);
    assert_eq!(seen[0], 8);
    assert!(terminal.clean, "{ends:?}");
    assert!(closed_at_eos(ends[0]), "{ends:?}");
    assert!(eos_sent(&a) >= 1);
}

/// Repair is served through the linger: the tail datagram is lost on the
/// wire, the EOS names the bound past it, the receiver NAKs the hole and
/// the sender repairs it before the image ends cleanly.
#[test]
fn repair_is_served_during_the_linger() {
    let (mut a, mut b, publication, mut reader) = pair(2_000 * MS, 1);
    // From now on: the third DATA datagram, the tail, is lost.
    b.net.as_mut().unwrap().drop_receiver_data(&[2]);
    offer_all(&mut a, &publication, 1, 3);
    a.remove_aggregate(&publication).unwrap();
    let (terminal, ends, seen) = read_to_end(&mut a, &mut b, &mut reader);
    assert_eq!(seen[0], 3);
    assert!(terminal.clean && closed_at_eos(ends[0]), "{ends:?}");
    let receiver = b.net.as_ref().unwrap().receiver_counters().unwrap();
    assert!(receiver.naks >= 1, "{receiver:?}");
}

/// The stream outlives the removal by its linger: still retiring while the
/// sender lingers (and its EOS repeats), freed only after the linger and
/// `RemoveSenderSession`.
#[test]
fn the_stream_is_freed_only_after_the_linger() {
    let linger = 300 * MS;
    let (mut a, mut b, publication, mut reader) = pair(linger, 1);
    offer_all(&mut a, &publication, 1, 2);
    let removed = Instant::now();
    a.remove_aggregate(&publication).unwrap();
    let (terminal, _, _) = read_to_end(&mut a, &mut b, &mut reader);
    assert!(terminal.clean);
    // The image ended at the EOS, well before the linger is over.
    assert_eq!(stream_state(&a, &publication, 0), StreamState::Retiring);
    assert!(a.network_publication_state(&publication).is_some());
    pump(&mut [&mut a, &mut b], |drivers| {
        stream_state(drivers[0], &publication, 0) == StreamState::Freed
    });
    assert!(removed.elapsed() >= Duration::from_nanos(linger));
    assert!(a.network_publication_state(&publication).is_none());
    assert!(eos_sent(&a) >= 2, "repeated through the linger");
}

/// A zero linger: each lane's EOS goes once, and the stream is freed at
/// once after it.
#[test]
fn a_zero_linger_sends_eos_once_then_frees() {
    let (mut a, mut b, publication, mut reader) = pair(0, 1);
    offer_all(&mut a, &publication, 1, 2);
    a.remove_aggregate(&publication).unwrap();
    pump(&mut [&mut a, &mut b], |drivers| {
        stream_state(drivers[0], &publication, 0) == StreamState::Freed
    });
    assert_eq!(eos_sent(&a), 1);
    let (terminal, ends, _) = read_to_end(&mut a, &mut b, &mut reader);
    assert!(terminal.clean && closed_at_eos(ends[0]), "{ends:?}");
}

/// A driver stop during the linger frees the stream at once: no linger,
/// and a stop before the drain sends no EOS.
#[test]
fn a_driver_stop_frees_the_stream_with_no_linger() {
    // Stopped before the sender ran: no EOS left it.
    let (mut a, mut b, publication, _reader) = pair(60_000 * MS, 1);
    offer_all(&mut a, &publication, 1, 2);
    a.remove_aggregate(&publication).unwrap();
    let _ = a.close_network();
    let _ = a.do_work().unwrap();
    assert_eq!(stream_state(&a, &publication, 0), StreamState::Freed);
    for _ in 0..50 {
        let _ = b.do_work().unwrap();
    }
    let receiver = b.net.as_ref().unwrap().receiver_counters().unwrap();
    assert_eq!(receiver.eos_bounds, 0, "{receiver:?}");
    // Stopped in the middle of a long linger: freed at once, not after it.
    let (mut a, mut b, publication, mut reader) = pair(60_000 * MS, 1);
    a.remove_aggregate(&publication).unwrap();
    let (terminal, _, _) = read_to_end(&mut a, &mut b, &mut reader);
    assert!(terminal.clean);
    assert_eq!(stream_state(&a, &publication, 0), StreamState::Retiring);
    let _ = a.close_network();
    let _ = a.do_work().unwrap();
    assert_eq!(stream_state(&a, &publication, 0), StreamState::Freed);
}

/// A sender failure during the linger frees the stream at once (DN-9:
/// fatal for the driver), with no linger.
#[test]
fn a_sender_failure_frees_the_stream_with_no_linger() {
    let (mut a, mut b, publication, mut reader) = pair(60_000 * MS, 1);
    a.remove_aggregate(&publication).unwrap();
    let (terminal, _, _) = read_to_end(&mut a, &mut b, &mut reader);
    assert!(terminal.clean);
    assert_eq!(stream_state(&a, &publication, 0), StreamState::Retiring);
    a.net
        .as_ref()
        .unwrap()
        .links()
        .sender
        .post(|_| crate::agents::AgentCommand::Panic)
        .unwrap();
    assert!(a.do_work().is_err(), "the failure is fatal");
    let _ = a.do_work();
    assert_eq!(stream_state(&a, &publication, 0), StreamState::Freed);
}

/// An aggregate: each lane drains to its own seal and sends its own EOS;
/// the image ends cleanly once both lanes reach theirs, and the
/// publication is freed after the linger.
#[test]
fn each_lane_of_an_aggregate_ends_at_its_own_eos() {
    let (mut a, mut b, publication, mut reader) = pair(200 * MS, 2);
    offer_all(&mut a, &publication, 2, 4);
    a.remove_aggregate(&publication).unwrap();
    let (terminal, ends, seen) = read_to_end(&mut a, &mut b, &mut reader);
    assert_eq!(seen, [4, 4]);
    assert!(terminal.clean, "{ends:?}");
    assert!(ends.iter().all(|end| closed_at_eos(*end)), "{ends:?}");
    assert!(eos_sent(&a) >= 2, "one per lane");
    pump(&mut [&mut a, &mut b], |drivers| {
        (0..2).all(|lane| stream_state(drivers[0], &publication, lane) == StreamState::Freed)
    });
}

fn removals_undrained(driver: &EmbeddedDriver) -> u64 {
    driver
        .net
        .as_ref()
        .and_then(|net| net.sender_counters())
        .map_or(0, |counters| counters.removals_undrained)
}

/// A publication whose receiver stopped sending SMs before the removal (B
/// is no longer driven): its flow-control window never opens again, so
/// lane 0 can never drain past it. Offered until the publisher is held,
/// then removed with `linger`.
fn undrainable(
    linger: u64,
) -> (
    EmbeddedDriver,
    EmbeddedDriver,
    AggregateHandle,
    Instant,
    AggregateSubscription<HeapTerms>,
) {
    let (mut a, b, publication, reader) = pair(linger, 1);
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let mut held = 0;
    for _ in 0..20_000 {
        let _ = a.do_work().unwrap();
        match lane.offer(&[5u8; 1000]).unwrap() {
            OfferOutcome::Accepted { .. } => held = 0,
            _ => held += 1,
        }
        if held > 200 {
            break;
        }
    }
    assert!(held > 200, "the publisher was never held");
    drop(lane);
    let removed = Instant::now();
    a.remove_aggregate(&publication).unwrap();
    (a, b, publication, removed, reader)
}

/// Drives B again, so it reads what A sent while it was stopped, and
/// returns how many EOS bounds its receiver recorded.
fn eos_bounds_received(b: &mut EmbeddedDriver) -> u64 {
    for _ in 0..200 {
        let _ = b.do_work().unwrap();
    }
    b.net
        .as_ref()
        .and_then(|net| net.receiver_counters())
        .map_or(0, |counters| counters.eos_bounds)
}

/// The drain is bounded by the linger from the removal's start: a lane that
/// cannot drain (its receiver stopped sending SMs, so its window is
/// closed) sends no EOS, the removal is counted undrained, and the stream
/// is still freed after the linger.
#[test]
fn an_undrainable_lane_is_given_up_at_the_linger() {
    let linger = 300 * MS;
    let (mut a, mut b, publication, removed, _reader) = undrainable(linger);
    let mut freed = false;
    for _ in 0..40_000 {
        let _ = a.do_work().unwrap();
        if stream_state(&a, &publication, 0) == StreamState::Freed {
            freed = true;
            break;
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    assert!(freed, "never freed");
    assert!(removed.elapsed() >= Duration::from_nanos(linger));
    assert_eq!(eos_sent(&a), 0);
    assert_eq!(removals_undrained(&a), 1);
    assert_eq!(eos_bounds_received(&mut b), 0);
}

/// With a zero linger the undrainable lane is given up at the drain bound,
/// one EOS interval (`path_heartbeat_interval`, 100 ms) after the removal:
/// no EOS, counted once, then freed.
#[test]
fn a_zero_linger_gives_an_undrainable_lane_up_within_one_interval() {
    let interval = Duration::from_nanos(AgentConfig::default().path_heartbeat_interval);
    let (mut a, mut b, publication, removed, _reader) = undrainable(0);
    let mut freed = None;
    for _ in 0..40_000 {
        let _ = a.do_work().unwrap();
        if stream_state(&a, &publication, 0) == StreamState::Freed {
            freed = Some(removed.elapsed());
            break;
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    let freed = freed.expect("never freed");
    assert!(freed >= interval, "{freed:?}");
    assert_eq!(eos_sent(&a), 0);
    assert_eq!(removals_undrained(&a), 1);
    assert_eq!(eos_bounds_received(&mut b), 0);
}

/// Re-adding a removed publication's key while its removal lingers is
/// refused with `DuplicateStream`, and nothing is left configured; once
/// the linger ended and its streams were freed, the same key is accepted.
#[test]
fn a_key_is_refused_during_the_linger_and_accepted_after_it() {
    let (mut a, mut b, publication, mut reader) = pair(200 * MS, 1);
    let silent = silent();
    let address = silent.local_addr().unwrap();
    a.remove_aggregate(&publication).unwrap();
    let (terminal, _, _) = read_to_end(&mut a, &mut b, &mut reader);
    assert!(terminal.clean);
    assert!(matches!(
        a.add_network_publication(aggregate(10, 3, 1), &channel(address, true)),
        Err(crate::error::DriverError::DuplicateStream {
            stream_id: 10,
            session_id: 3
        })
    ));
    pump(&mut [&mut a, &mut b], |drivers| {
        stream_state(drivers[0], &publication, 0) == StreamState::Freed
    });
    assert!(
        a.add_network_publication(aggregate(10, 3, 1), &channel(address, true))
            .is_ok()
    );
}

fn sender_counters(driver: &EmbeddedDriver) -> crate::agents::roles::SenderCounters {
    driver
        .net
        .as_ref()
        .and_then(|net| net.sender_counters())
        .unwrap()
}

/// A guarded lane whose guard closed sends no EOS (GC-6): the publication
/// submitted everything and its reader read it, the guard closes, the
/// publication is removed, and no EOS leaves it. The removal is counted as
/// guard closed, not undrained, and the stream is still freed after the
/// linger.
#[test]
fn a_closed_guard_sends_no_eos_at_removal() {
    use karyos_sys::guard::Closed;

    use crate::net::NetworkGuard;

    let (mut a, mut b) = (lingering(100 * MS), lingering(100 * MS));
    let guard = a.add_guard("linger").unwrap();
    assert_eq!(a.reopen_guard(guard, 1, 1).unwrap(), 2);
    let _ = b
        .add_network_subscription(10, &channel(ANY_PORT, true))
        .unwrap();
    let address = bound(&b, 10);
    // Spare slots for the sender's reservation and the guard's walker.
    let mut config = aggregate(10, 3, 1);
    config.stream.buffer.spare_slots = 4;
    let publication = a
        .add_guarded_network_publication(
            config,
            &channel(address, true),
            NetworkGuard {
                guard,
                messages: 2,
                rate: None,
            },
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
    offer_all(&mut a, &publication, 1, 2);
    let mut seen = 0;
    pump(&mut [&mut a, &mut b], |_| {
        let _ = reader.poll(|_, _, _| seen += 1, BUDGET);
        seen == 2
    });
    let Closed::Now { epoch } = a.close_guard(guard, 2).unwrap() else {
        panic!("not closed");
    };
    pump(&mut [&mut a, &mut b], |drivers| {
        drivers[0]
            .close_guard_ack(guard, epoch)
            .unwrap()
            .effective()
            == Some(true)
    });
    a.remove_aggregate(&publication).unwrap();
    pump(&mut [&mut a, &mut b], |drivers| {
        stream_state(drivers[0], &publication, 0) == StreamState::Freed
    });
    let counters = sender_counters(&a);
    assert_eq!(counters.eos_sent, 0, "{counters:?}");
    assert_eq!(
        (counters.removals_guard_closed, counters.removals_undrained),
        (1, 0),
        "{counters:?}"
    );
    assert_eq!(eos_bounds_received(&mut b), 0);
}

/// #354 review: a guarded lane whose guard closed before its committed
/// messages left cannot drain (its first sends never reach the seal), so
/// it is given up at the drain bound. It sends no EOS, the removal is
/// counted as guard closed, not undrained, and the stream is still freed,
/// no earlier than the linger.
#[test]
fn a_closed_guard_lane_is_given_up_at_the_drain_bound() {
    use karyos_sys::guard::Closed;

    use crate::net::NetworkGuard;

    let linger = 200 * MS;
    let (mut a, mut b) = (lingering(linger), lingering(linger));
    let guard = a.add_guard("give-up").unwrap();
    assert_eq!(a.reopen_guard(guard, 1, 1).unwrap(), 2);
    let _ = b
        .add_network_subscription(10, &channel(ANY_PORT, true))
        .unwrap();
    let address = bound(&b, 10);
    let mut config = aggregate(10, 3, 1);
    config.stream.buffer.spare_slots = 4;
    let publication = a
        .add_guarded_network_publication(
            config,
            &channel(address, true),
            NetworkGuard {
                guard,
                messages: 2,
                rate: None,
            },
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
    // Committed, then closed before any cycle of A could send them: the
    // sender is shared, so it runs only in A's duty.
    offer_all(&mut a, &publication, 1, 2);
    let Closed::Now { .. } = a.close_guard(guard, 2).unwrap() else {
        panic!("not closed");
    };
    let removed = Instant::now();
    a.remove_aggregate(&publication).unwrap();
    let mut seen = 0;
    pump(&mut [&mut a, &mut b], |drivers| {
        let _ = reader.poll(|_, _, _| seen += 1, BUDGET);
        stream_state(drivers[0], &publication, 0) == StreamState::Freed
    });
    assert!(removed.elapsed() >= Duration::from_nanos(linger));
    assert_eq!(seen, 0, "a message left after the close");
    let counters = sender_counters(&a);
    assert_eq!(counters.eos_sent, 0, "{counters:?}");
    assert_eq!(
        (counters.removals_guard_closed, counters.removals_undrained),
        (1, 0),
        "{counters:?}"
    );
    assert_eq!(eos_bounds_received(&mut b), 0);
}

/// A removal with no established receiver ends at once, with no linger:
/// nobody would read its EOS. It is counted, and sends none.
#[test]
fn a_removal_with_no_established_receiver_ends_at_once() {
    let mut a = lingering(60_000 * MS);
    let silent = silent();
    let publication = a
        .add_network_publication(
            aggregate(10, 3, 1),
            &channel(silent.local_addr().unwrap(), true),
        )
        .unwrap();
    for _ in 0..20 {
        let _ = a.do_work().unwrap();
    }
    let removed = Instant::now();
    a.remove_aggregate(&publication).unwrap();
    pump(&mut [&mut a], |drivers| {
        stream_state(drivers[0], &publication, 0) == StreamState::Freed
    });
    assert!(removed.elapsed() < Duration::from_secs(10), "no linger");
    let counters = sender_counters(&a);
    assert_eq!(
        (counters.removals_unestablished, counters.eos_sent),
        (1, 0),
        "{counters:?}"
    );
}

/// `publication_linger` is at most 60 s: 60 s is accepted, a nanosecond
/// more is refused as `InvalidConfig`.
#[test]
fn a_linger_above_sixty_seconds_is_refused() {
    let with = |linger| {
        EmbeddedDriver::with_config(DriverConfig {
            network: Some(NetworkConfig {
                threading: ThreadingMode::Shared,
                agents: AgentConfig::default(),
                stream_defaults: NetworkStreamDefaults {
                    publication_linger: linger,
                    ..NetworkStreamDefaults::default()
                },
                ..NetworkConfig::default()
            }),
            ..DriverConfig::default()
        })
    };
    assert_eq!(crate::net::MAX_PUBLICATION_LINGER, 60_000_000_000);
    assert!(with(crate::net::MAX_PUBLICATION_LINGER).is_ok());
    assert!(matches!(
        with(crate::net::MAX_PUBLICATION_LINGER + 1),
        Err(crate::error::DriverError::InvalidConfig)
    ));
}

/// A removed publication's lanes send only EOS through the linger, never
/// an idle heartbeat (SPEC §6, G1): the linger outlasts several
/// `sender_heartbeat_interval`s, yet `heartbeats_sent` stays where the
/// removal found it while the EOS repeats; and the receiver, whose image
/// ended at the EOS, solicits no new image. (The repeated EOS frames
/// reach it unbound once its image ended; an EOS solicits nothing, where
/// an unbound idle heartbeat would.)
#[test]
fn a_removed_publication_sends_only_eos_through_its_linger() {
    let interval = AgentConfig::default().sender_heartbeat_interval;
    let linger = 6 * interval;
    let (mut a, mut b, publication, mut reader) = pair(linger, 1);
    offer_all(&mut a, &publication, 1, 4);
    let mut seen = 0;
    pump(&mut [&mut a, &mut b], |_| {
        let _ = reader.poll(|_, _, _| seen += 1, BUDGET);
        seen == 4
    });
    let heartbeats = sender_counters(&a).heartbeats_sent;
    a.remove_aggregate(&publication).unwrap();
    let (terminal, ends, _) = read_to_end(&mut a, &mut b, &mut reader);
    assert!(terminal.clean && closed_at_eos(ends[0]), "{ends:?}");
    pump(&mut [&mut a, &mut b], |drivers| {
        stream_state(drivers[0], &publication, 0) == StreamState::Freed
    });
    let sender = sender_counters(&a);
    assert_eq!(sender.heartbeats_sent, heartbeats, "{sender:?}");
    assert!(
        sender.eos_sent >= 2,
        "repeated through the linger: {sender:?}"
    );
    let receiver = b.net.as_ref().unwrap().receiver_counters().unwrap();
    assert_eq!(receiver.create_image, 1, "{receiver:?}");
}

/// rp-w5b follow-up (ACS 17249): a removed publication over two paths
/// sends each lane's EOS on both paths; the tail is delivered once, in
/// order, and the image ends cleanly at `EndOfStream`. Linux, after the
/// multicast probe; the second path is loopback, as in
/// `a_two_path_publication_reaches_a_two_path_subscription`.
#[cfg(target_os = "linux")]
#[test]
fn a_removed_two_path_publication_ends_at_its_eos_on_both_paths() {
    use std::io::Write as _;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use karyos_protocol::channel::{Destination, Interface, Security, UdpConfig};

    if let Err(why) = super::multicast_probe() {
        let _ = writeln!(
            std::io::stderr(),
            "SKIPPED a_removed_two_path_publication_ends_at_its_eos_on_both_paths: {why}"
        );
        return;
    }
    let port = free_address().port();
    let group = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 0, 5)), port);
    let channel = UdpConfig {
        destination: Destination::Multicast { group, ttl: None },
        interface: None,
        paths: vec![
            Interface::Address(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            Interface::Address(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ],
        reliable: true,
        flow_control: None,
        security: Security::Trusted,
    };
    let (mut a, mut b) = (lingering(200 * MS), lingering(200 * MS));
    for side in [&mut a, &mut b] {
        side.net.as_mut().unwrap().assume_isolated_paths();
    }
    let _ = b.add_network_subscription(10, &channel).unwrap();
    let publication = a
        .add_network_publication(aggregate(10, 3, 1), &channel)
        .unwrap();
    let mut image = None;
    pump(&mut [&mut a, &mut b], |drivers| {
        image = drivers[1].network_image(10, 3);
        image.is_some()
    });
    let mut reader = b
        .subscribe_aggregate(&image.unwrap(), Role::Required)
        .unwrap();
    offer_all(&mut a, &publication, 1, 8);
    a.remove_aggregate(&publication).unwrap();
    let (terminal, ends, seen) = read_to_end(&mut a, &mut b, &mut reader);
    assert_eq!(seen[0], 8);
    assert!(terminal.clean, "{ends:?}");
    assert!(closed_at_eos(ends[0]), "{ends:?}");
    assert!(eos_sent(&a) >= 1);
}
