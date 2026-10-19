// SPDX-License-Identifier: Apache-2.0

//! The aggregate subscriber over an embedded driver (`quantstratum-docs:
//! karyos/design/aggregate-subscriber.md`, l3): every message once per lane
//! and in lane order, DRR service by quanta, fragmented messages across
//! polls, terminal and clean EOS, and redelivery after a panicking handler.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use karyos_client::aggregate::{AggregatePoll, AggregateSubscription};
use karyos_client::{ClientPublication, OfferOutcome};
use karyos_protocol::lanes::drr::Budget;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, Role};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

use super::*;

/// The largest charged frame: the MTU aligned to 32 bytes.
fn frame() -> u64 {
    u64::from(karyos_sys::sizing::align_frame(DEFAULT_MTU).unwrap())
}

/// A payload whose one frame is charged exactly `frame()`.
fn full_frame(sequence: u8) -> Vec<u8> {
    vec![sequence; usize::try_from(frame()).unwrap() - 32]
}

fn message(lane: u8, sequence: u8, length: usize) -> Vec<u8> {
    let mut bytes = vec![sequence ^ lane; length.max(2)];
    bytes[0] = lane;
    bytes[1] = sequence;
    bytes
}

struct Fixture {
    driver: EmbeddedDriver,
    handle: AggregateHandle,
    publications: Vec<ClientPublication>,
}

fn fixture(stream_id: i32, quanta: &[u64], max_subscribers: u8) -> Fixture {
    let mut driver = EmbeddedDriver::new().unwrap();
    let handle = driver
        .add_aggregate(AggregateConfig {
            stream: StreamConfig {
                buffer: LogBufferConfig {
                    term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                    spare_slots: 3,
                    max_subscribers,
                    mtu: DEFAULT_MTU,
                    max_reserved: MIN_TERM_LENGTH / 8,
                    initial_term_id: TermId::new(7),
                    lane: Lane::ZERO,
                    session_id: 1,
                    stream_id,
                    claim_deadline: 100,
                    publication: karyos_sys::log_buffer::PublicationMode::Exclusive,
                    schedule_capacity: 0,
                },
                allow_unconnected: true,
                on_required_loss: karyos_sys::log_buffer::LossPolicy::Hold,
                conflation: None,
            },
            quanta: quanta.to_vec(),
        })
        .unwrap();
    let publications = (0..quanta.len())
        .map(|number| {
            let lane = Lane::try_new(u8::try_from(number).unwrap()).unwrap();
            driver.publication(handle.lane(lane).unwrap()).unwrap()
        })
        .collect();
    Fixture {
        driver,
        handle,
        publications,
    }
}

fn offer(publication: &mut ClientPublication, bytes: &[u8]) {
    assert!(matches!(
        publication.offer(bytes).unwrap(),
        OfferOutcome::Accepted { .. }
    ));
}

/// Polls once, collecting `(lane, bytes)` of every message delivered.
fn poll(
    subscription: &mut AggregateSubscription,
    budget: Budget,
    out: &mut Vec<(u8, Vec<u8>)>,
) -> AggregatePoll {
    subscription.poll(
        |bytes, lane, _| out.push((lane.get(), bytes.to_vec())),
        budget,
    )
}

#[test]
fn every_message_arrives_once_per_lane_in_order() {
    let mut f = fixture(2, &[frame() * 2, frame(), frame()], 4);
    let mut subscription = f
        .driver
        .subscribe_aggregate(&f.handle, Role::Required)
        .unwrap();
    let budget = Budget {
        work: 5,
        bytes: 2 * frame(),
    };
    let mut sent: Vec<Vec<Vec<u8>>> = vec![Vec::new(); 3];
    let mut out = Vec::new();
    for sequence in 0..40u8 {
        for lane in 0..3u8 {
            let length = 24 + (usize::from(sequence) * 911 + usize::from(lane) * 307) % 5200;
            let bytes = message(lane, sequence, length);
            // A required reader bounds the publication: poll until it has
            // room, running the driver's duty cycles for rotations.
            let mut tries = 0;
            while !matches!(
                f.publications[usize::from(lane)].offer(&bytes).unwrap(),
                OfferOutcome::Accepted { .. }
            ) {
                tries += 1;
                assert!(tries < 1000, "never accepted");
                let _ = f.driver.do_work().unwrap();
                let _ = poll(&mut subscription, budget, &mut out);
            }
            sent[usize::from(lane)].push(bytes);
        }
        // Small calls, interleaved with the appends.
        let _ = poll(&mut subscription, budget, &mut out);
    }
    for _ in 0..2000 {
        if out.len() == 120 {
            break;
        }
        let _ = f.driver.do_work().unwrap();
        let report = poll(&mut subscription, budget, &mut out);
        assert!(report.terminal.is_none());
    }
    for lane in 0..3u8 {
        let received: Vec<Vec<u8>> = out
            .iter()
            .filter(|(from, _)| *from == lane)
            .map(|(_, bytes)| bytes.clone())
            .collect();
        assert_eq!(received, sent[usize::from(lane)], "lane {lane}");
    }
}

#[test]
fn backlogged_lanes_are_served_by_their_quanta() {
    let mut f = fixture(3, &[frame() * 2, frame()], 4);
    let mut subscription = f
        .driver
        .subscribe_aggregate(&f.handle, Role::Required)
        .unwrap();
    for sequence in 0..8u8 {
        for lane in 0..2 {
            offer(&mut f.publications[lane], &full_frame(sequence));
        }
    }
    let mut out = Vec::new();
    let report = poll(
        &mut subscription,
        Budget {
            work: 64,
            bytes: 6 * frame(),
        },
        &mut out,
    );
    // Two rounds: lane 0 two frames per round, lane 1 one.
    assert_eq!(report.drr.lanes[0].served_bytes, 4 * frame());
    assert_eq!(report.drr.lanes[1].served_bytes, 2 * frame());
    assert_eq!(report.lanes[0].delivered, 4);
    assert_eq!(report.lanes[1].delivered, 2);
}

#[test]
fn a_fragmented_message_is_served_across_polls_and_delivered_once() {
    let mut f = fixture(4, &[frame(), frame()], 4);
    let mut subscription = f
        .driver
        .subscribe_aggregate(&f.handle, Role::Required)
        .unwrap();
    let large = message(0, 1, 6000);
    offer(&mut f.publications[0], &large);
    let mut out = Vec::new();
    let mut polls = 0;
    while out.is_empty() {
        polls += 1;
        assert!(polls < 32, "never delivered");
        let _ = poll(
            &mut subscription,
            Budget {
                work: 4,
                bytes: frame(),
            },
            &mut out,
        );
    }
    assert!(polls >= 4, "one frame per poll: {polls}");
    assert_eq!(out, [(0, large)]);
    for _ in 0..4 {
        let _ = poll(
            &mut subscription,
            Budget {
                work: 4,
                bytes: frame(),
            },
            &mut out,
        );
    }
    assert_eq!(out.len(), 1, "delivered once");
}

#[test]
fn removing_the_aggregate_ends_every_lane_with_a_clean_eos() {
    let mut f = fixture(5, &[frame(), frame()], 4);
    let mut subscription = f
        .driver
        .subscribe_aggregate(&f.handle, Role::Required)
        .unwrap();
    offer(&mut f.publications[0], &message(0, 1, 100));
    offer(&mut f.publications[1], &message(1, 1, 3000));
    let budget = Budget {
        work: 16,
        bytes: 8 * frame(),
    };
    let mut out = Vec::new();
    let _ = poll(&mut subscription, budget, &mut out);
    assert_eq!(out.len(), 2);
    f.publications.clear();
    f.driver.remove_aggregate(&f.handle).unwrap();
    let _ = f.driver.do_work().unwrap();
    let mut terminal = None;
    for _ in 0..8 {
        let report = poll(&mut subscription, budget, &mut out);
        if report.terminal.is_some() {
            terminal = report.terminal;
            assert!(report.lanes.iter().all(|lane| lane.end.is_some()));
            break;
        }
        let _ = f.driver.do_work().unwrap();
    }
    assert_eq!(terminal.map(|terminal| terminal.clean), Some(true));
}

#[test]
fn a_panicking_handler_gets_its_message_again() {
    let mut f = fixture(6, &[frame(), frame()], 4);
    let mut subscription = f
        .driver
        .subscribe_aggregate(&f.handle, Role::Required)
        .unwrap();
    offer(&mut f.publications[1], &message(1, 7, 200));
    let budget = Budget {
        work: 16,
        bytes: 8 * frame(),
    };
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        subscription.poll(|_, _, _| panic!("handler failed"), budget)
    }));
    assert!(failed.is_err());
    let mut out = Vec::new();
    let report = poll(&mut subscription, budget, &mut out);
    assert_eq!(out, [(1, message(1, 7, 200))]);
    assert_eq!(report.lanes[1].delivered, 1);
}

#[test]
fn a_failure_at_any_lane_subscribes_none() {
    // One subscriber per lane: a direct subscription to lane 1 takes it.
    let mut f = fixture(7, &[frame(), frame()], 1);
    let taken = f
        .driver
        .subscribe(
            f.handle.lane(Lane::try_new(1).unwrap()).unwrap(),
            Role::Required,
        )
        .unwrap();
    assert!(
        f.driver
            .subscribe_aggregate(&f.handle, Role::Required)
            .is_err()
    );
    // Lane 0's cell was released: once lane 1 is free, the aggregate
    // subscribes.
    drop(taken);
    let _ = f.driver.do_work().unwrap();
    assert!(
        f.driver
            .subscribe_aggregate(&f.handle, Role::Required)
            .is_ok()
    );
}

/// An optional lane that is lapped applies its rejoin policy in the
/// control step, records its first loss and goes on; the other lane is
/// served throughout; and the terminal after removal is not clean.
#[test]
fn a_lapped_lane_records_its_loss_and_the_terminal_is_not_clean() {
    let mut f = fixture(8, &[frame(), frame()], 4);
    let mut subscription = f
        .driver
        .subscribe_aggregate(&f.handle, Role::Optional)
        .unwrap();
    let budget = Budget {
        work: 64,
        bytes: 64 * frame(),
    };
    // Lane 0 runs several terms ahead while nothing polls.
    for sequence in 0..200u8 {
        let _ = f.publications[0]
            .offer(&message(0, sequence, 3000))
            .unwrap();
        let _ = f.driver.do_work().unwrap();
    }
    offer(&mut f.publications[1], &message(1, 1, 100));
    let mut out = Vec::new();
    let report = poll(&mut subscription, budget, &mut out);
    let (overrun, _) = report.lanes[0].overrun.expect("lane 0 was lapped");
    assert_eq!(report.lanes[0].first_loss, Some(overrun.from));
    assert!(report.lanes[0].end.is_none(), "rejoined at the head");
    assert!(out.iter().any(|(lane, _)| *lane == 1));
    // The loss is kept; the terminal after removal reports it.
    f.publications.clear();
    f.driver.remove_aggregate(&f.handle).unwrap();
    let mut terminal = None;
    for _ in 0..16 {
        let _ = f.driver.do_work().unwrap();
        let report = poll(&mut subscription, budget, &mut out);
        assert_eq!(report.lanes[0].first_loss, Some(overrun.from));
        if report.terminal.is_some() {
            terminal = report.terminal;
            break;
        }
    }
    assert_eq!(terminal.map(|terminal| terminal.clean), Some(false));
}
