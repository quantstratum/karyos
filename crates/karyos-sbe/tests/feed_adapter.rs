// SPDX-License-Identifier: Apache-2.0

//! The SBE feed adapter end to end (karyos#647): a client subscribes to a
//! feed's two lines, A and B, on an embedded Karyos driver, receives SBE
//! `Car` messages on both and pushes them into one [`SbeFeed`]. Each
//! sequenced message reaches the client once, in sequence order, framed by
//! its SBE header and decoded in place: a message missing on line A is
//! filled from line B, the copies on the other line are suppressed, a
//! frame of another schema or an unknown version is refused, and a
//! sequence missing on both lines is declared a gap.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

mod common;

use karyos_client::{ClientConductor, ClientSubscription, MessageLimit, OfferOutcome, Outcome};
use karyos_driver::{EmbeddedDriver, StreamConfig};
use karyos_protocol::cnc::{StreamKey, SubscriberRole};
use karyos_sbe::adapter::{SbeEvent, SbeFeed, SbeSchema, SbeSequence};
use karyos_sbe::feed::{ArbiterConfig, Identity, Line, Start};
use karyos_sbe::{CAR_SCHEMA_ID, CAR_SCHEMA_VERSION, decode_car};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::LogBufferConfig;
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

/// The test feed's extractor: one epoch, each `Car`'s serial number its
/// sequence, read in place.
struct BySerial;

impl SbeSequence for BySerial {
    fn identity(&self, _: &ironsbe_core::header::MessageHeader, frame: &[u8]) -> Option<Identity> {
        decode_car(frame).ok().map(|car| Identity {
            epoch: 1,
            sequence: car.serial_number(),
        })
    }
}

/// The skew window, in the test's nanoseconds.
const SKEW: u64 = 1_000;

fn feed() -> SbeFeed<BySerial> {
    SbeFeed::new(
        SbeSchema {
            schema_id: CAR_SCHEMA_ID,
            max_version: CAR_SCHEMA_VERSION,
        },
        BySerial,
        ArbiterConfig {
            capacity: 16,
            max_message_length: 512,
            skew_window: SKEW,
            start: Start::AtFirst,
        },
    )
    .unwrap()
}

/// The version 1 golden vector with serial number `sequence`.
fn car(sequence: u64) -> Vec<u8> {
    let mut frame = common::vector(include_str!("vectors/car-v1.hex"));
    // `serialNumber` is the first field of the root block, after the
    // 8-byte message header.
    frame[8..16].copy_from_slice(&sequence.to_le_bytes());
    frame
}

/// `car(sequence)` with its header's `field` (2 bytes at `at`) set.
fn with_header(sequence: u64, at: usize, value: u16) -> Vec<u8> {
    let mut frame = car(sequence);
    frame[at..at + 2].copy_from_slice(&value.to_le_bytes());
    frame
}

fn stream(stream_id: i32) -> StreamConfig {
    StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 3,
            max_subscribers: 4,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication: karyos_sys::log_buffer::PublicationMode::Exclusive,
            schedule_capacity: 0,
        },
        allow_unconnected: true,
        on_required_loss: karyos_sys::log_buffer::LossPolicy::Hold,
        conflation: None,
    }
}

/// The client subscribes to `stream_id`.
fn subscribe(
    driver: &mut EmbeddedDriver,
    client: &mut ClientConductor,
    stream_id: i32,
) -> ClientSubscription {
    let request = client
        .add_subscription(
            StreamKey {
                stream_id,
                session_id: 1,
            },
            SubscriberRole::Required,
        )
        .unwrap();
    let _ = driver.do_work().unwrap();
    let mut subscription = None;
    let _ = client.poll(usize::MAX, |completion| {
        if completion.sequence == request
            && let Outcome::Subscription(granted) = completion.outcome
        {
            subscription = Some(granted);
        }
    });
    subscription.expect("subscribed")
}

/// Every message the subscription has received so far.
fn received(subscription: &mut ClientSubscription) -> Vec<Vec<u8>> {
    let mut messages = Vec::new();
    let _ = subscription
        .poll(
            |bytes, _| messages.push(bytes.to_vec()),
            MessageLimit::new(64),
        )
        .unwrap();
    messages
}

/// What the client sees: each delivered message's line and serial number,
/// decoded in place from the frame, and each gap.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Message(Line, u64),
    Gap(u64, u64),
}

fn record(seen: &mut Vec<Seen>) -> impl FnMut(SbeEvent<'_>) + '_ {
    |event| match event {
        SbeEvent::Message {
            line,
            identity,
            header,
            frame,
        } => {
            assert_eq!(header.schema_id, CAR_SCHEMA_ID);
            let car = decode_car(frame).unwrap();
            assert_eq!(car.serial_number(), identity.sequence);
            seen.push(Seen::Message(line, identity.sequence));
        }
        SbeEvent::Gap { from, count, .. } => seen.push(Seen::Gap(from, count)),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn a_client_sees_each_sbe_message_of_two_lines_once_in_order() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let a = driver.add_stream(stream(2)).unwrap();
    let b = driver.add_stream(stream(3)).unwrap();
    let mut client = driver.connect().unwrap();
    let mut on_a = subscribe(&mut driver, &mut client, 2);
    let mut on_b = subscribe(&mut driver, &mut client, 3);
    let mut line_a = driver.publication(a).unwrap();
    let mut line_b = driver.publication(b).unwrap();
    macro_rules! offer {
        ($publication:expr, $frame:expr) => {
            assert!(matches!(
                $publication.offer($frame).unwrap(),
                OfferOutcome::Accepted { .. }
            ))
        };
    }
    // Line A loses 3; line B brings every message, behind A. Line B also
    // carries a frame of another schema and one of an unknown version,
    // which the adapter refuses. Sequence 7 is lost on both lines.
    for sequence in [1, 2, 4, 5, 6, 8] {
        offer!(line_a, &car(sequence));
    }
    for sequence in [1, 2, 3, 4, 5, 6] {
        offer!(line_b, &car(sequence));
    }
    offer!(line_b, &with_header(9, 4, CAR_SCHEMA_ID + 1));
    offer!(line_b, &with_header(9, 6, CAR_SCHEMA_VERSION + 1));
    offer!(line_b, &car(8));
    let _ = driver.do_work().unwrap();
    let from_a = received(&mut on_a);
    let from_b = received(&mut on_b);
    assert_eq!((from_a.len(), from_b.len()), (6, 9));

    // The client reads A's first five, then all of B, then A's last. A
    // brings 1, 2, 4, 5 and 6 first; its hole at 3 holds 4 to 6 until B
    // fills it, and they go out as A brought them.
    let mut feed = feed();
    let mut seen = Vec::new();
    let mut now = 0;
    for frame in &from_a[..5] {
        now += 1;
        feed.push(Line::A, frame, now, record(&mut seen));
    }
    for frame in &from_b {
        now += 1;
        feed.push(Line::B, frame, now, record(&mut seen));
    }
    now += 1;
    feed.push(Line::A, &from_a[5], now, record(&mut seen));
    // Sequence 7 never comes: the skew window passes and it is a gap, and
    // 8, held behind it, is delivered.
    feed.poll(now + SKEW + 1, record(&mut seen));

    assert_eq!(
        seen,
        [
            Seen::Message(Line::A, 1),
            Seen::Message(Line::A, 2),
            Seen::Message(Line::B, 3),
            Seen::Message(Line::A, 4),
            Seen::Message(Line::A, 5),
            Seen::Message(Line::A, 6),
            Seen::Gap(7, 1),
            Seen::Message(Line::B, 8),
        ]
    );
    let counters = feed.counters();
    assert_eq!(counters.feed.delivered, 7);
    assert_eq!(counters.feed.gaps, 1);
    assert_eq!(counters.refused, 2, "another schema and an unknown version");
    assert!(counters.feed.duplicates_a + counters.feed.duplicates_b + counters.feed.late_b >= 5);
}
