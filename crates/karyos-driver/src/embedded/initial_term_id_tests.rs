// SPDX-License-Identifier: Apache-2.0

//! A local publication's first term id (SPEC §4, initial state): drawn on
//! the control path for each stream or aggregate, or pinned by the test
//! override, and read across the term id wrap by every local reader.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use karyos_client::{ClientPublication, Completion, MessageLimit, OfferOutcome, Outcome};
use karyos_protocol::cnc::{StreamKey, SubscriberRole};
use karyos_sys::conflation::Budget;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{AppendOptions, LogBufferConfig, Role};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};

use super::*;

/// Messages of this size fill a 64 KiB term in about 63 of them.
const MESSAGE: usize = 1000;

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
            claim_deadline: 100,
            publication: karyos_sys::log_buffer::PublicationMode::Exclusive,
            schedule_capacity: 0,
        },
        allow_unconnected: false,
        on_required_loss: karyos_sys::log_buffer::LossPolicy::Hold,
        conflation: None,
    }
}

fn aggregate(stream_id: i32, lanes: usize) -> AggregateConfig {
    AggregateConfig {
        stream: stream(stream_id),
        quanta: vec![u64::from(karyos_sys::sizing::align_frame(DEFAULT_MTU).unwrap()); lanes],
    }
}

fn initial_term_id(driver: &EmbeddedDriver, stream: StreamHandle) -> u32 {
    driver
        .stream_ref(stream)
        .unwrap()
        .config
        .initial_term_id
        .get()
}

/// A driver whose local publications start at `initial_term_id`.
fn pinned(initial_term_id: u32) -> EmbeddedDriver {
    EmbeddedDriver::with_config(DriverConfig {
        initial_term_id: Some(initial_term_id),
        ..DriverConfig::default()
    })
    .unwrap()
}

/// Offers `value` with `options` until accepted, running the driver
/// between attempts.
fn offer(
    driver: &mut EmbeddedDriver,
    publication: &mut ClientPublication,
    value: &[u8],
    options: AppendOptions,
) {
    for _ in 0..10_000 {
        match publication.offer_with(value, options).unwrap() {
            OfferOutcome::Accepted { .. } => return,
            OfferOutcome::BackPressured | OfferOutcome::AdminAction => {
                let _ = driver.do_work().unwrap();
            }
            other => panic!("publication unavailable: {other:?}"),
        }
    }
    panic!("offer never accepted");
}

/// Two streams draw their own ids, which the configuration's `7` does not
/// pin; an aggregate draws one that every lane shares. A match of two
/// draws is retried once.
#[test]
fn local_publications_draw_their_initial_term_ids() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let first = driver.add_stream(stream(2)).unwrap();
    let second = driver.add_stream(stream(3)).unwrap();
    let (first, second) = (
        initial_term_id(&driver, first),
        initial_term_id(&driver, second),
    );
    let second = if first == second {
        let retried = driver.add_stream(stream(4)).unwrap();
        initial_term_id(&driver, retried)
    } else {
        second
    };
    assert_ne!(first, second);
    let handle = driver.add_aggregate(aggregate(5, 3)).unwrap();
    let drawn: Vec<u32> = handle
        .streams()
        .map(|lane| initial_term_id(&driver, lane))
        .collect();
    assert_eq!(drawn.len(), 3);
    assert!(drawn.iter().all(|id| *id == drawn[0]), "{drawn:?}");
}

/// The override pins every local publication's id, a stream's and every
/// lane's of an aggregate.
#[test]
fn the_override_pins_local_initial_term_ids() {
    let mut driver = pinned(42);
    let stream = driver.add_stream(stream(2)).unwrap();
    assert_eq!(initial_term_id(&driver, stream), 42);
    let handle = driver.add_aggregate(aggregate(3, 2)).unwrap();
    for lane in handle.streams() {
        assert_eq!(initial_term_id(&driver, lane), 42);
    }
}

/// A stream starting just below `u32::MAX` crosses the term id wrap: an
/// in-process subscriber and a client's subscriber read every message in
/// order across it.
#[test]
fn a_local_stream_crosses_the_term_id_wrap() {
    let mut driver = pinned(u32::MAX - 1);
    let handle = driver.add_stream(stream(2)).unwrap();
    assert_eq!(initial_term_id(&driver, handle), u32::MAX - 1);
    let mut publication = driver.publication(handle).unwrap();
    let mut local = driver.subscribe(handle, Role::Required).unwrap();
    let mut client = driver.connect().unwrap();
    let key = StreamKey {
        stream_id: 2,
        session_id: 1,
    };
    let _ = client
        .add_subscription(key, SubscriberRole::Required)
        .unwrap();
    let _ = driver.do_work().unwrap();
    let mut done: Vec<Completion> = Vec::new();
    let _ = client.poll(usize::MAX, |completion| done.push(completion));
    let mut remote = match done.pop().unwrap().outcome {
        Outcome::Subscription(subscription) => subscription,
        other => panic!("unexpected {other:?}"),
    };
    // About four 64 KiB terms: term ids MAX - 1, MAX, 0 and 1.
    let count: u32 = 256;
    let (mut seen_local, mut seen_remote) = (Vec::new(), Vec::new());
    for index in 0..count {
        let mut message = [0u8; MESSAGE];
        message[..4].copy_from_slice(&index.to_le_bytes());
        offer(
            &mut driver,
            &mut publication,
            &message,
            AppendOptions::default(),
        );
        let _ = driver.do_work().unwrap();
        let first = |bytes: &[u8]| u32::from_le_bytes(bytes[..4].try_into().unwrap());
        let _ = local
            .poll(
                |bytes, _| seen_local.push(first(bytes)),
                MessageLimit::new(8),
            )
            .unwrap();
        let _ = remote
            .poll(
                |bytes, _| seen_remote.push(first(bytes)),
                MessageLimit::new(8),
            )
            .unwrap();
    }
    let expected: Vec<u32> = (0..count).collect();
    assert_eq!(seen_local, expected);
    assert_eq!(seen_remote, expected);
    assert!(local.position() > 3 * u64::from(MIN_TERM_LENGTH));
}

/// A conflated stream starting just below `u32::MAX` crosses the wrap: its
/// feeder keeps every key's latest value across it.
#[test]
fn a_conflated_stream_crosses_the_term_id_wrap() {
    let mut driver = pinned(u32::MAX - 1);
    let mut config = stream(2);
    config.conflation = Some(karyos_sys::conflation::ConflationConfig {
        keys: 4,
        value_capacity: 8,
        journal_capacity: 1024,
    });
    let handle = driver.add_stream(config).unwrap();
    let mut publication = driver.publication(handle).unwrap();
    let mut conflated = driver.subscribe_conflated(handle).unwrap();
    // 8-byte values take 64-byte frames: about four 64 KiB terms.
    let count: u64 = 4200;
    for index in 0..count {
        let options = AppendOptions {
            reserved_value: i64::try_from(index % 4).unwrap(),
            ..AppendOptions::default()
        };
        offer(&mut driver, &mut publication, &index.to_le_bytes(), options);
        let _ = driver.do_work().unwrap();
    }
    for _ in 0..8 {
        let _ = driver.do_work().unwrap();
    }
    // The feeder, the only required reader, consumed past three terms.
    let consumed = driver
        .stream_ref(handle)
        .unwrap()
        .buffer
        .required_position()
        .unwrap();
    assert!(consumed > 3 * u64::from(MIN_TERM_LENGTH));
    let mut latest = Vec::new();
    let _ = conflated
        .poll_changed_with(
            Budget {
                keys: 8,
                retries: 3,
            },
            |key, value| {
                latest.push((key, u64::from_le_bytes(value.payload().try_into().unwrap())));
            },
        )
        .unwrap();
    latest.sort_unstable();
    let expected: Vec<(u32, u64)> = (count - 4..count)
        .map(|index| (u32::try_from(index % 4).unwrap(), index))
        .collect();
    assert_eq!(latest, expected);
}
