// SPDX-License-Identifier: Apache-2.0

//! Driver integration tests for the required keyed conflation feeder.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use karyos_client::{ClientError, MessageLimit, OfferOutcome};
use karyos_driver::{
    ConflatedSubscription, DriverError, EmbeddedDriver, Reconfiguration, StreamConfig,
};
use karyos_sys::conflation::{Budget, ConflationConfig};
use karyos_sys::counters::{CellRead, KIND_NONE};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{AppendOptions, LogBufferConfig, Role};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::{Generation, TermId};

fn config(conflation: Option<ConflationConfig>) -> StreamConfig {
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
            stream_id: 2,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication: karyos_sys::log_buffer::PublicationMode::Exclusive,
            schedule_capacity: 0,
        },
        allow_unconnected: false,
        on_required_loss: karyos_sys::log_buffer::LossPolicy::Hold,
        conflation,
    }
}

fn offer_keyed(
    driver: &mut EmbeddedDriver,
    publication: &mut karyos_client::ClientPublication,
    key: i64,
    value: &[u8],
) {
    let options = AppendOptions {
        reserved_value: key,
        ..AppendOptions::default()
    };
    for _ in 0..10_000 {
        match publication.offer_with(value, options).unwrap() {
            OfferOutcome::Accepted { .. } => return,
            OfferOutcome::BackPressured | OfferOutcome::AdminAction => {
                let _ = driver.do_work().unwrap();
            }
            OfferOutcome::NotConnected
            | OfferOutcome::Closed
            | OfferOutcome::Gated
            | OfferOutcome::RateLimited => {
                panic!("publication unavailable")
            }
        }
    }
    panic!("offer never accepted");
}

fn conflation_config() -> ConflationConfig {
    ConflationConfig {
        keys: 4,
        value_capacity: 8,
        journal_capacity: 1024,
    }
}

#[test]
fn feeder_keeps_latest_value_and_regular_subscriber_gets_every_message() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let stream = driver
        .add_stream(config(Some(conflation_config())))
        .unwrap();
    let mut publication = driver.publication(stream).unwrap();
    let mut ordinary = driver.subscribe(stream, Role::Required).unwrap();
    let mut conflated: ConflatedSubscription = driver.subscribe_conflated(stream).unwrap();

    offer_keyed(&mut driver, &mut publication, 1, b"first");
    let _ = driver.do_work().unwrap();
    offer_keyed(&mut driver, &mut publication, 1, b"latest");
    let _ = driver.do_work().unwrap();

    let mut ordinary_values = Vec::new();
    let summary = ordinary
        .poll(
            |value, _| ordinary_values.push(value.to_vec()),
            MessageLimit::new(8),
        )
        .unwrap();
    assert_eq!(summary.delivered, 2);
    assert_eq!(ordinary_values, [b"first".to_vec(), b"latest".to_vec()]);

    let mut values = Vec::new();
    let report = conflated.poll_changed_with(
        Budget {
            keys: 8,
            retries: 3,
        },
        |key, version, value| values.push((key, version, value.to_vec())),
    );
    assert_eq!(report.delivered, 1);
    assert_eq!(values, [(1, 4, b"latest".to_vec())]);
}

#[test]
fn publication_validation_precedes_reservation_and_close_closes_the_table() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let stream = driver
        .add_stream(config(Some(conflation_config())))
        .unwrap();
    let mut publication = driver.publication(stream).unwrap();
    let mut conflated = driver.subscribe_conflated(stream).unwrap();

    let invalid_key = publication.offer_with(
        b"bad-key",
        AppendOptions {
            reserved_value: 99,
            ..AppendOptions::default()
        },
    );
    assert!(matches!(
        invalid_key,
        Err(ClientError::Conflation(
            karyos_sys::conflation::ConflationError::KeyOutOfRange { .. }
        ))
    ));
    let oversized = publication.offer_with(
        b"too-long-value",
        AppendOptions {
            reserved_value: 1,
            ..AppendOptions::default()
        },
    );
    assert!(matches!(
        oversized,
        Err(ClientError::Conflation(
            karyos_sys::conflation::ConflationError::ValueTooLarge { .. }
        ))
    ));
    assert!(matches!(
        publication
            .offer_with(
                b"ok",
                AppendOptions {
                    reserved_value: 1,
                    ..AppendOptions::default()
                }
            )
            .unwrap(),
        OfferOutcome::Accepted { position: 0, .. }
    ));
    let _ = driver.do_work().unwrap();

    let mut values = Vec::new();
    let report = conflated.poll_changed_with(
        Budget {
            keys: 8,
            retries: 3,
        },
        |key, version, value| values.push((key, version, value.to_vec())),
    );
    assert_eq!(report.delivered, 1);
    assert_eq!(values, [(1, 2, b"ok".to_vec())]);

    driver.remove_stream(stream).unwrap();
    let _ = driver.do_work().unwrap();
    let report = conflated.poll_changed(|_, _| {});
    assert!(report.closed);
}

#[test]
fn conflated_subscription_requires_stream_configuration() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let stream = driver.add_stream(config(None)).unwrap();
    assert!(matches!(
        driver.subscribe_conflated(stream),
        Err(DriverError::NotConflated)
    ));
}

#[test]
fn feeder_and_table_survive_a_mapping_cutover() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let stream = driver
        .add_stream(config(Some(conflation_config())))
        .unwrap();
    let mut publication = driver.publication(stream).unwrap();
    let mut conflated = driver.subscribe_conflated(stream).unwrap();

    offer_keyed(&mut driver, &mut publication, 1, b"before");
    let _ = driver.do_work().unwrap();
    assert_eq!(
        driver
            .reconfigure_stream(
                stream,
                Reconfiguration {
                    term_length: TermLength::try_new(MIN_TERM_LENGTH * 2).unwrap(),
                    spare_slots: 3,
                }
            )
            .unwrap(),
        Generation::try_new(1).unwrap()
    );

    offer_keyed(&mut driver, &mut publication, 2, b"after");
    let _ = driver.do_work().unwrap();

    let mut values = Vec::new();
    let report = conflated.poll_changed_with(
        Budget {
            keys: 8,
            retries: 3,
        },
        |key, version, value| values.push((key, version, value.to_vec())),
    );
    assert_eq!(report.delivered, 2);
    assert_eq!(
        values,
        [(1, 2, b"before".to_vec()), (2, 2, b"after".to_vec())]
    );
}

/// The value of the feeder counter `label` keyed to stream `stream`, after
/// checking its type and keys; `None` when no such cell is allocated.
fn feeder_counter(driver: &EmbeddedDriver, stream: u64, lane: u8, label: &str) -> Option<u64> {
    let reader = driver.counters();
    (0..reader.capacity()).find_map(|index| match reader.read(index) {
        CellRead::Allocated {
            metadata, value, ..
        } if metadata.label() == label.as_bytes() && metadata.keys.stream == stream => {
            assert_eq!(
                metadata.type_id,
                karyos_driver::counters::TYPE_EVENTS,
                "{label}"
            );
            assert_eq!(metadata.keys.lane, lane, "{label}");
            assert_eq!(metadata.keys.kind, KIND_NONE, "{label}");
            assert_eq!(metadata.keys.participant, 0, "{label}");
            Some(value)
        }
        _ => None,
    })
}

const FEEDER_COUNTERS: [&str; 3] = [
    "conflation updates written",
    "conflation keys rejected",
    "conflation values too large",
];

/// conflation-end-to-end.md, Counters: the feeder's counters are allocated
/// per conflated stream, keyed by the stream and its lane, count the
/// table writes, and are freed with the stream.
#[test]
fn feeder_counters_are_keyed_per_stream_and_freed_with_it() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let mut keyed = config(Some(conflation_config()));
    keyed.buffer.lane = Lane::try_new(3).unwrap();
    let stream = driver.add_stream(keyed).unwrap();
    let mut other = config(None);
    other.buffer.stream_id = 5;
    let plain = driver.add_stream(other).unwrap();
    let registration = driver.trace_identity(stream).unwrap().registration;
    let plain_registration = driver.trace_identity(plain).unwrap().registration;
    for label in FEEDER_COUNTERS {
        assert_eq!(feeder_counter(&driver, registration, 3, label), Some(0));
        // A stream without conflation has no feeder and no counters.
        assert_eq!(feeder_counter(&driver, plain_registration, 0, label), None);
    }

    let mut publication = driver.publication(stream).unwrap();
    let _conflated = driver.subscribe_conflated(stream).unwrap();
    for value in [b"one".as_slice(), b"two", b"three"] {
        offer_keyed(&mut driver, &mut publication, 2, value);
    }
    let _ = driver.do_work().unwrap();
    assert_eq!(
        feeder_counter(&driver, registration, 3, FEEDER_COUNTERS[0]),
        Some(3)
    );
    assert_eq!(
        feeder_counter(&driver, registration, 3, FEEDER_COUNTERS[1]),
        Some(0)
    );

    drop(publication);
    driver.remove_stream(stream).unwrap();
    let _ = driver.do_work().unwrap();
    for label in FEEDER_COUNTERS {
        assert_eq!(feeder_counter(&driver, registration, 3, label), None);
    }
}

// ---- Phase 1 closing audit of #7: the design's remaining tests ----

/// The latest value and version of every key, read until the view has
/// delivered every change; `seen` holds the versions delivered so far and
/// checks that none goes backwards.
fn read_all(
    conflated: &mut ConflatedSubscription,
    seen: &mut std::collections::BTreeMap<u32, (u64, Vec<u8>)>,
) {
    for _ in 0..64 {
        let report = conflated.poll_changed_with(
            Budget {
                keys: 64,
                retries: 3,
            },
            |key, version, value| {
                if let Some((before, _)) = seen.get(&key) {
                    assert!(version > *before, "key {key}: {version} after {before}");
                }
                let _ = seen.insert(key, (version, value.to_vec()));
            },
        );
        assert!(!report.closed, "the table closed");
        if report.pending == 0 && !report.scanning && report.journal_drained {
            return;
        }
    }
    panic!("the view never caught up");
}

/// conflation-end-to-end.md, `test_conflation_feeder_latest_value_per_key`:
/// interleaved updates to several keys; every key ends at its last update,
/// and versions never go backwards across reads made in between.
#[test]
fn test_conflation_feeder_latest_value_per_key() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let stream = driver
        .add_stream(config(Some(conflation_config())))
        .unwrap();
    let mut publication = driver.publication(stream).unwrap();
    let mut conflated = driver.subscribe_conflated(stream).unwrap();
    let mut seen = std::collections::BTreeMap::new();
    let rounds = 50u8;
    for round in 0..rounds {
        for key in 0..4u8 {
            offer_keyed(&mut driver, &mut publication, i64::from(key), &[round, key]);
        }
        let _ = driver.do_work().unwrap();
        if round % 7 == 3 {
            read_all(&mut conflated, &mut seen);
        }
    }
    let _ = driver.do_work().unwrap();
    read_all(&mut conflated, &mut seen);
    for key in 0..4u8 {
        // Each write advances a key's version by two.
        assert_eq!(
            seen.get(&u32::from(key)),
            Some(&(2 * u64::from(rounds), vec![rounds - 1, key])),
            "key {key}"
        );
    }
}

/// conflation-end-to-end.md, `test_conflation_feeder_back_pressures_never_loses`:
/// with the feeder starved of duty cycles the publisher is back pressured;
/// once the feeder runs, every accepted update is in the version sequence.
#[test]
fn test_conflation_feeder_back_pressures_never_loses() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let stream = driver
        .add_stream(config(Some(conflation_config())))
        .unwrap();
    let mut publication = driver.publication(stream).unwrap();
    let mut conflated = driver.subscribe_conflated(stream).unwrap();
    let options = AppendOptions {
        reserved_value: 0,
        ..AppendOptions::default()
    };
    let mut accepted = 0u64;
    loop {
        let value = accepted.to_le_bytes();
        match publication.offer_with(&value, options).unwrap() {
            OfferOutcome::Accepted { .. } => accepted += 1,
            OfferOutcome::BackPressured => break,
            other => panic!("after {accepted}: {other:?}"),
        }
        assert!(accepted < 1_000_000, "never back pressured");
    }
    assert!(accepted > 1);
    // The feeder runs: nothing accepted is missing.
    let mut seen = std::collections::BTreeMap::new();
    for _ in 0..64 {
        let _ = driver.do_work().unwrap();
    }
    read_all(&mut conflated, &mut seen);
    assert_eq!(
        seen.get(&0),
        Some(&(2 * accepted, (accepted - 1).to_le_bytes().to_vec()))
    );
    // The publisher goes on.
    offer_keyed(&mut driver, &mut publication, 0, b"more");
    let _ = driver.do_work().unwrap();
    read_all(&mut conflated, &mut seen);
    assert_eq!(seen.get(&0), Some(&(2 * accepted + 2, b"more".to_vec())));
}

/// A manual clock for the paused-driver variant.
#[derive(Debug, Clone, Default)]
struct ManualClock(std::sync::Arc<std::sync::atomic::AtomicU64>);

impl karyos_driver::MonotonicClock for ManualClock {
    fn now(&mut self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// conflation-end-to-end.md, `test_conflation_view_survives_cutover`, the
/// slow-feeder and paused-driver variants: updates before, during and after
/// a cutover, with a feeder that copies one message per duty cycle and is
/// still on the predecessor when the successor opens, and optionally with
/// the driver's clock moved past the cutover deadline before its next duty
/// cycle. The feeder is not fenced, versions continue without reset, no
/// update is lost and the table stays open.
#[test]
fn test_conflation_view_survives_cutover_with_a_slow_feeder_and_a_paused_driver() {
    for paused in [false, true] {
        let clock = ManualClock::default();
        let mut driver = EmbeddedDriver::with_clock(
            karyos_driver::DriverConfig {
                conflation_feeder_budget: std::num::NonZeroU32::new(1).unwrap(),
                cutover_deadline: 1_000,
                ..karyos_driver::DriverConfig::default()
            },
            Box::new(clock.clone()),
        )
        .unwrap();
        let stream = driver
            .add_stream(config(Some(conflation_config())))
            .unwrap();
        let mut publication = driver.publication(stream).unwrap();
        let mut conflated = driver.subscribe_conflated(stream).unwrap();
        let mut seen = std::collections::BTreeMap::new();
        let updates = 30u8;
        for n in 0..updates {
            offer_keyed(&mut driver, &mut publication, i64::from(n % 2), &[n]);
        }
        // The feeder has copied at most one message per duty cycle so far.
        assert_eq!(
            driver
                .reconfigure_stream(
                    stream,
                    Reconfiguration {
                        term_length: TermLength::try_new(MIN_TERM_LENGTH * 2).unwrap(),
                        spare_slots: 3,
                    }
                )
                .unwrap(),
            Generation::try_new(1).unwrap(),
            "paused: {paused}"
        );
        // The precondition: the feeder is behind on the predecessor when
        // the cutover starts, so it is still there when the successor
        // opens.
        let mut behind = 0u32;
        let _ = conflated.poll_changed_with(
            Budget {
                keys: 64,
                retries: 3,
            },
            |_, version, _| {
                assert!(version < 2 * u64::from(updates) / 2, "the feeder caught up");
                behind += 1;
            },
        );
        assert!(behind <= 2, "paused: {paused}");
        if paused {
            // The driver sleeps through the cutover deadline.
            clock.0.store(10_000, std::sync::atomic::Ordering::Relaxed);
        }
        for n in updates..2 * updates {
            offer_keyed(&mut driver, &mut publication, i64::from(n % 2), &[n]);
        }
        for _ in 0..4 * u32::from(updates) {
            let _ = driver.do_work().unwrap();
        }
        read_all(&mut conflated, &mut seen);
        for key in 0..2u8 {
            let last = 2 * updates - 2 + key;
            assert_eq!(
                seen.get(&u32::from(key)),
                Some(&(2 * u64::from(updates), vec![last])),
                "paused: {paused}, key {key}"
            );
        }
        assert_eq!(
            driver
                .generations(stream)
                .unwrap()
                .last()
                .unwrap()
                .generation,
            Generation::try_new(1).unwrap(),
            "paused: {paused}"
        );
    }
}

/// observability-and-tools.md, Client counters: a conflated view feeds its
/// reader-side counts into two client counter cells its client allocated;
/// tools read them in the client counters region.
#[test]
fn a_conflated_view_feeds_its_reader_counts_into_client_counters() {
    use karyos_client::{
        CONFLATION_BUDGETS_EXHAUSTED, CONFLATION_SKIPS, ClientCounterHandle, Outcome,
    };
    let mut driver = EmbeddedDriver::new().unwrap();
    let stream = driver
        .add_stream(config(Some(conflation_config())))
        .unwrap();
    let mut client = driver.connect().unwrap();
    let mut allocate = |label: &str| -> ClientCounterHandle {
        let _ = client
            .allocate_counter(karyos_driver::counters::TYPE_EVENTS, label, 0, 0)
            .unwrap();
        let _ = driver.do_work().unwrap();
        let mut handle = None;
        let _ = client.poll(usize::MAX, |completion| match completion.outcome {
            Outcome::Counter(counter) => handle = Some(counter),
            other => panic!("unexpected {other:?}"),
        });
        handle.unwrap()
    };
    let skips = allocate(CONFLATION_SKIPS);
    let exhausted = allocate(CONFLATION_BUDGETS_EXHAUSTED);
    let cells = (skips.cell(), exhausted.cell());
    let mut conflated = driver
        .subscribe_conflated(stream)
        .unwrap()
        .with_counters(skips, exhausted);
    let mut publication = driver.publication(stream).unwrap();
    for key in 0..4 {
        offer_keyed(&mut driver, &mut publication, key, b"v");
    }
    let _ = driver.do_work().unwrap();
    // One key per poll: the budget runs out until the view caught up.
    for _ in 0..8 {
        let _ = conflated.poll_changed_with(
            Budget {
                keys: 1,
                retries: 1,
            },
            |_, _, _| {},
        );
    }
    let counts = conflated.counts();
    assert!(counts.budgets_exhausted >= 3, "{counts:?}");
    let read = |cell: usize| match driver.client_counters().read(cell) {
        CellRead::Allocated {
            metadata, value, ..
        } => (
            String::from_utf8_lossy(metadata.label()).into_owned(),
            value,
        ),
        other => panic!("{other:?}"),
    };
    assert_eq!(read(cells.0), (CONFLATION_SKIPS.to_owned(), counts.skips));
    assert_eq!(
        read(cells.1),
        (
            CONFLATION_BUDGETS_EXHAUSTED.to_owned(),
            counts.budgets_exhausted
        )
    );
}
