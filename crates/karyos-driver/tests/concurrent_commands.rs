// SPDX-License-Identifier: Apache-2.0

//! Concurrent publication through client commands
//! (`quantstratum-docs: karyos/design/client-concurrent-publication.md`, d2).

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use karyos_client::{
    ClientConcurrentPublication, ClientConductor, Completion, ConcurrentOfferOutcome,
    ConductorError, MessageLimit, Outcome,
};
use karyos_driver::{DriverConfig, DriverError, EmbeddedDriver, StreamConfig, StreamHandle};
use karyos_protocol::cnc::{ErrorCode, StreamKey, SubscriberRole};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

const PUBLISHERS: u8 = 2;
const CONCURRENT: i32 = 2;
const EXCLUSIVE: i32 = 3;

fn stream_config(stream_id: i32, publication: PublicationMode) -> StreamConfig {
    StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 6,
            max_subscribers: 4,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication,
        },
        allow_unconnected: false,
        on_required_loss: karyos_sys::log_buffer::LossPolicy::Hold,
        conflation: None,
    }
}

fn key(stream_id: i32) -> StreamKey {
    StreamKey {
        stream_id,
        session_id: 1,
    }
}

/// A driver with a concurrent stream and an exclusive one.
fn driver_with(config: DriverConfig) -> (EmbeddedDriver, StreamHandle, StreamHandle) {
    let mut driver = EmbeddedDriver::with_config(config).unwrap();
    let concurrent = driver
        .add_stream(stream_config(
            CONCURRENT,
            PublicationMode::Concurrent {
                publishers: PUBLISHERS,
                allow_non_lse: true,
            },
        ))
        .unwrap();
    let exclusive = driver
        .add_stream(stream_config(EXCLUSIVE, PublicationMode::Exclusive))
        .unwrap();
    (driver, concurrent, exclusive)
}

/// Runs a duty cycle, then drains the client.
fn cycle(driver: &mut EmbeddedDriver, client: &mut ClientConductor) -> Vec<Completion> {
    let _ = driver.do_work().unwrap();
    let mut done = Vec::new();
    let report = client.poll(usize::MAX, |completion| done.push(completion));
    assert!(report.drained);
    done
}

fn handle(outcome: Outcome) -> ClientConcurrentPublication {
    match outcome {
        Outcome::ConcurrentPublication(publication) => publication,
        other => panic!("expected a concurrent publication, got {other:?}"),
    }
}

fn request(driver: &mut EmbeddedDriver, client: &mut ClientConductor) -> Outcome {
    let sequence = client
        .add_concurrent_publication(key(CONCURRENT), false)
        .unwrap();
    let mut done = cycle(driver, client);
    assert_eq!(done.len(), 1);
    let completion = done.pop().unwrap();
    assert_eq!(completion.sequence, sequence);
    completion.outcome
}

#[test]
fn a_concurrent_handle_is_handed_over_and_publishes() {
    let (mut driver, stream, _) = driver_with(DriverConfig::default());
    let mut client = driver.connect().unwrap();
    let _ = client
        .add_subscription(key(CONCURRENT), SubscriberRole::Required)
        .unwrap();
    let Outcome::Subscription(mut subscription) =
        cycle(&mut driver, &mut client).pop().unwrap().outcome
    else {
        panic!("no subscription");
    };
    let mut first = handle(request(&mut driver, &mut client));
    let mut second = handle(request(&mut driver, &mut client));
    assert!(first.origin().is_some());
    assert_eq!(driver.live_leases(stream).unwrap(), 3);
    for (publication, payload) in [(&mut first, b"one"), (&mut second, b"two")] {
        assert!(matches!(
            publication.offer(payload).unwrap(),
            ConcurrentOfferOutcome::Accepted { .. }
        ));
    }
    let mut seen = Vec::new();
    let _ = subscription
        .poll(|bytes, _| seen.push(bytes.to_vec()), MessageLimit::new(8))
        .unwrap();
    assert_eq!(seen, vec![b"one".to_vec(), b"two".to_vec()]);
}

#[test]
fn a_kind_that_does_not_match_the_mode_is_refused_with_no_effect() {
    let (mut driver, concurrent, exclusive) = driver_with(DriverConfig::default());
    let mut client = driver.connect().unwrap();
    let wrong_exclusive = client.add_publication(key(CONCURRENT), false).unwrap();
    let wrong_concurrent = client
        .add_concurrent_publication(key(EXCLUSIVE), false)
        .unwrap();
    let mut done: Vec<_> = (0..2)
        .flat_map(|_| cycle(&mut driver, &mut client))
        .collect();
    done.sort_by_key(|completion| completion.sequence);
    assert_eq!(done[0].sequence, wrong_exclusive);
    assert_eq!(done[1].sequence, wrong_concurrent);
    for (completion, stream_id) in done.iter().zip([CONCURRENT, EXCLUSIVE]) {
        assert!(
            matches!(
                completion.outcome,
                Outcome::Refused {
                    code: ErrorCode::InvalidPublicationMode,
                    detail,
                } if detail == u64::from(stream_id.cast_unsigned())
            ),
            "{:?}",
            completion.outcome
        );
    }
    assert_eq!(driver.live_leases(concurrent).unwrap(), 0);
    assert_eq!(driver.live_leases(exclusive).unwrap(), 0);
    // Nothing was consumed: the right kinds are still issued, P of them.
    for _ in 0..PUBLISHERS {
        let _ = handle(request(&mut driver, &mut client));
    }
    let _ = client.add_publication(key(EXCLUSIVE), false).unwrap();
    assert!(matches!(
        cycle(&mut driver, &mut client).pop().unwrap().outcome,
        Outcome::Publication(_)
    ));
}

#[test]
fn p_handles_are_issued_and_the_next_is_refused_as_taken() {
    let (mut driver, stream, _) = driver_with(DriverConfig::default());
    let mut client = driver.connect().unwrap();
    let handles: Vec<_> = (0..PUBLISHERS)
        .map(|_| handle(request(&mut driver, &mut client)))
        .collect();
    assert!(matches!(
        request(&mut driver, &mut client),
        Outcome::Refused {
            code: ErrorCode::PublicationTaken,
            ..
        }
    ));
    assert_eq!(
        driver.live_leases(stream).unwrap(),
        u64::from(PUBLISHERS),
        "the refusal holds nothing"
    );
    drop(handles);
    assert_eq!(driver.live_leases(stream).unwrap(), 0);
    let _ = handle(request(&mut driver, &mut client));
}

#[test]
fn an_untaken_entry_holds_its_slot_until_the_client_closes() {
    let (mut driver, stream, _) = driver_with(DriverConfig::default());
    let mut client = driver.connect().unwrap();
    for _ in 0..PUBLISHERS {
        let _ = client
            .add_concurrent_publication(key(CONCURRENT), false)
            .unwrap();
    }
    // Served, never taken: every publisher slot is in a held entry.
    for _ in 0..PUBLISHERS {
        let _ = driver.do_work().unwrap();
    }
    assert_eq!(driver.live_leases(stream).unwrap(), u64::from(PUBLISHERS));
    assert!(matches!(
        driver.concurrent_publication(stream),
        Err(DriverError::PublicationTaken)
    ));
    client.close();
    let _ = driver.do_work().unwrap();
    assert_eq!(driver.live_leases(stream).unwrap(), 0);
    let _direct = driver.concurrent_publication(stream).unwrap();
}

#[test]
fn remove_frees_the_slot_and_a_full_ring_returns_the_handle() {
    let config = DriverConfig {
        max_pending_per_client: 64,
        ..DriverConfig::default()
    };
    let (mut driver, stream, _) = driver_with(config);
    let mut client = driver.connect().unwrap();
    let handles: Vec<_> = (0..PUBLISHERS)
        .map(|_| handle(request(&mut driver, &mut client)))
        .collect();
    let mut handles = handles.into_iter();
    let first = handles.next().unwrap();
    let _second = handles.next().unwrap();
    // Fill the ring with requests the driver has not served yet.
    while client
        .add_subscription(key(99), SubscriberRole::Optional)
        .is_ok()
    {}
    let (first, error) = client.remove_concurrent_publication(first).unwrap_err();
    assert_eq!(error, ConductorError::Full);
    assert_eq!(driver.live_leases(stream).unwrap(), u64::from(PUBLISHERS));
    for _ in 0..64 {
        let _ = cycle(&mut driver, &mut client);
    }
    let removed = client.remove_concurrent_publication(first).unwrap();
    let done = cycle(&mut driver, &mut client);
    assert!(
        done.iter()
            .any(|c| c.sequence == removed && matches!(c.outcome, Outcome::Succeeded))
    );
    assert_eq!(
        driver.live_leases(stream).unwrap(),
        u64::from(PUBLISHERS) - 1
    );
    // The removed handle's slot is issued again.
    let _ = handle(request(&mut driver, &mut client));
}

#[test]
fn a_foreign_concurrent_handle_cannot_be_removed() {
    let (mut driver, stream, _) = driver_with(DriverConfig::default());
    let mut owner = driver.connect().unwrap();
    let mut other = driver.connect().unwrap();
    let owned = handle(request(&mut driver, &mut owner));
    let (_owned, error) = other.remove_concurrent_publication(owned).unwrap_err();
    assert_eq!(error, ConductorError::ForeignHandle);
    // A handle from the direct API has no origin either.
    let direct = driver.concurrent_publication(stream).unwrap();
    assert!(matches!(
        owner.remove_concurrent_publication(direct),
        Err((_, ConductorError::ForeignHandle))
    ));
}
