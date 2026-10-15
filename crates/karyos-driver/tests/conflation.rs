// SPDX-License-Identifier: Apache-2.0

//! Driver integration tests for the required keyed conflation feeder.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use karyos_client::{ClientError, MessageLimit, OfferOutcome};
use karyos_driver::{
    ConflatedSubscription, DriverError, EmbeddedDriver, Reconfiguration, StreamConfig,
};
use karyos_sys::conflation::{Budget, ConflationConfig};
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
            OfferOutcome::NotConnected | OfferOutcome::Closed => panic!("publication unavailable"),
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
