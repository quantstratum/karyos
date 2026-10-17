// SPDX-License-Identifier: Apache-2.0

//! A recording's reader over a driver stream: the roles it admits, the
//! publisher a required one bounds, the lap an optional one rejoins
//! from, and the cell a dropped one frees.

#![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

use karyos_client::{ClientPublication, OfferOutcome};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{
    LogBufferConfig, LossPolicy, PublicationMode, ReadError, ReadOrigin, ReadOutcome, Role,
};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;
use karyos_sys::term_bytes::HeapTerms;

use super::*;
use crate::embedded::StreamConfig;

const MESSAGE: usize = 1000;

fn stream() -> StreamConfig {
    StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 4,
            max_subscribers: 4,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id: 42,
            claim_deadline: 100,
            publication: PublicationMode::Exclusive,
            schedule_capacity: 0,
        },
        allow_unconnected: true,
        on_required_loss: LossPolicy::Hold,
        conflation: None,
    }
}

/// Offers until the publication stops accepting, running the driver
/// between offers; returns how many it accepted.
fn offer_until_refused(
    driver: &mut EmbeddedDriver<HeapTerms>,
    publication: &mut ClientPublication,
    most: usize,
) -> usize {
    let mut accepted = 0;
    let mut refused = 0;
    while accepted < most && refused < 16 {
        match publication.offer(&[7; MESSAGE]).unwrap() {
            OfferOutcome::Accepted { .. } => {
                accepted += 1;
                refused = 0;
            }
            _ => refused += 1,
        }
        driver.do_work().unwrap();
    }
    accepted
}

/// Reads and acknowledges everything committed.
fn drain(reader: &mut LaneReader) -> u64 {
    let mut out = vec![0u8; usize::try_from(MIN_TERM_LENGTH).unwrap()];
    loop {
        let from = reader.position();
        match reader.read_committed(from, ReadOrigin::Cursor, &mut out) {
            Ok(ReadOutcome::Copied { next, .. } | ReadOutcome::Canonical { next, .. }) => {
                reader.sent(next).unwrap();
            }
            Ok(ReadOutcome::Pending) | Err(ReadError::Retry) => return reader.position(),
            Err(error) => panic!("{error:?}"),
        }
    }
}

/// An observer, a walker or a conductor cell is not a recording: refused
/// before anything is admitted, and no occupant id is spent.
#[test]
fn a_recording_reader_admits_only_required_and_optional() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let handle = driver.add_stream(stream()).unwrap();
    let before = driver.next_export;
    for role in [Role::Observer, Role::Walker] {
        assert!(
            matches!(
                driver.recording_reader(handle, role),
                Err(DriverError::Sys(SysError::InvalidPublicationMode { .. }))
            ),
            "{role:?}"
        );
    }
    assert_eq!(driver.next_export, before);
    // With every cell taken, the role is still refused as a role: the
    // check comes before the admission, which would refuse for room.
    let mut held = Vec::new();
    while let Ok(subscription) = driver.subscribe(handle, Role::Observer) {
        held.push(subscription);
    }
    assert!(!held.is_empty());
    assert!(matches!(
        driver.recording_reader(handle, Role::Observer),
        Err(DriverError::Sys(SysError::InvalidPublicationMode { .. }))
    ));
    drop(held);
    let required = driver.recording_reader(handle, Role::Required).unwrap();
    let optional = driver.recording_reader(handle, Role::Optional).unwrap();
    assert_eq!(driver.next_export, before + 2);
    drop((required, optional));
}

/// A required recording bounds the publisher until it reads and
/// acknowledges; dropping it frees the publisher.
#[test]
fn a_required_recording_bounds_the_publisher() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let handle = driver.add_stream(stream()).unwrap();
    let (mut reader, lease) = driver
        .recording_reader(handle, Role::Required)
        .unwrap()
        .into_parts();
    let mut publication = driver.publication(handle).unwrap();
    let most = 4 * usize::try_from(MIN_TERM_LENGTH).unwrap() / MESSAGE;
    let first = offer_until_refused(&mut driver, &mut publication, most);
    assert!(first > 0 && first < most, "bounded: {first} of {most}");
    // Reading and acknowledging opens the window again.
    assert!(drain(&mut reader) > 0);
    driver.do_work().unwrap();
    assert!(offer_until_refused(&mut driver, &mut publication, most) > 0);
    // Dropped, it no longer bounds anything.
    drop((reader, lease));
    driver.do_work().unwrap();
    assert_eq!(
        offer_until_refused(&mut driver, &mut publication, most),
        most
    );
}

/// An optional recording never bounds the publisher: lapped, its read is
/// `Unavailable`, and it rejoins at the head and reads what follows.
#[test]
fn an_optional_recording_is_lapped_and_rejoins_at_the_head() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let handle = driver.add_stream(stream()).unwrap();
    let (mut reader, _lease) = driver
        .recording_reader(handle, Role::Optional)
        .unwrap()
        .into_parts();
    let mut publication = driver.publication(handle).unwrap();
    let most = 5 * usize::try_from(MIN_TERM_LENGTH).unwrap() / MESSAGE;
    assert_eq!(
        offer_until_refused(&mut driver, &mut publication, most),
        most
    );
    let mut out = vec![0u8; usize::try_from(MIN_TERM_LENGTH).unwrap()];
    let from = reader.position();
    assert!(matches!(
        reader.read_committed(from, ReadOrigin::Cursor, &mut out),
        Err(ReadError::Unavailable { .. })
    ));
    let head = reader.rejoin_at_head().unwrap();
    assert!(head > from);
    assert!(matches!(
        publication.offer(&[9; MESSAGE]).unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    driver.do_work().unwrap();
    match reader.read_committed(head, ReadOrigin::Cursor, &mut out) {
        Ok(ReadOutcome::Copied { len, .. }) => {
            assert!(len > MESSAGE);
            assert!(out[len - MESSAGE..len].iter().all(|&byte| byte == 9));
        }
        other => panic!("{other:?}"),
    }
}

/// A removed stream stays while a recording reader holds its lease: its
/// conductor positions the seal, the reader ends there, and the stream is
/// freed only once the reader and the lease are dropped.
#[test]
fn a_recording_reader_keeps_a_removed_stream_to_its_seal() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let handle = driver.add_stream(stream()).unwrap();
    let (mut reader, lease) = driver
        .recording_reader(handle, Role::Required)
        .unwrap()
        .into_parts();
    let mut publication = driver.publication(handle).unwrap();
    assert_eq!(offer_until_refused(&mut driver, &mut publication, 3), 3);
    drop(publication);
    driver.remove_stream(handle).unwrap();
    for _ in 0..4 {
        driver.do_work().unwrap();
    }
    assert!(driver.seal_state(handle).is_ok(), "kept while leased");
    let end = drain(&mut reader);
    assert_eq!(
        reader.seal_position(),
        Some(end),
        "ends at the positioned seal"
    );
    drop(reader);
    driver.do_work().unwrap();
    assert!(
        driver.seal_state(handle).is_ok(),
        "the lease still keeps it"
    );
    drop(lease);
    driver.do_work().unwrap();
    assert!(matches!(
        driver.seal_state(handle),
        Err(DriverError::UnknownStream { .. })
    ));
}

/// #352 review P2: a recording's reader follows one mapping, so a stream it
/// holds refuses a cutover until the reader and its lease are dropped.
#[test]
fn a_recorded_stream_refuses_a_cutover() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let handle = driver.add_stream(stream()).unwrap();
    let reconfiguration = crate::generations::Reconfiguration {
        term_length: TermLength::try_new(MIN_TERM_LENGTH * 2).unwrap(),
        spare_slots: 6,
    };
    let (reader, lease) = driver
        .recording_reader(handle, Role::Required)
        .unwrap()
        .into_parts();
    assert!(matches!(
        driver.reconfigure_stream(handle, reconfiguration),
        Err(DriverError::RecordingCutover { .. })
    ));
    // The reader alone dropped: the lease still holds the stream.
    drop(reader);
    assert!(matches!(
        driver.reconfigure_stream(handle, reconfiguration),
        Err(DriverError::RecordingCutover { .. })
    ));
    drop(lease);
    assert!(driver.reconfigure_stream(handle, reconfiguration).is_ok());
}
