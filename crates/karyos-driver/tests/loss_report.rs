// SPDX-License-Identifier: Apache-2.0

//! Loss reports from clients over an embedded driver (`quantstratum-docs:
//! karyos/design/observability-and-tools.md`, "Loss reports from clients"):
//! an overrun optional subscriber handed over by a client conductor
//! reports its loss, which the driver records and counts.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use karyos_client::{
    ClientConductor, ClientPublication, ClientSubscription, LOSS_REPORT_QUEUE, MessageLimit,
    OfferOutcome, Outcome, Overrun, RejoinOutcome, RejoinPolicy, ReplayFallbackReason, Secondary,
    SecondaryOutcome,
};
use karyos_driver::{DriverConfig, EmbeddedDriver, StreamConfig, StreamHandle};
use karyos_protocol::cnc::{StreamKey, SubscriberRole};
use karyos_sys::counters::{CellRead, KIND_CLIENT};
use karyos_sys::diag::LossRecord;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::LogBufferConfig;
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

const KEY: StreamKey = StreamKey {
    stream_id: 2,
    session_id: 1,
};

fn config() -> StreamConfig {
    StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 3,
            max_subscribers: 4,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::try_new(1).unwrap(),
            session_id: KEY.session_id,
            stream_id: KEY.stream_id,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication: karyos_sys::log_buffer::PublicationMode::Exclusive,
        },
        allow_unconnected: true,
        on_required_loss: karyos_sys::log_buffer::LossPolicy::Hold,
        conflation: None,
    }
}

/// Offers one message, running the driver until it is accepted.
fn offer(driver: &mut EmbeddedDriver, publication: &mut ClientPublication) {
    for _ in 0..10_000 {
        if let OfferOutcome::Accepted { .. } = publication.offer(&[7u8; 512]).unwrap() {
            return;
        }
        let _ = driver.do_work().unwrap();
    }
    panic!("offer never accepted");
}

/// Publishes until a lagging reader's data is reclaimed.
fn lap(driver: &mut EmbeddedDriver, publication: &mut ClientPublication) {
    for _ in 0..300 {
        offer(driver, publication);
        let _ = driver.do_work().unwrap();
    }
}

/// A driver, a stream, its publication, a client and an optional
/// subscription handed over to it with `policy`.
fn setup(
    policy: RejoinPolicy,
) -> (
    EmbeddedDriver,
    StreamHandle,
    ClientPublication,
    ClientConductor,
    ClientSubscription,
) {
    setup_with(policy, DriverConfig::default())
}

fn setup_with(
    policy: RejoinPolicy,
    driver_config: DriverConfig,
) -> (
    EmbeddedDriver,
    StreamHandle,
    ClientPublication,
    ClientConductor,
    ClientSubscription,
) {
    let mut driver = EmbeddedDriver::with_config(driver_config).unwrap();
    let stream = driver.add_stream(config()).unwrap();
    let mut client = driver.connect().unwrap();
    let _ = client
        .add_subscription(KEY, SubscriberRole::Optional)
        .unwrap();
    let _ = driver.do_work().unwrap();
    let mut handle = None;
    let _ = client.poll(usize::MAX, |completion| match completion.outcome {
        Outcome::Subscription(subscription) => handle = Some(subscription),
        other => panic!("unexpected {other:?}"),
    });
    let subscription = handle.unwrap().with_rejoin(policy);
    let publication = driver.publication(stream).unwrap();
    (driver, stream, publication, client, subscription)
}

/// Laps `subscription` and polls it into its overrun.
fn overrun(
    driver: &mut EmbeddedDriver,
    publication: &mut ClientPublication,
    subscription: &mut ClientSubscription,
) -> (Overrun, RejoinOutcome) {
    lap(driver, publication);
    let summary = subscription.poll(|_, _| {}, MessageLimit::new(1)).unwrap();
    (summary.overrun.unwrap(), summary.rejoin.unwrap())
}

/// Runs the client and the driver until every report was sent and
/// answered; the client reports no completion for them.
fn settle(driver: &mut EmbeddedDriver, client: &mut ClientConductor) {
    for _ in 0..1000 {
        let _ = client.poll(usize::MAX, |completion| {
            panic!("unexpected completion {completion:?}");
        });
        if client.loss_reports_queued() == 0 && client.pending() == 0 {
            return;
        }
        let _ = driver.do_work().unwrap();
    }
    panic!("the reports never settled");
}

fn losses(driver: &EmbeddedDriver) -> Vec<LossRecord> {
    let mut records = Vec::new();
    let _ = driver
        .loss_report()
        .scan(&mut 0, |_, record| records.push(record));
    records
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

/// The record a verified report of `overrun` names.
fn expected(
    driver: &mut EmbeddedDriver,
    stream: StreamHandle,
    client: &ClientConductor,
    subscription: &ClientSubscription,
    overrun: Overrun,
) -> LossRecord {
    let identity = driver.trace_identity(stream).unwrap();
    let [high, low] = identity.driver;
    LossRecord {
        time: 0,
        kind: 1,
        reason: 0,
        lane: 1,
        configured_policy: 1,
        applied_policy: 1,
        flags: 0,
        instance: u128::from(high) << 64 | u128::from(low),
        stream_registration: identity.registration,
        incarnation: identity.incarnation,
        stream_id: 2,
        from: overrun.from,
        to: overrun.lost_to,
        participant: subscription.origin().unwrap().registration(),
        client: client.owner().client,
    }
}

#[test]
fn test_overrun_of_an_optional_subscriber_records_one_verified_loss() {
    let (mut driver, stream, mut publication, mut client, mut subscription) =
        setup(RejoinPolicy::RejoinAtHead);
    let (lost, outcome) = overrun(&mut driver, &mut publication, &mut subscription);
    assert_eq!(outcome, RejoinOutcome::ResumedAtHead);
    assert!(lost.from < lost.lost_to);
    assert_eq!(client.loss_reports_queued(), 1);
    settle(&mut driver, &mut client);
    let [record] = losses(&driver)[..] else {
        panic!("expected exactly one loss record");
    };
    assert!(record.time > 0);
    assert_eq!(
        LossRecord { time: 0, ..record },
        expected(&mut driver, stream, &client, &subscription, lost)
    );
    assert_eq!(counter(&driver, "overruns rejoin at head"), 1);
    assert_eq!(counter(&driver, "loss reports unverified"), 0);
    assert_eq!(counter(&driver, "clients faulty"), 0);
    assert_eq!(client.loss_reports_dropped(), 0);
    assert!(client.loss_reports_dropped_counter().is_none());
}

#[test]
fn test_a_replay_fallback_reports_its_reason_and_secondary() {
    let (mut driver, stream, mut publication, mut client, mut subscription) =
        setup(RejoinPolicy::Replay {
            secondary: Secondary::Close,
        });
    let (lost, outcome) = overrun(&mut driver, &mut publication, &mut subscription);
    assert_eq!(
        outcome,
        RejoinOutcome::ReplayFallback {
            reason: ReplayFallbackReason::NoArchive,
            secondary: SecondaryOutcome::Closed,
        }
    );
    settle(&mut driver, &mut client);
    let [record] = losses(&driver)[..] else {
        panic!("expected exactly one loss record");
    };
    // Captured before the closure dropped the cell: the lane, the identity
    // and the range are those of the live subscription.
    assert_eq!(
        LossRecord { time: 0, ..record },
        LossRecord {
            reason: 1,
            configured_policy: 4,
            applied_policy: 4,
            ..expected(&mut driver, stream, &client, &subscription, lost)
        }
    );
    assert_eq!(counter(&driver, "overruns close"), 1);
    assert_eq!(counter(&driver, "replay fallbacks"), 1);
    assert_eq!(counter(&driver, "overruns rejoin at head"), 0);
}

#[test]
fn test_a_full_report_queue_drops_the_oldest_and_counts_it() {
    let (mut driver, _stream, mut publication, mut client, mut subscription) =
        setup(RejoinPolicy::RejoinAtHead);
    // More overruns than the queue holds, before the client polls.
    let ranges: Vec<Overrun> = (0..LOSS_REPORT_QUEUE + 2)
        .map(|_| overrun(&mut driver, &mut publication, &mut subscription).0)
        .collect();
    assert_eq!(client.loss_reports_queued(), LOSS_REPORT_QUEUE);
    assert_eq!(client.loss_reports_dropped(), 2);
    settle(&mut driver, &mut client);
    // The two oldest were dropped; the rest arrived in order.
    let records = losses(&driver);
    assert_eq!(
        records.iter().map(|r| (r.from, r.to)).collect::<Vec<_>>(),
        ranges[2..]
            .iter()
            .map(|o| (o.from, o.lost_to))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        counter(&driver, "overruns rejoin at head"),
        LOSS_REPORT_QUEUE as u64
    );
    // The client allocated its own `loss reports dropped` counter, keyed
    // to itself, and brought it up to the local count.
    let handle = client.loss_reports_dropped_counter().unwrap();
    let CellRead::Allocated {
        metadata, value, ..
    } = driver.client_counters().read(handle.cell())
    else {
        panic!("the client counter is not allocated");
    };
    assert_eq!(metadata.label(), b"loss reports dropped");
    assert_eq!(metadata.keys.stream, 0);
    assert_eq!(metadata.keys.kind, KIND_CLIENT);
    assert_eq!(metadata.keys.participant, client.owner().client);
    assert_eq!(value, 2);
    // A later drop reaches the cell on the next poll.
    for _ in 0..=LOSS_REPORT_QUEUE {
        let _ = overrun(&mut driver, &mut publication, &mut subscription);
    }
    assert_eq!(client.loss_reports_dropped(), 3);
    settle(&mut driver, &mut client);
    let handle = client.loss_reports_dropped_counter().unwrap();
    assert!(matches!(
        driver.client_counters().read(handle.cell()),
        CellRead::Allocated { value: 3, .. }
    ));
}

#[test]
fn test_a_refused_dropped_counter_keeps_the_count_local() {
    let (mut driver, _stream, mut publication, mut client, mut subscription) = setup_with(
        RejoinPolicy::RejoinAtHead,
        DriverConfig {
            max_counters_per_client: 1,
            ..DriverConfig::default()
        },
    );
    // The application holds the client's only counter.
    let _ = client.allocate_counter(9, "application", 0, 0).unwrap();
    let _ = driver.do_work().unwrap();
    let mut application = None;
    let _ = client.poll(usize::MAX, |completion| match completion.outcome {
        Outcome::Counter(handle) => application = Some(handle),
        other => panic!("unexpected {other:?}"),
    });
    let _application = application.unwrap();
    for _ in 0..LOSS_REPORT_QUEUE + 1 {
        let _ = overrun(&mut driver, &mut publication, &mut subscription);
    }
    settle(&mut driver, &mut client);
    // Refused once: the count stays local and is not asked for again.
    assert_eq!(client.loss_reports_dropped(), 1);
    assert!(client.loss_reports_dropped_counter().is_none());
    assert_eq!(counter(&driver, "commands refused"), 1);
    for _ in 0..=LOSS_REPORT_QUEUE {
        let _ = overrun(&mut driver, &mut publication, &mut subscription);
    }
    settle(&mut driver, &mut client);
    assert_eq!(client.loss_reports_dropped(), 2);
    assert_eq!(counter(&driver, "commands refused"), 1);
    assert_eq!(
        counter(&driver, "overruns rejoin at head"),
        2 * LOSS_REPORT_QUEUE as u64
    );
}
