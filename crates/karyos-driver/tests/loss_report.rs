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
/// The lane of the stream: a one-lane aggregate on lane 1, which a
/// command names.
const LANE: Lane = match Lane::try_new(1) {
    Ok(lane) => lane,
    Err(_) => panic!("lane 1 exists"),
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
            lane: LANE,
            session_id: KEY.session_id,
            stream_id: KEY.stream_id,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication: karyos_sys::log_buffer::PublicationMode::Exclusive,
            schedule_capacity: 0,
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
    setup_stream(policy, driver_config, config())
}

fn setup_stream(
    policy: RejoinPolicy,
    driver_config: DriverConfig,
    stream_config: StreamConfig,
) -> (
    EmbeddedDriver,
    StreamHandle,
    ClientPublication,
    ClientConductor,
    ClientSubscription,
) {
    let mut driver = EmbeddedDriver::with_config(driver_config).unwrap();
    let stream = driver.add_stream(stream_config).unwrap();
    let mut client = driver.connect().unwrap();
    let _ = client
        .add_subscription_on_lane(KEY, LANE, SubscriberRole::Optional)
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

// ---- Phase 1 closing audit of #9: the design's remaining loss report tests ----

/// A second optional subscription of `client` to the stream.
fn second_subscription(
    driver: &mut EmbeddedDriver,
    client: &mut ClientConductor,
    policy: RejoinPolicy,
) -> ClientSubscription {
    let _ = client
        .add_subscription_on_lane(KEY, LANE, SubscriberRole::Optional)
        .unwrap();
    let _ = driver.do_work().unwrap();
    let mut handle = None;
    let _ = client.poll(usize::MAX, |completion| match completion.outcome {
        Outcome::Subscription(subscription) => handle = Some(subscription),
        other => panic!("unexpected {other:?}"),
    });
    handle.unwrap().with_rejoin(policy)
}

/// observability-and-tools.md, Tests, "Loss reports": two subscriptions of
/// one client report separately, each with its own registration.
#[test]
fn test_two_subscriptions_of_one_client_report_separately() {
    // Two optional readers take a spare-slot credit each.
    let mut stream_config = config();
    stream_config.buffer.spare_slots = 5;
    let (mut driver, _stream, mut publication, mut client, mut first) = setup_stream(
        RejoinPolicy::RejoinAtHead,
        DriverConfig::default(),
        stream_config,
    );
    let mut second = second_subscription(&mut driver, &mut client, RejoinPolicy::RejoinAtHead);
    lap(&mut driver, &mut publication);
    let lost = [&mut first, &mut second].map(|subscription| {
        let summary = subscription.poll(|_, _| {}, MessageLimit::new(1)).unwrap();
        (
            subscription.origin().unwrap().registration(),
            summary.overrun.unwrap(),
        )
    });
    assert_ne!(lost[0].0, lost[1].0);
    settle(&mut driver, &mut client);
    let records = losses(&driver);
    assert_eq!(records.len(), 2, "{records:?}");
    for (registration, overrun) in lost {
        let record = records
            .iter()
            .find(|record| record.participant == registration)
            .unwrap_or_else(|| panic!("no record of {registration}: {records:?}"));
        assert_eq!((record.from, record.to), (overrun.from, overrun.lost_to));
        assert_eq!(record.client, client.owner().client);
        assert_eq!(record.flags, 0, "verified");
    }
}

/// observability-and-tools.md, Tests, "Loss reports": a report queued
/// across the removal and the re-adding of its stream names the old
/// incarnation, and is recorded unverified since its subscription ended.
#[test]
fn test_a_report_queued_across_a_stream_re_add_names_the_old_incarnation() {
    let (mut driver, stream, mut publication, mut client, mut subscription) =
        setup(RejoinPolicy::RejoinAtHead);
    let old = driver.trace_identity(stream).unwrap();
    let (lost, _) = overrun(&mut driver, &mut publication, &mut subscription);
    // The report waits in the client; the subscription ends and the
    // stream is removed, freed and added again under the same key.
    assert_eq!(client.loss_reports_queued(), 1);
    drop(subscription);
    drop(publication);
    driver.remove_stream(stream).unwrap();
    for _ in 0..10 {
        let _ = driver.do_work().unwrap();
    }
    let again = driver.add_stream(config()).unwrap();
    let new = driver.trace_identity(again).unwrap();
    assert_ne!(
        (new.registration, new.incarnation),
        (old.registration, old.incarnation)
    );
    settle(&mut driver, &mut client);
    let records = losses(&driver);
    assert_eq!(records.len(), 1, "{records:?}");
    let record = records[0];
    assert_eq!(
        (record.stream_registration, record.incarnation),
        (old.registration, old.incarnation)
    );
    assert_eq!((record.from, record.to), (lost.from, lost.lost_to));
    assert_eq!(record.flags & 1, 1, "recorded unverified");
}

/// observability-and-tools.md, Tests, "Loss reports": a full command ring
/// delays a report without losing it.
#[test]
fn test_a_full_command_ring_delays_a_report_without_losing_it() {
    let (mut driver, _stream, mut publication, mut client, mut subscription) = setup_with(
        RejoinPolicy::RejoinAtHead,
        DriverConfig {
            max_pending_per_client: 256,
            ..DriverConfig::default()
        },
    );
    let (lost, _) = overrun(&mut driver, &mut publication, &mut subscription);
    // Fill the ring with requests the driver has not served yet.
    let unknown = StreamKey {
        stream_id: 99,
        session_id: 1,
    };
    let mut filled = 0;
    while client
        .add_subscription(unknown, SubscriberRole::Optional)
        .is_ok()
    {
        filled += 1;
        assert!(filled < 1000, "the ring never filled");
    }
    // The report cannot be sent: it stays queued, nothing is dropped.
    let _ = client.poll(usize::MAX, |_| {});
    assert_eq!(client.loss_reports_queued(), 1);
    assert_eq!(client.loss_reports_dropped(), 0);
    assert!(losses(&driver).is_empty());
    // The driver drains the ring; the report follows and is recorded.
    for _ in 0..1000 {
        let _ = driver.do_work().unwrap();
        let _ = client.poll(usize::MAX, |_| {});
        if client.loss_reports_queued() == 0 && client.pending() == 0 {
            break;
        }
    }
    assert_eq!(client.loss_reports_queued(), 0);
    let records = losses(&driver);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!((records[0].from, records[0].to), (lost.from, lost.lost_to));
    assert_eq!(client.loss_reports_dropped(), 0);
}

/// A provider with no replay for any gap: the Archive refuses it.
struct Refusing;

impl karyos_client::ReplayProvider for Refusing {
    fn replay(&mut self, _request: &karyos_client::ReplayRequest) -> karyos_client::ReplayStatus {
        karyos_client::ReplayStatus::Unavailable(karyos_client::ReplayUnavailable::Refused)
    }

    fn cancel(&mut self) {}
}

/// A replay rejoin reports its overrun once, when it resolved, as `replay`
/// with the provider's reason and the secondary's outcome; the wrapped
/// subscription's own `rejoin at head` is not reported.
#[test]
fn test_a_replay_rejoin_reports_its_overrun_once_resolved() {
    let (mut driver, stream, mut publication, mut client, subscription) =
        setup(RejoinPolicy::RejoinAtHead);
    let source = driver.trace_identity(stream).unwrap();
    let mut rejoin = karyos_client::ReplayRejoin::new(
        subscription,
        source,
        Box::new(Refusing),
        Secondary::RejoinAtHead,
    );
    lap(&mut driver, &mut publication);
    let first = rejoin.poll(|_, _| {}, MessageLimit::new(1)).unwrap();
    let lost = first.overrun.unwrap();
    assert_eq!(first.rejoin, Some(RejoinOutcome::Replaying));
    assert_eq!(client.loss_reports_queued(), 0);
    let resolved = rejoin.poll(|_, _| {}, MessageLimit::new(1)).unwrap();
    assert_eq!(
        resolved.rejoin,
        Some(RejoinOutcome::ReplayFallback {
            reason: ReplayFallbackReason::Refused,
            secondary: SecondaryOutcome::ResumedAtHead,
        })
    );
    assert_eq!(client.loss_reports_queued(), 1);
    settle(&mut driver, &mut client);
    let [record] = losses(&driver)[..] else {
        panic!("expected exactly one loss record");
    };
    assert_eq!(
        (
            record.configured_policy,
            record.applied_policy,
            record.reason,
            record.from,
            record.to
        ),
        (4, 1, 5, lost.from, lost.lost_to)
    );
    assert_eq!(counter(&driver, "overruns rejoin at head"), 1);
    assert_eq!(counter(&driver, "replay fallbacks"), 1);
}

/// A provider that never answers: the gap stays asked for.
struct Pending;

impl karyos_client::ReplayProvider for Pending {
    fn replay(&mut self, _request: &karyos_client::ReplayRequest) -> karyos_client::ReplayStatus {
        karyos_client::ReplayStatus::Pending
    }

    fn cancel(&mut self) {}
}

/// A live reader taken back from a replay rejoin has its own policy and
/// loss reports again: its next overrun is closed by its `close` policy,
/// and reported as such.
#[test]
fn test_a_reader_taken_back_reports_by_its_own_policy() {
    let (mut driver, stream, mut publication, mut client, subscription) =
        setup(RejoinPolicy::Close);
    let source = driver.trace_identity(stream).unwrap();
    let rejoin = karyos_client::ReplayRejoin::new(
        subscription,
        source,
        Box::new(Refusing),
        Secondary::RejoinAtHead,
    );
    let mut live = rejoin.into_live().unwrap();
    lap(&mut driver, &mut publication);
    let first = live.poll(|_, _| {}, MessageLimit::new(1)).unwrap();
    let lost = first.overrun.unwrap();
    assert_eq!(first.rejoin, Some(RejoinOutcome::Closed));
    settle(&mut driver, &mut client);
    let [record] = losses(&driver)[..] else {
        panic!("expected exactly one loss record");
    };
    assert_eq!(
        (
            record.configured_policy,
            record.applied_policy,
            record.reason,
            record.from,
            record.to
        ),
        (3, 4, 0, lost.from, lost.lost_to)
    );
}

/// A gap given up while it is asked for is reported once, as `replay`
/// withdrawn with the reader resumed at its resume: when the live reader
/// is taken back, and when the rejoin is dropped.
#[test]
fn test_a_withdrawn_replay_rejoin_reports_its_overrun() {
    for taken_back in [true, false] {
        let (mut driver, stream, mut publication, mut client, subscription) =
            setup(RejoinPolicy::RejoinAtHead);
        let source = driver.trace_identity(stream).unwrap();
        let mut rejoin = karyos_client::ReplayRejoin::new(
            subscription,
            source,
            Box::new(Pending),
            Secondary::RejoinAtHead,
        );
        lap(&mut driver, &mut publication);
        let first = rejoin.poll(|_, _| {}, MessageLimit::new(1)).unwrap();
        let lost = first.overrun.unwrap();
        assert_eq!(first.rejoin, Some(RejoinOutcome::Replaying));
        let asking = rejoin.poll(|_, _| {}, MessageLimit::new(1)).unwrap();
        assert_eq!(asking.rejoin, None);
        assert!(rejoin.is_recovering());
        assert_eq!(client.loss_reports_queued(), 0);
        if taken_back {
            drop(rejoin.into_live());
        } else {
            drop(rejoin);
        }
        settle(&mut driver, &mut client);
        let [record] = losses(&driver)[..] else {
            panic!("expected exactly one loss record, taken back {taken_back}");
        };
        assert_eq!(
            (
                record.configured_policy,
                record.applied_policy,
                record.reason,
                record.from,
                record.to
            ),
            (4, 1, 7, lost.from, lost.lost_to),
            "taken back {taken_back}"
        );
        assert_eq!(counter(&driver, "replay fallbacks"), 1);
    }
}

/// #420 review P1: a valid loss report served after its subscription's
/// stream was freed is not a protocol violation. The overrun subscriber's
/// report is sent, then its `Remove` is queued behind it; the stream is
/// removed, and the next cycle frees it (no lease is left) before serving
/// the two commands. The report is counted unverified, the client is not
/// retired, and the `Remove` then succeeds.
#[test]
fn test_a_loss_report_after_its_stream_is_freed_does_not_retire_the_client() {
    let (mut driver, stream, mut publication, mut client, mut subscription) =
        setup(RejoinPolicy::RejoinAtHead);
    let _ = overrun(&mut driver, &mut publication, &mut subscription);
    assert_eq!(client.loss_reports_queued(), 1);
    drop(publication);
    // The report goes first, then the Remove, in one ring.
    let _ = client.poll(usize::MAX, |completion| {
        panic!("unexpected completion {completion:?}");
    });
    assert_eq!(client.loss_reports_queued(), 0);
    let remove = client.remove_subscription(subscription).unwrap();
    driver.remove_stream(stream).unwrap();
    let _ = driver.do_work().unwrap();
    assert_eq!(
        driver.stream_state(stream).unwrap(),
        karyos_driver::StreamState::Freed
    );
    // One command per ring per visit: the Remove is served after the
    // report.
    let mut done = Vec::new();
    for _ in 0..10 {
        let _ = client.poll(usize::MAX, |completion| done.push(completion));
        if !done.is_empty() {
            break;
        }
        let _ = driver.do_work().unwrap();
    }
    assert_eq!(done.len(), 1, "{done:?}");
    assert_eq!(done[0].sequence, remove);
    assert!(matches!(done[0].outcome, Outcome::Succeeded));
    assert_eq!(counter(&driver, "clients faulty"), 0);
    assert_eq!(counter(&driver, "loss reports unverified"), 1);
    assert_eq!(driver.clients(), 1, "the client is still served");
}
