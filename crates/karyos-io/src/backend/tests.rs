// SPDX-License-Identifier: Apache-2.0

//! Unit tests of the common types: identities, the report and its rules.

use std::net::{Ipv4Addr, SocketAddr};

use proptest::prelude::*;

use super::*;

fn id(slot: u32, generation: u64) -> SubmissionId {
    SubmissionId::new(
        InstanceId::FIRST,
        BackendEpoch::FIRST,
        slot,
        NonZeroU64::new(generation).unwrap(),
    )
}

fn entry(slot: u32) -> TxEntry {
    TxEntry {
        ticket: TxTicket::new(id(slot, 1)),
        token: SenderToken::new(u64::from(slot)),
        len: 1,
        outcome: TxItemOutcome::Submitted {
            release: Release::AtSubmission,
        },
        late: false,
    }
}

fn fill(report: &mut TxReport, count: u32) {
    let mut writer = report.writer().unwrap();
    for slot in 0..count {
        writer.push(entry(slot)).unwrap();
    }
}

#[test]
fn identity_counters_are_checked() {
    assert_eq!(InstanceId::FIRST.get().get(), 1);
    assert_eq!(InstanceId::FIRST.next().unwrap().get().get(), 2);
    assert_eq!(
        InstanceId::new(NonZeroU32::MAX).next(),
        Err(OpenError::InstanceExhausted)
    );
    assert_eq!(BackendEpoch::FIRST.next().unwrap().get().get(), 2);
    assert_eq!(
        BackendEpoch::new(NonZeroU32::MAX).next(),
        Err(OpenError::EpochExhausted)
    );
    assert_eq!(Authority::FIRST.next().unwrap().get().get(), 2);
    assert_eq!(Authority::new(NonZeroU64::MAX).next(), None);
}

#[test]
fn identity_old_epoch_or_generation_never_matches() {
    let ticket = TxTicket::new(id(3, 7));
    assert_eq!(ticket.id().slot(), 3);
    assert_eq!(ticket.id().generation().get(), 7);
    assert_eq!(ticket.id().instance(), InstanceId::FIRST);
    // Another generation of the same slot.
    assert_ne!(ticket, TxTicket::new(id(3, 8)));
    // The same slot and generation in another epoch.
    let next_epoch = SubmissionId::new(
        InstanceId::FIRST,
        BackendEpoch::FIRST.next().unwrap(),
        3,
        NonZeroU64::new(7).unwrap(),
    );
    assert_ne!(ticket.id(), next_epoch);
    assert_eq!(next_epoch.epoch().get().get(), 2);
    // Another instance.
    let other_instance = SubmissionId::new(
        InstanceId::FIRST.next().unwrap(),
        BackendEpoch::FIRST,
        3,
        NonZeroU64::new(7).unwrap(),
    );
    assert_ne!(ticket.id(), other_instance);
}

#[test]
fn handles_across_reset_differ_by_epoch_at_the_type_level() {
    let generation = NonZeroU32::MIN;
    let old = TxQueueId::new(BackendEpoch::FIRST, 0, generation);
    let new = TxQueueId::new(BackendEpoch::FIRST.next().unwrap(), 0, generation);
    assert_ne!(old, new);
    assert_eq!(
        (new.index(), new.generation()),
        (old.index(), old.generation())
    );
    let old_route = RouteId::new(BackendEpoch::FIRST, 0, generation);
    let new_route = RouteId::new(BackendEpoch::FIRST.next().unwrap(), 0, generation);
    assert_ne!(old_route, new_route);
    assert_eq!(new_route.epoch().get().get(), 2);
}

#[test]
fn report_not_empty_refuses_a_writer_and_changes_nothing() {
    let mut report = TxReport::new();
    assert!(report.is_empty());
    fill(&mut report, 2);
    assert!(!report.is_empty());
    assert!(report.writer().is_none());
    // The refused writer changed nothing: both entries are still there.
    assert_eq!(report.pop_front(), Some(entry(0)));
    assert!(report.writer().is_none(), "one unread entry still refuses");
    assert_eq!(report.pop_front(), Some(entry(1)));
    assert_eq!(report.pop_front(), None);
    assert!(report.writer().is_some());
}

#[test]
fn report_capacity_is_tx_report_capacity() {
    let mut report = TxReport::default();
    let mut writer = report.writer().unwrap();
    for slot in 0..u32::try_from(TX_REPORT_CAPACITY).unwrap() {
        assert_eq!(
            writer.remaining(),
            TX_REPORT_CAPACITY - usize::try_from(slot).unwrap()
        );
        writer.push(entry(slot)).unwrap();
    }
    assert_eq!(writer.remaining(), 0);
    let extra = entry(1000);
    assert_eq!(writer.push(extra), Err(extra));
    let mut popped = 0;
    while let Some(entry) = report.pop_front() {
        assert_eq!(entry.ticket.id().slot(), popped);
        popped += 1;
    }
    assert_eq!(usize::try_from(popped).unwrap(), TX_REPORT_CAPACITY);
}

proptest! {
    /// Entries leave in the order they were written, each exactly once,
    /// across any number of fill and drain rounds.
    #[test]
    fn report_entries_leave_once_in_order(rounds in proptest::collection::vec(0..=64_u32, 1..8)) {
        let mut report = TxReport::new();
        for count in rounds {
            fill(&mut report, count);
            for slot in 0..count {
                prop_assert_eq!(report.pop_front(), Some(entry(slot)));
            }
            prop_assert!(report.is_empty());
            prop_assert_eq!(report.pop_front(), None);
        }
    }
}

#[test]
fn budget_and_baseline_options() {
    let budget = Budget::new(1, 2, 3);
    assert_eq!(
        (budget.datagrams(), budget.bytes(), budget.ops()),
        (1, 2, 3)
    );
    assert_eq!(Spent::default().ops, 0);
    assert!(TxOptions::none().is_none());
    assert_eq!(TxOptions::default(), TxOptions::none());
}

#[test]
fn rx_datagram_lends_its_fields() {
    let bytes = [1_u8, 2, 3];
    let source = SocketAddr::from((Ipv4Addr::LOCALHOST, 4000));
    let observation = Observation {
        point: ObservationPoint::RecvReturn,
        domain: ClockDomain::HostMonotonic,
        epoch: ClockEpoch::new(0),
        time_ns: 10,
        uncertainty_ns: 1,
    };
    let datagram = RxDatagram::new(
        &bytes,
        source,
        PathId::new(1),
        BackendEpoch::FIRST,
        Some(observation),
    );
    assert_eq!(datagram.bytes(), &bytes);
    assert_eq!(datagram.source(), source);
    assert_eq!(datagram.path().get(), 1);
    assert_eq!(datagram.epoch(), BackendEpoch::FIRST);
    assert_eq!(datagram.observation(), Some(observation));
    assert_eq!(observation.epoch.get(), 0);
}

#[test]
fn errors_name_the_offending_value() {
    assert_eq!(
        ClaimError::TooLarge {
            len: 9000,
            max: 1408
        }
        .to_string(),
        "claim of 9000 bytes exceeds the datagram limit of 1408"
    );
    assert_eq!(
        QueueError::OverCommitted {
            requested: 5,
            free: 4
        }
        .to_string(),
        "queue of 5 pending frames exceeds the 4 uncommitted tx slots"
    );
    assert_eq!(
        RouteError::PathTooSmall {
            datagram: 1408,
            overhead: 48,
            route_mtu: 1280
        }
        .to_string(),
        "datagram of 1408 bytes plus 48 header bytes exceeds route mtu 1280"
    );
    assert_eq!(
        OpenError::RequiredCapability {
            capability: Capability::TxBatch,
            state: CapabilityState::Unavailable(Reason::Unsupported { errno: 38 }),
        }
        .to_string(),
        "required capability TxBatch is Unavailable(Unsupported { errno: 38 })"
    );
    assert_eq!(
        BackendFailure::Invariant {
            operation: "sendmmsg"
        }
        .to_string(),
        "sendmmsg returned a result outside its documented range"
    );
}
