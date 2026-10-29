// SPDX-License-Identifier: Apache-2.0

//! Aggregate publications (`quantstratum-docs:
//! karyos/design/aggregate-ownership.md`): all-or-nothing creation, one
//! identity for every lane, removal and reconfiguration per aggregate.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use karyos_client::OfferOutcome;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, Role, SealState};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

use super::*;
use crate::generations::Reconfiguration;

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
        allow_unconnected: true,
        on_required_loss: karyos_sys::log_buffer::LossPolicy::Hold,
        conflation: None,
    }
}

/// The allocated cells of the driver's counters.
fn allocated(driver: &EmbeddedDriver) -> usize {
    let reader = driver.counters();
    (0..reader.capacity())
        .filter(|index| {
            matches!(
                reader.read(*index),
                karyos_sys::counters::CellRead::Allocated { .. }
            )
        })
        .count()
}

/// The largest charged frame of `stream`: the MTU aligned to 32 bytes.
fn frame() -> u64 {
    u64::from(karyos_sys::sizing::align_frame(DEFAULT_MTU).unwrap())
}

fn aggregate(stream_id: i32, lanes: usize) -> AggregateConfig {
    AggregateConfig {
        stream: stream(stream_id),
        quanta: vec![frame(); lanes],
    }
}

fn lane(number: u8) -> Lane {
    Lane::try_new(number).unwrap()
}

/// Four lanes, each its own stream with its own positions, all reporting
/// the aggregate's identity with their lane.
#[test]
fn an_aggregate_has_one_identity_and_independent_lanes() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let handle = driver.add_aggregate(aggregate(2, 4)).unwrap();
    assert_eq!(handle.lanes(), 4);
    let first = driver
        .trace_identity(handle.lane(lane(0)).unwrap())
        .unwrap();
    for number in 0..4 {
        let stream = handle.lane(lane(number)).unwrap();
        let identity = driver.trace_identity(stream).unwrap();
        assert_eq!(identity, first, "lane {number}");
        let found = driver.stream(stream).unwrap();
        assert_eq!(found.config.lane, lane(number));
        assert_eq!(found.aggregate.lanes, 4);
    }
    // Each lane publishes and delivers on its own: equal positions,
    // distinct lanes.
    let mut readers: Vec<_> = (0..4)
        .map(|number| {
            driver
                .subscribe(handle.lane(lane(number)).unwrap(), Role::Optional)
                .unwrap()
        })
        .collect();
    for number in 0..4u8 {
        let mut publication = driver
            .publication(handle.lane(lane(number)).unwrap())
            .unwrap();
        assert!(matches!(
            publication.offer(&[number; 8]).unwrap(),
            OfferOutcome::Accepted { .. }
        ));
    }
    for (number, reader) in readers.iter_mut().enumerate() {
        let mut seen = Vec::new();
        reader
            .poll(
                |payload, _| seen.push(payload.to_vec()),
                karyos_client::MessageLimit::new(4),
            )
            .unwrap();
        assert_eq!(seen, vec![vec![number as u8; 8]]);
    }
    // A lane the aggregate does not have is not reachable.
    let two = driver.add_aggregate(aggregate(3, 2)).unwrap();
    assert!(two.lane(lane(2)).is_none());
}

/// No lane, five lanes, or a quantum below the largest frame are refused,
/// as are a key in use and a lane count over the stream quota; nothing is
/// added.
#[test]
fn an_aggregate_is_validated_before_anything_is_added() {
    let mut driver = EmbeddedDriver::with_config(DriverConfig {
        max_streams: 3,
        ..DriverConfig::default()
    })
    .unwrap();
    for config in [
        aggregate(2, 0),
        aggregate(2, 5),
        AggregateConfig {
            quanta: vec![frame() - 1],
            ..aggregate(2, 1)
        },
    ] {
        assert!(matches!(
            driver.add_aggregate(config),
            Err(DriverError::InvalidConfig)
        ));
    }
    assert!(matches!(
        driver.add_aggregate(aggregate(2, 4)),
        Err(DriverError::TooManyStreams)
    ));
    let _ = driver.add_aggregate(aggregate(2, 2)).unwrap();
    assert!(matches!(
        driver.add_aggregate(aggregate(2, 1)),
        Err(DriverError::DuplicateStream { .. })
    ));
    assert_eq!(driver.streams.len(), 2);
}

/// A failure while building any lane of a four-lane aggregate leaves no
/// lane, consumes no stream id and frees the counters of the lanes built
/// before it.
#[test]
fn a_failure_at_any_lane_leaves_nothing() {
    for failing in 0..4u64 {
        let mut driver = EmbeddedDriver::new().unwrap();
        let mut config = aggregate(2, 4);
        config.stream.conflation = Some(karyos_sys::conflation::ConflationConfig {
            keys: 4,
            value_capacity: 8,
            journal_capacity: 1024,
            refresh: false,
        });
        let next = driver.next_stream;
        let free = allocated(&driver);
        driver.fail_at = Some(next + failing);
        assert!(
            driver.add_aggregate(config.clone()).is_err(),
            "lane {failing}"
        );
        assert!(driver.streams.is_empty());
        assert_eq!(driver.next_stream, next);
        assert_eq!(allocated(&driver), free, "lane {failing}");
        driver.fail_at = None;
        let handle = driver.add_aggregate(config).unwrap();
        assert_eq!(handle.lanes(), 4);
    }
}

/// A lane of a multi-lane aggregate is removed and reconfigured only with
/// its aggregate; removal seals every lane.
#[test]
fn removal_seals_every_lane() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let handle = driver.add_aggregate(aggregate(2, 3)).unwrap();
    let mut observer = driver.connect().unwrap();
    let one = handle.lane(lane(1)).unwrap();
    assert!(matches!(
        driver.remove_stream(one),
        Err(DriverError::LaneOfAggregate { .. })
    ));
    let reconfiguration = Reconfiguration {
        term_length: TermLength::try_new(MIN_TERM_LENGTH * 2).unwrap(),
        spare_slots: 4,
    };
    assert!(matches!(
        driver.reconfigure_stream(one, reconfiguration),
        Err(DriverError::LaneOfAggregate { .. })
    ));
    driver.remove_aggregate(&handle).unwrap();
    // A retiring aggregate refuses issuance on every lane.
    for number in 0..3 {
        let stream = handle.lane(lane(number)).unwrap();
        assert_ne!(driver.seal_state(stream).unwrap(), SealState::Active);
        assert!(driver.stream(stream).unwrap().retiring);
        assert!(driver.publication(stream).is_err(), "lane {number}");
        assert!(
            driver.subscribe(stream, Role::Optional).is_err(),
            "lane {number}"
        );
    }
    // Each lane's closing names its lane.
    let _ = observer.poll(usize::MAX, |_| {});
    let _ = driver.do_work().unwrap();
    let _ = observer.poll(usize::MAX, |_| {});
    let closed: Vec<_> = observer
        .take_events()
        .filter_map(|event| match event {
            karyos_protocol::cnc::Event::PublicationClosed { stream, lane, .. } => {
                Some((stream.stream_id, lane.get()))
            }
            _ => None,
        })
        .collect();
    assert_eq!(closed, [(2, 0), (2, 1), (2, 2)]);
    // A one-lane stream is removed as before.
    let single = driver.add_stream(stream(9)).unwrap();
    driver.remove_stream(single).unwrap();
}

/// Reconfiguration is all or nothing: a lane that cannot prepare its
/// successor leaves every lane on its generation; otherwise every lane
/// moves to the next one.
#[test]
fn reconfiguration_is_per_aggregate_and_all_or_nothing() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let handle = driver.add_aggregate(aggregate(2, 3)).unwrap();
    let reconfiguration = Reconfiguration {
        term_length: TermLength::try_new(MIN_TERM_LENGTH * 2).unwrap(),
        spare_slots: 4,
    };
    let generation_of = |driver: &EmbeddedDriver, number: u8| {
        driver
            .stream_ref(handle.lane(lane(number)).unwrap())
            .unwrap()
            .generation
            .get()
    };
    driver.fail_at = Some(driver.stream(handle.lane(lane(2)).unwrap()).unwrap().id);
    assert!(
        driver
            .reconfigure_aggregate(&handle, reconfiguration)
            .is_err()
    );
    for number in 0..3 {
        assert_eq!(generation_of(&driver, number), 0);
        let stream = handle.lane(lane(number)).unwrap();
        assert_eq!(driver.seal_state(stream).unwrap(), SealState::Active);
        assert!(driver.stream(stream).unwrap().cutover.is_none());
    }
    driver.fail_at = None;
    let generation = driver
        .reconfigure_aggregate(&handle, reconfiguration)
        .unwrap();
    assert_eq!(generation.get(), 1);
    for number in 0..3 {
        let stream = handle.lane(lane(number)).unwrap();
        assert!(
            driver.stream(stream).unwrap().cutover.is_some() || generation_of(&driver, number) == 1
        );
    }
}

/// Counter keys and position cells name the aggregate's registration and
/// the lane.
#[test]
fn counters_and_positions_name_the_aggregate_and_the_lane() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let handle = driver.add_aggregate(aggregate(2, 2)).unwrap();
    let registration = driver.stream(handle.lane(lane(0)).unwrap()).unwrap().id;
    driver.positions.force_due();
    let _ = driver.do_work().unwrap();
    let reader = driver.counters();
    let mut lanes = Vec::new();
    for index in 0..reader.capacity() {
        if let karyos_sys::counters::CellRead::Allocated { metadata, .. } = reader.read(index)
            && metadata.label() == b"stream head"
        {
            assert_eq!(metadata.keys.stream, registration);
            lanes.push(metadata.keys.lane);
        }
    }
    lanes.sort_unstable();
    assert_eq!(lanes, vec![0, 1]);
}

/// Re-review of #814: an aggregate's change publishes its lanes' shared
/// gate slot exactly once, at the new version.
#[test]
fn an_aggregate_change_publishes_its_gate_slot_once() {
    use karyos_sys::rate_limit::{Rate, RatePolicy};
    use karyos_sys::rate_policy_slot::{SEQUENCE, SLOT_WORDS, SlotRead, try_read};

    let mut driver = EmbeddedDriver::new().unwrap();
    let aggregate = driver
        .add_aggregate(AggregateConfig {
            stream: stream(2),
            quanta: vec![u64::from(DEFAULT_MTU) * 4; 2],
        })
        .unwrap();
    let guard = driver.add_guard("orders").unwrap();
    let policy = |per_second| RatePolicy {
        messages: Rate {
            per_second,
            burst: 10,
        },
        bytes: None,
    };
    for lane in aggregate.streams() {
        driver
            .guard_stream(
                lane,
                guard,
                4,
                Some(crate::guards::GuardRate::publication(policy(100))),
            )
            .unwrap();
    }
    // The lanes share one slot, as a guarded network publication's do.
    let slot = Arc::new(crate::shared_words::Words::heap(SLOT_WORDS));
    let mut lanes = aggregate.streams();
    let first = lanes.next().unwrap();
    driver
        .stream(first)
        .unwrap()
        .guarded
        .as_mut()
        .unwrap()
        .set_gate_slot(Arc::clone(&slot));
    for lane in lanes {
        driver
            .stream(lane)
            .unwrap()
            .guarded
            .as_mut()
            .unwrap()
            .keep_gate_slot(Arc::clone(&slot));
    }
    let sequence = |slot: &crate::shared_words::Words| {
        slot.words()[SEQUENCE].load(std::sync::atomic::Ordering::Acquire)
    };
    let before = sequence(&slot);
    assert_eq!(
        driver.change_aggregate_rate_policy(
            &aggregate,
            1,
            policy(50),
            (crate::guards::RateAuthority::Safety, 1)
        ),
        Ok(2)
    );
    // One publication: the sequence word moves by 2 (odd, then even).
    assert_eq!(sequence(&slot), before + 2);
    let words = slot.words();
    assert!(matches!(
        try_read(&words, 0),
        SlotRead::Policy { version: 2, policy: published } if published == policy(50)
    ));
}

/// Follow-up 6 of the #814 review: the first lane guarded with a rate
/// gives the policy to the rateless lanes guarded before it, and their
/// shared gate slot is published once, at version 1.
#[test]
fn the_first_rate_publishes_the_rateless_lanes_gate_slot_once() {
    use karyos_sys::rate_limit::{Rate, RatePolicy};
    use karyos_sys::rate_policy_slot::{SEQUENCE, SLOT_WORDS, SlotRead, try_read};

    let mut driver = EmbeddedDriver::new().unwrap();
    let aggregate = driver
        .add_aggregate(AggregateConfig {
            stream: stream(2),
            quanta: vec![u64::from(DEFAULT_MTU) * 4; 3],
        })
        .unwrap();
    let guard = driver.add_guard("orders").unwrap();
    let policy = RatePolicy {
        messages: Rate {
            per_second: 100,
            burst: 10,
        },
        bytes: None,
    };
    let lanes: Vec<StreamHandle> = aggregate.streams().collect();
    // Two lanes guarded with no rate, sharing one slot.
    let slot = Arc::new(crate::shared_words::Words::heap(SLOT_WORDS));
    for (index, lane) in lanes[..2].iter().enumerate() {
        driver.guard_stream(*lane, guard, 4, None).unwrap();
        let guarded = driver.stream(*lane).unwrap().guarded.as_mut().unwrap();
        if index == 0 {
            guarded.set_gate_slot(Arc::clone(&slot));
        } else {
            guarded.keep_gate_slot(Arc::clone(&slot));
        }
    }
    let sequence = |slot: &crate::shared_words::Words| {
        slot.words()[SEQUENCE].load(std::sync::atomic::Ordering::Acquire)
    };
    let before = sequence(&slot);
    driver
        .guard_stream(
            lanes[2],
            guard,
            4,
            Some(crate::guards::GuardRate::publication(policy)),
        )
        .unwrap();
    // One publication for both lanes: the sequence word moves by 2.
    assert_eq!(sequence(&slot), before + 2);
    let words = slot.words();
    assert!(matches!(
        try_read(&words, 0),
        SlotRead::Policy { version: 1, policy: published } if published == policy
    ));
}

/// Re-review of #814: a change named on a lane whose aggregate cannot be
/// assembled (a lane missing from the table, which the API never leaves)
/// is refused with the lookup's error and audited for every guard of the
/// lanes still there.
#[test]
fn a_change_on_an_aggregate_with_a_lane_gone_is_audited_for_every_guard() {
    use karyos_sys::rate_limit::{Rate, RatePolicy};

    let mut driver = EmbeddedDriver::new().unwrap();
    let aggregate = driver
        .add_aggregate(AggregateConfig {
            stream: stream(2),
            quanta: vec![u64::from(DEFAULT_MTU) * 4; 3],
        })
        .unwrap();
    let policy = |per_second| RatePolicy {
        messages: Rate {
            per_second,
            burst: 10,
        },
        bytes: None,
    };
    let lanes: Vec<StreamHandle> = aggregate.streams().collect();
    let (a, b) = (
        driver.add_guard("a").unwrap(),
        driver.add_guard("b").unwrap(),
    );
    for (lane, guard) in [(lanes[0], a), (lanes[1], b)] {
        driver
            .guard_stream(
                lane,
                guard,
                4,
                Some(crate::guards::GuardRate::publication(policy(100))),
            )
            .unwrap();
    }
    // Lane 2 leaves the table under the aggregate.
    driver.streams.retain(|lane| lane.id != lanes[2].stream);
    let refused = driver.change_rate_policy(
        lanes[0],
        1,
        policy(50),
        (crate::guards::RateAuthority::Safety, 9),
    );
    assert!(
        matches!(refused, Err(DriverError::UnknownStream { .. })),
        "{refused:?}"
    );
    let audit: Vec<_> = driver
        .guard_audit()
        .records
        .iter()
        .filter(|record| record.operation == 9)
        .map(|record| (record.guard, record.before, record.after))
        .collect();
    assert_eq!(audit, [(a.id(), 1, 1), (b.id(), 1, 1)]);
}

/// Re-review V2 of #814: a publication's stored rate policy goes with its
/// last lane, so creating and removing publications never grows it.
#[test]
fn a_publications_rate_policy_goes_with_its_last_lane() {
    use karyos_sys::rate_limit::{Rate, RatePolicy};

    let mut driver = EmbeddedDriver::new().unwrap();
    let guard = driver.add_guard("orders").unwrap();
    let policy = RatePolicy {
        messages: Rate {
            per_second: 100,
            burst: 10,
        },
        bytes: None,
    };
    for round in 0..3 {
        let aggregate = driver
            .add_aggregate(AggregateConfig {
                stream: stream(2 + round),
                quanta: vec![u64::from(DEFAULT_MTU) * 4; 2],
            })
            .unwrap();
        for lane in aggregate.streams() {
            driver
                .guard_stream(
                    lane,
                    guard,
                    4,
                    Some(crate::guards::GuardRate::publication(policy)),
                )
                .unwrap();
        }
        assert_eq!(driver.rate_policies.len(), 1);
        driver.remove_aggregate(&aggregate).unwrap();
        driver.free_retired_streams();
        assert!(driver.rate_policies.is_empty(), "round {round}");
    }
}

/// Follow-up 7 of the #814 review: with one lane of a removed publication
/// freed and another still retiring (a lease held), the stored policy
/// stays; it goes when the last lane is freed.
#[test]
fn a_publications_rate_policy_stays_while_a_lane_is_retiring() {
    use karyos_client::link::{Lease, LeaseEnd};
    use karyos_sys::rate_limit::{Rate, RatePolicy};

    let mut driver = EmbeddedDriver::new().unwrap();
    let guard = driver.add_guard("orders").unwrap();
    let policy = RatePolicy {
        messages: Rate {
            per_second: 100,
            burst: 10,
        },
        bytes: None,
    };
    let aggregate = driver
        .add_aggregate(AggregateConfig {
            stream: stream(2),
            quanta: vec![u64::from(DEFAULT_MTU) * 4; 2],
        })
        .unwrap();
    for lane in aggregate.streams() {
        driver
            .guard_stream(
                lane,
                guard,
                4,
                Some(crate::guards::GuardRate::publication(policy)),
            )
            .unwrap();
    }
    let kept = aggregate.streams().nth(1).unwrap();
    let lease = Lease::acquire(
        &driver.stream(kept).unwrap().leases,
        &Arc::new(LeaseEnd::default()),
    );
    driver.remove_aggregate(&aggregate).unwrap();
    driver.free_retired_streams();
    assert_eq!(driver.streams.len(), 1, "one lane freed, one retiring");
    assert_eq!(driver.rate_policies.len(), 1);
    drop(lease);
    driver.free_retired_streams();
    assert!(driver.streams.is_empty());
    assert!(driver.rate_policies.is_empty());
}

/// The #841 review: one `free_retired_streams` over several removed
/// publications drops the policy of each whose last lane went, and keeps
/// the one with a lane still retiring.
#[test]
fn freeing_several_publications_drops_only_the_policies_with_no_lane_left() {
    use karyos_client::link::{Lease, LeaseEnd};
    use karyos_sys::rate_limit::{Rate, RatePolicy};

    let mut driver = EmbeddedDriver::new().unwrap();
    let guard = driver.add_guard("orders").unwrap();
    let policy = RatePolicy {
        messages: Rate {
            per_second: 100,
            burst: 10,
        },
        bytes: None,
    };
    let aggregates: Vec<_> = (0..3)
        .map(|index| {
            let aggregate = driver
                .add_aggregate(AggregateConfig {
                    stream: stream(2 + index),
                    quanta: vec![u64::from(DEFAULT_MTU) * 4; 2],
                })
                .unwrap();
            for lane in aggregate.streams() {
                driver
                    .guard_stream(
                        lane,
                        guard,
                        4,
                        Some(crate::guards::GuardRate::publication(policy)),
                    )
                    .unwrap();
            }
            aggregate
        })
        .collect();
    assert_eq!(driver.rate_policies.len(), 3);
    // The middle one keeps a lane retiring.
    let kept = aggregates[1].streams().nth(1).unwrap();
    let registration = driver.stream(kept).unwrap().aggregate.registration;
    let lease = Lease::acquire(
        &driver.stream(kept).unwrap().leases,
        &Arc::new(LeaseEnd::default()),
    );
    for aggregate in &aggregates {
        driver.remove_aggregate(aggregate).unwrap();
    }
    driver.free_retired_streams();
    assert_eq!(driver.streams.len(), 1);
    assert_eq!(
        driver.rate_policies.keys().copied().collect::<Vec<_>>(),
        vec![registration]
    );
    drop(lease);
    driver.free_retired_streams();
    assert!(driver.rate_policies.is_empty());
}

/// A1 of the #841 review: the driver validates a byte burst against the
/// largest charge its sender gate does, the MTU aligned as a frame, so a
/// burst between the MTU and that charge is refused at the change and
/// never reaches a gate that would refuse it.
#[test]
fn a_byte_burst_below_the_aligned_mtu_is_refused_at_the_change() {
    use karyos_sys::rate_limit::{Rate, RatePolicy};

    let mtu = 1400;
    let aligned = u64::from(karyos_sys::sizing::align_frame(mtu).unwrap());
    assert!(aligned > u64::from(mtu));
    let mut driver = EmbeddedDriver::new().unwrap();
    let mut config = stream(2);
    config.buffer.mtu = mtu;
    let handle = driver.add_stream(config).unwrap();
    let guard = driver.add_guard("orders").unwrap();
    let policy = |burst| RatePolicy {
        messages: Rate {
            per_second: 100,
            burst: 10,
        },
        bytes: Some(Rate {
            per_second: 1_000_000,
            burst,
        }),
    };
    // At guarding too (#841 review, point 5): a byte burst of the MTU,
    // below the aligned charge, is refused.
    assert!(matches!(
        driver.guard_stream(
            handle,
            guard,
            4,
            Some(crate::guards::GuardRate::publication(policy(u64::from(
                mtu
            )))),
        ),
        Err(DriverError::InvalidRatePolicy(_))
    ));
    driver
        .guard_stream(
            handle,
            guard,
            4,
            Some(crate::guards::GuardRate::publication(policy(aligned * 4))),
        )
        .unwrap();
    let admin = (crate::guards::RateAuthority::Administrator, 1);
    assert!(matches!(
        driver.change_rate_policy(handle, 1, policy(u64::from(mtu)), admin),
        Err(DriverError::InvalidRatePolicy(_))
    ));
    // Refused and audited so; nothing published, the policy in force kept.
    let refused = *driver.guard_audit().records.last().unwrap();
    assert!(matches!(
        refused.outcome,
        crate::guards::AuditOutcome::Refused(_)
    ));
    assert_eq!((refused.before, refused.after), (1, 1));
    assert_eq!(
        driver.rate_policies.values().copied().collect::<Vec<_>>(),
        vec![(policy(aligned * 4), 1)]
    );
    assert_eq!(
        driver.change_rate_policy(handle, 1, policy(aligned), admin),
        Ok(2)
    );
}

/// #841 review, point 6: the control reserve's byte floor counts each
/// reserved message as the aligned charge too, so on an MTU of 1400 a
/// reserve of 10 messages a second needs 14 080 bytes a second, not 14 000.
#[test]
fn the_reserve_floor_counts_the_aligned_charge() {
    use karyos_sys::rate_limit::{Rate, RatePolicy};

    let mtu = 1400;
    let aligned = u64::from(karyos_sys::sizing::align_frame(mtu).unwrap());
    let policy = |bytes_per_second| RatePolicy {
        messages: Rate {
            per_second: 100,
            burst: 100,
        },
        bytes: Some(Rate {
            per_second: bytes_per_second,
            burst: aligned * 100,
        }),
    };
    let reserve = Rate {
        per_second: 10,
        burst: 10,
    };
    let mut driver = EmbeddedDriver::new().unwrap();
    let mut config = stream(2);
    config.buffer.mtu = mtu;
    let handle = driver.add_stream(config).unwrap();
    let guard = driver.add_guard("orders").unwrap();
    driver
        .guard_stream(
            handle,
            guard,
            4,
            Some(crate::guards::GuardRate::publication(policy(1_000_000)).with_reserve(reserve)),
        )
        .unwrap();
    let admin = (crate::guards::RateAuthority::Administrator, 1);
    assert_eq!(
        driver.change_rate_policy(handle, 1, policy(10 * u64::from(mtu)), admin),
        Err(DriverError::RateChange(
            crate::guards::RateChangeError::ReserveCrossed
        ))
    );
    assert_eq!(
        driver.change_rate_policy(handle, 1, policy(10 * aligned), admin),
        Ok(2)
    );
}

/// QS-COORDINATOR, ACS 33899: with every lane the driver can hold guarded
/// with a rate, the stored policies never pass `max_streams`, and the next
/// stream is refused before any policy could be stored for it.
#[test]
fn the_stored_policies_never_pass_max_streams() {
    use karyos_sys::rate_limit::{Rate, RatePolicy};

    let max_streams = 4;
    let mut driver = EmbeddedDriver::with_config(DriverConfig {
        max_streams,
        ..DriverConfig::default()
    })
    .unwrap();
    let guard = driver.add_guard("orders").unwrap();
    let policy = RatePolicy {
        messages: Rate {
            per_second: 100,
            burst: 10,
        },
        bytes: None,
    };
    for stream_id in 0..i32::try_from(max_streams).unwrap() {
        let handle = driver.add_stream(stream(10 + stream_id)).unwrap();
        driver
            .guard_stream(
                handle,
                guard,
                4,
                Some(crate::guards::GuardRate::publication(policy)),
            )
            .unwrap();
        assert!(driver.rate_policies.len() <= max_streams);
    }
    assert_eq!(driver.rate_policies.len(), max_streams);
    assert!(driver.add_stream(stream(99)).is_err());
    assert_eq!(driver.rate_policies.len(), max_streams);
}
