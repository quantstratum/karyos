// SPDX-License-Identifier: Apache-2.0

//! Application trace points (R-CORE-1, karyos#722) cost the data path
//! nothing new, over a counting global allocator: a driver point's record
//! allocates nothing and keeps layout version 3 with no point registered,
//! and recording an application point, metadata included, allocates
//! nothing either.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use karyos_protocol::journal::{Append, Stamp};
use karyos_sys::alloc_count::{CountingAllocator, count};
use karyos_trace::{
    ApplicationContext, ApplicationPoint, Metadata, ObservedTime, ObserverId, Point, PublicationId,
    TraceIds, TraceRecord, Value, encode_record, trace_journal,
};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

const OBSERVER: ObserverId = ObserverId {
    driver: [3, 4],
    journal: 1,
};

fn publish(position: u64) -> TraceRecord {
    TraceRecord {
        point: Point::Publish,
        publication: PublicationId {
            driver: [1, 2],
            registration: 5,
            stream_id: 10,
            session_id: 3,
            incarnation: 1,
        },
        lane: 0,
        position,
        ids: TraceIds {
            trace_id: [7, 8],
            span_id: 1,
            parent_span_id: 0,
            message_id: position,
        },
        observed: ObservedTime {
            time: position,
            clock: 1,
            epoch: 0,
            uncertainty: 0,
        },
        subscriber: None,
        packet: None,
        network: None,
        root: false,
    }
}

fn stamp(time: u64) -> Stamp {
    Stamp {
        time,
        clock: 1,
        epoch: 0,
    }
}

#[test]
fn a_driver_point_without_application_points_allocates_nothing() {
    let (mut writer, _collector) = trace_journal(8, 2, OBSERVER, 1).unwrap();
    let record = publish(64);
    let (appended, operations) = count(|| writer.record(&record, stamp(1)));
    assert_eq!(appended, Ok(Append::Stored { sequence: 0 }));
    assert_eq!(operations, 0);
    // Layout version 3 and point 1, exactly as before application points.
    let words = encode_record(&record, stamp(1)).unwrap();
    assert_eq!(words[0] & 0xFFFF, 0x0103);
}

#[test]
fn observing_an_application_point_allocates_nothing() {
    let (writer, _collector) = trace_journal(8, 2, OBSERVER, 1).unwrap();
    let mut writer = writer.for_client(9);
    let point = ApplicationPoint::new(4, 9).unwrap();
    let sample = publish(32);
    let context = ApplicationContext {
        publication: sample.publication,
        lane: sample.lane,
        position: sample.position,
        ids: sample.ids,
        observed: sample.observed,
    };
    let (appended, operations) = count(|| {
        let metadata = Metadata::new(&[
            Value::U64(1),
            Value::I64(-1),
            Value::from_f64(0.5),
            Value::Tag(*b"fill\0\0\0\0"),
        ])?;
        point.observe(&mut writer, &context, metadata, stamp(2))
    });
    assert_eq!(appended, Ok(Append::Stored { sequence: 0 }));
    assert_eq!(operations, 0);
}
