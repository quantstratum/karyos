// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::path::PathBuf;

use super::*;
use crate::api::{API_VERSION, TraceCounts};

/// One view with every type and every `DriverState` variant, `None` and
/// `Some` alike.
fn every_field() -> AgentView {
    let counter = Counter {
        label: "streams active".to_owned(),
        type_id: 2,
        stream: 0,
        lane: 0,
        kind: 0,
        participant: 0,
        value: u64::MAX,
    };
    let attached = DriverView {
        dir: PathBuf::from("/run/karyos/a"),
        state: DriverState::Attached,
        instance: Some(0x0123_4567_89ab_cdef_0011_2233_4455_6677),
        sample: Some(Sample {
            consistent: true,
            sampled: true,
            age_ns: Some(1500),
            counters: vec![counter.clone()],
            lanes: vec![Lane {
                stream: 3,
                lane: 1,
                limit: Some(4096),
                head: Some(1024),
                floor: None,
                headroom: Some(3072),
                subscribers: vec![Subscriber {
                    registration: 5,
                    label: "subscriber position generation 0 cell 1".to_owned(),
                    position: 2048,
                    lag: Some(-1024),
                }],
            }],
        }),
        client_counters: vec![counter],
        errors: Feed {
            records: vec![ErrorEntry {
                seq: 0,
                first: 10,
                last: 20,
                occurrences: 3,
                code: 4,
                source: 1,
                key: [2, 1],
                message: "stream \"2\" rejected\n\ttwice\u{1}".to_owned(),
            }],
            delivered: 1,
            overwritten: 0,
        },
        losses: Feed {
            records: vec![LossEntry {
                seq: 7,
                time: 30,
                kind: 1,
                reason: 2,
                lane: 0,
                stream_id: 9,
                stream_registration: 3,
                from: 100,
                to: 200,
                participant: 5,
                client: 6,
            }],
            delivered: 8,
            overwritten: 7,
        },
        guards: Feed {
            records: vec![GuardEntry {
                seq: 1,
                time: 40,
                guard: 1,
                before: 2,
                after: 3,
                operation: 42,
                requester_kind: 1,
                requester: 6,
                outcome: 4,
                refusal: 9,
            }],
            delivered: 2,
            overwritten: 0,
        },
        latencies: Vec::new(),
        trace: TraceCounts::default(),
    };
    let unavailable = DriverView {
        dir: PathBuf::from("/run/karyos/b"),
        state: DriverState::Unavailable {
            reason: "no socket".to_owned(),
        },
        instance: None,
        sample: None,
        client_counters: Vec::new(),
        errors: Feed::default(),
        losses: Feed::default(),
        guards: Feed::default(),
        latencies: Vec::new(),
        trace: TraceCounts::default(),
    };
    let closed = DriverView {
        dir: PathBuf::from("/run/karyos/c"),
        state: DriverState::Closed,
        ..unavailable.clone()
    };
    AgentView {
        version: API_VERSION,
        drivers: vec![attached, unavailable, closed],
    }
}

/// API v1's JSON, field for field. This is the compatibility contract
/// (ADR-0055 Validation): a field renamed, removed, retyped or moved fails
/// here, and needs API v2. A field added to v1 is appended to this text.
const V1: &str = concat!(
    r#"{"version":1,"drivers":["#,
    r#"{"dir":"/run/karyos/a","state":{"state":"attached"},"#,
    r#""instance":"0123456789abcdef0011223344556677","#,
    r#""sample":{"consistent":true,"sampled":true,"age_ns":1500,"#,
    r#""counters":[{"label":"streams active","type_id":2,"stream":0,"lane":0,"kind":0,"participant":0,"value":18446744073709551615}],"#,
    r#""lanes":[{"stream":3,"lane":1,"limit":4096,"head":1024,"floor":null,"headroom":3072,"#,
    r#""subscribers":[{"registration":5,"label":"subscriber position generation 0 cell 1","position":2048,"lag":-1024}]}]},"#,
    r#""client_counters":[{"label":"streams active","type_id":2,"stream":0,"lane":0,"kind":0,"participant":0,"value":18446744073709551615}],"#,
    r#""errors":{"records":[{"seq":0,"first":10,"last":20,"occurrences":3,"code":4,"source":1,"key":[2,1],"message":"stream \"2\" rejected\n\ttwice\u0001"}],"delivered":1,"overwritten":0},"#,
    r#""losses":{"records":[{"seq":7,"time":30,"kind":1,"reason":2,"lane":0,"stream_id":9,"stream_registration":3,"from":100,"to":200,"participant":5,"client":6}],"delivered":8,"overwritten":7},"#,
    r#""guards":{"records":[{"seq":1,"time":40,"guard":1,"before":2,"after":3,"operation":42,"requester_kind":1,"requester":6,"outcome":4,"refusal":9}],"delivered":2,"overwritten":0}},"#,
    r#"{"dir":"/run/karyos/b","state":{"state":"unavailable","reason":"no socket"},"instance":null,"sample":null,"client_counters":[],"#,
    r#""errors":{"records":[],"delivered":0,"overwritten":0},"losses":{"records":[],"delivered":0,"overwritten":0},"guards":{"records":[],"delivered":0,"overwritten":0}},"#,
    r#"{"dir":"/run/karyos/c","state":{"state":"closed"},"instance":null,"sample":null,"client_counters":[],"#,
    r#""errors":{"records":[],"delivered":0,"overwritten":0},"losses":{"records":[],"delivered":0,"overwritten":0},"guards":{"records":[],"delivered":0,"overwritten":0}}"#,
    r#"]}"#,
);

#[test]
fn api_v1_encodes_field_for_field() {
    assert_eq!(view(&every_field()), V1);
}

#[test]
fn an_error_lists_the_supported_versions() {
    assert_eq!(
        error("unsupported version", Some(&[1])),
        r#"{"error":"unsupported version","supported":[1]}"#
    );
    assert_eq!(
        error("not authorized", None),
        r#"{"error":"not authorized"}"#
    );
}
