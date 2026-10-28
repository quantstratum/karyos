// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::path::PathBuf;

use super::*;
use crate::api::{API_VERSION, GapView, JournalView, LaneLatency, QuantileBounds, TraceCounts};

/// One view with every type and every `DriverState` variant, `None` and
/// `Some` alike.
fn every_field() -> AgentView {
    let counter = Counter {
        cell_registration: 0,
        read_ns: 0,
        changed_ns: None,
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
                sampled_ns: Some(900),
                stream: 3,
                lane: 1,
                limit: Some(4096),
                head: Some(1024),
                floor: None,
                headroom: Some(3072),
                subscribers: vec![Subscriber {
                    cell_registration: 41,
                    changed_ns: Some(800),
                    registration: 5,
                    label: "subscriber position generation 0 cell 1".to_owned(),
                    position: 2048,
                    lag: Some(-1024),
                }],
            }],
        }),
        // The client counter pins the `Some` encodings.
        client_counters: vec![Counter {
            cell_registration: 77,
            read_ns: 1000,
            changed_ns: Some(990),
            ..counter
        }],
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
                requester_kind: 2,
                requester: 6,
                outcome: 4,
                refusal: 9,
                operator: 1000,
                parameters: 77,
            }],
            delivered: 2,
            overwritten: 0,
        },
        latencies: vec![LaneLatency {
            stream: 3,
            incarnation: 1,
            lane: 1,
            available: 10,
            unavailable: 2,
            incomplete: false,
            p50: Some(QuantileBounds {
                low: Some(480),
                high: Some(520),
            }),
            p90: Some(QuantileBounds {
                low: Some(900),
                high: None,
            }),
            p99: None,
            p999: None,
            max: Some(QuantileBounds {
                low: Some(-5),
                high: Some(1000),
            }),
        }],
        trace: TraceCounts {
            records: 1,
            malformed: 2,
            unknown_journal: 3,
            network_ignored: 4,
            points_ignored: 5,
            duplicates: 6,
            journals_dropped: 7,
            pending_dropped: 8,
            polls_dropped: 9,
            lanes_dropped: 10,
            aged_out: 11,
            mirror_overwritten: 12,
            pending: 13,
            buckets_evicted: 14,
            buckets_over_budget: 15,
        },
        alerts: vec![
            Alert {
                kind: AlertKind::Lag,
                stream: 3,
                lane: 1,
                participant: 5,
                value: 1024,
                since: 50,
            },
            Alert {
                kind: AlertKind::Loss,
                stream: 0,
                lane: 0,
                participant: 0,
                value: 15,
                since: 60,
            },
            Alert {
                kind: AlertKind::GuardAck,
                stream: 0,
                lane: 0,
                participant: 2,
                value: 1,
                since: 70,
            },
        ],
        catalog: Some(Catalog {
            recordings: vec![
                CatalogRecording {
                    recording_id: 1,
                    stream_id: 42,
                    session_id: -7,
                    channel: "karyos:ipc".to_owned(),
                    start: 0,
                    start_time_ns: 5,
                    recording: true,
                    position: 4096,
                    stopped_ns: None,
                    stop_reason: None,
                    incomplete: false,
                },
                CatalogRecording {
                    recording_id: 2,
                    stream_id: 42,
                    session_id: 1,
                    channel: "karyos:udp?endpoint=\"x\"".to_owned(),
                    start: 64,
                    start_time_ns: 6,
                    recording: false,
                    position: 8192,
                    stopped_ns: Some(9),
                    stop_reason: Some("failed_required_lapped".to_owned()),
                    incomplete: true,
                },
            ],
            left_out: 3,
            listed_at: Some(80),
            listings: 4,
            failures: 1,
            last_error: Some("connect: timed out".to_owned()),
        }),
        attachment: crate::api::Attachment {
            since_ns: Some(50),
            attaches: 2,
            previous: Some(crate::api::AttachEnd::new(
                0xabc,
                40,
                crate::api::AttachEndReason::Detached,
            )),
        },
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
        alerts: Vec::new(),
        catalog: None,
        attachment: crate::api::Attachment::default(),
    };
    let closed = DriverView {
        dir: PathBuf::from("/run/karyos/c"),
        state: DriverState::Closed,
        // Configured, nothing listed yet.
        catalog: Some(Catalog::default()),
        attachment: crate::api::Attachment {
            since_ns: None,
            attaches: 1,
            previous: Some(crate::api::AttachEnd::new(
                0xabc,
                60,
                crate::api::AttachEndReason::DriverGone,
            )),
        },
        ..unavailable.clone()
    };
    AgentView {
        version: API_VERSION,
        drivers: vec![attached, unavailable, closed],
        journal: Some(JournalView {
            recording: Some(4),
            unsealed: true,
            unavailable: false,
            error: None,
            failed_appends: 2,
            gap: Some(GapView {
                position: 96,
                from: 10,
                to: 70,
                reason: "unclean_stop",
            }),
            alerts: vec![Alert {
                kind: AlertKind::JournalGap,
                stream: 0,
                lane: 0,
                participant: 96,
                value: 60,
                since: 70,
            }],
        }),
        agent: crate::api::AgentIdentity::new(Some("ns/pod-0".to_owned()), 4242, 99),
    }
}

/// A journal that could not be opened, written beside the full one.
#[test]
fn a_journal_that_could_not_open_is_written_with_its_error() {
    let agent = AgentView {
        version: API_VERSION,
        drivers: Vec::new(),
        journal: Some(JournalView {
            recording: None,
            unsealed: true,
            unavailable: true,
            error: Some("no such directory".to_owned()),
            failed_appends: 0,
            gap: None,
            alerts: Vec::new(),
        }),
        agent: crate::api::AgentIdentity::new(None, 7, 1),
    };
    assert_eq!(
        view(&agent),
        concat!(
            r#"{"version":1,"drivers":[],"journal":{"recording":null,"unsealed":true,"#,
            r#""unavailable":true,"error":"no such directory","failed_appends":0,"#,
            r#""gap":null,"alerts":[]},"agent":{"id":null,"pid":7,"started_ns":1}}"#
        )
    );
}

/// API v1's JSON, field for field. This is the compatibility contract
/// (ADR-0055 Validation): a field renamed, removed, retyped or moved fails
/// here, and needs API v2. A field added to v1 is appended to this text:
/// `latencies` and `trace` (M6c) were, in M8, and `alerts` (M9), each
/// at the end of its driver, in `DriverView`'s declaration order; a guard
/// record's `operator` and `parameters` (M10) at the end of the record;
/// `catalog` (M11) at the end of each driver; `journal` (M10b) at the
/// end of the view.
const V1: &str = concat!(
    r#"{"version":1,"drivers":["#,
    r#"{"dir":"/run/karyos/a","state":{"state":"attached"},"#,
    r#""instance":"0123456789abcdef0011223344556677","#,
    r#""sample":{"consistent":true,"sampled":true,"age_ns":1500,"#,
    r#""counters":[{"label":"streams active","type_id":2,"stream":0,"lane":0,"kind":0,"participant":0,"cell_registration":0,"value":18446744073709551615,"read_ns":0,"changed_ns":null}],"#,
    r#""lanes":[{"stream":3,"lane":1,"limit":4096,"head":1024,"floor":null,"headroom":3072,"#,
    r#""subscribers":[{"registration":5,"cell_registration":41,"label":"subscriber position generation 0 cell 1","position":2048,"lag":-1024,"changed_ns":800}],"sampled_ns":900}]},"#,
    r#""client_counters":[{"label":"streams active","type_id":2,"stream":0,"lane":0,"kind":0,"participant":0,"cell_registration":77,"value":18446744073709551615,"read_ns":1000,"changed_ns":990}],"#,
    r#""errors":{"records":[{"seq":0,"first":10,"last":20,"occurrences":3,"code":4,"source":1,"key":[2,1],"message":"stream \"2\" rejected\n\ttwice\u0001"}],"delivered":1,"overwritten":0},"#,
    r#""losses":{"records":[{"seq":7,"time":30,"kind":1,"reason":2,"lane":0,"stream_id":9,"stream_registration":3,"from":100,"to":200,"participant":5,"client":6}],"delivered":8,"overwritten":7},"#,
    r#""guards":{"records":[{"seq":1,"time":40,"guard":1,"before":2,"after":3,"operation":42,"requester_kind":2,"requester":6,"outcome":4,"refusal":9,"operator":1000,"parameters":77}],"delivered":2,"overwritten":0}"#,
    r#","latencies":[{"stream":3,"incarnation":1,"lane":1,"available":10,"unavailable":2,"incomplete":false,"p50":{"low":480,"high":520},"p90":{"low":900,"high":null},"p99":null,"p999":null,"max":{"low":-5,"high":1000}}],"#,
    r#""trace":{"records":1,"malformed":2,"unknown_journal":3,"network_ignored":4,"points_ignored":5,"duplicates":6,"journals_dropped":7,"pending_dropped":8,"polls_dropped":9,"lanes_dropped":10,"aged_out":11,"mirror_overwritten":12,"pending":13,"buckets_evicted":14,"buckets_over_budget":15},"#,
    r#""alerts":[{"kind":"lag","stream":3,"lane":1,"participant":5,"value":1024,"since":50},{"kind":"loss","stream":0,"lane":0,"participant":0,"value":15,"since":60},{"kind":"guard_ack","stream":0,"lane":0,"participant":2,"value":1,"since":70}],"#,
    r#""catalog":{"recordings":[{"recording_id":1,"stream_id":42,"session_id":-7,"channel":"karyos:ipc","start":0,"start_time_ns":5,"recording":true,"position":4096,"stopped_ns":null,"stop_reason":null,"incomplete":false},"#,
    r#"{"recording_id":2,"stream_id":42,"session_id":1,"channel":"karyos:udp?endpoint=\"x\"","start":64,"start_time_ns":6,"recording":false,"position":8192,"stopped_ns":9,"stop_reason":"failed_required_lapped","incomplete":true}],"#,
    r#""left_out":3,"listed_at":80,"listings":4,"failures":1,"last_error":"connect: timed out"},"#,
    r#""attachment":{"since_ns":50,"attaches":2,"previous":{"instance":"00000000000000000000000000000abc","ended_ns":40,"reason":"detached"}}},"#,
    r#"{"dir":"/run/karyos/b","state":{"state":"unavailable","reason":"no socket"},"instance":null,"sample":null,"client_counters":[],"#,
    r#""errors":{"records":[],"delivered":0,"overwritten":0},"losses":{"records":[],"delivered":0,"overwritten":0},"guards":{"records":[],"delivered":0,"overwritten":0},"#,
    r#""latencies":[],"trace":{"records":0,"malformed":0,"unknown_journal":0,"network_ignored":0,"points_ignored":0,"duplicates":0,"journals_dropped":0,"pending_dropped":0,"polls_dropped":0,"lanes_dropped":0,"aged_out":0,"mirror_overwritten":0,"pending":0,"buckets_evicted":0,"buckets_over_budget":0},"alerts":[],"catalog":null,"#,
    r#""attachment":{"since_ns":null,"attaches":0,"previous":null}},"#,
    r#"{"dir":"/run/karyos/c","state":{"state":"closed"},"instance":null,"sample":null,"client_counters":[],"#,
    r#""errors":{"records":[],"delivered":0,"overwritten":0},"losses":{"records":[],"delivered":0,"overwritten":0},"guards":{"records":[],"delivered":0,"overwritten":0},"#,
    r#""latencies":[],"trace":{"records":0,"malformed":0,"unknown_journal":0,"network_ignored":0,"points_ignored":0,"duplicates":0,"journals_dropped":0,"pending_dropped":0,"polls_dropped":0,"lanes_dropped":0,"aged_out":0,"mirror_overwritten":0,"pending":0,"buckets_evicted":0,"buckets_over_budget":0},"alerts":[],"#,
    r#""catalog":{"recordings":[],"left_out":0,"listed_at":null,"listings":0,"failures":0,"last_error":null},"#,
    r#""attachment":{"since_ns":null,"attaches":1,"previous":{"instance":"00000000000000000000000000000abc","ended_ns":60,"reason":"driver_gone"}}}"#,
    r#"],"journal":{"recording":4,"unsealed":true,"unavailable":false,"error":null,"failed_appends":2,"#,
    r#""gap":{"position":96,"from":10,"to":70,"reason":"unclean_stop"},"#,
    r#""alerts":[{"kind":"journal_gap","stream":0,"lane":0,"participant":96,"value":60,"since":70}]},"#,
    r#""agent":{"id":"ns/pod-0","pid":4242,"started_ns":99}}"#,
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

/// R-CORE-24: v1's capability names are a closed, documented list, and
/// each answer entry is a self-describing object, so a later agent may
/// add a name and a v1 client that keeps only the names it knows reads the
/// rest unchanged.
#[test]
fn capability_names_are_closed_in_v1_and_extensible() {
    use crate::api::{CAPABILITIES, Capability, CapabilityState};

    assert_eq!(
        CAPABILITIES,
        [
            "view",
            "guard-close",
            "guard-reopen",
            "gap-ack",
            "catalog",
            "trace-window",
            "limits",
            "trace-buckets"
        ]
    );
    let known = Capability {
        name: "view",
        state: CapabilityState::Served,
    };
    let future = Capability {
        name: "a-later-capability",
        state: CapabilityState::Unavailable {
            reason: "not_configured",
        },
    };
    let alone = capabilities(&[known]);
    let with_future = capabilities(&[known, future]);
    // The known entry is written the same, whatever follows it.
    let entry = r#"{"name":"view","state":"served","reason":null}"#;
    assert!(alone.contains(entry) && with_future.contains(entry));
    assert_eq!(
        with_future,
        concat!(
            r#"{"capabilities":[{"name":"view","state":"served","reason":null},"#,
            r#"{"name":"a-later-capability","state":"unavailable","reason":"not_configured"}]}"#
        )
    );
}

/// A bucket of `lanes` lanes, each with a histogram spread over `spread`
/// values.
fn spread_bucket(number: u64, lanes: u8, spread: i64) -> crate::api::TraceBucket {
    let mut histogram = karyos_trace::Histogram::new(3, 10_000_000_000, 1).unwrap();
    for value in 0..spread {
        let value = value * 9_973;
        histogram
            .record(karyos_trace::Latency::Available {
                min: value,
                max: value + 5,
            })
            .unwrap();
    }
    crate::api::TraceBucket {
        number,
        start_ns: number * 10,
        end_ns: number * 10 + 10,
        lanes: (0..lanes)
            .map(|lane| crate::api::BucketLane {
                stream: 5,
                incarnation: 1,
                lane,
                counts: histogram.counts(),
            })
            .collect(),
        loss: crate::api::Loss::default(),
        incomplete: false,
    }
}

/// R-CORE-23 (E2): a `trace-buckets` reply stays within its byte bound,
/// with full lanes and spread histograms. It stops before the first
/// bucket that would pass it, never cutting one, and names it in `next`;
/// the first bucket is always whole, so a reader always progresses.
#[test]
fn a_bucket_reply_stops_at_a_whole_bucket_within_its_bound() {
    let read = crate::api::BucketRead {
        epoch: 7,
        slice_ns: 10,
        current: 3,
        oldest: 0,
        buckets: (0..3)
            .map(|number| spread_bucket(number, 4, 2_000))
            .collect(),
    };
    let whole = trace_buckets(&read, usize::MAX);
    assert!(
        whole.ends_with(r#""next":null}"#),
        "{}",
        &whole[whole.len() - 40..]
    );
    let one = whole.len() / 3;
    for bound in [one + one / 2, 2 * one + one / 2] {
        let cut = trace_buckets(&read, bound);
        assert!(cut.len() <= bound + 300, "{} over {bound}", cut.len());
        let kept = cut.matches(r#""number":"#).count();
        let next = if kept == 1 {
            r#""next":1}"#
        } else {
            r#""next":2}"#
        };
        assert!(cut.ends_with(next), "{}", &cut[cut.len() - 40..]);
    }
    // Even a bound below one bucket returns that bucket, whole.
    let tiny = trace_buckets(&read, 10);
    assert_eq!(tiny.matches(r#""number":"#).count(), 1);
    assert!(tiny.ends_with(r#""next":1}"#));
    assert!(
        tiny.starts_with(
            r#"{"epoch":7,"slice_ns":10,"current":3,"oldest":0,"buckets":[{"number":0,"#
        )
    );
}

/// R-CORE-23: each refusal is typed, with what the reader needs to resume.
#[test]
fn bucket_refusals_are_typed() {
    use crate::api::BucketRefusal;

    assert_eq!(
        bucket_refusal(&BucketRefusal::EpochChanged {
            epoch: 9,
            oldest: 4
        }),
        r#"{"error":"epoch changed","epoch":9,"oldest":4}"#
    );
    assert_eq!(
        bucket_refusal(&BucketRefusal::Expired { oldest: 4 }),
        r#"{"error":"buckets expired","oldest":4}"#
    );
    assert_eq!(
        bucket_refusal(&BucketRefusal::OverBudget { number: 3 }),
        r#"{"error":"bucket over budget","number":3}"#
    );
}

/// R-CORE-23: a bucket larger than the reply bound on its own comes back
/// whole and alone, with `next` naming the one after it: the reply is at
/// most `max(MAX_BUCKET_REPLY, one bucket)`.
#[test]
fn a_bucket_over_the_reply_bound_comes_back_whole_and_alone() {
    let read = crate::api::BucketRead {
        epoch: 7,
        slice_ns: 10,
        current: 2,
        oldest: 0,
        buckets: (0..2)
            .map(|number| spread_bucket(number, 16, 20_000))
            .collect(),
    };
    let alone = {
        let mut text = String::new();
        trace_bucket(&mut Out(&mut text), &read.buckets[0]);
        text
    };
    assert!(
        alone.len() > crate::api::MAX_BUCKET_REPLY,
        "{}",
        alone.len()
    );
    let reply = trace_buckets(&read, crate::api::MAX_BUCKET_REPLY);
    assert_eq!(reply.matches(r#""number":"#).count(), 1);
    assert!(reply.contains(&alone), "the bucket is whole");
    assert!(reply.ends_with(r#""next":1}"#));
    assert!(reply.len() <= alone.len() + 256);
}
