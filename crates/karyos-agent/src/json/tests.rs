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
            retention: Some(crate::api::RetentionView {
                recordings: vec![crate::api::RecordingRetention {
                    recording_id: 1,
                    hold: "held",
                    hold_since_ns: None,
                    close_time_ns: Some(4096),
                    earliest_expiry_ns: Some(8192),
                    policy: Some((1, 2)),
                }],
                min_free_bytes: 1024,
                free_bytes: None,
                read_at: Some(81),
                last_error: None,
            }),
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
        rates: vec![crate::api::RateView::new(
            std::path::PathBuf::from("/run/a"),
            7,
            -2,
            3,
            11,
        )],
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
        rates: Vec::new(),
    };
    assert_eq!(
        view(&agent),
        concat!(
            r#"{"version":1,"drivers":[],"journal":{"recording":null,"unsealed":true,"#,
            r#""unavailable":true,"error":"no such directory","failed_appends":0,"#,
            r#""gap":null,"alerts":[]},"agent":{"id":null,"pid":7,"started_ns":1},"rates":[]}"#
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
    r#""left_out":3,"listed_at":80,"listings":4,"failures":1,"last_error":"connect: timed out","#,
    r#""retention":{"recordings":[{"recording_id":1,"hold":"held","hold_since_ns":null,"close_time_ns":4096,"earliest_expiry_ns":8192,"policy":{"id":1,"version":2}}],"#,
    r#""min_free_bytes":1024,"free_bytes":null,"read_at":81,"last_error":null}},"#,
    r#""attachment":{"since_ns":50,"attaches":2,"previous":{"instance":"00000000000000000000000000000abc","ended_ns":40,"reason":"detached"}}},"#,
    r#"{"dir":"/run/karyos/b","state":{"state":"unavailable","reason":"no socket"},"instance":null,"sample":null,"client_counters":[],"#,
    r#""errors":{"records":[],"delivered":0,"overwritten":0},"losses":{"records":[],"delivered":0,"overwritten":0},"guards":{"records":[],"delivered":0,"overwritten":0},"#,
    r#""latencies":[],"trace":{"records":0,"malformed":0,"unknown_journal":0,"network_ignored":0,"points_ignored":0,"duplicates":0,"journals_dropped":0,"pending_dropped":0,"polls_dropped":0,"lanes_dropped":0,"aged_out":0,"mirror_overwritten":0,"pending":0,"buckets_evicted":0,"buckets_over_budget":0},"alerts":[],"catalog":null,"#,
    r#""attachment":{"since_ns":null,"attaches":0,"previous":null}},"#,
    r#"{"dir":"/run/karyos/c","state":{"state":"closed"},"instance":null,"sample":null,"client_counters":[],"#,
    r#""errors":{"records":[],"delivered":0,"overwritten":0},"losses":{"records":[],"delivered":0,"overwritten":0},"guards":{"records":[],"delivered":0,"overwritten":0},"#,
    r#""latencies":[],"trace":{"records":0,"malformed":0,"unknown_journal":0,"network_ignored":0,"points_ignored":0,"duplicates":0,"journals_dropped":0,"pending_dropped":0,"polls_dropped":0,"lanes_dropped":0,"aged_out":0,"mirror_overwritten":0,"pending":0,"buckets_evicted":0,"buckets_over_budget":0},"alerts":[],"#,
    r#""catalog":{"recordings":[],"left_out":0,"listed_at":null,"listings":0,"failures":0,"last_error":null,"retention":null},"#,
    r#""attachment":{"since_ns":null,"attaches":1,"previous":{"instance":"00000000000000000000000000000abc","ended_ns":60,"reason":"driver_gone"}}}"#,
    r#"],"journal":{"recording":4,"unsealed":true,"unavailable":false,"error":null,"failed_appends":2,"#,
    r#""gap":{"position":96,"from":10,"to":70,"reason":"unclean_stop"},"#,
    r#""alerts":[{"kind":"journal_gap","stream":0,"lane":0,"participant":96,"value":60,"since":70}]},"#,
    r#""agent":{"id":"ns/pod-0","pid":4242,"started_ns":99},"#,
    r#""rates":[{"dir":"/run/a","stream_id":7,"session_id":-2,"version":3,"operation":11}]}"#,
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
            "trace-buckets",
            "trace-export",
            "join-registry",
            "join-put",
            "rate-change",
            "guard-preview",
            "submit",
            "clocks",
            "rate-limits",
            "cluster-command"
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
        lanes_total: usize::from(lanes),
        first_lane: 0,
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
        loss: Some(crate::api::Loss::default()),
        incomplete: false,
    }
}

/// R-CORE-23: a reply names where the next read starts, a bucket and a
/// lane, or `null`; each bucket states its lanes in all and the first one
/// it holds, and the lengths a read bounds it by are its encoding's.
#[test]
fn a_bucket_reply_names_its_next_bucket_and_lane() {
    let mut bucket = spread_bucket(4, 3, 50);
    bucket.first_lane = 1;
    bucket.lanes.remove(0);
    let header = bucket_header_len(&bucket);
    let lanes: usize = bucket.lanes.iter().map(bucket_lane_len).sum();
    let mut read = crate::api::BucketRead {
        epoch: 7,
        slice_ns: 10,
        current: 9,
        oldest: 0,
        buckets: vec![bucket],
        next: Some(crate::api::BucketCursor::new(4, 3)),
    };
    let text = trace_buckets(&read);
    assert!(
        text.starts_with(
            r#"{"epoch":7,"slice_ns":10,"current":9,"oldest":0,"buckets":[{"number":4,"#
        ),
        "{text}"
    );
    assert!(text.contains(r#""lanes_total":3,"first_lane":1,"lanes":[{"#));
    assert!(text.ends_with(r#""next":{"number":4,"lane":3}}"#), "{text}");
    // The bucket's encoding is its header and its lanes, as counted.
    assert!(text.len() <= BUCKET_REPLY_OVERHEAD + header + lanes);
    assert!(text.len() + 2 >= header + lanes);
    read.next = None;
    assert!(trace_buckets(&read).ends_with(r#""next":null}"#));
}

/// R-CORE-23: the largest lane, every count array full of the largest
/// indices and counts, encodes within `MAX_LANE_REPLY`, and the arrays'
/// length is the layout's.
#[test]
fn the_largest_lane_encodes_within_its_bound() {
    use crate::api::{LANE_BUCKETS, MAX_LANE_REPLY};
    use karyos_trace::{Histogram, HistogramCounts, HistogramError, SideCounts};

    let full = |count: u64| SideCounts {
        non_negative: (0..u32::try_from(LANE_BUCKETS).unwrap())
            .map(|index| (index, count))
            .collect(),
        negative: (0..u32::try_from(LANE_BUCKETS).unwrap())
            .map(|index| (index, count))
            .collect(),
        above: count,
        below: count,
    };
    let counts = |count: u64, available: u64| HistogramCounts {
        digits: 3,
        highest: 10_000_000_000,
        unit: 1,
        min: full(count),
        max: full(count),
        available,
        unavailable: [u64::MAX; 4],
        incomplete: true,
    };
    let lane = crate::api::BucketLane {
        stream: u64::MAX,
        incarnation: u64::MAX,
        lane: u8::MAX,
        counts: counts(u64::MAX, u64::MAX),
    };
    let size = bucket_lane_len(&lane);
    assert!(size <= MAX_LANE_REPLY, "{size} > {MAX_LANE_REPLY}");
    // LANE_BUCKETS is the layout's: one more index is out of it.
    let like = Histogram::new(3, 10_000_000_000, 1).unwrap();
    let total = 2 * u64::try_from(LANE_BUCKETS).unwrap() + 2;
    assert!(Histogram::from_counts(&counts(1, total), &like).is_ok());
    let mut over = counts(1, total + 1);
    over.min
        .non_negative
        .push((u32::try_from(LANE_BUCKETS).unwrap(), 1));
    over.max
        .non_negative
        .push((u32::try_from(LANE_BUCKETS).unwrap(), 1));
    assert_eq!(
        Histogram::from_counts(&over, &like).err(),
        Some(HistogramError::InvalidCounts)
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

fn export_page(records: u64) -> crate::api::ExportPage {
    use crate::api::{ExportJournal, ExportLoss, ExportPage, ExportRecord};

    ExportPage {
        epoch: 0xab,
        from: 2,
        lost: vec![ExportLoss {
            first: 2,
            last: 4,
            reason: crate::api::LossReason::Overwritten,
        }],
        records: (5..5 + records)
            .map(|seq| ExportRecord {
                seq,
                journal: 10,
                sequence: seq,
                payload: vec![seq; 26],
            })
            .collect(),
        next: 5 + records,
        head: 5 + records,
        journals: vec![ExportJournal::Unknown { journal: 10 }],
        points: Vec::new(),
        unknown_records: 3,
        unreadable_records: 0,
        network_journals_refused: crate::api::RefusedReads::default(),
    }
}

/// R-CORE-13: a page states its loss first, then whole records, `next`,
/// the head, the journals and the unknown count, encoded whole: the read
/// bounded it, the encoder cuts nothing. A record's length is computed
/// without encoding it, exactly.
#[test]
fn an_export_page_is_encoded_whole() {
    let page = export_page(3);
    let whole = trace_export(&page);
    assert!(
        whole.starts_with(
            r#"{"epoch":"000000000000000000000000000000ab","from":2,"lost":[{"first":2,"last":4,"reason":"overwritten"}],"records":[{"seq":5,"journal":10,"sequence":5,"payload":[5,"#
        ),
        "{whole}"
    );
    assert!(
        whole.ends_with(r#""next":8,"head":8,"journals":[{"journal":10,"table":"unknown"}],"points":[],"unknown_records":3,"unreadable_records":0,"network_journals_refused":{"attach":null,"before":0,"after":0}}"#),
        "{whole}"
    );
    assert_eq!(whole.matches(r#"{"seq":"#).count(), 3);
    for record in [
        crate::api::ExportRecord {
            seq: 0,
            journal: 9,
            sequence: 10,
            payload: Vec::new(),
        },
        crate::api::ExportRecord {
            seq: u64::MAX,
            journal: 1,
            sequence: 999,
            payload: vec![0, 9, 10, 99, 100, u64::MAX],
        },
    ] {
        let mut text = String::new();
        export_record(&mut Out(&mut text), &record);
        assert_eq!(export_record_len(&record), text.len() + 1, "{text}");
    }
}

/// R-CORE-13: a cursor of another driver instance is refused, typed, with
/// this instance.
#[test]
fn export_refusals_are_typed() {
    assert_eq!(
        export_refusal(&crate::api::ExportRefusal::EpochChanged { epoch: 0xab }),
        r#"{"error":"epoch changed","epoch":"000000000000000000000000000000ab"}"#
    );
}

/// R-CORE-13 (ACS 33179, condition 4): the largest record and the largest
/// journal encode within their stated bounds, so a reply is at most
/// `MAX_EXPORT_REPLY` plus one of each.
#[test]
fn the_largest_record_and_journal_encode_within_their_bounds() {
    use crate::api::{ExportJournal, ExportRecord, MAX_JOURNAL_REPLY, MAX_RECORD_REPLY};
    use karyos_sys::record_journal::DropRange;
    use karyos_sys::trace_mirror::{
        JournalEntry, JournalKind, JournalState, MAX_MIRROR_PAYLOAD, MIRROR_RANGES, TimeNamespace,
    };

    let record = ExportRecord {
        seq: u64::MAX,
        journal: u64::MAX,
        sequence: u64::MAX,
        payload: vec![u64::MAX; MAX_MIRROR_PAYLOAD],
    };
    let mut text = String::new();
    export_record(&mut Out(&mut text), &record);
    assert!(
        text.len() <= MAX_RECORD_REPLY,
        "{} > {MAX_RECORD_REPLY}",
        text.len()
    );
    // A network receiver journal, which carries the most: its join and
    // every NT-4 fact (karyos#931).
    let mut entry = JournalEntry::open(
        u64::MAX,
        u64::MAX,
        JournalKind::NetworkReceiver,
        u64::MAX,
        u64::MAX,
    );
    entry.join = Some(u64::MAX);
    entry.network = Some(karyos_sys::trace_mirror::NetworkFacts {
        sender_driver: [u64::MAX; 2],
        start: Some(u64::MAX),
        boundary: Some(u64::MAX),
        first_gap: Some(u64::MAX),
    });
    entry.state = JournalState::WriterLost;
    entry.registration = u64::MAX;
    entry.stream = u64::MAX;
    entry.incarnation = u64::MAX;
    entry.time_namespace = TimeNamespace::Different;
    entry.provenance = u64::MAX;
    entry.sequence = u64::MAX;
    entry.attempted = u64::MAX;
    entry.stored = u64::MAX;
    entry.mirrored = u64::MAX;
    entry.lost_before = Some(u64::MAX);
    entry.unstable = u64::MAX;
    entry.ranges = [DropRange {
        first: u64::MAX,
        last: u64::MAX,
        first_time: u64::MAX,
        last_time: u64::MAX,
        clock: u64::MAX,
        epoch: u64::MAX,
    }; MIRROR_RANGES];
    entry.range_count = MIRROR_RANGES;
    let mut text = String::new();
    export_journal(&mut Out(&mut text), &ExportJournal::Live(Box::new(entry)));
    assert!(
        text.len() <= MAX_JOURNAL_REPLY,
        "{} > {MAX_JOURNAL_REPLY}",
        text.len()
    );
    // A page of many such records stays within the bound plus one of each.
    let page = crate::api::ExportPage {
        epoch: u128::MAX,
        from: 0,
        lost: Vec::new(),
        records: vec![record; 4000],
        next: 4000,
        head: 4000,
        journals: vec![ExportJournal::Live(Box::new(entry))],
        points: Vec::new(),
        unknown_records: 0,
        unreadable_records: 0,
        network_journals_refused: crate::api::RefusedReads {
            attach: Some(u64::MAX),
            before: u64::MAX,
            after: u64::MAX,
        },
    };
    // One record and one journal, the most a reply holds past the bound.
    let one = crate::api::ExportPage {
        records: page.records[..1].to_vec(),
        ..page
    };
    let reply = trace_export(&one);
    assert!(
        reply.len() <= crate::json::EXPORT_REPLY_OVERHEAD + MAX_RECORD_REPLY + MAX_JOURNAL_REPLY
    );
}

/// karyos#931: a live network journal carries its NT-4 facts, each `null`
/// when its validity flag is clear, never 0; another kind carries none;
/// `join` is `null` when the driver recorded none.
#[test]
fn a_network_journal_exports_its_facts_with_unknown_as_null() {
    use crate::api::ExportJournal;
    use karyos_sys::trace_mirror::{JournalEntry, JournalKind, NetworkFacts};

    let mut receiver = JournalEntry::open(7, 0, JournalKind::NetworkReceiver, 3, 1);
    receiver.join = Some(4096);
    receiver.network = Some(NetworkFacts {
        sender_driver: [11, 12],
        start: None,
        boundary: Some(12_345),
        first_gap: None,
    });
    let mut text = String::new();
    export_journal(
        &mut Out(&mut text),
        &ExportJournal::Live(Box::new(receiver)),
    );
    assert!(text.contains(r#""join":4096,"#), "{text}");
    assert!(
        text.contains(
            r#""network":{"sender_driver":[11,12],"start":null,"boundary":12345,"first_gap":null}"#
        ),
        "{text}"
    );
    let unfilled = JournalEntry::open(8, 0, JournalKind::NetworkSender, 3, 1);
    let mut text = String::new();
    export_journal(
        &mut Out(&mut text),
        &ExportJournal::Live(Box::new(unfilled)),
    );
    assert!(text.contains(r#""network":null"#), "{text}");
    let publisher = JournalEntry::open(9, 5, JournalKind::Publisher, 3, 1);
    let mut text = String::new();
    export_journal(
        &mut Out(&mut text),
        &ExportJournal::Live(Box::new(publisher)),
    );
    assert!(!text.contains("network"), "{text}");
    assert!(text.contains(r#""join":null"#), "{text}");
}

/// karyos#931: a page states the mirror's `network_journals_refused` at
/// the agent's attach (`null` when not recorded) and before and after its
/// journal table read.
#[test]
fn an_export_page_states_the_refused_network_journals() {
    let mut page = export_page(0);
    page.network_journals_refused = crate::api::RefusedReads {
        attach: None,
        before: 2,
        after: 3,
    };
    assert!(
        trace_export(&page).ends_with(
            r#""unreadable_records":0,"network_journals_refused":{"attach":null,"before":2,"after":3}}"#
        ),
        "{}",
        trace_export(&page)
    );
    page.network_journals_refused.attach = Some(1);
    assert!(trace_export(&page).contains(r#"{"attach":1,"before":2,"after":3}"#));
}

/// R-CORE-40 (karyos#741): a clocks read, each clock with its epoch and
/// uncertainty and a calibration state that is never a number, and the
/// calibrations with their ranges; an empty list says why.
#[test]
fn a_clocks_read_writes_states_never_numbers() {
    use crate::api::{
        CalibrationState, CalibrationUnavailable, CalibrationView, ClockState, ClocksRead,
    };
    use karyos_trace::{Calibration, ClockKey, ObserverId};

    let clock = |journal| ClockKey {
        observer: ObserverId {
            driver: [1, 2],
            journal,
        },
        domain: 1,
        epoch: 3,
    };
    let state = |journal, calibration| ClockState {
        journal,
        provenance: "host_monotonic",
        same_namespace: true,
        domain: Some(1),
        epoch: Some(3),
        time: Some(1000),
        uncertainty: Some(2),
        calibration,
    };
    let read = ClocksRead {
        dir: "/run/a".into(),
        read_ns: 5,
        driver: 0x1_0000_0000_0000_0002,
        clocks: vec![
            state(
                10,
                CalibrationState::Unavailable {
                    reason: CalibrationUnavailable::NoCalibration,
                },
            ),
            state(11, CalibrationState::Valid { count: 1 }),
        ],
        calibrations: vec![CalibrationView {
            calibration: Calibration {
                from: clock(11),
                to: clock(10),
                reference: 900,
                offset: -5,
                offset_uncertainty: 1,
                drift: 2,
                drift_uncertainty: 3,
                valid_from: 900,
                valid_to: 2000,
            },
            state: "valid",
        }],
        calibrations_unavailable: None,
    };
    let driver = "00000000000000010000000000000002";
    assert_eq!(
        clocks(&read),
        [
            r#"{"dir":"/run/a","driver":""#,
            driver,
            r#"","read_ns":5,"clocks":["#,
            r#"{"journal":10,"provenance":"host_monotonic","same_namespace":true,"domain":1,"epoch":3,"time":1000,"uncertainty":2,"calibration":{"state":"unavailable","reason":"no_calibration"}},"#,
            r#"{"journal":11,"provenance":"host_monotonic","same_namespace":true,"domain":1,"epoch":3,"time":1000,"uncertainty":2,"calibration":{"state":"valid","count":1}}],"#,
            r#""calibrations":[{"from":{"driver":""#,
            driver,
            r#"","journal":11,"domain":1,"epoch":3},"to":{"driver":""#,
            driver,
            r#"","journal":10,"domain":1,"epoch":3},"reference":900,"offset":-5,"offset_uncertainty":1,"drift":2,"drift_uncertainty":3,"valid_from":900,"valid_to":2000,"state":"valid"}],"#,
            r#""calibrations_unavailable":null}"#,
        ]
        .concat()
    );
    let empty = ClocksRead {
        clocks: Vec::new(),
        calibrations: Vec::new(),
        calibrations_unavailable: Some("no_producer"),
        ..read
    };
    assert!(
        clocks(&empty).ends_with(
            r#""clocks":[],"calibrations":[],"calibrations_unavailable":"no_producer"}"#
        )
    );
}

/// R-CORE-40 (karyos#741): a rate limits read: the version in force and
/// each limiter limited with its policy and refusals, `none` or
/// `not_counted`, so a 0 is only a bucket that refused nothing.
#[test]
fn a_rate_limits_read_tells_zero_refusals_from_not_counted() {
    use crate::api::{Limiter, PublicationRates, RateLimitsRead};
    use karyos_sys::rate_limit::{Rate, RatePolicy};

    let read = RateLimitsRead {
        dir: "/run/a".into(),
        read_ns: Some(7),
        publications: vec![
            PublicationRates {
                registration: 5,
                publication: Limiter::Limited {
                    policy: RatePolicy {
                        messages: Rate {
                            per_second: 100,
                            burst: 10,
                        },
                        bytes: Some(Rate {
                            per_second: 6400,
                            burst: 640,
                        }),
                    },
                    refusals: 0,
                },
                control: Limiter::None,
                version: Some(3),
            },
            PublicationRates {
                registration: 7,
                publication: Limiter::Unknown,
                control: Limiter::Unknown,
                version: None,
            },
        ],
    };
    assert_eq!(
        rate_limits(&read),
        concat!(
            r#"{"dir":"/run/a","read_ns":7,"publications":["#,
            r#"{"registration":5,"version":3,"publication":{"state":"limited","policy":{"messages":{"per_second":100,"burst":10},"bytes":{"per_second":6400,"burst":640}},"refusals":0},"control":{"state":"none"}},"#,
            r#"{"registration":7,"version":null,"publication":{"state":"not_counted"},"control":{"state":"not_counted"}}]}"#
        )
    );
}
