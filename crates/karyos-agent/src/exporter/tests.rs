// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use super::*;
use crate::api::{
    API_VERSION, Alert, AlertKind, Feed, Lane, LaneLatency, Sample, Subscriber, TraceCounts,
};

fn counter(label: &str, type_id: u64, value: u64) -> Counter {
    Counter {
        label: label.to_owned(),
        type_id,
        stream: 0,
        lane: 0,
        kind: 0,
        participant: 0,
        value,
    }
}

fn view() -> AgentView {
    let attached = DriverView {
        dir: PathBuf::from("/run/karyos/\"a\"\\b"),
        state: DriverState::Attached,
        instance: Some(1),
        sample: Some(Sample {
            consistent: true,
            sampled: true,
            age_ns: Some(1500),
            counters: vec![
                counter("commands", TYPE_EVENT, 7),
                counter("streams active", TYPE_GAUGE, 2),
                counter("spin time", TYPE_SPIN_TIME, 900),
                counter("conductor duty at", TYPE_TIMESTAMP, 12),
                counter("odd\nlabel", 99, 1),
            ],
            lanes: vec![Lane {
                stream: 3,
                lane: 1,
                limit: Some(4096),
                head: Some(1024),
                floor: None,
                headroom: Some(3072),
                subscribers: vec![Subscriber {
                    registration: 5,
                    label: "subscriber position".to_owned(),
                    position: 2048,
                    lag: Some(-1024),
                }],
            }],
        }),
        client_counters: vec![
            counter("messages", TYPE_EVENT, 3),
            Counter {
                kind: karyos_sys::counters::KIND_CLIENT,
                participant: 11,
                ..counter("orders \"filled\"\nby desk", TYPE_APPLICATION_EVENT, 42)
            },
            Counter {
                kind: karyos_sys::counters::KIND_CLIENT,
                participant: 11,
                ..counter("queue\\depth", TYPE_APPLICATION_GAUGE, 7)
            },
        ],
        errors: Feed::default(),
        losses: Feed::default(),
        guards: Feed::default(),
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
            max: None,
        }],
        trace: TraceCounts::default(),
        alerts: vec![Alert {
            kind: AlertKind::Lag,
            stream: 3,
            lane: 1,
            participant: 5,
            value: 1024,
            since: 50,
        }],
        catalog: Some(Catalog {
            recordings: Vec::new(),
            left_out: 2,
            listed_at: Some(90),
            listings: 3,
            failures: 1,
            last_error: None,
        }),
        attachment: crate::api::Attachment::default(),
    };
    let closed = DriverView {
        dir: PathBuf::from("/run/karyos/c"),
        state: DriverState::Closed,
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
    AgentView {
        version: API_VERSION,
        drivers: vec![attached, closed],
        journal: None,
        agent: crate::api::AgentIdentity::new(None, 1, 1),
    }
}

/// One sample line: its family name, labels and value.
fn sample(line: &str) -> (String, Vec<(String, String)>, f64) {
    let (series, value) = line.rsplit_once(' ').unwrap();
    let value: f64 = value.parse().unwrap_or_else(|_| panic!("{line}: value"));
    let Some((name, labels)) = series.split_once('{') else {
        return (series.to_owned(), Vec::new(), value);
    };
    let labels = labels
        .strip_suffix('}')
        .unwrap_or_else(|| panic!("{line}: braces"));
    // key="value" pairs, values escaped.
    let mut out = Vec::new();
    let mut rest = labels;
    while !rest.is_empty() {
        let (key, after) = rest
            .split_once("=\"")
            .unwrap_or_else(|| panic!("{line}: label"));
        let mut value = String::new();
        let mut chars = after.char_indices();
        let end = loop {
            match chars.next() {
                Some((_, '\\')) => match chars.next() {
                    Some((_, '\\')) => value.push('\\'),
                    Some((_, '"')) => value.push('"'),
                    Some((_, 'n')) => value.push('\n'),
                    other => panic!("{line}: escape {other:?}"),
                },
                Some((at, '"')) => break at,
                Some((_, c)) => value.push(c),
                None => panic!("{line}: unterminated"),
            }
        };
        out.push((key.to_owned(), value));
        rest = after[end + 1..]
            .strip_prefix(',')
            .unwrap_or(&after[end + 1..]);
    }
    (name.to_owned(), out, value)
}

/// A parsed family: its type, and each sample's labels and value.
type Parsed = (String, Vec<(Vec<(String, String)>, f64)>);

/// Parses an exposition as Prometheus would read the text format: every
/// sample after its family's `TYPE`, each family in one block, and the
/// names valid; returns each family's type and its samples.
fn parse(text: &str) -> BTreeMap<String, Parsed> {
    let mut families: BTreeMap<String, Parsed> = BTreeMap::new();
    let mut current: Option<String> = None;
    let mut closed = BTreeSet::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("# HELP ") {
            let name = rest.split(' ').next().unwrap().to_owned();
            if let Some(previous) = current.replace(name.clone()) {
                closed.insert(previous);
            }
            assert!(!closed.contains(&name), "{name} in two blocks");
            continue;
        }
        if let Some(rest) = line.strip_prefix("# TYPE ") {
            let (name, kind) = rest.split_once(' ').unwrap();
            assert_eq!(Some(name), current.as_deref(), "TYPE without HELP");
            assert!(["counter", "gauge"].contains(&kind), "{kind}");
            let _ = families.insert(name.to_owned(), (kind.to_owned(), Vec::new()));
            continue;
        }
        let (name, labels, value) = sample(line);
        assert!(
            name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "{name}"
        );
        assert_eq!(Some(&name), current.as_ref(), "{line} outside its family");
        let family = families.get_mut(&name).unwrap();
        if family.0 == "counter" {
            assert!(name.ends_with("_total"), "{name}");
        }
        family.1.push((labels, value));
    }
    families
}

fn label<'a>(labels: &'a [(String, String)], key: &str) -> Option<&'a str> {
    labels
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.as_str())
}

#[test]
fn the_exposition_parses_and_each_counter_keeps_its_type() {
    let text = render(&view());
    let families = parse(&text);
    // An event cell is a counter, of the driver and of the client.
    let (kind, samples) = &families["karyos_events_total"];
    assert_eq!(kind, "counter");
    let sources: BTreeSet<&str> = samples
        .iter()
        .map(|(labels, _)| label(labels, "source").unwrap())
        .collect();
    assert_eq!(sources, BTreeSet::from(["client", "driver"]));
    for (family, kind) in [
        ("karyos_gauge", "gauge"),
        ("karyos_spin_time_ns_total", "counter"),
        ("karyos_timestamp_ns", "gauge"),
        ("karyos_value", "gauge"),
        ("karyos_subscriber_lag", "gauge"),
        ("karyos_trace_latency_ns", "gauge"),
        ("karyos_trace_events_total", "counter"),
    ] {
        assert_eq!(families[family].0, kind, "{family}");
    }
    // Label values come back as they were: quotes, backslashes, newlines.
    let gauge = &families["karyos_gauge"].1[0];
    assert_eq!(label(&gauge.0, "driver"), Some("/run/karyos/\"a\"\\b"));
    let odd = &families["karyos_value"].1[0];
    assert_eq!(label(&odd.0, "name"), Some("odd\nlabel"));
    // A negative lag, and only the bounded sides of a quantile.
    assert_eq!(families["karyos_subscriber_lag"].1[0].1, -1024.0);
    let p90: Vec<&str> = families["karyos_trace_latency_ns"]
        .1
        .iter()
        .filter(|(labels, _)| label(labels, "quantile") == Some("0.9"))
        .map(|(labels, _)| label(labels, "bound").unwrap())
        .collect();
    assert_eq!(p90, ["low"]);
    // Alerts (M9): a count per driver, 0 included, and each one's value.
    let firing: BTreeMap<&str, f64> = families["karyos_alerts_firing"]
        .1
        .iter()
        .map(|(labels, value)| (label(labels, "driver").unwrap(), *value))
        .collect();
    assert_eq!(
        firing.values().copied().collect::<Vec<_>>(),
        [1.0, 0.0],
        "{firing:?}"
    );
    let (labels, value) = &families["karyos_alert_value"].1[0];
    assert_eq!(
        (label(labels, "kind"), label(labels, "participant"), *value),
        (Some("lag"), Some("5"), 1024.0)
    );
    assert_eq!(families["karyos_alert_since_ns"].1[0].1, 50.0);
    // The catalog (M11): only for a driver configured with an Archive.
    for (family, kind, value) in [
        ("karyos_archive_recordings", "gauge", 2.0),
        ("karyos_archive_listings_total", "counter", 3.0),
        ("karyos_archive_listing_failures_total", "counter", 1.0),
        ("karyos_archive_listed_at_ns", "gauge", 90.0),
    ] {
        let (found, samples) = &families[family];
        assert_eq!(found, kind, "{family}");
        assert_eq!(samples.len(), 1, "{family}");
        assert_eq!(samples[0].1, value, "{family}");
    }
    // The closed driver: attached 0, closed 1.
    let closed = |family: &str| {
        families[family]
            .1
            .iter()
            .find(|(labels, _)| label(labels, "driver") == Some("/run/karyos/c"))
            .unwrap()
            .1
    };
    assert_eq!(
        (
            closed("karyos_driver_attached"),
            closed("karyos_driver_closed")
        ),
        (0.0, 1.0)
    );
}

/// R-CORE-3: an application counter has its own family, labelled with its
/// name as given, quotes, backslashes and newlines escaped, and its client;
/// it is not repeated among the client's CnC counters.
#[test]
fn application_counters_have_their_own_families_and_escaped_names() {
    let families = parse(&render(&view()));
    let (kind, events) = &families["karyos_application_events_total"];
    assert_eq!(kind, "counter");
    assert_eq!(events.len(), 1);
    let (labels, value) = &events[0];
    assert_eq!(label(labels, "name"), Some("orders \"filled\"\nby desk"));
    assert_eq!(label(labels, "client"), Some("11"));
    assert_eq!(*value, 42.0);
    let (kind, gauges) = &families["karyos_application_gauge"];
    assert_eq!(kind, "gauge");
    assert_eq!(label(&gauges[0].0, "name"), Some("queue\\depth"));
    assert_eq!(gauges[0].1, 7.0);
    let text = render(&view());
    assert!(
        text.contains(r#"name="orders \"filled\"\nby desk",client="11"} 42"#),
        "{text}"
    );
    for family in ["karyos_events_total", "karyos_gauge", "karyos_value"] {
        assert!(
            families[family]
                .1
                .iter()
                .all(|(labels, _)| label(labels, "participant") != Some("11")),
            "{family}"
        );
    }
}

#[test]
fn only_a_loopback_address_is_bound() {
    for address in ["0.0.0.0:0", "10.0.0.1:0", "[::]:0"] {
        assert!(matches!(
            bind(address.parse().unwrap()),
            Err(ExportError::NotLoopback(_))
        ));
    }
    assert!(bind("127.0.0.1:0".parse().unwrap()).is_ok());
}

/// Sends `request` and returns the whole answer.
fn exchange(exporter: &mut Exporter, request: &str) -> (String, Vec<Answered>) {
    let mut client = TcpStream::connect(exporter.local_addr().unwrap()).unwrap();
    client.write_all(request.as_bytes()).unwrap();
    let mut answered = Vec::new();
    for _ in 0..200 {
        answered = exporter.poll(|| "karyos_up 1\n".to_owned()).unwrap();
        if !answered.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut answer = String::new();
    let _ = client.read_to_string(&mut answer).unwrap();
    (answer, answered)
}

#[test]
fn get_metrics_is_answered_and_nothing_else() {
    let mut exporter = bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let (answer, answered) = exchange(&mut exporter, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(answered, [Answered::Metrics]);
    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
    assert!(answer.contains(CONTENT_TYPE));
    assert!(answer.ends_with("\r\n\r\nkaryos_up 1\n"), "{answer}");
    let (answer, answered) = exchange(&mut exporter, "GET / HTTP/1.1\r\n\r\n");
    assert_eq!(answered, [Answered::Refused]);
    assert!(answer.starts_with("HTTP/1.1 404"), "{answer}");
    let (answer, answered) = exchange(&mut exporter, "POST /metrics HTTP/1.1\r\n\r\n");
    assert_eq!(answered, [Answered::Refused]);
    assert!(answer.starts_with("HTTP/1.1 405"), "{answer}");
}

#[test]
fn a_poll_answers_a_bounded_number_of_connections() {
    let mut exporter = bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let address = exporter.local_addr().unwrap();
    let clients: Vec<TcpStream> = (0..MAX_PER_POLL + 4)
        .map(|_| {
            let mut client = TcpStream::connect(address).unwrap();
            client.write_all(b"GET /metrics HTTP/1.0\r\n\r\n").unwrap();
            client
        })
        .collect();
    std::thread::sleep(Duration::from_millis(50));
    let first = exporter.poll(String::new).unwrap();
    assert_eq!(first.len(), MAX_PER_POLL);
    let second = exporter.poll(String::new).unwrap();
    assert_eq!(second.len(), 4);
    drop(clients);
}
