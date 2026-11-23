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
        cell_registration: 0,
        read_ns: 0,
        changed_ns: None,
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
                sampled_ns: None,
                stream: 3,
                lane: 1,
                limit: Some(4096),
                head: Some(1024),
                floor: None,
                headroom: Some(3072),
                subscribers: vec![Subscriber {
                    cell_registration: 0,
                    changed_ns: None,
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
                cell_registration: 0,
                read_ns: 0,
                changed_ns: None,
                kind: karyos_sys::counters::KIND_CLIENT,
                participant: 11,
                ..counter("orders \"filled\"\nby desk", TYPE_APPLICATION_EVENT, 42)
            },
            Counter {
                cell_registration: 0,
                read_ns: 0,
                changed_ns: None,
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
            retention: None,
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
        rates: Vec::new(),
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
    // Alerts (M9): a count per attached driver, 0 included, and each
    // one's value; a driver not attached has none (karyos#734).
    let firing: BTreeMap<&str, f64> = families["karyos_alerts_firing"]
        .1
        .iter()
        .map(|(labels, value)| (label(labels, "driver").unwrap(), *value))
        .collect();
    assert_eq!(
        firing.values().copied().collect::<Vec<_>>(),
        [1.0],
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

/// R-CORE-1: a trace point's cell is a name whose value is an id, not a
/// metric: the exposition leaves it out entirely.
#[test]
fn a_trace_point_is_not_exported_as_a_sample() {
    let mut with_point = view();
    with_point.drivers[0].client_counters.push(Counter {
        cell_registration: 0,
        read_ns: 0,
        changed_ns: None,
        kind: karyos_sys::counters::KIND_CLIENT,
        participant: 12,
        ..counter("order received", karyos_sys::counters::TYPE_TRACE_POINT, 3)
    });
    assert_eq!(render(&with_point), render(&view()));
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

/// R-CORE-39 (karyos#734): every family written is one of [`FAMILIES`],
/// with its type, and each family appears once with its HELP and TYPE.
#[test]
fn every_family_is_published_with_its_type() {
    let text = render(&view());
    let families = parse(&text);
    let published: BTreeMap<&str, &str> = FAMILIES
        .iter()
        .map(|(name, kind, _)| (*name, *kind))
        .collect();
    assert_eq!(published.len(), FAMILIES.len(), "a family listed twice");
    for (name, (kind, _)) in &families {
        assert_eq!(
            published.get(name.as_str()),
            Some(&kind.as_str()),
            "{name} is not published as a {kind}"
        );
    }
    // The per-cell families keyed by a driver's counter label are the
    // unstable ones.
    let unstable: Vec<&str> = FAMILIES
        .iter()
        .filter(|(_, _, stability)| *stability == Stability::Unstable)
        .map(|(name, _, _)| *name)
        .collect();
    assert_eq!(
        unstable,
        [
            "karyos_events_total",
            "karyos_spin_time_ns_total",
            "karyos_gauge",
            "karyos_value",
            "karyos_position",
            "karyos_timestamp_ns"
        ]
    );
}

/// R-CORE-39 (karyos#734): the exporter's identity and each driver's
/// attachment are exported; a driver not attached is a state, never a
/// scrape of zeros or of its last values.
#[test]
fn identity_and_attachment_are_exported_and_an_absent_driver_is_a_state() {
    let mut view = view();
    view.agent = crate::api::AgentIdentity::new(Some("ns/pod".to_owned()), 42, 7);
    let text = render(&view);
    let families = parse(&text);
    let (labels, value) = &families["karyos_exporter_info"].1[0];
    assert_eq!(
        (label(labels, "id"), label(labels, "pid"), *value),
        (Some("ns/pod"), Some("42"), 1.0)
    );
    assert_eq!(families["karyos_exporter_started_ns"].1[0].1, 7.0);
    let attached = view.drivers[0].dir.display().to_string();
    let absent = view.drivers[1].dir.display().to_string();
    let of = |family: &str, dir: &str| -> Vec<(Vec<(String, String)>, f64)> {
        families
            .get(family)
            .map(|(_, samples)| {
                samples
                    .iter()
                    .filter(|(labels, _)| label(labels, "driver") == Some(dir))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    };
    assert_eq!(of("karyos_driver_up", &attached)[0].1, 1.0);
    assert_eq!(of("karyos_driver_up", &absent)[0].1, 0.0);
    let state = |dir: &str| -> Vec<(String, f64)> {
        of("karyos_driver_state", dir)
            .into_iter()
            .map(|(labels, value)| (label(&labels, "state").unwrap().to_owned(), value))
            .collect()
    };
    assert_eq!(
        state(&attached),
        [
            ("attached".to_owned(), 1.0),
            ("closed".to_owned(), 0.0),
            ("unavailable".to_owned(), 0.0)
        ]
    );
    assert_eq!(state(&absent).iter().filter(|(_, v)| *v == 1.0).count(), 1);
    assert_eq!(
        label(&of("karyos_driver_info", &attached)[0].0, "instance"),
        Some("00000000000000000000000000000001")
    );
    // The absent driver: its state families and its catalog only.
    let allowed = [
        "karyos_driver_up",
        "karyos_driver_state",
        "karyos_driver_info",
        "karyos_driver_attaches_total",
        "karyos_driver_attached_since_ns",
        "karyos_driver_attached",
        "karyos_driver_closed",
        "karyos_archive_recordings",
        "karyos_archive_listings_total",
        "karyos_archive_listing_failures_total",
        "karyos_archive_listed_at_ns",
    ];
    for family in families.keys() {
        if !of(family, &absent).is_empty() {
            assert!(
                allowed.contains(&family.as_str()),
                "{family} for an absent driver"
            );
        }
    }
}

/// R-CORE-39 (karyos#734): with a token, a scrape without it or with
/// another is `401` with a Bearer challenge, and with it `200`; a request
/// head that is not one is `400`.
#[test]
fn a_token_guards_every_scrape_and_a_bad_head_is_400() {
    let token = Token::new(b"0123456789abcdef0123456789abcdef".to_vec()).unwrap();
    let mut exporter = bind("127.0.0.1:0".parse().unwrap())
        .unwrap()
        .with_token(token);
    let (answer, answered) = exchange(&mut exporter, "GET /metrics HTTP/1.1\r\n\r\n");
    assert_eq!(answered, [Answered::Unauthorized]);
    assert!(answer.starts_with("HTTP/1.1 401"), "{answer}");
    assert!(answer.contains("WWW-Authenticate: Bearer\r\n"), "{answer}");
    assert!(!answer.contains("karyos_up"), "{answer}");
    let (answer, answered) = exchange(
        &mut exporter,
        "GET /metrics HTTP/1.1\r\nAuthorization: Bearer 0123456789abcdef0123456789abcdeX\r\n\r\n",
    );
    assert_eq!(answered, [Answered::Unauthorized], "{answer}");
    let (answer, answered) = exchange(
        &mut exporter,
        "GET /metrics HTTP/1.1\r\nauthorization: bearer 0123456789abcdef0123456789abcdef\r\n\r\n",
    );
    assert_eq!(answered, [Answered::Metrics], "{answer}");
    assert!(answer.ends_with("karyos_up 1\n"), "{answer}");
    for bad in [
        "GET /metrics\r\n\r\n",
        "GET /metrics HTTP/1.1 extra\r\n\r\n",
        "GET /metrics SPDY/3\r\n\r\n",
        "\u{7f}\r\n\r\n",
    ] {
        let (answer, answered) = exchange(&mut exporter, bad);
        assert_eq!(answered, [Answered::Refused], "{bad:?}");
        assert!(answer.starts_with("HTTP/1.1 400"), "{bad:?}: {answer}");
    }
}

/// A token is 32 to 256 bytes of visible ASCII, from a file of mode 0600;
/// its comparison refuses a prefix, an extension and one byte off.
#[test]
fn a_token_is_bounded_and_read_from_a_private_file() {
    assert!(Token::new(vec![b'a'; MIN_TOKEN - 1]).is_none());
    assert!(Token::new(vec![b'a'; MAX_TOKEN + 1]).is_none());
    assert!(Token::new(b"0123456789abcdef0123456789abcde f".to_vec()).is_none());
    let token = Token::new(vec![b'a'; MIN_TOKEN]).unwrap();
    assert!(token.matches(&[b'a'; MIN_TOKEN]));
    assert!(!token.matches(&[b'a'; MIN_TOKEN - 1]));
    assert!(!token.matches(&[b'a'; MIN_TOKEN + 1]));
    let mut off = vec![b'a'; MIN_TOKEN];
    off[MIN_TOKEN - 1] = b'b';
    assert!(!token.matches(&off));
    assert_eq!(format!("{token:?}"), "Token(..)");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("karyos-token-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("token");
        std::fs::write(&path, format!("{}\n", "t".repeat(40))).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(Token::read(&path), Err(TokenError::Mode(_))));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            Token::read(&path).unwrap(),
            Token::new(vec![b't'; 40]).unwrap()
        );
        std::fs::write(&path, "short").unwrap();
        assert!(matches!(Token::read(&path), Err(TokenError::Content(_))));
        // A large file is read only to one byte past the bound, and refused.
        std::fs::write(&path, vec![b't'; 1 << 20]).unwrap();
        assert!(matches!(Token::read(&path), Err(TokenError::Content(_))));
        // A symlink is followed: the file it names is checked and read.
        std::fs::write(&path, "t".repeat(40)).unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert_eq!(
            Token::read(&link).unwrap(),
            Token::new(vec![b't'; 40]).unwrap()
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(Token::read(&link), Err(TokenError::Mode(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// One raw head to `exporter` and what it answered; the answer's bytes
/// may be cut by a reset when the head went past its bound.
fn exchange_bytes(exporter: &mut Exporter, request: &[u8]) -> (Vec<u8>, Vec<Answered>) {
    let mut client = TcpStream::connect(exporter.local_addr().unwrap()).unwrap();
    let _ = client.write_all(request);
    let _ = client.shutdown(std::net::Shutdown::Write);
    let mut answered = Vec::new();
    for _ in 0..200 {
        answered = exporter.poll(|| "karyos_up 1\n".to_owned()).unwrap();
        if !answered.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut answer = Vec::new();
    let _ = client.read_to_end(&mut answer);
    (answer, answered)
}

const TOKEN: &[u8] = b"0123456789abcdef0123456789abcdef";

/// The token a head offers, by an oracle of its own: within the bytes the
/// exporter reads, the last `Authorization` header before the blank line,
/// its scheme `Bearer` in any case followed by one space, and the rest
/// trimmed. `None` when there is no such header.
fn bearer_of(head: &[u8]) -> Option<Vec<u8>> {
    let read = head.get(..MAX_REQUEST).unwrap_or(head);
    let mut lines = read.split(|byte| *byte == b'\n');
    let _request = lines.next()?;
    let mut offered = None;
    for line in lines {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let (name, value) = line.split_at(colon);
        let value = value.get(1..).unwrap_or_default();
        if !name.trim_ascii().eq_ignore_ascii_case(b"authorization") {
            continue;
        }
        let value = value.trim_ascii();
        offered = match value.get(..7) {
            Some(scheme) if scheme.eq_ignore_ascii_case(b"bearer ") => {
                value.get(7..).map(|token| token.trim_ascii().to_vec())
            }
            _ => None,
        };
    }
    offered
}

/// A generated head: request lines and `Authorization` variants (the
/// token, one byte off, a prefix, an extension, another scheme, no space,
/// any case), other headers, non-UTF-8 bytes, and padding up to and past
/// the head's bound, cut anywhere.
fn head() -> impl proptest::strategy::Strategy<Value = Vec<u8>> {
    use proptest::prelude::*;
    let line = prop_oneof![
        6 => Just(b"GET /metrics HTTP/1.1\r\n".to_vec()),
        1 => Just(b"GET /metrics HTTP/1.0\n".to_vec()),
        1 => Just(b"get /metrics HTTP/1.1\r\n".to_vec()),
        1 => Just(b"GET /other HTTP/1.1\r\n".to_vec()),
        1 => Just(b"POST /metrics HTTP/1.1\r\n".to_vec()),
        1 => Just(b"GET /metrics\r\n".to_vec()),
        1 => Just(b"GET /metrics SPDY/3\r\n".to_vec()),
        1 => proptest::collection::vec(any::<u8>(), 0..64),
    ];
    let mut off = TOKEN.to_vec();
    if let Some(last) = off.last_mut() {
        *last = b'X';
    }
    let value = prop_oneof![
        6 => Just(TOKEN.to_vec()),
        1 => Just(off),
        1 => Just(TOKEN.get(..31).unwrap().to_vec()),
        1 => Just([TOKEN, b"0"].concat()),
        1 => proptest::collection::vec(any::<u8>(), 0..300),
    ];
    let scheme = prop_oneof![
        Just(b"Bearer ".to_vec()),
        Just(b"bearer ".to_vec()),
        Just(b"BEARER  ".to_vec()),
        Just(b"Bearer".to_vec()),
        Just(b"Basic ".to_vec()),
        // Seven bytes, as `Bearer `: only the scheme check refuses it.
        Just(b"Basic  ".to_vec()),
    ];
    let name = prop_oneof![
        Just(b"Authorization: ".to_vec()),
        Just(b"authorization:".to_vec()),
        Just(b"Authorisation: ".to_vec()),
        Just(b"X-Authorization: ".to_vec()),
    ];
    let authorization = (name, scheme, value)
        .prop_map(|(name, scheme, value)| [name, scheme, value, b"\r\n".to_vec()].concat());
    let header = prop_oneof![
        3 => authorization,
        1 => Just(b"Host: localhost\r\n".to_vec()),
        1 => proptest::collection::vec(any::<u8>(), 0..40),
        1 => (0..1200usize).prop_map(|length| [vec![b'p'; length], b"\r\n".to_vec()].concat()),
    ];
    (
        line,
        proptest::collection::vec(header, 0..4),
        any::<bool>(),
        any::<prop::sample::Index>(),
    )
        .prop_map(|(line, headers, cut, at)| {
            let mut head = [line, headers.concat(), b"\r\n".to_vec()].concat();
            if cut {
                head.truncate(at.index(head.len() + 1));
            }
            head
        })
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(128))]

    /// Whatever head comes (karyos#893): a poll never fails or panics, and
    /// metrics are served only to a head whose bounded part carries an
    /// `Authorization` header with exactly the token.
    #[test]
    fn no_head_without_the_token_is_served_metrics(head in head()) {
        let token = Token::new(TOKEN.to_vec()).unwrap();
        let mut exporter = bind("127.0.0.1:0".parse().unwrap())
            .unwrap()
            .with_token(token);
        let (answer, answered) = exchange_bytes(&mut exporter, &head);
        proptest::prop_assert_eq!(answered.len(), 1);
        if answered.contains(&Answered::Metrics) {
            proptest::prop_assert!(
                bearer_of(&head).as_deref() == Some(TOKEN),
                "{:?}",
                String::from_utf8_lossy(&head)
            );
        } else {
            proptest::prop_assert!(
                !answer.windows(9).any(|window| window == b"karyos_up"),
                "{:?}",
                String::from_utf8_lossy(&answer)
            );
        }
    }
}

/// The scheme, the header's name, and the last header decide (karyos#893,
/// codex): a seven-byte scheme other than `Bearer `, a header named
/// otherwise, and an earlier good header overridden by a later bad one
/// are refused; a later good one is served.
#[test]
fn only_the_last_bearer_authorization_with_the_token_is_served() {
    let token = Token::new(TOKEN.to_vec()).unwrap();
    let mut exporter = bind("127.0.0.1:0".parse().unwrap())
        .unwrap()
        .with_token(token);
    let good = "Authorization: Bearer 0123456789abcdef0123456789abcdef\r\n";
    let bad = "Authorization: Bearer 0123456789abcdef0123456789abcdeX\r\n";
    for (head, expected) in [
        (
            "Authorization: Basic  0123456789abcdef0123456789abcdef\r\n".to_owned(),
            Answered::Unauthorized,
        ),
        (
            "X-Authorization: Bearer 0123456789abcdef0123456789abcdef\r\n".to_owned(),
            Answered::Unauthorized,
        ),
        (format!("{good}{bad}"), Answered::Unauthorized),
        (format!("{bad}{good}"), Answered::Metrics),
    ] {
        let request = format!("GET /metrics HTTP/1.1\r\n{head}\r\n");
        let (_, answered) = exchange(&mut exporter, &request);
        assert_eq!(answered, [expected], "{head:?}");
        assert_eq!(
            bearer_of(request.as_bytes()).as_deref() == Some(TOKEN),
            expected == Answered::Metrics,
            "the oracle agrees: {head:?}"
        );
    }
}

/// A header line that is not UTF-8 makes the head bad (karyos#893, codex):
/// a good `Authorization` followed by one whose token is not UTF-8 is a
/// 400, never metrics on the earlier header.
#[test]
fn a_head_with_a_header_that_is_not_utf8_is_refused() {
    let token = Token::new(TOKEN.to_vec()).unwrap();
    let mut exporter = bind("127.0.0.1:0".parse().unwrap())
        .unwrap()
        .with_token(token);
    let head = [
        &b"GET /metrics HTTP/1.1\r\nAuthorization: Bearer "[..],
        TOKEN,
        b"\r\nAuthorization: Bearer \xff\r\n\r\n",
    ]
    .concat();
    let (answer, answered) = exchange_bytes(&mut exporter, &head);
    assert_eq!(answered, [Answered::Refused]);
    assert!(
        answer.starts_with(b"HTTP/1.1 400"),
        "{:?}",
        String::from_utf8_lossy(&answer)
    );
}

/// A peer that connects to `exporter` and trickles one byte of `bytes`
/// every 40 ms, each within [`IO_TIMEOUT`], until the exporter hangs up;
/// returns what one poll answered and how long it took (karyos#887
/// review).
fn trickle(exporter: &mut Exporter, bytes: &'static [u8]) -> (Vec<Answered>, Duration) {
    let address = exporter.local_addr().unwrap();
    let peer = std::thread::spawn(move || {
        let mut peer = TcpStream::connect(address).unwrap();
        for byte in bytes.iter().cycle().take(200) {
            if peer.write_all(&[*byte]).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(40));
        }
    });
    std::thread::sleep(Duration::from_millis(20));
    let started = std::time::Instant::now();
    let mut answered = Vec::new();
    while answered.is_empty() && started.elapsed() < Duration::from_secs(5) {
        answered = exporter.poll(|| "karyos_up 1\n".to_owned()).unwrap();
    }
    let took = started.elapsed();
    drop(peer);
    (answered, took)
}

#[test]
fn a_peer_that_trickles_its_request_is_cut_off_at_the_deadline() {
    let mut exporter = bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let (answered, took) = trickle(&mut exporter, b"GET /metrics HTTP/1.1\r\nX: ");
    assert_eq!(answered, vec![Answered::Dropped]);
    assert!(took < CONNECTION_DEADLINE + IO_TIMEOUT * 3, "{took:?}");
}

/// karyos#887: the exporter over TLS.
#[cfg(feature = "exporter-tls")]
mod over_tls {
    use std::sync::Arc;

    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, ServerName};

    use super::*;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../karyos-control/tests/fixtures")
            .join(name)
    }

    /// `source` copied to a private file of mode `mode` in a test
    /// directory named `name`.
    fn copied(source: &std::path::Path, name: &str, mode: u32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("karyos-887-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("key.pem");
        std::fs::copy(source, &path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    fn key(name: &str) -> PathBuf {
        copied(&fixture("server.key"), name, 0o600)
    }

    fn token() -> Token {
        Token::new(vec![b'k'; 32]).unwrap()
    }

    fn exporter(address: &str, name: &str) -> Exporter {
        let config = tls::server_config(&fixture("server.pem"), &key(name)).unwrap();
        bind_tls(address.parse().unwrap(), config, Some(token())).unwrap()
    }

    /// The fixture CA, or none.
    fn roots(trusted: bool) -> rustls::RootCertStore {
        let mut roots = rustls::RootCertStore::empty();
        if trusted {
            for root in CertificateDer::pem_file_iter(fixture("ca.pem")).unwrap() {
                roots.add(root.unwrap()).unwrap();
            }
        }
        roots
    }

    /// A TLS 1.3 client with `roots`, naming the server `name`, sends
    /// `request` to the exporter on 127.0.0.1 in a thread while the
    /// exporter is polled; the answer, or `None` when the handshake or the
    /// read failed.
    fn exchange_tls(
        exporter: &mut Exporter,
        roots: rustls::RootCertStore,
        name: &'static str,
        request: &str,
    ) -> (Option<String>, Vec<Answered>) {
        exchange_tls_after(exporter, roots, name, request, Duration::ZERO)
    }

    /// [`exchange_tls`], the request sent `pause` after the handshake.
    fn exchange_tls_after(
        exporter: &mut Exporter,
        roots: rustls::RootCertStore,
        name: &'static str,
        request: &str,
        pause: Duration,
    ) -> (Option<String>, Vec<Answered>) {
        let port = exporter.local_addr().unwrap().port();
        let request = request.to_owned();
        let client = std::thread::spawn(move || {
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls_graviola::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
            let connection = rustls::ClientConnection::new(
                Arc::new(config),
                ServerName::try_from(name).unwrap(),
            )
            .unwrap();
            let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            let mut stream = rustls::StreamOwned::new(connection, tcp);
            if !pause.is_zero() {
                while stream.conn.is_handshaking() {
                    stream.conn.complete_io(&mut stream.sock).ok()?;
                }
                std::thread::sleep(pause);
            }
            stream.write_all(request.as_bytes()).ok()?;
            let mut answer = String::new();
            stream.read_to_string(&mut answer).ok()?;
            Some(answer)
        });
        let mut answered = Vec::new();
        for _ in 0..400 {
            answered = exporter.poll(|| "karyos_up 1\n".to_owned()).unwrap();
            if !answered.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        (client.join().unwrap(), answered)
    }

    fn scrape(
        exporter: &mut Exporter,
        roots: rustls::RootCertStore,
        name: &'static str,
    ) -> (Option<String>, Vec<Answered>) {
        exchange_tls(
            exporter,
            roots,
            name,
            &format!(
                "GET /metrics HTTP/1.1\r\nAuthorization: Bearer {}\r\n\r\n",
                "k".repeat(32)
            ),
        )
    }

    #[test]
    fn a_scrape_over_tls_is_answered_and_its_token_guards_it() {
        let mut exporter = exporter("127.0.0.1:0", "guards");
        let (answer, answered) = scrape(&mut exporter, roots(true), "localhost");
        assert_eq!(answered, vec![Answered::Metrics]);
        let answer = answer.unwrap();
        assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
        assert!(answer.ends_with("karyos_up 1\n"), "{answer}");
        let (answer, answered) = exchange_tls(
            &mut exporter,
            roots(true),
            "localhost",
            "GET /metrics HTTP/1.1\r\n\r\n",
        );
        assert_eq!(answered, vec![Answered::Unauthorized]);
        assert!(answer.unwrap().starts_with("HTTP/1.1 401"));
    }

    #[test]
    fn the_certificate_is_verified_by_its_ip_san_too() {
        let mut exporter = exporter("127.0.0.1:0", "ip-san");
        let (answer, answered) = scrape(&mut exporter, roots(true), "127.0.0.1");
        assert_eq!(answered, vec![Answered::Metrics]);
        assert!(answer.unwrap().starts_with("HTTP/1.1 200 OK"));
    }

    #[test]
    fn a_scraper_that_does_not_trust_the_ca_or_names_another_host_gets_nothing() {
        let mut exporter = exporter("127.0.0.1:0", "untrusted");
        let (answer, answered) = scrape(&mut exporter, roots(false), "localhost");
        assert_eq!((answer, answered), (None, vec![Answered::Dropped]));
        let (answer, answered) = scrape(&mut exporter, roots(true), "metrics.example.com");
        assert_eq!((answer, answered), (None, vec![Answered::Dropped]));
    }

    #[test]
    fn a_non_loopback_address_is_bound_only_with_tls_and_a_token() {
        assert!(matches!(
            bind("0.0.0.0:0".parse().unwrap()),
            Err(ExportError::NotLoopback(_))
        ));
        let config = tls::server_config(&fixture("server.pem"), &key("no-token")).unwrap();
        assert!(matches!(
            bind_tls("0.0.0.0:0".parse().unwrap(), Arc::clone(&config), None),
            Err(ExportError::NoToken(_))
        ));
        let mut exporter = bind_tls("0.0.0.0:0".parse().unwrap(), config, Some(token())).unwrap();
        let (answer, answered) = scrape(&mut exporter, roots(true), "localhost");
        assert_eq!(answered, vec![Answered::Metrics]);
        assert!(answer.unwrap().starts_with("HTTP/1.1 200 OK"));
        let (answer, answered) = exchange_tls(
            &mut exporter,
            roots(true),
            "localhost",
            "GET /metrics HTTP/1.1\r\n\r\n",
        );
        assert_eq!(answered, vec![Answered::Unauthorized]);
        assert!(answer.unwrap().starts_with("HTTP/1.1 401"));
    }

    #[test]
    fn a_peer_that_trickles_its_handshake_is_cut_off_at_the_deadline() {
        let mut exporter = exporter("0.0.0.0:0", "trickle");
        // A TLS record header of a ClientHello, then its body byte by byte.
        let (answered, took) = trickle(
            &mut exporter,
            b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03",
        );
        assert_eq!(answered, vec![Answered::Dropped]);
        assert_eq!(exporter.deadline(), TLS_CONNECTION_DEADLINE);
        assert!(took < TLS_CONNECTION_DEADLINE + IO_TIMEOUT * 3, "{took:?}");
        // A shorter deadline is honoured.
        let mut short = self::exporter("0.0.0.0:0", "trickle-short")
            .with_deadline(CONNECTION_DEADLINE)
            .unwrap();
        let (answered, took) = trickle(&mut short, b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03");
        assert_eq!(answered, vec![Answered::Dropped]);
        assert!(took < CONNECTION_DEADLINE + IO_TIMEOUT * 3, "{took:?}");
    }

    /// karyos#887 review: a deadline outside 1 ms to 30 s is a typed
    /// error, and the step follows the transport however often it is set.
    #[test]
    fn a_deadline_is_bounded_and_its_step_follows_the_transport() {
        for bad in [
            Duration::ZERO,
            MAX_CONNECTION_DEADLINE + Duration::from_millis(1),
            Duration::MAX,
        ] {
            assert!(matches!(
                exporter("127.0.0.1:0", "bad-deadline").with_deadline(bad),
                Err(ExportError::InvalidDeadline(_))
            ));
        }
        let tls = exporter("127.0.0.1:0", "tls-step")
            .with_deadline(Duration::from_millis(50))
            .unwrap()
            .with_deadline(Duration::from_secs(3))
            .unwrap();
        assert_eq!(
            (tls.deadline(), tls.step),
            (Duration::from_secs(3), Duration::from_secs(3))
        );
        let plain = bind("127.0.0.1:0".parse().unwrap())
            .unwrap()
            .with_deadline(Duration::from_millis(50))
            .unwrap()
            .with_deadline(Duration::from_secs(3))
            .unwrap();
        assert_eq!(
            (plain.deadline(), plain.step),
            (Duration::from_secs(3), IO_TIMEOUT)
        );
    }

    /// A remote scraper whose request comes a long round trip after the
    /// handshake, past `IO_TIMEOUT` but within the TLS deadline, is still
    /// answered (karyos#887 review).
    #[test]
    fn a_scraper_on_a_slow_network_is_answered_within_the_tls_deadline() {
        let mut exporter = exporter("127.0.0.1:0", "slow-network");
        let (answer, answered) = exchange_tls_after(
            &mut exporter,
            roots(true),
            "localhost",
            &format!(
                "GET /metrics HTTP/1.1\r\nAuthorization: Bearer {}\r\n\r\n",
                "k".repeat(32)
            ),
            Duration::from_millis(400),
        );
        assert_eq!(answered, vec![Answered::Metrics]);
        assert!(answer.unwrap().starts_with("HTTP/1.1 200 OK"));
    }

    #[test]
    fn plain_http_to_a_tls_exporter_is_dropped() {
        let mut exporter = exporter("127.0.0.1:0", "plain");
        let (answer, answered) = exchange(&mut exporter, "GET /metrics HTTP/1.1\r\n\r\n");
        assert_eq!(answered, vec![Answered::Dropped]);
        assert!(!answer.contains("karyos_up"), "{answer}");
    }

    #[test]
    fn a_bad_key_or_certificate_file_is_a_typed_refusal() {
        let cert = fixture("server.pem");
        assert!(matches!(
            tls::server_config(&fixture("missing.pem"), &key("missing")),
            Err(tls::TlsError::Pem { .. })
        ));
        // A key readable by others.
        let open = copied(&fixture("server.key"), "open-key", 0o644);
        assert!(matches!(
            tls::server_config(&cert, &open),
            Err(tls::TlsError::KeyMode(_))
        ));
        // A certificate where the key should be.
        let not_a_key = copied(&cert, "not-a-key", 0o600);
        assert!(matches!(
            tls::server_config(&cert, &not_a_key),
            Err(tls::TlsError::Pem { .. })
        ));
        // A key where the certificate should be.
        assert!(matches!(
            tls::server_config(&key("no-cert"), &key("no-cert-key")),
            Err(tls::TlsError::Pem { .. })
        ));
        // A valid key that is not the certificate's.
        let other = copied(
            &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/other.key"),
            "other-key",
            0o600,
        );
        assert!(matches!(
            tls::server_config(&cert, &other),
            Err(tls::TlsError::Rustls(_))
        ));
    }

    /// The suites a scraper can negotiate: the provider's TLS 1.3 suites
    /// only (recorded in the admission record).
    #[test]
    fn only_tls13_suites_are_offered() {
        let config = tls::server_config(&fixture("server.pem"), &key("suites")).unwrap();
        let suites: Vec<String> = config
            .crypto_provider()
            .cipher_suites
            .iter()
            .filter(|suite| suite.version() == &rustls::version::TLS13)
            .map(|suite| format!("{:?}", suite.suite()))
            .collect();
        assert_eq!(
            suites,
            [
                "TLS13_AES_128_GCM_SHA256",
                "TLS13_AES_256_GCM_SHA384",
                "TLS13_CHACHA20_POLY1305_SHA256"
            ]
        );
    }

    /// The development and CI hosts have the provider's features.
    #[test]
    fn this_cpu_runs_the_provider() {
        assert!(tls::check_cpu().is_ok());
    }
}
