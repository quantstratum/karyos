// SPDX-License-Identifier: Apache-2.0

//! karyos#706: the OTLP export against a collector stub on loopback.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use karyos_agent::exporter::{
    MetricFamily, MetricKind, MetricSample, MetricValue, render_families,
};
use karyos_otlp::{OtlpConfig, OtlpError, OtlpExport};
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::common::v1::any_value::Value;
use opentelemetry_proto::tonic::metrics::v1::metric::Data;
use opentelemetry_proto::tonic::metrics::v1::number_data_point;
use prost::Message as _;

/// A collector stub: the first `refuse` connections are dropped unread
/// (an unavailable collector), the rest answered 200 with their body
/// kept.
struct Collector {
    address: SocketAddr,
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Collector {
    fn start(refuse: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let kept = Arc::clone(&bodies);
        let seen = AtomicUsize::new(0);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                if seen.fetch_add(1, Ordering::AcqRel) < refuse {
                    drop(stream);
                    continue;
                }
                if let Some(body) = answer(stream) {
                    kept.lock().unwrap().push(body);
                }
            }
        });
        Self { address, bodies }
    }

    fn bodies(&self) -> Vec<Vec<u8>> {
        self.bodies.lock().unwrap().clone()
    }
}

/// Reads one request and answers it 200; its body.
fn answer(stream: TcpStream) -> Option<Vec<u8>> {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut length = 0;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse().ok()?;
        }
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).ok()?;
    let mut stream = stream;
    stream
        .write_all(
            b"HTTP/1.1 200 OK\r\ncontent-type: application/x-protobuf\r\ncontent-length: 0\r\n\r\n",
        )
        .ok()?;
    Some(body)
}

/// One sampling pass with a counter, an unsigned gauge and a signed
/// gauge, two series each.
fn pass() -> Vec<MetricFamily> {
    let sample = |labels: &[(&'static str, &str)], value: MetricValue| MetricSample {
        labels: labels
            .iter()
            .map(|(key, value)| (*key, (*value).to_owned()))
            .collect(),
        value,
    };
    vec![
        MetricFamily {
            name: "karyos_events_total",
            kind: MetricKind::Counter,
            help: "A CnC event counter.",
            samples: vec![
                sample(
                    &[("driver", "/d"), ("name", "sent")],
                    MetricValue::Unsigned(42),
                ),
                sample(
                    &[("driver", "/d"), ("name", "lost")],
                    MetricValue::Unsigned(3),
                ),
            ],
        },
        MetricFamily {
            name: "karyos_driver_up",
            kind: MetricKind::Gauge,
            help: "Whether the driver is attached.",
            samples: vec![
                sample(&[("driver", "/d")], MetricValue::Unsigned(1)),
                sample(&[("driver", "/e")], MetricValue::Unsigned(0)),
            ],
        },
        MetricFamily {
            name: "karyos_subscriber_lag",
            kind: MetricKind::Gauge,
            help: "A subscriber's lag.",
            samples: vec![
                sample(
                    &[("driver", "/d"), ("subscriber", "7")],
                    MetricValue::Signed(-5),
                ),
                sample(
                    &[("driver", "/d"), ("subscriber", "8")],
                    MetricValue::Signed(1 << 40),
                ),
            ],
        },
    ]
}

/// A series: family name, sorted labels and value, as text.
type Series = (String, Vec<(String, String)>, String);

/// The series of a Prometheus exposition.
fn prometheus(text: &str) -> BTreeSet<Series> {
    let mut series = BTreeSet::new();
    for line in text.lines().filter(|line| !line.starts_with('#')) {
        let (head, value) = line.rsplit_once(' ').unwrap();
        let (name, labels) = match head.split_once('{') {
            Some((name, rest)) => {
                let mut labels: Vec<(String, String)> = rest
                    .trim_end_matches('}')
                    .split(',')
                    .map(|pair| {
                        let (key, value) = pair.split_once('=').unwrap();
                        (key.to_owned(), value.trim_matches('"').to_owned())
                    })
                    .collect();
                labels.sort();
                (name, labels)
            }
            None => (head, Vec::new()),
        };
        series.insert((name.to_owned(), labels, value.to_owned()));
    }
    series
}

/// The series of the OTLP requests' last export, and each metric's
/// kind (`sum` monotonic and cumulative, or `gauge`).
fn otlp(body: &[u8]) -> (BTreeSet<Series>, BTreeSet<(String, &'static str)>) {
    let request = ExportMetricsServiceRequest::decode(body).unwrap();
    let mut series = BTreeSet::new();
    let mut kinds = BTreeSet::new();
    for metric in request
        .resource_metrics
        .iter()
        .flat_map(|resource| &resource.scope_metrics)
        .flat_map(|scope| &scope.metrics)
    {
        let (points, kind) = match metric.data.as_ref().unwrap() {
            Data::Sum(sum) => {
                assert!(sum.is_monotonic, "{}", metric.name);
                // Cumulative, as a Prometheus counter.
                assert_eq!(sum.aggregation_temporality, 2, "{}", metric.name);
                (&sum.data_points, "sum")
            }
            Data::Gauge(gauge) => (&gauge.data_points, "gauge"),
            other => panic!("{}: {other:?}", metric.name),
        };
        kinds.insert((metric.name.clone(), kind));
        for point in points {
            let mut labels: Vec<(String, String)> = point
                .attributes
                .iter()
                .map(|attribute| {
                    let value = match attribute.value.as_ref().and_then(|v| v.value.as_ref()) {
                        Some(Value::StringValue(value)) => value.clone(),
                        other => panic!("{other:?}"),
                    };
                    (attribute.key.clone(), value)
                })
                .collect();
            labels.sort();
            let value = match point.value.unwrap() {
                number_data_point::Value::AsInt(value) => value.to_string(),
                number_data_point::Value::AsDouble(value) => panic!("a double: {value}"),
            };
            series.insert((metric.name.clone(), labels, value));
        }
    }
    (series, kinds)
}

/// The Prometheus and OTLP views of one sampling pass hold the same
/// names, labels and values; a counter family is a cumulative monotonic
/// sum, a gauge family a gauge.
#[test]
fn the_prometheus_and_otlp_views_of_one_pass_agree() {
    let collector = Collector::start(0);
    let export = OtlpExport::start(
        &OtlpConfig::new(collector.address).with_interval(Duration::from_secs(3600)),
    )
    .unwrap();
    export.publish(pass());
    export.flush().unwrap();
    let bodies = collector.bodies();
    assert_eq!(bodies.len(), 1);
    let (series, kinds) = otlp(&bodies[0]);
    assert_eq!(series, prometheus(&render_families(&pass())));
    assert_eq!(
        kinds,
        BTreeSet::from([
            ("karyos_driver_up".to_owned(), "gauge"),
            ("karyos_events_total".to_owned(), "sum"),
            ("karyos_subscriber_lag".to_owned(), "gauge"),
        ])
    );
    export.shutdown().unwrap();
}

/// An unavailable collector holds neither the agent nor memory: a
/// publish returns at once while exports fail, each failed export is
/// dropped rather than queued, and the first that succeeds afterwards
/// carries one point per series, the latest pass, not a backlog.
#[test]
fn an_unavailable_collector_blocks_nothing_and_queues_nothing() {
    // Every connection of the first exports dropped unread.
    let collector = Collector::start(40);
    let export = OtlpExport::start(
        &OtlpConfig::new(collector.address)
            .with_interval(Duration::from_secs(3600))
            .with_timeout(Duration::from_millis(500)),
    )
    .unwrap();
    let mut failed = 0;
    let deadline = Instant::now() + Duration::from_secs(120);
    for round in 0..10_u64 {
        let mut families = pass();
        families[0].samples[0].value = MetricValue::Unsigned(round);
        let started = Instant::now();
        export.publish(families);
        assert!(started.elapsed() < Duration::from_millis(100));
        if export.flush().is_err() {
            failed += 1;
        }
        assert!(Instant::now() < deadline);
    }
    assert!(failed > 0, "the collector refused nothing");
    // Up again: one export, one point per series of the latest pass.
    let mut last = pass();
    last[0].samples[0].value = MetricValue::Unsigned(1_000);
    export.publish(last.clone());
    while collector.bodies().is_empty() {
        assert!(Instant::now() < deadline, "the collector never received");
        let _ = export.flush();
    }
    let (series, _) = otlp(collector.bodies().last().unwrap());
    assert_eq!(series, prometheus(&render_families(&last)));
    export.shutdown().unwrap();
}

/// A non-loopback collector is refused unless allowed.
#[test]
fn a_remote_collector_needs_its_opt_in() {
    let remote: SocketAddr = "192.0.2.1:4318".parse().unwrap();
    assert!(matches!(
        OtlpExport::start(&OtlpConfig::new(remote)),
        Err(OtlpError::NotLoopback(address)) if address == remote
    ));
    let export = OtlpExport::start(&OtlpConfig::new(remote).allowing_remote()).unwrap();
    drop(export);
}
