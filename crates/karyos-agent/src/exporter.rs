// SPDX-License-Identifier: Apache-2.0

//! The Prometheus exporter (SPEC.md §11, `karyos-exporter`; ADR-0055;
//! quantstratum-docs: karyos/design/management-agent-gap-analysis.md, M8;
//! owner item 51, interim 4).
//!
//! - **What.** [`render`] writes an [`AgentView`] in the Prometheus text
//!   exposition format (version 0.0.4): one family per kind of value, each
//!   with its `HELP` and `TYPE` lines and its samples together. A driver
//!   counter keeps its type: an event cell is a `counter` (`_total`), spin
//!   time a `counter` of nanoseconds, a gauge or a position a `gauge`, a
//!   timestamp a `gauge` of host `CLOCK_MONOTONIC` nanoseconds. Label values
//!   are escaped as the format requires (`\\`, `\"`, `\n`).
//! - **Where.** [`Exporter`] answers `GET /metrics` on a TCP listener bound
//!   to a loopback address only ([`bind`] refuses any other), read-only,
//!   one request per connection with [`IO_TIMEOUT`] on its reads and
//!   writes. It is off unless the `karyos-exporter` binary is started with
//!   an address. Without TLS it serves loopback only, and exposing it
//!   beyond the pod takes a TLS-terminating sidecar or mesh (R-CORE-39,
//!   karyos#734). Built with the `exporter-tls` feature, [`bind_tls`]
//!   serves `/metrics` over TLS 1.3 on any address, with a certificate and
//!   key from files (karyos#887); loopback plain HTTP stays the default.
//!   An optional bearer [`Token`] (`--token-file`) guards
//!   scrapes from the other processes of the pod's network namespace: a
//!   request for `/metrics` without it is answered `401`; only `/metrics`
//!   needs it, any other path being `404` or `405` either way. A request head that is not one
//!   is answered `400`.
//! - **Attachment** (karyos#734): its own identity as an agent's
//!   (`karyos_exporter_info`), and per driver its state, instance and
//!   attaches. A driver not attached is a state (`karyos_driver_up` 0),
//!   never a scrape of zeros or of its last values. The families and their
//!   stability are [`FAMILIES`].
//! - **Alerts** (M9) are `karyos_alerts_firing` per attached driver, 0 included,
//!   and each firing alert's `karyos_alert_value` and
//!   `karyos_alert_since_ns`, labelled by kind, stream, lane and
//!   participant.
//! - **Cost.** The exporter attaches to each driver as a tool, so it takes
//!   one of the driver's tool slots (`max_tools`) while attached.
//! - **Trace latencies** are the agent's window (M6c): observed latencies,
//!   never trace verdicts; a quantile's bound past the histogram's range is
//!   left out rather than written as infinite.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use crate::api::{
    AgentView, Alert, AlertKind, Catalog, Counter, DriverState, DriverView, QuantileBounds,
};

/// The `Content-Type` of the exposition.
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";
/// The longest request head read, in bytes.
pub const MAX_REQUEST: usize = 1024;
/// The read and write timeout of each connection.
pub const IO_TIMEOUT: Duration = Duration::from_millis(100);
/// Connections answered per [`Exporter::poll`] at most, so a burst cannot
/// hold the agent's refresh.
pub const MAX_PER_POLL: usize = 16;

/// How far a dashboard may depend on a metric family (R-CORE-39,
/// karyos#734; quantstratum-docs: karyos/design/observability-and-tools.md,
/// Exporter metric families).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Stability {
    /// Its name, type and labels change only with a release note and a
    /// release in which the old name is still exported.
    Stable,
    /// Keyed by a driver's internal counter label, which a release may
    /// rename: its name and type are stable, its `name` label values are not.
    Unstable,
}

/// Every metric family the exporter writes: name, Prometheus type and
/// stability. A test checks that an exposition holds no other family and
/// that each keeps its type.
pub const FAMILIES: [(&str, &str, Stability); 37] = [
    ("karyos_exporter_info", "gauge", Stability::Stable),
    ("karyos_exporter_started_ns", "gauge", Stability::Stable),
    ("karyos_driver_up", "gauge", Stability::Stable),
    ("karyos_driver_state", "gauge", Stability::Stable),
    ("karyos_driver_info", "gauge", Stability::Stable),
    ("karyos_driver_attaches_total", "counter", Stability::Stable),
    (
        "karyos_driver_attached_since_ns",
        "gauge",
        Stability::Stable,
    ),
    ("karyos_driver_attached", "gauge", Stability::Stable),
    ("karyos_driver_closed", "gauge", Stability::Stable),
    ("karyos_alerts_firing", "gauge", Stability::Stable),
    ("karyos_alert_value", "gauge", Stability::Stable),
    ("karyos_alert_since_ns", "gauge", Stability::Stable),
    ("karyos_sample_consistent", "gauge", Stability::Stable),
    ("karyos_sample_age_ns", "gauge", Stability::Stable),
    ("karyos_lane_position", "gauge", Stability::Stable),
    ("karyos_lane_headroom", "gauge", Stability::Stable),
    ("karyos_subscriber_position", "gauge", Stability::Stable),
    ("karyos_subscriber_lag", "gauge", Stability::Stable),
    (
        "karyos_application_events_total",
        "counter",
        Stability::Stable,
    ),
    ("karyos_application_gauge", "gauge", Stability::Stable),
    (
        "karyos_ring_records_read_total",
        "counter",
        Stability::Stable,
    ),
    (
        "karyos_ring_records_overwritten_total",
        "counter",
        Stability::Stable,
    ),
    ("karyos_error_occurrences", "gauge", Stability::Stable),
    ("karyos_trace_events_total", "counter", Stability::Stable),
    ("karyos_trace_latency_ns", "gauge", Stability::Stable),
    ("karyos_trace_pending", "gauge", Stability::Stable),
    ("karyos_trace_window_pairs", "gauge", Stability::Stable),
    ("karyos_archive_recordings", "gauge", Stability::Stable),
    (
        "karyos_archive_listings_total",
        "counter",
        Stability::Stable,
    ),
    (
        "karyos_archive_listing_failures_total",
        "counter",
        Stability::Stable,
    ),
    ("karyos_archive_listed_at_ns", "gauge", Stability::Stable),
    ("karyos_events_total", "counter", Stability::Unstable),
    ("karyos_spin_time_ns_total", "counter", Stability::Unstable),
    ("karyos_gauge", "gauge", Stability::Unstable),
    ("karyos_value", "gauge", Stability::Unstable),
    ("karyos_position", "gauge", Stability::Unstable),
    ("karyos_timestamp_ns", "gauge", Stability::Unstable),
];

/// The counter types of the CnC (`karyos_sys::counters`), and the driver's
/// spin time.
const TYPE_EVENT: u64 = 1;
const TYPE_GAUGE: u64 = 2;
const TYPE_SPIN_TIME: u64 = 3;
const TYPE_POSITION: u64 = 4;
const TYPE_TIMESTAMP: u64 = 5;
const TYPE_APPLICATION_EVENT: u64 = karyos_sys::counters::TYPE_APPLICATION_EVENT;
const TYPE_APPLICATION_GAUGE: u64 = karyos_sys::counters::TYPE_APPLICATION_GAUGE;
const TYPE_TRACE_POINT: u64 = karyos_sys::counters::TYPE_TRACE_POINT;

/// One metric family: its type, help and sample lines.
struct Family {
    kind: &'static str,
    help: &'static str,
    samples: Vec<String>,
}

/// The families of one exposition, by name, in name order.
#[derive(Default)]
struct Families(BTreeMap<&'static str, Family>);

impl Families {
    /// Adds a sample of family `name`.
    fn sample(
        &mut self,
        name: &'static str,
        kind: &'static str,
        help: &'static str,
        labels: &[(&str, String)],
        value: impl std::fmt::Display,
    ) {
        let mut line = String::from(name);
        if !labels.is_empty() {
            line.push('{');
            for (index, (key, value)) in labels.iter().enumerate() {
                if index > 0 {
                    line.push(',');
                }
                let _ = write!(line, "{key}=\"{}\"", escape(value));
            }
            line.push('}');
        }
        let _ = write!(line, " {value}");
        self.0
            .entry(name)
            .or_insert_with(|| Family {
                kind,
                help,
                samples: Vec::new(),
            })
            .samples
            .push(line);
    }

    fn render(self) -> String {
        let mut out = String::new();
        for (name, family) in self.0 {
            let _ = writeln!(out, "# HELP {name} {}", family.help);
            let _ = writeln!(out, "# TYPE {name} {}", family.kind);
            for sample in family.samples {
                out.push_str(&sample);
                out.push('\n');
            }
        }
        out
    }
}

/// A label value as the text format writes it.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

/// `view` in the Prometheus text exposition format.
#[must_use]
pub fn render(view: &AgentView) -> String {
    let mut families = Families::default();
    // Its own identity, as the agent's (R-CORE-24): the exporter is an
    // agent of its own, attached to each driver as a tool.
    families.sample(
        "karyos_exporter_info",
        "gauge",
        "The exporter's identity: its --agent-id (empty when none) and pid.",
        &[
            ("id", view.agent.id.clone().unwrap_or_default()),
            ("pid", view.agent.pid.to_string()),
        ],
        1,
    );
    families.sample(
        "karyos_exporter_started_ns",
        "gauge",
        "Host monotonic nanoseconds at which the exporter started.",
        &[],
        view.agent.started_ns,
    );
    for driver in &view.drivers {
        render_driver(&mut families, driver);
    }
    families.render()
}

fn render_driver(families: &mut Families, driver: &DriverView) {
    let dir = driver.dir.display().to_string();
    let base = [("driver", dir.clone())];
    families.sample(
        "karyos_driver_attached",
        "gauge",
        "Whether the agent is attached to the driver (1) or not (0).",
        &base,
        u8::from(driver.state == DriverState::Attached),
    );
    families.sample(
        "karyos_driver_closed",
        "gauge",
        "Whether the driver exited (1).",
        &base,
        u8::from(driver.state == DriverState::Closed),
    );
    // Attached or not, as a state: an absent driver is never a scrape of
    // zeros, which a dashboard would read as healthy.
    let attached = driver.state == DriverState::Attached;
    families.sample(
        "karyos_driver_up",
        "gauge",
        "Whether the driver is attached and read (1) or not (0); when 0, no other value of the driver is current.",
        &base,
        u8::from(attached),
    );
    let current = match driver.state {
        DriverState::Attached => "attached",
        DriverState::Closed => "closed",
        DriverState::Unavailable { .. } => "unavailable",
    };
    for state in ["attached", "closed", "unavailable"] {
        families.sample(
            "karyos_driver_state",
            "gauge",
            "The driver's attachment state: 1 for the current one.",
            &[("driver", dir.clone()), ("state", state.to_owned())],
            u8::from(state == current),
        );
    }
    if let Some(instance) = driver.instance {
        families.sample(
            "karyos_driver_info",
            "gauge",
            "The driver instance attached: a restarted driver is a new instance, and its series start over.",
            &[("driver", dir.clone()), ("instance", format!("{instance:032x}"))],
            1,
        );
    }
    families.sample(
        "karyos_driver_attaches_total",
        "counter",
        "Attaches to the driver since the exporter started.",
        &base,
        driver.attachment.attaches,
    );
    if let Some(since) = driver.attachment.since_ns {
        families.sample(
            "karyos_driver_attached_since_ns",
            "gauge",
            "Host monotonic nanoseconds since which the current attachment holds.",
            &base,
            since,
        );
    }
    // The Archive catalog has a connection of its own.
    if let Some(catalog) = &driver.catalog {
        render_catalog(families, &dir, catalog);
    }
    // Nothing else of a driver not attached: its last values are not
    // current, and its alerts are not evaluated.
    if !attached {
        return;
    }
    render_alerts(families, &dir, &driver.alerts);
    if let Some(sample) = &driver.sample {
        families.sample(
            "karyos_sample_consistent",
            "gauge",
            "Whether the last sampling pass read was consistent (1) or mixed (0).",
            &base,
            u8::from(sample.consistent),
        );
        if let Some(age) = sample.age_ns {
            families.sample(
                "karyos_sample_age_ns",
                "gauge",
                "Host monotonic nanoseconds since the driver's last sampling pass.",
                &base,
                age,
            );
        }
        for counter in &sample.counters {
            render_counter(families, &dir, "driver", counter);
        }
        for lane in &sample.lanes {
            let keys = [
                ("driver", dir.clone()),
                ("stream", lane.stream.to_string()),
                ("lane", lane.lane.to_string()),
            ];
            for (position, value) in [
                ("limit", lane.limit),
                ("head", lane.head),
                ("floor", lane.floor),
            ] {
                if let Some(value) = value {
                    let mut labels = keys.to_vec();
                    labels.push(("position", position.to_owned()));
                    families.sample(
                        "karyos_lane_position",
                        "gauge",
                        "A stream lane's limit, head and floor positions.",
                        &labels,
                        value,
                    );
                }
            }
            if let Some(headroom) = lane.headroom {
                families.sample(
                    "karyos_lane_headroom",
                    "gauge",
                    "A stream lane's limit minus its head.",
                    &keys,
                    headroom,
                );
            }
            for subscriber in &lane.subscribers {
                let mut labels = keys.to_vec();
                labels.push(("subscriber", subscriber.registration.to_string()));
                families.sample(
                    "karyos_subscriber_position",
                    "gauge",
                    "A subscriber's position.",
                    &labels,
                    subscriber.position,
                );
                if let Some(lag) = subscriber.lag {
                    families.sample(
                        "karyos_subscriber_lag",
                        "gauge",
                        "A subscriber's lag: the head minus its position.",
                        &labels,
                        lag,
                    );
                }
            }
        }
    }
    for counter in &driver.client_counters {
        // A trace point's cell is a name, not a metric (R-CORE-1): its
        // value is an id, so it is never exported as a sample.
        if counter.type_id == TYPE_TRACE_POINT {
            continue;
        }
        if !render_application(families, &dir, counter) {
            render_counter(families, &dir, "client", counter);
        }
    }
    for (ring, delivered, overwritten) in [
        ("errors", driver.errors.delivered, driver.errors.overwritten),
        ("losses", driver.losses.delivered, driver.losses.overwritten),
        ("guards", driver.guards.delivered, driver.guards.overwritten),
    ] {
        let labels = [("driver", dir.clone()), ("ring", ring.to_owned())];
        families.sample(
            "karyos_ring_records_read_total",
            "counter",
            "Records the agent read from a diagnostic ring of the driver instance.",
            &labels,
            delivered,
        );
        families.sample(
            "karyos_ring_records_overwritten_total",
            "counter",
            "Records a diagnostic ring overwrote before the agent read them.",
            &labels,
            overwritten,
        );
    }
    let mut occurrences: BTreeMap<u32, u64> = BTreeMap::new();
    for error in &driver.errors.records {
        let sum = occurrences.entry(error.code).or_insert(0);
        *sum = sum.checked_add(error.occurrences).unwrap_or(*sum);
    }
    for (code, sum) in occurrences {
        families.sample(
            "karyos_error_occurrences",
            "gauge",
            "Occurrences of each error code in the error records the agent keeps only, not since the driver started.",
            &[("driver", dir.clone()), ("code", code.to_string())],
            sum,
        );
    }
    for latency in &driver.latencies {
        let keys = [
            ("driver", dir.clone()),
            ("stream", latency.stream.to_string()),
            ("incarnation", latency.incarnation.to_string()),
            ("lane", latency.lane.to_string()),
        ];
        for (result, count) in [
            ("available", latency.available),
            ("unavailable", latency.unavailable),
        ] {
            let mut labels = keys.to_vec();
            labels.push(("result", result.to_owned()));
            families.sample(
                "karyos_trace_window_pairs",
                "gauge",
                "Publish to poll pairs in the trace window, with and without a latency interval.",
                &labels,
                count,
            );
        }
        if latency.incomplete {
            continue;
        }
        for (quantile, bounds) in [
            ("0.5", latency.p50),
            ("0.9", latency.p90),
            ("0.99", latency.p99),
            ("0.999", latency.p999),
            ("1", latency.max),
        ] {
            let Some(QuantileBounds { low, high }) = bounds else {
                continue;
            };
            for (bound, value) in [("low", low), ("high", high)] {
                if let Some(value) = value {
                    let mut labels = keys.to_vec();
                    labels.push(("quantile", quantile.to_owned()));
                    labels.push(("bound", bound.to_owned()));
                    families.sample(
                        "karyos_trace_latency_ns",
                        "gauge",
                        "Bounds of a quantile of the observed Publish to SubscriberPoll latencies in the trace window, in nanoseconds (not trace verdicts).",
                        &labels,
                        value,
                    );
                }
            }
        }
    }
    let trace = driver.trace;
    for (what, count) in [
        ("records", trace.records),
        ("malformed", trace.malformed),
        ("unknown_journal", trace.unknown_journal),
        ("network_ignored", trace.network_ignored),
        ("points_ignored", trace.points_ignored),
        ("duplicates", trace.duplicates),
        ("journals_dropped", trace.journals_dropped),
        ("pending_dropped", trace.pending_dropped),
        ("polls_dropped", trace.polls_dropped),
        ("lanes_dropped", trace.lanes_dropped),
        ("aged_out", trace.aged_out),
        ("mirror_overwritten", trace.mirror_overwritten),
    ] {
        families.sample(
            "karyos_trace_events_total",
            "counter",
            "What the trace window counted for the driver instance.",
            &[("driver", dir.clone()), ("event", what.to_owned())],
            count,
        );
    }
    families.sample(
        "karyos_trace_pending",
        "gauge",
        "Messages in the trace window waiting for their pair.",
        &base,
        trace.pending,
    );
}

/// One CnC cell, in the family its type gives.
/// The alerts firing (M9): how many per driver, 0 included, and each
/// one's value and start.
fn render_alerts(families: &mut Families, dir: &str, alerts: &[Alert]) {
    families.sample(
        "karyos_alerts_firing",
        "gauge",
        "Alerts firing for the driver.",
        &[("driver", dir.to_owned())],
        alerts.len(),
    );
    for alert in alerts {
        let keys = [
            ("driver", dir.to_owned()),
            (
                "kind",
                match alert.kind {
                    AlertKind::Lag => "lag",
                    AlertKind::Loss => "loss",
                    AlertKind::GuardAck => "guard_ack",
                    AlertKind::JournalGap => "journal_gap",
                }
                .to_owned(),
            ),
            ("stream", alert.stream.to_string()),
            ("lane", alert.lane.to_string()),
            ("participant", alert.participant.to_string()),
        ];
        families.sample(
            "karyos_alert_value",
            "gauge",
            "A firing alert's value: the lag in bytes, or the losses counted.",
            &keys,
            alert.value,
        );
        families.sample(
            "karyos_alert_since_ns",
            "gauge",
            "Host monotonic nanoseconds of the refresh at which the alert began firing.",
            &keys,
            alert.since,
        );
    }
}

/// A driver's Archive catalog (M11): its size and the agent's attempts.
fn render_catalog(families: &mut Families, dir: &str, catalog: &Catalog) {
    let base = [("driver", dir.to_owned())];
    let listed = u64::try_from(catalog.recordings.len())
        .ok()
        .and_then(|kept| kept.checked_add(catalog.left_out));
    if let Some(listed) = listed {
        families.sample(
            "karyos_archive_recordings",
            "gauge",
            "Recordings in the driver's Archive catalog at the last complete listing.",
            &base,
            listed,
        );
    }
    families.sample(
        "karyos_archive_listings_total",
        "counter",
        "Complete listings of the driver's Archive catalog.",
        &base,
        catalog.listings,
    );
    families.sample(
        "karyos_archive_listing_failures_total",
        "counter",
        "Failed attempts to list the driver's Archive catalog.",
        &base,
        catalog.failures,
    );
    if let Some(at) = catalog.listed_at {
        families.sample(
            "karyos_archive_listed_at_ns",
            "gauge",
            "Host monotonic nanoseconds when the last listing ended.",
            &base,
            at,
        );
    }
}

fn render_counter(families: &mut Families, dir: &str, source: &str, counter: &Counter) {
    let labels = [
        ("driver", dir.to_owned()),
        ("source", source.to_owned()),
        ("name", counter.label.clone()),
        ("stream", counter.stream.to_string()),
        ("lane", counter.lane.to_string()),
        ("kind", counter.kind.to_string()),
        ("participant", counter.participant.to_string()),
    ];
    let (name, kind, help) = match counter.type_id {
        TYPE_EVENT => ("karyos_events_total", "counter", "A CnC event counter."),
        TYPE_SPIN_TIME => (
            "karyos_spin_time_ns_total",
            "counter",
            "A CnC spin time counter, in nanoseconds.",
        ),
        TYPE_GAUGE => ("karyos_gauge", "gauge", "A CnC gauge."),
        TYPE_POSITION => ("karyos_position", "gauge", "A CnC position."),
        TYPE_TIMESTAMP => (
            "karyos_timestamp_ns",
            "gauge",
            "A CnC timestamp, host monotonic nanoseconds.",
        ),
        _ => (
            "karyos_value",
            "gauge",
            "A CnC cell of a type this exporter does not know.",
        ),
    };
    families.sample(name, kind, help, &labels, counter.value);
}

/// An application counter (R-CORE-3) in its own family, labelled with its
/// name, escaped as the text format requires, and its client; whether
/// `counter` is one.
fn render_application(families: &mut Families, dir: &str, counter: &Counter) -> bool {
    let (name, kind, help) = match counter.type_id {
        TYPE_APPLICATION_EVENT => (
            "karyos_application_events_total",
            "counter",
            "An application's event counter, registered by its client.",
        ),
        TYPE_APPLICATION_GAUGE => (
            "karyos_application_gauge",
            "gauge",
            "An application's gauge, registered by its client.",
        ),
        _ => return false,
    };
    let labels = [
        ("driver", dir.to_owned()),
        ("name", counter.label.clone()),
        ("client", counter.participant.to_string()),
    ];
    families.sample(name, kind, help, &labels, counter.value);
    true
}

/// Why the exporter could not start.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ExportError {
    /// The address is not a loopback address, and no TLS is configured.
    #[error(
        "{0} is not a loopback address: without TLS the exporter serves loopback only; configure TLS (--tls-cert and --tls-key, in a build with the exporter-tls feature) or expose it through a TLS-terminating sidecar or mesh"
    )]
    NotLoopback(SocketAddr),
    /// The TLS configuration was refused (karyos#887).
    #[cfg(feature = "exporter-tls")]
    #[error(transparent)]
    Tls(#[from] tls::TlsError),
    /// The operating system's error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// How a connection was answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Answered {
    /// `200` with the exposition.
    Metrics,
    /// `404` (another path), `405` (another method) or `400` (a request
    /// head that is not one).
    Refused,
    /// `401`: the exporter has a token, and the request did not carry it
    /// (karyos#734).
    Unauthorized,
    /// The client went away, or sent no request head in time.
    Dropped,
}

/// The exporter's listener.
#[derive(Debug)]
pub struct Exporter {
    listener: TcpListener,
    /// The bearer token every scrape must carry, when configured.
    token: Option<Token>,
    /// The TLS configuration every connection is served with, when
    /// configured (karyos#887).
    #[cfg(feature = "exporter-tls")]
    tls: Option<std::sync::Arc<rustls::ServerConfig>>,
}

/// A scrape token (`--token-file`, karyos#734): 32 to 256 bytes of visible
/// ASCII, read from a file that only its owner may read or write.
#[derive(Clone, PartialEq, Eq)]
pub struct Token(Vec<u8>);

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Token(..)")
    }
}

/// The shortest token, in bytes.
pub const MIN_TOKEN: usize = 32;
/// The longest token, in bytes.
pub const MAX_TOKEN: usize = 256;

/// Why a token file was refused.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TokenError {
    /// Group or others may read or write it.
    #[error("{} must be readable and writable by its owner only (mode 0600)", .0.display())]
    Mode(std::path::PathBuf),
    /// Not 32 to 256 bytes of visible ASCII, one final newline allowed.
    #[error("{} must hold 32 to 256 bytes of visible ASCII", .0.display())]
    Content(std::path::PathBuf),
    /// The operating system's error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl Token {
    /// The token in the file at `path`.
    ///
    /// # Errors
    ///
    /// [`TokenError::Mode`] when group or others have any access to it,
    /// [`TokenError::Content`] for a token of another length or with a
    /// byte that is not visible ASCII, and the operating system's errors.
    pub fn read(path: &std::path::Path) -> Result<Self, TokenError> {
        use std::io::Read as _;
        // One open: the mode is checked on the handle that is read, so a
        // file swapped or re-chmodded in between is never read unchecked.
        // A symlink is followed (a Kubernetes secret mount is one), and the
        // file it names is what is checked.
        let file = std::fs::File::open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if file.metadata()?.permissions().mode() & 0o077 != 0 {
                return Err(TokenError::Mode(path.to_path_buf()));
            }
        }
        // At most one byte past the longest token and its newline, so a
        // large file is never read whole.
        let limit = u64::try_from(MAX_TOKEN + 2).unwrap_or(u64::MAX);
        let mut bytes = Vec::with_capacity(MAX_TOKEN + 2);
        file.take(limit).read_to_end(&mut bytes)?;
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
        }
        Self::new(bytes).ok_or_else(|| TokenError::Content(path.to_path_buf()))
    }

    /// `bytes` as a token, if 32 to 256 bytes of visible ASCII.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Option<Self> {
        ((MIN_TOKEN..=MAX_TOKEN).contains(&bytes.len()) && bytes.iter().all(u8::is_ascii_graphic))
            .then_some(Self(bytes))
    }

    /// Whether `offered` is this token, in a time that depends on the
    /// lengths only, never on where the bytes differ.
    fn matches(&self, offered: &[u8]) -> bool {
        let mut difference = u8::from(offered.len() != self.0.len());
        for (index, byte) in self.0.iter().enumerate() {
            difference |= byte ^ offered.get(index).copied().unwrap_or(0);
        }
        difference == 0
    }
}

/// Listens on `address`, which must be a loopback address.
///
/// # Errors
///
/// [`ExportError::NotLoopback`] for any other address, and the operating
/// system's errors.
pub fn bind(address: SocketAddr) -> Result<Exporter, ExportError> {
    if !address.ip().is_loopback() {
        return Err(ExportError::NotLoopback(address));
    }
    let listener = TcpListener::bind(address)?;
    listener.set_nonblocking(true)?;
    Ok(Exporter {
        listener,
        token: None,
        #[cfg(feature = "exporter-tls")]
        tls: None,
    })
}

/// Listens on `address`, any address, serving every connection over TLS
/// 1.3 with `config` ([`tls::server_config`]; karyos#887). A connection
/// whose handshake fails is [`Answered::Dropped`].
///
/// # Errors
///
/// The operating system's errors.
#[cfg(feature = "exporter-tls")]
pub fn bind_tls(
    address: SocketAddr,
    config: std::sync::Arc<rustls::ServerConfig>,
) -> Result<Exporter, ExportError> {
    let listener = TcpListener::bind(address)?;
    listener.set_nonblocking(true)?;
    Ok(Exporter {
        listener,
        token: None,
        tls: Some(config),
    })
}

impl Exporter {
    /// Requires `token` on every scrape (`Authorization: Bearer`): a
    /// request without it, or with another, is answered `401`.
    #[must_use]
    pub fn with_token(mut self, token: Token) -> Self {
        self.token = Some(token);
        self
    }

    /// The address bound.
    ///
    /// # Errors
    ///
    /// The operating system's error.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Answers up to [`MAX_PER_POLL`] pending connections with `body`'s
    /// exposition. Never waits for a connection.
    ///
    /// # Errors
    ///
    /// The operating system's error when `accept` fails.
    pub fn poll(&mut self, body: impl Fn() -> String) -> Result<Vec<Answered>, ExportError> {
        let mut answered = Vec::new();
        while answered.len() < MAX_PER_POLL {
            match self.listener.accept() {
                Ok((stream, _)) => answered.push(self.answer(stream, &body)),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(answered)
    }

    /// Answers one connection, over TLS when configured.
    fn answer(&self, stream: TcpStream, body: &impl Fn() -> String) -> Answered {
        let ready = stream.set_nonblocking(false).is_ok()
            && stream.set_read_timeout(Some(IO_TIMEOUT)).is_ok()
            && stream.set_write_timeout(Some(IO_TIMEOUT)).is_ok();
        if !ready {
            return Answered::Dropped;
        }
        #[cfg(feature = "exporter-tls")]
        if let Some(config) = &self.tls {
            let Ok(connection) = rustls::ServerConnection::new(std::sync::Arc::clone(config))
            else {
                return Answered::Dropped;
            };
            let mut stream = rustls::StreamOwned::new(connection, stream);
            // The handshake, within the same timeouts.
            while stream.conn.is_handshaking() {
                if stream.conn.complete_io(&mut stream.sock).is_err() {
                    return Answered::Dropped;
                }
            }
            let answered = serve(&mut stream, self.token.as_ref(), body);
            stream.conn.send_close_notify();
            let _ = stream.conn.complete_io(&mut stream.sock);
            return answered;
        }
        let mut stream = stream;
        serve(&mut stream, self.token.as_ref(), body)
    }
}

/// Serves one request on `stream`, plain or TLS.
fn serve<S: Read + Write>(
    stream: &mut S,
    token: Option<&Token>,
    body: &impl Fn() -> String,
) -> Answered {
    let Some(limit) = u64::try_from(MAX_REQUEST).ok() else {
        return Answered::Dropped;
    };
    let mut reader = BufReader::new(Read::by_ref(stream).take(limit));
    let mut line = String::new();
    if !matches!(reader.read_line(&mut line), Ok(read) if read > 0) {
        return Answered::Dropped;
    }
    // The rest of the head, to its blank line, so the close does not reset
    // the connection over unread bytes; bounded by the same limit.
    // The token offered, if any: the last `Authorization: Bearer` header.
    let mut offered: Option<Vec<u8>> = None;
    // A header line that cannot be read (not UTF-8, or past the bound)
    // makes the whole head bad: an earlier header is never taken for the
    // last one (karyos#893, codex).
    let mut malformed = false;
    let mut header = String::new();
    loop {
        match reader.read_line(&mut header) {
            Ok(0) => break,
            Ok(_) if matches!(header.as_str(), "\r\n" | "\n") => break,
            Ok(_) => {}
            Err(_) => {
                malformed = true;
                break;
            }
        }
        if let Some((name, value)) = header.split_once(':')
            && name.trim().eq_ignore_ascii_case("authorization")
        {
            let value = value.trim();
            offered = value
                .get(..7)
                .filter(|scheme| scheme.eq_ignore_ascii_case("bearer "))
                .and_then(|_| value.get(7..))
                .map(|token| token.trim().as_bytes().to_vec());
        }
        header.clear();
    }
    drop(reader);
    let mut words = line.split_whitespace();
    let request = (words.next(), words.next(), words.next(), words.next());
    let authorized = token.is_none_or(|token| offered.as_deref().is_some_and(|o| token.matches(o)));
    let (status, answered, content) = match request {
        _ if malformed => (
            "400 Bad Request",
            Answered::Refused,
            "bad request\n".to_owned(),
        ),
        (Some(_), Some(_), Some(version), None) if !version.starts_with("HTTP/1.") => (
            "400 Bad Request",
            Answered::Refused,
            "bad request\n".to_owned(),
        ),
        (Some("GET"), Some("/metrics"), Some(_), None) if authorized => {
            ("200 OK", Answered::Metrics, body())
        }
        (Some("GET"), Some("/metrics"), Some(_), None) => (
            "401 Unauthorized",
            Answered::Unauthorized,
            "a bearer token is required\n".to_owned(),
        ),
        (Some("GET"), Some(_), Some(_), None) => {
            ("404 Not Found", Answered::Refused, "not found\n".to_owned())
        }
        (Some(_), Some(_), Some(_), None) => (
            "405 Method Not Allowed",
            Answered::Refused,
            "only GET /metrics\n".to_owned(),
        ),
        _ => (
            "400 Bad Request",
            Answered::Refused,
            "bad request\n".to_owned(),
        ),
    };
    let content_type = if answered == Answered::Metrics {
        CONTENT_TYPE
    } else {
        "text/plain; charset=utf-8"
    };
    let challenge = if answered == Answered::Unauthorized {
        "WWW-Authenticate: Bearer\r\n"
    } else {
        ""
    };
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{challenge}Connection: close\r\n\r\n",
        content.len()
    );
    let written = stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(content.as_bytes()))
        .and_then(|()| stream.flush());
    if written.is_err() {
        return Answered::Dropped;
    }
    answered
}

#[cfg(feature = "exporter-tls")]
pub mod tls;

#[cfg(test)]
mod tests;
