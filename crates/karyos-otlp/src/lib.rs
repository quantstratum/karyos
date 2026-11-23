// SPDX-License-Identifier: Apache-2.0

//! OTLP metrics export of the agent's view (SPEC.md §14, the
//! `karyos-exporter` row; karyos#706; quantstratum-docs:
//! karyos/reviews/dependency-admission-opentelemetry.md).
//!
//! - **What.** [`OtlpExport`] pushes the metric families of
//!   [`karyos_agent::exporter::families`], the same definition the
//!   Prometheus exposition is written from, so the two views never differ
//!   in a name, a label or a value. A `counter` family is an OTLP
//!   cumulative monotonic sum, a `gauge` family an OTLP gauge; every value
//!   is a `u64`. Each family name of
//!   [`FAMILIES`] is one instrument, read
//!   from the last [`OtlpExport::publish`]ed pass.
//! - **How.** OTLP/HTTP with binary protobuf, HTTP/1.1 in clear, to
//!   `http://ADDRESS:PORT/v1/metrics`, from the SDK's periodic reader at
//!   the configured interval. Requests run on a current-thread `tokio`
//!   runtime on a thread of their own ([`Client`]), each bounded by the
//!   request timeout, with at most [`MAX_RESPONSE`] bytes of response
//!   read. Only a loopback collector is accepted unless
//!   [`OtlpConfig::allow_remote`] (then `karyos-exporter-otlp` writes a
//!   warning at start).
//! - **Off by default.** Nothing here runs unless a collector is
//!   configured (`karyos-exporter-otlp --otlp-endpoint`); owner item 51's
//!   "no OTLP yet" interim stays the default, as the admission record's
//!   condition 6 requires.
//! - **A collector down or slow** never blocks the agent: [`OtlpExport::publish`]
//!   only swaps the pass under a lock, and export runs on the reader's and
//!   the runtime's threads. A failed export is dropped, not queued: the
//!   SDK keeps one cumulative point per series, so memory does not grow
//!   with the outage.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use karyos_agent::exporter::{FAMILIES, MetricFamily, MetricKind, MetricValue, SIGNED_FAMILIES};
use opentelemetry::KeyValue;
use opentelemetry::metrics::{AsyncInstrument, MeterProvider as _};
use opentelemetry_http::{HttpClient, HttpError, Request, Response};
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};

/// The longest response body read from the collector, in bytes.
pub const MAX_RESPONSE: usize = 64 * 1024;
/// The default export interval.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(10);
/// The default request timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Where and how often to export.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OtlpConfig {
    /// The collector's OTLP/HTTP address.
    pub endpoint: SocketAddr,
    /// The export interval.
    pub interval: Duration,
    /// Each request's timeout, its connection and response included.
    pub timeout: Duration,
    /// A non-loopback collector is accepted (with a warning at start).
    pub allow_remote: bool,
}

impl OtlpConfig {
    /// A loopback collector at `endpoint`, with the default interval and
    /// timeout.
    #[must_use]
    pub fn new(endpoint: SocketAddr) -> Self {
        Self {
            endpoint,
            interval: DEFAULT_INTERVAL,
            timeout: DEFAULT_TIMEOUT,
            allow_remote: false,
        }
    }

    /// With the export `interval`.
    #[must_use]
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// With each request's `timeout`.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Accepting a non-loopback collector.
    #[must_use]
    pub fn allowing_remote(mut self) -> Self {
        self.allow_remote = true;
        self
    }
}

/// Why the export could not start or flush.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OtlpError {
    /// A non-loopback collector without [`OtlpConfig::allow_remote`].
    #[error(
        "{0} is not a loopback address: a remote collector needs --otlp-allow-remote (OTLP is sent in clear)"
    )]
    NotLoopback(SocketAddr),
    /// The runtime or its thread could not start.
    #[error("the export runtime: {0}")]
    Runtime(#[from] std::io::Error),
    /// The OTLP exporter could not be built.
    #[error("the OTLP exporter: {0}")]
    Build(String),
    /// An export or a flush failed.
    #[error("the export: {0}")]
    Export(String),
}

/// The last sampling pass, which the instruments' callbacks read.
type Pass = Arc<Mutex<Vec<MetricFamily>>>;

/// The OTLP export of the agent's view: see the module docs.
#[derive(Debug)]
pub struct OtlpExport {
    provider: SdkMeterProvider,
    pass: Pass,
    runtime: Runtime,
}

impl OtlpExport {
    /// Starts exporting to `config`'s collector. Nothing is sent before
    /// the first [`OtlpExport::publish`].
    ///
    /// # Errors
    ///
    /// [`OtlpError::NotLoopback`] for a remote collector not allowed,
    /// [`OtlpError::Runtime`] and [`OtlpError::Build`].
    pub fn start(config: &OtlpConfig) -> Result<Self, OtlpError> {
        if !config.endpoint.ip().is_loopback() && !config.allow_remote {
            return Err(OtlpError::NotLoopback(config.endpoint));
        }
        let runtime = Runtime::start()?;
        let client = Client {
            handle: runtime.handle.clone(),
            timeout: config.timeout,
        };
        let exporter = opentelemetry_otlp::MetricExporter::builder()
            .with_http()
            .with_http_client(client)
            .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
            .with_endpoint(format!("http://{}/v1/metrics", config.endpoint))
            .with_timeout(config.timeout)
            .build()
            .map_err(|error| OtlpError::Build(error.to_string()))?;
        let reader = PeriodicReader::builder(exporter)
            .with_interval(config.interval)
            .build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let pass: Pass = Arc::new(Mutex::new(Vec::new()));
        register(&provider, &pass);
        Ok(Self {
            provider,
            pass,
            runtime,
        })
    }

    /// Replaces the pass exported with `families`, the agent's latest.
    /// Never waits on the collector.
    pub fn publish(&self, families: Vec<MetricFamily>) {
        *self.pass.lock().unwrap_or_else(PoisonError::into_inner) = families;
    }

    /// Exports the current pass now, waiting for the collector's answer
    /// (bounded by the request timeout).
    ///
    /// # Errors
    ///
    /// [`OtlpError::Export`] when the export fails.
    pub fn flush(&self) -> Result<(), OtlpError> {
        self.provider
            .force_flush()
            .map_err(|error| OtlpError::Export(error.to_string()))
    }

    /// Exports what is left and stops.
    ///
    /// # Errors
    ///
    /// [`OtlpError::Export`] when the last export fails.
    pub fn shutdown(self) -> Result<(), OtlpError> {
        let result = self
            .provider
            .shutdown()
            .map_err(|error| OtlpError::Export(error.to_string()));
        drop(self.runtime);
        result
    }
}

/// One observable instrument per family name, reading the last pass: a
/// `counter` family a `u64` observable counter, a `gauge` family a `u64`
/// or, for [`SIGNED_FAMILIES`], an `i64` observable gauge.
fn register(provider: &SdkMeterProvider, pass: &Pass) {
    let meter = provider.meter("karyos-exporter");
    for (name, kind, _) in FAMILIES {
        if SIGNED_FAMILIES.contains(&name) {
            let pass = Arc::clone(pass);
            let _gauge = meter
                .i64_observable_gauge(name)
                .with_callback(move |observer| {
                    observe(&pass, name, |value, attributes| {
                        if let MetricValue::Signed(value) = value {
                            observer.observe(value, attributes);
                        }
                    });
                })
                .build();
            continue;
        }
        let pass = Arc::clone(pass);
        let unsigned = move |observer: &dyn AsyncInstrument<u64>| {
            observe(&pass, name, |value, attributes| {
                if let MetricValue::Unsigned(value) = value {
                    observer.observe(value, attributes);
                }
            });
        };
        if kind == MetricKind::Counter.name() {
            let _counter = meter
                .u64_observable_counter(name)
                .with_callback(move |observer| unsigned(observer))
                .build();
        } else {
            let _gauge = meter
                .u64_observable_gauge(name)
                .with_callback(move |observer| unsigned(observer))
                .build();
        }
    }
}

/// Calls `record` with each sample of family `name` in the last pass.
fn observe(pass: &Pass, name: &str, mut record: impl FnMut(MetricValue, &[KeyValue])) {
    let pass = pass.lock().unwrap_or_else(PoisonError::into_inner);
    for family in pass.iter().filter(|family| family.name == name) {
        for sample in &family.samples {
            let attributes: Vec<KeyValue> = sample
                .labels
                .iter()
                .map(|(key, value)| KeyValue::new(*key, value.clone()))
                .collect();
            record(sample.value, &attributes);
        }
    }
}

/// A current-thread `tokio` runtime driven by a thread of its own, on
/// which every request runs.
#[derive(Debug)]
struct Runtime {
    handle: tokio::runtime::Handle,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Runtime {
    fn start() -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let handle = runtime.handle().clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("karyos-otlp".to_owned())
            .spawn(move || {
                runtime.block_on(async move {
                    while !stopping.load(Ordering::Acquire) {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                });
            })?;
        Ok(Self {
            handle,
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The exporter's own `HttpClient` (the admission record's condition 4):
/// each request runs on the exporter's own runtime, over `hyper`'s HTTP/1.1 client on
/// plain TCP, within `timeout`, reading at most [`MAX_RESPONSE`] bytes of
/// answer. The reader's thread only awaits the join handle, which needs
/// no `tokio` context.
#[derive(Debug)]
pub struct Client {
    handle: tokio::runtime::Handle,
    timeout: Duration,
}

#[async_trait::async_trait]
impl HttpClient for Client {
    async fn send_bytes(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let timeout = self.timeout;
        self.handle
            .spawn(async move {
                match tokio::time::timeout(timeout, send(request)).await {
                    Ok(answer) => answer,
                    Err(_) => Err(HttpError::from("the collector did not answer in time")),
                }
            })
            .await
            .map_err(|error| HttpError::from(error.to_string()))?
    }
}

/// Sends `request` over one HTTP/1.1 connection to its URI's authority.
async fn send(request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
    let authority = request
        .uri()
        .authority()
        .ok_or_else(|| HttpError::from("no authority in the URI"))?
        .as_str()
        .to_owned();
    let stream = tokio::net::TcpStream::connect(authority).await?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await?;
    let driving = tokio::spawn(connection);
    let (parts, body) = request.into_parts();
    let answer = sender
        .send_request(hyper::Request::from_parts(parts, Full::new(body)))
        .await?;
    let (parts, body) = answer.into_parts();
    let body = Limited::new(body, MAX_RESPONSE).collect().await?.to_bytes();
    driving.abort();
    Ok(Response::from_parts(parts, body))
}
