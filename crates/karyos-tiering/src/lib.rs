// SPDX-License-Identifier: Apache-2.0

//! The Archive's object storage client (quantstratum-docs: karyos/SPEC.md
//! §8.4, "Tiered storage"; karyos#965).
//!
//! [`S3Store`] implements `karyos_archive::integrity::tiering::ObjectStore`
//! over S3: `rusty-s3` signs each request (SigV4, as a presigned URL whose
//! signed headers the request carries), and `hyper`'s HTTP/1.1 client
//! sends it over `tokio-rustls`, TLS 1.3 only, with the server certificate
//! verified against roots the operator configures. The admission record's
//! conditions hold here:
//!
//! - this crate is the only one with these dependencies, it is not a
//!   default member, and `karyos-archive` does not depend on it: the
//!   recording path cannot reach object storage (`scripts/check-tiering-graph.sh`
//!   checks the graph);
//! - the TLS provider is `rustls-graviola`, pure Rust, and its CPU
//!   requirements are checked when the store is made ([`cpu::check`]),
//!   with a typed error, never a panic;
//! - credentials come from configuration, never from the environment.
//!
//! Each call runs on the store's own current-thread runtime and is bounded
//! by the configured timeout: the store is called from the control path.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use hyper::body::{Body, Bytes, Frame, Incoming, SizeHint};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use karyos_archive::integrity::copies::Enforcement;
use karyos_archive::integrity::tiering::{ObjectKey, ObjectStore};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use rusty_s3::{Bucket, Credentials, S3Action, UrlStyle};
use tokio_rustls::TlsConnector;

pub mod cpu;

/// How long a signed request stays valid.
const SIGNED_FOR: Duration = Duration::from_secs(300);

/// The most of an error response's body kept for its message: an error
/// body never counts against `max_object`, so a large one cannot hide the
/// status.
const ERROR_BODY: usize = 4096;

/// An object store's configuration. Nothing here has a default taken from
/// the environment. Its `Debug` output redacts the credentials.
#[derive(Clone)]
pub struct S3Config {
    /// The endpoint, `https://` only.
    pub endpoint: String,
    /// Path-style URLs (`https://host/bucket/key`) rather than virtual
    /// host ones.
    pub path_style: bool,
    /// The bucket.
    pub bucket: String,
    /// The region.
    pub region: String,
    /// The access key id.
    pub access_key: String,
    /// The secret access key.
    pub secret_key: String,
    /// The roots the server's certificate must chain to.
    pub roots: Vec<CertificateDer<'static>>,
    /// Whether objects are written under object-lock retention
    /// (`COMPLIANCE` mode until the copy's retention ends).
    pub object_lock: bool,
    /// The time one request may take, connect to last byte.
    pub timeout: Duration,
    /// The largest object read back, in bytes.
    pub max_object: usize,
}

impl std::fmt::Debug for S3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Config")
            .field("endpoint", &self.endpoint)
            .field("path_style", &self.path_style)
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("access_key", &"<redacted>")
            .field("secret_key", &"<redacted>")
            .field("roots", &self.roots.len())
            .field("object_lock", &self.object_lock)
            .field("timeout", &self.timeout)
            .field("max_object", &self.max_object)
            .finish()
    }
}

/// Why a store could not be made.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum S3Error {
    /// The TLS provider cannot run on this CPU.
    #[error(transparent)]
    Cpu(#[from] cpu::CpuError),
    /// The endpoint or bucket is not usable: not `https`, no host, or a
    /// bucket name the URL style cannot carry.
    #[error("object storage endpoint refused: {0}")]
    Endpoint(String),
    /// The TLS configuration was refused.
    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),
    /// The runtime could not be built.
    #[error("runtime: {0}")]
    Runtime(#[from] io::Error),
}

/// An object store on S3.
pub struct S3Store {
    bucket: Bucket,
    credentials: Credentials,
    tls: Arc<ClientConfig>,
    runtime: tokio::runtime::Runtime,
    object_lock: bool,
    timeout: Duration,
    max_object: usize,
}

impl std::fmt::Debug for S3Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Store")
            .field("bucket", &self.bucket.name())
            .field("object_lock", &self.object_lock)
            .finish_non_exhaustive()
    }
}

impl S3Store {
    /// A store for `config`, after checking the TLS provider's CPU
    /// requirements.
    ///
    /// # Errors
    ///
    /// [`S3Error`].
    pub fn new(config: S3Config) -> Result<Self, S3Error> {
        cpu::check()?;
        let endpoint = url::Url::parse(&config.endpoint)
            .map_err(|error| S3Error::Endpoint(error.to_string()))?;
        if endpoint.scheme() != "https" {
            return Err(S3Error::Endpoint("only https is allowed".to_owned()));
        }
        let style = if config.path_style {
            UrlStyle::Path
        } else {
            UrlStyle::VirtualHost
        };
        let bucket = Bucket::new(endpoint, style, config.bucket, config.region)
            .map_err(|error| S3Error::Endpoint(error.to_string()))?;
        let mut roots = RootCertStore::empty();
        for root in config.roots {
            roots.add(root)?;
        }
        let mut tls =
            ClientConfig::builder_with_provider(Arc::new(rustls_graviola::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_root_certificates(roots)
                .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()?;
        Ok(Self {
            bucket,
            credentials: Credentials::new(config.access_key, config.secret_key),
            tls: Arc::new(tls),
            runtime,
            object_lock: config.object_lock,
            timeout: config.timeout,
            max_object: config.max_object,
        })
    }

    /// Sends `method` to the signed `url` with the signed `headers` and
    /// `body`, within the timeout: the status and the body. A successful
    /// response's body is at most `max_object` bytes, or the call fails;
    /// an error response's is cut to [`ERROR_BODY`] bytes, so its status
    /// is never lost. Called from inside a Tokio runtime it returns an
    /// error, never blocking on (or panicking in) that runtime.
    fn send(
        &self,
        method: hyper::Method,
        url: &url::Url,
        headers: &[(String, String)],
        body: Option<Bytes>,
    ) -> io::Result<(StatusCode, Vec<u8>)> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(io::Error::other(
                "the object store is synchronous: call it outside a Tokio runtime",
            ));
        }
        let call = async {
            let host = url
                .host_str()
                .ok_or_else(|| io::Error::other("no host"))?
                .to_owned();
            let port = url.port_or_known_default().unwrap_or(443);
            let tcp = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
            let name = ServerName::try_from(host.clone()).map_err(io::Error::other)?;
            let tls = TlsConnector::from(Arc::clone(&self.tls))
                .connect(name, tcp)
                .await?;
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake::<_, Payload>(TokioIo::new(tls))
                    .await
                    .map_err(io::Error::other)?;
            // The connection's driver lives exactly as long as this call:
            // a timeout or an error drops the guard, which cancels it.
            let _driver = AbortOnDrop(tokio::spawn(connection));
            let path = match url.query() {
                Some(query) => format!("{}?{query}", url.path()),
                None => url.path().to_owned(),
            };
            let authority = match url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.clone(),
            };
            let length = body.as_ref().map_or(0, Bytes::len);
            let mut request = Request::builder()
                .method(method)
                .uri(path)
                .header(hyper::header::HOST, authority)
                .header(hyper::header::CONTENT_LENGTH, length);
            for (name, value) in headers {
                request = request.header(name.as_str(), value.as_str());
            }
            let request = request.body(Payload(body)).map_err(io::Error::other)?;
            let response = sender
                .send_request(request)
                .await
                .map_err(io::Error::other)?;
            let status = response.status();
            let bytes = if status.is_success() {
                body_within(response.into_body(), self.max_object)
                    .await
                    .ok_or_else(|| io::Error::other("object too large or cut short"))?
            } else {
                body_prefix(response.into_body(), ERROR_BODY).await
            };
            Ok::<_, io::Error>((status, bytes))
        };
        self.runtime.block_on(async {
            tokio::time::timeout(self.timeout, call)
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
        })
    }
}

impl ObjectStore for S3Store {
    fn put(
        &mut self,
        key: &ObjectKey,
        bytes: &[u8],
        retain_until_ns: u64,
    ) -> io::Result<Enforcement> {
        let name = key.name();
        let mut action = self.bucket.put_object(Some(&self.credentials), &name);
        // A SHA-256 checksum of the bytes on every PUT, signed with the
        // request: S3 requires one (or Content-MD5) for an upload under
        // object-lock retention, and it checks the bytes it stores.
        let mut headers = vec![
            (
                "x-amz-sdk-checksum-algorithm".to_owned(),
                "SHA256".to_owned(),
            ),
            ("x-amz-checksum-sha256".to_owned(), checksum_sha256(bytes)),
        ];
        if self.object_lock {
            let until = rfc3339(retain_until_ns);
            headers.push(("x-amz-object-lock-mode".to_owned(), "COMPLIANCE".to_owned()));
            headers.push(("x-amz-object-lock-retain-until-date".to_owned(), until));
        }
        for (header, value) in &headers {
            action.headers_mut().insert(header.clone(), value.clone());
        }
        let url = action.sign(SIGNED_FOR);
        let (status, body) = self.send(
            hyper::Method::PUT,
            &url,
            &headers,
            Some(Bytes::copy_from_slice(bytes)),
        )?;
        if status != StatusCode::OK {
            return Err(io::Error::other(format!(
                "PutObject {name}: status {status}: {}",
                String::from_utf8_lossy(&body)
            )));
        }
        Ok(if self.object_lock {
            Enforcement::ObjectLock
        } else {
            Enforcement::Unsupported
        })
    }

    fn get(&mut self, key: &ObjectKey) -> io::Result<Vec<u8>> {
        let name = key.name();
        let url = self
            .bucket
            .get_object(Some(&self.credentials), &name)
            .sign(SIGNED_FOR);
        let (status, body) = self.send(hyper::Method::GET, &url, &[], None)?;
        match status {
            StatusCode::OK => Ok(body),
            StatusCode::NOT_FOUND => Err(io::Error::from(io::ErrorKind::NotFound)),
            status => Err(io::Error::other(format!(
                "GetObject {name}: status {status}"
            ))),
        }
    }
}

/// A spawned task cancelled when this guard drops.
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The base64 of `bytes`' SHA-256, as S3's `x-amz-checksum-sha256` takes it.
#[must_use]
pub fn checksum_sha256(bytes: &[u8]) -> String {
    use graviola::hashing::{Hash, Sha256};
    base64(Sha256::hash(bytes).as_ref())
}

/// Standard base64 with padding.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3).saturating_mul(4));
    for chunk in bytes.chunks(3) {
        let b = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (index, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if index <= chunk.len() {
                let six = usize::try_from((n >> shift) & 0x3f).unwrap_or(0);
                out.push(char::from(ALPHABET.get(six).copied().unwrap_or(b'=')));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A request body of one frame.
struct Payload(Option<Bytes>);

impl Body for Payload {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        Poll::Ready(self.get_mut().0.take().map(|data| Ok(Frame::data(data))))
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(
            self.0
                .as_ref()
                .map_or(0, |data| u64::try_from(data.len()).unwrap_or(u64::MAX)),
        )
    }
}

/// The whole of `body`, at most `max` bytes.
async fn body_within(mut body: Incoming, max: usize) -> Option<Vec<u8>> {
    if body.size_hint().lower() > u64::try_from(max).ok()? {
        return None;
    }
    let mut out = Vec::new();
    loop {
        match std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
            None => return Some(out),
            Some(Err(_)) => return None,
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    if out.len().checked_add(data.len())? > max {
                        return None;
                    }
                    out.extend_from_slice(&data);
                }
            }
        }
    }
}

/// At most the first `max` bytes of `body`, read to its end so the
/// connection completes; what does not fit is dropped, never an error.
async fn body_prefix(mut body: Incoming, max: usize) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(Ok(frame)) = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await
    {
        if let Ok(data) = frame.into_data() {
            let room = max.saturating_sub(out.len());
            out.extend_from_slice(data.get(..room.min(data.len())).unwrap_or_default());
        }
    }
    out
}

/// `ns` of UTC as an RFC 3339 timestamp to the second, as S3's
/// `x-amz-object-lock-retain-until-date` takes it (rounded up, so the
/// retention never ends early).
#[must_use]
pub fn rfc3339(ns: u64) -> String {
    let seconds = ns.div_ceil(1_000_000_000);
    let days = seconds / 86_400;
    let rest = seconds % 86_400;
    let (year, month, day) = civil(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3_600,
        rest % 3_600 / 60,
        rest % 60
    )
}

/// The civil date of `days` since 1970-01-01 (Howard Hinnant's algorithm,
/// for days at or after the epoch).
const fn civil(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

#[cfg(test)]
mod tests;
