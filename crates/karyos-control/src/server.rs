// SPDX-License-Identifier: Apache-2.0

//! The HTTPS server: `hyper`'s HTTP/1.1 over `tokio-rustls`, on a
//! current-thread `tokio` runtime (the agent HTTP stack's admission
//! record).
//!
//! - **Routes.** `GET /v1/view` relays `view`; `GET /v1/capabilities`
//!   relays `capabilities`; `POST /v1/request` relays its body, one API v1
//!   request without its `KARYOS-AGENT 1` prefix (`guard-close DIR GUARD
//!   REASON`, `join-get DIR KIND KEY` and so on), at most
//!   [`relay::MAX_REQUEST`] bytes. Any other
//!   path is `404`, another method on a route `405`.
//! - **Answers.** The agent's answer is the body, unchanged, with `200`:
//!   an agent refusal (`forbidden`, `bad request`, `not authorized`) is
//!   its v1 JSON, as on the local socket. The component's own refusals are
//!   JSON objects too: `401` `{"error":"not authenticated"}` with neither
//!   a certificate nor a token; `401` `{"error":"invalid token",
//!   "reason":R}` with `WWW-Authenticate: Bearer error="invalid_token"`
//!   for a refused token (R is [`jwt::TokenError::reason`]); `503`
//!   `{"error":"token keys unavailable"}` when no fresh key set can verify
//!   a token ([`jwks`](crate::jwks)), never a grant; `403`
//!   `{"error":"not authorized"}` for a certificate pinned to no service;
//!   `400` `{"error":"bad request"}` for a body that is no request; `502`
//!   `{"error":"agent unavailable"}` when the agent cannot be reached or
//!   does not answer.
//! - **Who.** A request with `Authorization: Bearer TOKEN` is a person's,
//!   when an issuer is configured ([`Oidc`]): the token is verified
//!   ([`jwt`]) and its principal relayed, whatever certificate the client
//!   presented. Any other request is the service's whose pinned
//!   certificate the client presented. With an issuer configured, a client
//!   may connect without a certificate (a person's browser or console);
//!   a certificate it presents must still chain to the client CA.
//! - **Headers.** None is read but the method, the path, the body's length
//!   and `Authorization`. A header that claims a role or an identity
//!   reaches nothing, and so does a role claim in a token.
//! - **Bounds.** [`HANDSHAKE_TIMEOUT`] for the TLS handshake,
//!   [`HEADER_TIMEOUT`] for a request's head, [`CONNECTION_DEADLINE`] for
//!   a connection in all, one request per connection (no keep-alive), and
//!   [`ControlConfig::max_connections`] connections at once; one past it
//!   is closed at once.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use hyper::body::{Body, Bytes, Frame, Incoming, SizeHint};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::pki_types::CertificateDer;
use rustls::server::ServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use crate::jwks::{Jwks, KeysError};
use crate::{jwt, relay};

/// The time a client has to complete the TLS handshake.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// The time a client has to send a request's head.
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
/// The time a connection may last in all.
pub const CONNECTION_DEADLINE: Duration = Duration::from_secs(30);
/// The connections served at once by default.
pub const DEFAULT_MAX_CONNECTIONS: usize = 64;

/// A service: the certificate it presents, pinned, and the principal name
/// its requests are relayed for.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Service {
    /// The principal name, as the agent's principal table names it.
    pub name: String,
    /// Its end-entity certificate, compared byte for byte.
    pub certificate: CertificateDer<'static>,
}

impl Service {
    /// Service `name` presenting `certificate`; `None` for a name that is
    /// not a principal name.
    #[must_use]
    pub fn new(name: &str, certificate: CertificateDer<'static>) -> Option<Self> {
        relay::valid_principal(name).then(|| Self {
            name: name.to_owned(),
            certificate,
        })
    }
}

/// What the component serves, and where it relays.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ControlConfig {
    /// The TLS configuration ([`crate::tls::server_config`]).
    pub tls: Arc<ServerConfig>,
    /// The services, by their pinned certificates.
    pub services: Vec<Service>,
    /// The agent's API socket.
    pub agent_socket: PathBuf,
    /// The connections served at once.
    pub max_connections: usize,
    /// The issuer whose agent-audience access tokens people present.
    pub oidc: Option<Arc<Oidc>>,
}

/// People's sign-in (owner item 43): the issuer's access tokens, verified
/// under `policy` with `keys`. The sign-in itself, the authorization code
/// flow with PKCE, runs in the console, which presents the token.
#[derive(Debug)]
#[non_exhaustive]
pub struct Oidc {
    /// What a token must satisfy.
    pub policy: jwt::Policy,
    /// The issuer's key sets.
    pub keys: Jwks,
}

impl Oidc {
    /// Tokens under `policy`, verified with `keys`.
    #[must_use]
    pub fn new(policy: jwt::Policy, keys: Jwks) -> Self {
        Self { policy, keys }
    }

    /// The principal of bearer `token`, verified now.
    ///
    /// # Errors
    ///
    /// The token's refusal, or [`KeysError`] when no fresh key set can
    /// verify it.
    pub async fn principal(
        &self,
        token: &str,
    ) -> Result<Result<String, jwt::TokenError>, KeysError> {
        let parsed = match jwt::parse(token, &self.policy) {
            Ok(parsed) => parsed,
            Err(error) => return Ok(Err(error)),
        };
        let keys = self.keys.keys_for(parsed.kid()).await?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        Ok(jwt::verify(&parsed, &keys, &self.policy, now))
    }
}

impl ControlConfig {
    /// Serving `services` with `tls`, relaying to `agent_socket`.
    #[must_use]
    pub fn new(tls: Arc<ServerConfig>, services: Vec<Service>, agent_socket: PathBuf) -> Self {
        Self {
            tls,
            services,
            agent_socket,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            oidc: None,
        }
    }

    /// The same, taking people's tokens with `oidc`. The TLS configuration
    /// should then not require a client certificate
    /// ([`crate::tls::ClientAuth::Optional`]).
    #[must_use]
    pub fn with_oidc(mut self, oidc: Oidc) -> Self {
        self.oidc = Some(Arc::new(oidc));
        self
    }

    /// The same, serving `max_connections` at once.
    #[must_use]
    pub fn with_max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = max_connections;
        self
    }
}

/// Why the component stopped.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ControlError {
    /// The operating system's error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// The state every connection shares.
struct Shared {
    acceptor: TlsAcceptor,
    services: Vec<Service>,
    agent_socket: PathBuf,
    max_connections: usize,
    connections: AtomicUsize,
    oidc: Option<Arc<Oidc>>,
}

/// One connection's place among [`ControlConfig::max_connections`],
/// given back when dropped.
struct Slot(Arc<Shared>);

impl Slot {
    fn take(shared: &Arc<Shared>) -> Option<Self> {
        let taken = shared
            .connections
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < shared.max_connections).then(|| count.saturating_add(1))
            });
        taken.is_ok().then(|| Self(Arc::clone(shared)))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let _ = self
            .0
            .connections
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                Some(count.saturating_sub(1))
            });
    }
}

/// The component, listening.
pub struct Control {
    listener: TcpListener,
    shared: Arc<Shared>,
}

impl std::fmt::Debug for Control {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Control")
            .field("listener", &self.listener)
            .field("agent_socket", &self.shared.agent_socket)
            .finish_non_exhaustive()
    }
}

impl Control {
    /// Listens on `address` (call within a `tokio` runtime).
    ///
    /// # Errors
    ///
    /// The operating system's error.
    pub async fn bind(address: SocketAddr, config: ControlConfig) -> Result<Self, ControlError> {
        let listener = TcpListener::bind(address).await?;
        Ok(Self {
            listener,
            shared: Arc::new(Shared {
                acceptor: TlsAcceptor::from(config.tls),
                services: config.services,
                agent_socket: config.agent_socket,
                max_connections: config.max_connections,
                connections: AtomicUsize::new(0),
                oidc: config.oidc,
            }),
        })
    }

    /// The address it listens on.
    ///
    /// # Errors
    ///
    /// The operating system's error.
    pub fn local_addr(&self) -> Result<SocketAddr, ControlError> {
        Ok(self.listener.local_addr()?)
    }

    /// Serves connections until accepting fails.
    ///
    /// # Errors
    ///
    /// The operating system's error when `accept` fails.
    pub async fn serve(self) -> Result<(), ControlError> {
        loop {
            let (tcp, _) = self.listener.accept().await?;
            let Some(slot) = Slot::take(&self.shared) else {
                drop(tcp);
                continue;
            };
            // Detached: the task ends with its connection.
            drop(tokio::spawn(connection(slot, tcp)));
        }
    }
}

/// Serves `address` with `config` on a current-thread runtime until
/// accepting fails.
///
/// # Errors
///
/// [`ControlError`] when the runtime cannot start, the address cannot be
/// bound or accepting fails.
pub fn run(address: SocketAddr, config: ControlConfig) -> Result<(), ControlError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;
    runtime.block_on(async { Control::bind(address, config).await?.serve().await })
}

/// One connection: the handshake, then one request.
async fn connection(slot: Slot, tcp: TcpStream) {
    let shared = Arc::clone(&slot.0);
    let Ok(Ok(tls)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, shared.acceptor.accept(tcp)).await
    else {
        return;
    };
    let presented = tls.get_ref().1.peer_certificates();
    let channel = match principal(&shared.services, presented) {
        Some(name) => Channel::Service(name),
        None if presented.is_some_and(|chain| !chain.is_empty()) => Channel::Unpinned,
        None => Channel::Anonymous,
    };
    let service = hyper::service::service_fn(move |request| {
        handle(Arc::clone(&shared), channel.clone(), request)
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    let _ = builder
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT)
        .keep_alive(false);
    let _ = tokio::time::timeout(
        CONNECTION_DEADLINE,
        builder.serve_connection(TokioIo::new(tls), service),
    )
    .await;
    drop(slot);
}

/// The principal name of the service whose pinned certificate is the
/// client's end-entity certificate, if any.
fn principal(services: &[Service], presented: Option<&[CertificateDer<'_>]>) -> Option<String> {
    let presented = presented?.first()?;
    services
        .iter()
        .find(|service| service.certificate.as_ref() == presented.as_ref())
        .map(|service| service.name.clone())
}

/// What the client's certificate made of the connection.
#[derive(Debug, Clone)]
enum Channel {
    /// A pinned service's.
    Service(String),
    /// A certificate of the client CA pinned to no service.
    Unpinned,
    /// No certificate.
    Anonymous,
}

/// A whole body, sent as one frame.
#[derive(Debug)]
pub struct Reply(Option<Bytes>);

impl Reply {
    /// An empty body.
    #[must_use]
    pub const fn empty() -> Self {
        Self(None)
    }
}

impl Body for Reply {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Poll::Ready(self.get_mut().0.take().map(|data| Ok(Frame::data(data))))
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.0.as_ref().map_or(0, |data| data.len() as u64))
    }
}

/// A JSON answer with `status`.
fn json(status: StatusCode, body: impl Into<Bytes>) -> Response<Reply> {
    let mut response = Response::new(Reply(Some(body.into())));
    *response.status_mut() = status;
    let _ = response.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    response
}

/// The component's own refusal `error` with `status`.
fn refusal(status: StatusCode, error: &'static str) -> Response<Reply> {
    json(status, format!("{{\"error\":\"{error}\"}}\n"))
}

/// The body of `body`, at most `max` bytes; `None` past it or on error.
async fn body_within(mut body: Incoming, max: usize) -> Option<Vec<u8>> {
    if body.size_hint().lower() > max as u64 {
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

/// A refused token's answer.
fn invalid_token(error: jwt::TokenError) -> Response<Reply> {
    let mut response = json(
        StatusCode::UNAUTHORIZED,
        format!(
            "{{\"error\":\"invalid token\",\"reason\":\"{}\"}}\n",
            error.reason()
        ),
    );
    let _ = response.headers_mut().insert(
        hyper::header::WWW_AUTHENTICATE,
        hyper::header::HeaderValue::from_static("Bearer error=\"invalid_token\""),
    );
    response
}

/// The principal a request is relayed for, or the answer refusing it.
async fn authenticate(
    shared: &Shared,
    channel: Channel,
    authorization: Option<&hyper::header::HeaderValue>,
) -> Result<String, Box<Response<Reply>>> {
    let Some(authorization) = authorization else {
        return match channel {
            Channel::Service(name) => Ok(name),
            Channel::Unpinned => Err(Box::new(refusal(StatusCode::FORBIDDEN, "not authorized"))),
            Channel::Anonymous => Err(Box::new(refusal(
                StatusCode::UNAUTHORIZED,
                "not authenticated",
            ))),
        };
    };
    let token = authorization
        .to_str()
        .ok()
        .and_then(|value| value.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .map(|(_, token)| token.trim());
    let (Some(token), Some(oidc)) = (token, shared.oidc.as_deref()) else {
        return Err(Box::new(invalid_token(jwt::TokenError::Malformed)));
    };
    match oidc.principal(token).await {
        Ok(Ok(principal)) => Ok(principal),
        Ok(Err(error)) => Err(Box::new(invalid_token(error))),
        Err(KeysError::Unavailable) => Err(Box::new(refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "token keys unavailable",
        ))),
    }
}

/// Answers one request on `channel`.
async fn handle(
    shared: Arc<Shared>,
    channel: Channel,
    request: Request<Incoming>,
) -> Result<Response<Reply>, Infallible> {
    let route = match (request.uri().path(), request.method()) {
        ("/v1/view", &Method::GET) => Some("view".to_owned()),
        ("/v1/capabilities", &Method::GET) => Some("capabilities".to_owned()),
        ("/v1/request", &Method::POST) => None,
        ("/v1/view" | "/v1/capabilities" | "/v1/request", _) => {
            return Ok(refusal(
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed",
            ));
        }
        _ => return Ok(refusal(StatusCode::NOT_FOUND, "not found")),
    };
    let authorization = request.headers().get(hyper::header::AUTHORIZATION);
    let principal = match authenticate(&shared, channel, authorization).await {
        Ok(principal) => principal,
        Err(answer) => return Ok(*answer),
    };
    let text = match route {
        Some(text) => text,
        None => {
            let body = body_within(request.into_body(), relay::MAX_REQUEST).await;
            match body.and_then(|body| String::from_utf8(body).ok()) {
                Some(text) => text,
                None => return Ok(refusal(StatusCode::BAD_REQUEST, "bad request")),
            }
        }
    };
    let Ok(line) = relay::line(&principal, &text) else {
        return Ok(refusal(StatusCode::BAD_REQUEST, "bad request"));
    };
    let socket = shared.agent_socket.clone();
    match tokio::task::spawn_blocking(move || relay::relay(&socket, &line)).await {
        Ok(Ok(answer)) => Ok(json(StatusCode::OK, answer)),
        _ => Ok(refusal(StatusCode::BAD_GATEWAY, "agent unavailable")),
    }
}
