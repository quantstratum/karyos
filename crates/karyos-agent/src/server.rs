// SPDX-License-Identifier: Apache-2.0

//! API v1 over a local Unix socket (quantstratum-docs:
//! karyos/design/management-agent-gap-analysis.md, M7; owner item 51,
//! interims 1 to 3: a local socket with the peer's uid checked, a uid to
//! role table, JSON written by hand).
//!
//! - **Where.** `agent.sock` ([`SOCKET_NAME`]) in the API directory, which
//!   is created with mode `0700` or must already be a private directory of
//!   this uid; the socket has mode `0600`. A stale socket (one that
//!   refuses connections) is replaced; a live agent's never is.
//! - **Who.** The peer's uid (`SO_PEERCRED`) is looked up in the role
//!   table; a uid not in it is answered `not authorized`. Every role may
//!   read; the roles bound the guard operations (M10b, item 2 interim:
//!   [`Role::may_close`], [`Role::may_reopen`], [`Role::may_acknowledge`]),
//!   and an operation the role may not make is answered `forbidden`.
//! - **Exchange.** One request per connection: a line `KARYOS-AGENT
//!   <version> <request>`, at most [`MAX_REQUEST`] bytes. The answer is one
//!   JSON object and a newline, then the agent closes the connection. A
//!   version other than [`API_VERSION`] is answered with the versions
//!   supported (`{"error":"unsupported version","supported":[1]}`), so a
//!   client learns what to ask for. Requests: `view` (the whole
//!   [`AgentView`](crate::api::AgentView)); `guard-close DIR GUARD
//!   [REASON]` and `guard-reopen DIR GUARD EPOCH [REASON]`, made for the
//!   peer's uid as the operator, the reason being the rest of the line
//!   (M10b; a `DIR` holds no space); `gap-ack POSITION`, an
//!   administrator's acknowledgement of the journal's unknown interval;
//!   `limits [DIMENSION=VALUE ...]`, the negotiation of the bounds below
//!   (R-CORE-38); `capabilities`, each capability of the closed v1 list
//!   served, unavailable in this deployment or forbidden for the peer's
//!   role (R-CORE-24). A request this agent knows with arguments it does
//!   not take is `{"error":"bad arguments","request":NAME}`.
//! - **Bounds.** Each connection is served on the calling thread with
//!   [`IO_TIMEOUT`] on its reads and each write, and [`WRITE_DEADLINE`] on
//!   writing its whole reply, checked after every write; one poll starts
//!   connections for [`POLL_BUDGET`] at most: a client that reads a large reply too slowly
//!   gets it cut short, never the polling thread held for longer, and the
//!   connection closed. A reply without a final newline, followed by EOF,
//!   is incomplete and is discarded; the reader retries with the same
//!   cursor, as reading consumes nothing.
//! - **Limits (R-CORE-38).** `limits` answers every dimension of [`LIMITS`]
//!   with one of three answers, never "unknown": `{"value":N,
//!   "negotiable":true}`, a bound a client may propose within;
//!   `{"value":N,"negotiable":false}`, a fixed bound; `{"value":null}`, no
//!   bound. A client may propose values: a proposal above a bound is
//!   refused with the bound (`{"error":"above bound","dimension":D,
//!   "bound":N}`); any other is answered with the effective value, which
//!   for a fixed bound is the bound. The exchange is stateless, like every
//!   v1 request: a negotiated value that a later request uses is repeated
//!   in that request and applies to it only, so no client changes
//!   another's. In v1 only `read.request_bytes` is negotiable, downwards:
//!   a proposal at or below 256 is the effective value and applies to the
//!   `limits` request itself, whose line, its newline included, must fit
//!   it. A proposal for a
//!   dimension the agent does not know is refused by name
//!   (`{"error":"unknown dimension","dimension":D}`), never as `bad
//!   request`. A client reads "limits not supported" only from `bad
//!   request` to `limits` without proposals, never as "no limits". A
//!   future dimension, such as the page
//!   sizes of R-CORE-13 and R-CORE-14, enters [`LIMITS`] as a new entry,
//!   negotiable or not, and a v1 client that does not name it is unaffected.

use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::api::{API_VERSION, Limit};
use crate::{Agent, json};

/// The API socket's name in its directory.
pub const SOCKET_NAME: &str = "agent.sock";
/// The first word of every request.
pub const PROTOCOL: &str = "KARYOS-AGENT";
/// The longest request line, in bytes.
pub const MAX_REQUEST: usize = 256;
/// The read and write timeout of each connection.
pub const IO_TIMEOUT: Duration = Duration::from_millis(100);
/// The time a whole reply may take to write: past it, the reply is cut
/// short and the connection closed (`Served::Dropped`).
pub const WRITE_DEADLINE: Duration = Duration::from_millis(250);
/// The time a whole request may take to read: past it, the connection is
/// dropped unanswered.
pub const READ_DEADLINE: Duration = Duration::from_millis(250);
/// The bytes of one write of a reply at most.
const WRITE_CHUNK: usize = 64 << 10;
/// The time one [`Server::poll`] starts connections in. One started before
/// it may still take [`READ_DEADLINE`] to read and [`WRITE_DEADLINE`] to
/// answer, besides the work of building its answer (an export page is
/// bounded by its count and bytes, and waits for busy journal entries 1 ms
/// at most), so a poll's waiting on clients is at
/// most `POLL_BUDGET + READ_DEADLINE + WRITE_DEADLINE`, 1 s, however many
/// clients wait.
pub const POLL_BUDGET: Duration = Duration::from_millis(500);
/// Connections one [`Server::poll`] serves at most; the rest wait for the
/// next poll, so a burst of clients cannot hold the polling thread.
pub const MAX_ACCEPTS: usize = 16;

/// The dimensions `limits` answers, their bounds being the constants
/// above. Only `read.request_bytes` is negotiable in v1, and only
/// downwards: no bound is raised. The `trace.*` dimensions are the
/// driver's application trace point bounds (R-CORE-1): the ids an instance
/// assigns, a protocol constant, and the per-client bounds at the
/// driver's built-in defaults: the CnC does not expose a driver's
/// configured values, so a `karyosd` started with others is not reflected
/// (a follow-up).
pub const LIMITS: [Limit; 11] = [
    Limit {
        name: "read.request_bytes",
        bound: Some(MAX_REQUEST as u64),
        negotiable: true,
    },
    Limit {
        name: "read.timeout_ms",
        bound: Some(IO_TIMEOUT.as_millis() as u64),
        negotiable: false,
    },
    Limit {
        name: "read.deadline_ms",
        bound: Some(READ_DEADLINE.as_millis() as u64),
        negotiable: false,
    },
    Limit {
        name: "write.timeout_ms",
        bound: Some(IO_TIMEOUT.as_millis() as u64),
        negotiable: false,
    },
    Limit {
        name: "write.deadline_ms",
        bound: Some(WRITE_DEADLINE.as_millis() as u64),
        negotiable: false,
    },
    Limit {
        name: "write.response_bytes",
        bound: None,
        negotiable: false,
    },
    Limit {
        name: "connection.accepts_per_poll",
        bound: Some(MAX_ACCEPTS as u64),
        negotiable: false,
    },
    Limit {
        name: "connection.requests",
        bound: Some(1),
        negotiable: false,
    },
    Limit {
        name: "trace.point_ids",
        bound: Some(u16::MAX as u64),
        negotiable: false,
    },
    Limit {
        name: "trace.points_per_client",
        bound: Some(16),
        negotiable: false,
    },
    Limit {
        name: "trace.point_registrations_per_client",
        bound: Some(256),
        negotiable: false,
    },
];

/// Why a `limits` proposal was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal<'a> {
    /// Above this limit's bound.
    Above(Limit),
    /// A dimension this agent does not know.
    Unknown(&'a str),
    /// Malformed or repeated.
    Bad,
}

/// The effective value of each of `limits` given `proposals`
/// (`DIMENSION=VALUE` separated by single spaces), in `limits` order: a
/// negotiable dimension takes its proposal, any other keeps its bound.
fn negotiate<'a, const N: usize>(
    limits: &[Limit; N],
    proposals: &'a str,
) -> Result<[Option<u64>; N], Refusal<'a>> {
    let mut effective = limits.map(|limit| limit.bound);
    let mut proposed = [false; N];
    for proposal in proposals.split(' ').filter(|_| !proposals.is_empty()) {
        let (name, value) = proposal.split_once('=').ok_or(Refusal::Bad)?;
        let value = value.parse::<u64>().map_err(|_| Refusal::Bad)?;
        let ((limit, slot), seen) = limits
            .iter()
            .zip(effective.iter_mut())
            .zip(proposed.iter_mut())
            .find(|((limit, _), _)| limit.name == name)
            .ok_or(Refusal::Unknown(name))?;
        if core::mem::replace(seen, true) {
            return Err(Refusal::Bad);
        }
        if limit.bound.is_some_and(|bound| value > bound) {
            return Err(Refusal::Above(*limit));
        }
        if limit.negotiable {
            *slot = Some(value);
        }
    }
    Ok(effective)
}

/// The negotiated `read.request_bytes` applied to the request `line` that
/// negotiated it: `Some` with the negotiated bound when the line, its
/// newline included as [`parse`] counts it against [`MAX_REQUEST`], is
/// longer.
fn request_within<const N: usize>(
    line: &str,
    limits: &[Limit; N],
    effective: &[Option<u64>; N],
) -> Option<Limit> {
    let length = u64::try_from(line.len()).ok()?;
    limits
        .iter()
        .zip(effective)
        .find(|(limit, _)| limit.name == "read.request_bytes")
        .and_then(|(limit, bound)| {
            bound.filter(|bound| length > *bound).map(|bound| Limit {
                bound: Some(bound),
                ..*limit
            })
        })
}

/// What an operator may do (SPEC §11, access control). Every API v1
/// request reads, which every role may.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Role {
    /// Reads.
    Viewer,
    /// Reads and operates (guards, M10).
    Operator,
    /// An operator who may also reopen guards (M10).
    RiskOfficer,
    /// Everything, the configuration included.
    Administrator,
}

impl Role {
    /// Whether the role may close a guard: an operator or a risk officer
    /// (interim matrix, owner item 2).
    #[must_use]
    pub const fn may_close(self) -> bool {
        matches!(self, Self::Operator | Self::RiskOfficer)
    }

    /// Whether the role may reopen a guard: a risk officer or an
    /// administrator.
    #[must_use]
    pub const fn may_reopen(self) -> bool {
        matches!(self, Self::RiskOfficer | Self::Administrator)
    }

    /// Whether the role may acknowledge the journal's unknown interval: an
    /// administrator.
    #[must_use]
    pub const fn may_acknowledge(self) -> bool {
        matches!(self, Self::Administrator)
    }

    /// The role named `name`: `viewer`, `operator`, `risk-officer` or
    /// `administrator`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "viewer" => Self::Viewer,
            "operator" => Self::Operator,
            "risk-officer" => Self::RiskOfficer,
            "administrator" => Self::Administrator,
            _ => return None,
        })
    }
}

/// Where the API listens and who may use it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ApiConfig {
    /// The API socket's directory.
    pub dir: PathBuf,
    /// The role of each uid allowed to connect.
    pub roles: Vec<(u32, Role)>,
}

impl ApiConfig {
    /// Listening in `dir` for the uids of `roles`.
    #[must_use]
    pub fn new(dir: PathBuf, roles: Vec<(u32, Role)>) -> Self {
        Self { dir, roles }
    }
}

/// Why the API could not start.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ServeError {
    /// The directory is not a private directory of this uid, or its socket
    /// path holds something other than an API socket of this uid.
    #[error("{0}")]
    NotPrivate(&'static str),
    /// Another agent is serving in this directory.
    #[error("a live agent holds {}", .0.display())]
    Live(PathBuf),
    /// The operating system's error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// What a connection was answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Served {
    /// The view.
    View,
    /// A guard operation or an acknowledgement, made (whatever came of
    /// it).
    Operated,
    /// The limits, negotiated or reported.
    Limits,
    /// The capabilities, for the caller's role (R-CORE-24).
    Capabilities,
    /// Closed trace buckets, or the window's refusal (R-CORE-23).
    TraceBuckets,
    /// Raw trace records, or the export's refusal (R-CORE-13).
    TraceExport,
    /// A refusal: a uid without a role, a version not served, or a
    /// request not understood.
    Refused,
    /// The client went away, or its request never came within the timeout.
    Dropped,
}

/// The API socket, serving an [`Agent`]'s view.
#[derive(Debug)]
pub struct Server {
    listener: UnixListener,
    path: PathBuf,
    roles: Vec<(u32, Role)>,
}

impl Server {
    /// Listens in `config.dir` (see the module).
    ///
    /// # Errors
    ///
    /// [`ServeError`] for a directory that is not private, a live agent's
    /// socket, or a call that fails.
    pub fn bind(config: ApiConfig) -> Result<Self, ServeError> {
        use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
        match std::fs::DirBuilder::new().mode(0o700).create(&config.dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        let uid = karyos_sys::ipc::own_uid();
        let dir = std::fs::symlink_metadata(&config.dir)?;
        if !dir.is_dir() || dir.uid() != uid || dir.mode() & 0o777 != 0o700 {
            return Err(ServeError::NotPrivate(
                "the API directory is not a private directory of this uid",
            ));
        }
        let path = config.dir.join(SOCKET_NAME);
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(metadata) => {
                if !metadata.file_type().is_socket()
                    || metadata.uid() != uid
                    || metadata.mode() & 0o777 != 0o600
                {
                    return Err(ServeError::NotPrivate(
                        "the API socket path holds something other than an API socket",
                    ));
                }
                match UnixStream::connect(&path) {
                    Ok(_) => return Err(ServeError::Live(path)),
                    Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                        std::fs::remove_file(&path)?;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            path,
            roles: config.roles,
        })
    }

    /// The socket's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Serves the pending connections, at most [`MAX_ACCEPTS`], from
    /// `agent`'s current view; returns how each was answered. Never waits
    /// for a connection.
    ///
    /// # Errors
    ///
    /// The operating system's error when `accept` fails.
    pub fn poll(&mut self, agent: &mut Agent) -> Result<Vec<Served>, ServeError> {
        let start = std::time::Instant::now();
        let mut served = Vec::new();
        // At most MAX_ACCEPTS connections, and none started past the
        // poll's budget: the rest wait for the next poll.
        while served.len() < MAX_ACCEPTS && start.elapsed() < POLL_BUDGET {
            match self.listener.accept() {
                Ok((stream, _)) => served.push(self.serve(stream, agent)),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(served)
    }

    /// Answers one connection.
    fn serve(&self, stream: UnixStream, agent: &mut Agent) -> Served {
        let ready = stream.set_nonblocking(false).is_ok()
            && stream.set_read_timeout(Some(IO_TIMEOUT)).is_ok()
            && stream.set_write_timeout(Some(IO_TIMEOUT)).is_ok();
        if !ready {
            return Served::Dropped;
        }
        let peer = karyos_sys::ipc::peer_credentials(stream.as_fd())
            .ok()
            .and_then(|peer| {
                let uid = peer.uid.as_raw();
                self.roles
                    .iter()
                    .find(|(allowed, _)| *allowed == uid)
                    .map(|(_, role)| (uid, *role))
            });
        let Some(line) = read_request(&stream) else {
            return Served::Dropped;
        };
        let forbidden = || (json::error("forbidden", None), Served::Refused);
        let (answer, served) = match (peer, parse(&line)) {
            (None, _) => (json::error("not authorized", None), Served::Refused),
            (Some(_), Request::View) => (json::view(&agent.view()), Served::View),
            (Some((_, role)), Request::Capabilities) => (
                json::capabilities(&agent.capabilities(
                    role.may_close(),
                    role.may_reopen(),
                    role.may_acknowledge(),
                )),
                Served::Capabilities,
            ),
            (Some(_), Request::BadArguments(request)) => {
                (json::bad_arguments(request), Served::Refused)
            }
            (Some((uid, role)), Request::GuardClose { dir, guard, reason }) => {
                if role.may_close() {
                    let answer = agent.guard_close(Path::new(dir), guard, uid, reason.as_bytes());
                    (json::guard_answer(&answer), Served::Operated)
                } else {
                    forbidden()
                }
            }
            (
                Some((uid, role)),
                Request::GuardReopen {
                    dir,
                    guard,
                    expected,
                    reason,
                },
            ) => {
                if role.may_reopen() {
                    let answer =
                        agent.guard_reopen(Path::new(dir), guard, expected, uid, reason.as_bytes());
                    (json::guard_answer(&answer), Served::Operated)
                } else {
                    forbidden()
                }
            }
            (Some((uid, role)), Request::GapAck { position }) => {
                if role.may_acknowledge() {
                    let answer = match agent.acknowledge_gap(position, uid) {
                        Ok(()) => json::acknowledged(position),
                        Err(crate::journal::JournalError::NoGap) => {
                            json::error("no such unknown interval", None)
                        }
                        Err(_) => json::error("journal unavailable", None),
                    };
                    (answer, Served::Operated)
                } else {
                    forbidden()
                }
            }
            (Some(_), Request::Limits { proposals }) => match negotiate(&LIMITS, proposals) {
                Ok(effective) => match request_within(&line, &LIMITS, &effective) {
                    None => (json::limits(&LIMITS, &effective), Served::Limits),
                    Some(limit) => (json::above_bound(&limit), Served::Refused),
                },
                Err(Refusal::Above(limit)) => (json::above_bound(&limit), Served::Refused),
                Err(Refusal::Unknown(name)) => (json::unknown_dimension(name), Served::Refused),
                Err(Refusal::Bad) => (json::error("bad request", None), Served::Refused),
            },
            (
                Some(_),
                Request::TraceBuckets {
                    dir,
                    from,
                    count,
                    epoch,
                },
            ) => match agent.trace_buckets(Path::new(dir), from, count, epoch) {
                Ok(Ok(read)) => (json::trace_buckets(&read), Served::TraceBuckets),
                Ok(Err(refusal)) => (json::bucket_refusal(&refusal), Served::Refused),
                Err(answer) => (json::guard_answer(&answer), Served::Refused),
            },
            (
                Some(_),
                Request::TraceExport {
                    dir,
                    from,
                    count,
                    epoch,
                },
            ) => match agent.trace_export(Path::new(dir), from, count, epoch) {
                Ok(Ok(page)) => (json::trace_export(&page), Served::TraceExport),
                Ok(Err(refusal)) => (json::export_refusal(&refusal), Served::Refused),
                Err(answer) => (json::guard_answer(&answer), Served::Refused),
            },
            (Some(_), Request::Version) => (
                json::error("unsupported version", Some(&[API_VERSION])),
                Served::Refused,
            ),
            (Some(_), Request::Bad) => (json::error("bad request", None), Served::Refused),
        };
        let mut stream = stream;
        let mut reply = answer.into_bytes();
        reply.push(b'\n');
        if !write_within(&mut stream, &reply, WRITE_DEADLINE) {
            // Closed at once, both ways: the cut reply ends at EOF, and
            // nothing is ever written after it on this connection.
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return Served::Dropped;
        }
        served
    }
}

/// Writes `reply` to `stream` within `deadline` in all: one `write` at a
/// time, each under the time left (at most [`IO_TIMEOUT`]), the deadline
/// checked again after every one, so a client that reads a little at a
/// time cannot stretch it; `false` when a write failed or the deadline
/// passed.
fn write_within(stream: &mut UnixStream, reply: &[u8], deadline: Duration) -> bool {
    let start = std::time::Instant::now();
    let mut rest = reply;
    while !rest.is_empty() {
        let left = deadline.saturating_sub(start.elapsed());
        if left.is_zero()
            || stream
                .set_write_timeout(Some(left.min(IO_TIMEOUT)))
                .is_err()
        {
            return false;
        }
        let chunk = rest.get(..WRITE_CHUNK.min(rest.len())).unwrap_or(rest);
        match stream.write(chunk) {
            Ok(written) if written > 0 => rest = rest.get(written..).unwrap_or(&[]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Ok(_) | Err(_) => return false,
        }
    }
    // Written whole: served, even if the last write ended past the
    // deadline.
    stream.flush().is_ok()
}

impl Drop for Server {
    /// Removes the socket file, so the next agent finds none.
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A request line, as the agent understood it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Request<'a> {
    View,
    /// The capability discovery of R-CORE-24.
    Capabilities,
    /// A known request with arguments it does not take.
    BadArguments(&'static str),
    GuardClose {
        dir: &'a str,
        guard: u64,
        reason: &'a str,
    },
    GuardReopen {
        dir: &'a str,
        guard: u64,
        expected: u64,
        reason: &'a str,
    },
    GapAck {
        position: u64,
    },
    Limits {
        proposals: &'a str,
    },
    TraceBuckets {
        dir: &'a str,
        from: crate::api::BucketCursor,
        count: usize,
        epoch: Option<u64>,
    },
    TraceExport {
        dir: &'a str,
        from: u64,
        count: usize,
        epoch: Option<u128>,
    },
    /// A well-formed request of another version.
    Version,
    Bad,
}

/// Reads one request line, up to [`MAX_REQUEST`] bytes; `None` when the
/// client sent none in time or closed first.
fn read_request(stream: &UnixStream) -> Option<String> {
    let start = std::time::Instant::now();
    let limit = MAX_REQUEST.checked_add(1)?;
    let mut stream = stream;
    let mut line = Vec::with_capacity(limit);
    let mut buffer = [0u8; MAX_REQUEST + 1];
    // Within READ_DEADLINE in all: each read gets the time left, so a
    // client sending a byte at a time cannot hold the polling thread.
    while !line.contains(&b'\n') && line.len() < limit {
        let left = READ_DEADLINE.saturating_sub(start.elapsed());
        if left.is_zero() || stream.set_read_timeout(Some(left.min(IO_TIMEOUT))).is_err() {
            return None;
        }
        let want = limit.saturating_sub(line.len());
        match stream.read(buffer.get_mut(..want)?) {
            Ok(0) => break,
            Ok(read) => line.extend_from_slice(buffer.get(..read)?),
            // A signal is not the client's doing: read again, within the
            // same deadline.
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    if let Some(end) = line.iter().position(|byte| *byte == b'\n') {
        line.truncate(end + 1);
    }
    if line.is_empty() {
        return None;
    }
    String::from_utf8(line).ok()
}

/// `KARYOS-AGENT <version> <request> [arguments]`, with or without its
/// newline. A reason is the rest of the line after the last fixed
/// argument, single spaces kept.
fn parse(line: &str) -> Request<'_> {
    if line.len() > MAX_REQUEST {
        return Request::Bad;
    }
    let line = line.trim_end_matches(['\n', '\r']);
    let mut words = line.splitn(3, ' ');
    let (Some(PROTOCOL), Some(version), Some(rest)) = (words.next(), words.next(), words.next())
    else {
        return Request::Bad;
    };
    match version.parse::<u32>() {
        Ok(API_VERSION) => request(rest).unwrap_or(Request::Bad),
        Ok(_) => Request::Version,
        Err(_) => Request::Bad,
    }
}

/// A v1 request and its arguments.
fn request(rest: &str) -> Option<Request<'_>> {
    let (name, arguments) = rest.split_once(' ').unwrap_or((rest, ""));
    let number = |word: &str| word.parse::<u64>().ok();
    match name {
        "view" if arguments.is_empty() => Some(Request::View),
        // A malformed request this agent knows gets its own typed error
        // (the rule of karyos#733); an agent that does not know it answers
        // `bad request`, which a client reads as "not supported".
        "capabilities" if arguments.is_empty() => Some(Request::Capabilities),
        "capabilities" => Some(Request::BadArguments("capabilities")),
        "guard-close" => {
            let mut fields = arguments.splitn(3, ' ');
            let dir = fields.next().filter(|dir| !dir.is_empty())?;
            let guard = number(fields.next()?)?;
            let reason = fields.next().unwrap_or("");
            Some(Request::GuardClose { dir, guard, reason })
        }
        "guard-reopen" => {
            let mut fields = arguments.splitn(4, ' ');
            let dir = fields.next().filter(|dir| !dir.is_empty())?;
            let guard = number(fields.next()?)?;
            let expected = number(fields.next()?)?;
            let reason = fields.next().unwrap_or("");
            Some(Request::GuardReopen {
                dir,
                guard,
                expected,
                reason,
            })
        }
        "limits" => Some(Request::Limits {
            proposals: arguments,
        }),
        "gap-ack" => Some(Request::GapAck {
            position: number(arguments)?,
        }),
        // `trace-buckets DIR FROM [COUNT [EPOCH [LANE]]]` (R-CORE-23): a
        // continuation names the lane its bucket's next page starts at,
        // with the epoch; a count of 0 or above BUCKETS_MAX is a bad
        // argument.
        "trace-buckets" => {
            let mut fields = arguments.split(' ');
            let parsed = (|| {
                let dir = fields.next().filter(|dir| !dir.is_empty())?;
                let from = number(fields.next()?)?;
                let count = match fields.next() {
                    None => crate::api::BUCKETS_DEFAULT,
                    Some(word) => usize::try_from(number(word)?)
                        .ok()
                        .filter(|count| (1..=crate::api::BUCKETS_MAX).contains(count))?,
                };
                let epoch = match fields.next() {
                    None => None,
                    Some(word) => Some(number(word)?),
                };
                let lane = match fields.next() {
                    None => 0,
                    Some(word) => usize::try_from(number(word)?).ok()?,
                };
                fields.next().is_none().then_some(Request::TraceBuckets {
                    dir,
                    from: crate::api::BucketCursor::new(from, lane),
                    count,
                    epoch,
                })
            })();
            Some(parsed.unwrap_or(Request::BadArguments("trace-buckets")))
        }
        // `trace-export DIR FROM [COUNT [EPOCH]]` (R-CORE-13): EPOCH is
        // the driver instance, 32 hex digits; a count of 0 or above
        // EXPORT_MAX is a bad argument.
        "trace-export" => {
            let mut fields = arguments.split(' ');
            let parsed = (|| {
                let dir = fields.next().filter(|dir| !dir.is_empty())?;
                let from = number(fields.next()?)?;
                let count = match fields.next() {
                    None => crate::api::EXPORT_DEFAULT,
                    Some(word) => usize::try_from(number(word)?)
                        .ok()
                        .filter(|count| (1..=crate::api::EXPORT_MAX).contains(count))?,
                };
                let epoch = match fields.next() {
                    None => None,
                    Some(word)
                        if word.len() == 32 && word.bytes().all(|b| b.is_ascii_hexdigit()) =>
                    {
                        Some(u128::from_str_radix(word, 16).ok()?)
                    }
                    Some(_) => return None,
                };
                fields.next().is_none().then_some(Request::TraceExport {
                    dir,
                    from,
                    count,
                    epoch,
                })
            })();
            Some(parsed.unwrap_or(Request::BadArguments("trace-export")))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_parse_strictly() {
        assert_eq!(parse("KARYOS-AGENT 1 view\n"), Request::View);
        assert_eq!(parse("KARYOS-AGENT 1 view"), Request::View);
        assert_eq!(parse("KARYOS-AGENT 2 view\n"), Request::Version);
        assert_eq!(parse("KARYOS-AGENT 1 drop\n"), Request::Bad);
        assert_eq!(parse("KARYOS-AGENT 1 view extra\n"), Request::Bad);
        assert_eq!(parse("karyos-agent 1 view\n"), Request::Bad);
        assert_eq!(parse("KARYOS-AGENT x view\n"), Request::Bad);
        assert_eq!(parse(""), Request::Bad);
        let long = format!("KARYOS-AGENT 1 {}", "v".repeat(MAX_REQUEST));
        assert_eq!(parse(&long), Request::Bad);
    }

    /// R-CORE-23: `trace-buckets DIR FROM [COUNT [EPOCH]]`; a count of 0
    /// or above the maximum, a word that is not a number, or one more
    /// argument is its own bad-arguments error.
    #[test]
    fn trace_buckets_parse_with_their_bounds() {
        let buckets = |dir, from, count, epoch| Request::TraceBuckets {
            dir,
            from: crate::api::BucketCursor::new(from, 0),
            count,
            epoch,
        };
        assert_eq!(
            parse("KARYOS-AGENT 1 trace-buckets /run/k 4\n"),
            buckets("/run/k", 4, crate::api::BUCKETS_DEFAULT, None)
        );
        assert_eq!(
            parse("KARYOS-AGENT 1 trace-buckets /run/k 4 60 77\n"),
            buckets("/run/k", 4, 60, Some(77))
        );
        // A continuation: bucket 4 from its lane 3.
        assert_eq!(
            parse("KARYOS-AGENT 1 trace-buckets /run/k 4 60 77 3\n"),
            Request::TraceBuckets {
                dir: "/run/k",
                from: crate::api::BucketCursor::new(4, 3),
                count: 60,
                epoch: Some(77),
            }
        );
        for bad in [
            "trace-buckets",
            "trace-buckets /run/k",
            "trace-buckets /run/k x",
            "trace-buckets /run/k 4 0",
            "trace-buckets /run/k 4 61",
            "trace-buckets /run/k 4 6 e",
            "trace-buckets /run/k 4 6 7 x",
            "trace-buckets /run/k 4 6 7 8 9",
        ] {
            assert_eq!(
                parse(&format!("KARYOS-AGENT 1 {bad}\n")),
                Request::BadArguments("trace-buckets"),
                "{bad}"
            );
        }
    }

    /// R-CORE-13: `trace-export DIR FROM [COUNT [EPOCH]]`, EPOCH the
    /// driver instance in 32 hex digits; a count of 0 or above the
    /// maximum, an epoch of another form, or one more argument is its own
    /// bad-arguments error.
    #[test]
    fn trace_export_parses_with_its_bounds() {
        let export = |dir, from, count, epoch| Request::TraceExport {
            dir,
            from,
            count,
            epoch,
        };
        let epoch = "000000000000000000000000000000ff";
        assert_eq!(
            parse("KARYOS-AGENT 1 trace-export /run/k 4\n"),
            export("/run/k", 4, crate::api::EXPORT_DEFAULT, None)
        );
        assert_eq!(
            parse(&format!(
                "KARYOS-AGENT 1 trace-export /run/k 4 16384 {epoch}\n"
            )),
            export("/run/k", 4, 16_384, Some(0xff))
        );
        for bad in [
            "trace-export",
            "trace-export /run/k",
            "trace-export /run/k x",
            "trace-export /run/k 4 0",
            "trace-export /run/k 4 16385",
            "trace-export /run/k 4 6 ff",
            "trace-export /run/k 4 6 +0000000000000000000000000000ff",
            "trace-export /run/k 4 6 000000000000000000000000000000fg",
            "trace-export /run/k 4 6 000000000000000000000000000000ff 8",
        ] {
            assert_eq!(
                parse(&format!("KARYOS-AGENT 1 {bad}\n")),
                Request::BadArguments("trace-export"),
                "{bad}"
            );
        }
    }

    /// A reply that a client reads too slowly is cut short at the write
    /// deadline, never holding the polling thread for longer, and the
    /// connection closed: the client reads part of it with no final
    /// newline, then EOF, and discards it. Its retry with the same cursor
    /// gets the same buckets, whole (review of #817, QS-COORDINATOR, ACS
    /// 33400 and 33440).
    #[test]
    fn a_reply_cut_at_its_deadline_ends_at_eof_and_a_retry_gets_it_whole() {
        let mut window = crate::trace_window::TraceWindow::new(
            crate::WindowConfig::default().with_window(60, 6),
            [1, 2],
        );
        let mirror = karyos_sys::trace_mirror::trace_mirror(4, 4, 4).unwrap();
        window.scan(&mirror.reader(), 1);
        window.scan(&mirror.reader(), 25);
        let cursor = crate::api::BucketCursor::new(0, 0);
        let first = window
            .buckets(cursor, 6, None, crate::api::MAX_BUCKET_REPLY)
            .unwrap();
        // The reply, padded past any socket buffer so a peer that does not
        // read blocks the write.
        let mut reply = json::trace_buckets(&first).into_bytes();
        reply.resize(16 << 20, b' ');
        reply.push(b'\n');
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        let start = std::time::Instant::now();
        assert!(!write_within(&mut writer, &reply, WRITE_DEADLINE));
        assert!(
            start.elapsed() < WRITE_DEADLINE + IO_TIMEOUT * 2,
            "{:?}",
            start.elapsed()
        );
        // As `serve` does after a cut.
        writer.shutdown(std::net::Shutdown::Both).unwrap();
        let mut cut = Vec::new();
        reader.read_to_end(&mut cut).unwrap();
        assert!(!cut.is_empty() && cut.len() < reply.len(), "{}", cut.len());
        assert_ne!(cut.last(), Some(&b'\n'), "a cut reply has no final newline");
        // The retry, with the same cursor, read whole.
        let again = window
            .buckets(cursor, 6, None, crate::api::MAX_BUCKET_REPLY)
            .unwrap();
        assert_eq!(again.buckets, first.buckets);
        let mut reply = json::trace_buckets(&again).into_bytes();
        reply.push(b'\n');
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        let read = std::thread::spawn(move || {
            let mut all = Vec::new();
            reader.read_to_end(&mut all).unwrap();
            all
        });
        assert!(write_within(&mut writer, &reply, WRITE_DEADLINE));
        drop(writer);
        assert_eq!(read.join().unwrap(), reply);
    }

    /// Review B1 of #826: a client that reads a few KiB at a time, often
    /// enough for each write to progress, still cannot stretch a reply past
    /// its deadline: it is checked after every write.
    #[test]
    fn a_trickling_reader_cannot_stretch_the_deadline() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        let trickle = std::thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            let mut total = 0;
            while let Ok(read) = reader.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                total += read;
                std::thread::sleep(Duration::from_millis(20));
            }
            total
        });
        let reply = vec![b'z'; 64 << 20];
        let start = std::time::Instant::now();
        assert!(!write_within(&mut writer, &reply, WRITE_DEADLINE));
        let took = start.elapsed();
        // The deadline plus the one write it cut short, with a write's
        // timeout of slack for a loaded machine's scheduling: a trickling
        // reader once held it for seconds.
        assert!(took < WRITE_DEADLINE + IO_TIMEOUT * 2, "{took:?}");
        writer.shutdown(std::net::Shutdown::Both).unwrap();
        assert!(trickle.join().unwrap() < reply.len());
    }

    /// Re-review F2 of #826: a client sending a request a byte at a time,
    /// just under each read's timeout, cannot hold the polling thread past
    /// the read deadline; a whole request is read.
    #[test]
    fn a_request_is_read_within_its_deadline() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let trickle = std::thread::spawn(move || {
            for byte in b"KARYOS-AGENT 1 view\n" {
                if writer.write_all(&[*byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(60));
            }
        });
        let start = std::time::Instant::now();
        assert_eq!(read_request(&reader), None);
        assert!(
            start.elapsed() < READ_DEADLINE + IO_TIMEOUT * 2,
            "{:?}",
            start.elapsed()
        );
        drop(reader);
        trickle.join().unwrap();
        let (reader, mut writer) = UnixStream::pair().unwrap();
        writer.write_all(b"KARYOS-AGENT 1 view\nextra").unwrap();
        assert_eq!(
            read_request(&reader).as_deref(),
            Some("KARYOS-AGENT 1 view\n")
        );
    }

    /// R-CORE-38: a dimension this agent does not know is refused by
    /// name, so a client tells it from an agent without `limits`.
    #[test]
    fn an_unknown_dimension_is_refused_by_name() {
        assert_eq!(
            negotiate(&LIMITS, "read.timeout_ms=1 page.rows=10"),
            Err(Refusal::Unknown("page.rows"))
        );
        assert_eq!(
            json::unknown_dimension("page.rows"),
            r#"{"error":"unknown dimension","dimension":"page.rows"}"#
        );
    }

    /// R-CORE-38's three answers, on a table with a negotiable dimension
    /// (only `read.request_bytes` is in v1): a proposal within its bound is applied, one above
    /// it is refused with the bound, and the answer renders the negotiable,
    /// the fixed and the unbounded dimension.
    #[test]
    fn a_negotiable_dimension_takes_a_proposal_within_its_bound() {
        let table = [
            Limit {
                name: "page.rows",
                bound: Some(1000),
                negotiable: true,
            },
            Limit {
                name: "read.timeout_ms",
                bound: Some(100),
                negotiable: false,
            },
            Limit {
                name: "write.response_bytes",
                bound: None,
                negotiable: false,
            },
        ];
        assert_eq!(negotiate(&table, ""), Ok([Some(1000), Some(100), None]));
        let effective = negotiate(&table, "page.rows=50 read.timeout_ms=50").unwrap();
        assert_eq!(effective, [Some(50), Some(100), None]);
        assert_eq!(
            negotiate(&table, "page.rows=1001"),
            Err(Refusal::Above(table[0]))
        );
        assert_eq!(
            json::above_bound(&table[0]),
            r#"{"error":"above bound","dimension":"page.rows","bound":1000}"#
        );
        assert_eq!(
            json::limits(&table, &effective),
            concat!(
                r#"{"limits":{"page.rows":{"value":50,"negotiable":true},"#,
                r#""read.timeout_ms":{"value":100,"negotiable":false},"#,
                r#""write.response_bytes":{"value":null}}}"#
            )
        );
    }

    /// R-CORE-38: the negotiated `read.request_bytes` applies to the
    /// request that negotiated it.
    #[test]
    fn a_negotiated_request_size_applies_to_its_request() {
        // 44 bytes, its newline included, as `parse` counts against
        // `MAX_REQUEST`: a bound of 44 takes it, 43 refuses it with 43.
        let line = "KARYOS-AGENT 1 limits read.request_bytes=44\n";
        assert_eq!(line.len(), 44);
        let effective = negotiate(&LIMITS, "read.request_bytes=44").unwrap();
        assert_eq!(request_within(line, &LIMITS, &effective), None);
        let line = "KARYOS-AGENT 1 limits read.request_bytes=43\n";
        let effective = negotiate(&LIMITS, "read.request_bytes=43").unwrap();
        let refused = request_within(line, &LIMITS, &effective).unwrap();
        assert_eq!(
            (refused.name, refused.bound),
            ("read.request_bytes", Some(43))
        );
        let bounds = LIMITS.map(|limit| limit.bound);
        assert_eq!(request_within(line, &LIMITS, &bounds), None);
    }

    /// R-CORE-38: `limits` parses with or without proposals.
    #[test]
    fn limits_requests_parse() {
        assert_eq!(
            parse("KARYOS-AGENT 1 limits\n"),
            Request::Limits { proposals: "" }
        );
        assert_eq!(
            parse("KARYOS-AGENT 1 limits read.timeout_ms=50\n"),
            Request::Limits {
                proposals: "read.timeout_ms=50"
            }
        );
    }

    /// R-CORE-38: only `read.request_bytes` is negotiable in v1, so a
    /// proposal within it is the effective value; a proposal within a fixed
    /// bound is answered with the bound.
    #[test]
    fn a_fixed_bound_answers_its_value_whatever_is_proposed() {
        let bounds = LIMITS.map(|limit| limit.bound);
        let negotiable: Vec<_> = LIMITS
            .iter()
            .filter(|limit| limit.negotiable)
            .map(|limit| limit.name)
            .collect();
        assert_eq!(negotiable, ["read.request_bytes"]);
        assert_eq!(negotiate(&LIMITS, ""), Ok(bounds));
        assert_eq!(negotiate(&LIMITS, "read.timeout_ms=50"), Ok(bounds));
        assert_eq!(negotiate(&LIMITS, "write.response_bytes=4096"), Ok(bounds));
        let mut lowered = bounds;
        lowered[0] = Some(100);
        assert_eq!(negotiate(&LIMITS, "read.request_bytes=100"), Ok(lowered));
        assert_eq!(bounds[0], Some(256));
        assert_eq!(bounds[1], Some(100));
        assert_eq!(bounds[2], Some(250));
        assert_eq!(bounds[3], Some(100));
        assert_eq!(bounds[4], Some(250));
        assert_eq!(bounds[5], None);
        assert_eq!(bounds[6], Some(16));
        assert_eq!(bounds[7], Some(1));
    }

    /// R-CORE-38: a proposal above a bound is refused with that limit;
    /// a malformed or repeated one is a bad request.
    #[test]
    fn a_proposal_above_a_bound_is_refused_with_the_bound() {
        assert_eq!(
            negotiate(&LIMITS, "write.timeout_ms=101"),
            Err(Refusal::Above(LIMITS[3]))
        );
        assert_eq!(
            negotiate(&LIMITS, "read.request_bytes=256 connection.requests=2"),
            Err(Refusal::Above(LIMITS[7]))
        );
        for bad in [
            "read.timeout_ms",
            "read.timeout_ms=x",
            "read.timeout_ms=-1",
            "read.timeout_ms=1 read.timeout_ms=2",
            "read.timeout_ms=1  write.timeout_ms=1",
        ] {
            assert_eq!(negotiate(&LIMITS, bad), Err(Refusal::Bad), "{bad}");
        }
    }

    /// M10b: the guard requests and their arguments, a reason being the
    /// rest of the line.
    #[test]
    fn guard_requests_parse_with_their_reason() {
        assert_eq!(
            parse("KARYOS-AGENT 1 guard-close /run/a 3 desk halted, see ticket 7\n"),
            Request::GuardClose {
                dir: "/run/a",
                guard: 3,
                reason: "desk halted, see ticket 7"
            }
        );
        assert_eq!(
            parse("KARYOS-AGENT 1 guard-close /run/a 3"),
            Request::GuardClose {
                dir: "/run/a",
                guard: 3,
                reason: ""
            }
        );
        assert_eq!(
            parse("KARYOS-AGENT 1 guard-reopen /run/a 3 5 cleared"),
            Request::GuardReopen {
                dir: "/run/a",
                guard: 3,
                expected: 5,
                reason: "cleared"
            }
        );
        assert_eq!(
            parse("KARYOS-AGENT 1 gap-ack 96"),
            Request::GapAck { position: 96 }
        );
        for bad in [
            "KARYOS-AGENT 1 guard-close /run/a",
            "KARYOS-AGENT 1 guard-close /run/a x",
            "KARYOS-AGENT 1 guard-close  3",
            "KARYOS-AGENT 1 guard-reopen /run/a 3",
            "KARYOS-AGENT 1 guard-reopen /run/a 3 -1",
            "KARYOS-AGENT 1 gap-ack",
            "KARYOS-AGENT 1 gap-ack 1 2",
        ] {
            assert_eq!(parse(bad), Request::Bad, "{bad}");
        }
    }

    /// The interim matrix (owner item 2): operators and risk officers
    /// close; risk officers and administrators reopen; administrators
    /// acknowledge; viewers only read.
    #[test]
    fn the_roles_bound_the_guard_operations() {
        let matrix = [
            (Role::Viewer, false, false, false),
            (Role::Operator, true, false, false),
            (Role::RiskOfficer, true, true, false),
            (Role::Administrator, false, true, true),
        ];
        for (role, close, reopen, acknowledge) in matrix {
            assert_eq!(
                (role.may_close(), role.may_reopen(), role.may_acknowledge()),
                (close, reopen, acknowledge),
                "{role:?}"
            );
        }
    }

    #[test]
    fn roles_parse_by_name() {
        assert_eq!(Role::parse("viewer"), Some(Role::Viewer));
        assert_eq!(Role::parse("risk-officer"), Some(Role::RiskOfficer));
        assert_eq!(Role::parse("root"), None);
    }
}
