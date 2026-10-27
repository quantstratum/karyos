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
//!   (R-CORE-38).
//! - **Bounds.** Each connection is served on the calling thread with
//!   [`IO_TIMEOUT`] on its reads and writes, so a slow client delays the
//!   others by that much at most.
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
//!   another's. In v1 no dimension is negotiable. A proposal for a
//!   dimension the agent does not know is refused by name
//!   (`{"error":"unknown dimension","dimension":D}`), never as `bad
//!   request`. So `bad request` to `limits` means the agent predates it: a
//!   client reads that as "limits not supported", never as "no limits". A
//!   future dimension, such as the page
//!   sizes of R-CORE-13 and R-CORE-14, enters [`LIMITS`] as a new entry,
//!   negotiable or not, and a v1 client that does not name it is unaffected.

use std::io::{BufRead, BufReader, Read, Write};
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
/// Connections one [`Server::poll`] serves at most; the rest wait for the
/// next poll, so a burst of clients cannot hold the polling thread.
pub const MAX_ACCEPTS: usize = 16;

/// The dimensions `limits` answers, their bounds being the constants
/// above. None is negotiable in v1.
pub const LIMITS: [Limit; 6] = [
    Limit {
        name: "read.request_bytes",
        bound: Some(MAX_REQUEST as u64),
        negotiable: false,
    },
    Limit {
        name: "read.timeout_ms",
        bound: Some(IO_TIMEOUT.as_millis() as u64),
        negotiable: false,
    },
    Limit {
        name: "write.timeout_ms",
        bound: Some(IO_TIMEOUT.as_millis() as u64),
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
        let mut served = Vec::new();
        while served.len() < MAX_ACCEPTS {
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
                Ok(effective) => (json::limits(&LIMITS, &effective), Served::Limits),
                Err(Refusal::Above(limit)) => (json::above_bound(&limit), Served::Refused),
                Err(Refusal::Unknown(name)) => (json::unknown_dimension(name), Served::Refused),
                Err(Refusal::Bad) => (json::error("bad request", None), Served::Refused),
            },
            (Some(_), Request::Version) => (
                json::error("unsupported version", Some(&[API_VERSION])),
                Served::Refused,
            ),
            (Some(_), Request::Bad) => (json::error("bad request", None), Served::Refused),
        };
        let mut stream = stream;
        let written = stream
            .write_all(answer.as_bytes())
            .and_then(|()| stream.write_all(b"\n"))
            .and_then(|()| stream.flush());
        if written.is_err() {
            return Served::Dropped;
        }
        served
    }
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
    /// A well-formed request of another version.
    Version,
    Bad,
}

/// Reads one request line, up to [`MAX_REQUEST`] bytes; `None` when the
/// client sent none in time or closed first.
fn read_request(stream: &UnixStream) -> Option<String> {
    let limit = u64::try_from(MAX_REQUEST).ok()?.checked_add(1)?;
    let mut reader = BufReader::new(stream.take(limit));
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line),
    }
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
    /// (none is in v1): a proposal within its bound is applied, one above
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

    /// R-CORE-38: none of the v1 dimensions is negotiable, so every
    /// effective value is the bound, and a proposal within a fixed bound is
    /// answered with the bound.
    #[test]
    fn a_fixed_bound_answers_its_value_whatever_is_proposed() {
        let bounds = LIMITS.map(|limit| limit.bound);
        assert!(LIMITS.iter().all(|limit| !limit.negotiable));
        assert_eq!(negotiate(&LIMITS, ""), Ok(bounds));
        assert_eq!(negotiate(&LIMITS, "read.timeout_ms=50"), Ok(bounds));
        assert_eq!(negotiate(&LIMITS, "write.response_bytes=4096"), Ok(bounds));
        assert_eq!(bounds[0], Some(256));
        assert_eq!(bounds[1], Some(100));
        assert_eq!(bounds[2], Some(100));
        assert_eq!(bounds[3], None);
        assert_eq!(bounds[4], Some(16));
        assert_eq!(bounds[5], Some(1));
    }

    /// R-CORE-38: a proposal above a bound is refused with that limit;
    /// a malformed or repeated one is a bad request.
    #[test]
    fn a_proposal_above_a_bound_is_refused_with_the_bound() {
        assert_eq!(
            negotiate(&LIMITS, "write.timeout_ms=101"),
            Err(Refusal::Above(LIMITS[2]))
        );
        assert_eq!(
            negotiate(&LIMITS, "read.request_bytes=256 connection.requests=2"),
            Err(Refusal::Above(LIMITS[5]))
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
