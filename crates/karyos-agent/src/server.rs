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
//! - **Relays (karyos#708).** The uid of a remote control-plane component
//!   configured as a relay ([`ApiConfig::with_relays`]) may send
//!   `KARYOS-AGENT <version> relay PRINCIPAL <request>`: the request is
//!   served for that principal with the role this agent's principal table
//!   gives it, per request, never the relay's own role and never one the
//!   relay names; the journal records the principal's operator id and the
//!   relay's id as separate fields. Any other uid sending it, or an
//!   unknown principal, is answered `not authorized`. The local uid mode
//!   is unchanged.
//! - **Relay access (karyos#708).** A relay running under its own uid
//!   cannot reach a `0700` directory and a `0600` socket. With a relay
//!   group ([`ApiConfig::with_relay_group`]), and only then, the directory
//!   is `0710` and the socket `0660`, both of that group, which this
//!   agent's uid must be a member of: the relay's uid joins the group, no
//!   one else gains anything, and the peer's uid is still checked per
//!   connection. Without a relay group nothing changes. A directory left
//!   by a run with the other setting (this uid's, `0700` or `0710`) is
//!   brought to this run's at start; any other mode is refused.
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
//!   role (R-CORE-24); the join metadata registry's (karyos#736) `join-put
//!   DIR KIND KEY NAME=VALUE...` and `join-retire DIR KIND KEY`, for a
//!   registrar or an administrator, and `join-get DIR KIND KEY [AT_NS]`
//!   and `join-list DIR [KIND KEY]`, for every role; `rate-change DIR
//!   STREAM_ID SESSION_ID EXPECTED AUTHORITY MSG_RATE MSG_BURST BYTE_RATE
//!   BYTE_BURST [REASON]` (R-CORE-21, karyos#740; a byte rate and burst
//!   of 0 and 0 for no byte limit), AUTHORITY `safety` for an operator, a
//!   risk officer or an administrator and `administrator` for an
//!   administrator only. A `join-put` line may
//!   be up to [`MAX_JOIN_REQUEST`] bytes; past it, it is refused above the
//!   bound `join.request_bytes`. A request this agent knows with arguments it does
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
//!   `trace.points_per_client` and `trace.point_registrations_per_client`
//!   are the attached drivers' configured bounds ([`Agent::limits`];
//!   karyos#868), the smallest over several, and the driver's defaults
//!   when no attached driver publishes them.

use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::api::{API_VERSION, Limit, MAX_PRINCIPAL, valid_principal};
use crate::registry::{self, JoinError, Kind};
use crate::{Agent, json};

/// The API socket's name in its directory.
pub const SOCKET_NAME: &str = "agent.sock";
/// The first word of every request.
pub const PROTOCOL: &str = "KARYOS-AGENT";
/// The longest request line, in bytes, but a `join-put`'s.
pub const MAX_REQUEST: usize = 256;
/// The longest `join-put` line, in bytes (karyos#736): an entry's
/// attributes do not fit [`MAX_REQUEST`].
pub const MAX_JOIN_REQUEST: usize = 1024;
/// The word that makes a request a relayed one (karyos#708): `KARYOS-AGENT
/// <version> relay PRINCIPAL <request>`. The bounds above apply to the
/// request without its `relay PRINCIPAL ` prefix.
pub const RELAY: &str = "relay";
/// The longest `relay PRINCIPAL ` prefix, in bytes.
const MAX_RELAY_PREFIX: usize = RELAY.len() + MAX_PRINCIPAL + 2;
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
/// downwards: no bound is raised. The `join.*` dimensions are the join
/// metadata registry's (karyos#736): `join.memory_bytes` is the computed
/// worst case of the memory its entries hold, in layout bytes, measured
/// against the counting allocator (karyos#893). The `trace.*` dimensions are the
/// driver's application trace point bounds (R-CORE-1): the ids an instance
/// assigns, a protocol constant, and the per-client bounds at the
/// driver's built-in defaults: the CnC does not expose a driver's
/// configured values, so a `karyosd` started with others is not reflected
/// (a follow-up).
pub const LIMITS: [Limit; 21] = [
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
    Limit {
        name: "join.request_bytes",
        bound: Some(MAX_JOIN_REQUEST as u64),
        negotiable: false,
    },
    Limit {
        name: "join.keys",
        bound: Some(registry::MAX_KEYS as u64),
        negotiable: false,
    },
    Limit {
        name: "join.keys_per_driver",
        bound: Some(registry::MAX_KEYS_PER_DRIVER as u64),
        negotiable: false,
    },
    Limit {
        name: "join.versions_per_key",
        bound: Some(registry::MAX_VERSIONS as u64),
        negotiable: false,
    },
    Limit {
        name: "join.attributes_per_entry",
        bound: Some(registry::MAX_ATTRIBUTES as u64),
        negotiable: false,
    },
    Limit {
        name: "join.name_bytes",
        bound: Some(registry::MAX_NAME_BYTES as u64),
        negotiable: false,
    },
    Limit {
        name: "join.value_bytes",
        bound: Some(registry::MAX_VALUE_BYTES as u64),
        negotiable: false,
    },
    Limit {
        name: "join.key_bytes",
        bound: Some(registry::MAX_KEY_BYTES as u64),
        negotiable: false,
    },
    Limit {
        name: "join.list_page",
        bound: Some(registry::LIST_PAGE as u64),
        negotiable: false,
    },
    Limit {
        name: "join.memory_bytes",
        bound: Some(registry::MAX_MEMORY_BYTES as u64),
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
    /// Reads, and writes the join metadata registry, nothing else
    /// (karyos#736): a product's uid.
    Registrar,
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

    /// Whether the role may apply a legal hold: an operator, a risk
    /// officer or an administrator. A hold only preserves (M12; the matrix
    /// is in [`crate::retention`]).
    #[must_use]
    pub const fn may_hold(self) -> bool {
        matches!(
            self,
            Self::Operator | Self::RiskOfficer | Self::Administrator
        )
    }

    /// Whether the role may release a legal hold or purge: an
    /// administrator. Both expose or destroy evidence.
    #[must_use]
    pub const fn may_release_or_purge(self) -> bool {
        matches!(self, Self::Administrator)
    }

    /// Whether the role may write the join metadata registry: a registrar
    /// or an administrator (karyos#736).
    #[must_use]
    pub const fn may_register(self) -> bool {
        matches!(self, Self::Registrar | Self::Administrator)
    }

    /// The role named `name`: `viewer`, `operator`, `risk-officer`,
    /// `administrator` or `registrar`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "viewer" => Self::Viewer,
            "operator" => Self::Operator,
            "risk-officer" => Self::RiskOfficer,
            "administrator" => Self::Administrator,
            "registrar" => Self::Registrar,
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
    /// The uid of each relay (a remote control-plane component, karyos#708)
    /// allowed to carry requests for principals, with its relay id, which
    /// the journal records. A relay has no role of its own for what it
    /// carries.
    pub relays: Vec<(u32, u64)>,
    /// The principals a relay may carry requests for, each with the
    /// operator id and the role this agent gives it.
    pub principals: Vec<Principal>,
    /// The group whose members may reach the socket (a relay's uid), if
    /// any: the directory is then `0710` and the socket `0660` of that
    /// group; without one, `0700` and `0600`.
    pub relay_group: Option<u32>,
}

impl ApiConfig {
    /// Listening in `dir` for the uids of `roles`, with no relay.
    #[must_use]
    pub fn new(dir: PathBuf, roles: Vec<(u32, Role)>) -> Self {
        Self {
            dir,
            roles,
            relays: Vec::new(),
            principals: Vec::new(),
            relay_group: None,
        }
    }

    /// The same, the directory and socket reachable by `gid`'s members
    /// (karyos#708): a relay under a uid of its own joins that group.
    #[must_use]
    pub const fn with_relay_group(mut self, gid: u32) -> Self {
        self.relay_group = Some(gid);
        self
    }

    /// The same, also serving `relays` for `principals` (karyos#708).
    #[must_use]
    pub fn with_relays(mut self, relays: Vec<(u32, u64)>, principals: Vec<Principal>) -> Self {
        self.relays = relays;
        self.principals = principals;
        self
    }
}

/// A requester a relay may carry requests for (karyos#708): a person or a
/// service the relay authenticated, named as the relay names it. Its role
/// is this agent's, looked up per request; nothing the relay sends sets it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Principal {
    /// The name the relay gives it: 1 to [`MAX_PRINCIPAL`] bytes of ASCII
    /// letters, digits, `.`, `_`, `-`, `@` and `:`.
    pub name: String,
    /// The operator id the journal and the driver's audit record for it.
    pub operator: u32,
    /// Its role.
    pub role: Role,
}

impl Principal {
    /// Principal `name`, recorded as `operator`, with `role`; `None` for a
    /// name that is not a valid principal name.
    #[must_use]
    pub fn new(name: &str, operator: u32, role: Role) -> Option<Self> {
        valid_principal(name).then(|| Self {
            name: name.to_owned(),
            operator,
            role,
        })
    }
}

/// Who may call: the local uids' roles, the relays and their principals.
#[derive(Debug, Clone, Default)]
struct Callers {
    roles: Vec<(u32, Role)>,
    relays: Vec<(u32, u64)>,
    principals: Vec<Principal>,
}

/// The requester and role of request `line` from peer `uid`, and the line
/// to serve; `None` when it is not authorized. A line `KARYOS-AGENT
/// <version> relay PRINCIPAL <request>` from a relay's uid is the request
/// `KARYOS-AGENT <version> <request>` for that principal, with the role
/// this agent gives the principal: the relay's own role, if it has one as
/// a local uid, does not apply, and the relay cannot name a role. The same
/// line from any other uid, or for an unknown principal, is not
/// authorized. Any other line is the local peer's, as before relays.
fn authorize<'a>(
    callers: &Callers,
    uid: Option<u32>,
    line: &'a str,
) -> Option<(crate::Requester, Role, std::borrow::Cow<'a, str>)> {
    let uid = uid?;
    let mut words = line.splitn(5, ' ');
    if let (Some(PROTOCOL), Some(version), Some(RELAY)) = (words.next(), words.next(), words.next())
    {
        let relay = callers
            .relays
            .iter()
            .find(|(allowed, _)| *allowed == uid)
            .map(|(_, relay)| *relay)?;
        let name = words.next()?;
        let rest = words.next()?;
        let principal = callers
            .principals
            .iter()
            .find(|principal| valid_principal(name) && principal.name == name)?;
        return Some((
            crate::Requester::relayed(principal.operator, relay),
            principal.role,
            std::borrow::Cow::Owned(format!("{PROTOCOL} {version} {rest}")),
        ));
    }
    callers
        .roles
        .iter()
        .find(|(allowed, _)| *allowed == uid)
        .map(|(_, role)| {
            (
                crate::Requester::local(uid),
                *role,
                std::borrow::Cow::Borrowed(line),
            )
        })
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
    /// A join registry entry written: put or retired (karyos#736).
    Registered,
    /// A join registry read: an entry or a page.
    Join,
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
    callers: Callers,
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
        // Without a relay group, owner only; with one, the group may
        // reach the socket and nothing else.
        let (dir_mode, socket_mode) = match config.relay_group {
            None => (0o700, 0o600),
            Some(_) => (0o710, 0o660),
        };
        let uid = karyos_sys::ipc::own_uid();
        match std::fs::DirBuilder::new().mode(0o700).create(&config.dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        // The directory must be this uid's, in one of the agent's two modes
        // (a new one, or one left by a run with or without a relay group);
        // anything else is refused before anything changes.
        let dir = std::fs::symlink_metadata(&config.dir)?;
        if !dir.is_dir() || dir.uid() != uid || !matches!(dir.mode() & 0o777, 0o700 | 0o710) {
            return Err(ServeError::NotPrivate(
                "the API directory is not a private directory of this uid",
            ));
        }
        // A live agent's socket is never taken over, and its directory never
        // touched: this run binds the socket first, so a second agent that
        // starts and fails changes nothing of the first's.
        let path = config.dir.join(SOCKET_NAME);
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(metadata) => {
                if !metadata.file_type().is_socket()
                    || metadata.uid() != uid
                    || !matches!(metadata.mode() & 0o777, 0o600 | 0o660)
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
        // Binding fails if another agent bound it meanwhile.
        let listener = UnixListener::bind(&path)?;
        // From here the socket is this run's. Close its mode, then bring
        // the directory to this run's setting: the group before the mode
        // opens to it; then open the socket to the group.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        if let Some(gid) = config.relay_group {
            std::os::unix::fs::chown(&config.dir, None, Some(gid))?;
        }
        std::fs::set_permissions(&config.dir, std::fs::Permissions::from_mode(dir_mode))?;
        let dir = std::fs::symlink_metadata(&config.dir)?;
        if dir.mode() & 0o777 != dir_mode || config.relay_group.is_some_and(|gid| dir.gid() != gid)
        {
            let _ = std::fs::remove_file(&path);
            return Err(ServeError::NotPrivate(
                "the API directory could not be given this run's mode and group",
            ));
        }
        if let Some(gid) = config.relay_group {
            std::os::unix::fs::chown(&path, None, Some(gid))?;
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(socket_mode))?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            path,
            callers: Callers {
                roles: config.roles,
                relays: config.relays,
                principals: config.principals,
            },
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
        let uid = karyos_sys::ipc::peer_credentials(stream.as_fd())
            .ok()
            .map(|peer| peer.uid.as_raw());
        let Some(line) = read_request(&stream) else {
            return Served::Dropped;
        };
        // The caller's role is the agent's own table's, per request: a
        // relay's request takes its principal's role, never the relay's.
        let (peer, line) = match authorize(&self.callers, uid, &line) {
            Some((requester, role, line)) => (Some((requester, role)), line),
            None => (None, std::borrow::Cow::Borrowed(line.as_str())),
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
                    role.may_register(),
                )),
                Served::Capabilities,
            ),
            (Some(_), Request::BadArguments(request)) => {
                (json::bad_arguments(request), Served::Refused)
            }
            (Some((requester, role)), Request::GuardClose { dir, guard, reason }) => {
                if role.may_close() {
                    let answer =
                        agent.guard_close_for(Path::new(dir), guard, requester, reason.as_bytes());
                    (json::guard_answer(&answer), Served::Operated)
                } else {
                    forbidden()
                }
            }
            (
                Some((requester, role)),
                Request::GuardReopen {
                    dir,
                    guard,
                    expected,
                    reason,
                },
            ) => {
                if role.may_reopen() {
                    let answer = agent.guard_reopen_for(
                        Path::new(dir),
                        guard,
                        expected,
                        requester,
                        reason.as_bytes(),
                    );
                    (json::guard_answer(&answer), Served::Operated)
                } else {
                    forbidden()
                }
            }
            (
                Some((requester, role)),
                Request::Retention {
                    operation,
                    recording,
                    reason,
                },
            ) => {
                use crate::retention::Operation;
                let allowed = match operation {
                    Operation::Verify => true,
                    Operation::Hold => role.may_hold(),
                    _ => role.may_release_or_purge(),
                };
                if allowed {
                    let answer =
                        agent.retention(operation, recording, requester, reason.as_bytes());
                    (json::retention_answer(&answer), Served::Operated)
                } else {
                    forbidden()
                }
            }
            (
                Some((requester, role)),
                Request::GuardPreview {
                    kind,
                    dir,
                    guard,
                    reason,
                },
            ) => {
                if may(role, kind) {
                    let answer = agent.guard_preview_for(
                        kind,
                        Path::new(dir),
                        guard,
                        requester,
                        reason.as_bytes(),
                    );
                    (json::preview_answer(&answer), Served::View)
                } else {
                    forbidden()
                }
            }
            (
                Some((requester, role)),
                Request::Submit {
                    operation,
                    token,
                    kind,
                    dir,
                    guard,
                    reason,
                },
            ) => {
                if may(role, kind) {
                    match agent.guard_submit_for(
                        (operation, token),
                        kind,
                        Path::new(dir),
                        guard,
                        requester,
                        reason.as_bytes(),
                    ) {
                        Ok(answer) => (json::guard_answer(&answer), Served::Operated),
                        Err(refusal) => (json::error(refusal.text(), None), Served::Refused),
                    }
                } else {
                    forbidden()
                }
            }
            (Some((requester, role)), Request::GapAck { position }) => {
                if role.may_acknowledge() {
                    let answer = match agent.acknowledge_gap_for(position, requester) {
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
            (Some(_), Request::Limits { proposals }) => {
                let limits = agent.limits();
                match negotiate(&limits, proposals) {
                    Ok(effective) => match request_within(&line, &limits, &effective) {
                        None => (json::limits(&limits, &effective), Served::Limits),
                        Some(limit) => (json::above_bound(&limit), Served::Refused),
                    },
                    Err(Refusal::Above(limit)) => (json::above_bound(&limit), Served::Refused),
                    Err(Refusal::Unknown(name)) => (json::unknown_dimension(name), Served::Refused),
                    Err(Refusal::Bad) => (json::error("bad request", None), Served::Refused),
                }
            }
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
            (
                Some((requester, role)),
                Request::JoinPut {
                    dir,
                    kind,
                    key,
                    attributes,
                },
            ) => {
                if role.may_register() {
                    match agent.join_put(Path::new(dir), kind, key, attributes, requester) {
                        Ok(version) => (
                            json::join_written(
                                false,
                                Path::new(dir),
                                kind,
                                key,
                                version,
                                agent.join_generation(),
                            ),
                            Served::Registered,
                        ),
                        Err(error) => (json::join_refusal("join-put", error), Served::Refused),
                    }
                } else {
                    forbidden()
                }
            }
            (Some((_, role)), Request::JoinRetire { dir, kind, key }) => {
                if role.may_register() {
                    match agent.join_retire(Path::new(dir), kind, key) {
                        Ok(version) => (
                            json::join_written(
                                true,
                                Path::new(dir),
                                kind,
                                key,
                                version,
                                agent.join_generation(),
                            ),
                            Served::Registered,
                        ),
                        Err(error) => (json::join_refusal("join-retire", error), Served::Refused),
                    }
                } else {
                    forbidden()
                }
            }
            (Some(_), Request::JoinGet { dir, kind, key, at }) => {
                match agent.join_get(Path::new(dir), kind, key, at) {
                    Ok(read) => (json::join_read(&read), Served::Join),
                    Err(error) => (json::join_refusal("join-get", error), Served::Refused),
                }
            }
            (Some(_), Request::JoinList { dir, after }) => {
                match agent.join_list(Path::new(dir), after) {
                    Ok(page) => (json::join_page(&page), Served::Join),
                    Err(error) => (json::join_refusal("join-list", error), Served::Refused),
                }
            }
            (
                Some((requester, role)),
                Request::RateChange {
                    dir,
                    stream,
                    expected,
                    authority,
                    policy,
                    reason,
                },
            ) => {
                // The safety path only tightens: a closer's. Any other
                // change is an administrator's (R-CORE-21).
                let allowed = match authority {
                    karyos_protocol::cnc::RateAuthority::Safety => {
                        role.may_close() || role.may_acknowledge()
                    }
                    karyos_protocol::cnc::RateAuthority::Administrator => role.may_acknowledge(),
                };
                if allowed {
                    let answer = agent.rate_change_for(
                        Path::new(dir),
                        crate::operations::RateChange::new(stream, expected, policy, authority),
                        requester,
                        reason.as_bytes(),
                    );
                    (json::rate_answer(&answer), Served::Operated)
                } else {
                    forbidden()
                }
            }
            (Some(_), Request::JoinTooLong) => (
                json::join_refusal(
                    "join-put",
                    JoinError::Refused(registry::Refusal::Above {
                        dimension: "join.request_bytes",
                        bound: MAX_JOIN_REQUEST as u64,
                    }),
                ),
                Served::Refused,
            ),
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
    /// `guard-close-preview DIR GUARD [REASON]` and
    /// `guard-reopen-preview DIR GUARD [REASON]` (R-CORE-18, karyos#738).
    GuardPreview {
        kind: crate::preview::PreviewKind,
        dir: &'a str,
        guard: u64,
        reason: &'a str,
    },
    /// `submit OPID TOKEN guard-close|guard-reopen DIR GUARD [REASON]`
    /// (R-CORE-18, karyos#738).
    Submit {
        operation: u64,
        token: crate::preview::Token,
        kind: crate::preview::PreviewKind,
        dir: &'a str,
        guard: u64,
        reason: &'a str,
    },
    /// `legal-hold RECORDING [REASON]`, `hold-release RECORDING [REASON]`,
    /// `purge RECORDING BEFORE [REASON]` and `seal-verify RECORDING`
    /// (M12).
    Retention {
        operation: crate::retention::Operation,
        recording: u64,
        reason: &'a str,
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
    /// `rate-change DIR STREAM_ID SESSION_ID EXPECTED AUTHORITY MSG_RATE
    /// MSG_BURST BYTE_RATE BYTE_BURST [REASON]` (R-CORE-21, karyos#740).
    RateChange {
        dir: &'a str,
        stream: karyos_protocol::cnc::StreamKey,
        expected: u64,
        authority: karyos_protocol::cnc::RateAuthority,
        policy: karyos_sys::rate_limit::RatePolicy,
        reason: &'a str,
    },
    /// `join-put DIR KIND KEY NAME=VALUE...` (karyos#736).
    JoinPut {
        dir: &'a str,
        kind: Kind,
        key: &'a str,
        attributes: &'a str,
    },
    /// `join-retire DIR KIND KEY`.
    JoinRetire {
        dir: &'a str,
        kind: Kind,
        key: &'a str,
    },
    /// `join-get DIR KIND KEY [AT_NS]`.
    JoinGet {
        dir: &'a str,
        kind: Kind,
        key: &'a str,
        at: Option<u64>,
    },
    /// `join-list DIR [KIND KEY]`, after that key.
    JoinList {
        dir: &'a str,
        after: Option<(Kind, &'a str)>,
    },
    /// A `join-put` line longer than [`MAX_JOIN_REQUEST`].
    JoinTooLong,
    /// A well-formed request of another version.
    Version,
    Bad,
}

/// Reads one request line, up to [`MAX_JOIN_REQUEST`] bytes, the longest
/// any request may be ([`parse`] holds every other to [`MAX_REQUEST`]),
/// and a relay's prefix;
/// `None` when the client sent none in time or closed first.
fn read_request(stream: &UnixStream) -> Option<String> {
    let start = std::time::Instant::now();
    let limit = MAX_JOIN_REQUEST
        .checked_add(MAX_RELAY_PREFIX)?
        .checked_add(1)?;
    let mut stream = stream;
    let mut line = Vec::with_capacity(limit);
    let mut buffer = [0u8; MAX_JOIN_REQUEST + MAX_RELAY_PREFIX + 1];
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
    // A `join-put` may be longer than the others, up to its own bound.
    let join_put = line
        .split(' ')
        .nth(2)
        .is_some_and(|name| name.trim_end_matches(['\n', '\r']) == "join-put");
    if line.len() > MAX_JOIN_REQUEST && join_put {
        return Request::JoinTooLong;
    }
    if line.len() > MAX_REQUEST && !join_put {
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

/// A join registry request's arguments; `None` when malformed.
fn join_request<'a>(name: &str, arguments: &'a str) -> Option<Request<'a>> {
    let mut fields = arguments.splitn(4, ' ');
    let dir = fields.next().filter(|dir| !dir.is_empty())?;
    let kind = fields.next().map(Kind::parse);
    let key = fields.next().filter(|key| !key.is_empty());
    let rest = fields.next();
    match name {
        "join-put" => Some(Request::JoinPut {
            dir,
            kind: kind??,
            key: key?,
            attributes: rest?,
        }),
        "join-retire" => {
            if rest.is_some() {
                return None;
            }
            Some(Request::JoinRetire {
                dir,
                kind: kind??,
                key: key?,
            })
        }
        "join-get" => Some(Request::JoinGet {
            dir,
            kind: kind??,
            key: key?,
            at: match rest {
                None => None,
                Some(word) => Some(word.parse::<u64>().ok()?),
            },
        }),
        _ => match (kind, key, rest) {
            (None, None, None) => Some(Request::JoinList { dir, after: None }),
            (Some(Some(kind)), Some(key), None) => Some(Request::JoinList {
                dir,
                after: Some((kind, key)),
            }),
            _ => None,
        },
    }
}

/// A `rate-change` request's arguments: a byte rate and burst of 0 and 0
/// is no byte limit, as on the wire.
fn rate_change(arguments: &str) -> Option<Request<'_>> {
    use karyos_sys::rate_limit::{Rate, RatePolicy};
    let mut fields = arguments.splitn(10, ' ');
    let dir = fields.next().filter(|dir| !dir.is_empty())?;
    let stream = karyos_protocol::cnc::StreamKey {
        stream_id: fields.next()?.parse().ok()?,
        session_id: fields.next()?.parse().ok()?,
    };
    let number = |word: Option<&str>| word?.parse::<u64>().ok();
    let expected = number(fields.next())?;
    let authority = match fields.next()? {
        "safety" => karyos_protocol::cnc::RateAuthority::Safety,
        "administrator" => karyos_protocol::cnc::RateAuthority::Administrator,
        _ => return None,
    };
    let messages = Rate {
        per_second: number(fields.next())?,
        burst: number(fields.next())?,
    };
    let bytes = Rate {
        per_second: number(fields.next())?,
        burst: number(fields.next())?,
    };
    let reason = fields.next().unwrap_or("");
    let bytes = (bytes.per_second != 0 || bytes.burst != 0).then_some(bytes);
    Some(Request::RateChange {
        dir,
        stream,
        expected,
        authority,
        policy: RatePolicy { messages, bytes },
        reason,
    })
}

/// A v1 request and its arguments.
/// Whether `role` may preview or submit `kind`: as it may make it.
const fn may(role: Role, kind: crate::preview::PreviewKind) -> bool {
    match kind {
        crate::preview::PreviewKind::Close => role.may_close(),
        crate::preview::PreviewKind::Reopen => role.may_reopen(),
    }
}

/// The request name of a preview of `kind` (`preview`), or of `kind`.
const fn name_of(kind: crate::preview::PreviewKind, preview: bool) -> &'static str {
    match (kind, preview) {
        (crate::preview::PreviewKind::Close, true) => "guard-close-preview",
        (crate::preview::PreviewKind::Reopen, true) => "guard-reopen-preview",
        (kind, false) => kind.name(),
    }
}

/// `OPID TOKEN guard-close|guard-reopen DIR GUARD [REASON]` (karyos#738).
fn submit(arguments: &str) -> Option<Request<'_>> {
    let mut fields = arguments.splitn(6, ' ');
    let operation = fields.next()?.parse::<u64>().ok()?;
    let token = crate::preview::Token::parse(fields.next()?)?;
    let kind = match fields.next()? {
        "guard-close" => crate::preview::PreviewKind::Close,
        "guard-reopen" => crate::preview::PreviewKind::Reopen,
        _ => return None,
    };
    let dir = fields.next().filter(|dir| !dir.is_empty())?;
    let guard = fields.next()?.parse::<u64>().ok()?;
    let reason = fields.next().unwrap_or("");
    Some(Request::Submit {
        operation,
        token,
        kind,
        dir,
        guard,
        reason,
    })
}

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
        "rate-change" => rate_change(arguments).or(Some(Request::BadArguments("rate-change"))),
        "guard-close-preview" | "guard-reopen-preview" => {
            let kind = if name == "guard-close-preview" {
                crate::preview::PreviewKind::Close
            } else {
                crate::preview::PreviewKind::Reopen
            };
            let mut fields = arguments.splitn(3, ' ');
            let target = fields
                .next()
                .filter(|dir| !dir.is_empty())
                .zip(fields.next().and_then(number));
            let Some((dir, guard)) = target else {
                return Some(Request::BadArguments(name_of(kind, true)));
            };
            let reason = fields.next().unwrap_or("");
            Some(Request::GuardPreview {
                kind,
                dir,
                guard,
                reason,
            })
        }
        "submit" => submit(arguments).or(Some(Request::BadArguments("submit"))),
        "legal-hold" | "hold-release" | "seal-verify" => {
            let (recording, reason) = arguments.split_once(' ').unwrap_or((arguments, ""));
            let operation = match name {
                "legal-hold" => crate::retention::Operation::Hold,
                "hold-release" => crate::retention::Operation::Release,
                _ if reason.is_empty() => crate::retention::Operation::Verify,
                _ => return Some(Request::BadArguments("seal-verify")),
            };
            Some(Request::Retention {
                operation,
                recording: number(recording)?,
                reason,
            })
        }
        "purge" => {
            let mut fields = arguments.splitn(3, ' ');
            let recording = number(fields.next()?)?;
            let before = number(fields.next()?)?;
            Some(Request::Retention {
                operation: crate::retention::Operation::Purge { before },
                recording,
                reason: fields.next().unwrap_or(""),
            })
        }
        "limits" => Some(Request::Limits {
            proposals: arguments,
        }),
        // The join metadata registry (karyos#736): DIR, a kind and a key,
        // then a put's attributes, a get's instant or a list's cursor.
        "join-put" | "join-retire" | "join-get" | "join-list" => {
            Some(join_request(name, arguments).unwrap_or(match name {
                "join-put" => Request::BadArguments("join-put"),
                "join-retire" => Request::BadArguments("join-retire"),
                "join-get" => Request::BadArguments("join-get"),
                _ => Request::BadArguments("join-list"),
            }))
        }
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
        // A bounded reply, and a pair whose buffer is filled first and then
        // drained by less than the reply: a peer that reads no more blocks
        // the write part way, whatever the host's buffer size.
        let mut reply = json::trace_buckets(&first).into_bytes();
        reply.resize(REPLY_BYTES, b' ');
        reply.push(b'\n');
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        let Some(held) = fill_socket(&writer) else {
            return;
        };
        let drained = drain(&mut reader, (held / 2).min(REPLY_BYTES / 2));
        let start = std::time::Instant::now();
        assert!(!write_within(&mut writer, &reply, WRITE_DEADLINE));
        assert!(
            start.elapsed() < WRITE_DEADLINE + IO_TIMEOUT * 2,
            "{:?}",
            start.elapsed()
        );
        // As `serve` does after a cut.
        writer.shutdown(std::net::Shutdown::Both).unwrap();
        // The rest of the fill, then the cut reply, counted as they stream.
        let mut fill_left = held - drained;
        let mut cut = 0usize;
        let mut last = None;
        let mut buffer = vec![0u8; 64 << 10];
        loop {
            let read = reader.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            let skip = fill_left.min(read);
            fill_left -= skip;
            let bytes = &buffer[skip..read];
            if let Some(&byte) = bytes.last() {
                assert!(cut > 0 || bytes[0] == reply[0], "the cut starts the reply");
                last = Some(byte);
            }
            cut += bytes.len();
        }
        assert_eq!(fill_left, 0);
        assert!(cut > 0 && cut < reply.len(), "{cut}");
        assert_ne!(last, Some(b'\n'), "a cut reply has no final newline");
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

    /// The bounded reply of the deadline tests.
    const REPLY_BYTES: usize = 4 << 20;

    /// The most a deadline test fills a socket buffer with.
    const FILL_CAP: usize = 256 << 20;

    /// Fills a pair's buffer without blocking, writing one 64 KiB chunk
    /// over and over, and answers the bytes it holds; the socket is left
    /// blocking. A host may tune its default send buffer far above a fixed
    /// reply (one with `net.core.wmem_default` at 128 MiB held 64 MiB
    /// whole), so the tests fill it instead of outsizing it. The fill only
    /// uses kernel buffer memory and stops at 256 MiB: a buffer that holds
    /// that much answers `None`, and the test skips its blocking assertions
    /// with a logged reason rather than fill further.
    #[allow(clippy::print_stderr, reason = "a skipped test logs why")]
    fn fill_socket(writer: &UnixStream) -> Option<usize> {
        writer.set_nonblocking(true).unwrap();
        let chunk = [0u8; 64 << 10];
        let mut held = 0usize;
        loop {
            match (&*writer).write(&chunk) {
                Ok(written) if written > 0 => held += written,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                other => panic!("filling the socket: {other:?}"),
            }
            if held >= FILL_CAP {
                eprintln!("skipped: this host's socket buffer holds {FILL_CAP} bytes or more");
                return None;
            }
        }
        writer.set_nonblocking(false).unwrap();
        Some(held)
    }

    /// Reads exactly `bytes` of the fill and discards them.
    fn drain(reader: &mut UnixStream, bytes: usize) -> usize {
        let mut buffer = vec![0u8; 64 << 10];
        let mut left = bytes;
        while left > 0 {
            let want = left.min(buffer.len());
            reader.read_exact(&mut buffer[..want]).unwrap();
            left -= want;
        }
        bytes
    }

    /// Review B1 of #826: a client that reads a few KiB at a time, often
    /// enough for each write to progress, still cannot stretch a reply past
    /// its deadline: it is checked after every write.
    #[test]
    fn a_trickling_reader_cannot_stretch_the_deadline() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        let Some(held) = fill_socket(&writer) else {
            return;
        };
        let trickle = std::thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            let mut total = 0;
            let started = std::time::Instant::now();
            // It trickles until the writer's deadline has long passed, then
            // stops: draining a large host buffer at this pace would take
            // minutes.
            while let Ok(read) = reader.read(&mut buffer) {
                if read == 0 || started.elapsed() > WRITE_DEADLINE * 4 {
                    break;
                }
                total += read;
                std::thread::sleep(Duration::from_millis(20));
            }
            total
        });
        let reply = vec![b'z'; REPLY_BYTES];
        let start = std::time::Instant::now();
        assert!(!write_within(&mut writer, &reply, WRITE_DEADLINE));
        let took = start.elapsed();
        // The deadline plus the one write it cut short, with a write's
        // timeout of slack for a loaded machine's scheduling: a trickling
        // reader once held it for seconds.
        assert!(took < WRITE_DEADLINE + IO_TIMEOUT * 2, "{took:?}");
        writer.shutdown(std::net::Shutdown::Both).unwrap();
        assert!(trickle.join().unwrap() < held + reply.len());
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

    /// R-CORE-21 (karyos#740): a rate change's stream, version, authority
    /// and policy, a byte rate and burst of 0 and 0 being no byte limit;
    /// malformed arguments get the request's own typed error.
    #[test]
    fn rate_change_requests_parse_with_their_policy() {
        use karyos_protocol::cnc::{RateAuthority, StreamKey};
        use karyos_sys::rate_limit::{Rate, RatePolicy};
        let stream = StreamKey {
            stream_id: 7,
            session_id: -2,
        };
        assert_eq!(
            parse("KARYOS-AGENT 1 rate-change /run/a 7 -2 3 safety 100 10 0 0 incident 4\n"),
            Request::RateChange {
                dir: "/run/a",
                stream,
                expected: 3,
                authority: RateAuthority::Safety,
                policy: RatePolicy {
                    messages: Rate {
                        per_second: 100,
                        burst: 10,
                    },
                    bytes: None,
                },
                reason: "incident 4",
            }
        );
        assert_eq!(
            parse("KARYOS-AGENT 1 rate-change /run/a 7 -2 3 administrator 100 10 4096 2048"),
            Request::RateChange {
                dir: "/run/a",
                stream,
                expected: 3,
                authority: RateAuthority::Administrator,
                policy: RatePolicy {
                    messages: Rate {
                        per_second: 100,
                        burst: 10,
                    },
                    bytes: Some(Rate {
                        per_second: 4096,
                        burst: 2048,
                    }),
                },
                reason: "",
            }
        );
        for line in [
            "KARYOS-AGENT 1 rate-change /run/a 7 -2 3 root 100 10 0 0",
            "KARYOS-AGENT 1 rate-change /run/a 7 -2 3 safety 100 10 0",
            "KARYOS-AGENT 1 rate-change /run/a x -2 3 safety 100 10 0 0",
            "KARYOS-AGENT 1 rate-change  7 -2 3 safety 100 10 0 0",
        ] {
            assert_eq!(parse(line), Request::BadArguments("rate-change"), "{line}");
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

    fn callers() -> Callers {
        Callers {
            // The relay's uid 990 is also a local administrator.
            roles: vec![(1000, Role::Viewer), (990, Role::Administrator)],
            relays: vec![(990, 7)],
            principals: vec![
                Principal::new("svc.viewer", 50_001, Role::Viewer).unwrap(),
                Principal::new("alice@example", 50_002, Role::RiskOfficer).unwrap(),
            ],
        }
    }

    /// A relayed request takes its principal's role from the agent's own
    /// table (karyos#708): a relay that is an administrator on the local
    /// socket, or that names a role as the principal, grants nothing.
    #[test]
    fn a_relay_cannot_grant_a_role() {
        let callers = callers();
        let (requester, role, line) = authorize(
            &callers,
            Some(990),
            "KARYOS-AGENT 1 relay svc.viewer guard-close /d 3 drill\n",
        )
        .unwrap();
        assert_eq!(requester, crate::Requester::relayed(50_001, 7));
        assert_eq!(role, Role::Viewer);
        assert!(!role.may_close());
        assert_eq!(line, "KARYOS-AGENT 1 guard-close /d 3 drill\n");
        // A role's name is no principal, and a principal's name no role.
        for name in [
            "administrator",
            "svc.viewer:administrator",
            "role=administrator",
        ] {
            let line = format!("KARYOS-AGENT 1 relay {name} gap-ack 1\n");
            assert_eq!(authorize(&callers, Some(990), &line), None, "{name}");
        }
        // The relay's own requests are its local role's, as before.
        let (requester, role, _) = authorize(&callers, Some(990), "KARYOS-AGENT 1 view\n").unwrap();
        assert_eq!(
            (requester, role),
            (crate::Requester::local(990), Role::Administrator)
        );
        let (requester, role, _) = authorize(
            &callers,
            Some(990),
            "KARYOS-AGENT 1 relay alice@example guard-reopen /d 3 9\n",
        )
        .unwrap();
        assert_eq!(
            (requester, role),
            (crate::Requester::relayed(50_002, 7), Role::RiskOfficer)
        );
    }

    /// Only a relay's uid may relay, only for a known principal, and a
    /// relayed line keeps its version for the request's own parsing.
    #[test]
    fn only_a_relay_relays_for_a_known_principal() {
        let callers = callers();
        let line = "KARYOS-AGENT 1 relay svc.viewer view\n";
        assert_eq!(authorize(&callers, Some(1000), line), None);
        assert_eq!(authorize(&callers, Some(4242), line), None);
        assert_eq!(authorize(&callers, None, line), None);
        for line in [
            "KARYOS-AGENT 1 relay nobody view\n",
            "KARYOS-AGENT 1 relay svc.viewer\n",
            "KARYOS-AGENT 1 relay  view\n",
        ] {
            assert_eq!(authorize(&callers, Some(990), line), None, "{line}");
        }
        let (_, _, line) = authorize(
            &callers,
            Some(990),
            "KARYOS-AGENT 2 relay svc.viewer view\n",
        )
        .unwrap();
        assert_eq!(parse(&line), Request::Version);
        // The local uid mode is unchanged: the same line, the same role.
        let (requester, role, line) =
            authorize(&callers, Some(1000), "KARYOS-AGENT 1 view\n").unwrap();
        assert_eq!(
            (requester, role),
            (crate::Requester::local(1000), Role::Viewer)
        );
        assert_eq!(line, "KARYOS-AGENT 1 view\n");
        assert_eq!(
            authorize(&callers, Some(4242), "KARYOS-AGENT 1 view\n"),
            None
        );
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
        // The registrar writes the join registry and nothing else
        // (karyos#736); an administrator may too.
        let registrar = Role::parse("registrar").unwrap();
        assert!(registrar.may_register());
        assert!(!registrar.may_close() && !registrar.may_reopen() && !registrar.may_acknowledge());
        assert!(Role::Administrator.may_register());
        assert!(!Role::Viewer.may_register() && !Role::Operator.may_register());
    }

    /// A join request line: the head and a tail of generated words, or
    /// any text, around both request bounds.
    fn join_line() -> impl proptest::strategy::Strategy<Value = String> {
        use proptest::prelude::*;
        let word = proptest::collection::vec(
            prop_oneof![
                6 => proptest::char::range('a', 'z'),
                1 => proptest::char::range('0', '9'),
                1 => Just('='),
                1 => Just(' '),
                1 => Just('\r'),
                1 => Just('é'),
            ],
            0..80,
        )
        .prop_map(|chars| chars.into_iter().collect::<String>());
        let name = prop_oneof![
            Just("join-put"),
            Just("join-retire"),
            Just("join-get"),
            Just("join-list"),
            Just("view"),
        ];
        let kind = prop_oneof![
            Just("stream"),
            Just("point"),
            Just("counter"),
            Just("table")
        ];
        prop_oneof![
            (
                name,
                kind,
                proptest::collection::vec(word, 0..20),
                any::<bool>()
            )
                .prop_map(|(name, kind, words, newline)| {
                    let tail = words.join(" ");
                    let end = if newline { "\n" } else { "" };
                    format!("KARYOS-AGENT 1 {name} /run/d {kind} {tail}{end}")
                }),
            any::<String>(),
        ]
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(1024))]

        /// Any line (karyos#893): the parser never panics; a join request
        /// it reads came from a line within its bound, and each field it
        /// returns is text of that line.
        #[test]
        fn a_join_request_parses_within_its_bounds(line in join_line()) {
            let parsed = parse(&line);
            let within = |field: &str| line.contains(field);
            match parsed {
                Request::JoinPut { dir, key, attributes, .. } => {
                    proptest::prop_assert!(line.len() <= MAX_JOIN_REQUEST);
                    proptest::prop_assert!(within(dir) && within(key) && within(attributes));
                    proptest::prop_assert!(!key.is_empty());
                }
                Request::JoinRetire { dir, key, .. } | Request::JoinGet { dir, key, .. } => {
                    proptest::prop_assert!(line.len() <= MAX_REQUEST);
                    proptest::prop_assert!(within(dir) && within(key) && !key.is_empty());
                }
                Request::JoinList { dir, after } => {
                    proptest::prop_assert!(line.len() <= MAX_REQUEST);
                    proptest::prop_assert!(within(dir));
                    if let Some((_, key)) = after {
                        proptest::prop_assert!(within(key) && !key.is_empty());
                    }
                }
                Request::JoinTooLong => proptest::prop_assert!(line.len() > MAX_JOIN_REQUEST),
                _ => {}
            }
        }
    }
}
