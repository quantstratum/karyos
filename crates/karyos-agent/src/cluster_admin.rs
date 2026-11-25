// SPDX-License-Identifier: Apache-2.0

//! A product Cluster's admin commands through the agent (R-CORE-41,
//! karyos#772; quantstratum-docs: karyos/design/product-requirements-on-core.md,
//! the R-CORE-41 row): an authorised operator submits a command the
//! product registered, the agent journals it before and after, forwards
//! it to the product's Cluster and returns its sequenced outcome with the
//! evidence digest the product attached.
//!
//! This module is the contract; `tests/cluster_admin.rs` checks it
//! against a fixture product Cluster built on C10's service container
//! (`karyos_cluster::service`).
//!
//! # The request
//!
//! `cluster-command OPID CLUSTER COMMAND PARAMETERS [REASON]` on API v1
//! (see `server`), relayed or local as every v1 request (karyos#708):
//!
//! - `OPID`: the caller's operation id, a nonzero `u64`. One id names one
//!   operation. An id becomes used when the command is dispatched (its
//!   request record durable, the gateway called), whatever comes of it,
//!   `unknown` included; an id used in this run or a journalled earlier
//!   one is refused as `operation id conflict`, unsent. An id stays free
//!   after an agent refusal, `busy`, `journal unavailable` and `bad
//!   arguments`. An id of 0, or parameters past [`MAX_PARAMETERS`], are
//!   `bad arguments` on every path ([`cluster_command`]), neither
//!   journalled nor sent.
//! - `CLUSTER`: the name the product's Cluster was attached under
//!   ([`valid_name`]).
//! - `COMMAND`: one of the names the product registered for that Cluster
//!   ([`AdminCommand`]).
//! - `PARAMETERS`: the command's parameters, opaque bytes as lowercase or
//!   uppercase hex, at most [`MAX_PARAMETERS`] bytes; `-` for none.
//! - `REASON`: the operator's reason, the rest of the line, cut to the
//!   journal's [`MAX_REASON`] bytes.
//! - The requester: the local peer's uid, or a relay's principal
//!   (`KARYOS-AGENT 1 relay PRINCIPAL cluster-command ...`) with the
//!   operator id and role this agent's principal table gives it: the
//!   principal's role authorises the command, never the relay's. The
//!   journal records the operator and the relay apart.
//!
//! # Registration
//!
//! The product attaches its Cluster with [`ClusterGateway`]
//! (`Agent::attach_cluster`): the gateway names the commands the product
//! accepts ([`ClusterGateway::commands`]), each with the [`Authority`] it
//! needs, read once at attach. The agent forwards only a registered name;
//! any other is refused as `unregistered command`, journalled, unsent.
//! The agent never reads a command's name or parameters for meaning: it
//! matches the name against the registration, and passes both, with the
//! operation id and the requester, to the gateway as they came. What
//! "kill", "reopen" or "upgrade activation" do is the product's.
//!
//! # Authorisation
//!
//! By the caller's role ([`Clearance`], from the server's role table):
//!
//! | Command's authority | Viewer | Registrar | Operator | Risk officer | Administrator |
//! |---------------------|--------|-----------|----------|--------------|---------------|
//! | operator            | no     | no        | yes      | yes          | yes           |
//! | administrator       | no     | no        | no       | no           | yes           |
//!
//! The capability `cluster-command` is served to a role only when an
//! attached Cluster registers a command that role may make.
//!
//! A caller without the command's authority is answered `forbidden`, and
//! the refusal is journalled ([`Kind::ClusterRefused`], code
//! [`RefusalCode::Forbidden`]) with nothing sent.
//!
//! # The journal
//!
//! - **Before.** A [`Kind::ClusterRequest`] record, durable, before the
//!   command is sent: the only record that is durable and the only one
//!   that gates dispatch. The core cannot tell a command that only makes the
//!   product safer from one that loosens it, so every admin command fails
//!   closed: without a journal, or when the append fails, it is answered
//!   `journal unavailable` and never sent.
//! - **After.** A [`Kind::ClusterOutcome`] record: `code` 0 for a
//!   sequenced command, with the log index in `word` and the term in
//!   `expected`; the product's refusal code otherwise; or
//!   [`UNKNOWN_OUTCOME`]. Appended, not waited for: when the append fails
//!   the answer keeps the product's result and carries
//!   `"journalled":false`, so the caller reconciles it without retrying.
//! - **Refused before sending.** A [`Kind::ClusterRefused`] record, its
//!   [`RefusalCode`] in `code`, for a forbidden role, an unregistered
//!   command, an unknown Cluster and an operation id conflict; the answer
//!   carries `"journalled":true` or `false` as the append went.
//! - **Busy.** The Cluster is reserved from before the request record
//!   until the worker that called its gateway exits, so a command made
//!   while another is in flight, even one whose caller already got
//!   `unknown`, is `busy`: neither journalled nor sent.
//! - Each of the three carries the Cluster's name ([`JournalRecord::target`]),
//!   the command's name ([`JournalRecord::command`]) and, on an outcome,
//!   the evidence ([`JournalRecord::evidence`]); `parameters` is the
//!   digest of the parameters' bytes with the operation and the operator.
//!
//! # The outcome
//!
//! - **Sequenced** ([`ClusterAnswer::Sequenced`]): the Cluster's log
//!   applied the command at an index and term, and the product's reply
//!   bytes (opaque, shown as hex) with the evidence digest it attached.
//! - **Refused** ([`ClusterAnswer::Refused`]): the product refused it,
//!   with its code and reason, verbatim.
//! - **Unknown** ([`ClusterAnswer::NoAnswer`]): the gateway gave no
//!   answer, or none within the agent's wait. The command may or may not
//!   have been sequenced: the outcome record carries [`UNKNOWN_OUTCOME`],
//!   never success. An agent that stops between the request record and
//!   the outcome record leaves a request without outcome, which the next
//!   start journals as an unknown interval
//!   ([`crate::journal::GapReason::RequestWithoutOutcome`]).
//!
//! # Evidence
//!
//! A product attaches an [`Evidence`] to a sequenced reply (for an upgrade
//! activation, the digest of the replay evidence it checked): an
//! algorithm name and a digest of at most [`MAX_EVIDENCE`] bytes. The
//! agent does not compute or check it: it shows it in the answer
//! (`"evidence":{"algorithm":...,"digest":<hex>}`, or `null` when none was
//! attached) and journals it as `<algorithm>:<hex digest>` in the outcome
//! record.

use std::num::NonZeroU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use crate::journal::{Journal, JournalRecord, Kind, MAX_REASON, UNKNOWN_OUTCOME};

/// The longest Cluster or command name, in bytes.
pub const MAX_NAME: usize = 32;
/// The most parameter bytes a command carries.
pub const MAX_PARAMETERS: usize = 48;
/// The most bytes of an evidence digest.
pub const MAX_EVIDENCE: usize = 64;
/// The longest evidence algorithm name, in bytes.
pub const MAX_ALGORITHM: usize = 16;
/// The most reply bytes the agent shows of a sequenced command; a longer
/// reply is refused by [`ClusterReply::sequenced`].
pub const MAX_REPLY: usize = 1024;
/// The longest refusal reason the agent keeps of the product's, in bytes.
pub const MAX_PRODUCT_REASON: usize = 128;
/// The Clusters an agent attaches at most.
pub const MAX_CLUSTERS: usize = 16;
/// The commands one Cluster registers at most.
pub const MAX_COMMANDS: usize = 64;

/// Whether `name` is a valid Cluster or command name: 1 to [`MAX_NAME`]
/// bytes of ASCII lowercase letters, digits, `.`, `_` and `-`.
#[must_use]
pub fn valid_name(name: &str) -> bool {
    (1..=MAX_NAME).contains(&name.len())
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

/// What a registered command needs of its caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Authority {
    /// An operator, a risk officer or an administrator.
    Operator,
    /// An administrator only.
    Administrator,
}

/// What the caller's role grants for admin commands (the server maps each
/// role to one; see the module's table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Clearance {
    /// A viewer or a registrar: no admin command.
    None,
    /// An operator or a risk officer: operator commands.
    Operator,
    /// An administrator: every command.
    Administrator,
}

impl Clearance {
    /// Whether it allows a command that needs `authority`.
    #[must_use]
    pub const fn allows(self, authority: Authority) -> bool {
        matches!(
            (self, authority),
            (Self::Operator | Self::Administrator, Authority::Operator)
                | (Self::Administrator, Authority::Administrator)
        )
    }
}

/// A command a product's Cluster accepts: its name and the authority it
/// needs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AdminCommand {
    /// Its name ([`valid_name`]).
    pub name: String,
    /// What it needs of its caller.
    pub authority: Authority,
}

impl AdminCommand {
    /// Command `name`, for callers with `authority`; `None` for a name
    /// that is not valid.
    #[must_use]
    pub fn new(name: &str, authority: Authority) -> Option<Self> {
        valid_name(name).then(|| Self {
            name: name.to_owned(),
            authority,
        })
    }
}

/// The digest a product attached to a sequenced command.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Evidence {
    /// The digest's algorithm, as the product names it ([`valid_name`],
    /// at most [`MAX_ALGORITHM`] bytes).
    pub algorithm: String,
    /// The digest, 1 to [`MAX_EVIDENCE`] bytes.
    pub digest: Vec<u8>,
}

impl Evidence {
    /// `digest` under `algorithm`; `None` for an algorithm name that is
    /// not valid or longer than [`MAX_ALGORITHM`], or a digest that is
    /// empty or longer than [`MAX_EVIDENCE`].
    #[must_use]
    pub fn new(algorithm: &str, digest: &[u8]) -> Option<Self> {
        (valid_name(algorithm)
            && algorithm.len() <= MAX_ALGORITHM
            && (1..=MAX_EVIDENCE).contains(&digest.len()))
        .then(|| Self {
            algorithm: algorithm.to_owned(),
            digest: digest.to_vec(),
        })
    }

    /// As journalled: `<algorithm>:<lowercase hex digest>`.
    #[must_use]
    pub fn journalled(&self) -> Vec<u8> {
        let mut out = self.algorithm.clone().into_bytes();
        out.push(b':');
        out.extend_from_slice(hex(&self.digest).as_bytes());
        out
    }
}

/// A product's refusal code: never 0 (success) and never
/// [`UNKNOWN_OUTCOME`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductCode(NonZeroU64);

impl ProductCode {
    /// Code `code`; `None` for 0 or [`UNKNOWN_OUTCOME`].
    #[must_use]
    pub fn new(code: u64) -> Option<Self> {
        if code == UNKNOWN_OUTCOME {
            return None;
        }
        NonZeroU64::new(code).map(Self)
    }

    /// Its value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// What the product's Cluster answered, as its gateway reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClusterReply {
    /// The Cluster's log applied the command.
    Sequenced {
        /// The entry's log index.
        index: u64,
        /// The entry's term.
        term: u64,
        /// The product's reply, at most [`MAX_REPLY`] bytes.
        reply: Vec<u8>,
        /// The evidence the product attached, if any.
        evidence: Option<Evidence>,
    },
    /// The product refused it.
    Refused {
        /// The product's code.
        code: ProductCode,
        /// Its reason, at most [`MAX_PRODUCT_REASON`] bytes.
        reason: String,
    },
    /// No answer: the command may or may not have been sequenced.
    NoAnswer,
}

impl ClusterReply {
    /// A sequenced reply; `None` for a reply longer than [`MAX_REPLY`].
    #[must_use]
    pub fn sequenced(
        index: u64,
        term: u64,
        reply: &[u8],
        evidence: Option<Evidence>,
    ) -> Option<Self> {
        (reply.len() <= MAX_REPLY).then(|| Self::Sequenced {
            index,
            term,
            reply: reply.to_vec(),
            evidence,
        })
    }

    /// A refusal; the reason is cut to [`MAX_PRODUCT_REASON`] bytes, at a
    /// character boundary.
    #[must_use]
    pub fn refused(code: ProductCode, reason: &str) -> Self {
        let mut end = reason.len().min(MAX_PRODUCT_REASON);
        while !reason.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        Self::Refused {
            code,
            reason: reason.get(..end).unwrap_or("").to_owned(),
        }
    }
}

/// A command as the gateway receives it: what the operator asked, unread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Submission<'a> {
    /// The registered command's name.
    pub command: &'a str,
    /// Its parameters, as they came.
    pub parameters: &'a [u8],
    /// The operation id, as journalled: a gateway over C10 uses it as the
    /// request's identity, so that the Cluster's deduplication runs it
    /// once.
    pub operation: u64,
    /// The operator.
    pub operator: u32,
    /// The relay that carried the request, 0 for none.
    pub relay: u64,
}

/// A product's Cluster, as the agent reaches it. The product implements
/// it over its Cluster's ingress (C10's service container proposes the
/// command and answers it when the entry applies); the core holds no
/// Cluster client of its own.
pub trait ClusterGateway: Send + core::fmt::Debug {
    /// The commands the product accepts, read once when the Cluster is
    /// attached.
    fn commands(&self) -> Vec<AdminCommand>;

    /// Submits `submission` and waits for its outcome. Called off the
    /// agent's polling thread, which waits for it a bounded time; a reply
    /// that comes later is lost, and the outcome journalled as unknown.
    fn submit(&mut self, submission: &Submission<'_>) -> ClusterReply;
}

/// A gateway shared with the worker that calls it.
pub type SharedGateway = Arc<Mutex<Box<dyn ClusterGateway>>>;

/// An attached Cluster: its name, registration and gateway.
#[derive(Debug, Clone)]
pub struct Attached {
    name: String,
    commands: Vec<AdminCommand>,
    gateway: SharedGateway,
    /// Set from before a command's request record is appended until the
    /// worker that calls the gateway exits (karyos#772 review): while set,
    /// another command to this Cluster is `busy`, neither journalled nor
    /// sent.
    in_flight: Arc<AtomicBool>,
}

/// A Cluster's in-flight reservation: cleared when dropped.
#[derive(Debug)]
struct Reservation(Arc<AtomicBool>);

impl Reservation {
    /// Takes `flag`; `None` when it is already taken.
    fn take(flag: &Arc<AtomicBool>) -> Option<Self> {
        flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Self(Arc::clone(flag)))
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl Attached {
    /// Its name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The commands it registered.
    #[must_use]
    pub fn commands(&self) -> &[AdminCommand] {
        &self.commands
    }
}

/// Why a Cluster could not be attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AttachError {
    /// The name is not valid ([`valid_name`]).
    #[error("not a valid cluster name")]
    Name,
    /// A Cluster of that name is attached.
    #[error("a cluster of that name is attached")]
    Duplicate,
    /// [`MAX_CLUSTERS`] are attached.
    #[error("{MAX_CLUSTERS} clusters are attached")]
    TooMany,
    /// The registration names a command twice, or more than
    /// [`MAX_COMMANDS`].
    #[error("the registration names a command twice or more than {MAX_COMMANDS} commands")]
    Registration,
}

/// The Clusters attached to an agent.
#[derive(Debug, Default)]
pub struct Clusters {
    attached: Vec<Attached>,
}

impl Clusters {
    /// Attaches `gateway` as `name`, reading its registration.
    ///
    /// # Errors
    ///
    /// [`AttachError`], with nothing attached.
    pub fn attach(
        &mut self,
        name: &str,
        gateway: Box<dyn ClusterGateway>,
    ) -> Result<(), AttachError> {
        if !valid_name(name) {
            return Err(AttachError::Name);
        }
        if self.find(name).is_some() {
            return Err(AttachError::Duplicate);
        }
        if self.attached.len() >= MAX_CLUSTERS {
            return Err(AttachError::TooMany);
        }
        let commands = gateway.commands();
        let mut names: Vec<&str> = commands
            .iter()
            .map(|command| command.name.as_str())
            .collect();
        names.sort_unstable();
        names.dedup();
        if names.len() != commands.len() || commands.len() > MAX_COMMANDS {
            return Err(AttachError::Registration);
        }
        self.attached.push(Attached {
            name: name.to_owned(),
            commands,
            gateway: Arc::new(Mutex::new(gateway)),
            in_flight: Arc::default(),
        });
        Ok(())
    }

    /// The Cluster attached as `name`.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&Attached> {
        self.attached.iter().find(|cluster| cluster.name == name)
    }

    /// Whether an attached Cluster registers a command `clearance`
    /// allows.
    #[must_use]
    pub fn any_allowed(&self, clearance: Clearance) -> bool {
        self.attached.iter().any(|cluster| {
            cluster
                .commands
                .iter()
                .any(|command| clearance.allows(command.authority))
        })
    }

    /// Whether none is attached.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.attached.is_empty()
    }

    /// The attached Clusters.
    #[must_use]
    pub fn attached(&self) -> &[Attached] {
        &self.attached
    }
}

/// Why a command was refused before it was sent, as journalled in a
/// [`Kind::ClusterRefused`] record's `code`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RefusalCode {
    /// The caller's role does not allow the command.
    Forbidden,
    /// The Cluster did not register the command.
    UnregisteredCommand,
    /// No Cluster is attached under the name.
    UnknownCluster,
    /// The operation id was used before.
    OperationConflict,
}

impl RefusalCode {
    /// The code a refusal record carries.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            Self::Forbidden => 1,
            Self::UnregisteredCommand => 2,
            Self::UnknownCluster => 3,
            Self::OperationConflict => 4,
        }
    }

    /// The refusal's text in an answer.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::Forbidden => "forbidden",
            Self::UnregisteredCommand => "unregistered command",
            Self::UnknownCluster => "unknown cluster",
            Self::OperationConflict => "operation id conflict",
        }
    }
}

/// What an admin command came to.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClusterAnswer {
    /// The Cluster sequenced it.
    Sequenced {
        /// The operation id.
        operation: u64,
        /// The entry's log index.
        index: u64,
        /// The entry's term.
        term: u64,
        /// The product's reply.
        reply: Vec<u8>,
        /// The evidence the product attached.
        evidence: Option<Evidence>,
        /// Whether its outcome record was written; `false` when the
        /// append failed: the result stands, its record is missing.
        journalled: bool,
    },
    /// The product refused it.
    Refused {
        /// The operation id.
        operation: u64,
        /// The product's code.
        code: u64,
        /// Its reason.
        reason: String,
        /// Whether its outcome record was written.
        journalled: bool,
    },
    /// Refused by the agent, never sent.
    Rejected {
        /// Why.
        code: RefusalCode,
        /// Whether its refusal record was written.
        journalled: bool,
    },
    /// No durable request record: never sent, the id still free.
    JournalUnavailable,
    /// An earlier command to the same Cluster is still in flight: not
    /// sent, not journalled, the id still free.
    Busy,
    /// An operation id of 0, or parameters past [`MAX_PARAMETERS`]:
    /// neither journalled nor sent.
    BadArguments,
    /// Sent, and no answer came: unknown, journalled as such.
    NoAnswer {
        /// The operation id.
        operation: u64,
        /// Whether its outcome record was written.
        journalled: bool,
    },
}

/// One admin command as asked.
#[derive(Debug, Clone, Copy)]
pub struct Command<'a> {
    /// The Cluster's name.
    pub cluster: &'a str,
    /// The command's name.
    pub command: &'a str,
    /// Its parameters, at most [`MAX_PARAMETERS`] bytes.
    pub parameters: &'a [u8],
    /// The caller's operation id.
    pub operation: u64,
    /// The operator.
    pub operator: u32,
    /// The relay, 0 for none.
    pub relay: u64,
    /// What the caller's role grants.
    pub clearance: Clearance,
    /// The reason; at most [`MAX_REASON`] bytes are kept.
    pub reason: &'a [u8],
}

impl Command<'_> {
    fn record(&self, kind: Kind, now: u64) -> JournalRecord {
        let reason = self.reason.get(..MAX_REASON).unwrap_or(self.reason);
        let mut record = JournalRecord::new(kind, now);
        record.operation = self.operation;
        record.operator = u64::from(self.operator);
        record.parameters = karyos_protocol::cnc::guard_parameters(
            0,
            0,
            self.operation,
            u64::from(self.operator),
            self.parameters,
        );
        record.reason = reason.to_vec();
        record.relay = self.relay;
        record.target = self.cluster.as_bytes().to_vec();
        record.command = self.command.as_bytes().to_vec();
        record
    }
}

/// Makes `command` on `clusters`, journalled in `journal`: refused and
/// journalled, unsent, for an unknown Cluster, an unregistered command, a
/// caller without the command's authority or an id in `used`; `busy`,
/// unjournalled and unsent, while another command to the Cluster is in
/// flight; otherwise sent only once its request record is durable, its
/// outcome journalled after it. The gateway is called on a worker and
/// waited for at most `wait`; no answer in time is unknown. `used` decides
/// whether the id is fresh, and is told when it is taken: when the command
/// is dispatched, whatever comes of it.
pub fn cluster_command(
    mut journal: Option<&mut Journal>,
    clusters: &Clusters,
    command: &Command<'_>,
    (wait, used): (Duration, impl FnMut(u64, bool) -> bool),
    mut now: impl FnMut() -> u64,
) -> ClusterAnswer {
    match dispatch(
        journal.as_deref_mut(),
        clusters,
        command,
        (wait, used),
        &mut now,
    ) {
        Dispatched::Answered(answer) => answer,
        Dispatched::Sent(answer) => record_outcome(journal, command, answer, now),
    }
}

/// What [`dispatch`] came to.
enum Dispatched {
    /// Answered without sending: its answer is final.
    Answered(ClusterAnswer),
    /// Sent: its answer, whose outcome record is still to write.
    Sent(ClusterAnswer),
}

/// Checks `command`, journals its request and calls the gateway: every
/// step of [`cluster_command`] but the outcome record.
fn dispatch(
    journal: Option<&mut Journal>,
    clusters: &Clusters,
    command: &Command<'_>,
    (wait, mut used): (Duration, impl FnMut(u64, bool) -> bool),
    now: &mut impl FnMut() -> u64,
) -> Dispatched {
    // Checked here, whoever calls: nothing is journalled or sent.
    if command.operation == 0 || command.parameters.len() > MAX_PARAMETERS {
        return Dispatched::Answered(ClusterAnswer::BadArguments);
    }
    let refusal = match clusters.find(command.cluster) {
        None => Err(RefusalCode::UnknownCluster),
        Some(cluster) => match cluster
            .commands
            .iter()
            .find(|registered| registered.name == command.command)
        {
            None => Err(RefusalCode::UnregisteredCommand),
            Some(registered) if !command.clearance.allows(registered.authority) => {
                Err(RefusalCode::Forbidden)
            }
            // Checked, not taken: an id is used up only once sent.
            Some(_) if used(command.operation, false) => Err(RefusalCode::OperationConflict),
            Some(_) => Ok(cluster),
        },
    };
    let cluster = match refusal {
        Ok(cluster) => cluster,
        Err(code) => {
            let journalled = journal.is_some_and(|journal| {
                let mut record = command.record(Kind::ClusterRefused, now());
                record.code = code.code();
                journal.append(&record, record.time).is_ok()
            });
            return Dispatched::Answered(ClusterAnswer::Rejected { code, journalled });
        }
    };
    // Reserved before the request record and held by the worker until it
    // exits, so a second command is `busy`, unjournalled and unsent, even
    // after this one's caller stopped waiting.
    let Some(reservation) = Reservation::take(&cluster.in_flight) else {
        return Dispatched::Answered(ClusterAnswer::Busy);
    };
    let record = command.record(Kind::ClusterRequest, now());
    let durable =
        journal.is_some_and(|journal| journal.append_durable(&record, record.time).is_ok());
    if !durable {
        return Dispatched::Answered(ClusterAnswer::JournalUnavailable);
    }
    let _ = used(command.operation, true);
    let operation = command.operation;
    let journalled = false;
    Dispatched::Sent(match call(&cluster.gateway, command, wait, reservation) {
        Some(ClusterReply::Sequenced {
            index,
            term,
            reply,
            evidence,
        }) => ClusterAnswer::Sequenced {
            operation,
            index,
            term,
            reply,
            evidence,
            journalled,
        },
        Some(ClusterReply::Refused { code, reason }) => ClusterAnswer::Refused {
            operation,
            code: code.get(),
            reason,
            journalled,
        },
        Some(ClusterReply::NoAnswer) | None => ClusterAnswer::NoAnswer {
            operation,
            journalled,
        },
    })
}

/// Journals the outcome of the sent `command`, `answer`, and reports in
/// it whether the record was written: a failed append keeps the product's
/// result and says its record is missing.
fn record_outcome(
    journal: Option<&mut Journal>,
    command: &Command<'_>,
    mut answer: ClusterAnswer,
    mut now: impl FnMut() -> u64,
) -> ClusterAnswer {
    let mut record = command.record(Kind::ClusterOutcome, now());
    match &answer {
        ClusterAnswer::Sequenced {
            index,
            term,
            evidence,
            ..
        } => {
            record.word = *index;
            record.expected = *term;
            record.evidence = evidence
                .as_ref()
                .map(Evidence::journalled)
                .unwrap_or_default();
        }
        ClusterAnswer::Refused { code, .. } => record.code = *code,
        _ => record.code = UNKNOWN_OUTCOME,
    }
    let written = journal.is_some_and(|journal| journal.append(&record, record.time).is_ok());
    match &mut answer {
        ClusterAnswer::Sequenced { journalled, .. }
        | ClusterAnswer::Refused { journalled, .. }
        | ClusterAnswer::NoAnswer { journalled, .. } => *journalled = written,
        _ => {}
    }
    answer
}

/// Calls the gateway for `command` on a worker, waiting at most `wait`:
/// `None` when no answer came in time, the call then finishing on its own.
/// The worker holds `reservation` while it calls the gateway, and releases
/// it, with the gateway's lock, before it hands the reply over: a caller
/// that has its answer finds the Cluster free for its next command, never
/// `busy` from a worker that answered and has not exited yet (karyos#1067).
fn call(
    gateway: &SharedGateway,
    command: &Command<'_>,
    wait: Duration,
    reservation: Reservation,
) -> Option<ClusterReply> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let gateway = Arc::clone(gateway);
    let name = command.command.to_owned();
    let parameters = command.parameters.to_vec();
    let (operation, operator, relay) = (command.operation, command.operator, command.relay);
    let spawned = std::thread::Builder::new()
        .name("karyos-agent-cluster".to_owned())
        .spawn(move || {
            let _reservation = reservation;
            let Ok(mut gateway) = gateway.lock() else {
                return;
            };
            let reply = gateway.submit(&Submission {
                command: &name,
                parameters: &parameters,
                operation,
                operator,
                relay,
            });
            drop(gateway);
            drop(_reservation);
            let _ = sender.send(reply);
        });
    spawned.ok()?;
    receiver.recv_timeout(wait).ok()
}

/// `bytes` as lowercase hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        for nibble in [byte >> 4, byte & 0xf] {
            if let Some(&digit) = DIGITS.get(usize::from(nibble)) {
                out.push(char::from(digit));
            }
        }
    }
    out
}

/// The bytes of `text`, an even number of hex digits; `-` is none.
/// `None` for anything else, or more than [`MAX_PARAMETERS`] bytes.
#[must_use]
pub fn parse_parameters(text: &str) -> Option<Vec<u8>> {
    if text == "-" {
        return Some(Vec::new());
    }
    let bytes = text.as_bytes();
    if bytes.is_empty()
        || !bytes.len().is_multiple_of(2)
        || bytes.len() / 2 > MAX_PARAMETERS
        || !bytes.iter().all(u8::is_ascii_hexdigit)
    {
        return None;
    }
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = core::str::from_utf8(pair).ok()?;
            u8::from_str_radix(text, 16).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests;
