// SPDX-License-Identifier: Apache-2.0

//! The service container (quantstratum-docs: karyos/SPEC.md §9;
//! karyos/design/cluster-gap-analysis.md §6, C10), core neutral: a
//! [`ClusteredService`], the user's state machine, fed the committed
//! entries of the replicated log in order by a [`ServiceContainer`].
//!
//! - **Entries.** Every entry the container proposes is an [`Envelope`]:
//!   a client's registration, close or request, a timer firing, or a
//!   configuration change. Timer firings and configuration changes are
//!   entries like any other, so the service sees them only when they are
//!   applied, in log order, never around the log (SPEC.md §9, "Timer
//!   firings and relevant configuration changes enter the replicated log
//!   before service delivery"). An empty payload is a core's own entry
//!   and delivers nothing.
//! - **Determinism.** The service sees only what the log carries: the
//!   entry's index and term, and the log time, the highest event time
//!   applied ([`SessionTable::log_time`]). It has no wall clock and no
//!   randomness outside the log, so every replica that applies the same
//!   entries holds the same state and gives the same replies.
//! - **Deduplication.** Requests go through C7a's [`SessionTable`]: a
//!   retried request (same client, epoch and sequence) gets its retained
//!   reply, and the command runs once. The service writes its reply
//!   straight into the session's slot.
//! - **Timers.** The service schedules and cancels timers through its
//!   [`Context`], at most [`ContainerConfig::timers`] at once, all
//!   allocated when the container is made. A timer is replicated state:
//!   it fires when an entry [`Envelope::TimerFired`] with its id and
//!   deadline is applied. A firing for a timer cancelled, rescheduled or
//!   already fired is a no-op, so a firing proposed twice (by two leaders)
//!   delivers once.
//! - **Proposing.** The container reaches the consensus core through
//!   [`Propose`], which a core's adapter implements; nothing here depends
//!   on which core is used.
//!
//! Every entry the container reads is one message of schema 2 version 1
//! (SPEC.md §8.5; quantstratum-docs:
//! karyos/design/cluster-service-container.md §4, karyos#797), over the
//! ADR-0036 envelope of `karyos-codec`:
//!
//! | Template | Id | Block | Then | Maximum |
//! | --- | --- | --- | --- | --- |
//! | `Register` | 1 | client 8 | | 20 |
//! | `Close` | 2 | client 8, epoch 8 | | 28 |
//! | `Request` | 3 | client 8, epoch 8, sequence 8, lowest unanswered 8 | command, 0 to 65535 bytes | 65581 |
//! | `TimerFired` | 4 | timer 8, deadline 8 | | 28 |
//! | `Configuration` | 5 | none | configuration, 1 to 4096 bytes | 4110 |
//!
//! A client or an epoch of 0, and a lowest unanswered sequence past the
//! sequence plus one, are `ValueOutOfRange`.
//!
//! **The core's own entries** (karyos#927) are outside schema 2, which
//! stays as it is: they are schema [`CORE_SCHEMA_ID`] (5) version 1, over
//! the same envelope. Its one template is [`SessionBounds`], the session
//! table's bounds (`S`, `K`, `R` and TTL, item 37 of the decisions of
//! 2026-10-21), carried in the log so that a replica reads them from it:
//!
//! | Template | Id | Block | Maximum |
//! | --- | --- | --- | --- |
//! | `SessionBounds` | 1 | sessions 4, window 4, response bytes 4, ttl 8 | 32 |
//! | `Membership` | 2 | voters 1, learners 1, 7 ids of 8 | 70 |
//!
//! Every field of 0 is `ValueOutOfRange`. The container applies a
//! `SessionBounds` entry against its table's [`DedupConfig`]. The first
//! such entry in the log is the cluster's bounds: equal bounds deliver
//! nothing, as any core entry; different bounds rebuild a table still
//! fresh (no registration applied) from the logged ones, and stop the
//! container ([`ApplyError::BoundsDiffer`]) once a registration has
//! applied, never rebuilding under live sessions. Every later
//! `SessionBounds` entry, whatever it carries, delivers nothing: a new
//! leader that proposed its own bounds before applying an inherited entry
//! never replaces or contradicts the first (karyos#927 review). A leader
//! proposes the bounds through [`ServiceContainer::propose_bounds`] while
//! the log it applied carries none, and accepts no registration until
//! they apply. A log written before karyos#927 carries no bounds entry:
//! its registrations apply under the replica's configured bounds, as
//! before, and a bounds entry that later differs from them stops the
//! container as above. A `Membership` entry is a configuration entry of
//! the core's ([`crate::membership`], karyos#711): it delivers nothing.
//!
//! **Rolling upgrades** (ADR-0122, karyos#715): templates 3,
//! [`Activation`], and 4, [`CoordinatedStop`], of schema 5 change the
//! log's [`ActiveVersion`] at an index ahead of their entry, or stop every
//! replica at one. The service sees only the active version
//! ([`Context::active_version`]), never the binary's; a command the active
//! version cannot run ([`ClusteredService::required_version`]) is refused
//! at the leader ([`ProposeRefused::VersionInactive`]) and again when it
//! applies ([`Applied::CoreRefused`]). See the `service::upgrade` module's table.

mod compose;
#[cfg(test)]
mod golden;
#[cfg(test)]
mod tests;
mod upgrade;

pub use compose::{
    ComposeError, ComposedSnapshot, MAX_SERVICE_PARTS, PART_METADATA, RestoreError, RestoreRefused,
    SESSIONS_SECTION_VERSION, SESSIONS_SECTION_VERSION_1, ServicePart, ServiceSnapshot,
    SnapshotFull, TIMERS_VERSION,
};
pub use upgrade::{
    ACTIVATION, Activation, ActiveVersion, COORDINATED_STOP, CoordinatedStop, CoreRefusal,
};

use karyos_codec::{CodecError, Decoder, ENVELOPE_LENGTH, Encoder, Template, VAR_HEADER_LENGTH};

use crate::dedup::{
    ConfigError, DedupConfig, Outcome, RegisterError, Registered, Request, SessionTable,
};
use crate::guards::{
    GUARD_SCHEMA_ID, GuardBounds, GuardEffect, GuardEntry, GuardOutcome, GuardStop, GuardTable,
    SectionError,
};
use crate::log::Entry;
use crate::membership::MembershipEntry;

/// Schema 2, the Cluster's log entries.
pub const SCHEMA_ID: u16 = 2;
/// The only version of schema 2.
pub const VERSION: u16 = 1;
/// The longest command a `Request` carries.
pub const MAX_COMMAND: usize = 65535;
/// The longest configuration a `Configuration` carries.
pub const MAX_CONFIGURATION: usize = 4096;

/// Schema 5, the core's own entries (karyos#927).
pub const CORE_SCHEMA_ID: u16 = 5;
/// The version of schema 5 this build writes: 2 since karyos#750, the
/// same bounds under the exact identity's deduplication rules
/// ([`crate::dedup`]). Version 1 still decodes: its log replays the
/// earlier contiguous rules.
pub const CORE_VERSION: u16 = 2;
/// The version of schema 5 earlier builds wrote.
pub const CORE_VERSION_1: u16 = 1;
/// `SessionBounds`, template 1 of schema 5: a 20-byte block.
pub const SESSION_BOUNDS: Template = Template {
    schema_id: CORE_SCHEMA_ID,
    template_id: 1,
    version: CORE_VERSION,
    block_length: 20,
    max_length: ENVELOPE_LENGTH as u32 + 20,
};
/// [`SESSION_BOUNDS`] as earlier builds wrote it, version 1.
const SESSION_BOUNDS_1: Template = Template {
    version: CORE_VERSION_1,
    ..SESSION_BOUNDS
};

const fn template(template_id: u16, block_length: u16, variable: u32) -> Template {
    Template {
        schema_id: SCHEMA_ID,
        template_id,
        version: VERSION,
        block_length,
        max_length: ENVELOPE_LENGTH as u32 + block_length as u32 + variable,
    }
}

const VARIABLE: u32 = VAR_HEADER_LENGTH as u32;
/// `Register`, template 1.
pub const REGISTER: Template = template(1, 8, 0);
/// `Close`, template 2.
pub const CLOSE: Template = template(2, 16, 0);
/// `Request`, template 3.
pub const REQUEST: Template = template(3, 32, VARIABLE + MAX_COMMAND as u32);
/// `TimerFired`, template 4.
pub const TIMER_FIRED: Template = template(4, 16, 0);
/// `Configuration`, template 5.
pub const CONFIGURATION: Template = template(5, 0, VARIABLE + MAX_CONFIGURATION as u32);

/// `value`, or `ValueOutOfRange` naming `field` when it is 0.
fn nonzero(field: &'static str, value: u64) -> Result<u64, CodecError> {
    if value == 0 {
        Err(CodecError::ValueOutOfRange { field })
    } else {
        Ok(value)
    }
}

/// `value`, or `ValueOutOfRange` naming `field` when it is 0.
fn nonzero32(field: &'static str, value: u32) -> Result<u32, CodecError> {
    if value == 0 {
        Err(CodecError::ValueOutOfRange { field })
    } else {
        Ok(value)
    }
}

/// The session table's bounds as a core's own entry: schema 5 version 1,
/// template 1 (karyos#927).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SessionBounds {
    /// The bounds the log carries.
    pub config: DedupConfig,
    /// The exact identity's rules: a version 2 entry, as this build
    /// writes; `false` for a version 1 entry of an earlier build.
    pub exact: bool,
}

impl SessionBounds {
    /// The entry for `config`, as this build writes it (version 2).
    #[must_use]
    pub fn new(config: DedupConfig) -> Self {
        Self {
            config,
            exact: true,
        }
    }

    /// Encodes into `out`; returns the message's length, 32.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] for a short `out`, and
    /// [`CodecError::ValueOutOfRange`] for a bound of 0.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let config = self.config;
        let template = if self.exact {
            &SESSION_BOUNDS
        } else {
            &SESSION_BOUNDS_1
        };
        let mut encoder = Encoder::new(out, template)?;
        encoder.u32(0, nonzero32("sessions", config.sessions)?)?;
        encoder.u32(4, nonzero32("window", config.window)?)?;
        encoder.u32(8, nonzero32("response_bytes", config.response_bytes)?)?;
        encoder.u64(12, nonzero("ttl", config.ttl)?)?;
        encoder.finish()
    }

    /// The message's bytes.
    ///
    /// # Errors
    ///
    /// As [`SessionBounds::encode`], but never `Truncated`.
    pub fn to_vec(&self) -> Result<Vec<u8>, CodecError> {
        let mut out = vec![0; usize::try_from(SESSION_BOUNDS.max_length).unwrap_or(usize::MAX)];
        let length = self.encode(&mut out)?;
        out.truncate(length);
        Ok(out)
    }

    /// Decodes exactly one `SessionBounds` message from `bytes`.
    ///
    /// # Errors
    ///
    /// [`CodecError::UnsupportedSchema`] for any tuple but schema 5,
    /// template 1, version 1, [`CodecError::ValueOutOfRange`] for a bound
    /// of 0, and every other [`CodecError`] the envelope can raise.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let envelope = karyos_codec::Envelope::read(bytes)?;
        if envelope.schema_id != CORE_SCHEMA_ID
            || !matches!(envelope.version, CORE_VERSION | CORE_VERSION_1)
            || envelope.template_id != SESSION_BOUNDS.template_id
        {
            return Err(CodecError::UnsupportedSchema {
                schema: envelope.schema_id,
                template: envelope.template_id,
                version: envelope.version,
            });
        }
        let exact = envelope.version == CORE_VERSION;
        let template = if exact {
            &SESSION_BOUNDS
        } else {
            &SESSION_BOUNDS_1
        };
        let (block, decoder) = Decoder::new(bytes, template)?;
        let config = DedupConfig::default()
            .with_sessions(nonzero32("sessions", block.u32(0)?)?)
            .with_window(nonzero32("window", block.u32(4)?)?)
            .with_response_bytes(nonzero32("response_bytes", block.u32(8)?)?)
            .with_ttl(nonzero("ttl", block.u64(12)?)?);
        decoder.finish()?;
        Ok(Self { config, exact })
    }
}

/// A decoded entry: the service's (schema 2), the core's (schema 5) or a
/// guard entry (schema 6, [`crate::guards`]).
enum Decoded<'a> {
    Service(Envelope<'a>),
    Bounds(SessionBounds),
    Membership,
    Activation(Activation<'a>),
    Stop(CoordinatedStop),
    Guard(GuardEntry),
}

impl<'a> Decoded<'a> {
    fn of(bytes: &'a [u8]) -> Result<Self, CodecError> {
        match karyos_codec::Envelope::read(bytes)?.schema_id {
            CORE_SCHEMA_ID if MembershipEntry::is_one(bytes) => {
                let _ = MembershipEntry::decode(bytes)?;
                Ok(Self::Membership)
            }
            CORE_SCHEMA_ID if upgrade::is_core_template(bytes, ACTIVATION.template_id) => {
                Ok(Self::Activation(Activation::decode(bytes)?))
            }
            CORE_SCHEMA_ID if upgrade::is_core_template(bytes, COORDINATED_STOP.template_id) => {
                Ok(Self::Stop(CoordinatedStop::decode(bytes)?))
            }
            CORE_SCHEMA_ID => Ok(Self::Bounds(SessionBounds::decode(bytes)?)),
            GUARD_SCHEMA_ID => Ok(Self::Guard(GuardEntry::decode(bytes)?)),
            _ => Ok(Self::Service(Envelope::decode(bytes)?)),
        }
    }
}

/// A request's lowest unanswered sequence is at most its sequence plus one.
fn check_request(request: &Request) -> Result<(), CodecError> {
    let _ = nonzero("client", request.client)?;
    let _ = nonzero("epoch", request.epoch)?;
    if request.sequence != u64::MAX && request.lowest_unanswered > request.sequence + 1 {
        return Err(CodecError::ValueOutOfRange {
            field: "lowest_unanswered",
        });
    }
    Ok(())
}

/// One entry's content, as the container proposes and applies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Envelope<'a> {
    /// A client opens a session; its epoch is the entry's index. Propose
    /// it with [`ServiceContainer::propose`], which holds it until the
    /// session bounds apply (ADR-0087), never as raw bytes through
    /// [`Propose::propose`] (karyos#1062).
    Register {
        /// The client's stable identity.
        client: u64,
    },
    /// A client closes its session.
    Close {
        /// The client.
        client: u64,
        /// The session's epoch.
        epoch: u64,
    },
    /// A client's command.
    Request {
        /// Its client, epoch, sequence and lowest unanswered sequence.
        request: Request,
        /// The command, for the service.
        command: &'a [u8],
    },
    /// A timer is due.
    TimerFired {
        /// The timer.
        timer: u64,
        /// The deadline it was scheduled for.
        deadline: u64,
    },
    /// A configuration change, for the service.
    Configuration(&'a [u8]),
}

impl<'a> Envelope<'a> {
    /// Encodes into `out`; returns the message's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] for a short `out`,
    /// [`CodecError::ValueOutOfRange`] for a value rule of schema 2, and
    /// [`CodecError::LengthOutOfRange`] for a command or configuration
    /// outside its bounds.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        match *self {
            Self::Register { client } => {
                let mut encoder = Encoder::new(out, &REGISTER)?;
                encoder.u64(0, nonzero("client", client)?)?;
                encoder.finish()
            }
            Self::Close { client, epoch } => {
                let mut encoder = Encoder::new(out, &CLOSE)?;
                encoder.u64(0, nonzero("client", client)?)?;
                encoder.u64(8, nonzero("epoch", epoch)?)?;
                encoder.finish()
            }
            Self::Request { request, command } => {
                check_request(&request)?;
                let mut encoder = Encoder::new(out, &REQUEST)?;
                encoder.u64(0, request.client)?;
                encoder.u64(8, request.epoch)?;
                encoder.u64(16, request.sequence)?;
                encoder.u64(24, request.lowest_unanswered)?;
                encoder.bytes("command", 0, MAX_COMMAND, command)?;
                encoder.finish()
            }
            Self::TimerFired { timer, deadline } => {
                let mut encoder = Encoder::new(out, &TIMER_FIRED)?;
                encoder.u64(0, timer)?;
                encoder.u64(8, deadline)?;
                encoder.finish()
            }
            Self::Configuration(configuration) => {
                let mut encoder = Encoder::new(out, &CONFIGURATION)?;
                encoder.bytes("configuration", 1, MAX_CONFIGURATION, configuration)?;
                encoder.finish()
            }
        }
    }

    /// The message's bytes. A host proposes them through
    /// [`ServiceContainer::propose`], not by handing these bytes to
    /// [`Propose::propose`] (karyos#1062).
    ///
    /// # Errors
    ///
    /// As [`Envelope::encode`], but never `Truncated`.
    pub fn to_vec(&self) -> Result<Vec<u8>, CodecError> {
        let mut out = Vec::new();
        self.encode_into(&mut out)?;
        Ok(out)
    }

    /// Encodes into `out`, which it replaces: no allocation once `out`
    /// has held the template's longest message.
    ///
    /// # Errors
    ///
    /// As [`Envelope::encode`].
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), CodecError> {
        let max = match self {
            Self::Register { .. } => REGISTER.max_length,
            Self::Close { .. } => CLOSE.max_length,
            Self::Request { .. } => REQUEST.max_length,
            Self::TimerFired { .. } => TIMER_FIRED.max_length,
            Self::Configuration(_) => CONFIGURATION.max_length,
        };
        out.clear();
        out.resize(usize::try_from(max).unwrap_or(usize::MAX), 0);
        let length = self.encode(out)?;
        out.truncate(length);
        Ok(())
    }

    /// Decodes exactly one schema 2 message from `bytes`, validated whole.
    ///
    /// # Errors
    ///
    /// [`CodecError::UnsupportedSchema`] for any tuple but schema 2,
    /// version 1 and a listed template, and every other [`CodecError`] its
    /// fields can raise.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, CodecError> {
        let envelope = karyos_codec::Envelope::read(bytes)?;
        let unsupported = CodecError::UnsupportedSchema {
            schema: envelope.schema_id,
            template: envelope.template_id,
            version: envelope.version,
        };
        if envelope.schema_id != SCHEMA_ID || envelope.version != VERSION {
            return Err(unsupported);
        }
        let template = match envelope.template_id {
            1 => &REGISTER,
            2 => &CLOSE,
            3 => &REQUEST,
            4 => &TIMER_FIRED,
            5 => &CONFIGURATION,
            _ => return Err(unsupported),
        };
        let (block, mut decoder) = Decoder::new(bytes, template)?;
        let envelope = match envelope.template_id {
            1 => Self::Register {
                client: nonzero("client", block.u64(0)?)?,
            },
            2 => Self::Close {
                client: nonzero("client", block.u64(0)?)?,
                epoch: nonzero("epoch", block.u64(8)?)?,
            },
            3 => {
                let request =
                    Request::new(block.u64(0)?, block.u64(8)?, block.u64(16)?, block.u64(24)?);
                check_request(&request)?;
                let command = decoder.bytes("command", 0, MAX_COMMAND)?;
                Self::Request { request, command }
            }
            4 => Self::TimerFired {
                timer: block.u64(0)?,
                deadline: block.u64(8)?,
            },
            _ => Self::Configuration(decoder.bytes("configuration", 1, MAX_CONFIGURATION)?),
        };
        decoder.finish()?;
        Ok(envelope)
    }
}

/// A proposal refused: this node does not lead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not the leader")]
#[non_exhaustive]
pub struct NotLeader {
    /// The node this one believes leads, if any.
    pub leader: Option<u64>,
}

impl NotLeader {
    /// Refused, with `leader` as the hint.
    #[must_use]
    pub fn new(leader: Option<u64>) -> Self {
        Self { leader }
    }
}

/// The consensus core as the container sees it: a core's adapter
/// implements it (design decisions D1 and E2 of karyos#686). A proposal
/// is not told its index: its answer is found when the entry applies, by
/// the request's client, epoch and sequence, which a forward and a retry
/// share.
pub trait Propose {
    /// Appends `payload` as a new entry, if this node leads.
    ///
    /// **A host's obligation (ADR-0087, karyos#1062):** service entries
    /// go through [`ServiceContainer::propose`], never straight to this
    /// method. The container holds a leader's `Register` back until the
    /// log's session bounds have applied; bytes proposed here directly
    /// bypass that gate, and a registration committed ahead of the first
    /// `SessionBounds` entry can stop the cluster with
    /// [`ApplyError::BoundsDiffer`] on a replica with other startup
    /// bounds. The core cannot tell a registration from any other
    /// payload, so the gate is not enforced below the container.
    ///
    /// # Errors
    ///
    /// [`NotLeader`] when it does not, with the leader it knows of.
    fn propose(&mut self, payload: Vec<u8>) -> Result<(), NotLeader>;

    /// [`Propose::propose`], borrowing `payload`, for a host that keeps
    /// its buffer (C6, karyos#681). The default copies it.
    ///
    /// # Errors
    ///
    /// As [`Propose::propose`].
    fn propose_slice(&mut self, payload: &[u8]) -> Result<(), NotLeader> {
        self.propose(payload.to_vec())
    }

    /// Whether this node leads now, as far as it knows. The container's
    /// registration gate ([`ServiceContainer::propose`]) holds a
    /// registration back only on a leader; a follower's goes to
    /// [`Propose::propose`], which refuses it with the leader's hint. The
    /// default, `true`, applies the gate on every node: conservative, the
    /// answer is retryable either way.
    fn leads(&self) -> bool {
        true
    }
}

/// A proposal [`ServiceContainer::propose`] did not make.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProposeRefused {
    /// This node does not lead.
    #[error(transparent)]
    NotLeader(#[from] NotLeader),
    /// A registration on a leader whose log has not applied the session
    /// bounds yet (ADR-0087, karyos#1053): nothing was proposed. The host
    /// holds it until [`ServiceContainer::bounds_logged`], or answers its
    /// client with a retryable refusal; it never proposes it earlier.
    #[error("the session bounds have not applied yet")]
    BoundsPending,
    /// The envelope does not encode (schema 2 refuses it): never proposed.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// A command the log's active version cannot run (ADR-0122 decision
    /// 3): it needs service version `required` (`None`: a command type, or
    /// a schema 2 version, the active version does not know). Refused even
    /// while a higher activation is pending; nothing was proposed.
    #[error("the command needs version {required:?}, the active one is {active:?}")]
    VersionInactive {
        /// The service version the command needs.
        required: Option<u32>,
        /// The log's active version.
        active: ActiveVersion,
    },
    /// A coordinated stop (ADR-0122 decision 6): the leader that appended
    /// it refuses every proposal until it restarts, and while the log
    /// carries it every service proposal is refused until the resuming
    /// `Activation` applies.
    #[error("the cluster is stopping for a coordinated restart")]
    Stopping,
}

/// The user's state machine (SPEC.md §9). Every method sees only its
/// [`Context`] and the entry's bytes, so it is a function of the log.
pub trait ClusteredService {
    /// Runs `command` of `client`, once, and writes its reply into
    /// `reply`; returns the reply's length, or `None` for a reply that
    /// does not fit, whose effects still stand.
    fn on_command(
        &mut self,
        context: &mut Context<'_>,
        client: u64,
        command: &[u8],
        reply: &mut [u8],
    ) -> Option<usize>;

    /// Timer `timer`, scheduled through a [`Context`], is due.
    fn on_timer(&mut self, context: &mut Context<'_>, timer: u64);

    /// A configuration change has been applied.
    fn on_configuration(&mut self, context: &mut Context<'_>, configuration: &[u8]);

    /// Writes the service's state after the last applied entry into
    /// `parts`, as one or more parts (R-CORE-9; the contract is
    /// [`ServiceContainer::snapshot`]'s). It is called between two applies,
    /// never during one, so every part is from the same log position. The
    /// default writes none: a service with no state of its own.
    ///
    /// # Errors
    ///
    /// [`SnapshotFull`] from `parts`: the snapshot is not taken.
    fn snapshot(&self, parts: &mut ServiceSnapshot) -> Result<(), SnapshotFull> {
        let _ = parts;
        Ok(())
    }

    /// Replaces the service's state with the `parts` a snapshot holds, in
    /// the order they were written: all of them, or, on refusal, none
    /// (the state must stay as it was). The default accepts no part.
    ///
    /// # Errors
    ///
    /// [`RestoreRefused`]: an unknown part id, a version newer than the
    /// service reads, a missing or malformed part.
    fn restore(&mut self, parts: &[ServicePart<'_>]) -> Result<(), RestoreRefused> {
        match parts.first() {
            Some(part) => Err(RestoreRefused::UnknownPart { id: part.id }),
            None => Ok(()),
        }
    }

    /// The service version `command` needs (ADR-0122 decision 3), or
    /// `None` for a command type the service does not know at any version.
    /// The container refuses a command needing more than the log's active
    /// version, at the leader and again when it applies, so it never
    /// reaches [`ClusteredService::on_command`]. The default: every
    /// command runs from version 1.
    fn required_version(&self, command: &[u8]) -> Option<u32> {
        let _ = command;
        Some(1)
    }

    /// The highest service version this binary runs (ADR-0122 decision
    /// 4). An `Activation` above it applies as pending, and the container
    /// stops ([`ApplyError::VersionUnsupported`]) at its activation index.
    /// The default: version 1.
    fn supported_version(&self) -> u32 {
        1
    }
}

/// The scheduled timers: ids and deadlines, sorted by id, never more
/// than the configured bound. The bound is kept, not read from the
/// vector's capacity, which may exceed what was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Timers {
    scheduled: Vec<(u64, u64)>,
    bound: usize,
}

impl Timers {
    fn deadline(&self, timer: u64) -> Option<u64> {
        let slot = self
            .scheduled
            .binary_search_by_key(&timer, |&(id, _)| id)
            .ok()?;
        self.scheduled.get(slot).map(|&(_, deadline)| deadline)
    }

    fn remove(&mut self, timer: u64) -> bool {
        match self.scheduled.binary_search_by_key(&timer, |&(id, _)| id) {
            Ok(slot) => {
                let _ = self.scheduled.remove(slot);
                true
            }
            Err(_) => false,
        }
    }
}

/// Every timer slot is in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("every timer slot is in use")]
#[non_exhaustive]
pub struct TimersFull;

/// What the service sees of the entry it is applying.
#[derive(Debug)]
pub struct Context<'a> {
    index: u64,
    term: u64,
    log_time: u64,
    active: ActiveVersion,
    timers: &'a mut Timers,
}

impl<'a> Context<'a> {
    /// For `entry`, whose event time the log time includes.
    fn of(
        entry: &Entry,
        sessions: &SessionTable,
        active: ActiveVersion,
        timers: &'a mut Timers,
    ) -> Self {
        Self {
            index: entry.index,
            term: entry.term,
            log_time: sessions.log_time().max(entry.event_time),
            active,
            timers,
        }
    }

    /// The log's active version at this entry (ADR-0122 decision 4): the
    /// only version the service is given, never the binary's own.
    #[must_use]
    pub fn active_version(&self) -> ActiveVersion {
        self.active
    }

    /// The entry's log index.
    #[must_use]
    pub fn index(&self) -> u64 {
        self.index
    }

    /// The entry's term.
    #[must_use]
    pub fn term(&self) -> u64 {
        self.term
    }

    /// The log time: the highest event time applied, this entry's
    /// included. The service's only clock.
    #[must_use]
    pub fn log_time(&self) -> u64 {
        self.log_time
    }

    /// Schedules `timer` for log time `deadline`, replacing its earlier
    /// deadline if it had one.
    ///
    /// # Errors
    ///
    /// [`TimersFull`] for a new timer when every slot is in use.
    pub fn schedule(&mut self, timer: u64, deadline: u64) -> Result<(), TimersFull> {
        let bound = self.timers.bound;
        let timers = &mut self.timers.scheduled;
        match timers.binary_search_by_key(&timer, |&(id, _)| id) {
            Ok(slot) => {
                if let Some(entry) = timers.get_mut(slot) {
                    entry.1 = deadline;
                }
            }
            Err(slot) => {
                if timers.len() >= bound {
                    return Err(TimersFull);
                }
                timers.insert(slot, (timer, deadline));
            }
        }
        Ok(())
    }

    /// Cancels `timer`; `false` if it was not scheduled.
    pub fn cancel(&mut self, timer: u64) -> bool {
        self.timers.remove(timer)
    }
}

/// The container's bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ContainerConfig {
    /// The session table's.
    pub dedup: DedupConfig,
    /// Timers scheduled at once, at most.
    pub timers: u32,
    /// The bytes its session table may reserve, for its own bounds and
    /// for bounds a log entry carries ([`crate::dedup::DEFAULT_BUDGET`] by
    /// default; karyos#1070).
    ///
    /// **Every replica of a cluster must use the same budget**
    /// (karyos#1097). The bounds are a log entry every replica applies; a
    /// replica whose budget is smaller than the logged bounds need refuses
    /// the entry the others accept and stops at its index with
    /// [`ApplyError::BoundsUnheld`]`(`[`ConfigError::OverBudget`]`)`, naming
    /// the bytes asked and its budget. It does not apply the entry or any
    /// later one, so it stays behind until it restarts with a budget that
    /// holds the bounds.
    pub session_budget: u64,
    /// The guard table's bounds ([`crate::guards`]): **the same on every
    /// replica**. The log's first `GuardBounds` entry is checked against
    /// them, and a replica configured otherwise stops at it with
    /// [`ApplyError::Guard`].
    pub guards: GuardBounds,
}

/// The timers of [`ContainerConfig::default`].
pub const DEFAULT_TIMERS: u32 = 1024;

impl Default for ContainerConfig {
    /// The default session table, and [`DEFAULT_TIMERS`] timers.
    fn default() -> Self {
        Self {
            dedup: DedupConfig::default(),
            timers: DEFAULT_TIMERS,
            session_budget: crate::dedup::DEFAULT_BUDGET,
            guards: GuardBounds::default(),
        }
    }
}

impl ContainerConfig {
    /// With the session table bounded by `dedup`.
    #[must_use]
    pub fn with_dedup(mut self, dedup: DedupConfig) -> Self {
        self.dedup = dedup;
        self
    }

    /// With its session table limited to `budget` reserved bytes: the same
    /// on every replica ([`ContainerConfig::session_budget`]).
    #[must_use]
    pub fn with_session_budget(mut self, budget: u64) -> Self {
        self.session_budget = budget;
        self
    }

    /// With the guard table bounded by `guards`: the same on every replica.
    #[must_use]
    pub fn with_guards(mut self, guards: GuardBounds) -> Self {
        self.guards = guards;
        self
    }

    /// With `timers` timers at most.
    #[must_use]
    pub fn with_timers(mut self, timers: u32) -> Self {
        self.timers = timers;
        self
    }
}

/// What applying an entry did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Applied<'a> {
    /// A core's own entry, or a firing of a timer not scheduled for that
    /// deadline or not yet due at the log time: nothing was delivered.
    Nothing,
    /// A registration: the session opened, or why not.
    Registered(Result<Registered, RegisterError>),
    /// A close: whether a live session was closed.
    Closed(bool),
    /// A request, and what the session table made of it.
    Answered {
        /// The request.
        request: Request,
        /// Its outcome; the reply for an applied or retained one.
        outcome: Outcome<'a>,
    },
    /// A timer fired, and the service ran it.
    Fired {
        /// The timer.
        timer: u64,
    },
    /// The service took a configuration change.
    Configured,
    /// A guard entry ([`crate::guards`]): its outcome, and every change it
    /// made, in the order the host hands them to its driver.
    Guard {
        /// The entry's own outcome.
        outcome: GuardOutcome,
        /// The operator operation it carries (`Close`, `Reopen`), for
        /// correlation even when it changed nothing.
        operation: Option<u64>,
        /// The entry's log index.
        index: u64,
        /// The log time it applied at.
        log_time: u64,
        /// Its effects: a lapse's first, then its own, then the lease's.
        effects: &'a [GuardEffect],
    },
    /// An entry the container refused, the same on every replica
    /// (ADR-0122): an `Activation` or `CoordinatedStop` that breaks a
    /// rule, a command the active version cannot run (its client gets
    /// this refusal as its response), or a schema 2 entry past a
    /// coordinated stop. It changed nothing and reached no service code;
    /// the log time moved on.
    CoreRefused(CoreRefusal),
}

/// An entry the container cannot apply. It stops: no later entry may be
/// applied, since the replicas would no longer agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ApplyError {
    /// The entry is not the one after the last applied, or not index 1
    /// for the first.
    #[error("entry {index} after {last:?}: not in log order")]
    OutOfOrder {
        /// The entry's index.
        index: u64,
        /// The last applied.
        last: Option<u64>,
    },
    /// Its payload is neither a schema 2 message, a core's own entry of
    /// schema 5 nor a guard entry of schema 6 version 1: a safety stop
    /// (see [`ServiceContainer::apply`]).
    #[error("not a schema 2, 5 or 6 message: {0}")]
    Envelope(CodecError),
    /// A guard entry the guard table cannot apply, its bounds differing
    /// from this replica's among them: a safety stop.
    #[error(transparent)]
    Guard(GuardStop),
    /// A `SessionBounds` entry differs from the bounds of a table that
    /// has applied a registration: a safety stop, never a rebuild under
    /// live sessions (karyos#927).
    #[error("the logged session bounds {logged:?} differ from the table's {table:?}")]
    BoundsDiffer {
        /// The bounds the entry carries.
        logged: DedupConfig,
        /// The table's.
        table: DedupConfig,
    },
    /// A `SessionBounds` entry names bounds this replica cannot hold: a
    /// safety stop. [`ConfigError::OverBudget`] here means this replica's
    /// [`ContainerConfig::session_budget`] is smaller than another
    /// replica's, which proposed the bounds (karyos#1097).
    #[error("the logged session bounds cannot be held: {0}")]
    BoundsUnheld(ConfigError),
    /// The log activates service version `required`, above the
    /// `supported` this binary runs (ADR-0122 decision 4): a stop at the
    /// activation index, never at the `Activation` entry, so a node
    /// upgraded inside the window keeps running.
    #[error("the log activates version {required}, this binary runs at most {supported}")]
    VersionUnsupported {
        /// The service version activated.
        required: u32,
        /// [`ClusteredService::supported_version`].
        supported: u32,
    },
    /// A coordinated stop (ADR-0122 decision 6): the entry is past the
    /// stop index `at`, and this binary does not run `resume`. The host
    /// snapshots at `at` and restarts with a binary that does.
    #[error("stopped at index {at} for a restart at version {resume}")]
    Stopped {
        /// The stop index, the last applied.
        at: u64,
        /// The version to resume at.
        resume: u32,
    },
}

/// The container: a service, its session table and its timers, applying
/// committed entries in order.
#[derive(Debug)]
pub struct ServiceContainer<S> {
    service: S,
    sessions: SessionTable,
    timers: Timers,
    applied: Option<u64>,
    /// No registration applied yet: the table may still be rebuilt from
    /// logged bounds. Snapshot install (karyos#065) clears it.
    fresh: bool,
    /// A `SessionBounds` entry has applied.
    bounds_logged: bool,
    /// [`ContainerConfig::session_budget`], for bounds a log entry carries.
    session_budget: u64,
    /// The guard table.
    guards: GuardTable,
    /// When this node last proposed a renewal while leading; local, not
    /// replicated.
    renewed_at: Option<u64>,
    /// The active version, any pending activation and any logged stop
    /// (ADR-0122): log state.
    versions: upgrade::Versions,
    /// This node, as leader, appended a `CoordinatedStop` (ADR-0122
    /// decision 6): it refuses every proposal until it restarts. Local,
    /// not replicated.
    stop_appended: bool,
}

impl<S: ClusteredService> ServiceContainer<S> {
    /// A container for `service`, with every byte its tables will use
    /// allocated.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] for a session table that cannot be held.
    pub fn new(service: S, config: ContainerConfig) -> Result<Self, ConfigError> {
        let timers = usize::try_from(config.timers).map_err(|_| ConfigError::TooLarge)?;
        Ok(Self {
            service,
            sessions: SessionTable::new_within(config.dedup, config.session_budget)?,
            timers: Timers {
                scheduled: Vec::with_capacity(timers),
                bound: timers,
            },
            applied: None,
            fresh: true,
            bounds_logged: false,
            session_budget: config.session_budget,
            guards: GuardTable::new(config.guards),
            renewed_at: None,
            versions: upgrade::Versions::default(),
            stop_appended: false,
        })
    }

    /// The log's active version (ADR-0122).
    #[must_use]
    pub fn active_version(&self) -> ActiveVersion {
        self.versions.active
    }

    /// A pending activation: its version and its activation index.
    #[must_use]
    pub fn pending_activation(&self) -> Option<(ActiveVersion, u64)> {
        self.versions
            .pending
            .as_ref()
            .map(|pending| (pending.version, pending.at))
    }

    /// A logged coordinated stop: its stop index and its resume version.
    /// The host takes its snapshot once the stop index has applied.
    #[must_use]
    pub fn stop(&self) -> Option<(u64, u32)> {
        self.versions.stop.map(|stop| (stop.at, stop.resume))
    }

    /// Proposes `activation` through `core` (ADR-0122 decision 1). It is
    /// checked when it applies, never here. A stop known only from the
    /// log does not refuse it, so the first leader after the resuming
    /// restart can propose the resuming `Activation`.
    ///
    /// # Errors
    ///
    /// [`ProposeRefused::Stopping`] once this node appended a
    /// `CoordinatedStop`, [`ProposeRefused::Codec`] for an entry that does
    /// not encode, [`ProposeRefused::NotLeader`] when `core` does not lead.
    pub fn propose_activation<P: Propose>(
        &self,
        activation: &Activation<'_>,
        core: &mut P,
    ) -> Result<(), ProposeRefused> {
        if self.stop_appended {
            return Err(ProposeRefused::Stopping);
        }
        core.propose(activation.to_vec()?)?;
        Ok(())
    }

    /// Proposes `stop` through `core` (ADR-0122 decision 6): once it is
    /// appended, this node refuses every proposal until it restarts, and
    /// once it applies, every node refuses service proposals.
    ///
    /// # Errors
    ///
    /// [`ProposeRefused::Stopping`] while a stop is logged or appended,
    /// [`ProposeRefused::Codec`] and [`ProposeRefused::NotLeader`].
    pub fn propose_stop<P: Propose>(
        &mut self,
        stop: &CoordinatedStop,
        core: &mut P,
    ) -> Result<(), ProposeRefused> {
        if self.stopping() {
            return Err(ProposeRefused::Stopping);
        }
        core.propose(stop.to_vec()?)?;
        self.stop_appended = true;
        Ok(())
    }

    /// A stop is logged, or this node appended one.
    fn stopping(&self) -> bool {
        self.stop_appended || self.versions.stop.is_some()
    }

    /// Whether the active version runs `command`: `Ok`, or the version it
    /// needs as this binary reads it (`None`: not known to the active
    /// version).
    fn admits(&self, command: &[u8]) -> Result<(), Option<u32>> {
        let active = self.versions.active;
        let required = if VERSION > active.schema {
            None
        } else {
            self.service.required_version(command)
        };
        match required {
            Some(required) if required <= active.service => Ok(()),
            required => Err(required),
        }
    }

    /// The service.
    #[must_use]
    pub fn service(&self) -> &S {
        &self.service
    }

    /// The session table.
    #[must_use]
    pub fn sessions(&self) -> &SessionTable {
        &self.sessions
    }

    /// The last index applied.
    #[must_use]
    pub fn applied(&self) -> Option<u64> {
        self.applied
    }

    /// Whether a `SessionBounds` entry has applied.
    #[must_use]
    pub fn bounds_logged(&self) -> bool {
        self.bounds_logged
    }

    /// The guard table.
    #[must_use]
    pub fn guards(&self) -> &GuardTable {
        &self.guards
    }

    /// Proposes the guard table's bounds while the log carries none: `true`
    /// if it proposed. A leader does this as it does
    /// [`ServiceContainer::propose_bounds`].
    ///
    /// # Errors
    ///
    /// [`NotLeader`] when the core does not lead.
    pub fn propose_guard_bounds<P: Propose>(&self, core: &mut P) -> Result<bool, NotLeader> {
        if self.guards.bounds_logged() || self.stop_appended {
            return Ok(false);
        }
        let Ok(payload) = GuardEntry::Bounds(self.guards.bounds()).to_vec() else {
            return Ok(false);
        };
        core.propose(payload)?;
        Ok(true)
    }

    /// Proposes a lease renewal issued at `now` when one is due: `true` if
    /// it proposed. The host calls this at every tick with the core's
    /// clock, the one it stamps entries' event times with, so a renewal's
    /// `issued` is its entry's event time; the container proposes on the
    /// first call after the node starts to lead, then every
    /// [`GuardBounds::renew_every`]. A node that does not lead forgets its
    /// last renewal, so it renews at once when it leads again.
    ///
    /// # Errors
    ///
    /// [`NotLeader`] when the core does not lead. A `now` of 0 proposes
    /// nothing.
    pub fn propose_renew<P: Propose>(&mut self, core: &mut P, now: u64) -> Result<bool, NotLeader> {
        if !core.leads() {
            self.renewed_at = None;
            return Err(NotLeader::new(None));
        }
        let every = self.guards.bounds().renew_every;
        if self.stop_appended
            || self
                .renewed_at
                .is_some_and(|at| now.saturating_sub(at) < every)
        {
            return Ok(false);
        }
        let Ok(payload) = (GuardEntry::Renew { issued: now }).to_vec() else {
            return Ok(false);
        };
        core.propose(payload)
            .inspect_err(|_| self.renewed_at = None)?;
        self.renewed_at = Some(now);
        Ok(true)
    }

    /// Replaces the guard table with a snapshot section's (of `version`), for a snapshot
    /// at `index` whose log time is `log_time`: validated whole first.
    ///
    /// # Errors
    ///
    /// [`SectionError`]: the table is unchanged.
    pub fn restore_guards(
        &mut self,
        version: u64,
        section: &[u8],
        index: u64,
        log_time: u64,
    ) -> Result<(), SectionError> {
        self.guards = GuardTable::restore(version, section, self.guards.bounds(), index, log_time)?;
        Ok(())
    }

    /// Proposes the table's bounds as a `SessionBounds` entry through
    /// `core` while none has applied; a leader calls it in each
    /// leadership, so the first leader of a cluster writes the bounds into
    /// its log. `Ok(false)` when the log already carries them. A second
    /// copy, from two leaders, applies as equal bounds and delivers
    /// nothing.
    ///
    /// # Errors
    ///
    /// [`NotLeader`] when `core` does not lead.
    pub fn propose_bounds<P: Propose>(&self, core: &mut P) -> Result<bool, NotLeader> {
        if self.bounds_logged || self.stop_appended {
            return Ok(false);
        }
        // A table's bounds are never 0 (`SessionTable::new`), so this
        // always encodes.
        let Ok(payload) = SessionBounds::new(self.sessions.config()).to_vec() else {
            return Ok(false);
        };
        core.propose(payload)?;
        Ok(true)
    }

    /// Proposes `envelope` through `core`, enforcing ADR-0087's gate: a
    /// leader proposes no `Register` until the log's session bounds have
    /// applied, so no registration precedes the first `SessionBounds`
    /// entry a leader writes (karyos#1053). Every other envelope, and a
    /// registration once the bounds applied or on a follower, goes to
    /// `core` as is.
    ///
    /// # Errors
    ///
    /// [`ProposeRefused::BoundsPending`] for a registration held back,
    /// [`ProposeRefused::NotLeader`] when `core` does not lead,
    /// [`ProposeRefused::Codec`] for an envelope schema 2 refuses,
    /// [`ProposeRefused::Stopping`] while the log carries a coordinated
    /// stop, and [`ProposeRefused::VersionInactive`] for a command the
    /// active version cannot run (ADR-0122 decision 3).
    pub fn propose<P: Propose>(
        &self,
        envelope: &Envelope<'_>,
        core: &mut P,
    ) -> Result<(), ProposeRefused> {
        self.propose_with(envelope, core, &mut Vec::new())
    }

    /// [`ServiceContainer::propose`], encoding into `buf`, which the host
    /// keeps: no allocation once it has held the longest envelope (C6,
    /// karyos#681).
    ///
    /// # Errors
    ///
    /// As [`ServiceContainer::propose`].
    pub fn propose_with<P: Propose>(
        &self,
        envelope: &Envelope<'_>,
        core: &mut P,
        buf: &mut Vec<u8>,
    ) -> Result<(), ProposeRefused> {
        if self.stopping() {
            return Err(ProposeRefused::Stopping);
        }
        if let Envelope::Request { command, .. } = envelope
            && let Err(required) = self.admits(command)
        {
            return Err(ProposeRefused::VersionInactive {
                required,
                active: self.versions.active,
            });
        }
        if matches!(envelope, Envelope::Register { .. }) && !self.bounds_logged && core.leads() {
            return Err(ProposeRefused::BoundsPending);
        }
        envelope.encode_into(buf)?;
        core.propose_slice(buf)?;
        Ok(())
    }

    /// The deadline `timer` is scheduled for, if it is.
    #[must_use]
    pub fn timer(&self, timer: u64) -> Option<u64> {
        self.timers.deadline(timer)
    }

    /// The scheduled timers whose deadline is at most `now`, as the
    /// envelopes a leader proposes for them, in timer order.
    pub fn due(&self, now: u64) -> impl Iterator<Item = Envelope<'static>> + '_ {
        self.timers
            .scheduled
            .iter()
            .filter(move |&&(_, deadline)| deadline <= now)
            .map(|&(timer, deadline)| Envelope::TimerFired { timer, deadline })
    }

    /// Applies the committed `entry`, the one after the last applied.
    ///
    /// # Errors
    ///
    /// [`ApplyError`] for an entry out of order, a payload that is not
    /// a schema 2 or schema 5 message, or logged bounds that differ from
    /// a table that has applied a registration. That is a safety stop, not a recoverable error:
    /// every replica applies the same committed entries, so every replica
    /// stops at the same index for the same reason, and none applies past
    /// it. The entry is never delivered, and the container applies nothing
    /// more until an operator acts.
    pub fn apply(&mut self, entry: &Entry) -> Result<Applied<'_>, ApplyError> {
        // The log starts at index 1 until snapshot install (#065) gives
        // the container another start.
        let expected = self.applied.map_or(1, |last| last.saturating_add(1));
        if entry.index != expected {
            return Err(ApplyError::OutOfOrder {
                index: entry.index,
                last: self.applied,
            });
        }
        let decoded = if entry.payload.is_empty() {
            None
        } else {
            Some(Decoded::of(&entry.payload).map_err(ApplyError::Envelope)?)
        };
        // A coordinated stop: a binary that does not run the resume
        // version stops past the stop index; one that does refuses every
        // schema 2 entry there until the resuming `Activation` applies.
        let past_stop = match self.versions.stop {
            Some(stop) if entry.index > stop.at => {
                let supported = self.service.supported_version();
                if supported < stop.resume {
                    return Err(ApplyError::Stopped {
                        at: stop.at,
                        resume: stop.resume,
                    });
                }
                true
            }
            _ => false,
        };
        // The entry's own fallible checks run before the activation at
        // its index, so an entry that stops the container changes no
        // version and reaches no `on_configuration`.
        let rebuilt = match &decoded {
            Some(Decoded::Bounds(bounds)) => self.prepare_bounds(bounds)?,
            _ => None,
        };
        self.activate(entry)?;
        let envelope = match decoded {
            None => None,
            Some(Decoded::Service(_)) if past_stop => {
                return Ok(self.refused(entry, CoreRefusal::PastStop));
            }
            Some(decoded) => match decoded {
                Decoded::Service(envelope) => Some(envelope),
                Decoded::Bounds(bounds) => return Ok(self.apply_bounds(entry, &bounds, rebuilt)),
                Decoded::Membership => {
                    // The core's: it delivers nothing, and moves the log
                    // time on as any entry.
                    self.applied = Some(entry.index);
                    self.sessions.observe(entry.event_time);
                    return Ok(Applied::Nothing);
                }
                Decoded::Activation(activation) => {
                    return Ok(match self.versions.activation(entry.index, &activation) {
                        Ok(()) => self.refused_or_nothing(entry, None),
                        Err(refusal) => self.refused(entry, refusal),
                    });
                }
                Decoded::Stop(stop) => {
                    return Ok(match self.versions.stop(entry.index, stop) {
                        Ok(()) => self.refused_or_nothing(entry, None),
                        Err(refusal) => self.refused(entry, refusal),
                    });
                }
                Decoded::Guard(guard) => return self.apply_guard(entry, guard),
            },
        };
        if let Some(Envelope::Request { command, .. }) = envelope
            && self.admits(command).is_err()
        {
            let refusal = CoreRefusal::VersionInactive {
                active: self.versions.active,
            };
            return Ok(self.refused(entry, refusal));
        }
        self.applied = Some(entry.index);
        if matches!(envelope, Some(Envelope::Register { .. })) {
            self.fresh = false;
        }
        let active = self.versions.active;
        let Self {
            service,
            sessions,
            timers,
            ..
        } = self;
        let Some(envelope) = envelope else {
            sessions.observe(entry.event_time);
            return Ok(Applied::Nothing);
        };
        Ok(match envelope {
            Envelope::Register { client } => {
                Applied::Registered(sessions.register(client, entry.index, entry.event_time))
            }
            Envelope::Close { client, epoch } => {
                Applied::Closed(sessions.close(client, epoch, entry.event_time))
            }
            Envelope::Request { request, command } => {
                let mut context = Context::of(entry, sessions, active, timers);
                let outcome = sessions.request(request, command, entry.event_time, |reply| {
                    service.on_command(&mut context, request.client, command, reply)
                });
                Applied::Answered { request, outcome }
            }
            Envelope::TimerFired { timer, deadline } => {
                sessions.observe(entry.event_time);
                if timers.deadline(timer) == Some(deadline) && deadline <= sessions.log_time() {
                    let _ = timers.remove(timer);
                    service.on_timer(&mut Context::of(entry, sessions, active, timers), timer);
                    Applied::Fired { timer }
                } else {
                    Applied::Nothing
                }
            }
            Envelope::Configuration(configuration) => {
                sessions.observe(entry.event_time);
                service.on_configuration(
                    &mut Context::of(entry, sessions, active, timers),
                    configuration,
                );
                Applied::Configured
            }
        })
    }

    /// An entry applied as nothing, or as `refusal`: it moves the log
    /// time on as any entry.
    fn refused_or_nothing(
        &mut self,
        entry: &Entry,
        refusal: Option<CoreRefusal>,
    ) -> Applied<'static> {
        self.applied = Some(entry.index);
        self.sessions.observe(entry.event_time);
        refusal.map_or(Applied::Nothing, Applied::CoreRefused)
    }

    fn refused(&mut self, entry: &Entry, refusal: CoreRefusal) -> Applied<'static> {
        self.refused_or_nothing(entry, Some(refusal))
    }

    /// Activates a pending `Activation` whose index `entry` reaches,
    /// before `entry` applies: the new version, then its configuration to
    /// the service with `entry`'s [`Context`] (ADR-0122 decision 2).
    ///
    /// # Errors
    ///
    /// [`ApplyError::VersionUnsupported`] for a version above the
    /// binary's: nothing changes.
    fn activate(&mut self, entry: &Entry) -> Result<(), ApplyError> {
        if !self
            .versions
            .pending
            .as_ref()
            .is_some_and(|pending| entry.index >= pending.at)
        {
            return Ok(());
        }
        let supported = self.service.supported_version();
        let Some(pending) = self
            .versions
            .pending
            .take_if(|pending| pending.version.service <= supported)
        else {
            let required = self
                .versions
                .pending
                .as_ref()
                .map_or(0, |pending| pending.version.service);
            return Err(ApplyError::VersionUnsupported {
                required,
                supported,
            });
        };
        self.versions.active = pending.version;
        if !pending.configuration.is_empty() {
            self.versions.configured = true;
            let active = self.versions.active;
            let Self {
                service,
                sessions,
                timers,
                ..
            } = self;
            service.on_configuration(
                &mut Context::of(entry, sessions, active, timers),
                &pending.configuration,
            );
        }
        Ok(())
    }

    /// Applies a `SessionBounds` entry. Only the log's first counts: equal
    /// bounds deliver nothing; a fresh table is rebuilt from different
    /// ones, keeping its log time; a table that has applied a registration
    /// stops. A later one delivers nothing, whatever it carries.
    /// A guard entry: the table applies it at the log time once the
    /// entry's event time is observed. A stop applies nothing.
    fn apply_guard(&mut self, entry: &Entry, guard: GuardEntry) -> Result<Applied<'_>, ApplyError> {
        let log_time = self.sessions.log_time().max(entry.event_time);
        let outcome = self
            .guards
            .apply(guard, entry.index, log_time)
            .map_err(ApplyError::Guard)?;
        self.applied = Some(entry.index);
        self.sessions.observe(entry.event_time);
        let operation = match guard {
            GuardEntry::Close { operation, .. } | GuardEntry::Reopen { operation, .. } => {
                Some(operation)
            }
            _ => None,
        };
        Ok(Applied::Guard {
            outcome,
            operation,
            index: entry.index,
            log_time,
            effects: self.guards.effects(),
        })
    }

    /// The checks of a bounds entry that can stop the container, with
    /// nothing changed: the rebuilt table when different bounds rebuild a
    /// fresh one.
    fn prepare_bounds(&self, bounds: &SessionBounds) -> Result<Option<SessionTable>, ApplyError> {
        let table = self.sessions.config();
        if self.bounds_logged || bounds.config == table {
            return Ok(None);
        }
        if !self.fresh {
            return Err(ApplyError::BoundsDiffer {
                logged: bounds.config,
                table,
            });
        }
        SessionTable::new_within(bounds.config, self.session_budget)
            .map(Some)
            .map_err(ApplyError::BoundsUnheld)
    }

    fn apply_bounds(
        &mut self,
        entry: &Entry,
        bounds: &SessionBounds,
        rebuilt: Option<SessionTable>,
    ) -> Applied<'_> {
        if let Some(mut rebuilt) = rebuilt {
            rebuilt.observe(self.sessions.log_time());
            self.sessions = rebuilt;
        }
        // The log's first bounds choose the deduplication rules: a log of
        // an earlier build replays its own (karyos#750).
        if !self.bounds_logged {
            self.sessions.set_exact(bounds.exact);
        }
        self.applied = Some(entry.index);
        self.bounds_logged = true;
        self.sessions.observe(entry.event_time);
        Applied::Nothing
    }
}
