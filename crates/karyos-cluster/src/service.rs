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
//! container as above.

#[cfg(test)]
mod golden;
#[cfg(test)]
mod tests;

use karyos_codec::{CodecError, Decoder, ENVELOPE_LENGTH, Encoder, Template, VAR_HEADER_LENGTH};

use crate::dedup::{
    ConfigError, DedupConfig, Outcome, RegisterError, Registered, Request, SessionTable,
};
use crate::log::Entry;

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
/// The only version of schema 5.
pub const CORE_VERSION: u16 = 1;
/// `SessionBounds`, template 1 of schema 5: a 20-byte block.
pub const SESSION_BOUNDS: Template = Template {
    schema_id: CORE_SCHEMA_ID,
    template_id: 1,
    version: CORE_VERSION,
    block_length: 20,
    max_length: ENVELOPE_LENGTH as u32 + 20,
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
}

impl SessionBounds {
    /// The entry for `config`.
    #[must_use]
    pub fn new(config: DedupConfig) -> Self {
        Self { config }
    }

    /// Encodes into `out`; returns the message's length, 32.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] for a short `out`, and
    /// [`CodecError::ValueOutOfRange`] for a bound of 0.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let config = self.config;
        let mut encoder = Encoder::new(out, &SESSION_BOUNDS)?;
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
            || envelope.version != CORE_VERSION
            || envelope.template_id != SESSION_BOUNDS.template_id
        {
            return Err(CodecError::UnsupportedSchema {
                schema: envelope.schema_id,
                template: envelope.template_id,
                version: envelope.version,
            });
        }
        let (block, decoder) = Decoder::new(bytes, &SESSION_BOUNDS)?;
        let config = DedupConfig::default()
            .with_sessions(nonzero32("sessions", block.u32(0)?)?)
            .with_window(nonzero32("window", block.u32(4)?)?)
            .with_response_bytes(nonzero32("response_bytes", block.u32(8)?)?)
            .with_ttl(nonzero("ttl", block.u64(12)?)?);
        decoder.finish()?;
        Ok(Self { config })
    }
}

/// A decoded entry: the service's (schema 2) or the core's (schema 5).
enum Decoded<'a> {
    Service(Envelope<'a>),
    Bounds(SessionBounds),
}

impl<'a> Decoded<'a> {
    fn of(bytes: &'a [u8]) -> Result<Self, CodecError> {
        if karyos_codec::Envelope::read(bytes)?.schema_id == CORE_SCHEMA_ID {
            Ok(Self::Bounds(SessionBounds::decode(bytes)?))
        } else {
            Ok(Self::Service(Envelope::decode(bytes)?))
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
    /// A client opens a session; its epoch is the entry's index.
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

    /// The message's bytes.
    ///
    /// # Errors
    ///
    /// As [`Envelope::encode`], but never `Truncated`.
    pub fn to_vec(&self) -> Result<Vec<u8>, CodecError> {
        let max = match self {
            Self::Register { .. } => REGISTER.max_length,
            Self::Close { .. } => CLOSE.max_length,
            Self::Request { .. } => REQUEST.max_length,
            Self::TimerFired { .. } => TIMER_FIRED.max_length,
            Self::Configuration(_) => CONFIGURATION.max_length,
        };
        let mut out = vec![0; usize::try_from(max).unwrap_or(usize::MAX)];
        let length = self.encode(&mut out)?;
        out.truncate(length);
        Ok(out)
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
    /// # Errors
    ///
    /// [`NotLeader`] when it does not, with the leader it knows of.
    fn propose(&mut self, payload: Vec<u8>) -> Result<(), NotLeader>;

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
    timers: &'a mut Timers,
}

impl<'a> Context<'a> {
    /// For `entry`, whose event time the log time includes.
    fn of(entry: &Entry, sessions: &SessionTable, timers: &'a mut Timers) -> Self {
        Self {
            index: entry.index,
            term: entry.term,
            log_time: sessions.log_time().max(entry.event_time),
            timers,
        }
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
    pub session_budget: u64,
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

    /// With its session table limited to `budget` reserved bytes.
    #[must_use]
    pub fn with_session_budget(mut self, budget: u64) -> Self {
        self.session_budget = budget;
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
    /// Its payload is neither a schema 2 message nor a core's own entry
    /// of schema 5: a safety stop (see [`ServiceContainer::apply`]).
    #[error("not a schema 2 or schema 5 message: {0}")]
    Envelope(CodecError),
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
    /// safety stop.
    #[error("the logged session bounds cannot be held: {0}")]
    BoundsUnheld(ConfigError),
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
        })
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
        if self.bounds_logged {
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
    /// [`ProposeRefused::NotLeader`] when `core` does not lead, and
    /// [`ProposeRefused::Codec`] for an envelope schema 2 refuses.
    pub fn propose<P: Propose>(
        &self,
        envelope: &Envelope<'_>,
        core: &mut P,
    ) -> Result<(), ProposeRefused> {
        if matches!(envelope, Envelope::Register { .. }) && !self.bounds_logged && core.leads() {
            return Err(ProposeRefused::BoundsPending);
        }
        core.propose(envelope.to_vec()?)?;
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
        let envelope = if entry.payload.is_empty() {
            None
        } else {
            match Decoded::of(&entry.payload).map_err(ApplyError::Envelope)? {
                Decoded::Service(envelope) => Some(envelope),
                Decoded::Bounds(bounds) => return self.apply_bounds(entry, bounds),
            }
        };
        self.applied = Some(entry.index);
        if matches!(envelope, Some(Envelope::Register { .. })) {
            self.fresh = false;
        }
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
                let mut context = Context::of(entry, sessions, timers);
                let outcome = sessions.request(request, entry.event_time, |reply| {
                    service.on_command(&mut context, request.client, command, reply)
                });
                Applied::Answered { request, outcome }
            }
            Envelope::TimerFired { timer, deadline } => {
                sessions.observe(entry.event_time);
                if timers.deadline(timer) == Some(deadline) && deadline <= sessions.log_time() {
                    let _ = timers.remove(timer);
                    service.on_timer(&mut Context::of(entry, sessions, timers), timer);
                    Applied::Fired { timer }
                } else {
                    Applied::Nothing
                }
            }
            Envelope::Configuration(configuration) => {
                sessions.observe(entry.event_time);
                service.on_configuration(&mut Context::of(entry, sessions, timers), configuration);
                Applied::Configured
            }
        })
    }

    /// Applies a `SessionBounds` entry. Only the log's first counts: equal
    /// bounds deliver nothing; a fresh table is rebuilt from different
    /// ones, keeping its log time; a table that has applied a registration
    /// stops. A later one delivers nothing, whatever it carries.
    fn apply_bounds(
        &mut self,
        entry: &Entry,
        bounds: SessionBounds,
    ) -> Result<Applied<'_>, ApplyError> {
        let table = self.sessions.config();
        if !self.bounds_logged && bounds.config != table {
            if !self.fresh {
                return Err(ApplyError::BoundsDiffer {
                    logged: bounds.config,
                    table,
                });
            }
            let mut rebuilt = SessionTable::new_within(bounds.config, self.session_budget)
                .map_err(ApplyError::BoundsUnheld)?;
            rebuilt.observe(self.sessions.log_time());
            self.sessions = rebuilt;
        }
        self.applied = Some(entry.index);
        self.bounds_logged = true;
        self.sessions.observe(entry.event_time);
        Ok(Applied::Nothing)
    }
}
