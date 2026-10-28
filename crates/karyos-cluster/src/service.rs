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
}

/// The timers of [`ContainerConfig::default`].
pub const DEFAULT_TIMERS: u32 = 1024;

impl Default for ContainerConfig {
    /// The default session table, and [`DEFAULT_TIMERS`] timers.
    fn default() -> Self {
        Self {
            dedup: DedupConfig::default(),
            timers: DEFAULT_TIMERS,
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
    /// Its payload is not a schema 2 message: a safety stop (see
    /// [`ServiceContainer::apply`]).
    #[error("not a schema 2 message: {0}")]
    Envelope(CodecError),
}

/// The container: a service, its session table and its timers, applying
/// committed entries in order.
#[derive(Debug)]
pub struct ServiceContainer<S> {
    service: S,
    sessions: SessionTable,
    timers: Timers,
    applied: Option<u64>,
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
            sessions: SessionTable::new(config.dedup)?,
            timers: Timers {
                scheduled: Vec::with_capacity(timers),
                bound: timers,
            },
            applied: None,
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
    /// [`ApplyError`] for an entry out of order or a payload that is not
    /// a schema 2 message. That is a safety stop, not a recoverable error:
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
            Some(Envelope::decode(&entry.payload).map_err(ApplyError::Envelope)?)
        };
        self.applied = Some(entry.index);
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
}
