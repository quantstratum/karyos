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
//! The envelope's bytes are version [`ENVELOPE_VERSION`], not frozen
//! (karyos#686, design decision D3); a schema 2 version 1 of SPEC.md §8.5
//! replaces them before the phase 4 gate. Little endian; every envelope starts with the version byte and a
//! kind byte:
//!
//! | Kind | Byte | Then |
//! | --- | --- | --- |
//! | register | 1 | client 8 |
//! | close | 2 | client 8, epoch 8 |
//! | request | 3 | client 8, epoch 8, sequence 8, lowest unanswered 8, command |
//! | timer fired | 4 | timer 8, deadline 8 |
//! | configuration | 5 | configuration |

#[cfg(test)]
mod tests;

use crate::dedup::{
    ConfigError, DedupConfig, Outcome, RegisterError, Registered, Request, SessionTable,
};
use crate::log::Entry;

/// The envelope's version.
pub const ENVELOPE_VERSION: u8 = 1;

const REGISTER: u8 = 1;
const CLOSE: u8 = 2;
const REQUEST: u8 = 3;
const TIMER_FIRED: u8 = 4;
const CONFIGURATION: u8 = 5;

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

/// Bytes that are not an envelope of this version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EnvelopeError {
    /// Another version.
    #[error("envelope version {0}, not {ENVELOPE_VERSION}")]
    Version(u8),
    /// An unknown kind.
    #[error("unknown envelope kind {0}")]
    Kind(u8),
    /// Cut short, or bytes left over.
    #[error("envelope of the wrong length")]
    Length,
}

impl<'a> Envelope<'a> {
    /// Appends the envelope's bytes to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(ENVELOPE_VERSION);
        match *self {
            Self::Register { client } => {
                out.push(REGISTER);
                out.extend_from_slice(&client.to_le_bytes());
            }
            Self::Close { client, epoch } => {
                out.push(CLOSE);
                out.extend_from_slice(&client.to_le_bytes());
                out.extend_from_slice(&epoch.to_le_bytes());
            }
            Self::Request { request, command } => {
                out.push(REQUEST);
                for field in [
                    request.client,
                    request.epoch,
                    request.sequence,
                    request.lowest_unanswered,
                ] {
                    out.extend_from_slice(&field.to_le_bytes());
                }
                out.extend_from_slice(command);
            }
            Self::TimerFired { timer, deadline } => {
                out.push(TIMER_FIRED);
                out.extend_from_slice(&timer.to_le_bytes());
                out.extend_from_slice(&deadline.to_le_bytes());
            }
            Self::Configuration(configuration) => {
                out.push(CONFIGURATION);
                out.extend_from_slice(configuration);
            }
        }
    }

    /// The envelope's bytes.
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }

    /// The envelope in `bytes`.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError`] for another version, an unknown kind, or bytes
    /// cut short or left over.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, EnvelopeError> {
        let [version, kind, rest @ ..] = bytes else {
            return Err(EnvelopeError::Length);
        };
        if *version != ENVELOPE_VERSION {
            return Err(EnvelopeError::Version(*version));
        }
        let mut fields = Fields(rest);
        let envelope = match *kind {
            REGISTER => Self::Register {
                client: fields.u64()?,
            },
            CLOSE => Self::Close {
                client: fields.u64()?,
                epoch: fields.u64()?,
            },
            REQUEST => {
                let request =
                    Request::new(fields.u64()?, fields.u64()?, fields.u64()?, fields.u64()?);
                return Ok(Self::Request {
                    request,
                    command: fields.0,
                });
            }
            TIMER_FIRED => Self::TimerFired {
                timer: fields.u64()?,
                deadline: fields.u64()?,
            },
            CONFIGURATION => return Ok(Self::Configuration(rest)),
            other => return Err(EnvelopeError::Kind(other)),
        };
        if fields.0.is_empty() {
            Ok(envelope)
        } else {
            Err(EnvelopeError::Length)
        }
    }
}

/// The fixed fields of an envelope, read in order.
struct Fields<'a>(&'a [u8]);

impl Fields<'_> {
    fn u64(&mut self) -> Result<u64, EnvelopeError> {
        let (field, rest) = self
            .0
            .split_first_chunk::<8>()
            .ok_or(EnvelopeError::Length)?;
        self.0 = rest;
        Ok(u64::from_le_bytes(*field))
    }
}

/// An entry proposed: where the core put it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Proposed {
    /// Its log index.
    pub index: u64,
    /// Its term.
    pub term: u64,
}

impl Proposed {
    /// At `index` in `term`.
    #[must_use]
    pub fn new(index: u64, term: u64) -> Self {
        Self { index, term }
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
/// implements it (design decision D1 of karyos#686).
pub trait Propose {
    /// Appends `payload` as a new entry, if this node leads.
    ///
    /// # Errors
    ///
    /// [`NotLeader`] when it does not, with the leader it knows of.
    fn propose(&mut self, payload: Vec<u8>) -> Result<Proposed, NotLeader>;
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

/// The scheduled timers: ids and deadlines, sorted by id, never past
/// their capacity.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Timers(Vec<(u64, u64)>);

impl Timers {
    fn deadline(&self, timer: u64) -> Option<u64> {
        let slot = self.0.binary_search_by_key(&timer, |&(id, _)| id).ok()?;
        self.0.get(slot).map(|&(_, deadline)| deadline)
    }

    fn remove(&mut self, timer: u64) -> bool {
        match self.0.binary_search_by_key(&timer, |&(id, _)| id) {
            Ok(slot) => {
                let _ = self.0.remove(slot);
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
        let timers = &mut self.timers.0;
        match timers.binary_search_by_key(&timer, |&(id, _)| id) {
            Ok(slot) => {
                if let Some(entry) = timers.get_mut(slot) {
                    entry.1 = deadline;
                }
            }
            Err(slot) => {
                if timers.len() == timers.capacity() {
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
    /// The entry is not the one after the last applied.
    #[error("entry {index} after {last:?}: not in log order")]
    OutOfOrder {
        /// The entry's index.
        index: u64,
        /// The last applied.
        last: Option<u64>,
    },
    /// Its payload is not an envelope this container reads.
    #[error(transparent)]
    Envelope(#[from] EnvelopeError),
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
            timers: Timers(Vec::with_capacity(timers)),
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
            .0
            .iter()
            .filter(move |&&(_, deadline)| deadline <= now)
            .map(|&(timer, deadline)| Envelope::TimerFired { timer, deadline })
    }

    /// Applies the committed `entry`, the one after the last applied.
    ///
    /// # Errors
    ///
    /// [`ApplyError`] for an entry out of order or a payload that is not
    /// an envelope; the container applies nothing more.
    pub fn apply(&mut self, entry: &Entry) -> Result<Applied<'_>, ApplyError> {
        if self.applied.is_some_and(|last| entry.index != last + 1) {
            return Err(ApplyError::OutOfOrder {
                index: entry.index,
                last: self.applied,
            });
        }
        let envelope = if entry.payload.is_empty() {
            None
        } else {
            Some(Envelope::decode(&entry.payload)?)
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
