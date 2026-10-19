// SPDX-License-Identifier: Apache-2.0

//! The Archive's client (quantstratum-docs:
//! karyos/design/archive-gap-analysis.md, A6b; archive-control-codec.md
//! §7a): a requester over the Archive's control streams that hands out
//! replays to a live merge, as a [`ReplayProvider`].
//!
//! Asked for a replay of a source's `[from, to)`, it lists the Archive's
//! recordings, finds one of that publication and incarnation that covers
//! the range, asks for a replay of exactly that range onto its
//! [`ClientConfig::target_stream_id`], and subscribes to the target, which
//! the host's [`ReplayTargets`] finds at that stream and the replay id's
//! low 32 bits. It never blocks: each [`ReplayProvider::replay`] call sends
//! what it can and reads the answers there are. A recording that still
//! records and has not reached `to` is listed again until
//! [`ClientConfig::deadline`].
//!
//! Why no replay comes ([`ReplayUnavailable`]):
//! - no recording of the source covers the range: `NoRecording`;
//! - every recording of the source starts after `from`: `RetentionShort`;
//! - a recording of the source that still records had not reached `to` by
//!   the deadline: `RecordingBehind`;
//! - the Archive refused the request, or the target never appeared:
//!   `Refused`.
//!
//! Correlation ids carry [`ClientConfig::client_id`] in their high 32
//! bits; answers to other requesters, and signals, are skipped. A replay
//! handed out stops through its [`ReplayStop`], which sends a
//! `StopReplay`, or queues it when the request stream has no room. A
//! replay withdrawn before it was handed out is stopped when its answer
//! comes. Queued stops and late answers are handled by every call, and by
//! [`ArchiveClient::duty`], which a host calls while no replay is asked
//! for; dropping the client sends what it can.
//!
//! A descriptor names no lane: a recording of another lane of the same
//! publication cannot be told apart. Only lane 0 is replayed (A6, Q6).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use karyos_client::{
    ClientSubscription, Replay, ReplayProvider, ReplayRequest, ReplayStatus, ReplayStop,
    ReplayUnavailable,
};
use karyos_sys::term_bytes::{HeapTerms, TermBytes};

use crate::catalog::SourceIncarnation;
use crate::control::{
    self, ControlMessage, ControlResponse, MAX_CHANNEL, MAX_LIST_COUNT, RecordingDescriptor,
    RecordingState, ReplayRate, ResponseCode,
};
use crate::server::{MAX_ANSWER, MAX_REQUEST, replay_session_id};

#[cfg(test)]
mod tests;

/// Answers read at most per call.
const ANSWERS_PER_CALL: usize = 64;

/// Withdrawn replay requests remembered at most.
const MAX_ORPHANS: usize = 64;

/// Stops queued at most; past it, the oldest is dropped, and its replay
/// runs to its end.
const MAX_STOPS: usize = 64;

/// The request stream, as a requester writes it.
pub trait ControlRequests: Send {
    /// Sends one request; `false` when there is no room yet, and the same
    /// request is offered again later.
    fn send(&mut self, message: &[u8]) -> bool;
}

/// The response stream, as a requester reads it.
pub trait ControlResponses: Send {
    /// Copies the next message into `out` and returns its length, or
    /// `None` when there is none. A message longer than `out` is the
    /// stream's to drop.
    fn next(&mut self, out: &mut [u8]) -> Option<usize>;
}

/// Where the replay targets are: the host's driver, which the Archive's
/// client does not know (SPEC.md §14).
pub trait ReplayTargets<T: TermBytes = HeapTerms>: Send {
    /// A subscription to the replay target at `stream_id` and
    /// `session_id`, once the host has it; `None` until then.
    fn subscribe(&mut self, stream_id: i32, session_id: i32) -> Option<ClientSubscription<T>>;
}

/// The client's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ClientConfig {
    /// This client's id, the high 32 bits of its correlation ids, unique
    /// among the Archive's requesters (archive-control-codec.md §7a), and
    /// for each client instance: the low 32 bits restart at 1 with each.
    pub client_id: u32,
    /// The stream replays are asked onto: kept for replays, so a target's
    /// key never collides with another stream's.
    pub target_stream_id: i32,
    /// The channel named in replay requests, 1 to [`MAX_CHANNEL`] bytes.
    pub target_channel: String,
    /// How long a request waits, from its first call, for a recording to
    /// cover its range and for its target to appear.
    pub deadline: Duration,
    /// How long between two lists while a recording is behind.
    pub relist: Duration,
    /// Recordings asked for in one list, 1 to [`MAX_LIST_COUNT`].
    pub page: u32,
}

impl ClientConfig {
    /// A client `client_id` asking for replays onto `target_stream_id`
    /// over `karyos:ipc`, waiting up to a second.
    #[must_use]
    pub fn new(client_id: u32, target_stream_id: i32) -> Self {
        Self {
            client_id,
            target_stream_id,
            target_channel: "karyos:ipc".to_owned(),
            deadline: Duration::from_secs(1),
            relist: Duration::from_millis(10),
            page: MAX_LIST_COUNT,
        }
    }
}

/// A client configuration that cannot work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The target channel is empty or longer than [`MAX_CHANNEL`] bytes,
    /// so no replay request could be sent.
    #[error("the target channel is 1 to {MAX_CHANNEL} bytes")]
    TargetChannel,
}

/// What the client and the stops of the replays it handed out share: the
/// request stream, the stops not sent yet, and the correlation ids.
struct Outbox<Q> {
    requests: Q,
    /// Stops that found no room yet: the replay id, and the correlation id
    /// each was given when queued.
    stops: Vec<(u64, u64)>,
    client_id: u32,
    next: u32,
    buffer: Vec<u8>,
}

impl<Q: ControlRequests> Outbox<Q> {
    /// A new correlation id; `None` once this client's ids are used up.
    fn correlation(&mut self) -> Option<u64> {
        let low = self.next;
        self.next = low.checked_add(1)?;
        Some((u64::from(self.client_id) << 32) | u64::from(low))
    }

    /// Encodes `message` and sends it; `false` when there is no room.
    fn send(&mut self, message: &ControlMessage<'_>) -> bool {
        match message.encode(&mut self.buffer) {
            Ok(length) => self
                .buffer
                .get(..length)
                .is_some_and(|bytes| self.requests.send(bytes)),
            // Every request this client builds encodes: a failure is a bug,
            // and the request is dropped rather than sent malformed.
            Err(_) => true,
        }
    }

    /// Stops replay `replay_id`, now or once there is room. Its
    /// correlation id is taken once, here; with none left the stop cannot
    /// be sent, and the replay runs to its end.
    fn stop(&mut self, replay_id: u64) {
        let Some(correlation_id) = self.correlation() else {
            return;
        };
        if self.stops.len() >= MAX_STOPS {
            self.stops.remove(0);
        }
        self.stops.push((replay_id, correlation_id));
        self.flush_stops();
    }

    /// Sends the stops that wait, in order, while there is room.
    fn flush_stops(&mut self) {
        while let Some(&(replay_id, correlation_id)) = self.stops.first() {
            let message = ControlMessage::StopReplay(control::StopReplay {
                correlation_id,
                replay_id,
            });
            if !self.send(&message) {
                return;
            }
            self.stops.remove(0);
        }
    }
}

/// Locks `outbox`, also after a panic in another holder.
fn lock<Q>(outbox: &Mutex<Outbox<Q>>) -> std::sync::MutexGuard<'_, Outbox<Q>> {
    match outbox.lock() {
        Ok(outbox) => outbox,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Stops a handed-out replay through the client's request stream.
struct Stopper<Q> {
    outbox: Arc<Mutex<Outbox<Q>>>,
    replay_id: u64,
}

impl<Q: ControlRequests> ReplayStop for Stopper<Q> {
    fn stop(&mut self) {
        lock(&self.outbox).stop(self.replay_id);
    }
}

/// What the lists found for the request so far.
#[derive(Debug, Clone, Copy, Default)]
struct Found {
    /// A recording of the source that covers the range.
    covering: Option<u64>,
    /// A recording of the source exists.
    any: bool,
    /// A recording of the source starts at or before `from`.
    in_time: bool,
    /// One of those still records and has not reached `to`.
    behind: bool,
    /// The lowest id of a recording of the source that starts at or
    /// before `from`: where a list again begins.
    first_in_time: Option<u64>,
}

/// Where a request stands.
#[derive(Debug, Clone, Copy)]
enum Step {
    /// A list page from `from_id`, answered under `correlation_id`.
    Listing {
        correlation_id: u64,
        from_id: u64,
        found: Found,
        /// The last recording listed in this page.
        last: Option<u64>,
        sent: bool,
    },
    /// The recording is behind, as the list answered at `listed` said:
    /// list again a relist interval later.
    Behind { listed: u64 },
    /// The replay of `recording_id`, answered under `correlation_id`.
    Asking {
        correlation_id: u64,
        recording_id: u64,
        sent: bool,
    },
    /// The replay runs; its target is looked for.
    Subscribing { replay_id: u64 },
}

/// A request and where it stands.
#[derive(Debug, Clone, Copy)]
struct Pending {
    request: ReplayRequest,
    /// The bytes to replay: `to - from`, nonzero.
    length: u64,
    /// Its first call, on the client's clock.
    since: u64,
    step: Step,
    /// A list found the recording behind: past the deadline it is
    /// `RecordingBehind`, even while a list again is unanswered.
    behind: bool,
    /// Where a list again begins.
    relist_from: u64,
}

/// What a call ends with.
enum Outcome<T: TermBytes> {
    Waiting(Pending),
    Done(ReplayStatus<T>),
}

/// The Archive's client: a [`ReplayProvider`] over its control streams
/// (see the module documentation).
pub struct ArchiveClient<Q: ControlRequests + 'static, R: ControlResponses, S> {
    config: ClientConfig,
    outbox: Arc<Mutex<Outbox<Q>>>,
    responses: R,
    targets: S,
    clock: Box<dyn FnMut() -> u64 + Send>,
    pending: Option<Pending>,
    /// Correlation ids of replay requests withdrawn before their answer:
    /// a replay they started is stopped when the answer comes.
    orphans: Vec<u64>,
    answer: Vec<u8>,
}

impl<Q: ControlRequests + 'static, R: ControlResponses, S> core::fmt::Debug
    for ArchiveClient<Q, R, S>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ArchiveClient")
            .field("config", &self.config)
            .field("pending", &self.pending)
            .finish_non_exhaustive()
    }
}

impl<Q: ControlRequests + 'static, R: ControlResponses, S> ArchiveClient<Q, R, S> {
    /// A client sending on `requests`, reading `responses` and finding the
    /// targets through `targets`, on a monotonic clock.
    ///
    /// # Errors
    ///
    /// [`ConfigError::TargetChannel`] for a target channel no request can
    /// carry.
    pub fn new(
        config: ClientConfig,
        requests: Q,
        responses: R,
        targets: S,
    ) -> Result<Self, ConfigError> {
        let epoch = Instant::now();
        let clock = move || u64::try_from(epoch.elapsed().as_nanos()).unwrap_or(u64::MAX);
        Self::with_clock(config, requests, responses, targets, Box::new(clock))
    }

    /// [`ArchiveClient::new`] on `clock`, which tells nanoseconds.
    ///
    /// # Errors
    ///
    /// As [`ArchiveClient::new`].
    pub fn with_clock(
        config: ClientConfig,
        requests: Q,
        responses: R,
        targets: S,
        clock: Box<dyn FnMut() -> u64 + Send>,
    ) -> Result<Self, ConfigError> {
        if !(1..=MAX_CHANNEL).contains(&config.target_channel.len()) {
            return Err(ConfigError::TargetChannel);
        }
        Ok(Self {
            outbox: Arc::new(Mutex::new(Outbox {
                requests,
                stops: Vec::new(),
                client_id: config.client_id,
                next: 1,
                buffer: vec![0; MAX_REQUEST],
            })),
            config,
            responses,
            targets,
            clock,
            pending: None,
            orphans: Vec::new(),
            answer: vec![0; MAX_ANSWER],
        })
    }

    /// The work a host gives the client while no replay is asked for: the
    /// stops that wait are sent, and the answers there are read, which
    /// stops a replay withdrawn before its answer came. While a replay is
    /// asked for, [`ReplayProvider::replay`] does this itself.
    pub fn duty(&mut self) {
        lock(&self.outbox).flush_stops();
        if self.pending.is_some() {
            return;
        }
        let mut buffer = std::mem::take(&mut self.answer);
        for _ in 0..ANSWERS_PER_CALL {
            let Some(length) = self.responses.next(&mut buffer) else {
                break;
            };
            if let Some(Ok(message)) = buffer.get(..length).map(ControlMessage::decode) {
                self.orphaned(&message);
            }
        }
        self.answer = buffer;
    }

    /// Whether more than the deadline passed since `since`, at `now`.
    fn expired(&self, since: u64, now: u64) -> bool {
        let deadline = u64::try_from(self.config.deadline.as_nanos()).unwrap_or(u64::MAX);
        now.checked_sub(since)
            .is_some_and(|waited| waited > deadline)
    }

    /// Whether a relist interval passed since the list answered at
    /// `listed`.
    fn relisting(&self, listed: u64, now: u64) -> bool {
        let relist = u64::try_from(self.config.relist.as_nanos()).unwrap_or(u64::MAX);
        now.checked_sub(listed)
            .is_some_and(|waited| waited >= relist)
    }

    /// A new list from `from_id`, carrying what earlier pages found.
    fn list(&mut self, from_id: u64, found: Found) -> Option<Step> {
        Some(Step::Listing {
            correlation_id: lock(&self.outbox).correlation()?,
            from_id,
            found,
            last: None,
            sent: false,
        })
    }

    /// Sends the step's request if it has not gone yet; the step after.
    fn send(&mut self, pending: &Pending) -> Step {
        let mut outbox = lock(&self.outbox);
        match pending.step {
            Step::Listing {
                correlation_id,
                from_id,
                found,
                last,
                sent: false,
            } => Step::Listing {
                correlation_id,
                from_id,
                found,
                last,
                sent: outbox.send(&ControlMessage::ListRecordings(control::ListRecordings {
                    correlation_id,
                    from_id,
                    max_count: self.config.page.clamp(1, MAX_LIST_COUNT),
                })),
            },
            Step::Asking {
                correlation_id,
                recording_id,
                sent: false,
            } => Step::Asking {
                correlation_id,
                recording_id,
                sent: outbox.send(&ControlMessage::Replay(control::Replay {
                    correlation_id,
                    recording_id,
                    position: pending.request.from,
                    length: pending.length,
                    rate: ReplayRate::Full,
                    target_stream_id: self.config.target_stream_id,
                    target_channel: &self.config.target_channel,
                })),
            },
            step => step,
        }
    }

    /// What the lists found, decided at `now`.
    fn decide<T: TermBytes>(&mut self, pending: Pending, found: Found, now: u64) -> Outcome<T> {
        let step = if let Some(recording_id) = found.covering {
            match lock(&self.outbox).correlation() {
                Some(correlation_id) => Step::Asking {
                    correlation_id,
                    recording_id,
                    sent: false,
                },
                None => {
                    return Outcome::Done(ReplayStatus::Unavailable(ReplayUnavailable::Refused));
                }
            }
        } else if found.behind {
            if self.expired(pending.since, now) {
                return Outcome::Done(ReplayStatus::Unavailable(
                    ReplayUnavailable::RecordingBehind,
                ));
            }
            return Outcome::Waiting(Pending {
                step: Step::Behind { listed: now },
                behind: true,
                relist_from: found.first_in_time.unwrap_or(0),
                ..pending
            });
        } else if found.any && !found.in_time {
            return Outcome::Done(ReplayStatus::Unavailable(ReplayUnavailable::RetentionShort));
        } else {
            return Outcome::Done(ReplayStatus::Unavailable(ReplayUnavailable::NoRecording));
        };
        Outcome::Waiting(Pending { step, ..pending })
    }

    /// Takes one answer into the pending request.
    fn take<T: TermBytes>(
        &mut self,
        pending: Pending,
        message: &ControlMessage<'_>,
        now: u64,
    ) -> Outcome<T> {
        match (pending.step, message) {
            (
                Step::Listing {
                    correlation_id,
                    from_id,
                    mut found,
                    sent,
                    ..
                },
                ControlMessage::RecordingDescriptor(descriptor),
            ) if descriptor.correlation_id == correlation_id => {
                look_at(descriptor, &pending.request, &mut found);
                Outcome::Waiting(Pending {
                    step: Step::Listing {
                        correlation_id,
                        from_id,
                        found,
                        last: Some(descriptor.recording_id),
                        sent,
                    },
                    ..pending
                })
            }
            (
                Step::Listing {
                    correlation_id,
                    found,
                    last,
                    ..
                },
                ControlMessage::ControlResponse(response),
            ) if response.correlation_id == correlation_id => {
                if response.code != ResponseCode::Ok {
                    return Outcome::Done(ReplayStatus::Unavailable(ReplayUnavailable::Refused));
                }
                let full = response.id >= u64::from(self.config.page.clamp(1, MAX_LIST_COUNT));
                match last.and_then(|last| last.checked_add(1)).filter(|_| full) {
                    // A full page: the next one, unless one already covers.
                    Some(next) if found.covering.is_none() => match self.list(next, found) {
                        Some(step) => Outcome::Waiting(Pending { step, ..pending }),
                        None => {
                            Outcome::Done(ReplayStatus::Unavailable(ReplayUnavailable::Refused))
                        }
                    },
                    _ => self.decide(pending, found, now),
                }
            }
            (Step::Asking { correlation_id, .. }, ControlMessage::ControlResponse(response))
                if response.correlation_id == correlation_id =>
            {
                answered(pending, response)
            }
            _ => {
                self.orphaned(message);
                Outcome::Waiting(pending)
            }
        }
    }

    /// Stops a replay started by a request withdrawn before its answer.
    fn orphaned(&mut self, message: &ControlMessage<'_>) {
        let ControlMessage::ControlResponse(response) = message else {
            return;
        };
        let Some(index) = self
            .orphans
            .iter()
            .position(|orphan| *orphan == response.correlation_id)
        else {
            return;
        };
        self.orphans.swap_remove(index);
        if response.code == ResponseCode::Ok {
            lock(&self.outbox).stop(response.id);
        }
    }

    /// Withdraws `pending`: a replay it may have started is stopped.
    fn withdraw(&mut self, pending: Pending) {
        match pending.step {
            Step::Asking {
                correlation_id,
                sent: true,
                ..
            } => {
                if self.orphans.len() >= MAX_ORPHANS {
                    self.orphans.remove(0);
                }
                self.orphans.push(correlation_id);
            }
            Step::Subscribing { replay_id } => lock(&self.outbox).stop(replay_id),
            _ => {}
        }
    }

    /// One call's work on `pending`, at `now`: the stops that wait, the
    /// step's request, the answers there are, then the steps that move
    /// without one.
    fn advance<T: TermBytes>(&mut self, pending: Pending, now: u64) -> Outcome<T>
    where
        S: ReplayTargets<T>,
    {
        lock(&self.outbox).flush_stops();
        let mut current = Pending {
            step: self.send(&pending),
            ..pending
        };
        let mut buffer = std::mem::take(&mut self.answer);
        for _ in 0..ANSWERS_PER_CALL {
            let Some(length) = self.responses.next(&mut buffer) else {
                break;
            };
            // A message that does not decode is no answer to this client.
            let Some(Ok(message)) = buffer.get(..length).map(ControlMessage::decode) else {
                continue;
            };
            match self.take(current, &message, now) {
                // A new step's request goes out at once.
                Outcome::Waiting(next) => {
                    current = Pending {
                        step: self.send(&next),
                        ..next
                    };
                }
                Outcome::Done(status) => {
                    self.answer = buffer;
                    return Outcome::Done(status);
                }
            }
        }
        self.answer = buffer;
        self.unanswered(current, now)
    }

    /// The steps that move without an answer: a list again once the
    /// recording may have caught up, the target once it appears, and the
    /// deadline.
    fn unanswered<T: TermBytes>(&mut self, pending: Pending, now: u64) -> Outcome<T>
    where
        S: ReplayTargets<T>,
    {
        let expired = self.expired(pending.since, now);
        match pending.step {
            Step::Behind { .. } if expired => Outcome::Done(ReplayStatus::Unavailable(
                ReplayUnavailable::RecordingBehind,
            )),
            Step::Behind { listed } if self.relisting(listed, now) => {
                match self.list(pending.relist_from, Found::default()) {
                    Some(step) => Outcome::Waiting(Pending {
                        step: self.send(&Pending { step, ..pending }),
                        ..pending
                    }),
                    None => Outcome::Done(ReplayStatus::Unavailable(ReplayUnavailable::Refused)),
                }
            }
            Step::Subscribing { replay_id } => {
                let session_id = replay_session_id(replay_id);
                if let Some(subscription) = self
                    .targets
                    .subscribe(self.config.target_stream_id, session_id)
                {
                    let stop = Stopper {
                        outbox: Arc::clone(&self.outbox),
                        replay_id,
                    };
                    let replay =
                        Replay::new(subscription, pending.request.source).with_stop(Box::new(stop));
                    return Outcome::Done(ReplayStatus::Ready(Box::new(replay)));
                }
                if expired {
                    // The target never appeared.
                    self.withdraw(pending);
                    return Outcome::Done(ReplayStatus::Unavailable(ReplayUnavailable::Refused));
                }
                Outcome::Waiting(pending)
            }
            // A list again, unanswered when the recording was behind.
            Step::Listing { .. } if expired && pending.behind => Outcome::Done(
                ReplayStatus::Unavailable(ReplayUnavailable::RecordingBehind),
            ),
            // No answer in time.
            Step::Listing { .. } | Step::Asking { .. } if expired => {
                self.withdraw(pending);
                Outcome::Done(ReplayStatus::Unavailable(ReplayUnavailable::Refused))
            }
            _ => Outcome::Waiting(pending),
        }
    }
}

impl<Q, R, S, T> ReplayProvider<T> for ArchiveClient<Q, R, S>
where
    Q: ControlRequests + 'static,
    R: ControlResponses,
    S: ReplayTargets<T>,
    T: TermBytes,
{
    fn replay(&mut self, request: &ReplayRequest) -> ReplayStatus<T> {
        let now = (self.clock)();
        let pending = match self.pending.take() {
            Some(pending) if pending.request == *request => pending,
            other => {
                // Another request replaces the one pending.
                if let Some(old) = other {
                    self.withdraw(old);
                }
                let Some(length) = request
                    .to
                    .checked_sub(request.from)
                    .filter(|length| *length > 0)
                else {
                    return ReplayStatus::Unavailable(ReplayUnavailable::Refused);
                };
                let Some(step) = self.list(0, Found::default()) else {
                    return ReplayStatus::Unavailable(ReplayUnavailable::Refused);
                };
                Pending {
                    request: *request,
                    length,
                    since: now,
                    step,
                    behind: false,
                    relist_from: 0,
                }
            }
        };
        match self.advance(pending, now) {
            Outcome::Waiting(pending) => {
                self.pending = Some(pending);
                ReplayStatus::Pending
            }
            Outcome::Done(status) => status,
        }
    }

    fn cancel(&mut self) {
        if let Some(pending) = self.pending.take() {
            self.withdraw(pending);
        }
        self.duty();
    }
}

impl<Q: ControlRequests + 'static, R: ControlResponses, S> Drop for ArchiveClient<Q, R, S> {
    /// Withdraws the request pending and sends what can be sent: a replay
    /// whose answer comes after the drop runs to its end.
    fn drop(&mut self) {
        if let Some(pending) = self.pending.take() {
            self.withdraw(pending);
        }
        self.duty();
    }
}

/// Folds one descriptor of the list into `found`.
fn look_at(descriptor: &RecordingDescriptor<'_>, request: &ReplayRequest, found: &mut Found) {
    if !same_source(descriptor, request) {
        return;
    }
    found.any = true;
    if descriptor.start > request.from {
        return;
    }
    found.in_time = true;
    let id = descriptor.recording_id;
    found.first_in_time = Some(found.first_in_time.map_or(id, |first| first.min(id)));
    let (end, recording) = match descriptor.state {
        RecordingState::Recording { written, .. } => (written, true),
        RecordingState::Stopped(stop) => (stop.position, false),
    };
    if end >= request.to {
        found.covering.get_or_insert(descriptor.recording_id);
    } else if recording {
        found.behind = true;
    }
}

/// Whether `descriptor` is a recording of the publication `request` names.
fn same_source(descriptor: &RecordingDescriptor<'_>, request: &ReplayRequest) -> bool {
    let source = &request.source;
    descriptor.stream_id == source.stream_id
        && descriptor.session_id == source.session_id
        && descriptor.source
            == SourceIncarnation {
                driver: source.driver,
                registration: source.registration,
                incarnation: source.incarnation,
            }
}

/// The replay request's answer.
fn answered<T: TermBytes>(pending: Pending, response: &ControlResponse<'_>) -> Outcome<T> {
    match response.code {
        ResponseCode::Ok => Outcome::Waiting(Pending {
            step: Step::Subscribing {
                replay_id: response.id,
            },
            ..pending
        }),
        // The recording went between the list and the replay.
        ResponseCode::UnknownRecording => {
            Outcome::Done(ReplayStatus::Unavailable(ReplayUnavailable::NoRecording))
        }
        _ => Outcome::Done(ReplayStatus::Unavailable(ReplayUnavailable::Refused)),
    }
}
