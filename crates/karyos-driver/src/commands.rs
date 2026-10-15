// SPDX-License-Identifier: Apache-2.0

//! Client admission and command service of the embedded driver
//! (quantstratum-docs: karyos/design/client-commands.md).
//!
//! The sender of a command is the ring it was read from, never a payload
//! field. Each command is decoded, then checked by a preflight that changes
//! nothing (ownership, stream, limits, identity counters); a refused command
//! gets an `Error` response and has no effect. An accepted command applies
//! its effect and transmits exactly one response, after the duty cycle has
//! verified that the broadcast buffer can take it. A driver that cannot
//! answer enters its terminal state instead.
//!
//! Client counters (`quantstratum-docs:
//! karyos/design/observability-and-tools.md`, "Client counters"):
//! `AllocateCounter` allocates a cell of the client counters region owned by
//! the sending client, keyed to a live stream and to a live participant of
//! that client (each optional), within `max_counters_per_client`.
//! `ReleaseCounter` frees the owner's exact allocation; any other
//! `ReleaseCounter` is a protocol violation, which frees nothing and
//! retires the client as faulty, without a response. A client's remaining
//! cells are freed only when its slot is removed after its close flag.
//!
//! Loss reports (`quantstratum-docs:
//! karyos/design/observability-and-tools.md`, "Loss reports from clients"):
//! `ReportLoss` is attributed to the client whose ring carried it. A report
//! naming another driver instance, a stream registration, incarnation or
//! subscription registration this driver never issued, or a live
//! registration that is not a subscription of the sending client on the
//! named stream, is a protocol violation: nothing is recorded and the
//! client is retired as faulty. A live subscription of the sender gives a
//! verified record; one that has already ended gives a record flagged
//! unverified, counted in `loss reports unverified`. Every record counts
//! once under the policy actually applied (`overruns rejoin at head`,
//! `overruns snapshot` whether the source rebuilt or failed, `overruns
//! close`), and a `replay` fallback also in `replay fallbacks`.
//!
//! Trace journals (`quantstratum-docs:
//! karyos/design/trace-journal-region.md`, J2 and J3; see
//! `trace_journals`): `TraceJournal` reserves a table entry and creates the
//! journal, on the heap for an in-process client (its writer waits in the
//! client's hand-over table) or as a `Journal` region for a remote client
//! (a `Held` grant of stream 0 in its export ledger, fetched like a log
//! buffer, bound by `max_exports_per_client` and the fetch bounds), and
//! answers `JournalReady` with the journal number (a trace number) and a
//! hand-over key taken from the registration counter, so it never names
//! another grant. A journal that names a subscription must name a live
//! subscription of the sender; otherwise it is refused with
//! `UnknownRegistration` before anything is created. The table entry then
//! carries the subscription, its stream and its join position, which the
//! driver recorded when it registered the subscription (the mapping's base
//! plus the cell's position); a publisher-side journal (subscription 0) has
//! none. `CloseJournal` records the boundary of the client's own open
//! journal, once.

use std::sync::Arc;

use karyos_client::ClientConductor;
use karyos_client::link::{
    Capability, ClientLink, HandOverEntry, Lease, LeaseEnd, LeaseState, Owner,
};
use karyos_protocol::cnc::{
    CloseReason, Command, CounterLabel, ErrorCode, Event as DriverEvent, LossPolicyCode,
    MAX_COMMAND_LENGTH, MAX_EVENT_LENGTH, MAX_RESPONSE_LENGTH, RejoinOutcomeCode, ReportedLoss,
    RequestId, Response, StreamKey,
};
use karyos_sys::command_ring::{RingConsumer, command_ring};
use karyos_sys::counters::{CounterKeys, KIND_CLIENT, KIND_PUBLICATION, KIND_SUBSCRIBER};
use karyos_sys::log_buffer::{LossPolicy, PublicationEnd, Revocation, Role, SealState};
use karyos_sys::record_journal::{JournalDrain, JournalLayout};
use karyos_sys::registration;

use crate::client_counters::Refusal;
use crate::counters::Event;
use crate::embedded::{EmbeddedDriver, StreamTerms};
use crate::error::DriverError;
use crate::generations::MemberKind;
use crate::ledger::{Grant, GrantState, Ledger, Participant};

/// A client's registration in the driver.
/// A lost `hold` participant whose bound has not been withdrawn yet.
#[derive(Debug)]
pub(crate) struct Holding {
    stream: u64,
    key: StreamKey,
    cell: usize,
    occupant: u64,
    registration: u64,
    position: u64,
}

#[derive(Debug)]
pub(crate) struct ClientSlot<T: StreamTerms> {
    id: u64,
    /// `None` once the client is retired; the slot itself stays until the
    /// client's producer is known to be detached (its close flag).
    consumer: Option<RingConsumer>,
    link: Arc<ClientLink<T>>,
    /// The client heartbeat last seen and the driver time it was first
    /// seen at; `None` until the first sample.
    seen: Option<(u64, u64)>,
    /// The export ledger of a remote client; `None` for an in-process one
    /// (`quantstratum-docs: karyos/design/ipc-data-path.md`).
    pub(crate) ledger: Option<Ledger>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Publication,
    Subscription,
}

/// A publication or subscription registration.
#[derive(Debug)]
pub(crate) struct Registration {
    id: u64,
    client: u64,
    stream: u64,
    kind: Kind,
    end: Arc<LeaseEnd>,
    /// For a subscription: its cell, its occupant id and its role.
    pub(crate) subscriber: Option<(usize, u64, Role)>,
    /// For a subscription: its join position, the stream position of its
    /// cell when the driver registered it (the mapping's base plus the
    /// cell's position), which a trace journal of it carries
    /// (`quantstratum-docs: karyos/design/trace-journal-region.md`, J3).
    pub(crate) join: Option<u64>,
}

impl<T: StreamTerms> ClientSlot<T> {
    /// The client's id.
    pub(crate) fn id(&self) -> u64 {
        self.id
    }
}

impl Registration {
    /// The stream id this registration belongs to.
    pub(crate) fn stream(&self) -> u64 {
        self.stream
    }
}

impl<T: StreamTerms> EmbeddedDriver<T> {
    /// Admits a client (control path: allocates its command ring and
    /// broadcast receiver) and returns its conductor.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError::TooManyClients`] at `max_clients`,
    /// [`DriverError::ClientIdsExhausted`], and [`DriverError::Terminal`]
    /// after the driver entered its terminal state.
    pub fn connect(&mut self) -> Result<ClientConductor<T>, DriverError> {
        if self.terminal {
            return Err(DriverError::Terminal);
        }
        if self.clients.len() >= self.config.max_clients {
            return Err(DriverError::TooManyClients);
        }
        let (producer, consumer) =
            command_ring(self.config.ring_capacity).map_err(|_| DriverError::InvalidConfig)?;
        let link = Arc::new(ClientLink::new());
        let receiver = self.broadcast.receiver();
        let id = self.admit(consumer, Arc::clone(&link), None)?;
        Ok(ClientConductor::new(
            Owner {
                driver: self.id,
                client: id,
            },
            producer,
            receiver,
            link,
            self.config.max_pending_per_client,
        )
        .with_counters(self.client_counters.cells()))
    }

    /// Registers an admitted client with its ring's consumer and link, and
    /// the export ledger of a remote client; returns its id. The caller
    /// checked the terminal state and `max_clients`.
    pub(crate) fn admit(
        &mut self,
        consumer: RingConsumer,
        link: Arc<ClientLink<T>>,
        ledger: Option<Ledger>,
    ) -> Result<u64, DriverError> {
        let id = self.next_client;
        let next = id.checked_add(1).ok_or(DriverError::ClientIdsExhausted)?;
        self.next_client = next;
        self.counters.add(Event::ClientsAdmitted, 1);
        self.clients.push(ClientSlot {
            id,
            consumer: Some(consumer),
            link,
            seen: None,
            ledger,
        });
        self.update_stream_gauges();
        Ok(id)
    }

    /// Stops serving client `client` (see `retire_faulty`), keeping its
    /// slot until its link is closed.
    #[cfg(target_os = "linux")]
    pub(crate) fn retire_faulty_client(&mut self, client: u64) {
        if let Some(index) = self.clients.iter().position(|slot| slot.id == client) {
            self.retire_faulty(index);
        }
    }

    /// Liveness (quantstratum-docs:
    /// `karyos/design/required-participant-loss.md`): while clients are
    /// admitted, advances the driver heartbeat once per heartbeat interval
    /// and samples each served client's heartbeat. A client whose
    /// heartbeat has not changed for the liveness timeout of driver time is
    /// timed out: it is no longer served and its ring is closed, as for a
    /// faulty client. Timing out is not a detach proof: its slot stays until
    /// its close flag, `Leave` or exit proof. The clock is read only while a
    /// client is admitted. Returns the clients timed out.
    pub(crate) fn serve_liveness(&mut self) -> u32 {
        if self.clients.is_empty() {
            return 0;
        }
        let now = self.clock.now();
        let due = self
            .last_beat
            .is_none_or(|last| now.saturating_sub(last) >= self.config.heartbeat_interval);
        if due {
            // A closed broadcast buffer stays closed; nothing to advance.
            let _ = self.broadcast.beat();
            self.last_beat = Some(now);
        }
        let timeout = self.config.client_liveness_timeout;
        let mut late = Vec::new();
        for (index, slot) in self.clients.iter_mut().enumerate() {
            // A client that closed since retirement ran is retired on the
            // next cycle, not timed out.
            if slot.link.is_closed() {
                continue;
            }
            let Some(consumer) = slot.consumer.as_ref() else {
                continue;
            };
            let beat = consumer.heartbeat();
            match slot.seen {
                Some((seen, since)) if seen == beat => {
                    if now.saturating_sub(since) >= timeout {
                        late.push(index);
                    }
                }
                _ => slot.seen = Some((beat, now)),
            }
        }
        let timed_out = u32::try_from(late.len()).unwrap_or(u32::MAX);
        for index in late {
            if let Some(client) = self.clients.get(index).map(|slot| slot.id) {
                self.revoke_client(client);
            }
            self.stop_serving(index, Event::ClientsTimedOut);
        }
        timed_out
    }

    /// Hands every subscriber of a lost client to its stream's loss policy
    /// (quantstratum-docs: `karyos/design/required-participant-loss.md`):
    /// each cell is revoked as its occupant, so a cell that changed hands
    /// is left alone.
    fn revoke_client(&mut self, client: u64) {
        let lost: Vec<(u64, u64, usize, u64, Role)> = self
            .registrations
            .iter()
            .filter(|registration| registration.client == client)
            .filter_map(|registration| {
                registration.subscriber.map(|(cell, occupant, role)| {
                    (registration.id, registration.stream, cell, occupant, role)
                })
            })
            .collect();
        for (registration, stream, cell, occupant, role) in lost {
            let Some(target) = self.streams.iter_mut().find(|s| s.id == stream) else {
                continue;
            };
            let policy = target.policy;
            let key = StreamKey {
                stream_id: target.stream_id,
                session_id: target.session_id,
            };
            let position = target.conductor.cell_position(cell).unwrap_or(0);
            // Sealing is idempotent: only the revocation that moves the
            // stream out of `Active` reports its closing.
            let was_active = target.conductor.seal_state() == SealState::Active;
            let revocation = target.conductor.revoke_participant(cell, occupant, policy);
            let revocation = match revocation {
                Ok(Revocation::Stale) | Err(_) => continue,
                Ok(revocation) => revocation,
            };
            self.counters.add(Event::ParticipantsRevoked, 1);
            if role != Role::Required {
                continue;
            }
            self.counters.add(Event::RequiredParticipantsLost, 1);
            let [high, low] = self.driver_id;
            let loss = karyos_sys::diag::LossRecord {
                kind: crate::diagnostics::LossKind::RequiredParticipantLost as u16,
                configured_policy: crate::diagnostics::policy_code(policy),
                applied_policy: crate::diagnostics::policy_code(policy),
                instance: u128::from(high) << 64 | u128::from(low),
                stream_registration: stream,
                incarnation: crate::embedded::FIRST_INCARNATION,
                stream_id: u64::from(key.stream_id.cast_unsigned()),
                from: position,
                to: position,
                participant: registration,
                client,
                ..karyos_sys::diag::LossRecord::default()
            };
            self.diagnostics.loss(&mut self.counters, loss);
            if matches!(revocation, Revocation::Sealed) && was_active {
                // The `abort` policy sealed the incarnation at `position`.
                let aborted = karyos_sys::diag::LossRecord {
                    kind: crate::diagnostics::LossKind::AbortedIncarnation as u16,
                    ..loss
                };
                self.diagnostics.loss(&mut self.counters, aborted);
            }
            self.emit(&DriverEvent::ParticipantLost {
                stream: key,
                registration,
                client,
                policy: match policy {
                    LossPolicy::Hold => LossPolicyCode::Hold,
                    LossPolicy::Continue => LossPolicyCode::Continue,
                    LossPolicy::Abort => LossPolicyCode::Abort,
                },
                position,
            });
            match revocation {
                Revocation::Holding => self.holding.push(Holding {
                    stream,
                    key,
                    cell,
                    occupant,
                    registration,
                    position,
                }),
                Revocation::Withdrawn if policy == LossPolicy::Hold => {
                    self.emit(&DriverEvent::RequiredBoundWithdrawn {
                        stream: key,
                        registration,
                        position,
                    });
                }
                Revocation::Sealed if was_active => self.emit(&DriverEvent::PublicationClosed {
                    stream: key,
                    reason: CloseReason::RequiredParticipantLost,
                }),
                _ => {}
            }
        }
    }

    /// Reports every lost `hold` participant whose bound a duty cycle's
    /// rescan withdrew (or whose cell was freed by its detach).
    pub(crate) fn report_withdrawn_bounds(&mut self) {
        let mut index = 0;
        while let Some(entry) = self.holding.get(index) {
            let still = self
                .streams
                .iter()
                .find(|s| s.id == entry.stream)
                .is_some_and(|s| s.conductor.holding(entry.cell, entry.occupant));
            if still {
                index += 1;
                continue;
            }
            let entry = self.holding.swap_remove(index);
            self.emit(&DriverEvent::RequiredBoundWithdrawn {
                stream: entry.key,
                registration: entry.registration,
                position: entry.position,
            });
        }
    }

    /// Transmits a driver event when the broadcast buffer has room for it;
    /// otherwise counts it as not sent. Events are best effort: the
    /// counters record every loss either way.
    pub(crate) fn emit(&mut self, event: &DriverEvent) {
        let mut out = [0u8; MAX_EVENT_LENGTH];
        let sent = event
            .encode(&mut out)
            .ok()
            .and_then(|length| out.get(..length))
            .filter(|payload| self.broadcast.has_room(payload.len()))
            .map(|payload| self.broadcast.transmit(event.type_id(), payload));
        if !matches!(sent, Some(Ok(_))) {
            self.counters.add(Event::EventsNotSent, 1);
        }
    }

    /// Clients currently admitted, including retired ones whose producer has
    /// not yet detached.
    #[must_use]
    pub fn clients(&self) -> usize {
        self.clients.len()
    }

    /// Releases every client whose close flag is set: its ring, its
    /// admission slot, its untaken hand-over entries, its registrations and
    /// its client counter cells (those of an in-process client once its
    /// last counter handle is gone). Handles it still holds keep their
    /// leases.
    pub(crate) fn retire_closed_clients(&mut self) {
        self.client_counters.free_orphans();
        let mut index = 0;
        while let Some(slot) = self.clients.get(index) {
            if slot.link.is_closed() {
                let mut slot = self.clients.swap_remove(index);
                self.counters.add(Event::ClientsRetired, 1);
                slot.link.drop_all(false);
                self.registrations
                    .retain(|registration| registration.client != slot.id);
                // The close flag is the exit proof (or Leave) of a remote
                // client, and the conductor's drop of an in-process one.
                self.client_counters
                    .client_removed(slot.id, slot.link.counter_releases());
                // The close flag of a remote client is its exit proof (or
                // its Leave): every grant it holds ends, sent or not.
                if let Some(ledger) = slot.ledger.take() {
                    for grant in ledger.into_grants() {
                        self.end_grant(&grant);
                    }
                }
            } else {
                index += 1;
            }
        }
    }

    /// Stops serving a faulty client: discards its ring and untaken
    /// hand-over entries and its registrations, but keeps its admission slot
    /// until its producer is known to be detached.
    fn retire_faulty(&mut self, index: usize) {
        self.stop_serving(index, Event::ClientsFaulty);
    }

    /// Stops serving client `index`, counting `reason` once: closes and
    /// discards its ring, drops its untaken hand-over entries and forgets
    /// its registrations. The slot stays until the client's close flag.
    fn stop_serving(&mut self, index: usize, reason: Event) {
        if let Some(slot) = self.clients.get_mut(index) {
            if slot.consumer.is_some() {
                self.counters.add(reason, 1);
            }
            // Publish the closure to the producer before discarding the
            // consumer.
            if let Some(mut consumer) = slot.consumer.take() {
                consumer.close();
            }
            slot.link.drop_all(false);
            let client = slot.id;
            // A grant never sent reached no one: it ends at once. Sent ones
            // stay charged until the exit proof.
            let unsent = slot
                .ledger
                .as_mut()
                .map(Ledger::take_unsent)
                .unwrap_or_default();
            self.registrations
                .retain(|registration| registration.client != client);
            for grant in unsent {
                self.end_grant(&grant);
            }
        }
    }

    /// Forgets registrations whose capability was dropped without
    /// `remove`, so dropping handles cannot accumulate registration
    /// records. A registration whose handle was dropped by `remove` stays
    /// until its queued `Remove` is served (or its client is retired).
    pub(crate) fn sweep_ended_registrations(&mut self) {
        let before = self.registrations.len();
        self.registrations
            .retain(|registration| registration.end.state() != LeaseState::Dropped);
        let swept = before - self.registrations.len();
        if swept > 0 {
            self.counters.add(
                Event::RegistrationsSwept,
                u64::try_from(swept).unwrap_or(u64::MAX),
            );
        }
    }

    pub(crate) fn enter_terminal(&mut self) {
        self.terminal = true;
        self.counters.set(Event::Terminal, 1);
        self.broadcast.close();
    }

    /// Serves up to `command_budget` commands, at most one per ring per
    /// visit, from the persistent scan cursor. Returns commands served.
    pub(crate) fn serve_commands(&mut self) -> u32 {
        let mut served = 0u32;
        let rings = self.clients.len();
        let budget = self.config.command_budget;
        let mut visits = 0;
        while !self.terminal && visits < rings && (served as usize) < budget {
            if !self.broadcast.has_room(MAX_RESPONSE_LENGTH) {
                self.enter_terminal();
                break;
            }
            let index = self.scan_cursor % rings;
            self.scan_cursor = (index + 1) % rings;
            visits += 1;
            let Some(slot) = self.clients.get_mut(index) else {
                continue;
            };
            let Some(consumer) = slot.consumer.as_mut() else {
                continue;
            };
            let client = slot.id;
            let link = Arc::clone(&slot.link);
            let mut bytes = [0u8; MAX_COMMAND_LENGTH];
            let copied = match consumer.read() {
                Ok(None) => continue,
                Ok(Some(message)) => {
                    let length = message.payload.len();
                    bytes.get_mut(..length).map(|target| {
                        target.copy_from_slice(message.payload);
                        (message.type_id, length)
                    })
                }
                Err(_) => None,
            };
            let decoded = copied.and_then(|(type_id, length)| {
                Command::decode(type_id, bytes.get(..length).unwrap_or(&[])).ok()
            });
            served += 1;
            let Some(command) = decoded else {
                // Malformed: no response, the client is faulty.
                self.diagnostics.error(
                    &mut self.counters,
                    crate::diagnostics::ErrorCode::ClientProtocolViolation,
                    [client, copied.map_or(0, |(type_id, _)| u64::from(type_id))],
                    "malformed command; the client is retired",
                );
                self.retire_faulty(index);
                continue;
            };
            self.counters.add(Event::CommandsServed, 1);
            let response = match self.serve(client, &link, command) {
                Ok(response) => response,
                Err(violation) => {
                    // A protocol violation: no response, the client is
                    // faulty.
                    self.diagnostics.error(
                        &mut self.counters,
                        crate::diagnostics::ErrorCode::ClientProtocolViolation,
                        [client, u64::from(command.type_id())],
                        violation,
                    );
                    self.retire_faulty(index);
                    continue;
                }
            };
            if matches!(response, Response::Error { .. }) {
                self.counters.add(Event::CommandsRefused, 1);
            }
            let mut out = [0u8; MAX_RESPONSE_LENGTH];
            let sent = response
                .encode(&mut out)
                .ok()
                .and_then(|length| out.get(..length))
                .map(|payload| self.broadcast.transmit(response.type_id(), payload));
            if matches!(sent, Some(Ok(_))) {
                self.counters.add(Event::ResponsesSent, 1);
            } else {
                // A broken invariant after the room check.
                self.enter_terminal();
            }
        }
        served
    }

    fn find_stream(&self, stream: StreamKey) -> Option<usize> {
        // Commands bind by wire key at execution; retiring streams accept
        // nothing new.
        self.streams.iter().position(|s| {
            !s.retiring && s.stream_id == stream.stream_id && s.session_id == stream.session_id
        })
    }

    pub(crate) fn held_total(&self) -> usize {
        self.clients.iter().map(|slot| slot.link.held()).sum()
    }

    /// Serves one decoded command: its single response, or, for a
    /// protocol violation, which has no effect, the error log's message.
    fn serve(
        &mut self,
        client: u64,
        link: &Arc<ClientLink<T>>,
        command: Command,
    ) -> Result<Response, &'static str> {
        match command {
            Command::ReleaseCounter {
                sequence,
                cell,
                registration,
            } => {
                // Only the owner's release of its exact allocation: anything
                // else frees nothing and is a protocol violation.
                if self.client_counters.release(client, cell, registration) {
                    Ok(Response::OperationSucceeded {
                        request: RequestId { client, sequence },
                    })
                } else {
                    Err("release of a counter the client does not own; the client is retired")
                }
            }
            Command::ReportLoss { sequence, loss } => {
                self.report_loss(client, &loss)?;
                Ok(Response::OperationSucceeded {
                    request: RequestId { client, sequence },
                })
            }
            _ => Ok(self.execute(client, link, command)),
        }
    }

    /// Serves `ReportLoss` from `client` (see the module documentation):
    /// appends the loss record and counts the overrun, or returns the
    /// violation's message and records nothing.
    fn report_loss(&mut self, client: u64, loss: &ReportedLoss) -> Result<(), &'static str> {
        if loss.driver != self.driver_id {
            return Err("loss report of another driver instance; the client is retired");
        }
        let issued = |id: u64, next: u64| id != 0 && id < next;
        if !issued(loss.stream_registration, self.next_stream)
            || loss.incarnation != crate::embedded::FIRST_INCARNATION
            || !issued(loss.subscription, self.next_registration)
        {
            return Err("loss report of an identity never issued; the client is retired");
        }
        let verified = match self
            .registrations
            .iter()
            .find(|r| r.id == loss.subscription)
        {
            Some(live)
                if live.client == client
                    && live.kind == Kind::Subscription
                    && live.stream == loss.stream_registration =>
            {
                true
            }
            Some(_) => {
                return Err(
                    "loss report of a registration that is not the client's subscription on that stream; the client is retired",
                );
            }
            // Ended: its owner can no longer be checked.
            None => false,
        };
        let stream_id = self
            .streams
            .iter()
            .find(|s| s.id == loss.stream_registration)
            .map_or(0, |s| u64::from(s.stream_id.cast_unsigned()));
        let [high, low] = loss.driver;
        self.diagnostics.loss(
            &mut self.counters,
            karyos_sys::diag::LossRecord {
                kind: crate::diagnostics::LossKind::Overrun as u16,
                reason: loss.fallback.map_or(0, |reason| u16::from(reason as u8)),
                lane: loss.lane,
                configured_policy: loss.configured as u8,
                applied_policy: loss.applied as u8,
                flags: if verified {
                    0
                } else {
                    crate::diagnostics::LOSS_UNVERIFIED
                },
                instance: u128::from(high) << 64 | u128::from(low),
                stream_registration: loss.stream_registration,
                incarnation: loss.incarnation,
                stream_id,
                from: loss.from,
                to: loss.to,
                participant: loss.subscription,
                client,
                ..karyos_sys::diag::LossRecord::default()
            },
        );
        if !verified {
            self.counters.add(Event::LossReportsUnverified, 1);
        }
        self.counters.add(
            match loss.applied {
                RejoinOutcomeCode::ResumedAtHead => Event::OverrunsRejoinAtHead,
                RejoinOutcomeCode::SnapshotRebuilt | RejoinOutcomeCode::SnapshotFailed => {
                    Event::OverrunsSnapshot
                }
                RejoinOutcomeCode::Closed => Event::OverrunsClose,
            },
            1,
        );
        // Only a replay that fell back: once replay can succeed (phase 3)
        // it reports no fallback reason and is not counted here.
        if loss.fallback.is_some() {
            self.counters.add(Event::ReplayFallbacks, 1);
        }
        Ok(())
    }

    /// Preflight, then effect. Returns the single response.
    fn execute(&mut self, client: u64, link: &Arc<ClientLink<T>>, command: Command) -> Response {
        let request = RequestId {
            client,
            sequence: command.sequence(),
        };
        let refuse = |code: ErrorCode, detail: u64| Response::Error {
            request,
            code,
            detail,
        };
        match command {
            Command::AddPublication { stream, .. }
            | Command::AddConcurrentPublication { stream, .. }
            | Command::AddSubscription { stream, .. } => {
                let detail = u64::from(stream.stream_id.cast_unsigned());
                let Some(index) = self.find_stream(stream) else {
                    return refuse(ErrorCode::UnknownStream, detail);
                };
                let remote = self.ledger(client).map(Ledger::full);
                match remote {
                    // The export bound refuses before anything is reserved.
                    Some(true) => return refuse(ErrorCode::ResourcesUnavailable, detail),
                    Some(false) => return self.add_remote(client, index, command, request),
                    None => {}
                }
                if link.held() >= self.config.max_pending_per_client
                    || self.held_total() >= self.config.max_hand_over
                {
                    return refuse(ErrorCode::ResourcesUnavailable, detail);
                }
                let registration = self.next_registration;
                let Some(next) = registration.checked_add(1) else {
                    return refuse(ErrorCode::IdentitiesExhausted, 0);
                };
                let Some(target) = self.streams.get_mut(index) else {
                    return refuse(ErrorCode::UnknownStream, detail);
                };
                // New handles wait for a pending cutover's successor
                // (quantstratum-docs: karyos/design/mapping-generations.md).
                if target.issuing().is_err() {
                    return refuse(ErrorCode::ResourcesUnavailable, detail);
                }
                let occupant = self.next_export;
                let mut subscriber = None;
                let mut occupant_used = None;
                let (capability, kind) = match command {
                    Command::AddPublication {
                        allow_unconnected, ..
                    } => match target.spare.take() {
                        Some(inner) => (
                            Capability::Publication {
                                inner,
                                allow_unconnected,
                            },
                            Kind::Publication,
                        ),
                        None => match target.buffer.publication_owned() {
                            Ok(Some(inner)) => (
                                Capability::Publication {
                                    inner,
                                    allow_unconnected,
                                },
                                Kind::Publication,
                            ),
                            Ok(None) => return refuse(ErrorCode::PublicationTaken, detail),
                            Err(error) => return refuse(issue_refusal(&error), detail),
                        },
                    },
                    Command::AddConcurrentPublication {
                        allow_unconnected, ..
                    } => match target.conductor.concurrent_publication() {
                        Ok(Some(inner)) => (
                            Capability::ConcurrentPublication {
                                inner,
                                allow_unconnected,
                            },
                            Kind::Publication,
                        ),
                        Ok(None) => return refuse(ErrorCode::PublicationTaken, detail),
                        Err(error) => return refuse(issue_refusal(&error), detail),
                    },
                    _ => {
                        let role = subscription_role(command);
                        // A required reader of a `continue` stream reserves
                        // its slots like an optional one.
                        let reserve =
                            role == Role::Required && target.policy == LossPolicy::Continue;
                        let Some(next_occupant) = occupant.checked_add(1) else {
                            return refuse(ErrorCode::IdentitiesExhausted, 0);
                        };
                        match target.conductor.subscribe_as(role, reserve, occupant) {
                            Ok(inner) => {
                                subscriber = Some((inner.cell(), occupant, role));
                                occupant_used = Some(next_occupant);
                                (Capability::Subscription(inner), Kind::Subscription)
                            }
                            Err(_) => return refuse(ErrorCode::ResourcesUnavailable, detail),
                        }
                    }
                };
                // Recorded by the driver, never taken from the client.
                let join = subscriber.and_then(|(cell, _, _)| {
                    target
                        .conductor
                        .cell_position(cell)
                        .map(|position| target.base.saturating_add(position))
                });
                // Effect: everything below cannot fail.
                let member = match &capability {
                    Capability::Publication { .. } => MemberKind::Exclusive,
                    Capability::ConcurrentPublication { .. } => MemberKind::Concurrent,
                    Capability::Subscription(inner) => MemberKind::Subscriber {
                        role: subscription_role(command),
                        cell: inner.cell(),
                    },
                };
                let generation = Some(target.join(member));
                let publication = karyos_protocol::trace_hook::PublicationIdentity {
                    driver: self.driver_id,
                    registration: target.id,
                    stream_id: target.stream_id,
                    session_id: target.session_id,
                    incarnation: crate::embedded::FIRST_INCARNATION,
                };
                let end = Arc::new(LeaseEnd::default());
                let lease = Lease::acquire(&target.leases, &end);
                self.next_registration = next;
                link.hold(HandOverEntry {
                    key: registration,
                    capability,
                    lease,
                    generation,
                    publication: Some(publication),
                });
                let stream_id = target.id;
                if let Some(next) = occupant_used {
                    self.next_export = next;
                }
                self.registrations.push(Registration {
                    id: registration,
                    client,
                    stream: stream_id,
                    kind,
                    end,
                    subscriber,
                    join,
                });
                match kind {
                    Kind::Publication => Response::PublicationReady {
                        request,
                        registration,
                        key: registration,
                    },
                    Kind::Subscription => Response::SubscriptionReady {
                        request,
                        registration,
                        key: registration,
                    },
                }
            }
            Command::RemovePublication { registration, .. }
            | Command::RemoveSubscription { registration, .. } => {
                let kind = if matches!(command, Command::RemovePublication { .. }) {
                    Kind::Publication
                } else {
                    Kind::Subscription
                };
                let Some(index) = self
                    .registrations
                    .iter()
                    .position(|r| r.id == registration && r.client == client && r.kind == kind)
                else {
                    return refuse(ErrorCode::UnknownRegistration, registration);
                };
                self.registrations.swap_remove(index);
                // Drops a capability still held; a taken one was dropped by
                // the client's remove.
                link.drop_entry(registration);
                self.remove_remote(client, registration);
                Response::OperationSucceeded { request }
            }
            Command::AllocateCounter {
                type_id,
                label,
                stream,
                participant,
                ..
            } => self.allocate_counter(client, request, type_id, label, stream, participant),
            // Served by `serve`, which never passes them here.
            Command::ReleaseCounter { registration, .. } => {
                refuse(ErrorCode::UnknownRegistration, registration)
            }
            Command::ReportLoss { loss, .. } => {
                refuse(ErrorCode::UnknownRegistration, loss.subscription)
            }
            Command::TraceJournal {
                capacity,
                payload_words,
                drop_ranges,
                subscription,
                ..
            } => self.trace_journal(
                client,
                link,
                request,
                JournalRequest {
                    capacity,
                    payload_words,
                    drop_ranges,
                    subscription,
                },
            ),
            Command::CloseJournal {
                journal, boundary, ..
            } => {
                if self.trace_journals.close(client, journal, boundary) {
                    Response::OperationSucceeded { request }
                } else {
                    refuse(ErrorCode::UnknownRegistration, journal)
                }
            }
        }
    }

    /// Serves `TraceJournal` (see the module documentation): every check
    /// first (the observed subscription, sizes, bytes budget, a free table
    /// entry, identities, the export bounds and the region of a remote
    /// client), then the effects, which cannot fail.
    fn trace_journal(
        &mut self,
        client: u64,
        link: &Arc<ClientLink<T>>,
        request: RequestId,
        asked: JournalRequest,
    ) -> Response {
        let refuse = |code: ErrorCode| Response::Error {
            request,
            code,
            detail: 0,
        };
        let JournalRequest {
            capacity,
            payload_words,
            drop_ranges,
            subscription,
        } = asked;
        // A nonzero subscription must be a live subscription of the
        // sender; its stream and join position are the driver's record.
        let observed = if subscription == 0 {
            None
        } else {
            let live = self.registrations.iter().find(|registration| {
                registration.id == subscription
                    && registration.client == client
                    && registration.kind == Kind::Subscription
                    && registration.end.state() == LeaseState::Alive
            });
            match live {
                Some(registration) => Some((subscription, registration.stream, registration.join)),
                None => {
                    return Response::Error {
                        request,
                        code: ErrorCode::UnknownRegistration,
                        detail: subscription,
                    };
                }
            }
        };
        let (Ok(capacity), Ok(payload_words), Ok(drop_ranges)) = (
            usize::try_from(capacity),
            usize::try_from(payload_words),
            usize::try_from(drop_ranges),
        ) else {
            return refuse(ErrorCode::ResourcesUnavailable);
        };
        let layout = JournalLayout {
            capacity,
            payload_words,
            drop_ranges,
        };
        let (index, bytes) = match self.trace_journals.preflight(&layout) {
            Ok(found) => found,
            Err(crate::trace_journals::Refusal::Exhausted) => {
                return refuse(ErrorCode::TraceJournalsExhausted);
            }
            Err(crate::trace_journals::Refusal::Resources) => {
                return refuse(ErrorCode::ResourcesUnavailable);
            }
        };
        let key = self.next_registration;
        let journal = self.next_trace_number;
        let (Some(next_key), Some(next_journal)) = (key.checked_add(1), journal.checked_add(1))
        else {
            return refuse(ErrorCode::IdentitiesExhausted);
        };
        let drain = match self
            .ledger(client)
            .map(|ledger| (ledger.full(), ledger.fetchable(1, bytes)))
        {
            // A remote client: a region and a `Held` grant.
            Some((false, true)) => {
                let export = self.next_export;
                if !registration::valid_export(export) {
                    return refuse(ErrorCode::IdentitiesExhausted);
                }
                let Some(drain) = self.journal_region(layout) else {
                    return refuse(ErrorCode::ResourcesUnavailable);
                };
                // Effect: everything below cannot fail.
                self.next_export = export + 1;
                if let Some(ledger) = self.ledger_mut(client) {
                    ledger.push(Grant {
                        export,
                        registration: journal,
                        key,
                        stream: 0,
                        participant: Participant::Journal { journal },
                        state: GrantState::Held,
                        sent: false,
                        generation: 0,
                        fence_at: None,
                        fenced: false,
                    });
                }
                self.counters.add(Event::GrantsReserved, 1);
                drain
            }
            // Beyond the export bound, or a region no fetch could carry.
            Some(_) => return refuse(ErrorCode::ResourcesUnavailable),
            // An in-process client: a heap journal, its writer held.
            None => {
                let Ok((writer, drain)) = karyos_sys::record_journal::journal_block(layout) else {
                    return refuse(ErrorCode::ResourcesUnavailable);
                };
                link.hold_journal(key, writer);
                drain
            }
        };
        self.next_registration = next_key;
        self.next_trace_number = next_journal;
        self.trace_journals
            .insert(index, journal, client, observed, drain, bytes);
        Response::JournalReady {
            request,
            journal,
            key,
        }
    }

    /// A journal region for a remote client; `None` when it cannot be
    /// created.
    #[cfg(target_os = "linux")]
    fn journal_region(&mut self, layout: JournalLayout) -> Option<JournalDrain> {
        let (instance, region) = self.admission.as_mut()?.next_region().ok()?;
        karyos_sys::record_journal::journal_region(instance, region, layout).ok()
    }

    /// Remote clients exist only on Linux.
    #[cfg(not(target_os = "linux"))]
    #[allow(
        clippy::unused_self,
        reason = "the Linux version creates the region through the admission"
    )]
    fn journal_region(&mut self, _layout: JournalLayout) -> Option<JournalDrain> {
        None
    }

    /// Serves `AllocateCounter` (`quantstratum-docs:
    /// karyos/design/observability-and-tools.md`, "Client counters"): a
    /// nonzero `stream` must be a live, not retiring, stream registration
    /// and a nonzero `participant` a live registration of this client, on
    /// that stream when both are given; otherwise the answer is an `Error`
    /// and nothing is allocated. `key0` is the stream, `key1` the
    /// participant's lane and kind (kind client when there is none) and
    /// `key2` the participant or the client.
    fn allocate_counter(
        &mut self,
        client: u64,
        request: RequestId,
        type_id: u64,
        label: CounterLabel,
        stream: u64,
        participant: u64,
    ) -> Response {
        let refuse = |code: ErrorCode, detail: u64| Response::Error {
            request,
            code,
            detail,
        };
        if stream != 0 && !self.streams.iter().any(|s| s.id == stream && !s.retiring) {
            return refuse(ErrorCode::UnknownStream, stream);
        }
        let keys = if participant == 0 {
            CounterKeys {
                stream,
                lane: 0,
                kind: KIND_CLIENT,
                participant: client,
            }
        } else {
            let Some(found) = self
                .registrations
                .iter()
                .find(|r| r.id == participant && r.client == client)
                .filter(|r| stream == 0 || r.stream == stream)
            else {
                return refuse(ErrorCode::UnknownRegistration, participant);
            };
            let lane = self
                .streams
                .iter()
                .find(|s| s.id == found.stream)
                .map_or(0, |s| s.config.lane.get());
            CounterKeys {
                stream,
                lane,
                kind: match found.kind {
                    Kind::Subscription => KIND_SUBSCRIBER,
                    Kind::Publication => KIND_PUBLICATION,
                },
                participant,
            }
        };
        match self
            .client_counters
            .allocate(client, type_id, label.as_str(), keys)
        {
            Ok((cell, registration)) => Response::CounterAllocated {
                request,
                cell: cell as u64,
                registration,
            },
            Err(refusal) => {
                // Keyed by client and reason: repeats update one record.
                let (reason, message) = match refusal {
                    Refusal::ClientLimit => (1, "client counter limit reached"),
                    Refusal::Exhausted => (2, "no free client counter cell"),
                    Refusal::IdentitiesExhausted => (3, "counter identities exhausted"),
                };
                self.diagnostics.error(
                    &mut self.counters,
                    crate::diagnostics::ErrorCode::CounterAllocationRefused,
                    [client, reason],
                    message,
                );
                match refusal {
                    Refusal::ClientLimit => refuse(ErrorCode::ResourcesUnavailable, 0),
                    Refusal::Exhausted => {
                        self.counters.add(Event::CountersUnavailable, 1);
                        refuse(ErrorCode::ResourcesUnavailable, 0)
                    }
                    Refusal::IdentitiesExhausted => refuse(ErrorCode::IdentitiesExhausted, 0),
                }
            }
        }
    }
}

impl<T: StreamTerms> EmbeddedDriver<T> {
    /// A remote client's `Add*` (`quantstratum-docs:
    /// karyos/design/ipc-data-path.md`, Grants and the export ledger, step
    /// 1): reserves the participant in the buffer under the next export id,
    /// stored in its registration word before anything is sent, records
    /// the grant `Held` and answers with its key. No in-process capability
    /// is created.
    fn add_remote(
        &mut self,
        client: u64,
        index: usize,
        command: Command,
        request: RequestId,
    ) -> Response {
        let refuse = |code: ErrorCode, detail: u64| Response::Error {
            request,
            code,
            detail,
        };
        let registration = self.next_registration;
        let Some(next) = registration.checked_add(1) else {
            return refuse(ErrorCode::IdentitiesExhausted, 0);
        };
        let export = self.next_export;
        // Export ids stop below the adoption and fence marks; they never
        // wrap.
        if !registration::valid_export(export) {
            return refuse(ErrorCode::IdentitiesExhausted, 0);
        }
        let Some(target) = self.streams.get_mut(index) else {
            return refuse(ErrorCode::UnknownStream, 0);
        };
        let detail = u64::from(target.stream_id.cast_unsigned());
        if target.issuing().is_err() {
            return refuse(ErrorCode::ResourcesUnavailable, detail);
        }
        // A grant no fetch could carry is refused rather than handed a key
        // (one log buffer region per grant: one lane).
        let bytes = fetch_bytes(&target.buffer);
        let fetchable = self
            .clients
            .iter()
            .find(|slot| slot.id == client)
            .and_then(|slot| slot.ledger.as_ref())
            .is_some_and(|ledger| ledger.fetchable(1, bytes));
        if !fetchable {
            return refuse(ErrorCode::ResourcesUnavailable, detail);
        }
        let Some(target) = self.streams.get_mut(index) else {
            return refuse(ErrorCode::UnknownStream, 0);
        };
        let participant = match command {
            Command::AddPublication { .. } => {
                // A spare publication is the driver's own issuance.
                if target.spare.is_some() {
                    return refuse(ErrorCode::PublicationTaken, detail);
                }
                match target.conductor.register_publication(export) {
                    Ok(true) => Participant::Exclusive,
                    Ok(false) => return refuse(ErrorCode::PublicationTaken, detail),
                    Err(error) => return refuse(issue_refusal(&error), detail),
                }
            }
            Command::AddConcurrentPublication { .. } => {
                match target.conductor.register_concurrent_publication(export) {
                    Ok(Some(slot)) => Participant::Concurrent { slot },
                    Ok(None) => return refuse(ErrorCode::PublicationTaken, detail),
                    Err(error) => return refuse(issue_refusal(&error), detail),
                }
            }
            _ => {
                let role = subscription_role(command);
                let reserve = role == Role::Required && target.policy == LossPolicy::Continue;
                match target
                    .conductor
                    .register_subscriber_with(role, reserve, export)
                {
                    Ok(cell) => Participant::Subscriber { cell, role },
                    Err(_) => return refuse(ErrorCode::ResourcesUnavailable, detail),
                }
            }
        };
        // Recorded by the driver, never taken from the client.
        let join = match participant {
            Participant::Subscriber { cell, .. } => target
                .conductor
                .cell_position(cell)
                .map(|position| target.base.saturating_add(position)),
            _ => None,
        };
        // Effect: everything below cannot fail.
        let stream = target.id;
        let generation = target.generation.get();
        self.next_registration = next;
        self.next_export = export + 1;
        if let Some(ledger) = self.ledger_mut(client) {
            ledger.push(Grant {
                export,
                registration,
                key: registration,
                stream,
                participant,
                state: GrantState::Held,
                sent: false,
                generation,
                fence_at: None,
                fenced: false,
            });
        }
        let (kind, subscriber) = match participant {
            Participant::Subscriber { cell, role } => {
                (Kind::Subscription, Some((cell, export, role)))
            }
            // Never built here: a journal grant comes from `TraceJournal`.
            Participant::Exclusive
            | Participant::Concurrent { .. }
            | Participant::Journal { .. } => (Kind::Publication, None),
        };
        self.registrations.push(Registration {
            id: registration,
            client,
            stream,
            kind,
            // A remote registration has no in-process lease: it ends with
            // its grant.
            end: Arc::new(LeaseEnd::default()),
            subscriber,
            join,
        });
        self.counters.add(Event::GrantsReserved, 1);
        match kind {
            Kind::Publication => Response::PublicationReady {
                request,
                registration,
                key: registration,
            },
            Kind::Subscription => Response::SubscriptionReady {
                request,
                registration,
                key: registration,
            },
        }
    }

    /// The export ledger of remote client `client`.
    pub(crate) fn ledger(&self, client: u64) -> Option<&Ledger> {
        self.clients
            .iter()
            .find(|slot| slot.id == client)
            .and_then(|slot| slot.ledger.as_ref())
    }

    /// The export ledger of remote client `client`, to change.
    pub(crate) fn ledger_mut(&mut self, client: u64) -> Option<&mut Ledger> {
        self.clients
            .iter_mut()
            .find(|slot| slot.id == client)
            .and_then(|slot| slot.ledger.as_mut())
    }

    /// A remote client's `Remove*` of `registration`: a grant never sent is
    /// ended at once, its participant released in the buffer; a sent one
    /// stays charged until its `Detach` or the client's exit proof.
    fn remove_remote(&mut self, client: u64, registration: u64) {
        let Some(ledger) = self.ledger_mut(client) else {
            return;
        };
        for grant in ledger.take_unsent_of(registration) {
            self.end_grant(&grant);
        }
    }

    /// Ends `grant`'s registration in its stream's buffer. The caller holds
    /// the proof that no access follows: the grant was never sent, or its
    /// `Detach` or the client's exit proof arrived.
    pub(crate) fn end_grant(&mut self, grant: &Grant) {
        // A journal grant names no stream: its writer is gone.
        if let Participant::Journal { journal } = grant.participant {
            self.trace_journals
                .writer_gone(journal, &mut self.diagnostics, &mut self.counters);
            self.counters.add(Event::GrantsEnded, 1);
            return;
        }
        let Some(stream) = self.streams.iter_mut().find(|s| s.id == grant.stream) else {
            return;
        };
        // The grant's own generation: the current mapping or a retained
        // predecessor.
        let conductor = if stream.generation.get() == grant.generation {
            &mut stream.conductor
        } else if let Some(retained) = stream
            .retained
            .iter_mut()
            .find(|retained| retained.generation.get() == grant.generation)
        {
            &mut retained.conductor
        } else {
            return;
        };
        let ended = match grant.participant {
            Participant::Subscriber { cell, .. } => conductor.end_subscriber(cell, grant.export),
            Participant::Exclusive => conductor
                .end_publication(grant.export)
                .is_ok_and(|end| end != PublicationEnd::Stale),
            Participant::Concurrent { slot } => conductor
                .end_concurrent_publication(slot, grant.export)
                .unwrap_or(false),
            Participant::Journal { .. } => false,
        };
        if ended {
            self.counters.add(Event::GrantsEnded, 1);
        }
    }
}

/// What a `TraceJournal` asked for.
#[derive(Debug, Clone, Copy)]
struct JournalRequest {
    capacity: u64,
    payload_words: u64,
    drop_ranges: u64,
    /// The observed subscription's registration, 0 for none.
    subscription: u64,
}

/// The bytes a fetch of `buffer` carries: its whole region, header
/// included (`quantstratum-docs: karyos/design/ipc-data-path.md`, Bounds);
/// 0 for a heap buffer, which has no region to carry.
pub(crate) fn fetch_bytes<T: StreamTerms>(buffer: &karyos_sys::log_buffer::LogBuffer<T>) -> u64 {
    #[cfg(target_os = "linux")]
    {
        // A full region: its header stride and its structure; a size that
        // does not fit counts as too large.
        <T as crate::embedded::sealed::Create>::region(buffer).map_or(0, |region| {
            region
                .record()
                .structure_length
                .checked_add(karyos_sys::ipc::HEADER_STRIDE)
                .and_then(|bytes| u64::try_from(bytes).ok())
                .unwrap_or(u64::MAX)
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = buffer;
        0
    }
}

/// The refusal code of a failed publication issuance: a kind that does not
/// match the stream's mode, or a resource (staging, loan) not available.
/// The reader role an `AddSubscription` asks for; `Required` for any
/// other command (the callers only reach it for subscriptions).
fn subscription_role(command: Command) -> Role {
    match command {
        Command::AddSubscription { role, .. } => Role::from(role),
        _ => Role::Required,
    }
}

fn issue_refusal(error: &karyos_sys::error::SysError) -> ErrorCode {
    match error {
        karyos_sys::error::SysError::InvalidPublicationMode { .. } => {
            ErrorCode::InvalidPublicationMode
        }
        _ => ErrorCode::ResourcesUnavailable,
    }
}

impl<T: StreamTerms> Drop for EmbeddedDriver<T> {
    fn drop(&mut self) {
        // Position cells are released in a final pass, not left to their
        // owners' drops outside any pass.
        self.positions.close(&mut self.counters);
        self.broadcast.close();
        for slot in &self.clients {
            slot.link.drop_all(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use karyos_client::Outcome;
    use karyos_protocol::cnc::{Response, SubscriberRole};
    use karyos_sys::broadcast::Received;
    use karyos_sys::command_ring::RingProducer;
    use karyos_sys::frame::Lane;
    use karyos_sys::log_buffer::LogBufferConfig;
    use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
    use karyos_sys::term::TermId;

    use super::*;
    use crate::embedded::{StreamConfig, StreamHandle};
    use karyos_protocol::cnc::RejoinPolicyCode;

    fn driver() -> EmbeddedDriver {
        driver_with_stream().0
    }

    fn driver_with_stream() -> (EmbeddedDriver, StreamHandle) {
        let mut driver = EmbeddedDriver::new().unwrap();
        let stream = driver
            .add_stream(StreamConfig {
                buffer: LogBufferConfig {
                    term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                    spare_slots: 3,
                    max_subscribers: 4,
                    mtu: DEFAULT_MTU,
                    max_reserved: MIN_TERM_LENGTH / 8,
                    initial_term_id: TermId::new(7),
                    lane: Lane::ZERO,
                    session_id: 1,
                    stream_id: 2,
                    claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
                    publication: karyos_sys::log_buffer::PublicationMode::Exclusive,
                },
                allow_unconnected: false,
                on_required_loss: karyos_sys::log_buffer::LossPolicy::Hold,
                conflation: None,
            })
            .unwrap();
        (driver, stream)
    }

    /// Admits a raw client whose producer the test controls.
    fn raw_client(driver: &mut EmbeddedDriver) -> (u64, RingProducer, Arc<ClientLink>) {
        let (producer, consumer) = command_ring(1024).unwrap();
        let link = Arc::new(ClientLink::new());
        let id = driver.next_client;
        driver.next_client += 1;
        driver.clients.push(ClientSlot {
            id,
            consumer: Some(consumer),
            link: Arc::clone(&link),
            seen: None,
            ledger: None,
        });
        (id, producer, link)
    }

    /// Admits a raw remote client with an export ledger of `limit` grants.
    fn remote_client(driver: &mut EmbeddedDriver, limit: usize) -> (u64, RingProducer) {
        remote_client_with(driver, Ledger::new(limit, 4, 1 << 30))
    }

    /// Admits a raw remote client with `ledger`.
    fn remote_client_with(driver: &mut EmbeddedDriver, ledger: Ledger) -> (u64, RingProducer) {
        let (producer, consumer) = command_ring(1024).unwrap();
        let link = Arc::new(ClientLink::new());
        let id = driver.admit(consumer, link, Some(ledger)).unwrap();
        (id, producer)
    }

    /// Every response the broadcast buffer carries from `observer`'s cursor.
    fn responses(observer: &mut karyos_sys::broadcast::BroadcastReceiver) -> Vec<Response> {
        let mut out = Vec::new();
        while let Received::Message {
            type_id, payload, ..
        } = observer.receive()
        {
            if let Ok(response) = Response::decode(type_id, payload) {
                out.push(response);
            }
        }
        out
    }

    fn ledger(driver: &EmbeddedDriver, client: u64) -> &[Grant] {
        driver
            .clients
            .iter()
            .find(|slot| slot.id == client)
            .and_then(|slot| slot.ledger.as_ref())
            .unwrap()
            .grants()
    }

    fn remote_ledger(driver: &mut EmbeddedDriver, client: u64) -> &mut Ledger {
        driver
            .clients
            .iter_mut()
            .find(|slot| slot.id == client)
            .and_then(|slot| slot.ledger.as_mut())
            .unwrap()
    }

    const KEY: StreamKey = StreamKey {
        stream_id: 2,
        session_id: 1,
    };

    #[test]
    fn a_remote_subscription_is_reserved_under_an_export_and_answered_with_its_key() {
        let mut driver = driver();
        let mut observer = driver.broadcast.receiver();
        let (client, mut producer) = remote_client(&mut driver, 4);
        write(
            &mut producer,
            Command::AddSubscription {
                sequence: 1,
                stream: KEY,
                role: SubscriberRole::Required,
            },
        );
        let _ = driver.do_work().unwrap();
        let [
            Response::SubscriptionReady {
                registration, key, ..
            },
        ] = responses(&mut observer)[..]
        else {
            panic!("expected one SubscriptionReady");
        };
        let grants = ledger(&driver, client);
        assert_eq!(grants.len(), 1);
        let grant = grants[0];
        assert_eq!((grant.registration, grant.key), (registration, key));
        assert_eq!(grant.state, GrantState::Held);
        assert!(!grant.sent);
        let Participant::Subscriber { cell, role } = grant.participant else {
            panic!("a subscriber grant");
        };
        assert_eq!(role, Role::Required);
        // Nothing waits in the in-process hand-over table, and the export
        // is in the registration word before anything is sent: a
        // participant adopts the cell with it.
        assert_eq!(driver.clients[0].link.held(), 0);
        let buffer = Arc::clone(&driver.streams[0].buffer);
        assert_eq!(buffer.attached_subscribers(), 1);
        assert!(
            karyos_sys::log_buffer::Subscription::adopt(buffer, cell, Role::Required, grant.export)
                .is_ok()
        );
        assert_eq!(driver.next_export, grant.export + 1);
    }

    #[test]
    fn removing_a_held_remote_grant_ends_it_in_the_buffer() {
        let mut driver = driver();
        let mut observer = driver.broadcast.receiver();
        let (client, mut producer) = remote_client(&mut driver, 4);
        write(
            &mut producer,
            Command::AddSubscription {
                sequence: 1,
                stream: KEY,
                role: SubscriberRole::Optional,
            },
        );
        let _ = driver.do_work().unwrap();
        let registration = ledger(&driver, client)[0].registration;
        write(
            &mut producer,
            Command::RemoveSubscription {
                sequence: 2,
                registration,
            },
        );
        let _ = driver.do_work().unwrap();
        assert!(matches!(
            responses(&mut observer)[..],
            [
                Response::SubscriptionReady { .. },
                Response::OperationSucceeded { .. }
            ]
        ));
        assert!(ledger(&driver, client).is_empty());
        assert_eq!(driver.streams[0].buffer.attached_subscribers(), 0);
        assert!(driver.registrations.is_empty());
    }

    #[test]
    fn the_export_bound_refuses_a_command_without_reserving() {
        let mut driver = driver();
        let mut observer = driver.broadcast.receiver();
        let (client, mut producer) = remote_client(&mut driver, 1);
        for sequence in 1..=2 {
            write(
                &mut producer,
                Command::AddSubscription {
                    sequence,
                    stream: KEY,
                    role: SubscriberRole::Optional,
                },
            );
            let _ = driver.do_work().unwrap();
        }
        let export = driver.next_export;
        assert!(matches!(
            responses(&mut observer)[..],
            [
                Response::SubscriptionReady { .. },
                Response::Error {
                    code: ErrorCode::ResourcesUnavailable,
                    ..
                }
            ]
        ));
        assert_eq!(ledger(&driver, client).len(), 1);
        assert_eq!(driver.streams[0].buffer.attached_subscribers(), 1);
        assert_eq!(driver.next_export, export);
    }

    #[test]
    fn a_remote_exclusive_publication_takes_the_one_issuance() {
        let (mut driver, stream) = driver_with_stream();
        let mut observer = driver.broadcast.receiver();
        let (client, mut producer) = remote_client(&mut driver, 4);
        for sequence in 1..=2 {
            write(
                &mut producer,
                Command::AddPublication {
                    sequence,
                    stream: KEY,
                    allow_unconnected: false,
                },
            );
            let _ = driver.do_work().unwrap();
        }
        assert!(matches!(
            responses(&mut observer)[..],
            [
                Response::PublicationReady { .. },
                Response::Error {
                    code: ErrorCode::PublicationTaken,
                    ..
                }
            ]
        ));
        assert_eq!(
            ledger(&driver, client)[0].participant,
            Participant::Exclusive
        );
        assert!(matches!(
            driver.publication(stream),
            Err(DriverError::PublicationTaken)
        ));
    }

    #[test]
    fn a_closed_remote_client_ends_every_grant_and_a_retired_one_its_unsent() {
        for closed in [true, false] {
            let mut driver = driver();
            let (client, mut producer) = remote_client(&mut driver, 4);
            for sequence in 1..=2 {
                write(
                    &mut producer,
                    Command::AddSubscription {
                        sequence,
                        stream: KEY,
                        role: SubscriberRole::Required,
                    },
                );
                let _ = driver.do_work().unwrap();
            }
            assert_eq!(driver.streams[0].buffer.attached_subscribers(), 2);
            // One grant's descriptor left: only the exit proof ends it.
            let sent = ledger(&driver, client)[0].registration;
            remote_ledger(&mut driver, client).mark_sent(sent);
            let index = driver
                .clients
                .iter()
                .position(|slot| slot.id == client)
                .unwrap();
            if closed {
                // The close flag (exit proof or Leave) ends both.
                driver.clients[index].link.mark_closed();
                let _ = driver.do_work().unwrap();
                assert_eq!(driver.clients(), 0);
                assert_eq!(driver.streams[0].buffer.attached_subscribers(), 0);
            } else {
                // Retired: the unsent grant ends, the sent one stays.
                driver.retire_faulty(index);
                let _ = driver.do_work().unwrap();
                assert_eq!(driver.streams[0].buffer.attached_subscribers(), 1);
                assert_eq!(ledger(&driver, client).len(), 1);
                assert_eq!(ledger(&driver, client)[0].registration, sent);
            }
        }
    }

    #[test]
    fn an_unadopted_successor_is_fenced_and_the_predecessor_freed_after_its_grant_ends() {
        let mut driver = EmbeddedDriver::with_config(crate::embedded::DriverConfig {
            cutover_deadline: 1,
            ..crate::embedded::DriverConfig::default()
        })
        .unwrap();
        let stream = driver
            .add_stream(StreamConfig {
                buffer: LogBufferConfig {
                    term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                    spare_slots: 3,
                    max_subscribers: 4,
                    mtu: DEFAULT_MTU,
                    max_reserved: MIN_TERM_LENGTH / 8,
                    initial_term_id: TermId::new(7),
                    lane: Lane::ZERO,
                    session_id: 1,
                    stream_id: 2,
                    claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
                    publication: karyos_sys::log_buffer::PublicationMode::Exclusive,
                },
                allow_unconnected: false,
                on_required_loss: karyos_sys::log_buffer::LossPolicy::Hold,
                conflation: None,
            })
            .unwrap();
        let mut observer = driver.broadcast.receiver();
        let (client, mut producer) = remote_client(&mut driver, 4);
        write(
            &mut producer,
            Command::AddSubscription {
                sequence: 1,
                stream: KEY,
                role: SubscriberRole::Required,
            },
        );
        let _ = driver.do_work().unwrap();
        let old = ledger(&driver, client)[0];
        remote_ledger(&mut driver, client).mark_sent(old.export);
        let _ = driver
            .reconfigure_stream(
                stream,
                crate::generations::Reconfiguration {
                    term_length: TermLength::try_new(MIN_TERM_LENGTH * 2).unwrap(),
                    spare_slots: 5,
                },
            )
            .unwrap();
        let start = std::time::Instant::now();
        while counter(&driver, "grants fenced") == 0 {
            assert!(
                start.elapsed() < std::time::Duration::from_secs(5),
                "never fenced"
            );
            let _ = driver.do_work().unwrap();
        }
        // The successor was never sent: it ends at once; the old grant stays.
        let left = ledger(&driver, client);
        assert_eq!(left.len(), 1, "{left:?}");
        assert_eq!(left[0].export, old.export);
        assert_eq!(driver.streams[0].buffer.attached_subscribers(), 0);
        let mut fenced = false;
        while let Received::Message {
            type_id, payload, ..
        } = observer.receive()
        {
            fenced |= matches!(
                karyos_protocol::cnc::Event::decode(type_id, payload),
                Ok(karyos_protocol::cnc::Event::Fenced { registration, .. })
                    if registration == old.registration
            );
        }
        assert!(fenced);
        // The predecessor is retained while the old grant is charged, and
        // freed once the client's exit proof ends it.
        assert_eq!(driver.generations(stream).unwrap().len(), 2);
        driver.clients[0].link.mark_closed();
        let _ = driver.do_work().unwrap();
        let _ = driver.do_work().unwrap();
        assert_eq!(driver.generations(stream).unwrap().len(), 1);
    }

    #[test]
    fn a_fenced_sent_successor_is_not_moved_by_a_later_cutover() {
        let mut driver = EmbeddedDriver::with_config(crate::embedded::DriverConfig {
            cutover_deadline: 50_000_000,
            ..crate::embedded::DriverConfig::default()
        })
        .unwrap();
        let stream = driver
            .add_stream(StreamConfig {
                buffer: LogBufferConfig {
                    term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                    spare_slots: 3,
                    max_subscribers: 4,
                    mtu: DEFAULT_MTU,
                    max_reserved: MIN_TERM_LENGTH / 8,
                    initial_term_id: TermId::new(7),
                    lane: Lane::ZERO,
                    session_id: 1,
                    stream_id: 2,
                    claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
                    publication: karyos_sys::log_buffer::PublicationMode::Exclusive,
                },
                allow_unconnected: false,
                on_required_loss: karyos_sys::log_buffer::LossPolicy::Hold,
                conflation: None,
            })
            .unwrap();
        let mut observer = driver.broadcast.receiver();
        let (client, mut producer) = remote_client(&mut driver, 4);
        write(
            &mut producer,
            Command::AddSubscription {
                sequence: 1,
                stream: KEY,
                role: SubscriberRole::Required,
            },
        );
        let _ = driver.do_work().unwrap();
        let old = ledger(&driver, client)[0];
        remote_ledger(&mut driver, client).mark_sent(old.export);
        let first = driver
            .reconfigure_stream(
                stream,
                crate::generations::Reconfiguration {
                    term_length: TermLength::try_new(MIN_TERM_LENGTH * 2).unwrap(),
                    spare_slots: 5,
                },
            )
            .unwrap();
        // The successor's descriptor leaves, but its participant never
        // adopts it: the fence wins and the sent grant stays charged.
        let start = std::time::Instant::now();
        while counter(&driver, "grants fenced") == 0 {
            assert!(
                start.elapsed() < std::time::Duration::from_secs(5),
                "never fenced"
            );
            let _ = driver.do_work().unwrap();
            let successor = ledger(&driver, client)
                .iter()
                .find(|grant| grant.generation == first.get() && !grant.sent)
                .map(|grant| grant.export);
            if let Some(export) = successor {
                remote_ledger(&mut driver, client).mark_sent(export);
            }
        }
        let fenced = ledger(&driver, client)
            .iter()
            .find(|grant| grant.generation == first.get())
            .copied()
            .unwrap();
        assert!(fenced.sent && fenced.fenced && fenced.fence_at.is_none());
        let _ = responses(&mut observer);
        // A later cutover moves nothing: the client never reached `first`.
        let second = driver
            .reconfigure_stream(
                stream,
                crate::generations::Reconfiguration {
                    term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                    spare_slots: 5,
                },
            )
            .unwrap();
        for _ in 0..4 {
            let _ = driver.do_work().unwrap();
        }
        let grants = ledger(&driver, client);
        assert_eq!(grants.len(), 2, "{grants:?}");
        assert!(grants.iter().all(|grant| grant.generation != second.get()));
        while let Received::Message {
            type_id, payload, ..
        } = observer.receive()
        {
            assert!(
                !matches!(
                    karyos_protocol::cnc::Event::decode(type_id, payload),
                    Ok(karyos_protocol::cnc::Event::SuccessorReady { .. })
                ),
                "a fenced grant was moved"
            );
        }
    }

    fn counter(driver: &EmbeddedDriver, label: &str) -> u64 {
        let reader = driver.counters();
        (0..reader.capacity())
            .find_map(|index| match reader.read(index) {
                karyos_sys::counters::CellRead::Allocated {
                    metadata, value, ..
                } if metadata.label() == label.as_bytes() => Some(value),
                _ => None,
            })
            .unwrap()
    }

    #[test]
    fn a_cutover_reserves_the_successor_of_a_sent_remote_grant() {
        let (mut driver, stream) = driver_with_stream();
        let mut observer = driver.broadcast.receiver();
        let (client, mut producer) = remote_client(&mut driver, 4);
        write(
            &mut producer,
            Command::AddSubscription {
                sequence: 1,
                stream: KEY,
                role: SubscriberRole::Required,
            },
        );
        let _ = driver.do_work().unwrap();
        // Its descriptor left: the participant is mapped in its process.
        let old = ledger(&driver, client)[0];
        remote_ledger(&mut driver, client).mark_sent(old.export);
        let _ = responses(&mut observer);
        let generation = driver
            .reconfigure_stream(
                stream,
                crate::generations::Reconfiguration {
                    term_length: TermLength::try_new(MIN_TERM_LENGTH * 2).unwrap(),
                    spare_slots: 5,
                },
            )
            .unwrap();
        // A cutover opens on the writer's next call; without one, a duty
        // cycle positions the seal.
        for _ in 0..4 {
            let _ = driver.do_work().unwrap();
        }
        let grants = ledger(&driver, client);
        assert_eq!(grants.len(), 2, "{grants:?}");
        let successor = grants
            .iter()
            .find(|grant| grant.generation == generation.get())
            .copied()
            .unwrap();
        assert_eq!(successor.registration, old.registration);
        assert_ne!(successor.export, old.export);
        assert_eq!(successor.state, GrantState::Held);
        assert!(successor.fence_at.is_some());
        // Told with SuccessorReady, carrying the new key.
        let mut events = Vec::new();
        while let Received::Message {
            type_id, payload, ..
        } = observer.receive()
        {
            if let Ok(event) = karyos_protocol::cnc::Event::decode(type_id, payload) {
                events.push(event);
            }
        }
        assert!(
            events.iter().any(|event| matches!(
                event,
                karyos_protocol::cnc::Event::SuccessorReady { registration, key, generation: g, .. }
                    if *registration == old.registration
                        && *key == successor.key
                        && *g == u64::from(generation.get())
            )),
            "{events:?}"
        );
        // The predecessor stays while the old grant is charged.
        assert_eq!(driver.generations(stream).unwrap().len(), 2);
        // A second reconfiguration waits for the successor to settle.
        assert!(matches!(
            driver.reconfigure_stream(
                stream,
                crate::generations::Reconfiguration {
                    term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                    spare_slots: 5,
                }
            ),
            Err(DriverError::CutoverPending { .. })
        ));
    }

    #[test]
    fn a_successor_beyond_the_export_bound_is_fenced_at_once() {
        // At `max_exports_per_client`; the fetch bound needs a region, so
        // the admission tests cover it.
        let (mut driver, stream) = driver_with_stream();
        let bounds = Ledger::new(1, 4, 1 << 30);
        let mut observer = driver.broadcast.receiver();
        let (client, mut producer) = remote_client_with(&mut driver, bounds);
        write(
            &mut producer,
            Command::AddSubscription {
                sequence: 1,
                stream: KEY,
                role: SubscriberRole::Required,
            },
        );
        let _ = driver.do_work().unwrap();
        let old = ledger(&driver, client)[0];
        remote_ledger(&mut driver, client).mark_sent(old.export);
        let _ = responses(&mut observer);
        driver
            .reconfigure_stream(
                stream,
                crate::generations::Reconfiguration {
                    term_length: TermLength::try_new(MIN_TERM_LENGTH * 2).unwrap(),
                    spare_slots: 5,
                },
            )
            .unwrap();
        for _ in 0..4 {
            let _ = driver.do_work().unwrap();
        }
        // Nothing was reserved; the client is told at once.
        let grants = ledger(&driver, client);
        assert_eq!(grants.len(), 1, "{grants:?}");
        assert_eq!(grants[0].export, old.export);
        let mut events = Vec::new();
        while let Received::Message {
            type_id, payload, ..
        } = observer.receive()
        {
            if let Ok(event) = karyos_protocol::cnc::Event::decode(type_id, payload) {
                events.push(event);
            }
        }
        assert!(
            events.iter().any(|event| matches!(
                event,
                karyos_protocol::cnc::Event::Fenced { registration, .. }
                    if *registration == old.registration
            )),
            "{events:?}"
        );
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, karyos_protocol::cnc::Event::SuccessorReady { .. })),
            "{events:?}"
        );
    }

    #[test]
    fn a_sent_grant_outlives_its_remove_and_keeps_its_stream() {
        let (mut driver, stream) = driver_with_stream();
        let (client, mut producer) = remote_client(&mut driver, 4);
        write(
            &mut producer,
            Command::AddSubscription {
                sequence: 1,
                stream: KEY,
                role: SubscriberRole::Optional,
            },
        );
        let _ = driver.do_work().unwrap();
        let registration = ledger(&driver, client)[0].registration;
        // A descriptor of it left: it is charged until Detach or exit.
        remote_ledger(&mut driver, client).mark_sent(registration);
        write(
            &mut producer,
            Command::RemoveSubscription {
                sequence: 2,
                registration,
            },
        );
        driver.remove_stream(stream).unwrap();
        let _ = driver.do_work().unwrap();
        let _ = driver.do_work().unwrap();
        assert_eq!(ledger(&driver, client).len(), 1);
        assert_eq!(driver.streams[0].buffer.attached_subscribers(), 1);
        assert_eq!(driver.streams.len(), 1);
    }

    fn write(producer: &mut RingProducer, command: Command) {
        let mut bytes = [0u8; MAX_COMMAND_LENGTH];
        let length = command.encode(&mut bytes).unwrap();
        producer.write(command.type_id(), &bytes[..length]).unwrap();
    }

    #[test]
    fn a_malformed_command_retires_but_keeps_the_slot_until_close() {
        let mut driver = driver();
        let (_, mut producer, link) = raw_client(&mut driver);
        let mut observer = driver.broadcast.receiver();
        producer.write(0x99, &[0; 8]).unwrap();
        let _ = driver.do_work().unwrap();
        // No response, client retired and told so, slot still charged.
        assert_eq!(observer.receive(), Received::Pending);
        // The error log names the client and the command type.
        let mut records = Vec::new();
        let _ = driver
            .error_log()
            .scan(&mut 0, |record| records.push(record));
        assert_eq!(records.len(), 1);
        assert_eq!(
            (records[0].code, records[0].key),
            (
                crate::diagnostics::ErrorCode::ClientProtocolViolation as u32,
                [driver.clients[0].id, 0x99]
            )
        );
        assert_eq!(driver.clients(), 1);
        assert!(driver.clients[0].consumer.is_none());
        assert!(producer.is_closed());
        assert!(producer.write(1, &[0; 8]).is_err());
        // The producer detaches, then the close flag is set.
        drop(producer);
        link.mark_closed();
        let _ = driver.do_work().unwrap();
        assert_eq!(driver.clients(), 0);
    }

    #[test]
    fn a_retired_client_sees_its_ring_closed() {
        let mut driver = driver();
        let mut client = driver.connect().unwrap();
        let request = client
            .add_publication(
                StreamKey {
                    stream_id: 2,
                    session_id: 1,
                },
                false,
            )
            .unwrap();
        // The driver retires this client as faulty while the broadcast and
        // the driver stay open.
        driver.retire_faulty(0);
        let mut done = Vec::new();
        let _ = client.poll(usize::MAX, |completion| done.push(completion));
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].sequence, request);
        assert!(matches!(done[0].outcome, Outcome::Unknown));
        assert!(matches!(
            client.add_publication(
                StreamKey {
                    stream_id: 2,
                    session_id: 1
                },
                false
            ),
            Err(karyos_client::ConductorError::Closed)
        ));
        assert!(!driver.is_terminal());
        // The slot stays until the client drops its conductor.
        let _ = driver.do_work().unwrap();
        assert_eq!(driver.clients(), 1);
        drop(client);
        let _ = driver.do_work().unwrap();
        assert_eq!(driver.clients(), 0);
    }

    #[test]
    fn a_retired_client_resolves_pending_under_a_tiny_poll_budget() {
        let mut driver = driver();
        let mut retired = driver.connect().unwrap();
        let mut busy = driver.connect().unwrap();
        let request = retired
            .add_subscription(
                StreamKey {
                    stream_id: 9,
                    session_id: 1,
                },
                SubscriberRole::Optional,
            )
            .unwrap();
        driver.retire_faulty(0);
        // The busy client keeps one response per cycle in the broadcast; the
        // retired client polls one record per cycle and never sees Pending.
        let mut done = Vec::new();
        for _ in 0..3 {
            let _ = busy
                .add_subscription(
                    StreamKey {
                        stream_id: 9,
                        session_id: 1,
                    },
                    SubscriberRole::Optional,
                )
                .unwrap();
            let _ = driver.do_work().unwrap();
            let report = retired.poll(1, |completion| done.push(completion));
            assert!(!report.drained);
            let _ = busy.poll(usize::MAX, |_| {});
        }
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].sequence, request);
        assert!(matches!(done[0].outcome, Outcome::Unknown));
    }

    #[test]
    fn another_clients_registration_cannot_be_removed() {
        let mut driver = driver();
        let mut owner = driver.connect().unwrap();
        let _ = owner
            .add_publication(
                StreamKey {
                    stream_id: 2,
                    session_id: 1,
                },
                false,
            )
            .unwrap();
        let _ = driver.do_work().unwrap();
        let mut handle = None;
        let _ = owner.poll(usize::MAX, |completion| {
            if let Outcome::Publication(publication) = completion.outcome {
                handle = Some(publication);
            }
        });
        let handle = handle.unwrap();
        let registration = handle.origin().unwrap().registration();
        let (intruder, mut producer, _link) = raw_client(&mut driver);
        let mut observer = driver.broadcast.receiver();
        write(
            &mut producer,
            Command::RemovePublication {
                sequence: 1,
                registration,
            },
        );
        let _ = driver.do_work().unwrap();
        let Received::Message {
            type_id, payload, ..
        } = observer.receive()
        else {
            panic!("expected a response");
        };
        assert_eq!(
            Response::decode(type_id, payload).unwrap(),
            Response::Error {
                request: RequestId {
                    client: intruder,
                    sequence: 1
                },
                code: ErrorCode::UnknownRegistration,
                detail: registration,
            }
        );
        assert_eq!(driver.registrations.len(), 1);
        drop(handle);
    }

    #[test]
    fn dropped_handles_do_not_accumulate_registrations() {
        let mut driver = EmbeddedDriver::with_config(crate::embedded::DriverConfig {
            max_pending_per_client: 1,
            max_hand_over: 1,
            ..crate::embedded::DriverConfig::default()
        })
        .unwrap();
        let mut other = self::driver();
        // Reuse the test stream configuration of `driver()`.
        let stream = other.streams.pop().unwrap();
        driver.streams.push(stream);
        let mut client = driver.connect().unwrap();
        for _ in 0..50 {
            let _ = client
                .add_subscription(
                    StreamKey {
                        stream_id: 2,
                        session_id: 1,
                    },
                    SubscriberRole::Optional,
                )
                .unwrap();
            let _ = driver.do_work().unwrap();
            let mut taken = 0;
            let _ = client.poll(usize::MAX, |completion| {
                assert!(matches!(completion.outcome, Outcome::Subscription(_)));
                taken += 1;
            });
            assert_eq!(taken, 1);
            // The handle was dropped inside the callback without remove.
            let _ = driver.do_work().unwrap();
            assert!(driver.registrations.is_empty());
        }
    }

    #[test]
    fn a_queued_remove_survives_other_drops() {
        let mut driver = EmbeddedDriver::with_config(crate::embedded::DriverConfig {
            max_pending_per_client: 1,
            max_hand_over: 1,
            ..crate::embedded::DriverConfig::default()
        })
        .unwrap();
        let mut other = self::driver();
        driver.streams.push(other.streams.pop().unwrap());
        let mut client = driver.connect().unwrap();
        let mut handles = Vec::new();
        for _ in 0..2 {
            let _ = client
                .add_subscription(
                    StreamKey {
                        stream_id: 2,
                        session_id: 1,
                    },
                    SubscriberRole::Required,
                )
                .unwrap();
            let _ = driver.do_work().unwrap();
            let _ = client.poll(usize::MAX, |completion| match completion.outcome {
                Outcome::Subscription(handle) => handles.push(handle),
                other => panic!("unexpected {other:?}"),
            });
        }
        let second = handles.pop().unwrap();
        let first = handles.pop().unwrap();
        let remove = client.remove_subscription(first).unwrap();
        drop(second);
        let _ = driver.do_work().unwrap();
        let mut done = Vec::new();
        let _ = client.poll(usize::MAX, |completion| done.push(completion));
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].sequence, remove);
        assert!(matches!(done[0].outcome, Outcome::Succeeded));
        assert!(driver.registrations.is_empty());
    }

    #[test]
    fn registration_exhaustion_refuses_without_effect() {
        let mut driver = driver();
        driver.next_registration = u64::MAX;
        let (client, mut producer, link) = raw_client(&mut driver);
        let mut observer = driver.broadcast.receiver();
        write(
            &mut producer,
            Command::AddPublication {
                sequence: 1,
                stream: StreamKey {
                    stream_id: 2,
                    session_id: 1,
                },
                allow_unconnected: false,
            },
        );
        let _ = driver.do_work().unwrap();
        let Received::Message {
            type_id, payload, ..
        } = observer.receive()
        else {
            panic!("expected a response");
        };
        assert_eq!(
            Response::decode(type_id, payload).unwrap(),
            Response::Error {
                request: RequestId {
                    client,
                    sequence: 1
                },
                code: ErrorCode::IdentitiesExhausted,
                detail: 0,
            }
        );
        assert_eq!(link.held(), 0);
        assert!(driver.registrations.is_empty());
        // The publication was not issued: it is still available.
        assert!(
            driver.streams[0]
                .buffer
                .publication_owned()
                .unwrap()
                .is_some()
        );
    }

    fn allocate(sequence: u64, label: &str, stream: u64, participant: u64) -> Command {
        Command::AllocateCounter {
            sequence,
            type_id: 7,
            label: CounterLabel::new(label).unwrap(),
            stream,
            participant,
        }
    }

    fn client_cell(driver: &EmbeddedDriver, cell: u64) -> karyos_sys::counters::CellRead {
        driver
            .client_counters()
            .read(usize::try_from(cell).unwrap())
    }

    fn allocated(response: &Response) -> (u64, u64) {
        match *response {
            Response::CounterAllocated {
                cell, registration, ..
            } => (cell, registration),
            other => panic!("expected CounterAllocated, got {other:?}"),
        }
    }

    #[test]
    fn a_client_counter_is_keyed_to_its_client_stream_and_participant() {
        let (mut driver, stream) = driver_with_stream();
        let stream_registration = driver.trace_identity(stream).unwrap().registration;
        let mut observer = driver.broadcast.receiver();
        let (client, mut producer, link) = raw_client(&mut driver);
        write(
            &mut producer,
            Command::AddSubscription {
                sequence: 1,
                stream: KEY,
                role: SubscriberRole::Optional,
            },
        );
        let _ = driver.do_work().unwrap();
        let [Response::SubscriptionReady { registration, .. }] = responses(&mut observer)[..]
        else {
            panic!("expected one SubscriptionReady");
        };
        // Keep the capability held, so the registration stays live.
        assert_eq!(link.held(), 1);
        let stream_id = stream_registration;
        write(&mut producer, allocate(2, "client wide", 0, 0));
        let _ = driver.do_work().unwrap();
        write(
            &mut producer,
            allocate(3, "per subscription", stream_id, registration),
        );
        let _ = driver.do_work().unwrap();
        write(&mut producer, allocate(4, "per stream", stream_id, 0));
        let _ = driver.do_work().unwrap();
        let answered = responses(&mut observer);
        assert_eq!(answered.len(), 3);
        let expected = [
            ("client wide", 0, 0, KIND_CLIENT, client),
            (
                "per subscription",
                stream_id,
                0,
                KIND_SUBSCRIBER,
                registration,
            ),
            ("per stream", stream_id, 0, KIND_CLIENT, client),
        ];
        for (response, (label, key0, lane, kind, key2)) in answered.iter().zip(expected) {
            let (cell, registration) = allocated(response);
            let karyos_sys::counters::CellRead::Allocated {
                metadata,
                value: 0,
                release_pending: false,
            } = client_cell(&driver, cell)
            else {
                panic!("expected an allocated cell");
            };
            assert_eq!(metadata.registration_id, registration);
            assert_eq!(metadata.type_id, 7);
            assert_eq!(metadata.label(), label.as_bytes());
            assert_eq!(
                metadata.keys,
                CounterKeys {
                    stream: key0,
                    lane,
                    kind,
                    participant: key2,
                }
            );
        }
        assert_eq!(driver.client_counters.owned_by(client), 3);
    }

    #[test]
    fn a_counter_for_an_unknown_stream_or_a_foreign_participant_is_refused() {
        let (mut driver, stream) = driver_with_stream();
        let stream_registration = driver.trace_identity(stream).unwrap().registration;
        let mut observer = driver.broadcast.receiver();
        let (_owner, mut owner_producer, _owner_link) = raw_client(&mut driver);
        write(
            &mut owner_producer,
            Command::AddPublication {
                sequence: 1,
                stream: KEY,
                allow_unconnected: false,
            },
        );
        let _ = driver.do_work().unwrap();
        let [Response::PublicationReady { registration, .. }] = responses(&mut observer)[..] else {
            panic!("expected one PublicationReady");
        };
        let (client, mut producer, _link) = raw_client(&mut driver);
        let other_stream = stream_registration + 100;
        for (sequence, command) in [
            // A stream registration never issued.
            (1, allocate(1, "x", other_stream, 0)),
            // Another client's participant.
            (2, allocate(2, "x", 0, registration)),
            // A participant never issued.
            (3, allocate(3, "x", 0, registration + 100)),
        ] {
            write(&mut producer, command);
            let _ = driver.do_work().unwrap();
            let [Response::Error { request, code, .. }] = responses(&mut observer)[..] else {
                panic!("expected one Error");
            };
            assert_eq!(request.sequence, sequence);
            let expected = if sequence == 1 {
                ErrorCode::UnknownStream
            } else {
                ErrorCode::UnknownRegistration
            };
            assert_eq!(code, expected);
        }
        // The owner's participant on another stream than the one named.
        let second = driver
            .add_stream(StreamConfig {
                buffer: LogBufferConfig {
                    stream_id: 3,
                    ..driver.streams[0].config
                },
                allow_unconnected: false,
                on_required_loss: karyos_sys::log_buffer::LossPolicy::Hold,
                conflation: None,
            })
            .unwrap();
        let second = driver.trace_identity(second).unwrap().registration;
        write(&mut owner_producer, allocate(2, "x", second, registration));
        let _ = driver.do_work().unwrap();
        assert!(matches!(
            responses(&mut observer)[..],
            [Response::Error {
                code: ErrorCode::UnknownRegistration,
                ..
            }]
        ));
        // A retiring stream takes no new counter.
        driver.remove_stream(stream).unwrap();
        write(&mut producer, allocate(4, "x", stream_registration, 0));
        let _ = driver.do_work().unwrap();
        assert!(matches!(
            responses(&mut observer)[..],
            [Response::Error {
                code: ErrorCode::UnknownStream,
                ..
            }]
        ));
        assert_eq!(driver.client_counters.owned_by(client), 0);
        let reader = driver.client_counters();
        assert!(
            (0..reader.capacity())
                .all(|cell| reader.read(cell) == karyos_sys::counters::CellRead::Free)
        );
    }

    #[test]
    fn counters_per_client_and_cells_are_bounded() {
        let mut driver = EmbeddedDriver::with_config(crate::embedded::DriverConfig {
            client_counters_capacity: 3,
            max_counters_per_client: 2,
            ..crate::embedded::DriverConfig::default()
        })
        .unwrap();
        let mut observer = driver.broadcast.receiver();
        let (first, mut first_producer, _first_link) = raw_client(&mut driver);
        let (second, mut second_producer, _second_link) = raw_client(&mut driver);
        for sequence in 1..=3 {
            write(&mut first_producer, allocate(sequence, "x", 0, 0));
            let _ = driver.do_work().unwrap();
        }
        let answered = responses(&mut observer);
        assert!(matches!(
            answered[..],
            [
                Response::CounterAllocated { .. },
                Response::CounterAllocated { .. },
                Response::Error {
                    code: ErrorCode::ResourcesUnavailable,
                    ..
                }
            ]
        ));
        // The region has one cell left: the second client takes it, then
        // finds none free, which counts `counters unavailable`.
        let unavailable = counter(&driver, "counters unavailable");
        for sequence in 1..=2 {
            write(&mut second_producer, allocate(sequence, "y", 0, 0));
            let _ = driver.do_work().unwrap();
        }
        assert!(matches!(
            responses(&mut observer)[..],
            [
                Response::CounterAllocated { .. },
                Response::Error {
                    code: ErrorCode::ResourcesUnavailable,
                    ..
                }
            ]
        ));
        assert_eq!(counter(&driver, "counters unavailable"), unavailable + 1);
        // Both refusals are in the error log, keyed by client and reason.
        let mut refused = Vec::new();
        let _ = driver.error_log().scan(&mut 0, |record| {
            if record.code == crate::diagnostics::ErrorCode::CounterAllocationRefused as u32 {
                refused.push(record.key);
            }
        });
        assert_eq!(refused, [[first, 1], [second, 2]]);
        assert_eq!(driver.client_counters.owned_by(first), 2);
        assert_eq!(driver.client_counters.owned_by(second), 1);
        // A release makes room for the same client again.
        let (cell, registration) = allocated(&answered[0]);
        write(
            &mut first_producer,
            Command::ReleaseCounter {
                sequence: 4,
                cell,
                registration,
            },
        );
        write(&mut first_producer, allocate(5, "x", 0, 0));
        let _ = driver.do_work().unwrap();
        let _ = driver.do_work().unwrap();
        let answered = responses(&mut observer);
        assert!(matches!(
            answered[..],
            [
                Response::OperationSucceeded { .. },
                Response::CounterAllocated { .. }
            ]
        ));
        // The freed cell was reused with a fresh registration.
        let (reused, fresh) = allocated(&answered[1]);
        assert_eq!(reused, cell);
        assert_ne!(fresh, registration);
    }

    #[test]
    fn a_foreign_or_stale_release_is_a_protocol_violation_and_frees_nothing() {
        // Another client's allocation, the owner's cell with a wrong
        // registration, and a cell the owner does not hold.
        for case in 0..3u64 {
            let mut driver = driver();
            let mut observer = driver.broadcast.receiver();
            let (owner, mut owner_producer, _owner_link) = raw_client(&mut driver);
            write(&mut owner_producer, allocate(1, "owned", 0, 0));
            let _ = driver.do_work().unwrap();
            let [ref response] = responses(&mut observer)[..] else {
                panic!("expected one response");
            };
            let (cell, registration) = allocated(response);
            let (sender, mut producer) = if case == 0 {
                let (intruder, producer, _link) = raw_client(&mut driver);
                (intruder, producer)
            } else {
                (owner, owner_producer)
            };
            let (named_cell, named_registration) = match case {
                0 => (cell, registration),
                1 => (cell, registration + 1),
                _ => (cell + 1, registration),
            };
            write(
                &mut producer,
                Command::ReleaseCounter {
                    sequence: 9,
                    cell: named_cell,
                    registration: named_registration,
                },
            );
            let faulty = counter(&driver, "clients faulty");
            let _ = driver.do_work().unwrap();
            // No response, the sender retired as faulty, the cell intact.
            assert_eq!(responses(&mut observer), Vec::new(), "case {case}");
            assert_eq!(counter(&driver, "clients faulty"), faulty + 1);
            let slot = driver
                .clients
                .iter()
                .find(|slot| slot.id == sender)
                .unwrap();
            assert!(slot.consumer.is_none());
            assert!(matches!(
                client_cell(&driver, cell),
                karyos_sys::counters::CellRead::Allocated {
                    release_pending: false,
                    ..
                }
            ));
            assert_eq!(driver.client_counters.owned_by(owner), 1);
            // The violation is in the error log under the sender.
            let mut violations = Vec::new();
            let _ = driver.error_log().scan(&mut 0, |record| {
                if record.code == crate::diagnostics::ErrorCode::ClientProtocolViolation as u32 {
                    violations.push(record.key[0]);
                }
            });
            assert!(violations.contains(&sender), "case {case}");
        }
    }

    #[test]
    fn cells_are_freed_only_when_the_slot_is_removed_after_the_close_flag() {
        let mut driver = driver();
        let mut observer = driver.broadcast.receiver();
        let (client, mut producer) = remote_client(&mut driver, 4);
        write(&mut producer, allocate(1, "kept", 0, 0));
        let _ = driver.do_work().unwrap();
        let [ref response] = responses(&mut observer)[..] else {
            panic!("expected one response");
        };
        let (cell, _) = allocated(response);
        let index = driver
            .clients
            .iter()
            .position(|slot| slot.id == client)
            .unwrap();
        // Retired as faulty (as a timeout or a closed socket would): the
        // cell stays charged.
        driver.retire_faulty(index);
        let _ = driver.do_work().unwrap();
        assert_eq!(driver.client_counters.owned_by(client), 1);
        assert!(matches!(
            client_cell(&driver, cell),
            karyos_sys::counters::CellRead::Allocated { .. }
        ));
        // The exit proof (the close flag) frees it with the slot.
        driver.clients[index].link.mark_closed();
        let _ = driver.do_work().unwrap();
        assert_eq!(driver.clients(), 0);
        assert_eq!(driver.client_counters.owned_by(client), 0);
        assert_eq!(
            client_cell(&driver, cell),
            karyos_sys::counters::CellRead::Free
        );
    }

    fn take_counter(
        driver: &mut EmbeddedDriver,
        client: &mut ClientConductor,
        stream: u64,
        participant: u64,
    ) -> karyos_client::ClientCounterHandle {
        let sequence = client
            .allocate_counter(9, "messages handled", stream, participant)
            .unwrap();
        let _ = driver.do_work().unwrap();
        let mut done = Vec::new();
        let _ = client.poll(usize::MAX, |completion| done.push(completion));
        let [completion] = <[_; 1]>::try_from(done).unwrap();
        assert_eq!(completion.sequence, sequence);
        match completion.outcome {
            Outcome::Counter(counter) => counter,
            other => panic!("expected a counter, got {other:?}"),
        }
    }

    #[test]
    fn an_in_process_client_writes_its_counter_and_releases_it() {
        let (mut driver, stream) = driver_with_stream();
        let stream_registration = driver.trace_identity(stream).unwrap().registration;
        let mut client = driver.connect().unwrap();
        let first = take_counter(&mut driver, &mut client, stream_registration, 0);
        assert_eq!(first.increment(4), Ok(4));
        assert_eq!(
            first.increment(u64::MAX),
            Err(karyos_sys::counters::CounterError::Overflow)
        );
        let (cell, registration) = (first.cell() as u64, first.registration());
        let karyos_sys::counters::CellRead::Allocated {
            metadata, value, ..
        } = client_cell(&driver, cell)
        else {
            panic!("expected an allocated cell");
        };
        assert_eq!((metadata.registration_id, value), (registration, 4));
        assert_eq!(metadata.keys.kind, KIND_CLIENT);
        assert_eq!(metadata.keys.stream, stream_registration);
        // `release` queues it; the next poll sends it and the driver frees
        // the cell. The conductor reports nothing for it.
        first.release();
        let mut done = Vec::new();
        let _ = client.poll(usize::MAX, |completion| done.push(completion));
        let _ = driver.do_work().unwrap();
        let _ = client.poll(usize::MAX, |completion| done.push(completion));
        assert!(done.is_empty());
        assert_eq!(client.pending(), 0);
        assert_eq!(
            client_cell(&driver, cell),
            karyos_sys::counters::CellRead::Free
        );
        // Dropping a handle releases it too.
        let second = take_counter(&mut driver, &mut client, 0, 0);
        second.set(11);
        let cell = second.cell() as u64;
        drop(second);
        let _ = client.poll(usize::MAX, |_| {});
        let _ = driver.do_work().unwrap();
        assert_eq!(
            client_cell(&driver, cell),
            karyos_sys::counters::CellRead::Free
        );
        assert_eq!(driver.client_counters.owned_by(client.owner().client), 0);
    }

    #[test]
    fn a_counter_keyed_to_an_in_process_participant_names_its_lane_and_kind() {
        let (mut driver, stream) = driver_with_stream();
        let stream_registration = driver.trace_identity(stream).unwrap().registration;
        let mut client = driver.connect().unwrap();
        let _ = client.add_publication(KEY, false).unwrap();
        let _ = driver.do_work().unwrap();
        let mut publication = None;
        let _ = client.poll(usize::MAX, |completion| {
            if let Outcome::Publication(handle) = completion.outcome {
                publication = Some(handle);
            }
        });
        let publication = publication.unwrap();
        let registration = publication.origin().unwrap().registration();
        let counter = take_counter(&mut driver, &mut client, stream_registration, registration);
        let karyos_sys::counters::CellRead::Allocated { metadata, .. } =
            client_cell(&driver, counter.cell() as u64)
        else {
            panic!("expected an allocated cell");
        };
        assert_eq!(
            metadata.keys,
            CounterKeys {
                stream: stream_registration,
                lane: 0,
                kind: KIND_PUBLICATION,
                participant: registration,
            }
        );
        drop(publication);
    }

    /// A handle can outlive its conductor: the client's slot goes with the
    /// close flag, but its cells stay charged until the last handle is gone.
    #[test]
    fn a_handle_outliving_its_conductor_keeps_its_cell() {
        let mut driver = driver();
        let mut client = driver.connect().unwrap();
        let id = client.owner().client;
        let kept = take_counter(&mut driver, &mut client, 0, 0);
        let forgotten_release = take_counter(&mut driver, &mut client, 0, 0);
        let (kept_cell, other_cell) = (kept.cell() as u64, forgotten_release.cell() as u64);
        // Released but never sent: the conductor closes first.
        drop(forgotten_release);
        drop(client);
        let _ = driver.do_work().unwrap();
        assert_eq!(driver.clients(), 0);
        assert_eq!(driver.client_counters.owned_by(id), 2);
        // A new allocation takes another cell; the old writer still writes
        // only its own.
        let mut other = driver.connect().unwrap();
        let fresh = take_counter(&mut driver, &mut other, 0, 0);
        assert_ne!(fresh.cell() as u64, kept_cell);
        assert_ne!(fresh.cell() as u64, other_cell);
        assert_eq!(kept.increment(2), Ok(2));
        assert!(matches!(
            client_cell(&driver, kept_cell),
            karyos_sys::counters::CellRead::Allocated { value: 2, .. }
        ));
        drop(kept);
        let _ = driver.do_work().unwrap();
        assert_eq!(driver.client_counters.owned_by(id), 0);
        for cell in [kept_cell, other_cell] {
            assert_eq!(
                client_cell(&driver, cell),
                karyos_sys::counters::CellRead::Free
            );
        }
        drop(fresh);
    }

    #[test]
    fn the_terminal_state_serves_nothing_and_makes_pending_unknown() {
        let mut driver = driver();
        let mut client = driver.connect().unwrap();
        let request = client
            .add_publication(
                StreamKey {
                    stream_id: 2,
                    session_id: 1,
                },
                false,
            )
            .unwrap();
        driver.enter_terminal();
        assert!(driver.is_terminal());
        assert_eq!(driver.do_work().unwrap(), 0);
        let mut done = Vec::new();
        let _ = client.poll(usize::MAX, |completion| done.push(completion));
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].sequence, request);
        assert!(matches!(done[0].outcome, Outcome::Unknown));
        assert!(matches!(driver.connect(), Err(DriverError::Terminal)));
    }

    /// A driver with a stream, a raw client and one subscription of it;
    /// returns the client, its producer and the subscription's
    /// registration.
    fn reporting_client(driver: &mut EmbeddedDriver) -> (u64, RingProducer, u64) {
        let (client, mut producer, _link) = raw_client(driver);
        let mut observer = driver.broadcast.receiver();
        write(
            &mut producer,
            Command::AddSubscription {
                sequence: 1,
                stream: KEY,
                // Required: the stream's slot credit admits one optional
                // reader only, and the driver does not check the role.
                role: SubscriberRole::Required,
            },
        );
        let _ = driver.do_work().unwrap();
        let answered = responses(&mut observer);
        let [Response::SubscriptionReady { registration, .. }] = answered[..] else {
            panic!("expected the subscription, got {answered:?}");
        };
        (client, producer, registration)
    }

    /// A report of `subscription` on the driver's first stream.
    fn reported(driver: &EmbeddedDriver, subscription: u64) -> ReportedLoss {
        ReportedLoss {
            driver: driver.driver_id,
            stream_registration: driver.streams[0].id,
            incarnation: crate::embedded::FIRST_INCARNATION,
            subscription,
            lane: 0,
            from: 4096,
            to: 12_288,
            configured: RejoinPolicyCode::RejoinAtHead,
            applied: RejoinOutcomeCode::ResumedAtHead,
            fallback: None,
        }
    }

    fn losses(driver: &EmbeddedDriver) -> Vec<karyos_sys::diag::LossRecord> {
        let mut records = Vec::new();
        let _ = driver
            .loss_report()
            .scan(&mut 0, |_, record| records.push(record));
        records
    }

    #[test]
    fn a_loss_report_of_a_live_subscription_is_recorded_verified() {
        let mut driver = driver();
        let (client, mut producer, subscription) = reporting_client(&mut driver);
        let mut observer = driver.broadcast.receiver();
        let loss = ReportedLoss {
            lane: 0,
            configured: RejoinPolicyCode::Snapshot,
            applied: RejoinOutcomeCode::SnapshotRebuilt,
            ..reported(&driver, subscription)
        };
        write(&mut producer, Command::ReportLoss { sequence: 2, loss });
        let _ = driver.do_work().unwrap();
        assert_eq!(
            responses(&mut observer),
            vec![Response::OperationSucceeded {
                request: RequestId {
                    client,
                    sequence: 2
                }
            }]
        );
        let [record] = losses(&driver)[..] else {
            panic!("expected one loss record");
        };
        let [high, low] = driver.driver_id;
        assert_eq!(
            karyos_sys::diag::LossRecord { time: 0, ..record },
            karyos_sys::diag::LossRecord {
                time: 0,
                kind: crate::diagnostics::LossKind::Overrun as u16,
                reason: 0,
                lane: 0,
                configured_policy: 2,
                applied_policy: 2,
                flags: 0,
                instance: u128::from(high) << 64 | u128::from(low),
                stream_registration: driver.streams[0].id,
                incarnation: 1,
                stream_id: 2,
                from: 4096,
                to: 12_288,
                participant: subscription,
                client,
            }
        );
        assert!(record.time > 0);
        assert_eq!(counter(&driver, "overruns snapshot"), 1);
        assert_eq!(counter(&driver, "loss reports unverified"), 0);
        assert_eq!(counter(&driver, "clients faulty"), 0);
    }

    #[test]
    fn a_loss_report_of_an_ended_subscription_is_recorded_unverified() {
        let mut driver = driver();
        let (_, mut producer, subscription) = reporting_client(&mut driver);
        let mut observer = driver.broadcast.receiver();
        write(
            &mut producer,
            Command::RemoveSubscription {
                sequence: 2,
                registration: subscription,
            },
        );
        let loss = reported(&driver, subscription);
        write(&mut producer, Command::ReportLoss { sequence: 3, loss });
        let _ = driver.do_work().unwrap();
        let _ = driver.do_work().unwrap();
        assert_eq!(responses(&mut observer).len(), 2);
        let [record] = losses(&driver)[..] else {
            panic!("expected one loss record");
        };
        assert_eq!(record.flags, crate::diagnostics::LOSS_UNVERIFIED);
        assert_eq!(record.participant, subscription);
        assert_eq!(counter(&driver, "loss reports unverified"), 1);
        assert_eq!(counter(&driver, "overruns rejoin at head"), 1);
        assert_eq!(counter(&driver, "clients faulty"), 0);
    }

    #[test]
    fn a_loss_report_of_a_foreign_or_never_issued_identity_is_a_violation() {
        type Case = fn(&mut ReportedLoss, u64);
        let cases: [(&str, Case); 9] = [
            ("another driver instance", |loss, _| loss.driver[1] ^= 1),
            ("subscription 0", |loss, _| loss.subscription = 0),
            ("subscription never issued", |loss, next| {
                loss.subscription = next;
            }),
            ("stream 0", |loss, _| loss.stream_registration = 0),
            ("stream never issued", |loss, _| {
                loss.stream_registration += 1;
            }),
            ("another incarnation", |loss, _| loss.incarnation = 2),
            ("another stream", |loss, _| loss.stream_registration = 1),
            // Patched below: another client's live subscription, and this
            // client's publication.
            ("another client's subscription", |_, _| {}),
            ("a publication", |_, _| {}),
        ];
        for (name, case) in cases {
            let mut driver = driver();
            // A second stream, issued and live, before the reported one.
            let mut other = self::driver();
            let mut moved = other.streams.pop().unwrap();
            moved.id = driver.next_stream;
            moved.stream_id = 3;
            driver.next_stream += 1;
            driver.streams.insert(0, moved);
            let stream = driver.streams[1].id;
            let (owner, _owner_producer, foreign) = reporting_client(&mut driver);
            let (sender, mut producer, subscription) = reporting_client(&mut driver);
            let mut loss = ReportedLoss {
                stream_registration: stream,
                ..reported(&driver, subscription)
            };
            case(&mut loss, driver.next_registration);
            if name == "another stream" {
                loss.stream_registration = driver.streams[0].id;
            }
            if name == "another client's subscription" {
                loss.subscription = foreign;
                assert_ne!(owner, sender);
            }
            if name == "a publication" {
                let mut observer = driver.broadcast.receiver();
                write(
                    &mut producer,
                    Command::AddPublication {
                        sequence: 5,
                        stream: KEY,
                        allow_unconnected: true,
                    },
                );
                let _ = driver.do_work().unwrap();
                let [Response::PublicationReady { registration, .. }] =
                    responses(&mut observer)[..]
                else {
                    panic!("expected the publication");
                };
                loss.subscription = registration;
            }
            let mut observer = driver.broadcast.receiver();
            let faulty = counter(&driver, "clients faulty");
            write(&mut producer, Command::ReportLoss { sequence: 9, loss });
            let _ = driver.do_work().unwrap();
            // No response, the sender retired as faulty, nothing recorded.
            assert_eq!(responses(&mut observer), Vec::new(), "{name}");
            assert_eq!(counter(&driver, "clients faulty"), faulty + 1, "{name}");
            let slot = driver
                .clients
                .iter()
                .find(|slot| slot.id == sender)
                .unwrap();
            assert!(slot.consumer.is_none(), "{name}");
            assert_eq!(losses(&driver), Vec::new(), "{name}");
            for label in [
                "overruns rejoin at head",
                "loss reports unverified",
                "replay fallbacks",
            ] {
                assert_eq!(counter(&driver, label), 0, "{name}: {label}");
            }
            // The violation is in the error log under the sender and the
            // command type.
            let mut violations = Vec::new();
            let _ = driver.error_log().scan(&mut 0, |record| {
                if record.code == crate::diagnostics::ErrorCode::ClientProtocolViolation as u32 {
                    violations.push(record.key);
                }
            });
            assert_eq!(violations, vec![[sender, 0x08]], "{name}");
        }
    }

    #[test]
    fn overruns_are_counted_by_the_policy_applied() {
        let mut driver = driver();
        let (_, mut producer, subscription) = reporting_client(&mut driver);
        let replay = Some(karyos_protocol::cnc::FallbackReasonCode::NoArchive);
        let reports = [
            (
                RejoinPolicyCode::RejoinAtHead,
                RejoinOutcomeCode::ResumedAtHead,
                None,
            ),
            (
                RejoinPolicyCode::Snapshot,
                RejoinOutcomeCode::SnapshotRebuilt,
                None,
            ),
            (
                RejoinPolicyCode::Snapshot,
                RejoinOutcomeCode::SnapshotFailed,
                None,
            ),
            (RejoinPolicyCode::Close, RejoinOutcomeCode::Closed, None),
            (
                RejoinPolicyCode::Replay,
                RejoinOutcomeCode::ResumedAtHead,
                replay,
            ),
            (
                RejoinPolicyCode::Replay,
                RejoinOutcomeCode::SnapshotFailed,
                replay,
            ),
            (RejoinPolicyCode::Replay, RejoinOutcomeCode::Closed, replay),
        ];
        for (sequence, (configured, applied, fallback)) in (2..).zip(reports) {
            let loss = ReportedLoss {
                configured,
                applied,
                fallback,
                ..reported(&driver, subscription)
            };
            write(&mut producer, Command::ReportLoss { sequence, loss });
            let _ = driver.do_work().unwrap();
        }
        assert_eq!(counter(&driver, "overruns rejoin at head"), 2);
        assert_eq!(counter(&driver, "overruns snapshot"), 3);
        assert_eq!(counter(&driver, "overruns close"), 2);
        assert_eq!(counter(&driver, "replay fallbacks"), 3);
        assert_eq!(counter(&driver, "loss reports unverified"), 0);
        let records = losses(&driver);
        assert_eq!(records.len(), 7);
        // A fallback keeps its reason and its secondary's outcome.
        assert_eq!(
            records
                .iter()
                .map(|r| (r.configured_policy, r.applied_policy, r.reason))
                .collect::<Vec<_>>(),
            vec![
                (1, 1, 0),
                (2, 2, 0),
                (2, 3, 0),
                (3, 4, 0),
                (4, 1, 1),
                (4, 3, 1),
                (4, 4, 1)
            ]
        );
    }
}
