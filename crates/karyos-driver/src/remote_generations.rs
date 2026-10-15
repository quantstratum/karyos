// SPDX-License-Identifier: Apache-2.0

//! A cutover with remote participants (`quantstratum-docs:
//! karyos/design/ipc-data-path.md`, Generations across processes).
//!
//! When a cutover opens, every remote participant of the predecessor whose
//! grant was sent gets its successor participant reserved under a new
//! grant (`Held`, a new export and a new key), exactly as for a command,
//! and the client is told with `SuccessorReady`. The client fetches and
//! prepares it on its control path and adopts it when its handle reaches
//! the seal. A successor grant still unadopted at the cutover deadline is
//! fenced: adoption and fence are one compare-exchange each on the
//! registration word, so exactly one wins. A fenced grant never sent ends
//! at once; a sent one stays charged until its `Detach` or the exit proof.
//! A predecessor is retained while any remote grant of its generation is
//! charged.

use karyos_protocol::cnc::{Event as DriverEvent, StreamKey};
use karyos_sys::log_buffer::LossPolicy;
use karyos_sys::registration;

use crate::embedded::{EmbeddedDriver, StreamTerms};
use crate::ledger::{Grant, GrantState, Participant};

impl<T: StreamTerms> EmbeddedDriver<T> {
    /// Reserves the successor of every sent remote grant of `stream`'s
    /// generation `predecessor`, after its cutover opened at `now`.
    pub(crate) fn open_remote_successors(&mut self, stream: u64, predecessor: u32, now: u64) {
        let movers: Vec<(u64, Grant)> = self
            .clients
            .iter()
            .filter_map(|slot| slot.ledger.as_ref().map(|ledger| (slot.id(), ledger)))
            .flat_map(|(client, ledger)| {
                ledger
                    .grants()
                    .iter()
                    .filter(|grant| {
                        grant.stream == stream && grant.generation == predecessor && grant.sent
                    })
                    .map(move |grant| (client, *grant))
            })
            .collect();
        let deadline = self.config.cutover_deadline;
        for (client, old) in movers {
            let reserved = self.reserve_successor(stream, &old);
            let Some(target) = self.streams.iter().find(|s| s.id == stream) else {
                return;
            };
            let key = StreamKey {
                stream_id: target.stream_id,
                session_id: target.session_id,
            };
            let (base, generation) = (target.base, target.generation.get());
            match reserved {
                Some((export, participant, handover)) => {
                    if let Some(ledger) = self.ledger_mut(client) {
                        ledger.push(Grant {
                            export,
                            registration: old.registration,
                            key: handover,
                            stream,
                            participant,
                            state: GrantState::Held,
                            sent: false,
                            generation,
                            fence_at: Some(now.saturating_add(deadline)),
                        });
                    }
                    self.counters.add(crate::counters::Event::GrantsReserved, 1);
                    self.emit(&DriverEvent::SuccessorReady {
                        stream: key,
                        registration: old.registration,
                        key: handover,
                        base,
                        generation: u64::from(generation),
                    });
                }
                // No successor participant could be reserved: the handle
                // cannot move, as if fenced at once.
                None => self.emit(&DriverEvent::Fenced {
                    stream: key,
                    registration: old.registration,
                }),
            }
        }
    }

    /// Reserves `old`'s participant in `stream`'s current mapping under a
    /// new export and a new hand-over key.
    fn reserve_successor(&mut self, stream: u64, old: &Grant) -> Option<(u64, Participant, u64)> {
        let export = self.next_export;
        let handover = self.next_registration;
        if !registration::valid_export(export) {
            return None;
        }
        let next_export = export.checked_add(1)?;
        let next_handover = handover.checked_add(1)?;
        let target = self.streams.iter_mut().find(|s| s.id == stream)?;
        let participant = match old.participant {
            Participant::Exclusive => {
                if !target.conductor.register_publication(export).ok()? {
                    return None;
                }
                Participant::Exclusive
            }
            Participant::Concurrent { .. } => {
                let slot = target
                    .conductor
                    .register_concurrent_publication(export)
                    .ok()??;
                Participant::Concurrent { slot }
            }
            Participant::Subscriber { role, .. } => {
                let reserve = role == karyos_sys::log_buffer::Role::Required
                    && target.policy == LossPolicy::Continue;
                let cell = target
                    .conductor
                    .register_subscriber_with(role, reserve, export)
                    .ok()?;
                Participant::Subscriber { cell, role }
            }
        };
        self.next_export = next_export;
        self.next_registration = next_handover;
        Some((export, participant, handover))
    }

    /// Whether a successor grant waits for its fence.
    pub(crate) fn fences_pending(&self) -> bool {
        self.clients.iter().any(|slot| {
            slot.ledger
                .as_ref()
                .is_some_and(|ledger| ledger.grants().iter().any(|g| g.fence_at.is_some()))
        })
    }

    /// Fences every successor grant whose deadline passed at `now` and
    /// that its participant has not adopted. A fenced grant never sent
    /// ends at once.
    pub(crate) fn fence_late_successors(&mut self, now: u64) {
        let late: Vec<(u64, Grant)> = self
            .clients
            .iter()
            .filter_map(|slot| slot.ledger.as_ref().map(|ledger| (slot.id(), ledger)))
            .flat_map(|(client, ledger)| {
                ledger
                    .grants()
                    .iter()
                    .filter(|grant| grant.fence_at.is_some_and(|at| now >= at))
                    .map(move |grant| (client, *grant))
            })
            .collect();
        for (client, grant) in late {
            let fenced = self.fence_grant(&grant);
            let Some(ledger) = self.ledger_mut(client) else {
                continue;
            };
            let unsent = fenced && !grant.sent;
            if let Some(entry) = ledger
                .grants_mut()
                .iter_mut()
                .find(|entry| entry.export == grant.export)
            {
                entry.fence_at = None;
            }
            if unsent {
                ledger
                    .grants_mut()
                    .retain(|entry| entry.export != grant.export);
            }
            if fenced {
                if let Some(target) = self.streams.iter().find(|s| s.id == grant.stream) {
                    let key = StreamKey {
                        stream_id: target.stream_id,
                        session_id: target.session_id,
                    };
                    self.emit(&DriverEvent::Fenced {
                        stream: key,
                        registration: grant.registration,
                    });
                }
                self.counters.add(crate::counters::Event::GrantsFenced, 1);
            }
            if unsent {
                self.end_grant(&grant);
            }
        }
    }

    /// Fences `grant` in its stream's mapping of its generation; returns
    /// whether the fence won against the adoption.
    fn fence_grant(&mut self, grant: &Grant) -> bool {
        let Some(stream) = self.streams.iter_mut().find(|s| s.id == grant.stream) else {
            return false;
        };
        let conductor = if stream.generation.get() == grant.generation {
            &mut stream.conductor
        } else if let Some(retained) = stream
            .retained
            .iter_mut()
            .find(|retained| retained.generation.get() == grant.generation)
        {
            &mut retained.conductor
        } else {
            return false;
        };
        match grant.participant {
            Participant::Subscriber { cell, .. } => conductor.fence_subscriber(cell, grant.export),
            Participant::Exclusive => conductor.fence_publication(grant.export),
            Participant::Concurrent { slot } => {
                conductor.fence_concurrent_publication(slot, grant.export)
            }
        }
    }

    /// The `(stream, generation)` pairs some remote grant still charges.
    pub(crate) fn charged_generations(&self) -> Vec<(u64, u32)> {
        let mut charged: Vec<(u64, u32)> = self
            .clients
            .iter()
            .filter_map(|slot| slot.ledger.as_ref())
            .flat_map(|ledger| ledger.grants().iter().map(|g| (g.stream, g.generation)))
            .collect();
        charged.sort_unstable();
        charged.dedup();
        charged
    }
}
