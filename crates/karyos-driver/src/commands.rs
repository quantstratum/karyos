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

use std::sync::Arc;

use karyos_client::ClientConductor;
use std::collections::VecDeque;

use karyos_client::link::{Capability, ClientLink, HandOverEntry, Lease, LeaseEnd, Owner};
use karyos_protocol::cnc::{
    Command, ErrorCode, MAX_COMMAND_LENGTH, MAX_RESPONSE_LENGTH, RequestId, Response, StreamKey,
    SubscriberRole,
};
use karyos_sys::command_ring::{RingConsumer, command_ring};
use karyos_sys::log_buffer::Role;

use crate::embedded::EmbeddedDriver;
use crate::error::DriverError;

/// A client's registration in the driver.
#[derive(Debug)]
pub(crate) struct ClientSlot {
    id: u64,
    /// `None` once the client is retired; the slot itself stays until the
    /// client's producer is known to be detached (its close flag).
    consumer: Option<RingConsumer>,
    link: Arc<ClientLink>,
    /// Registrations of this client forgotten because their capability
    /// ended, so a `Remove` already queued for one still succeeds. Bounded:
    /// the oldest is evicted first.
    ended: VecDeque<u64>,
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
    kind: Kind,
    end: Arc<LeaseEnd>,
}

impl EmbeddedDriver {
    /// Admits a client (control path: allocates its command ring and
    /// broadcast receiver) and returns its conductor.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError::TooManyClients`] at `max_clients`,
    /// [`DriverError::ClientIdsExhausted`], and [`DriverError::Terminal`]
    /// after the driver entered its terminal state.
    pub fn connect(&mut self) -> Result<ClientConductor, DriverError> {
        if self.terminal {
            return Err(DriverError::Terminal);
        }
        if self.clients.len() >= self.config.max_clients {
            return Err(DriverError::TooManyClients);
        }
        let id = self.next_client;
        let next = id.checked_add(1).ok_or(DriverError::ClientIdsExhausted)?;
        let (producer, consumer) =
            command_ring(self.config.ring_capacity).map_err(|_| DriverError::InvalidConfig)?;
        let link = Arc::new(ClientLink::new());
        let receiver = self.broadcast.receiver();
        self.next_client = next;
        self.clients.push(ClientSlot {
            id,
            consumer: Some(consumer),
            link: Arc::clone(&link),
            ended: VecDeque::new(),
        });
        Ok(ClientConductor::new(
            Owner {
                driver: self.id,
                client: id,
            },
            producer,
            receiver,
            link,
            self.config.max_pending_per_client,
        ))
    }

    /// Clients currently admitted, including retired ones whose producer has
    /// not yet detached.
    #[must_use]
    pub fn clients(&self) -> usize {
        self.clients.len()
    }

    /// Releases every client whose close flag is set: its ring, its
    /// admission slot, its untaken hand-over entries and its registrations.
    /// Handles it still holds keep their leases.
    pub(crate) fn retire_closed_clients(&mut self) {
        let mut index = 0;
        while let Some(slot) = self.clients.get(index) {
            if slot.link.is_closed() {
                let slot = self.clients.swap_remove(index);
                slot.link.drop_all(false);
                self.registrations
                    .retain(|registration| registration.client != slot.id);
            } else {
                index += 1;
            }
        }
    }

    /// Stops serving a faulty client: discards its ring and untaken
    /// hand-over entries and its registrations, but keeps its admission slot
    /// until its producer is known to be detached.
    fn retire_faulty(&mut self, index: usize) {
        if let Some(slot) = self.clients.get_mut(index) {
            // Publish the closure to the producer before discarding the
            // consumer.
            if let Some(mut consumer) = slot.consumer.take() {
                consumer.close();
            }
            slot.link.drop_all(false);
            let client = slot.id;
            self.registrations
                .retain(|registration| registration.client != client);
        }
    }

    /// Forgets registrations whose capability ended (its handle or held
    /// entry was dropped), so dropping handles without `remove` cannot
    /// accumulate registration records.
    pub(crate) fn sweep_ended_registrations(&mut self) {
        let limit = self.config.max_pending_per_client;
        let clients = &mut self.clients;
        self.registrations.retain(|registration| {
            if !registration.end.ended() {
                return true;
            }
            if let Some(slot) = clients
                .iter_mut()
                .find(|slot| slot.id == registration.client)
            {
                if slot.ended.len() >= limit {
                    slot.ended.pop_front();
                }
                slot.ended.push_back(registration.id);
            }
            false
        });
    }

    pub(crate) fn enter_terminal(&mut self) {
        self.terminal = true;
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
                self.retire_faulty(index);
                continue;
            };
            let response = self.execute(client, &link, command);
            let mut out = [0u8; MAX_RESPONSE_LENGTH];
            let sent = response
                .encode(&mut out)
                .ok()
                .and_then(|length| out.get(..length))
                .map(|payload| self.broadcast.transmit(response.type_id(), payload));
            if !matches!(sent, Some(Ok(_))) {
                // A broken invariant after the room check.
                self.enter_terminal();
            }
        }
        served
    }

    fn find_stream(&self, stream: StreamKey) -> Option<usize> {
        self.streams
            .iter()
            .position(|s| s.stream_id == stream.stream_id && s.session_id == stream.session_id)
    }

    fn held_total(&self) -> usize {
        self.clients.iter().map(|slot| slot.link.held()).sum()
    }

    /// Preflight, then effect. Returns the single response.
    fn execute(&mut self, client: u64, link: &Arc<ClientLink>, command: Command) -> Response {
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
            Command::AddPublication { stream, .. } | Command::AddSubscription { stream, .. } => {
                let detail = u64::from(stream.stream_id.cast_unsigned());
                let Some(index) = self.find_stream(stream) else {
                    return refuse(ErrorCode::UnknownStream, detail);
                };
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
                let (capability, kind) = match command {
                    Command::AddPublication {
                        allow_unconnected, ..
                    } => match target.buffer.publication_owned() {
                        Ok(Some(inner)) => (
                            Capability::Publication {
                                inner,
                                allow_unconnected,
                            },
                            Kind::Publication,
                        ),
                        Ok(None) => return refuse(ErrorCode::PublicationTaken, detail),
                        Err(_) => return refuse(ErrorCode::ResourcesUnavailable, detail),
                    },
                    _ => {
                        let role = match command {
                            Command::AddSubscription {
                                role: SubscriberRole::Optional,
                                ..
                            } => Role::Optional,
                            _ => Role::Required,
                        };
                        match target.conductor.subscribe(role) {
                            Ok(inner) => (Capability::Subscription(inner), Kind::Subscription),
                            Err(_) => return refuse(ErrorCode::ResourcesUnavailable, detail),
                        }
                    }
                };
                // Effect: everything below cannot fail.
                let end = Arc::new(LeaseEnd::default());
                let lease = Lease::acquire(&target.leases, &end);
                self.next_registration = next;
                link.hold(HandOverEntry {
                    key: registration,
                    capability,
                    lease,
                });
                self.registrations.push(Registration {
                    id: registration,
                    client,
                    kind,
                    end,
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
                    // Already forgotten because its capability ended: the
                    // client drops the handle right after writing Remove.
                    let forgotten = self
                        .clients
                        .iter_mut()
                        .find(|slot| slot.id == client)
                        .and_then(|slot| {
                            let index = slot.ended.iter().position(|&id| id == registration)?;
                            slot.ended.remove(index)
                        });
                    return match forgotten {
                        Some(_) => Response::OperationSucceeded { request },
                        None => refuse(ErrorCode::UnknownRegistration, registration),
                    };
                };
                self.registrations.swap_remove(index);
                // Drops a capability still held; a taken one was dropped by
                // the client's remove.
                link.drop_entry(registration);
                Response::OperationSucceeded { request }
            }
        }
    }
}

impl Drop for EmbeddedDriver {
    fn drop(&mut self) {
        self.broadcast.close();
        for slot in &self.clients {
            slot.link.drop_all(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use karyos_client::Outcome;
    use karyos_protocol::cnc::Response;
    use karyos_sys::broadcast::Received;
    use karyos_sys::command_ring::RingProducer;
    use karyos_sys::frame::Lane;
    use karyos_sys::log_buffer::LogBufferConfig;
    use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
    use karyos_sys::term::TermId;

    use super::*;
    use crate::embedded::StreamConfig;

    fn driver() -> EmbeddedDriver {
        let mut driver = EmbeddedDriver::new().unwrap();
        let _ = driver
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
                },
                allow_unconnected: false,
            })
            .unwrap();
        driver
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
            ended: VecDeque::new(),
        });
        (id, producer, link)
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
        let registration = handle.origin().unwrap().registration;
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
        assert!(driver.clients[0].ended.len() <= 1);
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
}
