// SPDX-License-Identifier: Apache-2.0

//! Network channels a client names by URI (wiring note W5b; coordinator
//! ACS 16021, 16027 and 16077): the driver side of `AddNetworkPublication`
//! and `AddNetworkSubscription`.
//!
//! - **Parse.** The driver parses the URI (`ChannelConfig::parse`); one
//!   that does not parse is refused with `InvalidChannel`, its detail the
//!   parse error's code.
//! - **Publication.** `karyos:ipc` resolves the stream by its id alone, as
//!   `AddPublication` does (two sessions of the id are ambiguous:
//!   `UnknownStream`). `karyos:udp` creates an aggregate from the
//!   network's stream defaults and the URI's `term-length`, `mtu` and
//!   `lanes`, under a session id the driver draws, sends it (W2), and
//!   grants lane 0 as `AddPublication` does.
//! - **Subscription.** `karyos:udp` subscribes the stream (W3) and answers
//!   `NetworkSubscriptionReady`; each image is then announced with
//!   `ImageAvailable`, and the client attaches with `AddSubscription`
//!   naming its alias. `karyos:ipc` is `AddSubscription`'s, refused here.
//! - **Ownership.** What a client creates is owned by its registration:
//!   one reconcile pass, run every cycle, removes a network publication
//!   whose registration ended (removed, dropped or its client gone) and a
//!   network subscription whose client is no longer served. Nothing a
//!   client created outlives it.
//! - **Shared terms.** A driver admitting other processes refuses `udp`
//!   with `UnsupportedChannel` (D3, SPEC §18).

use std::sync::Arc;

use karyos_client::link::ClientLink;
use karyos_protocol::channel::{ChannelConfig, CommonConfig, Media, UdpConfig};
use karyos_protocol::cnc::{
    Command, ErrorCode, Event as DriverEvent, RequestId, Response, StreamKey,
};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, LossPolicy, PublicationMode};
use karyos_sys::sizing::TermLength;
use karyos_sys::term::TermId;

use super::{NetworkStreamDefaults, NetworkSubscription};
use crate::agents::EndpointId;
use crate::embedded::{
    AggregateConfig, AggregateHandle, EmbeddedDriver, StreamConfig, StreamTerms,
};
use crate::error::DriverError;

/// What a client created by URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Owned {
    /// A network publication: the aggregate its registration's grant is
    /// lane 0 of.
    Publication(AggregateHandle),
    /// A network subscription, and whether its images installed before it
    /// were announced.
    Subscription {
        handle: NetworkSubscription,
        announced: bool,
    },
}

/// A network resource a client owns through a registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OwnedNetwork {
    pub(crate) registration: u64,
    pub(crate) client: u64,
    pub(crate) owned: Owned,
}

/// The refusal code of a network operation's error.
fn refusal(error: DriverError) -> ErrorCode {
    match error {
        DriverError::NetworkUnavailable | DriverError::UnsupportedChannel => {
            ErrorCode::UnsupportedChannel
        }
        DriverError::StreamIdsExhausted | DriverError::ExportIdsExhausted => {
            ErrorCode::IdentitiesExhausted
        }
        DriverError::ReliabilityMismatch => ErrorCode::ReliabilityMismatch,
        DriverError::ReceiverIdentityMismatch => ErrorCode::ReceiverIdentityMismatch,
        _ => ErrorCode::ResourcesUnavailable,
    }
}

/// The aggregate of a network publication of `stream_id` under
/// `session_id`, from `defaults` and the URI's `common` parameters.
fn aggregate(
    defaults: &NetworkStreamDefaults,
    common: &CommonConfig,
    stream_id: i32,
    session_id: i32,
    allow_unconnected: bool,
) -> Result<AggregateConfig, DriverError> {
    let term_length = match common.term_length {
        Some(term_length) => term_length,
        None => {
            TermLength::try_new(defaults.term_length).map_err(|_| DriverError::InvalidConfig)?
        }
    };
    let mtu = common.mtu.unwrap_or(defaults.mtu);
    let lanes = common.lanes.unwrap_or(defaults.lanes);
    let quantum = u64::from(mtu)
        .checked_mul(4)
        .ok_or(DriverError::InvalidConfig)?;
    Ok(AggregateConfig {
        stream: StreamConfig {
            buffer: LogBufferConfig {
                term_length,
                spare_slots: defaults.spare_slots,
                max_subscribers: defaults.max_subscribers,
                mtu,
                max_reserved: term_length.get() / 8,
                initial_term_id: TermId::new(0),
                lane: Lane::ZERO,
                session_id,
                stream_id,
                claim_deadline: defaults.claim_deadline,
                publication: PublicationMode::Exclusive,
                schedule_capacity: 0,
            },
            allow_unconnected,
            on_required_loss: LossPolicy::Hold,
            conflation: None,
        },
        quanta: vec![quantum; usize::from(lanes)],
    })
}

impl<T: StreamTerms> EmbeddedDriver<T> {
    /// Serves `AddNetworkPublication` (W5b).
    pub(crate) fn serve_network_publication(
        &mut self,
        client: u64,
        link: &Arc<ClientLink<T>>,
        request: RequestId,
        stream_id: i32,
        allow_unconnected: bool,
        uri: &str,
    ) -> Response {
        let refuse = |code: ErrorCode, detail: u64| Response::Error {
            request,
            code,
            detail,
        };
        let detail = u64::from(stream_id.cast_unsigned());
        let channel = match ChannelConfig::parse(uri) {
            Ok(channel) => channel,
            Err(error) => return refuse(ErrorCode::InvalidChannel, error.code()),
        };
        let grant = |driver: &mut Self, stream: StreamKey| {
            driver.execute(
                client,
                link,
                Command::AddPublication {
                    sequence: request.sequence,
                    stream,
                    lane: Lane::ZERO,
                    allow_unconnected,
                },
            )
        };
        let udp = match channel.media {
            Media::Ipc => {
                let mut sessions = self
                    .streams
                    .iter()
                    .filter(|stream| !stream.retiring && stream.stream_id == stream_id)
                    .map(|stream| stream.session_id);
                let (Some(session_id), None) = (sessions.next(), sessions.next()) else {
                    return refuse(ErrorCode::UnknownStream, detail);
                };
                return grant(
                    self,
                    StreamKey {
                        stream_id,
                        session_id,
                    },
                );
            }
            Media::Udp(udp) => udp,
        };
        let Some(defaults) = self.config.network.map(|network| network.stream_defaults) else {
            return refuse(ErrorCode::UnsupportedChannel, detail);
        };
        let Some(session_id) = self.draw_session(stream_id) else {
            return refuse(ErrorCode::IdentitiesExhausted, detail);
        };
        let config = match aggregate(
            &defaults,
            &channel.common,
            stream_id,
            session_id,
            allow_unconnected,
        ) {
            Ok(config) => config,
            Err(error) => return refuse(refusal(error), detail),
        };
        let handle =
            match <T as crate::embedded::sealed::Create>::network_publication(self, config, &udp) {
                Ok(handle) => handle,
                Err(error) => return refuse(refusal(error), detail),
            };
        let response = grant(
            self,
            StreamKey {
                stream_id,
                session_id,
            },
        );
        match response {
            Response::PublicationReady { registration, .. } => {
                self.net_owned.push(OwnedNetwork {
                    registration,
                    client,
                    owned: Owned::Publication(handle),
                });
            }
            // Nothing was granted: nothing may stay.
            _ => {
                let _ = self.remove_aggregate(&handle);
            }
        }
        response
    }

    /// A session id for a new publication of `stream_id`, nonzero and used
    /// by no stream of that id; `None` when the random source fails or
    /// every draw collides.
    fn draw_session(&self, stream_id: i32) -> Option<i32> {
        for _ in 0..16 {
            let mut word = [0u64; 1];
            karyos_sys::random::fill_u64s(&mut word).ok()?;
            let session_id = u32::try_from(word[0] & u64::from(u32::MAX))
                .ok()?
                .cast_signed();
            if session_id != 0
                && !self
                    .streams
                    .iter()
                    .any(|stream| (stream.stream_id, stream.session_id) == (stream_id, session_id))
            {
                return Some(session_id);
            }
        }
        None
    }

    /// Serves `AddNetworkSubscription` (W5b).
    pub(crate) fn serve_network_subscription(
        &mut self,
        client: u64,
        request: RequestId,
        stream_id: i32,
        uri: &str,
    ) -> Response {
        let refuse = |code: ErrorCode, detail: u64| Response::Error {
            request,
            code,
            detail,
        };
        let detail = u64::from(stream_id.cast_unsigned());
        let udp = match ChannelConfig::parse(uri) {
            Err(error) => return refuse(ErrorCode::InvalidChannel, error.code()),
            // An IPC subscription is `AddSubscription`'s.
            Ok(ChannelConfig {
                media: Media::Ipc, ..
            }) => return refuse(ErrorCode::UnsupportedChannel, detail),
            Ok(ChannelConfig {
                media: Media::Udp(udp),
                ..
            }) => udp,
        };
        let registration = self.next_registration;
        let Some(next) = registration.checked_add(1) else {
            return refuse(ErrorCode::IdentitiesExhausted, 0);
        };
        let handle = match <T as crate::embedded::sealed::Create>::network_subscription(
            self, stream_id, &udp,
        ) {
            Ok(handle) => handle,
            Err(error) => return refuse(refusal(error), detail),
        };
        self.next_registration = next;
        self.net_owned.push(OwnedNetwork {
            registration,
            client,
            owned: Owned::Subscription {
                handle,
                announced: false,
            },
        });
        Response::NetworkSubscriptionReady {
            request,
            registration,
        }
    }

    /// Removes the network subscription `registration` of `client`;
    /// `false` when it is not one.
    pub(crate) fn remove_owned_subscription(&mut self, client: u64, registration: u64) -> bool {
        let Some(index) = self.net_owned.iter().position(|owned| {
            owned.registration == registration
                && owned.client == client
                && matches!(owned.owned, Owned::Subscription { .. })
        }) else {
            return false;
        };
        let owned = self.net_owned.swap_remove(index);
        self.release_owned(owned);
        true
    }

    /// Removes what the clients' ended registrations owned (W5b B3): a
    /// network publication whose registration is gone, a network
    /// subscription whose client is no longer served. Run every cycle,
    /// after registrations are retired and swept.
    pub(crate) fn reconcile_network_owned(&mut self) {
        let registrations = &self.registrations;
        let clients = &self.clients;
        let ended: Vec<OwnedNetwork> = self
            .net_owned
            .extract_if(.., |owned| match owned.owned {
                Owned::Publication(_) => !registrations
                    .iter()
                    .any(|registration| registration.id() == owned.registration),
                Owned::Subscription { .. } => !clients
                    .iter()
                    .any(|slot| slot.id() == owned.client && slot.serving()),
            })
            .collect();
        for owned in ended {
            self.release_owned(owned);
        }
    }

    /// Releases one owned resource.
    fn release_owned(&mut self, owned: OwnedNetwork) {
        match owned.owned {
            Owned::Publication(handle) => {
                let _ = self.remove_aggregate(&handle);
            }
            Owned::Subscription { handle, .. } => {
                if let Some(net) = &mut self.net {
                    net.remove_subscription_later(handle);
                }
            }
        }
    }

    /// Announces the image `handle`, which arrived on `endpoint`, to every
    /// network subscription of its stream there: `ImageAvailable`, or
    /// `ImageUnavailable` once it retires.
    pub(crate) fn announce_image(
        &mut self,
        endpoint: EndpointId,
        handle: &AggregateHandle,
        available: bool,
    ) {
        let Some(stream) = self
            .streams
            .iter()
            .find(|stream| stream.id == handle.registration())
            .map(|stream| StreamKey {
                stream_id: stream.stream_id,
                session_id: stream.session_id,
            })
        else {
            return;
        };
        let subscribers: Vec<u64> = self
            .net_owned
            .iter()
            .filter_map(|owned| match owned.owned {
                Owned::Subscription { handle, .. }
                    if handle.endpoint() == endpoint && handle.stream_id() == stream.stream_id =>
                {
                    Some(owned.registration)
                }
                _ => None,
            })
            .collect();
        for registration in subscribers {
            self.emit(&if available {
                DriverEvent::ImageAvailable {
                    stream,
                    registration,
                }
            } else {
                DriverEvent::ImageUnavailable {
                    stream,
                    registration,
                }
            });
        }
    }

    /// Announces the images installed before a network subscription was
    /// created, once, after its `NetworkSubscriptionReady` went out.
    pub(crate) fn announce_existing_images(&mut self) {
        let pending: Vec<(usize, NetworkSubscription, u64)> = self
            .net_owned
            .iter()
            .enumerate()
            .filter_map(|(index, owned)| match owned.owned {
                Owned::Subscription {
                    handle,
                    announced: false,
                } => Some((index, handle, owned.registration)),
                _ => None,
            })
            .collect();
        if pending.is_empty() {
            return;
        }
        let images: Vec<(EndpointId, AggregateHandle)> = self
            .net
            .as_ref()
            .map(|net| net.exposed_images().collect())
            .unwrap_or_default();
        for (index, subscription, registration) in pending {
            for (endpoint, handle) in &images {
                let stream = self
                    .streams
                    .iter()
                    .find(|stream| stream.id == handle.registration() && !stream.retiring)
                    .map(|stream| StreamKey {
                        stream_id: stream.stream_id,
                        session_id: stream.session_id,
                    });
                if let Some(stream) = stream
                    && *endpoint == subscription.endpoint()
                    && stream.stream_id == subscription.stream_id()
                {
                    self.emit(&DriverEvent::ImageAvailable {
                        stream,
                        registration,
                    });
                }
            }
            if let Some(OwnedNetwork {
                owned: Owned::Subscription { announced, .. },
                ..
            }) = self.net_owned.get_mut(index)
            {
                *announced = true;
            }
        }
    }
}

/// The heap-terms side of the network operations a client's URI asks for.
impl EmbeddedDriver<karyos_sys::term_bytes::HeapTerms> {
    pub(crate) fn client_network_publication(
        &mut self,
        config: AggregateConfig,
        channel: &UdpConfig,
    ) -> Result<AggregateHandle, DriverError> {
        self.add_network_publication(config, channel)
    }

    pub(crate) fn client_network_subscription(
        &mut self,
        stream_id: i32,
        channel: &UdpConfig,
    ) -> Result<NetworkSubscription, DriverError> {
        self.add_network_subscription(stream_id, channel)
    }
}

#[cfg(test)]
mod tests;
