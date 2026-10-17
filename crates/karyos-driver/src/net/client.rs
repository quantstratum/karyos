// SPDX-License-Identifier: Apache-2.0

//! Network channels a client names by URI (wiring note W5b; coordinator
//! ACS 16021, 16027 and 16077): the driver side of `AddNetworkPublication`
//! and `AddNetworkSubscription`.
//!
//! - **Parse.** The driver parses the URI (`ChannelConfig::parse`); one
//!   that does not parse is refused with `InvalidChannel`, its detail the
//!   parse error's code.
//! - **Publication.** `karyos:ipc` resolves the stream by its id alone:
//!   the one active aggregate of the id, its lanes counted once, that is
//!   not the network's (a network publication or an image); none or two
//!   is `UnknownStream`. `karyos:udp` creates an aggregate from the
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
//!   client created outlives it. A client owns at most
//!   `NetworkConfig::max_owned_per_client`; another is refused with
//!   `ResourcesUnavailable` and counted.
//! - **Images.** A subscription learns of the images already there once,
//!   in the cycle it is created, and of every later image and retirement
//!   as it happens; never of one twice, nor of the retirement of one it
//!   was not told about. Both rest on `announced`: set only once every
//!   event of `announce_existing_images` went out, and the only gate of
//!   `announce_image`, which runs after it in each cycle.
//! - **Shared terms.** A driver admitting other processes refuses `udp`
//!   with `UnsupportedChannel` (D3, SPEC §18).

use std::sync::Arc;

use karyos_client::link::ClientLink;
use karyos_protocol::channel::{ChannelConfig, CommonConfig, Media, UdpConfig};
use karyos_protocol::cnc::{
    Command, ErrorCode, Event as DriverEvent, RequestId, Response, StreamKey, SubscriberRole,
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

/// One word of the system's random source; `None` when it fails.
fn random_word() -> Option<u64> {
    let mut word = [0u64; 1];
    karyos_sys::random::fill_u64s(&mut word).ok()?;
    Some(word[0])
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

/// The most network resources a client may own by URI
/// (`NetworkConfig::max_owned_per_client`).
pub(crate) const MAX_OWNED_PER_CLIENT: usize = 4096;

/// The owned table's capacity for `network` and `max_clients`: one bound
/// per client. `None` when it overflows.
pub(crate) fn owned_capacity(
    network: &crate::net::NetworkConfig,
    max_clients: usize,
) -> Option<usize> {
    network.max_owned_per_client.checked_mul(max_clients)
}

/// Whether a network configuration's client parameters hold, at start:
/// its stream defaults make a valid log on every lane count they allow,
/// and a client may own something, within [`MAX_OWNED_PER_CLIENT`] and a
/// table that fits for `max_clients`.
pub(crate) fn valid_network(network: &crate::net::NetworkConfig, max_clients: usize) -> bool {
    let defaults = network.stream_defaults;
    (1..=MAX_OWNED_PER_CLIENT).contains(&network.max_owned_per_client)
        && owned_capacity(network, max_clients).is_some()
        && (1..=Lane::COUNT).contains(&defaults.lanes)
        && aggregate(&defaults, &CommonConfig::default(), 0, 1, false).is_ok_and(|config| {
            karyos_sys::log_buffer::LogBuffer::<karyos_sys::term_bytes::HeapTerms>::validate(
                &config.stream.buffer,
            )
            .is_ok()
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
                let Some(stream) = self.ipc_stream(stream_id) else {
                    return refuse(ErrorCode::UnknownStream, detail);
                };
                // A URI that names `lanes` must name the stream's: checked
                // before lane 0 is granted, as an exclusive publication is
                // granted once per incarnation (W8).
                if let Some(named) = channel.common.lanes {
                    let configured = self
                        .streams
                        .iter()
                        .find(|found| {
                            !found.retiring
                                && (found.stream_id, found.session_id)
                                    == (stream.stream_id, stream.session_id)
                        })
                        .map(|found| found.aggregate.lanes);
                    if let Some(configured) = configured
                        && configured != named
                    {
                        return refuse(ErrorCode::LaneMismatch, u64::from(configured));
                    }
                }
                return grant(self, stream);
            }
            Media::Udp(udp) => udp,
        };
        let Some(defaults) = self.config.network.map(|network| network.stream_defaults) else {
            return refuse(ErrorCode::UnsupportedChannel, detail);
        };
        if !self.may_own(client) {
            return refuse(ErrorCode::ResourcesUnavailable, detail);
        }
        let session_id = match self.draw_session(stream_id, random_word) {
            Ok(session_id) => session_id,
            Err(code) => return refuse(code, detail),
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

    /// The only stream a `karyos:ipc` URI of `stream_id` names, which
    /// carries no session id: the one active aggregate of the id that is
    /// not the network's (a network publication or an image). Its lanes
    /// count once. `None` when there is none or more than one.
    fn ipc_stream(&self, stream_id: i32) -> Option<StreamKey> {
        let net = self.net.as_ref();
        let mut found: Option<StreamKey> = None;
        for stream in &self.streams {
            let candidate = !stream.retiring
                && stream.stream_id == stream_id
                && stream.id == stream.aggregate.registration
                && !net.is_some_and(|net| net.is_network_aggregate(stream.aggregate.registration));
            if !candidate {
                continue;
            }
            match found {
                None => {
                    found = Some(StreamKey {
                        stream_id,
                        session_id: stream.session_id,
                    });
                }
                Some(key) if key.session_id == stream.session_id => {}
                Some(_) => return None,
            }
        }
        found
    }

    /// Whether `client` may own one more network resource
    /// (`NetworkConfig::max_owned_per_client`); a refusal is counted.
    fn may_own(&mut self, client: u64) -> bool {
        let cap = self
            .config
            .network
            .map_or(0, |network| network.max_owned_per_client);
        let owned = self
            .net_owned
            .iter()
            .filter(|owned| owned.client == client)
            .count();
        let room = owned < cap;
        if !room {
            match self.owned_refusals.checked_add(1) {
                Some(count) => self.owned_refusals = count,
                None => self.owned_refusals_overflowed = true,
            }
        }
        room
    }

    /// A session id for a new publication of `stream_id` from the words of
    /// `random`: nonzero and used by no stream of that id.
    ///
    /// # Errors
    ///
    /// `ResourcesUnavailable` when the random source fails,
    /// `IdentitiesExhausted` when every draw collides.
    pub(crate) fn draw_session(
        &self,
        stream_id: i32,
        mut random: impl FnMut() -> Option<u64>,
    ) -> Result<i32, ErrorCode> {
        for _ in 0..16 {
            let word = random().ok_or(ErrorCode::ResourcesUnavailable)?;
            let session_id = u32::try_from(word & u64::from(u32::MAX))
                .map_err(|_| ErrorCode::ResourcesUnavailable)?
                .cast_signed();
            if session_id != 0
                && !self
                    .streams
                    .iter()
                    .any(|stream| (stream.stream_id, stream.session_id) == (stream_id, session_id))
            {
                return Ok(session_id);
            }
        }
        Err(ErrorCode::IdentitiesExhausted)
    }

    /// Serves `AddNetworkSubscription` (W5b). A `karyos:ipc` URI subscribes
    /// the only stream of `stream_id` as `AddSubscription` does (W7).
    pub(crate) fn serve_network_subscription(
        &mut self,
        client: u64,
        link: &Arc<ClientLink<T>>,
        request: RequestId,
        stream_id: i32,
        role: SubscriberRole,
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
            Ok(ChannelConfig {
                media: Media::Ipc, ..
            }) => {
                let Some(stream) = self.ipc_stream(stream_id) else {
                    return refuse(ErrorCode::UnknownStream, detail);
                };
                return self.execute(
                    client,
                    link,
                    Command::AddSubscription {
                        sequence: request.sequence,
                        stream,
                        lane: Lane::ZERO,
                        role,
                    },
                );
            }
            Ok(ChannelConfig {
                media: Media::Udp(udp),
                ..
            }) => udp,
        };
        if self.config.network.is_none() {
            return refuse(ErrorCode::UnsupportedChannel, detail);
        }
        if !self.may_own(client) {
            return refuse(ErrorCode::ResourcesUnavailable, detail);
        }
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
        // A subscription not announced yet learns of its images from
        // `announce_existing_images`, never twice, and of no retirement of
        // an image it was not told about.
        for index in 0..self.net_owned.len() {
            let Some(OwnedNetwork {
                registration,
                owned:
                    Owned::Subscription {
                        handle: subscription,
                        announced: true,
                    },
                ..
            }) = self.net_owned.get(index).copied()
            else {
                continue;
            };
            if subscription.endpoint() != endpoint || subscription.stream_id() != stream.stream_id {
                continue;
            }
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
    /// created, once, after its `NetworkSubscriptionReady` went out. It runs
    /// before the cycle's image events, which announce only to announced
    /// subscriptions. A subscription stays unannounced while an event
    /// cannot be sent (the broadcast is closed or its positions are
    /// exhausted, which does not pass).
    pub(crate) fn announce_existing_images(&mut self) {
        let images = self
            .net
            .as_ref()
            .map_or(0, crate::net::Network::image_slots);
        for index in 0..self.net_owned.len() {
            let Some(OwnedNetwork {
                registration,
                owned:
                    Owned::Subscription {
                        handle: subscription,
                        announced: false,
                    },
                ..
            }) = self.net_owned.get(index).copied()
            else {
                continue;
            };
            let mut sent = true;
            for image in 0..images {
                let Some((endpoint, handle)) = self
                    .net
                    .as_ref()
                    .and_then(|net| net.exposed_image_at(image))
                else {
                    continue;
                };
                let stream = self
                    .streams
                    .iter()
                    .find(|stream| stream.id == handle.registration() && !stream.retiring)
                    .map(|stream| StreamKey {
                        stream_id: stream.stream_id,
                        session_id: stream.session_id,
                    });
                if let Some(stream) = stream
                    && endpoint == subscription.endpoint()
                    && stream.stream_id == subscription.stream_id()
                {
                    sent &= self.try_emit(&DriverEvent::ImageAvailable {
                        stream,
                        registration,
                    });
                }
            }
            if sent
                && let Some(OwnedNetwork {
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
