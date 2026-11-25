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
//!   `ImageAvailable`, naming its registration and its source, and the
//!   client attaches with `AddImageSubscription` naming the image, or with
//!   `AddSubscription` naming its alias, which reaches the oldest image of
//!   it (`quantstratum-docs: karyos/design/per-source-images.md`).
//!   `karyos:ipc` is `AddSubscription`'s, refused here.
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
//! - **Backings (network-shared-terms n4).** A `udp` channel is served on
//!   either backing: on an IPC driver a remote client's network
//!   publication and its images are shared regions, which the client
//!   fetches as it does a local stream's. A driver with no network refuses
//!   `udp` with `UnsupportedChannel`.

use std::sync::Arc;

use karyos_client::link::ClientLink;
use karyos_protocol::channel::{ChannelConfig, CommonConfig, Media};
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
        /// Its role: its awaiting cells' (ADR-0100) and its attaches'.
        role: SubscriberRole,
    },
}

/// A network resource a client owns through a registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OwnedNetwork {
    pub(crate) registration: u64,
    pub(crate) client: u64,
    pub(crate) owned: Owned,
    /// The admission state's code last sent for a publication
    /// (`PublicationAdmission`, karyos#637); 0 before the first.
    pub(crate) admission_sent: u64,
}

/// One word of the system's random source; `None` when it fails.
fn random_word() -> Option<u64> {
    let mut word = [0u64; 1];
    karyos_sys::random::fill_u64s(&mut word).ok()?;
    Some(word[0])
}

/// The refusal code of a network operation's error. A key still held by
/// a removed publication's linger (`DuplicateStream`) is
/// `ResourcesUnavailable`, as every other refusal not listed: a retry once
/// the removal ended succeeds, at worst `max(publication_linger,
/// path_heartbeat_interval) + publication_linger` after it started (about
/// 10 s at the defaults).
fn refusal(error: &DriverError) -> ErrorCode {
    match error {
        // A `control-mode=dynamic` channel, and the registration settings
        // only a dynamic channel takes: the client path carries no
        // allowlist and no receiver identity, so no retry is granted
        // (karyos#941 item 4).
        // An interface this host does not have: the channel cannot be
        // served here, and no retry changes that (karyos#1043).
        DriverError::NetworkUnavailable
        | DriverError::UnsupportedChannel
        | DriverError::UnknownInterface { .. }
        | DriverError::DynamicRegistrationUnsupported => ErrorCode::UnsupportedChannel,
        DriverError::StreamIdsExhausted | DriverError::ExportIdsExhausted => {
            ErrorCode::IdentitiesExhausted
        }
        DriverError::ReliabilityMismatch => ErrorCode::ReliabilityMismatch,
        DriverError::ReceiverIdentityMismatch => ErrorCode::ReceiverIdentityMismatch,
        DriverError::StrategyConflict => ErrorCode::StrategyConflict,
        // A list longer than the membership holds, or a repeated
        // `receiver_id`: invalid roles, which no retry grants.
        DriverError::InvalidRoles => ErrorCode::InvalidRoles,
        // A lane above `max_stream_bytes`: the channel's geometry, which
        // no retry changes (karyos#809).
        DriverError::StreamTooLarge { .. } => ErrorCode::StreamTooLarge,
        _ => ErrorCode::ResourcesUnavailable,
    }
}

/// The detail word of a network operation's refusal: the request's own
/// (its stream id), except for `StreamTooLarge`, whose detail is the
/// lane's bytes, as the C driver path carries them (karyos#824).
fn refusal_detail(error: &DriverError, detail: u64) -> u64 {
    match error {
        DriverError::StreamTooLarge { bytes, .. } => *bytes,
        DriverError::EndpointCapacity {
            limit,
            capacity,
            needed,
        } => limit.detail(*capacity, *needed),
        _ => detail,
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
    /// Serves `AddNetworkPublication` (W5b): with `concurrent`, a
    /// concurrent handle on lane 0 of a `karyos:ipc` stream (M11). With
    /// `roles` (`AddNetworkPublicationWithRoles`, karyos#637), a network
    /// publication whose receivers have them; a `karyos:ipc` URI has no
    /// receivers and is refused with `UnsupportedChannel`.
    pub(crate) fn serve_network_publication(
        &mut self,
        client: u64,
        link: &Arc<ClientLink<T>>,
        request: RequestId,
        stream_id: i32,
        (allow_unconnected, concurrent): (bool, bool),
        (uri, roles): (&str, Option<karyos_protocol::roles::PublicationRoles>),
    ) -> Result<Response, &'static str> {
        let refuse = |code: ErrorCode, detail: u64| {
            Ok(Response::Error {
                request,
                code,
                detail,
            })
        };
        let detail = u64::from(stream_id.cast_unsigned());
        // A publication refuses what only a subscription admits: an
        // `endpoint` on port 0 (karyos#656).
        let channel = match ChannelConfig::parse(uri)
            .and_then(|channel| channel.check_publication().map(|()| channel))
        {
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
            Media::Ipc if roles.is_some() => {
                return refuse(ErrorCode::UnsupportedChannel, detail);
            }
            Media::Ipc => {
                let Some(stream) = self.ipc_stream(stream_id) else {
                    return refuse(ErrorCode::UnknownStream, detail);
                };
                // A concurrent handle shares lane 0 with the stream's other
                // publishers; an exclusive stream refuses it with
                // `InvalidPublicationMode` (M11).
                if concurrent {
                    return self.execute(
                        client,
                        link,
                        Command::AddConcurrentPublication {
                            sequence: request.sequence,
                            stream,
                            lane: Lane::ZERO,
                            allow_unconnected,
                        },
                    );
                }
                // A URI that names `lanes` must name the stream's: checked
                // before lane 0 is granted, as an exclusive publication is
                // granted once per incarnation (W8).
                if let Some(named) = channel.common.lanes {
                    let configured = self
                        .streams
                        .iter()
                        .find(|found| {
                            // The local stream's lanes: an image of the
                            // same key may live beside it (karyos#490).
                            !found.retiring
                                && found.source.is_none()
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
            // A network publication is exclusive: its session is drawn
            // for this publisher alone.
            Media::Udp(_) if concurrent => {
                return refuse(ErrorCode::UnsupportedChannel, detail);
            }
            // Roles that contradict the URI's `fc` are refused before
            // anything else of the request is looked at, so the conflict
            // is the answer whatever the driver serves (karyos#637).
            Media::Udp(udp)
                if roles.as_ref().is_some_and(|roles| {
                    crate::net::publish::strategy_of(&udp).is_ok_and(|fc| fc != roles.strategy)
                }) =>
            {
                return refuse(ErrorCode::StrategyConflict, detail);
            }
            Media::Udp(udp) => udp,
            // A medium a later protocol version parses: not served.
            _ => return refuse(ErrorCode::UnsupportedChannel, detail),
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
        let mut config = match aggregate(
            &defaults,
            &channel.common,
            stream_id,
            session_id,
            allow_unconnected,
        ) {
            Ok(config) => config,
            Err(error) => return refuse(refusal(&error), refusal_detail(&error, detail)),
        };
        // A timed stream's publication: a schedule ring on each lane,
        // released by the sender (`NetworkStreamDefaults::timed`).
        let added = match defaults.timed_capacity(stream_id) {
            Some(capacity) => {
                config.stream.buffer.schedule_capacity = capacity;
                self.add_network(
                    config,
                    &udp,
                    None,
                    roles.map(Box::new),
                    Some((karyos_client::schedule::ScheduleOptions::default(), None)),
                    (&[], None),
                )
            }
            None => self.add_network(config, &udp, None, roles.map(Box::new), None, (&[], None)),
        };
        let handle = match added {
            Ok(handle) => handle,
            Err(error) => return refuse(refusal(&error), refusal_detail(&error, detail)),
        };
        let response = grant(
            self,
            StreamKey {
                stream_id,
                session_id,
            },
        );
        match response {
            Ok(Response::PublicationReady { registration, .. }) => {
                self.net_owned.push(OwnedNetwork {
                    registration,
                    client,
                    owned: Owned::Publication(handle),
                    admission_sent: 0,
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
    pub(crate) fn ipc_stream(&self, stream_id: i32) -> Option<StreamKey> {
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
    /// the only stream of `stream_id` as `AddSubscription` does (W7). With
    /// `identity` (`AddNetworkSubscriptionAs`, karyos#637), its images name
    /// that receiver identity; a `karyos:ipc` URI has no images and is
    /// refused with `UnsupportedChannel`.
    pub(crate) fn serve_network_subscription(
        &mut self,
        client: u64,
        link: &Arc<ClientLink<T>>,
        request: RequestId,
        stream_id: i32,
        role: SubscriberRole,
        (uri, identity): (&str, Option<karyos_protocol::roles::ReceiverIdentity>),
    ) -> Result<Response, &'static str> {
        let refuse = |code: ErrorCode, detail: u64| {
            Ok(Response::Error {
                request,
                code,
                detail,
            })
        };
        let detail = u64::from(stream_id.cast_unsigned());
        let udp = match ChannelConfig::parse(uri) {
            Err(error) => return refuse(ErrorCode::InvalidChannel, error.code()),
            Ok(ChannelConfig {
                media: Media::Ipc, ..
            }) if identity.is_some() => {
                return refuse(ErrorCode::UnsupportedChannel, detail);
            }
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
            // A medium a later protocol version parses: not served.
            Ok(_) => return refuse(ErrorCode::UnsupportedChannel, detail),
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
        // A URI's `endpoint=<host>:0` binds an ephemeral port of its own
        // (karyos#656), unlike the embedded calls, which share a bind
        // address's endpoint.
        let added = self.subscribe_network(stream_id, &udp, (identity, None), false, true);
        let handle = match added {
            Ok(handle) => handle,
            Err(error) => return refuse(refusal(&error), refusal_detail(&error, detail)),
        };
        let bound = self.network_subscription_bound(&handle, &udp);
        self.next_registration = next;
        self.net_owned.push(OwnedNetwork {
            registration,
            client,
            owned: Owned::Subscription {
                handle,
                announced: false,
                role,
            },
            admission_sent: 0,
        });
        self.refresh_awaiting();
        Ok(Response::NetworkSubscriptionReady {
            request,
            registration,
            bound,
        })
    }

    /// Sends the admission state of each network publication a client
    /// owns when it differs from the one last sent (`PublicationAdmission`,
    /// owner item 7, karyos#637): the last state observed, not each
    /// transition. Run every cycle; a load and a compare per publication,
    /// no allocation. An event the broadcast buffer cannot take is sent on
    /// a later cycle.
    pub(crate) fn send_network_admissions(&mut self) {
        for index in 0..self.net_owned.len() {
            let Some(owned) = self.net_owned.get(index).copied() else {
                continue;
            };
            if let Owned::Publication(handle) = owned.owned {
                self.send_admission(index, handle, owned.registration, false);
            }
        }
    }

    /// Sends again the admission state of `client`'s network publication
    /// `registration`, if it is one with a state: before the answer to a
    /// `QueryCutover`, so a client that lapped the broadcast buffer
    /// resynchronizes (karyos#637).
    pub(crate) fn resend_network_admission(&mut self, client: u64, registration: u64) {
        let found = self.net_owned.iter().position(|owned| {
            owned.client == client
                && owned.registration == registration
                && matches!(owned.owned, Owned::Publication(_))
        });
        if let Some(index) = found
            && let Some(Owned::Publication(handle)) =
                self.net_owned.get(index).map(|owned| owned.owned)
        {
            self.send_admission(index, handle, registration, true);
        }
    }

    /// Sends `net_owned[index]`'s publication state, when it changed or
    /// with `again`.
    fn send_admission(
        &mut self,
        index: usize,
        handle: AggregateHandle,
        registration: u64,
        again: bool,
    ) {
        let Some(state) = self
            .net
            .as_ref()
            .and_then(|net| net.publication_admission(handle.registration()))
        else {
            return;
        };
        let sent = self.net_owned.get(index).map(|owned| owned.admission_sent);
        if !again && sent == Some(state.code()) {
            return;
        }
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
        let event = karyos_protocol::cnc::Event::PublicationAdmission {
            stream,
            registration,
            admission: state,
        };
        if self.try_emit(&event)
            && let Some(owned) = self.net_owned.get_mut(index)
        {
            owned.admission_sent = state.code();
        }
    }

    /// Rebuilds the awaiting entries the image table registers cells for
    /// (ADR-0100) from the network subscriptions clients own. Run after
    /// each change of `net_owned`'s subscriptions; it never allocates past
    /// the capacity `net_owned` was given.
    pub(crate) fn refresh_awaiting(&mut self) {
        self.awaiting_entries.clear();
        for owned in &self.net_owned {
            if let Owned::Subscription { handle, role, .. } = owned.owned {
                self.awaiting_entries
                    .push(crate::agents::images::AwaitingEntry {
                        endpoint: handle.endpoint(),
                        stream_id: handle.stream_id(),
                        parent: owned.registration,
                        client: owned.client,
                        role: karyos_sys::log_buffer::Role::from(role),
                    });
            }
        }
        // The embedded API's subscriptions that await their images.
        let embedded = self.embedded_awaiting.iter().map(|(_, entry)| *entry);
        self.awaiting_entries.extend(embedded);
    }

    /// Withdraws every awaiting cell (ADR-0100) that `matches` selects,
    /// on every stream: its cell ends as a lost reader's would, at once.
    pub(crate) fn withdraw_awaiting(
        &mut self,
        mut matches: impl FnMut(&crate::embedded::StreamAwaiting) -> bool,
    ) {
        for stream in &mut self.streams {
            let conductor = &mut stream.conductor;
            stream.awaiting.retain(|awaiting| {
                if matches(awaiting) {
                    let _ = conductor.end_subscriber(awaiting.cell.cell(), awaiting.cell.export());
                    false
                } else {
                    true
                }
            });
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
                // Its awaiting cells go with it (ADR-0100), so none waits
                // for an attach that cannot come.
                self.withdraw_awaiting(|awaiting| awaiting.parent == owned.registration);
                self.refresh_awaiting();
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
        // The image is named by its registration, with its source
        // (`quantstratum-docs: karyos/design/per-source-images.md`, D2-3).
        let image = handle.registration();
        let Some((stream, source)) = self
            .streams
            .iter()
            .find(|stream| stream.id == image)
            .and_then(|stream| Some((stream.key(), stream.source?.source)))
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
                        ..
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
                    image,
                    source,
                }
            } else {
                DriverEvent::ImageUnavailable {
                    stream,
                    registration,
                    image,
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
                        ..
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
                let image = handle.registration();
                let found = self
                    .streams
                    .iter()
                    .find(|stream| stream.id == image && !stream.retiring)
                    .and_then(|stream| Some((stream.key(), stream.source?.source)));
                if let Some((stream, source)) = found
                    && endpoint == subscription.endpoint()
                    && stream.stream_id == subscription.stream_id()
                {
                    sent &= self.try_emit(&DriverEvent::ImageAvailable {
                        stream,
                        registration,
                        image,
                        source,
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

#[cfg(test)]
mod tests;
