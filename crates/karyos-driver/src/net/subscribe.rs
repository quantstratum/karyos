// SPDX-License-Identifier: Apache-2.0

//! Network subscriptions of the embedded driver (wiring note W-e, W3;
//! coordinator ACS 15937): a stream subscribed on a UDP channel, whose
//! images become streams of this driver.
//!
//! - **Per-source images (D2).** Each installed image is exposed as one
//!   aggregate named by its registration, with its source
//!   (`quantstratum-docs: karyos/design/per-source-images.md`): images of
//!   one alias from several sources are each exposed and announced. A
//!   client attaches to one by its registration (`AddImageSubscription`);
//!   its alias, `StreamKey { stream_id, session_id }`, reaches the oldest
//!   live image of it. An image whose alias is a local stream's key, or
//!   one the stream table has no room for, is installed and fed but not
//!   exposed, and counted.
//! - **Retirement.** A retiring image's streams are sealed with
//!   [`SealReason::ImageRetired`](karyos_sys::log_buffer::SealReason) and
//!   retired; they free once no lease holds them, and only then does the
//!   image table reclaim the image. An image whose every lane reached the
//!   terminal bound its EOS named, through a complete prefix, is sealed
//!   with `SealReason::EndOfStream` instead: its clean end. A lane that
//!   dropped a frame past its bound does not end clean; that image is
//!   sealed with `ImageRetired`.
//! - **EOS on the wire.** EOS reaches a receiver as the application's
//!   per-message EOS flag, or as the EOS heartbeat a removed publication's
//!   sender sends at each lane's seal once the lane drained to it, repeated
//!   through `publication_linger` (driver-network-agents.md §7). A removal
//!   therefore ends its receivers' images cleanly, every lane at its seal,
//!   an unused lane included, once each lane's complete prefix reaches it.
//!   No EOS is sent, so the images end unclean at their liveness timeout,
//!   for a lane not drained within the linger's drain bound, a lane whose
//!   guard closed, a driver stop or a sender failure, and, until the routed
//!   sender's follow-up, every lane of a routed (redundant paths)
//!   publication.
//! - **Scope.** Unicast (the channel's `endpoint` is the local receive
//!   address) and IPv4 multicast (the group's port, joined on `interface`
//!   or any); interface names and IPv6 groups are refused.
//! - **Backings (network-shared-terms n3).** An image is exposed on either
//!   backing: on an IPC driver its lanes are shared regions, so in-process
//!   subscribers read it as any stream of the driver and remote clients
//!   subscribe to its stream key and fetch its regions. The calls here
//!   serve either backing (n4).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use karyos_io::sockets::endpoint::{InterfaceSel, MulticastConfig};
use karyos_protocol::channel::{Destination, Interface, UdpConfig};

use super::{LATER_PATHS, NetworkSubscription};
use crate::agents::images::DEFAULT_MAX_IMAGE_TERM_LENGTH;
use crate::embedded::{AggregateHandle, EmbeddedDriver, StreamTerms};
use crate::error::DriverError;
use crate::membership::ReceiverIdentity;

/// The local address and multicast group of each later path of a
/// channel with `paths` (redundant-paths.md): multicast IPv4 only, each
/// path joining the channel's group on its interface address, the first
/// path being the route of [`receive_route`]. Unicast `paths` need a
/// destination per path, which the URI cannot name yet (owner item 11).
/// Runs on the control path, so it may allocate.
fn later_routes(channel: &UdpConfig) -> Result<Vec<(SocketAddr, MulticastConfig)>, DriverError> {
    let Some((_, later)) = channel.paths.split_first() else {
        return Ok(Vec::new());
    };
    // Unicast `paths`, even a single one, need a destination per path.
    let Destination::Multicast { group, .. } = &channel.destination else {
        return Err(DriverError::UnsupportedChannel);
    };
    if later.len() > LATER_PATHS {
        return Err(DriverError::UnsupportedChannel);
    }
    let mut routes = Vec::with_capacity(later.len());
    for path in later {
        let Interface::Address(IpAddr::V4(address)) = path else {
            return Err(DriverError::UnsupportedChannel);
        };
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), group.port());
        routes.push((
            bind,
            MulticastConfig::new(group.ip(), InterfaceSel::Address(*address)),
        ));
    }
    Ok(routes)
}

/// The local address a subscription binds, and its multicast group: with
/// `paths`, those of the first path.
fn receive_route(
    channel: &UdpConfig,
) -> Result<(SocketAddr, Option<MulticastConfig>), DriverError> {
    let first_path = channel.paths.first().cloned();
    let interface = match first_path.as_ref().or(channel.interface.as_ref()) {
        None => None,
        Some(Interface::Address(ip)) => Some(*ip),
        Some(Interface::Name(_)) => return Err(DriverError::UnsupportedChannel),
    };
    match &channel.destination {
        Destination::Unicast(address) => Ok((*address, None)),
        Destination::Multicast { group, .. } => {
            let IpAddr::V4(_) = group.ip() else {
                return Err(DriverError::UnsupportedChannel);
            };
            let selected = match interface {
                Some(IpAddr::V4(address)) => address,
                None => Ipv4Addr::UNSPECIFIED,
                Some(IpAddr::V6(_)) => return Err(DriverError::UnsupportedChannel),
            };
            let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), group.port());
            Ok((
                bind,
                Some(MulticastConfig::new(
                    group.ip(),
                    InterfaceSel::Address(selected),
                )),
            ))
        }
        Destination::MultiDestination { .. } => Err(DriverError::UnsupportedChannel),
    }
}

impl<T: StreamTerms> EmbeddedDriver<T> {
    /// Subscribes `stream_id` on `channel` (control path): its images,
    /// once installed, are streams of this driver
    /// ([`EmbeddedDriver::network_image`]).
    ///
    /// # Errors
    ///
    /// [`DriverError::NetworkUnavailable`] without a network,
    /// [`DriverError::UnsupportedChannel`], [`DriverError::NetworkEndpoint`],
    /// [`DriverError::NetworkBusy`], and
    /// [`DriverError::ReliabilityMismatch`] for a stream already subscribed
    /// on the endpoint with another reliability.
    pub fn add_network_subscription(
        &mut self,
        stream_id: i32,
        channel: &UdpConfig,
    ) -> Result<NetworkSubscription, DriverError> {
        self.subscribe_network(stream_id, channel, (None, None))
    }

    /// [`EmbeddedDriver::add_network_subscription`] whose images name the
    /// configured receiver `identity` (MC-1, MC-2): its `receiver_id` in
    /// every RB block and its `group_tag` in their SMs. Driver-internal:
    /// the public way in is owner item 7.
    ///
    /// # Errors
    ///
    /// As [`EmbeddedDriver::add_network_subscription`], and
    /// [`DriverError::ReceiverIdentityMismatch`] for a stream already
    /// subscribed on the endpoint with another identity, or with none.
    #[allow(
        dead_code,
        reason = "driver-internal until owner item 7 gives identities a public way in"
    )]
    pub(crate) fn add_network_subscription_as(
        &mut self,
        stream_id: i32,
        channel: &UdpConfig,
        identity: ReceiverIdentity,
    ) -> Result<NetworkSubscription, DriverError> {
        self.subscribe_network(stream_id, channel, (Some(identity), None))
    }

    /// [`EmbeddedDriver::add_network_subscription`] with a conflated view
    /// of `lane` of its images, a table of `config` (conflated-network-images.md
    /// (a)): the receiver gates that lane's seals through the view's barrier
    /// mailbox, and the conductor feeds the view of each exposed image.
    /// Driver-internal: a URI or public form is the owner's (item 7).
    ///
    /// # Errors
    ///
    /// As [`EmbeddedDriver::add_network_subscription`], and
    /// [`DriverError::ConflationMismatch`] for a stream already subscribed
    /// on the endpoint with another conflated lane, or with none.
    #[allow(
        dead_code,
        reason = "driver-internal until owner item 7 gives conflated network views a way in"
    )]
    pub(crate) fn add_network_subscription_conflated(
        &mut self,
        stream_id: i32,
        channel: &UdpConfig,
        lane: karyos_sys::frame::Lane,
        config: karyos_sys::conflation::ConflationConfig,
    ) -> Result<NetworkSubscription, DriverError> {
        self.subscribe_network(stream_id, channel, (None, Some((lane, config))))
    }

    /// Stops `subscription`: its images retire, which seals their streams
    /// with `ImageRetired`. `false` when it is not a subscription of this
    /// driver.
    ///
    /// # Errors
    ///
    /// [`DriverError::NetworkBusy`]; nothing changes then.
    pub fn remove_network_subscription(
        &mut self,
        subscription: NetworkSubscription,
    ) -> Result<bool, DriverError> {
        self.unsubscribe_network(subscription)
    }

    /// The aggregate exposing the image of `stream_id` and `session_id`,
    /// if one is installed and exposed. Images of one alias from several
    /// sources are each exposed (`quantstratum-docs:
    /// karyos/design/per-source-images.md`, D2-2); this returns the oldest
    /// that is not retiring.
    #[must_use]
    pub fn network_image(&self, stream_id: i32, session_id: i32) -> Option<AggregateHandle> {
        self.exposed_network_image(stream_id, session_id)
    }

    /// Network subscriptions the receiver refused although the conductor's
    /// mirror of its table had room: a drift between the two, never
    /// expected (ACS 16077).
    #[must_use]
    pub fn network_subscription_refusals(&self) -> u64 {
        self.net
            .as_ref()
            .map_or(0, crate::net::Network::subscription_refusals)
    }

    /// NAK control group joins that failed (RC-15): those subscriptions
    /// run without peer suppression input.
    #[must_use]
    pub fn network_control_join_failures(&self) -> u64 {
        self.net
            .as_ref()
            .map_or(0, crate::net::Network::control_join_failures)
    }

    /// Channels with `paths` refused because their sockets cannot be
    /// isolated (owner item 12), and later paths of subscriptions that
    /// could not be held.
    #[must_use]
    pub fn network_path_counters(&self) -> (u64, u64) {
        self.net
            .as_ref()
            .map_or((0, 0), crate::net::Network::path_counters)
    }

    /// Endpoints the network holds (tests).
    #[cfg(test)]
    pub(crate) fn network_held_endpoints(&self) -> usize {
        self.net
            .as_ref()
            .map_or(0, crate::net::Network::held_endpoints)
    }

    /// Network publications and subscriptions refused by channel URI
    /// because their client owned `NetworkConfig::max_owned_per_client`.
    #[must_use]
    pub fn network_owned_refusals(&self) -> u64 {
        self.owned_refusals
    }

    /// Images installed but not exposed so far: their alias was in use.
    #[must_use]
    pub fn network_images_unexposed(&self) -> u64 {
        self.net
            .as_ref()
            .map_or(0, crate::net::Network::images_unexposed)
    }
}

/// The driver's own network subscription calls, which the public ones
/// above and the client's URI path go through.
impl<T: StreamTerms> EmbeddedDriver<T> {
    /// Tests only, not part of the API: the address the endpoint of
    /// `stream_id`'s network subscription is bound to, so a test can
    /// subscribe on port 0 and publish to the port the kernel chose,
    /// instead of picking a free port that another process may take
    /// before the bind. `None` without such a subscription.
    #[doc(hidden)]
    #[must_use]
    pub fn network_subscription_address(&self, stream_id: i32) -> Option<std::net::SocketAddr> {
        self.net.as_ref()?.subscription_address(stream_id)
    }

    /// The bound address `subscription` on `channel` reports in
    /// `NetworkSubscriptionReady` (decision row 26): its first path's
    /// endpoint address as the socket reports it, or for a multicast
    /// subscription the group address with the bound port, not the
    /// interface. `None` without such an endpoint.
    pub(crate) fn network_subscription_bound(
        &self,
        subscription: &NetworkSubscription,
        channel: &UdpConfig,
    ) -> Option<SocketAddr> {
        let local = self
            .net
            .as_ref()?
            .endpoint_address(subscription.endpoint())?;
        Some(match &channel.destination {
            Destination::Multicast { group, .. } => SocketAddr::new(group.ip(), local.port()),
            Destination::Unicast(_) | Destination::MultiDestination { .. } => local,
        })
    }

    pub(crate) fn subscribe_network(
        &mut self,
        stream_id: i32,
        channel: &UdpConfig,
        options: (
            Option<ReceiverIdentity>,
            Option<(
                karyos_sys::frame::Lane,
                karyos_sys::conflation::ConflationConfig,
            )>,
        ),
    ) -> Result<NetworkSubscription, DriverError> {
        let net = self.net.as_mut().ok_or(DriverError::NetworkUnavailable)?;
        // Redundant paths need sockets isolated per interface; without
        // that every datagram would count on every path (owner item 12).
        if !channel.paths.is_empty() && !net.paths_isolated() {
            net.count_paths_refused();
            return Err(DriverError::UnsupportedChannel);
        }
        let route = receive_route(channel)?;
        let later = later_routes(channel)?;
        net.add_subscription(
            stream_id,
            route,
            &later,
            DEFAULT_MAX_IMAGE_TERM_LENGTH,
            channel.reliable,
            options,
        )
    }

    /// Stops `subscription`, as [`EmbeddedDriver::remove_network_subscription`].
    ///
    /// # Errors
    ///
    /// [`DriverError::NetworkBusy`]; nothing changes then.
    pub(crate) fn unsubscribe_network(
        &mut self,
        subscription: NetworkSubscription,
    ) -> Result<bool, DriverError> {
        match &mut self.net {
            Some(net) => net.remove_subscription(subscription),
            None => Ok(false),
        }
    }

    /// The aggregate exposing the image of `stream_id` and `session_id`,
    /// as [`EmbeddedDriver::network_image`].
    /// Every exposed, non-retiring image of `stream_id`, the oldest first,
    /// with its source (tests; a public form is the owner's, item 7).
    #[cfg(test)]
    pub(crate) fn network_images(
        &self,
        stream_id: i32,
    ) -> Vec<(AggregateHandle, std::net::SocketAddr)> {
        self.net.as_ref().map_or_else(Vec::new, |net| {
            net.exposed_images()
                .filter_map(|handle| {
                    // The image's source is its stream's (D2-1).
                    self.streams
                        .iter()
                        .find(|stream| {
                            stream.id == handle.registration()
                                && !stream.retiring
                                && stream.stream_id == stream_id
                        })
                        .and_then(|stream| Some((handle, stream.source?.source)))
                })
                .collect()
        })
    }

    pub(crate) fn exposed_network_image(
        &self,
        stream_id: i32,
        session_id: i32,
    ) -> Option<AggregateHandle> {
        self.net.as_ref()?.exposed_image(|handle| {
            self.streams.iter().any(|stream| {
                stream.aggregate.registration == handle.registration()
                    && !stream.retiring
                    && (stream.stream_id, stream.session_id) == (stream_id, session_id)
            })
        })
    }
}

#[cfg(test)]
mod tests;
