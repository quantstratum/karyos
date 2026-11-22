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
use karyos_protocol::channel::{ControlMode, Destination, Interface, UdpConfig};

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
/// `paths`, those of the first path. A `control-mode=dynamic` channel is
/// served only when `dynamic` (karyos#644): it binds `interface`, else the
/// unspecified address of `control`'s family, on a port the kernel picks,
/// and registers at `control` (design 3.2).
fn receive_route(
    channel: &UdpConfig,
    dynamic: bool,
) -> Result<(SocketAddr, Option<MulticastConfig>), DriverError> {
    let first_path = channel.paths.first().cloned();
    let interface = match first_path.as_ref().or(channel.interface.as_ref()) {
        None => None,
        Some(Interface::Address(ip)) => Some(*ip),
        // A name, or an interface form a later protocol version parses.
        Some(_) => return Err(DriverError::UnsupportedChannel),
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
        // Dynamic registration with no listed destination and no
        // redundant path, as its publication (design 3.2), only through
        // the crate-internal call that carries the receiver's identity:
        // every public call refuses dynamic mode until the registration
        // defects found after karyos#939 are fixed (karyos#644, reopened:
        // https://github.com/quantstratum/karyos/issues/644#issuecomment-6826655946).
        Destination::MultiDestination {
            destinations,
            control: Some(control),
            mode: ControlMode::Dynamic,
        } if dynamic => {
            if !destinations.is_empty() || !channel.paths.is_empty() {
                return Err(DriverError::UnsupportedChannel);
            }
            let ip = match interface {
                Some(ip) if ip.is_ipv4() == control.is_ipv4() => ip,
                Some(_) => return Err(DriverError::UnsupportedChannel),
                None if control.is_ipv4() => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                None => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            };
            Ok((SocketAddr::new(ip, 0), None))
        }
        Destination::MultiDestination {
            mode: ControlMode::Dynamic,
            ..
        } => Err(DriverError::DynamicRegistrationUnsupported),
        // Manual multi-destination, or a destination a later protocol
        // version parses: not served.
        _ => Err(DriverError::UnsupportedChannel),
    }
}

/// The `control` address a subscription of `channel` registers at: that
/// of a `control-mode=dynamic` channel, else none.
fn register_at(channel: &UdpConfig) -> Option<SocketAddr> {
    match &channel.destination {
        Destination::MultiDestination {
            control,
            mode: ControlMode::Dynamic,
            ..
        } => *control,
        _ => None,
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
        self.subscribe_network(stream_id, channel, (None, None), false, false)
    }

    /// [`EmbeddedDriver::add_network_subscription`] whose images name the
    /// configured receiver `identity` (MC-1, MC-2): its `receiver_id` in
    /// every RB block and its `group_tag` in their SMs (owner decisions of
    /// 2026-10-21, item 7): what a publication's required `receiver_id`s
    /// and `tagged` group name.
    ///
    /// # Errors
    ///
    /// As [`EmbeddedDriver::add_network_subscription`], and
    /// [`DriverError::ReceiverIdentityMismatch`] for a stream already
    /// subscribed on the endpoint with another identity, or with none.
    pub fn add_network_subscription_as(
        &mut self,
        stream_id: i32,
        channel: &UdpConfig,
        identity: ReceiverIdentity,
    ) -> Result<NetworkSubscription, DriverError> {
        self.subscribe_network(stream_id, channel, (Some(identity), None), false, false)
    }

    /// [`EmbeddedDriver::add_network_subscription`] with a conflated view
    /// of `lane` of its images, a table of `config` (conflated-network-images.md
    /// (a)): the receiver gates that lane's seals through the view's barrier
    /// mailbox, and the conductor feeds the view of each exposed image
    /// (owner decisions of 2026-10-21, item 7: "receiver-side conflated
    /// subscriptions"; karyos#637). Read a view with
    /// [`EmbeddedDriver::subscribe_conflated`] on the image's lane stream
    /// (`AggregateHandle::lane` of [`EmbeddedDriver::network_image`]): each
    /// value comes with its freshness. A view its terminal cell closed is
    /// recreated with [`EmbeddedDriver::recreate_network_view`]. This is the
    /// in-process way in, as for IPC views; a client of a driver in another
    /// process is refused a network view (`Client::add_conflated_subscription`,
    /// `UnsupportedChannel`): its table is on the driver's heap
    /// (`quantstratum-docs: karyos/design/conflated-network-images.md`, (c)).
    ///
    /// # Errors
    ///
    /// As [`EmbeddedDriver::add_network_subscription`],
    /// [`DriverError::ConflationMismatch`] for a stream already subscribed
    /// on the endpoint with another conflated lane, or with none, and
    /// [`DriverError::BarrierAckTimeout`] for an unreliable channel whose
    /// `barrier_ack_timeout` plus seal deadline reaches the far-window
    /// timeout (karyos#658).
    pub fn add_network_subscription_conflated(
        &mut self,
        stream_id: i32,
        channel: &UdpConfig,
        lane: karyos_sys::frame::Lane,
        config: karyos_sys::conflation::ConflationConfig,
    ) -> Result<NetworkSubscription, DriverError> {
        self.subscribe_network(
            stream_id,
            channel,
            (None, Some((lane, config))),
            false,
            false,
        )
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

    /// How far the registration of `subscription`, a
    /// `control-mode=dynamic` one, has got (karyos#941 item 3): whether
    /// its publisher answered, refused it with ERR REGISTRATION, or bound
    /// it, or nothing has come back from `control` yet. `None` for a
    /// subscription that does not register, or one removed.
    ///
    /// Every public path refuses `control-mode=dynamic` until karyos#944
    /// lifts that refusal, so through the public API this returns `None`
    /// for now.
    #[must_use]
    pub fn network_registration_state(
        &self,
        subscription: NetworkSubscription,
    ) -> Option<crate::sessions::register::RegistrationState> {
        self.net.as_ref()?.registration_state(subscription)
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

    /// The entries of the driver's NAK control group table in use: the
    /// configured ones, and those channels' `nak-control` keys added while
    /// a channel holds them (karyos#1086). At most
    /// [`MAX_CONTROL_GROUPS`](crate::net::MAX_CONTROL_GROUPS).
    #[must_use]
    pub fn network_control_groups_in_use(&self) -> usize {
        self.net
            .as_ref()
            .map_or(0, crate::net::Network::control_groups_in_use)
    }

    /// NAK control group joins that failed (RC-15): those subscriptions
    /// run without peer suppression input.
    #[must_use]
    pub fn network_control_join_failures(&self) -> u64 {
        self.net
            .as_ref()
            .map_or(0, crate::net::Network::control_join_failures)
    }

    /// The driver's unicast control endpoints that send SOLICITs, one per
    /// address family with a multicast subscription (network-control-
    /// schemas.md §6.3, plan 164): their bound addresses, port and family.
    #[must_use]
    pub fn network_solicit_endpoints(&self) -> Vec<std::net::SocketAddr> {
        self.net
            .as_ref()
            .map(|net| net.solicit_endpoints().collect())
            .unwrap_or_default()
    }

    /// Unicast control endpoints for SOLICITs that could not open: those
    /// subscriptions send theirs from their own endpoint (plan 164).
    #[must_use]
    pub fn network_solicit_endpoint_failures(&self) -> u64 {
        self.net
            .as_ref()
            .map_or(0, crate::net::Network::solicit_endpoint_failures)
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
            // A form a later protocol version parses is refused before a
            // subscription exists (`receive_route`); the socket's own
            // address stands.
            _ => local,
        })
    }

    /// [`EmbeddedDriver::add_network_subscription_as`] on a
    /// `control-mode=dynamic` multi-destination channel
    /// (`karyos:udp?control=<address>|control-mode=dynamic`; ADR-0056,
    /// ADR-0082; `quantstratum-docs:
    /// karyos/design/multi-destination-unicast.md` 3.2; karyos#644): the
    /// subscription binds `interface`, else the unspecified address of
    /// `control`'s family, on a port the kernel picks. Every dynamic
    /// subscription of a driver with the same bind address shares that one
    /// endpoint and port (karyos#941 item 6): a publisher sees them as one
    /// source, so its per-source bounds (`registration_pending_per_source`,
    /// 2, and the per-address REGISTER rate) are shared by all of them,
    /// and at most two of them are pending at one publisher at once. It
    /// registers at the channel's `control` address until an image of the
    /// stream from there is bound, and again once that image is gone.
    /// REGISTERs start every `setup_interval` and back off, doubling to
    /// sixteen times it while nothing binds; an ANNOUNCE from `control`
    /// starts the backoff over. They draw on their own bucket per
    /// `control` address, so they never spend the RSP_SETUP limits the
    /// CHALLENGE answering that ANNOUNCE needs (karyos#941 item 1). Only
    /// `control`, port included, may set up its image: an ANNOUNCE or
    /// ANSWER of the stream from anywhere else is dropped and counted
    /// (karyos#941 item 5). How far it got, and an ERR REGISTRATION from
    /// `control` (a full destination table), is shown by
    /// [`EmbeddedDriver::network_registration_state`] and by the CnC cells
    /// `registers sent`, `registers unsent` and `registration refusals
    /// received` (karyos#941 item 3); the subscription keeps registering.
    ///
    /// A dynamic subscription names its configured `identity` in every
    /// REGISTER and status message: the publisher looks a registrant up by
    /// its `receiver_id`, which must be stable across restarts, and names
    /// its required receivers by it (design 2.3; multicast-flow-control.md
    /// M1). One receiving driver is at most one destination of a
    /// publication.
    ///
    /// The one call that subscribes in dynamic mode: the other
    /// subscription calls carry no registration and refuse it with
    /// [`DriverError::DynamicRegistrationUnsupported`] (karyos#644).
    ///
    /// # Errors
    ///
    /// As [`EmbeddedDriver::add_network_subscription_as`];
    /// [`DriverError::UnsupportedChannel`] for a channel that is not
    /// `control-mode=dynamic` with a `control` address, that lists
    /// destinations or names redundant paths, whose `interface` is of
    /// another family than `control`, or for a stream already subscribed
    /// on the endpoint registering at another address;
    /// [`DriverError::InvalidRegistrationControl`] for a `control` with a
    /// zero port or an unspecified, multicast or broadcast address.
    pub fn add_dynamic_network_subscription(
        &mut self,
        stream_id: i32,
        channel: &UdpConfig,
        identity: ReceiverIdentity,
    ) -> Result<NetworkSubscription, DriverError> {
        let Some(control) = register_at(channel) else {
            return Err(DriverError::UnsupportedChannel);
        };
        // A hand-built channel skips the URI parser: a `control` no
        // REGISTER can reach would count every one unsent for ever
        // (karyos#941 item 7).
        if !crate::agents::roles::answerable(control) {
            return Err(DriverError::InvalidRegistrationControl { control });
        }
        self.subscribe_network(stream_id, channel, (Some(identity), None), true, false)
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
        dynamic: bool,
        own_port: bool,
    ) -> Result<NetworkSubscription, DriverError> {
        let net = self.net.as_mut().ok_or(DriverError::NetworkUnavailable)?;
        // Redundant paths need sockets isolated per interface; without
        // that every datagram would count on every path (owner item 12).
        if !channel.paths.is_empty() && !net.paths_isolated() {
            net.count_paths_refused();
            return Err(DriverError::UnsupportedChannel);
        }
        // A conflated view of an unreliable channel needs its fail-safe to
        // close the view before the far-window close ends the image
        // (karyos#658).
        // The channel's `path-skew` (owner item 17), validated once here,
        // at channel admission (karyos#1056).
        let path_skew = super::publish::skew_ns(channel)?;
        if options.1.is_some() && !channel.reliable {
            net.unreliable_view_bound(path_skew)
                .map_err(DriverError::BarrierAckTimeout)?;
        }
        let route = receive_route(channel, dynamic)?;
        let later = later_routes(channel)?;
        // The channel's NAK control groups join the driver's one table
        // first, so the subscription's join finds them (karyos#654).
        let held = net.map_nak_control(channel)?;
        let added = net.add_subscription(
            stream_id,
            route,
            &later,
            DEFAULT_MAX_IMAGE_TERM_LENGTH,
            (channel.reliable, own_port, !channel.nak_control.is_empty()),
            (options.0, options.1, register_at(channel), path_skew),
        );
        // The key counts the entries its paths joined itself, so what the
        // channel's mapping counted only bridged the add: released either
        // way (karyos#1086 review).
        net.release_control_groups(&held);
        added
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
