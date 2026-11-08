// SPDX-License-Identifier: Apache-2.0

//! Network publications of the embedded driver (wiring note W-d, W2;
//! coordinator ACS 15884): an aggregate publication whose local log the
//! sender agent reads and sends over a UDP channel.
//!
//! - **Interim (W5).** The channel is given to the driver call; the SPEC
//!   client API, a channel URI in the client's `AddPublication`, calls the
//!   same function later.
//! - **Scope.** Unicast and multicast destinations on the trusted
//!   profile, a local bind by address or the default route. Multi-
//!   destination channels and interface names are refused
//!   ([`DriverError::UnsupportedChannel`]). Either backing
//!   (network-shared-terms n4): on an IPC driver the lanes are regions.
//! - **Redundant paths** (redundant-paths.md, rp-w4b2c). A multicast IPv4
//!   channel with `paths` sends on one endpoint per path, bound to that
//!   path's interface address, every path toward the channel's group: one
//!   routed publication. Refused while the sockets cannot be isolated per
//!   path ([`SocketOps::isolates_paths`], owner item 12), as subscriptions
//!   are, and unicast `paths` need a destination per path (owner item 11).
//!   Item 12 also covers the sending side: each path's socket must pick its
//!   multicast interface (`IP_MULTICAST_IF`), not only bind its address.
//! - **Readers.** Each lane's sender reader is a required participant of
//!   its log with an L_send reservation (S2 2.1), so a publisher never
//!   overruns what the sender has not sent.
//!
//! [`SocketOps::isolates_paths`]: karyos_io::sockets::ops::SocketOps::isolates_paths

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use crate::embedded::StreamTerms;
use karyos_protocol::channel::{ControlMode, Destination, FlowControl, Interface, UdpConfig};
use karyos_protocol::network::{Alias, Identity, Lanes, TermParams};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{DEFAULT_CORRUPT_RETRIES, Role, SenderRead};
use karyos_sys::submission_frontier::SubmissionFrontier;

use super::{NetworkPublicationState, SenderChannel};
use karyos_io::lanes::routes::MAX_ROUTES;

use crate::agents::EndpointId;
use crate::agents::data::{GuardSpec, Outbound};
use crate::embedded::{AggregateConfig, AggregateHandle, EmbeddedDriver, FIRST_INCARNATION};
use crate::error::DriverError;
use crate::guards::{GuardHandle, GuardRate};
use crate::membership::{PublicationRoles, Strategy};
use crate::sessions::send::Publication;

/// Where a channel sends, and the local address its endpoint binds: one
/// per path for a channel with `paths`, the founding path first (control
/// path, may allocate).
fn route(channel: &UdpConfig) -> Result<(SocketAddr, Vec<SocketAddr>), DriverError> {
    let destination = match &channel.destination {
        Destination::Unicast(address) => *address,
        Destination::Multicast { group, .. } => *group,
        // A manual destination set sends from one endpoint (design 2.1),
        // bound as for unicast; its first destination stands for the
        // address family. `control` has no meaning in manual mode (design
        // 11.1) and redundant paths are not combined with destinations
        // (ADR-0056).
        Destination::MultiDestination {
            destinations,
            control: None,
            mode: ControlMode::Manual,
        } if channel.paths.is_empty() => *destinations
            .first()
            .ok_or(DriverError::UnsupportedChannel)?,
        // Dynamic registration stays refused until it is implemented and
        // tested (ADR-0082; karyos#644).
        Destination::MultiDestination {
            mode: ControlMode::Dynamic,
            ..
        } => return Err(DriverError::DynamicRegistrationUnsupported),
        Destination::MultiDestination { .. } => return Err(DriverError::UnsupportedChannel),
        // A destination a later protocol version parses: not served.
        _ => return Err(DriverError::UnsupportedChannel),
    };
    if !channel.paths.is_empty() {
        // Multicast IPv4 only: unicast paths need a destination each.
        let (Destination::Multicast { .. }, true) = (
            &channel.destination,
            destination.is_ipv4() && channel.paths.len() <= MAX_ROUTES,
        ) else {
            return Err(DriverError::UnsupportedChannel);
        };
        let mut binds = Vec::with_capacity(channel.paths.len());
        for path in &channel.paths {
            let Interface::Address(ip @ IpAddr::V4(_)) = path else {
                return Err(DriverError::UnsupportedChannel);
            };
            binds.push(SocketAddr::new(*ip, 0));
        }
        return Ok((destination, binds));
    }
    let ip = match &channel.interface {
        Some(Interface::Address(ip)) => *ip,
        // A name, or an interface form a later protocol version parses.
        Some(_) => return Err(DriverError::UnsupportedChannel),
        None if destination.is_ipv4() => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        None => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    Ok((destination, vec![SocketAddr::new(ip, 0)]))
}

/// The destinations of a multi-destination channel and its required ones
/// (design 2.1, 3.5; MD-6, MD-11, MD-17): none for another channel, which
/// names no required destination. At most `max_destinations`, the
/// destinations distinct, of one address family, and the required ones
/// among them.
///
/// # Errors
///
/// [`DriverError::InvalidConfig`] for required destinations on another
/// channel or that are not destinations; [`DriverError::UnsupportedChannel`]
/// for too many destinations, one named twice or mixed families.
fn destinations_of(
    channel: &UdpConfig,
    required: &[SocketAddr],
    max_destinations: usize,
) -> Result<(Vec<SocketAddr>, Vec<SocketAddr>), DriverError> {
    let Destination::MultiDestination { destinations, .. } = &channel.destination else {
        return if required.is_empty() {
            Ok((Vec::new(), Vec::new()))
        } else {
            Err(DriverError::InvalidConfig)
        };
    };
    let family = destinations.first().map(SocketAddr::is_ipv4);
    let distinct = destinations.iter().enumerate().all(|(at, address)| {
        !destinations
            .iter()
            .skip(at + 1)
            .any(|other| other == address)
    });
    if destinations.is_empty()
        || destinations.len() > max_destinations
        || !distinct
        || destinations
            .iter()
            .any(|address| Some(address.is_ipv4()) != family)
    {
        return Err(DriverError::UnsupportedChannel);
    }
    let required_distinct = required
        .iter()
        .enumerate()
        .all(|(at, address)| !required.iter().skip(at + 1).any(|other| other == address));
    if !required_distinct
        || required
            .iter()
            .any(|address| !destinations.contains(address))
    {
        return Err(DriverError::InvalidConfig);
    }
    Ok((destinations.clone(), required.to_vec()))
}

/// The guard of a guarded network publication: every lane stream is
/// guarded by `guard` with an outcome ring of `messages` records and, with
/// `rate`, the publication's rate limit, as
/// [`EmbeddedDriver::guard_stream`] guards a local stream; the sender agent
/// runs its gate (local close only on sockets, O-11 and GC-6).
#[derive(Debug, Clone, Copy)]
pub struct NetworkGuard {
    /// The guard.
    pub guard: GuardHandle,
    /// Outcome records per lane stream (`C_m`).
    pub messages: u64,
    /// The publication's rate limit (GC-5: a channel's lanes are one
    /// publication).
    pub rate: Option<GuardRate>,
}

/// The strategy a network publication of `channel` runs: its `fc`, `min`
/// without one (owner item 7, karyos#637).
///
/// # Errors
///
/// [`DriverError::UnsupportedChannel`] for `fc=tagged:0`, which names no
/// group, or a flow control a later protocol version parses.
pub(crate) fn strategy_of(channel: &UdpConfig) -> Result<Strategy, DriverError> {
    match channel.flow_control {
        None | Some(FlowControl::Min) => Ok(Strategy::Min),
        Some(FlowControl::Max) => Ok(Strategy::Max),
        Some(FlowControl::Tagged(group)) if group != 0 => Ok(Strategy::Tagged(group)),
        Some(_) => Err(DriverError::UnsupportedChannel),
    }
}

impl<T: StreamTerms> EmbeddedDriver<T> {
    /// Creates an aggregate publication, as [`EmbeddedDriver::add_aggregate`]
    /// does, whose lanes the sender agent sends over `channel` (control
    /// path). The publication is posted to the agents; its state is
    /// [`EmbeddedDriver::network_publication_state`]. Removing the
    /// aggregate stops it.
    ///
    /// # Errors
    ///
    /// [`DriverError::NetworkUnavailable`] without a network,
    /// [`DriverError::UnsupportedChannel`] (`fc=tagged:0` included: a
    /// tagged group is never 0), [`DriverError::NetworkEndpoint`],
    /// [`DriverError::NetworkBusy`], [`DriverError::ExportIdsExhausted`] and
    /// the errors of [`EmbeddedDriver::add_aggregate`]. Nothing is left
    /// configured on error. The key of a removed network publication stays
    /// in use while its removal lingers
    /// ([`NetworkStreamDefaults::publication_linger`](crate::net::NetworkStreamDefaults)):
    /// [`DriverError::DuplicateStream`] until the removal ends, at worst
    /// `max(publication_linger, path_heartbeat_interval) +
    /// publication_linger` after it started (about 10 s at the defaults),
    /// and a retry after it succeeds.
    pub fn add_network_publication(
        &mut self,
        config: AggregateConfig,
        channel: &UdpConfig,
    ) -> Result<AggregateHandle, DriverError> {
        self.add_network(config, channel, None, None, None, &[])
    }

    /// [`EmbeddedDriver::add_network_publication`] whose receivers have the
    /// configured `roles`: the required `receiver_id`s and the receivers'
    /// tags (MC-1; owner decisions of 2026-10-21, item 7). The channel's
    /// `fc` stays the one source of the strategy (`min` without one), so
    /// `roles.strategy` must name the same strategy.
    ///
    /// # Errors
    ///
    /// As [`EmbeddedDriver::add_network_publication`],
    /// [`DriverError::InvalidRoles`] for roles a membership cannot hold
    /// ([`crate::membership::check_roles`]), and
    /// [`DriverError::StrategyConflict`] for roles whose strategy is not
    /// the channel's `fc`.
    pub fn add_network_publication_with_roles(
        &mut self,
        config: AggregateConfig,
        channel: &UdpConfig,
        roles: PublicationRoles,
    ) -> Result<AggregateHandle, DriverError> {
        self.add_network(config, channel, None, Some(Box::new(roles)), None, &[])
    }

    /// [`EmbeddedDriver::add_network_publication_with_roles`] on a
    /// multi-destination channel (`control-mode=manual`) whose
    /// `required` destinations, named by endpoint, are required: they
    /// bound the sender and are never removed, and the others are optional
    /// (ADR-0056, ADR-0082; design MD-11, MD-17; karyos#630). `roles`
    /// gives the strategy and any required or tagged receiver ids.
    ///
    /// # Errors
    ///
    /// As [`EmbeddedDriver::add_network_publication`]; also
    /// [`DriverError::InvalidConfig`] for a required destination that is
    /// not one of the channel's.
    pub fn add_network_publication_with_destinations(
        &mut self,
        config: AggregateConfig,
        channel: &UdpConfig,
        roles: Option<PublicationRoles>,
        required: &[SocketAddr],
    ) -> Result<AggregateHandle, DriverError> {
        self.add_network(config, channel, None, roles.map(Box::new), None, required)
    }

    /// [`EmbeddedDriver::add_timed_network_publication`] with `roles`
    /// (tests: a required receiver holds its registered position).
    #[cfg(test)]
    pub(crate) fn add_timed_network_publication_with_roles(
        &mut self,
        config: AggregateConfig,
        channel: &UdpConfig,
        roles: PublicationRoles,
        schedule: karyos_client::schedule::ScheduleOptions,
    ) -> Result<AggregateHandle, DriverError> {
        self.add_network(
            config,
            channel,
            None,
            Some(Box::new(roles)),
            Some((schedule, None)),
            &[],
        )
    }

    /// [`EmbeddedDriver::add_network_publication`], guarded by `guard`:
    /// every lane stream is guarded before the sender exists, and the
    /// sender runs the guard's gate from its first send. A close is local
    /// on sockets (O-11, GC-6).
    ///
    /// Each lane's outcome records follow the gate's submissions
    /// (`crate::guard_streams`): a message's reservation is released when a
    /// backend takes it, not at commit, so the publisher holds at most
    /// `guard.messages` (`C_m`) messages committed and not yet sent, and
    /// the lane's effective window is the smaller of its receivers' and
    /// `C_m` messages.
    ///
    /// # Errors
    ///
    /// Those of [`EmbeddedDriver::add_network_publication`], of
    /// [`EmbeddedDriver::guard_stream`] and of
    /// [`EmbeddedDriver::register_guard_sender`]. Nothing is left
    /// configured on error.
    pub fn add_guarded_network_publication(
        &mut self,
        config: AggregateConfig,
        channel: &UdpConfig,
        guard: NetworkGuard,
    ) -> Result<AggregateHandle, DriverError> {
        self.add_network(config, channel, Some(guard), None, None, &[])
    }

    /// [`EmbeddedDriver::add_network_publication`] whose lanes are timed
    /// (`quantstratum-docs: karyos/design/timed-tx.md`; P2.11, the software
    /// route): every lane of `config` has a schedule ring
    /// (`schedule_capacity`), takes `schedule` as its settings
    /// ([`EmbeddedDriver::schedule_stream`], fixed from the add on), and
    /// its sender holds each message until its requested time, one message
    /// per datagram, then sends it. A plain network publication whose lanes
    /// have a ring is timed with the default settings. Guarded by `guard`,
    /// if any, as [`EmbeddedDriver::add_guarded_network_publication`].
    ///
    /// The sender times heads on the network clock, the host monotonic
    /// clock, as `ClockDomain::Monotonic` offers are timed; no time
    /// namespace is checked, as on the local route.
    ///
    /// On a reliable channel a message's schedule entry is held until the
    /// receivers acknowledge it (the lane's registered position passes
    /// it), so a reset can read it again: `schedule_capacity` must cover
    /// the unacknowledged window, or offers are back-pressured until the
    /// receivers consume. A message read again after a reset is resent at
    /// once, outside the late policy, and counted as rewound, not late.
    /// NAK repairs go through the repair path, never the timed gate.
    ///
    /// # Errors
    ///
    /// [`DriverError::TimedNetworkUnsupported`] for a channel with paths,
    /// the `Tai` domain, cancel-on-deadline or a `max_horizon` that, with
    /// one `sender_heartbeat_interval`, reaches
    /// `image_liveness_timeout`;
    /// [`DriverError::InvalidConfig`] for lanes with no schedule ring; the
    /// errors of [`EmbeddedDriver::add_network_publication`] and of
    /// [`EmbeddedDriver::schedule_stream`]. Nothing is left configured on
    /// error.
    pub fn add_timed_network_publication(
        &mut self,
        config: AggregateConfig,
        channel: &UdpConfig,
        guard: Option<NetworkGuard>,
        schedule: karyos_client::schedule::ScheduleOptions,
    ) -> Result<AggregateHandle, DriverError> {
        if config.stream.buffer.schedule_capacity == 0 {
            return Err(DriverError::InvalidConfig);
        }
        self.add_network(config, channel, guard, None, Some((schedule, None)), &[])
    }

    /// Undoes an add refused before its handle was returned
    /// (karyos#859): its lanes are removed and freed at once, as no client,
    /// lease or sender holds them, so the same key can be added again in
    /// this cycle; a retry after `ResourcesUnavailable` never meets
    /// `DuplicateStream`.
    fn discard_refused(&mut self, handle: &AggregateHandle) {
        let _ = self.remove_aggregate(handle);
        self.free_retired_streams();
    }

    /// [`EmbeddedDriver::add_timed_network_publication`] whose lanes check
    /// offers against `clock`, as
    /// [`EmbeddedDriver::schedule_stream_with_clock`] does for a stream: a
    /// network lane takes its settings and its clock at creation, both
    /// fixed for the publication's life. The sender still times heads on
    /// the network clock.
    ///
    /// # Errors
    ///
    /// As [`EmbeddedDriver::add_timed_network_publication`].
    pub fn add_timed_network_publication_with_clock(
        &mut self,
        config: AggregateConfig,
        channel: &UdpConfig,
        guard: Option<NetworkGuard>,
        schedule: karyos_client::schedule::ScheduleOptions,
        clock: karyos_client::schedule::ScheduleClock,
    ) -> Result<AggregateHandle, DriverError> {
        if config.stream.buffer.schedule_capacity == 0 {
            return Err(DriverError::InvalidConfig);
        }
        self.add_network(
            config,
            channel,
            guard,
            None,
            Some((schedule, Some(clock))),
            &[],
        )
    }

    pub(crate) fn add_network(
        &mut self,
        config: AggregateConfig,
        channel: &UdpConfig,
        guard: Option<NetworkGuard>,
        roles: Option<Box<PublicationRoles>>,
        schedule: Option<(
            karyos_client::schedule::ScheduleOptions,
            Option<karyos_client::schedule::ScheduleClock>,
        )>,
        required_destinations: &[SocketAddr],
    ) -> Result<AggregateHandle, DriverError> {
        let Some(net) = self.net.as_mut() else {
            return Err(DriverError::NetworkUnavailable);
        };
        // The channel's `fc` is the strategy (owner item 7, karyos#637):
        // typed roles name the same one, and `max` or `tagged:<group>`
        // without roles runs on a membership with no required or tagged
        // receiver. A tagged group of 0 is no group: refused, not run as
        // `min`.
        let strategy = strategy_of(channel)?;
        if let Some(roles) = &roles {
            crate::membership::check_roles(
                &roles.roles(),
                crate::membership::DEFAULT_MAX_RECEIVERS,
            )
            .map_err(|_| DriverError::InvalidRoles)?;
        }
        let roles = match roles {
            Some(roles) if roles.strategy != strategy => {
                return Err(DriverError::StrategyConflict);
            }
            None if strategy != Strategy::Min => Some(Box::new(PublicationRoles {
                strategy,
                required: Vec::new(),
                tags: Vec::new(),
            })),
            roles => roles,
        };
        // Timed lanes (a schedule ring on every lane): what the software
        // route does not support yet is refused before anything exists.
        let (options, clock) = schedule.unwrap_or_default();
        let timed = (config.stream.buffer.schedule_capacity > 0).then_some(options);
        if let Some(options) = timed {
            let liveness = self.config.network.map(|network| {
                (
                    network.agents.image_liveness_timeout,
                    network.agents.sender_heartbeat_interval,
                )
            });
            timed_supported(channel, options, liveness)?;
        }
        // Redundant paths need sockets isolated per interface; without it
        // they are refused and counted, as for subscriptions.
        if !channel.paths.is_empty() && !net.paths_isolated() {
            net.count_paths_refused();
            return Err(DriverError::UnsupportedChannel);
        }
        let (destination, binds) = route(channel)?;
        let max_destinations = net.max_destinations();
        let destinations = destinations_of(channel, required_destinations, max_destinations)?;
        // Guards and timed lanes are not combined with destinations yet
        // (karyos#630).
        if !destinations.0.is_empty() && (guard.is_some() || timed.is_some()) {
            return Err(DriverError::UnsupportedChannel);
        }
        let quanta = Lanes::new(&config.quanta).map_err(|_| DriverError::InvalidConfig)?;
        // The channel's `retransmit-window` (owner item 63), fixed here, at
        // channel creation: at most half the term. Its other bounds, nonzero
        // and a multiple of 32, are the URI's.
        if let Some(window) = channel.retransmit_window {
            let term_length = config.stream.buffer.term_length.get();
            if window > term_length / 2 {
                return Err(DriverError::RetransmitWindowAboveHalfTerm {
                    window,
                    term_length,
                });
            }
        }
        // The incarnation's first term id, drawn on the control path before
        // the publication and its SETUP exist (SPEC §4, initial state; §5),
        // shared by every lane; a failed draw refuses the add.
        let forced = self
            .config
            .network
            .and_then(|network| network.stream_defaults.initial_term_id);
        let mut config = config;
        config.stream.buffer.initial_term_id = self.draw_initial_term_id(forced)?;
        let handle = self.add_aggregate_drawn(config)?;
        if let Some(options) = timed
            && let Err(error) = self.time_lanes(&handle, options, clock)
        {
            self.discard_refused(&handle);
            return Err(error);
        }
        let channel = SenderChannel {
            destination,
            destinations: destinations.0,
            required_destinations: destinations.1,
            binds,
            reliable: channel.reliable,
            quanta,
            guard,
            roles,
            retransmit_window: channel.retransmit_window,
        };
        let added = self.attach_sender(&handle, channel, FIRST_INCARNATION, false);
        if let Err(error) = added {
            self.discard_refused(&handle);
            return Err(error);
        }
        Ok(handle)
    }

    /// Applies `options` to every lane of `handle` and allocates its timed
    /// counters, before the sender exists; the settings are fixed from
    /// then on, as once a handle is issued.
    fn time_lanes(
        &mut self,
        handle: &AggregateHandle,
        options: karyos_client::schedule::ScheduleOptions,
        clock: Option<karyos_client::schedule::ScheduleClock>,
    ) -> Result<(), DriverError> {
        for stream in handle.streams() {
            match &clock {
                Some(clock) => self.schedule_stream_with_clock(stream, options, clock.clone())?,
                None => self.schedule_stream(stream, options)?,
            }
            self.ensure_timed_counters(stream)?;
            self.stream(stream)?.fix_schedule()?;
        }
        Ok(())
    }

    /// The state of the network publication `aggregate`; `None` when it
    /// is not one, or once it was removed.
    /// [`NetworkPublicationState::Reincarnating`] while it is between
    /// incarnations after a guard reopen.
    #[must_use]
    pub fn network_publication_state(
        &self,
        aggregate: &AggregateHandle,
    ) -> Option<NetworkPublicationState> {
        self.net
            .as_ref()?
            .publication_state(aggregate.registration())
    }

    /// The admission state of the network publication `aggregate`, as its
    /// sender last observed it (owner item 7, karyos#637): `Open`,
    /// `NotJoined` while a configured required receiver has not joined, or
    /// `LostRequired` once one is lost. `None` before the sender's first
    /// cycle, and for an aggregate that is not a network publication. It is
    /// the last state observed, not a list of transitions: the membership
    /// counters count those. Offers keep the existing outcome mapping:
    /// under `NotJoined` and `LostRequired` the sender stages nothing, so
    /// the publication fills its window and offers answer `BackPressured`.
    #[must_use]
    pub fn network_publication_admission(
        &self,
        aggregate: &AggregateHandle,
    ) -> Option<karyos_protocol::cnc::NetworkAdmission> {
        self.net
            .as_ref()?
            .publication_admission(aggregate.registration())
    }

    /// Adds the optional destination `destination` to the multi-destination
    /// publication `aggregate` at run time (MD-3; ADR-0082; karyos#630):
    /// it is announced to and joins at the sender's position, and a
    /// receiver there NAKs what it missed. An optional destination moves by
    /// [`EmbeddedDriver::remove_network_destination`] and this. The
    /// sender answers through
    /// [`EmbeddedDriver::take_network_destination_changes`]: refused for a
    /// required destination (fixed at creation), one already present, one
    /// removed less than `image_liveness_timeout` ago (MD-14), or a full
    /// set. A removed destination holds its slot until its removal is
    /// reported, in the sender cycle of the removal: a move at
    /// `max_destinations` answers `Full` until then, and a move retried
    /// after the removal shows in
    /// [`EmbeddedDriver::network_removed_destinations`] finds the slot
    /// free.
    ///
    /// # Errors
    ///
    /// [`DriverError::NetworkUnavailable`], [`DriverError::InvalidConfig`]
    /// for no such active network publication,
    /// [`DriverError::EndpointCapacity`] when its endpoint cannot hold one
    /// more route with its queues, counting the additions not answered yet
    /// (karyos#859; retryable once room is freed),
    /// [`DriverError::NetworkBusy`] when the sender's ring is full or
    /// `max_destinations` additions wait for their answer (nothing
    /// changes; retry).
    pub fn add_network_destination(
        &mut self,
        aggregate: &AggregateHandle,
        destination: SocketAddr,
    ) -> Result<(), DriverError> {
        self.net
            .as_mut()
            .ok_or(DriverError::NetworkUnavailable)?
            .change_destination(aggregate.registration(), destination, true)
    }

    /// Removes the optional destination `destination` of the
    /// multi-destination publication `aggregate` at run time (MD-3): it is
    /// sent nothing more, reported as removed by command
    /// ([`EmbeddedDriver::network_removed_destinations`]), and quarantined
    /// before it can be added again (MD-14). A required destination is
    /// never removed (ADR-0082). Answered as
    /// [`EmbeddedDriver::add_network_destination`].
    ///
    /// # Errors
    ///
    /// As [`EmbeddedDriver::add_network_destination`].
    pub fn remove_network_destination(
        &mut self,
        aggregate: &AggregateHandle,
        destination: SocketAddr,
    ) -> Result<(), DriverError> {
        self.net
            .as_mut()
            .ok_or(DriverError::NetworkUnavailable)?
            .change_destination(aggregate.registration(), destination, false)
    }

    /// The sender's answers to the destination changes of `aggregate`,
    /// oldest first (the latest `max_destinations`), taken.
    pub fn take_network_destination_changes(
        &mut self,
        aggregate: &AggregateHandle,
    ) -> Vec<(SocketAddr, crate::agents::data::DestinationChange)> {
        self.net
            .as_mut()
            .map(|net| net.take_destination_changes(aggregate.registration()))
            .unwrap_or_default()
    }

    /// The destinations the multi-destination publication `aggregate` has
    /// removed, the newest `max_destinations` in order, each with its
    /// reason: an optional destination whose queue was full (MD-7), whose
    /// sends kept faulting (MD-12), or removed by command (MD-3)
    /// (karyos#630). Empty for another publication.
    #[must_use]
    pub fn network_removed_destinations(
        &self,
        aggregate: &AggregateHandle,
    ) -> Vec<crate::agents::data::DestinationRemoval> {
        self.net
            .as_ref()
            .map(|net| net.removed_destinations(aggregate.registration()))
            .unwrap_or_default()
    }

    /// How many removals of `aggregate`'s destinations were overwritten in
    /// [`Self::network_removed_destinations`], which keeps the newest
    /// `max_destinations` (karyos#630).
    #[must_use]
    pub fn network_removals_overwritten(&self, aggregate: &AggregateHandle) -> u64 {
        self.net
            .as_ref()
            .map_or(0, |net| net.removals_overwritten(aggregate.registration()))
    }

    /// Guards every lane stream of `handle` with `guard`, unless a
    /// reincarnation already did (`guarded`), and registers the
    /// publication's sender gate with the guard's owner: the spec the
    /// sender's gate is built from. The streams' guard goes with the
    /// aggregate when it is removed.
    fn guard_lanes(
        &mut self,
        handle: &AggregateHandle,
        guard: Option<NetworkGuard>,
        guarded: bool,
    ) -> Result<Option<(GuardSpec, crate::guard_ack::GuardSenderId)>, DriverError> {
        let Some(guard) = guard else {
            return Ok(None);
        };
        for (lane, stream) in handle.streams().enumerate().filter(|_| !guarded) {
            #[cfg(test)]
            if self.guard_lane_fault == Some(lane) {
                return Err(DriverError::GuardWalkerUnavailable {
                    stream: self.stream(stream)?.id,
                    reason: crate::WalkerUnavailable::NoSpareCredit,
                });
            }
            #[cfg(not(test))]
            let _ = lane;
            self.guard_stream(stream, guard.guard, guard.messages, guard.rate)?;
        }
        // The gate reads the policy its lanes publish (R-CORE-21): one slot
        // for the publication, kept across its incarnations.
        let slot = handle.streams().next().and_then(|stream| {
            self.stream(stream)
                .ok()?
                .guarded
                .as_ref()?
                .gate_slot()
                .cloned()
        });
        let slot = match slot {
            Some(slot) => slot,
            None => {
                let slot = Arc::new(crate::shared_words::Words::heap(
                    karyos_sys::rate_policy_slot::SLOT_WORDS,
                ));
                // Published once, by the first guarded lane; the others
                // keep the same slot.
                let mut published = false;
                for stream in handle.streams() {
                    if let Some(guarded) = self.stream(stream)?.guarded.as_mut() {
                        if published {
                            guarded.keep_gate_slot(Arc::clone(&slot));
                        } else {
                            guarded.set_gate_slot(Arc::clone(&slot));
                            published = true;
                        }
                    }
                }
                slot
            }
        };
        // The gate starts from the publication's policy in force, a change
        // or a policy given to its rateless lanes included, not the one it
        // was guarded with (R-CORE-21).
        let rate = handle
            .streams()
            .find_map(|stream| self.stream_ref(stream).ok()?.guarded.as_ref()?.rate);
        // The gate reads word 0: the guard's word in the guard words.
        let (words, index) = self.guards.view(guard.guard)?;
        let word = Arc::new(crate::shared_words::WordAt::new(words, index))
            as Arc<dyn karyos_client::SharedWords>;
        let epoch = self.guards.state(guard.guard)?.epoch;
        // The walker records each lane's outcomes by its sender gate's
        // submissions, not at commit.
        let frontier = Arc::new(SubmissionFrontier::new());
        for (index, stream) in handle.streams().enumerate() {
            let lane = u8::try_from(index)
                .ok()
                .and_then(|index| Lane::try_new(index).ok())
                .ok_or(DriverError::InvalidConfig)?;
            if let Some(guarded) = self.stream(stream)?.guarded.as_mut() {
                guarded.submit_through(Arc::clone(&frontier), lane);
            }
        }
        // A reincarnation's gate starts empty when it began, the time its
        // handles' rings carry too (R-CORE-21); 0, unknown, is now. A
        // network publication's lanes reincarnate together, in one step
        // (`reincarnate_network`), so its first lane's time is every lane's.
        let empty_since = guarded.then(|| {
            handle
                .streams()
                .find_map(|stream| {
                    self.stream_ref(stream)
                        .ok()
                        .map(|found| found.reincarnated_at)
                })
                .filter(|at| *at != 0)
                .unwrap_or_else(karyos_sys::host_clock::host_monotonic_ns)
        });
        let (id, cell) = self.register_guard_sender(guard.guard)?;
        Ok(Some((
            GuardSpec {
                word,
                cell,
                epoch,
                rate,
                empty_since,
                policy: Some(slot as Arc<dyn karyos_client::SharedWords>),
                frontier,
            },
            id,
        )))
    }

    /// Builds the sender's data path over the lanes of `handle` for its
    /// `incarnation`, guards its lanes with the channel's guard (unless a
    /// reincarnation already did, `guarded`), and posts it with the
    /// guard's spec and the receivers' roles.
    pub(crate) fn attach_sender(
        &mut self,
        handle: &AggregateHandle,
        channel: SenderChannel,
        incarnation: u64,
        guarded: bool,
    ) -> Result<(), DriverError> {
        let mut guard_sender = None;
        let posted = self.post_sender(handle, channel, (incarnation, guarded), &mut guard_sender);
        // A sender never posted leaves the close acknowledgement at once,
        // and no gate will ever decide its lanes.
        if posted.is_err()
            && let Some((id, frontier)) = guard_sender
        {
            let _ = self.deregister_guard_sender(id);
            crate::net::supersede(&frontier, handle.lanes());
        }
        posted
    }

    fn post_sender(
        &mut self,
        handle: &AggregateHandle,
        channel: SenderChannel,
        (incarnation, guarded): (u64, bool),
        guard_sender: &mut Option<(crate::guard_ack::GuardSenderId, Arc<SubmissionFrontier>)>,
    ) -> Result<(), DriverError> {
        let kept = channel.clone();
        let SenderChannel {
            destination,
            destinations,
            required_destinations,
            binds,
            reliable,
            quanta,
            guard,
            roles,
            retransmit_window,
        } = channel;
        let mut readers = Vec::with_capacity(usize::from(handle.lanes()));
        let mut term = None;
        let mut occupant = self.next_export;
        for stream in handle.streams() {
            let next = occupant
                .checked_add(1)
                .ok_or(DriverError::ExportIdsExhausted)?;
            let target = self.stream(stream)?;
            let config = target.config;
            term.get_or_insert((
                config,
                Alias {
                    session_id: target.session_id,
                    stream_id: target.stream_id,
                },
            ));
            let subscription = target
                .conductor
                .subscribe_as(Role::Required, true, occupant)
                .map_err(|_| DriverError::InvalidConfig)?;
            let mut reader = SenderRead::new(subscription, DEFAULT_CORRUPT_RETRIES)
                .map_err(|_| DriverError::InvalidConfig)?;
            // A reliable lane's retention hold, the floor at `sent -
            // retransmit_window` (quantstratum-docs:
            // karyos/design/retention-floor-optional-receivers.md), as its
            // own occupant, from the reader's registered position; an
            // unreliable lane has none. A full registry refuses the
            // publication; the reader frees the hold on drop, and a hold it
            // refused is freed here.
            let next = if reliable {
                let hold = target
                    .conductor
                    .admit_hold(next, reader.sent_position())
                    .map_err(|_| DriverError::RetentionHoldUnavailable { stream: target.id })?;
                if let Err((_, hold)) = reader.with_hold(hold) {
                    let _ = target.conductor.release_hold(hold);
                    return Err(DriverError::InvalidConfig);
                }
                next.checked_add(1).ok_or(DriverError::ExportIdsExhausted)?
            } else {
                next
            };
            // Unconnected until a receiver's status messages are live
            // (SPEC.md §4): before any client is granted the publication.
            let _ = reader.set_receivers_live(false);
            readers.push(reader);
            occupant = next;
        }
        self.next_export = occupant;
        // Guarded after the sender's readers hold their reservations, so a
        // stream short of spare slots for its walker says so
        // (`GuardWalkerUnavailable`).
        let guard = self.guard_lanes(handle, guard, guarded)?;
        *guard_sender = guard
            .as_ref()
            .map(|(spec, id)| (*id, Arc::clone(&spec.frontier)));
        let (config, alias) = term.ok_or(DriverError::InvalidConfig)?;
        let lane_count = u8::try_from(readers.len()).map_err(|_| DriverError::InvalidConfig)?;
        let publication = |endpoint| Publication {
            endpoint,
            alias,
            identity: Identity {
                driver_id: self.driver_id,
                registration_id: handle.registration(),
                incarnation,
            },
            term: TermParams {
                term_length: config.term_length.get(),
                initial_term_id: config.initial_term_id.get().cast_signed(),
                mtu: config.mtu,
            },
            lane_count,
        };
        // Timed lanes: each one's tolerance and counter cells, for its
        // sender's timed gate.
        let mut timed = None;
        for stream in handle.streams() {
            let cells = self.timed_counters(stream)?;
            let found = self.stream_ref(stream)?;
            if found.buffer.schedule_ring().is_none() {
                continue;
            }
            let (policies, counters) = timed.get_or_insert_with(|| {
                (
                    Vec::with_capacity(usize::from(handle.lanes())),
                    Vec::with_capacity(usize::from(handle.lanes())),
                )
            });
            let options = found.schedule.unwrap_or_default();
            policies.push(crate::timed_gate::LatePolicy {
                tolerance: options.lateness_tolerance,
                cancel_on_deadline: false,
                max_horizon: options.max_horizon,
            });
            counters.push(cells);
        }
        let cells = crate::embedded::stream_network_cells(
            &mut self.counters,
            handle.registration(),
            &crate::agents::PUBLICATION_CELLS,
        );
        let net = self.net.as_mut().ok_or(DriverError::NetworkUnavailable)?;
        // One send endpoint per path, all or nothing.
        let mut held: Vec<(EndpointId, SocketAddr)> = Vec::with_capacity(binds.len());
        for bind in &binds {
            match net.hold_send_endpoint(*bind) {
                Ok(endpoint) => held.push((endpoint, destination)),
                Err(error) => {
                    for (endpoint, _) in held {
                        net.release_send_endpoint(endpoint);
                    }
                    return Err(error);
                }
            }
        }
        let &(endpoint, _) = held.first().ok_or(DriverError::InvalidConfig)?;
        // The family of every destination: the shared endpoint's own. An
        // endpoint of unknown address is not taken for IPv4: its
        // destinations are refused (plan 157, point 6).
        let ipv4 = net
            .endpoint_address(endpoint)
            .map(|address| address.is_ipv4());
        let max_destinations = net.max_destinations();
        let outbound = if held.len() > 1 {
            Outbound::new_routed(&held, alias, readers, &quanta, config.mtu, reliable)
        } else {
            Outbound::new(
                endpoint,
                alias,
                destination,
                readers,
                &quanta,
                config.mtu,
                reliable,
            )
            .and_then(|mut outbound| {
                if !destinations.is_empty() {
                    outbound.set_destinations(
                        max_destinations,
                        &destinations,
                        &required_destinations,
                        ipv4,
                    )?;
                }
                Ok(outbound)
            })
        };
        let posted = outbound
            .and_then(|mut outbound| {
                if let Some((policies, counters)) = timed {
                    let now = karyos_sys::host_clock::host_monotonic_ns();
                    outbound.set_timed(&policies, counters, now)?;
                }
                // Its counters' cells (M2b), dropped with the outbound if
                // it is refused (a dropped cell is reused).
                if let Some(cells) = cells {
                    outbound.set_cells(cells);
                }
                outbound.set_retransmit_window(retransmit_window);
                Ok(outbound)
            })
            .map_err(|_| DriverError::InvalidConfig)
            .and_then(|outbound| {
                net.add_publication(
                    handle.registration(),
                    publication(endpoint),
                    Box::new(outbound),
                    guard,
                    roles,
                    kept,
                )
            });
        if posted.is_err() {
            for (endpoint, _) in &held {
                net.release_send_endpoint(*endpoint);
            }
            return posted;
        }
        // Its sender serves this incarnation of every lane.
        for stream in handle.streams() {
            self.stream(stream)?.network = crate::embedded::NetworkLane::Sending;
        }
        Ok(())
    }
}

/// Refuses what a timed network publication does not support yet (P2.11
/// PR1).
fn timed_supported(
    channel: &UdpConfig,
    options: karyos_client::schedule::ScheduleOptions,
    liveness: Option<(u64, u64)>,
) -> Result<(), DriverError> {
    use crate::error::TimedNetworkUnsupported as Unsupported;

    let reason = if !channel.paths.is_empty() {
        Some(Unsupported::Routed)
    } else if options.domain == karyos_client::schedule::ClockDomain::Tai {
        Some(Unsupported::TaiDomain)
    } else if options.cancel_on_deadline {
        Some(Unsupported::CancelOnDeadline)
    } else if liveness.is_some_and(|(liveness, heartbeat)| {
        // A lane's last heartbeat can come one interval before its held
        // head: the silence is up to the horizon plus that interval.
        options
            .max_horizon
            .checked_add(heartbeat)
            .is_none_or(|silence| silence >= liveness)
    }) {
        Some(Unsupported::HorizonPastLiveness)
    } else {
        None
    };
    reason.map_or(Ok(()), |reason| {
        Err(DriverError::TimedNetworkUnsupported { reason })
    })
}

#[cfg(test)]
mod tests;
