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
use karyos_protocol::channel::{Destination, FlowControl, Interface, UdpConfig};
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
        self.add_network(config, channel, None, None, None)
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
        self.add_network(config, channel, None, Some(Box::new(roles)), None)
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
        self.add_network(config, channel, Some(guard), None, None)
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
        self.add_network(config, channel, guard, None, Some((schedule, None)))
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
        self.add_network(config, channel, guard, None, Some((schedule, Some(clock))))
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
        let quanta = Lanes::new(&config.quanta).map_err(|_| DriverError::InvalidConfig)?;
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
            let _ = self.remove_aggregate(&handle);
            return Err(error);
        }
        let channel = SenderChannel {
            destination,
            binds,
            reliable: channel.reliable,
            quanta,
            guard,
            roles,
        };
        let added = self.attach_sender(&handle, channel, FIRST_INCARNATION, false);
        if let Err(error) = added {
            let _ = self.remove_aggregate(&handle);
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
        let (id, cell) = self.register_guard_sender(guard.guard)?;
        Ok(Some((
            GuardSpec {
                word,
                cell,
                epoch,
                rate: guard.rate.map(|rate| rate.policy),
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
            binds,
            reliable,
            quanta,
            guard,
            roles,
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
