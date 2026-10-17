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
//!   ([`DriverError::UnsupportedChannel`]). Heap terms only (D3, SPEC §18).
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

use karyos_protocol::channel::{Destination, Interface, UdpConfig};
use karyos_protocol::network::{Alias, Identity, Lanes, TermParams};
use karyos_sys::log_buffer::{DEFAULT_CORRUPT_RETRIES, Role, SenderRead};
use karyos_sys::term_bytes::HeapTerms;

use super::NetworkPublicationState;
use karyos_io::lanes::routes::MAX_ROUTES;

use crate::agents::EndpointId;
use crate::agents::data::{GuardSpec, Outbound};
use crate::embedded::{AggregateConfig, AggregateHandle, EmbeddedDriver, FIRST_INCARNATION};
use crate::error::DriverError;
use crate::guards::{GuardHandle, GuardRate};
use crate::membership::PublicationRoles;
use crate::sessions::send::Publication;

/// Where a channel sends, and the local address its endpoint binds: one
/// per path for a channel with `paths`, the founding path first (control
/// path, may allocate).
fn route(channel: &UdpConfig) -> Result<(SocketAddr, Vec<SocketAddr>), DriverError> {
    let destination = match &channel.destination {
        Destination::Unicast(address) => *address,
        Destination::Multicast { group, .. } => *group,
        Destination::MultiDestination { .. } => return Err(DriverError::UnsupportedChannel),
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
        Some(Interface::Name(_)) => return Err(DriverError::UnsupportedChannel),
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

impl EmbeddedDriver<HeapTerms> {
    /// Creates an aggregate publication, as [`EmbeddedDriver::add_aggregate`]
    /// does, whose lanes the sender agent sends over `channel` (control
    /// path). The publication is posted to the agents; its state is
    /// [`EmbeddedDriver::network_publication_state`]. Removing the
    /// aggregate stops it.
    ///
    /// # Errors
    ///
    /// [`DriverError::NetworkUnavailable`] without a network,
    /// [`DriverError::UnsupportedChannel`], [`DriverError::NetworkEndpoint`],
    /// [`DriverError::NetworkBusy`], [`DriverError::ExportIdsExhausted`] and
    /// the errors of [`EmbeddedDriver::add_aggregate`]. Nothing is left
    /// configured on error. The key of a removed network publication stays
    /// in use while its removal lingers, for up to `publication_linger`
    /// ([`NetworkStreamDefaults::publication_linger`](crate::net::NetworkStreamDefaults)):
    /// [`DriverError::DuplicateStream`] until then, and a retry after it
    /// succeeds.
    pub fn add_network_publication(
        &mut self,
        config: AggregateConfig,
        channel: &UdpConfig,
    ) -> Result<AggregateHandle, DriverError> {
        self.add_network(config, channel, None, None)
    }

    /// [`EmbeddedDriver::add_network_publication`] whose receivers have the
    /// configured `roles` and strategy (MC-1). Driver-internal: the public
    /// way in is owner item 7.
    ///
    /// # Errors
    ///
    /// As [`EmbeddedDriver::add_network_publication`]; the sender refuses
    /// roles its membership cannot hold, which leaves the publication
    /// refused.
    #[allow(
        dead_code,
        reason = "driver-internal until owner item 7 gives roles a public way in"
    )]
    pub(crate) fn add_network_publication_with_roles(
        &mut self,
        config: AggregateConfig,
        channel: &UdpConfig,
        roles: PublicationRoles,
    ) -> Result<AggregateHandle, DriverError> {
        self.add_network(config, channel, None, Some(Box::new(roles)))
    }

    /// [`EmbeddedDriver::add_network_publication`], guarded by `guard`:
    /// every lane stream is guarded before the sender exists, and the
    /// sender runs the guard's gate from its first send. A close is local
    /// on sockets (O-11, GC-6).
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
        self.add_network(config, channel, Some(guard), None)
    }

    fn add_network(
        &mut self,
        config: AggregateConfig,
        channel: &UdpConfig,
        guard: Option<NetworkGuard>,
        roles: Option<Box<PublicationRoles>>,
    ) -> Result<AggregateHandle, DriverError> {
        let Some(net) = self.net.as_mut() else {
            return Err(DriverError::NetworkUnavailable);
        };
        // Redundant paths need sockets isolated per interface; without it
        // they are refused and counted, as for subscriptions.
        if !channel.paths.is_empty() && !net.paths_isolated() {
            net.count_paths_refused();
            return Err(DriverError::UnsupportedChannel);
        }
        let (destination, binds) = route(channel)?;
        let quanta = Lanes::new(&config.quanta).map_err(|_| DriverError::InvalidConfig)?;
        let handle = self.add_aggregate(config)?;
        let added = self.attach_sender(
            &handle,
            destination,
            &binds,
            channel.reliable,
            quanta,
            (guard, roles),
        );
        if let Err(error) = added {
            let _ = self.remove_aggregate(&handle);
            return Err(error);
        }
        Ok(handle)
    }

    /// The state of the network publication `aggregate`; `None` when it
    /// is not one, or once it was removed.
    #[must_use]
    pub fn network_publication_state(
        &self,
        aggregate: &AggregateHandle,
    ) -> Option<NetworkPublicationState> {
        self.net
            .as_ref()?
            .publication_state(aggregate.registration())
    }

    /// Guards every lane stream of `handle` with `guard`, and registers the
    /// publication's sender gate with the guard's owner: the spec the
    /// sender's gate is built from. The streams' guard goes with the
    /// aggregate when it is removed.
    fn guard_lanes(
        &mut self,
        handle: &AggregateHandle,
        guard: Option<NetworkGuard>,
    ) -> Result<Option<(GuardSpec, crate::guard_ack::GuardSenderId)>, DriverError> {
        let Some(guard) = guard else {
            return Ok(None);
        };
        for (lane, stream) in handle.streams().enumerate() {
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
        let word = self.guards.view(guard.guard)?;
        let epoch = self.guards.state(guard.guard)?.epoch;
        let (id, cell) = self.register_guard_sender(guard.guard)?;
        Ok(Some((
            GuardSpec {
                word,
                cell,
                epoch,
                rate: guard.rate.map(|rate| rate.policy),
            },
            id,
        )))
    }

    /// Builds the sender's data path over the lanes of `handle`, guards its
    /// lanes with `guard`, and posts it with the guard's spec and the
    /// receivers' `roles`.
    fn attach_sender(
        &mut self,
        handle: &AggregateHandle,
        destination: SocketAddr,
        binds: &[SocketAddr],
        reliable: bool,
        quanta: Lanes<u64>,
        (guard, roles): (Option<NetworkGuard>, Option<Box<PublicationRoles>>),
    ) -> Result<(), DriverError> {
        let mut guard_sender = None;
        let posted = self.post_sender(
            handle,
            (destination, binds),
            reliable,
            quanta,
            (guard, roles),
            &mut guard_sender,
        );
        // A sender never posted leaves the close acknowledgement at once.
        if posted.is_err()
            && let Some(id) = guard_sender
        {
            let _ = self.deregister_guard_sender(id);
        }
        posted
    }

    fn post_sender(
        &mut self,
        handle: &AggregateHandle,
        (destination, binds): (SocketAddr, &[SocketAddr]),
        reliable: bool,
        quanta: Lanes<u64>,
        (guard, roles): (Option<NetworkGuard>, Option<Box<PublicationRoles>>),
        guard_sender: &mut Option<crate::guard_ack::GuardSenderId>,
    ) -> Result<(), DriverError> {
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
            let reader = SenderRead::new(subscription, DEFAULT_CORRUPT_RETRIES)
                .map_err(|_| DriverError::InvalidConfig)?;
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
        let guard = self.guard_lanes(handle, guard)?;
        *guard_sender = guard.as_ref().map(|(_, id)| *id);
        let (config, alias) = term.ok_or(DriverError::InvalidConfig)?;
        let lane_count = u8::try_from(readers.len()).map_err(|_| DriverError::InvalidConfig)?;
        let publication = |endpoint| Publication {
            endpoint,
            alias,
            identity: Identity {
                driver_id: self.driver_id,
                registration_id: handle.registration(),
                incarnation: FIRST_INCARNATION,
            },
            term: TermParams {
                term_length: config.term_length.get(),
                initial_term_id: config.initial_term_id.get().cast_signed(),
                mtu: config.mtu,
            },
            lane_count,
        };
        let net = self.net.as_mut().ok_or(DriverError::NetworkUnavailable)?;
        // One send endpoint per path, all or nothing.
        let mut held: Vec<(EndpointId, SocketAddr)> = Vec::with_capacity(binds.len());
        for bind in binds {
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
            .map_err(|_| DriverError::InvalidConfig)
            .and_then(|outbound| {
                net.add_publication(
                    handle.registration(),
                    publication(endpoint),
                    Box::new(outbound),
                    guard,
                    roles,
                )
            });
        if posted.is_err() {
            for (endpoint, _) in &held {
                net.release_send_endpoint(*endpoint);
            }
        }
        posted
    }
}

#[cfg(test)]
mod tests;
