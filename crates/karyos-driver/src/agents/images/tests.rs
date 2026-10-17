// SPDX-License-Identifier: Apache-2.0

//! The image chain over real loopback sockets (phase 4b-2): an accepted
//! answer becomes an installed image; a late `ImageReady` is released;
//! the storage limits refuse before allocating; stale replies are counted.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::net::SocketAddr;
use std::time::Duration;

use karyos_io::sockets::OsSocket;
use karyos_io::sockets::endpoint::SocketsConfig;
use karyos_protocol::network::{Alias, Identity, Lanes, SetupAnnounce, TermParams};

use super::super::endpoints::{EndpointEvent, Endpoints};
use super::super::{AgentCommand, AgentConfig, AgentLinks, NetworkAgents, network_agents};
use super::*;
use crate::sessions::send::Publication;

type Agents = NetworkAgents<OsSocket>;
type Links = AgentLinks<OsSocket>;

const MS: u64 = 1_000_000;

/// Units of each session ring (the default `session_command_capacity`).
const FULL: usize = 192;

fn alias() -> Alias {
    Alias {
        session_id: 5,
        stream_id: 6,
    }
}

fn identity() -> Identity {
    Identity {
        driver_id: [1, 2],
        registration_id: 3,
        incarnation: 1,
    }
}

fn term(term_length: u32) -> TermParams {
    TermParams {
        term_length,
        initial_term_id: 9,
        mtu: 1408,
    }
}

/// What a rig announces and accepts.
#[derive(Clone)]
struct Setup {
    /// The publication's term length.
    term_length: u32,
    /// The subscription's `max_image_term_length`.
    max_term_length: u32,
    template: ImageTemplate,
    /// Whether the channel is reliable: the sender is then a required
    /// participant of its log.
    reliable: bool,
    /// The receiver's `alias_quarantine`, when not the default.
    alias_quarantine: Option<u64>,
    /// Whether the sender answers NAKs; tests of the receiver's loss
    /// handling answer them by hand instead.
    repairs: bool,
    /// Whether the subscription's endpoint receives a multicast group: its
    /// images time their NAKs by cycle (the rig still runs on loopback
    /// unicast).
    multicast: bool,
    /// A fixed multicast NAK delay in place of the random draw.
    nak_delay: Option<u64>,
    /// A guarded publication's guard.
    guard: Option<super::super::data::GuardSpec>,
    /// Whether the subscription has a NAK control group: a third loopback
    /// endpoint C stands for it, its own address as the group.
    control_group: bool,
    /// The receiver's `group_nak_budget`, when not the default.
    group_nak_budget: Option<u32>,
    /// Messages on each lane before the sender's reader subscribes: the
    /// image then joins above 0.
    before: u8,
    /// The subscription's configured receiver identity (MC-1).
    identity: Option<crate::membership::ReceiverIdentity>,
    /// The publication's configured roles (MC-1), built at the add.
    roles: Option<fn() -> crate::membership::PublicationRoles>,
    /// The subscription's conflated lane (conflated-network-images.md).
    conflated: Option<Lane>,
}

impl Setup {
    /// The same setup without its guard, for a second rig or path.
    fn again(&self) -> Self {
        Self {
            guard: None,
            ..*self
        }
    }
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            term_length: 65_536,
            max_term_length: DEFAULT_MAX_IMAGE_TERM_LENGTH,
            template: ImageTemplate::default(),
            reliable: false,
            alias_quarantine: None,
            repairs: true,
            multicast: false,
            nak_delay: None,
            guard: None,
            control_group: false,
            group_nak_budget: None,
            before: 0,
            identity: None,
            roles: None,
            conflated: None,
        }
    }
}

std::thread_local! {
    /// The rig's virtual time, which the agents' own clocks read: the
    /// sender stamps submissions with it, as the driver clock would.
    static VIRTUAL_NOW: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

fn virtual_now() -> u64 {
    VIRTUAL_NOW.with(std::cell::Cell::get)
}

struct Rig {
    /// The publishing endpoint A.
    publisher: EndpointId,
    /// The control group endpoint C, with `Setup::control_group`.
    control: Option<EndpointId>,
    /// The publication's log on A (64 KiB terms, whatever is announced).
    log: Option<super::super::data::testing::TestLog>,
    /// A second publisher's log, with [`Rig::second_publisher`].
    second: Option<super::super::data::testing::TestLog>,
    agents: Agents,
    links: Links,
    endpoints: Endpoints<OsSocket>,
    images: ImageTable,
    events: Vec<ImageEvent>,
    now: u64,
}

impl Rig {
    /// Two loopback endpoints A and B, and a publication of two lanes on A
    /// announced to B: published on A, subscribed on B.
    fn new(setup: Setup) -> (Self, EndpointId) {
        let mut config = AgentConfig::default();
        if let Some(quarantine) = setup.alias_quarantine {
            config.sessions.alias_quarantine = quarantine;
        }
        if let Some(budget) = setup.group_nak_budget {
            config.group_nak_budget = budget;
        }
        let (mut agents, links) = network_agents::<OsSocket>(config).unwrap();
        VIRTUAL_NOW.with(|now| now.set(0));
        agents.sender.role.set_clock(virtual_now);
        agents.receiver.role.set_clock(virtual_now);
        if !setup.repairs {
            agents.sender.role.ignore_naks();
        }
        if let Some(delay) = setup.nak_delay {
            agents.receiver.role.fix_nak_delay(delay);
        }
        let mut rig = Self {
            publisher: EndpointId(u32::MAX),
            control: None,
            log: None,
            second: None,
            agents,
            links,
            endpoints: Endpoints::new(&config),
            images: ImageTable::new(config.sessions.max_images, setup.template),
            events: Vec::new(),
            now: 0,
        };
        let loopback = SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
        let a = rig
            .endpoints
            .open(&rig.links, loopback, OsSocket::new())
            .unwrap();
        let b = rig
            .endpoints
            .open(&rig.links, loopback, OsSocket::new())
            .unwrap();
        let control = setup.control_group.then(|| {
            rig.endpoints
                .open(&rig.links, loopback, OsSocket::new())
                .unwrap()
        });
        let endpoints = 2 + usize::from(control.is_some());
        let mut opened = 0;
        for _ in 0..100 {
            rig.agents.do_work(0).unwrap();
            rig.endpoints.poll(
                &rig.links,
                rig.now,
                |event| opened += usize::from(matches!(event, EndpointEvent::Opened(_))),
                |_| {},
            );
            if opened == endpoints {
                break;
            }
        }
        assert_eq!(opened, endpoints);
        rig.publisher = a;
        rig.control = control;
        let control_group =
            control.map(|control| (control, rig.endpoints.local_address(control).unwrap()));
        let destination = rig.endpoints.local_address(b).unwrap();
        rig.links
            .receiver
            .post(|reply| AgentCommand::AddPublishedAlias {
                reply,
                endpoint: a,
                alias: alias(),
            })
            .unwrap();
        rig.links
            .receiver
            .post(|reply| AgentCommand::AddSubscription {
                reply,
                endpoint: b,
                stream_id: alias().stream_id,
                max_term_length: setup.max_term_length,
                reliable: setup.reliable,
                multicast: setup.multicast,
                control_group,
                identity: setup.identity,
                conflated: setup.conflated,
            })
            .unwrap();
        // The log's terms stay small: a refused size is only announced.
        let (outbound, log) = super::super::data::testing::outbound_joined(
            a,
            alias(),
            destination,
            term(65_536),
            2,
            setup.reliable,
            setup.before,
        );
        rig.log = Some(log);
        rig.links
            .sender
            .post(|reply| AgentCommand::AddPublication {
                reply,
                publication: Publication {
                    endpoint: a,
                    alias: alias(),
                    identity: identity(),
                    term: term(setup.term_length),
                    lane_count: 2,
                },
                outbound,
                guard: setup.guard,
                roles: setup.roles.map(|roles| Box::new(roles())),
            })
            .unwrap();
        (rig, b)
    }

    /// One round: the agents, then the conductor's tables; `serve` lets the
    /// image table serve the session ring.
    fn round(&mut self, serve: bool) {
        self.now += MS;
        VIRTUAL_NOW.with(|now| now.set(self.now));
        // The publication's conductor: rotation, floor and limit.
        for log in [&mut self.log, &mut self.second].into_iter().flatten() {
            for conductor in &mut log.conductors {
                let _ = conductor.duty_cycle().unwrap();
            }
        }
        self.agents.do_work(self.now).unwrap();
        self.endpoints.poll(&self.links, self.now, |_| {}, |_| {});
        if serve {
            let events = &mut self.events;
            self.images
                .poll(&self.links.sessions, |image| events.push(image));
        }
        std::thread::sleep(Duration::from_micros(200));
    }

    /// A second publisher on its own loopback endpoint A2, announcing the
    /// same alias as A with another identity to B (`destination`), two
    /// lanes of 64 KiB terms. Returns A2.
    fn second_publisher(&mut self, destination: SocketAddr, identity: Identity) -> EndpointId {
        let loopback = SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
        let a2 = self
            .endpoints
            .open(&self.links, loopback, OsSocket::new())
            .unwrap();
        let mut opened = false;
        for _ in 0..100 {
            self.agents.do_work(self.now).unwrap();
            self.endpoints.poll(
                &self.links,
                self.now,
                |event| opened |= matches!(event, EndpointEvent::Opened(_)),
                |_| {},
            );
            if opened {
                break;
            }
        }
        assert!(opened);
        self.links
            .receiver
            .post(|reply| AgentCommand::AddPublishedAlias {
                reply,
                endpoint: a2,
                alias: alias(),
            })
            .unwrap();
        let (outbound, log) =
            super::super::data::testing::outbound(a2, alias(), destination, term(65_536), 2, true);
        self.second = Some(log);
        self.links
            .sender
            .post(|reply| AgentCommand::AddPublication {
                reply,
                publication: Publication {
                    endpoint: a2,
                    alias: alias(),
                    identity,
                    term: term(65_536),
                    lane_count: 2,
                },
                outbound,
                guard: None,
                roles: None,
            })
            .unwrap();
        a2
    }

    /// A second receiving endpoint B2 subscribed to the stream, and the
    /// publication's ANNOUNCE delivered on it from A, as a redundant path
    /// would carry it: B2 challenges A and binds a later path of the image
    /// (RP-1). `announce` is what B2 receives. Returns B2.
    fn second_path(
        &mut self,
        setup: &Setup,
        announce: SetupAnnounce,
        joins: Option<Lanes<u64>>,
    ) -> EndpointId {
        let loopback = SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
        let b2 = self
            .endpoints
            .open(&self.links, loopback, OsSocket::new())
            .unwrap();
        let mut opened = false;
        for _ in 0..100 {
            self.agents.do_work(self.now).unwrap();
            self.endpoints.poll(
                &self.links,
                self.now,
                |event| opened |= matches!(event, EndpointEvent::Opened(_)),
                |_| {},
            );
            if opened {
                break;
            }
        }
        assert!(opened);
        self.links
            .receiver
            .post(|reply| AgentCommand::AddSubscription {
                reply,
                endpoint: b2,
                stream_id: alias().stream_id,
                max_term_length: setup.max_term_length,
                reliable: setup.reliable,
                multicast: false,
                control_group: None,
                identity: setup.identity,
                conflated: setup.conflated,
            })
            .unwrap();
        self.round(true);
        let source = self.endpoints.local_address(self.publisher).unwrap();
        let receiver = &mut self.agents.receiver;
        receiver.role.inject_control(
            &receiver.sessions,
            b2,
            source,
            karyos_protocol::network::Control::SetupAnnounce(announce),
            self.now,
        );
        // The sender answers toward its one destination, B (sender paths
        // are rp-w4): the answer a multicast path would carry is handed
        // to B2 here, echoing B2's challenge, at the joins `joins`.
        let challenge = self
            .agents
            .receiver
            .role
            .posted_challenges()
            .iter()
            .rev()
            .find_map(|(endpoint, control)| match control {
                karyos_protocol::network::Control::Challenge(challenge) if *endpoint == b2 => {
                    Some(*challenge)
                }
                _ => None,
            });
        if let Some(challenge) = challenge {
            let answer = karyos_protocol::network::SetupAnswer {
                alias: announce.alias,
                identity: announce.identity,
                term: announce.term,
                challenge: challenge.challenge,
                joins: joins.unwrap_or_else(|| Lanes::new(&[0, 0]).unwrap()),
            };
            let receiver = &mut self.agents.receiver;
            receiver.role.inject_control(
                &receiver.sessions,
                b2,
                source,
                karyos_protocol::network::Control::SetupAnswer(answer),
                self.now,
            );
        }
        b2
    }

    /// Delivers the publication's ANNOUNCE again on `endpoint` and answers
    /// its challenge, as a path coming back would (see
    /// [`Rig::second_path`]).
    fn reannounce(&mut self, endpoint: EndpointId, announce: SetupAnnounce) {
        let source = self.endpoints.local_address(self.publisher).unwrap();
        let receiver = &mut self.agents.receiver;
        receiver.role.inject_control(
            &receiver.sessions,
            endpoint,
            source,
            karyos_protocol::network::Control::SetupAnnounce(announce),
            self.now,
        );
        let challenge = self
            .agents
            .receiver
            .role
            .posted_challenges()
            .iter()
            .rev()
            .find_map(|(held, control)| match control {
                karyos_protocol::network::Control::Challenge(challenge) if *held == endpoint => {
                    Some(*challenge)
                }
                _ => None,
            });
        if let Some(challenge) = challenge {
            let answer = karyos_protocol::network::SetupAnswer {
                alias: announce.alias,
                identity: announce.identity,
                term: announce.term,
                challenge: challenge.challenge,
                joins: Lanes::new(&[0, 0]).unwrap(),
            };
            let receiver = &mut self.agents.receiver;
            receiver.role.inject_control(
                &receiver.sessions,
                endpoint,
                source,
                karyos_protocol::network::Control::SetupAnswer(answer),
                self.now,
            );
        }
    }

    /// Removes the subscription of the stream on `endpoint`.
    fn unsubscribe(&mut self, endpoint: EndpointId) {
        self.links
            .receiver
            .post(|reply| AgentCommand::RemoveSubscription {
                reply,
                endpoint,
                stream_id: alias().stream_id,
            })
            .unwrap();
    }

    /// Free units of the session rings: (receiver to conductor, conductor
    /// to receiver).
    fn credits(&self) -> (usize, usize) {
        let sessions = &self.agents.receiver.sessions;
        (
            sessions.events.available().unwrap(),
            sessions.credit.available().unwrap(),
        )
    }

    fn until(&mut self, serve: bool, done: impl Fn(&Self) -> bool) {
        for _ in 0..2000 {
            self.round(serve);
            if done(self) {
                return;
            }
        }
        panic!("not reached: {:?}", self.events);
    }
}

/// The whole chain: announce, challenge, answer, `CreateImage`, the
/// conductor allocates both lanes at their join points, `InstallImage`,
/// the receiver installs it and reports `ImageInstalled`; subscribers may
/// attach. The charge is the image's term bytes.
#[test]
fn an_accepted_answer_installs_an_image() {
    let (mut rig, b) = Rig::new(Setup::default());
    rig.until(true, |rig| !rig.events.is_empty());
    let [
        ImageEvent::Installed {
            slot,
            endpoint,
            identity: installed,
        },
    ] = rig.events.as_slice()
    else {
        panic!("{:?}", rig.events);
    };
    assert_eq!((*endpoint, *installed), (b, identity()));
    let lanes = rig.images.installed(*slot).unwrap();
    assert_eq!(lanes.len(), 2);
    // The joins are the sender's read cursors: nothing was published yet.
    for (lane, join) in lanes.iter().zip([0, 0]) {
        assert!(matches!(
            lane.config().publication,
            PublicationMode::Image { join: at, .. } if at == join
        ));
    }
    assert!(rig.agents.receiver.role.has_image(*slot));
    // 64 KiB terms, 3 + 5 slots, two lanes.
    assert_eq!(rig.images.charged(), 65_536 * 8 * 2);
    assert_eq!(rig.images.allocations, 1);
    // The installed image holds its RetireImage and StorageReclaimed units.
    assert_eq!(rig.credits(), (FULL - 1, FULL - 1));
}

/// A conductor slower than the challenge: `ImageReady` after the timeout
/// is released; nothing is bound and the storage and its charge are freed.
#[test]
fn a_late_image_ready_is_released() {
    let (mut rig, _b) = Rig::new(Setup::default());
    // The answer is accepted, but the conductor does not serve it yet.
    rig.until(false, |rig| {
        rig.agents.receiver.counters().create_image == 1
    });
    rig.now += 2_000 * MS;
    rig.until(true, |rig| !rig.events.is_empty());
    assert!(matches!(
        rig.events.as_slice(),
        [ImageEvent::Released { .. }]
    ));
    assert!(rig.images.is_empty());
    assert_eq!(rig.images.charged(), 0);
    assert_eq!(rig.images.allocations, 1);
    assert_eq!(rig.credits(), (FULL, FULL));
}

/// A reachable refusal: an image over the storage budget is answered
/// `RefuseImage` before any allocation, and the receiver's `image_refused`
/// removes the challenge.
#[test]
fn a_budget_refusal_removes_the_challenge() {
    let setup = Setup {
        template: ImageTemplate {
            storage_budget: 65_536 * 8 * 2 - 1,
            ..ImageTemplate::default()
        },
        ..Setup::default()
    };
    let (mut rig, _b) = Rig::new(setup);
    rig.until(true, |rig| !rig.events.is_empty());
    assert!(matches!(
        rig.events.as_slice(),
        [ImageEvent::Refused { .. }]
    ));
    let counters = rig.images.counters();
    assert_eq!((counters.refused_budget, counters.offered), (1, 0));
    assert!(rig.images.is_empty());
    assert_eq!(rig.images.charged(), 0);
    let sessions = rig.agents.receiver.role.session_counters();
    assert_eq!((sessions.released, sessions.installed), (1, 0));
    assert_eq!(rig.images.allocations, 0);
    assert_eq!(rig.credits(), (FULL, FULL));
}

/// A 1 GiB term the subscription accepts: 16 GiB of image terms against
/// the 2 GiB default budget, refused with nothing allocated.
#[test]
fn a_1_gib_request_is_refused_without_allocating() {
    let setup = Setup {
        term_length: 1 << 30,
        max_term_length: 1 << 30,
        ..Setup::default()
    };
    let (mut rig, _b) = Rig::new(setup);
    rig.until(true, |rig| !rig.events.is_empty());
    assert!(matches!(
        rig.events.as_slice(),
        [ImageEvent::Refused { .. }]
    ));
    assert_eq!(rig.images.counters().refused_budget, 1);
    assert_eq!(rig.images.counters().offered, 0);
    assert_eq!(rig.images.charged(), 0);
    // Nothing was allocated, not even lazily: `allocate` never ran.
    assert_eq!(rig.images.allocations, 0);
}

/// An announcement above the subscription's `max_image_term_length` is
/// never challenged: no `CreateImage`, no image.
#[test]
fn an_oversized_announcement_is_not_challenged() {
    let setup = Setup {
        term_length: 131_072,
        max_term_length: 65_536,
        ..Setup::default()
    };
    let (mut rig, _b) = Rig::new(setup);
    rig.until(true, |rig| {
        rig.agents.receiver.counters().term_too_large >= 3
    });
    assert_eq!(rig.agents.receiver.counters().create_image, 0);
    assert_eq!(rig.agents.receiver.role.session_counters().challenges, 0);
    assert!(rig.events.is_empty());
}

/// A full table refuses before allocating; the receiver's later reply has
/// no entry and is counted stale.
#[test]
fn a_full_table_refuses_without_allocating() {
    let (mut rig, _b) = Rig::new(Setup::default());
    rig.images = ImageTable::new(0, ImageTemplate::default());
    rig.until(true, |rig| !rig.events.is_empty());
    assert!(matches!(
        rig.events.as_slice(),
        [ImageEvent::Refused { .. }]
    ));
    rig.until(true, |rig| rig.images.counters().stale_replies == 1);
    let counters = rig.images.counters();
    assert_eq!((counters.refused_full, counters.offered), (1, 0));
    assert_eq!(rig.images.charged(), 0);
    assert_eq!(rig.images.allocations, 0);
    assert_eq!(rig.credits(), (FULL, FULL));
    let sessions = rig.agents.receiver.role.session_counters();
    assert_eq!((sessions.released, sessions.installed), (1, 0));
}

/// Replies the table did not ask for are ignored and counted: an
/// `ImageInstalled` for no image, and an `ImageReleased` or a second
/// `ImageInstalled` for an installed one.
#[test]
fn stale_replies_are_counted() {
    let (mut rig, _b) = Rig::new(Setup::default());
    rig.until(true, |rig| !rig.events.is_empty());
    let [ImageEvent::Installed { slot, .. }] = rig.events.as_slice() else {
        panic!("{:?}", rig.events);
    };
    let installed = *slot;
    let pending = rig.images.images[0].slot;
    let unknown = SlotRef {
        slot: 63,
        generation: 0,
    };
    let mut events = Vec::new();
    for event in [
        SessionEvent::ImageInstalled {
            slot: unknown,
            installed: unknown,
            freshness: None,
        },
        SessionEvent::ImageInstalled {
            slot: pending,
            installed,
            freshness: None,
        },
        SessionEvent::ImageReleased { slot: pending },
    ] {
        rig.images
            .handle(&rig.links.sessions, event, |image| events.push(image));
    }
    assert!(events.is_empty());
    assert_eq!(rig.images.counters().stale_replies, 3);
    assert!(rig.images.installed(installed).is_some());
}

/// Partial credit: with only two receiver-to-conductor units free, the
/// chain (three on that ring) cannot be reserved; the answer is dropped and
/// the two units come back, none leaked. Once the held units return, the
/// image installs and holds exactly one unit per ring.
#[test]
fn partial_credit_drops_the_answer_and_recovers() {
    let (mut rig, _b) = Rig::new(Setup::default());
    let events = &rig.agents.receiver.sessions.events;
    let held: Vec<_> = (0..FULL - 2).map(|_| events.reserve().unwrap()).collect();
    for _ in 0..300 {
        rig.round(true);
    }
    assert_eq!(rig.agents.receiver.counters().create_image, 0);
    assert!(rig.agents.receiver.role.session_counters().dropped >= 1);
    assert_eq!(rig.credits(), (2, FULL));
    drop(held);
    rig.until(true, |rig| !rig.events.is_empty());
    assert!(matches!(
        rig.events.as_slice(),
        [ImageEvent::Installed { .. }]
    ));
    assert_eq!(rig.credits(), (FULL - 1, FULL - 1));
}

/// Establishment (§4.3, network-control-schemas.md §6.2 step 1): the
/// installed image's first SM reaches the sender from the bound receiver,
/// is accepted, and the publication's SETUP stops; SMs keep flowing every
/// `sm_interval`.
#[test]
fn the_first_sm_establishes_and_stops_setup() {
    let (mut rig, _b) = Rig::new(Setup::default());
    rig.until(true, |rig| {
        rig.agents.sender.role.session_counters().established == 1
    });
    let announces = rig.agents.sender.role.session_counters().announces;
    let accepted = rig.agents.sender.role.counters().sm_accepted;
    // 500 ms more: SMs every 10 ms, no SETUP (its interval is 100 ms).
    for _ in 0..500 {
        rig.round(true);
    }
    assert_eq!(
        rig.agents.sender.role.session_counters().announces,
        announces
    );
    let sender = rig.agents.sender.role.counters();
    assert!(sender.sm_accepted >= accepted + 10, "{sender:?}");
    assert_eq!((sender.sm_unbound, sender.sm_mismatch), (0, 0));
    assert!(rig.agents.receiver.counters().sm_sent >= sender.sm_accepted);
}

/// An SM from a source this sender never answered changes nothing, even
/// with the publication's alias and identity: it is counted unbound and
/// SETUP goes on.
#[test]
fn a_spoofed_sm_changes_nothing() {
    use std::net::UdpSocket;

    use karyos_protocol::network::{
        Control, LaneStatus, MAX_CONTROL_LENGTH, Receiver, StatusMessage,
    };

    // The subscription accepts no term length: the publication is
    // announced, never challenged nor answered, so no receiver is bound.
    let setup = Setup {
        max_term_length: 0,
        ..Setup::default()
    };
    let (mut rig, _b) = Rig::new(setup);
    let target = rig.endpoints.local_address(rig.publisher).unwrap();
    let status = Control::Status(StatusMessage {
        alias: alias(),
        identity: identity(),
        receiver: Receiver {
            receiver_boot_id: [7, 8],
            receiver_id: 1,
        },
        group_tag: 0,
        lanes: Lanes::new(&[
            LaneStatus {
                consumption: 0,
                window: 32_768,
            },
            LaneStatus {
                consumption: 0,
                window: 32_768,
            },
        ])
        .unwrap(),
    });
    let mut bytes = [0u8; MAX_CONTROL_LENGTH];
    let length = status.encode(&mut bytes).unwrap();
    let spoofer = UdpSocket::bind("127.0.0.1:0").unwrap();
    for _ in 0..20 {
        spoofer.send_to(&bytes[..length], target).unwrap();
    }
    rig.until(true, |rig| {
        rig.agents.sender.role.counters().sm_unbound >= 1
    });
    for _ in 0..200 {
        rig.round(true);
    }
    assert_eq!(rig.agents.sender.role.counters().sm_accepted, 0);
    assert_eq!(rig.agents.sender.role.session_counters().established, 0);
    assert!(rig.agents.sender.role.session_counters().announces >= 2);
}

/// Liveness and retirement (S1): with no evidence from the binding for
/// `image_liveness_timeout`, the receiver retires the image; a subscriber
/// still holding a lane keeps the storage; once it lets go the conductor
/// reclaims it and posts `StorageReclaimed`, and every unit of the chain is
/// back.
#[test]
fn an_idle_image_is_retired_and_reclaimed() {
    let (mut rig, _b) = Rig::new(Setup::default());
    rig.until(true, |rig| {
        rig.agents.sender.role.session_counters().established == 1
    });
    let Some(ImageEvent::Installed { slot, .. }) = rig.events.first().copied() else {
        panic!("{:?}", rig.events);
    };
    // A local subscriber holds a lane.
    let held = rig.images.installed(slot).unwrap()[0].clone();
    rig.now += 11_000 * MS;
    rig.until(true, |rig| {
        rig.events
            .iter()
            .any(|event| matches!(event, ImageEvent::Retiring { .. }))
    });
    assert_eq!(rig.agents.receiver.counters().images_retired, 1);
    assert!(!rig.agents.receiver.role.has_image(slot));
    assert!(rig.images.installed(slot).is_none());
    for _ in 0..50 {
        rig.round(true);
    }
    assert!(
        !rig.events
            .iter()
            .any(|event| matches!(event, ImageEvent::Reclaimed { .. })),
        "reclaimed while a subscriber holds a lane"
    );
    drop(held);
    rig.until(true, |rig| {
        rig.events.contains(&ImageEvent::Reclaimed { slot })
    });
    rig.round(true);
    assert_eq!(rig.images.charged(), 0);
    assert!(rig.images.is_empty());
    assert_eq!(rig.credits(), (FULL, FULL));
    let sessions = rig.agents.receiver.role.session_counters();
    assert_eq!((sessions.retired, sessions.stale_commands), (1, 0));
}

/// S1's SM slot rule: one slot per image. With the sender stalled, the
/// image's periodic SMs find their slot still occupied and are skipped and
/// counted; once the sender runs, exactly the one waiting SM arrives.
#[test]
fn a_busy_sm_slot_skips_the_period() {
    let (mut rig, _b) = Rig::new(Setup::default());
    rig.until(true, |rig| {
        rig.agents.sender.role.session_counters().established == 1
    });
    // Drain what is in flight, then stall the sender.
    for _ in 0..5 {
        rig.round(true);
    }
    let accepted = rig.agents.sender.role.counters().sm_accepted;
    let skipped = rig.agents.receiver.counters().sm_skipped;
    for _ in 0..100 {
        rig.now += MS;
        rig.agents.receiver.do_work(rig.now).unwrap();
    }
    assert!(rig.agents.receiver.counters().sm_skipped >= skipped + 5);
    // One sender cycle sends the one waiting SM; the receiver reads it on
    // its next cycle and the sender accepts it on the one after.
    rig.agents.sender.do_work(rig.now).unwrap();
    std::thread::sleep(Duration::from_millis(5));
    rig.agents.receiver.do_work(rig.now).unwrap();
    rig.agents.sender.do_work(rig.now).unwrap();
    assert_eq!(rig.agents.sender.role.counters().sm_accepted, accepted + 1);
}

/// A subscriber of the installed image's lane `lane`.
fn image_subscriber(
    rig: &Rig,
    slot: SlotRef,
    lane: usize,
    role: karyos_sys::log_buffer::Role,
) -> (
    karyos_sys::log_buffer::Conductor<std::sync::Arc<LogBuffer>>,
    karyos_sys::log_buffer::Subscription<std::sync::Arc<LogBuffer>>,
) {
    let buffer = rig.images.installed(slot).unwrap()[lane].clone();
    let mut conductor = buffer.conductor_owned().unwrap();
    let subscription = conductor.subscribe(role).unwrap();
    (conductor, subscription)
}

/// Polls `subscription` for one message.
fn poll_message(
    subscription: &mut karyos_sys::log_buffer::Subscription<std::sync::Arc<LogBuffer>>,
) -> Option<Vec<u8>> {
    use karyos_sys::log_buffer::PollOutcome;

    let mut out = vec![0u8; 65_536];
    match subscription.poll(&mut out).unwrap() {
        PollOutcome::Message { length, .. } => {
            subscription.acknowledge();
            out.truncate(length as usize);
            Some(out)
        }
        _ => None,
    }
}

/// Runs the rig until establishment and returns the installed slot.
fn established(rig: &mut Rig) -> SlotRef {
    rig.until(true, |rig| {
        rig.agents.sender.role.session_counters().established == 1
    });
    let Some(ImageEvent::Installed { slot, .. }) = rig.events.first().copied() else {
        panic!("{:?}", rig.events);
    };
    slot
}

/// Test 1 (driver-network-agents.md §9): after establishment, messages
/// published on A reach a local subscriber of B's image, in order, through
/// the sender's read capability, the lane queue and the receive owner.
fn round_trip(reliable: bool) {
    use karyos_sys::log_buffer::{AppendOptions, AppendOutcome, Role};

    let (mut rig, _b) = Rig::new(Setup {
        reliable,
        ..Setup::default()
    });
    let slot = established(&mut rig);
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    let messages: Vec<Vec<u8>> = (0..20u8)
        .map(|i| vec![i; 100 + usize::from(i) * 150])
        .collect();
    for message in &messages {
        let log = rig.log.as_mut().unwrap();
        let outcome = log.publications[0]
            .append(message, AppendOptions::default())
            .unwrap();
        assert!(
            matches!(outcome, AppendOutcome::Appended { .. }),
            "{outcome:?}"
        );
    }
    let mut delivered = Vec::new();
    for _ in 0..2000 {
        rig.round(true);
        while let Some(message) = poll_message(&mut subscriber) {
            delivered.push(message);
        }
        if delivered.len() == messages.len() {
            break;
        }
    }
    assert_eq!(delivered, messages);
    let receiver = rig.agents.receiver.counters();
    assert!(receiver.data_committed >= 20, "{receiver:?}");
    assert_eq!(
        (
            receiver.data_unbound,
            receiver.data_invalid,
            receiver.data_refused
        ),
        (0, 0, 0)
    );
}

#[test]
fn a_message_reaches_a_subscriber_of_the_image() {
    round_trip(false);
}

#[test]
fn a_reliable_message_reaches_a_subscriber_of_the_image() {
    round_trip(true);
}

/// Test 3, receiver side (§5): on a reliable channel the sender's position
/// is the least consumption its receivers report; with the receiver
/// stopped it does not move, and the publisher meets back pressure. Once
/// the receiver runs again, the publisher resumes.
#[test]
fn a_stopped_receiver_back_pressures_a_reliable_publisher() {
    use karyos_sys::log_buffer::{AppendOptions, AppendOutcome};

    let (mut rig, _b) = Rig::new(Setup {
        reliable: true,
        ..Setup::default()
    });
    established(&mut rig);
    let data = vec![7u8; 992];
    // Only the sender runs: the receiver reads nothing and reports nothing.
    let mut pressed = false;
    for _ in 0..2000 {
        let log = rig.log.as_mut().unwrap();
        match log.publications[0]
            .append(&data, AppendOptions::default())
            .unwrap()
        {
            AppendOutcome::Appended { .. } => {}
            AppendOutcome::BackPressured => {
                pressed = true;
                break;
            }
            AppendOutcome::AdminAction => {}
            other => panic!("{other:?}"),
        }
        for conductor in &mut rig.log.as_mut().unwrap().conductors {
            let _ = conductor.duty_cycle().unwrap();
        }
        rig.now += MS;
        rig.agents.sender.do_work(rig.now).unwrap();
    }
    assert!(pressed, "never back pressured");
    // The receiver runs again: its SMs move the sender's position.
    let mut resumed = false;
    for _ in 0..2000 {
        rig.round(true);
        let log = rig.log.as_mut().unwrap();
        if matches!(
            log.publications[0]
                .append(&data, AppendOptions::default())
                .unwrap(),
            AppendOutcome::Appended { .. }
        ) {
            resumed = true;
            break;
        }
    }
    assert!(resumed, "never resumed");
}

/// Test 5, two lanes: each lane's messages reach its own image lane under
/// the data DRR, and neither waits for the other.
#[test]
fn two_lanes_are_both_served() {
    use karyos_sys::log_buffer::{AppendOptions, Role};

    let (mut rig, _b) = Rig::new(Setup::default());
    let slot = established(&mut rig);
    let (_c0, mut lane0) = image_subscriber(&rig, slot, 0, Role::Optional);
    let (_c1, mut lane1) = image_subscriber(&rig, slot, 1, Role::Optional);
    for i in 0..10u8 {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[i; 500], AppendOptions::default())
            .unwrap();
        let _ = log.publications[1]
            .append(&[i + 100; 700], AppendOptions::default())
            .unwrap();
    }
    let (mut got0, mut got1) = (Vec::new(), Vec::new());
    for _ in 0..2000 {
        rig.round(true);
        while let Some(message) = poll_message(&mut lane0) {
            got0.push(message[0]);
        }
        while let Some(message) = poll_message(&mut lane1) {
            got1.push(message[0]);
        }
        if got0.len() == 10 && got1.len() == 10 {
            break;
        }
    }
    assert_eq!(got0, (0..10).collect::<Vec<u8>>());
    assert_eq!(got1, (100..110).collect::<Vec<u8>>());
}

/// P1-1 of the #255 review: on a reliable channel the sender's registered
/// position never passes what a bound receiver consumed. When the only
/// receiver's binding expires (its SMs stopped), the position holds; it
/// never jumps to what was submitted.
#[test]
fn a_reliable_position_holds_when_its_receiver_goes() {
    use karyos_sys::log_buffer::{AppendOptions, AppendOutcome};

    let (mut rig, _b) = Rig::new(Setup {
        reliable: true,
        ..Setup::default()
    });
    established(&mut rig);
    for _ in 0..20 {
        rig.round(true);
    }
    let sent = |rig: &Rig| rig.agents.sender.role.outbound(0).unwrap().readers()[0].sent_position();
    let held = sent(&rig);
    // The receiver stops: no more SMs. Past the image liveness timeout the
    // confirmed binding expires.
    rig.now += 11_000 * MS;
    let data = vec![3u8; 992];
    for _ in 0..200 {
        let log = rig.log.as_mut().unwrap();
        match log.publications[0]
            .append(&data, AppendOptions::default())
            .unwrap()
        {
            AppendOutcome::Appended { .. } | AppendOutcome::AdminAction => {}
            AppendOutcome::BackPressured => break,
            other => panic!("{other:?}"),
        }
        for conductor in &mut rig.log.as_mut().unwrap().conductors {
            let _ = conductor.duty_cycle().unwrap();
        }
        rig.now += MS;
        rig.agents.sender.do_work(rig.now).unwrap();
    }
    assert!(rig.agents.sender.role.counters().bindings_expired >= 1);
    assert_eq!(
        sent(&rig),
        held,
        "the position moved with no bound receiver"
    );
}

/// P2-6 of the #255 review: a reset of the sending endpoint while data is
/// in flight on a reliable lane loses nothing: the lane rewinds to its
/// registered position (a block boundary) and sends again, and the
/// receive owner drops what it already had.
#[test]
fn a_reliable_lane_resends_after_a_reset() {
    use karyos_sys::log_buffer::{AppendOptions, Role};

    let (mut rig, _b) = Rig::new(Setup {
        reliable: true,
        ..Setup::default()
    });
    let slot = established(&mut rig);
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    let messages: Vec<Vec<u8>> = (0..30u8).map(|i| vec![i; 900]).collect();
    for message in &messages {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(message, AppendOptions::default())
            .unwrap();
    }
    rig.round(true);
    let publisher = rig.publisher;
    let before = rig.endpoints.local_address(publisher);
    rig.endpoints.reset(&rig.links, publisher).unwrap();
    let mut delivered = Vec::new();
    for _ in 0..3000 {
        rig.round(true);
        while let Some(message) = poll_message(&mut subscriber) {
            delivered.push(message);
        }
        if delivered.len() == messages.len() {
            break;
        }
    }
    assert_eq!(delivered, messages);
    assert_eq!(rig.endpoints.local_address(publisher), before);
}

/// RP-2: a DATA heartbeat is image evidence, never path evidence. With
/// fresh heartbeats every second and no data, the path is lost when
/// `path_liveness_timeout` (10 s) passes since establishment, and the image
/// is kept; afterwards the unbound heartbeats are refused.
#[test]
fn a_data_heartbeat_does_not_refresh_its_path() {
    let (mut rig, b) = Rig::new(Setup::default());
    let slot = established(&mut rig);
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    assert_eq!(rig.agents.receiver.role.live_paths(slot), 1);
    let before = rig.agents.receiver.counters();
    let mut lost_at = None;
    for second in 1..=12u64 {
        rig.now += 1_000_000_000;
        let receiver = &mut rig.agents.receiver;
        receiver
            .role
            .inject_heartbeat(&receiver.sessions, b, source, slot, 32 * second, rig.now);
        rig.round(true);
        if lost_at.is_none() && rig.agents.receiver.role.live_paths(slot) == 0 {
            lost_at = Some(second);
        }
    }
    assert_eq!(lost_at, Some(10));
    let after = rig.agents.receiver.counters();
    assert_eq!(after.heartbeats, before.heartbeats + 10);
    assert_eq!(after.data_unbound, before.data_unbound + 2);
    assert!(rig.agents.receiver.role.has_image(slot));
}

/// The needs_reset wiring: a publication that needs a reset asks the
/// endpoint table through the sender's events; the table resets the
/// endpoint, the new epoch clears the need, and messages flow again.
#[test]
fn a_publication_needing_a_reset_gets_one() {
    use karyos_sys::log_buffer::{AppendOptions, Role};

    let (mut rig, _b) = Rig::new(Setup {
        reliable: true,
        ..Setup::default()
    });
    let slot = established(&mut rig);
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    // Messages sent when the need arises all arrive after the reset (the
    // rewind itself is tested over the scripted socket, where the reset
    // returns what loopback would already have sent).
    let messages: Vec<Vec<u8>> = (0..30u8).map(|i| vec![i; 900]).collect();
    for message in &messages {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(message, AppendOptions::default())
            .unwrap();
    }
    rig.round(true);
    let force = |rig: &mut Rig| {
        rig.agents
            .sender
            .role
            .outbound_mut(0)
            .unwrap()
            .force_needs_reset();
    };
    force(&mut rig);
    rig.until(true, |rig| rig.endpoints.counters().resets == 1);
    rig.until(true, |rig| {
        !rig.agents.sender.role.outbound(0).unwrap().needs_reset()
            && rig.agents.sender.counters().needs_reset == 0
    });
    let mut delivered = Vec::new();
    for _ in 0..3000 {
        rig.round(true);
        while let Some(message) = poll_message(&mut subscriber) {
            delivered.push(message);
        }
        if delivered.len() == messages.len() {
            break;
        }
    }
    assert_eq!(delivered, messages);
    assert_eq!(rig.endpoints.counters().resets, 1);
    // A second need right after the reset is asked for on the next cycle:
    // the new epoch cleared the last request's record.
    let requests = rig.agents.sender.counters().reset_requests;
    force(&mut rig);
    rig.round(true);
    assert_eq!(rig.agents.sender.counters().reset_requests, requests + 1);
}

/// Test 3, subscriber side (§5): the image's SMs report its least required
/// subscriber's position. With a required subscriber stopped and both
/// agents running, the reliable publisher meets back pressure; once the
/// subscriber reads, it resumes. An optional subscriber bounds nothing.
#[test]
fn a_stopped_required_subscriber_back_pressures_a_reliable_publisher() {
    use karyos_sys::log_buffer::{AppendOptions, AppendOutcome, Role};

    let (mut rig, _b) = Rig::new(Setup {
        reliable: true,
        ..Setup::default()
    });
    let slot = established(&mut rig);
    let (mut conductor, mut required) = image_subscriber(&rig, slot, 0, Role::Required);
    let _optional = conductor.subscribe(Role::Optional).unwrap();
    let data = vec![7u8; 992];
    let append = |rig: &mut Rig| {
        let log = rig.log.as_mut().unwrap();
        match log.publications[0]
            .append(&data, AppendOptions::default())
            .unwrap()
        {
            AppendOutcome::Appended { .. } => true,
            AppendOutcome::BackPressured | AppendOutcome::AdminAction => false,
            other => panic!("{other:?}"),
        }
    };
    let mut pressed = false;
    for _ in 0..4000 {
        if !append(&mut rig) {
            // Back pressure persists across rounds, not one admin action.
            let mut held = true;
            for _ in 0..50 {
                rig.round(true);
                held &= !append(&mut rig);
            }
            if held {
                pressed = true;
                break;
            }
        }
        rig.round(true);
    }
    assert!(pressed, "never back pressured");
    // The subscriber reads: the image's SMs move the sender's position.
    let mut resumed = false;
    for _ in 0..4000 {
        while poll_message(&mut required).is_some() {}
        rig.round(true);
        if append(&mut rig) {
            resumed = true;
            break;
        }
    }
    assert!(resumed, "never resumed");
    // The sender stopped at the subscriber: the image refused nothing.
    let receiver = rig.agents.receiver.counters();
    assert_eq!(receiver.data_refused, 0, "{receiver:?}");
}

/// M5 (#255 third pass): a heartbeat below its lane's mark, through the
/// receiver's DATA intake, is counted stale and changes no evidence.
#[test]
fn a_stale_heartbeat_through_the_intake_changes_no_evidence() {
    let (mut rig, b) = Rig::new(Setup::default());
    let slot = established(&mut rig);
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    rig.now += MS;
    let receiver = &mut rig.agents.receiver;
    receiver
        .role
        .inject_heartbeat(&receiver.sessions, b, source, slot, 64, rig.now);
    let fresh_at = rig.now;
    assert_eq!(receiver.role.image_evidence(slot), Some(fresh_at));
    let before = receiver.counters();
    rig.now += MS;
    receiver
        .role
        .inject_heartbeat(&receiver.sessions, b, source, slot, 32, rig.now);
    let after = receiver.counters();
    assert_eq!(after.heartbeats_stale, before.heartbeats_stale + 1);
    assert_eq!(after.heartbeats, before.heartbeats);
    assert_eq!(receiver.role.image_evidence(slot), Some(fresh_at));
}

/// §6.3 end to end, a unicast receiver restart within the sender's
/// binding: the receiver retires its idle image while its SMs keep the
/// sender's binding alive, so the sender stays established, announces
/// nothing and keeps sending up to the member's edge. That DATA reaches an
/// unbound key and sends one SOLICIT, whose answer installs a new image
/// in another slot (the quarantine is short here; its refusal and holdoff
/// are tested on the session table). With no live member left, MC-3 stops
/// first sends, so no DATA would come to solicit from (ACS 15932).
#[test]
fn unbound_data_solicits_a_new_image() {
    use karyos_sys::log_buffer::AppendOptions;

    let (mut rig, _b) = Rig::new(Setup {
        alias_quarantine: Some(1),
        ..Setup::default()
    });
    let first = established(&mut rig);
    // Idle in steps: the image's SMs keep the binding fresh until the
    // image retires after `image_liveness_timeout`.
    let mut retired = false;
    for _ in 0..200 {
        rig.now += 99 * MS;
        rig.round(true);
        if rig
            .events
            .iter()
            .any(|event| matches!(event, ImageEvent::Retiring { .. }))
        {
            retired = true;
            break;
        }
    }
    assert!(retired);
    assert!(!rig.agents.receiver.role.has_image(first));
    let announces = rig.agents.sender.role.session_counters().announces;
    let message = vec![3u8; 500];
    let append = |rig: &mut Rig| {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&message, AppendOptions::default())
            .unwrap();
    };
    let mut installed = false;
    for _ in 0..2000 {
        append(&mut rig);
        rig.round(true);
        if rig.agents.receiver.role.session_counters().installed == 2 {
            installed = true;
            break;
        }
    }
    let sessions = rig.agents.receiver.role.session_counters();
    assert!(
        installed,
        "{sessions:?} {:?}",
        rig.agents.receiver.counters()
    );
    assert_eq!((sessions.solicits, sessions.solicits_answered), (1, 1));
    // No announcement was needed.
    assert_eq!(
        rig.agents.sender.role.session_counters().announces,
        announces
    );
    let second = rig
        .events
        .iter()
        .rev()
        .find_map(|event| match event {
            ImageEvent::Installed { slot, .. } => Some(*slot),
            _ => None,
        })
        .unwrap();
    assert_ne!(second, first);
    // DATA reaches the new image: its frames are committed. (Frames sent
    // between the answer and the installation were unbound and dropped:
    // the hole they leave waits for repair, phase 6.)
    let committed = rig.agents.receiver.counters().data_committed;
    for _ in 0..200 {
        append(&mut rig);
        rig.round(true);
    }
    assert!(rig.agents.receiver.counters().data_committed > committed);
}

/// A guard close on a network publication is local (O-11, GC-6): the
/// sender sends nothing more, the receiver gets no abort, and its image
/// ends as an interrupted session at its liveness timeout.
#[test]
fn a_guard_closed_publication_ends_its_image_at_liveness() {
    use std::sync::Arc;

    use karyos_sys::applied_epoch::AppliedEpoch;
    use karyos_sys::log_buffer::AppendOptions;
    use karyos_sys::sync::Ordering;

    let word = Arc::new(karyos_client::HeapWords::zeroed(1));
    word.words()[0].store(karyos_sys::guard::created(), Ordering::Release);
    assert_eq!(karyos_sys::guard::reopen(&word.words()[0], 1), Ok(2));
    let (mut rig, _b) = Rig::new(Setup {
        guard: Some(super::super::data::GuardSpec {
            word: Arc::clone(&word) as Arc<dyn karyos_client::SharedWords>,
            cell: Arc::new(AppliedEpoch::new()),
            epoch: 2,
            rate: None,
        }),
        ..Setup::default()
    });
    rig.until(true, |rig| {
        rig.events
            .iter()
            .any(|event| matches!(event, ImageEvent::Installed { .. }))
    });
    let append = |rig: &mut Rig| {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[1; 100], AppendOptions::default())
            .unwrap();
    };
    append(&mut rig);
    rig.until(true, |rig| {
        rig.agents.receiver.counters().data_committed >= 1
    });
    let _ = karyos_sys::guard::close(&word.words()[0]).unwrap();
    // Let the sender apply the close, then publish more.
    for _ in 0..5 {
        rig.round(true);
    }
    let committed = rig.agents.receiver.counters().data_committed;
    append(&mut rig);
    for _ in 0..50 {
        rig.round(true);
    }
    assert_eq!(
        rig.agents.receiver.counters().data_committed,
        committed,
        "nothing after the close"
    );
    rig.now += 11_000 * MS;
    rig.until(true, |rig| {
        rig.events
            .iter()
            .any(|event| matches!(event, ImageEvent::Retiring { .. }))
    });
    assert_eq!(rig.agents.receiver.counters().images_retired, 1);
}

/// ACS 15933: a sender whose only receiver is gone past
/// `image_liveness_timeout` (no live member, no confirmed binding)
/// announces SETUP again; the receiver binds a new image through a fresh
/// challenge and messages reach it. The announcements stop again at the
/// next accepted SM.
#[test]
fn a_sender_with_no_receiver_announces_again() {
    use karyos_sys::log_buffer::{AppendOptions, Role};

    let (mut rig, _b) = Rig::new(Setup {
        alias_quarantine: Some(1),
        ..Setup::default()
    });
    let first = established(&mut rig);
    let before = rig.agents.sender.role.session_counters();
    // The receiver's image idles out and the sender's binding expires.
    rig.now += 11_000 * MS;
    rig.until(true, |rig| {
        rig.agents.sender.role.session_counters().reannounced == 1
    });
    rig.until(true, |rig| {
        rig.agents.sender.role.session_counters().established == 2
    });
    let after = rig.agents.sender.role.session_counters();
    assert!(after.announces > before.announces, "{after:?}");
    let second = rig
        .events
        .iter()
        .rev()
        .find_map(|event| match event {
            ImageEvent::Installed { slot, .. } => Some(*slot),
            _ => None,
        })
        .unwrap();
    assert_ne!(second, first);
    // Established again: announcements stop.
    let announces = rig.agents.sender.role.session_counters().announces;
    for _ in 0..50 {
        rig.round(true);
    }
    rig.now += 2_000 * MS;
    for _ in 0..10 {
        rig.round(true);
    }
    assert_eq!(
        rig.agents.sender.role.session_counters().announces,
        announces
    );
    // Messages reach the new image.
    let (_conductor, mut subscriber) = image_subscriber(&rig, second, 0, Role::Optional);
    let message = vec![4u8; 600];
    let log = rig.log.as_mut().unwrap();
    let _ = log.publications[0]
        .append(&message, AppendOptions::default())
        .unwrap();
    let mut delivered = None;
    for _ in 0..2000 {
        rig.round(true);
        if let Some(got) = poll_message(&mut subscriber) {
            delivered = Some(got);
            break;
        }
    }
    assert_eq!(delivered, Some(message));
}

/// Phase 6 wiring: a DATA datagram lost on a reliable channel leaves a
/// hole the receiver NAKs to the sender at once, naming the image and the
/// hole, and again one RTT later while it is not repaired (the sender here
/// ignores NAKs).
#[test]
fn a_lost_datagram_is_naked() {
    use karyos_sys::log_buffer::AppendOptions;

    let (mut rig, _b) = Rig::new(Setup {
        reliable: true,
        repairs: false,
        ..Setup::default()
    });
    let slot = established(&mut rig);
    rig.agents.receiver.role.drop_data(&[1]);
    for i in 0..4u8 {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[i; 900], AppendOptions::default())
            .unwrap();
    }
    rig.until(true, |rig| rig.agents.receiver.counters().naks >= 1);
    let nak = rig.agents.receiver.role.posted_naks()[0];
    assert_eq!(nak.alias, alias());
    assert_eq!(nak.identity, identity());
    assert_eq!(
        nak.receiver.receiver_id,
        (u64::from(slot.slot) << 32) | u64::from(slot.generation)
    );
    assert!(
        nak.range.length >= 32 && nak.range.start % 32 == 0,
        "{nak:?}"
    );
    // Unrepaired: asked again after one RTT (rtt_initial, 1 ms).
    rig.until(true, |rig| rig.agents.receiver.counters().naks >= 2);
    assert_eq!(rig.agents.receiver.role.posted_naks()[1].range, nak.range);
    // A unicast image runs no multicast cycles.
    assert_eq!(rig.agents.receiver.counters().nak_cycles, 0);
}

/// Phase 6, both sides: a DATA datagram lost on a reliable channel is
/// NAKed, resent by the sender's repair path and fills the hole; the
/// receiver counts it repaired and asks no more.
#[test]
fn a_lost_datagram_is_repaired() {
    use karyos_sys::log_buffer::AppendOptions;

    let (mut rig, _b) = Rig::new(Setup {
        reliable: true,
        ..Setup::default()
    });
    let slot = established(&mut rig);
    rig.agents.receiver.role.drop_data(&[1]);
    for i in 0..4u8 {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[i; 900], AppendOptions::default())
            .unwrap();
    }
    rig.until(true, |rig| {
        rig.agents
            .receiver
            .role
            .loss_counters(slot)
            .is_some_and(|counters| counters.repaired >= 1)
    });
    let counters = rig.agents.receiver.role.loss_counters(slot).unwrap();
    assert_eq!(counters.detected, counters.repaired, "{counters:?}");
    assert!(rig.agents.sender.counters().repairs >= 1);
    // Repaired: no NAK follows.
    let naks = rig.agents.receiver.counters().naks;
    for _ in 0..50 {
        rig.round(true);
    }
    assert_eq!(rig.agents.receiver.counters().naks, naks);
}

/// Phase 6 wiring: a RANGE_UNAVAILABLE that echoes the outstanding NAK
/// proves the hole unrecoverable; under the default `on_unrecoverable =
/// close` the image closes and is retired.
#[test]
fn range_unavailable_closes_a_reliable_image() {
    use karyos_protocol::network::{NakReply, NakReplyReason};
    use karyos_sys::log_buffer::AppendOptions;

    let (mut rig, b) = Rig::new(Setup {
        repairs: false,
        reliable: true,
        ..Setup::default()
    });
    let slot = established(&mut rig);
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    rig.agents.receiver.role.drop_data(&[1]);
    for i in 0..4u8 {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[i; 900], AppendOptions::default())
            .unwrap();
    }
    rig.until(true, |rig| rig.agents.receiver.counters().naks >= 1);
    // The NAK's report settles on the next steps.
    for _ in 0..5 {
        rig.round(true);
    }
    let nak = rig.agents.receiver.role.posted_naks()[0];
    let reply = NakReply::answering(
        &nak,
        NakReplyReason::RangeUnavailable {
            lowest_retained: nak.range.start + u64::from(nak.range.length),
        },
    );
    let receiver = &mut rig.agents.receiver;
    receiver.role.inject_control(
        &receiver.sessions,
        b,
        source,
        karyos_protocol::network::Control::NakReply(reply),
        rig.now,
    );
    rig.until(true, |rig| !rig.agents.receiver.role.has_image(slot));
    assert_eq!(
        rig.agents.receiver.counters().images_closed_unrecoverable,
        1
    );
}

/// Phase 6 wiring: on an unreliable channel a lost datagram is never
/// NAKed; the skip policy seals its hole after the reorder timeout and
/// later messages reach the subscriber.
#[test]
fn an_unreliable_loss_is_sealed() {
    use karyos_sys::log_buffer::{AppendOptions, Role};

    let (mut rig, _b) = Rig::new(Setup::default());
    let slot = established(&mut rig);
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    rig.agents.receiver.role.drop_data(&[1]);
    for i in 0..4u8 {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[i; 900], AppendOptions::default())
            .unwrap();
    }
    rig.until(true, |rig| rig.agents.receiver.counters().gaps_sealed >= 1);
    let mut delivered = Vec::new();
    for _ in 0..200 {
        rig.round(true);
        while let Some(message) = poll_message(&mut subscriber) {
            delivered.push(message[0]);
        }
    }
    assert!(delivered.contains(&3), "{delivered:?}");
    assert_eq!(rig.agents.receiver.counters().naks, 0);
}

/// Phase 6 wiring, tail loss (ACS 15957, 15984): with nothing covered
/// above the rebuild position, a heartbeat mark ahead of it is a hole once
/// it persists one RTT; its NAK ends at the mark, the sender's position.
#[test]
fn a_tail_loss_is_naked_up_to_the_heartbeat() {
    let (mut rig, b) = Rig::new(Setup {
        reliable: true,
        ..Setup::default()
    });
    let slot = established(&mut rig);
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    rig.now += MS;
    let receiver = &mut rig.agents.receiver;
    receiver
        .role
        .inject_heartbeat(&receiver.sessions, b, source, slot, 4096, rig.now);
    // Not before one RTT.
    rig.round(true);
    assert_eq!(rig.agents.receiver.counters().naks, 0);
    rig.until(true, |rig| rig.agents.receiver.counters().naks >= 1);
    let nak = rig.agents.receiver.role.posted_naks()[0];
    assert_eq!(nak.range.length, 4096, "{nak:?}");
}

/// Phase 6 wiring: `range_invalid_limit` consecutive RANGE_INVALID for
/// the outstanding NAK are a protocol fault, and the image closes.
#[test]
fn repeated_range_invalid_closes_the_image() {
    use karyos_protocol::network::{Control, NakReply, NakReplyReason};
    use karyos_sys::log_buffer::AppendOptions;

    let (mut rig, b) = Rig::new(Setup {
        repairs: false,
        reliable: true,
        ..Setup::default()
    });
    let slot = established(&mut rig);
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    rig.agents.receiver.role.drop_data(&[1]);
    for i in 0..4u8 {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[i; 900], AppendOptions::default())
            .unwrap();
    }
    rig.until(true, |rig| rig.agents.receiver.counters().naks >= 1);
    for _ in 0..5 {
        rig.round(true);
    }
    let nak = rig.agents.receiver.role.posted_naks()[0];
    for _ in 0..3 {
        let receiver = &mut rig.agents.receiver;
        receiver.role.inject_control(
            &receiver.sessions,
            b,
            source,
            Control::NakReply(NakReply::answering(&nak, NakReplyReason::RangeInvalid)),
            rig.now,
        );
    }
    rig.until(true, |rig| !rig.agents.receiver.role.has_image(slot));
    assert_eq!(
        rig.agents.receiver.counters().images_closed_protocol_fault,
        1
    );
}

/// Phase 6 wiring: the NAK's report settles its submission, so its retry
/// waits one RTT from it (the path's measured RTT, a few rig steps), not
/// one cycle: over 50 steps the NAK goes out again, but far fewer than 50
/// times.
#[test]
fn a_nak_retry_waits_one_rtt() {
    use karyos_sys::log_buffer::AppendOptions;

    let (mut rig, _b) = Rig::new(Setup {
        repairs: false,
        reliable: true,
        ..Setup::default()
    });
    let slot = established(&mut rig);
    rig.agents.receiver.role.drop_data(&[1]);
    for i in 0..4u8 {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[i; 900], AppendOptions::default())
            .unwrap();
    }
    rig.until(true, |rig| rig.agents.receiver.counters().naks >= 1);
    let first = rig.agents.receiver.counters().naks;
    for _ in 0..50 {
        rig.round(true);
    }
    let counters = rig.agents.receiver.role.loss_counters(slot).unwrap();
    let naks = rig.agents.receiver.counters().naks - first;
    assert!((2..=26).contains(&naks), "{naks} NAKs: {counters:?}");
    assert_eq!(counters.retries, counters.submitted - 1, "{counters:?}");
}

/// Phase 6 wiring, RC-6: a route fault (a second uncertain NAK while one
/// is unresolved) stops the image's NAKs, and the receiver asks for its
/// endpoint's reset (#284 review P2-2); the reset's new epoch resolves
/// them and the NAKs resume.
#[test]
fn a_route_fault_resets_its_endpoint_and_naks_resume() {
    use karyos_sys::log_buffer::AppendOptions;

    let (mut rig, _b) = Rig::new(Setup {
        repairs: false,
        reliable: true,
        ..Setup::default()
    });
    let slot = established(&mut rig);
    rig.agents.receiver.role.drop_data(&[1]);
    for i in 0..4u8 {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[i; 900], AppendOptions::default())
            .unwrap();
    }
    rig.until(true, |rig| rig.agents.receiver.counters().naks >= 1);
    for _ in 0..5 {
        rig.round(true);
    }
    let nak = rig.agents.receiver.role.posted_naks()[0];
    rig.agents.receiver.role.fault_naks(slot, &nak);
    let naks = rig.agents.receiver.counters().naks;
    rig.until(true, |rig| rig.endpoints.counters().resets >= 1);
    assert!(rig.agents.receiver.counters().reset_requests >= 1);
    rig.until(true, |rig| rig.agents.receiver.counters().naks > naks);
}

/// #284 review P2-1 (GU-6): on an unreliable image, arrivals that all land
/// beyond the receive window for `far_window_timeout` (1 s), with nothing
/// committed meanwhile, close the image with `GapCannotResume`.
#[test]
fn far_ahead_arrivals_close_an_unreliable_image() {
    let (mut rig, b) = Rig::new(Setup::default());
    let slot = established(&mut rig);
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    // Three terms ahead of the join: beyond the window {r, r + 1}.
    let ahead = 3 * 65_536;
    for _ in 0..13 {
        rig.now += 100 * MS;
        let receiver = &mut rig.agents.receiver;
        receiver
            .role
            .inject_frame(&receiver.sessions, b, source, slot, ahead, 32, rig.now);
        rig.round(true);
        if !rig.agents.receiver.role.has_image(slot) {
            break;
        }
    }
    assert!(!rig.agents.receiver.role.has_image(slot));
    assert_eq!(
        rig.agents.receiver.counters().images_closed_cannot_resume,
        1
    );
}

/// #284 review P2-3: a RANGE_UNAVAILABLE whose floor lies beyond the
/// receive window closes the image with `GapCannotResume`, whatever the
/// skip policy.
#[test]
fn a_floor_beyond_the_window_closes_the_image() {
    use karyos_protocol::network::{Control, NakReply, NakReplyReason};
    use karyos_sys::log_buffer::AppendOptions;

    let (mut rig, b) = Rig::new(Setup {
        repairs: false,
        reliable: true,
        ..Setup::default()
    });
    let slot = established(&mut rig);
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    rig.agents.receiver.role.drop_data(&[1]);
    for i in 0..4u8 {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[i; 900], AppendOptions::default())
            .unwrap();
    }
    rig.until(true, |rig| rig.agents.receiver.counters().naks >= 1);
    for _ in 0..5 {
        rig.round(true);
    }
    let nak = rig.agents.receiver.role.posted_naks()[0];
    // Two terms past the hole's term: beyond {r, r + 1}.
    let beyond = (nak.range.start / 65_536 + 2) * 65_536;
    let receiver = &mut rig.agents.receiver;
    receiver.role.inject_control(
        &receiver.sessions,
        b,
        source,
        Control::NakReply(NakReply::answering(
            &nak,
            NakReplyReason::RangeUnavailable {
                lowest_retained: beyond,
            },
        )),
        rig.now,
    );
    rig.until(true, |rig| !rig.agents.receiver.role.has_image(slot));
    let counters = rig.agents.receiver.counters();
    assert_eq!(
        (
            counters.images_closed_cannot_resume,
            counters.images_closed_unrecoverable
        ),
        (1, 0)
    );
}

/// The receive window is the pair {r, r + 1}: a floor in the next term is
/// inside it, so RANGE_UNAVAILABLE there proves the hole unrecoverable and
/// `close` closes the image as unrecoverable, not as `GapCannotResume`.
#[test]
fn a_floor_in_the_next_term_is_inside_the_window() {
    use karyos_protocol::network::{Control, NakReply, NakReplyReason};
    use karyos_sys::log_buffer::AppendOptions;

    let (mut rig, b) = Rig::new(Setup {
        repairs: false,
        reliable: true,
        ..Setup::default()
    });
    let slot = established(&mut rig);
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    rig.agents.receiver.role.drop_data(&[1]);
    for i in 0..4u8 {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[i; 900], AppendOptions::default())
            .unwrap();
    }
    rig.until(true, |rig| rig.agents.receiver.counters().naks >= 1);
    for _ in 0..5 {
        rig.round(true);
    }
    let nak = rig.agents.receiver.role.posted_naks()[0];
    let next_term = (nak.range.start / 65_536 + 1) * 65_536 + 64;
    let receiver = &mut rig.agents.receiver;
    receiver.role.inject_control(
        &receiver.sessions,
        b,
        source,
        Control::NakReply(NakReply::answering(
            &nak,
            NakReplyReason::RangeUnavailable {
                lowest_retained: next_term,
            },
        )),
        rig.now,
    );
    rig.until(true, |rig| !rig.agents.receiver.role.has_image(slot));
    let counters = rig.agents.receiver.counters();
    assert_eq!(
        (
            counters.images_closed_unrecoverable,
            counters.images_closed_cannot_resume
        ),
        (1, 0)
    );
}

/// mc-w1, RC-2: on a multicast image a hole's NAK is not sent at once:
/// its cycle draws a delay over `[0, rtt * nak_delay_scale / 16]` (here
/// the bound itself), and the NAK goes once the delay has passed.
#[test]
fn a_multicast_nak_waits_for_its_drawn_delay() {
    use karyos_sys::log_buffer::AppendOptions;

    let (mut rig, _b) = Rig::new(Setup {
        reliable: true,
        multicast: true,
        nak_delay: Some(u64::MAX),
        repairs: false,
        ..Setup::default()
    });
    let slot = established(&mut rig);
    rig.agents.receiver.role.drop_data(&[1]);
    for i in 0..4u8 {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[i; 900], AppendOptions::default())
            .unwrap();
    }
    rig.until(true, |rig| rig.agents.receiver.counters().nak_cycles >= 1);
    let started = rig.now;
    assert_eq!(rig.agents.receiver.counters().naks, 0);
    let bound = rig.agents.receiver.role.last_nak_delay_bound().unwrap();
    // The default scale is 16: the bound is one RTT snapshot.
    assert!(bound > 0, "{bound}");
    rig.until(true, |rig| rig.agents.receiver.counters().naks >= 1);
    assert!(
        rig.now - started >= bound,
        "{} < {bound}",
        rig.now - started
    );
    let nak = rig.agents.receiver.role.posted_naks()[0];
    assert_eq!(nak.alias, alias());
    assert_eq!(
        nak.receiver.receiver_id,
        (u64::from(slot.slot) << 32) | u64::from(slot.generation)
    );
}

/// mc-w1, RC-3: a multicast NAK opens its cycle's window, `W = rtt +
/// repair_linger + repair_slack`; only when it ends with the hole still
/// there does the next cycle draw again. So the hole is asked once per
/// cycle, and two NAKs are at least `repair_linger + repair_slack` (2 ms
/// by default) apart.
#[test]
fn a_multicast_hole_is_asked_once_per_cycle() {
    use karyos_sys::log_buffer::AppendOptions;

    let (mut rig, _b) = Rig::new(Setup {
        reliable: true,
        multicast: true,
        nak_delay: Some(0),
        repairs: false,
        ..Setup::default()
    });
    let slot = established(&mut rig);
    rig.agents.receiver.role.drop_data(&[1]);
    for i in 0..4u8 {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[i; 900], AppendOptions::default())
            .unwrap();
    }
    rig.until(true, |rig| rig.agents.receiver.counters().naks >= 1);
    let first = rig.now;
    rig.until(true, |rig| rig.agents.receiver.counters().naks >= 2);
    assert!(rig.now - first >= 2 * MS, "{}", rig.now - first);
    for _ in 0..50 {
        rig.round(true);
    }
    let counters = rig.agents.receiver.counters();
    let loss = rig.agents.receiver.role.loss_counters(slot).unwrap();
    assert_eq!(counters.nak_cycles, loss.cycles, "{loss:?}");
    // One NAK per cycle; the last cycle's may still be waiting.
    assert!(
        (counters.nak_cycles - 1..=counters.nak_cycles).contains(&counters.naks),
        "{counters:?}"
    );
    let posted = rig.agents.receiver.role.posted_naks();
    assert!(posted.iter().all(|nak| nak.range == posted[0].range));
}

/// Phase 6 wiring, ACS 15957 note 2: the sender's step 8 sends the whole
/// frames before a failing head, then its RANGE_INVALID, in one cycle. A
/// receiver that handles the ERR before its repair step observes the
/// shrink counts one RANGE_INVALID, and the partial repair then starts the
/// count over: two more RANGE_INVALID for the smaller hole stay below the
/// limit of three, and the image stays open.
#[test]
fn a_partial_repair_after_a_step_8_err_resets_its_count() {
    use karyos_protocol::network::{Control, NakReply, NakReplyReason};
    use karyos_sys::log_buffer::AppendOptions;

    let (mut rig, b) = Rig::new(Setup {
        reliable: true,
        repairs: false,
        ..Setup::default()
    });
    let slot = established(&mut rig);
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    // Two frames lost: one hole of two frames.
    rig.agents.receiver.role.drop_data(&[1, 2]);
    for i in 0..4u8 {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[i; 900], AppendOptions::default())
            .unwrap();
    }
    rig.until(true, |rig| rig.agents.receiver.counters().naks >= 1);
    for _ in 0..5 {
        rig.round(true);
    }
    let nak = rig.agents.receiver.role.posted_naks()[0];
    // One aligned 900-byte frame is 960 bytes: the hole holds two.
    assert_eq!(nak.range.length, 2 * 960, "{nak:?}");
    // The ERR first, then the frame the sender sent before it.
    let receiver = &mut rig.agents.receiver;
    receiver.role.inject_control(
        &receiver.sessions,
        b,
        source,
        Control::NakReply(NakReply::answering(&nak, NakReplyReason::RangeInvalid)),
        rig.now,
    );
    receiver.role.inject_frame(
        &receiver.sessions,
        b,
        source,
        slot,
        nak.range.start,
        900,
        rig.now,
    );
    assert_eq!(
        rig.agents
            .receiver
            .role
            .loss_counters(slot)
            .unwrap()
            .range_invalid,
        1
    );
    rig.until(true, |rig| {
        rig.agents
            .receiver
            .role
            .loss_counters(slot)
            .is_some_and(|counters| counters.partial_repairs >= 1)
    });
    // The smaller hole's NAK, answered RANGE_INVALID twice.
    let naks = rig.agents.receiver.counters().naks;
    rig.until(true, |rig| rig.agents.receiver.counters().naks > naks);
    for _ in 0..5 {
        rig.round(true);
    }
    let retry = *rig.agents.receiver.role.posted_naks().last().unwrap();
    assert_eq!(retry.range.start, nak.range.start + 960, "{retry:?}");
    for _ in 0..2 {
        let receiver = &mut rig.agents.receiver;
        receiver.role.inject_control(
            &receiver.sessions,
            b,
            source,
            Control::NakReply(NakReply::answering(&retry, NakReplyReason::RangeInvalid)),
            rig.now,
        );
    }
    for _ in 0..5 {
        rig.round(true);
    }
    assert!(rig.agents.receiver.role.has_image(slot));
    assert_eq!(
        rig.agents.receiver.counters().images_closed_protocol_fault,
        0
    );
}

/// mc-w1 with the sender's repair: a datagram lost on a multicast image is
/// NAKed after its drawn delay, repaired, and asked no more.
#[test]
fn a_lost_multicast_datagram_is_repaired() {
    use karyos_sys::log_buffer::AppendOptions;

    let (mut rig, _b) = Rig::new(Setup {
        reliable: true,
        multicast: true,
        nak_delay: Some(0),
        ..Setup::default()
    });
    let slot = established(&mut rig);
    rig.agents.receiver.role.drop_data(&[1]);
    for i in 0..4u8 {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[i; 900], AppendOptions::default())
            .unwrap();
    }
    rig.until(true, |rig| {
        rig.agents
            .receiver
            .role
            .loss_counters(slot)
            .is_some_and(|counters| counters.repaired >= 1)
    });
    let counters = rig.agents.receiver.role.loss_counters(slot).unwrap();
    assert_eq!(counters.detected, counters.repaired, "{counters:?}");
    assert!(counters.cycles >= 1, "{counters:?}");
    let naks = rig.agents.receiver.counters().naks;
    for _ in 0..50 {
        rig.round(true);
    }
    assert_eq!(rig.agents.receiver.counters().naks, naks);
}

/// The setup of the control group tests: a reliable multicast image with
/// a control group (C), whose sender does not repair, so holes persist.
fn control_setup(nak_delay: u64) -> Setup {
    Setup {
        reliable: true,
        multicast: true,
        nak_delay: Some(nak_delay),
        repairs: false,
        control_group: true,
        ..Setup::default()
    }
}

/// Loses datagram 1 of four 900-byte messages on lane 0.
fn lose_one(rig: &mut Rig) {
    use karyos_sys::log_buffer::AppendOptions;

    rig.agents.receiver.role.drop_data(&[1]);
    for i in 0..4u8 {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[i; 900], AppendOptions::default())
            .unwrap();
    }
}

/// The encoded bytes of `control`.
fn encoded(control: karyos_protocol::network::Control) -> Vec<u8> {
    let mut bytes = vec![0u8; 2048];
    let length = control.encode(&mut bytes).unwrap();
    bytes.truncate(length);
    bytes
}

/// A peer receiver's NAK of `range` on `slot`'s image.
fn peer_nak(range: karyos_protocol::network::NakRange) -> karyos_protocol::network::Nak {
    karyos_protocol::network::Nak {
        alias: alias(),
        identity: identity(),
        receiver: karyos_protocol::network::Receiver {
            receiver_boot_id: [7, 7],
            receiver_id: 99,
        },
        range,
    }
}

/// mc-w2, RC-7: each NAK of a multicast image with a control group goes
/// to the sender and, once, to the control group, after the unicast copy
/// and with no report. The receiver's own copy comes back on the group
/// (here C sends to itself) and is dropped: it never suppresses.
#[test]
fn a_nak_copy_goes_to_the_control_group() {
    let (mut rig, _b) = Rig::new(control_setup(0));
    let _slot = established(&mut rig);
    lose_one(&mut rig);
    rig.until(true, |rig| rig.agents.receiver.counters().naks >= 1);
    rig.until(true, |rig| {
        rig.agents.receiver.counters().group_nak_own >= 1
    });
    let receiver = rig.agents.receiver.counters();
    assert_eq!(receiver.group_nak_copies, receiver.naks, "{receiver:?}");
    assert_eq!(receiver.group_nak_suppressions, 0);
    assert!(rig.agents.sender.counters().group_nak_copies_sent >= 1);
    let nak = rig.agents.receiver.role.posted_naks()[0];
    assert_eq!(nak.range, HOLE);
}

/// The hole `lose_one` leaves: the second 960-byte frame of lane 0.
const HOLE: karyos_protocol::network::NakRange = karyos_protocol::network::NakRange {
    lane: karyos_protocol::frame::Lane::ZERO,
    length: 960,
    start: 960,
};

/// mc-w2, B: a peer's group NAK covering the hole before the cycle's
/// drawn delay cancels the local NAK; the window runs from it, and when it
/// ends with the hole still there the next cycle NAKs.
#[test]
fn a_peer_group_nak_suppresses_the_cycle() {
    let (mut rig, _b) = Rig::new(control_setup(u64::MAX));
    let _slot = established(&mut rig);
    let control = rig.control.unwrap();
    lose_one(&mut rig);
    rig.until(true, |rig| rig.agents.receiver.counters().nak_cycles >= 1);
    assert_eq!(rig.agents.receiver.counters().naks, 0);
    let bytes = encoded(karyos_protocol::network::Control::Nak(peer_nak(HOLE)));
    rig.agents
        .receiver
        .role
        .inject_group(control, &bytes, rig.now);
    let counters = rig.agents.receiver.counters();
    assert_eq!(counters.group_naks, 1, "{counters:?}");
    assert_eq!(counters.group_nak_suppressions, 1, "{counters:?}");
    // Past the drawn delay (at most one RTT): still no local NAK.
    let bound = rig.agents.receiver.role.last_nak_delay_bound().unwrap();
    let until = rig.now + bound;
    while rig.now <= until {
        rig.round(true);
    }
    assert_eq!(rig.agents.receiver.counters().naks, 0);
    // The window ends, the hole persists: the next cycle NAKs.
    rig.until(true, |rig| rig.agents.receiver.counters().naks >= 1);
    assert!(rig.agents.receiver.counters().nak_cycles >= 2);
}

/// mc-w2, RC-15 validation, in order: a datagram that is not a NAK; a
/// NAK of another incarnation or of a lane past the image's; this
/// receiver's own NAK; a range that breaks the term rule. Each is dropped
/// and counted, and suppresses nothing.
#[test]
fn group_naks_are_validated() {
    use karyos_protocol::network::{Control, NakRange, NakReply, NakReplyReason};

    let (mut rig, _b) = Rig::new(control_setup(u64::MAX));
    let slot = established(&mut rig);
    let control = rig.control.unwrap();
    lose_one(&mut rig);
    rig.until(true, |rig| rig.agents.receiver.counters().nak_cycles >= 1);
    let mut other_alias = peer_nak(HOLE);
    other_alias.alias.session_id += 1;
    let mut own = peer_nak(HOLE);
    own.receiver = rig.agents.receiver.role.receiver_of(slot);
    // The image has two lanes: lane 2 is the first past them.
    let past_lane = peer_nak(NakRange {
        lane: karyos_protocol::frame::Lane::try_new(2).unwrap(),
        ..HOLE
    });
    // Across the end of the first 64 KiB term.
    let across = peer_nak(NakRange {
        start: 65_536 - 32,
        length: 64,
        ..HOLE
    });
    let reply = Control::NakReply(NakReply::answering(
        &peer_nak(HOLE),
        NakReplyReason::RangeInvalid,
    ));
    for control_bytes in [
        encoded(reply),
        encoded(Control::Nak(other_alias)),
        encoded(Control::Nak(past_lane)),
        encoded(Control::Nak(own)),
        encoded(Control::Nak(across)),
    ] {
        rig.agents
            .receiver
            .role
            .inject_group(control, &control_bytes, rig.now);
    }
    let counters = rig.agents.receiver.counters();
    assert_eq!(counters.group_nak_not_nak, 1, "{counters:?}");
    assert_eq!(counters.group_nak_unbound, 2, "{counters:?}");
    assert_eq!(counters.group_nak_own, 1, "{counters:?}");
    assert_eq!(counters.group_nak_range, 1, "{counters:?}");
    assert_eq!(counters.group_naks, 0, "{counters:?}");
    assert_eq!(counters.group_nak_suppressions, 0, "{counters:?}");
}

/// mc-w2, loop rule and inbound budget: real datagrams on the control
/// group are read at most `group_nak_budget` per receiver cycle, change
/// only suppression state, and never reach the sender.
#[test]
fn group_naks_are_budgeted_and_never_reach_the_sender() {
    use std::net::UdpSocket;

    let (mut rig, _b) = Rig::new(Setup {
        group_nak_budget: Some(1),
        ..control_setup(u64::MAX)
    });
    let _slot = established(&mut rig);
    let control = rig.control.unwrap();
    let group = rig.endpoints.local_address(control).unwrap();
    lose_one(&mut rig);
    rig.until(true, |rig| rig.agents.receiver.counters().nak_cycles >= 1);
    let sender_naks = rig.agents.sender.counters().naks;
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    let bytes = encoded(karyos_protocol::network::Control::Nak(peer_nak(HOLE)));
    for _ in 0..3 {
        peer.send_to(&bytes, group).unwrap();
    }
    // Real datagrams arrive on their own schedule, not the rig's clock:
    // the check is per cycle, at most one read, until all three are in.
    let mut previous = rig.agents.receiver.counters().group_naks;
    for _ in 0..20_000 {
        rig.round(true);
        let read = rig.agents.receiver.counters().group_naks;
        assert!(read - previous <= 1, "{read} after {previous} in one cycle");
        previous = read;
        if read >= 3 {
            break;
        }
    }
    let counters = rig.agents.receiver.counters();
    assert_eq!(counters.group_naks, 3, "{counters:?}");
    assert!(counters.group_nak_budget_full >= 3, "{counters:?}");
    // Whether a peer NAK suppresses depends on its arrival against the
    // drawn delay; a_peer_group_nak_suppresses_the_cycle asserts it
    // through inject_group, which no kernel delivery can delay.
    assert_eq!(rig.agents.sender.counters().naks, sender_naks);
}

/// #296 review: with the delay pool empty and its refill failing, a
/// multicast cycle draws the bound; the failed refill and the empty draw
/// are each counted, the draw in the step that made it. A later refill
/// that succeeds is counted as a draw from the system.
#[test]
fn an_empty_delay_pool_is_counted_in_its_step() {
    let (mut rig, _b) = Rig::new(Setup {
        reliable: true,
        multicast: true,
        repairs: false,
        ..Setup::default()
    });
    let _slot = established(&mut rig);
    rig.agents.receiver.role.drain_nak_delays(true);
    lose_one(&mut rig);
    rig.until(true, |rig| rig.agents.receiver.counters().nak_cycles >= 1);
    let counters = rig.agents.receiver.counters();
    assert_eq!(
        counters.nak_delay_empty, counters.nak_cycles,
        "{counters:?}"
    );
    assert!(counters.nak_delay_refill_failures >= 1, "{counters:?}");
    let draws = counters.nak_delay_draws;
    rig.agents.receiver.role.drain_nak_delays(false);
    rig.round(true);
    assert_eq!(rig.agents.receiver.counters().nak_delay_draws, draws + 1);
}

/// #298 review: a NAK on an endpoint that is not this image's control
/// group finds no image, and validation runs in order, so a NAK failing
/// several checks counts only the first: another alias before its own
/// block, its own block before the term rule.
#[test]
fn group_nak_validation_is_ordered_and_bound_to_its_control_group() {
    use karyos_protocol::network::{Control, NakRange};

    let (mut rig, b) = Rig::new(control_setup(u64::MAX));
    let slot = established(&mut rig);
    let control = rig.control.unwrap();
    lose_one(&mut rig);
    rig.until(true, |rig| rig.agents.receiver.counters().nak_cycles >= 1);
    let own = rig.agents.receiver.role.receiver_of(slot);
    // A valid peer NAK, but on the data endpoint B.
    let valid = encoded(Control::Nak(peer_nak(HOLE)));
    rig.agents.receiver.role.inject_group(b, &valid, rig.now);
    // Another alias and our own block: unbound, not own.
    let mut other_and_own = peer_nak(HOLE);
    other_and_own.alias.session_id += 1;
    other_and_own.receiver = own;
    // Our own block and a range across the term: own, not range.
    let mut own_and_across = peer_nak(NakRange {
        start: 65_536 - 32,
        length: 64,
        ..HOLE
    });
    own_and_across.receiver = own;
    for bytes in [
        encoded(Control::Nak(other_and_own)),
        encoded(Control::Nak(own_and_across)),
    ] {
        rig.agents
            .receiver
            .role
            .inject_group(control, &bytes, rig.now);
    }
    let counters = rig.agents.receiver.counters();
    assert_eq!(counters.group_nak_unbound, 2, "{counters:?}");
    assert_eq!(counters.group_nak_own, 1, "{counters:?}");
    assert_eq!(counters.group_nak_range, 0, "{counters:?}");
    assert_eq!(counters.group_naks, 0, "{counters:?}");
}

/// The configured identity of the rig's subscription: receiver 77 with
/// `group_tag`.
fn identity_77(group_tag: u64) -> crate::membership::ReceiverIdentity {
    crate::membership::ReceiverIdentity {
        receiver_id: core::num::NonZeroU64::new(77).unwrap(),
        group_tag,
    }
}

/// MC-1: a subscription's configured identity is what its image names in
/// every RB block. The sender binds receiver 77 from its SMs, the image's
/// NAK names it, and its RTTM round trip still matches (a sample is
/// taken). The negative control, an image with no identity, names the id
/// derived from its slot, unchanged.
#[test]
fn an_image_names_its_configured_receiver_identity() {
    use karyos_sys::log_buffer::AppendOptions;

    for configured in [true, false] {
        let (mut rig, _b) = Rig::new(Setup {
            reliable: true,
            repairs: false,
            identity: configured.then(|| identity_77(0)),
            ..Setup::default()
        });
        let slot = established(&mut rig);
        let expected = if configured {
            77
        } else {
            (u64::from(slot.slot) << 32) | u64::from(slot.generation)
        };
        rig.until(true, |rig| {
            rig.agents.sender.role.bound_receivers(alias()) == [Some(expected)]
        });
        rig.agents.receiver.role.drop_data(&[1]);
        for i in 0..4u8 {
            let log = rig.log.as_mut().unwrap();
            let _ = log.publications[0]
                .append(&[i; 900], AppendOptions::default())
                .unwrap();
        }
        rig.until(true, |rig| rig.agents.receiver.counters().naks >= 1);
        let nak = rig.agents.receiver.role.posted_naks()[0];
        assert_eq!(
            nak.receiver.receiver_id, expected,
            "configured {configured}"
        );
        rig.until(true, |rig| rig.agents.receiver.counters().rttm_samples >= 1);
    }
}

/// MC-2: an SM whose `group_tag` is not the tag configured for its
/// receiver is rejected whole before it touches the sender's binding
/// (#304 ruling): counted, it pins no receiver id and never establishes
/// the session, so it cannot hold retention either. The negative control,
/// the configured tag, binds receiver 77, establishes and joins.
#[test]
fn an_sm_with_another_tag_is_rejected_whole() {
    use crate::membership::{PublicationRoles, Strategy};

    fn tagged_5() -> PublicationRoles {
        PublicationRoles {
            strategy: Strategy::Min,
            required: Vec::new(),
            tags: vec![(77, 5)],
        }
    }
    for declared in [6, 5] {
        let (mut rig, _b) = Rig::new(Setup {
            reliable: true,
            identity: Some(identity_77(declared)),
            roles: Some(tagged_5),
            ..Setup::default()
        });
        if declared == 5 {
            let _ = established(&mut rig);
            rig.until(true, |rig| {
                rig.agents
                    .sender
                    .role
                    .membership_of(alias())
                    .is_some_and(|membership| membership.counters().joins >= 1)
            });
            assert_eq!(rig.agents.sender.counters().sm_tag_mismatch, 0);
            assert_eq!(rig.agents.sender.role.bound_receivers(alias()), [Some(77)]);
        } else {
            rig.until(true, |rig| {
                rig.agents.sender.counters().sm_tag_mismatch >= 3
            });
            assert_eq!(rig.agents.sender.role.session_counters().established, 0);
            assert!(
                rig.agents
                    .sender
                    .role
                    .bound_receivers(alias())
                    .iter()
                    .all(Option::is_none),
                "a mismatched SM pins no receiver id"
            );
            assert_eq!(rig.agents.sender.counters().sm_accepted, 0);
        }
    }
}

/// #304 review: with a configured identity, the receiver still knows its
/// own NAK copy when the control group loops it back (it names receiver
/// 77, not the slot's id), so it never suppresses its own NAK.
#[test]
fn an_identity_knows_its_own_group_copy() {
    let (mut rig, _b) = Rig::new(Setup {
        identity: Some(identity_77(0)),
        ..control_setup(0)
    });
    let _slot = established(&mut rig);
    lose_one(&mut rig);
    rig.until(true, |rig| rig.agents.receiver.counters().naks >= 1);
    rig.until(true, |rig| {
        rig.agents.receiver.counters().group_nak_own >= 1
    });
    assert_eq!(rig.agents.receiver.counters().group_nak_suppressions, 0);
    assert_eq!(
        rig.agents.receiver.role.posted_naks()[0]
            .receiver
            .receiver_id,
        77
    );
}

/// SPEC §13 phase 2, alias collision: two publishers on different source
/// endpoints announce the same `session_id` and stream, with different
/// identities, to one receiving endpoint. The receiver keeps two images,
/// keyed by source; each image's subscriber reads only its own
/// publisher's messages, in order, and no frame crosses between them.
#[test]
fn test_receiver_alias_collision_keeps_two_images_apart() {
    use karyos_sys::log_buffer::{AppendOptions, Role};

    let (mut rig, b) = Rig::new(Setup {
        reliable: true,
        ..Setup::default()
    });
    let first = established(&mut rig);
    let destination = rig.endpoints.local_address(b).unwrap();
    let other = Identity {
        driver_id: [8, 9],
        registration_id: 4,
        incarnation: 1,
    };
    let _a2 = rig.second_publisher(destination, other);
    rig.until(true, |rig| {
        rig.agents.sender.role.session_counters().established == 2
    });
    rig.until(true, |rig| {
        rig.events
            .iter()
            .filter(|event| matches!(event, ImageEvent::Installed { .. }))
            .count()
            == 2
    });
    let second = rig
        .events
        .iter()
        .find_map(|event| match event {
            ImageEvent::Installed { slot, .. } if *slot != first => Some(*slot),
            _ => None,
        })
        .unwrap();
    assert_ne!(first, second);
    let (_c1, mut one) = image_subscriber(&rig, first, 0, Role::Optional);
    let (_c2, mut two) = image_subscriber(&rig, second, 0, Role::Optional);
    // Publisher A writes 1s, A2 writes 2s, each with its own sequence.
    for i in 0..8u8 {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[1, i, 0, 0], AppendOptions::default())
            .unwrap();
        let log = rig.second.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[2, i, 0, 0], AppendOptions::default())
            .unwrap();
    }
    let (mut seen_one, mut seen_two) = (Vec::new(), Vec::new());
    for _ in 0..2000 {
        rig.round(true);
        while let Some(message) = poll_message(&mut one) {
            seen_one.push((message[0], message[1]));
        }
        while let Some(message) = poll_message(&mut two) {
            seen_two.push((message[0], message[1]));
        }
        if seen_one.len() >= 8 && seen_two.len() >= 8 {
            break;
        }
    }
    let expect = |publisher| (0..8u8).map(|i| (publisher, i)).collect::<Vec<_>>();
    // The first image is A's, the second A2's: established in that order.
    assert_eq!(seen_one, expect(1));
    assert_eq!(seen_two, expect(2));
}

/// The ANNOUNCE of the rig's publication, as a later path receives it.
fn announce(term_length: u32) -> SetupAnnounce {
    SetupAnnounce {
        alias: alias(),
        identity: identity(),
        term: term(term_length),
        lane_count: 2,
    }
}

/// rp-w1, RP-1 and RP-2: a later path of the publication binds to the
/// image through its own challenge, with the image's identity, terms and
/// lanes; the image stays while either path's subscription remains, and
/// retires with the last.
#[test]
fn a_later_path_binds_and_keeps_the_image() {
    let setup = Setup {
        reliable: true,
        ..Setup::default()
    };
    let (mut rig, b) = Rig::new(setup.again());
    let slot = established(&mut rig);
    let b2 = rig.second_path(&setup, announce(setup.term_length), None);
    rig.until(true, |rig| rig.agents.receiver.role.live_paths(slot) == 2);
    // The founding path's subscription goes: the later path keeps it.
    rig.unsubscribe(b);
    for _ in 0..50 {
        rig.round(true);
    }
    assert!(rig.agents.receiver.role.has_image(slot));
    // The last path's subscription goes: the image retires.
    rig.unsubscribe(b2);
    rig.until(true, |rig| !rig.agents.receiver.role.has_image(slot));
}

/// rp-w1, RP-1: a later path whose announcement does not match the
/// image (another lane count) binds nothing: the image keeps one path.
#[test]
fn a_mismatched_later_path_is_refused() {
    let setup = Setup {
        reliable: true,
        ..Setup::default()
    };
    let (mut rig, _b) = Rig::new(setup.again());
    let slot = established(&mut rig);
    let _b2 = rig.second_path(
        &setup,
        SetupAnnounce {
            lane_count: 1,
            ..announce(setup.term_length)
        },
        None,
    );
    for _ in 0..100 {
        rig.round(true);
    }
    assert_eq!(rig.agents.receiver.role.live_paths(slot), 1);
}

/// rp-w1, RP-1: a later path joins at the sender's current positions,
/// above the image's join; the binding moves no position, so a
/// subscriber of the image keeps reading every message once, in order.
#[test]
fn a_later_path_join_moves_no_position() {
    use karyos_sys::log_buffer::{AppendOptions, Role};

    let setup = Setup {
        reliable: true,
        ..Setup::default()
    };
    let (mut rig, _b) = Rig::new(setup.again());
    let slot = established(&mut rig);
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    let mut seen = Vec::new();
    let send = |rig: &mut Rig, from: u8, to: u8| {
        for i in from..to {
            let log = rig.log.as_mut().unwrap();
            let _ = log.publications[0]
                .append(&[i; 600], AppendOptions::default())
                .unwrap();
        }
    };
    send(&mut rig, 0, 4);
    for _ in 0..200 {
        rig.round(true);
        while let Some(message) = poll_message(&mut subscriber) {
            seen.push(message[0]);
        }
        if seen.len() == 4 {
            break;
        }
    }
    // The later path joins where the sender is now: four 600-byte
    // messages (640 aligned bytes each) above the image's join.
    let joins = Lanes::new(&[4 * 640, 0]).unwrap();
    let _b2 = rig.second_path(&setup, announce(setup.term_length), Some(joins));
    rig.until(true, |rig| rig.agents.receiver.role.live_paths(slot) == 2);
    send(&mut rig, 4, 8);
    for _ in 0..200 {
        rig.round(true);
        while let Some(message) = poll_message(&mut subscriber) {
            seen.push(message[0]);
        }
        if seen.len() == 8 {
            break;
        }
    }
    assert_eq!(seen, (0..8).collect::<Vec<u8>>());
}

/// rp-w1, RP-2: a path with no fresh evidence times out at the path
/// liveness timeout and is removed; the image stays while the other path
/// keeps delivering, and no path loss retires it.
#[test]
fn losing_one_path_keeps_the_image() {
    use karyos_sys::log_buffer::AppendOptions;

    let setup = Setup {
        reliable: true,
        ..Setup::default()
    };
    let (mut rig, _b) = Rig::new(setup.again());
    let slot = established(&mut rig);
    let _b2 = rig.second_path(&setup, announce(setup.term_length), None);
    rig.until(true, |rig| rig.agents.receiver.role.live_paths(slot) == 2);
    // Data comes only on the founding path; the later one hears nothing.
    let mut lost = false;
    for i in 0..15u8 {
        rig.now += 1_000_000_000;
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[i; 100], AppendOptions::default())
            .unwrap();
        for _ in 0..5 {
            rig.round(true);
        }
        if rig.agents.receiver.role.live_paths(slot) == 1 {
            lost = true;
            break;
        }
    }
    assert!(lost, "the silent path never timed out");
    assert!(rig.agents.receiver.role.has_image(slot));
}

/// rp-w1, RP-6: once the lane's rebuild position passes a term's end, the
/// term is complete and each bound path is charged what it did not deliver
/// fresh in it, from the term after its join's: the founding path
/// delivered all of term 1, the silent later path is missing all of it.
#[test]
fn a_complete_term_charges_each_path_its_missing_bytes() {
    use karyos_sys::log_buffer::AppendOptions;

    let setup = Setup {
        reliable: true,
        ..Setup::default()
    };
    let (mut rig, _b) = Rig::new(setup.again());
    let slot = established(&mut rig);
    let _b2 = rig.second_path(&setup, announce(setup.term_length), None);
    rig.until(true, |rig| rig.agents.receiver.role.live_paths(slot) == 2);
    // A little over two 64 KiB terms on lane 0, each message offered
    // again while the publication is back-pressured.
    let mut sent = 0u8;
    for _ in 0..20_000 {
        let log = rig.log.as_mut().unwrap();
        let outcome = log.publications[0]
            .append(&[sent; 900], AppendOptions::default())
            .unwrap();
        if matches!(
            outcome,
            karyos_sys::log_buffer::AppendOutcome::Appended { .. }
        ) {
            sent += 1;
            if sent == 140 {
                break;
            }
        }
        rig.round(true);
    }
    assert_eq!(sent, 140);
    rig.until(true, |rig| {
        rig.agents
            .receiver
            .role
            .path_counts(slot, 1)
            .is_some_and(|counts| counts.missing_bytes > 0)
    });
    let founding = rig.agents.receiver.role.path_counts(slot, 0).unwrap();
    let later = rig.agents.receiver.role.path_counts(slot, 1).unwrap();
    assert_eq!(
        later.missing_bytes,
        u64::from(setup.term_length),
        "{later:?}"
    );
    assert_eq!(founding.missing_bytes, 0, "{founding:?}");
}

/// Detection-to-NAK time of a lost datagram on a reliable image: the rig
/// time between the round its hole is detected and the round its NAK is
/// handed over.
fn nak_wait(rig: &mut Rig, slot: SlotRef) -> u64 {
    use karyos_sys::log_buffer::AppendOptions;

    rig.agents.receiver.role.drop_data(&[1]);
    for i in 0..4u8 {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[i; 900], AppendOptions::default())
            .unwrap();
    }
    rig.until(true, |rig| {
        rig.agents
            .receiver
            .role
            .loss_counters(slot)
            .is_some_and(|counters| counters.detected >= 1)
    });
    let detected = rig.now;
    let naks = rig.agents.receiver.counters().naks;
    if naks >= 1 {
        return 0;
    }
    rig.until(true, |rig| rig.agents.receiver.counters().naks >= 1);
    rig.now - detected
}

/// rp-w2, ADR-0018's case: with a later path live and silent, a gap on the
/// founding path is requested only once the skew window (1 ms) passed
/// since detection, in case the other path delivers it; with one live
/// path the NAK goes in the round that detected the gap (RP-5).
#[test]
fn a_gap_waits_the_skew_window_while_another_path_is_live() {
    let setup = Setup {
        reliable: true,
        repairs: false,
        ..Setup::default()
    };
    let (mut rig, _b) = Rig::new(setup.again());
    let slot = established(&mut rig);
    let _b2 = rig.second_path(&setup, announce(setup.term_length), None);
    rig.until(true, |rig| rig.agents.receiver.role.live_paths(slot) == 2);
    let wait = nak_wait(&mut rig, slot);
    assert!(wait >= 1_000_000, "{wait} ns");
    let (mut single, _b) = Rig::new(setup.again());
    let slot = established(&mut single);
    assert_eq!(nak_wait(&mut single, slot), 0);
}

/// rp-w3, RP-7: an image's SMs go on every bound path: the founding path
/// in its reserved slot, each later path as a copy; the default control
/// ring holds them all, so none is skipped.
#[test]
fn an_sm_goes_on_every_bound_path() {
    let setup = Setup {
        reliable: true,
        ..Setup::default()
    };
    let (mut rig, _b) = Rig::new(setup.again());
    let slot = established(&mut rig);
    let _b2 = rig.second_path(&setup, announce(setup.term_length), None);
    rig.until(true, |rig| rig.agents.receiver.role.live_paths(slot) == 2);
    let sent = rig.agents.receiver.counters().sm_sent;
    rig.until(true, |rig| {
        rig.agents.receiver.counters().sm_sent >= sent + 3
    });
    let counters = rig.agents.receiver.counters();
    assert!(counters.sm_copies >= 3, "{counters:?}");
    assert_eq!(counters.sm_copies_skipped, 0, "{counters:?}");
}

/// rp-w3, RP-7: a NAK goes on every bound path, the founding path first
/// and a copy on each later one, and the copies anchor it once: the loss
/// state records one submission per NAK handed over, not one per copy.
#[test]
fn a_nak_goes_on_every_bound_path() {
    use karyos_sys::log_buffer::AppendOptions;

    let setup = Setup {
        reliable: true,
        repairs: false,
        ..Setup::default()
    };
    let (mut rig, _b) = Rig::new(setup.again());
    let slot = established(&mut rig);
    let _b2 = rig.second_path(&setup, announce(setup.term_length), None);
    rig.until(true, |rig| rig.agents.receiver.role.live_paths(slot) == 2);
    rig.agents.receiver.role.drop_data(&[1]);
    for i in 0..4u8 {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[i; 900], AppendOptions::default())
            .unwrap();
    }
    rig.until(true, |rig| rig.agents.receiver.counters().naks >= 2);
    for _ in 0..10 {
        rig.round(true);
    }
    let counters = rig.agents.receiver.counters();
    let loss = rig.agents.receiver.role.loss_counters(slot).unwrap();
    assert!(counters.nak_copies >= counters.naks - 1, "{counters:?}");
    assert_eq!(counters.nak_copies_skipped, 0, "{counters:?}");
    assert!(loss.submitted <= counters.naks, "{loss:?} {counters:?}");
    assert_eq!(loss.retries, loss.submitted - 1, "{loss:?}");
}

/// #307 review P2-3: once the founding path's subscription is removed and
/// a later path keeps the image, its control still flows, on the later
/// path only: NAK copies anchor the NAK (the loss state records the
/// submission), and SM copies keep going.
#[test]
fn control_flows_on_the_later_path_after_the_founding_one_goes() {
    use karyos_sys::log_buffer::AppendOptions;

    let setup = Setup {
        reliable: true,
        repairs: false,
        ..Setup::default()
    };
    let (mut rig, b) = Rig::new(setup.again());
    let slot = established(&mut rig);
    let _b2 = rig.second_path(&setup, announce(setup.term_length), None);
    rig.until(true, |rig| rig.agents.receiver.role.live_paths(slot) == 2);
    rig.unsubscribe(b);
    for _ in 0..5 {
        rig.round(true);
    }
    assert!(rig.agents.receiver.role.has_image(slot));
    let before = rig.agents.receiver.counters();
    let founding = rig.agents.receiver.role.founding_naks();
    let founding_sms = rig.agents.receiver.role.founding_sms();
    rig.agents.receiver.role.drop_data(&[1]);
    for i in 0..4u8 {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[i; 900], AppendOptions::default())
            .unwrap();
    }
    rig.until(true, |rig| {
        rig.agents
            .receiver
            .role
            .loss_counters(slot)
            .is_some_and(|loss| loss.submitted >= 1)
    });
    rig.until(true, |rig| {
        rig.agents.receiver.counters().sm_copies > before.sm_copies + 2
    });
    let after = rig.agents.receiver.counters();
    assert!(after.nak_copies > before.nak_copies, "{after:?}");
    // Nothing went on the founding path: no NAK and no SM.
    assert_eq!(rig.agents.receiver.role.founding_naks(), founding);
    assert_eq!(rig.agents.receiver.role.founding_sms(), founding_sms);
}

/// #307 review, §8 join reconciliation: a later path whose join is below
/// the image's is accepted, and its frames below the image's join are
/// `Late` on that path.
#[test]
fn a_later_path_below_the_join_delivers_late() {
    let setup = Setup {
        reliable: true,
        before: 4,
        ..Setup::default()
    };
    let (mut rig, _b) = Rig::new(setup.again());
    let slot = established(&mut rig);
    let b2 = rig.second_path(
        &setup,
        announce(setup.term_length),
        Some(Lanes::new(&[0, 0]).unwrap()),
    );
    rig.until(true, |rig| rig.agents.receiver.role.live_paths(slot) == 2);
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    let receiver = &mut rig.agents.receiver;
    receiver
        .role
        .inject_frame(&receiver.sessions, b2, source, slot, 0, 1000, rig.now);
    let later = rig.agents.receiver.role.path_counts(slot, 1).unwrap();
    assert_eq!(later.late, 1, "{later:?}");
}

/// #307 review, §8: a path lost at its liveness timeout and established
/// again binds once more and reconciles the same way.
#[test]
fn a_lost_path_is_established_again() {
    use karyos_sys::log_buffer::AppendOptions;

    let setup = Setup {
        reliable: true,
        ..Setup::default()
    };
    let (mut rig, _b) = Rig::new(setup.again());
    let slot = established(&mut rig);
    let b2 = rig.second_path(&setup, announce(setup.term_length), None);
    rig.until(true, |rig| rig.agents.receiver.role.live_paths(slot) == 2);
    for i in 0..15u8 {
        rig.now += 1_000_000_000;
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[i; 100], AppendOptions::default())
            .unwrap();
        for _ in 0..5 {
            rig.round(true);
        }
        if rig.agents.receiver.role.live_paths(slot) == 1 {
            break;
        }
    }
    assert_eq!(rig.agents.receiver.role.live_paths(slot), 1);
    // The path announces again on B2 and completes a fresh challenge.
    rig.reannounce(b2, announce(setup.term_length));
    rig.until(true, |rig| rig.agents.receiver.role.live_paths(slot) == 2);
    assert!(rig.agents.receiver.role.has_image(slot));
}

/// #307 review, §8: an announcement of another identity on a later
/// endpoint binds no path of the image.
#[test]
fn a_later_path_of_another_identity_binds_nothing() {
    let setup = Setup {
        reliable: true,
        ..Setup::default()
    };
    let (mut rig, _b) = Rig::new(setup.again());
    let slot = established(&mut rig);
    let other = SetupAnnounce {
        identity: Identity {
            incarnation: 2,
            ..identity()
        },
        ..announce(setup.term_length)
    };
    let _b2 = rig.second_path(&setup, other, None);
    for _ in 0..100 {
        rig.round(true);
    }
    assert_eq!(rig.agents.receiver.role.live_paths(slot), 1);
}

/// #307 review, §8 liveness: with every path silent the last one is lost
/// and the image follows image liveness: it retires.
#[test]
fn losing_the_last_path_retires_the_image() {
    let setup = Setup {
        reliable: true,
        ..Setup::default()
    };
    let (mut rig, _b) = Rig::new(setup.again());
    let slot = established(&mut rig);
    let _b2 = rig.second_path(&setup, announce(setup.term_length), None);
    rig.until(true, |rig| rig.agents.receiver.role.live_paths(slot) == 2);
    for _ in 0..30 {
        rig.now += 1_000_000_000;
        for _ in 0..3 {
            rig.round(true);
        }
        if !rig.agents.receiver.role.has_image(slot) {
            break;
        }
    }
    assert!(!rig.agents.receiver.role.has_image(slot));
}

/// C3 (conflated-network-images.md (b)): a conflated lane whose view's
/// feeder is not attached seals at once, counted; an unconflated image has
/// no link and its seals are untouched (control).
#[test]
fn an_unattached_conflated_lane_seals_at_once() {
    for conflated in [Some(Lane::ZERO), None] {
        let (mut rig, _b) = Rig::new(Setup {
            conflated,
            ..Setup::default()
        });
        let slot = established(&mut rig);
        assert_eq!(rig.images.freshness(slot).map(|(lane, _)| lane), conflated);
        lose_one(&mut rig);
        rig.until(true, |rig| rig.agents.receiver.counters().gaps_sealed >= 1);
        let counters = rig.agents.receiver.counters();
        assert_eq!(counters.seals_unattached, u64::from(conflated.is_some()));
        assert_eq!((counters.barrier_posts, counters.seals_gated), (0, 0));
    }
}

/// With its feeder attached, the hole is posted and its seal held past the
/// reorder deadline until the feeder acknowledges; then it is sealed, and
/// the terminal cell stays empty.
#[test]
fn an_attached_conflated_lane_seals_after_the_ack() {
    let (mut rig, _b) = Rig::new(Setup {
        conflated: Some(Lane::ZERO),
        ..Setup::default()
    });
    let slot = established(&mut rig);
    let link = rig.images.freshness(slot).unwrap().1.clone();
    let feeder = link.mailbox().unwrap();
    feeder.attach();
    lose_one(&mut rig);
    rig.until(true, |rig| {
        rig.agents.receiver.counters().barrier_posts >= 1
    });
    let request = feeder.pending().unwrap();
    for _ in 0..20 {
        rig.round(true);
    }
    let counters = rig.agents.receiver.counters();
    assert_eq!(counters.gaps_sealed, 0, "held for the ack");
    assert!(counters.seals_gated >= 1);
    feeder.acknowledge(request.request).unwrap();
    rig.until(true, |rig| rig.agents.receiver.counters().gaps_sealed >= 1);
    let counters = rig.agents.receiver.counters();
    assert_eq!((counters.barrier_acks, counters.barrier_timeouts), (1, 0));
    assert_eq!(
        karyos_sys::freshness::TerminalCell::read(&link.terminal_words()),
        None
    );
}

/// A stalled feeder: at `barrier_ack_timeout` the receiver publishes the
/// view's terminal cell with the posted interval, then seals (design (c)).
#[test]
fn a_stalled_feeder_closes_the_conflated_view() {
    let (mut rig, _b) = Rig::new(Setup {
        conflated: Some(Lane::ZERO),
        ..Setup::default()
    });
    let slot = established(&mut rig);
    let link = rig.images.freshness(slot).unwrap().1.clone();
    let feeder = link.mailbox().unwrap();
    feeder.attach();
    lose_one(&mut rig);
    rig.until(true, |rig| {
        rig.agents.receiver.counters().barrier_posts >= 1
    });
    let request = feeder.pending().unwrap();
    rig.until(true, |rig| rig.agents.receiver.counters().gaps_sealed >= 1);
    let counters = rig.agents.receiver.counters();
    assert_eq!((counters.barrier_timeouts, counters.barrier_acks), (1, 0));
    assert_eq!(
        karyos_sys::freshness::TerminalCell::read(&link.terminal_words()),
        Some(karyos_sys::freshness::Terminal {
            start: request.start,
            end: request.end,
            reason: karyos_sys::freshness::TERMINAL_BARRIER_TIMEOUT,
        })
    );
}

/// #310 review, RC-6 per route: a faulted later route asks for its own
/// endpoint's reset, and the reset's new epoch clears the route.
#[test]
fn a_faulted_later_route_is_reset_and_cleared() {
    let setup = Setup {
        reliable: true,
        ..Setup::default()
    };
    let (mut rig, _b) = Rig::new(setup.again());
    let slot = established(&mut rig);
    let _b2 = rig.second_path(&setup, announce(setup.term_length), None);
    rig.until(true, |rig| rig.agents.receiver.role.live_paths(slot) == 2);
    rig.agents.receiver.role.fault_route(slot, 1);
    let resets = rig.endpoints.counters().resets;
    rig.until(true, |rig| rig.endpoints.counters().resets > resets);
    rig.until(true, |rig| !rig.agents.receiver.role.route_faulted(slot, 1));
}

/// #310 review: a path lost and bound again starts with a clean route; it
/// does not inherit the old route's fault.
#[test]
fn a_rebound_path_starts_with_a_clean_route() {
    use karyos_sys::log_buffer::AppendOptions;

    let setup = Setup {
        reliable: true,
        ..Setup::default()
    };
    let (mut rig, _b) = Rig::new(setup.again());
    let slot = established(&mut rig);
    let b2 = rig.second_path(&setup, announce(setup.term_length), None);
    rig.until(true, |rig| rig.agents.receiver.role.live_paths(slot) == 2);
    for i in 0..15u8 {
        rig.now += 1_000_000_000;
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[i; 100], AppendOptions::default())
            .unwrap();
        for _ in 0..5 {
            rig.round(true);
        }
        if rig.agents.receiver.role.live_paths(slot) == 1 {
            break;
        }
    }
    // The lost path's route is faulted; it asks no reset while unbound.
    rig.agents.receiver.role.fault_route(slot, 1);
    rig.reannounce(b2, announce(setup.term_length));
    rig.until(true, |rig| rig.agents.receiver.role.live_paths(slot) == 2);
    assert!(!rig.agents.receiver.role.route_faulted(slot, 1));
}

/// #312 review P2: the founding route already faulted when its
/// subscription goes. The later route is healthy, so NAKs still go on it,
/// and the released founding endpoint asks for no reset.
#[test]
fn a_faulted_founding_route_that_goes_leaves_the_later_path_naking() {
    use karyos_sys::log_buffer::AppendOptions;

    let setup = Setup {
        reliable: true,
        repairs: false,
        ..Setup::default()
    };
    let (mut rig, b) = Rig::new(setup.again());
    let slot = established(&mut rig);
    let _b2 = rig.second_path(&setup, announce(setup.term_length), None);
    rig.until(true, |rig| rig.agents.receiver.role.live_paths(slot) == 2);
    rig.agents.receiver.role.drop_data(&[1]);
    for i in 0..4u8 {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[i; 900], AppendOptions::default())
            .unwrap();
    }
    rig.until(true, |rig| rig.agents.receiver.counters().naks >= 1);
    for _ in 0..5 {
        rig.round(true);
    }
    // The founding route faults, then its subscription goes.
    let nak = rig.agents.receiver.role.posted_naks()[0];
    let resets = rig.agents.receiver.counters().reset_requests;
    rig.agents.receiver.role.fault_naks(slot, &nak);
    rig.unsubscribe(b);
    for _ in 0..3 {
        rig.round(true);
    }
    let before = rig.agents.receiver.counters();
    rig.until(true, |rig| {
        rig.agents.receiver.counters().nak_copies > before.nak_copies + 1
    });
    for _ in 0..20 {
        rig.round(true);
    }
    assert_eq!(rig.agents.receiver.counters().reset_requests, resets);
}

/// T10 (contract-traceability-phase-2.md, "Challenge lifecycle"): a SETUP
/// replayed through the liveness timeout neither keeps the image alive nor
/// blocks a rebind. With the publication silent (its guard closed), the
/// old ANNOUNCE delivered again every second is dropped and counted while
/// the image is bound, the image still retires at `image_liveness_timeout`,
/// the replays after that meet the quarantine (counted, no challenge), and
/// a new incarnation binds a new image through its own challenge.
#[test]
fn a_replayed_setup_neither_keeps_the_image_nor_blocks_a_rebind() {
    use std::sync::Arc;

    use karyos_sys::applied_epoch::AppliedEpoch;
    use karyos_sys::sync::Ordering;

    let word = Arc::new(karyos_client::HeapWords::zeroed(1));
    word.words()[0].store(karyos_sys::guard::created(), Ordering::Release);
    assert_eq!(karyos_sys::guard::reopen(&word.words()[0], 1), Ok(2));
    let (mut rig, b) = Rig::new(Setup {
        guard: Some(super::super::data::GuardSpec {
            word: Arc::clone(&word) as Arc<dyn karyos_client::SharedWords>,
            cell: Arc::new(AppliedEpoch::new()),
            epoch: 2,
            rate: None,
        }),
        ..Setup::default()
    });
    let slot = established(&mut rig);
    // The publication goes silent: no DATA, no heartbeat.
    let _ = karyos_sys::guard::close(&word.words()[0]).unwrap();
    for _ in 0..5 {
        rig.round(true);
    }
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    let challenges = rig.agents.receiver.role.session_counters().challenges;
    let dropped = rig.agents.receiver.role.session_counters().dropped;
    let replay = |rig: &mut Rig| {
        let receiver = &mut rig.agents.receiver;
        receiver.role.inject_control(
            &receiver.sessions,
            b,
            source,
            karyos_protocol::network::Control::SetupAnnounce(announce(65_536)),
            rig.now,
        );
    };
    // One replay a second, through the liveness timeout and past it.
    let mut replays = 0u64;
    let mut retired_after = None;
    for second in 1..=12u64 {
        rig.now += 1_000 * MS;
        replay(&mut rig);
        replays += 1;
        rig.round(true);
        if retired_after.is_none() && !rig.agents.receiver.role.has_image(slot) {
            retired_after = Some(second);
        }
    }
    let retired_after = retired_after.expect("the replays kept the image alive");
    assert!(retired_after <= 11, "retired after {retired_after} s");
    assert_eq!(rig.agents.receiver.counters().images_retired, 1);
    let sessions = rig.agents.receiver.role.session_counters();
    assert_eq!(sessions.dropped, dropped + replays, "every replay counted");
    assert_eq!(sessions.challenges, challenges, "no replay challenged");
    // A new incarnation binds a new image.
    let installed = rig
        .events
        .iter()
        .filter(|event| matches!(event, ImageEvent::Installed { .. }))
        .count();
    rig.reannounce(
        b,
        SetupAnnounce {
            identity: Identity {
                incarnation: 2,
                ..identity()
            },
            ..announce(65_536)
        },
    );
    rig.until(true, |rig| {
        rig.events
            .iter()
            .filter(|event| matches!(event, ImageEvent::Installed { .. }))
            .count()
            == installed + 1
    });
    assert_eq!(
        rig.agents.receiver.role.session_counters().challenges,
        challenges + 1
    );
}
