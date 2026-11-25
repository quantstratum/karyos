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
    /// Further changes to the agents' configuration.
    tune: Option<fn(&mut AgentConfig)>,
    /// Messages on each lane before the sender's reader subscribes: the
    /// image then joins above 0.
    before: u8,
    /// The subscription's configured receiver identity (MC-1).
    identity: Option<crate::membership::ReceiverIdentity>,
    /// The publication's configured roles (MC-1), built at the add.
    roles: Option<fn() -> crate::membership::PublicationRoles>,
    /// The subscription's conflated lane (conflated-network-images.md).
    conflated: Option<Lane>,
    /// Concurrent handles on each lane of the publication's log, in place
    /// of the exclusive publication.
    concurrent: Option<u8>,
    /// The channel's `path-skew` in ns, on both sides (karyos#1056).
    path_skew: Option<u64>,
    /// Whether the subscription has a unicast control endpoint S, from
    /// which its SOLICITs and multicast CHALLENGEs leave (ADR-0096).
    solicit: bool,
    /// Whether the publication is authenticated (ADR-0086): its
    /// `Outbound` requires a sealer before anything leaves.
    auth: bool,
    /// A remote guard's spec: the publication is admission-pending until
    /// the guard's word first reads open.
    remote_guard: Option<super::super::data::GuardSpec>,
}

impl Setup {
    /// The same setup without its guard, for a second rig or path.
    fn again(&self) -> Self {
        Self {
            guard: None,
            remote_guard: None,
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
            tune: None,
            before: 0,
            identity: None,
            roles: None,
            conflated: None,
            concurrent: None,
            path_skew: None,
            solicit: false,
            auth: false,
            remote_guard: None,
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
    /// The unicast control endpoint S, with `Setup::solicit`.
    solicit: Option<EndpointId>,
    /// The publication's log on A (64 KiB terms, whatever is announced).
    log: Option<super::super::data::testing::TestLog>,
    /// A second publisher's log, with [`Rig::second_publisher`].
    second: Option<super::super::data::testing::TestLog>,
    agents: Agents,
    links: Links,
    endpoints: Endpoints<OsSocket>,
    images: ImageTable,
    events: Vec<ImageEvent>,
    /// The network trace events the agents answered (P2.12 step 3).
    trace_events: Vec<crate::agents::AgentEvent<OsSocket>>,
    now: u64,
    /// The sender agent no longer runs: its publisher is silent, no DATA
    /// and no heartbeat of any kind.
    sender_stopped: bool,
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
        if let Some(tune) = setup.tune {
            tune(&mut config);
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
            solicit: None,
            log: None,
            second: None,
            agents,
            links,
            endpoints: Endpoints::new(&config),
            images: ImageTable::new(config.sessions.max_images, setup.template),
            events: Vec::new(),
            now: 0,
            trace_events: Vec::new(),
            sender_stopped: false,
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
        let solicit = setup.solicit.then(|| {
            rig.endpoints
                .open(&rig.links, loopback, OsSocket::new())
                .unwrap()
        });
        let endpoints = 2 + usize::from(control.is_some()) + usize::from(solicit.is_some());
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
        rig.solicit = solicit;
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
                solicit_from: solicit,
                register_at: None,
                path_skew: setup.path_skew,
            })
            .unwrap();
        // The log's terms stay small: a refused size is only announced.
        let (outbound, log) = match setup.concurrent {
            Some(publishers) => super::super::data::testing::outbound_concurrent(
                a,
                alias(),
                destination,
                term(65_536),
                2,
                setup.reliable,
                publishers,
            ),
            None => super::super::data::testing::outbound_joined(
                a,
                alias(),
                destination,
                term(65_536),
                2,
                setup.reliable,
                setup.before,
            ),
        };
        rig.log = Some(log);
        let mut outbound = outbound;
        outbound.set_path_skew(setup.path_skew);
        if setup.auth {
            outbound.require_auth().unwrap();
        }
        if let Some(spec) = setup.remote_guard.clone() {
            outbound.guard_remote(spec);
        }
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

    /// rp-w5b's two-path rig: publisher endpoints A and A2, subscriber
    /// endpoints B and B2, and one routed publication of two lanes over the
    /// paths A to B and A2 to B2, subscribed on both B and B2. Each path's
    /// SETUP side announces, challenges and answers on its own endpoints.
    /// Returns the rig, `[A, A2]` and `[B, B2]`.
    fn routed(setup: Setup) -> (Self, [EndpointId; 2], [EndpointId; 2]) {
        let mut config = AgentConfig::default();
        if let Some(tune) = setup.tune {
            tune(&mut config);
        }
        let (mut agents, links) = network_agents::<OsSocket>(config).unwrap();
        VIRTUAL_NOW.with(|now| now.set(0));
        agents.sender.role.set_clock(virtual_now);
        agents.receiver.role.set_clock(virtual_now);
        if !setup.repairs {
            agents.sender.role.ignore_naks();
        }
        let mut rig = Self {
            publisher: EndpointId(u32::MAX),
            control: None,
            solicit: None,
            log: None,
            second: None,
            agents,
            links,
            endpoints: Endpoints::new(&config),
            images: ImageTable::new(config.sessions.max_images, setup.template),
            events: Vec::new(),
            now: 0,
            trace_events: Vec::new(),
            sender_stopped: false,
        };
        let loopback = SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
        let mut open = || {
            rig.endpoints
                .open(&rig.links, loopback, OsSocket::new())
                .unwrap()
        };
        let (a, a2, b, b2) = (open(), open(), open(), open());
        let mut opened = 0;
        for _ in 0..100 {
            rig.agents.do_work(0).unwrap();
            rig.endpoints.poll(
                &rig.links,
                rig.now,
                |event| opened += usize::from(matches!(event, EndpointEvent::Opened(_))),
                |_| {},
            );
            if opened == 4 {
                break;
            }
        }
        assert_eq!(opened, 4);
        rig.publisher = a;
        for publisher in [a, a2] {
            rig.links
                .receiver
                .post(|reply| AgentCommand::AddPublishedAlias {
                    reply,
                    endpoint: publisher,
                    alias: alias(),
                })
                .unwrap();
        }
        for subscriber in [b, b2] {
            rig.links
                .receiver
                .post(|reply| AgentCommand::AddSubscription {
                    reply,
                    endpoint: subscriber,
                    stream_id: alias().stream_id,
                    max_term_length: setup.max_term_length,
                    reliable: setup.reliable,
                    multicast: false,
                    control_group: None,
                    identity: setup.identity,
                    conflated: setup.conflated,
                    solicit_from: None,
                    register_at: None,
                    path_skew: setup.path_skew,
                })
                .unwrap();
        }
        let routes = [
            (a, rig.endpoints.local_address(b).unwrap()),
            (a2, rig.endpoints.local_address(b2).unwrap()),
        ];
        let (outbound, log) = super::super::data::testing::outbound_routed(
            &routes,
            alias(),
            term(65_536),
            2,
            setup.reliable,
        );
        rig.log = Some(log);
        let mut outbound = outbound;
        outbound.set_path_skew(setup.path_skew);
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
        (rig, [a, a2], [b, b2])
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
        if self.sender_stopped {
            self.agents.receiver.do_work(self.now).unwrap();
        } else {
            self.agents.do_work(self.now).unwrap();
        }
        let trace_events = &mut self.trace_events;
        self.endpoints.poll(
            &self.links,
            self.now,
            |_| {},
            |event| {
                if matches!(
                    event,
                    crate::agents::AgentEvent::NetworkTraceSet { .. }
                        | crate::agents::AgentEvent::NetworkJournalOpened { .. }
                        | crate::agents::AgentEvent::NetworkJournalRefused { .. }
                        | crate::agents::AgentEvent::NetworkJournalClosed { .. }
                ) {
                    trace_events.push(event);
                }
            },
        );
        if serve {
            let events = &mut self.events;
            self.images
                .poll(&self.links.sessions, &mut LaneSource::heap(), |image| {
                    events.push(image);
                });
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
        // Its own control group (karyos#1064), sending to itself as the
        // first path's does.
        let control_group = setup.control_group.then(|| {
            let control = self
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
            (control, self.endpoints.local_address(control).unwrap())
        });
        self.links
            .receiver
            .post(|reply| AgentCommand::AddSubscription {
                reply,
                endpoint: b2,
                stream_id: alias().stream_id,
                max_term_length: setup.max_term_length,
                reliable: setup.reliable,
                multicast: false,
                control_group,
                identity: setup.identity,
                conflated: setup.conflated,
                solicit_from: None,
                register_at: None,
                path_skew: setup.path_skew,
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
            source,
            identity: installed,
            alias: arrived,
        },
    ] = rig.events.as_slice()
    else {
        panic!("{:?}", rig.events);
    };
    assert_eq!((*endpoint, *installed, *arrived), (b, identity(), alias()));
    // The source is the publisher's endpoint, as the binding names it.
    assert_eq!(Some(*source), rig.endpoints.local_address(rig.publisher));
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
        rig.images.handle(
            &rig.links.sessions,
            &mut LaneSource::heap(),
            event,
            |image| {
                events.push(image);
            },
        );
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

/// The endpoint each CHALLENGE the receiver sent left from.
fn challenge_endpoints(rig: &Rig) -> Vec<EndpointId> {
    rig.agents
        .receiver
        .role
        .posted_challenges()
        .iter()
        .filter_map(|(endpoint, control)| {
            matches!(control, karyos_protocol::network::Control::Challenge(_)).then_some(*endpoint)
        })
        .collect()
}

/// ADR-0096 decision 1 (karyos#1067): a multicast key's CHALLENGE leaves
/// from its unicast control endpoint S, not from its group endpoint B, and
/// still binds: the answer comes to B, and the SM leaves from B.
#[test]
fn a_multicast_challenge_leaves_from_the_control_endpoint() {
    let (mut rig, b) = Rig::new(Setup {
        multicast: true,
        solicit: true,
        ..Setup::default()
    });
    let _slot = established(&mut rig);
    let solicit = rig.solicit.unwrap();
    assert_ne!(solicit, b);
    let sent = challenge_endpoints(&rig);
    assert!(!sent.is_empty());
    assert!(sent.iter().all(|endpoint| *endpoint == solicit), "{sent:?}");
    assert_eq!(
        rig.agents.receiver.role.counters().challenges_from_arrival,
        0
    );
}

/// ADR-0096 decision 1, fallback: a multicast key with no control endpoint
/// challenges from its arrival endpoint, counted; a unicast key always
/// does, uncounted.
#[test]
fn a_challenge_without_a_control_endpoint_leaves_from_its_arrival_endpoint() {
    for multicast in [true, false] {
        let (mut rig, b) = Rig::new(Setup {
            multicast,
            ..Setup::default()
        });
        let _slot = established(&mut rig);
        let sent = challenge_endpoints(&rig);
        assert!(!sent.is_empty());
        assert!(sent.iter().all(|endpoint| *endpoint == b), "{sent:?}");
        let counted = rig.agents.receiver.role.counters().challenges_from_arrival;
        let expected = if multicast {
            u64::try_from(sent.len()).unwrap()
        } else {
            0
        };
        assert_eq!(counted, expected, "multicast {multicast}");
        // An ANNOUNCE from an unanswerable source gets no CHALLENGE, so
        // nothing is counted as sent from the arrival socket.
        let unanswerable = rig.agents.receiver.counters().unanswerable_source;
        let receiver = &mut rig.agents.receiver;
        receiver.role.inject_control(
            &receiver.sessions,
            b,
            "239.1.1.1:4000".parse().unwrap(),
            karyos_protocol::network::Control::SetupAnnounce(announce(65_536)),
            rig.now,
        );
        let counters = rig.agents.receiver.counters();
        assert_eq!(
            counters.unanswerable_source,
            unanswerable + 1,
            "{counters:?}"
        );
        assert_eq!(counters.challenges_from_arrival, expected);
    }
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

/// T7 (contract-traceability-phase-2.md, "Required sender stall", the
/// trusted part; SPEC §13): the network sender is a required participant
/// of its log, with its `L_send` reservation. It stalls in the second half
/// of term 0, so the publisher's head crosses into term 1 and term 0 is
/// a candidate for reclamation. While the sender stops consuming (its
/// agent does not run), its registered position stays, the publisher meets
/// back pressure within the limit that position allows, and the retention
/// floor never passes it, however long the conductor runs on: nothing the
/// sender has not sent is reclaimed. Once the sender runs again, the
/// remote subscriber reads every message, in order and once.
#[test]
fn a_stalled_network_sender_holds_its_log_and_loses_nothing() {
    use karyos_sys::log_buffer::{AppendOptions, AppendOutcome, PollOutcome, Role};

    let (mut rig, _b) = Rig::new(Setup {
        reliable: true,
        ..Setup::default()
    });
    let slot = established(&mut rig);
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    // The sender's reader is the publication's one subscriber cell,
    // registered as occupant 1.
    let sender_position = |rig: &Rig| {
        rig.log.as_ref().unwrap().conductors[0]
            .subscribers()
            .find(|cell| cell.registration == 1)
            .unwrap()
            .position
    };
    let message = |n: u32| {
        let mut data = vec![0u8; 992];
        data[..4].copy_from_slice(&n.to_le_bytes());
        data
    };
    let mut received = Vec::new();
    let mut out = vec![0u8; 2048];
    let mut read = |subscriber: &mut karyos_sys::log_buffer::Subscription<_>,
                    received: &mut Vec<u32>| {
        while let PollOutcome::Message { length, .. } = subscriber.poll(&mut out).unwrap() {
            subscriber.acknowledge();
            assert_eq!(length, 992);
            received.push(u32::from_le_bytes(out[..4].try_into().unwrap()));
        }
    };
    // Forty messages flow first: the sender then stands in the second
    // half of term 0 (992 bytes after a 32-byte header, 1024 a message).
    let flowed = 40u32;
    let mut appended = 0u32;
    for _ in 0..2000 {
        // Paced: the publisher takes them as the limit allows.
        if appended < flowed {
            let log = rig.log.as_mut().unwrap();
            if let AppendOutcome::Appended { .. } = log.publications[0]
                .append(&message(appended), AppendOptions::default())
                .unwrap()
            {
                appended += 1;
            }
        }
        rig.round(true);
        read(&mut subscriber, &mut received);
        if received.len() == 40 {
            break;
        }
    }
    assert_eq!(received, (0..flowed).collect::<Vec<_>>());
    // The receiver's status messages move the sender's registered position
    // past them.
    rig.until(true, |rig| sender_position(rig) == u64::from(flowed) * 1024);
    // The sender stalls: only the conductor and the receiver run.
    let stalled_at = sender_position(&rig);
    // The limit the stalled position allows, once a duty cycle published it.
    let log = rig.log.as_mut().unwrap();
    let _ = log.conductors[0].duty_cycle().unwrap();
    let limit = log.conductors[0].limit();
    let held = |rig: &mut Rig| {
        let log = rig.log.as_mut().unwrap();
        for conductor in &mut log.conductors {
            let _ = conductor.duty_cycle().unwrap();
        }
        rig.now += MS;
        rig.agents.receiver.do_work(rig.now).unwrap();
        let conductor = &rig.log.as_ref().unwrap().conductors[0];
        assert_eq!(sender_position(rig), stalled_at, "a stalled sender moved");
        assert_eq!(conductor.limit(), limit, "the limit moved during the stall");
        assert!(
            conductor.floor() <= stalled_at,
            "the floor {} passed the stalled sender at {stalled_at}",
            conductor.floor()
        );
    };
    let mut pressed = false;
    for _ in 0..2000 {
        let log = rig.log.as_mut().unwrap();
        match log.publications[0]
            .append(&message(appended), AppendOptions::default())
            .unwrap()
        {
            AppendOutcome::Appended { .. } => appended += 1,
            AppendOutcome::BackPressured => {
                pressed = true;
                break;
            }
            AppendOutcome::AdminAction => {}
            other => panic!("{other:?}"),
        }
        held(&mut rig);
    }
    assert!(pressed, "never back pressured");
    // Pressed at the limit the stalled position allows, in term 1: term 0
    // is behind the head, and only the stalled sender keeps it.
    let head = rig.log.as_ref().unwrap().conductors[0].head().unwrap();
    assert!(
        stalled_at < head && head <= limit,
        "{stalled_at} {head} {limit}"
    );
    assert!(head > 65_536, "the head {head} never left term 0");
    // A long stall: the conductor runs on and reclaims nothing unsent.
    for _ in 0..500 {
        held(&mut rig);
    }
    // The sender runs again: every message arrives, in order, once.
    for _ in 0..2000 {
        rig.round(true);
        read(&mut subscriber, &mut received);
        if received.len() == usize::try_from(appended).unwrap() {
            break;
        }
    }
    assert_eq!(received, (0..appended).collect::<Vec<_>>());
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
    // The sender's own idle heartbeats (SPEC §6) and PATH_HBs (karyos#859)
    // wait past the test, so only the injected heartbeats count.
    let (mut rig, b) = Rig::new(Setup {
        tune: Some(|config| {
            config.image_liveness_timeout = 100_000_000_000;
            config.idle_image_timeout = 100_000_000_000;
            config.sender_heartbeat_interval = 50_000_000_000;
            config.path_heartbeat_interval = 50_000_000_000;
        }),
        ..Setup::default()
    });
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

    // The idle sender's stationary heartbeats keep its image only until
    // `idle_image_timeout`, here as short as allowed.
    let (mut rig, _b) = Rig::new(Setup {
        alias_quarantine: Some(1),
        tune: Some(|config| config.idle_image_timeout = config.image_liveness_timeout),
        ..Setup::default()
    });
    let first = established(&mut rig);
    // Idle in steps: the image's SMs keep the binding fresh, and its
    // PATH_HBs its path (karyos#859), until the image retires after
    // `idle_image_timeout` and then `image_liveness_timeout`.
    let mut retired = false;
    for _ in 0..400 {
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
    // The idle sender's heartbeats are unbound DATA too, so they may
    // solicit before the message does; every solicit is answered.
    assert!(sessions.solicits >= 1, "{sessions:?}");
    assert_eq!(sessions.solicits, sessions.solicits_answered);
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
            empty_since: None,
            rate: None,
            reserve: None,
            policy: None,
            frontier: Default::default(),
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

/// Polls `subscription` until it returns something other than `Pending`,
/// for at most 200 rounds of `rig`; a message is acknowledged.
fn next_outcome(
    rig: &mut Rig,
    subscription: &mut karyos_sys::log_buffer::Subscription<std::sync::Arc<LogBuffer>>,
) -> karyos_sys::log_buffer::PollOutcome {
    use karyos_sys::log_buffer::PollOutcome;

    let mut out = vec![0u8; 65_536];
    for _ in 0..200 {
        match subscription.poll(&mut out).unwrap() {
            PollOutcome::Pending => rig.round(true),
            outcome => {
                if matches!(outcome, PollOutcome::Message { .. }) {
                    subscription.acknowledge();
                }
                return outcome;
            }
        }
    }
    panic!("nothing delivered");
}

/// T2 (contract-traceability-phase-2.md, "Aborts over the network"): a
/// writer's claim aborted at its commit deadline on a reliable channel,
/// read by a subscriber of the remote image. With `lose`, the ABORTED
/// datagram is lost: the receiver NAKs the hole, which is the aborted
/// extent exactly, and the sender's repair resends the aborted record.
/// Either way the subscriber is told the aborted range, then reads the
/// messages after it, and no NAK names a byte past the extent (without
/// `lose`, none at all).
fn aborted_over_the_network(lose: bool) {
    use karyos_sys::log_buffer::{
        AppendOptions, ClaimDeadline, ClaimOutcome, DEFAULT_CLAIM_DEADLINE, PollOutcome, Role,
    };

    // 900 bytes after a 32-byte header, at 32-byte strides.
    const STRIDE: u64 = 960;

    let (mut rig, _b) = Rig::new(Setup {
        reliable: true,
        ..Setup::default()
    });
    let slot = established(&mut rig);
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    let log = rig.log.as_mut().unwrap();
    let _ = log.publications[0]
        .append(&[1; 900], AppendOptions::default())
        .unwrap();
    assert!(matches!(
        next_outcome(&mut rig, &mut subscriber),
        PollOutcome::Message { length: 900, .. }
    ));
    // The writer claims a block and never commits it.
    let log = rig.log.as_mut().unwrap();
    let ClaimOutcome::Claimed(claim) = log.publications[0]
        .try_claim(1000, AppendOptions::default())
        .unwrap()
    else {
        panic!("not claimed");
    };
    core::mem::forget(claim);
    // The conductor dates the claim, then aborts it at its deadline.
    let conductor = &mut log.conductors[0];
    assert_eq!(
        conductor.abort_expired_claims(rig.now).unwrap(),
        ClaimDeadline::Waiting
    );
    let ClaimDeadline::Aborted {
        position: start,
        extent,
    } = conductor
        .abort_expired_claims(rig.now + DEFAULT_CLAIM_DEADLINE + 1)
        .unwrap()
    else {
        panic!("not aborted at the deadline");
    };
    let end = start + u64::from(extent);
    // The sender's next DATA datagram is the aborted record, alone.
    let before = rig.agents.receiver.role.posted_naks().len();
    if lose {
        rig.agents.receiver.role.drop_data(&[0]);
    }
    for _ in 0..5 {
        rig.round(true);
    }
    // Messages after it reveal the hole.
    let log = rig.log.as_mut().unwrap();
    for i in 2..4u8 {
        let _ = log.publications[0]
            .append(&[i; 900], AppendOptions::default())
            .unwrap();
    }
    assert_eq!(
        next_outcome(&mut rig, &mut subscriber),
        PollOutcome::Aborted {
            position: start,
            extent
        }
    );
    for (i, at) in [(2u8, end), (3, end + STRIDE)] {
        let PollOutcome::Message {
            position, length, ..
        } = next_outcome(&mut rig, &mut subscriber)
        else {
            panic!("message {i} not delivered");
        };
        assert_eq!((position, length), (at, 900));
    }
    for _ in 0..50 {
        rig.round(true);
    }
    let posted = &rig.agents.receiver.role.posted_naks()[before..];
    if !lose {
        assert!(posted.is_empty(), "{posted:?}");
        return;
    }
    // The hole is the aborted extent, whole, and every NAK (a retry while
    // the repair is in flight) names exactly it: none past its end.
    assert!(!posted.is_empty());
    assert_eq!(
        (posted[0].range.start, posted[0].range.length),
        (start, extent)
    );
    assert_eq!(start + u64::from(extent), end);
    for nak in posted {
        assert_eq!(
            nak.range, posted[0].range,
            "a NAK of another range: {nak:?}"
        );
    }
    let counters = rig.agents.receiver.role.loss_counters(slot).unwrap();
    assert_eq!(
        (counters.detected, counters.repaired),
        (1, 1),
        "{counters:?}"
    );
    assert!(rig.agents.sender.counters().repairs >= 1);
}

#[test]
fn a_lost_aborted_record_is_repaired_and_never_naked_past() {
    aborted_over_the_network(true);
}

#[test]
fn an_aborted_record_reaches_the_subscriber_of_the_image() {
    aborted_over_the_network(false);
}

/// One frame of the rig's publication, lane 0, at stream `position`, as a
/// faulty peer would send it: `word0`, the header, then `payload`.
fn peer_frame(
    word0: karyos_protocol::frame::Word0,
    position: u64,
    reserved_value: i64,
    payload: &[u8],
) -> Vec<u8> {
    // The rig publication's terms, as `Rig::new` announces them.
    let params = term(65_536);
    let term_length = u64::from(params.term_length);
    let term_id = params
        .initial_term_id
        .cast_unsigned()
        .wrapping_add(u32::try_from(position / term_length).unwrap());
    let term_offset = u32::try_from(position % term_length).unwrap();
    let mut bytes = Vec::with_capacity(32 + payload.len());
    bytes.extend_from_slice(&word0.pack().to_le_bytes());
    bytes.extend_from_slice(&term_offset.to_le_bytes());
    bytes.extend_from_slice(&alias().session_id.to_le_bytes());
    bytes.extend_from_slice(&alias().stream_id.to_le_bytes());
    bytes.extend_from_slice(&term_id.to_le_bytes());
    bytes.extend_from_slice(&reserved_value.to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

/// T3 (contract-traceability-phase-2.md, "Fragmented commit and abort
/// (network)"; SPEC §13 and the assembler rule of §5): a faulty peer
/// sends a BEGIN, an ABORTED record and a stray END, then a whole message,
/// each in its own DATA datagram. The subscriber of the image gets the
/// partial message discarded as `Interrupted` (the assembler's protocol
/// error, counted as discarded partial bytes), the aborted extent, the
/// stray END dropped as an `Orphan`, and then the next message, whole.
#[test]
fn an_injected_begin_aborted_end_is_discarded_and_the_next_frame_delivered() {
    use karyos_protocol::frame::{Flags, FrameType, Word0};
    use karyos_sys::log_buffer::{AppendOptions, PollOutcome, Role, SkipReason};

    let (mut rig, b) = Rig::new(Setup::default());
    let slot = established(&mut rig);
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    let log = rig.log.as_mut().unwrap();
    let _ = log.publications[0]
        .append(&[1; 900], AppendOptions::default())
        .unwrap();
    assert!(matches!(
        next_outcome(&mut rig, &mut subscriber),
        PollOutcome::Message {
            position: 0,
            length: 900,
            ..
        }
    ));
    // 900 bytes after a 32-byte header, at 32-byte strides.
    let at = 960;
    let fragment = |begin: bool, end: bool| {
        Word0::new(
            64,
            Flags::new(begin, end, false, false, Lane::ZERO),
            FrameType::Data,
        )
    };
    let aborted = Word0::new(32, Flags::NONE, FrameType::Aborted);
    let datagrams = [
        peer_frame(fragment(true, false), at, 0, &[2; 32]),
        peer_frame(aborted, at + 64, 64, &[]),
        peer_frame(fragment(false, true), at + 128, 0, &[3; 32]),
        peer_frame(fragment(true, true), at + 192, 0, &[4; 32]),
    ];
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    for bytes in &datagrams {
        let receiver = &mut rig.agents.receiver;
        receiver
            .role
            .inject_data(&receiver.sessions, b, source, alias(), bytes, rig.now);
    }
    let skipped = |position: u64, reason: SkipReason| PollOutcome::Skipped {
        position,
        extent: 64,
        reason,
    };
    assert_eq!(
        next_outcome(&mut rig, &mut subscriber),
        skipped(at, SkipReason::Interrupted)
    );
    assert_eq!(subscriber.loss_counters().discarded_partial_bytes, 64);
    assert_eq!(
        next_outcome(&mut rig, &mut subscriber),
        PollOutcome::Aborted {
            position: at + 64,
            extent: 64
        }
    );
    assert_eq!(
        next_outcome(&mut rig, &mut subscriber),
        skipped(at + 128, SkipReason::Orphan)
    );
    let mut out = vec![0u8; 64];
    let PollOutcome::Message {
        position, length, ..
    } = subscriber.poll(&mut out).unwrap()
    else {
        panic!("the next frame is not delivered");
    };
    assert_eq!((position, length), (at + 192, 32));
    assert_eq!(&out[..32], &[4; 32]);
    // The stray END is dropped, not counted as a partial.
    assert_eq!(subscriber.loss_counters().discarded_partial_bytes, 64);
}

/// T3, the writers' half (contract-traceability-phase-2.md, "Fragmented
/// commit and abort (network)"; SPEC §13): two concurrent writers of
/// fragmented messages on a reliable channel, the first stopped in the
/// middle of its copy, after its first fragment. The second commits behind
/// it, and nothing reaches the remote subscriber while the first block is
/// open. The commit deadline aborts the first block: the subscriber of the
/// image gets one aborted extent, then the second writer's message whole,
/// and the stopped writer learns that its offer was aborted.
#[test]
fn a_fragmented_writer_aborted_mid_copy_reaches_a_remote_reader_as_one_extent() {
    use karyos_sys::log_buffer::{
        AppendOptions, ConcurrentOfferOutcome, DEFAULT_CLAIM_DEADLINE, PollOutcome, Role,
    };

    let (mut rig, _b) = Rig::new(Setup {
        reliable: true,
        concurrent: Some(2),
        ..Setup::default()
    });
    let slot = established(&mut rig);
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    let log = rig.log.as_mut().unwrap();
    let mut handles = std::mem::take(&mut log.concurrent[0]);
    let mut second = handles.pop().unwrap();
    let mut first = handles.pop().unwrap();
    // Both fragmented: more than one 1376-byte fragment each.
    let tagged =
        |tag: u8, length: usize| -> Vec<u8> { (0..length).map(|i| tag ^ (i as u8)).collect() };
    let first_data = tagged(1, 4000);
    let second_data = tagged(2, 3000);
    /// Lets the stopped writer go on when dropped, so a failed assertion
    /// fails the test instead of leaving the writer waiting.
    struct Release(std::sync::mpsc::SyncSender<()>);
    impl Drop for Release {
        fn drop(&mut self) {
            let _ = self.0.try_send(());
        }
    }

    let (paused_tx, paused_rx) = std::sync::mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel::<()>(1);
    std::thread::scope(|scope| {
        let writer = scope.spawn(move || {
            first
                .offer_pausing_after_fragment(&first_data, AppendOptions::default(), 0, &mut || {
                    paused_tx.send(()).unwrap();
                    resume_rx.recv().unwrap();
                })
                .unwrap()
        });
        // The first writer has copied one fragment of its block.
        paused_rx.recv().unwrap();
        let release = Release(resume_tx);
        let ConcurrentOfferOutcome::Appended { position: behind } = second
            .offer(&second_data, AppendOptions::default())
            .unwrap()
        else {
            panic!("the second writer did not commit");
        };
        let mut out = vec![0u8; 8192];
        for _ in 0..50 {
            rig.round(true);
            assert_eq!(
                subscriber.poll(&mut out).unwrap(),
                PollOutcome::Pending,
                "a message got past the open block"
            );
        }
        // The deadline aborts the first block.
        let now = rig.now;
        let conductor = &mut rig.log.as_mut().unwrap().conductors[0];
        assert!(conductor.service_deadlines(&mut || now).unwrap().waiting);
        let report = conductor
            .service_deadlines(&mut || now + DEFAULT_CLAIM_DEADLINE + 1)
            .unwrap();
        assert_eq!(
            (report.aborted, report.aborted_bytes),
            (1, behind),
            "{report:?}"
        );
        assert_eq!(
            next_outcome(&mut rig, &mut subscriber),
            PollOutcome::Aborted {
                position: 0,
                extent: u32::try_from(behind).unwrap(),
            }
        );
        let PollOutcome::Message {
            position, length, ..
        } = subscriber.poll(&mut out).unwrap()
        else {
            panic!("the second message is not delivered");
        };
        assert_eq!((position, length), (behind, 3000));
        assert_eq!(&out[..3000], &second_data[..]);
        drop(release);
        assert_eq!(
            writer.join().unwrap(),
            ConcurrentOfferOutcome::Aborted { position: 0 }
        );
    });
}

/// Plan item 8 (contract-traceability-phase-2.md, "Aborts over the
/// network"; SPEC §13): T2 for a concurrent writer. Of two concurrent
/// writers on a reliable channel, the first stops in the middle of its
/// copy and the second commits behind it; the commit deadline aborts the
/// first block, and the ABORTED datagram is lost. The receiver NAKs the
/// hole, the sender's repair resends the aborted record, and the subscriber
/// of the image is told the aborted range, then reads the second writer's
/// message whole; every NAK names exactly the aborted extent, none past it.
#[test]
fn a_concurrent_writers_lost_aborted_record_is_repaired_and_never_naked_past() {
    use karyos_sys::log_buffer::{
        AppendOptions, ConcurrentOfferOutcome, DEFAULT_CLAIM_DEADLINE, PollOutcome, Role,
    };

    let (mut rig, _b) = Rig::new(Setup {
        reliable: true,
        concurrent: Some(2),
        ..Setup::default()
    });
    let slot = established(&mut rig);
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    let log = rig.log.as_mut().unwrap();
    let mut handles = std::mem::take(&mut log.concurrent[0]);
    let mut second = handles.pop().unwrap();
    let mut first = handles.pop().unwrap();
    let tagged =
        |tag: u8, length: usize| -> Vec<u8> { (0..length).map(|i| tag ^ (i as u8)).collect() };
    let first_data = tagged(1, 4000);
    let second_data = tagged(2, 900);
    /// Lets the stopped writer go on when dropped, so a failed assertion
    /// fails the test instead of leaving the writer waiting.
    struct Release(std::sync::mpsc::SyncSender<()>);
    impl Drop for Release {
        fn drop(&mut self) {
            let _ = self.0.try_send(());
        }
    }

    let (paused_tx, paused_rx) = std::sync::mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel::<()>(1);
    std::thread::scope(|scope| {
        let writer = scope.spawn(move || {
            first
                .offer_pausing_after_fragment(&first_data, AppendOptions::default(), 0, &mut || {
                    paused_tx.send(()).unwrap();
                    resume_rx.recv().unwrap();
                })
                .unwrap()
        });
        paused_rx.recv().unwrap();
        let release = Release(resume_tx);
        let ConcurrentOfferOutcome::Appended { position: behind } = second
            .offer(&second_data, AppendOptions::default())
            .unwrap()
        else {
            panic!("the second writer did not commit");
        };
        for _ in 0..20 {
            rig.round(true);
        }
        // The deadline aborts the first block; its ABORTED datagram, the
        // sender's next DATA datagram, is lost.
        let before = rig.agents.receiver.role.posted_naks().len();
        rig.agents.receiver.role.drop_data(&[0]);
        let now = rig.now;
        let conductor = &mut rig.log.as_mut().unwrap().conductors[0];
        assert!(conductor.service_deadlines(&mut || now).unwrap().waiting);
        let report = conductor
            .service_deadlines(&mut || now + DEFAULT_CLAIM_DEADLINE + 1)
            .unwrap();
        assert_eq!(
            (report.aborted, report.aborted_bytes),
            (1, behind),
            "{report:?}"
        );
        let extent = u32::try_from(behind).unwrap();
        assert_eq!(
            next_outcome(&mut rig, &mut subscriber),
            PollOutcome::Aborted {
                position: 0,
                extent,
            }
        );
        let mut out = vec![0u8; 8192];
        let PollOutcome::Message {
            position, length, ..
        } = (loop {
            match subscriber.poll(&mut out).unwrap() {
                PollOutcome::Pending => rig.round(true),
                outcome => break outcome,
            }
        })
        else {
            panic!("the second message is not delivered");
        };
        assert_eq!((position, length), (behind, 900));
        assert_eq!(&out[..900], &second_data[..]);
        drop(release);
        assert_eq!(
            writer.join().unwrap(),
            ConcurrentOfferOutcome::Aborted { position: 0 }
        );
        for _ in 0..50 {
            rig.round(true);
        }
        let posted = &rig.agents.receiver.role.posted_naks()[before..];
        assert!(
            !posted.is_empty(),
            "the lost ABORTED record was never NAKed"
        );
        for nak in posted {
            assert_eq!(
                (nak.range.start, nak.range.length),
                (0, extent),
                "a NAK of another range than the aborted extent: {nak:?}"
            );
        }
        let counters = rig.agents.receiver.role.loss_counters(slot).unwrap();
        assert_eq!(
            (counters.detected, counters.repaired),
            (1, 1),
            "{counters:?}"
        );
        assert!(rig.agents.sender.counters().repairs >= 1);
    });
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

/// karyos#1064: on a two-path image whose paths each have a control group,
/// every NAK is copied once to each path's group, and the receiver's own
/// copies come back on both groups and are recognised as its own (an
/// unbound group NAK would mean the later path's group was not bound).
#[test]
fn each_paths_control_group_gets_the_nak_copy() {
    use karyos_sys::log_buffer::AppendOptions;

    let setup = Setup {
        reliable: true,
        repairs: false,
        control_group: true,
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
    rig.until(true, |rig| rig.agents.receiver.counters().naks >= 1);
    rig.until(true, |rig| {
        rig.agents.receiver.counters().group_nak_own >= 2
    });
    let counters = rig.agents.receiver.counters();
    assert!(counters.group_nak_copies >= 2, "{counters:?}");
    assert_eq!(counters.group_nak_unbound, 0, "{counters:?}");
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

/// rp-w7b, ADR-0018's case end to end: one path fails (the later path,
/// live and silent) while the other keeps delivering duplicates of earlier
/// frames, every DATA datagram twice. The duplicates move nothing: the gap
/// is NAKed at the skew deadline fixed at detection, one window (1 ms, one
/// rig round) after it, not later.
#[test]
fn duplicates_on_one_path_do_not_delay_the_skew_deadline() {
    let (wait, _) = skew_wait_under_duplicates(Setup {
        reliable: true,
        repairs: false,
        ..Setup::default()
    });
    let window = crate::paths::PathConfig::default().path_skew_window;
    assert!(
        (window..=window + MS).contains(&wait),
        "NAK {wait} ns after detection, window {window} ns"
    );
}

/// ADR-0018's case on multicast: the NAK fires at the skew deadline plus
/// the cycle's NAK delay (here its bound, `rtt * nak_delay_scale / 16`, in
/// place of the random draw).
#[test]
fn a_multicast_nak_fires_at_the_skew_deadline_plus_its_delay() {
    let (wait, delay) = skew_wait_under_duplicates(Setup {
        reliable: true,
        repairs: false,
        multicast: true,
        nak_delay: Some(u64::MAX),
        ..Setup::default()
    });
    let delay = delay.expect("the cycle drew its bound");
    assert!(delay > 0);
    let window = crate::paths::PathConfig::default().path_skew_window;
    assert!(
        (window + delay..=window + delay + MS).contains(&wait),
        "NAK {wait} ns after detection, window {window} ns, delay {delay} ns"
    );
}

/// karyos#1056: a channel's `path-skew` replaces the receiver's
/// `path_skew_window` for its images: the gap is NAKed one channel window
/// (5 ms here, five times the driver's) after detection, not one driver
/// window.
#[test]
fn a_channels_path_skew_sets_the_skew_deadline() {
    let window = 5 * MS;
    assert_ne!(window, crate::paths::PathConfig::default().path_skew_window);
    let (wait, _) = skew_wait_under_duplicates(Setup {
        reliable: true,
        repairs: false,
        path_skew: Some(window),
        ..Setup::default()
    });
    assert!(
        (window..=window + MS).contains(&wait),
        "NAK {wait} ns after detection, window {window} ns"
    );
}

/// The ns from a gap's detection to its first NAK, while the later path
/// is live and silent and the founding path delivers every DATA datagram
/// twice; and, on multicast, the last NAK delay bound drawn.
fn skew_wait_under_duplicates(setup: Setup) -> (u64, Option<u64>) {
    use karyos_sys::log_buffer::AppendOptions;

    let (mut rig, _b) = Rig::new(setup.again());
    let slot = established(&mut rig);
    let _b2 = rig.second_path(&setup, announce(setup.term_length), None);
    rig.until(true, |rig| rig.agents.receiver.role.live_paths(slot) == 2);
    rig.agents.receiver.role.drop_data(&[1]);
    rig.agents.receiver.role.repeat_data_from(0);
    for i in 0..8u8 {
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
    assert_eq!(rig.agents.receiver.counters().naks, 0, "within the window");
    rig.until(true, |rig| rig.agents.receiver.counters().naks >= 1);
    let wait = rig.now - detected;
    assert_eq!(rig.agents.receiver.role.live_paths(slot), 2);
    let counts = rig.agents.receiver.role.path_counts(slot, 0).unwrap();
    assert!(
        counts.stale + counts.duplicates > 0,
        "the founding path delivered duplicates: {counts:?}"
    );
    (wait, rig.agents.receiver.role.last_nak_delay_bound())
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
/// and the image follows image liveness: it retires. The publisher stops
/// (its sender no longer runs): one that still sends rebinds a lost path
/// through a SOLICIT (plan 164; see the test after this one).
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
    rig.sender_stopped = true;
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

/// karyos#859: an idle publication on one path sends a PATH_HB each
/// `path_heartbeat_interval`, so its path stays live through three
/// `path_liveness_timeout`s (30 s) with no SOLICIT. Without it the path
/// was lost every 10 s and bound again by SOLICIT.
#[test]
fn an_idle_single_path_publication_keeps_its_path() {
    let (mut rig, _b) = Rig::new(Setup {
        reliable: true,
        ..Setup::default()
    });
    let slot = established(&mut rig);
    let solicits = rig.agents.receiver.role.session_counters().solicits;
    for second in 1..=30u64 {
        for _ in 0..10 {
            rig.now += 100 * MS;
            rig.round(true);
        }
        assert_eq!(
            rig.agents.receiver.role.live_paths(slot),
            1,
            "path lost at {second} s"
        );
    }
    assert_eq!(
        rig.agents.receiver.role.session_counters().solicits,
        solicits
    );
    assert!(rig.agents.sender.role.counters().path_heartbeats_sent >= 290);
    assert!(rig.agents.receiver.role.counters().path_heartbeats >= 290);
}

/// karyos#859: a path with DATA in every `path_heartbeat_interval` sends
/// no PATH_HB (RP-3): the DATA is its evidence.
#[test]
fn a_single_path_publication_with_data_sends_no_path_heartbeat() {
    use karyos_sys::log_buffer::AppendOptions;

    let (mut rig, _b) = Rig::new(Setup {
        reliable: true,
        ..Setup::default()
    });
    let _slot = established(&mut rig);
    let before = rig.agents.sender.role.counters().path_heartbeats_sent;
    for i in 0..100u8 {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[i; 100], AppendOptions::default())
            .unwrap();
        for _ in 0..10 {
            rig.round(true);
        }
    }
    assert!(rig.now >= 1_000 * MS, "a second of rounds");
    assert_eq!(
        rig.agents.sender.role.counters().path_heartbeats_sent,
        before
    );
}

/// Plan 164: a publisher that still sends after its paths are lost (no
/// PATH_HB reaches them) rebinds them through a SOLICIT each time,
/// within the retry window, whose ANSWER binds though a retry is due
/// first: through 30 s and every loss, the image lives on.
#[test]
fn a_live_publisher_rebinds_its_lost_paths_through_a_solicit() {
    // Its PATH_HBs (karyos#859) wait past the test: its paths are lost at
    // `path_liveness_timeout` as a publisher's whose PATH_HBs do not arrive.
    let setup = Setup {
        reliable: true,
        tune: Some(|config| config.path_heartbeat_interval = 100_000_000_000),
        ..Setup::default()
    };
    let (mut rig, _b) = Rig::new(setup.again());
    let slot = established(&mut rig);
    let _b2 = rig.second_path(&setup, announce(setup.term_length), None);
    rig.until(true, |rig| rig.agents.receiver.role.live_paths(slot) == 2);
    let mut lost_at = None;
    let mut losses = 0u32;
    for second in 1..=30u64 {
        rig.now += 1_000_000_000;
        for _ in 0..3 {
            rig.round(true);
        }
        assert!(
            rig.agents.receiver.role.has_image(slot),
            "retired at {second} s"
        );
        let paths = rig.agents.receiver.role.live_paths(slot);
        match lost_at {
            None if paths == 0 => {
                lost_at = Some(second);
                losses += 1;
            }
            // Within the retry window (2 × `setup_challenge_timeout`).
            Some(at) if paths > 0 => {
                assert!(second - at <= 2, "lost at {at} s, rebound at {second} s");
                lost_at = None;
            }
            _ => {}
        }
    }
    assert!(losses >= 2, "{losses} losses");
    assert!(
        rig.agents
            .receiver
            .role
            .session_counters()
            .solicits_answered
            >= 2
    );
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

/// #315 review P3: the founding route faulted while its subscription
/// stays and a later route is healthy. The NAK goes on the later path's
/// copy only; the faulted founding route takes none.
#[test]
fn a_faulted_founding_route_naks_on_the_later_path_only() {
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
    rig.until(true, |rig| rig.agents.receiver.counters().naks >= 1);
    for _ in 0..5 {
        rig.round(true);
    }
    let nak = rig.agents.receiver.role.posted_naks()[0];
    rig.agents.receiver.role.fault_naks(slot, &nak);
    let founding = rig.agents.receiver.role.founding_naks();
    let copies = rig.agents.receiver.counters().nak_copies;
    rig.until(true, |rig| {
        rig.agents.receiver.counters().nak_copies > copies
    });
    assert_eq!(rig.agents.receiver.role.founding_naks(), founding);
}

/// #315 review P3: with the founding subscription gone and the later
/// route faulted, no copy can go. The NAK is not counted as sent; it
/// stays due.
#[test]
fn a_nak_with_no_copy_posted_is_not_counted() {
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
    rig.unsubscribe(b);
    rig.agents.receiver.role.fault_route(slot, 1);
    let naks = rig.agents.receiver.counters().naks;
    let mut rounds = 0;
    while rig.agents.receiver.role.route_faulted(slot, 1) && rounds < 40 {
        rig.now += 10_000_000;
        rig.round(true);
        assert_eq!(rig.agents.receiver.counters().naks, naks);
        rounds += 1;
    }
    assert!(rounds > 3, "{rounds} rounds while the route was faulted");
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
            empty_since: None,
            rate: None,
            reserve: None,
            policy: None,
            frontier: Default::default(),
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
    // Each replay is counted as it is handled, read around it: the real
    // sockets of the rig may deliver other dropped control frames at any
    // round under host load, so a total over the run is not exact
    // (karyos#1067).
    let replay = |rig: &mut Rig| {
        let receiver = &mut rig.agents.receiver;
        let before = receiver.role.session_counters().dropped;
        receiver.role.inject_control(
            &receiver.sessions,
            b,
            source,
            karyos_protocol::network::Control::SetupAnnounce(announce(65_536)),
            rig.now,
        );
        assert_eq!(
            receiver.role.session_counters().dropped,
            before + 1,
            "every replay counted"
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
    assert!(
        sessions.dropped >= dropped + replays,
        "every replay counted"
    );
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

/// Plan item 7 (contract-traceability-phase-2.md, "Challenge lifecycle";
/// SPEC §13: "no join point is lowered ... and no duplicate detection
/// reset"): a SETUP of the bound image, repeated after binding with its
/// own identity or another, changes nothing the image knows. Neither is
/// challenged nor installs an image; the frames already received, replayed
/// byte for byte, are dropped as duplicates, committed nowhere and never
/// delivered again; and the next message continues where the stream was,
/// read once.
#[test]
fn a_duplicate_setup_after_binding_keeps_the_images_duplicates_and_join() {
    use karyos_sys::log_buffer::{AppendOptions, PollOutcome, Role};

    // A frame of 1000 bytes is 1032 bytes, at 32-byte strides.
    const STRIDE: u64 = 1056;

    let (mut rig, b) = Rig::new(Setup {
        reliable: true,
        ..Setup::default()
    });
    let slot = established(&mut rig);
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    let mut out = vec![0u8; 2048];
    let mut read = |rig: &mut Rig, count: usize| {
        let mut delivered = Vec::new();
        for _ in 0..200 {
            rig.round(true);
            while let PollOutcome::Message { position, .. } = subscriber.poll(&mut out).unwrap() {
                subscriber.acknowledge();
                delivered.push(position);
            }
            if delivered.len() >= count {
                break;
            }
        }
        // Rounds past the last, so a message delivered twice would show.
        for _ in 0..20 {
            rig.round(true);
            while let PollOutcome::Message { position, .. } = subscriber.poll(&mut out).unwrap() {
                subscriber.acknowledge();
                delivered.push(position);
            }
        }
        delivered
    };
    // Three messages, received and read: positions 0 to 2 * STRIDE.
    let log = rig.log.as_mut().unwrap();
    for _ in 0..3 {
        let _ = log.publications[0]
            .append(&[7; 1000], AppendOptions::default())
            .unwrap();
    }
    assert_eq!(read(&mut rig, 3), [0, STRIDE, 2 * STRIDE]);
    let installed = rig
        .events
        .iter()
        .filter(|event| matches!(event, ImageEvent::Installed { .. }))
        .count();
    let sessions = rig.agents.receiver.role.session_counters();
    let committed = rig.agents.receiver.counters().data_committed;
    let dropped = rig.agents.receiver.counters().data_dropped;
    // The bound image's SETUP again, with its own identity, then with
    // another incarnation's.
    for incarnation in [1, 2] {
        let receiver = &mut rig.agents.receiver;
        receiver.role.inject_control(
            &receiver.sessions,
            b,
            source,
            karyos_protocol::network::Control::SetupAnnounce(SetupAnnounce {
                identity: Identity {
                    incarnation,
                    ..identity()
                },
                ..announce(65_536)
            }),
            rig.now,
        );
        rig.round(true);
    }
    assert!(rig.agents.receiver.role.has_image(slot), "the image stays");
    let after = rig.agents.receiver.role.session_counters();
    assert_eq!(after.challenges, sessions.challenges, "no SETUP challenged");
    assert_eq!(after.installed, sessions.installed, "nothing installed");
    assert_eq!(
        rig.events
            .iter()
            .filter(|event| matches!(event, ImageEvent::Installed { .. }))
            .count(),
        installed
    );
    // The frames already received, replayed byte for byte.
    for offset in [0, STRIDE, 2 * STRIDE] {
        let receiver = &mut rig.agents.receiver;
        receiver.role.inject_data(
            &receiver.sessions,
            b,
            source,
            alias(),
            &stale_frame(9, u32::try_from(offset).unwrap(), 1000),
            rig.now,
        );
    }
    assert_eq!(read(&mut rig, 0), [], "a replayed frame delivered again");
    assert_eq!(
        rig.agents.receiver.counters().data_committed,
        committed,
        "a replayed frame committed again"
    );
    assert!(
        rig.agents.receiver.counters().data_dropped >= dropped + 3,
        "the replays dropped as duplicates"
    );
    // The control: the same injection one frame on, a position the image
    // has not seen, is committed and read once, so the replays above met
    // the image's duplicate detection, not a closed door; and the stream
    // continues where it was. The publication's own frame there is then
    // a duplicate in turn.
    let receiver = &mut rig.agents.receiver;
    receiver.role.inject_data(
        &receiver.sessions,
        b,
        source,
        alias(),
        &stale_frame(9, u32::try_from(3 * STRIDE).unwrap(), 1000),
        rig.now,
    );
    assert_eq!(read(&mut rig, 1), [3 * STRIDE]);
    assert_eq!(rig.agents.receiver.counters().data_committed, committed + 1);
    let log = rig.log.as_mut().unwrap();
    let _ = log.publications[0]
        .append(&[7; 1000], AppendOptions::default())
        .unwrap();
    assert_eq!(
        read(&mut rig, 0),
        [],
        "the publication's frame delivered twice"
    );
}

/// A whole DATA frame of `payload` bytes on lane 0 of the rig's alias,
/// for `term_id` at `term_offset`, as a datagram of any incarnation
/// carries it: DATA names no incarnation, only the alias and the term.
fn stale_frame(term_id: u32, term_offset: u32, payload: usize) -> Vec<u8> {
    use karyos_protocol::frame::{Flags, FrameType, Word0};

    let length = 32 + payload;
    let word0 = Word0::new(
        i32::try_from(length).unwrap(),
        Flags::new(true, true, false, false, Lane::ZERO),
        FrameType::Data,
    );
    let mut bytes = vec![7u8; length];
    bytes[..8].copy_from_slice(&word0.pack().to_le_bytes());
    bytes[8..12].copy_from_slice(&term_offset.to_le_bytes());
    bytes[12..16].copy_from_slice(&alias().session_id.to_le_bytes());
    bytes[16..20].copy_from_slice(&alias().stream_id.to_le_bytes());
    bytes[20..24].copy_from_slice(&term_id.to_le_bytes());
    bytes[24..32].fill(0);
    bytes
}

/// T5 (contract-traceability-phase-2.md, "Stale datagrams after sender
/// restart", the trusted half; SPEC §6): a sender driver restart reuses
/// the alias, and DATA of the old incarnation is still in flight. The
/// old image retires; the new incarnation binds a new image through its
/// own challenge, with another initial term id. Stale DATA of the old
/// terms then commits nothing and reaches no subscriber. Of nine probes
/// around and far from the new window, none commits; only the window's own
/// terms (`r` and `r + 1`) do: a stale datagram is accepted only if its
/// term id falls there. This proves the receiver's window. The rate SPEC
/// asks for, about 3 in 2^32, also needs the restarted sender to draw its
/// initial term id at random, which a network publication does (G2,
/// `network_publications_draw_their_initial_term_ids`); this test sets
/// one by hand so the probes are placed around a known window. The
/// authenticated half (always rejected) needs the authenticated profile
/// (owner decision 5, ADR-0035).
#[test]
fn stale_data_after_a_sender_restart_is_accepted_only_inside_the_new_window() {
    use std::sync::Arc;

    use karyos_sys::applied_epoch::AppliedEpoch;
    use karyos_sys::log_buffer::{PollOutcome, Role};
    use karyos_sys::sync::Ordering;

    // The new incarnation's initial term id, set by hand so the probes
    // know the window: half the term id space away from the old one, 9.
    const NEW: u32 = 9 + (1 << 31);

    let word = Arc::new(karyos_client::HeapWords::zeroed(1));
    word.words()[0].store(karyos_sys::guard::created(), Ordering::Release);
    assert_eq!(karyos_sys::guard::reopen(&word.words()[0], 1), Ok(2));
    let (mut rig, b) = Rig::new(Setup {
        guard: Some(super::super::data::GuardSpec {
            word: Arc::clone(&word) as Arc<dyn karyos_client::SharedWords>,
            cell: Arc::new(AppliedEpoch::new()),
            epoch: 2,
            empty_since: None,
            rate: None,
            reserve: None,
            policy: None,
            frontier: Default::default(),
        }),
        ..Setup::default()
    });
    let old = established(&mut rig);
    // The old incarnation goes silent, as its driver stops; its image
    // retires at the liveness timeout.
    let _ = karyos_sys::guard::close(&word.words()[0]).unwrap();
    for _ in 0..15 {
        rig.now += 1_000 * MS;
        rig.round(true);
        if !rig.agents.receiver.role.has_image(old) {
            break;
        }
    }
    assert!(!rig.agents.receiver.role.has_image(old));
    // The restarted driver announces the alias again: a new incarnation
    // and a fresh initial term id.
    let installed = |rig: &Rig| {
        rig.events
            .iter()
            .filter(|event| matches!(event, ImageEvent::Installed { .. }))
            .count()
    };
    let before = installed(&rig);
    rig.reannounce(
        b,
        SetupAnnounce {
            identity: Identity {
                incarnation: 2,
                ..identity()
            },
            term: TermParams {
                initial_term_id: NEW.cast_signed(),
                ..term(65_536)
            },
            ..announce(65_536)
        },
    );
    rig.until(true, |rig| installed(rig) == before + 1);
    let Some(ImageEvent::Installed { slot, .. }) = rig.events.last().copied() else {
        panic!("{:?}", rig.events);
    };
    assert_ne!(slot, old);
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    let inject = |rig: &mut Rig, term_id: u32| {
        let receiver = &mut rig.agents.receiver;
        receiver.role.inject_data(
            &receiver.sessions,
            b,
            source,
            alias(),
            &stale_frame(term_id, 0, 32),
            rig.now,
        );
        rig.round(true);
    };
    let committed = |rig: &Rig| rig.agents.receiver.counters().data_committed;
    // Nine probes outside the new window {r, r + 1} (r = NEW at the join):
    // the old incarnation's terms, both sides of the window, and two
    // quarters of the term id space away.
    let outside = [
        9,
        10,
        11,
        NEW.wrapping_sub(2),
        NEW.wrapping_sub(1),
        NEW.wrapping_add(2),
        NEW.wrapping_add(3),
        NEW.wrapping_add(1 << 30),
        NEW.wrapping_sub(1 << 30),
    ];
    assert_eq!(
        outside
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        outside.len(),
        "the probes are distinct"
    );
    let start = committed(&rig);
    for term_id in outside {
        inject(&mut rig, term_id);
        assert_eq!(
            committed(&rig),
            start,
            "term id {term_id:#x} outside the window committed"
        );
    }
    let mut out = vec![0u8; 256];
    assert_eq!(subscriber.poll(&mut out).unwrap(), PollOutcome::Pending);
    // Inside the window, a frame commits whatever incarnation sent it: the
    // residual risk the initial term id makes small.
    for (i, term_id) in [NEW, NEW.wrapping_add(1)].into_iter().enumerate() {
        inject(&mut rig, term_id);
        assert_eq!(
            committed(&rig),
            start + 1 + u64::try_from(i).unwrap(),
            "term id {term_id:#x} inside the window"
        );
    }
    assert!(matches!(
        subscriber.poll(&mut out).unwrap(),
        PollOutcome::Message {
            position: 0,
            length: 32,
            ..
        }
    ));
}

/// T6 (contract-traceability-phase-2.md, "Receiver restart freshness",
/// the trusted half; SPEC §13): a restarted receiver, here a fresh rig
/// with a new boot id and no binding, challenge or quarantine state, while
/// the publisher stays live. Replayed old DATA is unbound and delivered
/// nowhere. The replayed SETUP makes the receiver challenge afresh, and
/// while that challenge is pending a replayed old SETUP_ANSWER, echoing the
/// old boot id and nonce, is dropped and binds nothing: only the fresh
/// challenge's answer binds. Once bound, above a join point, old DATA
/// below the join and every replayed copy of a committed frame are not
/// delivered: each message reaches the subscriber once. `multicast` only
/// changes how the image times its NAKs here (the rig runs on loopback
/// unicast). The MAC cases need the authenticated profile (owner decision
/// 5, ADR-0035).
fn a_restarted_receiver_binds_only_through_a_fresh_challenge(multicast: bool) {
    use karyos_protocol::network::{ChallengeBlock, Control, SetupAnswer};
    use karyos_sys::log_buffer::{AppendOptions, PollOutcome, Role};

    let (mut rig, b) = Rig::new(Setup {
        multicast,
        before: 2,
        ..Setup::default()
    });
    // The subscription and the publication are added.
    rig.round(true);
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    let sessions = rig.agents.receiver.role.session_counters();
    assert_eq!(sessions.installed, 0);
    // The answer the receiver got before its restart, replayed.
    let old_answer = SetupAnswer {
        alias: alias(),
        identity: identity(),
        term: term(65_536),
        challenge: ChallengeBlock {
            receiver_boot_id: [0x0b00_7001, 1],
            nonce: [0x0001_d001, 2],
        },
        joins: Lanes::new(&[0, 0]).unwrap(),
    };
    // Old DATA of the alias, replayed: no image binds it.
    let unbound = rig.agents.receiver.counters().data_unbound;
    let receiver = &mut rig.agents.receiver;
    receiver.role.inject_data(
        &receiver.sessions,
        b,
        source,
        alias(),
        &stale_frame(9, 0, 32),
        rig.now,
    );
    assert_eq!(rig.agents.receiver.counters().data_unbound, unbound + 1);
    // The old SETUP, replayed: the receiver challenges with its new boot
    // id, and that challenge is pending.
    let receiver = &mut rig.agents.receiver;
    receiver.role.inject_control(
        &receiver.sessions,
        b,
        source,
        Control::SetupAnnounce(announce(65_536)),
        rig.now,
    );
    // (The old DATA solicited; the SETUP's challenge replaces that.)
    let pending = rig.agents.receiver.role.session_counters();
    assert!(
        pending.challenges + pending.challenges_replaced
            > sessions.challenges + sessions.challenges_replaced,
        "no challenge pending: {pending:?}"
    );
    // The old answer, replayed while it is: its boot id and nonce are not
    // the pending challenge's, so it is dropped and binds nothing.
    let receiver = &mut rig.agents.receiver;
    receiver.role.inject_control(
        &receiver.sessions,
        b,
        source,
        Control::SetupAnswer(old_answer),
        rig.now,
    );
    let after = rig.agents.receiver.role.session_counters();
    assert_eq!(after.dropped, pending.dropped + 1, "the old answer");
    assert_eq!(after.installed, 0);
    // Only the fresh challenge's answer, from the live publisher, binds.
    let slot = established(&mut rig);
    let challenges: Vec<_> = rig
        .agents
        .receiver
        .role
        .posted_challenges()
        .iter()
        .filter_map(|(_, control)| match control {
            Control::Challenge(challenge) => Some(challenge.challenge),
            _ => None,
        })
        .collect();
    // Every challenge carries the restarted receiver's own boot id.
    let boot_id = challenges.first().unwrap().receiver_boot_id;
    assert!(
        challenges
            .iter()
            .all(|challenge| challenge.receiver_boot_id == boot_id),
        "{challenges:?}"
    );
    assert_eq!(rig.agents.receiver.role.session_counters().installed, 1);
    // The image joins above 0: after the two messages appended first.
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    let join = 2 * 1056;
    // Every DATA datagram from here arrives twice, as replays would.
    let dropped = rig.agents.receiver.counters().data_dropped;
    rig.agents.receiver.role.drop_data(&[]);
    rig.agents.receiver.role.repeat_data_from(0);
    let log = rig.log.as_mut().unwrap();
    for i in 0..3u8 {
        let _ = log.publications[0]
            .append(&[i; 1000], AppendOptions::default())
            .unwrap();
    }
    let mut delivered = Vec::new();
    let mut out = vec![0u8; 2048];
    for _ in 0..200 {
        rig.round(true);
        while let PollOutcome::Message { position, .. } = subscriber.poll(&mut out).unwrap() {
            subscriber.acknowledge();
            delivered.push(position);
        }
        if delivered.len() == 3 {
            break;
        }
    }
    assert_eq!(delivered, [join, join + 1056, join + 2 * 1056]);
    // Each frame's copy was dropped as a duplicate.
    let copies = rig.agents.receiver.counters().data_dropped - dropped;
    assert!(copies >= 3, "{copies} copies dropped");
    // Old DATA below the join point, replayed.
    let dropped = rig.agents.receiver.counters().data_dropped;
    let committed = rig.agents.receiver.counters().data_committed;
    for offset in [0, 1056] {
        let receiver = &mut rig.agents.receiver;
        receiver.role.inject_data(
            &receiver.sessions,
            b,
            source,
            alias(),
            &stale_frame(9, offset, 1000),
            rig.now,
        );
    }
    for _ in 0..20 {
        rig.round(true);
    }
    assert_eq!(rig.agents.receiver.counters().data_committed, committed);
    assert!(rig.agents.receiver.counters().data_dropped >= dropped + 2);
    assert_eq!(subscriber.poll(&mut out).unwrap(), PollOutcome::Pending);
}

#[test]
fn a_restarted_unicast_receiver_binds_only_through_a_fresh_challenge() {
    a_restarted_receiver_binds_only_through_a_fresh_challenge(false);
}

#[test]
fn a_restarted_multicast_receiver_binds_only_through_a_fresh_challenge() {
    a_restarted_receiver_binds_only_through_a_fresh_challenge(true);
}

/// P2.12 step 3 PR 2: a hook that records the receiver's commits and its
/// journals' opens and closes.
/// What a [`CommitRecorder`] saw: the commits, the journals opened and
/// how many closed.
type Recorded = (
    Vec<(
        karyos_protocol::frame::TraceExtension,
        karyos_protocol::trace_hook::NetCommit,
    )>,
    Vec<u64>,
    u32,
);

#[derive(Clone, Default)]
struct CommitRecorder(std::sync::Arc<std::sync::Mutex<Recorded>>);

impl karyos_protocol::trace_hook::NetworkTraceHook for CommitRecorder {
    fn open_journal(&mut self, journal: karyos_protocol::trace_hook::NetJournal) {
        self.0.lock().unwrap().1.push(journal.number);
    }

    fn close_journal(
        &mut self,
        _side: karyos_protocol::trace_hook::NetSide,
        _publication: &karyos_protocol::trace_hook::PublicationIdentity,
        _lane: Lane,
    ) {
        self.0.lock().unwrap().2 += 1;
    }

    fn on_sender_pickup(
        &mut self,
        _ext: &karyos_protocol::frame::TraceExtension,
        _at: &karyos_protocol::trace_hook::NetPickup,
    ) {
    }

    fn on_receiver_commit(
        &mut self,
        ext: &karyos_protocol::frame::TraceExtension,
        at: &karyos_protocol::trace_hook::NetCommit,
    ) {
        self.0.lock().unwrap().0.push((*ext, *at));
    }
}

/// The rig publication's identity, as a trace journal names it.
fn traced_publication() -> karyos_protocol::trace_hook::PublicationIdentity {
    karyos_protocol::trace_hook::PublicationIdentity {
        driver: identity().driver_id,
        registration: identity().registration_id,
        stream_id: alias().stream_id,
        session_id: alias().session_id,
        incarnation: identity().incarnation,
    }
}

fn trace_extension(message_id: u64) -> karyos_protocol::frame::TraceExtension {
    karyos_protocol::frame::TraceExtension {
        extension_flags: 0,
        trace_id: [7, 9],
        span_id: 3,
        parent_span_id: 0,
        message_id,
    }
}

impl Rig {
    /// Sets `hook` on the receiver, then posts it a journal of lane 0 of
    /// the rig's publication, numbered `number`, and runs a round.
    fn trace_receiver(&mut self, hook: Option<CommitRecorder>, b: EndpointId, number: u64) {
        self.links
            .receiver
            .post(|reply| AgentCommand::SetNetworkTrace {
                reply,
                hook: hook.map(|hook| crate::agents::net_trace::TraceHook(Box::new(hook))),
            })
            .unwrap();
        self.round(true);
        let (writer, _consumer) = karyos_protocol::journal::record_journal(4, 1, 1).unwrap();
        self.links
            .receiver
            .post(|reply| AgentCommand::OpenNetworkJournal {
                reply,
                endpoint: b,
                alias: alias(),
                journal: karyos_protocol::trace_hook::NetJournal {
                    side: karyos_protocol::trace_hook::NetSide::Receiver,
                    publication: traced_publication(),
                    lane: Lane::ZERO,
                    number,
                    writer,
                },
            })
            .unwrap();
        self.round(true);
    }

    /// Asks the receiver to close journal `number`, of lane 0, and returns
    /// the facts it answered.
    fn close_receiver_journal(
        &mut self,
        number: u64,
    ) -> Option<crate::agents::net_trace::JournalFacts> {
        self.trace_events.clear();
        self.links
            .receiver
            .post(|reply| AgentCommand::CloseNetworkJournal {
                reply,
                publication: traced_publication(),
                lane: Lane::ZERO,
                number,
            })
            .unwrap();
        self.round(true);
        self.trace_events.iter().find_map(|event| match event {
            crate::agents::AgentEvent::NetworkJournalClosed { facts, .. } => Some(facts.clone()),
            _ => None,
        })?
    }
}

/// P2.12 step 3 PR 2 (trace-network.md §4, §5, NT-2): a receiver journal
/// opens with the lane's next commit position as its start; a traced frame
/// records one `ReceiverCommit` when it commits, naming its path; an
/// untraced one records nothing; the close answers the start, the
/// lane's resolved prefix as the commit boundary and no gap, and closes
/// the journal through the hook.
#[test]
fn a_receiver_journal_records_each_traced_commit_once() {
    use karyos_sys::log_buffer::{AppendOptions, AppendOutcome};

    let (mut rig, b) = Rig::new(Setup::default());
    let slot = established(&mut rig);
    // Something commits before the journal arrives: its start is past it.
    let log = rig.log.as_mut().unwrap();
    let _ = log.publications[0]
        .append(&[0; 100], AppendOptions::default())
        .unwrap();
    rig.until(true, |rig| {
        rig.agents.receiver.counters().data_committed >= 1
    });
    let next = rig.agents.receiver.role.rebuild_position(slot, Lane::ZERO);
    assert!(next.is_some_and(|next| next > 0), "{next:?}");
    let recorder = CommitRecorder::default();
    rig.trace_receiver(Some(recorder.clone()), b, 9);
    let start = rig.trace_events.iter().find_map(|event| match event {
        crate::agents::AgentEvent::NetworkJournalOpened {
            number: 9, start, ..
        } => Some(*start),
        _ => None,
    });
    assert_eq!(start, next, "the start is the lane's next commit position");
    assert_eq!(recorder.0.lock().unwrap().1, [9]);
    let mut bytes = [0u8; 64];
    trace_extension(1).encode(&mut bytes).unwrap();
    let traced = AppendOptions {
        extension: Some(bytes),
        ..AppendOptions::default()
    };
    let log = rig.log.as_mut().unwrap();
    let AppendOutcome::Appended { position } =
        log.publications[0].append(&[1; 100], traced).unwrap()
    else {
        panic!("not appended");
    };
    let _ = log.publications[0]
        .append(&[2; 100], AppendOptions::default())
        .unwrap();
    rig.until(true, |rig| {
        rig.agents.receiver.counters().data_committed >= 3
    });
    for _ in 0..20 {
        rig.round(true);
    }
    let commits = recorder.0.lock().unwrap().0.clone();
    assert_eq!(commits.len(), 1, "one traced frame, once: {commits:?}");
    let (ext, at) = commits[0];
    assert_eq!(ext, trace_extension(1));
    assert_eq!(
        (at.publication, at.lane, at.position, at.path),
        (traced_publication(), Lane::ZERO, position, 0)
    );
    let boundary = rig.agents.receiver.role.rebuild_position(slot, Lane::ZERO);
    let facts = rig.close_receiver_journal(9).expect("facts");
    assert_eq!(
        (Some(facts.start), Some(facts.boundary), facts.first_gap),
        (next, boundary, None)
    );
    assert_eq!(recorder.0.lock().unwrap().2, 1, "closed through the hook");
    // A second close finds nothing.
    assert_eq!(rig.close_receiver_journal(9), None);
}

/// P2.12 step 3 PR 2 (NT-2, #327 review): a traced frame lost and
/// repaired by NAK records its commit once, at the repair; every copy of
/// an already committed frame (Duplicate or Late) records nothing.
#[test]
fn a_repaired_traced_frame_records_once_and_its_copies_never() {
    use karyos_sys::log_buffer::{AppendOptions, AppendOutcome};

    let (mut rig, b) = Rig::new(Setup {
        reliable: true,
        ..Setup::default()
    });
    let slot = established(&mut rig);
    let recorder = CommitRecorder::default();
    rig.trace_receiver(Some(recorder.clone()), b, 5);
    // The second datagram is lost; every one from the third on, the
    // repair included, arrives twice.
    rig.agents.receiver.role.drop_data(&[1]);
    rig.agents.receiver.role.repeat_data_from(2);
    let dropped = rig.agents.receiver.counters().data_dropped;
    let mut positions = Vec::new();
    for i in 0..4u8 {
        let mut bytes = [0u8; 64];
        trace_extension(u64::from(i)).encode(&mut bytes).unwrap();
        let traced = AppendOptions {
            extension: Some(bytes),
            ..AppendOptions::default()
        };
        let log = rig.log.as_mut().unwrap();
        let AppendOutcome::Appended { position } =
            log.publications[0].append(&[i; 900], traced).unwrap()
        else {
            panic!("not appended");
        };
        positions.push(position);
    }
    rig.until(true, |rig| {
        rig.agents
            .receiver
            .role
            .loss_counters(slot)
            .is_some_and(|counters| counters.repaired >= 1)
    });
    for _ in 0..20 {
        rig.round(true);
    }
    assert!(
        rig.agents.receiver.counters().data_dropped > dropped,
        "copies arrived"
    );
    let mut commits: Vec<(u64, u64)> = recorder
        .0
        .lock()
        .unwrap()
        .0
        .iter()
        .map(|(ext, at)| (ext.message_id, at.position))
        .collect();
    commits.sort_unstable();
    let expected: Vec<(u64, u64)> = (0..4u64).zip(positions).collect();
    assert_eq!(commits, expected, "each traced frame once, at its position");
}

/// P2.12 step 3 PR 3b (§5): each gap the skip policy seals on a traced
/// lane is kept in its journal's facts, in order; the first is the first
/// gap fact.
#[test]
fn a_receiver_journal_keeps_its_sealed_gaps() {
    use karyos_sys::log_buffer::{AppendOptions, AppendOutcome};

    let (mut rig, b) = Rig::new(Setup::default());
    let _slot = established(&mut rig);
    let recorder = CommitRecorder::default();
    rig.trace_receiver(Some(recorder.clone()), b, 9);
    // The second and fourth datagrams are lost: two holes.
    rig.agents.receiver.role.drop_data(&[1, 3]);
    let mut positions = Vec::new();
    for i in 0..5u8 {
        let log = rig.log.as_mut().unwrap();
        let AppendOutcome::Appended { position } = log.publications[0]
            .append(&[i; 900], AppendOptions::default())
            .unwrap()
        else {
            panic!("not appended");
        };
        positions.push(position);
    }
    rig.until(true, |rig| rig.agents.receiver.counters().gaps_sealed >= 2);
    let facts = rig.close_receiver_journal(9).expect("facts");
    let gaps = facts.gaps.as_deref().unwrap().intervals();
    assert_eq!(gaps.len(), 2, "{gaps:?}");
    assert_eq!((gaps[0].0, gaps[1].0), (positions[1], positions[3]));
    assert!(gaps.iter().all(|(start, end)| end > start));
    assert_eq!(facts.first_gap, Some(positions[1]));
    assert!(!facts.gaps.as_deref().unwrap().overflowed());
}

/// P2.12 step 3 PR 2 (Q2, ACS 16519): an image that retires closes its
/// lanes' journals at once and posts their facts to the conductor
/// unsolicited; a later close answers the same facts once.
#[test]
fn a_retired_image_closes_its_journals_with_their_facts() {
    use karyos_sys::log_buffer::AppendOptions;

    let (mut rig, b) = Rig::new(Setup::default());
    let slot = established(&mut rig);
    let recorder = CommitRecorder::default();
    rig.trace_receiver(Some(recorder.clone()), b, 11);
    let start = rig.trace_events.iter().find_map(|event| match event {
        crate::agents::AgentEvent::NetworkJournalOpened {
            number: 11, start, ..
        } => Some(*start),
        _ => None,
    });
    let log = rig.log.as_mut().unwrap();
    let _ = log.publications[0]
        .append(&[1; 100], AppendOptions::default())
        .unwrap();
    rig.until(true, |rig| {
        rig.agents.receiver.counters().data_committed >= 1
    });
    let boundary = rig.agents.receiver.role.rebuild_position(slot, Lane::ZERO);
    assert!(boundary > start, "{boundary:?} {start:?}");
    rig.trace_events.clear();
    rig.now += 11_000 * MS;
    rig.until(true, |rig| {
        rig.agents.receiver.counters().images_retired >= 1
    });
    rig.round(true);
    let posted = rig.trace_events.iter().find_map(|event| match event {
        crate::agents::AgentEvent::NetworkJournalClosed {
            facts: Some(facts), ..
        } => Some(facts.clone()),
        _ => None,
    });
    let posted = posted.expect("the retirement posted the close");
    assert_eq!(posted.publication, traced_publication());
    assert_eq!(
        (Some(posted.start), Some(posted.boundary), posted.first_gap),
        (start, boundary, None),
        "the facts at the retirement"
    );
    assert_eq!(recorder.0.lock().unwrap().2, 1, "closed through the hook");
    // A close naming another number (a reinstalled identity's journal)
    // finds nothing; the right one has the same facts, then nothing.
    assert_eq!(rig.close_receiver_journal(12), None);
    // The gaps went with the posted event; a later close answers the rest.
    assert!(posted.gaps.is_some());
    let mut again = posted.clone();
    again.gaps = None;
    assert_eq!(rig.close_receiver_journal(11), Some(again));
    assert_eq!(rig.close_receiver_journal(11), None);
}

/// P2.12 step 3 PR 2: without a hook, or for a publication no image
/// receives, the journal is refused and comes back.
#[test]
fn a_receiver_journal_is_refused_without_a_hook_or_an_image() {
    let (mut rig, b) = Rig::new(Setup::default());
    let _slot = established(&mut rig);
    rig.trace_receiver(None, b, 3);
    assert!(rig.trace_events.iter().any(|event| matches!(
        event,
        crate::agents::AgentEvent::NetworkJournalRefused { journal, .. } if journal.number == 3
    )));
    rig.trace_events.clear();
    rig.trace_receiver(Some(CommitRecorder::default()), b, 4);
    assert!(rig.trace_events.iter().any(|event| matches!(
        event,
        crate::agents::AgentEvent::NetworkJournalOpened { number: 4, .. }
    )));
    // A second journal for the same lane is refused.
    rig.trace_events.clear();
    rig.trace_receiver(Some(CommitRecorder::default()), b, 5);
    assert!(
        rig.trace_events.iter().any(|event| matches!(
            event,
            crate::agents::AgentEvent::NetworkTraceSet {
                closed: Some(1),
                ..
            }
        )),
        "the new hook closed the journal the old one held"
    );
}

/// P2.12 step 3 PR 2: a frame whose EXT does not decode never reaches the
/// commit point: datagram validation refuses it (`data_invalid`), so it is
/// never traced. (The commit point still counts an EXT it cannot decode,
/// `net_trace_ext_invalid`, should validation ever let one through.)
#[test]
fn an_undecodable_extension_is_refused_and_never_traced() {
    use karyos_sys::log_buffer::AppendOptions;

    let (mut rig, b) = Rig::new(Setup::default());
    let _slot = established(&mut rig);
    let recorder = CommitRecorder::default();
    rig.trace_receiver(Some(recorder.clone()), b, 9);
    let garbage = AppendOptions {
        extension: Some([0xFF; 64]),
        ..AppendOptions::default()
    };
    let log = rig.log.as_mut().unwrap();
    let _ = log.publications[0].append(&[1; 100], garbage).unwrap();
    rig.until(true, |rig| rig.agents.receiver.counters().data_invalid >= 1);
    let counters = rig.agents.receiver.counters();
    assert_eq!(
        (counters.data_committed, counters.net_trace_ext_invalid),
        (0, 0)
    );
    assert!(recorder.0.lock().unwrap().0.is_empty());
}

/// T8 (contract-traceability-phase-2.md, "Bounded scheduling"): one whole
/// receiver and sender cycle under overload keeps every per-cycle bound at
/// once. With small bounds, both lanes publish as fast as the log takes
/// them and lose datagrams, so each lane's earliest hole is NAKed and two
/// NAKs can reach the sender in one cycle. Both lanes are needed: the
/// receiver keeps one NAK in flight per lane, so a single lane never
/// exceeds a sender budget of one NAK a cycle. Every single cycle reads at most
/// `rx_datagrams` per endpoint, admits at most `naks_per_cycle` NAKs and
/// repairs within the repair byte budget; the excess waits (counted), and
/// every message still arrives, in order.
#[test]
fn an_overloaded_cycle_keeps_every_per_cycle_bound() {
    use karyos_sys::log_buffer::{AppendOptions, AppendOutcome, Role};

    const RX: u32 = 4;
    const NAKS: u32 = 1;
    const REPAIR_BYTES: u64 = 4_096;
    /// The rig's endpoints: A and B.
    const ENDPOINTS: u64 = 2;
    /// The largest datagram a repair submits.
    const DATAGRAM: u64 = 1_408;
    const MESSAGES: u8 = 48;
    let (mut rig, _b) = Rig::new(Setup {
        reliable: true,
        tune: Some(|config| {
            config.rx_datagrams = RX;
            config.repair.naks_per_cycle = NAKS;
            config.repair.budget.bytes = REPAIR_BYTES;
        }),
        ..Setup::default()
    });
    let slot = established(&mut rig);
    let mut subscribers = [
        image_subscriber(&rig, slot, 0, Role::Optional),
        image_subscriber(&rig, slot, 1, Role::Optional),
    ];
    rig.agents
        .receiver
        .role
        .drop_data(&[1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23]);
    let mut appended = [0u8; 2];
    let mut delivered = [Vec::new(), Vec::new()];
    let mut fullest_read = 0u64;
    let mut before = (rig.agents.receiver.counters(), rig.agents.sender.counters());
    for _ in 0..4_000 {
        for (lane, count) in appended.iter_mut().enumerate() {
            while *count < MESSAGES {
                let log = rig.log.as_mut().unwrap();
                match log.publications[lane]
                    .append(&[*count; 900], AppendOptions::default())
                    .unwrap()
                {
                    AppendOutcome::Appended { .. } => *count += 1,
                    _ => break,
                }
            }
        }
        rig.round(true);
        let after = (rig.agents.receiver.counters(), rig.agents.sender.counters());
        let read = after.0.datagrams - before.0.datagrams;
        let admitted = after.1.naks - before.1.naks;
        let repairs = after.1.repairs - before.1.repairs;
        assert!(
            read <= u64::from(RX) * ENDPOINTS,
            "{read} datagrams in a cycle"
        );
        assert!(
            admitted <= u64::from(NAKS),
            "{admitted} NAKs admitted in a cycle"
        );
        // A repair is admitted while budget remains, so the last one may
        // overrun it by at most one datagram.
        assert!(
            repairs
                .checked_sub(1)
                .is_none_or(|full| full * DATAGRAM <= REPAIR_BYTES),
            "{repairs} repairs in a cycle"
        );
        fullest_read = fullest_read.max(read);
        before = after;
        for (lane, (_, subscriber)) in subscribers.iter_mut().enumerate() {
            while let Some(message) = poll_message(subscriber) {
                delivered[lane].push(message[0]);
            }
        }
        if delivered
            .iter()
            .all(|lane| lane.len() == usize::from(MESSAGES))
        {
            break;
        }
    }
    for lane in &delivered {
        assert_eq!(
            lane,
            &(0..MESSAGES).collect::<Vec<_>>(),
            "every message, in order"
        );
    }
    // The bounds were reached, not merely unchallenged.
    assert!(fullest_read > u64::from(RX), "{fullest_read}");
    let sender = rig.agents.sender.counters();
    assert!(sender.nak_cycle_budget >= 1, "{sender:?}");
    assert!(sender.repairs >= 12, "{sender:?}");
}

/// rp-w5b's two-path rig: a routed publication over A to B and A2 to B2
/// reaches one image, bound on both paths, every message once.
#[test]
fn a_routed_publication_reaches_its_image_on_both_paths() {
    use karyos_sys::log_buffer::{AppendOptions, Role};

    let setup = Setup {
        reliable: true,
        ..Setup::default()
    };
    let (mut rig, _publishers, _subscribers) = Rig::routed(setup.again());
    let slot = established(&mut rig);
    rig.until(true, |rig| rig.agents.receiver.role.live_paths(slot) == 2);
    let mut reader = image_subscriber(&rig, slot, 0, Role::Optional);
    for i in 0..4u8 {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[i; 900], AppendOptions::default())
            .unwrap();
    }
    // Each message arrives on both paths: the subscriber reads it once.
    assert_eq!(read_messages(&mut rig, &mut reader, 4), [0, 1, 2, 3]);
    assert_eq!(rig.agents.receiver.role.live_paths(slot), 2);
}

/// The image's conductor and lane 0 subscriber, kept by a test.
type Reader = (
    karyos_sys::log_buffer::Conductor<std::sync::Arc<LogBuffer>>,
    karyos_sys::log_buffer::Subscription<std::sync::Arc<LogBuffer>>,
);

/// The two-path rig with path A2 holding `withheld` datagrams alone (path A
/// skipped them) when it leaves before sending them: no path sends them.
/// Then four more messages (100 to 103) go on path A. Returns the image's
/// lane 0 reader, attached before any message.
fn abandoned_rig(reliable: bool, withheld: u32) -> (Rig, SlotRef, Reader) {
    use karyos_sys::log_buffer::{AppendOptions, Role};

    let setup = Setup {
        reliable,
        ..Setup::default()
    };
    let (mut rig, _publishers, _subscribers) = Rig::routed(setup.again());
    let slot = established(&mut rig);
    rig.until(true, |rig| rig.agents.receiver.role.live_paths(slot) == 2);
    let reader = image_subscriber(&rig, slot, 0, Role::Optional);
    let outbound = rig.agents.sender.role.publication_mut(0).unwrap();
    outbound.withhold_route(0, withheld);
    outbound.leave_before_serve(1);
    for i in 0..u8::try_from(withheld).unwrap() {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[i; 900], AppendOptions::default())
            .unwrap();
    }
    rig.round(true);
    let counters = rig
        .agents
        .sender
        .role
        .publication_mut(0)
        .unwrap()
        .path_counters(1)
        .unwrap();
    assert_eq!(counters.exits, 1);
    assert_eq!(counters.copies_abandoned, u64::from(withheld));
    // Later data on path A shows the receivers the gap.
    for i in 0..4u8 {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[100 + i; 900], AppendOptions::default())
            .unwrap();
    }
    (rig, slot, reader)
}

/// Reads lane 0 over up to 400 rounds until `count` messages arrived (or
/// the rounds ran out), then 50 rounds more, so a duplicate would show.
fn read_messages(rig: &mut Rig, reader: &mut Reader, count: usize) -> Vec<u8> {
    let mut seen = Vec::new();
    for _ in 0..400 {
        rig.round(true);
        while let Some(message) = poll_message(&mut reader.1) {
            seen.push(message[0]);
        }
        if seen.len() >= count {
            break;
        }
    }
    for _ in 0..50 {
        rig.round(true);
        while let Some(message) = poll_message(&mut reader.1) {
            seen.push(message[0]);
        }
    }
    seen
}

/// #16835, reliable: the datagrams a leaving path held alone reach the
/// receiver by NAK from retention: every message once, in order.
#[test]
fn an_abandoned_copy_is_repaired_on_a_reliable_channel() {
    let (mut rig, slot, mut reader) = abandoned_rig(true, 2);
    let seen = read_messages(&mut rig, &mut reader, 6);
    assert_eq!(seen, [0, 1, 100, 101, 102, 103]);
    let counters = rig.agents.receiver.role.loss_counters(slot).unwrap();
    assert!(counters.repaired >= 1, "{counters:?}");
    assert!(rig.agents.sender.role.counters().naks >= 1);
    assert!(rig.agents.sender.role.counters().repairs >= 1);
}

/// rp-w6, RP-11, end to end: a datagram lost on both paths is NAKed on
/// both paths; the sender absorbs the second copy, repairs once,
/// on both paths, and the subscriber reads every message once, in order.
#[test]
fn a_repair_goes_on_both_paths_and_a_nak_copy_is_absorbed() {
    use karyos_sys::log_buffer::{AppendOptions, Role};

    let setup = Setup {
        reliable: true,
        ..Setup::default()
    };
    let (mut rig, _publishers, _subscribers) = Rig::routed(setup.again());
    let slot = established(&mut rig);
    rig.until(true, |rig| rig.agents.receiver.role.live_paths(slot) == 2);
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    let append = |rig: &mut Rig, byte: u8| {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[byte; 900], AppendOptions::default())
            .unwrap();
    };
    append(&mut rig, 0);
    rig.round(true);
    // Both copies of the next datagram are lost.
    rig.agents.receiver.role.drop_data(&[0, 1]);
    for byte in 1..5 {
        append(&mut rig, byte);
    }
    let mut seen = Vec::new();
    for _ in 0..400 {
        rig.round(true);
        while let Some(message) = poll_message(&mut subscriber) {
            seen.push(message[0]);
        }
        if seen.len() >= 5 {
            break;
        }
    }
    for _ in 0..50 {
        rig.round(true);
        while let Some(message) = poll_message(&mut subscriber) {
            seen.push(message[0]);
        }
    }
    assert_eq!(seen, [0, 1, 2, 3, 4]);
    let sender = rig.agents.sender.role.counters();
    assert!(sender.nak_copies_absorbed >= 1, "{sender:?}");
    // Absorbed copies are not NAKs admitted, nor budget drops.
    assert_eq!(sender.nak_cycle_budget, 0, "{sender:?}");
    assert!(sender.naks >= 1, "{sender:?}");
    let outbound = rig.agents.sender.role.publication_mut(0).unwrap();
    let (a, b) = (
        outbound.repair_route_counts(0).unwrap(),
        outbound.repair_route_counts(1).unwrap(),
    );
    assert!(a.submitted >= 1 && b.submitted >= 1, "{a:?} {b:?}");
}

/// #16835, unreliable: the receiver's gap policy seals the gap the
/// abandoned datagrams left, and counts it.
#[test]
fn an_abandoned_copy_is_a_sealed_gap_on_an_unreliable_channel() {
    let (mut rig, _slot, mut reader) = abandoned_rig(false, 2);
    let seen = read_messages(&mut rig, &mut reader, 4);
    // The two abandoned messages are the sealed gap; the rest arrive once.
    assert_eq!(seen, [100, 101, 102, 103]);
    assert!(rig.agents.receiver.counters().gaps_sealed >= 1);
}

/// The receiver's end of the session rings, driven by hand, and the table
/// that serves them: the chain without agents or sockets.
struct Chain<T: StreamTerms> {
    end: super::super::chain::SessionEnd<T>,
    link: SessionLink<T>,
    images: ImageTable<T>,
    events: Vec<ImageEvent>,
}

impl<T: StreamTerms> Chain<T> {
    fn new(template: ImageTemplate) -> Self {
        let (end, link) =
            super::super::chain::session_rings(std::num::NonZeroUsize::new(FULL).unwrap());
        Self {
            end,
            link,
            images: ImageTable::new(8, template),
            events: Vec::new(),
        }
    }

    /// Posts the `CreateImage` of pending slot `slot` for `lanes` lanes of
    /// 64 KiB terms, with its whole chain reserved.
    fn create(&self, slot: u32, lanes: usize) {
        let create = self.end.events.reserve().unwrap();
        let chain = ImageChain {
            command: self.end.credit.reserve().unwrap(),
            reply: self.end.events.reserve().unwrap(),
            reclaimed: self.end.credit.reserve().unwrap(),
        };
        let event = SessionEvent::CreateImage {
            endpoint: EndpointId(1),
            source: std::net::SocketAddr::from(([127, 0, 0, 1], 40_000)),
            alias: alias(),
            slot: SlotRef {
                slot,
                generation: 1,
            },
            identity: identity(),
            term: term(65_536),
            joins: Lanes::new(&vec![0u64; lanes]).unwrap(),
            chain,
        };
        assert!(self.end.events.post(create, event).is_ok());
    }

    /// Posts `event` into a fresh unit.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "used by the Linux shared tests")
    )]
    fn post(&self, event: SessionEvent) {
        let unit = self.end.events.reserve().unwrap();
        assert!(self.end.events.post(unit, event).is_ok());
    }

    /// One poll of the table over `lanes`.
    fn poll(&mut self, lanes: &mut LaneSource<'_>) {
        let events = &mut self.events;
        let _ = self
            .images
            .poll(&self.link, lanes, |event| events.push(event));
    }

    /// The receive owner and reply unit of the next `InstallImage`.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "used by the Linux shared tests")
    )]
    fn install(&self) -> (Reservation, SlotRef, Box<ReceiveOwner<T>>) {
        match self.end.commands.try_take().unwrap() {
            Some(SessionCommand::InstallImage { reply, slot, owner }) => (reply, slot, owner),
            other => panic!("{other:?}"),
        }
    }
}

/// A lane that cannot be created at the second lane of a four-lane image
/// refuses the image: `RefuseImage` is answered, `refused_storage` counted,
/// nothing charged, and the first lane is already dropped when the answer
/// is posted. Heap lanes here; the shared variant below uses regions.
#[test]
fn a_lane_that_cannot_be_created_refuses_the_whole_image() {
    let mut chain = Chain::<karyos_sys::term_bytes::HeapTerms>::new(ImageTemplate::default());
    chain.images.fail_lane = Some(1);
    chain.create(1, 4);
    chain.poll(&mut LaneSource::heap());
    assert!(matches!(
        chain.end.commands.try_take().unwrap(),
        Some(SessionCommand::RefuseImage { .. })
    ));
    let counters = chain.images.counters();
    assert_eq!((counters.refused_storage, counters.offered), (1, 0));
    assert_eq!(chain.images.charged(), 0);
    assert_eq!(chain.images.last_lanes.len(), 1, "the first lane was built");
    assert!(
        chain
            .images
            .last_lanes
            .iter()
            .all(|lane| lane.upgrade().is_none())
    );
}

/// A CreateImage still queued when the network closes is refused, with no
/// lane built: the closing source lends neither memory nor regions.
#[test]
fn a_closing_network_refuses_a_queued_image() {
    let mut chain = Chain::<karyos_sys::term_bytes::HeapTerms>::new(ImageTemplate::default());
    chain.create(1, 4);
    chain.poll(&mut LaneSource::closing());
    assert!(matches!(
        chain.end.commands.try_take().unwrap(),
        Some(SessionCommand::RefuseImage { .. })
    ));
    let counters = chain.images.counters();
    assert_eq!((counters.refused_storage, counters.offered), (1, 0));
    assert_eq!(chain.images.charged(), 0);
    assert!(chain.images.last_lanes.is_empty(), "no lane was built");
}

#[cfg(target_os = "linux")]
mod shared {
    //! The image table over the shared lane source (network-shared-terms
    //! N-2): lanes in new regions with fresh, increasing ids.

    use karyos_sys::term_bytes::SharedTerms;

    use super::*;
    use crate::admission::RegionIds;

    const INSTANCE: u128 = 0x5eed;

    fn region_ids(lanes: &[Arc<LogBuffer<SharedTerms>>]) -> Vec<u64> {
        lanes
            .iter()
            .map(|lane| lane.region().unwrap().record().region)
            .collect()
    }

    /// Install, retire and reclaim over regions: each lane is a region of
    /// the driver's instance at generation 0, ids are fresh and increase
    /// across images, and the charge returns to zero once both images are
    /// reclaimed.
    #[test]
    fn image_lanes_are_regions_installed_retired_and_reclaimed() {
        let mut next = 40u64;
        let mut chain = Chain::<SharedTerms>::new(ImageTemplate::default());
        let mut ids = Vec::new();
        for slot in [1, 2] {
            chain.create(slot, 2);
            chain.poll(&mut LaneSource::regions(RegionIds::new(
                INSTANCE, &mut next,
            )));
            let (reply, pending, owner) = chain.install();
            let installed = SlotRef {
                slot,
                generation: 2,
            };
            assert!(
                chain
                    .end
                    .events
                    .post(
                        reply,
                        SessionEvent::ImageInstalled {
                            slot: pending,
                            installed,
                            freshness: None,
                        },
                    )
                    .is_ok()
            );
            chain.poll(&mut LaneSource::regions(RegionIds::new(
                INSTANCE, &mut next,
            )));
            let lanes = chain.images.installed(installed).unwrap();
            for lane in lanes {
                let record = lane.region().unwrap().record();
                assert_eq!((record.instance, record.generation), (INSTANCE, 0));
            }
            ids.extend(region_ids(lanes));
            drop(owner);
        }
        assert_eq!(ids, vec![40, 41, 42, 43], "fresh and increasing");
        assert_eq!(next, 44);
        assert!(chain.images.charged() > 0);
        for slot in [1, 2] {
            chain.post(SessionEvent::RetireImage {
                slot: SlotRef {
                    slot,
                    generation: 2,
                },
                complete: false,
                cells: None,
            });
        }
        chain.poll(&mut LaneSource::regions(RegionIds::new(
            INSTANCE, &mut next,
        )));
        let counters = chain.images.counters();
        assert_eq!((counters.retired, counters.reclaimed), (2, 2));
        assert_eq!(chain.images.charged(), 0);
        assert!(chain.images.is_empty());
        let reclaimed = std::iter::from_fn(|| chain.end.commands.try_take().unwrap())
            .filter(|command| matches!(command, SessionCommand::StorageReclaimed { .. }))
            .count();
        assert_eq!(reclaimed, 2);
    }

    /// A region failure at the second lane of a four-lane image refuses
    /// the image, counts `refused_storage` and drops the first lane's
    /// region before the answer; the next image takes fresh ids.
    #[test]
    fn a_region_failure_refuses_the_image_and_drops_its_regions() {
        let mut next = 7u64;
        let mut chain = Chain::<SharedTerms>::new(ImageTemplate::default());
        chain.images.fail_lane = Some(1);
        chain.create(1, 4);
        chain.poll(&mut LaneSource::regions(RegionIds::new(
            INSTANCE, &mut next,
        )));
        assert!(matches!(
            chain.end.commands.try_take().unwrap(),
            Some(SessionCommand::RefuseImage { .. })
        ));
        assert_eq!(chain.images.counters().refused_storage, 1);
        assert_eq!(chain.images.charged(), 0);
        assert_eq!(chain.images.last_lanes.len(), 1, "one region was created");
        assert!(
            chain
                .images
                .last_lanes
                .iter()
                .all(|lane| lane.upgrade().is_none())
        );
        assert_eq!(next, 8, "its id is spent, never reused");
        chain.images.fail_lane = None;
        chain.create(2, 1);
        chain.poll(&mut LaneSource::regions(RegionIds::new(
            INSTANCE, &mut next,
        )));
        let (_reply, _slot, owner) = chain.install();
        drop(owner);
        assert_eq!(chain.images.counters().offered, 1);
        assert_eq!(next, 9);
    }

    /// Exhausted region ids refuse the image as storage, with nothing
    /// charged or offered.
    #[test]
    fn exhausted_region_ids_refuse_the_image() {
        let mut next = u64::MAX;
        let mut chain = Chain::<SharedTerms>::new(ImageTemplate::default());
        chain.create(1, 1);
        chain.poll(&mut LaneSource::regions(RegionIds::new(
            INSTANCE, &mut next,
        )));
        assert!(matches!(
            chain.end.commands.try_take().unwrap(),
            Some(SessionCommand::RefuseImage { .. })
        ));
        let counters = chain.images.counters();
        assert_eq!((counters.refused_storage, counters.offered), (1, 0));
        assert_eq!(chain.images.charged(), 0);
    }

    /// A shared table lent no regions (never, in an IPC driver) refuses as
    /// storage rather than building heap lanes.
    #[test]
    fn a_shared_table_without_regions_refuses_the_image() {
        let mut chain = Chain::<SharedTerms>::new(ImageTemplate::default());
        chain.create(1, 1);
        chain.poll(&mut LaneSource::heap());
        assert_eq!(chain.images.counters().refused_storage, 1);
    }

    /// The marker of the child that runs out of descriptors.
    const EMFILE_CHILD: &str = "KARYOS_IMAGES_EMFILE_CHILD";

    /// A real `Region::create` failure, not a test hook: a child of this
    /// test binary, under a small `RLIMIT_NOFILE`, runs
    /// [`a_region_that_cannot_be_created_refuses_the_image_child`]. The
    /// limit is the child's own, so no other test runs short.
    #[test]
    fn a_region_that_cannot_be_created_refuses_the_image() {
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg("ulimit -n 64 && exec \"$0\" \"$@\"")
            .arg(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "agents::images::tests::shared::a_region_that_cannot_be_created_refuses_the_image_child",
                "--test-threads=1",
            ])
            .env(EMFILE_CHILD, "1")
            .output()
            .unwrap();
        // A filter that matches nothing also exits 0: the child must have
        // run its one test.
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "{output:?}");
        assert!(stdout.contains("test result: ok. 1 passed"), "{stdout}");
    }

    /// The child: every descriptor but one is taken, so a four-lane image
    /// creates its first lane's region and fails the second's `memfd`
    /// (`EMFILE`) in `LogBuffer::create_in`. The image is refused as
    /// storage, and the first region is dropped: its descriptor is free
    /// again. A no-op outside the child.
    #[test]
    #[ignore = "run by a_region_that_cannot_be_created_refuses_the_image"]
    fn a_region_that_cannot_be_created_refuses_the_image_child() {
        if std::env::var_os(EMFILE_CHILD).is_none() {
            return;
        }
        let mut next = 1u64;
        let mut chain = Chain::<SharedTerms>::new(ImageTemplate::default());
        chain.create(1, 4);
        let mut held = Vec::new();
        loop {
            match std::fs::File::open("/dev/null") {
                Ok(file) => held.push(file),
                Err(error) => {
                    assert_eq!(error.raw_os_error(), Some(24), "EMFILE");
                    break;
                }
            }
        }
        // One descriptor free: the first lane's region takes it.
        drop(held.pop());
        chain.poll(&mut LaneSource::regions(RegionIds::new(
            INSTANCE, &mut next,
        )));
        assert!(matches!(
            chain.end.commands.try_take().unwrap(),
            Some(SessionCommand::RefuseImage { .. })
        ));
        let counters = chain.images.counters();
        assert_eq!((counters.refused_storage, counters.offered), (1, 0));
        assert_eq!(chain.images.charged(), 0);
        assert_eq!(chain.images.last_lanes.len(), 1, "one region was created");
        assert!(
            chain
                .images
                .last_lanes
                .iter()
                .all(|lane| lane.upgrade().is_none())
        );
        // Its descriptor came back with the dropped region, and only it.
        held.push(std::fs::File::open("/dev/null").unwrap());
        assert!(std::fs::File::open("/dev/null").is_err());
        assert_eq!(next, 3, "two region ids were taken, none reused");
    }
}

/// An EOS heartbeat of the rig's image naming `position` of `lane`: a
/// header-only DATA frame with the EOS flag (network-sessions.md,
/// Liveness and terminal transitions).
fn eos_heartbeat(lane: u8, position: u64) -> Vec<u8> {
    frame_at(lane, position, 0, true)
}

/// A DATA frame of the rig's image carrying `payload` bytes at `position`
/// of `lane` (none: a heartbeat), with EOS on it when `eos`.
fn frame_at(lane: u8, position: u64, payload: usize, eos: bool) -> Vec<u8> {
    use karyos_protocol::frame::{Flags, FrameType, Word0};

    let term = 65_536u64;
    let term_id = 9u32 + u32::try_from(position / term).unwrap();
    let term_offset = i32::try_from(position % term).unwrap();
    let length = 32 + payload;
    let word0 = Word0::new(
        i32::try_from(length).unwrap(),
        Flags::new(true, true, eos, false, Lane::try_new(lane).unwrap()),
        FrameType::Data,
    );
    let mut bytes = vec![0u8; length];
    bytes[..8].copy_from_slice(&word0.pack().to_le_bytes());
    bytes[8..12].copy_from_slice(&term_offset.to_le_bytes());
    bytes[12..16].copy_from_slice(&alias().session_id.to_le_bytes());
    bytes[16..20].copy_from_slice(&alias().stream_id.to_le_bytes());
    bytes[20..24].copy_from_slice(&term_id.to_le_bytes());
    bytes
}

impl Rig {
    /// Hands `bytes` to B's receiver as a DATA datagram from A, as the
    /// sender's removal linger will send it.
    fn inject(&mut self, b: EndpointId, bytes: &[u8]) {
        let source = self.endpoints.local_address(self.publisher).unwrap();
        let receiver = &mut self.agents.receiver;
        receiver
            .role
            .inject_data(&receiver.sessions, b, source, alias(), bytes, self.now);
    }

    /// Whether the image retired cleanly, at its lanes' EOS bounds.
    fn closed_cleanly(&self) -> bool {
        self.events
            .iter()
            .any(|event| matches!(event, ImageEvent::Retiring { complete: true, .. }))
    }

    /// Whether the image retired any other way.
    fn closed_otherwise(&self) -> bool {
        self.events.iter().any(|event| {
            matches!(
                event,
                ImageEvent::Retiring {
                    complete: false,
                    ..
                }
            )
        })
    }

    /// Appends `messages` on lane `lane` and runs the rig until
    /// `subscriber` read them all; returns the lane's end.
    fn deliver(
        &mut self,
        lane: usize,
        messages: &[Vec<u8>],
        subscriber: &mut karyos_sys::log_buffer::Subscription<std::sync::Arc<LogBuffer>>,
    ) -> u64 {
        use karyos_sys::log_buffer::AppendOptions;

        for message in messages {
            let log = self.log.as_mut().unwrap();
            let _ = log.publications[lane]
                .append(message, AppendOptions::default())
                .unwrap();
        }
        let mut delivered = Vec::new();
        for _ in 0..2000 {
            self.round(true);
            while let Some(message) = poll_message(subscriber) {
                delivered.push(message);
            }
            if delivered.len() == messages.len() {
                break;
            }
        }
        assert_eq!(delivered, messages);
        subscriber.position()
    }
}

/// In-order data, then an EOS heartbeat at each lane's end: the image
/// closes cleanly (`RetireImage` complete), once.
#[test]
fn eos_heartbeats_after_in_order_data_close_the_image_cleanly() {
    use karyos_sys::log_buffer::Role;

    let (mut rig, b) = Rig::new(Setup::default());
    let slot = established(&mut rig);
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    let messages: Vec<Vec<u8>> = (0..3u8).map(|i| vec![i; 900]).collect();
    let end = rig.deliver(0, &messages, &mut subscriber);
    assert_eq!(end, 3 * 960);
    rig.inject(b, &eos_heartbeat(0, end));
    rig.inject(b, &eos_heartbeat(1, 0));
    rig.until(true, Rig::closed_cleanly);
    assert!(!rig.closed_otherwise());
    let counters = rig.agents.receiver.counters();
    assert_eq!((counters.eos_bounds, counters.images_closed_eos), (2, 1));
    assert_eq!(counters.images_retired, 1);
}

/// An aggregate completes only once every lane reached its bound: the
/// first lane's EOS alone keeps the image open.
#[test]
fn an_aggregate_completes_only_when_every_lane_reaches_its_bound() {
    use karyos_sys::log_buffer::Role;

    let (mut rig, b) = Rig::new(Setup::default());
    let slot = established(&mut rig);
    let (_first, mut lane0) = image_subscriber(&rig, slot, 0, Role::Optional);
    let (_second, mut lane1) = image_subscriber(&rig, slot, 1, Role::Optional);
    let end0 = rig.deliver(0, &[vec![1; 500], vec![2; 700]], &mut lane0);
    let end1 = rig.deliver(1, &[vec![3; 300]], &mut lane1);
    rig.inject(b, &eos_heartbeat(0, end0));
    for _ in 0..50 {
        rig.round(true);
    }
    assert!(!rig.closed_cleanly() && !rig.closed_otherwise());
    rig.inject(b, &eos_heartbeat(1, end1));
    rig.until(true, Rig::closed_cleanly);
    assert_eq!(rig.agents.receiver.counters().images_closed_eos, 1);
}

/// EOS ahead of a hole does not declare it delivered: the hole is NAKed
/// and the image stays open until the repair fills it, then closes
/// cleanly.
#[test]
fn eos_ahead_of_a_hole_waits_for_its_repair() {
    use karyos_sys::log_buffer::{AppendOptions, AppendOutcome};

    let (mut rig, b) = Rig::new(Setup {
        reliable: true,
        repairs: false,
        ..Setup::default()
    });
    let _slot = established(&mut rig);
    rig.agents.receiver.role.drop_data(&[1]);
    let mut end = 0;
    for i in 0..4u8 {
        let log = rig.log.as_mut().unwrap();
        let outcome = log.publications[0]
            .append(&[i; 900], AppendOptions::default())
            .unwrap();
        let AppendOutcome::Appended { position } = outcome else {
            panic!("{outcome:?}");
        };
        end = position + 960;
    }
    rig.until(true, |rig| rig.agents.receiver.counters().naks >= 1);
    rig.inject(b, &eos_heartbeat(0, end));
    rig.inject(b, &eos_heartbeat(1, 0));
    for _ in 0..50 {
        rig.round(true);
    }
    assert_eq!(rig.agents.receiver.counters().eos_bounds, 2);
    assert!(!rig.closed_cleanly() && !rig.closed_otherwise(), "the hole");
    rig.agents.sender.heed_naks();
    rig.until(true, Rig::closed_cleanly);
    assert!(rig.agents.receiver.counters().naks >= 1);
}

/// After the bound, no later position is accepted for that lane: a frame
/// past it is dropped and counted, and never reaches a subscriber. The
/// publisher wrote past its EOS, so the image does not end clean: once
/// every lane reaches its bound it is retired, not complete.
#[test]
fn a_frame_past_the_terminal_bound_is_dropped_and_ends_the_image_unclean() {
    use karyos_sys::log_buffer::{AppendOptions, Role};

    let (mut rig, b) = Rig::new(Setup::default());
    let slot = established(&mut rig);
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    let end = rig.deliver(0, &[vec![7; 400]], &mut subscriber);
    // Lane 0 ends here; lane 1 has no bound yet, so the image stays open.
    rig.inject(b, &eos_heartbeat(0, end));
    let log = rig.log.as_mut().unwrap();
    let _ = log.publications[0]
        .append(&[8; 400], AppendOptions::default())
        .unwrap();
    rig.until(true, |rig| {
        rig.agents.receiver.counters().data_past_terminal >= 1
    });
    assert_eq!(poll_message(&mut subscriber), None);
    rig.inject(b, &eos_heartbeat(1, 0));
    rig.until(true, Rig::closed_otherwise);
    assert!(!rig.closed_cleanly(), "{:?}", rig.events);
    assert_eq!(poll_message(&mut subscriber), None);
    let counters = rig.agents.receiver.counters();
    assert_eq!(
        (
            counters.images_closed_eos,
            counters.images_closed_eos_dropped
        ),
        (0, 1)
    );
}

/// The sender repeats its EOS heartbeat during its linger: a repeat is
/// idempotent and the image closes once.
#[test]
fn a_repeated_eos_heartbeat_is_idempotent() {
    use karyos_sys::log_buffer::Role;

    let (mut rig, b) = Rig::new(Setup::default());
    let slot = established(&mut rig);
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    let end = rig.deliver(0, &[vec![5; 600]], &mut subscriber);
    for _ in 0..3 {
        rig.inject(b, &eos_heartbeat(0, end));
        rig.inject(b, &eos_heartbeat(1, 0));
    }
    let counters = rig.agents.receiver.counters();
    assert_eq!((counters.eos_bounds, counters.eos_repeated), (2, 4));
    assert_eq!(counters.eos_refused, 0);
    rig.until(true, Rig::closed_cleanly);
    for _ in 0..20 {
        rig.round(true);
    }
    let retirements = rig
        .events
        .iter()
        .filter(|event| matches!(event, ImageEvent::Retiring { .. }))
        .count();
    assert_eq!(retirements, 1);
    assert_eq!(rig.agents.receiver.counters().images_closed_eos, 1);
}

/// EOS on a message's last fragment names the bound as an EOS heartbeat
/// does: a fragmented message ends lane 0 and a whole one lane 1, and the
/// image closes cleanly with no heartbeat.
#[test]
fn eos_on_a_last_fragment_closes_the_image_like_an_eos_heartbeat() {
    use karyos_sys::log_buffer::{AppendOptions, Role};

    let (mut rig, _b) = Rig::new(Setup::default());
    let slot = established(&mut rig);
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    let eos = AppendOptions {
        end_of_stream: true,
        ..AppendOptions::default()
    };
    // Three fragments at the 1408-byte MTU.
    let fragmented = vec![9u8; 3000];
    let log = rig.log.as_mut().unwrap();
    let _ = log.publications[0].append(&fragmented, eos).unwrap();
    let _ = log.publications[1].append(&[4; 200], eos).unwrap();
    let mut delivered = None;
    for _ in 0..2000 {
        rig.round(true);
        if delivered.is_none() {
            delivered = poll_message(&mut subscriber);
        }
        if rig.closed_cleanly() {
            break;
        }
    }
    assert_eq!(delivered, Some(fragmented));
    assert!(rig.closed_cleanly(), "{:?}", rig.events);
    let counters = rig.agents.receiver.counters();
    assert_eq!((counters.eos_bounds, counters.images_closed_eos), (2, 1));
}

/// EOS on one lane, then silence: completion never comes, so the image
/// ends by liveness, retired and not complete.
#[test]
fn liveness_after_eos_before_completion_ends_the_image_unclean() {
    use karyos_sys::log_buffer::Role;

    let (mut rig, b) = Rig::new(Setup::default());
    let slot = established(&mut rig);
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    let end = rig.deliver(0, &[vec![6; 500]], &mut subscriber);
    // Lane 1 never names its bound.
    rig.inject(b, &eos_heartbeat(0, end));
    for _ in 0..50 {
        rig.round(true);
    }
    assert!(!rig.closed_cleanly() && !rig.closed_otherwise());
    rig.now += 11_000 * MS;
    rig.until(true, Rig::closed_otherwise);
    assert!(!rig.closed_cleanly(), "{:?}", rig.events);
    let counters = rig.agents.receiver.counters();
    assert_eq!((counters.eos_bounds, counters.images_closed_eos), (1, 0));
    assert_eq!(counters.images_retired, 1);
}

/// An unreliable loss sealed as a local gap, then EOS: the receiver's
/// complete prefix passes the gap, so the image reaches its bounds and
/// its lanes end at `EndOfStream`, yet the aggregate's terminal is not
/// clean, since lane 0 keeps its first loss.
#[test]
fn a_sealed_local_gap_then_eos_gives_an_unclean_aggregate() {
    use karyos_client::aggregate::{AggregateSubscription, LaneEnd};
    use karyos_client::subscription::ClientSubscription;
    use karyos_protocol::lanes::drr::{Budget, DrrConfig};
    use karyos_sys::log_buffer::{AppendOptions, AppendOutcome, Role, SealReason};

    let (mut rig, b) = Rig::new(Setup::default());
    let slot = established(&mut rig);
    let (mut first, lane0) = image_subscriber(&rig, slot, 0, Role::Optional);
    let (mut second, lane1) = image_subscriber(&rig, slot, 1, Role::Optional);
    let mut aggregate = AggregateSubscription::new(
        DrrConfig::new(&[1408, 1408], 1408).unwrap(),
        vec![
            (Lane::ZERO, ClientSubscription::new(lane0)),
            (Lane::try_new(1).unwrap(), ClientSubscription::new(lane1)),
        ],
    )
    .unwrap();
    rig.agents.receiver.role.drop_data(&[1]);
    let mut end = 0;
    for i in 0..4u8 {
        let log = rig.log.as_mut().unwrap();
        let outcome = log.publications[0]
            .append(&[i; 900], AppendOptions::default())
            .unwrap();
        let AppendOutcome::Appended { position } = outcome else {
            panic!("{outcome:?}");
        };
        end = position + 960;
    }
    rig.until(true, |rig| rig.agents.receiver.counters().gaps_sealed >= 1);
    rig.inject(b, &eos_heartbeat(0, end));
    rig.inject(b, &eos_heartbeat(1, 0));
    rig.until(true, Rig::closed_cleanly);
    // The lanes seal as the driver's image service seals them.
    for conductor in [&mut first, &mut second] {
        conductor.seal_with_reason(SealReason::EndOfStream).unwrap();
    }
    let mut delivered = Vec::new();
    let mut terminal = None;
    for _ in 0..200 {
        for conductor in [&mut first, &mut second] {
            let _ = conductor.duty_cycle().unwrap();
        }
        let poll = aggregate.poll(
            |bytes, _, _| delivered.push(bytes[0]),
            Budget {
                work: 16,
                bytes: 16 * 1408,
            },
        );
        if poll.terminal.is_some() {
            terminal = Some(poll);
            break;
        }
    }
    let poll = terminal.expect("no terminal");
    assert_eq!(delivered, [0, 2, 3]);
    assert!(!poll.terminal.unwrap().clean, "{poll:?}");
    assert!(poll.lanes[0].first_loss.is_some(), "{poll:?}");
    for lane in &poll.lanes {
        assert!(
            matches!(
                lane.end,
                Some(LaneEnd::Closed {
                    reason: SealReason::EndOfStream,
                    ..
                })
            ),
            "{lane:?}"
        );
    }
}

/// An EOS heartbeat outside the receive window, through the intake: it is
/// refused and counted, records no bound, and is no liveness evidence.
#[test]
fn an_eos_heartbeat_outside_the_window_is_refused_at_the_intake() {
    use karyos_sys::log_buffer::Role;

    let (mut rig, b) = Rig::new(Setup::default());
    let slot = established(&mut rig);
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    let end = rig.deliver(0, &[vec![2; 300]], &mut subscriber);
    let before = rig.agents.receiver.counters();
    rig.inject(b, &eos_heartbeat(0, 8 * 65_536));
    let after = rig.agents.receiver.counters();
    assert_eq!(after.eos_refused, before.eos_refused + 1);
    assert_eq!(after.eos_bounds, before.eos_bounds);
    assert_eq!(after.heartbeats_rejected, before.heartbeats_rejected + 1);
    assert_eq!(after.heartbeats, before.heartbeats, "no evidence");
    // The lane's bound is still open: the real one is recorded.
    rig.inject(b, &eos_heartbeat(0, end));
    rig.inject(b, &eos_heartbeat(1, 0));
    rig.until(true, Rig::closed_cleanly);
    assert_eq!(rig.agents.receiver.counters().eos_bounds, 2);
}

/// A second EOS heartbeat naming a different bound, inside the window,
/// through the intake: the first EOS decides, the other is refused and
/// counted and is no liveness evidence, and the image closes at the first
/// bound.
#[test]
fn a_different_eos_bound_is_refused_at_the_intake() {
    use karyos_sys::log_buffer::Role;

    let (mut rig, b) = Rig::new(Setup::default());
    let slot = established(&mut rig);
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    let end = rig.deliver(0, &[vec![3; 300]], &mut subscriber);
    rig.inject(b, &eos_heartbeat(0, end));
    let before = rig.agents.receiver.counters();
    rig.inject(b, &eos_heartbeat(0, end + 64));
    let after = rig.agents.receiver.counters();
    assert_eq!(after.eos_refused, before.eos_refused + 1);
    assert_eq!(after.heartbeats_rejected, before.heartbeats_rejected + 1);
    assert_eq!(after.heartbeats, before.heartbeats, "no evidence");
    rig.inject(b, &eos_heartbeat(1, 0));
    rig.until(true, Rig::closed_cleanly);
    let counters = rig.agents.receiver.counters();
    assert_eq!((counters.eos_bounds, counters.eos_refused), (2, 1));
}

/// rp-w8: a one-path receiver allocates no path queues and queues nothing.
#[test]
fn a_one_path_receiver_has_no_path_queues() {
    use karyos_sys::log_buffer::{AppendOptions, Role};

    let (mut rig, _b) = Rig::new(Setup {
        reliable: true,
        ..Setup::default()
    });
    let slot = established(&mut rig);
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    for i in 0..4u8 {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[i; 900], AppendOptions::default())
            .unwrap();
    }
    let mut seen = Vec::new();
    for _ in 0..200 {
        rig.round(true);
        while let Some(message) = poll_message(&mut subscriber) {
            seen.push(message[0]);
        }
        if seen.len() == 4 {
            break;
        }
    }
    assert_eq!(seen, [0, 1, 2, 3]);
    assert!(!rig.agents.receiver.role.has_path_queues());
    let counters = rig.agents.receiver.counters();
    assert_eq!(
        (counters.path_queue_drops, counters.path_queue_bypassed),
        (0, 0)
    );
}

/// rp-w8, §8 "Queues and statistics": over two paths, the path queues are
/// allocated when the later path binds. With one-entry queues, a burst
/// fills them: each full queue drops only its own path's datagram,
/// counted, and the other path's copy, or repair once later data shows
/// the gap, still delivers every message once, in order.
#[test]
fn a_full_path_queue_drops_only_its_paths_copy() {
    use karyos_sys::log_buffer::{AppendOptions, Role};

    let setup = Setup {
        reliable: true,
        tune: Some(|config: &mut AgentConfig| config.path_queue_datagrams = 1),
        ..Setup::default()
    };
    let (mut rig, _publishers, _subscribers) = Rig::routed(setup.again());
    let slot = established(&mut rig);
    rig.until(true, |rig| rig.agents.receiver.role.live_paths(slot) == 2);
    assert!(rig.agents.receiver.role.has_path_queues());
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    for i in 0..8u8 {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[i; 900], AppendOptions::default())
            .unwrap();
    }
    // Then one message every ten rounds: later data shows the receiver
    // the gaps the drops left, and repair fills them.
    let mut seen = Vec::new();
    let mut next = 8u8;
    for round in 0..600 {
        if round % 10 == 0 && next < 16 {
            let log = rig.log.as_mut().unwrap();
            let _ = log.publications[0]
                .append(&[next; 900], AppendOptions::default())
                .unwrap();
            next += 1;
        }
        rig.round(true);
        while let Some(message) = poll_message(&mut subscriber) {
            seen.push(message[0]);
        }
        if seen.len() >= 16 {
            break;
        }
    }
    for _ in 0..50 {
        rig.round(true);
        while let Some(message) = poll_message(&mut subscriber) {
            seen.push(message[0]);
        }
    }
    assert_eq!(seen, (0..16).collect::<Vec<u8>>());
    let counters = rig.agents.receiver.counters();
    assert!(counters.path_queue_drops > 0, "{counters:?}");
}

/// An EOS data frame the receive owner does not commit names no bound: a
/// frame two terms ahead of the rebuild position reads `Received::Ahead`
/// (beyond the window `{r, r + 1}`) and is dropped, and the lane's real
/// bound is still recorded afterwards.
#[test]
fn an_eos_data_frame_ahead_of_the_window_names_no_bound() {
    use karyos_sys::log_buffer::Role;

    let (mut rig, b) = Rig::new(Setup::default());
    let slot = established(&mut rig);
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    let end = rig.deliver(0, &[vec![4; 300]], &mut subscriber);
    let before = rig.agents.receiver.counters();
    rig.inject(b, &frame_at(0, 2 * 65_536, 32, true));
    let after = rig.agents.receiver.counters();
    assert_eq!(after.data_dropped, before.data_dropped + 1, "Ahead");
    assert_eq!(after.eos_bounds, before.eos_bounds, "no bound");
    rig.inject(b, &eos_heartbeat(0, end));
    rig.inject(b, &eos_heartbeat(1, 0));
    let counters = rig.agents.receiver.counters();
    assert_eq!((counters.eos_bounds, counters.eos_refused), (2, 0));
    rig.until(true, Rig::closed_cleanly);
}

/// A heartbeat past a lane's recorded bound is counted and classified at
/// the bound: no fresh evidence beyond it.
#[test]
fn a_heartbeat_past_the_terminal_bound_is_counted() {
    use karyos_sys::log_buffer::Role;

    let (mut rig, b) = Rig::new(Setup::default());
    let slot = established(&mut rig);
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    let end = rig.deliver(0, &[vec![5; 300]], &mut subscriber);
    rig.inject(b, &eos_heartbeat(0, end));
    let before = rig.agents.receiver.counters();
    rig.inject(b, &frame_at(0, end + 64, 0, false));
    let after = rig.agents.receiver.counters();
    assert_eq!(
        after.heartbeats_past_terminal,
        before.heartbeats_past_terminal + 1
    );
    assert_eq!(
        after.heartbeats, before.heartbeats,
        "classified at the bound"
    );
    assert_eq!(after.eos_refused, before.eos_refused);
}

/// rp-w8b: a receiver that has path queues still bypasses them for an
/// image with one live path. While the later path is live, the founding
/// path's datagrams are queued; once it is lost, they are not, and none is
/// bypassed for lack of a queue.
#[test]
fn a_single_path_image_bypasses_the_path_queues() {
    use karyos_sys::log_buffer::AppendOptions;

    let setup = Setup {
        reliable: true,
        ..Setup::default()
    };
    let (mut rig, _b) = Rig::new(setup.again());
    let slot = established(&mut rig);
    let _b2 = rig.second_path(&setup, announce(setup.term_length), None);
    rig.until(true, |rig| rig.agents.receiver.role.live_paths(slot) == 2);
    assert!(rig.agents.receiver.role.has_path_queues());
    let send = |rig: &mut Rig, byte: u8| {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[byte; 100], AppendOptions::default())
            .unwrap();
        for _ in 0..5 {
            rig.round(true);
        }
    };
    send(&mut rig, 0);
    assert!(
        rig.agents.receiver.counters().path_queued > 0,
        "two live paths: queued"
    );
    // The silent later path times out: one live path is left.
    for second in 1..=15u8 {
        rig.now += 1_000_000_000;
        send(&mut rig, second);
        if rig.agents.receiver.role.live_paths(slot) == 1 {
            break;
        }
    }
    assert_eq!(rig.agents.receiver.role.live_paths(slot), 1);
    let queued = rig.agents.receiver.counters().path_queued;
    for byte in 100..104u8 {
        send(&mut rig, byte);
    }
    let counters = rig.agents.receiver.counters();
    assert_eq!(counters.path_queued, queued, "one live path: bypassed");
    assert_eq!(counters.path_queue_bypassed, 0, "{counters:?}");
    assert!(rig.agents.receiver.role.has_path_queues(), "kept");
}

/// rp-w7c, §8 Liveness: an idle path kept by PATH_HB stays live. Data
/// flows every second on path A only (path A2 takes no copy: its
/// selections are skipped, too few bytes for it to leave), for 15 s, past
/// the path liveness timeout: A2 stays bound on the sender's PATH_HB
/// alone, which never counts as image evidence (RP-2).
#[test]
fn an_idle_path_kept_by_path_heartbeats_stays_live() {
    use karyos_sys::log_buffer::AppendOptions;

    let setup = Setup {
        reliable: true,
        ..Setup::default()
    };
    let (mut rig, _publishers, _subscribers) = Rig::routed(setup.again());
    let slot = established(&mut rig);
    rig.until(true, |rig| rig.agents.receiver.role.live_paths(slot) == 2);
    rig.agents
        .sender
        .role
        .publication_mut(0)
        .unwrap()
        .withhold_route(1, 1_000);
    let heartbeats = rig.agents.receiver.counters().path_heartbeats;
    for second in 0..15u8 {
        rig.now += 1_000_000_000;
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[second; 100], AppendOptions::default())
            .unwrap();
        for _ in 0..5 {
            rig.round(true);
        }
        assert_eq!(
            rig.agents.receiver.role.live_paths(slot),
            2,
            "both paths live after {} s",
            second + 1
        );
    }
    assert!(rig.agents.receiver.counters().path_heartbeats > heartbeats);
    let outbound = rig.agents.sender.role.publication_mut(0).unwrap();
    assert_eq!(
        outbound.path_state(1).map(|state| state.0),
        Some(true),
        "A2 never left"
    );
}

/// rp-w7c, §8 Join reconciliation: a later path lost (silent past its
/// liveness timeout) and bound again reconciles as a new later path: the
/// image's position does not move, and its subscriber reads every message
/// once, in order, across the loss and the rebind.
#[test]
fn a_path_lost_and_bound_again_moves_no_cursor() {
    use karyos_sys::log_buffer::{AppendOptions, Role};

    let setup = Setup {
        reliable: true,
        ..Setup::default()
    };
    let (mut rig, _b) = Rig::new(setup.again());
    let slot = established(&mut rig);
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    let _b2 = rig.second_path(&setup, announce(setup.term_length), None);
    rig.until(true, |rig| rig.agents.receiver.role.live_paths(slot) == 2);
    let mut seen = Vec::new();
    let mut next = 0u8;
    let mut send = |rig: &mut Rig, seen: &mut Vec<u8>| {
        let log = rig.log.as_mut().unwrap();
        let _ = log.publications[0]
            .append(&[next; 100], AppendOptions::default())
            .unwrap();
        next += 1;
        for _ in 0..5 {
            rig.round(true);
            while let Some(message) = poll_message(&mut subscriber) {
                seen.push(message[0]);
            }
        }
    };
    // The later path is silent: it times out while data flows.
    for _ in 0..15 {
        rig.now += 1_000_000_000;
        send(&mut rig, &mut seen);
        if rig.agents.receiver.role.live_paths(slot) == 1 {
            break;
        }
    }
    assert_eq!(rig.agents.receiver.role.live_paths(slot), 1, "B2 lost");
    // Bound again: `second_path(None)` joins at 0, not at the sender's
    // position.
    let _b2 = rig.second_path(&setup, announce(setup.term_length), None);
    rig.until(true, |rig| rig.agents.receiver.role.live_paths(slot) == 2);
    for _ in 0..4 {
        send(&mut rig, &mut seen);
    }
    assert_eq!(seen, (0..next).collect::<Vec<u8>>());
    assert!(rig.agents.receiver.role.has_image(slot));
}

/// The channel key and the pairwise key of an authenticated image (ADR-0086
/// section 4): the publisher's DATA verifies under the first, the
/// receiver's controls are sealed under the second.
fn auth_keys(receiver_id: u64) -> (crate::wire_keys::KeyFile, crate::wire_keys::KeyFile) {
    let channel = crate::wire_keys::parse(
        "3-1.key",
        b"format=karyos-wire-key-v1\nkey_id=3\nfile_epoch=1\npurpose=channel\nprofile_id=1\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret=1111111111111111111111111111111111111111111111111111111111111111\nchannel_id=7\nstream_id=6\n",
    )
    .unwrap();
    let text = format!(
        "format=karyos-wire-key-v1\nkey_id=9\nfile_epoch=1\npurpose=pairwise\nprofile_id=1\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret=2222222222222222222222222222222222222222222222222222222222222222\nreceiver_id={receiver_id}\npublisher_id=5\n"
    );
    let pairwise = crate::wire_keys::parse("9-1.key", text.as_bytes()).unwrap();
    (channel, pairwise)
}

fn auth_wall() -> u64 {
    1_795_000_000_000_000_000
}

/// `frames` sealed by `sealer` into one datagram.
fn sealed(sealer: &mut crate::wire_auth::Sealer, frames: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; frames.len() + crate::wire_auth::ENVELOPE_LEN];
    bytes[..frames.len()].copy_from_slice(frames);
    let length = sealer.seal(&mut bytes, frames.len()).unwrap();
    bytes.truncate(length);
    bytes
}

/// An established image made authenticated, its publisher silent: the
/// rig, the subscriber endpoint, the publisher's source, the image's slot
/// and its sender's and receiver's parties and keys.
struct AuthRig {
    rig: Rig,
    b: EndpointId,
    source: SocketAddr,
    slot: SlotRef,
    sender: crate::wire_auth::Party,
    receiver: crate::wire_auth::Party,
    channel: crate::wire_keys::KeyFile,
    pairwise: crate::wire_keys::KeyFile,
}

fn auth_rig() -> AuthRig {
    let (mut rig, b) = Rig::new(Setup {
        reliable: true,
        ..Setup::default()
    });
    let slot = established(&mut rig);
    rig.sender_stopped = true;
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    let receiver_id = rig.agents.receiver.role.receiver_of(slot).receiver_id;
    let (channel, pairwise) = auth_keys(receiver_id);
    let (sender, receiver) = rig
        .agents
        .receiver
        .role
        .authenticate_image(slot, &channel, &pairwise, auth_wall)
        .unwrap();
    // The controls the trusted image queued before go.
    while rig.agents.sender.role.take_control().is_some() {}
    AuthRig {
        rig,
        b,
        source,
        slot,
        sender,
        receiver,
        channel,
        pairwise,
    }
}

impl AuthRig {
    fn inject(&mut self, bytes: &[u8]) {
        let receiver = &mut self.rig.agents.receiver;
        receiver
            .role
            .inject_datagram(&receiver.sessions, self.b, self.source, bytes, self.rig.now);
    }

    fn counters(&self) -> crate::agents::roles::ReceiverCounters {
        self.rig.agents.receiver.counters()
    }

    fn sessions(&self) -> crate::sessions::receive::SessionCounters {
        self.rig.agents.receiver.role.session_counters()
    }
}

/// `after` equals `before` but for the datagram count and `changed`.
fn only_changed(
    before: crate::agents::roles::ReceiverCounters,
    mut after: crate::agents::roles::ReceiverCounters,
    changed: fn(&mut crate::agents::roles::ReceiverCounters) -> &mut u64,
    by: u64,
) {
    assert_eq!(*changed(&mut after), *changed(&mut before.clone()) + by);
    *changed(&mut after) = *changed(&mut before.clone());
    after.datagrams = before.datagrams;
    assert_eq!(after, before, "a refusal changes nothing but its counter");
}

/// ADR-0086 section 2: an authenticated image delivers only DATA that
/// opens under its key. A replayed, altered or forged envelope, a bare
/// DATA frame for it, and an envelope for no binding are each dropped and
/// counted, and change nothing else: no commit, no SOLICIT, no state.
#[test]
fn an_authenticated_image_delivers_only_datagrams_that_open_under_its_key() {
    use crate::wire_auth::Sealer;

    let mut auth = auth_rig();
    let mut sealer = Sealer::new(&auth.channel, auth.sender, alias()).unwrap();
    let first = sealed(&mut sealer, &stale_frame(9, 0, 32));
    let before = auth.counters();
    auth.inject(&first);
    let after = auth.counters();
    assert_eq!(after.data_committed, before.data_committed + 1, "{after:?}");
    assert_eq!(
        (after.auth_rejected, after.auth_bare, after.auth_unbound),
        (0, 0, 0)
    );
    let sessions = auth.sessions();
    // A replay of the same envelope: refused by the window.
    let before = auth.counters();
    auth.inject(&first);
    only_changed(before, auth.counters(), |c| &mut c.auth_rejected, 1);
    // An altered one: refused by the tag.
    let mut altered = sealed(&mut sealer, &stale_frame(9, 64, 32));
    let at = 32 + 40;
    altered[at] ^= 1;
    let before = auth.counters();
    auth.inject(&altered);
    only_changed(before, auth.counters(), |c| &mut c.auth_rejected, 1);
    // A forged one, under another key of the same key id.
    let (mut forged_channel, _) = auth_keys(1);
    if let crate::wire_keys::Material::Secret(secret) = &mut forged_channel.material {
        secret[0] ^= 0xff;
    }
    let mut forger = Sealer::new(&forged_channel, auth.sender, alias()).unwrap();
    let forged = sealed(&mut forger, &stale_frame(9, 64, 32));
    let before = auth.counters();
    auth.inject(&forged);
    only_changed(before, auth.counters(), |c| &mut c.auth_rejected, 1);
    // A bare DATA frame for the authenticated binding.
    let before = auth.counters();
    auth.inject(&stale_frame(9, 64, 32));
    only_changed(before, auth.counters(), |c| &mut c.auth_bare, 1);
    // A bare PATH_HB for it.
    let heartbeat = encoded(karyos_protocol::network::Control::PathHeartbeat(
        karyos_protocol::network::PathHeartbeat {
            alias: alias(),
            identity: identity(),
        },
    ));
    let before = auth.counters();
    auth.inject(&heartbeat);
    only_changed(before, auth.counters(), |c| &mut c.auth_bare, 1);
    // An envelope for no binding: another session, never solicited.
    let other = Alias {
        session_id: 99,
        ..alias()
    };
    let mut stranger = Sealer::new(&auth.channel, auth.sender, other).unwrap();
    let mut frame = stale_frame(9, 64, 32);
    frame[12..16].copy_from_slice(&99i32.to_le_bytes());
    let unbound = sealed(&mut stranger, &frame);
    let before = auth.counters();
    auth.inject(&unbound);
    only_changed(before, auth.counters(), |c| &mut c.auth_unbound, 1);
    assert_eq!(auth.sessions(), sessions, "no SOLICIT, no session change");
    // The next genuine envelope still delivers.
    let before = auth.counters();
    auth.inject(&sealed(&mut sealer, &stale_frame(9, 64, 32)));
    assert_eq!(auth.counters().data_committed, before.data_committed + 1);
}

/// ADR-0086 sections 2 and 7a: an authenticated image's SMs and NAKs leave
/// sealed in domain 4 and open under a verifier of the receiver's party;
/// none is handed over to go bare.
#[test]
fn an_authenticated_images_sm_and_nak_go_sealed_in_domain_4() {
    use std::sync::{Arc, Mutex};

    use karyos_io::backend::InstanceId;
    use karyos_io::sockets::endpoint::SocketsEndpoint;
    use karyos_io::sockets::scripted::ScriptedSocket;
    use karyos_protocol::network::{Control, classify};
    use karyos_protocol::protection::hmac_sha256::Domain;

    use super::super::control::{ControlItem, ControlRoutes, ControlSeal};
    use crate::wire_auth::{Sealer, Verifier};

    let mut auth = auth_rig();
    let mut sealer = Sealer::new(&auth.channel, auth.sender, alias()).unwrap();
    // A gap: position 64 arrives, 0 is lost, so a NAK falls due.
    auth.inject(&sealed(&mut sealer, &stale_frame(9, 64, 32)));
    let mut items = Vec::new();
    for _ in 0..400 {
        auth.rig.round(true);
        while let Some(item) = auth.rig.agents.sender.role.take_control() {
            items.push(item);
        }
        let kinds = |nak: bool| {
            items.iter().any(|item| {
                matches!(
                    item,
                    ControlItem::Outgoing {
                        control: Control::Nak(_),
                        ..
                    }
                ) == nak
            })
        };
        if kinds(true) && kinds(false) {
            break;
        }
    }
    let socket = ScriptedSocket::new();
    let observer = socket.observer();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    observer.set_send_hook(Box::new(move |_, datagrams| {
        for datagram in datagrams {
            record.lock().unwrap().push(datagram.to_vec());
        }
    }));
    for _ in 0..items.len() {
        observer.push_send(karyos_io::sockets::ops::SendResult::Sent {
            sent: 1,
            error: None,
        });
    }
    let config = SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
    let endpoint = SocketsEndpoint::open(&config, InstanceId::FIRST, socket).unwrap();
    let (mut tx, _rx) = endpoint.split().unwrap();
    let mut routes = ControlRoutes::new(2);
    let (mut sms, mut naks) = (0, 0);
    let mut expected = Vec::new();
    for item in items {
        let ControlItem::Outgoing {
            control,
            destination,
            seal,
            ..
        } = item
        else {
            continue;
        };
        let mut seal = seal.expect("an authenticated image's control carries its sealer");
        assert_eq!(seal.domain(), Domain::ReceiverToPublisher);
        match control {
            Control::Status(_) => sms += 1,
            Control::Nak(_) => naks += 1,
            _ => {}
        }
        routes
            .send_sealed(&mut tx, destination, &control, &mut seal)
            .unwrap();
        expected.push(control);
    }
    assert!(sms > 0 && naks > 0, "{sms} SMs, {naks} NAKs");
    let mut verifier = Verifier::new([&auth.pairwise], auth.receiver, alias()).unwrap();
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), expected.len());
    for (bytes, control) in seen.iter().zip(&expected) {
        assert!(classify(bytes).is_err(), "never bare");
        let opened = verifier.open(bytes, auth_wall()).unwrap();
        let inner = &bytes[opened.start..][..opened.frames];
        let karyos_protocol::network::Datagram::Control(decoded) = classify(inner).unwrap() else {
            panic!("not a control");
        };
        assert_eq!(&decoded, control);
    }
    let _ = auth.slot;
}

/// ADR-0086 section 7a (until the SETUP proof of slice 3b): a bare SETUP
/// ANNOUNCE or ANSWER naming an authenticated image, from another source,
/// creates no challenge, consumes none, binds no path and moves nothing
/// but `auth_bare`.
#[test]
fn a_bare_setup_never_adds_a_path_to_an_authenticated_image() {
    use karyos_protocol::network::{ChallengeBlock, Control, SetupAnswer};

    let mut auth = auth_rig();
    let other: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let boot = auth
        .rig
        .agents
        .receiver
        .role
        .receiver_of(auth.slot)
        .receiver_boot_id;
    let sessions = auth.sessions();
    let answer = SetupAnswer {
        alias: alias(),
        identity: identity(),
        term: term(65_536),
        challenge: ChallengeBlock {
            receiver_boot_id: boot,
            nonce: [1, 2],
        },
        joins: Lanes::new(&[0, 0]).unwrap(),
    };
    for (source, control) in [
        (other, Control::SetupAnnounce(announce(65_536))),
        (other, Control::SetupAnswer(answer)),
        (auth.source, Control::SetupAnnounce(announce(65_536))),
    ] {
        let before = auth.counters();
        let receiver = &mut auth.rig.agents.receiver;
        receiver
            .role
            .inject_control(&receiver.sessions, auth.b, source, control, auth.rig.now);
        only_changed(before, auth.counters(), |c| &mut c.auth_bare, 1);
        assert_eq!(
            auth.sessions(),
            sessions,
            "no challenge created or consumed"
        );
        assert!(
            auth.rig.agents.sender.role.take_control().is_none(),
            "no CHALLENGE"
        );
    }
    assert_eq!(auth.counters().paths_bound, 0);
}

/// ADR-0086 sections 2 and 6: an envelope with a valid tag whose inner
/// frames are not its binding's is refused for them without consuming its
/// sequence, so the genuine datagram of that sequence still delivers. Each
/// refusal is counted by its reason on the image's binding; an envelope
/// for no binding is counted by reason in the unattributed bucket.
#[test]
fn refusals_are_counted_by_reason_and_an_inner_refusal_consumes_nothing() {
    use crate::agents::roles::receive_auth::AuthReason;
    use crate::wire_auth::Sealer;

    let mut auth = auth_rig();
    // Two sealers of one key, both from sequence 0.
    let mut wrong = Sealer::new(&auth.channel, auth.sender, alias()).unwrap();
    let mut right = Sealer::new(&auth.channel, auth.sender, alias()).unwrap();
    let mut frame = stale_frame(9, 0, 32);
    frame[12..16].copy_from_slice(&99i32.to_le_bytes());
    let foreign = sealed(&mut wrong, &frame);
    let before = auth.counters();
    auth.inject(&foreign);
    only_changed(before, auth.counters(), |c| &mut c.auth_inner_invalid, 1);
    let genuine = sealed(&mut right, &stale_frame(9, 0, 32));
    let before = auth.counters();
    auth.inject(&genuine);
    assert_eq!(auth.counters().data_committed, before.data_committed + 1);
    // A replay and an altered tag, each in its own slot.
    auth.inject(&genuine);
    let mut altered = sealed(&mut right, &stale_frame(9, 64, 32));
    let last = altered.len() - 1;
    altered[last] ^= 1;
    auth.inject(&altered);
    let role = &auth.rig.agents.receiver.role;
    let rejections = role.auth_rejections(auth.slot).unwrap();
    assert_eq!(rejections.get(AuthReason::Inner), 1);
    assert_eq!(rejections.get(AuthReason::Duplicate), 1);
    assert_eq!(rejections.get(AuthReason::Tag), 1);
    assert_eq!(rejections.counts().iter().sum::<u64>(), 3);
    // For no binding: the unattributed bucket.
    let mut stranger = Sealer::new(
        &auth.channel,
        auth.sender,
        Alias {
            session_id: 99,
            ..alias()
        },
    )
    .unwrap();
    auth.inject(&sealed(&mut stranger, &frame));
    let unattributed = auth.rig.agents.receiver.role.unattributed_auth_rejections();
    assert_eq!(unattributed.get(AuthReason::Unbound), 1);
    assert_eq!(unattributed.counts().iter().sum::<u64>(), 1);
}

/// ADR-0086 section 7a: an authenticated image's RTTM REQUEST leaves the
/// sender's duty cycle sealed in domain 4 and opens as that REQUEST.
#[test]
fn an_authenticated_images_rttm_request_leaves_the_duty_cycle_sealed() {
    use std::sync::{Arc, Mutex};

    use karyos_io::backend::InstanceId;
    use karyos_io::sockets::endpoint::SocketsEndpoint;
    use karyos_io::sockets::scripted::ScriptedSocket;
    use karyos_protocol::network::{Control, Datagram, RttmKind, classify};

    use super::super::control::ControlItem;
    use crate::wire_auth::Verifier;

    let mut auth = auth_rig();
    let mut request = None;
    for _ in 0..2000 {
        auth.rig.round(true);
        while let Some(item) = auth.rig.agents.sender.role.take_control() {
            if let ControlItem::Outgoing {
                control: Control::Rttm(rttm),
                ..
            } = &item
                && rttm.kind == RttmKind::Request
            {
                request = Some(item);
            }
        }
        if request.is_some() {
            break;
        }
    }
    let item = request.expect("an RTTM REQUEST falls due");
    let ControlItem::Outgoing {
        control: expected, ..
    } = &item
    else {
        unreachable!()
    };
    let expected = *expected;
    let socket = ScriptedSocket::new();
    let observer = socket.observer();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    observer.set_send_hook(Box::new(move |_, datagrams| {
        for datagram in datagrams {
            record.lock().unwrap().push(datagram.to_vec());
        }
    }));
    observer.push_send(karyos_io::sockets::ops::SendResult::Sent {
        sent: 1,
        error: None,
    });
    let config = SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
    let endpoint = SocketsEndpoint::open(&config, InstanceId::FIRST, socket).unwrap();
    let (tx, _rx) = endpoint.split().unwrap();
    // On an endpoint the sender has no cached route for: the rig's own
    // halves are real sockets.
    let ControlItem::Outgoing {
        destination,
        control,
        guard,
        seal,
        ..
    } = item
    else {
        unreachable!()
    };
    assert!(seal.is_some(), "it carries the image's sealer");
    let on = EndpointId(77);
    let mut halves = vec![(on, super::super::Half::Tx(Box::new(tx)))];
    auth.rig
        .agents
        .receiver
        .role
        .post_to_sender(ControlItem::Outgoing {
            endpoint: on,
            destination,
            control,
            guard,
            seal,
        });
    let now = auth.rig.now;
    let _ = auth.rig.agents.sender.role.duty(&mut halves, now).unwrap();
    let seen = seen.lock().unwrap();
    assert_eq!(
        seen.len(),
        1,
        "sent once: {:?}",
        auth.rig.agents.sender.role.counters()
    );
    assert!(classify(&seen[0]).is_err(), "never bare");
    let mut verifier = Verifier::new([&auth.pairwise], auth.receiver, alias()).unwrap();
    let opened = verifier.open(&seen[0], auth_wall()).unwrap();
    let Datagram::Control(decoded) = classify(&seen[0][opened.start..][..opened.frames]).unwrap()
    else {
        panic!("not a control");
    };
    assert_eq!(decoded, expected);
}

/// A rig whose publication on A and subscription on B (as receiver 77)
/// are authenticated, on the channel and pairwise keys returned, before
/// any traffic.
fn authenticated_rig() -> (Rig, EndpointId, crate::wire_keys::KeyFile) {
    use crate::agents::roles::publish_auth::PublicationAuth;
    use crate::agents::roles::receive_auth::SubscriptionAuth;

    let (mut rig, b) = Rig::new(Setup {
        auth: true,
        reliable: true,
        identity: Some(identity_77(0)),
        ..Setup::default()
    });
    let (channel, pairwise) = auth_keys(77);
    let a = rig.publisher;
    rig.agents.receiver.role.authenticate_published(a, alias());
    rig.agents.receiver.role.authenticate_subscription(
        SubscriptionAuth::new(b, alias(), &channel, &pairwise, 77).unwrap(),
    );
    rig.agents.sender.role.authenticate_publication(
        PublicationAuth::new(a, alias(), identity(), 2, &channel, &[&pairwise]).unwrap(),
    );
    (rig, b, channel)
}

/// ADR-0086 sections 2, 4, 7 and 7a, end to end on unicast: the SETUP
/// ANNOUNCE and ANSWER verify under the channel's SETUP proof, the
/// CHALLENGE under the pair's RSP_SETUP proof and the publisher rule, the
/// publication's session sealer is installed for the receiver's boot id
/// and nonce, its SMs and RTTM probes verify in domain 4, and every DATA
/// datagram is delivered sealed: nothing is refused on either side, and
/// RTTM REPLYs (domain 1) are matched.
#[test]
fn an_authenticated_publisher_and_receiver_establish_and_deliver() {
    use karyos_sys::log_buffer::{AppendOptions, Role};

    let (mut rig, _b, _channel) = authenticated_rig();
    let slot = established(&mut rig);
    let boot = rig.agents.receiver.role.receiver_of(slot).receiver_boot_id;
    let party = rig.agents.sender.role.outbound(0).unwrap().sealer_party();
    let Some(crate::wire_auth::Party::Sender {
        identity: sealed_for,
        lane_count,
        receiver_boot_id,
        ..
    }) = party
    else {
        panic!("the session sealer is installed: {party:?}");
    };
    assert_eq!(
        (sealed_for, lane_count, receiver_boot_id),
        (identity(), 2, boot)
    );
    assert!(
        rig.agents.receiver.role.auth_rejections(slot).is_some(),
        "the image is authenticated"
    );
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    let messages: Vec<Vec<u8>> = (0..10u8)
        .map(|i| vec![i; 100 + usize::from(i) * 90])
        .collect();
    for message in &messages {
        let _ = rig.log.as_mut().unwrap().publications[0]
            .append(message, AppendOptions::default())
            .unwrap();
    }
    let mut delivered = Vec::new();
    for _ in 0..3000 {
        rig.round(true);
        while let Some(message) = poll_message(&mut subscriber) {
            delivered.push(message);
        }
        if delivered.len() == messages.len() && rig.agents.receiver.counters().rttm_samples > 0 {
            break;
        }
    }
    assert_eq!(delivered, messages);
    let receiver = rig.agents.receiver.counters();
    let sender = rig.agents.sender.role.counters();
    assert!(receiver.data_committed >= 10, "{receiver:?}");
    assert!(receiver.rttm_samples > 0, "a domain 1 RTTM REPLY matched");
    assert_eq!(
        (
            receiver.auth_rejected,
            receiver.auth_bare,
            receiver.auth_unbound,
            receiver.auth_inner_invalid,
            receiver.auth_install_refused,
        ),
        (0, 0, 0, 0, 0),
        "{receiver:?}"
    );
    assert_eq!(
        (sender.auth_rejected, sender.auth_bare, sender.auth_unbound),
        (0, 0, 0),
        "{sender:?}"
    );
    assert_eq!(sender.auth_sealers_installed, 1);
}

/// ADR-0086 section 2: a bare SETUP ANNOUNCE for an authenticated
/// subscription creates no challenge; the trusted rig, with nothing
/// authenticated, establishes as before.
#[test]
fn a_bare_announce_for_an_authenticated_subscription_is_refused() {
    use karyos_protocol::network::Control;

    let (mut rig, b, _channel) = authenticated_rig();
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    let sessions = rig.agents.receiver.role.session_counters();
    let before = rig.agents.receiver.counters();
    let receiver = &mut rig.agents.receiver;
    receiver.role.inject_control(
        &receiver.sessions,
        b,
        source,
        Control::SetupAnnounce(announce(65_536)),
        rig.now,
    );
    only_changed(
        before,
        rig.agents.receiver.counters(),
        |c| &mut c.auth_bare,
        1,
    );
    assert_eq!(rig.agents.receiver.role.session_counters(), sessions);
}

/// #648 acceptance, ADR-0086 domains 3 and 4 (design sections 5 and 6),
/// end to end on two endpoints: a SESSION_ABORT signed by the
/// publication's abort authority closes the receiver's authenticated
/// image, whose SESSION_ABORT_ACK, sealed in domain 4, verifies at the
/// publisher. The identical datagram again hits the digest cache: the ACK
/// is resent and nothing transitions twice. A forged abort changes
/// nothing.
#[test]
fn a_remote_session_abort_closes_the_image_and_is_acknowledged_in_domain_4() {
    use crate::agents::roles::publish_auth::AbortAuthority;
    use crate::authority::Ed25519Signer;
    use crate::signed_control::Authority;

    let (mut rig, b, _channel) = authenticated_rig();
    let signer = Ed25519Signer::from_seed(&[9; 32]);
    let verifier = signer.verifier();
    let a = rig.publisher;
    rig.agents
        .sender
        .role
        .set_abort_authority(a, alias(), AbortAuthority::new(signer, 10, 10));
    rig.agents
        .receiver
        .role
        .trust_authorities(vec![Authority::of(10, verifier, 10, &[11], true)], rig.now);
    rig.agents.receiver.role.permit_abort(
        b,
        alias().stream_id,
        crate::agents::roles::AbortScope {
            authority_id: 10,
            guard_id: 11,
        },
    );
    let slot = established(&mut rig);
    // H8 finding 5: the guard that closed, not 0, which GUARD_CLOSED
    // refuses to encode.
    assert!(rig.agents.sender.role.request_abort(
        a,
        alias(),
        karyos_protocol::network::authenticated::GUARD_CLOSED,
        11,
        3
    ));
    for _ in 0..400 {
        rig.round(true);
        if rig.agents.sender.role.counters().abort_acks == 1 {
            break;
        }
    }
    let receiver = rig.agents.receiver.counters();
    let sender = rig.agents.sender.role.counters();
    assert_eq!(
        (
            receiver.images_closed_aborted,
            receiver.abort_acks_sent,
            receiver.signed_refused
        ),
        (1, 1, 0),
        "{receiver:?}"
    );
    assert_eq!(
        (
            sender.aborts_sent,
            sender.abort_acks,
            sender.aborts_completed
        ),
        (1, 1, 1),
        "{sender:?}"
    );
    assert_eq!(
        rig.agents.sender.role.pending_aborts(),
        0,
        "retired on completion"
    );
    let ack = rig.agents.sender.role.last_abort_ack().unwrap();
    assert_eq!((ack.guard_epoch, ack.receiver.receiver_id), (3, 77));
    assert_eq!(
        (ack.identity, ack.alias, ack.lanes.count()),
        (identity(), alias(), 2)
    );
    assert!(
        rig.agents.receiver.role.auth_rejections(slot).is_none(),
        "the image is gone"
    );
    // The identical SESSION_ABORT again: the cached ACK is resent.
    let bytes = rig.agents.sender.role.last_abort_bytes().unwrap();
    let source = rig.endpoints.local_address(a).unwrap();
    rig.round(true);
    let receiver = &mut rig.agents.receiver;
    receiver
        .role
        .inject_datagram(&receiver.sessions, b, source, &bytes, rig.now);
    for _ in 0..400 {
        rig.round(true);
        if rig.agents.sender.role.counters().abort_acks == 2 {
            break;
        }
    }
    let receiver = rig.agents.receiver.counters();
    assert_eq!(
        (receiver.images_closed_aborted, receiver.abort_acks_resent),
        (1, 1),
        "{receiver:?}"
    );
    assert_eq!(rig.agents.sender.role.counters().abort_acks, 2);
    assert_eq!(rig.agents.sender.role.counters().abort_acks_unmatched, 1);
    // H8 finding 8: the identical datagram from another source is no
    // cache hit, and finds no binding.
    let before = rig.agents.receiver.counters();
    let other: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let receiver = &mut rig.agents.receiver;
    receiver
        .role
        .inject_datagram(&receiver.sessions, b, other, &bytes, rig.now);
    let after = rig.agents.receiver.counters();
    assert_eq!(after.abort_acks_resent, before.abort_acks_resent);
    assert_eq!(after.aborts_refused, before.aborts_refused + 1);
    // A forged one: refused by its signature, nothing else.
    let mut forged = bytes.clone();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    rig.round(true);
    let before = rig.agents.receiver.counters();
    let receiver = &mut rig.agents.receiver;
    receiver
        .role
        .inject_datagram(&receiver.sessions, b, source, &forged, rig.now);
    let after = rig.agents.receiver.counters();
    assert_eq!(after.signed_refused, before.signed_refused + 1);
    assert_eq!(after.images_closed_aborted, 1);
}

/// An authenticated rig whose receiver trusts two abort-capable
/// authorities, 10 (guards 11 and 12) and 20 (guard 21), and admits
/// remote aborts of the publication per `scope`; established.
fn abort_rig(scope: Option<crate::agents::roles::AbortScope>) -> (Rig, EndpointId, SlotRef) {
    use crate::authority::Ed25519Signer;
    use crate::signed_control::Authority;

    let (mut rig, b, _channel) = authenticated_rig();
    rig.agents.receiver.role.trust_authorities(
        vec![
            Authority::of(
                10,
                Ed25519Signer::from_seed(&[9; 32]).verifier(),
                10,
                &[11, 12],
                true,
            ),
            Authority::of(
                20,
                Ed25519Signer::from_seed(&[8; 32]).verifier(),
                20,
                &[21],
                true,
            ),
        ],
        rig.now,
    );
    if let Some(scope) = scope {
        rig.agents
            .receiver
            .role
            .permit_abort(b, alias().stream_id, scope);
    }
    let slot = established(&mut rig);
    (rig, b, slot)
}

/// A SESSION_ABORT of the rig's publication signed by authority
/// `authority_id` (seed 9 for 10, 8 for 20).
fn signed_abort(authority_id: u64, guard_id: u64, reason: u16) -> Vec<u8> {
    use crate::agents::roles::publish_auth::AbortAuthority;
    use crate::authority::Ed25519Signer;
    use karyos_protocol::network::authenticated::SessionAbort;

    let seed = if authority_id == 10 { 9 } else { 8 };
    let key_id = u32::try_from(authority_id).unwrap();
    let mut signer =
        AbortAuthority::new(Ed25519Signer::from_seed(&[seed; 32]), key_id, authority_id);
    let mut bytes = vec![0u8; 256];
    let length = signer
        .sign(
            &SessionAbort {
                alias: alias(),
                identity: identity(),
                authority_id,
                guard_id,
                guard_epoch: 3,
                reason,
            },
            &mut bytes,
        )
        .unwrap();
    bytes.truncate(length);
    bytes
}

/// Injects `bytes` at the receiver from the publisher; returns the
/// counters after.
fn inject_abort(
    rig: &mut Rig,
    b: EndpointId,
    bytes: &[u8],
) -> crate::agents::roles::ReceiverCounters {
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    // The publisher's reserved verify budget refills between aborts.
    rig.now += 300 * MS;
    rig.round(true);
    let receiver = &mut rig.agents.receiver;
    receiver
        .role
        .inject_datagram(&receiver.sessions, b, source, bytes, rig.now);
    rig.agents.receiver.counters()
}

/// H8 finding 1, ADR-0118: a remote abort is admitted only from the
/// authority that guards the publication. Another trusted abort-capable
/// authority, the right authority under another of its guards, and a
/// GUARD_CLOSED under another guard are each refused before any state
/// changes and counted; the guarding authority's GUARD_CLOSED applies.
#[test]
fn only_the_guarding_authority_may_abort_a_publication() {
    use karyos_protocol::network::authenticated::GUARD_CLOSED;

    let scope = crate::agents::roles::AbortScope {
        authority_id: 10,
        guard_id: 11,
    };
    let (mut rig, b, slot) = abort_rig(Some(scope));
    for (authority, guard, reason) in [
        (20, 21, GUARD_CLOSED),
        (20, 0, 2),
        (10, 12, GUARD_CLOSED),
        (10, 12, 2),
    ] {
        let before = rig.agents.receiver.counters();
        let after = inject_abort(&mut rig, b, &signed_abort(authority, guard, reason));
        assert_eq!(
            (after.aborts_out_of_scope, after.abort_acks_sent),
            (before.aborts_out_of_scope + 1, before.abort_acks_sent),
            "{authority} {guard} {reason}"
        );
        assert!(
            rig.agents.receiver.role.auth_rejections(slot).is_some(),
            "still bound"
        );
    }
    let after = inject_abort(&mut rig, b, &signed_abort(10, 11, GUARD_CLOSED));
    assert_eq!(after.abort_acks_sent, 1, "{after:?}");
}

/// H8 finding 1, ADR-0118: another reason may name guard 0, but only
/// from the guarding authority.
#[test]
fn a_non_guard_abort_with_guard_zero_comes_only_from_the_guarding_authority() {
    let scope = crate::agents::roles::AbortScope {
        authority_id: 10,
        guard_id: 11,
    };
    let (mut rig, b, _slot) = abort_rig(Some(scope));
    let after = inject_abort(&mut rig, b, &signed_abort(20, 0, 2));
    assert_eq!((after.aborts_out_of_scope, after.abort_acks_sent), (1, 0));
    let after = inject_abort(&mut rig, b, &signed_abort(10, 0, 2));
    assert_eq!((after.aborts_out_of_scope, after.abort_acks_sent), (1, 1));
}

/// H8 finding 1, ADR-0118: a publication admitted with no guard accepts
/// no remote abort, even from a trusted abort-capable authority.
#[test]
fn an_unguarded_publication_accepts_no_remote_abort() {
    use karyos_protocol::network::authenticated::GUARD_CLOSED;

    let (mut rig, b, slot) = abort_rig(None);
    for (authority, guard, reason) in [(10, 11, GUARD_CLOSED), (10, 0, 2), (20, 0, 2)] {
        let _ = inject_abort(&mut rig, b, &signed_abort(authority, guard, reason));
    }
    let after = rig.agents.receiver.counters();
    assert_eq!((after.aborts_out_of_scope, after.abort_acks_sent), (3, 0));
    assert!(rig.agents.receiver.role.auth_rejections(slot).is_some());
}

/// H8 finding 2: once an abort is applied the image is terminal. A valid
/// DATA envelope still in flight when the abort lands, opened under the
/// image's key, is dropped before the receive owner and moves nothing:
/// before the fix it was committed past the ACK's prefix.
#[test]
fn data_after_an_applied_abort_is_dropped() {
    use crate::authority::Ed25519Signer;
    use crate::signed_control::Authority;
    use crate::wire_auth::Sealer;
    use karyos_protocol::network::authenticated::GUARD_CLOSED;

    let (mut rig, b) = Rig::new(Setup {
        reliable: true,
        ..Setup::default()
    });
    let slot = established(&mut rig);
    rig.sender_stopped = true;
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    let receiver_id = rig.agents.receiver.role.receiver_of(slot).receiver_id;
    let (channel, pairwise) = auth_keys(receiver_id);
    rig.agents.receiver.role.trust_authorities(
        vec![Authority::of(
            10,
            Ed25519Signer::from_seed(&[9; 32]).verifier(),
            10,
            &[11],
            true,
        )],
        rig.now,
    );
    rig.agents.receiver.role.permit_abort(
        b,
        alias().stream_id,
        crate::agents::roles::AbortScope {
            authority_id: 10,
            guard_id: 11,
        },
    );
    let (sender, _) = rig
        .agents
        .receiver
        .role
        .authenticate_image(slot, &channel, &pairwise, auth_wall)
        .unwrap();
    let mut sealer = Sealer::new(&channel, sender, alias()).unwrap();
    let inject = |rig: &mut Rig, bytes: &[u8]| {
        let receiver = &mut rig.agents.receiver;
        receiver
            .role
            .inject_datagram(&receiver.sessions, b, source, bytes, rig.now);
        rig.agents.receiver.counters()
    };
    let first = sealed(&mut sealer, &stale_frame(9, 0, 32));
    let in_flight = sealed(&mut sealer, &stale_frame(9, 64, 32));
    let before = rig.agents.receiver.counters();
    let after = inject(&mut rig, &first);
    assert_eq!(after.data_committed, before.data_committed + 1);
    let after = inject(&mut rig, &signed_abort(10, 11, GUARD_CLOSED));
    assert_eq!(after.abort_acks_sent, 1, "{after:?}");
    let before = after;
    let after = inject(&mut rig, &in_flight);
    assert_eq!(after.data_committed, before.data_committed, "{after:?}");
    assert_eq!(after.data_after_abort, before.data_after_abort + 1);
}

/// H8 finding 5: an unacknowledged abort is resent identically on the
/// backoff, an ACK that does not match it is dropped, and at its expiry
/// the session is reported interrupted and the record retired.
#[test]
fn an_unacknowledged_abort_is_resent_then_reported_interrupted() {
    use crate::agents::roles::publish_auth::AbortAuthority;
    use crate::authority::Ed25519Signer;
    use karyos_protocol::network::Receiver;
    use karyos_protocol::network::authenticated::{AbortAck, AckLane, GUARD_CLOSED};

    let (mut rig, _b, _channel) = authenticated_rig();
    let a = rig.publisher;
    rig.agents.sender.role.set_abort_authority(
        a,
        alias(),
        AbortAuthority::new(Ed25519Signer::from_seed(&[9; 32]), 10, 10),
    );
    let _slot = established(&mut rig);
    rig.agents.sender.role.set_abort_expiry(200 * MS);
    assert!(
        rig.agents
            .sender
            .role
            .request_abort(a, alias(), GUARD_CLOSED, 11, 3)
    );
    assert!(
        rig.agents
            .sender
            .role
            .request_abort(a, alias(), GUARD_CLOSED, 11, 3),
        "the same, once"
    );
    assert!(
        !rig.agents
            .sender
            .role
            .request_abort(a, alias(), GUARD_CLOSED, 11, 4),
        "another epoch"
    );
    rig.round(true);
    let first = rig.agents.sender.role.last_abort_bytes().unwrap();
    for _ in 0..40 {
        rig.round(true);
    }
    let sender = rig.agents.sender.role.counters();
    assert_eq!(sender.aborts_sent, 1);
    assert!(sender.aborts_resent >= 2, "{sender:?}");
    assert_eq!(
        rig.agents.sender.role.last_abort_bytes().unwrap(),
        first,
        "identical"
    );
    // An ACK of another epoch, then one past what was submitted: dropped.
    let ack = |guard_epoch, delivered| AbortAck {
        alias: alias(),
        identity: identity(),
        receiver: Receiver {
            receiver_boot_id: [1, 1],
            receiver_id: 77,
        },
        guard_epoch,
        lanes: Lanes::new(
            &[AckLane {
                delivered,
                unresolved_end: delivered,
            }; 2],
        )
        .unwrap(),
    };
    rig.agents.sender.role.abort_acked_for(a, &ack(4, 0));
    rig.agents
        .sender
        .role
        .abort_acked_for(a, &ack(3, u64::MAX / 2));
    assert_eq!(rig.agents.sender.role.counters().abort_acks_invalid, 2);
    assert_eq!(rig.agents.sender.role.pending_aborts(), 1);
    for _ in 0..200 {
        rig.round(true);
    }
    let sender = rig.agents.sender.role.counters();
    assert_eq!(sender.aborts_interrupted, 1, "{sender:?}");
    assert_eq!(rig.agents.sender.role.pending_aborts(), 0);
}

/// Marks in memory, for a followed guard.
#[derive(Debug, Default)]
struct MemoryMarks(std::collections::HashMap<u64, u64>);

impl crate::remote_guard::MarkStore for MemoryMarks {
    fn load(&self, guard_id: u64) -> Result<u64, crate::remote_guard::MarkError> {
        Ok(self.0.get(&guard_id).copied().unwrap_or(0))
    }

    fn latched(&self, _: u64) -> Result<bool, crate::remote_guard::MarkError> {
        Ok(false)
    }

    fn persist(&mut self, guard_id: u64, epoch: u64) -> Result<(), crate::remote_guard::MarkError> {
        let held = self.0.entry(guard_id).or_insert(0);
        *held = (*held).max(epoch);
        Ok(())
    }

    fn latch(&mut self, _: u64) -> Result<(), crate::remote_guard::MarkError> {
        Ok(())
    }
}

/// ADR-0086 section 7 and design 4.4, through the receiver's intake: a
/// followed guard starts closed and challenges; a signed `Open` STATE
/// before recovery is discarded; the signed STATUS answering its own
/// challenge recovers it open; a bare GUARD stays gated.
#[test]
fn a_followed_guard_recovers_only_through_its_own_challenge() {
    use karyos_protocol::network::authenticated::{
        AuthControl, GuardState, GuardStatus, GuardWord,
    };
    use karyos_protocol::protection::signed::{SignedBinding, SignedDomain, seal_signed};

    use super::super::control::ControlItem;
    use crate::authority::Ed25519Signer;
    use crate::remote_guard::{Phase, RemoteGuard};
    use crate::signed_control::Authority;

    let (mut rig, b) = Rig::new(Setup::default());
    rig.sender_stopped = true;
    let signer = Ed25519Signer::from_seed(&[9; 32]);
    let authority: SocketAddr = "127.0.0.1:9".parse().unwrap();
    rig.agents.receiver.role.trust_authorities(
        vec![Authority::of(10, signer.verifier(), 10, &[11], false)],
        0,
    );
    rig.agents.receiver.role.follow_guard(
        RemoteGuard::new(10, 11, 0),
        66,
        b,
        authority,
        Box::new(MemoryMarks::default()),
        None,
    );
    let sign = |control: AuthControl, seq: u64| {
        let mut bytes = vec![0u8; 256];
        let body = control.encode(&mut bytes).unwrap();
        let binding = SignedBinding {
            domain: SignedDomain::Guard,
            party_epoch: 0,
            session_id: 0,
            stream_id: 0,
            key_id: 10,
        };
        let length = seal_signed(&mut bytes, body, &binding, seq, &signer).unwrap();
        bytes.truncate(length);
        bytes
    };
    rig.round(true);
    // The challenge, bare, to the authority's address.
    let mut challenge = None;
    while let Some(item) = rig.agents.sender.role.take_control() {
        if let ControlItem::Raw {
            destination, bytes, ..
        } = item
            && destination == authority
        {
            let decoded =
                karyos_protocol::network::authenticated::decode_bare_status_challenge(bytes.get())
                    .unwrap();
            challenge = Some(decoded);
        }
    }
    let challenge = challenge.expect("a recovering guard challenges");
    assert_eq!(challenge.receiver.receiver_id, 66);
    let source: SocketAddr = "127.0.0.1:10".parse().unwrap();
    let state = sign(
        AuthControl::State(GuardState {
            authority_id: 10,
            guard_id: 11,
            word: GuardWord::from_epoch(4).unwrap(),
            lifetime_ms: 5_000,
        }),
        0,
    );
    let inject = |rig: &mut Rig, bytes: &[u8]| {
        rig.round(true);
        let receiver = &mut rig.agents.receiver;
        receiver
            .role
            .inject_datagram(&receiver.sessions, b, source, bytes, rig.now);
    };
    inject(&mut rig, &state);
    assert_eq!(rig.agents.receiver.counters().guard_refused, 1);
    assert_eq!(
        rig.agents.receiver.role.guard_phase(11, rig.now),
        Some(Phase::Recovering)
    );
    // A bare one stays gated: never decoded.
    let mut bare = vec![0u8; 256];
    let length = AuthControl::State(GuardState {
        authority_id: 10,
        guard_id: 11,
        word: GuardWord::from_epoch(4).unwrap(),
        lifetime_ms: 5_000,
    })
    .encode(&mut bare)
    .unwrap();
    bare.truncate(length);
    let decode_errors = rig.agents.receiver.counters().decode_errors;
    inject(&mut rig, &bare);
    assert_eq!(
        rig.agents.receiver.counters().decode_errors,
        decode_errors + 1
    );
    let status = sign(
        AuthControl::Status(GuardStatus {
            authority_id: 10,
            guard_id: 11,
            receiver: challenge.receiver,
            nonce: challenge.nonce,
            word: GuardWord::from_epoch(4).unwrap(),
        }),
        1,
    );
    inject(&mut rig, &status);
    assert_eq!(rig.agents.receiver.counters().guard_changes, 1);
    assert!(matches!(
        rig.agents.receiver.role.guard_phase(11, rig.now),
        Some(Phase::Open { epoch: 4, .. })
    ));
}

/// A heap guard word in `state`.
fn guard_word(epoch: u64, open: bool) -> std::sync::Arc<karyos_client::HeapWords> {
    let word = std::sync::Arc::new(karyos_client::HeapWords::zeroed(1));
    set_word(&word, epoch, open);
    word
}

fn set_word(word: &karyos_client::HeapWords, epoch: u64, open: bool) {
    word.words()[0].store(
        karyos_sys::guard::encode(karyos_sys::guard::GuardState { epoch, open }).unwrap(),
        karyos_sys::sync::Ordering::Release,
    );
}

/// A rig whose publication on A is guarded by guard 11 of authority 10,
/// which A's driver follows as receiver 66 through a mirror word: the
/// publication is admission-pending until that word first reads open.
/// With `authority`, B's driver is that authority, its guard word
/// `authority`, answering A's challenges. `marks` are the follower's
/// durable marks. Returns the rig, B's address and the authority's signer.
fn remotely_guarded_rig(
    marks: MemoryMarks,
    authority: Option<std::sync::Arc<karyos_client::HeapWords>>,
) -> (Rig, SocketAddr, crate::authority::Ed25519Signer) {
    use std::sync::Arc;

    use karyos_sys::applied_epoch::AppliedEpoch;

    use crate::authority::Ed25519Signer;
    use crate::guard_authority::{AuthorityGuard, GuardAuthority};
    use crate::remote_guard::RemoteGuard;
    use crate::signed_control::Authority;

    let mirror = guard_word(1, false);
    let (mut rig, b) = Rig::new(Setup {
        remote_guard: Some(super::super::data::GuardSpec {
            word: Arc::clone(&mirror) as Arc<dyn karyos_client::SharedWords>,
            cell: Arc::new(AppliedEpoch::new()),
            // Ignored: admission binds the epoch the guard first opens at.
            epoch: 0,
            empty_since: None,
            rate: None,
            reserve: None,
            policy: None,
            frontier: Default::default(),
        }),
        ..Setup::default()
    });
    let a = rig.publisher;
    let a_at = rig.endpoints.local_address(a).unwrap();
    let b_at = rig.endpoints.local_address(b).unwrap();
    let signer = Ed25519Signer::from_seed(&[9; 32]);
    let receiver = &mut rig.agents.receiver.role;
    receiver.trust_authorities(
        vec![Authority::of(10, signer.verifier(), 10, &[11], false)],
        0,
    );
    let guard = RemoteGuard::load(10, 11, &marks);
    receiver.follow_guard(guard, 66, a, b_at, Box::new(marks), Some(mirror));
    if let Some(word) = authority {
        let guards = vec![AuthorityGuard {
            guard_id: 11,
            word: word as Arc<dyn karyos_client::SharedWords>,
            lifetime_ms: 5_000,
            receivers: vec![(66, a_at)],
        }];
        receiver.set_guard_authority(Some(
            GuardAuthority::new(
                10,
                10,
                Ed25519Signer::from_seed(&[9; 32]),
                guards,
                Box::new(MemoryMarks::default()),
                0,
            )
            .unwrap(),
        ));
    }
    (rig, b_at, signer)
}

/// A GUARD STATE of guard 11 signed by `signer`.
fn signed_state(signer: &crate::authority::Ed25519Signer, epoch: u64, seq: u64) -> Vec<u8> {
    use karyos_protocol::network::authenticated::{AuthControl, GuardState, GuardWord};
    use karyos_protocol::protection::signed::{SignedBinding, SignedDomain, seal_signed};

    let mut bytes = vec![0u8; 256];
    let body = AuthControl::State(GuardState {
        authority_id: 10,
        guard_id: 11,
        word: GuardWord::from_epoch(epoch).unwrap(),
        lifetime_ms: 5_000,
    })
    .encode(&mut bytes)
    .unwrap();
    let binding = SignedBinding {
        domain: SignedDomain::Guard,
        party_epoch: 0,
        session_id: 0,
        stream_id: 0,
        key_id: 10,
    };
    let length = seal_signed(&mut bytes, body, &binding, seq, signer).unwrap();
    bytes.truncate(length);
    bytes
}

/// Injects `bytes` into A's driver from `from`, after a round.
fn inject_at_a(rig: &mut Rig, from: SocketAddr, bytes: &[u8]) {
    rig.round(true);
    let a = rig.publisher;
    let receiver = &mut rig.agents.receiver;
    receiver
        .role
        .inject_datagram(&receiver.sessions, a, from, bytes, rig.now);
}

/// Appends one message and runs `rounds` rounds; returns how many DATA
/// frames the receiver committed meanwhile.
fn send_one(rig: &mut Rig, rounds: usize) -> u64 {
    use karyos_sys::log_buffer::AppendOptions;

    let before = rig.agents.receiver.counters().data_committed;
    let _ = rig.log.as_mut().unwrap().publications[0]
        .append(&[3; 100], AppendOptions::default())
        .unwrap();
    for _ in 0..rounds {
        rig.round(true);
    }
    rig.agents.receiver.counters().data_committed - before
}

/// guards-and-abort.md, "The sender gate and applied epoch", step 3, with
/// a remote guard (ADR-0086 section 7, design 4.4): before the guard is
/// recovered and confirmed the publication is not admitted and sends
/// nothing, its waits counted; with no authority answering it stays so.
#[test]
fn a_remotely_guarded_publication_sends_nothing_before_recovery() {
    use crate::remote_guard::Phase;

    let (mut rig, _b_at, _signer) = remotely_guarded_rig(MemoryMarks::default(), None);
    let _slot = established(&mut rig);
    assert_eq!(send_one(&mut rig, 200), 0);
    assert_eq!(
        rig.agents.receiver.role.guard_phase(11, rig.now),
        Some(Phase::Recovering)
    );
    let outbound = rig.agents.sender.role.outbound(0).unwrap();
    assert!(outbound.admission_pending(), "admission-pending");
    assert!(outbound.guard_gate().is_none(), "no incarnation is bound");
    assert!(outbound.counters().admission_waits > 0);
    assert!(rig.agents.receiver.counters().guard_challenges >= 1);
}

/// Step 3 with a remote guard: the publication is admitted at the epoch
/// the authority's STATUS opens the guard at and sends; a signed `Closed`
/// STATE then aborts the incarnation for good, and a later reopen of the
/// guard (a higher open epoch, confirmed) does not resume it.
#[test]
fn a_remotely_guarded_publication_is_admitted_on_the_status_and_aborted_for_good_on_a_close() {
    use crate::remote_guard::Phase;

    let authority = guard_word(2, true);
    let (mut rig, b_at, signer) = remotely_guarded_rig(
        MemoryMarks::default(),
        Some(std::sync::Arc::clone(&authority)),
    );
    let _slot = established(&mut rig);
    rig.until(true, |rig| {
        matches!(
            rig.agents.receiver.role.guard_phase(11, rig.now),
            Some(Phase::Open { epoch: 2, .. })
        )
    });
    assert!(send_one(&mut rig, 100) >= 1, "admitted and sending");
    let outbound = rig.agents.sender.role.outbound(0).unwrap();
    assert!(!outbound.admission_pending() && outbound.guard_gate().is_some());
    // The authority closes; its STATE is pushed to A.
    set_word(&authority, 3, false);
    inject_at_a(&mut rig, b_at, &signed_state(&signer, 3, 0));
    assert_eq!(
        rig.agents.receiver.role.guard_phase(11, rig.now),
        Some(Phase::Closed)
    );
    assert_eq!(send_one(&mut rig, 100), 0, "nothing after the close");
    let gate = rig
        .agents
        .sender
        .role
        .outbound(0)
        .unwrap()
        .guard_gate()
        .unwrap();
    assert!(gate.counts().aborted >= 1, "the incarnation aborted");
    // The authority reopens at 4; A confirms it, and still nothing goes.
    set_word(&authority, 4, true);
    inject_at_a(&mut rig, b_at, &signed_state(&signer, 4, 1));
    rig.until(true, |rig| {
        matches!(
            rig.agents.receiver.role.guard_phase(11, rig.now),
            Some(Phase::Open { epoch: 4, .. })
        )
    });
    assert_eq!(send_one(&mut rig, 100), 0, "a reopen does not resume it");
}

/// Step 3 with a remote guard: with the authority silent the `Open`
/// lapses one lifetime after its last confirmation, and the admitted
/// incarnation aborts for good.
#[test]
fn a_remote_guard_that_lapses_aborts_its_incarnation() {
    use crate::remote_guard::Phase;

    let (mut rig, _b_at, _signer) =
        remotely_guarded_rig(MemoryMarks::default(), Some(guard_word(2, true)));
    let _slot = established(&mut rig);
    rig.until(true, |rig| {
        matches!(
            rig.agents.receiver.role.guard_phase(11, rig.now),
            Some(Phase::Open { .. })
        )
    });
    assert!(send_one(&mut rig, 100) >= 1);
    rig.agents.receiver.role.set_guard_authority(None);
    rig.now += 6_000 * MS;
    rig.round(true);
    assert_eq!(
        rig.agents.receiver.role.guard_phase(11, rig.now),
        Some(Phase::Closed)
    );
    assert_eq!(send_one(&mut rig, 100), 0, "nothing after the lapse");
    let gate = rig
        .agents
        .sender
        .role
        .outbound(0)
        .unwrap()
        .guard_gate()
        .unwrap();
    assert!(gate.counts().aborted >= 1, "the incarnation aborted");
}

/// ADR-0086 section 7: after a restart the stored mark refuses an old
/// OPEN: an authority restored below it latches the guard closed, the old
/// signed `Open` STATE is refused, and the publication is never admitted.
#[test]
fn a_restart_with_the_stored_mark_refuses_an_old_open() {
    use crate::remote_guard::Phase;

    let mut marks = MemoryMarks::default();
    marks.0.insert(11, 4);
    let (mut rig, b_at, signer) = remotely_guarded_rig(marks, Some(guard_word(2, true)));
    let _slot = established(&mut rig);
    rig.until(true, |rig| {
        rig.agents.receiver.role.guard_phase(11, rig.now) == Some(Phase::Latched)
    });
    let refused = rig.agents.receiver.counters().guard_refused;
    let receiver = &mut rig.agents.receiver;
    let a = rig.publisher;
    receiver.role.inject_datagram(
        &receiver.sessions,
        a,
        b_at,
        &signed_state(&signer, 2, 0),
        rig.now,
    );
    assert_eq!(rig.agents.receiver.counters().guard_refused, refused + 1);
    assert_eq!(send_one(&mut rig, 200), 0);
    assert!(
        rig.agents
            .sender
            .role
            .outbound(0)
            .unwrap()
            .admission_pending()
    );
}

/// The channel key and the pairwise key of an encrypted channel (ADR-0114
/// section 4a, `profile_id=16`).
fn enc_keys(receiver_id: u64) -> (crate::wire_keys::KeyFile, crate::wire_keys::KeyFile) {
    let channel = crate::wire_keys::parse(
        "3-1.key",
        b"format=karyos-wire-key-v1\nkey_id=3\nfile_epoch=1\npurpose=channel\nprofile_id=16\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret=3333333333333333333333333333333333333333333333333333333333333333\nchannel_id=7\nstream_id=6\n",
    )
    .unwrap();
    let text = format!(
        "format=karyos-wire-key-v1\nkey_id=9\nfile_epoch=1\npurpose=pairwise\nprofile_id=16\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret=4444444444444444444444444444444444444444444444444444444444444444\nreceiver_id={receiver_id}\npublisher_id=5\n"
    );
    let pairwise = crate::wire_keys::parse("9-1.key", text.as_bytes()).unwrap();
    (channel, pairwise)
}

/// A rig whose publication on A and subscription on B (as receiver 77)
/// are encrypted before any DATA. The class still fails at channel parse:
/// only this test constructor makes them encrypted.
fn encrypted_rig() -> (Rig, EndpointId) {
    use crate::agents::roles::publish_enc::PublicationEnc;
    use crate::agents::roles::receive_enc::SubscriptionEnc;

    let (mut rig, b) = Rig::new(Setup {
        reliable: true,
        identity: Some(identity_77(0)),
        ..Setup::default()
    });
    let (channel, pairwise) = enc_keys(77);
    let a = rig.publisher;
    rig.agents.receiver.role.encrypt_published(a, alias());
    rig.agents.receiver.role.encrypt_subscription(
        SubscriptionEnc::new(b, alias().stream_id, &[&channel], &[&pairwise], 77).unwrap(),
    );
    rig.agents.sender.role.encrypt_publication(
        PublicationEnc::new(
            a,
            alias(),
            identity(),
            &[&channel],
            &[&pairwise],
            crate::wire_enc::monotonic_ns,
        )
        .unwrap(),
    );
    // The publication arrives with the first duty; it is made encrypted
    // before any DATA is staged.
    rig.agents.do_work(rig.now).unwrap();
    rig.agents
        .sender
        .role
        .outbound_mut(0)
        .unwrap()
        .require_enc()
        .unwrap();
    (rig, b)
}

/// Appends `messages` and runs the rig until they are delivered or 600
/// rounds pass; returns what was delivered.
fn enc_deliver(
    rig: &mut Rig,
    subscriber: &mut karyos_sys::log_buffer::Subscription<std::sync::Arc<LogBuffer>>,
    messages: &[Vec<u8>],
) -> Vec<Vec<u8>> {
    use karyos_sys::log_buffer::AppendOptions;

    for message in messages {
        let _ = rig.log.as_mut().unwrap().publications[0]
            .append(message, AppendOptions::default())
            .unwrap();
    }
    let mut delivered = Vec::new();
    for _ in 0..600 {
        rig.round(true);
        while let Some(message) = poll_message(subscriber) {
            delivered.push(message);
        }
        if delivered.len() == messages.len() {
            break;
        }
    }
    delivered
}

/// H8 finding 4: a revoked key (here every key: the store disabled) stops
/// an encrypted publication. Its domain 1 sealer is withdrawn, its key
/// erased, and nothing more is delivered; its bound receiver's domain 4
/// opener is withdrawn, so no SM is accepted any more.
#[test]
fn a_revoked_key_stops_an_encrypted_publication() {
    use karyos_sys::log_buffer::Role;

    let (mut rig, _b) = encrypted_rig();
    let slot = established(&mut rig);
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    let first: Vec<Vec<u8>> = (0..4u8).map(|i| vec![i; 100]).collect();
    assert_eq!(enc_deliver(&mut rig, &mut subscriber, &first), first);
    rig.agents
        .sender
        .role
        .apply_keys(&crate::wire_auth::FixedKeys::default());
    let second: Vec<Vec<u8>> = (4..8u8).map(|i| vec![i; 100]).collect();
    assert!(enc_deliver(&mut rig, &mut subscriber, &second).is_empty());
    let accepted = rig.agents.sender.role.counters().sm_accepted;
    for _ in 0..200 {
        rig.round(true);
    }
    assert_eq!(rig.agents.sender.role.counters().sm_accepted, accepted);
}

/// H8 finding 4: a revoked key stops an encrypted image: its domain 1
/// opener refuses the publisher's DATA, and its domain 4 controls (SMs),
/// sealed by a withdrawn key shared with the sender agent, are no longer
/// sent, so the publisher accepts none.
#[test]
fn a_revoked_key_stops_an_encrypted_images_controls() {
    use karyos_sys::log_buffer::Role;

    let (mut rig, _b) = encrypted_rig();
    let slot = established(&mut rig);
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    let first: Vec<Vec<u8>> = (0..4u8).map(|i| vec![i; 100]).collect();
    assert_eq!(enc_deliver(&mut rig, &mut subscriber, &first), first);
    rig.agents
        .receiver
        .role
        .apply_keys(&crate::wire_auth::FixedKeys::default());
    let second: Vec<Vec<u8>> = (4..8u8).map(|i| vec![i; 100]).collect();
    assert!(enc_deliver(&mut rig, &mut subscriber, &second).is_empty());
    let accepted = rig.agents.sender.role.counters().sm_accepted;
    for _ in 0..200 {
        rig.round(true);
    }
    assert_eq!(rig.agents.sender.role.counters().sm_accepted, accepted);
}

/// ADR-0114 sections 4 to 9 and 6b end to end on unicast (#650): the
/// SETUP ANNOUNCE opens in domain 5, the CHALLENGE in domain 6 with its
/// pairwise trailer, the ANSWER is an ENC ANSWER (variant 3), every DATA
/// datagram is sealed in domain 1 and delivered, and the SMs, sealed in
/// domain 4, come back and are accepted. Then the publisher moves two
/// epochs on: the receiver sees DATA more than one epoch ahead, sends a
/// SOLICIT in domain 6, and the ENC ANSWER that echoes it resynchronises
/// the binding to the stated pair; delivery resumes. Nothing is refused
/// for its tag, trailer or class on either side.
#[test]
fn an_encrypted_publisher_and_receiver_establish_deliver_and_resynchronise() {
    use karyos_protocol::protection::aes_gcm_siv::EncRejection;
    use karyos_sys::log_buffer::{AppendOptions, Role};

    let (mut rig, b) = encrypted_rig();
    let a = rig.publisher;
    let slot = established(&mut rig);
    assert_eq!(
        rig.agents.receiver.role.enc_epochs(slot),
        Some((1, 0)),
        "the image is encrypted at the answer's epochs"
    );
    assert!(
        rig.agents.sender.role.counters().sm_accepted > 0,
        "an SM came back in domain 4"
    );
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    let deliver =
        |rig: &mut Rig,
         subscriber: &mut karyos_sys::log_buffer::Subscription<std::sync::Arc<LogBuffer>>,
         messages: &[Vec<u8>]| {
            for message in messages {
                let _ = rig.log.as_mut().unwrap().publications[0]
                    .append(message, AppendOptions::default())
                    .unwrap();
            }
            let mut delivered = Vec::new();
            for _ in 0..3000 {
                rig.round(true);
                while let Some(message) = poll_message(subscriber) {
                    delivered.push(message);
                }
                if delivered.len() == messages.len() {
                    break;
                }
            }
            delivered
        };
    let first: Vec<Vec<u8>> = (0..10u8)
        .map(|i| vec![i; 100 + usize::from(i) * 60])
        .collect();
    assert_eq!(deliver(&mut rig, &mut subscriber, &first), first);
    // The publisher's session sealer moves two epochs on: the receiver
    // cannot follow without a resynchronisation.
    rig.agents
        .sender
        .role
        .outbound_mut(0)
        .unwrap()
        .roll_enc_epochs(2);
    let second: Vec<Vec<u8>> = (10..20u8).map(|i| vec![i; 200]).collect();
    assert_eq!(deliver(&mut rig, &mut subscriber, &second), second);
    assert_eq!(
        rig.agents.receiver.role.enc_epochs(slot),
        Some((1, 2)),
        "resynchronised to the stated pair"
    );
    let receiver = rig
        .agents
        .receiver
        .role
        .enc_rejections(b, alias().stream_id)
        .unwrap();
    assert!(
        receiver.get(EncRejection::Epoch) > 0,
        "DATA ahead was refused first"
    );
    for reason in [
        EncRejection::Tag,
        EncRejection::Pairwise,
        EncRejection::MixedClass,
        EncRejection::InnerRejected,
        EncRejection::ResyncRefused,
    ] {
        assert_eq!(receiver.get(reason), 0, "{reason:?}: {receiver:?}");
    }
    let sender = rig.agents.sender.role.enc_rejections(a, alias()).unwrap();
    assert_eq!(sender.total(), 0, "{sender:?}");
}
