// SPDX-License-Identifier: Apache-2.0

//! The image chain over real loopback sockets (phase 4b-2): an accepted
//! answer becomes an installed image; a late `ImageReady` is released; a
//! refused geometry removes the challenge.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::net::SocketAddr;
use std::time::Duration;

use karyos_io::sockets::OsSocket;
use karyos_io::sockets::endpoint::SocketsConfig;
use karyos_protocol::network::{Alias, Identity, Lanes, TermParams};

use super::super::endpoints::{EndpointEvent, Endpoints};
use super::super::{AgentCommand, AgentConfig, AgentLinks, NetworkAgents, network_agents};
use super::*;
use crate::sessions::send::Publication;

type Agents = NetworkAgents<OsSocket>;
type Links = AgentLinks<OsSocket>;

const MS: u64 = 1_000_000;

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

fn term() -> TermParams {
    TermParams {
        term_length: 65_536,
        initial_term_id: 9,
        mtu: 1408,
    }
}

struct Rig {
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
    fn new() -> (Self, EndpointId) {
        let config = AgentConfig::default();
        let (agents, links) = network_agents::<OsSocket>(config).unwrap();
        let mut rig = Self {
            agents,
            links,
            endpoints: Endpoints::new(&config),
            images: ImageTable::new(config.sessions.max_images, ImageTemplate::default()),
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
        let mut opened = 0;
        for _ in 0..100 {
            rig.agents.do_work(0).unwrap();
            rig.endpoints.poll(
                &rig.links,
                |event| opened += usize::from(matches!(event, EndpointEvent::Opened(_))),
                |_| {},
            );
            if opened == 2 {
                break;
            }
        }
        assert_eq!(opened, 2);
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
            })
            .unwrap();
        rig.links
            .sender
            .post(|reply| AgentCommand::AddPublication {
                reply,
                publication: Publication {
                    endpoint: a,
                    alias: alias(),
                    identity: identity(),
                    term: term(),
                    lane_count: 2,
                },
                destination,
                joins: Lanes::new(&[64, 128]).unwrap(),
            })
            .unwrap();
        (rig, b)
    }

    /// One round: the agents, then the conductor's tables; `post` lets the
    /// image table post its pending commands.
    fn round(&mut self, post: bool) {
        self.now += MS;
        self.agents.do_work(self.now).unwrap();
        let images = &mut self.images;
        let events = &mut self.events;
        self.endpoints.poll(
            &self.links,
            |_| {},
            |event| {
                let _ = images.handle(event, |image| events.push(image));
            },
        );
        if post {
            self.images.post(&self.links);
        }
        std::thread::sleep(Duration::from_micros(200));
    }

    fn until(&mut self, post: bool, done: impl Fn(&Self) -> bool) {
        for _ in 0..2000 {
            self.round(post);
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
/// attach.
#[test]
fn an_accepted_answer_installs_an_image() {
    let (mut rig, b) = Rig::new();
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
    for (lane, join) in lanes.iter().zip([64, 128]) {
        assert!(matches!(
            lane.config().publication,
            PublicationMode::Image { join: at, .. } if at == join
        ));
    }
    assert!(rig.agents.receiver.role.has_image(*slot));
}

/// A conductor slower than the challenge: `ImageReady` after the timeout
/// is released; nothing is bound and the storage is freed.
#[test]
fn a_late_image_ready_is_released() {
    let (mut rig, _b) = Rig::new();
    // The image is allocated but its `InstallImage` held back.
    rig.until(false, |rig| rig.images.len() == 1);
    rig.now += 2_000 * MS;
    rig.until(true, |rig| !rig.events.is_empty());
    assert!(matches!(
        rig.events.as_slice(),
        [ImageEvent::Released { .. }]
    ));
    assert!(rig.images.is_empty());
}

/// A geometry the log buffer refuses (a term length that is not a power of
/// two) is answered `RefuseImage`; the receiver removes the challenge.
#[test]
fn a_refused_geometry_is_reported() {
    let config = AgentConfig::default();
    let (mut agents, links) = network_agents::<OsSocket>(config).unwrap();
    let mut images = ImageTable::new(4, ImageTemplate::default());
    let slot = SlotRef {
        slot: 0,
        generation: 0,
    };
    let bad = TermParams {
        term_length: 65_537,
        ..term()
    };
    let event = AgentEvent::<OsSocket>::CreateImage {
        endpoint: EndpointId(1),
        alias: alias(),
        slot,
        identity: identity(),
        term: bad,
        joins: Lanes::new(&[0]).unwrap(),
    };
    assert!(images.handle(event, |_| {}).is_none());
    images.post(&links);
    agents.do_work(0).unwrap();
    let mut events = Vec::new();
    while let Some(event) = links.receiver.take_event() {
        let _ = images.handle(event, |image| events.push(image));
    }
    assert_eq!(events, [ImageEvent::Refused { slot }]);
    assert!(images.is_empty());
}
