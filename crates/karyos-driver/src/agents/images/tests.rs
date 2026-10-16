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
use karyos_protocol::network::{Alias, Identity, Lanes, TermParams};

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
#[derive(Clone, Copy)]
struct Setup {
    /// The publication's term length.
    term_length: u32,
    /// The subscription's `max_image_term_length`.
    max_term_length: u32,
    template: ImageTemplate,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            term_length: 65_536,
            max_term_length: DEFAULT_MAX_IMAGE_TERM_LENGTH,
            template: ImageTemplate::default(),
        }
    }
}

struct Rig {
    /// The publishing endpoint A.
    publisher: EndpointId,
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
        let config = AgentConfig::default();
        let (agents, links) = network_agents::<OsSocket>(config).unwrap();
        let mut rig = Self {
            publisher: EndpointId(u32::MAX),
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
        rig.publisher = a;
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
                    term: term(setup.term_length),
                    lane_count: 2,
                },
                destination,
                joins: Lanes::new(&[64, 128]).unwrap(),
            })
            .unwrap();
        (rig, b)
    }

    /// One round: the agents, then the conductor's tables; `serve` lets the
    /// image table serve the session ring.
    fn round(&mut self, serve: bool) {
        self.now += MS;
        self.agents.do_work(self.now).unwrap();
        self.endpoints.poll(&self.links, |_| {}, |_| {});
        if serve {
            let events = &mut self.events;
            self.images
                .poll(&self.links.sessions, |image| events.push(image));
        }
        std::thread::sleep(Duration::from_micros(200));
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
    for (lane, join) in lanes.iter().zip([64, 128]) {
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
        },
        SessionEvent::ImageInstalled {
            slot: pending,
            installed,
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
