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
    /// Whether the channel is reliable: the sender is then a required
    /// participant of its log.
    reliable: bool,
    /// The receiver's `alias_quarantine`, when not the default.
    alias_quarantine: Option<u64>,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            term_length: 65_536,
            max_term_length: DEFAULT_MAX_IMAGE_TERM_LENGTH,
            template: ImageTemplate::default(),
            reliable: false,
            alias_quarantine: None,
        }
    }
}

struct Rig {
    /// The publishing endpoint A.
    publisher: EndpointId,
    /// The publication's log on A (64 KiB terms, whatever is announced).
    log: Option<super::super::data::testing::TestLog>,
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
        let (agents, links) = network_agents::<OsSocket>(config).unwrap();
        let mut rig = Self {
            publisher: EndpointId(u32::MAX),
            log: None,
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
                rig.now,
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
                reliable: setup.reliable,
            })
            .unwrap();
        // The log's terms stay small: a refused size is only announced.
        let (outbound, log) = super::super::data::testing::outbound(
            a,
            alias(),
            destination,
            term(65_536),
            2,
            setup.reliable,
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
            })
            .unwrap();
        (rig, b)
    }

    /// One round: the agents, then the conductor's tables; `serve` lets the
    /// image table serve the session ring.
    fn round(&mut self, serve: bool) {
        self.now += MS;
        // The publication's conductor: rotation, floor and limit.
        if let Some(log) = &mut self.log {
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
