// SPDX-License-Identifier: Apache-2.0

//! The establishment control path over real loopback sockets (phase 4b-1):
//! announce, challenge, answer, `CreateImage`; a spoofed SOLICIT flood
//! capped by `setup_answer_rate`; the receiver's filters, rates and drop
//! counters; and the sender's control routes across a reset.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use karyos_io::sockets::OsSocket;
use karyos_io::sockets::endpoint::SocketsConfig;
use karyos_protocol::network::{
    Alias, ChallengeBlock, Control, Identity, Lanes, MAX_CONTROL_LENGTH, RspSolicit, TermParams,
};

use super::super::endpoints::{EndpointEvent, Endpoints};
use super::super::{
    AgentCommand, AgentConfig, AgentEvent, AgentLinks, EndpointId, NetworkAgents, network_agents,
};
use crate::sessions::send::Publication;

type Agents = NetworkAgents<OsSocket>;
type Links = AgentLinks<OsSocket>;

fn loopback() -> SocketsConfig {
    SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)))
}

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

/// Two loopback endpoints, opened and attached: (agents, links, table, A,
/// B).
fn two_endpoints() -> (Agents, Links, Endpoints<OsSocket>, EndpointId, EndpointId) {
    two_endpoints_with(AgentConfig::default())
}

fn two_endpoints_with(
    config: AgentConfig,
) -> (Agents, Links, Endpoints<OsSocket>, EndpointId, EndpointId) {
    let (mut agents, links) = network_agents::<OsSocket>(config).unwrap();
    let mut endpoints = Endpoints::new(&config);
    // One at a time: a single event slot holds one answer.
    let open = |agents: &mut Agents, endpoints: &mut Endpoints<OsSocket>| {
        let id = endpoints.open(&links, loopback(), OsSocket::new()).unwrap();
        for _ in 0..100 {
            agents.do_work(0).unwrap();
            let mut opened = false;
            endpoints.poll(
                &links,
                |event| opened |= event == EndpointEvent::Opened(id),
                |_| {},
            );
            if opened {
                return id;
            }
        }
        panic!("endpoint did not open");
    };
    let a = open(&mut agents, &mut endpoints);
    let b = open(&mut agents, &mut endpoints);
    (agents, links, endpoints, a, b)
}

/// Drives the agents until `found` returns a value, with the clock moving
/// 1 ms per round.
fn drive<T>(
    agents: &mut Agents,
    links: &Links,
    endpoints: &mut Endpoints<OsSocket>,
    mut found: impl FnMut(AgentEvent<OsSocket>) -> Option<T>,
) -> T {
    let mut now = 0u64;
    for _ in 0..2000 {
        now += 1_000_000;
        agents.do_work(now).unwrap();
        let mut hit = None;
        endpoints.poll(
            links,
            |_| {},
            |event| {
                if hit.is_none() {
                    hit = found(event);
                }
            },
        );
        if let Some(hit) = hit {
            return hit;
        }
        std::thread::sleep(Duration::from_micros(200));
    }
    panic!("not reached");
}

/// Drives the agents until the receiver posts `CreateImage` on the session
/// ring: (endpoint, identity, joins).
fn created(
    agents: &mut Agents,
    links: &Links,
    endpoints: &mut Endpoints<OsSocket>,
) -> (EndpointId, Identity, Lanes<u64>) {
    let mut now = 0u64;
    for _ in 0..2000 {
        now += 1_000_000;
        agents.do_work(now).unwrap();
        endpoints.poll(links, |_| {}, |_| {});
        if let Some(super::super::chain::SessionEvent::CreateImage {
            endpoint,
            identity,
            joins,
            ..
        }) = links.sessions.take_event()
        {
            return (endpoint, identity, joins);
        }
        std::thread::sleep(Duration::from_micros(200));
    }
    panic!("no CreateImage");
}

/// The publication on A announced to B: the sender's publication, A's
/// published alias and B's subscription.
#[must_use = "the publication's log lives as long as its handles"]
fn add_publication(
    links: &Links,
    a: EndpointId,
    b: EndpointId,
    destination: SocketAddr,
) -> super::super::data::testing::TestLog {
    links
        .receiver
        .post(|reply| AgentCommand::AddPublishedAlias {
            reply,
            endpoint: a,
            alias: alias(),
        })
        .unwrap();
    links
        .receiver
        .post(|reply| AgentCommand::AddSubscription {
            reply,
            endpoint: b,
            stream_id: alias().stream_id,
            max_term_length: super::super::images::DEFAULT_MAX_IMAGE_TERM_LENGTH,
        })
        .unwrap();
    let (outbound, log) = outbound(a, destination);
    links
        .sender
        .post(|reply| AgentCommand::AddPublication {
            reply,
            publication: publication(a),
            outbound,
        })
        .unwrap();
    log
}

/// The one-lane test publication's data path on `endpoint`.
fn outbound(
    endpoint: EndpointId,
    destination: SocketAddr,
) -> (
    Box<super::super::data::Outbound>,
    super::super::data::testing::TestLog,
) {
    super::super::data::testing::outbound(
        endpoint,
        alias(),
        destination,
        publication(endpoint).term,
        1,
        false,
    )
}

fn publication(endpoint: EndpointId) -> Publication {
    Publication {
        endpoint,
        alias: alias(),
        identity: identity(),
        term: TermParams {
            term_length: 65_536,
            initial_term_id: 9,
            mtu: 1408,
        },
        lane_count: 1,
    }
}

/// The sender announces from A to B; B's receiver challenges A; A's
/// receiver hands the challenge to the sender, which answers toward B; B's
/// receiver accepts it and asks the conductor for the image.
#[test]
fn a_loopback_setup_reaches_create_image() {
    let (mut agents, links, mut endpoints, a, b) = two_endpoints();
    let destination = endpoints.local_address(b).unwrap();
    let _log = add_publication(&links, a, b, destination);
    let created = created(&mut agents, &links, &mut endpoints);
    assert_eq!(created, (b, identity(), Lanes::new(&[0]).unwrap()));
    assert_eq!(agents.receiver.counters().create_image, 1);
    assert!(
        agents.sender.counters().sent >= 3,
        "announce, challenge, answer"
    );
}

/// A spoofed SOLICIT flood at A: the sender answers at most
/// `setup_answer_rate` (20) of them, toward the channel destination, and
/// counts the rest.
#[test]
fn a_solicit_flood_is_capped() {
    let (mut agents, links, mut endpoints, a, b) = two_endpoints();
    let destination = endpoints.local_address(b).unwrap();
    let _log = add_publication(&links, a, b, destination);
    drive(&mut agents, &links, &mut endpoints, |event| match event {
        AgentEvent::PublicationAdded { .. } => Some(()),
        _ => None,
    });
    let spoofer = UdpSocket::bind("127.0.0.1:0").unwrap();
    let target = endpoints.local_address(a).unwrap();
    let mut bytes = [0u8; MAX_CONTROL_LENGTH];
    let solicit = Control::Solicit(RspSolicit {
        alias: alias(),
        challenge: ChallengeBlock {
            receiver_boot_id: [7, 8],
            nonce: [9, 9],
        },
    });
    let length = solicit.encode(&mut bytes).unwrap();
    for _ in 0..100 {
        spoofer.send_to(&bytes[..length], target).unwrap();
    }
    // Long enough for every datagram to be read, short enough (the clock
    // moves 1 ms per round) to refill only a few tokens.
    for round in 1..=40u64 {
        agents.do_work(round * 1_000).unwrap();
        endpoints.poll(&links, |_| {}, |_| {});
        std::thread::sleep(Duration::from_millis(1));
    }
    let refused = agents.sender.counters().refused;
    assert!(refused >= 79, "refused {refused} of 100");
    assert!(agents.receiver.counters().forwarded >= 99);
}

/// Condition (1), §7.3 and §6.2: an ANSWER to a CHALLENGE on a multicast
/// channel goes to the group (the channel's route), never to the spoofable
/// source of the CHALLENGE.
#[test]
fn a_multicast_answer_goes_to_the_group() {
    let (mut sender, _receiver) = super::roles(&AgentConfig::default()).unwrap();
    let group: SocketAddr = "239.1.1.1:40456".parse().unwrap();
    let publication = Publication {
        endpoint: EndpointId(1),
        alias: alias(),
        identity: identity(),
        term: TermParams {
            term_length: 65_536,
            initial_term_id: 9,
            mtu: 1408,
        },
        lane_count: 1,
    };
    sender.sessions.add(publication).unwrap();
    let (path, _log) = outbound(EndpointId(1), group);
    sender.publications.push(*path);
    let challenge = Control::Challenge(karyos_protocol::network::RspChallenge {
        alias: alias(),
        identity: identity(),
        challenge: ChallengeBlock {
            receiver_boot_id: [7, 8],
            nonce: [9, 9],
        },
    });
    let spoofed: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    let (destination, answer) = sender
        .answer_for(EndpointId(1), spoofed, 0, challenge)
        .unwrap();
    assert_eq!(destination, group);
    assert!(matches!(answer, Control::SetupAnswer(_)));
}

/// Condition (1), §7.3: an RSP_SETUP answers only a unicast source with a
/// nonzero port.
#[test]
fn only_unicast_sources_are_answerable() {
    for (source, answerable) in [
        ("10.0.0.1:4000", true),
        ("[::1]:4000", true),
        ("10.0.0.1:0", false),
        ("239.1.1.1:4000", false),
        ("255.255.255.255:4000", false),
        ("0.0.0.0:4000", false),
        ("[ff02::1]:4000", false),
        ("[::]:4000", false),
        ("[::ffff:10.0.0.1]:4000", true),
        ("[::ffff:239.1.1.1]:4000", false),
        ("[::ffff:255.255.255.255]:4000", false),
        ("[::ffff:0.0.0.0]:4000", false),
    ] {
        assert_eq!(
            super::answerable(source.parse().unwrap()),
            answerable,
            "{source}"
        );
    }
}

/// Condition (3): the control path sends controls only; every datagram it
/// emits classifies as one control. (`ControlRoutes::send` takes a typed
/// `Control`, and the always-permit gate is private to it.)
#[test]
fn the_control_path_emits_only_controls() {
    use std::sync::{Arc, Mutex};

    use karyos_io::backend::InstanceId;
    use karyos_io::sockets::endpoint::SocketsEndpoint;
    use karyos_io::sockets::scripted::ScriptedSocket;
    use karyos_protocol::network::{Datagram, classify};

    use super::super::control::ControlRoutes;

    let socket = ScriptedSocket::new();
    let observer = socket.observer();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    observer.set_send_hook(Box::new(move |_, datagrams| {
        for datagram in datagrams {
            record.lock().unwrap().push(datagram.to_vec());
        }
    }));
    let endpoint = SocketsEndpoint::open(&loopback(), InstanceId::FIRST, socket).unwrap();
    let (mut tx, _rx) = endpoint.split().unwrap();
    let mut routes = ControlRoutes::new(2);
    let controls = [
        Control::Solicit(RspSolicit {
            alias: alias(),
            challenge: ChallengeBlock {
                receiver_boot_id: [7, 8],
                nonce: [9, 9],
            },
        }),
        Control::SetupAnnounce(karyos_protocol::network::SetupAnnounce {
            alias: alias(),
            identity: identity(),
            term: TermParams {
                term_length: 65_536,
                initial_term_id: 9,
                mtu: 1408,
            },
            lane_count: 1,
        }),
    ];
    for (index, control) in controls.iter().enumerate() {
        let port = 41_000 + u16::try_from(index).unwrap();
        let _ = routes.send(&mut tx, SocketAddr::from(([127, 0, 0, 1], port)), control);
    }
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), controls.len());
    for (bytes, control) in seen.iter().zip(&controls) {
        assert_eq!(classify(bytes), Ok(Datagram::Control(*control)));
    }
}

/// Condition (4) and S1: the whole command chain is reserved before the
/// ANSWER is consumed. With every unit of the session event ring held, an
/// answer leaves the challenge pending (`NoCommandCredit`); once there is
/// room, the next answer creates the image.
#[test]
fn an_answer_waits_for_its_chain_credit() {
    let (mut agents, links, mut endpoints, a, b) = two_endpoints();
    let destination = endpoints.local_address(b).unwrap();
    let _log = add_publication(&links, a, b, destination);
    let held: Vec<_> = std::iter::from_fn(|| agents.receiver.sessions.events.reserve()).collect();
    assert_eq!(held.len(), AgentConfig::default().session_command_capacity);
    let mut now = 0u64;
    for _ in 0..300 {
        now += 1_000_000;
        agents.do_work(now).unwrap();
        endpoints.poll(&links, |_| {}, |_| {});
        std::thread::sleep(Duration::from_micros(200));
    }
    assert_eq!(agents.receiver.counters().create_image, 0);
    assert!(agents.receiver.role.sessions.counters().dropped >= 1);
    assert!(links.sessions.take_event().is_none());
    // Room again: the challenge, still pending, is answered again.
    drop(held);
    let (endpoint, ..) = created(&mut agents, &links, &mut endpoints);
    assert_eq!(endpoint, b);
}

/// A receiver role with `config`.
fn receiver_with(config: AgentConfig) -> (super::SenderRole, super::ReceiverRole) {
    super::roles(&config).unwrap()
}

/// An intake on endpoint 1 at `now`.
fn intake<'a>(
    role: &'a mut super::ReceiverRole,
    sessions: &'a super::SessionEnd,
    now: u64,
) -> super::Intake<'a> {
    super::Intake {
        endpoint: EndpointId(1),
        now,
        role,
        sessions,
        work: 0,
    }
}

fn event_ring() -> (super::SessionEnd, super::super::chain::SessionLink) {
    super::super::chain::session_rings(std::num::NonZeroUsize::new(4).unwrap())
}

fn challenge_control() -> Control {
    Control::Challenge(karyos_protocol::network::RspChallenge {
        alias: alias(),
        identity: identity(),
        challenge: ChallengeBlock {
            receiver_boot_id: [7, 8],
            nonce: [9, 9],
        },
    })
}

/// P1-3, §7.4: one destination gets at most `rsp_setup_rate_per_destination`
/// (20) challenges per second however many triggers it sends; the rest are
/// counted.
#[test]
fn rsp_setup_is_capped_per_destination() {
    let (_sender, mut role) = receiver_with(AgentConfig {
        control_capacity: 512,
        ..AgentConfig::default()
    });
    let (events, _keep) = event_ring();
    let source: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    let mut intake = intake(&mut role, &events, 1);
    for _ in 0..200 {
        intake.challenge(source, challenge_control());
    }
    // The IPv4-mapped form is the same destination.
    let mapped: SocketAddr = "[::ffff:10.0.0.9]:5000".parse().unwrap();
    intake.challenge(mapped, challenge_control());
    let counters = role.counters();
    assert_eq!(counters.forwarded, 20);
    assert_eq!(counters.rsp_setup_rate_limited, 181);
}

/// P1-3, §7.4: across destinations, at most `rsp_setup_rate` (256) per
/// driver per second.
#[test]
fn rsp_setup_is_capped_per_driver() {
    let (_sender, mut role) = receiver_with(AgentConfig {
        control_capacity: 512,
        rsp_setup_destinations: 512,
        ..AgentConfig::default()
    });
    let (events, _keep) = event_ring();
    let mut intake = intake(&mut role, &events, 1);
    for port in 1..=300u16 {
        intake.challenge(SocketAddr::from(([10, 0, 0, 9], port)), challenge_control());
    }
    let counters = role.counters();
    assert_eq!(counters.forwarded, 256);
    assert_eq!(counters.rsp_setup_total_limited, 44);
}

/// P3, §7.3 wiring: a challenge toward an unanswerable source is neither
/// forwarded nor charged to a rate; it is counted.
#[test]
fn an_unanswerable_source_gets_no_challenge() {
    let (_sender, mut role) = receiver_with(AgentConfig::default());
    let (events, _keep) = event_ring();
    let mut intake = intake(&mut role, &events, 1);
    for source in ["239.1.1.1:4000", "[::ffff:239.1.1.1]:4000", "10.0.0.1:0"] {
        intake.challenge(source.parse().unwrap(), challenge_control());
    }
    let counters = role.counters();
    assert_eq!(counters.forwarded, 0);
    assert_eq!(counters.unanswerable_source, 3);
    assert_eq!(counters.rsp_setup_rate_limited, 0);
}

/// P2: a full control ring drops each kind under its own counter.
#[test]
fn a_full_ring_counts_each_kind() {
    let (_sender, mut role) = receiver_with(AgentConfig {
        control_capacity: 1,
        ..AgentConfig::default()
    });
    let (events, _keep) = event_ring();
    let source: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    let solicit = Control::Solicit(RspSolicit {
        alias: alias(),
        challenge: ChallengeBlock::default(),
    });
    let outgoing = |control| super::ControlItem::Outgoing {
        endpoint: EndpointId(1),
        destination: source,
        control,
        guard: None,
    };
    let incoming = |control| super::ControlItem::Incoming {
        endpoint: EndpointId(1),
        source,
        control,
    };
    let mut intake = intake(&mut role, &events, 1);
    // The only slot.
    intake.forward(outgoing(challenge_control()));
    intake.forward(outgoing(challenge_control()));
    intake.forward(incoming(challenge_control()));
    intake.forward(incoming(challenge_control()));
    intake.forward(incoming(solicit));
    intake.forward(incoming(solicit));
    intake.forward(incoming(solicit));
    let counters = role.counters();
    assert_eq!(counters.forwarded, 1);
    assert_eq!(counters.ring_full_rsp_setup, 1);
    assert_eq!(counters.ring_full_challenge, 2);
    assert_eq!(counters.ring_full_solicit, 3);
}

/// An ANNOUNCE for an unsubscribed stream is not challenged; an SM,
/// CHALLENGE or SOLICIT for an alias not published on the endpoint never
/// reaches the ring.
#[test]
fn the_receiver_filters_before_the_ring() {
    let (_sender, mut role) = receiver_with(AgentConfig::default());
    let (events, _keep) = event_ring();
    let source: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    let status = Control::Status(karyos_protocol::network::StatusMessage {
        alias: alias(),
        identity: identity(),
        receiver: karyos_protocol::network::Receiver {
            receiver_boot_id: [7, 8],
            receiver_id: 1,
        },
        group_tag: 0,
        lanes: Lanes::new(&[karyos_protocol::network::LaneStatus {
            consumption: 0,
            window: 65_536,
        }])
        .unwrap(),
    });
    let announce = Control::SetupAnnounce(karyos_protocol::network::SetupAnnounce {
        alias: alias(),
        identity: identity(),
        term: TermParams {
            term_length: 65_536,
            initial_term_id: 9,
            mtu: 1408,
        },
        lane_count: 1,
    });
    let solicit = Control::Solicit(RspSolicit {
        alias: alias(),
        challenge: ChallengeBlock::default(),
    });
    let mut intake = intake(&mut role, &events, 1);
    intake.control(source, status);
    intake.control(source, announce);
    intake.control(source, challenge_control());
    intake.control(source, solicit);
    // A PATH_HB from no bound path creates nothing.
    intake.control(
        source,
        Control::PathHeartbeat(karyos_protocol::network::PathHeartbeat {
            alias: alias(),
            identity: identity(),
        }),
    );
    let counters = role.counters();
    assert_eq!(counters.path_heartbeats_unbound, 1);
    assert_eq!(counters.unsubscribed, 1);
    assert_eq!(counters.not_published, 3);
    assert_eq!(counters.forwarded, 0);
}

/// P3: a full route cache evicts the least recently used destination.
#[test]
fn control_routes_evict_the_least_recently_used() {
    use karyos_io::backend::InstanceId;
    use karyos_io::sockets::endpoint::SocketsEndpoint;
    use karyos_io::sockets::scripted::ScriptedSocket;

    use super::super::control::ControlRoutes;

    let socket = ScriptedSocket::new();
    // The kernel takes each of the four sends.
    for _ in 0..4 {
        socket.push_send(karyos_io::sockets::ops::SendResult::Sent {
            sent: 1,
            error: None,
        });
    }
    let endpoint = SocketsEndpoint::open(&loopback(), InstanceId::FIRST, socket).unwrap();
    let (mut tx, _rx) = endpoint.split().unwrap();
    let mut routes = ControlRoutes::new(2);
    let at = |port| SocketAddr::from(([127, 0, 0, 1], port));
    for port in [41_001, 41_002, 41_001, 41_003] {
        routes
            .send(&mut tx, at(port), &challenge_control())
            .unwrap();
    }
    assert_eq!(routes.cached(), [at(41_001), at(41_003)]);
}

/// P1-2: after A is reset, the sender's controls on A go out on the new
/// epoch's routes; none fails on a stale cached id.
#[test]
fn control_routes_survive_a_reset() {
    let (mut agents, links, mut endpoints, a, b) = two_endpoints();
    let destination = endpoints.local_address(b).unwrap();
    let _log = add_publication(&links, a, b, destination);
    created(&mut agents, &links, &mut endpoints);
    endpoints.reset(&links, a).unwrap();
    let mut now = 10_000_000_000u64;
    let mut reopened = false;
    for _ in 0..2000 {
        now += 1_000_000;
        agents.do_work(now).unwrap();
        endpoints.poll(
            &links,
            |event| {
                reopened |=
                    matches!(event, EndpointEvent::Reopened { endpoint, .. } if endpoint == a);
            },
            |_| {},
        );
        if reopened {
            break;
        }
    }
    assert!(reopened);
    let before = agents.sender.counters();
    // Announcements keep going every `setup_interval` (100 ms).
    for _ in 0..400 {
        now += 1_000_000;
        agents.do_work(now).unwrap();
        endpoints.poll(&links, |_| {}, |_| {});
    }
    let after = agents.sender.counters();
    assert!(after.sent >= before.sent + 3, "{before:?} {after:?}");
    assert_eq!(after.send_failures, before.send_failures);
}

/// Two subscriptions of one stream on one endpoint: the stricter
/// `max_image_term_length` holds, whatever their order.
#[test]
fn a_duplicate_subscription_keeps_the_smaller_limit() {
    let (_sender, mut role) = receiver_with(AgentConfig::default());
    let (replies, _keep) =
        super::ring::ring::<AgentEvent<OsSocket>>(std::num::NonZeroUsize::new(4).unwrap());
    for max_term_length in [1 << 20, 2 << 20, 512 << 10] {
        let command = AgentCommand::<OsSocket>::AddSubscription {
            reply: replies.reserve().unwrap(),
            endpoint: EndpointId(1),
            stream_id: 6,
            max_term_length,
        };
        assert!(matches!(
            role.command(command),
            Some((_, AgentEvent::Configured { accepted: true, .. }))
        ));
    }
    assert_eq!(role.subscriptions, [(EndpointId(1), 6, 512 << 10)]);
}

/// The sender accepts an SM only from a receiver it answered on that
/// endpoint (source, receiver boot id), with the answered identity, the
/// publication's lane count and, after the first, the same receiver id;
/// consumption never moves back; a new answer to the tuple starts the
/// binding over.
#[test]
fn the_sender_validates_sms_against_its_bindings() {
    use karyos_protocol::network::{LaneStatus, Receiver, SetupAnswer, StatusMessage};

    let (mut sender, _receiver) = super::roles(&AgentConfig::default()).unwrap();
    let endpoint = EndpointId(1);
    sender.sessions.add(publication(endpoint)).unwrap();
    let group: SocketAddr = "10.0.0.2:4000".parse().unwrap();
    let (path, _log) = outbound(endpoint, group);
    sender.publications.push(*path);
    let receiver: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    // The answer to the receiver's challenge binds it.
    let answer = |boot_id| SetupAnswer {
        alias: alias(),
        identity: identity(),
        term: publication(endpoint).term,
        challenge: ChallengeBlock {
            receiver_boot_id: boot_id,
            nonce: [9, 9],
        },
        joins: Lanes::new(&[0]).unwrap(),
    };
    sender.bind(endpoint, receiver, &answer([7, 8]), 0);
    let status = |boot_id, receiver_id, identity, lanes: &[LaneStatus]| StatusMessage {
        alias: alias(),
        identity,
        receiver: Receiver {
            receiver_boot_id: boot_id,
            receiver_id,
        },
        group_tag: 0,
        lanes: Lanes::new(lanes).unwrap(),
    };
    let at = |consumption| {
        [LaneStatus {
            consumption,
            window: 32_768,
        }]
    };
    let other = Identity {
        incarnation: 2,
        ..identity()
    };
    let spoofer: SocketAddr = "10.0.0.66:5000".parse().unwrap();
    // Another source, another boot id, another endpoint: unbound.
    sender.status(endpoint, spoofer, &status([7, 8], 1, identity(), &at(0)), 1);
    sender.status(
        endpoint,
        receiver,
        &status([9, 9], 1, identity(), &at(0)),
        1,
    );
    sender.status(
        EndpointId(2),
        receiver,
        &status([7, 8], 1, identity(), &at(0)),
        1,
    );
    // Bound, but another identity or lane count: mismatch.
    sender.status(endpoint, receiver, &status([7, 8], 1, other, &at(0)), 1);
    let two = [at(0)[0]; 2];
    sender.status(endpoint, receiver, &status([7, 8], 1, identity(), &two), 1);
    assert_eq!(sender.sessions.counters().established, 0);
    // The bound receiver, mapped or not: accepted, established.
    let mapped: SocketAddr = "[::ffff:10.0.0.9]:5000".parse().unwrap();
    sender.status(
        endpoint,
        mapped,
        &status([7, 8], 1, identity(), &at(4096)),
        2,
    );
    assert_eq!(sender.sessions.counters().established, 1);
    // A replayed older SM keeps the higher consumption, and is counted.
    sender.status(
        endpoint,
        receiver,
        &status([7, 8], 1, identity(), &at(1024)),
        3,
    );
    let held = sender.bindings[0].lanes.unwrap();
    assert_eq!(held.as_slice()[0].consumption, 4096);
    // Another receiver id: mismatch, until a new answer starts it over (a
    // reinstalled image).
    sender.status(
        endpoint,
        receiver,
        &status([7, 8], 2, identity(), &at(4096)),
        4,
    );
    sender.bind(endpoint, receiver, &answer([7, 8]), 5);
    sender.status(
        endpoint,
        receiver,
        &status([7, 8], 2, identity(), &at(4096)),
        6,
    );
    let counters = sender.counters();
    assert_eq!(
        (
            counters.sm_unbound,
            counters.sm_mismatch,
            counters.sm_accepted,
            counters.sm_stale
        ),
        (3, 3, 3, 1)
    );
}

/// P1: a flood of answered strangers cannot hold the binding table. An
/// unconfirmed binding expires after `setup_challenge_timeout` and is the
/// first evicted when the table is full; a confirmed one stays while its
/// SMs come, and goes once they stop for `image_liveness_timeout`.
#[test]
fn unconfirmed_bindings_never_hold_the_table() {
    use karyos_protocol::network::{LaneStatus, Receiver, SetupAnswer, StatusMessage};

    let config = AgentConfig::default();
    let (mut sender, _receiver) = super::roles(&config).unwrap();
    let endpoint = EndpointId(1);
    sender.sessions.add(publication(endpoint)).unwrap();
    let answer = |boot| SetupAnswer {
        alias: alias(),
        identity: identity(),
        term: publication(endpoint).term,
        challenge: ChallengeBlock {
            receiver_boot_id: [boot, 1],
            nonce: [9, 9],
        },
        joins: Lanes::new(&[0]).unwrap(),
    };
    let source = |port| SocketAddr::from(([10, 0, 0, 7], port));
    // A full table of strangers, answered at once.
    for boot in 1..=64u64 {
        let port = u16::try_from(boot).unwrap();
        sender.bind(endpoint, source(port), &answer(boot), 0);
    }
    assert_eq!(sender.bindings.len(), config.receiver_bindings);
    // The real receiver still binds (the oldest stranger goes) and is
    // confirmed by its SM.
    let receiver = SocketAddr::from(([10, 0, 0, 9], 5000));
    sender.bind(endpoint, receiver, &answer(99), 1);
    let status = StatusMessage {
        alias: alias(),
        identity: identity(),
        receiver: Receiver {
            receiver_boot_id: [99, 1],
            receiver_id: 1,
        },
        group_tag: 0,
        lanes: Lanes::new(&[LaneStatus {
            consumption: 0,
            window: 32_768,
        }])
        .unwrap(),
    };
    let (path, _log) = outbound(endpoint, receiver);
    sender.publications.push(*path);
    sender.status(endpoint, receiver, &status, 2);
    assert_eq!(sender.sessions.counters().established, 1);
    assert_eq!(sender.counters().bindings_evicted, 1);
    // Past the challenge timeout the strangers expire; the confirmed
    // binding stays while its SMs come.
    let later = config.sessions.setup_challenge_timeout + 10;
    sender.status(endpoint, receiver, &status, later);
    assert_eq!(sender.bindings.len(), 1);
    assert_eq!(sender.counters().bindings_expired, 63);
    // Its SMs stop: it goes after the image liveness timeout.
    sender.expire_bindings(later + config.image_liveness_timeout);
    assert!(sender.bindings.is_empty());
}

/// The heartbeat rule of the trusted profile (coordinator decision): above
/// the lane's highest seen position is fresh, at it stationary, below it
/// stale, outside the image's window rejected.
#[test]
fn heartbeats_are_classified_against_the_window_and_the_mark() {
    use std::sync::Arc;

    use karyos_protocol::frame::{Flags, FrameType, Lane, Word0};
    use karyos_sys::log_buffer::{
        DEFAULT_CLAIM_DEADLINE, LogBuffer, LogBufferConfig, PublicationMode, ReceiveOwner,
    };
    use karyos_sys::receive::{ImageParams, Item, ValidatedDatagram};
    use karyos_sys::sizing::TermLength;
    use karyos_sys::term::TermId;

    let term_length = TermLength::try_new(65_536).unwrap();
    let lane = Arc::new(
        LogBuffer::new(LogBufferConfig {
            term_length,
            spare_slots: 5,
            max_subscribers: 2,
            mtu: 1408,
            max_reserved: 8192,
            initial_term_id: TermId::new(9),
            lane: Lane::ZERO,
            session_id: 5,
            stream_id: 6,
            publication: PublicationMode::Image {
                join: 0,
                local_gaps: true,
            },
            claim_deadline: DEFAULT_CLAIM_DEADLINE,
            schedule_capacity: 0,
        })
        .unwrap(),
    );
    let params = ImageParams::new(5, 6, 1, term_length, 1408).unwrap();
    let owner = ReceiveOwner::new(params, vec![Arc::clone(&lane)]).unwrap();
    let mut image = super::Installed {
        slot: super::SlotRef {
            slot: 0,
            generation: 1,
        },
        owner: Box::new(owner),
        retire: None,
        key: super::BindingKey {
            endpoint: EndpointId(1),
            source: "10.0.0.9:5000".parse().unwrap(),
            alias: alias(),
        },
        identity: identity(),
        lane_count: 1,
        params,
        stats: crate::paths::stats::PathStats::new(&crate::paths::PathConfig::default(), 1, 8),
        initial_term_id: TermId::new(9),
        term_length: 65_536,
        heartbeat_marks: [None; 4],
        last_fresh: 0,
        window: 32_768,
        sm_last: None,
        sm_slot: None,
        sm: Arc::new(super::SmSlot::default()),
        evidence: 0,
    };
    let heartbeat = |term_id: u32, term_offset: i32| {
        let mut bytes = [0u8; 32];
        let word0 = Word0::new(
            32,
            Flags::new(true, true, false, false, Lane::ZERO),
            FrameType::Data,
        );
        bytes[..8].copy_from_slice(&word0.pack().to_le_bytes());
        bytes[8..12].copy_from_slice(&term_offset.to_le_bytes());
        bytes[12..16].copy_from_slice(&5i32.to_le_bytes());
        bytes[16..20].copy_from_slice(&6i32.to_le_bytes());
        bytes[20..24].copy_from_slice(&term_id.to_le_bytes());
        bytes
    };
    let mut classify = |bytes: [u8; 32]| {
        let datagram = ValidatedDatagram::parse(&bytes, &params).unwrap();
        let Some(Item::Heartbeat(heartbeat)) = datagram.items().next() else {
            panic!("not a heartbeat");
        };
        super::classify_heartbeat(&mut image, &heartbeat)
    };
    use super::HeartbeatClass::{Fresh, Rejected, Stale, Stationary};
    assert_eq!(classify(heartbeat(9, 64)), Fresh);
    assert_eq!(classify(heartbeat(9, 64)), Stationary);
    assert_eq!(classify(heartbeat(9, 32)), Stale);
    assert_eq!(classify(heartbeat(9, 128)), Fresh);
    // Three terms ahead: outside the window.
    assert_eq!(classify(heartbeat(12, 0)), Rejected);
}
