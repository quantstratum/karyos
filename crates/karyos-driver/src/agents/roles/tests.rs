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
                0,
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
            0,
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
        endpoints.poll(links, 0, |_| {}, |_| {});
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
            reliable: true,
            multicast: false,
            control_group: None,
            identity: None,
            conflated: None,
        })
        .unwrap();
    let (outbound, log) = outbound(a, destination);
    links
        .sender
        .post(|reply| AgentCommand::AddPublication {
            reply,
            publication: publication(a),
            outbound,
            guard: None,
            roles: None,
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
        endpoints.poll(&links, 0, |_| {}, |_| {});
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
    sender.publications.push(path);
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
        endpoints.poll(&links, 0, |_| {}, |_| {});
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
        seen: 1,
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
            0,
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
        endpoints.poll(&links, 0, |_| {}, |_| {});
    }
    let after = agents.sender.counters();
    assert!(after.sent >= before.sent + 3, "{before:?} {after:?}");
    assert_eq!(after.send_failures, before.send_failures);
}

/// A removed publication's alias leaves the receiver's pre-filter, once
/// (wiring note W-d, ACS 15929).
#[test]
fn a_published_alias_is_removed() {
    let (_sender, mut role) = receiver_with(AgentConfig::default());
    let (replies, _keep) =
        super::ring::ring::<AgentEvent<OsSocket>>(std::num::NonZeroUsize::new(4).unwrap());
    let alias = Alias {
        session_id: 5,
        stream_id: 6,
    };
    let add = AgentCommand::<OsSocket>::AddPublishedAlias {
        reply: replies.reserve().unwrap(),
        endpoint: EndpointId(1),
        alias,
    };
    assert!(matches!(
        role.command(add),
        Some((_, AgentEvent::Configured { accepted: true, .. }))
    ));
    assert_eq!(role.published, [(EndpointId(1), alias)]);
    for accepted in [true, false] {
        let remove = AgentCommand::<OsSocket>::RemovePublishedAlias {
            reply: replies.reserve().unwrap(),
            endpoint: EndpointId(1),
            alias,
        };
        assert!(matches!(
            role.command(remove),
            Some((_, AgentEvent::Configured { accepted: found, .. })) if found == accepted
        ));
    }
    assert!(role.published.is_empty());
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
            // Reliable if any subscription of the stream is.
            reliable: max_term_length == 2 << 20,
            multicast: false,
            control_group: None,
            identity: None,
            conflated: None,
        };
        assert!(matches!(
            role.command(command),
            Some((_, AgentEvent::Configured { accepted: true, .. }))
        ));
    }
    assert_eq!(
        role.subscriptions,
        [(EndpointId(1), 6, 512 << 10, true, false)]
    );
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
    sender.publications.push(path);
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
    // Another incarnation has no binding of its own: unbound. Bound, but
    // another lane count: mismatch.
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
        (4, 2, 3, 1)
    );
}

/// The membership wiring (ACS 15648, 15707): an accepted SM reaches the
/// publication's membership under its binding key; a re-bind whose next SM
/// names another receiver id ends the former membership first; a binding's
/// expiry ends its member, synchronously.
#[test]
fn accepted_sms_and_gone_bindings_reach_the_membership() {
    use karyos_protocol::frame::Lane;
    use karyos_protocol::network::{LaneStatus, Receiver, SetupAnswer, StatusMessage};

    use crate::membership::{Membership, MembershipConfig, Roles};
    use crate::repair::admission::Requester;

    let config = AgentConfig::default();
    let (mut sender, _receiver) = super::roles(&config).unwrap();
    let endpoint = EndpointId(1);
    sender.sessions.add(publication(endpoint)).unwrap();
    let receiver: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    let (mut path, _log) = outbound(endpoint, receiver);
    path.attach_membership(Box::new(
        Membership::new(
            MembershipConfig::new(1, 1408, 32_768),
            identity(),
            alias(),
            &Roles::default(),
            0,
        )
        .unwrap(),
    ));
    sender.publications.push(path);
    let answer = SetupAnswer {
        alias: alias(),
        identity: identity(),
        term: publication(endpoint).term,
        challenge: ChallengeBlock {
            receiver_boot_id: [7, 8],
            nonce: [9, 9],
        },
        joins: Lanes::new(&[0]).unwrap(),
    };
    let status = |receiver_id, consumption| StatusMessage {
        alias: alias(),
        identity: identity(),
        receiver: Receiver {
            receiver_boot_id: [7, 8],
            receiver_id,
        },
        group_tag: 0,
        lanes: Lanes::new(&[LaneStatus {
            consumption,
            window: 32_768,
        }])
        .unwrap(),
    };
    let member = |sender: &mut super::SenderRole, receiver_id, now| {
        sender.publications[0].membership_mut().unwrap().requester(
            Receiver {
                receiver_boot_id: [7, 8],
                receiver_id,
            },
            Lane::ZERO,
            now,
        )
    };
    sender.bind(endpoint, receiver, &answer, 0);
    sender.status(endpoint, receiver, &status(1, 0), 1);
    assert!(matches!(
        member(&mut sender, 1, 1),
        Requester::Member { .. }
    ));
    // A new answer (a reinstalled image), then an SM of receiver 2: 1 goes.
    sender.bind(endpoint, receiver, &answer, 2);
    sender.status(endpoint, receiver, &status(2, 0), 3);
    assert_eq!(member(&mut sender, 1, 3), Requester::Unknown);
    assert!(matches!(
        member(&mut sender, 2, 3),
        Requester::Member { .. }
    ));
    // A new answer resets the row; it expires before its next SM, and the
    // former receiver's membership goes with it.
    sender.bind(endpoint, receiver, &answer, 4);
    assert!(matches!(
        member(&mut sender, 2, 4),
        Requester::Member { .. }
    ));
    sender.expire_bindings(4 + config.sessions.setup_challenge_timeout);
    assert!(sender.bindings.is_empty());
    assert_eq!(member(&mut sender, 2, 5), Requester::Unknown);
    // Confirmed, then its SMs stop: the binding expires, and the member
    // with it, at once.
    sender.bind(endpoint, receiver, &answer, 6);
    sender.status(endpoint, receiver, &status(3, 0), 7);
    sender.expire_bindings(7 + config.image_liveness_timeout);
    assert!(sender.bindings.is_empty());
    assert_eq!(member(&mut sender, 3, 8), Requester::Unknown);
    // A reset row evicted for a newcomer ends its former receiver's too.
    let t = 8 + config.image_liveness_timeout;
    sender.bind(endpoint, receiver, &answer, t);
    sender.status(endpoint, receiver, &status(4, 0), t + 1);
    sender.bind(endpoint, receiver, &answer, t + 2);
    for boot in 1..u64::try_from(config.receiver_bindings).unwrap() {
        let mut stranger = answer;
        stranger.challenge.receiver_boot_id = [boot, 99];
        let port = 6000 + u16::try_from(boot).unwrap();
        sender.bind(
            endpoint,
            SocketAddr::from(([10, 0, 0, 8], port)),
            &stranger,
            t + 3,
        );
    }
    assert!(matches!(
        member(&mut sender, 4, t + 3),
        Requester::Member { .. }
    ));
    let mut newcomer = answer;
    newcomer.challenge.receiver_boot_id = [1, 1];
    sender.bind(
        endpoint,
        SocketAddr::from(([10, 0, 0, 7], 7000)),
        &newcomer,
        t + 4,
    );
    assert_eq!(sender.counters().bindings_evicted, 1);
    assert_eq!(member(&mut sender, 4, t + 4), Requester::Unknown);
}

/// A publication's membership follows the driver's SM cadence and image
/// liveness, and a configuration they cannot satisfy is refused.
#[test]
fn a_publication_membership_follows_the_driver_timing() {
    let config = AgentConfig {
        sm_interval: 20_000_000,
        image_liveness_timeout: 20_000_000_000,
        idle_image_timeout: 90_000_000_000,
        ..AgentConfig::default()
    };
    let (mut sender, _receiver) = super::roles(&config).unwrap();
    let (replies, _keep) =
        super::ring::ring::<AgentEvent<OsSocket>>(std::num::NonZeroUsize::new(4).unwrap());
    let endpoint = EndpointId(1);
    let (path, _log) = outbound(endpoint, "10.0.0.9:5000".parse().unwrap());
    let command = AgentCommand::<OsSocket>::AddPublication {
        reply: replies.reserve().unwrap(),
        publication: publication(endpoint),
        outbound: path,
        guard: None,
        roles: None,
    };
    assert!(matches!(
        sender.command(command),
        Some((_, AgentEvent::PublicationAdded { .. }))
    ));
    let held = *sender.publications[0].membership_mut().unwrap().config();
    assert_eq!(
        (
            held.sm_interval,
            held.receiver_timeout,
            held.pause_timeout,
            held.join_timeout
        ),
        (20_000_000, 20_000_000_000, 90_000_000_000, 20_000_000_000)
    );
    let short = AgentConfig {
        image_liveness_timeout: 9 * config.sm_interval,
        ..config
    };
    assert!(matches!(
        short.validate(),
        Err(super::AgentError::InvalidConfig(_))
    ));
}

/// An SM skipped because the image's previous one still waits stays due;
/// only a posted SM is recorded as sent.
#[test]
fn a_skipped_sm_stays_due() {
    let (_sender, mut role) = receiver_with(AgentConfig::default());
    let (image, _) = installed_image();
    role.images.push(image);
    let due = role.images[0].schedule.due(0, &[0]).unwrap();
    let waiting = super::SmGuard::take(&role.images[0].sm);
    role.send_sm(0, &due, 0);
    assert_eq!(role.counters().sm_skipped, 1);
    assert!(role.images[0].schedule.due(1, &[0]).is_some(), "still due");
    drop(waiting);
    role.send_sm(0, &due, 1);
    assert_eq!(role.counters().sm_sent, 1);
    assert!(role.images[0].schedule.due(2, &[0]).is_none(), "sent");
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
    sender.publications.push(path);
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
/// An installed one-lane image (session 5, stream 6, initial term 9,
/// 64 KiB terms) for the liveness tests.
fn installed_image() -> (super::Installed, karyos_sys::receive::ImageParams) {
    installed_image_with(karyos_sys::log_buffer::SkipConfig::reliable())
}

/// [`installed_image`] with `skip` as its skip policy's configuration.
fn installed_image_with(
    skip: karyos_sys::log_buffer::SkipConfig,
) -> (super::Installed, karyos_sys::receive::ImageParams) {
    use std::sync::Arc;

    use karyos_protocol::frame::Lane;
    use karyos_sys::log_buffer::{
        DEFAULT_CLAIM_DEADLINE, LogBuffer, LogBufferConfig, PublicationMode, ReceiveOwner,
    };
    use karyos_sys::receive::ImageParams;
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
    let image = super::Installed {
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
        schedule: crate::sm_schedule::SmSchedule::new(10_000_000, &[32_768]).unwrap(),
        sm_slot: None,
        sm: Arc::new(super::SmSlot::default()),
        evidence: 0,
        rtt: crate::rtt::RttProbes::new(crate::rtt::RttConfig::default(), 4).unwrap(),
        probes: (0..4)
            .map(|_| super::PathProbe {
                slot: Arc::new(super::ReportSlot::default()),
                pending: None,
            })
            .collect(),
        reliable: true,
        loss: crate::repair::loss::ImageLoss::new(
            crate::repair::loss::LossConfig::default(),
            alias(),
            identity(),
            karyos_protocol::network::Receiver {
                receiver_boot_id: [7, 8],
                receiver_id: 1,
            },
            1,
            0,
        )
        .unwrap(),
        skip: karyos_sys::log_buffer::SkipPolicy::new(skip, 1).unwrap(),
        naks: vec![super::PendingNak {
            slot: Arc::new(super::ReportSlot::default()),
            pending: None,
        }],
        closing: None,
        gate: None,
        tail_since: [None; 4],
        reset_requested: None,
        next_clean: [0; 4],
        copies: Vec::new(),
        routes: Vec::new(),
        anchored: [None; 4],
        uncertain_at: [None; 4],
        founding_gone: false,
        control_group: None,
        receiver_id: super::receiver_id(super::SlotRef {
            slot: 0,
            generation: 1,
        }),
        group_tag: 0,
    };
    (image, params)
}

#[test]
fn heartbeats_are_classified_against_the_window_and_the_mark() {
    use karyos_protocol::frame::{Flags, FrameType, Lane, Word0};
    use karyos_sys::receive::{Item, ValidatedDatagram};

    let (mut image, params) = installed_image();
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

#[test]
fn stationary_heartbeats_stop_refreshing_after_the_idle_timeout() {
    let (mut image, _) = installed_image();
    let idle = 60_000_000_000;
    super::apply_evidence(&mut image, true, false, 1_000, idle);
    assert_eq!((image.evidence, image.last_fresh), (1_000, 1_000));
    // Stationary within the idle timeout: alive, the idle clock kept.
    super::apply_evidence(&mut image, false, true, 1_000 + idle - 1, idle);
    assert_eq!(
        (image.evidence, image.last_fresh),
        (1_000 + idle - 1, 1_000)
    );
    // At the idle timeout: no longer evidence, so the image ages out.
    super::apply_evidence(&mut image, false, true, 1_000 + idle, idle);
    assert_eq!(
        (image.evidence, image.last_fresh),
        (1_000 + idle - 1, 1_000)
    );
    super::apply_evidence(&mut image, false, true, 1_000 + 2 * idle, idle);
    assert_eq!(image.evidence, 1_000 + idle - 1);
    // Fresh evidence restarts both.
    super::apply_evidence(&mut image, true, false, 1_000 + 2 * idle, idle);
    assert_eq!(
        (image.evidence, image.last_fresh),
        (1_000 + 2 * idle, 1_000 + 2 * idle)
    );
}

#[test]
fn a_stale_heartbeat_leaves_the_evidence_unchanged() {
    let (mut image, _) = installed_image();
    super::apply_evidence(&mut image, true, false, 5_000, 60_000_000_000);
    super::apply_evidence(&mut image, false, false, 9_000, 60_000_000_000);
    assert_eq!((image.evidence, image.last_fresh), (5_000, 5_000));
}

/// A sender with one publication on `EndpointId(1)`.
fn sm_sender() -> super::SenderRole {
    let (mut sender, _receiver) = super::roles(&AgentConfig::default()).unwrap();
    sender.sessions.add(publication(EndpointId(1))).unwrap();
    let (path, _log) = outbound(EndpointId(1), "10.0.0.2:4000".parse().unwrap());
    sender.publications.push(path);
    sender
}

/// The answer binding a receiver with `boot_id` at `join`.
fn sm_answer(boot_id: [u64; 2], join: u64) -> karyos_protocol::network::SetupAnswer {
    karyos_protocol::network::SetupAnswer {
        alias: alias(),
        identity: identity(),
        term: publication(EndpointId(1)).term,
        challenge: ChallengeBlock {
            receiver_boot_id: boot_id,
            nonce: [9, 9],
        },
        joins: Lanes::new(&[join]).unwrap(),
    }
}

/// An SM from the receiver with `boot_id` at `consumption`.
fn sm_status(boot_id: [u64; 2], consumption: u64) -> karyos_protocol::network::StatusMessage {
    use karyos_protocol::network::{LaneStatus, Receiver, StatusMessage};

    StatusMessage {
        alias: alias(),
        identity: identity(),
        receiver: Receiver {
            receiver_boot_id: boot_id,
            receiver_id: 1,
        },
        group_tag: 0,
        lanes: Lanes::new(&[LaneStatus {
            consumption,
            window: 32_768,
        }])
        .unwrap(),
    }
}

#[test]
fn a_rebind_never_moves_a_reliable_position_back() {
    let mut sender = sm_sender();
    let endpoint = EndpointId(1);
    let receiver: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    sender.bind(endpoint, receiver, &sm_answer([7, 8], 0), 0);
    sender.status(endpoint, receiver, &sm_status([7, 8], 8192), 1);
    assert_eq!(sender.consumption(endpoint, alias()).unwrap()[0], 8192);
    // A new answer to the same receiver, at an older join: held.
    sender.bind(endpoint, receiver, &sm_answer([7, 8], 0), 2);
    assert_eq!(sender.consumption(endpoint, alias()).unwrap()[0], 8192);
    // Its next SM, older still: held, counted stale.
    sender.status(endpoint, receiver, &sm_status([7, 8], 4096), 3);
    assert_eq!(sender.consumption(endpoint, alias()).unwrap()[0], 8192);
    assert_eq!(sender.counters().sm_stale, 1);
}

#[test]
fn an_unconfirmed_receiver_bounds_at_its_joins() {
    let mut sender = sm_sender();
    let endpoint = EndpointId(1);
    let first: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    let second: SocketAddr = "10.0.0.10:5000".parse().unwrap();
    assert_eq!(sender.consumption(endpoint, alias()), None);
    sender.bind(endpoint, first, &sm_answer([7, 8], 0), 0);
    sender.status(endpoint, first, &sm_status([7, 8], 8192), 1);
    sender.bind(endpoint, second, &sm_answer([3, 4], 1024), 2);
    // The second is answered but silent: it bounds at its join.
    assert_eq!(sender.consumption(endpoint, alias()).unwrap()[0], 1024);
    // Once heard from, at its consumption.
    sender.status(endpoint, second, &sm_status([3, 4], 16_384), 3);
    assert_eq!(sender.consumption(endpoint, alias()).unwrap()[0], 8192);
    // Another alias has no bound receiver.
    let other = Alias {
        session_id: 99,
        ..alias()
    };
    assert_eq!(sender.consumption(endpoint, other), None);
}

/// A publication that needs a reset asks for it once, then again only after
/// `RESET_REQUEST_CYCLES`; a request the ring could not take is counted and
/// asked again on the next cycle.
#[test]
fn a_reset_request_is_repeated_at_its_cadence() {
    use super::super::data::RESET_REQUEST_CYCLES;

    let mut sender = sm_sender();
    let mut asked = Vec::new();
    sender.cycle = 10;
    sender.request_resets(|endpoint| {
        asked.push(endpoint);
        true
    });
    assert!(asked.is_empty(), "nothing needs a reset");
    sender.publications[0].force_needs_reset();
    // The ring is full: counted, not recorded.
    sender.request_resets(|_| false);
    sender.cycle = 11;
    sender.request_resets(|endpoint| {
        asked.push(endpoint);
        true
    });
    assert_eq!(asked, [EndpointId(1)]);
    sender.cycle = 11 + RESET_REQUEST_CYCLES - 1;
    sender.request_resets(|endpoint| {
        asked.push(endpoint);
        true
    });
    assert_eq!(asked.len(), 1);
    sender.cycle = 11 + RESET_REQUEST_CYCLES;
    sender.request_resets(|endpoint| {
        asked.push(endpoint);
        true
    });
    assert_eq!(asked.len(), 2);
    let counters = sender.counters();
    assert_eq!(
        (counters.reset_requests, counters.reset_requests_full),
        (2, 1)
    );
}

/// The receiver's clock in the RTT tests.
static RTT_CLOCK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn rtt_clock() -> u64 {
    RTT_CLOCK.load(std::sync::atomic::Ordering::Relaxed)
}

/// RC-1, receiver side: a bound path gets one REQUEST per interval, at most
/// one in the ring; a REPLY to a submitted probe from that path, naming the
/// image and this receiver, gives a sample from the start the sender
/// reported to the clock read at validation; anything else gives none, and
/// a probe of a lost binding is not applied to the next.
#[test]
fn rttm_probes_measure_bound_paths() {
    use karyos_protocol::network::{Receiver, Rttm, RttmKind};

    use super::super::control::{ControlItem, ItemGuard};

    let config = AgentConfig::default();
    let (mut sender, mut role) = receiver_with(config);
    role.clock = rtt_clock;
    let (image, _) = installed_image();
    let (slot, key, identity) = (image.slot, image.key, image.identity);
    role.images.push(image);
    role.sessions
        .paths_mut()
        .bind_first(
            slot,
            identity,
            TermParams {
                term_length: 65_536,
                initial_term_id: 9,
                mtu: 1408,
            },
            key,
            Lanes::new(&[0]).unwrap(),
            0,
        )
        .unwrap();
    let take = |sender: &mut super::SenderRole| match sender.from_receiver.try_take() {
        Ok(Some(ControlItem::Outgoing {
            endpoint,
            destination,
            control: Control::Rttm(request),
            guard: Some(ItemGuard::Report(guard)),
        })) => {
            assert_eq!((endpoint, destination), (key.endpoint, key.source));
            (request, guard)
        }
        other => panic!("{other:?}"),
    };
    // One REQUEST on the bound path, naming the image and this receiver.
    assert_eq!(role.probe_paths(0, 0).unwrap(), 1);
    let (request, guard) = take(&mut sender);
    let receiver = Receiver {
        receiver_boot_id: role.sessions.boot_id(),
        receiver_id: super::receiver_id(slot),
    };
    assert_eq!((request.alias, request.identity), (key.alias, identity));
    assert_eq!(
        (request.receiver, request.kind),
        (receiver, RttmKind::Request)
    );
    assert_ne!(request.probe_id, 0);
    // In the ring: none more, even past the interval.
    assert_eq!(role.probe_paths(0, 2_000_000_000).unwrap(), 0);
    // The sender is in its backend call, started at 1000.
    let mut guard = guard;
    guard.sending(1_000);
    assert_eq!(role.probe_paths(0, 2_000_000_000).unwrap(), 0, "still busy");
    let reply = |probe_id| {
        Control::Rttm(Rttm {
            probe_id,
            kind: RttmKind::Reply {
                service_delay_ns: 1,
            },
            ..request
        })
    };
    let (events, _link) = event_ring();
    // A REPLY from another source, or naming another receiver: dropped.
    RTT_CLOCK.store(3_001_000, std::sync::atomic::Ordering::Relaxed);
    let mut other = intake(&mut role, &events, 0);
    other.control("10.0.0.10:5000".parse().unwrap(), reply(request.probe_id));
    let mut stranger = request;
    stranger.receiver.receiver_id += 1;
    other.control(
        key.source,
        Control::Rttm(Rttm {
            kind: RttmKind::Reply {
                service_delay_ns: 1,
            },
            ..stranger
        }),
    );
    let mut other_identity = request;
    other_identity.identity.incarnation += 1;
    other.control(
        key.source,
        Control::Rttm(Rttm {
            kind: RttmKind::Reply {
                service_delay_ns: 1,
            },
            ..other_identity
        }),
    );
    assert_eq!(role.counters().rttm_replies_unbound, 3);
    // A REPLY that overtakes the sender's final report proves the send:
    // 3 ms from the start it published.
    intake(&mut role, &events, 0).control(key.source, reply(request.probe_id));
    assert_eq!(role.counters().rttm_samples, 1);
    assert_eq!(role.images[0].rtt.estimate(0), 3_000_000);
    // The final report comes after; a later collection clears it.
    guard.submitted();
    assert!(!role.images[0].probes[0].slot.busy());
    // A duplicate gives none.
    intake(&mut role, &events, 0).control(key.source, reply(request.probe_id));
    assert_eq!(role.counters().rttm_replies_ignored, 1);
    // A REQUEST the sender drops yields no sample; the next waits an
    // interval.
    assert_eq!(role.probe_paths(0, 4_000_000_000).unwrap(), 1);
    let (_, guard) = take(&mut sender);
    drop(guard);
    assert_eq!(role.probe_paths(0, 4_500_000_000).unwrap(), 0);
    assert_eq!(role.images[0].rtt.counts().unsubmitted, 1);
    // An uncertain REQUEST yields no sample either.
    assert_eq!(role.probe_paths(0, 5_000_000_000).unwrap(), 1);
    let (_, mut guard) = take(&mut sender);
    guard.sending(5_000_000_000);
    guard.uncertain();
    assert_eq!(role.probe_paths(0, 5_500_000_000).unwrap(), 0);
    assert_eq!(role.images[0].rtt.counts().unsubmitted, 2);
    // A probe whose path is lost and bound again is not applied to the
    // new binding.
    assert_eq!(role.probe_paths(0, 6_000_000_000).unwrap(), 1);
    let (request, guard) = take(&mut sender);
    role.images[0].evidence = 20_000_000_000;
    let _ = role
        .duty::<OsSocket>(&mut [], &events, 20_000_000_000)
        .unwrap();
    assert_eq!(role.sessions.paths().live(slot), 0, "the path is lost");
    let mut guard = guard;
    guard.sending(6_000_000_000);
    guard.submitted();
    let rebound = role.sessions.paths_mut().offer_later(
        slot,
        key,
        identity,
        TermParams {
            term_length: 65_536,
            initial_term_id: 9,
            mtu: 1408,
        },
        Lanes::new(&[0]).unwrap(),
        20_000_000_000,
    );
    assert_eq!(rebound, Ok(0), "bound again at the same index");
    RTT_CLOCK.store(20_000_000_001, std::sync::atomic::Ordering::Relaxed);
    intake(&mut role, &events, 0).control(key.source, reply(request.probe_id));
    assert_eq!(
        role.counters().rttm_samples,
        1,
        "no sample from a lost path"
    );
    assert_eq!(
        role.images[0].rtt.counts().submitted,
        1,
        "stale report ignored"
    );
}

/// The sender's clock in the RTT tests.
static SENDER_CLOCK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn sender_clock() -> u64 {
    SENDER_CLOCK.load(std::sync::atomic::Ordering::Relaxed)
}

/// RC-1, sender side: a REQUEST's start is read before its backend call and
/// reported only when it submitted; a valid REQUEST from a bound receiver
/// is answered once with its probe id and the service delay, within the
/// reply rate; anything else is not.
#[test]
fn rttm_requests_are_reported_and_answered() {
    use std::sync::{Arc, Mutex};

    use karyos_io::backend::InstanceId;
    use karyos_io::sockets::endpoint::SocketsEndpoint;
    use karyos_io::sockets::ops::SendResult;
    use karyos_io::sockets::scripted::ScriptedSocket;
    use karyos_protocol::network::{
        Datagram, LaneStatus, Receiver, Rttm, RttmKind, SetupAnswer, StatusMessage, classify,
    };

    use super::super::Half;
    use super::super::control::{ControlItem, ItemGuard, ReportGuard, ReportSlot, SendReport};

    let config = AgentConfig {
        rtt: crate::rtt::RttConfig {
            rttm_reply_rate: 1,
            ..crate::rtt::RttConfig::default()
        },
        ..AgentConfig::default()
    };
    let (mut sender, role) = receiver_with(config);
    sender.clock = sender_clock;
    let socket = ScriptedSocket::new();
    let observer = socket.observer();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    // Each backend call takes 400 ns on the sender's clock: a start read
    // after the call would show it.
    observer.set_send_hook(Box::new(move |_, datagrams| {
        SENDER_CLOCK.fetch_add(400, std::sync::atomic::Ordering::Relaxed);
        for datagram in datagrams {
            record.lock().unwrap().push(datagram.to_vec());
        }
    }));
    let endpoint = SocketsEndpoint::open(&loopback(), InstanceId::FIRST, socket).unwrap();
    let (tx, _rx) = endpoint.split().unwrap();
    let mut halves = vec![(EndpointId(1), Half::Tx(Box::new(tx)))];
    let source: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    // A REQUEST submitted: its start is the clock before the call.
    let slot = Arc::new(ReportSlot::default());
    let request = Rttm {
        alias: alias(),
        identity: identity(),
        receiver: Receiver {
            receiver_boot_id: [7, 8],
            receiver_id: 1,
        },
        probe_id: 77,
        kind: RttmKind::Request,
    };
    let outgoing = |slot: &Arc<ReportSlot>| ControlItem::Outgoing {
        endpoint: EndpointId(1),
        destination: source,
        control: Control::Rttm(request),
        guard: Some(ItemGuard::Report(ReportGuard::take(slot))),
    };
    observer.push_send(SendResult::Sent {
        sent: 1,
        error: None,
    });
    SENDER_CLOCK.store(500, std::sync::atomic::Ordering::Relaxed);
    role.to_sender.try_post(outgoing(&slot)).unwrap();
    let _ = sender.duty(&mut halves, 600).unwrap();
    assert_eq!(slot.collect(false), Some(SendReport::Submitted(500)));
    assert_eq!(slot.collect(false), None, "collected once");
    // One the kernel refused: not submitted.
    observer.push_send(SendResult::Error(
        karyos_io::sockets::ops::Errno::NETUNREACH,
    ));
    role.to_sender.try_post(outgoing(&slot)).unwrap();
    let _ = sender.duty(&mut halves, 700).unwrap();
    assert_eq!(slot.collect(false), Some(SendReport::NotSubmitted));
    // A result outside the backend's ABI: exposure unknown, reported
    // uncertain at the start read before the call (RC-6).
    observer.push_send(SendResult::OutOfAbi { proven: 0 });
    SENDER_CLOCK.store(750, std::sync::atomic::Ordering::Relaxed);
    role.to_sender.try_post(outgoing(&slot)).unwrap();
    let _ = sender.duty(&mut halves, 760).unwrap();
    assert_eq!(slot.collect(false), Some(SendReport::Uncertain(750)));
    // A REQUEST from no bound receiver is not answered.
    let incoming = |request: Rttm, seen| ControlItem::Incoming {
        endpoint: EndpointId(1),
        source,
        control: Control::Rttm(request),
        seen,
    };
    role.to_sender.try_post(incoming(request, 800)).unwrap();
    let _ = sender.duty(&mut halves, 800).unwrap();
    assert_eq!(sender.counters().rttm_unbound, 1);
    // Bound and confirmed: answered with its probe id and service delay.
    sender.sessions.add(publication(EndpointId(1))).unwrap();
    let answer = SetupAnswer {
        alias: alias(),
        identity: identity(),
        term: publication(EndpointId(1)).term,
        challenge: ChallengeBlock {
            receiver_boot_id: [7, 8],
            nonce: [9, 9],
        },
        joins: Lanes::new(&[0]).unwrap(),
    };
    // An earlier incarnation's binding from the same receiver, found first.
    let mut old = answer;
    old.identity.incarnation -= 1;
    sender.bind(EndpointId(1), source, &old, 899);
    sender.bind(EndpointId(1), source, &answer, 900);
    let (path, _log) = outbound(EndpointId(1), source);
    sender.publications.push(path);
    let status = StatusMessage {
        alias: alias(),
        identity: identity(),
        receiver: request.receiver,
        group_tag: 0,
        lanes: Lanes::new(&[LaneStatus {
            consumption: 0,
            window: 32_768,
        }])
        .unwrap(),
    };
    sender.status(EndpointId(1), source, &status, 901);
    let sent_before = seen.lock().unwrap().len();
    observer.push_send(SendResult::Sent {
        sent: 1,
        error: None,
    });
    SENDER_CLOCK.store(1_250, std::sync::atomic::Ordering::Relaxed);
    role.to_sender.try_post(incoming(request, 1_000)).unwrap();
    let _ = sender.duty(&mut halves, 1_200).unwrap();
    assert_eq!(sender.counters().rttm_replied, 1);
    let replies: Vec<_> = seen.lock().unwrap()[sent_before..]
        .iter()
        .filter_map(|bytes| match classify(bytes) {
            Ok(Datagram::Control(Control::Rttm(reply))) => Some(reply),
            _ => None,
        })
        .collect();
    assert_eq!(
        replies,
        [Rttm {
            kind: RttmKind::Reply {
                service_delay_ns: 250
            },
            ..request
        }]
    );
    // Another receiver id: a mismatch. Another incarnation or receiver
    // boot: no binding. None is answered.
    let mut stranger = request;
    stranger.receiver.receiver_id = 2;
    role.to_sender.try_post(incoming(stranger, 1_300)).unwrap();
    let mut other = request;
    other.identity.incarnation += 1;
    role.to_sender.try_post(incoming(other, 1_300)).unwrap();
    let mut rebooted = request;
    rebooted.receiver.receiver_boot_id = [7, 9];
    role.to_sender.try_post(incoming(rebooted, 1_300)).unwrap();
    let _ = sender.duty(&mut halves, 1_300).unwrap();
    assert_eq!(sender.counters().rttm_mismatch, 1);
    assert_eq!(sender.counters().rttm_unbound, 3);
    // Over the reply rate (1 per second here): dropped.
    role.to_sender.try_post(incoming(request, 1_400)).unwrap();
    let _ = sender.duty(&mut halves, 1_400).unwrap();
    assert_eq!(sender.counters().rttm_refused, 1);
    assert_eq!(sender.rttm_reply_drops(), (1, 0));
    assert_eq!(sender.counters().rttm_replied, 1);
}

/// The probe ids are restocked on the timer step: a long-lived path keeps
/// probing past its first pool, and each draw is counted.
#[test]
fn rttm_probe_ids_are_restocked() {
    let (sender, mut role) = receiver_with(AgentConfig::default());
    let (image, _) = installed_image();
    let (slot, key, identity) = (image.slot, image.key, image.identity);
    role.images.push(image);
    role.sessions
        .paths_mut()
        .bind_first(
            slot,
            identity,
            TermParams {
                term_length: 65_536,
                initial_term_id: 9,
                mtu: 1408,
            },
            key,
            Lanes::new(&[0]).unwrap(),
            0,
        )
        .unwrap();
    let interval = crate::rtt::RttConfig::default().rtt_probe_interval;
    let mut sent = 0;
    for cycle in 0..40u64 {
        sent += role.probe_paths(0, cycle * interval).unwrap();
        // The sender drops each: not submitted.
        while let Ok(Some(item)) = sender.from_receiver.try_take() {
            drop(item);
        }
    }
    assert_eq!(sent, 40);
    assert!(role.counters().rttm_id_draws >= 1);
    assert_eq!(role.images[0].rtt.counts().id_failures, 0);
}

/// An RTTM REQUEST reaches the sender only for an alias published on the
/// endpoint, stamped with when it was taken from the backend.
#[test]
fn rttm_requests_reach_the_sender_for_published_aliases() {
    use karyos_protocol::network::{Receiver, Rttm, RttmKind};

    use super::super::control::ControlItem;

    let (sender, mut role) = receiver_with(AgentConfig::default());
    let (events, _link) = event_ring();
    let source: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    let request = Control::Rttm(Rttm {
        alias: alias(),
        identity: identity(),
        receiver: Receiver {
            receiver_boot_id: [7, 8],
            receiver_id: 1,
        },
        probe_id: 5,
        kind: RttmKind::Request,
    });
    intake(&mut role, &events, 3).control(source, request);
    assert_eq!(role.counters().not_published, 1);
    role.published.push((EndpointId(1), alias()));
    intake(&mut role, &events, 4).control(source, request);
    match sender.from_receiver.try_take() {
        Ok(Some(ControlItem::Incoming {
            endpoint,
            source: from,
            control,
            seen,
        })) => assert_eq!(
            (endpoint, from, control, seen),
            (EndpointId(1), source, request, 4)
        ),
        other => panic!("{other:?}"),
    }
    // A NAK for the published alias goes to the sender too.
    let nak = Control::Nak(karyos_protocol::network::Nak {
        alias: alias(),
        identity: identity(),
        receiver: Receiver {
            receiver_boot_id: [7, 8],
            receiver_id: 1,
        },
        range: karyos_protocol::network::NakRange {
            lane: karyos_protocol::frame::Lane::ZERO,
            length: 1056,
            start: 0,
        },
    });
    intake(&mut role, &events, 5).control(source, nak);
    assert!(matches!(
        sender.from_receiver.try_take(),
        Ok(Some(ControlItem::Incoming { control, .. })) if control == nak
    ));
}

/// The wired SM path never lowers a lane's reported consumption: after a
/// real SM, a lower sample (a required reader joining during a sample,
/// here a lowered published head) is clamped by the image's SM schedule
/// to the earlier report, which the sender would otherwise take for a
/// replay; a higher sample is reported as it is.
#[test]
fn an_sm_never_lowers_its_consumption() {
    use karyos_protocol::network::StatusMessage;

    let (sender, mut receiver) = super::roles(&AgentConfig::default()).unwrap();
    let (sessions, _link) = event_ring();
    let (image, _) = installed_image();
    receiver.images.push(image);
    let sent = |receiver: &mut super::ReceiverRole, head, now| {
        let image = &mut receiver.images[0];
        assert!(
            image
                .owner
                .set_published_head(karyos_protocol::frame::Lane::ZERO, head)
        );
        image.evidence = now;
        receiver.image_timers(&sessions, now).unwrap();
        let Ok(Some(super::ControlItem::Outgoing {
            control: Control::Status(StatusMessage { lanes, .. }),
            ..
        })) = sender.from_receiver.try_take()
        else {
            panic!("no SM at {now}");
        };
        lanes.as_slice()[0].consumption
    };
    assert_eq!(sent(&mut receiver, 4096, 20_000_000), 4096);
    assert_eq!(sent(&mut receiver, 1024, 40_000_000), 4096);
    assert_eq!(sent(&mut receiver, 8192, 60_000_000), 8192);
}

/// A sender with reliable publications on endpoint 1 for `aliases`, each
/// answered and confirmed by receiver 1 at 10.0.0.9:5000 and holding
/// `frames` 1000-byte messages already sent, over a scripted socket that
/// records every datagram.
struct RepairRig {
    sender: super::SenderRole,
    role: super::ReceiverRole,
    halves: Vec<(
        EndpointId,
        super::super::Half<karyos_io::sockets::scripted::ScriptedSocket>,
    )>,
    observer: karyos_io::sockets::scripted::ScriptedSocket,
    sent: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    /// The publishing sides, kept alive with the rig.
    _logs: Vec<super::super::data::testing::TestLog>,
}

const RECEIVER_SOURCE: ([u8; 4], u16) = ([10, 0, 0, 9], 5000);

impl RepairRig {
    fn new(config: AgentConfig, aliases: &[Alias], frames: u8) -> Self {
        use std::sync::{Arc, Mutex};

        use karyos_io::backend::InstanceId;
        use karyos_io::sockets::endpoint::SocketsEndpoint;
        use karyos_io::sockets::scripted::ScriptedSocket;
        use karyos_protocol::network::{LaneStatus, Receiver, SetupAnswer, StatusMessage};
        use karyos_sys::log_buffer::AppendOptions;

        let (mut sender, role) = super::roles(&config).unwrap();
        let socket = ScriptedSocket::new();
        let observer = socket.observer();
        let sent = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&sent);
        observer.set_send_hook(Box::new(move |_, datagrams| {
            for datagram in datagrams {
                record.lock().unwrap().push(datagram.to_vec());
            }
        }));
        let endpoint = SocketsEndpoint::open(&loopback(), InstanceId::FIRST, socket).unwrap();
        let (tx, _rx) = endpoint.split().unwrap();
        let halves = vec![(EndpointId(1), super::super::Half::Tx(Box::new(tx)))];
        let source = SocketAddr::from(RECEIVER_SOURCE);
        let (replies, _keep) =
            super::ring::ring::<AgentEvent<OsSocket>>(std::num::NonZeroUsize::new(8).unwrap());
        let mut logs = Vec::new();
        for alias in aliases {
            let publication = Publication {
                alias: *alias,
                ..publication(EndpointId(1))
            };
            let (path, mut log) = super::super::data::testing::outbound(
                EndpointId(1),
                *alias,
                source,
                publication.term,
                1,
                true,
            );
            let command = AgentCommand::<OsSocket>::AddPublication {
                reply: replies.reserve().unwrap(),
                publication,
                outbound: path,
                guard: None,
                roles: None,
            };
            assert!(matches!(
                sender.command(command),
                Some((_, AgentEvent::PublicationAdded { .. }))
            ));
            let answer = SetupAnswer {
                alias: *alias,
                identity: identity(),
                term: publication.term,
                challenge: ChallengeBlock {
                    receiver_boot_id: [7, 8],
                    nonce: [9, 9],
                },
                joins: Lanes::new(&[0]).unwrap(),
            };
            sender.bind(EndpointId(1), source, &answer, 0);
            let status = StatusMessage {
                alias: *alias,
                identity: identity(),
                receiver: Receiver {
                    receiver_boot_id: [7, 8],
                    receiver_id: 1,
                },
                group_tag: 0,
                lanes: Lanes::new(&[LaneStatus {
                    consumption: 0,
                    window: 32_768,
                }])
                .unwrap(),
            };
            sender.status(EndpointId(1), source, &status, 1);
            assert!(sender.sessions.is_established(EndpointId(1), *alias));
            for i in 0..frames {
                let _ = log.publications[0]
                    .append(&[i; 1000], AppendOptions::default())
                    .unwrap();
            }
            logs.push(log);
        }
        let rig = Self {
            sender,
            role,
            halves,
            observer,
            sent,
            _logs: logs,
        };
        rig.script(usize::from(frames) * aliases.len());
        let mut rig = rig;
        rig.cycle(2);
        assert_eq!(
            rig.datagrams().len(),
            usize::from(frames) * aliases.len(),
            "first sends"
        );
        rig
    }

    fn script(&self, count: usize) {
        for _ in 0..count {
            self.observer
                .push_send(karyos_io::sockets::ops::SendResult::Sent {
                    sent: 1,
                    error: None,
                });
        }
    }

    fn cycle(&mut self, now: u64) {
        let _ = self.sender.duty(&mut self.halves, now).unwrap();
    }

    fn datagrams(&self) -> Vec<Vec<u8>> {
        self.sent.lock().unwrap().clone()
    }

    /// A NAK of receiver 1 for `alias` from `source`, handed over by the
    /// receiver.
    fn nak(&self, alias: Alias, source: SocketAddr, start: u64, length: u32) {
        use karyos_protocol::frame::Lane;
        use karyos_protocol::network::{Nak, NakRange, Receiver};

        let nak = Nak {
            alias,
            identity: identity(),
            receiver: Receiver {
                receiver_boot_id: [7, 8],
                receiver_id: 1,
            },
            range: NakRange {
                lane: Lane::ZERO,
                length,
                start,
            },
        };
        self.role
            .to_sender
            .try_post(super::ControlItem::Incoming {
                endpoint: EndpointId(1),
                source,
                control: Control::Nak(nak),
                seen: 0,
            })
            .unwrap();
    }
}

/// The aligned length of one 1000-byte message's frame.
const FRAME: u64 = 1056;

/// A bound receiver's NAK is admitted in the control step and repaired in
/// the same cycle, before first sends; a NAK from another source naming
/// that receiver is dropped; admission's and step 8's ERRs go to the
/// receiver's bound source.
#[test]
fn naks_are_repaired_and_answered() {
    use karyos_protocol::network::{Datagram, NakReplyReason, classify};

    let mut rig = RepairRig::new(AgentConfig::default(), &[alias()], 4);
    let first = rig.datagrams();
    let source = SocketAddr::from(RECEIVER_SOURCE);
    rig.nak(alias(), source, FRAME, 1056);
    rig.nak(alias(), "10.0.0.66:5000".parse().unwrap(), 0, 1056);
    rig.script(1);
    rig.cycle(3);
    let counters = rig.sender.counters();
    assert_eq!(
        (counters.naks, counters.nak_unbound, counters.repairs),
        (1, 1, 1)
    );
    assert_eq!(rig.datagrams().last(), first.get(1));
    // Beyond what was sent: admission's RANGE_INVALID, to the source.
    rig.nak(alias(), source, 4 * FRAME, 1056);
    // Not a frame boundary: step 8's RANGE_INVALID, to the bound source.
    rig.nak(alias(), source, 2 * FRAME + 32, 1024);
    rig.script(2);
    rig.cycle(4);
    let replies: Vec<_> = rig
        .datagrams()
        .iter()
        .filter_map(|bytes| match classify(bytes) {
            Ok(Datagram::Control(Control::NakReply(reply))) => Some(reply),
            _ => None,
        })
        .collect();
    assert_eq!(replies.len(), 2, "{replies:?}");
    assert!(
        replies
            .iter()
            .all(|reply| reply.reason == NakReplyReason::RangeInvalid)
    );
    assert_eq!(
        (replies[0].range.start, replies[1].range.start),
        (4 * FRAME, 2 * FRAME + 32)
    );
    assert_eq!(rig.sender.counters().nak_replies, 2);
}

/// Step 8 ERRs go to the requester's binding as it is when they are sent:
/// a binding that moved to another receiver id, or expired, since the
/// NAK's admission gets none, and the ERR counts `nak_replies_unbound`.
#[test]
fn a_step_8_err_needs_its_binding_at_the_send() {
    use karyos_protocol::network::{Datagram, classify};

    let replies = |rig: &RepairRig| {
        rig.datagrams()
            .iter()
            .filter(|bytes| matches!(classify(bytes), Ok(Datagram::Control(Control::NakReply(_)))))
            .count()
    };
    for change in ["receiver id", "expiry"] {
        let mut rig = RepairRig::new(AgentConfig::default(), &[alias()], 4);
        let source = SocketAddr::from(RECEIVER_SOURCE);
        // Admitted with no repair budget: the job waits for step 8.
        let budget = rig.sender.repair.budget;
        rig.sender.repair.budget.loads = 0;
        rig.nak(alias(), source, 2 * FRAME + 32, 1024);
        rig.cycle(3);
        assert_eq!(rig.sender.counters().naks, 1, "{change}");
        match change {
            "receiver id" => rig.sender.bindings[0].receiver_id = Some(2),
            _ => {
                let _ = rig.sender.bindings.swap_remove(0);
            }
        }
        rig.sender.repair.budget = budget;
        rig.script(1);
        rig.cycle(4);
        let counters = rig.sender.counters();
        assert_eq!(
            (counters.nak_replies, counters.nak_replies_unbound),
            (0, 1),
            "{change}"
        );
        assert_eq!(replies(&rig), 0, "{change}");
    }
}

/// #301 review P2: an established guarded publication whose endpoint has
/// no TX half this cycle (it is being reset) still applies a guard close,
/// so the close acknowledgement does not wait for the reset.
#[test]
fn a_guard_close_applies_without_a_tx_half() {
    use std::sync::Arc;

    use karyos_sys::applied_epoch::AppliedEpoch;
    use karyos_sys::sync::Ordering;

    let mut rig = RepairRig::new(AgentConfig::default(), &[alias()], 2);
    let word = Arc::new(karyos_client::HeapWords::zeroed(1));
    word.words()[0].store(karyos_sys::guard::created(), Ordering::Release);
    assert_eq!(karyos_sys::guard::reopen(&word.words()[0], 1), Ok(2));
    let cell = Arc::new(AppliedEpoch::new());
    rig.sender.publications[0]
        .guard(
            super::super::data::GuardSpec {
                word: Arc::clone(&word) as Arc<dyn karyos_client::SharedWords>,
                cell: Arc::clone(&cell),
                epoch: 2,
                rate: None,
            },
            0,
        )
        .unwrap();
    let _ = karyos_sys::guard::close(&word.words()[0]).unwrap();
    let mut halves = std::mem::take(&mut rig.halves);
    halves.retain(|(_, half)| !matches!(half, super::super::Half::Tx(_)));
    let _ = rig.sender.duty(&mut halves, 3).unwrap();
    assert_eq!(cell.try_read().unwrap().epoch, 3);
}

/// At most `naks_per_cycle` NAKs reach admission in a cycle; the rest are
/// dropped and counted.
#[test]
fn naks_per_cycle_are_bounded() {
    let mut config = AgentConfig::default();
    config.repair.naks_per_cycle = 2;
    let mut rig = RepairRig::new(config, &[alias()], 4);
    let source = SocketAddr::from(RECEIVER_SOURCE);
    for at in 0..3 {
        rig.nak(alias(), source, at * FRAME, 1056);
    }
    rig.script(3);
    rig.cycle(3);
    let counters = rig.sender.counters();
    assert_eq!((counters.naks, counters.nak_cycle_budget), (2, 1));
    // A new cycle admits again.
    rig.nak(alias(), source, 3 * FRAME, 1056);
    rig.script(1);
    rig.cycle(4);
    assert_eq!(rig.sender.counters().naks, 3);
}

/// Repair runs the publications in turn from a cursor that moves every
/// cycle, within one budget per cycle: with room for one frame a cycle,
/// two publications with two-frame jobs alternate.
#[test]
fn repairs_take_turns_across_publications() {
    use karyos_protocol::network::{Datagram, classify};

    let mut config = AgentConfig::default();
    config.repair.budget.bytes = FRAME;
    let other = Alias {
        session_id: 7,
        stream_id: 6,
    };
    let mut rig = RepairRig::new(config, &[alias(), other], 2);
    let before = rig.datagrams().len();
    let source = SocketAddr::from(RECEIVER_SOURCE);
    rig.nak(alias(), source, 0, 2 * 1056);
    rig.nak(other, source, 0, 2 * 1056);
    for now in 3..7 {
        rig.script(1);
        rig.cycle(now);
    }
    let sessions: Vec<i32> = rig.datagrams()[before..]
        .iter()
        .filter_map(|bytes| match classify(bytes) {
            Ok(Datagram::DataBatch(data)) => Some(data.alias().session_id),
            _ => None,
        })
        .collect();
    assert_eq!(sessions.len(), 4);
    assert_ne!(sessions[0], sessions[1], "{sessions:?}");
    assert_ne!(sessions[1], sessions[2], "{sessions:?}");
    assert_eq!(rig.sender.counters().repairs, 4);
}

/// #275 review P2: a SOLICIT the RSP_SETUP limits refuse leaves no entry,
/// so the next DATA for the key asks again once the rate refills, instead
/// of waiting out an entry that was never sent and its holdoff.
#[test]
fn a_rate_limited_solicit_leaves_no_entry() {
    let config = AgentConfig {
        rsp_setup_per_destination: 1,
        ..AgentConfig::default()
    };
    let (sender, mut receiver) = super::roles(&config).unwrap();
    let (sessions, _link) = event_ring();
    receiver
        .subscriptions
        .push((EndpointId(1), 6, 1 << 20, true, false));
    let source: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    let other = Alias {
        session_id: 50,
        stream_id: 6,
    };
    let sent = || {
        let mut count = 0;
        while let Ok(Some(_)) = sender.from_receiver.try_take() {
            count += 1;
        }
        count
    };
    let bytes = [0u8; 32];
    receiver.inject_data(&sessions, EndpointId(1), source, alias(), &bytes, 1);
    assert_eq!(sent(), 1);
    // The destination's rate is spent: refused, and withdrawn.
    for at in 2..5 {
        receiver.inject_data(&sessions, EndpointId(1), source, other, &bytes, at);
    }
    assert_eq!(sent(), 0);
    // The rates are checked before any entry: nothing was created, so
    // nothing was withdrawn (ACS 15956).
    let counters = receiver.session_counters();
    assert_eq!((counters.solicits, counters.solicits_withdrawn), (1, 0));
    assert_eq!(receiver.counters().rsp_setup_rate_limited, 3);
    // A second later the rate has refilled: the key is solicited.
    receiver.inject_data(
        &sessions,
        EndpointId(1),
        source,
        other,
        &bytes,
        1_000_000_002,
    );
    assert_eq!(sent(), 1);
    let counters = receiver.session_counters();
    assert_eq!((counters.solicits, counters.solicits_withdrawn), (2, 0));
}

/// Mutants of the #275 review: DATA solicits only on a subscribed stream
/// and from an answerable source (no entry at all otherwise), and a
/// solicited answer cannot size an image above the subscription's term
/// bound.
#[test]
fn solicits_need_a_subscription_an_answerable_source_and_a_term_bound() {
    use karyos_protocol::network::SetupAnswer;

    let (sender, mut receiver) = super::roles(&AgentConfig::default()).unwrap();
    let (sessions, _link) = event_ring();
    let source: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    let bytes = [0u8; 32];
    // Not subscribed: nothing.
    receiver.inject_data(&sessions, EndpointId(1), source, alias(), &bytes, 1);
    assert!(sender.from_receiver.try_take().unwrap().is_none());
    receiver
        .subscriptions
        .push((EndpointId(1), 6, 65_536, true, false));
    // A group source cannot be answered: no entry is created.
    let group: SocketAddr = "239.1.1.1:5000".parse().unwrap();
    receiver.inject_data(&sessions, EndpointId(1), group, alias(), &bytes, 2);
    let counters = receiver.session_counters();
    assert_eq!((counters.solicits, counters.solicits_withdrawn), (0, 0));
    assert_eq!(receiver.counters().unanswerable_source, 1);
    // Subscribed and answerable: one SOLICIT.
    receiver.inject_data(&sessions, EndpointId(1), source, alias(), &bytes, 3);
    let Ok(Some(super::ControlItem::Outgoing {
        control: Control::Solicit(solicit),
        ..
    })) = sender.from_receiver.try_take()
    else {
        panic!("no SOLICIT");
    };
    assert_eq!(receiver.session_counters().solicits, 1);
    // Its answer names a term above the subscription's bound: dropped,
    // no image.
    let answer = SetupAnswer {
        alias: alias(),
        identity: identity(),
        term: TermParams {
            term_length: 1 << 20,
            initial_term_id: 9,
            mtu: 1408,
        },
        challenge: solicit.challenge,
        joins: Lanes::new(&[0]).unwrap(),
    };
    receiver.inject_control(
        &sessions,
        EndpointId(1),
        source,
        Control::SetupAnswer(answer),
        4,
    );
    assert_eq!(receiver.counters().term_too_large, 1);
    assert_eq!(receiver.counters().create_image, 0);
}

/// ACS 15956: the per-driver total is checked before any entry too: a
/// second source over `rsp_setup_rate` creates nothing.
#[test]
fn the_total_rsp_rate_is_checked_before_any_entry() {
    let config = AgentConfig {
        rsp_setup_rate: 1,
        ..AgentConfig::default()
    };
    let (sender, mut receiver) = super::roles(&config).unwrap();
    let (sessions, _link) = event_ring();
    receiver
        .subscriptions
        .push((EndpointId(1), 6, 1 << 20, true, false));
    let bytes = [0u8; 32];
    let first: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    let second: SocketAddr = "10.0.0.10:5000".parse().unwrap();
    receiver.inject_data(&sessions, EndpointId(1), first, alias(), &bytes, 1);
    receiver.inject_data(&sessions, EndpointId(1), second, alias(), &bytes, 2);
    let mut sent = 0;
    while let Ok(Some(_)) = sender.from_receiver.try_take() {
        sent += 1;
    }
    assert_eq!(sent, 1);
    let counters = receiver.session_counters();
    assert_eq!((counters.solicits, counters.solicits_withdrawn), (1, 0));
    assert_eq!(receiver.counters().rsp_setup_total_limited, 1);
}

/// ACS 15933: a confirmed binding keeps a publication established even
/// with no membership attached; once the binding expires, the publication
/// is disconnected and announces again.
#[test]
fn a_confirmed_binding_keeps_the_publication_established() {
    let mut sender = sm_sender();
    let endpoint = EndpointId(1);
    let receiver: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    sender.bind(endpoint, receiver, &sm_answer([7, 8], 0), 0);
    sender.status(endpoint, receiver, &sm_status([7, 8], 0), 1);
    assert!(sender.sessions.is_established(endpoint, alias()));
    let mut halves: [(EndpointId, super::Half<karyos_io::sockets::OsSocket>); 0] = [];
    sender.duty(&mut halves, 2).unwrap();
    assert!(sender.sessions.is_established(endpoint, alias()));
    assert_eq!(sender.session_counters().reannounced, 0);
    // Past `image_liveness_timeout` with no SM: the binding expires.
    sender
        .duty(
            &mut halves,
            1 + AgentConfig::default().image_liveness_timeout,
        )
        .unwrap();
    assert!(!sender.sessions.is_established(endpoint, alias()));
    assert_eq!(sender.session_counters().reannounced, 1);
}

/// Commits a DATA frame of `payload` bytes at `offset` of the first term
/// into `image`'s lane 0.
fn commit_frame(
    image: &mut super::Installed,
    params: &karyos_sys::receive::ImageParams,
    offset: u32,
    payload: usize,
) {
    use karyos_protocol::frame::{Flags, FrameType, Lane, Word0};
    use karyos_sys::receive::{Item, ValidatedDatagram};

    let length = 32 + payload;
    let mut bytes = vec![0u8; length];
    let word0 = Word0::new(
        i32::try_from(length).unwrap(),
        Flags::new(true, true, false, false, Lane::ZERO),
        FrameType::Data,
    );
    bytes[..8].copy_from_slice(&word0.pack().to_le_bytes());
    bytes[8..12].copy_from_slice(&offset.to_le_bytes());
    bytes[12..16].copy_from_slice(&5i32.to_le_bytes());
    bytes[16..20].copy_from_slice(&6i32.to_le_bytes());
    bytes[20..24].copy_from_slice(&9u32.to_le_bytes());
    let datagram = ValidatedDatagram::parse(&bytes, params).unwrap();
    for item in datagram.items() {
        let Item::Frame(frame) = item else {
            panic!("not a frame");
        };
        assert!(matches!(
            image.owner.receive(&frame),
            Ok(karyos_sys::log_buffer::Received::Committed { .. })
        ));
    }
}

/// The receiver with `image` installed alone, and the sender whose ring
/// its NAKs reach.
fn repairing(image: super::Installed) -> (super::SenderRole, super::ReceiverRole) {
    let (sender, mut receiver) = super::roles(&AgentConfig::default()).unwrap();
    receiver.images.push(image);
    (sender, receiver)
}

/// Takes the sender's next NAK and reports it submitted at `start`, as
/// the sender's control path does.
fn submit_nak(sender: &super::SenderRole, start: u64) -> karyos_protocol::network::Nak {
    let Ok(Some(super::ControlItem::Outgoing {
        control: Control::Nak(nak),
        guard: Some(super::ItemGuard::Report(mut guard)),
        ..
    })) = sender.from_receiver.try_take()
    else {
        panic!("no NAK");
    };
    guard.sending(start);
    guard.submitted();
    nak
}

/// Phase 6 wiring, RC-9 with `on_unrecoverable = skip`: RANGE_UNAVAILABLE
/// with a floor inside a NAKed hole that late data split makes the whole
/// NAKed range unrecoverable. The first part is sealed at the reply; the
/// part past the floor, found by the next observation inside the span, is
/// sealed then. No hole remains.
#[test]
fn a_split_hole_past_the_floor_is_sealed_whole() {
    use karyos_protocol::frame::Lane;
    use karyos_protocol::network::{NakReply, NakReplyReason};
    use karyos_sys::log_buffer::{SkipConfig, Unrecoverable};

    let (mut image, params) = installed_image_with(SkipConfig {
        on_unrecoverable: Unrecoverable::Skip,
        ..SkipConfig::reliable()
    });
    commit_frame(&mut image, &params, 0, 32);
    commit_frame(&mut image, &params, 1088, 32);
    let (sender, mut receiver) = repairing(image);
    receiver.repair(0, 1).unwrap();
    let nak = submit_nak(&sender, 1);
    assert_eq!((nak.range.start, nak.range.length), (64, 1024));
    receiver.repair(0, 2).unwrap();
    // Late original data splits the hole: [64, 320) and [576, 1088).
    commit_frame(&mut receiver.images[0], &params, 320, 224);
    receiver.repair(0, 3).unwrap();
    let reply = NakReply::answering(
        &nak,
        NakReplyReason::RangeUnavailable {
            lowest_retained: 400,
        },
    );
    let image = &mut receiver.images[0];
    let crate::repair::loss::ReplyOutcome::Unrecoverable {
        hole,
        lowest_retained,
        ..
    } = image.loss.reply(&reply, 1 << 20)
    else {
        panic!("not unrecoverable");
    };
    super::unrecoverable(
        image,
        &mut receiver.counters,
        Lane::ZERO,
        hole,
        lowest_retained,
        4,
    );
    receiver.repair(0, 5).unwrap();
    assert_eq!(
        receiver.images[0].owner.first_hole(Lane::ZERO).unwrap(),
        None
    );
    assert_eq!(receiver.counters().gaps_sealed, 2);
    assert!(receiver.images[0].closing.is_none());
}

/// Phase 6 wiring: a lane's NAK stays one in the ring: while its report
/// is not settled (the sender has not taken it), no other is posted.
#[test]
fn one_nak_per_lane_waits_in_the_ring() {
    let (mut image, params) = installed_image();
    commit_frame(&mut image, &params, 0, 32);
    commit_frame(&mut image, &params, 1088, 32);
    let (_sender, mut receiver) = repairing(image);
    for now in [1, 10_000_000, 20_000_000, 2_000_000_000] {
        receiver.repair(0, now).unwrap();
    }
    assert_eq!(receiver.counters().naks, 1);
}

/// Phase 6 wiring: with the control ring full, a due NAK is counted and
/// reported not submitted; it stays due.
#[test]
fn a_full_ring_reports_the_nak_not_submitted() {
    use karyos_protocol::frame::Lane;

    let (mut image, params) = installed_image();
    commit_frame(&mut image, &params, 0, 32);
    commit_frame(&mut image, &params, 1088, 32);
    let (_sender, mut receiver) = repairing(image);
    let filler = || super::ControlItem::Outgoing {
        endpoint: EndpointId(1),
        destination: "10.0.0.9:5000".parse().unwrap(),
        control: Control::SetupAnnounce(karyos_protocol::network::SetupAnnounce {
            alias: alias(),
            identity: identity(),
            term: publication(EndpointId(1)).term,
            lane_count: 1,
        }),
        guard: None,
    };
    while receiver.to_sender.try_post(filler()).is_ok() {}
    receiver.repair(0, 1).unwrap();
    let counters = receiver.counters();
    assert_eq!((counters.naks, counters.ring_full_nak), (0, 1));
    let loss = receiver.images[0].loss.counters();
    assert_eq!(loss.not_submitted, 1);
    assert!(receiver.images[0].loss.due(Lane::ZERO, 2).is_some());
}

/// Phase 6 wiring, RC-6: an uncertain NAK counts as submitted at its
/// start (its retry waits one RTT); a second while it is unresolved is a
/// route fault, and the image's NAKs stop.
#[test]
fn uncertain_naks_are_bounded_per_image() {
    let (mut image, params) = installed_image();
    commit_frame(&mut image, &params, 0, 32);
    commit_frame(&mut image, &params, 1088, 32);
    let (sender, mut receiver) = repairing(image);
    let take = |sender: &super::SenderRole| {
        let Ok(Some(super::ControlItem::Outgoing {
            guard: Some(super::ItemGuard::Report(mut guard)),
            ..
        })) = sender.from_receiver.try_take()
        else {
            panic!("no NAK");
        };
        guard.sending(1);
        guard.uncertain();
    };
    receiver.repair(0, 1).unwrap();
    take(&sender);
    receiver.repair(0, 2).unwrap();
    let loss = receiver.images[0].loss.counters();
    assert_eq!((loss.uncertain, loss.submitted), (1, 1));
    // Its retry, one RTT later, is uncertain too: a route fault.
    let rtt = crate::rtt::RttConfig::default().rtt_initial;
    receiver.repair(0, 2 + rtt).unwrap();
    take(&sender);
    receiver.repair(0, 3 + rtt).unwrap();
    assert_eq!(receiver.counters().nak_route_faults, 1);
    let naks = receiver.counters().naks;
    receiver.repair(0, 10 * rtt).unwrap();
    assert_eq!(receiver.counters().naks, naks);
}

/// #284 review P3: a NAK the sender did not submit is due again at once.
#[test]
fn a_nak_not_submitted_is_due_again() {
    let (mut image, params) = installed_image();
    commit_frame(&mut image, &params, 0, 32);
    commit_frame(&mut image, &params, 1088, 32);
    let (sender, mut receiver) = repairing(image);
    receiver.repair(0, 1).unwrap();
    // The sender drops it unsubmitted: its guard reports NotSubmitted.
    drop(sender.from_receiver.try_take().unwrap());
    receiver.repair(0, 2).unwrap();
    assert_eq!(receiver.counters().naks, 2);
    assert_eq!(receiver.images[0].loss.counters().not_submitted, 1);
}

/// #284 review P3: on a reliable image under `skip`, the skip policy's
/// duty seals the holes left below an unrecoverable range that its reply
/// could not seal in one call (at most a few per call).
#[test]
fn the_skip_duty_seals_what_one_reply_could_not() {
    use karyos_protocol::frame::Lane;
    use karyos_sys::log_buffer::{SkipConfig, Unrecoverable};

    let (mut image, params) = installed_image_with(SkipConfig {
        on_unrecoverable: Unrecoverable::Skip,
        ..SkipConfig::reliable()
    });
    // Ten 64-byte holes, each after a 64-byte frame.
    for k in 0..11u32 {
        commit_frame(&mut image, &params, 128 * k, 32);
    }
    let (_sender, mut receiver) = repairing(image);
    let hole = crate::repair::loss::Hole {
        start: 64,
        length: 64,
    };
    super::unrecoverable(
        &mut receiver.images[0],
        &mut receiver.counters,
        Lane::ZERO,
        hole,
        2048,
        1,
    );
    let sealed = receiver.counters().gaps_sealed;
    assert!(sealed < 10, "one call sealed {sealed}");
    receiver.repair(0, 2).unwrap();
    assert_eq!(receiver.counters().gaps_sealed, 10);
    assert_eq!(
        receiver.images[0].owner.first_hole(Lane::ZERO).unwrap(),
        None
    );
}

/// #284 review P3: a covered hole ends a tail wait, so a later tail waits
/// its RTT afresh instead of NAKing at once.
#[test]
fn a_covered_hole_restarts_the_tail_wait() {
    let (mut image, params) = installed_image();
    commit_frame(&mut image, &params, 0, 32);
    image.heartbeat_marks[0] = Some(4096);
    let (sender, mut receiver) = repairing(image);
    let rtt = crate::rtt::RttConfig::default().rtt_initial;
    // The tail is seen at 1: it waits one RTT.
    receiver.repair(0, 1).unwrap();
    assert_eq!(receiver.counters().naks, 0);
    // A frame further on leaves a covered hole [64, 1024): it is NAKed.
    commit_frame(&mut receiver.images[0], &params, 1024, 32);
    receiver.repair(0, 2).unwrap();
    assert_eq!(receiver.counters().naks, 1);
    drop(sender.from_receiver.try_take().unwrap());
    // The hole fills; the tail is back, and waits one RTT from now.
    commit_frame(&mut receiver.images[0], &params, 64, 928);
    receiver.repair(0, 1 + rtt).unwrap();
    assert_eq!(receiver.counters().naks, 1);
    receiver.repair(0, 1 + 2 * rtt).unwrap();
    assert_eq!(receiver.counters().naks, 2);
}

/// #284 review P3: NAK retries reach the receiver's counters, where a
/// reliable image whose sender never repairs is visible.
#[test]
fn nak_retries_are_counted_by_the_receiver() {
    let (mut image, params) = installed_image();
    commit_frame(&mut image, &params, 0, 32);
    commit_frame(&mut image, &params, 1088, 32);
    let (sender, mut receiver) = repairing(image);
    let rtt = crate::rtt::RttConfig::default().rtt_initial;
    receiver.repair(0, 1).unwrap();
    submit_nak(&sender, 1);
    receiver.repair(0, 2).unwrap();
    assert_eq!(receiver.counters().nak_retries, 0);
    receiver.repair(0, 1 + rtt).unwrap();
    submit_nak(&sender, 1 + rtt);
    receiver.repair(0, 2 + rtt).unwrap();
    assert_eq!(receiver.counters().nak_retries, 1);
}

/// #284 review P2-2: a route fault asks for the endpoint's reset at once,
/// then once per `RESET_REQUEST_CYCLES` while it holds; the reset's new
/// epoch resolves it, and a later fault asks again at once.
#[test]
fn a_route_fault_asks_for_a_reset_at_its_cadence() {
    use super::super::data::RESET_REQUEST_CYCLES;
    use karyos_io::backend::BackendEpoch;

    let (mut image, params) = installed_image();
    commit_frame(&mut image, &params, 0, 32);
    commit_frame(&mut image, &params, 1088, 32);
    let (_sender, mut receiver) = repairing(image);
    receiver.repair(0, 1).unwrap();
    let nak = receiver.posted_naks()[0];
    let slot = receiver.images[0].slot;
    receiver.fault_naks(slot, &nak);
    let mut asked = Vec::new();
    let mut ask = |receiver: &mut super::ReceiverRole, cycle| {
        receiver.cycle = cycle;
        receiver.request_resets(|endpoint| {
            asked.push((cycle, endpoint));
            true
        });
    };
    ask(&mut receiver, 10);
    ask(&mut receiver, 10 + RESET_REQUEST_CYCLES - 1);
    ask(&mut receiver, 10 + RESET_REQUEST_CYCLES);
    assert_eq!(
        asked,
        [
            (10, EndpointId(1)),
            (10 + RESET_REQUEST_CYCLES, EndpointId(1))
        ]
    );
    // The reset: a new epoch of the endpoint's RX half resolves the fault.
    receiver.rx_epoch(EndpointId(1), BackendEpoch::FIRST);
    receiver.rx_epoch(
        EndpointId(1),
        BackendEpoch::new(std::num::NonZeroU32::new(2).unwrap()),
    );
    assert!(!receiver.images[0].loss.is_faulted());
    // A later fault asks again at once.
    receiver.fault_naks(slot, &nak);
    let mut later = Vec::new();
    receiver.cycle = 11 + RESET_REQUEST_CYCLES;
    receiver.request_resets(|endpoint| {
        later.push(endpoint);
        true
    });
    assert_eq!(later, [EndpointId(1)]);
    assert_eq!(receiver.counters().reset_requests, 3);
}

/// rp-w3, RP-7 helpers: `image` with two path routes and a copy slot per
/// path on its one lane, its lane 0 hole observed and its NAK due.
fn two_route_image() -> (super::Installed, karyos_protocol::network::Nak) {
    use std::sync::Arc;

    use karyos_protocol::frame::Lane;

    let (mut image, _) = installed_image();
    image.routes = vec![super::CopyRoute::default(); 2];
    image.copies = (0..2)
        .map(|_| super::PendingNak {
            slot: Arc::new(super::ReportSlot::default()),
            pending: None,
        })
        .collect();
    let hole = crate::repair::loss::Hole {
        start: 0,
        length: 64,
    };
    let _ = image.loss.observe(Lane::ZERO, Some(hole), 0);
    let nak = image.loss.due(Lane::ZERO, 0).unwrap();
    (image, nak)
}

/// Reports `outcome` for the copy of lane 0 on `path`, started at `start`.
fn report_copy(
    image: &mut super::Installed,
    path: usize,
    nak: karyos_protocol::network::Nak,
    start: u64,
    submitted: bool,
) {
    let copy = &mut image.copies[path];
    let mut guard = super::ReportGuard::take(&copy.slot);
    guard.sending(start);
    if submitted {
        guard.submitted();
    } else {
        guard.uncertain();
    }
    copy.pending = Some(nak);
}

/// rp-w3, RP-7: a NAK's copies on several paths anchor it once, at the
/// first copy submitted; a later copy's report records nothing more.
#[test]
fn nak_copies_anchor_their_nak_once() {
    let (mut image, nak) = two_route_image();
    let mut counters = super::ReceiverCounters::default();
    report_copy(&mut image, 1, nak, 10, true);
    super::settle_copies(&mut image, &mut counters, 0);
    assert_eq!(image.loss.counters().submitted, 1);
    report_copy(&mut image, 0, nak, 20, true);
    super::settle_copies(&mut image, &mut counters, 0);
    assert_eq!(image.loss.counters().submitted, 1);
    assert_eq!(image.loss.counters().retries, 0);
}

/// rp-w3, RC-6 per route: an uncertain copy on one route anchors the NAK
/// (counted as submitted at its start) and faults nothing; a second
/// uncertain copy on the same route while the first is unresolved faults
/// that route only, never the image's own.
#[test]
fn an_uncertain_copy_faults_only_its_route() {
    let (mut image, nak) = two_route_image();
    let mut counters = super::ReceiverCounters::default();
    report_copy(&mut image, 1, nak, 10, false);
    super::settle_copies(&mut image, &mut counters, 0);
    super::anchor_uncertain(&mut image, 0);
    assert_eq!(image.loss.counters().submitted, 1);
    assert!(!image.routes[1].faulted);
    report_copy(&mut image, 1, nak, 20, false);
    super::settle_copies(&mut image, &mut counters, 0);
    assert!(image.routes[1].faulted);
    assert!(!image.routes[0].faulted);
    assert_eq!(counters.nak_route_faults, 1);
    assert!(!image.loss.is_faulted());
}

/// A guarded publication with no receiver yet is not served, but its
/// sender still applies a guard close each cycle, so the close
/// acknowledgement does not wait on it.
#[test]
fn an_unestablished_guarded_publication_applies_a_close() {
    use std::sync::Arc;

    use karyos_sys::applied_epoch::AppliedEpoch;
    use karyos_sys::sync::Ordering;

    let (mut sender, _role) = receiver_with(AgentConfig::default());
    let word = Arc::new(karyos_client::HeapWords::zeroed(1));
    word.words()[0].store(karyos_sys::guard::created(), Ordering::Release);
    assert_eq!(karyos_sys::guard::reopen(&word.words()[0], 1), Ok(2));
    let cell = Arc::new(AppliedEpoch::new());
    let (replies, _keep) =
        super::ring::ring::<AgentEvent<OsSocket>>(std::num::NonZeroUsize::new(4).unwrap());
    let (path, _log) = outbound(EndpointId(1), "10.0.0.9:5000".parse().unwrap());
    let command = AgentCommand::<OsSocket>::AddPublication {
        reply: replies.reserve().unwrap(),
        publication: publication(EndpointId(1)),
        outbound: path,
        guard: Some(super::super::data::GuardSpec {
            word: Arc::clone(&word) as Arc<dyn karyos_client::SharedWords>,
            cell: Arc::clone(&cell),
            epoch: 2,
            rate: None,
        }),
        roles: None,
    };
    assert!(matches!(
        sender.command(command),
        Some((_, AgentEvent::PublicationAdded { .. }))
    ));
    let _ = karyos_sys::guard::close(&word.words()[0]).unwrap();
    let _ = sender.duty::<OsSocket>(&mut [], 1).unwrap();
    assert_eq!(cell.try_read().unwrap().epoch, 3);
}

/// MC-1: a publication's configured roles reach its membership: its
/// strategy, and a required receiver that has not joined holds admission
/// (NotJoined) where the same publication without roles is open; roles the
/// membership cannot hold (a zero id) refuse the publication.
#[test]
fn a_publication_takes_its_configured_roles() {
    use crate::membership::{Admission, PublicationRoles, Strategy};

    let add = |roles: Option<PublicationRoles>| {
        let (mut sender, _role) = receiver_with(AgentConfig::default());
        let (replies, _keep) =
            super::ring::ring::<AgentEvent<OsSocket>>(std::num::NonZeroUsize::new(4).unwrap());
        let (path, _log) = outbound(EndpointId(1), "10.0.0.9:5000".parse().unwrap());
        let event = sender
            .command(AgentCommand::<OsSocket>::AddPublication {
                reply: replies.reserve().unwrap(),
                publication: publication(EndpointId(1)),
                outbound: path,
                guard: None,
                roles: roles.map(Box::new),
            })
            .map(|(_, event)| event);
        let membership = sender
            .membership_of(alias())
            .map(|membership| (membership.config().strategy, membership.admission(1)));
        (event, membership)
    };
    let (event, membership) = add(Some(PublicationRoles {
        strategy: Strategy::Max,
        required: vec![7],
        tags: vec![(9, 3)],
    }));
    assert!(
        matches!(event, Some(AgentEvent::PublicationAdded { .. })),
        "{event:?}"
    );
    assert_eq!(membership, Some((Strategy::Max, Admission::NotJoined)));
    let (_, membership) = add(None);
    assert_eq!(membership, Some((Strategy::Min, Admission::Open)));
    let (event, membership) = add(Some(PublicationRoles {
        strategy: Strategy::Min,
        required: vec![0],
        tags: Vec::new(),
    }));
    assert!(
        matches!(event, Some(AgentEvent::PublicationRefused { .. })),
        "{event:?}"
    );
    assert_eq!(membership, None);
    // The table bounds the roles: 64 entries (its default size) fit, 65
    // do not, for the required set and for the tags alike.
    for (count, added) in [(64u64, true), (65, false)] {
        for tagged in [false, true] {
            let ids: Vec<u64> = (1..=count).collect();
            let roles = if tagged {
                PublicationRoles {
                    strategy: Strategy::Min,
                    required: Vec::new(),
                    tags: ids.iter().map(|id| (*id, 1)).collect(),
                }
            } else {
                PublicationRoles {
                    strategy: Strategy::Min,
                    required: ids,
                    tags: Vec::new(),
                }
            };
            let (event, _) = add(Some(roles));
            assert_eq!(
                matches!(event, Some(AgentEvent::PublicationAdded { .. })),
                added,
                "{count} {}: {event:?}",
                if tagged { "tags" } else { "required" }
            );
        }
    }
}

/// #310 review: the anchor is the first copy submitted. An uncertain copy
/// reported first, in an earlier settle or in the same one, never
/// anchors when another copy of the round is submitted: the retry runs
/// from the submitted copy's start.
#[test]
fn a_submitted_copy_anchors_over_an_uncertain_one() {
    use karyos_protocol::frame::Lane;

    // Uncertain on path 0 first, submitted on path 1 later.
    let (mut image, nak) = two_route_image();
    let mut counters = super::ReceiverCounters::default();
    report_copy(&mut image, 0, nak, 10, false);
    super::settle_copies(&mut image, &mut counters, 0);
    report_copy(&mut image, 1, nak, 20, true);
    super::settle_copies(&mut image, &mut counters, 0);
    super::anchor_uncertain(&mut image, 0);
    assert_eq!(image.loss.counters().submitted, 1);
    // The retry is due one RTT after 20, not after 10: at 10 + RTT + 5
    // nothing is due yet.
    let rtt = crate::repair::loss::RttSource::rtt_snapshot(&image.rtt, 0);
    assert_eq!(image.loss.due(Lane::ZERO, 15 + rtt), None);
    // The same settle: both reports in before one call.
    let (mut image, nak) = two_route_image();
    report_copy(&mut image, 0, nak, 10, false);
    report_copy(&mut image, 1, nak, 20, true);
    super::settle_copies(&mut image, &mut counters, 0);
    super::anchor_uncertain(&mut image, 0);
    assert_eq!(image.loss.counters().submitted, 1);
    assert_eq!(image.loss.due(Lane::ZERO, 15 + rtt), None);
    assert!(image.uncertain_at[0].is_none());
}

/// #310 review: with no copy submitted once every copy reported, the
/// earliest uncertain copy anchors the NAK.
#[test]
fn the_earliest_uncertain_copy_anchors_when_none_is_submitted() {
    let (mut image, nak) = two_route_image();
    let mut counters = super::ReceiverCounters::default();
    report_copy(&mut image, 1, nak, 30, false);
    report_copy(&mut image, 0, nak, 10, false);
    super::settle_copies(&mut image, &mut counters, 0);
    super::anchor_uncertain(&mut image, 0);
    assert_eq!(image.loss.counters().submitted, 1);
    assert_eq!(counters.nak_copies_uncertain, 2);
    // Anchored at 10, the earliest start (#315 review): its retry is due
    // before an anchor at 30 would allow.
    let rtt = crate::repair::loss::RttSource::rtt_snapshot(&image.rtt, 0);
    assert!(
        image
            .loss
            .due(karyos_protocol::frame::Lane::ZERO, 25 + rtt)
            .is_some()
    );
}

/// Reports `outcome` for lane 0's NAK on the founding path.
fn report_founding(
    image: &mut super::Installed,
    nak: karyos_protocol::network::Nak,
    start: u64,
    submitted: bool,
) {
    let report = &mut image.naks[0];
    let mut guard = super::ReportGuard::take(&report.slot);
    guard.sending(start);
    if submitted {
        guard.submitted();
    } else {
        guard.uncertain();
    }
    report.pending = Some(nak);
}

/// #315 review P3: an uncertain founding copy is only a candidate, through
/// the founding report path: a later path's submitted copy anchors the
/// NAK at its own start. The founding route still counts its uncertainty.
#[test]
fn a_founding_uncertain_copy_yields_to_a_later_submitted_one() {
    use karyos_protocol::frame::Lane;

    let (mut image, nak) = two_route_image();
    let mut counters = super::ReceiverCounters::default();
    // The later copy is still in flight when the founding one reports.
    let mut copy = super::ReportGuard::take(&image.copies[1].slot);
    image.copies[1].pending = Some(nak);
    report_founding(&mut image, nak, 10, false);
    super::settle_founding(&mut image, &mut counters, 0);
    super::anchor_uncertain(&mut image, 0);
    assert_eq!(image.loss.counters().submitted, 0);
    assert_eq!(image.loss.counters().uncertain, 1);
    copy.sending(20);
    copy.submitted();
    super::settle_copies(&mut image, &mut counters, 0);
    super::anchor_uncertain(&mut image, 0);
    assert_eq!(image.loss.counters().submitted, 1);
    let rtt = crate::repair::loss::RttSource::rtt_snapshot(&image.rtt, 0);
    assert_eq!(image.loss.due(Lane::ZERO, 15 + rtt), None);
    assert!(image.uncertain_at[0].is_none());
}

/// #315 review P3: an uncertain copy that faults its route is no anchor
/// candidate; with no other copy the NAK stays unanchored.
#[test]
fn an_uncertain_copy_that_faults_its_route_is_no_candidate() {
    let (mut image, nak) = two_route_image();
    let mut counters = super::ReceiverCounters::default();
    image.routes[1].uncertain = true;
    report_copy(&mut image, 1, nak, 10, false);
    super::settle_copies(&mut image, &mut counters, 0);
    super::anchor_uncertain(&mut image, 0);
    assert!(image.routes[1].faulted);
    assert!(image.uncertain_at[0].is_none());
    assert_eq!(image.loss.counters().submitted, 0);
}

/// #310 review (M2): a NAK copy the control ring cannot take is skipped
/// and counted, its report slot left free: it never holds the lane's
/// next NAK back.
#[test]
fn a_skipped_copy_leaves_its_slot_free() {
    use std::num::NonZeroUsize;

    let (mut image, nak) = two_route_image();
    let mut counters = super::ReceiverCounters::default();
    let later = crate::sessions::receive::BindingKey {
        source: std::net::SocketAddr::from(([127, 0, 0, 1], 9)),
        ..image.key
    };
    let (mut to_sender, _from) = super::super::ring::ring(NonZeroUsize::new(1).unwrap());
    let filler = super::ControlItem::Outgoing {
        endpoint: image.key.endpoint,
        destination: image.key.source,
        control: karyos_protocol::network::Control::Nak(nak),
        guard: None,
    };
    assert!(to_sender.try_post(filler).is_ok());
    let _ = super::post_copies(
        &mut image,
        |path| (path == 1).then_some(later),
        &mut to_sender,
        &mut counters,
        0,
        nak,
    );
    assert_eq!(counters.nak_copies_skipped, 1);
    assert_eq!(counters.nak_copies, 0);
    assert!(image.copies[1].pending.is_none());
    assert!(!super::copies_busy(&image, 0));
}

/// #321 review P3: the sender role serves a routed publication over every
/// path's TX half, once it is established: each committed message goes out
/// on both paths.
#[test]
fn the_sender_serves_a_routed_publication_on_every_path() {
    use std::num::NonZeroU32;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use karyos_io::backend::InstanceId;
    use karyos_io::sockets::endpoint::SocketsEndpoint;
    use karyos_io::sockets::ops::SendResult;
    use karyos_io::sockets::scripted::ScriptedSocket;
    use karyos_protocol::network::{Datagram, classify};
    use karyos_sys::log_buffer::AppendOptions;

    use super::super::Half;

    let (mut sender, _receiver) = super::roles(&AgentConfig::default()).unwrap();
    sender.sessions.add(publication(EndpointId(1))).unwrap();
    let routes = [
        (EndpointId(1), "10.0.0.2:4000".parse().unwrap()),
        (EndpointId(2), "10.0.0.3:4000".parse().unwrap()),
    ];
    let (path, mut log) = super::super::data::testing::outbound_routed(
        &routes,
        alias(),
        publication(EndpointId(1)).term,
        1,
        false,
    );
    sender.publications.push(path);
    let mut halves = Vec::new();
    let mut counts = Vec::new();
    for id in 1..=2u32 {
        let socket = ScriptedSocket::new();
        let observer = socket.observer();
        let data = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&data);
        observer.set_send_hook(Box::new(move |_, datagrams| {
            for datagram in datagrams {
                if matches!(classify(datagram), Ok(Datagram::DataBatch(_))) {
                    count.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
        for _ in 0..16 {
            observer.push_send(SendResult::Sent {
                sent: 1,
                error: None,
            });
        }
        let instance = InstanceId::new(NonZeroU32::new(id).unwrap());
        let endpoint = SocketsEndpoint::open(&loopback(), instance, socket).unwrap();
        let (tx, _rx) = endpoint.split().unwrap();
        halves.push((EndpointId(id), Half::Tx(Box::new(tx))));
        counts.push(data);
    }
    let receiver: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    sender.bind(EndpointId(1), receiver, &sm_answer([7, 8], 0), 0);
    sender.status(EndpointId(1), receiver, &sm_status([7, 8], 1 << 20), 1);
    assert!(sender.sessions.is_established(EndpointId(1), alias()));
    for i in 0..2u8 {
        let _ = log.publications[0]
            .append(&[i; 1000], AppendOptions::default())
            .unwrap();
    }
    for now in 2..6 {
        let _ = sender.duty(&mut halves, now).unwrap();
    }
    assert_eq!(counts[0].load(Ordering::Relaxed), 2);
    assert_eq!(counts[1].load(Ordering::Relaxed), 2);
}

/// rp-w4b2b: a routed publication added to the sender has a SETUP side on
/// each path's endpoint: it is established once a receiver's SM arrives on
/// a later path, and its removal ends every path's side.
#[test]
fn a_routed_publication_has_a_setup_side_per_path() {
    let (mut sender, _receiver) = super::roles(&AgentConfig::default()).unwrap();
    let (replies, _keep) =
        super::ring::ring::<AgentEvent<OsSocket>>(std::num::NonZeroUsize::new(4).unwrap());
    let routes = [
        (EndpointId(1), "10.0.0.2:4000".parse().unwrap()),
        (EndpointId(2), "10.0.0.3:4000".parse().unwrap()),
    ];
    let (path, _log) = super::super::data::testing::outbound_routed(
        &routes,
        alias(),
        publication(EndpointId(1)).term,
        1,
        false,
    );
    let event = sender.command(AgentCommand::<OsSocket>::AddPublication {
        reply: replies.reserve().unwrap(),
        publication: publication(EndpointId(1)),
        outbound: path,
        guard: None,
        roles: None,
    });
    assert!(matches!(
        event,
        Some((_, AgentEvent::PublicationAdded { .. }))
    ));
    assert!(!sender.sessions.is_established(EndpointId(2), alias()));
    // The receiver of the later path answers and its SM arrives there.
    let receiver: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    sender.bind(EndpointId(2), receiver, &sm_answer([7, 8], 0), 0);
    sender.status(EndpointId(2), receiver, &sm_status([7, 8], 0), 1);
    assert!(sender.sessions.is_established(EndpointId(2), alias()));
    assert!(super::established(
        &sender.sessions,
        &sender.publications[0]
    ));
    // Removing it ends both paths' SETUP sides.
    let removed = sender.command(AgentCommand::<OsSocket>::RemovePublication {
        reply: replies.reserve().unwrap(),
        endpoint: EndpointId(1),
        alias: alias(),
        registration: 1,
    });
    assert!(matches!(
        removed,
        Some((_, AgentEvent::PublicationRemoved { .. }))
    ));
    assert!(!sender.sessions.remove(EndpointId(1), alias()));
    assert!(!sender.sessions.remove(EndpointId(2), alias()));
}
