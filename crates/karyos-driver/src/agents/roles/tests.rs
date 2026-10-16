// SPDX-License-Identifier: Apache-2.0

//! The establishment control path over real loopback sockets (phase 4b-1):
//! announce, challenge, answer, `CreateImage`; and a spoofed SOLICIT flood
//! capped by `setup_answer_rate`.

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

fn add_publication(links: &Links, a: EndpointId, destination: SocketAddr) {
    links
        .sender
        .post(|reply| AgentCommand::AddPublication {
            reply,
            publication: Publication {
                endpoint: a,
                alias: alias(),
                identity: identity(),
                term: TermParams {
                    term_length: 65_536,
                    initial_term_id: 9,
                    mtu: 1408,
                },
                lane_count: 1,
            },
            destination,
            joins: Lanes::new(&[0]).unwrap(),
        })
        .unwrap();
}

/// The sender announces from A to B; B's receiver challenges A; A's
/// receiver hands the challenge to the sender, which answers toward B; B's
/// receiver accepts it and asks the conductor for the image.
#[test]
fn a_loopback_setup_reaches_create_image() {
    let (mut agents, links, mut endpoints, a, b) = two_endpoints();
    let destination = endpoints.local_address(b).unwrap();
    add_publication(&links, a, destination);
    let (endpoint, created) = drive(&mut agents, &links, &mut endpoints, |event| match event {
        AgentEvent::CreateImage {
            endpoint,
            identity,
            joins,
            ..
        } => Some((endpoint, (identity, joins))),
        _ => None,
    });
    assert_eq!(endpoint, b);
    assert_eq!(created, (identity(), Lanes::new(&[0]).unwrap()));
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
    add_publication(&links, a, destination);
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
    sender
        .publications
        .push((EndpointId(1), alias(), group, Lanes::new(&[0]).unwrap()));
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

/// Condition (4): the `CreateImage` reply slot is reserved before the
/// ANSWER is consumed. With the receiver's event ring full, an answer
/// leaves the challenge pending (`NoCommandCredit`); once there is room,
/// the next answer installs it.
#[test]
fn an_answer_waits_for_its_create_image_slot() {
    let config = AgentConfig {
        event_capacity: 1,
        ..AgentConfig::default()
    };
    let (mut agents, links, mut endpoints, a, b) = two_endpoints_with(config);
    // The receiver's only event slot is held by an unread pong.
    links.receiver.ping(1).unwrap();
    agents.receiver.do_work(0).unwrap();
    let destination = endpoints.local_address(b).unwrap();
    add_publication(&links, a, destination);
    let mut now = 0u64;
    for _ in 0..300 {
        now += 1_000_000;
        agents.do_work(now).unwrap();
        // The sender's events only: the receiver's pong stays unread.
        while links.sender.take_event().is_some() {}
        std::thread::sleep(Duration::from_micros(200));
    }
    assert_eq!(agents.receiver.counters().create_image, 0);
    assert!(agents.receiver.role.sessions.counters().dropped >= 1);
    // Room again: the challenge, still pending, is answered again.
    assert!(links.receiver.take_event().is_some());
    let created = drive(&mut agents, &links, &mut endpoints, |event| match event {
        AgentEvent::CreateImage { endpoint, .. } => Some(endpoint),
        _ => None,
    });
    assert_eq!(created, b);
}
