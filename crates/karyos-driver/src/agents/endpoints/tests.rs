// SPDX-License-Identifier: Apache-2.0

//! The endpoint table over the scripted socket and the host's loopback
//! (`quantstratum-docs: karyos/design/driver-network-agents.md` §9, tests 8
//! and 9): open, reset, retire, refusals, and reclaiming after a stop.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::net::SocketAddr;

use karyos_io::sockets::scripted::ScriptedSocket;

use super::super::{
    AgentConfig, AgentRunner, NetworkAgents, ThreadingMode, YieldThenSleep, network_agents,
};
use super::*;

type S = ScriptedSocket;

fn config() -> SocketsConfig {
    SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)))
}

/// Drives the agents and the table until `want` events arrived.
fn settle<O: SocketOps>(
    agents: &mut NetworkAgents<O>,
    links: &AgentLinks<O>,
    endpoints: &mut Endpoints<O>,
    want: usize,
) -> Vec<EndpointEvent> {
    let mut events = Vec::new();
    for _ in 0..1000 {
        agents.do_work(0).unwrap();
        endpoints.poll(links, |event| events.push(event), |_| {});
        if events.len() >= want {
            return events;
        }
    }
    panic!("only {events:?}");
}

/// Open attaches both halves; reset reopens at the next epoch with the
/// halves attached again; retire closes the socket and empties the table.
#[test]
fn open_reset_and_retire() {
    let agent_config = AgentConfig::default();
    let (mut agents, links) = network_agents::<S>(agent_config).unwrap();
    let mut endpoints = Endpoints::new(&agent_config);
    let socket = ScriptedSocket::new();
    let observer = socket.observer();

    let id = endpoints.open(&links, config(), socket).unwrap();
    assert_eq!(
        settle(&mut agents, &links, &mut endpoints, 1),
        [EndpointEvent::Opened(id)]
    );
    assert!(endpoints.is_active(id));
    assert_eq!(observer.live_descriptors(), 2, "a TX and an RX descriptor");
    assert_eq!(observer.open_calls(), 1);

    endpoints.reset(&links, id).unwrap();
    assert_eq!(endpoints.reset(&links, id), Err(EndpointError::Busy(id)));
    // Reopened, then the reattached halves answer: active again.
    assert_eq!(
        settle(&mut agents, &links, &mut endpoints, 2),
        [
            EndpointEvent::Reopened {
                endpoint: id,
                returned: 0
            },
            EndpointEvent::Opened(id)
        ]
    );
    assert!(endpoints.is_active(id));
    assert_eq!(observer.open_calls(), 2, "reopened");
    assert_eq!(observer.live_descriptors(), 2);

    endpoints.retire(&links, id).unwrap();
    assert_eq!(
        settle(&mut agents, &links, &mut endpoints, 1),
        [EndpointEvent::Retired {
            endpoint: id,
            returned: 0
        }]
    );
    assert!(endpoints.is_empty());
    assert_eq!(observer.live_descriptors(), 0, "every descriptor closed");
    assert_eq!(
        endpoints.retire(&links, id),
        Err(EndpointError::Unknown(id))
    );
}

/// A full table, a failed open and full rings refuse the open with nothing
/// left open or posted.
#[test]
fn a_refused_open_leaves_nothing_behind() {
    let agent_config = AgentConfig {
        max_endpoints: 1,
        event_capacity: 2,
        ..AgentConfig::default()
    };
    let (mut agents, links) = network_agents::<S>(agent_config).unwrap();
    let mut endpoints = Endpoints::new(&agent_config);

    let failing = ScriptedSocket::new();
    let observer = failing.observer();
    failing.push_open(Err(OpenError::Retired));
    assert_eq!(
        endpoints.open(&links, config(), failing),
        Err(EndpointError::Open(OpenError::Retired))
    );
    assert_eq!(observer.live_descriptors(), 0);
    assert!(endpoints.is_empty());

    // Both reply slots of the sender taken by unread pongs: busy, and the
    // socket is never opened.
    links.sender.ping(1).unwrap();
    links.sender.ping(2).unwrap();
    agents.do_work(0).unwrap();
    let busy = ScriptedSocket::new();
    let observer = busy.observer();
    assert_eq!(
        endpoints.open(&links, config(), busy),
        Err(EndpointError::Agent(AgentError::Busy(AgentKind::Sender)))
    );
    assert_eq!(observer.open_calls(), 0);
    while links.sender.take_event().is_some() {}

    let first = endpoints.open(&links, config(), S::new()).unwrap();
    let full = ScriptedSocket::new();
    let observer = full.observer();
    assert_eq!(
        endpoints.open(&links, config(), full),
        Err(EndpointError::TableFull)
    );
    assert_eq!(observer.open_calls(), 0);
    assert_eq!(
        settle(&mut agents, &links, &mut endpoints, 1),
        [EndpointEvent::Opened(first)]
    );
}

/// After a stop (test 9) the runner hands the agents back; reclaiming their
/// halves joins and retires every endpoint, closing every descriptor.
#[test]
fn a_stop_reclaims_every_endpoint() {
    let agent_config = AgentConfig::default();
    let (mut agents, links) = network_agents::<S>(agent_config).unwrap();
    let mut endpoints = Endpoints::new(&agent_config);
    let sockets: Vec<ScriptedSocket> = (0..3).map(|_| ScriptedSocket::new()).collect();
    let observers: Vec<ScriptedSocket> = sockets.iter().map(ScriptedSocket::observer).collect();
    for socket in sockets {
        endpoints.open(&links, config(), socket).unwrap();
    }
    assert_eq!(settle(&mut agents, &links, &mut endpoints, 3).len(), 3);

    let runner = AgentRunner::start(
        ThreadingMode::Dedicated,
        agents,
        agent_config,
        YieldThenSleep::default,
    )
    .unwrap();
    let mut agents = runner.stop().into_agents().unwrap();
    let halves: Vec<_> = agents
        .sender
        .take_halves()
        .chain(agents.receiver.take_halves())
        .collect();
    assert_eq!(halves.len(), 6);
    assert_eq!(endpoints.reclaim(halves), 3);
    assert!(endpoints.is_empty());
    for observer in observers {
        assert_eq!(observer.live_descriptors(), 0);
    }
}

/// The same open, reset and retire over a real socket on the loopback
/// interface (design test 8).
#[test]
fn a_loopback_endpoint_opens_resets_and_retires() {
    use karyos_io::sockets::OsSocket;
    let agent_config = AgentConfig::default();
    let (mut agents, links) = network_agents::<OsSocket>(agent_config).unwrap();
    let mut endpoints = Endpoints::new(&agent_config);
    let id = endpoints.open(&links, config(), OsSocket::new()).unwrap();
    assert_eq!(
        settle(&mut agents, &links, &mut endpoints, 1),
        [EndpointEvent::Opened(id)]
    );
    endpoints.reset(&links, id).unwrap();
    let events = settle(&mut agents, &links, &mut endpoints, 2);
    assert_eq!(
        events,
        [
            EndpointEvent::Reopened {
                endpoint: id,
                returned: 0
            },
            EndpointEvent::Opened(id)
        ]
    );
    endpoints.retire(&links, id).unwrap();
    assert_eq!(
        settle(&mut agents, &links, &mut endpoints, 1),
        [EndpointEvent::Retired {
            endpoint: id,
            returned: 0
        }]
    );
}
