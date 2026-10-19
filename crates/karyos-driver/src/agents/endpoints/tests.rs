// SPDX-License-Identifier: Apache-2.0

//! The endpoint table over the scripted socket and the host's loopback
//! (`quantstratum-docs: karyos/design/driver-network-agents.md` §9, tests 8
//! and 9): open, reset, retire, refusals, failure and reclaiming after a
//! stop, with the cases of the #228 review.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::net::SocketAddr;
use std::num::NonZeroU16;

use karyos_io::backend::{
    Authority, Commit, SenderToken, TxBackend, TxFrame, TxOptions, TxQueueConfig,
};
use karyos_io::sockets::endpoint::CapabilitySet;
use karyos_io::sockets::scripted::ScriptedSocket;

use super::super::{AgentRunner, ThreadingMode, YieldThenSleep, network_agents};
use super::*;

type S = ScriptedSocket;

fn config() -> SocketsConfig {
    SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)))
}

fn table(agent_config: &AgentConfig) -> (NetworkAgents<S>, AgentLinks<S>, Endpoints<S>) {
    let (agents, links) = network_agents::<S>(*agent_config).unwrap();
    (agents, links, Endpoints::new(agent_config))
}

/// Drives the agents and the table until `want` events arrived (`Returned`
/// items included).
fn settle<O: SocketOps>(
    agents: &mut NetworkAgents<O>,
    links: &AgentLinks<O>,
    endpoints: &mut Endpoints<O>,
    want: usize,
) -> Vec<EndpointEvent> {
    let mut events = Vec::new();
    for _ in 0..1000 {
        agents.do_work(0).unwrap();
        endpoints.poll(links, 0, |event| events.push(event), |_| {});
        if events.len() >= want {
            return events;
        }
    }
    panic!("only {events:?}");
}

/// Open attaches both halves; reset reopens at the next epoch and reports
/// one `Reopened` once both agents hold the new halves; retire closes the
/// socket and empties the table.
#[test]
fn open_reset_and_retire() {
    let agent_config = AgentConfig::default();
    let (mut agents, links, mut endpoints) = table(&agent_config);
    let socket = ScriptedSocket::new();
    let observer = socket.observer();

    let id = endpoints.open(&links, config(), socket).unwrap();
    assert_eq!(
        settle(&mut agents, &links, &mut endpoints, 1),
        [EndpointEvent::Opened(id)]
    );
    assert!(endpoints.is_active(id));
    assert_eq!(observer.live_descriptors(), 2, "a TX and an RX descriptor");

    endpoints.reset(&links, id).unwrap();
    assert_eq!(endpoints.reset(&links, id), Err(EndpointError::Busy(id)));
    assert_eq!(
        settle(&mut agents, &links, &mut endpoints, 1),
        [EndpointEvent::Reopened {
            endpoint: id,
            returned: 0
        }]
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

/// Review M1: `Opened` needs both answers, not the first.
#[test]
fn opened_needs_both_answers() {
    let agent_config = AgentConfig::default();
    let (mut agents, links, mut endpoints) = table(&agent_config);
    let id = endpoints.open(&links, config(), S::new()).unwrap();
    let mut events = Vec::new();
    agents.sender.do_work(0).unwrap();
    endpoints.poll(&links, 0, |event| events.push(event), |_| {});
    assert!(events.is_empty() && !endpoints.is_active(id));
    agents.receiver.do_work(0).unwrap();
    endpoints.poll(&links, 0, |event| events.push(event), |_| {});
    assert_eq!(events, [EndpointEvent::Opened(id)]);
}

/// A failed open, busy rings (sender or receiver: review M6, the slots are
/// reserved before the socket opens) and a full table leave nothing open
/// or posted.
#[test]
fn a_refused_open_leaves_nothing_behind() {
    let agent_config = AgentConfig {
        max_endpoints: 1,
        event_capacity: 2,
        ..AgentConfig::default()
    };
    let (mut agents, links, mut endpoints) = table(&agent_config);

    let failing = S::new();
    let observer = failing.observer();
    failing.push_open(Err(OpenError::Retired));
    assert_eq!(
        endpoints.open(&links, config(), failing),
        Err(EndpointError::Open(OpenError::Retired))
    );
    assert_eq!(observer.live_descriptors(), 0);
    assert!(endpoints.is_empty());

    for link in [&links.sender, &links.receiver] {
        // Both reply slots of one agent taken by unread pongs.
        link.ping(1).unwrap();
        link.ping(2).unwrap();
        agents.do_work(0).unwrap();
        let busy = S::new();
        let observer = busy.observer();
        assert_eq!(
            endpoints.open(&links, config(), busy),
            Err(EndpointError::Agent(AgentError::Busy(link.kind())))
        );
        assert_eq!(observer.open_calls(), 0, "{:?}", link.kind());
        while link.take_event().is_some() {}
    }

    let first = endpoints.open(&links, config(), S::new()).unwrap();
    let full = S::new();
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

/// Review P2-1: when the agents refuse the halves (here a table larger
/// than the agents, a broken invariant), the entry is never active, both
/// halves close and one `Failed` is reported, after which the entry is
/// gone.
#[test]
fn refused_halves_fail_the_endpoint_once() {
    let small = AgentConfig {
        max_endpoints: 1,
        ..AgentConfig::default()
    };
    let (mut agents, links) = network_agents::<S>(small).unwrap();
    let mut endpoints = Endpoints::new(&AgentConfig::default());
    let first = endpoints.open(&links, config(), S::new()).unwrap();
    let socket = S::new();
    let observer = socket.observer();
    let second = endpoints.open(&links, config(), socket).unwrap();
    // Events of different endpoints come in no particular order.
    let events = settle(&mut agents, &links, &mut endpoints, 2);
    assert_eq!(events.len(), 2);
    assert!(events.contains(&EndpointEvent::Opened(first)));
    assert!(events.contains(&EndpointEvent::Failed {
        endpoint: second,
        error: EndpointError::Refused(AgentKind::Sender),
    }));
    assert!(!endpoints.is_active(second));
    assert_eq!(endpoints.len(), 1);
    assert_eq!(observer.live_descriptors(), 0);
    // Nothing more about it later.
    assert!(settle(&mut agents, &links, &mut endpoints, 0).is_empty());
}

/// Review M4: an agent refuses the other agent's half.
#[test]
fn an_agent_refuses_the_wrong_half() {
    let (mut agents, links) = network_agents::<S>(AgentConfig::default()).unwrap();
    let endpoint = SocketsEndpoint::open(&config(), InstanceId::FIRST, S::new()).unwrap();
    let (tx, rx) = endpoint.split().unwrap();
    links
        .sender
        .post(|reply| AgentCommand::Attach {
            reply,
            endpoint: EndpointId(9),
            half: Half::Rx(Box::new(rx)),
        })
        .unwrap();
    links
        .receiver
        .post(|reply| AgentCommand::Attach {
            reply,
            endpoint: EndpointId(9),
            half: Half::Tx(Box::new(tx)),
        })
        .unwrap();
    agents.do_work(0).unwrap();
    for link in [&links.sender, &links.receiver] {
        assert!(matches!(
            link.take_event(),
            Some(AgentEvent::Refused { agent, .. }) if agent == link.kind()
        ));
    }
}

/// Review M5: a reset that returns more items than one report holds is
/// drained over several calls, every item reported.
#[test]
fn a_reset_drains_every_returned_item() {
    let endpoint = SocketsEndpoint::open(&config(), InstanceId::FIRST, S::new()).unwrap();
    let (mut tx, rx) = endpoint.split().unwrap();
    let route = tx
        .add_route(SocketAddr::from(([127, 0, 0, 1], 40_000)))
        .unwrap();
    let queue = tx
        .open_queue(TxQueueConfig {
            authority: Authority::FIRST,
            route,
            max_pending: NonZeroU16::new(200).unwrap(),
        })
        .unwrap();
    for token in 0..150u64 {
        let mut frame = tx.claim_tx(queue, 10).unwrap();
        frame.bytes_mut().fill(1);
        frame
            .commit(Commit {
                len: 10,
                token: SenderToken::new(token),
                options: TxOptions::none(),
            })
            .unwrap();
    }
    let mut endpoint = SocketsEndpoint::join(tx, rx).unwrap();
    let mut report = TxReport::new();
    let mut events = Vec::new();
    let returned =
        Endpoints::<S>::drain_reset(&mut endpoint, &mut report, EndpointId(1), &mut |event| {
            events.push(event);
        })
        .unwrap();
    assert_eq!(returned, 150);
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, EndpointEvent::Returned { .. }))
            .count(),
        150
    );
}

/// After a stop (test 9) the runner hands the agents back; reclaiming their
/// halves joins and retires every endpoint, closing every descriptor.
#[test]
fn a_stop_reclaims_every_endpoint() {
    let agent_config = AgentConfig::default();
    let (mut agents, links, mut endpoints) = table(&agent_config);
    let sockets: Vec<S> = (0..3).map(|_| S::new()).collect();
    let observers: Vec<S> = sockets.iter().map(S::observer).collect();
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
    assert_eq!(endpoints.reclaim(&links, &mut agents, |_| {}), 3);
    assert!(endpoints.is_empty());
    for observer in observers {
        assert_eq!(observer.live_descriptors(), 0);
    }
}

/// Review P2-2 and M3: halves in flight at the stop are reclaimed by join
/// and retire too: an `Attach` the agent never read, a `Detached` answer
/// never polled, and halves the table holds after a reset waiting for ring
/// room.
#[test]
fn a_stop_reclaims_work_in_flight() {
    let agent_config = AgentConfig {
        command_capacity: 2,
        event_capacity: 4,
        ..AgentConfig::default()
    };
    let (mut agents, links, mut endpoints) = table(&agent_config);
    let sockets: Vec<S> = (0..3).map(|_| S::new()).collect();
    let observers: Vec<S> = sockets.iter().map(S::observer).collect();
    let mut sockets = sockets.into_iter();
    let held = endpoints
        .open(&links, config(), sockets.next().unwrap())
        .unwrap();
    let detached = endpoints
        .open(&links, config(), sockets.next().unwrap())
        .unwrap();
    assert_eq!(settle(&mut agents, &links, &mut endpoints, 2).len(), 2);

    // `held`: reset; the agents hand the halves back and the table joins,
    // reopens and splits it, but the sender's command ring is then full
    // (pings), so the new halves stay in the table.
    endpoints.reset(&links, held).unwrap();
    agents.do_work(0).unwrap();
    links.sender.ping(1).unwrap();
    links.sender.ping(2).unwrap();
    endpoints.poll(&links, 0, |_| {}, |_| {});
    assert!(!endpoints.is_active(held));
    // `detached`: retire; the agents answer, nobody polls.
    endpoints.retire(&links, detached).unwrap_err();
    // (The sender's command ring is full: the retire is refused.) Free it.
    agents.sender.do_work(0).unwrap();
    while links.sender.take_event().is_some() {}
    endpoints.retire(&links, detached).unwrap();
    agents.do_work(0).unwrap();
    // A third endpoint whose `Attach` commands are never read.
    endpoints
        .open(&links, config(), sockets.next().unwrap())
        .unwrap();

    agents
        .sender
        .core
        .stop
        .store(true, std::sync::atomic::Ordering::Release);
    agents
        .receiver
        .core
        .stop
        .store(true, std::sync::atomic::Ordering::Release);
    assert_eq!(endpoints.reclaim(&links, &mut agents, |_| {}), 3);
    assert!(endpoints.is_empty());
    for observer in observers {
        assert_eq!(observer.live_descriptors(), 0);
    }
}

/// Open, reset and retire over a real socket on the loopback interface
/// (design test 8), with the agents on the test thread and on their own
/// threads.
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
    // Port 0 resolved by the kernel: a reset keeps that port (ACS 15721).
    let bound = endpoints.local_address(id).unwrap();
    assert_ne!(bound.port(), 0);
    // The table keeps each epoch's capabilities (M3).
    let epoch = |endpoints: &Endpoints<OsSocket>| {
        let all: Vec<_> = endpoints.capabilities().collect();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].0, id);
        assert_eq!(all[0].1.local, bound);
        all[0].1.epoch.get().get()
    };
    assert_eq!(epoch(&endpoints), 1);
    for reset in 0..3 {
        endpoints.reset(&links, id).unwrap();
        assert_eq!(
            settle(&mut agents, &links, &mut endpoints, 1),
            [EndpointEvent::Reopened {
                endpoint: id,
                returned: 0
            }]
        );
        assert_eq!(endpoints.local_address(id), Some(bound));
        assert_eq!(epoch(&endpoints), reset + 2);
    }
    assert_eq!(endpoints.missing(), 0);
    endpoints.retire(&links, id).unwrap();
    assert_eq!(
        settle(&mut agents, &links, &mut endpoints, 1),
        [EndpointEvent::Retired {
            endpoint: id,
            returned: 0
        }]
    );

    for mode in [ThreadingMode::Dedicated, ThreadingMode::SharedNetwork] {
        let (agents, links) = network_agents::<OsSocket>(agent_config).unwrap();
        let mut endpoints = Endpoints::new(&agent_config);
        let runner =
            AgentRunner::start(mode, agents, agent_config, YieldThenSleep::default).unwrap();
        let wait = |endpoints: &mut Endpoints<OsSocket>, want: usize| {
            let mut events = Vec::new();
            for _ in 0..10_000 {
                endpoints.poll(&links, 0, |event| events.push(event), |_| {});
                if events.len() >= want {
                    return events;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            panic!("{mode:?}: only {events:?}");
        };
        let id = endpoints.open(&links, config(), OsSocket::new()).unwrap();
        assert_eq!(wait(&mut endpoints, 1), [EndpointEvent::Opened(id)]);
        endpoints.reset(&links, id).unwrap();
        assert!(matches!(
            wait(&mut endpoints, 1).as_slice(),
            [EndpointEvent::Reopened { .. }]
        ));
        endpoints.retire(&links, id).unwrap();
        assert!(matches!(
            wait(&mut endpoints, 1).as_slice(),
            [EndpointEvent::Retired { .. }]
        ));
        let mut agents = runner.stop().into_agents().unwrap();
        assert_eq!(endpoints.reclaim(&links, &mut agents, |_| {}), 0);
    }
}

/// A reset that reopens at another local address (a rebind the kernel did
/// not honour) fails the endpoint, reported, rather than move silently.
#[test]
fn a_reset_at_another_address_fails() {
    use karyos_io::sockets::scripted::default_probes;

    let agent_config = AgentConfig::default();
    let (mut agents, links, mut endpoints) = table(&agent_config);
    let socket = ScriptedSocket::new();
    let observer = socket.observer();
    let id = endpoints.open(&links, config(), socket).unwrap();
    assert_eq!(
        settle(&mut agents, &links, &mut endpoints, 1),
        [EndpointEvent::Opened(id)]
    );
    let bound = endpoints.local_address(id).unwrap();
    let mut moved = default_probes(&config());
    moved.local = std::net::SocketAddr::from(([127, 0, 0, 1], 49_999));
    observer.push_open(Ok(moved));
    endpoints.reset(&links, id).unwrap();
    assert_eq!(
        settle(&mut agents, &links, &mut endpoints, 1),
        [EndpointEvent::Failed {
            endpoint: id,
            error: EndpointError::AddressChanged {
                expected: bound,
                found: moved.local,
            },
        }]
    );
    assert!(endpoints.is_empty());
}

/// A reset whose reopen finds the address in use fails the endpoint with
/// the open error, reported and counted (#265 P3).
#[test]
fn a_reset_into_a_used_address_fails() {
    use karyos_io::sockets::ops::Errno;

    let agent_config = AgentConfig::default();
    let (mut agents, links, mut endpoints) = table(&agent_config);
    let socket = ScriptedSocket::new();
    let observer = socket.observer();
    let id = endpoints.open(&links, config(), socket).unwrap();
    assert_eq!(
        settle(&mut agents, &links, &mut endpoints, 1),
        [EndpointEvent::Opened(id)]
    );
    let in_use = OpenError::Os {
        operation: "bind",
        errno: Errno::ADDRINUSE.raw(),
    };
    observer.push_open(Err(in_use));
    endpoints.reset(&links, id).unwrap();
    assert_eq!(
        settle(&mut agents, &links, &mut endpoints, 1),
        [EndpointEvent::Failed {
            endpoint: id,
            error: EndpointError::Open(in_use),
        }]
    );
    assert!(endpoints.is_empty());
    assert_eq!(endpoints.counters().failed, 1);
}

/// Requested resets are bounded: a request within the endpoint's interval
/// is deferred, the reset after a deferral doubles the interval (to at
/// most 60 s), and one after a clean interval starts over at 1 s. Requests
/// for an endpoint that is not active are ignored.
#[test]
fn requested_resets_back_off_while_the_fault_recurs() {
    const SEC: u64 = 1_000_000_000;

    let agent_config = AgentConfig::default();
    let (mut agents, links, mut endpoints) = table(&agent_config);
    let id = endpoints
        .open(&links, config(), ScriptedSocket::new())
        .unwrap();
    assert_eq!(
        settle(&mut agents, &links, &mut endpoints, 1),
        [EndpointEvent::Opened(id)]
    );
    let reset_at = |endpoints: &mut Endpoints<S>, agents: &mut NetworkAgents<S>, now| {
        let resets = endpoints.counters().resets;
        endpoints.requested(&links, id, now);
        let started = endpoints.counters().resets > resets;
        if started {
            // A duplicate while the reset is in flight is ignored.
            let ignored = endpoints.counters().requests_ignored;
            endpoints.requested(&links, id, now);
            assert_eq!(endpoints.counters().requests_ignored, ignored + 1);
            let events = settle(agents, &links, endpoints, 1);
            assert!(
                matches!(events.as_slice(), [EndpointEvent::Reopened { endpoint, .. }] if *endpoint == id),
                "{events:?}"
            );
        }
        started
    };
    assert!(reset_at(&mut endpoints, &mut agents, 0));
    // The fault recurs at once: deferred until 1 s, then the interval
    // doubles: 2 s, 4 s, ... up to 60 s.
    let mut last = 0;
    let mut interval = SEC;
    for _ in 0..8 {
        assert!(!reset_at(&mut endpoints, &mut agents, last + interval / 2));
        assert!(reset_at(&mut endpoints, &mut agents, last + interval));
        last += interval;
        interval = (interval * 2).min(60 * SEC);
    }
    assert_eq!(interval, 60 * SEC);
    let counters = endpoints.counters();
    assert_eq!((counters.resets, counters.resets_deferred), (9, 8));
    // A clean interval: the next fault resets at once and starts over.
    let clean = last + 2 * interval;
    assert!(reset_at(&mut endpoints, &mut agents, clean));
    assert!(!reset_at(&mut endpoints, &mut agents, clean + SEC - 1));
    assert!(reset_at(&mut endpoints, &mut agents, clean + SEC));
    // An unknown endpoint is ignored.
    let ignored = endpoints.counters().requests_ignored;
    endpoints.requested(&links, EndpointId(u32::MAX - 1), clean);
    assert_eq!(endpoints.counters().requests_ignored, ignored + 1);
}

/// A clock stepped back behind the last requested reset does not defer
/// requests until it catches up: the interval counts as elapsed.
#[test]
fn a_clock_stepped_back_does_not_defer_resets() {
    const SEC: u64 = 1_000_000_000;

    let agent_config = AgentConfig::default();
    let (mut agents, links, mut endpoints) = table(&agent_config);
    let id = endpoints
        .open(&links, config(), ScriptedSocket::new())
        .unwrap();
    settle(&mut agents, &links, &mut endpoints, 1);
    endpoints.requested(&links, id, 100 * SEC);
    assert_eq!(endpoints.counters().resets, 1);
    settle(&mut agents, &links, &mut endpoints, 1);
    // The clock steps back 50 s: the next request resets at once.
    endpoints.requested(&links, id, 50 * SEC);
    assert_eq!(endpoints.counters().resets, 2);
    assert_eq!(endpoints.counters().resets_deferred, 0);
}

/// An open refused because a required capability is not active counts in
/// `missing` (`capability missing`, SPEC §16.8, M3); another refusal does
/// not.
#[test]
fn a_required_capability_refusal_counts_as_missing() {
    use karyos_io::backend::Capability;
    use karyos_io::sockets::OsSocket;
    let agent_config = AgentConfig::default();
    let (_agents, links) = network_agents::<OsSocket>(agent_config).unwrap();
    let mut endpoints = Endpoints::new(&agent_config);
    let config = SocketsConfig {
        // The baseline has no UDP segmentation offload.
        require: CapabilitySet::EMPTY.with(Capability::Gso),
        ..config()
    };
    assert!(matches!(
        endpoints.open(&links, config, OsSocket::new()),
        Err(EndpointError::Open(OpenError::RequiredCapability {
            capability: Capability::Gso,
            ..
        }))
    ));
    assert_eq!(endpoints.missing(), 1);
    assert_eq!(endpoints.capabilities().count(), 0);
    let used = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let taken = SocketsConfig::new(used.local_addr().unwrap());
    assert!(endpoints.open(&links, taken, OsSocket::new()).is_err());
    assert_eq!(endpoints.missing(), 1);
}

/// A reopen refused for a required capability fails the endpoint and counts
/// in `missing` (`capability missing`, M3), as an open's refusal does.
#[test]
fn a_reopen_refused_for_a_required_capability_counts_as_missing() {
    use karyos_io::backend::{Capability, CapabilityState, Reason};
    let agent_config = AgentConfig::default();
    let (mut agents, links, mut endpoints) = table(&agent_config);
    let socket = ScriptedSocket::new();
    // The open's probes, then a reopen whose required TX batching is gone.
    let _ = socket
        .push_open(Ok(karyos_io::sockets::scripted::default_probes(&config())))
        .push_open(Err(OpenError::RequiredCapability {
            capability: Capability::TxBatch,
            state: CapabilityState::Fallback(Reason::Platform),
        }));
    let id = endpoints.open(&links, config(), socket).unwrap();
    assert_eq!(
        settle(&mut agents, &links, &mut endpoints, 1),
        [EndpointEvent::Opened(id)]
    );
    assert_eq!(endpoints.missing(), 0);
    endpoints.reset(&links, id).unwrap();
    let events = settle(&mut agents, &links, &mut endpoints, 1);
    assert!(
        matches!(
            events.as_slice(),
            [EndpointEvent::Failed {
                endpoint,
                error: EndpointError::Open(OpenError::RequiredCapability { .. }),
            }] if *endpoint == id
        ),
        "{events:?}"
    );
    assert_eq!(endpoints.missing(), 1);
    assert_eq!(endpoints.capabilities().count(), 0);
}
