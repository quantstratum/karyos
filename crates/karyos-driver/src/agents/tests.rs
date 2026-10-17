// SPDX-License-Identifier: Apache-2.0

//! The network agents without network work: rings and reservations, the
//! three threading modes, stop, stop timeout and failure
//! (`quantstratum-docs: karyos/design/driver-network-agents.md` §9, tests 9
//! and 11), and the cases of the #224 review.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::sync::Mutex;

use karyos_io::sockets::scripted::ScriptedSocket;

use super::*;

type S = ScriptedSocket;

/// A ping reply as a comparable pair.
fn pong(event: &AgentEvent<S>) -> Option<(AgentKind, u64)> {
    match event {
        AgentEvent::Pong { agent, token } => Some((*agent, *token)),
        _ => None,
    }
}

const MODES: [ThreadingMode; 3] = [
    ThreadingMode::Shared,
    ThreadingMode::SharedNetwork,
    ThreadingMode::Dedicated,
];

fn new_agents(config: AgentConfig) -> (NetworkAgents<S>, AgentLinks<S>) {
    network_agents(config).unwrap()
}

fn start(mode: ThreadingMode, agents: NetworkAgents<S>, config: AgentConfig) -> AgentRunner<S> {
    AgentRunner::start(mode, agents, config, YieldThenSleep::default).unwrap()
}

/// Collects `count` events from `link`, driving `agents` when they run on
/// this thread, within a bounded number of tries.
fn events(
    link: &AgentLink<S>,
    agents: &mut Option<NetworkAgents<S>>,
    count: usize,
) -> Vec<(AgentKind, u64)> {
    let mut seen = Vec::new();
    for _ in 0..100_000 {
        if let Some(agents) = agents.as_mut() {
            agents.do_work(0).unwrap();
        }
        while let Some(event) = link.take_event() {
            seen.extend(pong(&event));
        }
        if seen.len() >= count {
            return seen;
        }
        std::thread::yield_now();
    }
    panic!("only {} of {count} events", seen.len());
}

/// Waits until `runner` reports `kind` failed.
fn wait_failed(runner: &AgentRunner<S>, kind: AgentKind) {
    for _ in 0..10_000 {
        if runner.failed().contains(&kind) {
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("{kind:?} never failed");
}

/// A reservation holds its slot until posted or dropped; a full ring
/// refuses; a reply posted into a reservation always fits; a reservation
/// of another ring is refused.
#[test]
fn reservations_keep_room_for_replies() {
    let two = NonZeroUsize::new(2).unwrap();
    let (sender, receiver) = ring::ring::<u32>(two);
    let reply = sender.reserve().unwrap();
    assert!(sender.try_post(1).is_ok());
    assert_eq!(
        sender.try_post(2),
        Err(PostError::Full(2)),
        "the reserved slot is not free"
    );
    assert!(sender.reserve().is_none());
    sender.post(reply, 3).unwrap();
    assert_eq!(receiver.try_take(), Ok(Some(1)));
    assert_eq!(receiver.try_take(), Ok(Some(3)));
    assert_eq!(receiver.try_take(), Ok(None));
    let dropped = sender.reserve().unwrap();
    let _second = sender.reserve().unwrap();
    drop(dropped);
    assert!(
        sender.try_post(4).is_ok(),
        "a dropped reservation frees its slot"
    );
    let (other, _other_receiver) = ring::ring::<u32>(two);
    let foreign = other.reserve().unwrap();
    assert_eq!(receiver.try_take(), Ok(Some(4)));
    assert_eq!(sender.post(foreign, 5), Err(PostError::Foreign(5)));
    assert!(
        other.reserve().is_some() && other.reserve().is_some(),
        "freed"
    );
    drop(sender);
    assert_eq!(receiver.try_take(), Err(ring::Disconnected));
}

/// Zero capacities and a zero budget are refused at creation, and so are
/// session rings below three units per image (S1) and multicast NAK
/// timings out of range or past `u64`.
#[test]
fn the_configuration_is_checked() {
    for config in [
        AgentConfig {
            command_capacity: 0,
            ..AgentConfig::default()
        },
        AgentConfig {
            session_command_capacity: 3 * AgentConfig::default().sessions.max_images - 1,
            ..AgentConfig::default()
        },
        AgentConfig {
            event_capacity: 0,
            ..AgentConfig::default()
        },
        AgentConfig {
            command_budget: 0,
            ..AgentConfig::default()
        },
        AgentConfig {
            max_endpoints: 0,
            ..AgentConfig::default()
        },
        // A multicast NAK delay scale out of range.
        AgentConfig {
            multicast: crate::repair::loss::MulticastConfig {
                nak_delay_scale: 0,
                ..crate::repair::loss::MulticastConfig::default()
            },
            ..AgentConfig::default()
        },
        // A multicast window past `u64` at the probe timeout.
        AgentConfig {
            multicast: crate::repair::loss::MulticastConfig {
                repair_linger_ns: u64::MAX,
                ..crate::repair::loss::MulticastConfig::default()
            },
            ..AgentConfig::default()
        },
        // A zero multicast delay bound at the RTT floor: 15 ns at scale 1.
        AgentConfig {
            multicast: crate::repair::loss::MulticastConfig {
                nak_delay_scale: 1,
                ..crate::repair::loss::MulticastConfig::default()
            },
            rtt: crate::rtt::RttConfig {
                rtt_floor: 15,
                ..crate::rtt::RttConfig::default()
            },
            ..AgentConfig::default()
        },
    ] {
        assert!(matches!(
            network_agents::<S>(config),
            Err(AgentError::InvalidConfig(_))
        ));
    }
}

/// A command is refused, with nothing posted, when its reply could not be
/// reserved.
#[test]
fn a_command_needs_its_reply_slot() {
    let config = AgentConfig {
        command_capacity: 4,
        event_capacity: 2,
        ..AgentConfig::default()
    };
    let (mut agents, links) = new_agents(config);
    links.sender.ping(1).unwrap();
    links.sender.ping(2).unwrap();
    assert_eq!(
        links.sender.ping(3),
        Err(AgentError::Busy(AgentKind::Sender))
    );
    agents.do_work(0).unwrap();
    assert_eq!(
        links.sender.take_event().as_ref().and_then(pong),
        Some((AgentKind::Sender, 1))
    );
    links.sender.ping(3).unwrap();
}

/// The same pings give the same replies, in order per agent, in the three
/// threading modes (test 11); every mode stops and hands the agents back
/// (test 9).
#[test]
fn every_threading_mode_serves_stops_and_returns_the_agents() {
    let mut replies = Vec::new();
    for mode in MODES {
        let config = AgentConfig::default();
        let (agents, links) = new_agents(config);
        let (mut local, runner) = if mode == ThreadingMode::Shared {
            (Some(agents), None)
        } else {
            (None, Some(start(mode, agents, config)))
        };
        for token in 0..20 {
            links.receiver.ping(token).unwrap();
            links.sender.ping(token + 100).unwrap();
        }
        let received = events(&links.receiver, &mut local, 20);
        let sent = events(&links.sender, &mut local, 20);
        replies.push((received, sent));
        let mut agents = match runner {
            Some(runner) => {
                let stopped = runner.stop();
                assert!(stopped.failures.is_empty() && stopped.late.is_empty());
                stopped.into_agents().unwrap()
            }
            None => {
                links.receiver.request_stop();
                links.sender.request_stop();
                let mut agents = local.take().unwrap();
                agents.do_work(0).unwrap();
                agents
            }
        };
        assert!(agents.is_stopped(), "{mode:?}");
        assert_eq!(agents.do_work(0), Ok(0), "a stopped agent does nothing");
    }
    assert!(replies.windows(2).all(|pair| pair[0] == pair[1]));
}

/// Review P2-1: stop cannot be refused by full rings. With every reply
/// slot taken by unread answers, stop still stops healthy agents in time.
#[test]
fn stop_is_never_refused_by_full_rings() {
    let config = AgentConfig::default();
    for mode in [ThreadingMode::Dedicated, ThreadingMode::SharedNetwork] {
        let (agents, links) = new_agents(config);
        let runner = start(mode, agents, config);
        for token in 0..64 {
            links.sender.ping(token).unwrap();
            links.receiver.ping(token).unwrap();
        }
        assert_eq!(
            links.sender.ping(64),
            Err(AgentError::Busy(AgentKind::Sender))
        );
        std::thread::sleep(Duration::from_millis(20));
        let stopped = runner.stop();
        assert!(stopped.late.is_empty(), "{mode:?}");
        assert!(stopped.failures.is_empty());
        assert!(stopped.into_agents().unwrap().is_stopped());
    }
}

/// `Shared` mode is the caller's: the runner refuses it and returns the
/// agents.
#[test]
fn the_runner_does_not_run_the_shared_mode() {
    let config = AgentConfig::default();
    let (agents, _links) = new_agents(config);
    let error = AgentRunner::start(
        ThreadingMode::Shared,
        agents,
        config,
        YieldThenSleep::default,
    )
    .unwrap_err();
    assert_eq!(error.error, AgentError::SharedMode);
    assert!(error.agents.into_agents().is_some());
}

/// Review P2-3: a stuck agent is returned late, not detached; the other
/// agent comes back; once released, the late thread hands its agent back
/// too (test 9).
#[test]
fn a_stuck_agent_is_returned_late() {
    let config = AgentConfig {
        stop_timeout: Duration::from_millis(50),
        ..AgentConfig::default()
    };
    let (agents, links) = new_agents(config);
    let runner = start(ThreadingMode::Dedicated, agents, config);
    let flag = Arc::new(AtomicBool::new(true));
    links
        .sender
        .commands
        .try_post(AgentCommand::Block(Arc::clone(&flag)))
        .unwrap();
    std::thread::sleep(Duration::from_millis(20));
    let mut stopped = runner.stop();
    assert!(stopped.receiver.is_some());
    assert!(stopped.sender.is_none());
    assert_eq!(stopped.late.len(), 1);
    let late = stopped.late.pop().unwrap();
    assert_eq!(late.kinds(), [AgentKind::Sender]);
    flag.store(false, Ordering::Release);
    let joined = late.join();
    assert!(joined.sender.unwrap().is_stopped());
}

/// A stop timeout too large for the clock waits without a deadline instead
/// of panicking.
#[test]
fn an_unbounded_stop_timeout_does_not_panic() {
    let config = AgentConfig {
        stop_timeout: Duration::MAX,
        ..AgentConfig::default()
    };
    let (agents, _links) = new_agents(config);
    let stopped = start(ThreadingMode::SharedNetwork, agents, config).stop();
    assert!(stopped.into_agents().is_some());
}

/// A panicking agent stops its thread, is reported failed with its exact
/// kind (DN-9), and is still handed back.
#[test]
fn an_agent_panic_is_reported_and_the_agent_returned() {
    for (mode, kind) in [
        (ThreadingMode::Dedicated, AgentKind::Sender),
        (ThreadingMode::SharedNetwork, AgentKind::Sender),
        (ThreadingMode::SharedNetwork, AgentKind::Receiver),
    ] {
        let config = AgentConfig::default();
        let (agents, links) = new_agents(config);
        let runner = start(mode, agents, config);
        let link = match kind {
            AgentKind::Sender => &links.sender,
            AgentKind::Receiver => &links.receiver,
        };
        link.commands.try_post(AgentCommand::Panic).unwrap();
        wait_failed(&runner, kind);
        let stopped = runner.stop();
        assert_eq!(stopped.failures, [AgentError::Panicked(kind)], "{mode:?}");
        assert!(stopped.late.is_empty());
        assert!(stopped.into_agents().is_some(), "handed back");
    }
}

/// Dropping the conductor's links stops the agents, also with a ping still
/// queued whose reply has no reader: a stop, not a failure.
#[test]
fn agents_stop_when_the_conductor_is_gone() {
    let config = AgentConfig::default();
    let (mut agents, links) = new_agents(config);
    drop(links);
    assert_eq!(agents.do_work(0), Ok(0));
    assert!(agents.is_stopped());

    let (mut agents, links) = new_agents(config);
    links.sender.ping(7).unwrap();
    drop(links);
    assert!(agents.do_work(0).is_ok());
    assert!(agents.is_stopped());
}

/// In one iteration the receiver runs before the sender (DN-2, design
/// §2.2), on the caller's thread and on the Shared network thread.
#[test]
fn the_receiver_runs_before_the_sender() {
    let config = AgentConfig::default();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let (mut local, _links) = new_agents(config);
    local.record_calls(&calls);
    local.do_work(0).unwrap();
    local.do_work(0).unwrap();
    assert_eq!(
        *calls.lock().unwrap(),
        [
            AgentKind::Receiver,
            AgentKind::Sender,
            AgentKind::Receiver,
            AgentKind::Sender
        ]
    );

    let threaded = Arc::new(Mutex::new(Vec::new()));
    let (mut agents, _links) = new_agents(config);
    agents.record_calls(&threaded);
    let stopped = start(ThreadingMode::SharedNetwork, agents, config).stop();
    assert!(stopped.into_agents().is_some());
    let calls = threaded.lock().unwrap();
    assert!(calls.len() >= 2);
    for pair in calls.chunks(2) {
        assert_eq!(pair, [AgentKind::Receiver, AgentKind::Sender]);
    }
}
