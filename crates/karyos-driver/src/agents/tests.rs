// SPDX-License-Identifier: Apache-2.0

//! The network agents without network work: rings and reservations, the
//! three threading modes, stop, stop timeout and failure
//! (`quantstratum-docs: karyos/design/driver-network-agents.md` §9, tests 9
//! and 11).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::sync::atomic::AtomicBool;

use super::*;

const MODES: [ThreadingMode; 3] = [
    ThreadingMode::Shared,
    ThreadingMode::SharedNetwork,
    ThreadingMode::Dedicated,
];

/// Collects `count` events from `link`, driving `agents` when they run on
/// this thread, within a bounded number of tries.
fn events(link: &AgentLink, agents: &mut Option<NetworkAgents>, count: usize) -> Vec<AgentEvent> {
    let mut seen = Vec::new();
    for _ in 0..100_000 {
        if let Some(agents) = agents.as_mut() {
            agents.do_work(0).unwrap();
        }
        while let Some(event) = link.take_event() {
            seen.push(event);
        }
        if seen.len() >= count {
            return seen;
        }
        std::thread::yield_now();
    }
    panic!("only {} of {count} events", seen.len());
}

/// A reservation holds its slot until posted or dropped; a full ring
/// refuses; a reply posted into a reservation always fits.
#[test]
fn reservations_keep_room_for_replies() {
    let (sender, receiver) = ring::ring::<u32>(2);
    let reply = sender.reserve().unwrap();
    assert!(sender.try_post(1).is_ok());
    assert_eq!(sender.try_post(2), Err(2), "the reserved slot is not free");
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
    drop(sender);
    assert_eq!(receiver.try_take(), Ok(Some(4)));
    assert_eq!(receiver.try_take(), Err(ring::Disconnected));
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
    let (mut agents, links) = network_agents(config);
    links.sender.ping(1).unwrap();
    links.sender.ping(2).unwrap();
    assert_eq!(
        links.sender.ping(3),
        Err(AgentError::Busy(AgentKind::Sender))
    );
    agents.do_work(0).unwrap();
    assert_eq!(
        links.sender.take_event(),
        Some(AgentEvent::Pong {
            agent: AgentKind::Sender,
            token: 1
        })
    );
    links.sender.ping(3).unwrap();
}

/// The same pings give the same replies, in order per agent, in the three
/// threading modes (test 11), and every mode stops cleanly (test 9).
#[test]
fn every_threading_mode_serves_and_stops() {
    let mut replies = Vec::new();
    for mode in MODES {
        let config = AgentConfig::default();
        let (agents, links) = network_agents(config);
        let (mut local, runner) = if mode == ThreadingMode::Shared {
            (Some(agents), None)
        } else {
            let runner = AgentRunner::start(mode, agents, config, YieldThenSleep::default).unwrap();
            (None, Some(runner))
        };
        for token in 0..20 {
            links.receiver.ping(token).unwrap();
            links.sender.ping(token + 100).unwrap();
        }
        let received = events(&links.receiver, &mut local, 20);
        let sent = events(&links.sender, &mut local, 20);
        replies.push((received, sent));
        match runner {
            Some(runner) => runner.stop(&links).unwrap(),
            None => {
                let mut agents = local.take().unwrap();
                links
                    .receiver
                    .post(|reply| AgentCommand::Stop { reply })
                    .unwrap();
                links
                    .sender
                    .post(|reply| AgentCommand::Stop { reply })
                    .unwrap();
                agents.do_work(0).unwrap();
                assert!(agents.is_stopped());
                assert_eq!(agents.do_work(0), Ok(0), "a stopped agent does nothing");
            }
        }
    }
    assert!(replies.windows(2).all(|pair| pair[0] == pair[1]));
    assert_eq!(
        replies[0].0.first(),
        Some(&AgentEvent::Pong {
            agent: AgentKind::Receiver,
            token: 0
        })
    );
}

/// `Shared` mode is the caller's: the runner refuses it.
#[test]
fn the_runner_does_not_run_the_shared_mode() {
    let config = AgentConfig::default();
    let (agents, _links) = network_agents(config);
    assert_eq!(
        AgentRunner::start(
            ThreadingMode::Shared,
            agents,
            config,
            YieldThenSleep::default
        )
        .unwrap_err(),
        AgentError::SharedMode
    );
}

/// A stuck agent is reported after the stop timeout and its thread
/// detached; the other agent stops (test 9).
#[test]
fn a_stuck_agent_is_reported_after_the_stop_timeout() {
    let config = AgentConfig {
        stop_timeout: Duration::from_millis(50),
        ..AgentConfig::default()
    };
    let (agents, links) = network_agents(config);
    let runner = AgentRunner::start(
        ThreadingMode::Dedicated,
        agents,
        config,
        YieldThenSleep::default,
    )
    .unwrap();
    let flag = Arc::new(AtomicBool::new(true));
    let _ = links
        .sender
        .commands
        .try_post(AgentCommand::Block(Arc::clone(&flag)));
    // Let the sender take the blocking command.
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(
        runner.stop(&links),
        Err(AgentError::StopTimeout(vec![AgentKind::Sender]))
    );
    // Release the detached thread so the test process can end cleanly.
    flag.store(false, Ordering::Release);
}

/// A panicking agent stops its thread and is reported failed (DN-9), in
/// both runner modes, whichever agent of a shared thread panicked.
#[test]
fn an_agent_panic_is_reported() {
    for (mode, kind) in [
        (ThreadingMode::Dedicated, AgentKind::Sender),
        (ThreadingMode::SharedNetwork, AgentKind::Sender),
        (ThreadingMode::SharedNetwork, AgentKind::Receiver),
    ] {
        let config = AgentConfig::default();
        let (agents, links) = network_agents(config);
        let runner = AgentRunner::start(mode, agents, config, YieldThenSleep::default).unwrap();
        let link = match kind {
            AgentKind::Sender => &links.sender,
            AgentKind::Receiver => &links.receiver,
        };
        let _ = link.commands.try_post(AgentCommand::Panic);
        for _ in 0..10_000 {
            if !runner.failed().is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(runner.failed().contains(&kind), "{mode:?} {kind:?}");
        assert_eq!(runner.stop(&links), Err(AgentError::Panicked(kind)));
    }
}

/// Dropping the conductor's links stops the agents: their command rings
/// disconnect.
#[test]
fn agents_stop_when_the_conductor_is_gone() {
    let config = AgentConfig::default();
    let (mut agents, links) = network_agents(config);
    drop(links);
    agents.do_work(0).unwrap();
    assert!(agents.is_stopped());
}
