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
/// this thread, for 30 s at most.
fn events(
    link: &AgentLink<S>,
    agents: &mut Option<NetworkAgents<S>>,
    count: usize,
) -> Vec<(AgentKind, u64)> {
    let mut seen = Vec::new();
    // A time limit, not 100 000 yields, which a loaded host ran through
    // before the agent threads were scheduled (karyos#1067).
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
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
    // A time limit, not 10 000 sleeps of 1 ms (karyos#1067).
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
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
        // A control ring that cannot hold an SM copy per path of every
        // image (RP-7): 64 images of 4 paths, 16 challenges and the floor
        // need 304 units.
        AgentConfig {
            control_capacity: 303,
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
        // RP-8's path policy: a window of 2 ns or more, a skip ratio of 1
        // to 100 percent and a minimum of one byte; RP-3's heartbeat.
        AgentConfig {
            path_policy: crate::agents::data::PathPolicy {
                lag_limit: 1,
                ..crate::agents::data::PathPolicy::default()
            },
            ..AgentConfig::default()
        },
        AgentConfig {
            path_policy: crate::agents::data::PathPolicy {
                skip_percent: 0,
                ..crate::agents::data::PathPolicy::default()
            },
            ..AgentConfig::default()
        },
        AgentConfig {
            path_policy: crate::agents::data::PathPolicy {
                skip_percent: 101,
                ..crate::agents::data::PathPolicy::default()
            },
            ..AgentConfig::default()
        },
        AgentConfig {
            path_policy: crate::agents::data::PathPolicy {
                skip_min_bytes: 0,
                ..crate::agents::data::PathPolicy::default()
            },
            ..AgentConfig::default()
        },
        AgentConfig {
            path_heartbeat_interval: 0,
            ..AgentConfig::default()
        },
        // rp-w8: path queues of at least 1 datagram, at most 64 MiB in all.
        AgentConfig {
            path_queue_datagrams: 0,
            ..AgentConfig::default()
        },
        AgentConfig {
            path_queue_datagrams: u16::MAX,
            ..AgentConfig::default()
        },
        // RP-9's backoffs: at least 1 ns, the maximum at least the initial.
        AgentConfig {
            path_policy: crate::agents::data::PathPolicy {
                backoff_initial: 0,
                ..crate::agents::data::PathPolicy::default()
            },
            ..AgentConfig::default()
        },
        AgentConfig {
            path_policy: crate::agents::data::PathPolicy {
                backoff_max: 1,
                ..crate::agents::data::PathPolicy::default()
            },
            ..AgentConfig::default()
        },
        AgentConfig {
            path_policy: crate::agents::data::PathPolicy {
                backoff_reset: 0,
                ..crate::agents::data::PathPolicy::default()
            },
            ..AgentConfig::default()
        },
        // A maximum past 60 s could keep a left path out for good.
        AgentConfig {
            path_policy: crate::agents::data::PathPolicy {
                backoff_max: crate::agents::data::MAX_PATH_BACKOFF + 1,
                ..crate::agents::data::PathPolicy::default()
            },
            ..AgentConfig::default()
        },
        // RP-11: the skew window at most 1 s, 1 to 65536 copy entries.
        AgentConfig {
            path_policy: crate::agents::data::PathPolicy {
                skew_window: crate::paths::MAX_SKEW_WINDOW + 1,
                ..crate::agents::data::PathPolicy::default()
            },
            ..AgentConfig::default()
        },
        AgentConfig {
            path_policy: crate::agents::data::PathPolicy {
                copy_entries: 0,
                ..crate::agents::data::PathPolicy::default()
            },
            ..AgentConfig::default()
        },
        AgentConfig {
            path_policy: crate::agents::data::PathPolicy {
                copy_entries: crate::agents::data::MAX_PATH_COPY_ENTRIES + 1,
                ..crate::agents::data::PathPolicy::default()
            },
            ..AgentConfig::default()
        },
    ] {
        assert!(matches!(
            network_agents::<S>(config),
            Err(AgentError::InvalidConfig(_))
        ));
    }
    assert!(
        network_agents::<S>(AgentConfig {
            path_policy: crate::agents::data::PathPolicy {
                backoff_max: crate::agents::data::MAX_PATH_BACKOFF,
                ..crate::agents::data::PathPolicy::default()
            },
            ..AgentConfig::default()
        })
        .is_ok()
    );
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
        // A stop budget a loaded host cannot exhaust: the test checks that
        // every mode stops and hands its agents back, not how fast
        // (karyos#1067, #1268 review).
        let config = AgentConfig {
            stop_timeout: Duration::from_secs(30),
            ..AgentConfig::default()
        };
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
    let gate = Arc::new(AtomicU8::new(crate::agents::BLOCK_ARMED));
    links
        .sender
        .commands
        .try_post(AgentCommand::Block(Arc::clone(&gate)))
        .unwrap();
    // Blocked for certain before the stop, not after a 20 ms guess.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while gate.load(Ordering::Acquire) != crate::agents::BLOCK_ENTERED {
        assert!(std::time::Instant::now() < deadline, "never blocked");
        std::thread::yield_now();
    }
    let mut stopped = runner.stop();
    assert!(stopped.receiver.is_some());
    assert!(stopped.sender.is_none());
    assert_eq!(stopped.late.len(), 1);
    let late = stopped.late.pop().unwrap();
    assert_eq!(late.kinds(), [AgentKind::Sender]);
    gate.store(crate::agents::BLOCK_RELEASED, Ordering::Release);
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

/// The redundant-path defaults are redundant-paths.md section 7's:
/// `path_lag_limit` 100 ms, `path_skip_ratio` 50%, `path_skip_min_bytes`
/// 64 KiB, RP-9's backoffs 10 ms, 1 s and 10 s, and RP-11's skew window
/// 1 ms (the receivers' default) and 256 copy entries; and RP-3's interim
/// heartbeat, 100 ms.
#[test]
fn the_path_defaults_are_section_sevens() {
    let config = AgentConfig::default();
    assert_eq!(
        config.path_policy,
        crate::agents::data::PathPolicy {
            lag_limit: 100_000_000,
            skip_percent: 50,
            skip_min_bytes: 64 * 1024,
            backoff_initial: 10_000_000,
            backoff_max: 1_000_000_000,
            backoff_reset: 10_000_000_000,
            skew_window: 1_000_000,
            copy_entries: 256,
        }
    );
    assert_eq!(config.path_heartbeat_interval, 100_000_000);
}

/// M2: an agent's cells take its counts at the end of each cycle, store a
/// count only when it changed, skip a cell the region had no room for,
/// and go back to the conductor whole.
#[test]
fn agent_cells_store_changed_counts_and_go_back() {
    use karyos_sys::counters::{CellRead, CounterKeys, counters};
    let (mut manager, reader) = counters(4).unwrap();
    let mut allocate = |label| {
        Some(
            manager
                .allocate_keyed(1, label, CounterKeys::DRIVER)
                .unwrap(),
        )
    };
    let mut cells = AgentCells::new(vec![allocate("one"), None, allocate("three")]);
    let value = |index| match reader.read(index) {
        CellRead::Allocated { value, .. } => value,
        other => panic!("{other:?}"),
    };
    cells.publish(&[5, 6, 7]);
    assert_eq!((value(0), value(1)), (5, 7));
    // An unchanged count is not stored: a write behind the agent's back
    // stays until the agent's own count changes.
    let taken: Vec<_> = cells.take().collect();
    taken[0].set(99);
    let mut cells = AgentCells::new(taken.into_iter().map(Some).collect());
    cells.publish(&[0, 7]);
    assert_eq!((value(0), value(1)), (99, 7));
    cells.publish(&[1, 7]);
    assert_eq!(value(0), 1);
    assert_eq!(cells.take().count(), 2);
    assert_eq!(cells.take().count(), 0);
}

/// karyos#889: `max_destinations` is 1 to 64, refused outside by its
/// typed error, and refused where a repair table holds less than one
/// entry per destination.
#[test]
fn max_destinations_is_one_to_sixty_four() {
    for value in [
        1,
        data::DEFAULT_MAX_DESTINATIONS,
        data::MAX_MAX_DESTINATIONS,
    ] {
        let config = AgentConfig {
            max_destinations: value,
            ..AgentConfig::default()
        };
        assert!(config.validate().is_ok(), "{value}");
    }
    for value in [0, data::MAX_MAX_DESTINATIONS + 1] {
        let config = AgentConfig {
            max_destinations: value,
            ..AgentConfig::default()
        };
        assert!(
            matches!(config.validate(), Err(AgentError::MaxDestinations { value: refused }) if refused == value),
            "{value}"
        );
    }
    // 64 destinations need 64 replies: 63 leave one without a share.
    let mut config = AgentConfig {
        max_destinations: data::MAX_MAX_DESTINATIONS,
        ..AgentConfig::default()
    };
    config.repair.replies = data::MAX_MAX_DESTINATIONS - 1;
    assert!(matches!(
        config.validate(),
        Err(AgentError::InvalidConfig(_))
    ));
}

/// karyos#943 M23 and karyos#941 item 3: each CnC cell of the agents
/// carries the counter its label names. Every counter takes its own
/// value, so two cells swapped, or one cell reading another counter, fail.
#[test]
fn every_agent_cell_carries_the_counter_its_label_names() {
    let sender = roles::SenderCounters {
        sent: 1,
        send_failures: 2,
        naks: 3,
        sm_accepted: 4,
        heartbeats_sent: 5,
        registrants_joined: 21,
        registrants_full: 22,
        registrants_refused: 23,
        registrants_restarted: 24,
        registrants_moved: 25,
        registrants_timed_out: 26,
        registration_replies_unsent: 32,
        bindings_reserved: 33,
        challenges_unbound: 34,
        ..roles::SenderCounters::default()
    };
    let registrations = crate::sessions::register::RegistrationCounters {
        registered: 6,
        retried: 7,
        refused_full: 8,
        dropped_refusal_limited: 9,
        dropped_source: 10,
        dropped_not_allowed: 11,
        dropped_source_rate: 12,
        dropped_rate: 13,
        dropped_pending_full: 14,
        dropped_source_pending_full: 15,
        dropped_bound: 16,
        dropped_boot_changed: 17,
        duplicate_receiver: 18,
        required_pending_replaced: 19,
        expired: 20,
        dropped_quarantined: 27,
        dropped_required_lost: 28,
        dropped_challenge_rate: 29,
        pending_replaced: 30,
        source_rates_full: 31,
        overflowed: true,
        ..crate::sessions::register::RegistrationCounters::default()
    };
    let expected_sender = [
        ("network controls sent", 1),
        ("network control send failures", 2),
        ("naks received", 3),
        ("status messages received", 4),
        ("heartbeats sent", 5),
        ("registrations", 6),
        ("registration retries", 7),
        ("registration errs sent", 8),
        ("registration errs suppressed", 9),
        ("registrations dropped source", 10),
        ("registrations dropped range", 11),
        ("registrations dropped source rate", 12),
        ("registrations dropped rate", 13),
        ("registrations dropped pending", 14),
        ("registrations dropped source pending", 15),
        ("registrations dropped bound", 16),
        ("registrations dropped boot changed", 17),
        ("registrations duplicate receiver", 18),
        ("required registrations replaced", 19),
        ("registrations expired", 20),
        ("registrants joined", 21),
        ("registrants full", 22),
        ("registrants refused", 23),
        ("registrants restarted", 24),
        ("registrants moved", 25),
        ("registrants timed out", 26),
        ("registrations dropped quarantined", 27),
        ("registrations dropped required lost", 28),
        ("registrations dropped challenge rate", 29),
        ("registrations pending replaced", 30),
        ("registration source table full", 31),
        ("registration replies unsent", 32),
        ("receiver bindings reserved", 33),
        ("challenges unbound", 34),
        ("sender counters overflowed", 1),
    ];
    let values = sender_values(&sender, &registrations);
    assert_eq!(SENDER_CELLS.len(), expected_sender.len());
    for ((label, value), (expected_label, expected)) in
        SENDER_CELLS.iter().zip(values).zip(expected_sender)
    {
        assert_eq!((*label, value), (expected_label, expected));
    }
    let receiver = roles::ReceiverCounters {
        datagrams: 1,
        backend_drops: 2,
        decode_errors: 3,
        sm_sent: 4,
        images_retired: 5,
        registers_sent: 6,
        registers_unsent: 7,
        registration_refusals: 8,
        registers_rate_limited: 9,
        setup_not_from_control: 10,
        ..roles::ReceiverCounters::default()
    };
    let expected_receiver = [
        ("datagrams received", 1),
        ("datagrams dropped by backend", 2),
        ("invalid frames received", 3),
        ("status messages sent", 4),
        ("images retired at timeout", 5),
        ("registers sent", 6),
        ("registers unsent", 7),
        ("registration refusals received", 8),
        ("registers rate limited", 9),
        ("setup not from control", 10),
        ("receiver counters overflowed", 0),
    ];
    assert_eq!(RECEIVER_CELLS.len(), expected_receiver.len());
    for ((label, value), (expected_label, expected)) in RECEIVER_CELLS
        .iter()
        .zip(receiver_values(&receiver))
        .zip(expected_receiver)
    {
        assert_eq!((*label, value), (expected_label, expected));
    }
}

/// karyos#1016: the overflow gauges follow each sticky flag on its own.
/// The sender's is 1 when either the sender's or the registrations'
/// counters saturated, and 0 with neither; the receiver's is 1 when its
/// counters saturated.
#[test]
fn each_overflow_flag_sets_its_gauge() {
    let at = |labels: &[&str], label: &str| labels.iter().position(|held| *held == label).unwrap();
    let sender_at = at(&SENDER_CELLS, "sender counters overflowed");
    let receiver_at = at(&RECEIVER_CELLS, "receiver counters overflowed");
    for (sender_flag, registrations_flag) in
        [(false, false), (true, false), (false, true), (true, true)]
    {
        let sender = roles::SenderCounters {
            overflowed: sender_flag,
            ..roles::SenderCounters::default()
        };
        let registrations = crate::sessions::register::RegistrationCounters {
            overflowed: registrations_flag,
            ..crate::sessions::register::RegistrationCounters::default()
        };
        assert_eq!(
            sender_values(&sender, &registrations)[sender_at],
            u64::from(sender_flag || registrations_flag),
            "sender {sender_flag}, registrations {registrations_flag}"
        );
    }
    for flag in [false, true] {
        let receiver = roles::ReceiverCounters {
            overflowed: flag,
            ..roles::ReceiverCounters::default()
        };
        assert_eq!(receiver_values(&receiver)[receiver_at], u64::from(flag));
    }
}
