// SPDX-License-Identifier: Apache-2.0

//! The multi-node host and its network (quantstratum-docs:
//! karyos/design/cluster-gap-analysis.md §6, C1), with the toy echo node:
//!
//! - a seed replays its run's trace byte for byte, over the seed list;
//! - each fault is seen by a scripted pair, with exact counts: loss,
//!   delay, duplication, reordering and queue overflow;
//! - a partition drops exactly the cut directions, `heal` restores them,
//!   and a cut can be one way only;
//! - skewed clocks fire timers at their own rates, exactly;
//! - a crashed node is not ticked, and what is due at it is dropped.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::panic)]

use karyos_sim::cluster::{CATCH_UP, ClockError, ClusterSim, Echo, EchoNode, NodeError};
use karyos_sim::net::{LinkConfig, LinkConfigError, LinkFaults, LinkState, NetCounters, NodeId};
use karyos_sim::rng::Rng;
use karyos_sim::scenarios;

type Sim = ClusterSim<EchoNode, Echo>;

/// `count` silent nodes (no timer) on links of a fixed delay of 1.
fn quiet(seed: u64, count: usize, link: LinkConfig) -> Sim {
    let mut sim = Sim::new("cluster", seed, link).unwrap();
    for _ in 0..count {
        let _ = sim.add_node(EchoNode::new(0, Vec::new()), 0, 0).unwrap();
    }
    sim
}

fn lossy(faults: LinkFaults) -> LinkConfig {
    LinkConfig {
        state: LinkState::Lossy(faults),
        ..LinkConfig::default()
    }
}

const NONE: LinkFaults = LinkFaults {
    loss_ppm: 0,
    reorder_ppm: 0,
    duplicate_ppm: 0,
};

fn received(sim: &Sim, node: NodeId) -> Vec<(NodeId, Echo, u64)> {
    sim.node(node).unwrap().received.clone()
}

/// Pongs `0..count` from `from` to `to`, all in this step; a pong is
/// never answered.
fn pongs(sim: &mut Sim, from: NodeId, to: NodeId, count: u64) {
    for number in 0..count {
        let _ = sim.send(from, to, Echo::Pong(number)).unwrap();
    }
}

/// A ring of three pinging nodes on lossy links, one skewed.
fn ring(seed: u64) -> Sim {
    let link = LinkConfig {
        state: LinkState::Lossy(LinkFaults {
            loss_ppm: 100_000,
            reorder_ppm: 200_000,
            duplicate_ppm: 100_000,
        }),
        min_delay: 1,
        max_delay: 7,
        cap: 16,
    };
    let mut sim = Sim::new("ring", seed, link).unwrap();
    let _ = sim.add_node(EchoNode::new(5, vec![1, 2]), 0, 0).unwrap();
    let _ = sim
        .add_node(EchoNode::new(7, vec![2, 0]), 3, 20_000)
        .unwrap();
    let _ = sim.add_node(EchoNode::new(4, vec![0]), 0, -10_000).unwrap();
    sim.run_for(150).unwrap();
    sim.net_mut().split(&[0], &[1, 2]);
    sim.run_for(50).unwrap();
    sim.net_mut().heal();
    sim.crash(2).unwrap();
    sim.run_for(30).unwrap();
    sim.restart(2).unwrap();
    sim.run_for(70).unwrap();
    sim
}

/// The trace of a seed, as bytes.
fn bytes(sim: &Sim) -> Vec<u8> {
    sim.trace().join("\n").into_bytes()
}

#[test]
fn a_seed_replays_its_trace_byte_for_byte() {
    for seed in scenarios::seeds() {
        let (first, second) = (ring(seed), ring(seed));
        assert_eq!(bytes(&first), bytes(&second), "seed {seed}");
        assert_eq!(first.digest(), second.digest(), "seed {seed}");
        assert_eq!(first.net().counters(), second.net().counters());
        let other = ring(seed.wrapping_add(1_000));
        assert_ne!(first.digest(), other.digest(), "seed {seed}");
    }
}

/// Every loss the counters report is a loss draw the trace shows true,
/// and every other message arrives.
#[test]
fn losses_are_drawn_and_counted_exactly() {
    for (loss_ppm, seed) in [(1_000_000, 1), (0, 2), (300_000, 3)] {
        let mut sim = quiet(seed, 2, lossy(LinkFaults { loss_ppm, ..NONE }));
        pongs(&mut sim, 0, 1, 200);
        sim.run_for(2).unwrap();
        let lost = sim
            .trace()
            .iter()
            .filter(|line| line.contains("loss draw") && line.ends_with(": true"))
            .count() as u64;
        let counters = sim.net().counters();
        assert_eq!(counters.dropped_loss, lost);
        assert_eq!(received(&sim, 1).len() as u64, 200 - lost);
        match loss_ppm {
            1_000_000 => assert_eq!(lost, 200),
            0 => assert_eq!(lost, 0),
            _ => assert!(lost > 0 && lost < 200, "{lost}"),
        }
    }
}

#[test]
fn a_delay_holds_a_message_exactly_that_long() {
    let link = LinkConfig {
        min_delay: 5,
        max_delay: 5,
        ..LinkConfig::default()
    };
    let mut sim = quiet(1, 2, link);
    sim.run_for(3).unwrap();
    pongs(&mut sim, 0, 1, 1);
    sim.run_for(4).unwrap();
    assert!(received(&sim, 1).is_empty(), "not before its delay");
    sim.run_for(1).unwrap();
    assert_eq!(received(&sim, 1), vec![(0, Echo::Pong(0), 8)]);
}

#[test]
fn a_duplicate_arrives_twice() {
    let mut sim = quiet(
        1,
        2,
        lossy(LinkFaults {
            duplicate_ppm: 1_000_000,
            ..NONE
        }),
    );
    pongs(&mut sim, 0, 1, 3);
    sim.run_for(2).unwrap();
    let numbers: Vec<Echo> = received(&sim, 1).into_iter().map(|(_, m, _)| m).collect();
    assert_eq!(
        numbers,
        [0, 0, 1, 1, 2, 2].map(Echo::Pong).to_vec(),
        "each copy follows its original"
    );
    let counters = sim.net().counters();
    assert_eq!((counters.duplicated, counters.delivered), (3, 6));
}

/// Each message overtakes the newest one in flight: `a, b, c` sent in
/// one step arrive `b, c, a`.
#[test]
fn a_reordered_message_overtakes_the_newest_in_flight() {
    let mut sim = quiet(
        1,
        2,
        lossy(LinkFaults {
            reorder_ppm: 1_000_000,
            ..NONE
        }),
    );
    pongs(&mut sim, 0, 1, 3);
    sim.run_for(2).unwrap();
    let numbers: Vec<Echo> = received(&sim, 1).into_iter().map(|(_, m, _)| m).collect();
    assert_eq!(numbers, [1, 2, 0].map(Echo::Pong).to_vec());
    // The first had nothing to overtake.
    assert_eq!(sim.net().counters().reordered, 2);
}

#[test]
fn a_full_queue_drops_the_overflow() {
    let link = LinkConfig {
        min_delay: 10,
        max_delay: 10,
        cap: 2,
        ..LinkConfig::default()
    };
    let mut sim = quiet(1, 2, link);
    pongs(&mut sim, 0, 1, 5);
    assert_eq!(sim.net().in_flight(0, 1), 2);
    sim.run_for(11).unwrap();
    let counters = sim.net().counters();
    assert_eq!((counters.dropped_overflow, counters.delivered), (3, 2));
    assert_eq!(received(&sim, 1).len(), 2);
}

/// Sends a pong on every direction among `nodes`, runs two steps, and
/// returns the directions that delivered.
fn directions(sim: &mut Sim, nodes: &[NodeId]) -> Vec<(NodeId, NodeId)> {
    let before: Vec<usize> = nodes.iter().map(|&n| received(sim, n).len()).collect();
    for &from in nodes {
        for &to in nodes.iter().filter(|&&to| to != from) {
            let _ = sim.send(from, to, Echo::Pong(u64::from(from))).unwrap();
        }
    }
    sim.run_for(2).unwrap();
    let mut open = Vec::new();
    for (&to, before) in nodes.iter().zip(before) {
        for (from, _, _) in received(sim, to).into_iter().skip(before) {
            open.push((from, to));
        }
    }
    open.sort_unstable();
    open
}

#[test]
fn a_partition_drops_exactly_the_cut_directions_and_heal_restores_them() {
    let mut sim = quiet(1, 3, LinkConfig::default());
    let nodes = [0, 1, 2];
    sim.net_mut().split(&[0], &[1, 2]);
    assert_eq!(directions(&mut sim, &nodes), vec![(1, 2), (2, 1)]);
    assert_eq!(sim.net().counters().dropped_link_down, 4);
    sim.net_mut().heal();
    assert_eq!(
        directions(&mut sim, &nodes),
        vec![(0, 1), (0, 2), (1, 0), (1, 2), (2, 0), (2, 1)]
    );
    assert_eq!(sim.net().counters().dropped_link_down, 4);
    sim.net_mut().isolate(2, &nodes);
    assert_eq!(directions(&mut sim, &nodes), vec![(0, 1), (1, 0)]);
    assert_eq!(sim.net().counters().dropped_link_down, 8);
}

#[test]
fn a_cut_can_be_one_way() {
    let mut sim = quiet(1, 2, LinkConfig::default());
    sim.net_mut().cut(0, 1);
    assert_eq!(directions(&mut sim, &[0, 1]), vec![(1, 0)]);
    assert_eq!(sim.net().counters().dropped_link_down, 1);
}

/// Over 1000 base units, a period of 10 fires `local / 10` times on each
/// clock: exact, from its offset and drift.
#[test]
fn skewed_clocks_fire_timers_at_their_own_rates() {
    let mut sim = Sim::new("clocks", 1, LinkConfig::default()).unwrap();
    for (offset, drift) in [(0, 0), (0, 500_000), (0, -250_000), (25, 0), (0, 1_000)] {
        let _ = sim
            .add_node(EchoNode::new(10, Vec::new()), offset, drift)
            .unwrap();
    }
    sim.run_for(1_000).unwrap();
    let ticks: Vec<u64> = sim
        .ids()
        .into_iter()
        .map(|id| sim.node(id).unwrap().ticks)
        .collect();
    // 1000, 1500, 750, 1025 and 1001 local units.
    assert_eq!(ticks, vec![100, 150, 75, 102, 100]);
    assert!(
        Sim::new("clocks", 1, LinkConfig::default())
            .unwrap()
            .add_node(EchoNode::new(10, Vec::new()), 0, -1_000_000)
            .is_err()
    );
}

#[test]
fn a_crashed_node_is_not_ticked_and_drops_what_is_due() {
    let link = LinkConfig {
        min_delay: 3,
        max_delay: 3,
        ..LinkConfig::default()
    };
    let mut sim = Sim::new("crash", 1, link).unwrap();
    let _ = sim.add_node(EchoNode::new(0, Vec::new()), 0, 0).unwrap();
    let _ = sim.add_node(EchoNode::new(10, Vec::new()), 0, 0).unwrap();
    sim.run_for(20).unwrap();
    pongs(&mut sim, 0, 1, 2);
    sim.crash(1).unwrap();
    sim.run_for(20).unwrap();
    assert_eq!(sim.node(1).unwrap().ticks, 2, "no tick while down");
    assert_eq!(
        sim.net().counters(),
        NetCounters {
            sent: 2,
            dropped_node_down: 2,
            ..NetCounters::default()
        }
    );
    sim.restart(1).unwrap();
    pongs(&mut sim, 0, 1, 1);
    sim.run_for(3).unwrap();
    let node = sim.node(1).unwrap();
    assert_eq!((node.restarts, node.received.len()), (1, 1));
    // Its timer catches up on its own clock.
    assert_eq!(node.ticks, 4);
}

/// A link configuration out of bounds is refused, with nothing changed:
/// a delay range upside down, or a rate above one million ppm.
#[test]
fn an_invalid_link_configuration_is_refused() {
    let upside_down = LinkConfig {
        min_delay: 5,
        max_delay: 4,
        ..LinkConfig::default()
    };
    let too_lossy = lossy(LinkFaults {
        loss_ppm: 1_000_001,
        ..NONE
    });
    assert_eq!(
        Sim::new("bad", 1, upside_down).err(),
        Some(LinkConfigError::DelayRange { min: 5, max: 4 })
    );
    assert_eq!(
        Sim::new("bad", 1, too_lossy).err(),
        Some(LinkConfigError::Rate { ppm: 1_000_001 })
    );
    let zero = LinkConfig {
        min_delay: 0,
        max_delay: 3,
        ..LinkConfig::default()
    };
    assert_eq!(
        Sim::new("bad", 1, zero).err(),
        Some(LinkConfigError::ZeroDelay)
    );
    assert_eq!(
        LinkConfigError::DelayRange { min: 5, max: 4 }.to_string(),
        "min_delay 5 is above max_delay 4"
    );
    assert_eq!(
        LinkConfigError::Rate { ppm: 1_000_001 }.to_string(),
        "a rate of 1000001 ppm is above 1000000"
    );
    let mut sim = quiet(1, 2, LinkConfig::default());
    assert_eq!(
        sim.net_mut().configure(0, 1, upside_down),
        Err(LinkConfigError::DelayRange { min: 5, max: 4 })
    );
    assert_eq!(
        sim.net_mut().set_state(0, 1, too_lossy.state),
        Err(LinkConfigError::Rate { ppm: 1_000_001 })
    );
    // Unchanged: a delay of 1, no loss.
    pongs(&mut sim, 0, 1, 1);
    sim.run_for(1).unwrap();
    assert_eq!(received(&sim, 1), vec![(0, Echo::Pong(0), 1)]);
}

/// The trace alone tells two runs of one seed apart when only a scripted
/// `configure` differs: the configuration reaches the trace.
#[test]
fn a_scripted_configure_reaches_the_trace() {
    let run = |delay: u64| {
        let mut sim = quiet(7, 2, LinkConfig::default());
        let config = LinkConfig {
            min_delay: delay,
            max_delay: delay,
            ..LinkConfig::default()
        };
        sim.net_mut().configure(0, 1, config).unwrap();
        sim.run_for(1).unwrap();
        bytes(&sim)
    };
    assert_eq!(run(3), run(3));
    assert_ne!(run(3), run(4));
}

/// A partition also stops what is already in flight: a message sent
/// before the cut, due during it, is dropped as `LinkDown`; one due after
/// the heal arrives.
#[test]
fn a_partition_drops_what_is_in_flight_when_it_falls_due() {
    let link = LinkConfig {
        min_delay: 10,
        max_delay: 10,
        ..LinkConfig::default()
    };
    let mut sim = quiet(1, 2, link);
    pongs(&mut sim, 0, 1, 1);
    sim.net_mut().split(&[0], &[1]);
    sim.run_for(12).unwrap();
    assert!(received(&sim, 1).is_empty());
    let counters = sim.net().counters();
    assert_eq!((counters.dropped_link_down, counters.delivered), (1, 0));
    // Sent during the cut's last steps, due after the heal: delivered.
    sim.net_mut().heal();
    pongs(&mut sim, 1, 0, 1);
    sim.run_for(10).unwrap();
    assert_eq!(received(&sim, 0), vec![(1, Echo::Pong(0), 22)]);
    assert_eq!(sim.net().counters().dropped_link_down, 1);
}

/// Delay jitter never reorders a link: 300 messages, one per step, with
/// delays drawn from 1 to 20, arrive in send order, each within its
/// bounds, and the delays differ.
#[test]
fn a_link_is_fifo_under_delay_jitter() {
    let link = LinkConfig {
        min_delay: 1,
        max_delay: 20,
        ..LinkConfig::default()
    };
    let mut sim = quiet(3, 2, link);
    let mut sent_at = Vec::new();
    for number in 0..300 {
        sent_at.push(sim.now());
        let _ = sim.send(0, 1, Echo::Pong(number)).unwrap();
        sim.run_for(1).unwrap();
    }
    sim.run_for(21).unwrap();
    let got = received(&sim, 1);
    let numbers: Vec<Echo> = got.iter().map(|(_, m, _)| *m).collect();
    assert_eq!(numbers, (0..300).map(Echo::Pong).collect::<Vec<_>>());
    assert_eq!(sim.net().counters().reordered, 0);
    let mut delays = Vec::new();
    for (index, (_, _, at)) in got.iter().enumerate() {
        let delay = at - sent_at[index];
        assert!((1..=20).contains(&delay), "{delay}");
        delays.push(delay);
    }
    delays.sort_unstable();
    delays.dedup();
    assert!(delays.len() > 1, "the delay range was drawn from");
}

/// A reordered message never leaves its delay bounds: with a fixed delay
/// of 5, a message sent 3 later has nothing within its bounds to overtake.
#[test]
fn a_reorder_keeps_the_delay_bounds() {
    let link = LinkConfig {
        state: LinkState::Lossy(LinkFaults {
            reorder_ppm: 1_000_000,
            ..NONE
        }),
        min_delay: 5,
        max_delay: 5,
        cap: 16,
    };
    let mut sim = quiet(1, 2, link);
    pongs(&mut sim, 0, 1, 1);
    sim.run_for(3).unwrap();
    let _ = sim.send(0, 1, Echo::Pong(1)).unwrap();
    sim.run_for(6).unwrap();
    assert_eq!(
        received(&sim, 1),
        vec![(0, Echo::Pong(0), 5), (0, Echo::Pong(1), 8)]
    );
    assert_eq!(sim.net().counters().reordered, 0);
    assert!(
        sim.trace()
            .iter()
            .any(|line| line.contains("#1 has nothing to overtake"))
    );
}

/// Each link draws from its own stream: cutting `0 -> 1` leaves what
/// `2 -> 3` delivers exactly as it was.
#[test]
fn a_cut_leaves_other_links_draws_alone() {
    let faults = lossy(LinkFaults {
        loss_ppm: 300_000,
        reorder_ppm: 300_000,
        duplicate_ppm: 300_000,
    });
    let run = |cut: bool| {
        let mut sim = quiet(
            5,
            4,
            LinkConfig {
                max_delay: 6,
                ..faults
            },
        );
        if cut {
            sim.net_mut().cut(0, 1);
        }
        for number in 0..100 {
            let _ = sim.send(0, 1, Echo::Pong(number)).unwrap();
            let _ = sim.send(2, 3, Echo::Pong(number)).unwrap();
            sim.run_for(1).unwrap();
        }
        sim.run_for(10).unwrap();
        (received(&sim, 1).len(), received(&sim, 3))
    };
    let ((open, three), (closed, cut_three)) = (run(false), run(true));
    assert!(open > 0);
    assert_eq!(closed, 0);
    assert_eq!(three, cut_three);
}

/// The setup is in the trace: the links' default and each node's clock.
#[test]
fn the_setup_is_traced() {
    let trace = |drift: i64| {
        let mut sim = Sim::new("setup", 1, LinkConfig::default()).unwrap();
        let _ = sim
            .add_node(EchoNode::new(0, Vec::new()), 7, drift)
            .unwrap();
        sim.trace().to_vec()
    };
    let (slow, fast) = (trace(0), trace(500_000));
    assert_ne!(slow, fast);
    assert!(slow[0].ends_with(&format!("links default {:?}", LinkConfig::default())));
    assert!(fast[1].ends_with("node 0 added: offset 7, drift 500000 ppm"));
}

/// Link changes, crashes and restarts are traced in the order made.
#[test]
fn link_changes_and_crashes_are_traced_in_order() {
    let mut sim = quiet(1, 2, LinkConfig::default());
    sim.run_for(2).unwrap();
    sim.net_mut().cut(0, 1);
    sim.crash(1).unwrap();
    sim.net_mut().heal();
    sim.restart(1).unwrap();
    let tail: Vec<&str> = sim
        .trace()
        .iter()
        .rev()
        .take(4)
        .rev()
        .map(|line| line.split("] ").nth(1).unwrap())
        .collect();
    assert_eq!(
        tail,
        [
            "link 0->1 Down",
            "node 1 crashed",
            "heal",
            "node 1 restarted at 2"
        ]
    );
}

#[test]
fn crashing_or_restarting_the_wrong_node_is_refused() {
    let mut sim = quiet(1, 2, LinkConfig::default());
    assert_eq!(sim.crash(7), Err(NodeError::Unknown(7)));
    assert_eq!(sim.restart(1), Err(NodeError::AlreadyUp(1)));
    sim.crash(1).unwrap();
    assert_eq!(sim.crash(1), Err(NodeError::AlreadyDown(1)));
    sim.restart(1).unwrap();
    assert_eq!(sim.node(1).unwrap().restarts, 1);
    assert_eq!(NodeError::AlreadyUp(1).to_string(), "node 1 is up");
    let refused = Sim::new("clock", 1, LinkConfig::default())
        .unwrap()
        .add_node(EchoNode::new(0, Vec::new()), 0, -1_000_000)
        .unwrap_err();
    assert_eq!(
        refused.reason,
        format!(
            "a node's clock: {}",
            ClockError::Drift {
                drift_ppm: -1_000_000
            }
        )
    );
    assert!(refused.reason.contains("-1000000 ppm"));
}

/// A node back after a long crash catches up at most `CATCH_UP` timer
/// firings per tick.
#[test]
fn a_timer_catches_up_a_bounded_number_of_firings_per_tick() {
    let mut sim = Sim::new("catch-up", 1, LinkConfig::default()).unwrap();
    let _ = sim.add_node(EchoNode::new(1, Vec::new()), 0, 0).unwrap();
    sim.run_for(1).unwrap();
    assert_eq!(sim.node(0).unwrap().ticks, 1);
    sim.crash(0).unwrap();
    sim.run_for(100).unwrap();
    sim.restart(0).unwrap();
    sim.run_for(1).unwrap();
    assert_eq!(sim.node(0).unwrap().ticks, 1 + CATCH_UP);
    sim.run_for(1).unwrap();
    assert_eq!(sim.node(0).unwrap().ticks, 1 + 2 * CATCH_UP);
}

/// `heal` returns a link to its configured state, not to `Up`.
#[test]
fn heal_restores_the_configured_state() {
    let mut sim = quiet(1, 2, LinkConfig::default());
    let all_lost = lossy(LinkFaults {
        loss_ppm: 1_000_000,
        ..NONE
    });
    sim.net_mut().configure(0, 1, all_lost).unwrap();
    sim.net_mut().cut(0, 1);
    sim.net_mut().heal();
    pongs(&mut sim, 0, 1, 1);
    sim.run_for(2).unwrap();
    let counters = sim.net().counters();
    assert_eq!((counters.dropped_loss, counters.delivered), (1, 0));
}

/// The tick order is drawn from the scheduler's stream only: the trace's
/// orders are exactly those of `Rng::new(seed)`, and they vary.
#[test]
fn the_tick_order_is_drawn_from_the_seed() {
    let seed = 11;
    let mut sim = Sim::new(
        "order",
        seed,
        lossy(LinkFaults {
            loss_ppm: 500_000,
            ..NONE
        }),
    )
    .unwrap();
    for _ in 0..3 {
        let _ = sim.add_node(EchoNode::new(2, vec![0, 1, 2]), 0, 0).unwrap();
    }
    sim.run_for(50).unwrap();
    let traced: Vec<String> = sim
        .trace()
        .iter()
        .filter_map(|line| line.split("] tick order ").nth(1).map(str::to_owned))
        .collect();
    let mut rng = Rng::new(seed);
    let expected: Vec<String> = (0..50)
        .map(|_| {
            let mut order = vec![0u32, 1, 2];
            let mut drawn = Vec::new();
            while !order.is_empty() {
                drawn.push(order.remove(rng.below(order.len() as u64) as usize));
            }
            format!("{drawn:?}")
        })
        .collect();
    assert_eq!(traced, expected);
    let mut distinct = expected.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert!(distinct.len() > 1);
}
