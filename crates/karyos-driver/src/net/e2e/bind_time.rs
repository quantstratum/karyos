// SPDX-License-Identifier: Apache-2.0

//! How long a late multicast subscriber takes to bind under loss
//! (karyos#805, plan 150): a measurement, not a pass or fail test. A
//! subscriber that joins a live group after the SETUP binds through the
//! SOLICIT its first unbound DATA sends (`quantstratum-docs:
//! karyos/design/network-control-schemas.md` §6.3); a lost SOLICIT or
//! answer costs `setup_challenge_timeout` plus `solicit_holdoff` before the
//! next. Each join's time from its first unbound DATA to its image's
//! install is recorded with the SOLICITs it took.
//!
//! Runs under `scripts/netem-test.sh` with `KARYOS_NETEM_MEASURE` set to
//! the number of joins, and the profile in `KARYOS_NETEM`:
//!
//! ```text
//! KARYOS_NETEM_MEASURE=200 KARYOS_NETEM='limit 100000 loss 2% reorder 10% 50% delay 1ms duplicate 1%' \
//!     scripts/netem-test.sh -p karyos-driver --lib --locked bind_time -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! Its module path does not name `netem`, so the default netem run (the N
//! suite, a release gate) never includes it. Without `KARYOS_NETEM_MEASURE`
//! it prints that it was skipped and measures nothing.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::print_stdout,
    reason = "a measurement printed to the job's log (ADR-0007 allows these in tests)"
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use karyos_client::OfferOutcome;
use karyos_protocol::channel::{Destination, FlowControl, Security, UdpConfig};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::Role;

use super::netem::MulticastOnLoopback;
use super::{BUDGET, aggregate, driver, free_port, shared};
use crate::agents::ThreadingMode;

/// The longest one join may take before the run gives up on it: well past
/// three lost exchanges of about 2 s each.
const JOIN_LIMIT: Duration = Duration::from_secs(30);
/// The publisher's pace: one 1000-byte message per millisecond.
const PACE: Duration = Duration::from_millis(1);
/// The gap before each join. Every joiner on this host sends its SOLICIT
/// from the group port, one source endpoint, and the publisher answers a
/// source at most `setup_answer_rate` times a second (20, burst 20;
/// network-control-schemas.md §7.4). Joins 60 ms apart stay under it, so
/// only loss makes a join solicit again.
const JOIN_GAP: Duration = Duration::from_millis(60);

/// One join: from the first unbound DATA to the install, from the
/// subscription to the install, and the SOLICITs it sent and saw expire.
#[derive(Debug, Clone, Copy)]
struct Join {
    bind: Duration,
    subscribe: Duration,
    solicits: u64,
    expired: u64,
}

/// The joins to measure, from `KARYOS_NETEM_MEASURE`; `None` prints the
/// skip.
fn joins() -> Option<usize> {
    super::super::netem::require_netem();
    let joins = std::env::var("KARYOS_NETEM_MEASURE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|joins| *joins > 0);
    if joins.is_none() {
        println!("SKIPPED: KARYOS_NETEM_MEASURE is unset, nothing measured");
    }
    joins
}

/// The value at rank `rank` (1-based) of `sorted`, clamped to its ends.
fn at_rank(sorted: &[Duration], rank: usize) -> Duration {
    sorted[rank.clamp(1, sorted.len()) - 1]
}

/// The nearest-rank `q` quantile of `sorted`.
fn quantile(sorted: &[Duration], q: f64) -> Duration {
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        reason = "a rank of at most a few thousand"
    )]
    let rank = (q * sorted.len() as f64).ceil() as usize;
    at_rank(sorted, rank)
}

/// A distribution-free 95% interval of the `q` quantile of `sorted`: the
/// order statistics at `n q ± 1.96 sqrt(n q (1 - q))`, the normal
/// approximation of the binomial ranks.
fn interval(sorted: &[Duration], q: f64) -> (Duration, Duration) {
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        reason = "ranks of at most a few thousand"
    )]
    let (low, high) = {
        let n = sorted.len() as f64;
        let spread = 1.96 * (n * q * (1.0 - q)).sqrt();
        (
            (n * q - spread).floor().max(1.0) as usize,
            (n * q + spread).ceil() as usize,
        )
    };
    (at_rank(sorted, low), at_rank(sorted, high))
}

/// Joins `count` fresh subscribers, one after another, to a live
/// multicast group of `reliable` delivery, and prints the distribution.
fn measure(label: &str, reliable: bool, count: usize) {
    let _route = MulticastOnLoopback::route();
    let group = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 0, 11)), free_port());
    let channel = UdpConfig {
        destination: Destination::Multicast { group, ttl: None },
        interface: None,
        paths: Vec::new(),
        reliable,
        // The anchor bounds the sender: a joiner that leaves never holds it.
        flow_control: Some(FlowControl::Max),
        security: Security::Trusted,
    };
    let (mut a, mut anchor) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let _ = anchor.add_network_subscription(10, &channel).unwrap();
    let publication = a
        .add_network_publication(aggregate(10, 3, 1), &channel)
        .unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let mut sent = 0u32;
    let mut last_offer = Instant::now();
    let mut offer = |lane: &mut karyos_client::ClientPublication<_>| {
        if last_offer.elapsed() >= PACE {
            let mut payload = [0u8; 1000];
            payload[..4].copy_from_slice(&sent.to_le_bytes());
            if matches!(lane.offer(&payload).unwrap(), OfferOutcome::Accepted { .. }) {
                sent += 1;
                last_offer = Instant::now();
            }
        }
    };
    // The anchor binds from the SETUP and reads, so the stream stays live.
    let started = Instant::now();
    let image = loop {
        offer(&mut lane);
        for driver in [&mut a, &mut anchor] {
            let _ = driver.do_work().unwrap();
        }
        if let Some(image) = anchor.network_image(10, 3) {
            break image;
        }
        assert!(started.elapsed() < JOIN_LIMIT, "the anchor never bound");
        std::thread::sleep(Duration::from_micros(100));
    };
    let mut reader = anchor.subscribe_aggregate(&image, Role::Required).unwrap();
    let mut joins = Vec::with_capacity(count);
    for _ in 0..count {
        let gap = Instant::now();
        while gap.elapsed() < JOIN_GAP {
            offer(&mut lane);
            for driver in [&mut a, &mut anchor] {
                let _ = driver.do_work().unwrap();
            }
            let _ = reader.poll(|_, _, _| {}, BUDGET);
            std::thread::sleep(Duration::from_micros(100));
        }
        let mut joiner = driver(ThreadingMode::Shared);
        let subscribed = Instant::now();
        let _ = joiner.add_network_subscription(10, &channel).unwrap();
        let mut unbound_at = None;
        loop {
            offer(&mut lane);
            for driver in [&mut a, &mut anchor, &mut joiner] {
                let _ = driver.do_work().unwrap();
            }
            let _ = reader.poll(|_, _, _| {}, BUDGET);
            let now = Instant::now();
            if unbound_at.is_none()
                && joiner
                    .net
                    .as_ref()
                    .unwrap()
                    .receiver_counters()
                    .unwrap()
                    .data_unbound
                    > 0
            {
                unbound_at = Some(now);
            }
            if joiner.network_image(10, 3).is_some() {
                let sessions = shared(&mut joiner).receiver.session_counters();
                if sessions.solicits > 1 {
                    // Why this join took another SOLICIT: what its sessions
                    // ignored (DATA while an entry or holdoff stands is
                    // the expected noise, summed apart).
                    let ignored = shared(&mut joiner).receiver.ignored_controls();
                    let noise = ignored
                        .iter()
                        .filter(|reason| {
                            matches!(
                                reason,
                                crate::sessions::receive::Ignored::EntryPending
                                    | crate::sessions::receive::Ignored::SolicitHoldoff
                            )
                        })
                        .count();
                    let other: Vec<_> = ignored
                        .iter()
                        .filter(|reason| {
                            !matches!(
                                reason,
                                crate::sessions::receive::Ignored::EntryPending
                                    | crate::sessions::receive::Ignored::SolicitHoldoff
                            )
                        })
                        .collect();
                    let publisher = a.net.as_ref().unwrap().receiver_counters().unwrap();
                    println!(
                        "bind_time slow join {}: {:.1} ms, solicits {} expired {} withdrawn {} | ignored {other:?} (+{noise} pending or held off) | publisher ring_full_solicit {} rsp_setup_rate_limited {} rsp_setup_total_limited {} unanswerable {}",
                        joins.len(),
                        now.duration_since(unbound_at.unwrap_or(subscribed))
                            .as_secs_f64()
                            * 1000.0,
                        sessions.solicits,
                        sessions.solicits_expired,
                        sessions.solicits_withdrawn,
                        publisher.ring_full_solicit,
                        publisher.rsp_setup_rate_limited,
                        publisher.rsp_setup_total_limited,
                        publisher.unanswerable_source,
                    );
                }
                joins.push(Join {
                    bind: now.duration_since(unbound_at.unwrap_or(subscribed)),
                    subscribe: now.duration_since(subscribed),
                    solicits: sessions.solicits,
                    expired: sessions.solicits_expired,
                });
                break;
            }
            assert!(
                subscribed.elapsed() < JOIN_LIMIT,
                "join {} never bound",
                joins.len()
            );
            std::thread::sleep(Duration::from_micros(100));
        }
    }
    let answers = shared(&mut a).sender.session_counters();
    println!(
        "bind_time {label} publisher answers {} rate_limited {} rate_sources_full {} dropped {}",
        answers.answers, answers.rate_limited, answers.rate_sources_full, answers.dropped
    );
    report(label, &joins, sent);
}

/// Prints `joins`' distribution: one line for the log and one record.
fn report(label: &str, joins: &[Join], sent: u32) {
    let mut bind: Vec<Duration> = joins.iter().map(|join| join.bind).collect();
    bind.sort_unstable();
    let mut subscribe: Vec<Duration> = joins.iter().map(|join| join.subscribe).collect();
    subscribe.sort_unstable();
    let by_solicits = |solicits: u64| {
        joins
            .iter()
            .filter(|join| join.solicits == solicits)
            .count()
    };
    let more = joins.iter().filter(|join| join.solicits >= 3).count();
    let expired: u64 = joins.iter().map(|join| join.expired).sum();
    let (p99_low, p99_high) = interval(&bind, 0.99);
    let ms = |duration: Duration| duration.as_secs_f64() * 1000.0;
    println!(
        "bind_time {label}: n {} | t_bind ms median {:.1} p90 {:.1} p99 {:.1} (95% {:.1} to {:.1}) max {:.1} \
         | t_subscribe ms median {:.1} max {:.1} | solicits 1: {} 2: {} 3+: {} (0: {}) expired {} | {} sent",
        joins.len(),
        ms(quantile(&bind, 0.5)),
        ms(quantile(&bind, 0.9)),
        ms(quantile(&bind, 0.99)),
        ms(p99_low),
        ms(p99_high),
        ms(at_rank(&bind, bind.len())),
        ms(quantile(&subscribe, 0.5)),
        ms(at_rank(&subscribe, subscribe.len())),
        by_solicits(1),
        by_solicits(2),
        more,
        by_solicits(0),
        expired,
        sent,
    );
    println!(
        "bind_time {label} profile: {}",
        std::env::var("KARYOS_NETEM_PROFILE").unwrap_or_default()
    );
    let samples: Vec<String> = bind
        .iter()
        .map(|duration| format!("{:.2}", ms(*duration)))
        .collect();
    println!("bind_time {label} samples ms: {}", samples.join(" "));
}

/// The late join of a reliable multicast group.
#[test]
#[ignore = "a measurement: scripts/netem-test.sh with KARYOS_NETEM_MEASURE"]
fn m150_a_late_reliable_multicast_subscriber_binds() {
    if let Some(count) = joins() {
        measure("reliable", true, count);
    }
}

/// The control: the same join on an unreliable group, whose bind path is
/// the same SOLICIT.
#[test]
#[ignore = "a measurement: scripts/netem-test.sh with KARYOS_NETEM_MEASURE"]
fn m150_a_late_unreliable_multicast_subscriber_binds() {
    if let Some(count) = joins() {
        measure("unreliable", false, count);
    }
}

/// The quantile helpers on a known sample.
#[test]
fn the_quantiles_are_nearest_rank() {
    let sorted: Vec<Duration> = (1..=200).map(Duration::from_millis).collect();
    assert_eq!(quantile(&sorted, 0.5), Duration::from_millis(100));
    assert_eq!(quantile(&sorted, 0.99), Duration::from_millis(198));
    let (low, high) = interval(&sorted, 0.99);
    assert_eq!(
        (low, high),
        (Duration::from_millis(195), Duration::from_millis(200))
    );
}
