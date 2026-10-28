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
//! it fails, measuring nothing, so a missing variable never reads as a
//! measurement. It runs in the test profile (a debug build), so its times
//! carry that build's overhead: the 2 s steps of a lost exchange do not.

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

/// The longest one join is waited for: well past three lost exchanges of
/// about 2 s each. A join still unbound then is censored: counted, and
/// ranked at this value.
const JOIN_LIMIT: Duration = Duration::from_secs(30);
/// The publisher's pace: one 1000-byte message per millisecond.
const PACE: Duration = Duration::from_millis(1);
/// The gap before each join. Every joiner on this host sends its SOLICIT
/// from the group port, one source endpoint, and the publisher answers a
/// source at most `setup_answer_rate` times a second (20, burst 20;
/// network-control-schemas.md §7.4). Joins 60 ms apart stay under it, so
/// only loss makes a join solicit again.
const JOIN_GAP: Duration = Duration::from_millis(60);

/// One join: from its first unbound DATA to the install (`None` when no
/// unbound DATA came before it), from the subscription to the install, the
/// SOLICITs it sent and saw expire, and whether it was censored.
#[derive(Debug, Clone, Copy)]
struct Join {
    bind: Option<Duration>,
    subscribe: Duration,
    solicits: u64,
    expired: u64,
    censored: bool,
}

/// The joins to measure, from `KARYOS_NETEM_MEASURE`; it fails without
/// a positive count, then without the netem job.
fn joins() -> usize {
    let value = std::env::var("KARYOS_NETEM_MEASURE")
        .unwrap_or_else(|_| panic!("KARYOS_NETEM_MEASURE is unset: nothing measured"));
    let joins = value
        .parse::<usize>()
        .ok()
        .filter(|joins| *joins > 0)
        .unwrap_or_else(|| panic!("KARYOS_NETEM_MEASURE={value:?} is not a positive count"));
    super::super::netem::require_netem();
    joins
}

/// Censored joins a run allows: one more stops it, a bind path that broke
/// would otherwise take `JOIN_LIMIT` on every join.
const CENSORED_LIMIT: usize = 3;

/// DATA while a solicit entry or its holdoff stands: the expected noise of
/// a join, apart from the reasons that explain one.
const fn expected(reason: crate::sessions::receive::Ignored) -> bool {
    use crate::sessions::receive::Ignored;
    matches!(reason, Ignored::EntryPending | Ignored::SolicitHoldoff)
}

/// The value at rank `rank` (1-based) of `sorted`, clamped to its ends.
fn at_rank(sorted: &[Duration], rank: usize) -> Duration {
    sorted[rank.clamp(1, sorted.len()) - 1]
}

/// The nearest-rank position of the `q` quantile among `n` samples,
/// 1-based (1 for an empty sample).
fn nearest_rank(n: usize, q: f64) -> usize {
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        reason = "a rank of at most a few thousand"
    )]
    let rank = (q * n as f64).ceil() as usize;
    rank.max(1)
}

/// The nearest-rank `q` quantile of `sorted`.
fn quantile(sorted: &[Duration], q: f64) -> Duration {
    at_rank(sorted, nearest_rank(sorted.len(), q))
}

/// `P(X <= k)` for every `k` in `0..=n`, `X` binomial of `n` trials and
/// success `q`, summed once in logs.
fn binomial_cdfs(n: usize, q: f64) -> Vec<f64> {
    let mut cdfs = Vec::with_capacity(n + 1);
    let (mut log_choose, mut total) = (0.0f64, 0.0f64);
    #[allow(
        clippy::cast_precision_loss,
        reason = "counts of at most a few thousand"
    )]
    let size = n as f64;
    for i in 0..=n {
        #[allow(clippy::cast_precision_loss, reason = "as above")]
        let at = i as f64;
        if i > 0 {
            log_choose += (size - at + 1.0).ln() - at.ln();
        }
        total += (log_choose + at * q.ln() + (size - at) * (1.0 - q).ln()).exp();
        cdfs.push(total.min(1.0));
    }
    cdfs
}

/// A distribution-free interval of at least `level` for the `q` quantile
/// of `n` samples, as 1-based ranks `(low, high)` of its order statistics,
/// from the exact binomial: `B`, the samples below the quantile, is
/// binomial of `n` and `q`; `low` is the largest rank with
/// `P(B <= low - 1) <= (1 - level) / 2`, `high` the smallest with
/// `P(B <= high - 1) >= 1 - (1 - level) / 2`, `None` when no rank reaches
/// it (the upper bound is open). When even rank 1 has more than the tail
/// below it, `low` is 1: the sample's minimum, the lowest bound it has.
/// Returns the coverage `P(low <= B <= high - 1)` too.
fn interval_ranks(n: usize, q: f64, level: f64) -> (usize, Option<usize>, f64) {
    let cdf = binomial_cdfs(n, q);
    let at = |k: usize| cdf.get(k).copied().unwrap_or(1.0);
    let tail = (1.0 - level) / 2.0;
    let mut low = 1;
    while low < n && at(low) <= tail {
        low += 1;
    }
    let high = (1..=n).find(|rank| at(rank - 1) >= 1.0 - tail);
    let below = low.checked_sub(1).map_or(0.0, at);
    let upto = high.map_or(1.0, |rank| at(rank - 1));
    (low, high, upto - below)
}

/// Prints why join `index` took another SOLICIT or never bound: what the
/// joiner's sessions ignored (DATA while an entry or holdoff stands is the
/// expected noise, summed apart) and the publisher's answer drops.
fn diagnose(
    joiner: &mut crate::embedded::EmbeddedDriver,
    publisher: &crate::embedded::EmbeddedDriver,
    kind: &str,
    index: usize,
    bind: Option<Duration>,
) {
    let sessions = shared(joiner).receiver.session_counters();
    let ignored = shared(joiner).receiver.ignored_controls();
    let noise: u64 = ignored
        .seen()
        .filter(|(reason, _)| expected(*reason))
        .map(|(_, count)| count)
        .sum();
    let other: Vec<_> = ignored
        .seen()
        .filter(|(reason, _)| !expected(*reason))
        .collect();
    let counters = publisher.net.as_ref().unwrap().receiver_counters().unwrap();
    println!(
        "bind_time {kind} join {index}: {} ms, solicits {} expired {} withdrawn {} | ignored {other:?} (+{noise} pending or held off, +{} unlisted) | publisher ring_full_solicit {} rsp_setup_rate_limited {} rsp_setup_total_limited {} unanswerable {}",
        bind.map_or_else(
            || "no unbound DATA".to_owned(),
            |bind| format!("{:.1}", bind.as_secs_f64() * 1000.0)
        ),
        sessions.solicits,
        sessions.solicits_expired,
        sessions.solicits_withdrawn,
        ignored.others(),
        counters.ring_full_solicit,
        counters.rsp_setup_rate_limited,
        counters.rsp_setup_total_limited,
        counters.unanswerable_source,
    );
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
    let mut joins: Vec<Join> = Vec::with_capacity(count);
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
                    diagnose(
                        &mut joiner,
                        &a,
                        "slow",
                        joins.len(),
                        unbound_at.map(|at| now.duration_since(at)),
                    );
                }
                joins.push(Join {
                    bind: unbound_at.map(|at| now.duration_since(at)),
                    subscribe: now.duration_since(subscribed),
                    solicits: sessions.solicits,
                    expired: sessions.solicits_expired,
                    censored: false,
                });
                break;
            }
            if subscribed.elapsed() >= JOIN_LIMIT {
                let sessions = shared(&mut joiner).receiver.session_counters();
                // Censored at `now`: a lower bound of its times.
                let bind = unbound_at.map(|at| now.duration_since(at));
                diagnose(&mut joiner, &a, "censored", joins.len(), bind);
                joins.push(Join {
                    bind,
                    subscribe: now.duration_since(subscribed),
                    solicits: sessions.solicits,
                    expired: sessions.solicits_expired,
                    censored: true,
                });
                if joins.iter().filter(|join| join.censored).count() > CENSORED_LIMIT {
                    publisher_line(&mut a, label);
                    report(label, &joins, sent, count);
                    panic!(
                        "more than {CENSORED_LIMIT} joins never bound within {JOIN_LIMIT:?}: \
                         the bind path is broken"
                    );
                }
                break;
            }
            std::thread::sleep(Duration::from_micros(100));
        }
    }
    publisher_line(&mut a, label);
    report(label, &joins, sent, count);
}

/// Prints the publisher's answers and their drops.
fn publisher_line(a: &mut crate::embedded::EmbeddedDriver, label: &str) {
    let answers = shared(a).sender.session_counters();
    println!(
        "bind_time {label} publisher answers {} rate_limited {} rate_sources_full {} dropped {}",
        answers.answers, answers.rate_limited, answers.rate_sources_full, answers.dropped
    );
}

/// Prints `joins`' distribution, of the `planned` joins: one line for the
/// log and one record. Censored joins rank after every other (their times
/// are lower bounds); a statistic whose rank falls among them prints as
/// `>= x (censored)`, and so do their samples.
fn report(label: &str, joins: &[Join], sent: u32, planned: usize) {
    // (censored, time), so the censored sort last.
    let mut bind: Vec<(bool, Duration)> = joins
        .iter()
        .filter_map(|join| join.bind.map(|bind| (join.censored, bind)))
        .collect();
    bind.sort_unstable();
    let mut subscribe: Vec<(bool, Duration)> = joins
        .iter()
        .map(|join| (join.censored, join.subscribe))
        .collect();
    subscribe.sort_unstable();
    let by_solicits = |solicits: u64| {
        joins
            .iter()
            .filter(|join| join.solicits == solicits)
            .count()
    };
    let more = joins.iter().filter(|join| join.solicits >= 3).count();
    let expired: u64 = joins.iter().map(|join| join.expired).sum();
    let censored = joins.iter().filter(|join| join.censored).count();
    let no_unbound = joins.iter().filter(|join| join.bind.is_none()).count();
    let ms = |duration: Duration| duration.as_secs_f64() * 1000.0;
    let shown = |(censored, time): (bool, Duration)| {
        if censored {
            format!(">= {:.1} (censored)", ms(time))
        } else {
            format!("{:.1}", ms(time))
        }
    };
    let value = |sorted: &[(bool, Duration)], rank: usize| {
        sorted
            .get(rank.clamp(1, sorted.len().max(1)) - 1)
            .map_or_else(|| "none".to_owned(), |entry| shown(*entry))
    };
    let interval = if bind.is_empty() {
        "no interval".to_owned()
    } else {
        let (low, high, coverage) = interval_ranks(bind.len(), 0.99, 0.95);
        format!(
            "{:.1}% {} to {}",
            coverage * 100.0,
            value(&bind, low),
            high.map_or_else(|| "open".to_owned(), |high| value(&bind, high)),
        )
    };
    let stopped = if joins.len() < planned {
        format!(" | stopped early: {} of {planned} joins", joins.len())
    } else {
        String::new()
    };
    println!(
        "bind_time {label}: joins {} (with unbound DATA {}) | t_bind ms median {} p90 {} p99 {} ({interval}) max {} \
         | t_subscribe ms median {} max {} | solicits 1: {} 2: {} 3+: {} (0: {}) expired {} \
         | censored {censored}, no unbound DATA {no_unbound} | {} sent{stopped}",
        joins.len(),
        bind.len(),
        value(&bind, nearest_rank(bind.len(), 0.5)),
        value(&bind, nearest_rank(bind.len(), 0.9)),
        value(&bind, nearest_rank(bind.len(), 0.99)),
        value(&bind, bind.len()),
        value(&subscribe, nearest_rank(subscribe.len(), 0.5)),
        value(&subscribe, subscribe.len()),
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
        .map(|&(censored, time)| {
            if censored {
                format!(">={:.2}", ms(time))
            } else {
                format!("{:.2}", ms(time))
            }
        })
        .collect();
    println!("bind_time {label} samples ms: {}", samples.join(" "));
}

/// The late join of a reliable multicast group.
#[test]
#[ignore = "a measurement: scripts/netem-test.sh with KARYOS_NETEM_MEASURE"]
fn m150_a_late_reliable_multicast_subscriber_binds() {
    measure("reliable", true, joins());
}

/// The control: the same join on an unreliable group, whose bind path is
/// the same SOLICIT.
#[test]
#[ignore = "a measurement: scripts/netem-test.sh with KARYOS_NETEM_MEASURE"]
fn m150_a_late_unreliable_multicast_subscriber_binds() {
    measure("unreliable", false, joins());
}

/// The quantile helpers on a known sample.
#[test]
fn the_quantiles_are_nearest_rank() {
    let sorted: Vec<Duration> = (1..=200).map(Duration::from_millis).collect();
    assert_eq!(quantile(&sorted, 0.5), Duration::from_millis(100));
    assert_eq!(quantile(&sorted, 0.99), Duration::from_millis(198));
}

/// The exact interval of the p99: at n = 200 no rank reaches the upper
/// bound, which is open; at n = 1000 both are found, covering at least
/// 95%.
#[test]
fn the_p99_interval_is_exact() {
    let (low, high, coverage) = interval_ranks(200, 0.99, 0.95);
    assert!(high.is_none(), "{low} {high:?} {coverage}");
    assert_eq!(low, 195, "P(B <= 194) <= 2.5% < P(B <= 195)");
    // P(B >= 195) for B binomial of 200 and 0.99, to four places.
    assert!((coverage - 0.9840).abs() < 1e-4, "{coverage}");
    let (low, high, coverage) = interval_ranks(1000, 0.99, 0.95);
    let high = high.unwrap();
    assert!(low < 990 && high > 990, "{low} {high}");
    assert!(coverage >= 0.95, "{coverage}");
    let cdf = binomial_cdfs(10, 0.5);
    assert!((cdf[10] - 1.0).abs() < 1e-9);
    assert!((cdf[4] - 0.376_953_125).abs() < 1e-9);
}
