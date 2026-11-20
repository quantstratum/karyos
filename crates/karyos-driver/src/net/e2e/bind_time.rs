// SPDX-License-Identifier: Apache-2.0

//! How long a late multicast subscriber takes to bind under loss
//! (karyos#805, plan 150): a measurement, not a pass or fail test. A
//! subscriber that joins a live group after the SETUP binds through the
//! SOLICIT its first unbound DATA sends (`quantstratum-docs:
//! karyos/design/network-control-schemas.md` §6.3); a lost SOLICIT or
//! answer costs `setup_challenge_timeout` plus `solicit_holdoff` before the
//! next. Since plan 164 an unanswered SOLICIT is retried at 50 ms,
//! doubling, with its entry's nonce. Each join's
//! time from its first unbound DATA to its image's install is recorded
//! with the SOLICITs it took, the retries included.
//!
//! `KARYOS_BIND_JOIN_GAP_MS` sets the gap before each join (default 60;
//! 0 is the unspaced run). `m164_simultaneous_joins_on_one_driver` joins
//! `KARYOS_BIND_STREAMS` streams (default 50) at once on one driver, whose
//! SOLICITs share one source endpoint and so one `setup_answer_rate`
//! bucket at the publisher (§7.4; plan 168), for
//! `KARYOS_NETEM_MEASURE` joins in all.
//!
//! Runs under `scripts/netem-test.sh` with `KARYOS_NETEM_MEASURE` set to
//! the number of joins, and the profile in `KARYOS_NETEM`:
//!
//! ```text
//! KARYOS_NETEM_MEASURE=200 KARYOS_NETEM='limit 100000 loss 2% reorder 10% 50% delay 1ms duplicate 1%' \
//!     scripts/netem-test.sh -p karyos-driver --lib --locked bind_time -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! The record (plan 164) also runs `delay 100ms` with `loss 2%`, an RTT of
//! about 200 ms, above the 50 ms first wait: a retry keeps its entry's
//! nonce, so the first ANSWER still binds and a join takes about one RTT.
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
/// about 2 s each. A join still unbound then is censored: its times, taken
/// at that moment, are lower bounds.
const JOIN_LIMIT: Duration = Duration::from_secs(30);
/// The publisher's pace: one 1000-byte message per millisecond.
const PACE: Duration = Duration::from_millis(1);
/// The gap before each join. Every joiner on this host sends its SOLICIT
/// from the group port, one source endpoint, and the publisher answers a
/// source at most `setup_answer_rate` times a second (20, burst 20;
/// network-control-schemas.md §7.4). Joins 60 ms apart stay under it, so
/// only loss makes a join solicit again.
const JOIN_GAP: Duration = Duration::from_millis(60);

/// The gap before each join: `KARYOS_BIND_JOIN_GAP_MS`, or [`JOIN_GAP`].
fn join_gap() -> Duration {
    std::env::var("KARYOS_BIND_JOIN_GAP_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map_or(JOIN_GAP, Duration::from_millis)
}

/// The streams joined at once on one driver: `KARYOS_BIND_STREAMS`, or 50.
fn streams() -> usize {
    std::env::var("KARYOS_BIND_STREAMS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|count| *count > 0)
        .unwrap_or(50)
}

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
        retransmit_window: None,
        nak_control: Vec::new(),
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
        while gap.elapsed() < join_gap() {
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
                if sessions.solicits + sessions.solicit_retries > 1 {
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
                    solicits: sessions.solicits + sessions.solicit_retries,
                    expired: sessions.solicits_expired,
                    censored: false,
                });
                break;
            }
            if now.duration_since(subscribed) >= JOIN_LIMIT {
                let sessions = shared(&mut joiner).receiver.session_counters();
                // Censored at `now`: a lower bound of its times.
                let bind = unbound_at.map(|at| now.duration_since(at));
                diagnose(&mut joiner, &a, "censored", joins.len(), bind);
                joins.push(Join {
                    bind,
                    subscribe: now.duration_since(subscribed),
                    solicits: sessions.solicits + sessions.solicit_retries,
                    expired: sessions.solicits_expired,
                    censored: true,
                });
                if joins.iter().filter(|join| join.censored).count() > CENSORED_LIMIT {
                    publisher_line(&mut a, label);
                    report(label, &joins, sent, Some(count));
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
    report(label, &joins, sent, None);
}

/// Prints the publisher's answers and their drops.
fn publisher_line(a: &mut crate::embedded::EmbeddedDriver, label: &str) {
    let answers = shared(a).sender.session_counters();
    println!(
        "bind_time {label} publisher answers {} rate_limited {} rate_sources_full {} dropped {}",
        answers.answers, answers.rate_limited, answers.rate_sources_full, answers.dropped
    );
}

/// A sample sorted by time alone, each marked censored or not: a rank is
/// exact only when no censored entry lies at or below it, otherwise the
/// value there is a lower bound.
struct Sample(Vec<(Duration, bool)>);

impl Sample {
    fn new(mut entries: Vec<(Duration, bool)>) -> Self {
        entries.sort_unstable_by_key(|(time, _)| *time);
        Self(entries)
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    /// The value at 1-based `rank`, clamped, as printed.
    fn at(&self, rank: usize) -> String {
        let Some(at) = rank.clamp(1, self.len().max(1)).checked_sub(1) else {
            return "none".to_owned();
        };
        let Some(&(time, _)) = self.0.get(at) else {
            return "none".to_owned();
        };
        let bounded = self.0.iter().take(at + 1).any(|(_, censored)| *censored);
        shown(time, bounded)
    }

    /// The maximum, as printed: a lower bound when any entry is censored.
    fn max(&self) -> String {
        let censored = self.0.iter().any(|(_, censored)| *censored);
        self.0
            .last()
            .map_or_else(|| "none".to_owned(), |&(time, _)| shown(time, censored))
    }
}

/// `time` in milliseconds, as a lower bound when `bounded`.
fn shown(time: Duration, bounded: bool) -> String {
    let ms = time.as_secs_f64() * 1000.0;
    if bounded {
        format!(">= {ms:.1} (censored)")
    } else {
        format!("{ms:.1}")
    }
}

/// Prints `joins`' distribution: one line for the log and one record,
/// which says when the run stopped early, of `planned` joins. A censored
/// join's times are lower bounds: a statistic whose rank has one at or
/// below it prints as `>= x (censored)`, and so do the censored samples.
fn report(label: &str, joins: &[Join], sent: u32, stopped_of: Option<usize>) {
    let bind = Sample::new(
        joins
            .iter()
            .filter_map(|join| join.bind.map(|bind| (bind, join.censored)))
            .collect(),
    );
    let subscribe = Sample::new(
        joins
            .iter()
            .map(|join| (join.subscribe, join.censored))
            .collect(),
    );
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
    let interval = if bind.len() == 0 {
        "no interval".to_owned()
    } else {
        let (low, high, coverage) = interval_ranks(bind.len(), 0.99, 0.95);
        format!(
            "{:.1}% {} to {}",
            coverage * 100.0,
            bind.at(low),
            high.map_or_else(|| "open".to_owned(), |high| bind.at(high)),
        )
    };
    let stopped = stopped_of.map_or_else(String::new, |planned| {
        format!(" | stopped early: {} of {planned} joins", joins.len())
    });
    println!(
        "bind_time {label}: joins {} (with unbound DATA {}) | t_bind ms median {} p90 {} p99 {} ({interval}) max {} \
         | t_subscribe ms median {} max {} | solicits 1: {} 2: {} 3+: {} (0: {}) expired {} \
         | censored {censored}, no unbound DATA {no_unbound} | {} sent{stopped}",
        joins.len(),
        bind.len(),
        bind.at(nearest_rank(bind.len(), 0.5)),
        bind.at(nearest_rank(bind.len(), 0.9)),
        bind.at(nearest_rank(bind.len(), 0.99)),
        bind.max(),
        subscribe.at(nearest_rank(subscribe.len(), 0.5)),
        subscribe.max(),
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
        .0
        .iter()
        .map(|&(time, censored)| shown(time, censored))
        .collect();
    println!("bind_time {label} samples ms: {}", samples.join(" "));
}

/// A censored entry bounds every rank at or above its own, and the max.
#[test]
fn a_censored_entry_bounds_the_ranks_above_it() {
    let sample = Sample::new(vec![
        (Duration::from_millis(5), false),
        (Duration::from_millis(12), false),
        (Duration::from_millis(7), true),
        (Duration::from_millis(20_000), false),
    ]);
    assert_eq!(sample.at(1), "5.0");
    assert_eq!(sample.at(2), ">= 7.0 (censored)");
    assert_eq!(sample.at(3), ">= 12.0 (censored)");
    assert_eq!(sample.max(), ">= 20000.0 (censored)");
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

/// Plan 164's known limit, measured: `streams()` publications on one
/// group, joined at once by one fresh driver per round, until
/// `KARYOS_NETEM_MEASURE` joins are recorded. Their SOLICITs share the
/// joiner's source endpoint, one `setup_answer_rate` bucket (20 a second,
/// burst 20) at the publisher; those beyond it bind at a later retry.
fn measure_one_driver(label: &str, reliable: bool, count: usize, streams: usize) {
    measure_drivers(label, reliable, count, streams, 1);
}

/// [`measure_one_driver`] with `drivers` fresh joiner drivers per round,
/// each joining every stream at once (plan 169): on one host they share
/// the group port, and without a per-driver SOLICIT endpoint they are one
/// source to the publisher's `setup_answer_rate`.
fn measure_drivers(label: &str, reliable: bool, count: usize, streams: usize, drivers: usize) {
    let _route = MulticastOnLoopback::route();
    let group = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 0, 12)), free_port());
    let channel = UdpConfig {
        retransmit_window: None,
        nak_control: Vec::new(),
        destination: Destination::Multicast { group, ttl: None },
        interface: None,
        paths: Vec::new(),
        reliable,
        flow_control: Some(FlowControl::Max),
        security: Security::Trusted,
    };
    let ids: Vec<i32> = (0..streams)
        .map(|index| 100 + i32::try_from(index).unwrap())
        .collect();
    // The publisher's endpoint holds every stream (karyos#859): per reliable
    // single-lane publication 9 slots, 2 queues and a route, with the
    // control reserve of 8 routes and queues of 4 slots.
    let mut a = sized_publisher(streams);
    let mut anchor = driver(ThreadingMode::Shared);
    let mut lanes = Vec::with_capacity(streams);
    for &stream in &ids {
        let _ = anchor.add_network_subscription(stream, &channel).unwrap();
        let publication = a
            .add_network_publication(aggregate(stream, 3, 1), &channel)
            .unwrap();
        lanes.push(
            a.publication(publication.lane(Lane::ZERO).unwrap())
                .unwrap(),
        );
    }
    let mut sent = 0u32;
    let mut last_offer = Instant::now();
    let mut next = 0usize;
    let mut offer = |lanes: &mut Vec<karyos_client::ClientPublication<_>>| {
        if last_offer.elapsed() >= PACE {
            let mut payload = [0u8; 100];
            payload[..4].copy_from_slice(&sent.to_le_bytes());
            let index = next % lanes.len();
            next = next.wrapping_add(1);
            if matches!(
                lanes[index].offer(&payload).unwrap(),
                OfferOutcome::Accepted { .. }
            ) {
                sent += 1;
                last_offer = Instant::now();
            }
        }
    };
    let started = Instant::now();
    let mut readers = Vec::with_capacity(streams);
    for &stream in &ids {
        let image = loop {
            offer(&mut lanes);
            for driver in [&mut a, &mut anchor] {
                let _ = driver.do_work().unwrap();
            }
            if let Some(image) = anchor.network_image(stream, 3) {
                break image;
            }
            assert!(
                started.elapsed() < JOIN_LIMIT,
                "the anchor never bound {stream}"
            );
            std::thread::sleep(Duration::from_micros(100));
        };
        readers.push(anchor.subscribe_aggregate(&image, Role::Required).unwrap());
    }
    let mut joins: Vec<Join> = Vec::with_capacity(count);
    while joins.len() < count {
        let mut joiners: Vec<_> = (0..drivers)
            .map(|_| driver(ThreadingMode::Shared))
            .collect();
        let subscribed = Instant::now();
        for joiner in &mut joiners {
            for &stream in &ids {
                let _ = joiner.add_network_subscription(stream, &channel).unwrap();
            }
        }
        let mut bound = vec![vec![false; streams]; drivers];
        let mut tick = Instant::now();
        loop {
            if std::env::var("KARYOS_BIND_TIMELINE").is_ok_and(|value| !value.is_empty())
                && tick.elapsed() >= Duration::from_secs(1)
            {
                tick = Instant::now();
                for (index, joiner) in joiners.iter_mut().enumerate() {
                    let sessions = shared(joiner).receiver.session_counters();
                    let own = joiner.net.as_ref().unwrap().receiver_counters().unwrap();
                    println!(
                        "bind_time timeline {:.1} s driver {index}: bound {} | data_unbound {} rate_limited {} | solicits {} retries {} answered {} expired {} withdrawn {} dropped {}",
                        subscribed.elapsed().as_secs_f64(),
                        bound[index].iter().filter(|done| **done).count(),
                        own.data_unbound,
                        own.rsp_setup_rate_limited,
                        sessions.solicits,
                        sessions.solicit_retries,
                        sessions.solicits_answered,
                        sessions.solicits_expired,
                        sessions.solicits_withdrawn,
                        sessions.dropped,
                    );
                }
            }
            offer(&mut lanes);
            for driver in [&mut a, &mut anchor] {
                let _ = driver.do_work().unwrap();
            }
            for joiner in &mut joiners {
                let _ = joiner.do_work().unwrap();
            }
            for reader in &mut readers {
                let _ = reader.poll(|_, _, _| {}, BUDGET);
            }
            let now = Instant::now();
            for (joiner, bound) in joiners.iter().zip(bound.iter_mut()) {
                for (index, &stream) in ids.iter().enumerate() {
                    if !bound[index] && joiner.network_image(stream, 3).is_some() {
                        bound[index] = true;
                        joins.push(Join {
                            bind: Some(now.duration_since(subscribed)),
                            subscribe: now.duration_since(subscribed),
                            solicits: 0,
                            expired: 0,
                            censored: false,
                        });
                    }
                }
            }
            let censored = now.duration_since(subscribed) >= JOIN_LIMIT;
            if bound.iter().flatten().all(|done| *done) || censored {
                for joiner in &mut joiners {
                    let sessions = shared(joiner).receiver.session_counters();
                    let ignored = shared(joiner).receiver.ignored_controls();
                    let reasons: Vec<_> = ignored.seen().collect();
                    let own = joiner.net.as_ref().unwrap().receiver_counters().unwrap();
                    println!(
                        "bind_time {label} round: solicits {} retries {} refused {} expired {} \
                         | joiner rsp_setup_rate_limited {} rsp_setup_total_limited {} rsp_setup_destinations_full {} \
                         ring_full_rsp_setup {} | ignored {reasons:?}",
                        sessions.solicits,
                        sessions.solicit_retries,
                        sessions.solicit_retries_refused,
                        sessions.solicits_expired,
                        own.rsp_setup_rate_limited,
                        own.rsp_setup_total_limited,
                        own.rsp_setup_destinations_full,
                        own.ring_full_rsp_setup,
                    );
                }
                if censored {
                    let missing = bound.iter().flatten().filter(|done| !**done).count();
                    for _ in 0..missing {
                        joins.push(Join {
                            bind: Some(now.duration_since(subscribed)),
                            subscribe: now.duration_since(subscribed),
                            solicits: 0,
                            expired: 0,
                            censored: true,
                        });
                    }
                }
                break;
            }
            std::thread::sleep(Duration::from_micros(100));
        }
    }
    publisher_line(&mut a, label);
    report(label, &joins, sent, None);
}

/// A publisher whose endpoint holds `streams` reliable single-lane
/// publications (karyos#859).
fn sized_publisher(streams: usize) -> crate::embedded::EmbeddedDriver {
    let count = u16::try_from(streams).unwrap();
    let tables = crate::net::EndpointTables {
        tx_slots: std::num::NonZeroU16::new(32 + 9 * count).unwrap(),
        max_queues: std::num::NonZeroU16::new(8 + 2 * count).unwrap(),
        max_routes: std::num::NonZeroU16::new(8 + count).unwrap(),
    };
    crate::embedded::EmbeddedDriver::with_config(crate::embedded::DriverConfig {
        network: Some(crate::net::NetworkConfig {
            threading: ThreadingMode::Shared,
            endpoint_tables: tables,
            ..crate::net::NetworkConfig::default()
        }),
        ..crate::embedded::DriverConfig::default()
    })
    .unwrap()
}

/// Plan 164: `KARYOS_BIND_STREAMS` reliable joins at once on one driver.
#[test]
#[ignore = "a measurement: scripts/netem-test.sh with KARYOS_NETEM_MEASURE"]
fn m164_simultaneous_joins_on_one_driver() {
    measure_one_driver("one driver", true, joins(), streams());
}

/// The joiner drivers of one round: `KARYOS_BIND_DRIVERS`, or 4.
fn drivers() -> usize {
    std::env::var("KARYOS_BIND_DRIVERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|count| *count > 0)
        .unwrap_or(4)
}

/// Plan 169: `KARYOS_BIND_DRIVERS` joiner drivers on one host, each
/// joining `KARYOS_BIND_STREAMS` reliable streams at once.
#[test]
#[ignore = "a measurement: scripts/netem-test.sh with KARYOS_NETEM_MEASURE"]
fn m169_simultaneous_joins_on_several_drivers() {
    measure_drivers("several drivers", true, joins(), streams(), drivers());
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
