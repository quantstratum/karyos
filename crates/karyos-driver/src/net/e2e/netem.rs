// SPDX-License-Identifier: Apache-2.0

//! The driver's network fault tests (W6): two embedded drivers over the
//! loopback that `scripts/netem-test.sh` shapes with tc netem (loss,
//! reorder, delay, duplicate). Ignored in the normal suites; each refuses
//! to run outside the job (`net::netem`).
//!
//! - N1: an unreliable channel delivers each message at most once and in
//!   order, and reports every lost message as a local gap.
//! - N2: a reliable channel delivers every message exactly once and in
//!   order, through NAKs and the sender's repairs.
//! - N3: N2 with 5% duplicated datagrams.
//! - N4 to N7 (T4, quantstratum-docs:
//!   karyos/testing/contract-traceability-phase-2.md, "Loss, reorder,
//!   duplicate"): N2 in Dedicated mode, on two lanes, on a multicast group
//!   with two subscribers, and across a blackout of the path, which the
//!   sender's idle DATA heartbeat (SPEC §6) lets the receiver repair.
//! - N8 (network-shared-terms n4): N2 between two IPC drivers, whose
//!   publication and image lanes are shared regions (Linux).
//! - N10 and N11 (karyos#626): reorder alone, with no loss or duplicate in
//!   the profile: a reliable channel still delivers exactly once and in
//!   order, and an unreliable one at most once and in order, every
//!   datagram that came too late for its place reported in a local gap.

#![allow(
    clippy::print_stdout,
    reason = "the job's log records what the faults did (run with --nocapture)"
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use karyos_client::OfferOutcome;
use karyos_protocol::channel::{Destination, Security, UdpConfig};
use karyos_protocol::lanes::drr::Budget;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{Role, SkipReason};
use karyos_sys::sizing::MIN_TERM_LENGTH;

use super::{
    ANY_PORT, BUDGET, aggregate, bound, channel, connected, driver, exchange, free_port, pump,
};
use crate::agents::ThreadingMode;
use crate::embedded::EmbeddedDriver;

/// The bytes a 1000-byte message takes in a term: its 32-byte header,
/// aligned to 32.
const FRAME: u64 = 1056;

/// One DRR step per poll (a probe and one service unit): a poll then
/// serves one message or one skipped range, so no skip is hidden behind
/// another in its report.
const ONE: Budget = Budget {
    work: 2,
    bytes: 1 << 22,
};

/// The stream position of message `n` of a log that holds only 1000-byte
/// messages from position 0: 62 to a term, whose last 64 bytes are padding.
fn position(n: u32) -> u64 {
    let term = u64::from(MIN_TERM_LENGTH);
    let per_term = u32::try_from(term / FRAME).unwrap();
    u64::from(n / per_term) * term + u64::from(n % per_term) * FRAME
}

/// N1: over loss, reordering and duplication an unreliable channel
/// delivers each message at most once and in order, at its position, and
/// every message it does not deliver lies in a local gap the subscriber
/// was told of; no gap covers a delivered message.
#[test]
#[ignore = "runs under scripts/netem-test.sh"]
fn n1_an_unreliable_channel_reports_every_loss_as_a_gap() {
    super::super::netem::require_netem();
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let (publication, image) = connected(&mut a, &mut b, false, 10);
    let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let count = 2000u32;
    let mut sent = 0u32;
    let mut delivered: Vec<u32> = Vec::new();
    // Local gaps as [start, end) stream positions, in order.
    let mut gaps: Vec<(u64, u64)> = Vec::new();
    // Messages below it were delivered or lie in a gap.
    let mut accounted = 0u32;
    pump(&mut [&mut a, &mut b], |_| {
        while sent < count {
            let mut payload = [0u8; 1000];
            payload[..4].copy_from_slice(&sent.to_le_bytes());
            match lane.offer(&payload).unwrap() {
                OfferOutcome::Accepted { .. } => sent += 1,
                _ => break,
            }
        }
        let poll = reader.poll(
            |bytes, _, info| {
                let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                assert!(
                    delivered.last().is_none_or(|last| index > *last),
                    "{index} after {:?}: at most once, in order",
                    delivered.last()
                );
                assert_eq!(info.position, position(index), "message {index}");
                delivered.push(index);
            },
            ONE,
        );
        if let Some(skipped) = poll.lanes[0].skipped
            && matches!(skipped.reason, SkipReason::LocalGap(_))
        {
            gaps.push((
                skipped.position,
                skipped.position + u64::from(skipped.extent),
            ));
        }
        let in_gap = |n: u32| {
            gaps.iter()
                .any(|&(start, end)| start <= position(n) && position(n) < end)
        };
        while accounted < count
            && (delivered.binary_search(&accounted).is_ok() || in_gap(accounted))
        {
            accounted += 1;
        }
        accounted == count
    });
    for &n in &delivered {
        assert!(
            !gaps
                .iter()
                .any(|&(start, end)| start <= position(n) && position(n) < end),
            "message {n} delivered inside a gap"
        );
    }
    let lost = count - u32::try_from(delivered.len()).unwrap();
    println!(
        "N1: sent {count}, delivered {}, lost {lost} in {} gaps",
        delivered.len(),
        gaps.len()
    );
    assert!(
        !gaps.is_empty(),
        "no loss over {count} messages: netem idle?"
    );
}

/// Two drivers and a reliable channel: every one of `count` messages
/// reaches a required subscriber exactly once and in order (`exchange`
/// asserts it), with no loss reported on the lane. Prints what the faults
/// cost. Returns the two drivers, sender first.
fn reliable_delivery(label: &str, count: u32) -> (EmbeddedDriver, EmbeddedDriver) {
    reliable_delivery_in(label, ThreadingMode::Shared, count)
}

/// [`reliable_delivery`] with both drivers in `threading`.
fn reliable_delivery_in(
    label: &str,
    threading: ThreadingMode,
    count: u32,
) -> (EmbeddedDriver, EmbeddedDriver) {
    let (mut a, mut b) = (driver(threading), driver(threading));
    let (publication, image) = connected(&mut a, &mut b, true, 10);
    let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
    exchange(&mut a, &mut b, &publication, &mut reader, count);
    let poll = reader.poll(|_, _, _| {}, ONE);
    assert_eq!(poll.lanes[0].first_loss, None, "a reliable lane lost data");
    let counters =
        |driver: &crate::embedded::EmbeddedDriver| driver.net.as_ref().unwrap().agent_counters();
    println!("{label}: {count} delivered in order exactly once");
    println!("{label} sender side: {}", counters(&a));
    println!("{label} receiver side: {}", counters(&b));
    (a, b)
}

/// N2: over loss, reordering and duplication a reliable channel delivers
/// every message exactly once and in order: the receiver NAKs each hole
/// and the sender's repair path resends it.
#[test]
#[ignore = "runs under scripts/netem-test.sh"]
fn n2_a_reliable_channel_delivers_exactly_once_in_order() {
    super::super::netem::require_netem();
    let (a, b) = reliable_delivery("N2", 2000);
    let (naks, repairs) = repair_work(&a, &b);
    println!("N2: {naks} NAKs, {repairs} repairs");
    assert!(naks > 0 && repairs > 0, "no repair: netem idle?");
}

/// The job's netem profile with `duplicate` raised for one test; the
/// job's profile is back on drop.
struct Profile {
    base: String,
}

impl Profile {
    /// Replaces the loopback's netem profile by the job's with
    /// `duplicate {percent}%`.
    fn duplicate(percent: u32) -> Self {
        let base = std::env::var("KARYOS_NETEM_PROFILE").unwrap();
        let mut words: Vec<String> = base.split_whitespace().map(str::to_owned).collect();
        match words.iter().position(|word| word == "duplicate") {
            Some(at) => words[at + 1] = format!("{percent}%"),
            None => words.extend(["duplicate".to_owned(), format!("{percent}%")]),
        }
        tc(&words);
        println!("netem profile for this test: {}", words.join(" "));
        Self { base }
    }

    /// Replaces the loopback's netem profile by `profile` until drop.
    fn replace(profile: &str) -> Self {
        let base = std::env::var("KARYOS_NETEM_PROFILE").unwrap();
        let words: Vec<String> = profile.split_whitespace().map(str::to_owned).collect();
        tc(&words);
        println!("netem profile now: {profile}");
        Self { base }
    }
}

impl Drop for Profile {
    fn drop(&mut self) {
        let words: Vec<String> = self.base.split_whitespace().map(str::to_owned).collect();
        tc(&words);
    }
}

/// `tc qdisc change dev lo root netem <profile>`.
fn tc(profile: &[String]) {
    let status = std::process::Command::new("tc")
        .args(["qdisc", "change", "dev", "lo", "root", "netem"])
        .args(profile)
        .status()
        .unwrap();
    assert!(status.success(), "tc qdisc change failed: {status}");
}

/// N3: N2 with 5% of the datagrams duplicated: repairs and duplicates
/// together still deliver every message exactly once and in order. A probe
/// over the same profile shows that the path duplicates; the receiver
/// dropped frames it had already committed or could not take, and the
/// sender repaired.
#[test]
#[ignore = "runs under scripts/netem-test.sh"]
fn n3_a_reliable_channel_survives_five_percent_duplicates() {
    super::super::netem::require_netem();
    let _profile = Profile::duplicate(5);
    let shaping = super::super::netem::probe_loopback(2000);
    println!("N3 probe: {shaping:?}");
    assert!(shaping.duplicates > 0, "the profile duplicated nothing");
    let (a, b) = reliable_delivery("N3", 2000);
    let (naks, repairs) = repair_work(&a, &b);
    let dropped = b
        .net
        .as_ref()
        .unwrap()
        .receiver_counters()
        .unwrap()
        .data_dropped;
    println!("N3: {naks} NAKs, {repairs} repairs, {dropped} DATA frames dropped");
    assert!(naks > 0 && repairs > 0, "no repair: netem idle?");
    assert!(dropped > 0, "no copy reached the receiver to be dropped");
    drop(_profile);
    // Duplicates alone (karyos#626): with no loss and no reorder in the
    // profile, nothing is missing, so nothing is NAKed or repaired, and
    // every DATA frame the receiver drops is a copy of one it committed.
    let _duplicates = Profile::replace("limit 100000 duplicate 5%");
    let shaping = super::super::netem::probe_loopback(2000);
    println!("N3 duplicates-only probe: {shaping:?}");
    assert!(shaping.duplicates > 0, "the profile duplicated nothing");
    assert_eq!((shaping.lost, shaping.reordered), (0, 0), "{shaping:?}");
    let (a, b) = reliable_delivery("N3 duplicates only", 2000);
    let (naks, repairs) = repair_work(&a, &b);
    let dropped = b
        .net
        .as_ref()
        .unwrap()
        .receiver_counters()
        .unwrap()
        .data_dropped;
    println!("N3 duplicates only: {naks} NAKs, {repairs} repairs, {dropped} dropped");
    assert_eq!((naks, repairs), (0, 0), "nothing was missing to repair");
    assert!(
        dropped > 0,
        "no duplicate reached the receiver to be dropped"
    );
}

/// The NAKs B's receiver sent and the repairs A's sender made, in Shared
/// mode: nonzero once netem cost datagrams on the path.
fn repair_work(a: &EmbeddedDriver, b: &EmbeddedDriver) -> (u64, u64) {
    let naks = b.net.as_ref().unwrap().receiver_counters().unwrap().naks;
    let repairs = a.net.as_ref().unwrap().sender_counters().unwrap().repairs;
    (naks, repairs)
}

/// N4 (T4): N2 with both drivers in Dedicated mode, each agent on its own
/// thread: every message arrives exactly once and in order, with no loss
/// reported, and the repair happened. Dedicated agents keep no agent
/// counters, so the repair is read from the per-stream cells N9 reads
/// (karyos#626): B's image sent NAKs and A's publication retransmitted.
#[test]
#[ignore = "runs under scripts/netem-test.sh"]
fn n4_a_reliable_channel_in_dedicated_mode_delivers_exactly_once_in_order() {
    super::super::netem::require_netem();
    let (mut a, mut b) = (
        driver(ThreadingMode::Dedicated),
        driver(ThreadingMode::Dedicated),
    );
    let (publication, image) = connected(&mut a, &mut b, true, 10);
    let (sent, seen) = (publication.registration(), image.registration());
    let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
    exchange(&mut a, &mut b, &publication, &mut reader, 2000);
    let poll = reader.poll(|_, _, _| {}, ONE);
    assert_eq!(poll.lanes[0].first_loss, None, "a reliable lane lost data");
    let value = |driver: &EmbeddedDriver, label: &str, stream: u64| {
        super::cells(driver, label)
            .into_iter()
            .find(|(_, keys)| keys.stream == stream)
            .map_or(0, |(value, _)| value)
    };
    // The agents store at the end of their cycles.
    pump(&mut [&mut a, &mut b], |drivers| {
        value(drivers[1], "network naks sent", seen) > 0
            && value(drivers[0], "network retransmits", sent) > 0
    });
    println!(
        "N4: 2000 delivered in order exactly once; naks sent {}, retransmits {}",
        value(&b, "network naks sent", seen),
        value(&a, "network retransmits", sent),
    );
}

/// The reorder-only profile of N10 and N11: every fourth datagram, half
/// the time with its successor, overtakes the others, which wait 2 ms.
/// netem reorders only with a delay; there is no loss and no duplicate.
const REORDER_ONLY: &str = "limit 100000 delay 2ms reorder 25% 50%";

/// Puts the reorder-only profile in place and shows that it reorders and
/// neither loses nor duplicates.
fn reorder_only(label: &str) -> Profile {
    let profile = Profile::replace(REORDER_ONLY);
    let shaping = super::super::netem::probe_loopback(2000);
    println!("{label} probe: {shaping:?}");
    assert!(shaping.reordered > 0, "the profile reordered nothing");
    assert_eq!((shaping.lost, shaping.duplicates), (0, 0), "{shaping:?}");
    profile
}

/// N10 (karyos#626): reorder alone on a reliable channel: every message
/// still reaches the subscriber exactly once and in order (`exchange`
/// asserts it, and fails on an out-of-order or repeated message), with no
/// loss reported. Holes that reordering opens may be NAKed and repaired,
/// or filled by the late datagram; either way the order is the log's.
#[test]
#[ignore = "runs under scripts/netem-test.sh"]
fn n10_a_reliable_channel_under_reorder_alone_delivers_exactly_once_in_order() {
    super::super::netem::require_netem();
    let _profile = reorder_only("N10");
    let (a, b) = reliable_delivery("N10", 2000);
    let (naks, repairs) = repair_work(&a, &b);
    println!("N10: {naks} NAKs, {repairs} repairs under reorder alone");
}

/// N11 (karyos#626): reorder alone on an unreliable channel: each message
/// is delivered at most once and in order, at its position. A datagram that
/// arrives after the subscriber was given a local gap over its place is
/// never delivered out of order: its message lies in that gap. Nothing is
/// lost in the profile, so every message is either delivered or in a gap
/// the subscriber was told of, and no gap covers a delivered message.
#[test]
#[ignore = "runs under scripts/netem-test.sh"]
fn n11_an_unreliable_channel_under_reorder_alone_delivers_in_order() {
    super::super::netem::require_netem();
    let _profile = reorder_only("N11");
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let (publication, image) = connected(&mut a, &mut b, false, 10);
    let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let count = 2000u32;
    let mut sent = 0u32;
    let mut delivered: Vec<u32> = Vec::new();
    let mut gaps: Vec<(u64, u64)> = Vec::new();
    let mut accounted = 0u32;
    pump(&mut [&mut a, &mut b], |_| {
        while sent < count {
            let mut payload = [0u8; 1000];
            payload[..4].copy_from_slice(&sent.to_le_bytes());
            match lane.offer(&payload).unwrap() {
                OfferOutcome::Accepted { .. } => sent += 1,
                _ => break,
            }
        }
        let poll = reader.poll(
            |bytes, _, info| {
                let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                assert!(
                    delivered.last().is_none_or(|last| index > *last),
                    "{index} after {:?}: at most once, in order",
                    delivered.last()
                );
                assert_eq!(info.position, position(index), "message {index}");
                delivered.push(index);
            },
            ONE,
        );
        if let Some(skipped) = poll.lanes[0].skipped
            && matches!(skipped.reason, SkipReason::LocalGap(_))
        {
            gaps.push((
                skipped.position,
                skipped.position + u64::from(skipped.extent),
            ));
        }
        let in_gap = |n: u32| {
            gaps.iter()
                .any(|&(start, end)| start <= position(n) && position(n) < end)
        };
        while accounted < count
            && (delivered.binary_search(&accounted).is_ok() || in_gap(accounted))
        {
            accounted += 1;
        }
        accounted == count
    });
    for &n in &delivered {
        assert!(
            !gaps
                .iter()
                .any(|&(start, end)| start <= position(n) && position(n) < end),
            "message {n} delivered inside a gap"
        );
    }
    println!(
        "N11: sent {count}, delivered {}, {} local gaps over late datagrams",
        delivered.len(),
        gaps.len()
    );
}

/// N5 (T4): a reliable publication of two lanes under the job's faults:
/// each lane delivers its own messages exactly once and in order, and
/// neither reports a loss; the receiver NAKed and the sender repaired.
#[test]
#[ignore = "runs under scripts/netem-test.sh"]
fn n5_two_reliable_lanes_each_deliver_exactly_once_in_order() {
    super::super::netem::require_netem();
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let _ = b
        .add_network_subscription(10, &channel(ANY_PORT, true))
        .unwrap();
    let address = bound(&b, 10);
    let publication = a
        .add_network_publication(aggregate(10, 3, 2), &channel(address, true))
        .unwrap();
    let mut image = None;
    pump(&mut [&mut a, &mut b], |drivers| {
        image = drivers[1].network_image(10, 3);
        image.is_some()
    });
    let mut reader = b
        .subscribe_aggregate(&image.unwrap(), Role::Required)
        .unwrap();
    let mut lanes = [
        a.publication(publication.lane(Lane::ZERO).unwrap())
            .unwrap(),
        a.publication(publication.lane(Lane::try_new(1).unwrap()).unwrap())
            .unwrap(),
    ];
    let count = 1000u32;
    let (mut sent, mut seen) = ([0u32; 2], [0u32; 2]);
    pump(&mut [&mut a, &mut b], |_| {
        for (lane, publication) in lanes.iter_mut().enumerate() {
            while sent[lane] < count {
                let mut payload = [0u8; 1000];
                payload[..4].copy_from_slice(&sent[lane].to_le_bytes());
                match publication.offer(&payload).unwrap() {
                    OfferOutcome::Accepted { .. } => sent[lane] += 1,
                    _ => break,
                }
            }
        }
        let _ = reader.poll(
            |bytes, lane, _| {
                let lane = usize::from(lane.get());
                let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                assert_eq!(index, seen[lane], "lane {lane}: exactly once, in order");
                seen[lane] += 1;
            },
            BUDGET,
        );
        seen == [count, count]
    });
    let poll = reader.poll(|_, _, _| {}, ONE);
    for lane in 0..2 {
        assert_eq!(poll.lanes[lane].first_loss, None, "lane {lane} lost data");
    }
    let (naks, repairs) = repair_work(&a, &b);
    println!("N5: {count} on each of 2 lanes, in order; {naks} NAKs, {repairs} repairs");
    assert!(naks > 0 && repairs > 0, "no repair: netem idle?");
}

/// Multicast groups in 239.255.0.0/16 carried by the loopback, which the
/// job shapes: `lo` takes multicast and a route of the range. Without it a
/// group's datagrams leave by the default route, unshaped. Undone on drop.
struct MulticastOnLoopback;

impl MulticastOnLoopback {
    fn route() -> Self {
        ip(&["link", "set", "lo", "multicast", "on"]);
        ip(&["route", "add", "239.255.0.0/16", "dev", "lo"]);
        Self
    }
}

impl Drop for MulticastOnLoopback {
    fn drop(&mut self) {
        ip(&["route", "del", "239.255.0.0/16", "dev", "lo"]);
        ip(&["link", "set", "lo", "multicast", "off"]);
    }
}

/// `ip <args>`.
fn ip(args: &[&str]) {
    let status = std::process::Command::new("ip")
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "ip {args:?} failed: {status}");
}

/// N6 (T4): a reliable multicast publication with two subscribers, the
/// group routed over the shaped loopback: each subscriber gets every
/// message from its join on, exactly once and in order, through its own
/// NAKs and the sender's repairs. Messages flow during the join: the
/// sender stops announcing after the first status message, so a
/// subscriber that missed the SETUP binds through the SOLICIT its unbound
/// DATA sends, and may join after the first messages. netem shapes the
/// loopback before the kernel copies a group datagram to each member, so
/// both subscribers meet the same losses.
#[test]
#[ignore = "runs under scripts/netem-test.sh"]
fn n6_a_reliable_multicast_group_delivers_exactly_once_to_each_subscriber() {
    super::super::netem::require_netem();
    let _route = MulticastOnLoopback::route();
    let group = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 0, 9)), free_port());
    let channel = UdpConfig {
        destination: Destination::Multicast { group, ttl: None },
        interface: None,
        paths: Vec::new(),
        reliable: true,
        flow_control: None,
        security: Security::Trusted,
    };
    let (mut a, mut b, mut c) = (
        driver(ThreadingMode::Shared),
        driver(ThreadingMode::Shared),
        driver(ThreadingMode::Shared),
    );
    for subscriber in [&mut b, &mut c] {
        let _ = subscriber.add_network_subscription(10, &channel).unwrap();
    }
    let publication = a
        .add_network_publication(aggregate(10, 3, 1), &channel)
        .unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let count = 1000u32;
    let mut sent = 0u32;
    let offer = |lane: &mut karyos_client::ClientPublication<_>, sent: &mut u32| {
        while *sent < count {
            let mut payload = [0u8; 1000];
            payload[..4].copy_from_slice(&sent.to_le_bytes());
            match lane.offer(&payload).unwrap() {
                OfferOutcome::Accepted { .. } => *sent += 1,
                _ => break,
            }
        }
    };
    // Publishing while both images come up.
    let mut images = (None, None);
    pump(&mut [&mut a, &mut b, &mut c], |drivers| {
        offer(&mut lane, &mut sent);
        images = (
            drivers[1].network_image(10, 3),
            drivers[2].network_image(10, 3),
        );
        images.0.is_some() && images.1.is_some()
    });
    let (Some(first), Some(second)) = images else {
        unreachable!("pumped until both exist");
    };
    let mut readers = [
        b.subscribe_aggregate(&first, Role::Required).unwrap(),
        c.subscribe_aggregate(&second, Role::Required).unwrap(),
    ];
    let mut seen: [Vec<u32>; 2] = [Vec::new(), Vec::new()];
    pump(&mut [&mut a, &mut b, &mut c], |_| {
        offer(&mut lane, &mut sent);
        for (reader, seen) in readers.iter_mut().zip(seen.iter_mut()) {
            let _ = reader.poll(
                |bytes, _, _| seen.push(u32::from_le_bytes(bytes[..4].try_into().unwrap())),
                BUDGET,
            );
        }
        seen.iter().all(|seen| seen.last() == Some(&(count - 1)))
    });
    // From each subscriber's first message on: every one, once, in order.
    for (subscriber, seen) in seen.iter().enumerate() {
        let from = seen[0];
        assert_eq!(
            seen,
            &(from..count).collect::<Vec<_>>(),
            "subscriber {subscriber}: not exactly once and in order from {from}"
        );
    }
    for reader in &mut readers {
        let poll = reader.poll(|_, _, _| {}, ONE);
        assert_eq!(poll.lanes[0].first_loss, None, "a reliable lane lost data");
    }
    let naks = [&b, &c].map(|driver| {
        driver
            .net
            .as_ref()
            .unwrap()
            .receiver_counters()
            .unwrap()
            .naks
    });
    let repairs = a.net.as_ref().unwrap().sender_counters().unwrap().repairs;
    let joins = seen.each_ref().map(|seen| seen[0]);
    println!(
        "N6: {count} offered, subscribers from {joins:?}, in order; NAKs {naks:?}, {repairs} repairs"
    );
    assert!(
        naks.iter().all(|naks| *naks > 0) && repairs > 0,
        "a subscriber never NAKed: the group is not on the shaped loopback?"
    );
}

/// N7 (T4): a reliable channel across a blackout of its tail. The first
/// 200 messages arrive; then the loopback loses every datagram for 500 ms
/// while the publisher offers its last 20, which fit the sender's window,
/// so the sender sends them all into the blackout and then has nothing
/// new to send. The tail is offered into the blackout so that only the
/// sender's idle DATA heartbeat (SPEC §6, at the default 100 ms) can
/// reveal it: with new DATA after the blackout, that DATA would show the
/// receiver the hole instead. Once the job's profile is back, the
/// receiver NAKs the tail the heartbeat shows and the sender repairs it:
/// every message arrives exactly once and in order, with no loss
/// reported. Without the heartbeat the tail never arrives.
#[test]
#[ignore = "runs under scripts/netem-test.sh"]
fn n7_a_reliable_channel_recovers_from_a_blackout() {
    super::super::netem::require_netem();
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let (publication, image) = connected(&mut a, &mut b, true, 10);
    let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    // 20 frames of 1056 bytes fit the 32 KiB window of a 64 KiB term.
    let (before, count) = (200u32, 220u32);
    let (mut sent, mut seen) = (0u32, 0u32);
    // Offers up to `upto` and reads what arrived: (sent, seen).
    let mut step = |upto: u32| {
        while sent < upto {
            let mut payload = [0u8; 1000];
            payload[..4].copy_from_slice(&sent.to_le_bytes());
            match lane.offer(&payload).unwrap() {
                OfferOutcome::Accepted { .. } => sent += 1,
                _ => break,
            }
        }
        let _ = reader.poll(
            |bytes, _, _| {
                let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                assert_eq!(index, seen, "exactly once, in order");
                seen += 1;
            },
            BUDGET,
        );
        (sent, seen)
    };
    pump(&mut [&mut a, &mut b], |_| step(before).1 == before);
    // Two more status messages from the receiver after it read the 200:
    // the later was sent after the reads, so the sender's window covers
    // the whole tail before the path goes dark.
    let status = |a: &EmbeddedDriver| {
        a.net
            .as_ref()
            .unwrap()
            .sender_counters()
            .unwrap()
            .sm_accepted
    };
    let read = status(&a);
    pump(&mut [&mut a, &mut b], |drivers| {
        status(drivers[0]) >= read + 2
    });
    let (naks_before, repairs_before) = repair_work(&a, &b);
    let blackout = Profile::replace("loss 100%");
    let start = Instant::now();
    let mut tail = (0, 0);
    pump(&mut [&mut a, &mut b], |_| {
        tail = step(count);
        start.elapsed() >= Duration::from_millis(500)
    });
    // The job's profile again.
    drop(blackout);
    let (offered, during) = tail;
    assert_eq!(offered, count, "the tail was offered during the blackout");
    pump(&mut [&mut a, &mut b], |_| step(count).1 == count);
    let poll = reader.poll(|_, _, _| {}, ONE);
    assert_eq!(poll.lanes[0].first_loss, None, "a reliable lane lost data");
    let (naks, repairs) = repair_work(&a, &b);
    let heartbeats = a
        .net
        .as_ref()
        .unwrap()
        .sender_counters()
        .unwrap()
        .heartbeats_sent;
    println!(
        "N7: {count} in order across a 500 ms blackout of the last {} (up to {during} by its end); {naks} NAKs, {repairs} repairs, {heartbeats} heartbeats",
        count - before
    );
    assert!(
        naks > naks_before && repairs > repairs_before && heartbeats > 0,
        "no repair after the blackout"
    );
}

/// N8 (network-shared-terms n4): N2 between two IPC drivers. The
/// publication's lanes and the image's are shared regions, so the
/// sender's staging and NAK reads and the receive owner's writes and
/// repairs run on shared terms; every message still arrives exactly once
/// and in order, and the faults did reach the path.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "runs under scripts/netem-test.sh"]
fn n8_a_reliable_channel_between_ipc_drivers_delivers_exactly_once_in_order() {
    super::super::netem::require_netem();
    let dirs = [ipc_dir("a"), ipc_dir("b")];
    let (mut a, mut b) = (ipc_driver(&dirs[0]), ipc_driver(&dirs[1]));
    let (publication, image) = connected(&mut a, &mut b, true, 10);
    let lane = image.lane(Lane::ZERO).unwrap();
    assert!(b.stream_ref(lane).unwrap().buffer.region().is_some());
    let lane = publication.lane(Lane::ZERO).unwrap();
    assert!(a.stream_ref(lane).unwrap().buffer.region().is_some());
    let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
    let count = 2000;
    exchange(&mut a, &mut b, &publication, &mut reader, count);
    let poll = reader.poll(|_, _, _| {}, ONE);
    assert_eq!(poll.lanes[0].first_loss, None, "a reliable lane lost data");
    let sender = a.net.as_ref().unwrap().sender_counters().unwrap();
    assert!(sender.naks >= 1 && sender.repairs >= 1, "{sender:?}");
    println!(
        "N8: {count} delivered in order exactly once between IPC drivers; {} NAKs, {} repairs",
        sender.naks, sender.repairs
    );
    drop(reader);
    let _ = (a.close_network(), b.close_network());
    drop((a, b));
    for dir in dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// A fresh directory for an IPC driver of this process.
#[cfg(target_os = "linux")]
fn ipc_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("karyos-n8-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// An IPC driver with a network, as [`driver`] in Shared mode.
#[cfg(target_os = "linux")]
fn ipc_driver(dir: &std::path::Path) -> EmbeddedDriver<karyos_sys::term_bytes::SharedTerms> {
    let timeout = 5_000_000_000;
    EmbeddedDriver::with_ipc(
        crate::embedded::DriverConfig {
            network: Some(crate::net::NetworkConfig {
                threading: ThreadingMode::Shared,
                ..crate::net::NetworkConfig::default()
            }),
            ..crate::embedded::DriverConfig::default()
        },
        crate::admission::IpcConfig {
            dir: dir.to_path_buf(),
            max_pending_hellos: 2,
            hello_timeout: timeout,
            max_outbound_per_client: 8,
            fetch_deadline: timeout,
            max_exports_per_client: 16,
            max_fetches_per_client: 4,
            max_regions_per_fetch: 4,
            max_fetch_bytes: 1 << 30,
            max_tools: crate::admission::DEFAULT_MAX_TOOLS,
        },
        Box::new(crate::clock::SystemClock::new()),
    )
    .unwrap()
}

/// N9 (M2b): under the job's faults the per-stream cells show the repair
/// work, in Shared and Dedicated mode alike (where N4 had no counters to
/// read): B's image counts losses and NAKs sent, A's publication counts
/// NAKs received and retransmits, while every message still arrives.
#[test]
#[ignore = "runs under scripts/netem-test.sh"]
fn n9_per_stream_cells_show_the_repair_work() {
    super::super::netem::require_netem();
    for threading in [ThreadingMode::Shared, ThreadingMode::Dedicated] {
        let (mut a, mut b) = (driver(threading), driver(threading));
        let (publication, image) = connected(&mut a, &mut b, true, 10);
        let (sent, seen) = (publication.registration(), image.registration());
        let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
        exchange(&mut a, &mut b, &publication, &mut reader, 2000);
        let value = |driver: &EmbeddedDriver, label: &str, stream: u64| {
            super::cells(driver, label)
                .into_iter()
                .find(|(_, keys)| keys.stream == stream)
                .map_or(0, |(value, _)| value)
        };
        // The agents store at the end of their cycles.
        pump(&mut [&mut a, &mut b], |drivers| {
            value(drivers[1], "network losses", seen) > 0
                && value(drivers[1], "network naks sent", seen) > 0
                && value(drivers[0], "network naks received", sent) > 0
                && value(drivers[0], "network retransmits", sent) > 0
        });
        println!(
            "N9 {threading:?}: losses {}, naks sent {}, repaired {}; naks received {}, \
             retransmits {}, frames sent {}",
            value(&b, "network losses", seen),
            value(&b, "network naks sent", seen),
            value(&b, "network repaired", seen),
            value(&a, "network naks received", sent),
            value(&a, "network retransmits", sent),
            value(&a, "network frames sent", sent),
        );
    }
}
