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

#![allow(
    clippy::print_stdout,
    reason = "the job's log records what the faults did (run with --nocapture)"
)]

use karyos_client::OfferOutcome;
use karyos_protocol::lanes::drr::Budget;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{Role, SkipReason};
use karyos_sys::sizing::MIN_TERM_LENGTH;

use super::{connected, driver, exchange, pump};
use crate::agents::ThreadingMode;

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
/// cost.
fn reliable_delivery(label: &str, count: u32) {
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
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
}

/// N2: over loss, reordering and duplication a reliable channel delivers
/// every message exactly once and in order: the receiver NAKs each hole
/// and the sender's repair path resends it.
#[test]
#[ignore = "runs under scripts/netem-test.sh"]
fn n2_a_reliable_channel_delivers_exactly_once_in_order() {
    super::super::netem::require_netem();
    reliable_delivery("N2", 2000);
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
/// together still deliver every message exactly once and in order.
#[test]
#[ignore = "runs under scripts/netem-test.sh"]
fn n3_a_reliable_channel_survives_five_percent_duplicates() {
    super::super::netem::require_netem();
    let _profile = Profile::duplicate(5);
    reliable_delivery("N3", 2000);
}
