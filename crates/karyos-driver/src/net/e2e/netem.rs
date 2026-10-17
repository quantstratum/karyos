// SPDX-License-Identifier: Apache-2.0

//! The driver's network fault tests (W6): two embedded drivers over the
//! loopback that `scripts/netem-test.sh` shapes with tc netem (loss,
//! reorder, delay, duplicate). Ignored in the normal suites; each refuses
//! to run outside the job (`net::netem`).
//!
//! - N1: an unreliable channel delivers each message at most once and in
//!   order, and reports every lost message as a local gap.
//! - N2 and N3 (reliable delivery exactly once and in order through
//!   repair, N3 with 5% duplicates) join once the sender's repair wiring
//!   is on main.

#![allow(
    clippy::print_stdout,
    reason = "the job's log records what the faults did (run with --nocapture)"
)]

use karyos_client::OfferOutcome;
use karyos_protocol::lanes::drr::Budget;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{Role, SkipReason};
use karyos_sys::sizing::MIN_TERM_LENGTH;

use super::{connected, driver, pump};
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
