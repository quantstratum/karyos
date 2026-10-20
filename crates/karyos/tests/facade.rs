// SPDX-License-Identifier: Apache-2.0

//! A consumer of the facade alone can name every claim and poll type, and
//! every image change type.

use karyos::embedded::{Aborted, ClaimOutcome, ClientClaim, ClientPublication, CommitOutcome};
use karyos::{ImageChange, ImageEnd, Lane, PollSummary, SealReason};

/// Uses each type by name; compiling is the test.
#[allow(dead_code)]
fn claim_through_the_facade(publication: &mut ClientPublication) -> Option<CommitOutcome> {
    match publication.try_claim(8) {
        Ok(ClaimOutcome::Claimed(mut claim)) => {
            let claim: &mut ClientClaim<'_> = &mut claim;
            claim.payload().fill(1);
            None
        }
        Ok(
            ClaimOutcome::BackPressured
            | ClaimOutcome::AdminAction
            | ClaimOutcome::NotConnected
            | ClaimOutcome::Aborted { .. }
            | ClaimOutcome::Closed
            | ClaimOutcome::Gated
            | ClaimOutcome::RateLimited,
        )
        | Err(_) => None,
        // Later outcomes: the enum is non-exhaustive.
        Ok(_) => None,
    }
}

#[test]
fn poll_and_abort_types_are_reachable() {
    let summary = {
        let mut value = PollSummary::default();
        value.aborted = Some(Aborted::new(0, 64));
        value
    };
    assert_eq!(summary.aborted.map(|aborted| aborted.extent), Some(64));
}

/// Drains image changes, as `Subscription::next_image_change` gives
/// them, by name; compiling is the test.
#[allow(dead_code)]
fn retired_ends_through_the_facade(
    mut next: impl FnMut() -> Option<ImageChange>,
) -> Vec<(u64, Option<u64>)> {
    let mut ends = Vec::new();
    while let Some(change) = next() {
        if let Some(ImageEnd {
            reason: SealReason::EndOfStream | SealReason::ImageRetired,
            position,
            ..
        }) = change.end
        {
            ends.push((change.image_id, position));
        }
    }
    ends
}

#[test]
fn image_change_types_are_reachable() {
    let end = ImageEnd::new(SealReason::EndOfStream, Some(64));
    let change = ImageChange::new(1, 2, Lane::ZERO, false).with_end(Some(end));
    assert_eq!(
        change.end.map(|end| (end.reason, end.position)),
        Some((SealReason::EndOfStream, Some(64)))
    );
}
