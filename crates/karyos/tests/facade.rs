// SPDX-License-Identifier: Apache-2.0

//! A consumer of the facade alone can name every claim and poll type,
//! every image change type, and implement `SnapshotSource` (karyos#777).

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

/// A snapshot source written against the facade alone: the trait, its
/// argument and its error are all `karyos::` paths (karyos#777).
struct Rebuilt {
    resumed_at: Option<u64>,
    fail: bool,
}

impl karyos::SnapshotSource for Rebuilt {
    fn rebuild(&mut self, overrun: &karyos::Overrun) -> Result<(), karyos::SnapshotFailed> {
        if self.fail {
            return Err(karyos::SnapshotFailed);
        }
        self.resumed_at = Some(overrun.resume);
        Ok(())
    }
}

#[test]
fn a_snapshot_source_is_implemented_through_the_facade() {
    let overrun = karyos::Overrun::new(10, 20, 24);
    let mut source = Rebuilt {
        resumed_at: None,
        fail: false,
    };
    assert_eq!(
        karyos::SnapshotSource::rebuild(&mut source, &overrun),
        Ok(())
    );
    assert_eq!(source.resumed_at, Some(24));
    let mut failing = Rebuilt {
        resumed_at: None,
        fail: true,
    };
    assert_eq!(
        karyos::SnapshotSource::rebuild(&mut failing, &overrun),
        Err(karyos::SnapshotFailed)
    );
    // It is what a subscription's rejoin policy takes.
    let _policy = karyos::RejoinPolicy::Snapshot(Box::new(source));
    // The budget's constructor, through the facade's name.
    let budget = karyos::ConflatedBudget::new(4, 1);
    assert_eq!((budget.keys, budget.retries), (4, 1));
}
