// SPDX-License-Identifier: Apache-2.0

//! A consumer of the facade alone can name every claim and poll type.

use karyos::{Aborted, ClaimOutcome, ClientClaim, ClientPublication, CommitOutcome, PollSummary};

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
            | ClaimOutcome::Gated,
        )
        | Err(_) => None,
    }
}

#[test]
fn poll_and_abort_types_are_reachable() {
    let summary = PollSummary {
        aborted: Some(Aborted {
            position: 0,
            extent: 64,
        }),
        ..PollSummary::default()
    };
    assert_eq!(summary.aborted.map(|aborted| aborted.extent), Some(64));
}
