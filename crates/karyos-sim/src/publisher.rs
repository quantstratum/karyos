// SPDX-License-Identifier: Apache-2.0

//! One interface over the exclusive and the concurrent client publication,
//! so that the scheduler drives both with the same script.

use karyos_sys::log_buffer::AppendOptions;

use karyos_client::{
    ClaimOutcome, ClientClaim, ClientConcurrentClaim, ClientConcurrentPublication, ClientError,
    ClientPublication, CommitOutcome, ConcurrentClaimOutcome, ConcurrentOfferOutcome, OfferOutcome,
};

/// The outcome of an attempt, as the oracle needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attempt {
    /// Accepted at a stream position.
    Accepted(u64),
    /// The block at a stream position will never carry the message.
    Aborted(u64),
    /// Back pressure, an admin action, no subscriber or a rate limit:
    /// nothing reserved.
    Retry,
    /// The publication is closed.
    Closed,
}

/// A claim held by the script.
pub trait SimClaim {
    /// The block's stream position.
    fn position(&self) -> u64;
    /// The payload to fill.
    fn payload(&mut self) -> &mut [u8];
    /// Commits the block.
    fn commit(self: Box<Self>) -> Attempt;
    /// Aborts the block.
    fn abort(self: Box<Self>);
}

/// A claim attempt.
pub enum Claimed<'a> {
    /// A claim to fill and resolve.
    Claim(Box<dyn SimClaim + 'a>),
    /// No claim.
    Outcome(Attempt),
}

/// A publication of either mode.
pub trait SimPublisher {
    /// Offers one message with `key` as its reserved value (the key of a
    /// conflated stream).
    ///
    /// # Errors
    ///
    /// As the client publication.
    fn offer(&mut self, payload: &[u8], key: i64) -> Result<Attempt, ClientError>;
    /// Claims `length` bytes with `key` as the reserved value.
    ///
    /// # Errors
    ///
    /// As the client publication.
    fn claim(&mut self, length: u32, key: i64) -> Result<Claimed<'_>, ClientError>;
}

/// Append options carrying `key` as the reserved value.
fn keyed(key: i64) -> AppendOptions {
    AppendOptions {
        reserved_value: key,
        ..AppendOptions::default()
    }
}

fn committed(outcome: CommitOutcome) -> Attempt {
    match outcome {
        CommitOutcome::Accepted { position, .. } => Attempt::Accepted(position),
        CommitOutcome::Aborted { position, .. } => Attempt::Aborted(position),
    }
}

impl SimClaim for ClientClaim<'_> {
    fn position(&self) -> u64 {
        ClientClaim::position(self)
    }
    fn payload(&mut self) -> &mut [u8] {
        ClientClaim::payload(self)
    }
    fn commit(self: Box<Self>) -> Attempt {
        committed(ClientClaim::commit(*self))
    }
    fn abort(self: Box<Self>) {
        ClientClaim::abort(*self);
    }
}

impl SimClaim for ClientConcurrentClaim<'_> {
    fn position(&self) -> u64 {
        ClientConcurrentClaim::position(self)
    }
    fn payload(&mut self) -> &mut [u8] {
        ClientConcurrentClaim::payload(self)
    }
    fn commit(self: Box<Self>) -> Attempt {
        committed(ClientConcurrentClaim::commit(*self))
    }
    fn abort(self: Box<Self>) {
        ClientConcurrentClaim::abort(*self);
    }
}

impl SimPublisher for ClientPublication {
    fn offer(&mut self, payload: &[u8], key: i64) -> Result<Attempt, ClientError> {
        Ok(
            match ClientPublication::offer_with(self, payload, keyed(key))? {
                OfferOutcome::Accepted { position, .. } => Attempt::Accepted(position),
                // No rate limit in the simulator either; a refusal retries.
                OfferOutcome::BackPressured
                | OfferOutcome::AdminAction
                | OfferOutcome::NotConnected
                | OfferOutcome::RateLimited => Attempt::Retry,
                // No guard in the simulator: a gate seal ends the publication.
                OfferOutcome::Closed | OfferOutcome::Gated => Attempt::Closed,
                // A later outcome the simulator does not know: it stops.
                _ => Attempt::Closed,
            },
        )
    }

    fn claim(&mut self, length: u32, key: i64) -> Result<Claimed<'_>, ClientError> {
        Ok(match self.try_claim_with(length, keyed(key))? {
            ClaimOutcome::Claimed(claim) => Claimed::Claim(Box::new(claim)),
            ClaimOutcome::Aborted { position, .. } => Claimed::Outcome(Attempt::Aborted(position)),
            ClaimOutcome::BackPressured
            | ClaimOutcome::AdminAction
            | ClaimOutcome::NotConnected
            | ClaimOutcome::RateLimited => Claimed::Outcome(Attempt::Retry),
            ClaimOutcome::Closed | ClaimOutcome::Gated => Claimed::Outcome(Attempt::Closed),
            // A later outcome the simulator does not know: it stops.
            _ => Claimed::Outcome(Attempt::Closed),
        })
    }
}

impl SimPublisher for ClientConcurrentPublication {
    fn offer(&mut self, payload: &[u8], key: i64) -> Result<Attempt, ClientError> {
        Ok(concurrent_offered(ClientConcurrentPublication::offer_with(
            self,
            payload,
            keyed(key),
        )?))
    }

    fn claim(&mut self, length: u32, key: i64) -> Result<Claimed<'_>, ClientError> {
        Ok(match self.try_claim_with(length, keyed(key))? {
            ConcurrentClaimOutcome::Claimed(claim) => Claimed::Claim(Box::new(claim)),
            other => Claimed::Outcome(concurrent_refused(&other)),
        })
    }
}

/// The attempt of a concurrent offer's outcome. A guarded handle's rate
/// copy refuses for now only (`RateLimited`): it retries, as the exclusive
/// adapter does; a gate seal ends the publication.
fn concurrent_offered(outcome: ConcurrentOfferOutcome) -> Attempt {
    match outcome {
        ConcurrentOfferOutcome::Accepted { position, .. } => Attempt::Accepted(position),
        ConcurrentOfferOutcome::Aborted { position, .. } => Attempt::Aborted(position),
        ConcurrentOfferOutcome::BackPressured
        | ConcurrentOfferOutcome::AdminAction
        | ConcurrentOfferOutcome::NotConnected
        | ConcurrentOfferOutcome::RateLimited => Attempt::Retry,
        ConcurrentOfferOutcome::Closed | ConcurrentOfferOutcome::Gated => Attempt::Closed,
        // A later outcome the simulator does not know: it stops.
        _ => Attempt::Closed,
    }
}

/// The attempt of a concurrent claim that claimed nothing, as
/// [`concurrent_offered`].
fn concurrent_refused<T: karyos_sys::term_bytes::TermBytes>(
    outcome: &ConcurrentClaimOutcome<'_, T>,
) -> Attempt {
    match outcome {
        ConcurrentClaimOutcome::Aborted { position, .. } => Attempt::Aborted(*position),
        ConcurrentClaimOutcome::BackPressured
        | ConcurrentClaimOutcome::AdminAction
        | ConcurrentClaimOutcome::NotConnected
        | ConcurrentClaimOutcome::RateLimited => Attempt::Retry,
        // A gate seal, a claim handled by the caller, or a later outcome
        // the simulator does not know: it stops.
        _ => Attempt::Closed,
    }
}

#[cfg(test)]
mod concurrent_tests {
    use super::*;

    /// Review of #1153: a guarded concurrent handle's `RateLimited`
    /// retries, offer and claim; `Gated` ends the publication.
    #[test]
    fn a_rate_limited_concurrent_attempt_retries() {
        assert_eq!(
            concurrent_offered(ConcurrentOfferOutcome::RateLimited),
            Attempt::Retry
        );
        assert_eq!(
            concurrent_offered(ConcurrentOfferOutcome::Gated),
            Attempt::Closed
        );
        let limited: ConcurrentClaimOutcome<'_> = ConcurrentClaimOutcome::RateLimited;
        assert_eq!(concurrent_refused(&limited), Attempt::Retry);
        let gated: ConcurrentClaimOutcome<'_> = ConcurrentClaimOutcome::Gated;
        assert_eq!(concurrent_refused(&gated), Attempt::Closed);
    }
}
