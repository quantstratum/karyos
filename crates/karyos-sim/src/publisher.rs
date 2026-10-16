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
    /// Back pressure, an admin action or no subscriber: nothing reserved.
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
                OfferOutcome::BackPressured
                | OfferOutcome::AdminAction
                | OfferOutcome::NotConnected => Attempt::Retry,
                // No guard in the simulator: a gate seal ends the publication.
                OfferOutcome::Closed | OfferOutcome::Gated => Attempt::Closed,
            },
        )
    }

    fn claim(&mut self, length: u32, key: i64) -> Result<Claimed<'_>, ClientError> {
        Ok(match self.try_claim_with(length, keyed(key))? {
            ClaimOutcome::Claimed(claim) => Claimed::Claim(Box::new(claim)),
            ClaimOutcome::Aborted { position, .. } => Claimed::Outcome(Attempt::Aborted(position)),
            ClaimOutcome::BackPressured
            | ClaimOutcome::AdminAction
            | ClaimOutcome::NotConnected => Claimed::Outcome(Attempt::Retry),
            ClaimOutcome::Closed | ClaimOutcome::Gated => Claimed::Outcome(Attempt::Closed),
        })
    }
}

impl SimPublisher for ClientConcurrentPublication {
    fn offer(&mut self, payload: &[u8], key: i64) -> Result<Attempt, ClientError> {
        Ok(
            match ClientConcurrentPublication::offer_with(self, payload, keyed(key))? {
                ConcurrentOfferOutcome::Accepted { position, .. } => Attempt::Accepted(position),
                ConcurrentOfferOutcome::Aborted { position, .. } => Attempt::Aborted(position),
                ConcurrentOfferOutcome::BackPressured
                | ConcurrentOfferOutcome::AdminAction
                | ConcurrentOfferOutcome::NotConnected => Attempt::Retry,
                ConcurrentOfferOutcome::Closed => Attempt::Closed,
            },
        )
    }

    fn claim(&mut self, length: u32, key: i64) -> Result<Claimed<'_>, ClientError> {
        Ok(match self.try_claim_with(length, keyed(key))? {
            ConcurrentClaimOutcome::Claimed(claim) => Claimed::Claim(Box::new(claim)),
            ConcurrentClaimOutcome::Aborted { position, .. } => {
                Claimed::Outcome(Attempt::Aborted(position))
            }
            ConcurrentClaimOutcome::BackPressured
            | ConcurrentClaimOutcome::AdminAction
            | ConcurrentClaimOutcome::NotConnected => Claimed::Outcome(Attempt::Retry),
            ConcurrentClaimOutcome::Closed => Claimed::Outcome(Attempt::Closed),
        })
    }
}
