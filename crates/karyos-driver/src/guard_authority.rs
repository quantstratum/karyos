// SPDX-License-Identifier: Apache-2.0

//! The guard authority's answer to a STATUS_CHALLENGE (`quantstratum-docs:
//! karyos/design/authenticated-control-schemas.md` sections 4.2 to 4.4,
//! `karyos/adr/0107-guard-recovery-and-renewal-on-the-wire.md`,
//! `karyos/adr/0086-wire-authentication-profile-v1.md` section 7; part of
//! quantstratum/karyos#648).
//!
//! A [`GuardAuthority`] owns guards whose words it reads, each with the
//! receivers it serves and their configured control endpoints. A bare
//! STATUS_CHALLENGE is answered with a GUARD STATUS signed in domain 2 over
//! the authority id, the guard, the challenger's boot id and receiver id,
//! its nonce and the guard's current word, sent only to the receiver's
//! configured endpoint. Before any signature: the challenge must name this
//! authority, a configured guard and one of its receivers, and come from
//! that receiver's configured address; then the per-driver budget (256
//! per second, at most 4 per duty cycle) and the per-destination budget
//! (4 per second, burst 4, one bucket per distinct endpoint, shared by
//! every guard naming it, preallocated at configuration). Anything else
//! is dropped and counted by reason. A challenge never changes authority
//! state. The configuration is refused at load beyond the capacity limits
//! of section 4.2.

use std::net::SocketAddr;
use std::sync::Arc;

use karyos_client::SharedWords;
use karyos_protocol::network::authenticated::{
    AuthControl, GuardStatus, GuardWord, decode_bare_status_challenge,
};
use karyos_protocol::protection::signed::{SignedBinding, SignedDomain, seal_signed};

use crate::authority::Ed25519Signer;
use crate::sessions::rate::normalized;
use crate::signed_control::Bucket;

/// STATUS answers per second per driver.
pub const DRIVER_STATUS_RATE: u32 = 256;
/// STATUS answers per duty cycle.
pub const STATUS_PER_CYCLE: u32 = 4;
/// STATUS answers per second, and burst, per receiver endpoint.
pub const ENDPOINT_STATUS_RATE: u32 = 4;
/// The lifetime range of a guard's `Open`, in milliseconds.
pub const LIFETIME_MS: core::ops::RangeInclusive<u32> = 1..=3_600_000;

/// One guard the authority owns.
#[derive(Debug, Clone)]
pub struct AuthorityGuard {
    /// The guard id, at least 1.
    pub guard_id: u64,
    /// The guard's word at word 0, read for each answer.
    pub word: Arc<dyn SharedWords>,
    /// The lifetime its receivers keep an `Open` for, in milliseconds.
    pub lifetime_ms: u32,
    /// The receivers it serves, each with its configured control endpoint.
    pub receivers: Vec<(u64, SocketAddr)>,
}

/// Why an authority's configuration is refused at load.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityConfigError {
    /// An id of 0, a lifetime out of range, or a guard or receiver named
    /// twice.
    #[error("invalid guard authority configuration")]
    Invalid,
    /// More receiver-guard confirmations than the per-driver budget's half
    /// (`64 × lifetime_s`, design section 4.2).
    #[error("the authority serves more receivers than its status budget allows")]
    AuthorityCapacity,
    /// A receiver endpoint needing more than half its budget (the sum of
    /// `2 / lifetime_s` over its guards above 2).
    #[error("a receiver endpoint is named by more guards than its status budget allows")]
    EndpointCapacity,
}

/// Why a challenge got no answer; one counter each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum ChallengeRefusal {
    /// Not a STATUS_CHALLENGE, or it does not decode.
    Malformed = 0,
    /// Another authority.
    WrongAuthority,
    /// No guard of that id.
    UnknownGuard,
    /// The guard does not list that receiver.
    UnknownReceiver,
    /// Not from the receiver's configured address.
    SourceMismatch,
    /// The duty cycle's or the driver's budget.
    DriverBudget,
    /// The receiver endpoint's budget.
    DestinationBudget,
    /// The guard word is corrupt: no state to report.
    CorruptWord,
    /// Signing failed, or the sequence is exhausted.
    Sign,
}

/// Refusal reasons.
pub const CHALLENGE_REFUSALS: usize = ChallengeRefusal::Sign as usize + 1;

/// A signed STATUS and where it goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Answer {
    /// The receiver's configured endpoint.
    pub destination: SocketAddr,
    /// The datagram length in `bytes`.
    pub len: usize,
    /// The datagram.
    pub bytes: [u8; 256],
}

impl Answer {
    /// The datagram.
    #[must_use]
    pub fn datagram(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or(&[])
    }
}

/// A guard authority: its signing key and guards, and the status budget.
pub struct GuardAuthority {
    authority_id: u64,
    key_id: u32,
    signer: Ed25519Signer,
    seq: u64,
    guards: Vec<AuthorityGuard>,
    cycle_left: u32,
    driver: Bucket,
    /// One bucket per distinct configured endpoint.
    endpoints: Vec<(SocketAddr, Bucket)>,
    refusals: [u64; CHALLENGE_REFUSALS],
    /// STATUS answers signed.
    pub answered: u64,
}

impl core::fmt::Debug for GuardAuthority {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GuardAuthority")
            .field("authority_id", &self.authority_id)
            .field("key_id", &self.key_id)
            .field("guards", &self.guards.len())
            .finish_non_exhaustive()
    }
}

impl GuardAuthority {
    /// The authority `authority_id` signing with `signer` under `key_id`,
    /// owning `guards`; its budgets full at `now` and allocated now.
    ///
    /// # Errors
    ///
    /// [`AuthorityConfigError`] for an invalid configuration or one beyond
    /// a capacity limit.
    pub fn new(
        authority_id: u64,
        key_id: u32,
        signer: Ed25519Signer,
        guards: Vec<AuthorityGuard>,
        now: u64,
    ) -> Result<Self, AuthorityConfigError> {
        check(authority_id, &guards)?;
        let mut endpoints: Vec<(SocketAddr, Bucket)> = Vec::new();
        for guard in &guards {
            for (_, endpoint) in &guard.receivers {
                let endpoint = normalized(*endpoint);
                if !endpoints.iter().any(|(held, _)| *held == endpoint) {
                    endpoints.push((
                        endpoint,
                        Bucket::full(ENDPOINT_STATUS_RATE, ENDPOINT_STATUS_RATE, now),
                    ));
                }
            }
        }
        Ok(Self {
            authority_id,
            key_id,
            signer,
            seq: 0,
            guards,
            cycle_left: STATUS_PER_CYCLE,
            driver: Bucket::full(DRIVER_STATUS_RATE, DRIVER_STATUS_RATE, now),
            endpoints,
            refusals: [0; CHALLENGE_REFUSALS],
            answered: 0,
        })
    }

    /// A new duty cycle.
    pub fn new_cycle(&mut self) {
        self.cycle_left = STATUS_PER_CYCLE;
    }

    /// The refusals for `reason`.
    #[must_use]
    pub fn refusals(&self, reason: ChallengeRefusal) -> u64 {
        self.refusals.get(reason as usize).copied().unwrap_or(0)
    }

    /// Answers the bare datagram `bytes` from `source` at `now`, if it is a
    /// STATUS_CHALLENGE this authority answers. Changes no guard and no
    /// authority state but the budgets. Allocates nothing.
    ///
    /// # Errors
    ///
    /// The [`ChallengeRefusal`], counted.
    pub fn answer(
        &mut self,
        bytes: &[u8],
        source: SocketAddr,
        now: u64,
    ) -> Result<Answer, ChallengeRefusal> {
        let result = self.answer_uncounted(bytes, source, now);
        if let Err(reason) = result
            && let Some(count) = self.refusals.get_mut(reason as usize)
        {
            *count = count.saturating_add(1);
        }
        result
    }

    fn answer_uncounted(
        &mut self,
        bytes: &[u8],
        source: SocketAddr,
        now: u64,
    ) -> Result<Answer, ChallengeRefusal> {
        let challenge =
            decode_bare_status_challenge(bytes).map_err(|_| ChallengeRefusal::Malformed)?;
        if challenge.authority_id != self.authority_id {
            return Err(ChallengeRefusal::WrongAuthority);
        }
        let guard = self
            .guards
            .iter()
            .find(|guard| guard.guard_id == challenge.guard_id)
            .ok_or(ChallengeRefusal::UnknownGuard)?;
        let destination = guard
            .receivers
            .iter()
            .find(|(receiver_id, _)| *receiver_id == challenge.receiver.receiver_id)
            .map(|(_, endpoint)| normalized(*endpoint))
            .ok_or(ChallengeRefusal::UnknownReceiver)?;
        // Charged to the receiver's bucket only from its own address.
        if normalized(source) != destination {
            return Err(ChallengeRefusal::SourceMismatch);
        }
        let word = karyos_sys::guard::load_in(&*guard.word, 0)
            .ok()
            .and_then(karyos_sys::guard::encode)
            .and_then(|raw| GuardWord::from_raw(raw).ok());
        if self.cycle_left == 0 || !self.driver.has(now) {
            return Err(ChallengeRefusal::DriverBudget);
        }
        let bucket = self
            .endpoints
            .iter_mut()
            .find(|(held, _)| *held == destination)
            .map(|(_, bucket)| bucket)
            .ok_or(ChallengeRefusal::UnknownReceiver)?;
        if !bucket.has(now) {
            return Err(ChallengeRefusal::DestinationBudget);
        }
        let word = word.ok_or(ChallengeRefusal::CorruptWord)?;
        bucket.take();
        self.driver.take();
        self.cycle_left -= 1;
        let status = AuthControl::Status(GuardStatus {
            authority_id: self.authority_id,
            guard_id: challenge.guard_id,
            receiver: challenge.receiver,
            nonce: challenge.nonce,
            word,
        });
        let mut answer = Answer {
            destination,
            len: 0,
            bytes: [0; 256],
        };
        let body = status
            .encode(&mut answer.bytes)
            .map_err(|_| ChallengeRefusal::Sign)?;
        let binding = SignedBinding {
            domain: SignedDomain::Guard,
            party_epoch: 0,
            session_id: 0,
            stream_id: 0,
            key_id: self.key_id,
        };
        answer.len = seal_signed(&mut answer.bytes, body, &binding, self.seq, &self.signer)
            .map_err(|_| ChallengeRefusal::Sign)?;
        self.seq = self.seq.checked_add(1).ok_or(ChallengeRefusal::Sign)?;
        self.answered = self.answered.saturating_add(1);
        Ok(answer)
    }
}

/// The load checks of design section 4.2.
fn check(authority_id: u64, guards: &[AuthorityGuard]) -> Result<(), AuthorityConfigError> {
    if authority_id == 0 {
        return Err(AuthorityConfigError::Invalid);
    }
    // In millionths: the sum of receivers / lifetime_s must stay within
    // 64; per endpoint the sum of 2 / lifetime_s within 2.
    let mut authority: u128 = 0;
    for (index, guard) in guards.iter().enumerate() {
        let duplicate = guards
            .get(..index)
            .is_some_and(|before| before.iter().any(|held| held.guard_id == guard.guard_id));
        if guard.guard_id == 0 || !LIFETIME_MS.contains(&guard.lifetime_ms) || duplicate {
            return Err(AuthorityConfigError::Invalid);
        }
        for (at, (receiver_id, _)) in guard.receivers.iter().enumerate() {
            let twice = guard
                .receivers
                .get(..at)
                .is_some_and(|before| before.iter().any(|(held, _)| held == receiver_id));
            if *receiver_id == 0 || twice {
                return Err(AuthorityConfigError::Invalid);
            }
        }
        let receivers = u128::try_from(guard.receivers.len()).unwrap_or(u128::MAX);
        authority = authority.saturating_add(
            receivers.saturating_mul(1_000_000_000) / u128::from(guard.lifetime_ms),
        );
    }
    if authority > 64 * 1_000_000 {
        return Err(AuthorityConfigError::AuthorityCapacity);
    }
    for guard in guards {
        for (_, endpoint) in &guard.receivers {
            let endpoint = normalized(*endpoint);
            let load: u128 = guards
                .iter()
                .filter(|held| {
                    held.receivers
                        .iter()
                        .any(|(_, other)| normalized(*other) == endpoint)
                })
                .map(|held| 2_000_000_000 / u128::from(held.lifetime_ms))
                .sum();
            if load > 2 * 1_000_000 {
                return Err(AuthorityConfigError::EndpointCapacity);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
