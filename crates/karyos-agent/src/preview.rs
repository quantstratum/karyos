// SPDX-License-Identifier: Apache-2.0

//! Preview calls and caller-chosen operation ids (R-CORE-18, karyos#738;
//! quantstratum-docs: karyos/design/product-requirements-on-core.md).
//!
//! - **Preview.** `guard-close-preview DIR GUARD [REASON]` and
//!   `guard-reopen-preview DIR GUARD [REASON]` answer what the operation
//!   would do: the guard's state as the agent last saw it in the driver's
//!   guard audit, the epoch after, and a token. A field the agent cannot
//!   read is answered `"unavailable"`, never as a zero or a false
//!   (RR-CON-0008): a guard with no transition in the audit records the
//!   agent follows has no known state, and then no token either.
//! - **The token** is 128 random bits naming a preview the agent keeps in
//!   memory: the principal (the requester and the relay that carried it),
//!   the target (the driver's directory and instance, and the guard), the
//!   parameters (the operation, the epoch it acts at and the reason), and
//!   its expiry, [`PREVIEW_TTL`] after the preview. At most
//!   [`MAX_PREVIEWS`] are kept; past that the oldest is dropped.
//! - **Submit.** `submit OPID TOKEN guard-close|guard-reopen DIR GUARD
//!   [REASON]` performs exactly the previewed operation under the caller's
//!   operation id `OPID`. It is refused, with nothing sent, when the token
//!   is unknown, used or expired, or when its principal, its target or
//!   its parameters differ from the preview's, or when the driver is a new
//!   instance since. The epoch is checked by the driver itself, atomically
//!   with the transition (`GuardCloseAt` and `GuardReopen`): a guard that
//!   moved since the preview is refused there (`GuardNotOpenAt`,
//!   `GuardNotClosedAt`) and audited. A token is used up by the submit that
//!   sends it, whatever its outcome.
//! - **The operation id.** A submit journals and audits its request and
//!   outcome under `OPID`, as one operation: the preview itself leaves no
//!   record. An id this agent already used in this run is refused
//!   (`operation id reused`).

use std::path::PathBuf;
use std::time::{Duration, Instant};

use karyos_sys::guard::GuardState;

use crate::agent::Requester;

/// How long a preview's token stays valid.
pub const PREVIEW_TTL: Duration = Duration::from_secs(60);

/// The previews the agent keeps at most.
pub const MAX_PREVIEWS: usize = 256;

/// The guard operation a preview is of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PreviewKind {
    /// `guard-close`.
    Close,
    /// `guard-reopen`.
    Reopen,
}

impl PreviewKind {
    /// Its request name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Close => "guard-close",
            Self::Reopen => "guard-reopen",
        }
    }
}

/// A preview's token: 128 random bits, written as 32 hex digits.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Token([u8; 16]);

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Token(..)")
    }
}

impl Token {
    /// A fresh token from the operating system's random source; `None`
    /// when it cannot be read.
    fn fresh() -> Option<Self> {
        use std::io::Read as _;
        let mut bytes = [0u8; 16];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut random| random.read_exact(&mut bytes))
            .ok()?;
        Some(Self(bytes))
    }

    /// The token written as `hex`, if it is 32 hex digits.
    #[must_use]
    pub fn parse(hex: &str) -> Option<Self> {
        if hex.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let digits = hex.get(index * 2..index * 2 + 2)?;
            *byte = u8::from_str_radix(digits, 16).ok()?;
        }
        Some(Self(bytes))
    }

    /// Its 32 hex digits.
    #[must_use]
    pub fn hex(&self) -> String {
        use std::fmt::Write as _;
        let mut text = String::with_capacity(32);
        for byte in self.0 {
            let _ = write!(text, "{byte:02x}");
        }
        text
    }
}

/// What a preview binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Bound {
    pub(crate) kind: PreviewKind,
    pub(crate) dir: PathBuf,
    pub(crate) guard: u64,
    pub(crate) requester: Requester,
    pub(crate) reason: Vec<u8>,
}

/// A kept preview.
#[derive(Debug, Clone)]
struct Kept {
    token: Token,
    bound: Bound,
    /// The driver instance it was taken of.
    instance: u128,
    /// The epoch the operation acts at: the open epoch a close replaces,
    /// or the closed one a reopen does.
    epoch: u64,
    expires: Instant,
}

/// What the agent saw of the guard for a preview.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Seen {
    pub(crate) instance: u128,
    /// The guard's state from the latest transition the agent followed in
    /// its audit; `None` when it has none.
    pub(crate) state: Option<GuardState>,
}

/// A preview's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PreviewAnswer {
    /// What the operation would do. `state` and `token` are `None` when
    /// unavailable; `epoch_after` is `None` when there is no change to
    /// make or the state is unavailable.
    Previewed {
        /// The operation.
        kind: PreviewKind,
        /// The guard.
        guard: u64,
        /// The driver instance.
        instance: u128,
        /// The guard's state as last seen.
        state: Option<GuardState>,
        /// The epoch after the operation.
        epoch_after: Option<u64>,
        /// The token a submit names, when there is a change to make.
        token: Option<Token>,
    },
    /// The directory is not one of the agent's drivers.
    UnknownDriver,
    /// The agent is not attached to that driver.
    Unattached,
}

/// Why a submit was refused; nothing was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SubmitRefusal {
    /// No preview has this token: never issued, already used, or dropped.
    TokenUnknown,
    /// The preview expired.
    TokenExpired,
    /// Another principal previewed it.
    PrincipalMismatch,
    /// It was previewed for another operation, driver or guard.
    TargetMismatch,
    /// It was previewed with another reason.
    ParametersMismatch,
    /// The driver is a new instance since the preview.
    TargetChanged,
    /// The operation id was already used in this run, or is 0.
    OperationReused,
}

impl SubmitRefusal {
    /// Its error text.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::TokenUnknown => "token unknown",
            Self::TokenExpired => "token expired",
            Self::PrincipalMismatch => "principal mismatch",
            Self::TargetMismatch => "target mismatch",
            Self::ParametersMismatch => "parameters mismatch",
            Self::TargetChanged => "target changed",
            Self::OperationReused => "operation id reused",
        }
    }
}

/// The previews the agent keeps.
#[derive(Debug, Default)]
pub(crate) struct Previews {
    kept: Vec<Kept>,
}

impl Previews {
    /// Answers a preview of `bound` over what the agent `seen`, at `now`,
    /// keeping a token when there is a change to make.
    pub(crate) fn preview(&mut self, bound: Bound, seen: Seen, now: Instant) -> PreviewAnswer {
        self.expire(now);
        let (kind, guard) = (bound.kind, bound.guard);
        let change = seen.state.and_then(|state| match (kind, state.open) {
            (PreviewKind::Close, true) | (PreviewKind::Reopen, false) => {
                // Never past the guard's last epoch: a reopen there is
                // exhausted, so there is nothing to preview a token for.
                state
                    .epoch
                    .checked_add(1)
                    .filter(|after| *after <= karyos_sys::guard::MAX_EPOCH)
                    .map(|after| (state.epoch, after))
            }
            _ => None,
        });
        let token = change.and_then(|(epoch, _)| {
            let token = Token::fresh()?;
            if self.kept.len() >= MAX_PREVIEWS {
                let _ = self.kept.remove(0);
            }
            self.kept.push(Kept {
                token,
                bound,
                instance: seen.instance,
                epoch,
                expires: now + PREVIEW_TTL,
            });
            Some(token)
        });
        PreviewAnswer::Previewed {
            kind,
            guard,
            instance: seen.instance,
            state: seen.state,
            epoch_after: change.map(|(_, after)| after),
            token,
        }
    }

    /// The epoch to act at for a submit of `bound` with `token`, against
    /// the driver's current `instance`, at `now`; the preview is used up
    /// when it matches.
    ///
    /// # Errors
    ///
    /// The [`SubmitRefusal`] that names the first mismatch; a mismatched
    /// preview is kept for its own principal.
    pub(crate) fn take(
        &mut self,
        token: Token,
        bound: &Bound,
        instance: Option<u128>,
        now: Instant,
    ) -> Result<u64, SubmitRefusal> {
        let index = self
            .kept
            .iter()
            .position(|kept| kept.token == token)
            .ok_or(SubmitRefusal::TokenUnknown)?;
        let kept = self.kept.get(index).ok_or(SubmitRefusal::TokenUnknown)?;
        if now >= kept.expires {
            let _ = self.kept.remove(index);
            return Err(SubmitRefusal::TokenExpired);
        }
        let previewed = &kept.bound;
        if previewed.requester != bound.requester {
            return Err(SubmitRefusal::PrincipalMismatch);
        }
        if previewed.kind != bound.kind
            || previewed.dir != bound.dir
            || previewed.guard != bound.guard
        {
            return Err(SubmitRefusal::TargetMismatch);
        }
        if previewed.reason != bound.reason {
            return Err(SubmitRefusal::ParametersMismatch);
        }
        let epoch = kept.epoch;
        let changed = instance != Some(kept.instance);
        let _ = self.kept.remove(index);
        if changed {
            return Err(SubmitRefusal::TargetChanged);
        }
        Ok(epoch)
    }

    /// Drops the previews expired at `now`.
    fn expire(&mut self, now: Instant) {
        self.kept.retain(|kept| now < kept.expires);
    }
}

/// The state of `guard` from the newest record in `audit` that carries
/// its word, if any: every record of a known guard carries the word after
/// it (a refusal, the unchanged one); an unknown guard's carries 0.
pub(crate) fn last_state(audit: &[crate::api::GuardEntry], guard: u64) -> Option<GuardState> {
    audit
        .iter()
        .rev()
        .filter(|entry| entry.guard == guard && entry.after != 0)
        .find_map(|entry| karyos_sys::guard::decode(entry.after).ok())
}

#[cfg(test)]
mod tests;
