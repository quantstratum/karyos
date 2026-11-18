// SPDX-License-Identifier: Apache-2.0

//! The protection profile a configuration names
//! (`quantstratum-docs: karyos/design/measurement-harness.md` §5.2).
//!
//! - `trusted`, and `trusted-<label>` for another copy of it in an A/A
//!   plan: [`Trusted`].
//! - `synthetic-<spin_ns>`: `Synthetic`, which spins `spin_ns`
//!   nanoseconds in each of `seal` and `open` with no envelope. It checks
//!   the harness end to end and is never a candidate profile: it exists
//!   only in a build with the feature `synthetic`, whose every result is
//!   report-only ([`crate::wire::stage::BUILD`] says `+synthetic`).

#[cfg(feature = "synthetic")]
use karyos_protocol::protection::Synthetic;
use karyos_protocol::protection::{Protection, SealError, Trusted, Verdict};

use crate::workloads::BenchError;

/// The configuration name prefix of the synthetic test profile.
pub const SYNTHETIC: &str = "synthetic-";

/// The protection of one configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// The trusted channel.
    Trusted,
    /// The synthetic test profile (feature `synthetic`).
    #[cfg(feature = "synthetic")]
    Synthetic(Synthetic),
}

/// Whether `configuration` names the synthetic test profile.
#[must_use]
pub fn is_synthetic(configuration: &str) -> bool {
    configuration.starts_with(SYNTHETIC)
}

impl Profile {
    /// The profile `configuration` names.
    ///
    /// # Errors
    ///
    /// An unknown name, a malformed spin, or a synthetic configuration in
    /// a build without the feature `synthetic`.
    pub fn of(configuration: &str) -> Result<Self, BenchError> {
        if configuration == "trusted" || configuration.starts_with("trusted-") {
            return Ok(Self::Trusted);
        }
        let Some(spin) = configuration.strip_prefix(SYNTHETIC) else {
            return Err(BenchError(format!("unknown profile {configuration}")));
        };
        let spin_ns: u64 = spin
            .parse()
            .map_err(|_| BenchError(format!("bad synthetic spin in {configuration}")))?;
        #[cfg(feature = "synthetic")]
        {
            Ok(Self::Synthetic(Synthetic {
                spin_ns,
                envelope: 0,
            }))
        }
        #[cfg(not(feature = "synthetic"))]
        {
            Err(BenchError(format!(
                "{configuration} (spin {spin_ns} ns) needs the synthetic build"
            )))
        }
    }
}

impl Protection for Profile {
    fn envelope_len(&self) -> usize {
        match self {
            Self::Trusted => Trusted.envelope_len(),
            #[cfg(feature = "synthetic")]
            Self::Synthetic(synthetic) => synthetic.envelope_len(),
        }
    }

    fn seal(&self, datagram: &mut [u8], frames: usize) -> Result<usize, SealError> {
        match self {
            Self::Trusted => Trusted.seal(datagram, frames),
            #[cfg(feature = "synthetic")]
            Self::Synthetic(synthetic) => synthetic.seal(datagram, frames),
        }
    }

    fn open(&self, datagram: &[u8]) -> Verdict {
        match self {
            Self::Trusted => Trusted.open(datagram),
            #[cfg(feature = "synthetic")]
            Self::Synthetic(synthetic) => synthetic.open(datagram),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configurations_name_their_profiles() {
        assert_eq!(Profile::of("trusted").ok(), Some(Profile::Trusted));
        assert_eq!(Profile::of("trusted-b").ok(), Some(Profile::Trusted));
        assert!(Profile::of("aes").is_err());
        assert!(Profile::of("synthetic-x").is_err());
        assert!(is_synthetic("synthetic-500"));
        assert!(!is_synthetic("trusted"));
        #[cfg(feature = "synthetic")]
        assert_eq!(
            Profile::of("synthetic-500").ok(),
            Some(Profile::Synthetic(Synthetic {
                spin_ns: 500,
                envelope: 0
            }))
        );
    }

    /// No candidate of ADR-0086 is a configuration the harness can run
    /// in a build without candidate evaluation: the construction is
    /// selected only on E1 or E2 evidence (owner decision item 5), so no
    /// provisional profile is reachable (#632). The opt-in
    /// `auth-candidates` evaluation build is exempt, since ADR-0086 runs
    /// the candidates there to produce that evidence.
    #[cfg(not(feature = "auth-candidates"))]
    #[test]
    fn no_candidate_profile_is_reachable_before_selection() {
        for candidate in [
            "hmac-sha256-t16",
            "hmac-sha256-t32",
            "aes128-cmac",
            "ed25519",
            "authenticated",
        ] {
            assert!(Profile::of(candidate).is_err(), "{candidate} is reachable");
        }
    }
}
