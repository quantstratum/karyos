// SPDX-License-Identifier: Apache-2.0

//! The protection profile a configuration names
//! (`quantstratum-docs: karyos/design/measurement-harness.md` §5.2).
//!
//! - `trusted`, and `trusted-<label>` for another copy of it in an A/A
//!   plan: [`Trusted`].
//! - `encrypted`: AES-256-GCM-SIV (ADR-0114), domain 1 DATA under the
//!   measured establishment's key ([`crate::enc_cost::data_key`]). Send is
//!   `seal_next`; receive is the verify and decrypt (`open_into`, into a
//!   scratch buffer) and the replay decision (`mark`), the complete receive
//!   processing of manifest 6.2 (karyos#650).
//! - `synthetic-<spin_ns>`: `Synthetic`, which spins `spin_ns`
//!   nanoseconds in each of `seal` and `open` with no envelope. It checks
//!   the harness end to end and is never a candidate profile: it exists
//!   only in a build with the feature `synthetic`, whose every result is
//!   report-only ([`crate::wire::stage::BUILD`] says `+synthetic`).

#[cfg(feature = "synthetic")]
use karyos_protocol::protection::Synthetic;
use karyos_protocol::protection::aes_gcm_siv::MAX_PLAINTEXT;
use karyos_protocol::protection::{AesGcmSiv, Protection, SealError, Trusted, Verdict};

use crate::workloads::BenchError;

/// The configuration name prefix of the synthetic test profile.
pub const SYNTHETIC: &str = "synthetic-";

/// A protection as the wire harness's receiver opens it (karyos#650): the
/// accepted inner frames, read in place for a profile that leaves them in
/// the datagram, or from `scratch`, which a decrypting profile fills.
pub trait WireOpen: Protection {
    /// The accepted inner frames of `datagram`.
    ///
    /// # Errors
    ///
    /// The protection's refusal, described.
    fn open_frames<'a>(
        &self,
        datagram: &'a [u8],
        scratch: &'a mut [u8],
    ) -> Result<&'a [u8], String> {
        let _ = scratch;
        match self.open(datagram) {
            Verdict::Accept { start, frames } => datagram
                .get(start..start.saturating_add(frames))
                .ok_or_else(|| "accepted frames past the datagram".to_string()),
            Verdict::Reject(rejection) => Err(format!("{rejection:?}")),
        }
    }
}

impl WireOpen for Trusted {}

#[cfg(feature = "synthetic")]
impl WireOpen for Synthetic {}

impl WireOpen for Profile {
    /// The encrypted profile decrypts into `scratch` (`open_into`), then
    /// takes the replay decision (`mark`): the complete receive processing
    /// of manifest 6.2. Every other profile reads in place.
    fn open_frames<'a>(
        &self,
        datagram: &'a [u8],
        scratch: &'a mut [u8],
    ) -> Result<&'a [u8], String> {
        match self {
            Self::Encrypted(key) => {
                let opened = key
                    .open_into(datagram, scratch)
                    .map_err(|reason| format!("{reason:?}"))?;
                key.mark(opened.seq)
                    .map_err(|reason| format!("{reason:?}"))?;
                scratch
                    .get(..opened.frames)
                    .ok_or_else(|| "decrypted frames past the scratch".to_string())
            }
            Self::Rotating(rotation) => {
                let key = rotation.opener(datagram).ok_or("no key of this epoch")?;
                let opened = key
                    .open_into(datagram, scratch)
                    .map_err(|reason| format!("{reason:?}"))?;
                key.mark(opened.seq)
                    .map_err(|reason| format!("{reason:?}"))?;
                scratch
                    .get(..opened.frames)
                    .ok_or_else(|| "decrypted frames past the scratch".to_string())
            }
            Self::Trusted => Trusted.open_frames(datagram, scratch),
            #[cfg(feature = "synthetic")]
            Self::Synthetic(synthetic) => synthetic.open_frames(datagram, scratch),
        }
    }
}

/// The scratch a receiver keeps for [`WireOpen::open_frames`]: the largest
/// plaintext.
pub const SCRATCH: usize = MAX_PLAINTEXT;

/// The configuration name of the encrypted profile.
pub const ENCRYPTED: &str = "encrypted";

/// The protection of one configuration.
#[derive(Debug)]
pub enum Profile {
    /// The trusted channel.
    Trusted,
    /// The encrypted class (ADR-0114), its domain 1 key.
    Encrypted(Box<AesGcmSiv>),
    /// The encrypted class under R5 (karyos#650): its keys across one
    /// in-band and one file epoch change.
    Rotating(Box<crate::enc_cost::Rotation>),
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
    /// The profile of `configuration` for a run of `load`: the encrypted
    /// profile rotates its keys under R5 (karyos#650).
    ///
    /// # Errors
    ///
    /// As [`Profile::of`], or keys that do not derive.
    pub fn for_run(
        configuration: &str,
        load: crate::wire::stage::StageLoad,
    ) -> Result<Self, BenchError> {
        if configuration == ENCRYPTED
            && matches!(load, crate::wire::stage::StageLoad::Rotation { .. })
        {
            return Ok(Self::Rotating(Box::new(crate::enc_cost::Rotation::new()?)));
        }
        Self::of(configuration)
    }

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
        if configuration == ENCRYPTED {
            return Ok(Self::Encrypted(Box::new(crate::enc_cost::data_key()?)));
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
            Self::Encrypted(key) => key.envelope_len(),
            Self::Rotating(rotation) => rotation.envelope_len(),
            #[cfg(feature = "synthetic")]
            Self::Synthetic(synthetic) => synthetic.envelope_len(),
        }
    }

    fn seal(&self, datagram: &mut [u8], frames: usize) -> Result<usize, SealError> {
        match self {
            Self::Trusted => Trusted.seal(datagram, frames),
            Self::Encrypted(key) => key.seal(datagram, frames),
            Self::Rotating(rotation) => rotation.seal(datagram, frames),
            #[cfg(feature = "synthetic")]
            Self::Synthetic(synthetic) => synthetic.seal(datagram, frames),
        }
    }

    fn open(&self, datagram: &[u8]) -> Verdict {
        match self {
            Self::Trusted => Trusted.open(datagram),
            Self::Encrypted(key) => {
                let mut scratch = [0_u8; MAX_PLAINTEXT];
                match key.open_into(datagram, &mut scratch) {
                    Ok(opened) => match key.mark(opened.seq) {
                        Ok(()) => Verdict::Accept {
                            start: opened.start,
                            frames: opened.frames,
                        },
                        Err(reason) => Verdict::Reject(reason.into()),
                    },
                    Err(reason) => Verdict::Reject(reason.into()),
                }
            }
            Self::Rotating(rotation) => rotation.open(datagram),
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
        assert!(matches!(Profile::of("trusted"), Ok(Profile::Trusted)));
        assert!(matches!(Profile::of("trusted-b"), Ok(Profile::Trusted)));
        assert!(matches!(Profile::of(ENCRYPTED), Ok(Profile::Encrypted(_))));
        assert!(Profile::of("aes").is_err());
        assert!(Profile::of("synthetic-x").is_err());
        assert!(is_synthetic("synthetic-500"));
        assert!(!is_synthetic("trusted"));
        #[cfg(feature = "synthetic")]
        assert!(matches!(
            Profile::of("synthetic-500"),
            Ok(Profile::Synthetic(Synthetic {
                spin_ns: 500,
                envelope: 0
            }))
        ));
    }

    /// No candidate of ADR-0086 is a configuration the harness can run
    /// in a build without candidate evaluation: the construction is
    /// selected only on E1 or E2 evidence (owner decision item 5), so no
    /// provisional profile is reachable (#632). The opt-in
    /// `auth-candidates` evaluation build is exempt, since ADR-0086 runs
    /// the candidates there to produce that evidence.
    /// The encrypted profile seals and opens its own datagram, and refuses
    /// the same datagram again (the replay decision is part of receive).
    #[test]
    fn the_encrypted_profile_round_trips_and_refuses_a_replay() {
        let sender = Profile::of(ENCRYPTED).unwrap();
        let receiver = Profile::of(ENCRYPTED).unwrap();
        // The committed frames at the start of the buffer, as the harness
        // composes them.
        let mut datagram = vec![0_u8; 1408];
        datagram[..64].fill(7);
        let length = sender.seal(&mut datagram, 64).unwrap();
        let mut scratch = vec![0_u8; SCRATCH];
        let frames = receiver
            .open_frames(&datagram[..length], &mut scratch)
            .unwrap();
        assert_eq!(frames, &[7_u8; 64][..], "decrypted");
        assert!(
            receiver
                .open_frames(&datagram[..length], &mut scratch)
                .is_err(),
            "a replay"
        );
    }

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
