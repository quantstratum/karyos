// SPDX-License-Identifier: Apache-2.0

//! Ed25519 guard and abort authority keys (owner decision P1b;
//! `quantstratum-docs: karyos/adr/0086-wire-authentication-profile-v1.md`
//! section 8). They implement the signer and verifier of
//! [`karyos_protocol::protection::signed`].
//!
//! Wire keys are not archival keys. This module serves the wire purpose
//! only, under the driver scope of
//! `karyos/reviews/dependency-admission-wire-auth-hmac.md`, and shares no
//! key with `karyos-archive`.

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use karyos_protocol::protection::signed::{AuthoritySigner, AuthorityVerifier, SIGNATURE_LEN};
use thiserror::Error;

/// Bytes of an Ed25519 public or secret key.
pub const KEY_LEN: usize = 32;

/// A public key the loader refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuthorityKeyError {
    /// The bytes do not decode to a curve point.
    #[error("the authority public key does not decode")]
    Malformed,
    /// The bytes decode, but are not the canonical encoding of the point:
    /// `ed25519-dalek` accepts some such encodings that `verify_strict`
    /// does not refuse (ADR-0086 evidence E-5).
    #[error("the authority public key is not canonically encoded")]
    NonCanonical,
    /// The point has small order.
    #[error("the authority public key has small order")]
    WeakKey,
}

/// A receiver's view of an authority: verifies, never signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519Verifier {
    key: VerifyingKey,
}

impl Ed25519Verifier {
    /// The 32 public key bytes (tests).
    #[cfg(test)]
    #[must_use]
    pub fn to_bytes(&self) -> [u8; KEY_LEN] {
        self.key.to_bytes()
    }

    /// Loads a public key. It is accepted only when decoding and
    /// re-encoding reproduces `bytes` and the point is not of small order
    /// (ADR-0086 section 8).
    ///
    /// # Errors
    ///
    /// [`AuthorityKeyError`] for each refused case.
    pub fn from_bytes(bytes: &[u8; KEY_LEN]) -> Result<Self, AuthorityKeyError> {
        let key = VerifyingKey::from_bytes(bytes).map_err(|_| AuthorityKeyError::Malformed)?;
        // `VerifyingKey` keeps the bytes it was given, so the check
        // re-encodes the decoded point itself.
        if key.to_edwards().compress().to_bytes() != *bytes {
            return Err(AuthorityKeyError::NonCanonical);
        }
        if key.is_weak() {
            return Err(AuthorityKeyError::WeakKey);
        }
        Ok(Self { key })
    }
}

impl AuthorityVerifier for Ed25519Verifier {
    fn verify(&self, message: &[u8], signature: &[u8; SIGNATURE_LEN]) -> bool {
        self.key
            .verify_strict(message, &Signature::from_bytes(signature))
            .is_ok()
    }
}

/// The authority's own signing key, loaded only by the authority's
/// driver. The secret is erased on drop (`ed25519-dalek` feature
/// `zeroize`).
pub struct Ed25519Signer {
    key: SigningKey,
}

impl core::fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ed25519Signer").finish_non_exhaustive()
    }
}

impl Ed25519Signer {
    /// A signer from a 32-byte secret seed.
    #[must_use]
    pub fn from_seed(seed: &[u8; KEY_LEN]) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
        }
    }

    /// The matching verifier.
    #[must_use]
    pub fn verifier(&self) -> Ed25519Verifier {
        Ed25519Verifier {
            key: self.key.verifying_key(),
        }
    }
}

impl AuthoritySigner for Ed25519Signer {
    fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.key.sign(message).to_bytes()
    }
}

#[cfg(test)]
mod h7_tests;
#[cfg(test)]
mod tests;
