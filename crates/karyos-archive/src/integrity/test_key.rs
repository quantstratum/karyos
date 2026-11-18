// SPDX-License-Identifier: Apache-2.0

//! A signing key on this host, for tests only: compiled under `cfg(test)`
//! or the `test-hooks` feature, which only dev-dependencies enable, never
//! a shipped build (the `ed25519-dalek` admission record: `SigningKey`
//! only in code compiled for tests). Every head it signs is labelled
//! [`Custody::NoSeparation`].

use ed25519_dalek::{Signer as _, SigningKey};

use super::Digest;
use super::signing::{HeadSigner, SignerUnavailable};
use super::trust::{ChainHead, Custody, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH, key_id};

/// A test signing key.
#[derive(Debug, Clone)]
pub struct TestKey(SigningKey);

impl TestKey {
    /// The key derived from `seed`.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&seed))
    }

    /// Its public key.
    #[must_use]
    pub fn public(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.0.verifying_key().to_bytes()
    }

    /// Signs `bytes`, as an authority endorsing a registry entry does.
    #[must_use]
    pub fn sign_bytes(&self, bytes: &[u8]) -> [u8; SIGNATURE_LENGTH] {
        self.0.sign(bytes).to_bytes()
    }
}

impl HeadSigner for TestKey {
    fn key_id(&self) -> Digest {
        key_id(&self.public())
    }

    fn custody(&self) -> Custody {
        Custody::NoSeparation
    }

    fn sign(&mut self, head: &ChainHead) -> Result<[u8; SIGNATURE_LENGTH], SignerUnavailable> {
        Ok(self.sign_bytes(&head.signed_bytes()))
    }
}
