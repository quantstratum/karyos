// SPDX-License-Identifier: Apache-2.0

//! The signed envelope of the authority domains: Ed25519 (`profile_id` 4)
//! over GUARD (domain 2) and SESSION_ABORT (domain 3) bodies
//! (`quantstratum-docs: karyos/adr/0086-wire-authentication-profile-v1.md`
//! sections 1, 2 and 8; owner decision P1b).
//!
//! The layout is the 32-byte header of [`super::hmac_sha256`] with
//! `profile_id` 4 and `tag_len` 64, the body, and the 64-byte signature
//! last. The signed message is `label || header || body`. This module
//! checks every header field against a [`SignedBinding`] before the
//! signature, and leaves the signature to an [`AuthorityVerifier`]. The
//! Ed25519 implementation lives in `karyos-driver`, the crate the
//! admission record scopes `ed25519-dalek` to. Nothing here allocates.
//!
//! The receive order of the signed domains (verification budget, digest
//! cache, epoch check) is the caller's: it runs around [`open_signed`].

use super::hmac_sha256::{FRAME_TYPE, HEADER_LEN, LABEL, VERSION};
use super::{Rejection, SealError};

/// The `profile_id` of Ed25519 authority signatures.
pub const PROFILE_ID: u8 = 4;
/// Bytes of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;
/// The largest body a signed envelope carries: the 88-byte bodies of the
/// authenticated control schemas, with room to spare.
pub const MAX_BODY_LEN: usize = 160;

/// The signed key purposes (ADR-0086 section 2, `domain`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SignedDomain {
    /// GUARD.
    Guard = 2,
    /// SESSION_ABORT.
    SessionAbort = 3,
}

/// The fields every signed datagram of one authority key must carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedBinding {
    /// Key purpose.
    pub domain: SignedDomain,
    /// The authority's key epoch.
    pub party_epoch: u8,
    /// The session id: the aborted session's for SESSION_ABORT, 0 for
    /// GUARD.
    pub session_id: i32,
    /// The stream id, as `session_id`.
    pub stream_id: i32,
    /// The authority key file.
    pub key_id: u32,
}

/// Produces a signature over a whole message.
pub trait AuthoritySigner {
    /// The Ed25519 signature of `message`.
    fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN];
}

/// Checks a signature over a whole message.
pub trait AuthorityVerifier {
    /// Whether `signature` is valid for `message` under strict rules.
    fn verify(&self, message: &[u8], signature: &[u8; SIGNATURE_LEN]) -> bool;
}

/// A signed datagram whose fields and signature verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenedSigned {
    /// Offset of the body.
    pub start: usize,
    /// Length of the body.
    pub body: usize,
    /// The envelope sequence: it only distinguishes messages (ADR-0086
    /// section 6), and is never a freshness input.
    pub seq: u64,
}

/// The signed message `label || header || body` in a stack buffer.
struct Message {
    buf: [u8; LABEL.len() + HEADER_LEN + MAX_BODY_LEN],
    len: usize,
}

impl Message {
    fn of(authed: &[u8]) -> Option<Self> {
        let mut buf = [0_u8; LABEL.len() + HEADER_LEN + MAX_BODY_LEN];
        let len = LABEL.len().checked_add(authed.len())?;
        buf.get_mut(..LABEL.len())?.copy_from_slice(LABEL);
        buf.get_mut(LABEL.len()..len)?.copy_from_slice(authed);
        Some(Self { buf, len })
    }

    fn bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or_default()
    }
}

/// Seals the `body` bytes at the start of `datagram` with sequence `seq`:
/// moves them behind the header, writes the header and the signature, and
/// returns the datagram length. Allocates nothing.
///
/// # Errors
///
/// [`SealError`] when `datagram` cannot hold the envelope or `body`
/// exceeds [`MAX_BODY_LEN`].
pub fn seal_signed(
    datagram: &mut [u8],
    body: usize,
    binding: &SignedBinding,
    seq: u64,
    signer: &dyn AuthoritySigner,
) -> Result<usize, SealError> {
    let too_big = SealError {
        needed: body,
        available: MAX_BODY_LEN,
    };
    if body > MAX_BODY_LEN {
        return Err(too_big);
    }
    let envelope = HEADER_LEN.saturating_add(SIGNATURE_LEN);
    let total = super::sealed_len(datagram, body, envelope)?;
    let length = i32::try_from(total).map_err(|_| too_big)?;
    let authed_len = HEADER_LEN.saturating_add(body);
    let sealed = datagram.get_mut(..total).ok_or(too_big)?;
    sealed.copy_within(..body, HEADER_LEN);
    let header = header(length, binding, seq);
    sealed
        .get_mut(..HEADER_LEN)
        .ok_or(too_big)?
        .copy_from_slice(&header);
    let (authed, tail) = sealed.split_at_mut_checked(authed_len).ok_or(too_big)?;
    let message = Message::of(authed).ok_or(too_big)?;
    tail.get_mut(..SIGNATURE_LEN)
        .ok_or(too_big)?
        .copy_from_slice(&signer.sign(message.bytes()));
    Ok(total)
}

/// Opens a signed datagram: the fixed fields, then the binding, then the
/// signature. A rejection changes no state. Allocates nothing.
///
/// # Errors
///
/// The first [`Rejection`] that applies; [`Rejection::Tag`] for a
/// signature that does not verify.
pub fn open_signed(
    datagram: &[u8],
    binding: &SignedBinding,
    verifier: &dyn AuthorityVerifier,
) -> Result<OpenedSigned, Rejection> {
    let min = HEADER_LEN.saturating_add(SIGNATURE_LEN);
    if datagram.len() < min {
        return Err(Rejection::Short);
    }
    let header = datagram.get(..HEADER_LEN).ok_or(Rejection::Short)?;
    let field =
        |at: usize, width: usize| header.get(at..at.saturating_add(width)).unwrap_or_default();
    let byte = |at: usize| header.get(at).copied().unwrap_or_default();
    let declared = i32::from_le_bytes(field(0, 4).try_into().map_err(|_| Rejection::Short)?);
    if usize::try_from(declared).ok() != Some(datagram.len()) {
        return Err(Rejection::Length);
    }
    if byte(4) != VERSION {
        return Err(Rejection::Version);
    }
    if byte(5) != 0 {
        return Err(Rejection::Flags);
    }
    if u16::from_le_bytes(field(6, 2).try_into().map_err(|_| Rejection::Short)?) != FRAME_TYPE {
        return Err(Rejection::FrameType);
    }
    if byte(8) != PROFILE_ID {
        return Err(Rejection::Profile);
    }
    if usize::from(byte(9)) != SIGNATURE_LEN {
        return Err(Rejection::TagLength);
    }
    if byte(10) != binding.domain as u8 {
        return Err(Rejection::Domain);
    }
    if byte(11) != binding.party_epoch {
        return Err(Rejection::Epoch);
    }
    let int = |at: usize| {
        field(at, 4)
            .try_into()
            .map(i32::from_le_bytes)
            .map_err(|_| Rejection::Short)
    };
    if int(12)? != binding.session_id || int(16)? != binding.stream_id {
        return Err(Rejection::Binding);
    }
    let key_id = field(20, 4)
        .try_into()
        .map(u32::from_le_bytes)
        .map_err(|_| Rejection::Short)?;
    if key_id != binding.key_id {
        return Err(Rejection::Key);
    }
    let seq = field(24, 8)
        .try_into()
        .map(u64::from_le_bytes)
        .map_err(|_| Rejection::Short)?;
    let authed_len = datagram
        .len()
        .checked_sub(SIGNATURE_LEN)
        .ok_or(Rejection::Short)?;
    let body = authed_len.checked_sub(HEADER_LEN).ok_or(Rejection::Short)?;
    if body > MAX_BODY_LEN {
        return Err(Rejection::Length);
    }
    let (authed, signature) = datagram
        .split_at_checked(authed_len)
        .ok_or(Rejection::Short)?;
    let signature: &[u8; SIGNATURE_LEN] = signature.try_into().map_err(|_| Rejection::Short)?;
    let message = Message::of(authed).ok_or(Rejection::Length)?;
    if !verifier.verify(message.bytes(), signature) {
        return Err(Rejection::Tag);
    }
    Ok(OpenedSigned {
        start: HEADER_LEN,
        body,
        seq,
    })
}

/// The 32 header bytes of a signed datagram of `length` bytes.
fn header(length: i32, binding: &SignedBinding, seq: u64) -> [u8; HEADER_LEN] {
    let mut header = [0_u8; HEADER_LEN];
    let mut put = |at: usize, bytes: &[u8]| {
        if let Some(slot) = header.get_mut(at..at.saturating_add(bytes.len())) {
            slot.copy_from_slice(bytes);
        }
    };
    put(0, &length.to_le_bytes());
    put(4, &[VERSION, 0]);
    put(6, &FRAME_TYPE.to_le_bytes());
    put(
        8,
        &[PROFILE_ID, 64, binding.domain as u8, binding.party_epoch],
    );
    put(12, &binding.session_id.to_le_bytes());
    put(16, &binding.stream_id.to_le_bytes());
    put(20, &binding.key_id.to_le_bytes());
    put(24, &seq.to_le_bytes());
    header
}

#[cfg(test)]
mod tests;
