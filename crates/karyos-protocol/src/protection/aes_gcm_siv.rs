// SPDX-License-Identifier: Apache-2.0

//! The encrypted protection profile v1: AES-256-GCM-SIV (RFC 8452) with a
//! 16-byte tag, `profile_id` 16 of `karyos-wire-enc` version 1
//! (`quantstratum-docs: karyos/adr/0114-encrypted-protection-profile-v1.md`;
//! owner decision D53).
//!
//! A datagram is `header || ciphertext || tag`. The 68-byte header is in
//! clear and authenticated as associated data:
//!
//! | Offset | Width | Field |
//! | --- | --- | --- |
//! | 0 | 4 | `datagram_length`, i32, tag included |
//! | 4 | 1 | `version`, 1 |
//! | 5 | 1 | `flags`, 0 |
//! | 6 | 2 | `frame_type`, `0x21` |
//! | 8 | 1 | `profile_id`, 16 |
//! | 9 | 1 | `tag_len`, 16 |
//! | 10 | 1 | `domain`: 1, 4, 5 or 6 |
//! | 11 | 1 | reserved, 0 |
//! | 12 | 4 | `key_epoch`, u32 |
//! | 16 | 2 | `party_epoch`, u16 |
//! | 18 | 2 | reserved, 0 |
//! | 20 | 4 | `session_id` |
//! | 24 | 4 | `stream_id` |
//! | 28 | 8 | `envelope_seq`, u64 |
//! | 36 | 32 | `party`: the identity block (domains 1 and 5) or the receiver block and 8 zero bytes (domains 4 and 6) |
//!
//! All integers are little-endian. The associated data is `label ||
//! header`, where the label is the 20 bytes `karyos-wire-enc-v01\0`, never
//! transmitted. The 96-bit nonce is `domain || 0 0 0 || envelope_seq`.
//!
//! Each [`AesGcmSiv`] value is one derived key: one domain, one epoch pair,
//! one party and one salt (ADR-0114 sections 4 and 5). Its key comes from
//! the provisioned channel or group key through HKDF-SHA-256 over a fixed
//! width `info`, and the provisioned key is never used as an AEAD key.
//! Domains 4 and 6 also carry the pairwise trailer of section 4 as the last
//! 20 bytes of the plaintext.
//!
//! What this module does not do: the channel gate (the `encrypted` class
//! stays refused at parse), key files, key slots and scratch derivation,
//! the open rate counters, the key age, retired identity tables, inner
//! batch validation and the virtual machine generation signal. Those belong
//! to the driver.

use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use ::aes_gcm_siv::aead::inout::InOutBuf;
use ::aes_gcm_siv::aead::{AeadInOut, KeyInit};
use ::aes_gcm_siv::{Aes256GcmSiv, Key, Nonce, Tag};
use zeroize::Zeroizing;

use super::hmac_key::{HmacKey, OUT_LEN};
use super::replay::{Replay, ReplayWindow};
use super::{Protection, Rejection, SealError, Verdict};

/// The label every associated data and every HKDF `info` starts with
/// (ADR-0114 section 1).
pub const LABEL: &[u8; 20] = b"karyos-wire-enc-v01\0";
/// Bytes of the cleartext header.
pub const HEADER_LEN: usize = 68;
/// Bytes of the AEAD tag.
pub const TAG_LEN: usize = 16;
/// Bytes the envelope adds to every datagram: header and tag (section 11).
pub const ENVELOPE_LEN: usize = HEADER_LEN + TAG_LEN;
/// The envelope's frame type (section 1).
pub const FRAME_TYPE: u16 = 0x21;
/// The envelope version.
pub const VERSION: u8 = 1;
/// The `profile_id` of AES-256-GCM-SIV with a 16-byte tag.
pub const PROFILE_ID: u8 = 16;
/// Reserved `profile_id` of ChaCha20-Poly1305; not in v1.
pub const RESERVED_CHACHA20_POLY1305: u8 = 17;
/// Reserved `profile_id` of AES-256-GCM; not in v1.
pub const RESERVED_AES_256_GCM: u8 = 18;
/// The largest datagram of an `encrypted` channel (sections 6 and 11).
pub const MAX_DATAGRAM: usize = 1408;
/// The largest plaintext a sender seals: `MAX_DATAGRAM - ENVELOPE_LEN`.
pub const MAX_PLAINTEXT: usize = MAX_DATAGRAM - ENVELOPE_LEN;
/// Bytes of the pairwise trailer of domains 4 and 6: `pairwise_epoch` and
/// the 16-byte pairwise tag.
pub const TRAILER_LEN: usize = 4 + PAIRWISE_TAG_LEN;
/// Bytes of the pairwise tag.
pub const PAIRWISE_TAG_LEN: usize = 16;
/// The `envelope_seq` cap of the data keys (domains 1 and 4): never sealed
/// or opened at or above it.
pub const DATA_SEQ_CAP: u64 = 1 << 32;
/// The `envelope_seq` cap of the bootstrap keys (domains 5 and 6).
pub const BOOTSTRAP_SEQ_CAP: u64 = 1 << 30;
/// Bytes a data key may protect (header and plaintext) before its party
/// moves to the next `party_epoch` (section 6, "Budgets per data key").
pub const DATA_BYTE_BUDGET: u64 = 1 << 42;
/// Bytes of a derived key.
pub const KEY_LEN: usize = 32;
/// Pairwise keys one profile holds: the one it seals with and one more it
/// still verifies, for the rotation overlap of the pairwise file.
pub const PAIRWISE_SLOTS: usize = 2;
/// The longest HKDF `info` (domains 4 and 6).
pub const MAX_INFO_LEN: usize = 20 + 8 + 4 + 2 + 24 + 32 + 1;
/// The pairwise key `info` length.
pub const PAIRWISE_INFO_LEN: usize = 20 + 8 + 4 + 24 + 32 + 1;

/// The key purposes of ADR-0114 section 2 (`domain`), numbered as in
/// ADR-0086.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Domain {
    /// Sender: DATA and the other sender frames.
    Sender = 1,
    /// Receiver: SM, NAK, SESSION_ABORT_ACK and the other receiver frames,
    /// with the pairwise trailer.
    Receiver = 4,
    /// First-contact SETUP.
    Setup = 5,
    /// RSP_SETUP, with the pairwise trailer.
    RspSetup = 6,
}

impl Domain {
    /// The domain of a header byte, if it is one.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Sender),
            4 => Some(Self::Receiver),
            5 => Some(Self::Setup),
            6 => Some(Self::RspSetup),
            _ => None,
        }
    }

    /// The 8-byte HKDF purpose tag, zero padded.
    #[must_use]
    pub const fn purpose(self) -> [u8; 8] {
        match self {
            Self::Sender => *b"snd\0\0\0\0\0",
            Self::Receiver => *b"rcv\0\0\0\0\0",
            Self::Setup => *b"setup\0\0\0",
            Self::RspSetup => *b"rsp\0\0\0\0\0",
        }
    }

    /// Whether the encrypting party is a receiver (domains 4 and 6), whose
    /// datagrams carry the pairwise trailer.
    #[must_use]
    pub const fn is_receiver(self) -> bool {
        matches!(self, Self::Receiver | Self::RspSetup)
    }

    /// Whether this is a bootstrap key (domains 5 and 6).
    #[must_use]
    pub const fn is_bootstrap(self) -> bool {
        matches!(self, Self::Setup | Self::RspSetup)
    }

    /// The `envelope_seq` cap of the domain.
    #[must_use]
    pub const fn seq_cap(self) -> u64 {
        if self.is_bootstrap() {
            BOOTSTRAP_SEQ_CAP
        } else {
            DATA_SEQ_CAP
        }
    }
}

/// A full publication identity: the identity block IB of
/// network-control-schemas.md 3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicationIdentity {
    /// `driver_id`, as its 16 wire bytes (two little-endian u64 words).
    pub driver_id: [u8; 16],
    /// `registration_id`, at least 1.
    pub registration_id: u64,
    /// `incarnation`, at least 1.
    pub incarnation: u64,
}

impl PublicationIdentity {
    /// The 32 bytes of the block.
    #[must_use]
    pub fn encode(&self) -> [u8; 32] {
        let mut out = [0_u8; 32];
        put(&mut out, 0, &self.driver_id);
        put(&mut out, 16, &self.registration_id.to_le_bytes());
        put(&mut out, 24, &self.incarnation.to_le_bytes());
        out
    }

    fn is_valid(&self) -> bool {
        self.driver_id != [0; 16] && self.registration_id != 0 && self.incarnation != 0
    }
}

/// A receiving agent: the receiver block RB of network-control-schemas.md
/// 3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReceiverIdentity {
    /// `receiver_boot_id`, as its 16 wire bytes.
    pub receiver_boot_id: [u8; 16],
    /// `receiver_id`, at least 1.
    pub receiver_id: u64,
}

impl ReceiverIdentity {
    /// The 24 bytes of the block.
    #[must_use]
    pub fn encode(&self) -> [u8; 24] {
        let mut out = [0_u8; 24];
        put(&mut out, 0, &self.receiver_boot_id);
        put(&mut out, 16, &self.receiver_id.to_le_bytes());
        out
    }

    fn is_valid(&self) -> bool {
        self.receiver_boot_id != [0; 16] && self.receiver_id != 0
    }
}

/// The HKDF salt of a derived key (section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Salt {
    /// The RFC 5869 default, 32 zero bytes: multicast data keys and every
    /// bootstrap key.
    Empty,
    /// Unicast data keys after establishment: the completed challenge.
    Challenge {
        /// The `receiver_boot_id` of the challenge.
        receiver_boot_id: [u8; 16],
        /// The `challenge_nonce`.
        nonce: [u8; 16],
    },
}

impl Salt {
    /// The 32 salt bytes HKDF-Extract keys with.
    fn bytes(&self) -> [u8; 32] {
        let mut out = [0_u8; 32];
        if let Self::Challenge {
            receiver_boot_id,
            nonce,
        } = self
        {
            put(&mut out, 0, receiver_boot_id);
            put(&mut out, 16, nonce);
        }
        out
    }
}

/// The full context of one derived key: every input of its derivation and
/// every header field a datagram under it must carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyContext {
    /// Key purpose.
    pub domain: Domain,
    /// The file epoch of the provisioned channel or group key, at least 1.
    pub key_epoch: u32,
    /// The party's in-band epoch under `key_epoch`; 0 in domains 5 and 6.
    pub party_epoch: u16,
    /// The session alias of the DATA header.
    pub session_id: i32,
    /// The stream id of the DATA header.
    pub stream_id: i32,
    /// The publication: the encrypting party in domains 1 and 5, the target
    /// publication in domains 4 and 6.
    pub publication: PublicationIdentity,
    /// The encrypting receiver of domains 4 and 6; `None` in 1 and 5.
    pub receiver: Option<ReceiverIdentity>,
    /// The HKDF salt; [`Salt::Empty`] in domains 5 and 6.
    pub salt: Salt,
}

/// Why a [`KeyContext`] or a key cannot make a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ContextError {
    /// The provisioned key or the pairwise secret is empty.
    #[error("an encrypted profile key must not be empty")]
    EmptyKey,
    /// `key_epoch` is 0.
    #[error("key_epoch must be at least 1")]
    KeyEpoch,
    /// A bootstrap domain with a nonzero `party_epoch`.
    #[error("domains 5 and 6 take party_epoch 0")]
    PartyEpoch,
    /// A bootstrap domain with a challenge salt.
    #[error("domains 5 and 6 take the empty salt")]
    Salt,
    /// A receiver domain without a receiver, or a sender domain with one.
    #[error("the receiver identity does not match the domain")]
    Receiver,
    /// An identity with an all-zero id or a zero counter.
    #[error("an identity field is zero")]
    Identity,
    /// A receiver domain without a pairwise key to seal with.
    #[error("a receiver domain needs a pairwise key")]
    Pairwise,
    /// More pairwise keys than [`PAIRWISE_SLOTS`].
    #[error("too many pairwise keys")]
    PairwiseSlots,
}

impl KeyContext {
    /// Checks the context against the rules of sections 2 and 4.
    ///
    /// # Errors
    ///
    /// The first [`ContextError`] that applies.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.key_epoch == 0 {
            return Err(ContextError::KeyEpoch);
        }
        if self.domain.is_bootstrap() {
            if self.party_epoch != 0 {
                return Err(ContextError::PartyEpoch);
            }
            if self.salt != Salt::Empty {
                return Err(ContextError::Salt);
            }
        }
        if self.domain.is_receiver() != self.receiver.is_some() {
            return Err(ContextError::Receiver);
        }
        if !self.publication.is_valid() || self.receiver.is_some_and(|r| !r.is_valid()) {
            return Err(ContextError::Identity);
        }
        if let Salt::Challenge {
            receiver_boot_id,
            nonce,
        } = self.salt
            && (receiver_boot_id == [0; 16] || nonce == [0; 16])
        {
            return Err(ContextError::Identity);
        }
        Ok(())
    }

    /// The 32 `party` bytes of the header.
    #[must_use]
    pub fn party(&self) -> [u8; 32] {
        match self.receiver {
            Some(receiver) => {
                let mut out = [0_u8; 32];
                put(&mut out, 0, &receiver.encode());
                out
            }
            None => self.publication.encode(),
        }
    }

    /// The HKDF `info` of this key and its length: `label || purpose ||
    /// key_epoch || party_epoch`, then the receiver block in domains 4 and
    /// 6, then the identity block, then `profile_id`.
    #[must_use]
    pub fn info(&self) -> ([u8; MAX_INFO_LEN], usize) {
        let mut out = [0_u8; MAX_INFO_LEN];
        let mut at = 0;
        let mut push = |bytes: &[u8]| {
            put(&mut out, at, bytes);
            at = at.saturating_add(bytes.len());
        };
        push(LABEL);
        push(&self.domain.purpose());
        push(&self.key_epoch.to_le_bytes());
        push(&self.party_epoch.to_le_bytes());
        if let Some(receiver) = self.receiver {
            push(&receiver.encode());
        }
        push(&self.publication.encode());
        push(&[PROFILE_ID]);
        (out, at)
    }

    /// The derived key: HKDF-SHA-256 with `IKM` the provisioned key, this
    /// context's salt and `info`, and `L` = 32.
    #[must_use]
    pub fn derive(&self, ikm: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
        let (info, len) = self.info();
        hkdf_sha256(&self.salt.bytes(), ikm, info.get(..len).unwrap_or_default())
    }
}

/// HKDF-SHA-256 (RFC 5869) with `L` = 32, through the erasing HKDF of
/// [`super::hkdf`].
#[must_use]
pub fn hkdf_sha256(salt: &[u8; 32], ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
    super::hkdf::hkdf_sha256::<KEY_LEN>(Some(salt), ikm, &[info])
}

/// The pairwise key `info` of section 4: `label || "pauth" ||
/// pairwise_epoch || receiver block || identity block || profile_id`.
#[must_use]
pub fn pairwise_info(
    pairwise_epoch: u32,
    receiver: &ReceiverIdentity,
    publication: &PublicationIdentity,
) -> [u8; PAIRWISE_INFO_LEN] {
    let mut out = [0_u8; PAIRWISE_INFO_LEN];
    put(&mut out, 0, LABEL);
    put(&mut out, 20, b"pauth\0\0\0");
    put(&mut out, 28, &pairwise_epoch.to_le_bytes());
    put(&mut out, 32, &receiver.encode());
    put(&mut out, 56, &publication.encode());
    put(&mut out, 88, &[PROFILE_ID]);
    out
}

/// `Kp` of section 4: HKDF-SHA-256 with `IKM` the pairwise file's secret,
/// the empty salt and [`pairwise_info`].
#[must_use]
pub fn derive_pairwise(
    secret: &[u8],
    pairwise_epoch: u32,
    receiver: &ReceiverIdentity,
    publication: &PublicationIdentity,
) -> Zeroizing<[u8; KEY_LEN]> {
    hkdf_sha256(
        &[0; 32],
        secret,
        &pairwise_info(pairwise_epoch, receiver, publication),
    )
}

/// One pairwise key: its file epoch and `Kp` as an HMAC key, erased on
/// drop.
#[derive(Clone)]
pub struct PairwiseKey {
    epoch: u32,
    mac: HmacKey,
}

impl core::fmt::Debug for PairwiseKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PairwiseKey")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl PairwiseKey {
    /// The pairwise key of `secret` at `pairwise_epoch` for `receiver` and
    /// the target `publication`.
    ///
    /// # Errors
    ///
    /// [`ContextError::EmptyKey`] when `secret` is empty, and
    /// [`ContextError::Identity`] when an identity field is zero.
    pub fn derive(
        secret: &[u8],
        pairwise_epoch: u32,
        receiver: &ReceiverIdentity,
        publication: &PublicationIdentity,
    ) -> Result<Self, ContextError> {
        if secret.is_empty() {
            return Err(ContextError::EmptyKey);
        }
        if !receiver.is_valid() || !publication.is_valid() {
            return Err(ContextError::Identity);
        }
        let kp = derive_pairwise(secret, pairwise_epoch, receiver, publication);
        Ok(Self {
            epoch: pairwise_epoch,
            mac: HmacKey::new(kp.as_slice()),
        })
    }

    /// The pairwise file epoch.
    #[must_use]
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// The leftmost 16 bytes of HMAC-SHA-256(`Kp`, `label || header ||
    /// covered`).
    fn tag(&self, header: &[u8], covered: &[u8]) -> Zeroizing<[u8; OUT_LEN]> {
        let mut mac = self.mac.mac();
        mac.update(LABEL);
        mac.update(header);
        mac.update(covered);
        mac.finalize()
    }

    fn verify(&self, header: &[u8], covered: &[u8], tag: &[u8]) -> bool {
        let mut mac = self.mac.mac();
        mac.update(LABEL);
        mac.update(header);
        mac.update(covered);
        tag.len() == PAIRWISE_TAG_LEN && mac.verify_truncated_left(tag)
    }
}

/// Why an encrypted datagram is rejected. Every reason is a counter reason
/// of ADR-0114; the downgrade cases of section 9 are each distinct.
/// [`Rejection`] carries the nearest older reason ([`From`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncRejection {
    /// Shorter than the envelope.
    Short,
    /// The declared datagram length is larger than the received length, or
    /// not a valid length.
    Length,
    /// Longer than [`MAX_DATAGRAM`].
    TooLong,
    /// An unknown envelope version.
    Version,
    /// Nonzero flags.
    Flags,
    /// A nonzero reserved field, or nonzero party padding in domains 4
    /// and 6.
    Reserved,
    /// An unknown outer frame type.
    FrameType,
    /// `enc_bare_frame`: a bare SPEC.md section 5 frame, the envelope
    /// stripped.
    BareFrame,
    /// `enc_wrong_class`: an authenticated envelope (`0x20`) as the outer
    /// frame.
    WrongClass,
    /// `enc_mixed_class`: bytes after the tag (the declared length is
    /// shorter than the datagram), or, from inner validation, an inner
    /// `0x21` or a forbidden inner `0x20`.
    MixedClass,
    /// `enc_plaintext_setup`: a bare SETUP or RSP_SETUP.
    PlaintextSetup,
    /// `enc_profile`: a `profile_id` other than the bound one.
    Profile,
    /// A `tag_len` other than 16.
    TagLength,
    /// A domain other than the key's, or no domain at all.
    Domain,
    /// `enc_epoch`: `key_epoch` or `party_epoch` other than the key's.
    Epoch,
    /// A session or stream id other than the bound one.
    Binding,
    /// The header `party` names another party than the key's.
    Party,
    /// `enc_seq_cap`: `envelope_seq` at or above the domain's cap.
    SequenceCap,
    /// Already accepted in the window.
    Duplicate,
    /// Older than the window.
    TooOld,
    /// The AEAD tag does not verify.
    Tag,
    /// `enc_pairwise`: the pairwise trailer is missing, names an epoch this
    /// key does not hold, or does not verify.
    Pairwise,
    /// `enc_unexpected`: an outer `0x21` on a `trusted` or `authenticated`
    /// channel. Raised by the channel, not by this profile.
    Unexpected,
    /// `enc_inner_rejected`: a forbidden or malformed inner frame. Raised
    /// by inner batch validation.
    InnerRejected,
    /// `enc_open_rate`: over the open rate of the channel. Raised by the
    /// driver.
    OpenRate,
    /// `enc_key_age`: a key past its age. Raised by the driver.
    KeyAge,
    /// `enc_retired_boot`: an RSP_SETUP naming a retired boot id. Raised by
    /// the driver.
    RetiredBoot,
    /// `enc_retired_party`: traffic of a retired publication identity.
    /// Raised by the driver.
    RetiredParty,
    /// `enc_resync_refused`: an answer refused as a resynchronisation.
    /// Raised by the driver.
    ResyncRefused,
    /// `enc_before_join`: verified, but before a join point or already
    /// delivered. Raised by the driver.
    BeforeJoin,
}

impl From<Replay> for EncRejection {
    fn from(replay: Replay) -> Self {
        match replay {
            Replay::Duplicate => Self::Duplicate,
            Replay::TooOld => Self::TooOld,
        }
    }
}

impl From<EncRejection> for Rejection {
    /// The nearest reason of the seam. Lossy: counters use
    /// [`EncRejection`] itself.
    fn from(reason: EncRejection) -> Self {
        match reason {
            EncRejection::Short => Self::Short,
            EncRejection::Length | EncRejection::TooLong | EncRejection::MixedClass => Self::Length,
            EncRejection::Version => Self::Version,
            EncRejection::Flags | EncRejection::Reserved => Self::Flags,
            EncRejection::FrameType
            | EncRejection::BareFrame
            | EncRejection::WrongClass
            | EncRejection::PlaintextSetup
            | EncRejection::Unexpected => Self::FrameType,
            EncRejection::Profile => Self::Profile,
            EncRejection::TagLength => Self::TagLength,
            EncRejection::Domain => Self::Domain,
            EncRejection::Epoch | EncRejection::SequenceCap | EncRejection::KeyAge => Self::Epoch,
            EncRejection::Binding
            | EncRejection::Duplicate
            | EncRejection::TooOld
            | EncRejection::BeforeJoin
            | EncRejection::ResyncRefused => Self::Binding,
            EncRejection::Party | EncRejection::RetiredBoot | EncRejection::RetiredParty => {
                Self::Key
            }
            EncRejection::Tag
            | EncRejection::Pairwise
            | EncRejection::InnerRejected
            | EncRejection::OpenRate => Self::Tag,
        }
    }
}

/// Why a seal is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EncSealError {
    /// The buffer cannot hold the frames, trailer and envelope.
    #[error(transparent)]
    Buffer(#[from] SealError),
    /// The plaintext would exceed [`MAX_PLAINTEXT`].
    #[error("a plaintext of {plaintext} bytes exceeds the encrypted cap")]
    TooLong {
        /// Bytes of frames and trailer.
        plaintext: usize,
    },
    /// The sequence cap of the key is reached: the party moves to the next
    /// `party_epoch` (domains 1 and 4) or stops sending in that domain
    /// until the next `key_epoch` (domains 5 and 6).
    #[error("the envelope sequence of this key is exhausted")]
    Exhausted,
    /// The byte budget of a data key is reached: the party moves to the
    /// next `party_epoch`.
    #[error("the byte budget of this key is exhausted")]
    BytesExhausted,
    /// The AEAD refused the input. Not reachable within the caps.
    #[error("the AEAD refused the input")]
    Aead,
}

/// A datagram that passed every check, its AEAD tag and, in domains 4 and
/// 6, its pairwise trailer. Its sequence is not yet marked: see
/// [`AesGcmSiv::mark`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opened {
    /// Offset of the inner frames: [`HEADER_LEN`].
    pub start: usize,
    /// Length of the inner frames, without the pairwise trailer.
    pub frames: usize,
    /// The envelope sequence, to mark after inner validation.
    pub seq: u64,
    /// The pairwise file epoch of the trailer, in domains 4 and 6.
    pub pairwise_epoch: Option<u32>,
}

/// One AES-256-GCM-SIV derived key of the encrypted profile, with its
/// sealing counter and its replay window.
///
/// The counter is an [`AtomicU64`], so `seal` takes `&self` and may run on
/// several threads: each seal reserves its `envelope_seq` with one
/// compare-and-swap loop that never passes the cap, so no sequence is used
/// twice and the counter never wraps. A seal that fails after the
/// reservation burns that sequence, which is safe. The replay window is
/// behind a mutex, so the check and the mark of section 8 step 8 are one
/// atomic operation.
///
/// The derived key bytes, the pairwise HMAC states and the AES and POLYVAL
/// key schedules (`aes` and `polyval` with `zeroize`) are erased on drop.
pub struct AesGcmSiv {
    aead: Aes256GcmSiv,
    context: KeyContext,
    party: [u8; 32],
    next_seq: AtomicU64,
    sealed_bytes: AtomicU64,
    window: Mutex<ReplayWindow>,
    pairwise: [Option<PairwiseKey>; PAIRWISE_SLOTS],
}

impl core::fmt::Debug for AesGcmSiv {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AesGcmSiv")
            .field("context", &self.context)
            .field("next_seq", &self.next_seq())
            .finish_non_exhaustive()
    }
}

impl AesGcmSiv {
    /// The profile of `context`, keyed by HKDF from the provisioned key
    /// `ikm`. `pairwise` lists the pairwise keys of a receiver domain: the
    /// first seals, every one verifies. It must be empty in domains 1
    /// and 5.
    ///
    /// # Errors
    ///
    /// [`ContextError`] when `ikm` is empty, the context is invalid, or the
    /// pairwise keys do not fit the domain.
    pub fn new(
        ikm: &[u8],
        context: KeyContext,
        pairwise: &[PairwiseKey],
    ) -> Result<Self, ContextError> {
        if ikm.is_empty() {
            return Err(ContextError::EmptyKey);
        }
        context.validate()?;
        if pairwise.len() > PAIRWISE_SLOTS {
            return Err(ContextError::PairwiseSlots);
        }
        if context.domain.is_receiver() == pairwise.is_empty() {
            return Err(ContextError::Pairwise);
        }
        let mut slots: [Option<PairwiseKey>; PAIRWISE_SLOTS] = [None, None];
        for (slot, key) in slots.iter_mut().zip(pairwise) {
            *slot = Some(key.clone());
        }
        let key = context.derive(ikm);
        let key_ref: &Key<Aes256GcmSiv> = (&*key).into();
        let aead = Aes256GcmSiv::new(key_ref);
        let profile = Self {
            aead,
            context,
            party: context.party(),
            next_seq: AtomicU64::new(0),
            sealed_bytes: AtomicU64::new(0),
            window: Mutex::new(ReplayWindow::new()),
            pairwise: slots,
        };
        // Lock once here, so that a platform whose mutex sets itself up on
        // first use (a lazily boxed pthread mutex) does it at construction,
        // never on the data path.
        drop(profile.lock());
        Ok(profile)
    }

    /// The context of this key.
    #[must_use]
    pub fn context(&self) -> &KeyContext {
        &self.context
    }

    /// The sequence the next seal reserves.
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.next_seq.load(Ordering::Relaxed)
    }

    /// Header and plaintext bytes sealed so far.
    #[must_use]
    pub fn sealed_bytes(&self) -> u64 {
        self.sealed_bytes.load(Ordering::Relaxed)
    }

    /// A copy of the replay window.
    #[must_use]
    pub fn window(&self) -> ReplayWindow {
        self.lock().clone()
    }

    /// Bytes the envelope adds to every datagram of this key, the pairwise
    /// trailer included.
    #[must_use]
    pub fn overhead(&self) -> usize {
        ENVELOPE_LEN.saturating_add(self.trailer_len())
    }

    fn trailer_len(&self) -> usize {
        if self.context.domain.is_receiver() {
            TRAILER_LEN
        } else {
            0
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ReplayWindow> {
        self.window.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Starts the counter at `seq`, for tests near the cap.
    #[cfg(test)]
    pub(crate) fn set_next_seq(&self, seq: u64) {
        self.next_seq.store(seq, Ordering::Relaxed);
    }

    /// The 96-bit nonce of `seq` (section 5).
    #[must_use]
    pub fn nonce(domain: Domain, seq: u64) -> [u8; 12] {
        let mut out = [0_u8; 12];
        put(&mut out, 0, &[domain as u8]);
        put(&mut out, 4, &seq.to_le_bytes());
        out
    }

    /// The header of a datagram of `length` bytes with sequence `seq`.
    fn header(&self, length: i32, seq: u64) -> [u8; HEADER_LEN] {
        let mut out = [0_u8; HEADER_LEN];
        put(&mut out, 0, &length.to_le_bytes());
        put(&mut out, 4, &[VERSION, 0]);
        put(&mut out, 6, &FRAME_TYPE.to_le_bytes());
        put(&mut out, 8, &[PROFILE_ID, 16, self.context.domain as u8, 0]);
        put(&mut out, 12, &self.context.key_epoch.to_le_bytes());
        put(&mut out, 16, &self.context.party_epoch.to_le_bytes());
        put(&mut out, 20, &self.context.session_id.to_le_bytes());
        put(&mut out, 24, &self.context.stream_id.to_le_bytes());
        put(&mut out, 28, &seq.to_le_bytes());
        put(&mut out, 36, &self.party);
        out
    }

    /// Reserves the next `envelope_seq` below the cap, or fails without
    /// changing the counter.
    ///
    /// `Relaxed` is enough: every read-modify-write of one atomic sees the
    /// latest value in its single modification order, so two reservations
    /// never return one value; no other memory is published through the
    /// counter.
    fn reserve(&self) -> Result<u64, EncSealError> {
        let cap = self.context.domain.seq_cap();
        self.next_seq
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |seq| {
                (seq < cap).then(|| seq.saturating_add(1))
            })
            .map_err(|_| EncSealError::Exhausted)
    }

    /// Charges `bytes` to the byte budget of a data key, or fails without
    /// changing it.
    fn charge(&self, bytes: u64) -> Result<(), EncSealError> {
        if self.context.domain.is_bootstrap() {
            return Ok(());
        }
        self.sealed_bytes
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |sealed| {
                sealed
                    .checked_add(bytes)
                    .filter(|total| *total <= DATA_BYTE_BUDGET)
            })
            .map(|_| ())
            .map_err(|_| EncSealError::BytesExhausted)
    }

    /// Seals the `frames` bytes at the start of `datagram` with the next
    /// `envelope_seq`: moves them behind the header, appends the pairwise
    /// trailer in domains 4 and 6, encrypts in place, writes the header and
    /// the detached tag, and returns the datagram length. Allocates
    /// nothing. A refusal writes nothing.
    ///
    /// # Errors
    ///
    /// [`EncSealError`].
    pub fn seal_next(&self, datagram: &mut [u8], frames: usize) -> Result<usize, EncSealError> {
        let trailer = self.trailer_len();
        let plaintext = frames.checked_add(trailer).ok_or(EncSealError::TooLong {
            plaintext: usize::MAX,
        })?;
        if plaintext > MAX_PLAINTEXT {
            return Err(EncSealError::TooLong { plaintext });
        }
        let total = super::sealed_len(datagram, plaintext, ENVELOPE_LEN)?;
        let length = i32::try_from(total).map_err(|_| EncSealError::Aead)?;
        let protected =
            u64::try_from(HEADER_LEN.saturating_add(plaintext)).map_err(|_| EncSealError::Aead)?;
        let seq = self.reserve()?;
        self.charge(protected)?;
        self.seal_at(datagram, frames, plaintext, total, length, seq)
    }

    fn seal_at(
        &self,
        datagram: &mut [u8],
        frames: usize,
        plaintext: usize,
        total: usize,
        length: i32,
        seq: u64,
    ) -> Result<usize, EncSealError> {
        let sealed = datagram.get_mut(..total).ok_or(EncSealError::Aead)?;
        sealed.copy_within(..frames, HEADER_LEN);
        let header = self.header(length, seq);
        let (head, rest) = sealed
            .split_at_mut_checked(HEADER_LEN)
            .ok_or(EncSealError::Aead)?;
        head.copy_from_slice(&header);
        let (body, tag_slot) = rest
            .split_at_mut_checked(plaintext)
            .ok_or(EncSealError::Aead)?;
        if let Some(pairwise) = self.pairwise.first().and_then(Option::as_ref) {
            let epoch_end = frames.saturating_add(4);
            let (covered, trailer) = body
                .split_at_mut_checked(epoch_end)
                .ok_or(EncSealError::Aead)?;
            if let Some(slot) = covered.get_mut(frames..) {
                slot.copy_from_slice(&pairwise.epoch.to_le_bytes());
            }
            let tag = pairwise.tag(&header, covered);
            if let Some(value) = tag.get(..PAIRWISE_TAG_LEN) {
                trailer.copy_from_slice(value);
            }
        }
        let aad = associated_data(&header);
        let nonce = Nonce::from(Self::nonce(self.context.domain, seq));
        let tag = self
            .aead
            .encrypt_inout_detached(&nonce, &aad, InOutBuf::from(body))
            .map_err(|_| EncSealError::Aead)?;
        tag_slot.copy_from_slice(tag.as_slice());
        Ok(total)
    }

    /// Checks everything that precedes the open, in the order of section 8
    /// steps 1 to 3 and 5. Changes nothing. Returns the sequence and the
    /// plaintext length.
    fn precheck(&self, datagram: &[u8]) -> Result<(u64, usize), EncRejection> {
        let field = |at: usize, width: usize| -> &[u8] {
            datagram
                .get(at..at.saturating_add(width))
                .unwrap_or_default()
        };
        let byte = |at: usize| datagram.get(at).copied().unwrap_or_default();
        let frame_type = field(6, 2)
            .try_into()
            .map(u16::from_le_bytes)
            .map_err(|_| EncRejection::Short)?;
        classify_outer(frame_type)?;
        if datagram.len() < ENVELOPE_LEN {
            return Err(EncRejection::Short);
        }
        if datagram.len() > MAX_DATAGRAM {
            return Err(EncRejection::TooLong);
        }
        let declared = field(0, 4)
            .try_into()
            .map(i32::from_le_bytes)
            .map_err(|_| EncRejection::Short)?;
        match usize::try_from(declared) {
            Ok(declared) if declared == datagram.len() => {}
            Ok(declared) if declared >= ENVELOPE_LEN && declared < datagram.len() => {
                return Err(EncRejection::MixedClass);
            }
            _ => return Err(EncRejection::Length),
        }
        if byte(4) != VERSION {
            return Err(EncRejection::Version);
        }
        if byte(5) != 0 {
            return Err(EncRejection::Flags);
        }
        if byte(8) != PROFILE_ID {
            return Err(EncRejection::Profile);
        }
        if usize::from(byte(9)) != TAG_LEN {
            return Err(EncRejection::TagLength);
        }
        if Domain::from_byte(byte(10)) != Some(self.context.domain) {
            return Err(EncRejection::Domain);
        }
        if byte(11) != 0 || field(18, 2) != [0, 0] {
            return Err(EncRejection::Reserved);
        }
        let key_epoch = field(12, 4)
            .try_into()
            .map(u32::from_le_bytes)
            .map_err(|_| EncRejection::Short)?;
        let party_epoch = field(16, 2)
            .try_into()
            .map(u16::from_le_bytes)
            .map_err(|_| EncRejection::Short)?;
        if key_epoch != self.context.key_epoch || party_epoch != self.context.party_epoch {
            return Err(EncRejection::Epoch);
        }
        let int = |at: usize| {
            field(at, 4)
                .try_into()
                .map(i32::from_le_bytes)
                .map_err(|_| EncRejection::Short)
        };
        if int(20)? != self.context.session_id || int(24)? != self.context.stream_id {
            return Err(EncRejection::Binding);
        }
        let party = field(36, 32);
        if self.context.domain.is_receiver() && party.get(24..) != Some(&[0_u8; 8][..]) {
            return Err(EncRejection::Reserved);
        }
        if party != self.party {
            return Err(EncRejection::Party);
        }
        let seq = field(28, 8)
            .try_into()
            .map(u64::from_le_bytes)
            .map_err(|_| EncRejection::Short)?;
        if seq >= self.context.domain.seq_cap() {
            return Err(EncRejection::SequenceCap);
        }
        self.lock().check(seq)?;
        let plaintext = datagram
            .len()
            .checked_sub(ENVELOPE_LEN)
            .ok_or(EncRejection::Short)?;
        if plaintext < self.trailer_len() {
            return Err(EncRejection::Pairwise);
        }
        Ok((seq, plaintext))
    }

    /// Checks the pairwise trailer of a verified plaintext (section 4).
    fn check_trailer(&self, header: &[u8], plaintext: &[u8]) -> Result<Option<u32>, EncRejection> {
        if !self.context.domain.is_receiver() {
            return Ok(None);
        }
        let covered_len = plaintext
            .len()
            .checked_sub(PAIRWISE_TAG_LEN)
            .ok_or(EncRejection::Pairwise)?;
        let (covered, tag) = plaintext
            .split_at_checked(covered_len)
            .ok_or(EncRejection::Pairwise)?;
        let epoch = covered
            .get(covered_len.saturating_sub(4)..)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u32::from_le_bytes)
            .ok_or(EncRejection::Pairwise)?;
        let key = self
            .pairwise
            .iter()
            .flatten()
            .find(|key| key.epoch == epoch)
            .ok_or(EncRejection::Pairwise)?;
        if key.verify(header, covered, tag) {
            Ok(Some(epoch))
        } else {
            Err(EncRejection::Pairwise)
        }
    }

    /// Opens `datagram` in place: every field, the sequence cap and the
    /// replay precheck, then the AEAD (verify and decrypt), then the
    /// pairwise trailer. On success the inner frames are plaintext at
    /// `start`; on any rejection `datagram` holds its received bytes again
    /// and no state changes. Allocates nothing.
    ///
    /// # Errors
    ///
    /// The first [`EncRejection`] that applies.
    pub fn open_in_place(&self, datagram: &mut [u8]) -> Result<Opened, EncRejection> {
        let (seq, plaintext) = self.precheck(datagram)?;
        let mut header = [0_u8; HEADER_LEN];
        header.copy_from_slice(datagram.get(..HEADER_LEN).ok_or(EncRejection::Short)?);
        let aad = associated_data(&header);
        let nonce = Nonce::from(Self::nonce(self.context.domain, seq));
        let rest = datagram.get_mut(HEADER_LEN..).ok_or(EncRejection::Short)?;
        let (body, tag) = rest
            .split_at_mut_checked(plaintext)
            .ok_or(EncRejection::Short)?;
        let tag = Tag::try_from(&*tag).map_err(|_| EncRejection::Short)?;
        // On failure the crate restores the ciphertext in place.
        self.aead
            .decrypt_inout_detached(&nonce, &aad, InOutBuf::from(&mut *body), &tag)
            .map_err(|_| EncRejection::Tag)?;
        match self.check_trailer(&header, body) {
            Ok(pairwise_epoch) => Ok(Opened {
                start: HEADER_LEN,
                frames: plaintext.saturating_sub(self.trailer_len()),
                seq,
                pairwise_epoch,
            }),
            Err(reason) => {
                // GCM-SIV is deterministic: sealing the verified plaintext
                // again under the same key, nonce and associated data gives
                // back the received ciphertext and tag.
                let _ = self
                    .aead
                    .encrypt_inout_detached(&nonce, &aad, InOutBuf::from(body));
                Err(reason)
            }
        }
    }

    /// Opens `datagram` into `out`, leaving `datagram` untouched. On
    /// success the inner frames are `out[..frames]`; on any rejection `out`
    /// is zeroed (the crate's failed decrypt between two buffers leaves the
    /// unverified plaintext in `out`) and no state changes. Allocates
    /// nothing.
    ///
    /// # Errors
    ///
    /// The first [`EncRejection`] that applies; [`EncRejection::Short`]
    /// when `out` cannot hold the plaintext.
    pub fn open_into(&self, datagram: &[u8], out: &mut [u8]) -> Result<Opened, EncRejection> {
        let (seq, plaintext) = self.precheck(datagram)?;
        let header = datagram.get(..HEADER_LEN).ok_or(EncRejection::Short)?;
        let (body, tag) = datagram
            .get(HEADER_LEN..)
            .and_then(|rest| rest.split_at_checked(plaintext))
            .ok_or(EncRejection::Short)?;
        let tag = Tag::try_from(tag).map_err(|_| EncRejection::Short)?;
        let target = out.get_mut(..plaintext).ok_or(EncRejection::Short)?;
        let aad = associated_data(header.try_into().map_err(|_| EncRejection::Short)?);
        let nonce = Nonce::from(Self::nonce(self.context.domain, seq));
        let buffer = InOutBuf::new(body, &mut *target).map_err(|_| EncRejection::Short)?;
        let result = self
            .aead
            .decrypt_inout_detached(&nonce, &aad, buffer, &tag)
            .map_err(|_| EncRejection::Tag)
            .and_then(|()| self.check_trailer(header, target));
        match result {
            Ok(pairwise_epoch) => Ok(Opened {
                start: HEADER_LEN,
                frames: plaintext.saturating_sub(self.trailer_len()),
                seq,
                pairwise_epoch,
            }),
            Err(reason) => {
                zeroize::Zeroize::zeroize(target);
                Err(reason)
            }
        }
    }

    /// Marks `seq` in the replay window after inner batch validation
    /// (section 8 step 8): the check and the mark are one atomic operation,
    /// so two copies of one datagram cannot both pass.
    ///
    /// # Errors
    ///
    /// [`EncRejection::SequenceCap`], [`EncRejection::Duplicate`] or
    /// [`EncRejection::TooOld`]; nothing changes.
    pub fn mark(&self, seq: u64) -> Result<(), EncRejection> {
        if seq >= self.context.domain.seq_cap() {
            return Err(EncRejection::SequenceCap);
        }
        self.lock().accept(seq).map_err(EncRejection::from)
    }
}

/// The outer frame type check of section 9: only `0x21` passes; the
/// downgrade cases are told apart.
///
/// # Errors
///
/// [`EncRejection::WrongClass`], [`EncRejection::PlaintextSetup`],
/// [`EncRejection::BareFrame`] or [`EncRejection::FrameType`].
pub fn classify_outer(frame_type: u16) -> Result<(), EncRejection> {
    use crate::frame::FrameType;
    if frame_type == FRAME_TYPE {
        return Ok(());
    }
    if frame_type == super::hmac_sha256::FRAME_TYPE {
        return Err(EncRejection::WrongClass);
    }
    match FrameType::try_from_code(frame_type) {
        Ok(FrameType::Setup | FrameType::RspSetup) => Err(EncRejection::PlaintextSetup),
        Ok(_) => Err(EncRejection::BareFrame),
        Err(_) => Err(EncRejection::FrameType),
    }
}

/// `label || header`.
fn associated_data(header: &[u8; HEADER_LEN]) -> [u8; 20 + HEADER_LEN] {
    let mut out = [0_u8; 20 + HEADER_LEN];
    put(&mut out, 0, LABEL);
    put(&mut out, 20, header);
    out
}

/// Copies `bytes` into `out` at `at`, when they fit.
fn put(out: &mut [u8], at: usize, bytes: &[u8]) {
    if let Some(slot) = out.get_mut(at..at.saturating_add(bytes.len())) {
        slot.copy_from_slice(bytes);
    }
}

impl Protection for AesGcmSiv {
    /// The header and the tag; receiver domains add [`TRAILER_LEN`] inside
    /// the plaintext ([`AesGcmSiv::overhead`]).
    fn envelope_len(&self) -> usize {
        self.overhead()
    }

    /// Seals with the next envelope sequence. A refusal other than a short
    /// buffer is reported with `needed == usize::MAX`: the party rolls its
    /// epoch, or the incarnation closes.
    fn seal(&self, datagram: &mut [u8], frames: usize) -> Result<usize, SealError> {
        let available = datagram.len();
        self.seal_next(datagram, frames)
            .map_err(|error| match error {
                EncSealError::Buffer(error) => error,
                _ => SealError {
                    needed: usize::MAX,
                    available,
                },
            })
    }

    /// Verifies the datagram without releasing plaintext: it decrypts into
    /// an erased stack buffer and discards it. An accepted datagram's
    /// frames are still ciphertext at `start`; a receiver reads them through
    /// [`AesGcmSiv::open_in_place`] or [`AesGcmSiv::open_into`]. Marks no
    /// sequence.
    fn open(&self, datagram: &[u8]) -> Verdict {
        let mut scratch = Zeroizing::new([0_u8; MAX_PLAINTEXT]);
        match self.open_into(datagram, scratch.as_mut_slice()) {
            Ok(opened) => Verdict::Accept {
                start: opened.start,
                frames: opened.frames,
            },
            Err(reason) => Verdict::Reject(reason.into()),
        }
    }
}

#[cfg(test)]
mod tests;
