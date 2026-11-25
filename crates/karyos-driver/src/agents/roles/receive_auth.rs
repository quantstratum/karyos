// SPDX-License-Identifier: Apache-2.0

//! The wire authentication of an image's receive side, unicast
//! (`quantstratum-docs:
//! karyos/adr/0086-wire-authentication-profile-v1.md` sections 2, 4, 6
//! and 7a; part of quantstratum/karyos#648).
//!
//! An authenticated image opens every datagram of its binding with its
//! domain 1 [`Verifier`] before any inner frame is read, and seals every
//! control it sends (SM, NAK, RTTM REQUEST) with its domain 4 [`Sealer`].
//! A refused datagram changes nothing but a counter; a bare frame for an
//! authenticated binding is refused, and an envelope for no authenticated
//! binding is refused. Nothing makes an image authenticated yet: whether a
//! channel is authenticated comes from its configuration bound at
//! establishment, and `authenticated` channels are still refused.

use karyos_protocol::network::Alias;
use karyos_protocol::protection::hmac_sha256::{Domain, FRAME_TYPE};

use karyos_protocol::protection::Rejection;
use karyos_protocol::protection::hmac_sha256::Opened;
use karyos_protocol::protection::replay::Replay;

use super::super::control::{ControlSeal, SharedSealer};
use crate::wire_auth::{Checked, KeyError, KeySet, Party, Refusal, Sealer, Verifier};
use crate::wire_keys::KeyFile;

/// Why a received datagram was refused, one counter each (ADR-0086
/// section 2: per key and source, by reason).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum AuthReason {
    /// Shorter than the envelope.
    Short = 0,
    /// `datagram_length` is not the datagram's length.
    Length,
    /// Another envelope version.
    Version,
    /// Nonzero flags.
    Flags,
    /// Another frame type.
    FrameType,
    /// Another profile.
    Profile,
    /// Another tag length.
    TagLength,
    /// Another domain.
    Domain,
    /// No key of its party epoch.
    Epoch,
    /// Another session or stream.
    Binding,
    /// An unknown `key_id`.
    Key,
    /// A tag that does not verify.
    Tag,
    /// A sequence already accepted.
    Duplicate,
    /// A sequence older than the window.
    TooOld,
    /// It opened, but its inner frames are not a datagram of its own
    /// binding and domain: its sequence is not consumed.
    Inner,
    /// An RSP_SETUP of a boot id already bound under another nonce: it
    /// would move the session key (ADR-0086 section 7, publisher rule).
    Rebind,
    /// An RSP_SETUP of a retired boot id.
    Retired,
    /// An RSP_SETUP that verified only under the previous file epoch.
    PreviousEpoch,
    /// An RSP_SETUP of a new boot id with no room left to retire the old.
    Full,
    /// An RSP_SETUP of another receiver than the publication's single one.
    OtherReceiver,
    /// An envelope for no authenticated binding.
    Unbound,
}

/// Reasons a datagram is refused for.
pub const AUTH_REASONS: usize = AuthReason::Unbound as usize + 1;

impl AuthReason {
    /// The reason of `refusal`.
    #[must_use]
    pub fn of(refusal: Refusal) -> Self {
        match refusal {
            Refusal::Envelope(rejection) => match rejection {
                Rejection::Short => Self::Short,
                Rejection::Length => Self::Length,
                Rejection::Version => Self::Version,
                Rejection::Flags => Self::Flags,
                Rejection::FrameType => Self::FrameType,
                Rejection::Profile => Self::Profile,
                Rejection::TagLength => Self::TagLength,
                Rejection::Domain => Self::Domain,
                Rejection::Epoch => Self::Epoch,
                Rejection::Binding => Self::Binding,
                Rejection::Key => Self::Key,
                Rejection::Tag => Self::Tag,
            },
            Refusal::Replay(Replay::Duplicate) => Self::Duplicate,
            Refusal::Replay(Replay::TooOld) => Self::TooOld,
        }
    }
}

/// Refusals by reason: fixed, saturating, allocation free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AuthRejections {
    counts: [u64; AUTH_REASONS],
}

impl AuthRejections {
    /// Counts one refusal for `reason`.
    pub fn bump(&mut self, reason: AuthReason) {
        if let Some(count) = self.counts.get_mut(reason as usize) {
            *count = count.saturating_add(1);
        }
    }

    /// The refusals for `reason`.
    #[cfg(test)]
    #[must_use]
    pub fn get(&self, reason: AuthReason) -> u64 {
        self.counts.get(reason as usize).copied().unwrap_or(0)
    }

    /// Every reason's count, by [`AuthReason`] value.
    #[cfg(test)]
    #[must_use]
    pub fn counts(&self) -> [u64; AUTH_REASONS] {
        self.counts
    }
}

/// An authenticated image's keys: the sender's datagrams are opened in
/// domain 1, its own controls sealed in domain 4.
#[derive(Debug)]
pub(crate) struct ImageAuth {
    verifier: Verifier,
    sealer: SharedSealer,
    /// The `key_id` and file epoch of its sealer's pairwise key.
    sealer_key: (u32, u32),
    /// Its sealer was withdrawn by a key reload: it sends nothing until
    /// the image is established again.
    withdrawn: bool,
    /// Its binding's refusals: one key and one source, by reason.
    pub(crate) rejections: AuthRejections,
    /// The monotonic clock in nanoseconds, for the in-band epoch overlap
    /// (H8 finding 7: never the wall clock).
    clock: fn() -> u64,
}

/// An authenticated subscription's keys (ADR-0086 sections 4 and 7a):
/// the channel's SETUP proof verifies its publishers' SETUP ANNOUNCE and
/// ANSWER (domain 5), its pairwise key's RSP_SETUP proof seals its
/// CHALLENGEs and SOLICITs (domain 6), and each image it installs derives
/// its domain 1 verifier and domain 4 sealer from the prototypes here.
#[derive(Debug)]
pub(crate) struct SubscriptionAuth {
    pub(crate) endpoint: crate::agents::EndpointId,
    pub(crate) stream_id: i32,
    /// Verify only, rebound to each SETUP's alias.
    setup: crate::wire_auth::Proof,
    /// Signing, rebound to each RSP_SETUP's alias.
    rsp: crate::wire_auth::Proof,
    /// The channel key's domain 1 verifier for no establishment yet.
    sender: Verifier,
    /// The pairwise key's domain 4 sealer for no boot id yet; withdrawn
    /// while a key reload leaves no pairwise signing key: no image
    /// installs until a later reload names one again.
    receiver: Sealer,
    /// Its refusals by reason: the SETUPs of its stream.
    pub(crate) rejections: AuthRejections,
}

impl SubscriptionAuth {
    /// The keys of the subscription to `stream_id` on `endpoint` as
    /// `receiver_id`: `channel` the channel key files (verify), `pairwise`
    /// the pairwise signing key. `alias` is any alias of the stream: the
    /// SETUP and RSP_SETUP proofs take only its stream, and an image
    /// derives its own keys for its session.
    ///
    /// # Errors
    ///
    /// [`KeyError`] when a file does not fit its purpose.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "no authenticated channel opens yet")
    )]
    pub(crate) fn new(
        endpoint: crate::agents::EndpointId,
        alias: Alias,
        channel: &KeyFile,
        pairwise: &KeyFile,
        receiver_id: u64,
    ) -> Result<Self, KeyError> {
        use crate::wire_auth::{Proof, ProofKind};

        let none = [0u64; 2];
        let identity = karyos_protocol::network::Identity {
            driver_id: none,
            registration_id: 0,
            incarnation: 0,
        };
        let setup = Proof::new(ProofKind::Setup, alias, None, [channel], channel.file_epoch)?;
        let rsp = Proof::new(
            ProofKind::RspSetup { receiver_id },
            alias,
            Some(pairwise),
            [pairwise],
            pairwise.file_epoch,
        )?;
        let sender = Verifier::new(
            [channel],
            Party::Sender {
                identity,
                lane_count: 1,
                receiver_boot_id: none,
                nonce: none,
            },
            alias,
        )?;
        let receiver = Sealer::new(
            pairwise,
            Party::Receiver {
                identity,
                receiver_boot_id: none,
                receiver_id,
            },
            alias,
        )?;
        Ok(Self {
            endpoint,
            stream_id: alias.stream_id,
            setup,
            rsp,
            sender,
            receiver,
            rejections: AuthRejections::default(),
        })
    }

    /// Applies the store's current key set (H8 finding 4): the SETUP and
    /// RSP_SETUP proofs and the domain 1 prototype take the files that now
    /// sign and verify, and the domain 4 prototype is re-keyed under the
    /// pairwise signing key, or withdrawn while there is none, so no image
    /// installs.
    pub(crate) fn apply_keys(&mut self, keys: &dyn KeySet) {
        self.setup.apply(keys);
        self.rsp.apply(keys);
        self.sender.apply(keys);
        let signing = keys.signing(self.receiver.key_ref().0);
        if self.receiver.signs_under(signing) {
            return;
        }
        match signing.map(|file| self.receiver.rekeyed(file)) {
            Some(Ok(rekeyed)) => self.receiver = rekeyed,
            Some(Err(_)) | None => self.receiver.withdraw(),
        }
    }

    /// Checks a SETUP ANNOUNCE or ANSWER envelope on `alias` under the
    /// channel's SETUP proof (domain 5); changes nothing.
    ///
    /// # Errors
    ///
    /// The [`Rejection`].
    pub(crate) fn verify_setup(
        &self,
        alias: Alias,
        datagram: &[u8],
    ) -> Result<crate::wire_auth::Proved, Rejection> {
        self.setup.for_alias(alias).verify(datagram)
    }

    /// The sealer of a CHALLENGE or SOLICIT on `alias` (domain 6).
    pub(crate) fn rsp_sealer(&self, alias: Alias) -> SharedSealer {
        SharedSealer::proof(self.rsp.for_alias(alias))
    }

    /// The keys of an image of this subscription on `alias`, for its
    /// domain 1 `sender` and domain 4 `receiver` parties.
    ///
    /// # Errors
    ///
    /// [`KeyError::Scope`] for a receiver id other than the pairwise
    /// key's: the image is then not installed (fail closed).
    pub(crate) fn image(
        &self,
        alias: Alias,
        sender: Party,
        receiver: Party,
    ) -> Result<ImageAuth, KeyError> {
        if !self.receiver.can_seal() {
            return Err(KeyError::NoKey);
        }
        let prototype = &self.receiver;
        let verifier = self.sender.with_party(sender, alias)?;
        let sealer = prototype.with_party(receiver, alias)?;
        Ok(ImageAuth {
            verifier,
            sealer_key: sealer.key_ref(),
            sealer: SharedSealer::new(sealer),
            withdrawn: false,
            rejections: AuthRejections::default(),
            clock: monotonic_ns,
        })
    }
}

impl ImageAuth {
    /// The keys of an image whose publication is `sender` (a
    /// [`Party::Sender`]) and whose receiver is `receiver` (a
    /// [`Party::Receiver`]) on `alias`: the channel key files `channel`
    /// verify the sender's datagrams, the pairwise signing key `pairwise`
    /// seals the receiver's controls.
    ///
    /// # Errors
    ///
    /// [`KeyError`] when a party is of the wrong kind or a file does not
    /// fit its party.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "no authenticated channel opens yet")
    )]
    pub(crate) fn new<'a>(
        channel: impl IntoIterator<Item = &'a KeyFile>,
        pairwise: &KeyFile,
        sender: Party,
        receiver: Party,
        alias: Alias,
    ) -> Result<Self, KeyError> {
        if !matches!(sender, Party::Sender { .. }) || !matches!(receiver, Party::Receiver { .. }) {
            return Err(KeyError::Purpose);
        }
        let verifier = Verifier::new(channel, sender, alias)?;
        let sealer = Sealer::new(pairwise, receiver, alias)?;
        if sealer.domain() != Domain::ReceiverToPublisher {
            return Err(KeyError::Purpose);
        }
        Ok(Self {
            verifier,
            sealer_key: sealer.key_ref(),
            sealer: SharedSealer::new(sealer),
            withdrawn: false,
            rejections: AuthRejections::default(),
            clock: monotonic_ns,
        })
    }

    /// Uses `clock` as the monotonic clock in nanoseconds (tests).
    #[cfg(test)]
    pub(crate) fn set_clock(&mut self, clock: fn() -> u64) {
        self.clock = clock;
    }

    /// The monotonic reading one datagram is checked and committed at.
    pub(crate) fn now(&self) -> u64 {
        (self.clock)()
    }

    /// Applies the store's current key set (H8 finding 4): the domain 1
    /// verifier keeps the windows of the channel file epochs that still
    /// verify and erases the rest, and an expired previous in-band epoch
    /// is erased. The domain 4 sealer, shared with the sender agent and
    /// any cached SESSION_ABORT_ACK, follows [`crate::wire_auth::key_move`]
    /// for every holder at once: on a routine rotation it moves to the new
    /// pairwise signing file under the same establishment; once its file
    /// is revoked, expired or no longer verifies (or the store is
    /// disabled) it is withdrawn and stays withdrawn: the image sends
    /// nothing until it is established again (fail closed).
    pub(crate) fn apply_keys(&mut self, keys: &dyn KeySet) {
        use crate::wire_auth::{KeyMove, key_move};

        self.verifier.apply(keys);
        self.verifier.tick(self.now());
        if self.withdrawn {
            return;
        }
        match key_move(self.sealer_key, keys) {
            KeyMove::Keep => {}
            KeyMove::Rekey(file) => {
                self.sealer.rekey(file);
                self.sealer_key = (file.key_id, file.file_epoch);
            }
            KeyMove::Withdraw => {
                self.sealer.withdraw();
                self.withdrawn = true;
            }
        }
    }

    /// The `key_id` and file epoch its domain 4 sealer is under (tests).
    #[cfg(test)]
    pub(crate) fn sealer_key(&self) -> (u32, u32) {
        self.sealer_key
    }

    /// Whether its sealer was withdrawn by a key reload.
    #[cfg(test)]
    pub(crate) fn withdrawn(&self) -> bool {
        self.withdrawn
    }

    /// Checks `datagram`'s fields, tag and replay window at `now`; changes
    /// nothing. Allocates nothing.
    ///
    /// # Errors
    ///
    /// The [`Refusal`].
    pub(crate) fn check(&self, datagram: &[u8], now: u64) -> Result<Checked, Refusal> {
        self.verifier.check(datagram, now)
    }

    /// Records a checked datagram its caller accepts: its sequence, and any
    /// in-band epoch move.
    ///
    /// # Errors
    ///
    /// The [`Refusal`]; nothing changes.
    pub(crate) fn commit(&mut self, checked: Checked, now: u64) -> Result<Opened, Refusal> {
        self.verifier.commit(checked, now)
    }

    /// The sealer of the image's controls: shared, allocation free.
    pub(crate) fn sealer(&self) -> SharedSealer {
        self.sealer.clone()
    }
}

/// Whether `bytes` starts like a wire authentication envelope: its frame
/// type field (bytes 6 to 8, little-endian) names the envelope.
pub(crate) fn is_envelope(bytes: &[u8]) -> bool {
    bytes
        .get(6..8)
        .is_some_and(|field| field == FRAME_TYPE.to_le_bytes())
}

/// The binding alias an envelope names (its `session_id` and `stream_id`
/// at offsets 12 and 16), read only to find the binding whose key opens
/// it; `None` for a datagram too short to hold them.
pub(crate) fn envelope_alias(bytes: &[u8]) -> Option<Alias> {
    let session_id = i32::from_le_bytes(bytes.get(12..16)?.try_into().ok()?);
    let stream_id = i32::from_le_bytes(bytes.get(16..20)?.try_into().ok()?);
    Some(Alias {
        session_id,
        stream_id,
    })
}

/// The process's monotonic clock in nanoseconds, for the in-band epoch
/// overlap (H8 finding 7): a wall clock correction never moves it back.
/// After about 584 years it reads the last tick, which ends every overlap.
pub(crate) fn monotonic_ns() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(std::time::Instant::now);
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// The authorities of the signed domains a key set names (H8 finding 4):
/// for each configured `key_id` in `applied`, the highest file that now
/// verifies, as an [`crate::signed_control::Authority`]. Returns the new
/// list only when it differs from the one `applied` records, which it then
/// updates; a key no longer named, or a file that is no authority key, is
/// left out (fail closed).
pub(crate) fn authorities_for(
    keys: &dyn KeySet,
    applied: &mut [(u32, Option<u32>)],
) -> Option<Vec<crate::signed_control::Authority>> {
    let mut changed = false;
    let mut authorities = Vec::with_capacity(applied.len());
    for (key_id, epoch) in applied.iter_mut() {
        let file = keys
            .verifying(*key_id)
            .into_iter()
            .flatten()
            .max_by_key(|file| file.file_epoch);
        let authority = file.and_then(|file| {
            crate::signed_control::Authority::from_file(file)
                .ok()
                .map(|authority| (file.file_epoch, authority))
        });
        let now = authority.as_ref().map(|(epoch, _)| *epoch);
        if now != *epoch {
            changed = true;
            *epoch = now;
        }
        authorities.extend(authority.map(|(_, authority)| authority));
    }
    changed.then_some(authorities)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use karyos_protocol::network::{Alias, Identity};

    use super::super::super::control::ControlSeal;
    use super::{ImageAuth, authorities_for};
    use crate::wire_auth::{ENVELOPE_LEN, FixedKeys, Party, Sealer};
    use crate::wire_keys::KeyFile;

    const ALIAS: Alias = Alias {
        session_id: 5,
        stream_id: 6,
    };

    const IDENTITY: Identity = Identity {
        driver_id: [1, 2],
        registration_id: 3,
        incarnation: 1,
    };

    fn channel(epoch: u32) -> KeyFile {
        crate::wire_keys::parse(
            &format!("3-{epoch}.key"),
            format!("format=karyos-wire-key-v1\nkey_id=3\nfile_epoch={epoch}\npurpose=channel\nprofile_id=1\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret=1111111111111111111111111111111111111111111111111111111111111111\nchannel_id=7\nstream_id=6\n").as_bytes(),
        )
        .unwrap()
    }

    fn pairwise(epoch: u32) -> KeyFile {
        crate::wire_keys::parse(
            &format!("9-{epoch}.key"),
            format!("format=karyos-wire-key-v1\nkey_id=9\nfile_epoch={epoch}\npurpose=pairwise\nprofile_id=1\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret=2222222222222222222222222222222222222222222222222222222222222222\nreceiver_id=66\npublisher_id=5\n").as_bytes(),
        )
        .unwrap()
    }

    const SENDER: Party = Party::Sender {
        identity: IDENTITY,
        lane_count: 1,
        receiver_boot_id: [7, 8],
        nonce: [9, 9],
    };

    const RECEIVER: Party = Party::Receiver {
        identity: IDENTITY,
        receiver_boot_id: [7, 8],
        receiver_id: 66,
    };

    fn image() -> ImageAuth {
        let mut auth =
            ImageAuth::new([&channel(1)], &pairwise(1), SENDER, RECEIVER, ALIAS).unwrap();
        auth.set_clock(|| 1_000);
        auth
    }

    fn sealed(sealer: &mut Sealer) -> Vec<u8> {
        let mut bytes = vec![0u8; 8 + ENVELOPE_LEN];
        let length = sealer.seal(&mut bytes, 8).unwrap();
        bytes.truncate(length);
        bytes
    }

    /// H8 finding 4: once its pairwise file no longer signs (a reload that
    /// rotated or revoked it, or a disabled store), an image's sealer is
    /// withdrawn for every holder: a clone kept elsewhere, as a cached
    /// SESSION_ABORT_ACK resend keeps one, seals nothing either, and it
    /// stays withdrawn when the key returns.
    #[test]
    fn a_reload_withdraws_an_images_sealer_for_every_holder() {
        let mut auth = image();
        let mut held = auth.sealer();
        let mut buffer = [0u8; 8 + ENVELOPE_LEN];
        assert!(held.seal_control(&mut buffer, 8).is_some());
        // The same key set: nothing changes.
        auth.apply_keys(&FixedKeys {
            files: vec![channel(1), pairwise(1)],
        });
        assert!(!auth.withdrawn());
        assert!(held.seal_control(&mut buffer, 8).is_some());
        // Epoch 1 revoked while epoch 2 signs: it no longer verifies.
        auth.apply_keys(&FixedKeys {
            files: vec![channel(1), pairwise(2)],
        });
        assert!(auth.withdrawn());
        assert!(held.seal_control(&mut buffer, 8).is_none());
        assert!(auth.sealer().seal_control(&mut buffer, 8).is_none());
        auth.apply_keys(&FixedKeys {
            files: vec![channel(1), pairwise(1)],
        });
        assert!(held.seal_control(&mut buffer, 8).is_none());
    }

    /// H8 finding 4: a disabled store names no key: the image's verifier
    /// verifies nothing and its sealer is withdrawn.
    #[test]
    fn a_disabled_store_stops_an_image() {
        let mut auth = image();
        let mut sender = Sealer::new(&channel(1), SENDER, ALIAS).unwrap();
        let first = sealed(&mut sender);
        let now = auth.now();
        assert!(auth.check(&first, now).is_ok());
        auth.apply_keys(&FixedKeys::default());
        assert!(auth.withdrawn());
        let next = sealed(&mut sender);
        assert!(auth.check(&next, now).is_err());
    }

    /// H8 finding 4: the trusted authorities follow the key set: a key no
    /// longer named is dropped, and an unchanged set asks for no change
    /// (so the digest cache is kept).
    #[test]
    fn the_authorities_follow_the_key_set() {
        let mut applied = vec![(10_u32, Some(1_u32))];
        let changed = authorities_for(&FixedKeys::default(), &mut applied);
        assert_eq!(changed.map(|list| list.len()), Some(0));
        assert_eq!(applied, vec![(10, None)]);
        assert!(authorities_for(&FixedKeys::default(), &mut applied).is_none());
    }
}
