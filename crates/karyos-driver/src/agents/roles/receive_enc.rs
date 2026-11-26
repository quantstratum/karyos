// SPDX-License-Identifier: Apache-2.0

//! The `encrypted` class on an image's receive side, unicast
//! (`quantstratum-docs: karyos/adr/0114-encrypted-protection-profile-v1.md`
//! sections 2, 4, 6a, 8 and 9; part of quantstratum/karyos#650 and #651).
//!
//! An encrypted subscription opens its publishers' SETUP ANNOUNCE and ENC
//! ANSWER in domain 5 under a scratch derivation from the header's identity
//! block, and seals its CHALLENGEs in domain 6 with its pairwise trailer.
//! The image an ENC ANSWER installs opens every DATA datagram of its
//! binding with its committed domain 1 keys, starting at the epoch pair the
//! answer states, and seals its SM, NAK and RTTM REQUEST in domain 4.
//!
//! Downgrade (section 9): the class comes from the subscription's
//! configuration, never from a datagram. On an encrypted stream a bare
//! frame, an authenticated envelope or a plaintext SETUP is dropped before
//! anything parses it, each counted with its own reason, and a plaintext
//! SETUP reaches no challenge. Every RSP_SETUP of an encrypted
//! subscription, CHALLENGE and SOLICIT alike, goes sealed in domain 6 with
//! its pairwise trailer under the target publication's key.
//!
//! Resynchronisation (section 6b): a bound image that sees a datagram more
//! than one epoch ahead starts one challenge for its binding and sends a
//! SOLICIT in domain 6; the ENC ANSWER that echoes that challenge before
//! expiry, verifies under the current file epoch, names the bound identity
//! and term parameters and states an epoch pair not lower than the bound
//! one moves the binding's domain 1 keys to that pair, with an empty
//! window and the previous context kept for the 10 s overlap. Its join
//! points are ignored and the unicast salt stays. Any other answer for a
//! bound identity is dropped and counted (`enc_resync_refused`).
//!
//! VM generation change (section 10): once the signal is seen, every
//! image's domain 1 keys, every pending answer and every domain 6 sealer
//! are dropped and each image's domain 4 sealer is replaced by one that
//! refuses; the subscriptions stay, so their streams keep refusing bare
//! frames, and every envelope is dropped and counted
//! (`enc_vm_generation`).
//!
//! An outer `0x21` on a stream that is not
//! encrypted is dropped and counted (`enc_unexpected`). A subscription is
//! made encrypted by its admission binding (`Binding::EncSubscription`).

use std::net::SocketAddr;

use karyos_protocol::network::encrypted::{EncAnswer, EncSetup, decode_setup};
use karyos_protocol::network::{
    Alias, ChallengeBlock, Control, Datagram, Identity, RspSolicit, TermParams, classify,
};
use karyos_protocol::protection::aes_gcm_siv::{
    AesGcmSiv, Domain, EncRejection, KeyContext, MAX_PLAINTEXT, PublicationIdentity,
    ReceiverIdentity, Salt, classify_outer,
};
use karyos_protocol::protection::hmac_sha256::Domain as ControlDomain;

use karyos_sys::receive::ValidatedDatagram;

use super::super::control::{ControlItem, ControlSeal, SealedBytes, SharedSealer};
use super::{BindingKey, Intake, ReceiverRole, SessionEnd, SlotRef, sender_frame_alias};
use crate::agents::EndpointId;
use crate::embedded::StreamTerms;
use crate::sessions::NonceSource;
use crate::wire_enc::vm_generation;
use crate::wire_enc::{
    ChannelKeys, EncChannel, EncKeyError, EncOpener, EncRejections, EncSealer, PairwiseFiles,
    VmGenerationWatch, check_resync, header, id128, identity_of, is_envelope, monotonic_ns,
    open_bootstrap_in, publication_of, quiesced,
};
use crate::wire_keys::KeyFile;

/// Entries of the role's bounded SETUP bookkeeping: the ENC ANSWERs being
/// installed and the (alias, publication) pairs a verified domain 5 SETUP
/// named; the oldest gives way (H8-02).
pub(crate) const RSP_TARGETS: usize = 8;

/// Domain 6 sealers a receiver role keeps for one `receiver_boot_id`
/// (H8-01): each bootstrap key, fixed by its key id, receiver id, target
/// publication, alias and boot id, has one counter for the whole boot,
/// whatever happens to the subscription that made it, so it is never made
/// twice. Preallocated at the first encrypted subscription; when it is
/// full no further target is challenged until the boot id is redrawn
/// (fail closed). 64 is eight targets for each of eight subscriptions,
/// the bound one subscription had before.
pub(crate) const RSP_SEALERS: usize = 64;

/// How long a resynchronisation challenge stays answerable: the default
/// `setup_challenge_timeout` of the session table, 1 s (SPEC.md section 5
/// challenge lifecycle; ADR-0114 section 6b step 1).
pub(crate) const RESYNC_CHALLENGE_TIMEOUT_NS: u64 = 1_000_000_000;

/// The encrypted sealers ride the control path's [`SharedSealer`]: their
/// domains carry the ADR-0086 numbers, which ADR-0114 keeps.
impl ControlSeal for EncSealer {
    fn domain(&self) -> ControlDomain {
        match EncSealer::domain(self) {
            Domain::Sender => ControlDomain::Data,
            Domain::Receiver => ControlDomain::ReceiverToPublisher,
            Domain::Setup => ControlDomain::SetupProof,
            Domain::RspSetup => ControlDomain::RspSetup,
        }
    }

    fn seal_control(&mut self, buffer: &mut [u8], frames: usize) -> Option<usize> {
        self.seal(buffer, frames).ok()
    }

    fn withdraw(&mut self) {
        EncSealer::withdraw(self);
    }

    #[cfg(test)]
    fn roll_for_test(&mut self) {
        self.roll_now();
    }

    fn apply_keys(&mut self, keys: &dyn crate::wire_auth::KeySet) {
        EncSealer::apply_keys(self, keys);
    }
}

/// A control an encrypted subscription cannot seal: it is refused, never
/// sent bare (a SOLICIT before the target's identity is verified).
#[derive(Debug)]
pub(crate) struct Refuse(pub(crate) ControlDomain);

impl ControlSeal for Refuse {
    fn domain(&self) -> ControlDomain {
        self.0
    }

    fn seal_control(&mut self, _: &mut [u8], _: usize) -> Option<usize> {
        None
    }

    /// It holds no key and seals nothing.
    fn withdraw(&mut self) {}

    fn apply_keys(&mut self, _: &dyn crate::wire_auth::KeySet) {}
}

/// An encrypted subscription's keys.
#[derive(Debug)]
pub(crate) struct SubscriptionEnc {
    pub(crate) endpoint: EndpointId,
    pub(crate) stream_id: i32,
    keys: ChannelKeys,
    pairwise: PairwiseFiles,
    receiver_id: u64,
    /// The `key_id` of its channel files: with the receiver id, what makes
    /// its domain 6 keys its own (H8-01).
    channel_key_id: u32,
    /// The channel's rate counters and rejections by reason.
    pub(crate) channel: EncChannel,
    /// The scratch slot of its domain 5 opens, made here and re-keyed for
    /// each SETUP: the data path constructs no key.
    bootstrap: Option<AesGcmSiv>,
}

impl SubscriptionEnc {
    /// The keys of the subscription to `stream_id` on `endpoint` as
    /// `receiver_id`: `channel` its `profile_id=16` channel files,
    /// `pairwise` its own pairwise files. A receiver whose configuration
    /// names no pairwise key of its own cannot join (section 4).
    ///
    /// # Errors
    ///
    /// [`EncKeyError`].
    pub(crate) fn new(
        endpoint: EndpointId,
        stream_id: i32,
        channel: &[&KeyFile],
        pairwise: &[&KeyFile],
        receiver_id: u64,
    ) -> Result<Self, EncKeyError> {
        let keys = ChannelKeys::new(channel)?;
        let pairwise = PairwiseFiles::new(pairwise)?;
        if !pairwise.names(receiver_id) {
            return Err(EncKeyError::Receiver);
        }
        // Any valid domain 5 context: every open re-keys it.
        let placeholder = KeyContext {
            domain: Domain::Setup,
            key_epoch: keys.current_epoch(),
            party_epoch: 0,
            session_id: 0,
            stream_id,
            publication: PublicationIdentity {
                driver_id: [1; 16],
                registration_id: 1,
                incarnation: 1,
            },
            receiver: None,
            salt: Salt::Empty,
        };
        let bootstrap = EncSealer::new(&keys, None, placeholder, monotonic_ns)?.into_key();
        let channel_key_id = keys.key_id().ok_or(EncKeyError::Files)?;
        Ok(Self {
            endpoint,
            stream_id,
            keys,
            pairwise,
            receiver_id,
            channel_key_id,
            channel: EncChannel::default(),
            bootstrap: Some(bootstrap),
        })
    }
}

/// One domain 6 sealer of the role's receiver boot (H8-01): everything
/// its key derives from but the file epoch, which the sealer itself
/// follows, and the sealer.
#[derive(Debug)]
struct RspEntry {
    channel_key_id: u32,
    receiver_id: u64,
    publication: PublicationIdentity,
    alias: Alias,
    boot: [u8; 16],
    sealer: SharedSealer,
}

/// The committed domain 1 keys of one encrypted image.
#[derive(Debug)]
struct ImageEnc {
    slot: SlotRef,
    endpoint: EndpointId,
    alias: Alias,
    identity: Identity,
    term: TermParams,
    opener: EncOpener,
    /// The outstanding resynchronisation challenge: its nonce and when it
    /// was sent. At most one per binding.
    resync: Option<([u64; 2], u64)>,
}

/// The encrypted class of a receiver role.
#[derive(Debug, Default)]
pub(crate) struct ReceiverEnc {
    subscriptions: Vec<SubscriptionEnc>,
    images: Vec<ImageEnc>,
    /// The local encrypted publications, by endpoint and alias: their
    /// receivers' envelopes go to the sender undecoded.
    published: Vec<(EndpointId, Alias)>,
    /// The verified ENC ANSWERs whose images are being installed: the
    /// image takes its keys at the stated epochs, or is not installed.
    answers: Vec<(EndpointId, Alias, EncAnswer)>,
    /// The (alias, publication) pairs a verified domain 5 SETUP named, by
    /// endpoint: the only targets a new domain 6 sealer is made for, and
    /// the SOLICIT target of DATA for an alias with no binding. Bounded,
    /// the oldest giving way; an unverified header records nothing
    /// (H8-02).
    verified: Vec<(EndpointId, Alias, PublicationIdentity)>,
    /// The domain 6 sealers of the current `receiver_boot_id`, kept for
    /// the whole boot independently of the subscriptions (H8-01).
    rsp: Vec<RspEntry>,
    /// Refusals no encrypted subscription owns, by reason:
    /// `enc_unexpected` on a trusted or authenticated stream among them.
    pub(crate) unattributed: EncRejections,
    /// The VM generation signal, read once the role has an encrypted
    /// incarnation (section 10).
    watch: Option<VmGenerationWatch>,
    /// The VM generation the role last redrew its identity for.
    seen: u64,
}

impl ReceiverEnc {
    /// The resynchronisation of section 6b for an ENC ANSWER of the bound
    /// identity, from subscription `index`, at `now`: the answer must echo
    /// the binding's outstanding challenge (`boot` and its nonce) before
    /// expiry, which consumes it, verify under the current file epoch
    /// (`current_epoch`, with the envelope's `key_epoch`), name the bound
    /// identity and term parameters, and state a pair not lower than the
    /// bound one. Then the binding's domain 1 keys move to that pair.
    ///
    /// Every condition is checked, and the move prepared, before the
    /// challenge is consumed; the consumption and the move are committed
    /// together, so a refused answer leaves the challenge to the
    /// legitimate one (section 6b, H8-08).
    ///
    /// # Errors
    ///
    /// [`EncRejection::ResyncRefused`]; nothing changes, but an expired
    /// challenge is dropped.
    fn resync(
        &mut self,
        index: usize,
        answer: &EncAnswer,
        envelope_key_epoch: u32,
        current_epoch: bool,
        boot: [u64; 2],
        now: u64,
    ) -> Result<(), EncRejection> {
        let current_key_epoch = self
            .subscriptions
            .get(index)
            .map(|subscription| subscription.keys.current_epoch())
            .ok_or(EncRejection::ResyncRefused)?;
        let image = self
            .images
            .iter_mut()
            .find(|image| image.identity == answer.answer.identity)
            .ok_or(EncRejection::ResyncRefused)?;
        let Some((nonce, sent)) = image.resync else {
            return Err(EncRejection::ResyncRefused);
        };
        if now.saturating_sub(sent) > RESYNC_CHALLENGE_TIMEOUT_NS {
            image.resync = None;
            return Err(EncRejection::ResyncRefused);
        }
        if answer.answer.challenge.receiver_boot_id != boot
            || answer.answer.challenge.nonce != nonce
            || !current_epoch
        {
            return Err(EncRejection::ResyncRefused);
        }
        check_resync(
            (&image.identity, &image.term),
            image.opener.epochs(),
            current_key_epoch,
            answer,
            envelope_key_epoch,
        )?;
        // The opener moves only on success, and only then is the challenge
        // consumed.
        image
            .opener
            .resync(answer.key_epoch, answer.party_epoch, now)?;
        image.resync = None;
        Ok(())
    }

    /// Applies the key store's current key set (H8 finding 4): each
    /// subscription drops the files no longer named, and each of its
    /// domain 6 sealers is withdrawn only once its own key is revoked or
    /// expired; each image's domain 1 opener is withdrawn once its key
    /// epoch is revoked or expired.
    pub(crate) fn apply_keys(&mut self, keys: &dyn crate::wire_auth::KeySet) {
        for subscription in &mut self.subscriptions {
            // Rotation: a newly admitted epoch serves the next bindings,
            // admitted before its predecessor goes.
            subscription.keys.admit(keys);
            subscription.pairwise.admit(keys);
            subscription.keys.retain(keys);
            subscription.pairwise.retain(keys);
            // New sealers take the epoch the key set signs with (H8-06).
            subscription.keys.follow_signing(keys);
        }
        // Each domain 6 sealer follows its own key only, keeping its
        // sequence; a withdrawn one stays in the table as a tombstone, so
        // its (target, key, boot id) is refused and never rebuilt with a
        // sequence restarted at 0 (nonce reuse).
        for entry in &mut self.rsp {
            entry.sealer.apply_keys(keys);
        }
        for image in &mut self.images {
            image.opener.apply_keys(keys);
        }
    }

    /// Makes a subscription encrypted, replacing an earlier one of its
    /// key.
    pub(crate) fn subscribe(&mut self, subscription: SubscriptionEnc) {
        self.unsubscribe(subscription.endpoint, subscription.stream_id);
        // The fixed tables, made once on the control path: the receive
        // path pushes into them without allocating.
        if self.rsp.capacity() < RSP_SEALERS {
            self.rsp
                .reserve_exact(RSP_SEALERS.saturating_sub(self.rsp.len()));
        }
        if self.verified.capacity() < RSP_TARGETS {
            self.verified
                .reserve_exact(RSP_TARGETS.saturating_sub(self.verified.len()));
        }
        self.subscriptions.push(subscription);
    }

    /// Drops the encrypted subscription to `stream_id` on `endpoint`, its
    /// keys erased on drop. Its domain 6 sealers stay with the role for
    /// the boot (H8-01): a subscription made again for the same target
    /// continues their sequences, never restarts them.
    pub(crate) fn unsubscribe(&mut self, endpoint: EndpointId, stream_id: i32) {
        self.subscriptions
            .retain(|sub| (sub.endpoint, sub.stream_id) != (endpoint, stream_id));
        self.verified
            .retain(|(held, alias, _)| (*held, alias.stream_id) != (endpoint, stream_id));
    }

    /// The domain 6 sealer of an RSP_SETUP of the subscription at `index`
    /// to `publication` on `alias` from the boot `boot`: the one the role
    /// made for that key before, whichever subscription made it, or, when
    /// `create` (a target a verified datagram named, H8-02) and the table
    /// has room, a new one under the signing epoch.
    fn rsp_sealer(
        &mut self,
        index: usize,
        publication: PublicationIdentity,
        alias: Alias,
        boot: [u8; 16],
        create: bool,
    ) -> Option<SharedSealer> {
        let subscription = self.subscriptions.get(index)?;
        let (channel_key_id, receiver_id) = (subscription.channel_key_id, subscription.receiver_id);
        if let Some(entry) = self.rsp.iter().find(|entry| {
            entry.channel_key_id == channel_key_id
                && entry.receiver_id == receiver_id
                && entry.publication == publication
                && entry.alias == alias
                && entry.boot == boot
        }) {
            return Some(entry.sealer.clone());
        }
        if !create || self.rsp.len() >= RSP_SEALERS {
            return None;
        }
        let context = KeyContext {
            domain: Domain::RspSetup,
            key_epoch: subscription.keys.signing_epoch()?,
            party_epoch: 0,
            session_id: alias.session_id,
            stream_id: alias.stream_id,
            publication,
            receiver: Some(ReceiverIdentity {
                receiver_boot_id: boot,
                receiver_id,
            }),
            salt: Salt::Empty,
        };
        let sealer = EncSealer::new(
            &subscription.keys,
            Some(&subscription.pairwise),
            context,
            monotonic_ns,
        )
        .ok()?;
        let shared = SharedSealer::of(sealer);
        self.rsp.push(RspEntry {
            channel_key_id,
            receiver_id,
            publication,
            alias,
            boot,
            sealer: shared.clone(),
        });
        Some(shared)
    }

    /// Records that a verified domain 5 SETUP on `endpoint` named
    /// `publication` for `alias`, in the fixed table whose oldest entry
    /// gives way (H8-02).
    fn note_verified(
        &mut self,
        endpoint: EndpointId,
        alias: Alias,
        publication: PublicationIdentity,
    ) {
        self.verified
            .retain(|(held, at, _)| (*held, *at) != (endpoint, alias));
        if self.verified.len() >= RSP_TARGETS {
            self.verified.remove(0);
        }
        self.verified.push((endpoint, alias, publication));
    }

    /// Whether a verified datagram named `publication` for `alias` on
    /// either endpoint: a verified SETUP, or a bound image.
    fn is_verified(
        &self,
        publication: PublicationIdentity,
        alias: Alias,
        first: EndpointId,
        second: EndpointId,
    ) -> bool {
        self.verified.iter().any(|(held, at, named)| {
            (*held == first || *held == second) && *at == alias && *named == publication
        }) || self.images.iter().any(|image| {
            (image.endpoint == first || image.endpoint == second)
                && image.alias == alias
                && publication_of(&image.identity) == publication
        })
    }

    /// Marks the local publication `alias` on `endpoint` encrypted.
    pub(crate) fn publish(&mut self, endpoint: EndpointId, alias: Alias) {
        if !self.published.contains(&(endpoint, alias)) {
            self.published.push((endpoint, alias));
        }
    }

    /// The local publication `alias` on `endpoint` is no longer encrypted
    /// (it went).
    pub(crate) fn unpublish(&mut self, endpoint: EndpointId, alias: Alias) {
        self.published.retain(|held| *held != (endpoint, alias));
    }

    /// The rejections of the encrypted subscription to `stream_id` on
    /// `endpoint`, by reason.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "no encrypted channel opens yet")
    )]
    pub(crate) fn rejections(&self, endpoint: EndpointId, stream_id: i32) -> Option<EncRejections> {
        self.subscriptions
            .iter()
            .find(|sub| sub.endpoint == endpoint && sub.stream_id == stream_id)
            .map(|sub| sub.channel.rejections)
    }

    fn subscription(&self, endpoint: EndpointId, stream_id: i32) -> Option<usize> {
        self.subscriptions
            .iter()
            .position(|sub| sub.endpoint == endpoint && sub.stream_id == stream_id)
    }

    fn published(&self, endpoint: EndpointId, alias: Alias) -> bool {
        self.published.contains(&(endpoint, alias))
    }

    /// Reads the signal with `watch`, the platform's or a test's, and
    /// registers the role with the fence from the current generation on.
    pub(crate) fn watch(&mut self, watch: VmGenerationWatch) {
        if self.watch.is_none() {
            vm_generation::register();
            self.seen = vm_generation::generation();
        }
        self.watch = Some(watch);
    }

    /// Section 10 step 2: drops every derived key and sequence, which
    /// erases them: the images' domain 1 openers, the answers not yet
    /// installed, the verified targets and every scratch slot. Every
    /// domain 6 sealer is withdrawn through its shared object, so a clone
    /// in a queued control is erased with it (H8-09); its entry stays as a
    /// tombstone until the boot id is redrawn ([`Self::redrawn`]). The
    /// subscriptions and their key files stay, so that their streams keep
    /// refusing bare frames and re-establish under the fresh identity.
    fn close(&mut self) {
        self.images.clear();
        self.answers.clear();
        self.verified.clear();
        for entry in &mut self.rsp {
            ControlSeal::withdraw(&mut entry.sealer);
        }
        for subscription in &mut self.subscriptions {
            subscription.bootstrap = None;
        }
    }

    /// The boot id was redrawn: no withdrawn domain 6 entry can name a key
    /// of the new boot, so the table is free again.
    fn redrawn(&mut self) {
        self.rsp.clear();
    }
}

/// The alias a bare frame or an authenticated envelope names: both put
/// `session_id` and `stream_id` at offsets 12 and 16.
fn bare_alias(bytes: &[u8]) -> Option<Alias> {
    let word = |at: usize| {
        bytes
            .get(at..at.saturating_add(4))
            .and_then(|slice| slice.try_into().ok())
            .map(i32::from_le_bytes)
    };
    Some(Alias {
        session_id: word(12)?,
        stream_id: word(16)?,
    })
}

/// The alias of an encrypted envelope: `session_id` and `stream_id` at
/// offsets 20 and 24, selectors only.
fn envelope_alias(bytes: &[u8]) -> Option<Alias> {
    let word = |at: usize| {
        bytes
            .get(at..at.saturating_add(4))
            .and_then(|slice| slice.try_into().ok())
            .map(i32::from_le_bytes)
    };
    Some(Alias {
        session_id: word(20)?,
        stream_id: word(24)?,
    })
}

impl<T: StreamTerms> Intake<'_, T> {
    /// The encrypted class's part of one unicast datagram: an outer `0x21`
    /// is handled here whatever its stream, and so is anything else for an
    /// encrypted stream, which is refused. Returns whether the datagram was
    /// taken; a datagram for no encrypted stream takes the other paths
    /// unchanged.
    pub(super) fn encrypted_in(&mut self, source: SocketAddr, bytes: &[u8]) -> bool {
        if is_envelope(bytes) {
            self.enc_envelope(source, bytes);
            return true;
        }
        let Some(alias) = bare_alias(bytes) else {
            return false;
        };
        let endpoint = self.endpoint;
        let subscription = self.role.enc.subscription(endpoint, alias.stream_id);
        if subscription.is_none() && !self.role.enc.published(endpoint, alias) {
            return false;
        }
        // Section 9: never parsed, never a challenge, never a fallback.
        let frame_type = bytes
            .get(6..8)
            .and_then(|field| field.try_into().ok())
            .map_or(0xFFFF, u16::from_le_bytes);
        let reason = classify_outer(frame_type)
            .err()
            .unwrap_or(EncRejection::BareFrame);
        self.enc_reject(subscription, reason);
        true
    }

    /// Counts `reason` on the subscription at `index`, or unattributed.
    fn enc_reject(&mut self, index: Option<usize>, reason: EncRejection) {
        match index.and_then(|index| self.role.enc.subscriptions.get_mut(index)) {
            Some(subscription) => subscription.channel.rejections.bump(reason),
            None => self.role.enc.unattributed.bump(reason),
        }
    }

    /// An encrypted envelope: for a local encrypted publication it goes to
    /// the sender undecoded; for an encrypted subscription it is opened in
    /// the receive order of section 8; for any other stream it is dropped
    /// and counted (`enc_unexpected`).
    fn enc_envelope(&mut self, source: SocketAddr, bytes: &[u8]) {
        let endpoint = self.endpoint;
        let Some(alias) = envelope_alias(bytes) else {
            self.role.enc.unattributed.bump(EncRejection::Short);
            return;
        };
        // Section 10: while a VM generation change is not released nothing
        // is opened, and nothing goes to the sender to be opened either.
        if quiesced() {
            let index = self.role.enc.subscription(endpoint, alias.stream_id);
            self.enc_reject(index, EncRejection::VmGeneration);
            return;
        }
        if self.role.enc.published(endpoint, alias) {
            match SealedBytes::copy(bytes) {
                Some(sealed) => {
                    let _ = self.forward(ControlItem::Sealed {
                        endpoint,
                        source,
                        bytes: sealed,
                        seen: self.now,
                    });
                }
                None => self.role.enc.unattributed.bump(EncRejection::TooLong),
            }
            return;
        }
        let Some(index) = self.role.enc.subscription(endpoint, alias.stream_id) else {
            self.role.enc.unattributed.bump(EncRejection::Unexpected);
            return;
        };
        let mut out = [0_u8; MAX_PLAINTEXT];
        let result = match header(bytes) {
            // Section 7, "Retired publication identities": traffic naming a
            // full identity inside its `alias_quarantine` selects a key the
            // receiver no longer holds; it is dropped before any derivation.
            Ok(head)
                if head.publication.is_some_and(|publication| {
                    self.role
                        .sessions
                        .is_quarantined(&identity_of(&publication), self.now)
                }) =>
            {
                Err(EncRejection::RetiredParty)
            }
            Ok(head) if head.domain == Domain::Setup => {
                self.enc_setup(source, alias, index, bytes, &mut out)
            }
            Ok(head) if head.domain == Domain::Sender => {
                self.enc_data(source, alias, index, bytes, &mut out)
            }
            Ok(_) => Err(EncRejection::Domain),
            Err(reason) => Err(reason),
        };
        if let Err(reason) = result {
            self.enc_reject(Some(index), reason);
        }
    }

    /// A domain 1 datagram of a bound encrypted image: opened under its
    /// committed keys, its inner frames checked as a datagram of that same
    /// binding, and only then delivered. DATA for no binding records its
    /// header's publication as the target of the SOLICIT it causes; a
    /// datagram more than one epoch ahead starts a resynchronisation.
    fn enc_data(
        &mut self,
        source: SocketAddr,
        alias: Alias,
        index: usize,
        bytes: &[u8],
        out: &mut [u8; MAX_PLAINTEXT],
    ) -> Result<(), EncRejection> {
        let head = header(bytes)?;
        let Some((slot, params)) = self
            .bound_image(source, alias)
            .and_then(|image| self.role.images.get(image))
            .map(|image| (image.slot, image.params))
        else {
            // A header is a selector only: it records nothing, and causes a
            // SOLICIT only toward the publication a verified SETUP named
            // for this alias (H8-02).
            let endpoint = self.endpoint;
            if head.publication.is_some()
                && self.role.enc.verified.iter().any(|(held, at, named)| {
                    (*held, *at) == (endpoint, alias) && Some(*named) == head.publication
                })
            {
                self.solicit(BindingKey {
                    endpoint,
                    source,
                    alias,
                });
            }
            return Err(EncRejection::Binding);
        };
        let now = self.now;
        let enc = &mut self.role.enc;
        let image = enc
            .images
            .iter_mut()
            .find(|image| image.slot == slot)
            .ok_or(EncRejection::Binding)?;
        let rate = &mut enc
            .subscriptions
            .get_mut(index)
            .ok_or(EncRejection::Binding)?
            .channel
            .rate;
        let mut data = None;
        let opened = image.opener.open(bytes, out, rate, now, |frames| {
            // The whole check of the bound image's data path runs here,
            // before the mark: a correctly tagged batch it would refuse
            // (lanes, term offsets, lengths) marks no sequence and
            // promotes no epoch (H8-04).
            data = match classify(frames) {
                Ok(Datagram::DataBatch(batch) | Datagram::Heartbeat(batch))
                    if batch.alias() == alias
                        && ValidatedDatagram::parse(frames, &params).is_ok() =>
                {
                    Some(true)
                }
                Ok(Datagram::Control(control)) if sender_frame_alias(&control) == Some(alias) => {
                    Some(false)
                }
                _ => None,
            };
            data.map(|_| ()).ok_or(EncRejection::InnerRejected)
        });
        let accepted = match opened {
            Ok(accepted) => accepted,
            Err(EncRejection::Epoch)
                if (head.key_epoch, head.party_epoch) > image.opener.epochs() =>
            {
                self.enc_start_resync(source, slot);
                return Err(EncRejection::Epoch);
            }
            Err(reason) => return Err(reason),
        };
        let frames = out.get(..accepted.frames).ok_or(EncRejection::Short)?;
        match (data, classify(frames)) {
            (Some(true), _) => self.deliver(source, alias, frames),
            (Some(false), Ok(Datagram::Control(control))) => {
                self.drain_own_queue();
                self.control(source, control);
            }
            _ => return Err(EncRejection::InnerRejected),
        }
        Ok(())
    }

    /// Section 6b step 1: starts the one resynchronisation challenge of the
    /// image at `slot` bound to `source`, unless one is outstanding, and
    /// sends its SOLICIT, sealed in domain 6, under the RSP_SETUP limits.
    fn enc_start_resync(&mut self, source: SocketAddr, slot: SlotRef) {
        let now = self.now;
        let Some(image) = self.role.enc.images.iter().find(|image| image.slot == slot) else {
            return;
        };
        if image
            .resync
            .is_some_and(|(_, sent)| now.saturating_sub(sent) <= RESYNC_CHALLENGE_TIMEOUT_NS)
        {
            return;
        }
        let (endpoint, alias) = (image.endpoint, image.alias);
        let Some(nonce) = self.role.nonces.nonce() else {
            return;
        };
        let solicit = RspSolicit {
            alias,
            challenge: ChallengeBlock {
                receiver_boot_id: self.role.sessions.boot_id(),
                nonce,
            },
        };
        if self.challenge_from(endpoint, source, Control::Solicit(solicit))
            && let Some(image) = self
                .role
                .enc
                .images
                .iter_mut()
                .find(|image| image.slot == slot)
        {
            image.resync = Some((nonce, now));
        }
    }

    /// A domain 5 SETUP: opened under a scratch derivation from its header,
    /// checked to be one ANNOUNCE or ENC ANSWER of the envelope's own alias
    /// and identity, and only under the current file epoch handled as a
    /// verified SETUP. An ENC ANSWER's image gets its keys at the stated
    /// epochs.
    fn enc_setup(
        &mut self,
        source: SocketAddr,
        alias: Alias,
        index: usize,
        bytes: &[u8],
        out: &mut [u8; MAX_PLAINTEXT],
    ) -> Result<(), EncRejection> {
        let now = self.now;
        let subscription = self
            .role
            .enc
            .subscriptions
            .get_mut(index)
            .ok_or(EncRejection::Binding)?;
        let opened = open_bootstrap_in(
            &mut subscription.bootstrap,
            &subscription.keys,
            None,
            None,
            bytes,
            out,
            &mut subscription.channel.rate,
            now,
            |head, frames| {
                let (control_alias, identity, key_epoch) = match decode_setup(frames) {
                    Ok(EncSetup::Announce(announce)) => {
                        (announce.alias, announce.identity, head.key_epoch)
                    }
                    Ok(EncSetup::Answer(answer)) => (
                        answer.answer.alias,
                        answer.answer.identity,
                        answer.key_epoch,
                    ),
                    Err(_) => return Err(EncRejection::InnerRejected),
                };
                if control_alias != alias
                    || Some(publication_of(&identity)) != head.publication
                    || key_epoch != head.key_epoch
                {
                    return Err(EncRejection::InnerRejected);
                }
                Ok(())
            },
        )?;
        let setup = out
            .get(..opened.frames)
            .map(decode_setup)
            .and_then(Result::ok)
            .ok_or(EncRejection::InnerRejected)?;
        // A SETUP for a bound full identity changes nothing; the
        // resynchronisation of section 6b is its only exception.
        if let EncSetup::Answer(answer) = &setup
            && self
                .role
                .enc
                .images
                .iter()
                .any(|image| image.identity == answer.answer.identity)
        {
            let boot = self.role.sessions.boot_id();
            return self.role.enc.resync(
                index,
                answer,
                opened.header.key_epoch,
                opened.current_epoch,
                boot,
                now,
            );
        }
        // Section 7: only the current file epoch creates a binding.
        if !opened.current_epoch {
            return Err(EncRejection::Epoch);
        }
        // A verified identity: the only kind a domain 6 sealer is made for.
        let named = match &setup {
            EncSetup::Announce(announce) => announce.identity,
            EncSetup::Answer(answer) => answer.answer.identity,
        };
        let endpoint = self.endpoint;
        self.role
            .enc
            .note_verified(endpoint, alias, publication_of(&named));
        match setup {
            EncSetup::Announce(announce) => {
                self.verified_control(source, Control::SetupAnnounce(announce));
            }
            EncSetup::Answer(answer) => {
                let answers = &mut self.role.enc.answers;
                answers.retain(|(endpoint, at, _)| (*endpoint, *at) != (self.endpoint, alias));
                if answers.len() >= RSP_TARGETS {
                    answers.remove(0);
                }
                answers.push((self.endpoint, alias, answer));
                self.verified_control(source, Control::SetupAnswer(answer.answer));
            }
        }
        Ok(())
    }

    /// Hands a SETUP that verified in domain 5 to the trusted handler.
    fn verified_control(&mut self, source: SocketAddr, control: Control) {
        self.drain_own_queue();
        self.role.verified_setup = true;
        self.control(source, control);
        self.role.verified_setup = false;
    }

    /// The sealer of a CHALLENGE or SOLICIT an encrypted subscription
    /// sends: domain 6 with its pairwise trailer, under the key of its
    /// target publication. A CHALLENGE names its target; a SOLICIT's is the
    /// bound image's identity, or else the publication a verified SETUP
    /// named for its alias. A new key is made only for a target a verified
    /// datagram named (H8-02). With no target, or no room left for a new
    /// target's key, it is refused and counted (`seal_failures` at the
    /// sender), never sent bare. `None` for a stream that is not
    /// encrypted.
    pub(super) fn enc_rsp_seal(
        &mut self,
        endpoint: EndpointId,
        control: &Control,
    ) -> Option<SharedSealer> {
        let (alias, named) = match control {
            Control::Challenge(challenge) => {
                (challenge.alias, Some(publication_of(&challenge.identity)))
            }
            Control::Solicit(solicit) => (solicit.alias, None),
            _ => return None,
        };
        let index = self
            .role
            .enc
            .subscription(self.endpoint, alias.stream_id)
            .or_else(|| self.role.enc.subscription(endpoint, alias.stream_id))?;
        let target = named.or_else(|| self.role.enc.solicit_target(alias, self.endpoint, endpoint));
        let boot = id128(self.role.sessions.boot_id());
        let sealer = target.and_then(|target| {
            let create = self
                .role
                .enc
                .is_verified(target, alias, self.endpoint, endpoint);
            self.role.enc.rsp_sealer(index, target, alias, boot, create)
        });
        Some(sealer.unwrap_or_else(|| SharedSealer::of(Refuse(ControlDomain::RspSetup))))
    }
}

impl ReceiverEnc {
    /// The target of a SOLICIT on `alias`: the bound image's publication,
    /// or the one a verified SETUP named on either endpoint.
    fn solicit_target(
        &self,
        alias: Alias,
        first: EndpointId,
        second: EndpointId,
    ) -> Option<PublicationIdentity> {
        self.images
            .iter()
            .find(|image| {
                image.alias == alias && (image.endpoint == first || image.endpoint == second)
            })
            .map(|image| publication_of(&image.identity))
            .or_else(|| {
                self.verified
                    .iter()
                    .find(|(held, at, _)| *at == alias && (*held == first || *held == second))
                    .map(|(_, _, publication)| *publication)
            })
    }
}

impl<T: StreamTerms> ReceiverRole<T> {
    /// Section 10 on the receive side, once per duty at `now`, while the
    /// role has an encrypted incarnation: reads the VM generation signal
    /// and, on a change seen by this role or any other, closes them and
    /// redraws the role's identity:
    ///
    /// 1. the fence already stops every key made before the change;
    /// 2. every encrypted image is retired (its binding goes at once, its
    ///    identity is quarantined) and every derived key, sequence and
    ///    pending answer is dropped, which erases them; any other image's
    ///    domain 4 sealer is replaced by one that refuses;
    /// 3. a fresh `receiver_boot_id` is drawn;
    /// 4. once every role has redrawn, the fence releases and the next
    ///    SETUP of each publication is challenged afresh under the new boot
    ///    id, so the incarnations re-establish.
    ///
    /// When no random word can be drawn the fence stays held and the next
    /// duty tries again (fail closed).
    pub(super) fn on_generation_change(&mut self, sessions: &SessionEnd<T>, now: u64) {
        if self.enc.subscriptions.is_empty()
            && self.enc.published.is_empty()
            && self.subscription_auth.is_empty()
            && self.published_auth.is_empty()
        {
            return;
        }
        if self.enc.watch.is_none() {
            self.enc.watch(VmGenerationWatch::platform());
        }
        let Some(watch) = self.enc.watch.as_mut() else {
            return;
        };
        let current = watch.poll(now);
        if current == self.enc.seen {
            return;
        }
        // Step 2. Each encrypted image's domain 4 sealer is withdrawn
        // through its shared object first, which erases its key for every
        // holder, a clone in a queued control included (H8-09).
        while let Some(image) = self.enc.images.pop() {
            if let Some(index) = self.images.iter().position(|held| held.slot == image.slot) {
                let mut installed = self.images.swap_remove(index);
                if let Some(seal) = installed.enc_seal.as_mut() {
                    ControlSeal::withdraw(seal);
                }
                self.retire(sessions, installed, false, now);
            }
        }
        self.enc.close();
        for image in &mut self.images {
            if let Some(seal) = image.enc_seal.as_mut() {
                ControlSeal::withdraw(seal);
                image.enc_seal = Some(SharedSealer::of(Refuse(ControlDomain::ReceiverToPublisher)));
            }
        }
        // The authenticated class (ADR-0086 section 7, "Snapshot rollback
        // and clones"; karyos#648): every authenticated image is retired,
        // its binding and its domain 1 and 4 keys with it (the shared
        // sealer is withdrawn for every holder), and the signed digest
        // cache is emptied, so nothing made before the change is answered
        // again. The durable guard marks stay.
        while let Some(index) = self.images.iter().position(|image| image.auth.is_some()) {
            let installed = self.images.swap_remove(index);
            if let Some(auth) = installed.auth.as_deref() {
                crate::agents::control::ControlSeal::withdraw(&mut auth.sealer());
            }
            self.retire(sessions, installed, false, now);
        }
        if let Some(intake) = self.signed.as_deref_mut() {
            intake.forget(|_| true);
        }
        // Step 3.
        let old = self.sessions.boot_id();
        let mut boot = [0_u64; 2];
        while boot == [0, 0] || boot == old {
            if karyos_sys::random::fill_u64s(&mut boot).is_err() {
                return;
            }
        }
        self.sessions.set_boot_id(boot);
        self.enc.redrawn();
        // The authenticated class re-establishes under the fresh
        // `receiver_boot_id`: once the fence releases, the next SETUP of
        // each publication is challenged afresh (a new nonce), and the
        // publisher binds the new boot id (ADR-0086 section 7). While the
        // fence is held no authenticated image installs.
        self.enc.seen = current;
        vm_generation::redrawn(current);
    }

    /// Reads the signal with `watch` instead of the platform's (tests).
    #[cfg(test)]
    pub(crate) fn enc_watch(&mut self, watch: VmGenerationWatch) {
        self.enc.watch(watch);
    }

    /// The VM generation the role last redrew for (tests).
    #[cfg(test)]
    pub(crate) fn enc_generation(&self) -> u64 {
        self.enc.seen
    }

    /// The domain 4 sealer of the image at `slot`, as a queued control
    /// holds it (tests).
    #[cfg(test)]
    pub(crate) fn enc_seal(&self, slot: SlotRef) -> Option<SharedSealer> {
        self.images
            .iter()
            .find(|image| image.slot == slot)
            .and_then(|image| image.enc_seal.clone())
    }

    /// The number of encrypted images holding keys (tests).
    #[cfg(test)]
    pub(crate) fn enc_images(&self) -> usize {
        self.enc.images.len()
    }

    /// The keys of an image an encrypted subscription installs (the
    /// install hook): its domain 1 opener at the epoch pair of the verified
    /// ENC ANSWER that set it up, salted with the completed challenge, and
    /// its domain 4 sealer, returned for its controls; its keys are
    /// committed at `now`, the role's clock. `Ok(None)` for a
    /// stream that is not encrypted.
    ///
    /// # Errors
    ///
    /// An encrypted image with no verified answer, or whose keys cannot be
    /// made, is not installed (fail closed).
    pub(super) fn enc_keys(
        &mut self,
        key: &BindingKey,
        identity: Identity,
        slot: SlotRef,
        receiver_id: u64,
        nonce: [u64; 2],
        now: u64,
    ) -> Result<Option<SharedSealer>, EncRejection> {
        let Some(index) = self.enc.subscription(key.endpoint, key.alias.stream_id) else {
            return Ok(None);
        };
        let images = &self.images;
        self.enc
            .images
            .retain(|held| images.iter().any(|image| image.slot == held.slot));
        let at = self
            .enc
            .answers
            .iter()
            .position(|(endpoint, alias, answer)| {
                (*endpoint, *alias) == (key.endpoint, key.alias)
                    && answer.answer.identity == identity
            });
        let Some((_, _, answer)) = at.map(|at| self.enc.answers.remove(at)) else {
            self.enc.unattributed.bump(EncRejection::Binding);
            return Err(EncRejection::Binding);
        };
        let boot = self.sessions.boot_id();
        let subscription = self
            .enc
            .subscriptions
            .get(index)
            .ok_or(EncRejection::Binding)?;
        let salt = Salt::Challenge {
            receiver_boot_id: id128(boot),
            nonce: id128(nonce),
        };
        let publication = publication_of(&identity);
        let base = KeyContext {
            domain: Domain::Sender,
            key_epoch: answer.key_epoch,
            party_epoch: answer.party_epoch,
            session_id: key.alias.session_id,
            stream_id: key.alias.stream_id,
            publication,
            receiver: None,
            salt,
        };
        let opener =
            EncOpener::new(&subscription.keys, None, base, now).map_err(|_| EncRejection::Epoch)?;
        let sealer = EncSealer::new(
            &subscription.keys,
            Some(&subscription.pairwise),
            KeyContext {
                domain: Domain::Receiver,
                // Sending takes the signing epoch (H8-06).
                key_epoch: subscription
                    .keys
                    .signing_epoch()
                    .ok_or(EncRejection::Epoch)?,
                party_epoch: 0,
                receiver: Some(ReceiverIdentity {
                    receiver_boot_id: id128(boot),
                    receiver_id,
                }),
                ..base
            },
            monotonic_ns,
        )
        .map_err(|_| EncRejection::Pairwise)?;
        self.enc.images.push(ImageEnc {
            slot,
            endpoint: key.endpoint,
            alias: key.alias,
            identity,
            term: answer.answer.term,
            opener,
            resync: None,
        });
        Ok(Some(SharedSealer::of(sealer)))
    }

    /// Makes the subscription to `stream_id` on `endpoint` encrypted:
    /// before any traffic.
    pub(crate) fn encrypt_subscription(&mut self, subscription: SubscriptionEnc) {
        self.enc.subscribe(subscription);
    }

    /// Marks the local publication `alias` on `endpoint` encrypted.
    pub(crate) fn encrypt_published(&mut self, endpoint: EndpointId, alias: Alias) {
        self.enc.publish(endpoint, alias);
    }

    /// The rejections of the encrypted subscription to `stream_id` on
    /// `endpoint` (tests).
    #[cfg(test)]
    pub(crate) fn enc_rejections(
        &self,
        endpoint: EndpointId,
        stream_id: i32,
    ) -> Option<EncRejections> {
        self.enc.rejections(endpoint, stream_id)
    }

    /// The domain 1 epoch pair of the encrypted image at `slot` (tests).
    #[cfg(test)]
    pub(crate) fn enc_epochs(&self, slot: SlotRef) -> Option<(u32, u16)> {
        self.enc
            .images
            .iter()
            .find(|image| image.slot == slot)
            .map(|image| image.opener.epochs())
    }
}

#[cfg(test)]
mod tests;
