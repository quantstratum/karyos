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
use std::sync::Arc;

use karyos_protocol::network::encrypted::{EncAnswer, EncSetup, decode_setup};
use karyos_protocol::network::{
    Alias, ChallengeBlock, Control, Datagram, Identity, RspSolicit, RttmKind, TermParams, classify,
};
use karyos_protocol::protection::aes_gcm_siv::{
    AesGcmSiv, Domain, EncRejection, KeyContext, MAX_PLAINTEXT, PublicationIdentity,
    ReceiverIdentity, Salt, classify_outer,
};
use karyos_protocol::protection::hmac_sha256::Domain as ControlDomain;

use super::super::control::{ControlItem, ControlSeal, SealedBytes, SharedSealer};
use super::{BindingKey, Intake, ReceiverRole, SessionEnd, SlotRef, sender_frame_alias};
use crate::agents::EndpointId;
use crate::embedded::StreamTerms;
use crate::sessions::NonceSource;
use crate::wire_enc::shards::{
    BindingView, ENC_SHARD_IN_FLIGHT, EncShardConfig, JobKind, ShardJob, ShardSet,
    SharedRejections, StreamView, serve_round,
};
use crate::wire_enc::verify_pool::{Done, Outcome, VerifyPool};
use crate::wire_enc::vm_generation;
use crate::wire_enc::{
    ChannelKeys, EncChannel, EncKeyError, EncOpener, EncRejections, EncSealer, EncVerifyConfig,
    Header, Lease, OpenerShare, PairwiseFiles, Pending, Prepared, Ticket, VmGenerationWatch,
    bootstrap_complete, check_matrix, check_resync, header, id128, identity_of, is_envelope,
    monotonic_ns, open_bootstrap_in, publication_of, quiesced,
};
use crate::wire_keys::KeyFile;

/// How long an idle duty waits for an endpoint's receive shards to find
/// their socket empty (ADR-0127): what was sent before the duty is then
/// decided in it.
const SHARD_QUIET: std::time::Duration = std::time::Duration::from_millis(5);

/// Entries of the role's bounded SETUP bookkeeping: the ENC ANSWERs being
/// installed and the (alias, publication) pairs a verified domain 5 SETUP
/// named; the oldest gives way (H8-02).
pub(crate) const RSP_TARGETS: usize = 8;

/// Domain 6 sealers a receiver role keeps for one `receiver_boot_id`
/// (H8-01, H8-10, H8-11): each bootstrap key, fixed by the derivation
/// inputs it is made of (the channel key id, from which the sealer follows
/// its file epochs, the receiver id, the target publication and the boot
/// id; `session_id` and `stream_id` are selectors, never HKDF inputs), has
/// one counter for as long as that key can be derived, whatever happens to
/// the subscription that made it and on whichever alias, so it is never
/// made twice. An entry is reclaimed only once it is withdrawn and every
/// file epoch it sealed under has stopped verifying, and a key id's
/// reclaimed epochs are never sealed under again in the boot
/// ([`RSP_FLOORS`]): its nonce history lives exactly as long as its keys.
/// Preallocated at the first encrypted subscription; while every entry
/// holds a live key no further target is challenged (fail closed), so 64
/// is the bound on the targets one receiver boot challenges at once under
/// keys still alive: eight for each of eight subscriptions.
pub(crate) const RSP_SEALERS: usize = 64;

/// Channel key ids whose reclaimed domain 6 entries a receiver boot
/// remembers (H8-11), each with the highest file epoch they sealed under:
/// no new domain 6 sealer of that key id takes an epoch at or below it.
/// One per key id, at most one per entry reclaimed; when it is full no
/// entry of a further key id is reclaimed (fail closed: it stays).
pub(crate) const RSP_FLOORS: usize = RSP_SEALERS;

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

    fn seal_control_as(&mut self, buffer: &mut [u8], frames: usize, alias: Alias) -> Option<usize> {
        self.seal_as(buffer, frames, Some((alias.session_id, alias.stream_id)))
            .ok()
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

    fn key_epoch(&self) -> Option<u32> {
        (!self.is_withdrawn()).then(|| self.context().key_epoch)
    }
}

/// A domain 6 entry's key reached on another alias than its context's
/// (H8-14): every seal reserves its sequence from the entry's one sealer
/// and only the header's selectors name `alias`, so a target's key has one
/// counter whichever alias it is challenged on, and no alias owns it.
#[derive(Debug)]
struct RspRoute {
    shared: SharedSealer,
    alias: Alias,
}

impl ControlSeal for RspRoute {
    fn domain(&self) -> ControlDomain {
        self.shared.domain()
    }

    fn seal_control(&mut self, buffer: &mut [u8], frames: usize) -> Option<usize> {
        self.shared.seal_control_as(buffer, frames, self.alias)
    }

    /// Withdraws the entry's key for every holder, as a clone would.
    fn withdraw(&mut self) {
        ControlSeal::withdraw(&mut self.shared);
    }

    #[cfg(test)]
    fn roll_for_test(&mut self) {
        self.shared.roll_for_test();
    }

    fn apply_keys(&mut self, keys: &dyn crate::wire_auth::KeySet) {
        self.shared.apply_keys(keys);
    }

    fn key_epoch(&self) -> Option<u32> {
        self.shared.key_epoch()
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
    /// The rejections its receive shards count (ADR-0127), added to the
    /// channel's.
    shard_counts: Arc<SharedRejections>,
    /// The scratch slot of its domain 5 opens, made here and re-keyed for
    /// each SETUP: the data path constructs no key.
    bootstrap: Option<AesGcmSiv>,
    /// The share its receive shards' domain 5 jobs are leased under
    /// (ADR-0127 decision 2, step 4): withdrawn with the subscription, so
    /// a queued SETUP of a dropped subscription is cancelled, not opened.
    setup_share: Arc<OpenerShare>,
}

impl Drop for SubscriptionEnc {
    fn drop(&mut self) {
        self.setup_share.withdraw();
    }
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
            shard_counts: Arc::new(SharedRejections::default()),
            bootstrap: Some(bootstrap),
            setup_share: Arc::new(OpenerShare::default()),
        })
    }
}

/// One domain 6 sealer of the role's receiver boot (H8-01, H8-10):
/// everything its key derives from but the file epoch, which the sealer
/// itself follows, the alias its context names (a selector only: another
/// alias is reached through an [`RspRoute`], H8-14), the highest file
/// epoch it was keyed under, and the sealer.
#[derive(Debug)]
struct RspEntry {
    channel_key_id: u32,
    receiver_id: u64,
    publication: PublicationIdentity,
    alias: Alias,
    boot: [u8; 16],
    /// The highest file epoch its key was derived from (H8-11).
    high_epoch: u32,
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

#[cfg(test)]
thread_local! {
    /// The verifier pool the next encrypted subscription of a role on
    /// this thread makes, and whether its verifiers run on threads
    /// (tests: [`with_enc_verifiers`]).
    static TEST_VERIFY: core::cell::Cell<Option<(EncVerifyConfig, bool)>> =
        const { core::cell::Cell::new(None) };
}

/// Runs `run` with every role made on this thread verifying through a
/// pool of `config`, its verifiers on threads when `spawn`, or run only by
/// the role when it waits (tests: the encrypted suite with a pool).
#[cfg(test)]
pub(crate) fn with_enc_verifiers<R>(
    config: EncVerifyConfig,
    spawn: bool,
    run: impl FnOnce() -> R,
) -> R {
    struct Reset(Option<(EncVerifyConfig, bool)>);
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_VERIFY.with(|cell| cell.set(self.0));
        }
    }
    let _reset = Reset(TEST_VERIFY.with(|cell| cell.replace(Some((config, spawn)))));
    run()
}

#[cfg(test)]
thread_local! {
    /// The receive shards the next role made on this thread starts on
    /// each encrypted endpoint, and their verifier pool (tests:
    /// [`with_enc_shards`]).
    static TEST_SHARDS: core::cell::Cell<Option<(EncShardConfig, EncVerifyConfig)>> =
        const { core::cell::Cell::new(None) };
}

/// Runs `run` with every role made on this thread receiving each
/// encrypted endpoint on the receive shards of `config`, verified by a
/// pool of `verify` (tests: the encrypted suite with shards).
#[cfg(test)]
pub(crate) fn with_enc_shards<R>(
    config: EncShardConfig,
    verify: EncVerifyConfig,
    run: impl FnOnce() -> R,
) -> R {
    struct Reset(Option<(EncShardConfig, EncVerifyConfig)>);
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_SHARDS.with(|cell| cell.set(self.0));
        }
    }
    let _reset = Reset(TEST_SHARDS.with(|cell| cell.replace(Some((config, verify)))));
    run()
}

/// The receive shards of one encrypted endpoint (ADR-0127), started at the
/// endpoint's capability epoch `epoch`.
#[derive(Debug)]
struct EndpointShards {
    endpoint: EndpointId,
    epoch: karyos_io::backend::BackendEpoch,
    set: ShardSet<SlotRef>,
}

/// The context a receiver role records for one domain 1 job at dispatch
/// (ADR-0126 decision 2): where it came from, the binding it was
/// dispatched for, the header's publication, the role's withdrawal fence
/// and the opener's [`Ticket`].
#[derive(Debug, Clone, Copy)]
pub(super) struct EncJob {
    endpoint: EndpointId,
    source: SocketAddr,
    alias: Alias,
    slot: SlotRef,
    publication: Option<PublicationIdentity>,
    fence: u64,
    ticket: Ticket,
}

/// The encrypted class of a receiver role.
#[derive(Debug, Default)]
pub(crate) struct ReceiverEnc {
    /// The receive shards of its encrypted endpoints (ADR-0127), started
    /// by the duty when `shard_config` names any. First, so that they are
    /// dropped first: every shard and its verifiers are joined, and every
    /// lease returned, before anything else of the role goes.
    shards: Vec<EndpointShards>,
    /// The shards' configuration, and their verifier pool's (`verify`
    /// below, at least one verifier).
    shard_config: EncShardConfig,
    /// The endpoints, at their epoch, whose shards could not start: the
    /// role receives them itself.
    shards_refused: Vec<(EndpointId, karyos_io::backend::BackendEpoch)>,
    /// The shards' snapshots are to be published again.
    shards_dirty: bool,
    /// The shard settings of the [`with_enc_shards`] the role was made in
    /// (tests).
    #[cfg(test)]
    test_shards: Option<(EncShardConfig, EncVerifyConfig)>,
    /// A shard racing each promoting commit: a lease on the previous key
    /// taken just before it, if a snapshot still holds one (tests).
    #[cfg(test)]
    pub(super) race_promotions: bool,
    /// The promoting commits raced, and the leases the race took (tests).
    #[cfg(test)]
    pub(super) raced: (u32, u32),
    /// When a previous key in a published snapshot leaves its overlap: the
    /// snapshots are published again then, without it.
    shards_refresh: u64,
    /// A ring datagram while the role serves it, taken out meanwhile.
    shard_buffer: Box<[u8]>,
    /// The verifier pool (ADR-0126), made at the first encrypted
    /// subscription when `verify` names verifiers. First, so that it is
    /// dropped first: its verifiers are joined and every lease returned
    /// before the role leaves the VM generation fence.
    pool: Option<VerifyPool<EncJob>>,
    /// The pool's configuration.
    verify: EncVerifyConfig,
    /// Moves when every job in flight is withdrawn ([`Self::quiesce`]): a
    /// job dispatched under an earlier value is refused.
    fence: u64,
    /// Results are not consumed while set (tests: jobs held in flight).
    #[cfg(test)]
    pub(super) hold: bool,
    subscriptions: Vec<SubscriptionEnc>,
    images: Vec<ImageEnc>,
    /// The local encrypted publications, by endpoint and alias: their
    /// receivers' envelopes go to the sender undecoded.
    published: Vec<(EndpointId, Alias)>,
    /// The verified ENC ANSWER the session handler is deciding: it goes
    /// with its slot's reserved chain only if the handler accepts it
    /// ([`Self::take_accepted`]), so a refused one changes no pending
    /// establishment (H8-23). The chain holds it until its image is
    /// installed or the chain goes, never evicted by another (H8-27).
    deciding: Option<(EndpointId, Alias, EncAnswer)>,
    /// The publication a verified ANNOUNCE names while the session handler
    /// decides it: noted as verified only if the handler accepts it
    /// ([`Self::accept_announce`], H8-26).
    announcing: Option<(EndpointId, Alias, PublicationIdentity)>,
    /// The (alias, publication) pairs a verified domain 5 SETUP named, by
    /// endpoint: the only targets a new domain 6 sealer is made for, and
    /// the SOLICIT target of DATA for an alias with no binding. Bounded,
    /// the oldest giving way; an unverified header records nothing
    /// (H8-02).
    verified: Vec<(EndpointId, Alias, PublicationIdentity)>,
    /// The domain 6 sealers of the current `receiver_boot_id`, kept
    /// independently of the subscriptions for as long as their keys can
    /// be derived (H8-01, H8-11).
    rsp: Vec<RspEntry>,
    /// Per channel key id, the highest file epoch a reclaimed domain 6
    /// entry of this boot sealed under (H8-11).
    floors: Vec<(u32, u32)>,
    /// Per channel key id, the highest file epoch seen to sign this boot:
    /// a subscription made again starts at it (H8-17).
    activation: crate::wire_enc::ActivationFloors,
    /// Refusals no encrypted subscription owns, by reason:
    /// `enc_unexpected` on a trusted or authenticated stream among them.
    pub(crate) unattributed: EncRejections,
    /// The VM generation signal, read once the role has an encrypted
    /// incarnation (section 10).
    watch: Option<VmGenerationWatch>,
    /// The role's place in the fence, from its first watch on; dropped
    /// with the role, it leaves the fence (H8-21).
    registration: Option<vm_generation::Registration>,
    /// The VM generation the role last redrew its identity for.
    seen: u64,
}

impl ReceiverEnc {
    /// The encrypted class of a role whose verifier pool is `verify` and
    /// whose encrypted endpoints run the receive shards of `shards`.
    pub(crate) fn new(verify: EncVerifyConfig, shards: EncShardConfig) -> Self {
        Self {
            verify,
            shard_config: shards,
            #[cfg(test)]
            test_shards: TEST_SHARDS.with(core::cell::Cell::get),
            ..Self::default()
        }
    }

    /// ADR-0127 decision 7: takes every shard snapshot back. Once this
    /// returns no shard dispatches under any opener, and no snapshot holds
    /// a key, so a key may change in place; the snapshots are published
    /// again at the next duty.
    pub(super) fn shards_take_back(&mut self) {
        for held in &self.shards {
            held.set.publish(crate::wire_enc::shards::Snapshot::clear);
        }
        for image in &mut self.images {
            image.opener.shard_unpublished();
        }
        self.shards_dirty = true;
    }

    /// The shards' configuration and verifier pool of a role made now.
    fn shard_settings(&self) -> (EncShardConfig, EncVerifyConfig) {
        #[cfg(test)]
        if let Some(settings) = self
            .test_shards
            .or_else(|| TEST_SHARDS.with(core::cell::Cell::get))
        {
            return settings;
        }
        (self.shard_config, self.verify)
    }

    /// The live clock source its shards and their verifiers read
    /// (ADR-0127 decision 4): the host's monotonic clock, the network's
    /// time base and so the role's and the key deadlines' (tests made
    /// with [`with_enc_shards`] run on a virtual clock: the role's
    /// published reading alone).
    fn shard_clock(&self) -> fn() -> u64 {
        #[cfg(test)]
        if self.test_shards.is_some() || TEST_SHARDS.with(core::cell::Cell::get).is_some() {
            return crate::wire_enc::shards::published_only;
        }
        karyos_sys::host_clock::host_monotonic_ns
    }

    /// ADR-0126 decision 5, for a key replacement or a VM generation
    /// change: every job in flight is withdrawn. Queued jobs are
    /// cancelled, running ones finish, and every result is consumed and
    /// refused (`enc_withdrawn`), so every lease is back, and no key a job
    /// held is changed or erased, before this returns. Allocates nothing.
    fn quiesce(&mut self) {
        // ADR-0127 decision 7: the shards stop dispatching under every
        // opener first; their jobs are withdrawn with the pool's.
        self.shards_take_back();
        self.fence = self.fence.wrapping_add(1);
        let mut plain = [0_u8; MAX_PLAINTEXT];
        let withdrawn = |enc: &mut Self, endpoint: EndpointId, alias: Alias| match enc
            .subscriptions
            .iter_mut()
            .find(|subscription| {
                (subscription.endpoint, subscription.stream_id) == (endpoint, alias.stream_id)
            }) {
            Some(subscription) => subscription
                .channel
                .rejections
                .bump(EncRejection::Withdrawn),
            None => enc.unattributed.bump(EncRejection::Withdrawn),
        };
        for at in 0..self.shards.len() {
            let Some(held) = self.shards.get(at) else {
                continue;
            };
            let endpoint = held.endpoint;
            let _ = held.set.cancel_all();
            // The snapshot is taken back: nothing more is dispatched.
            let limit = held.set.issued();
            while let Some(done) = self
                .shards
                .get(at)
                .and_then(|held| held.set.take_waiting(limit, &mut plain))
            {
                withdrawn(self, endpoint, done.context.alias);
                // Its lease returns here.
                drop(done);
            }
        }
        if let Some(pool) = self.pool.as_mut() {
            let _ = pool.cancel_where(|_| true);
        }
        while let Some(done) = self
            .pool
            .as_mut()
            .and_then(|pool| pool.take_waiting(&mut plain))
        {
            let job = done.context;
            match self.subscriptions.iter_mut().find(|subscription| {
                (subscription.endpoint, subscription.stream_id)
                    == (job.endpoint, job.alias.stream_id)
            }) {
                Some(subscription) => subscription
                    .channel
                    .rejections
                    .bump(EncRejection::Withdrawn),
                None => self.unattributed.bump(EncRejection::Withdrawn),
            }
            // Its lease returns here.
            drop(done);
        }
        zeroize::Zeroize::zeroize(&mut plain);
    }

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
        // The active binding epoch, the signing one, never below the
        // highest seen to sign (H8-12, H8-17).
        let binding_key_epoch = self
            .subscriptions
            .get(index)
            .and_then(|subscription| subscription.keys.binding_epoch())
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
            binding_key_epoch,
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
        // A key replacement withdraws every job in flight first (ADR-0126
        // decision 5): no key a lease holds changes under a verifier.
        self.quiesce();
        for subscription in &mut self.subscriptions {
            // Rotation: a newly admitted epoch serves the next bindings,
            // admitted before its predecessor goes.
            subscription.keys.admit(keys);
            subscription.pairwise.admit(keys);
            subscription.keys.retain(keys);
            subscription.pairwise.retain(keys);
            // New sealers take the epoch the key set signs with, channel
            // and pairwise (H8-06).
            subscription.keys.follow_signing(keys);
            subscription.pairwise.follow_signing(keys);
            self.activation.hold(&mut subscription.keys);
            // Its domain 5 scratch slot holds a key of an earlier set:
            // erased in place (H8-05).
            crate::wire_enc::erase_slot(&mut subscription.bootstrap);
        }
        // Each domain 6 sealer follows its own key only, keeping its
        // sequence; a withdrawn one stays in the table as a tombstone, so
        // its (target, key, boot id) is refused and never rebuilt with a
        // sequence restarted at 0 (nonce reuse), until every file epoch it
        // sealed under has stopped verifying (H8-11). An entry whose
        // target is gone (no subscription of its key and receiver, or no
        // verified SETUP or bound image names its publication) is not
        // advanced into a successor epoch: it is withdrawn under the epochs
        // it sealed under, kept only as their nonce history, so it is
        // reclaimed once they stop verifying, and a later verified target
        // gets the successor's key from sequence 0 ([`Self::rsp_sealer`]).
        let (subscriptions, verified, images) = (&self.subscriptions, &self.verified, &self.images);
        for entry in &mut self.rsp {
            if let Some(epoch) = entry.sealer.key_epoch() {
                entry.high_epoch = entry.high_epoch.max(epoch);
            }
            let active = subscriptions.iter().any(|subscription| {
                (subscription.channel_key_id, subscription.receiver_id)
                    == (entry.channel_key_id, entry.receiver_id)
            }) && (verified
                .iter()
                .any(|(_, _, publication)| *publication == entry.publication)
                || images
                    .iter()
                    .any(|image| publication_of(&image.identity) == entry.publication));
            let advances = keys
                .signing(entry.channel_key_id)
                .is_some_and(|file| file.file_epoch > entry.high_epoch);
            if !active && advances {
                ControlSeal::withdraw(&mut entry.sealer);
                continue;
            }
            entry.sealer.apply_keys(keys);
            if let Some(epoch) = entry.sealer.key_epoch() {
                entry.high_epoch = entry.high_epoch.max(epoch);
            }
        }
        self.reclaim(keys);
        for image in &mut self.images {
            image.opener.apply_keys(keys);
        }
    }

    /// Reclaims the domain 6 entries whose keys can no longer be derived
    /// (H8-11): withdrawn, and every file epoch of its key id up to the
    /// highest it sealed under no longer verifies, in `keys` or in any
    /// subscription's files. The key id's floor rises to that epoch first,
    /// so no sealer of this boot is made again at or below it, whatever
    /// file later verifies: each nonce history is kept exactly as long as
    /// its key. A live key's entry, or a withdrawn one whose file still
    /// verifies, stays. Allocates nothing: both tables are preallocated.
    fn reclaim(&mut self, keys: &dyn crate::wire_auth::KeySet) {
        let mut at = 0;
        while let Some(entry) = self.rsp.get(at) {
            let (key_id, high) = (entry.channel_key_id, entry.high_epoch);
            let derivable = entry.sealer.key_epoch().is_some()
                || keys
                    .verifying(key_id)
                    .into_iter()
                    .flatten()
                    .any(|file| file.file_epoch <= high)
                || self.subscriptions.iter().any(|subscription| {
                    subscription.channel_key_id == key_id
                        && subscription
                            .keys
                            .oldest_epoch()
                            .is_some_and(|oldest| oldest <= high)
                });
            if derivable {
                at = at.saturating_add(1);
                continue;
            }
            let room = self.floors.len() < RSP_FLOORS;
            match self.floors.iter_mut().find(|(held, _)| *held == key_id) {
                Some((_, floor)) => *floor = (*floor).max(high),
                None if room => self.floors.push((key_id, high)),
                None => {
                    at = at.saturating_add(1);
                    continue;
                }
            }
            let _ = self.rsp.swap_remove(at);
        }
    }

    /// Makes a subscription encrypted, replacing an earlier one of its
    /// key.
    pub(crate) fn subscribe(&mut self, mut subscription: SubscriptionEnc) {
        self.unsubscribe(subscription.endpoint, subscription.stream_id);
        self.shards_dirty = true;
        if self.shard_buffer.is_empty() {
            self.shard_buffer =
                vec![0; usize::from(karyos_io::sockets::endpoint::MAX_DATAGRAM) + 1]
                    .into_boxed_slice();
        }
        // The verifier pool (ADR-0126), made once on the control path.
        if self.pool.is_none() {
            #[cfg(not(test))]
            let (config, spawn) = (self.verify, true);
            #[cfg(test)]
            let (config, spawn) = TEST_VERIFY
                .with(core::cell::Cell::get)
                .unwrap_or((self.verify, true));
            // None of its verifiers started: inline, as with none
            // (counted by the pool).
            if config.verifiers > 0 || !spawn {
                self.pool = VerifyPool::new(config, spawn);
            }
        }
        // It starts at the role's activation floor, not 0 (H8-17).
        self.activation.hold(&mut subscription.keys);
        // The fixed tables, made once on the control path: the receive
        // path pushes into them without allocating.
        if self.rsp.capacity() < RSP_SEALERS {
            self.rsp
                .reserve_exact(RSP_SEALERS.saturating_sub(self.rsp.len()));
        }
        if self.floors.capacity() < RSP_FLOORS {
            self.floors
                .reserve_exact(RSP_FLOORS.saturating_sub(self.floors.len()));
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
        self.shards_dirty = true;
        self.subscriptions
            .retain(|sub| (sub.endpoint, sub.stream_id) != (endpoint, stream_id));
        self.verified
            .retain(|(held, alias, _)| (*held, alias.stream_id) != (endpoint, stream_id));
    }

    /// The domain 6 sealer of an RSP_SETUP of the subscription at `index`
    /// to `publication` on `alias` from the boot `boot`: the one the role
    /// made for that key before, whichever subscription made it, or, when
    /// `create` (a target a verified datagram named, H8-02) and the table
    /// has room, a new one under the signing epoch, above the key id's
    /// reclaimed epochs (H8-11).
    ///
    /// The key is fixed by its derivation inputs, not by the alias: one
    /// entry, so one sequence, serves every alias of its target (H8-10),
    /// and none owns it (H8-14). A `create` request on another alias than
    /// the entry's context gets a route that seals from the entry's
    /// sequence with only the header naming that alias; a request that no
    /// verified datagram backs gets nothing on another alias.
    ///
    /// An entry withdrawn below the signing epoch (its target went at a
    /// rotation, H8-11) is made again for a verified target under the
    /// signing epoch, above every epoch it sealed under: a key never used,
    /// so its sequence starts at 0 reusing no nonce.
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
        let found = self.rsp.iter().position(|entry| {
            entry.channel_key_id == channel_key_id
                && entry.receiver_id == receiver_id
                && entry.publication == publication
                && entry.boot == boot
        });
        let signing = subscription.keys.signing_epoch();
        if let Some(entry) = found.and_then(|at| self.rsp.get(at)) {
            let renewable = create
                && entry.sealer.key_epoch().is_none()
                && signing.is_some_and(|epoch| epoch > entry.high_epoch);
            if !renewable {
                if entry.alias == alias {
                    return Some(entry.sealer.clone());
                }
                return create.then(|| {
                    SharedSealer::of(RspRoute {
                        shared: entry.sealer.clone(),
                        alias,
                    })
                });
            }
        } else if !create || self.rsp.len() >= RSP_SEALERS {
            return None;
        }
        let key_epoch = signing?;
        if self
            .floors
            .iter()
            .any(|(held, floor)| *held == channel_key_id && key_epoch <= *floor)
        {
            return None;
        }
        let context = KeyContext {
            domain: Domain::RspSetup,
            key_epoch,
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
        let entry = RspEntry {
            channel_key_id,
            receiver_id,
            publication,
            alias,
            boot,
            high_epoch: key_epoch,
            sealer: shared.clone(),
        };
        match found.and_then(|at| self.rsp.get_mut(at)) {
            Some(held) => *held = entry,
            None => self.rsp.push(entry),
        }
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
        // The shards hand DATA for this target to the role from their
        // next snapshot on (ADR-0127).
        self.shards_dirty = true;
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

    /// The image at `slot` was retired: its domain 1 keys are dropped,
    /// which erases them (H8-09).
    ///
    /// Its jobs still queued are cancelled (ADR-0126 decision 5) and its
    /// opener is withdrawn for its verifiers; every result is consumed in
    /// order and refused, and a key a lease still holds is erased once
    /// the last returns.
    pub(crate) fn retire_image(&mut self, slot: SlotRef) {
        // ADR-0127 decision 7: no shard dispatches under it from here, and
        // no snapshot keeps its keys.
        self.shards_take_back();
        if let Some(pool) = self.pool.as_mut() {
            let _ = pool.cancel_where(|job| job.slot == slot);
        }
        self.images.retain(|image| image.slot != slot);
    }

    /// Marks the local publication `alias` on `endpoint` encrypted.
    pub(crate) fn publish(&mut self, endpoint: EndpointId, alias: Alias) {
        self.shards_dirty = true;
        if !self.published.contains(&(endpoint, alias)) {
            self.published.push((endpoint, alias));
        }
    }

    /// The local publication `alias` on `endpoint` is no longer encrypted
    /// (it went).
    pub(crate) fn unpublish(&mut self, endpoint: EndpointId, alias: Alias) {
        self.shards_dirty = true;
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
            .map(|sub| sub.shard_counts.merged(sub.channel.rejections))
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
        if self.registration.is_none() {
            self.registration = Some(vm_generation::Registration::enter());
            self.seen = vm_generation::generation();
        }
        self.watch = Some(watch);
    }

    /// The ENC ANSWER being decided for `alias` on `endpoint`, accepted
    /// by the session handler with the challenge `nonce`: returned for its
    /// slot's reserved chain, which keeps it for the image's installation
    /// (H8-27), and its publication noted as verified (H8-23). `None` for
    /// a plain answer.
    pub(super) fn take_accepted(
        &mut self,
        endpoint: EndpointId,
        alias: Alias,
        nonce: [u64; 2],
    ) -> Option<EncAnswer> {
        let (_, _, answer) = self.deciding.take_if(|(at, named, answer)| {
            (*at, *named) == (endpoint, alias) && answer.answer.challenge.nonce == nonce
        })?;
        self.note_verified(endpoint, alias, publication_of(&answer.answer.identity));
        Some(answer)
    }

    /// The ANNOUNCE being decided for `alias` on `endpoint`, of
    /// `identity`, accepted by the session handler (it challenges): its
    /// publication is noted as verified (H8-26). Nothing for a plain one.
    pub(super) fn accept_announce(
        &mut self,
        endpoint: EndpointId,
        alias: Alias,
        identity: &Identity,
    ) {
        let publication = publication_of(identity);
        if self
            .announcing
            .take_if(|held| *held == (endpoint, alias, publication))
            .is_some()
        {
            self.note_verified(endpoint, alias, publication);
        }
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
        self.deciding = None;
        self.announcing = None;
        self.verified.clear();
        for entry in &mut self.rsp {
            ControlSeal::withdraw(&mut entry.sealer);
        }
        for subscription in &mut self.subscriptions {
            subscription.bootstrap = None;
        }
    }

    /// The boot id was redrawn: no withdrawn domain 6 entry can name a key
    /// of the new boot, so the table and its floors are free again.
    fn redrawn(&mut self) {
        self.rsp.clear();
        self.floors.clear();
    }
}

/// The check of a verified domain 5 SETUP's one frame on `alias` (an
/// ANNOUNCE or ENC ANSWER of the envelope's own alias, identity and key
/// epoch), before its effect.
fn setup_names(alias: Alias) -> impl FnOnce(&Header, &[u8]) -> Result<(), EncRejection> {
    move |head, frames| {
        let (control_alias, identity, key_epoch) = match decode_setup(frames) {
            Ok(EncSetup::Announce(announce)) => (announce.alias, announce.identity, head.key_epoch),
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
    }
}

/// A domain 1 datagram of the image at `slot`, verified and queued in its
/// path's order before its handler ran: checked again, handed to its
/// handler and committed when its queue drains
/// ([`Intake::enc_queued`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct EncQueued {
    slot: SlotRef,
    pending: Pending,
}

/// What the inner frames of a verified domain 1 datagram of the binding
/// on `alias`, of incarnation `identity`, are: `Some(true)` a DATA batch
/// or heartbeat of that binding while it is `live`, `Some(false)` a sender
/// control naming it, `None` anything else. Structural only: no handler
/// state is read.
fn sender_datagram(frames: &[u8], alias: Alias, live: bool, identity: Identity) -> Option<bool> {
    match classify(frames) {
        Ok(Datagram::DataBatch(batch) | Datagram::Heartbeat(batch))
            if batch.alias() == alias && live =>
        {
            Some(true)
        }
        Ok(Datagram::Control(control))
            if sender_frame_alias(&control) == Some(alias)
                && sender_control_names(&control, identity) =>
        {
            Some(false)
        }
        _ => None,
    }
}

/// Whether a domain 1 sender control names the bound image's incarnation
/// `identity`: a PATH_HB, an ERR NAK_REPLY or an RTTM REPLY. A structural
/// check of the frame against its binding, as its alias is; what the
/// control may change is its handler's decision. Any other control is
/// refused: none is a sender's domain 1 control.
fn sender_control_names(control: &Control, identity: Identity) -> bool {
    match control {
        Control::PathHeartbeat(heartbeat) => heartbeat.identity == identity,
        Control::NakReply(reply) => reply.identity == identity,
        Control::Rttm(rttm) => {
            matches!(rttm.kind, RttmKind::Reply { .. }) && rttm.identity == identity
        }
        _ => false,
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

    /// Whether a SETUP for the subscription to `stream_id` states an `mtu`
    /// above the encrypted ceiling (ADR-0114 section 11) on an encrypted
    /// subscription: its DATA would exceed the AEAD plaintext bound, so
    /// it is never challenged nor imaged.
    pub(super) fn enc_mtu_too_large(&self, stream_id: i32, mtu: u32) -> bool {
        mtu > karyos_protocol::channel::MAX_ENCRYPTED_MTU
            && self
                .role
                .enc
                .subscription(self.endpoint, stream_id)
                .is_some()
    }

    /// The log MTU of an image of the subscription to `stream_id` whose
    /// SETUP advertised `mtu`, the whole datagram (ADR-0086 section 5,
    /// ADR-0114 section 11; H8-13): less the 84-byte envelope on an
    /// encrypted subscription, the 48-byte one on an authenticated one,
    /// unchanged on a trusted one. A SETUP's `mtu` is at least the
    /// 256-byte floor, so neither subtraction underflows; an image whose
    /// inner budget holds no frame is refused by its geometry check.
    pub(super) fn image_mtu(&self, stream_id: i32, mtu: u32) -> u32 {
        let envelope = if self
            .role
            .enc
            .subscription(self.endpoint, stream_id)
            .is_some()
        {
            karyos_protocol::protection::aes_gcm_siv::ENVELOPE_LEN
        } else if self.subscription_authenticated(stream_id) {
            crate::wire_auth::ENVELOPE_LEN
        } else {
            0
        };
        mtu.saturating_sub(u32::try_from(envelope).unwrap_or(u32::MAX))
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
                // Opened inline: the jobs dispatched before it are decided
                // first, in arrival order (ADR-0126 decision 4).
                self.role.enc_settle(self.sessions, self.now);
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

    /// A domain 1 datagram of a bound encrypted image: verified under its
    /// committed keys, its inner frames checked to be a datagram of that
    /// same binding, then handed to their handler, and committed (its
    /// sequence marked, a next epoch promoted) only if the handler took it
    /// (ADR-0114 sections 8 and 9): whatever any handler refuses marks and
    /// promotes nothing, with no copy of its checks run before. A DATA
    /// batch is taken when one of its frames or heartbeats takes effect
    /// ([`Intake::data`]), after the structural validation of the whole
    /// batch; one queued in its path's order is checked again, handled and
    /// committed when its queue drains. DATA for no binding records its
    /// header's publication as the target of the SOLICIT it causes; a
    /// datagram more than one epoch ahead starts a resynchronisation.
    ///
    /// The role is one thread, and each datagram's check, handler and
    /// commit run in one call: no other datagram is verified or committed
    /// between them, but the queue a control drains first, which is why
    /// the control is checked again after it. Two copies of one sequence
    /// therefore never both reach their handler.
    fn enc_data(
        &mut self,
        source: SocketAddr,
        alias: Alias,
        index: usize,
        bytes: &[u8],
        out: &mut [u8; MAX_PLAINTEXT],
    ) -> Result<(), EncRejection> {
        let head = header(bytes)?;
        if self.role.enc.pool.is_some() {
            if self.enc_dispatch(source, alias, index, bytes, &head)? {
                return Ok(());
            }
            // Opened inline: the jobs dispatched before it are decided
            // first, in arrival order (ADR-0126 decision 4).
            self.role.enc_settle(self.sessions, self.now);
        }
        let bound = self.bound_image(source, alias);
        let Some((slot, identity, aborted)) = bound
            .and_then(|image| self.role.images.get(image))
            .map(|image| (image.slot, image.identity, image.aborted.is_some()))
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
        // A binding that is no longer live (an inactive or aborted image)
        // takes no DATA: refused with its batch, so that the generic DATA
        // path, which would solicit an inactive key, never sees it.
        let live = self.role.sessions.is_active(slot) && !aborted;
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
        let verified = image.opener.verify(bytes, out, rate, now, |frames| {
            // The frames name this live binding (alias, and a control's
            // incarnation): no handler state is read. Whether they take
            // effect is their handler's decision, below.
            data = sender_datagram(frames, alias, live, identity);
            data.map(|_| ()).ok_or(EncRejection::InnerRejected)
        });
        let pending = match verified {
            Ok(pending) => pending,
            Err(EncRejection::Epoch)
                if (head.key_epoch, head.party_epoch) > image.opener.epochs() =>
            {
                self.enc_start_resync(source, slot);
                return Err(EncRejection::Epoch);
            }
            Err(reason) => return Err(reason),
        };
        // ADR-0127: the verification's check of a promotion could be
        // overtaken by a shard leasing the previous key; it is checked
        // again with the shards' snapshots taken back.
        let promotes = image.opener.commit_promotes(&pending);
        if promotes && !self.role.enc.shards.is_empty() {
            self.role.enc.shards_take_back();
            if let Err(reason) = self.enc_check(EncQueued { slot, pending }) {
                zeroize::Zeroize::zeroize(&mut *out);
                return Err(reason);
            }
        }
        let frames = out.get(..pending.frames).ok_or(EncRejection::Short)?;
        let data = data.ok_or(EncRejection::InnerRejected)?;
        self.enc_handle(source, alias, frames, EncQueued { slot, pending }, data)
    }

    /// ADR-0126 decision 2: a domain 1 datagram of a bound image, with a
    /// verifier pool. Every check before the open runs here, on the role
    /// thread, the open rate charged to the channel's one count
    /// ([`EncOpener::prepare`]); then a slot is reserved, the job's context
    /// recorded and its lease taken, and the job queued for a verifier.
    /// `Ok(true)` once queued; `Ok(false)` for a datagram to open here,
    /// inline: no binding, or the next epoch (a scratch derivation).
    ///
    /// # Errors
    ///
    /// The refusal of a check before the open, or
    /// [`EncRejection::VerifyBusy`] when no slot is free: dropped before
    /// dispatch.
    fn enc_dispatch(
        &mut self,
        source: SocketAddr,
        alias: Alias,
        index: usize,
        bytes: &[u8],
        head: &Header,
    ) -> Result<bool, EncRejection> {
        // A full table first gives back what is done (decision 4).
        if self
            .role
            .enc
            .pool
            .as_ref()
            .is_some_and(|pool| !pool.has_free())
        {
            self.role.enc_collect(self.sessions, self.now);
        }
        let Some(slot) = self
            .bound_image(source, alias)
            .and_then(|image| self.role.images.get(image))
            .map(|image| image.slot)
        else {
            return Ok(false);
        };
        let (now, endpoint) = (self.now, self.endpoint);
        let enc = &mut self.role.enc;
        let fence = enc.fence;
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
        let (ticket, lease) = match image.opener.prepare(bytes, rate, now) {
            Ok(Prepared::Dispatch(ticket, lease)) => (ticket, lease),
            Ok(Prepared::Inline) => return Ok(false),
            Err(EncRejection::Epoch)
                if (head.key_epoch, head.party_epoch) > image.opener.epochs() =>
            {
                self.enc_start_resync(source, slot);
                return Err(EncRejection::Epoch);
            }
            Err(reason) => return Err(reason),
        };
        let job = EncJob {
            endpoint,
            source,
            alias,
            slot,
            publication: head.publication,
            fence,
            ticket,
        };
        match enc.pool.as_mut() {
            // A refused dispatch hands the lease back, and it returns here.
            Some(pool) => pool
                .dispatch(bytes, lease, job)
                .map(|()| true)
                .map_err(|_| EncRejection::VerifyBusy),
            None => Err(EncRejection::VerifyBusy),
        }
    }

    /// ADR-0126 decision 3: a verifier's result, consumed in arrival order.
    /// A refusal is counted on its subscription and changes nothing else.
    fn enc_verified(&mut self, done: Done<EncJob>, plain: &mut [u8; MAX_PLAINTEXT]) {
        let job = done.context;
        if let Err(reason) = self.enc_recheck(done, plain) {
            let index = self
                .role
                .enc
                .subscription(job.endpoint, job.alias.stream_id);
            self.enc_reject(index, reason);
        }
    }

    /// The outcome of `done`: a refused open or a cancelled job is refused
    /// as such; a verified one is re-checked, decided and committed
    /// ([`Self::enc_decide`]), its plaintext erased when refused.
    fn enc_recheck(
        &mut self,
        done: Done<EncJob>,
        plain: &mut [u8; MAX_PLAINTEXT],
    ) -> Result<(), EncRejection> {
        let Done {
            context: job,
            outcome,
            lease,
            header,
            len,
        } = done;
        let opened = match outcome {
            Outcome::Verified(opened) => opened,
            Outcome::Failed(reason) => return Err(reason),
            Outcome::Cancelled => return Err(EncRejection::Withdrawn),
        };
        let lease = lease.ok_or(EncRejection::Withdrawn)?;
        let decided = self.enc_decide(&job, &opened, lease, (&header, len), plain);
        if decided.is_err()
            && let Some(frames) = plain.get_mut(..opened.frames)
        {
            zeroize::Zeroize::zeroize(frames);
        }
        decided
    }

    /// ADR-0126 decision 3 for a verified job: every predicate checked at
    /// dispatch is evaluated again, changing nothing: the role's
    /// withdrawal fence, the VM generation fence, the key fence, the
    /// retired identities, the binding (the same image, by the admission
    /// rule) and its liveness, and the opener's own
    /// ([`EncOpener::complete`]: instance, withdrawal, generation, key
    /// slot, age and replay window); its lease returns then. The inner
    /// frames are validated as on the inline path; the handler decides and
    /// the commit marks, as in ADR-0124. No second open.
    fn enc_decide(
        &mut self,
        job: &EncJob,
        opened: &karyos_protocol::protection::aes_gcm_siv::Opened,
        lease: Lease,
        authenticated: (
            &[u8; karyos_protocol::protection::aes_gcm_siv::HEADER_LEN],
            usize,
        ),
        plain: &[u8; MAX_PLAINTEXT],
    ) -> Result<(), EncRejection> {
        if job.fence != self.role.enc.fence {
            return Err(EncRejection::Withdrawn);
        }
        if quiesced() {
            return Err(EncRejection::VmGeneration);
        }
        if !self
            .role
            .key_generation
            .admits_now(crate::wire_auth::Side::Receiver)
        {
            self.role.count(|c| &mut c.auth_rejected);
            return Ok(());
        }
        if job.publication.is_some_and(|publication| {
            self.role
                .sessions
                .is_quarantined(&identity_of(&publication), self.now)
        }) {
            return Err(EncRejection::RetiredParty);
        }
        let (slot, identity, aborted) = self
            .bound_image(job.source, job.alias)
            .and_then(|image| self.role.images.get(image))
            .map(|image| (image.slot, image.identity, image.aborted.is_some()))
            .filter(|(slot, _, _)| *slot == job.slot)
            .ok_or(EncRejection::Binding)?;
        let live = self.role.sessions.is_active(slot) && !aborted;
        self.enc_freeze(slot, job.ticket.epochs());
        let now = self.now;
        let pending = self
            .role
            .enc
            .images
            .iter()
            .find(|image| image.slot == slot)
            .ok_or(EncRejection::Binding)
            .and_then(|image| {
                image
                    .opener
                    .complete(&job.ticket, &lease, opened, authenticated, now)
            })?;
        // Consumed: the lease returns.
        drop(lease);
        let frames = plain.get(..opened.frames).ok_or(EncRejection::Short)?;
        check_matrix(Domain::Sender, frames)?;
        let data = sender_datagram(frames, job.alias, live, identity)
            .ok_or(EncRejection::InnerRejected)?;
        self.enc_handle(
            job.source,
            job.alias,
            frames,
            EncQueued { slot, pending },
            data,
        )
    }

    /// The handler of a verified domain 1 datagram decides, and only an
    /// accepted one is committed (ADR-0124): `data` a DATA batch or
    /// heartbeat, delivered now or queued in its path's order, otherwise a
    /// sender control, checked again after the queue it drains first.
    fn enc_handle(
        &mut self,
        source: SocketAddr,
        alias: Alias,
        frames: &[u8],
        queued: EncQueued,
        data: bool,
    ) -> Result<(), EncRejection> {
        let accepted = match (data, classify(frames)) {
            (true, _) => match self.deliver_enc(source, alias, frames, queued) {
                // Queued in its path's order, or dropped by a full queue:
                // nothing is committed now.
                None => return Ok(()),
                Some(accepted) => accepted,
            },
            (false, Ok(Datagram::Control(control))) => {
                self.drain_own_queue();
                // The drain hands its queued datagrams to their handlers
                // and commits them: this one is checked again after it.
                self.enc_freeze(queued.slot, queued.pending.epochs);
                self.enc_check(queued)?;
                self.enc_sender_control(source, control)
            }
            _ => return Err(EncRejection::InnerRejected),
        };
        if !accepted {
            return Err(EncRejection::InnerRejected);
        }
        self.enc_commit(queued)
    }

    /// ADR-0127 decision 7 for a promotion: before the last check of a
    /// datagram under an epoch pair that would be promoted (no committed
    /// key holds it), every shard snapshot is taken back, and stays so
    /// through the handler's decision and the commit; it is published
    /// again after the commit, or at the next duty. No shard can then
    /// lease the previous key between the check and the commit, so the
    /// promotion the check found possible stays possible, and a datagram
    /// its handler took always commits.
    fn enc_freeze(&mut self, slot: SlotRef, epochs: (u32, u16)) {
        let now = self.now;
        let enc = &mut self.role.enc;
        if !enc.shards.is_empty()
            && enc
                .images
                .iter()
                .find(|image| image.slot == slot)
                .is_some_and(|image| image.opener.promotes(epochs, now))
        {
            enc.shards_take_back();
        }
    }

    /// With [`ReceiverEnc::race_promotions`], before a promoting commit:
    /// a lease on the previous key from every snapshot still holding one,
    /// as a shard dispatching then would take, held through the commit
    /// (tests).
    #[cfg(test)]
    fn race_previous(&mut self, promotes: bool) -> Vec<Lease> {
        let enc = &mut self.role.enc;
        if !enc.race_promotions || !promotes {
            return Vec::new();
        }
        let raced: Vec<Lease> = enc
            .shards
            .iter()
            .filter_map(|held| held.set.lease_previous())
            .collect();
        enc.raced = (
            enc.raced.0.saturating_add(1),
            enc.raced
                .1
                .saturating_add(u32::try_from(raced.len()).unwrap_or(u32::MAX)),
        );
        raced
    }

    /// Whether `queued` would still commit ([`EncOpener::check`]).
    fn enc_check(&self, queued: EncQueued) -> Result<(), EncRejection> {
        self.role
            .enc
            .images
            .iter()
            .find(|image| image.slot == queued.slot)
            .ok_or(EncRejection::Binding)
            .and_then(|image| image.opener.check(&queued.pending, self.now))
    }

    /// Commits `queued`, which its handler took ([`EncOpener::commit`]).
    ///
    /// At the clock reading and VM generation of its verification, which
    /// the token carries (H8-39): a datagram its handler took always
    /// commits. A failure would leave its effects unmarked; none is
    /// reachable, so it is asserted, and counted by its reason.
    fn enc_commit(&mut self, queued: EncQueued) -> Result<(), EncRejection> {
        // A promotion changes the keys in place: the shards' snapshots are
        // taken back first and published again after (ADR-0127).
        let promotes = self
            .role
            .enc
            .images
            .iter()
            .find(|image| image.slot == queued.slot)
            .is_some_and(|image| image.opener.commit_promotes(&queued.pending));
        #[cfg(test)]
        let _raced = self.race_previous(promotes);
        if promotes && !self.role.enc.shards.is_empty() {
            self.role.enc.shards_take_back();
        }
        let committed = self
            .role
            .enc
            .images
            .iter_mut()
            .find(|image| image.slot == queued.slot)
            .ok_or(EncRejection::Binding)
            .and_then(|image| image.opener.commit(queued.pending))
            .map(|_| ());
        debug_assert!(committed.is_ok(), "an accepted datagram commits");
        if promotes && !self.role.enc.shards.is_empty() {
            self.role.enc_shards_publish(self.now);
        }
        committed
    }

    /// A queued encrypted DATA datagram of `alias` from `source`, its
    /// plaintext `bytes`, as its path's queue drains: checked again, then
    /// handed to [`Intake::data`], and committed only if it took effect.
    /// A refusal is counted on its subscription.
    pub(super) fn enc_queued(
        &mut self,
        source: SocketAddr,
        alias: Alias,
        bytes: &[u8],
        queued: EncQueued,
    ) {
        let index = self.role.enc.subscription(self.endpoint, alias.stream_id);
        self.enc_freeze(queued.slot, queued.pending.epochs);
        let result = self.enc_check(queued).and_then(|()| {
            if self.data(source, alias, bytes) {
                self.enc_commit(queued)
            } else {
                Err(EncRejection::InnerRejected)
            }
        });
        if let Err(reason) = result {
            self.enc_reject(index, reason);
        }
    }

    /// A verified domain 1 sender control handed to its handler: whether
    /// it took effect. A PATH_HB that refreshed its bound path, an ERR
    /// NAK_REPLY that echoed an outstanding NAK, an RTTM REPLY that took
    /// its path's outstanding probe.
    fn enc_sender_control(&mut self, source: SocketAddr, control: Control) -> bool {
        match control {
            Control::PathHeartbeat(heartbeat) => self.path_heartbeat(source, &heartbeat),
            Control::NakReply(reply) => self.nak_reply(source, &reply),
            Control::Rttm(rttm) if matches!(rttm.kind, RttmKind::Reply { .. }) => {
                self.rttm_reply(source, &rttm)
            }
            _ => false,
        }
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
            setup_names(alias),
        )?;
        self.enc_setup_decide(source, alias, index, opened, &out[..])
    }

    /// ADR-0127 decision 2: a domain 5 SETUP whose scratch key a receive
    /// shard derived, under a lease on its subscription, and a verifier
    /// opened. Every predicate is evaluated again, charging nothing (the
    /// shard charged the scratch rate once): the withdrawal fence and the
    /// lease, the VM generation, the key fence, the retired identities, the
    /// subscription and the checks before the open
    /// ([`bootstrap_complete`]); then it is decided as an inline one. Its
    /// plaintext is erased after.
    fn enc_shard_setup(
        &mut self,
        job: &ShardJob<SlotRef>,
        (outcome, lease): (Outcome, Option<Lease>),
        authenticated: (
            &[u8; karyos_protocol::protection::aes_gcm_siv::HEADER_LEN],
            usize,
        ),
        plain: &mut [u8; MAX_PLAINTEXT],
    ) {
        let index = self
            .role
            .enc
            .subscription(self.endpoint, job.alias.stream_id);
        let opened = match outcome {
            Outcome::Verified(opened) => opened,
            Outcome::Failed(reason) => return self.enc_reject(index, reason),
            Outcome::Cancelled => return self.enc_reject(index, EncRejection::Withdrawn),
        };
        let decided = self.enc_setup_recheck(index, job, &opened, lease, authenticated, plain);
        if let Some(frames) = plain.get_mut(..opened.frames) {
            zeroize::Zeroize::zeroize(frames);
        }
        if let Err(reason) = decided {
            self.enc_reject(index, reason);
        }
    }

    /// The re-check and decision of [`Self::enc_shard_setup`].
    fn enc_setup_recheck(
        &mut self,
        index: Option<usize>,
        job: &ShardJob<SlotRef>,
        opened: &karyos_protocol::protection::aes_gcm_siv::Opened,
        lease: Option<Lease>,
        authenticated: (
            &[u8; karyos_protocol::protection::aes_gcm_siv::HEADER_LEN],
            usize,
        ),
        plain: &[u8; MAX_PLAINTEXT],
    ) -> Result<(), EncRejection> {
        let lease = lease.ok_or(EncRejection::Withdrawn)?;
        if lease.is_withdrawn() || job.fence != self.role.enc.fence {
            return Err(EncRejection::Withdrawn);
        }
        if quiesced() {
            return Err(EncRejection::VmGeneration);
        }
        if !self
            .role
            .key_generation
            .admits_now(crate::wire_auth::Side::Receiver)
        {
            self.role.count(|c| &mut c.auth_rejected);
            return Ok(());
        }
        if job.publication.is_some_and(|publication| {
            self.role
                .sessions
                .is_quarantined(&identity_of(&publication), self.now)
        }) {
            return Err(EncRejection::RetiredParty);
        }
        let index = index.ok_or(EncRejection::Unexpected)?;
        let subscription = self
            .role
            .enc
            .subscriptions
            .get(index)
            .ok_or(EncRejection::Binding)?;
        let opened = bootstrap_complete(
            &subscription.keys,
            (&job.ticket, &job.head),
            opened,
            authenticated,
            plain,
            setup_names(job.alias),
        )?;
        // Consumed: the lease returns.
        drop(lease);
        self.enc_setup_decide(job.source, job.alias, index, opened, plain)
    }

    /// A verified domain 5 SETUP decided: an ENC ANSWER for a bound
    /// identity is its resynchronisation; otherwise, only under the current
    /// file epoch, an ANNOUNCE or ENC ANSWER handed to its handler.
    fn enc_setup_decide(
        &mut self,
        source: SocketAddr,
        alias: Alias,
        index: usize,
        opened: crate::wire_enc::Bootstrap,
        out: &[u8],
    ) -> Result<(), EncRejection> {
        let now = self.now;
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
            // ADR-0127 decision 7: a resynchronisation moves the keys, which
            // no shard snapshot may hold meanwhile.
            self.role.enc.shards_take_back();
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
        // An answer's or an announcement's is noted only once accepted
        // (H8-23, H8-26).
        match setup {
            EncSetup::Announce(announce) => {
                self.drain_own_queue();
                let publication = publication_of(&announce.identity);
                self.role.enc.announcing = Some((self.endpoint, alias, publication));
                self.verified_control(source, Control::SetupAnnounce(announce));
                self.role.enc.announcing = None;
            }
            EncSetup::Answer(answer) => {
                // Queued controls first: only this answer's outcome may
                // take it (H8-23).
                self.drain_own_queue();
                self.role.enc.deciding = Some((self.endpoint, alias, answer));
                self.verified_control(source, Control::SetupAnswer(answer.answer));
                self.role.enc.deciding = None;
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
    ///
    /// It runs while the role holds any encrypted state, its domain 6
    /// table and openers included, or is registered with the fence, whether
    /// or not a subscription is left (H8-18): a role whose last subscription
    /// went still withdraws its shared domain 6 keys and reports itself
    /// redrawn, so the process fence releases. Each duty also erases every
    /// image's previous epoch key past its overlap (H8-16).
    pub(super) fn on_generation_change(&mut self, sessions: &SessionEnd<T>, now: u64) {
        // A previous key past its overlap leaves the shards' snapshots
        // first, so that no snapshot keeps it (ADR-0127).
        if now >= self.enc.shards_refresh && !self.enc.shards.is_empty() {
            self.enc.shards_dirty = true;
            self.enc_shards_publish(now);
        }
        for image in &mut self.enc.images {
            image.opener.expire_previous(now);
        }
        if self.enc.subscriptions.is_empty()
            && self.enc.published.is_empty()
            && self.enc.rsp.is_empty()
            && self.enc.images.is_empty()
            && self.enc.watch.is_none()
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
        // ADR-0126 decision 5: every job in flight is withdrawn and every
        // lease is back before anything is closed, and so before the role
        // reports itself redrawn.
        self.enc.quiesce();
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
        // The answers the pending chains hold go too: no image installs
        // at the old boot's establishment (H8-27).
        for chain in &mut self.chains {
            chain.enc = None;
        }
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
        if let Some(registration) = self.enc.registration.as_mut() {
            registration.redrawn(current);
        }
    }

    /// ADR-0126 decision 4: consumes every job in flight in arrival order,
    /// each at `now` with its own endpoint, waiting for the ones not yet
    /// done (running queued ones itself meanwhile). Called before any
    /// encrypted datagram is opened inline, so that a binding's datagrams
    /// are decided in the order they arrived, and by a duty that read
    /// nothing. Allocates nothing.
    pub(in crate::agents) fn enc_settle(&mut self, sessions: &SessionEnd<T>, now: u64) {
        self.enc_consume(sessions, now, true);
    }

    /// ADR-0126 decision 4: consumes the jobs already done, in arrival
    /// order, up to the first that is not: after each endpoint's receive
    /// poll, so that the verifiers work on one poll's datagrams while the
    /// role reads the next. Allocates nothing.
    pub(in crate::agents) fn enc_collect(&mut self, sessions: &SessionEnd<T>, now: u64) {
        self.enc_consume(sessions, now, false);
    }

    /// Consumes jobs in arrival order; with `wait`, every one in flight.
    fn enc_consume(&mut self, sessions: &SessionEnd<T>, now: u64, wait: bool) {
        #[cfg(test)]
        if self.enc.hold {
            return;
        }
        // ADR-0127: with `wait`, every shard lane's jobs dispatched by now
        // are decided too, each lane in its order.
        if wait {
            let mut plain = [0_u8; MAX_PLAINTEXT];
            for at in 0..self.enc.shards.len() {
                let Some((endpoint, limit)) = self
                    .enc
                    .shards
                    .get(at)
                    .map(|held| (held.endpoint, held.set.issued()))
                else {
                    continue;
                };
                while self.enc_shard_job(endpoint, Some(limit), sessions, now, &mut plain) {}
            }
            zeroize::Zeroize::zeroize(&mut plain);
        }
        if self
            .enc
            .pool
            .as_ref()
            .is_none_or(|pool| pool.in_flight() == 0)
        {
            return;
        }
        let mut plain = [0_u8; MAX_PLAINTEXT];
        while let Some(done) = self.enc.pool.as_mut().and_then(|pool| {
            if wait {
                pool.take_waiting(&mut plain)
            } else {
                pool.take(&mut plain)
            }
        }) {
            let mut intake = Intake {
                endpoint: done.context.endpoint,
                now,
                role: self,
                sessions,
                work: 0,
            };
            intake.enc_verified(done, &mut plain);
        }
    }

    /// Holds results in flight while `hold` (tests).
    #[cfg(test)]
    pub(crate) fn enc_hold(&mut self, hold: bool) {
        self.enc.hold = hold;
    }

    /// Races every promoting commit with a shard's lease on the previous
    /// key while `race` (tests).
    #[cfg(test)]
    pub(crate) fn enc_race_promotions(&mut self, race: bool) {
        self.enc.race_promotions = race;
    }

    /// The promoting commits raced, and the leases the race took (tests).
    #[cfg(test)]
    pub(crate) fn enc_raced(&self) -> (u32, u32) {
        self.enc.raced
    }

    /// Whether a shard snapshot holds a previous key a shard could lease
    /// (tests).
    #[cfg(test)]
    pub(crate) fn enc_shards_hold_previous(&self) -> bool {
        self.enc
            .shards
            .iter()
            .any(|held| held.set.lease_previous().is_some())
    }

    /// Jobs in flight, in the pool and the shard lanes (tests).
    #[cfg(test)]
    pub(crate) fn enc_in_flight(&self) -> usize {
        self.enc.pool.as_ref().map_or(0, VerifyPool::in_flight)
            + self
                .enc
                .shards
                .iter()
                .map(|held| held.set.in_flight())
                .sum::<usize>()
    }

    /// What the receive shards of `endpoint` counted (tests).
    #[cfg(test)]
    pub(crate) fn enc_shard_stats(
        &self,
        endpoint: EndpointId,
    ) -> Option<crate::wire_enc::shards::ShardStats> {
        self.enc
            .shards
            .iter()
            .find(|held| held.endpoint == endpoint)
            .map(|held| held.set.stats())
    }

    /// Counts the shard-handled datagrams of `length` (tests).
    #[cfg(test)]
    pub(crate) fn enc_shards_watch(&self, length: usize) {
        for held in &self.enc.shards {
            held.set.watch_length(length);
        }
    }

    /// The shard-handled datagrams of the watched length (tests).
    #[cfg(test)]
    pub(crate) fn enc_shards_watched(&self) -> u64 {
        self.enc.shards.iter().map(|held| held.set.watched()).sum()
    }

    /// Verifier threads running (tests).
    #[cfg(test)]
    pub(crate) fn enc_verifiers(&self) -> Option<usize> {
        self.enc.pool.as_ref().map(VerifyPool::verifiers)
    }

    /// Runs one queued job on this thread, as a verifier (tests).
    #[cfg(test)]
    pub(crate) fn enc_verify_one(&self) -> bool {
        self.enc.pool.as_ref().is_some_and(VerifyPool::verify_one)
            || self.enc.shards.iter().any(|held| held.set.verify_one())
    }

    /// ADR-0127: publishes every shard set's snapshot from the role's
    /// state at `now`, under its write lock: the withdrawal fence, the key
    /// fence, the endpoint's encrypted streams with their shared open-rate
    /// counters, its local encrypted publications, and each bound
    /// encrypted image's committed keys, by the founding source of its
    /// binding. Refills tables reserved when the set was made: allocates
    /// nothing.
    pub(in crate::agents) fn enc_shards_publish(&mut self, now: u64) {
        let ReceiverEnc {
            shards,
            images,
            subscriptions,
            published,
            verified,
            fence,
            shards_dirty,
            shards_refresh,
            ..
        } = &mut self.enc;
        *shards_dirty = false;
        *shards_refresh = u64::MAX;
        let (sessions, keys) = (&self.sessions, &self.key_generation);
        for image in images.iter_mut() {
            image.opener.shard_unpublished();
        }
        for held in shards.iter() {
            let endpoint = held.endpoint;
            held.set.publish(|snapshot| {
                snapshot.clear();
                snapshot.fence = *fence;
                snapshot.generation = vm_generation::generation();
                if snapshot.admits.is_none() {
                    snapshot.admits = Some(Arc::clone(keys));
                }
                for subscription in subscriptions
                    .iter()
                    .filter(|subscription| subscription.endpoint == endpoint)
                {
                    if snapshot.streams.len() < snapshot.streams.capacity() {
                        snapshot.streams.push(StreamView {
                            stream_id: subscription.stream_id,
                            rate: subscription.channel.rate.clone(),
                            counts: Arc::clone(&subscription.shard_counts),
                            setup: subscription.keys.shard_setup(),
                            setup_share: Arc::clone(&subscription.setup_share),
                        });
                    }
                }
                for (_, alias) in published.iter().filter(|(held, _)| *held == endpoint) {
                    snapshot.push_published(*alias);
                }
                for (_, alias, publication) in
                    verified.iter().filter(|(held, ..)| *held == endpoint)
                {
                    snapshot.push_verified(*alias, *publication);
                }
                for (identity, until) in sessions.quarantined_until() {
                    snapshot.push_retired(publication_of(&identity), until);
                }
                snapshot.complete = true;
                for image in images.iter_mut().filter(|image| image.endpoint == endpoint) {
                    let (true, Some((key, _))) = (
                        snapshot
                            .streams
                            .iter()
                            .any(|stream| stream.stream_id == image.alias.stream_id),
                        sessions.binding(image.slot),
                    ) else {
                        continue;
                    };
                    if snapshot.bindings.len() >= snapshot.bindings.capacity() {
                        // Its datagrams go to the role.
                        snapshot.complete = false;
                        continue;
                    }
                    let Some(opener) = image.opener.shard_view(now) else {
                        continue;
                    };
                    if let Some(previous) = opener.previous.as_ref() {
                        *shards_refresh = (*shards_refresh).min(previous.until);
                    }
                    snapshot.bindings.push(BindingView {
                        tag: image.slot,
                        alias: image.alias,
                        source: key.source,
                        opener,
                    });
                }
            });
        }
    }

    /// ADR-0127 decision 1: starts the receive shards of `endpoint` from
    /// `rx`'s socket when the role's configuration names shards, the
    /// endpoint has an encrypted subscription and none run yet. Control
    /// path, once per endpoint and epoch: duplicates the descriptor per
    /// shard and starts the threads. When none can start, the role keeps
    /// receiving the endpoint itself.
    pub(in crate::agents) fn enc_shards_start<O: karyos_io::sockets::ops::SocketOps>(
        &mut self,
        endpoint: EndpointId,
        rx: &karyos_io::sockets::endpoint::SocketsRx<O>,
        now: u64,
    ) {
        let (config, verify) = self.enc.shard_settings();
        let epoch = rx.capabilities().epoch;
        if config.shards == 0
            || self.enc.shards.iter().any(|held| held.endpoint == endpoint)
            || self.enc.shards_refused.contains(&(endpoint, epoch))
            || !self
                .enc
                .subscriptions
                .iter()
                .any(|subscription| subscription.endpoint == endpoint)
        {
            return;
        }
        let receivers: Vec<_> = (0..config.shards)
            .map_while(|_| rx.share_recv().ok())
            .collect();
        let tables = (
            self.enc.subscriptions.capacity().max(64),
            self.images.capacity().max(64),
            self.sessions.capacity().max(RSP_TARGETS),
        );
        // Decision 4: the shards and verifiers read a live clock in the
        // role's time domain, from `now` on.
        let clock = crate::wire_enc::shards::SetClock::new(self.enc.shard_clock(), now);
        match ShardSet::new(
            config,
            verify,
            receivers,
            usize::from(rx.max_datagram()),
            (tables, clock),
        ) {
            Some(set) => {
                self.enc.shards.push(EndpointShards {
                    endpoint,
                    epoch,
                    set,
                });
                self.enc_shards_publish(now);
            }
            None => self.enc.shards_refused.push((endpoint, epoch)),
        }
    }

    /// ADR-0127 decision 7: stops the shards of every endpoint whose RX
    /// half is gone or reopened, or that has no encrypted subscription
    /// left. Their snapshots are taken back, their threads joined (and
    /// their descriptors closed), and what they left in their lanes and
    /// rings is decided before the set goes; the role then receives the
    /// endpoint itself. Then the clock is published, and the snapshots
    /// when they changed.
    pub(in crate::agents) fn enc_shards_tend<O: karyos_io::sockets::ops::SocketOps>(
        &mut self,
        halves: &[(EndpointId, crate::agents::Half<O>)],
        sessions: &SessionEnd<T>,
        now: u64,
    ) {
        let mut at = 0;
        while let Some(held) = self.enc.shards.get(at) {
            let live = halves.iter().any(|(endpoint, half)| {
                *endpoint == held.endpoint
                    && matches!(half, crate::agents::Half::Rx(rx) if rx.capabilities().epoch == held.epoch)
            }) && self
                .enc
                .subscriptions
                .iter()
                .any(|subscription| subscription.endpoint == held.endpoint);
            if live {
                at += 1;
                continue;
            }
            let endpoint = held.endpoint;
            if let Some(held) = self.enc.shards.get_mut(at) {
                held.set.stop_shards();
            }
            self.enc.shards_take_back();
            self.enc_drain_shards(endpoint, sessions, now);
            drop(self.enc.shards.swap_remove(at));
        }
        for held in &self.enc.shards {
            held.set.set_clock(now);
        }
        if self.enc.shards_dirty {
            self.enc_shards_publish(now);
        }
    }

    /// ADR-0127 decision 6: one poll of the inputs of `endpoint`'s shards,
    /// round robin, each lane's results and each ring's datagrams in turn
    /// with `budget` each, so a busy input never starves another. `None`
    /// for an endpoint without shards, which the role receives itself.
    /// Allocates nothing.
    pub(in crate::agents) fn enc_serve_shards(
        &mut self,
        endpoint: EndpointId,
        sessions: &SessionEnd<T>,
        now: u64,
        budget: u32,
    ) -> Option<u32> {
        let held = self
            .enc
            .shards
            .iter()
            .find(|held| held.endpoint == endpoint)?;
        let lanes = held.set.lanes();
        let ended = held.set.take_ended();
        for _ in 0..held.set.take_backend_drops() {
            self.count(|c| &mut c.backend_drops);
        }
        for _ in 0..ended {
            self.count(|c| &mut c.datagrams);
        }
        let mut buffer = core::mem::take(&mut self.enc.shard_buffer);
        let mut plain = [0_u8; MAX_PLAINTEXT];
        // Each lane's turn takes the oldest job of a lane the replay window
        // allows (decision 5); each ring is served in its own turn.
        let served = serve_round(lanes.saturating_mul(2), budget, |input| {
            if input % 2 == 0 {
                self.enc_shard_job(endpoint, None, sessions, now, &mut plain)
            } else {
                self.enc_shard_other(endpoint, input / 2, &mut buffer, sessions, now)
            }
        });
        self.enc.shard_buffer = buffer;
        zeroize::Zeroize::zeroize(&mut plain);
        Some(served)
    }

    /// A result of `endpoint`'s shards, the oldest of a lane, that the
    /// replay window allows now (decision 5), decided as a pool's
    /// ([`Intake::enc_verified`]): with `limit`, the oldest in dispatch
    /// order, waiting for it while a job numbered below `limit` is still to
    /// be consumed. Whether one was consumed.
    fn enc_shard_job(
        &mut self,
        endpoint: EndpointId,
        limit: Option<u64>,
        sessions: &SessionEnd<T>,
        now: u64,
        plain: &mut [u8; MAX_PLAINTEXT],
    ) -> bool {
        #[cfg(test)]
        if self.enc.hold {
            return false;
        }
        let Some(held) = self
            .enc
            .shards
            .iter()
            .find(|held| held.endpoint == endpoint)
        else {
            return false;
        };
        let done = match limit {
            Some(limit) => held.set.take_waiting(limit, plain),
            None => held.set.take_next(plain),
        };
        let Some(Done {
            context,
            outcome,
            lease,
            header,
            len,
        }) = done
        else {
            return false;
        };
        self.count(|c| &mut c.datagrams);
        let mut intake = Intake {
            endpoint,
            now,
            role: self,
            sessions,
            work: 0,
        };
        let ShardJob {
            tag,
            kind,
            source,
            alias,
            publication,
            fence,
            ticket,
            ..
        } = context;
        let slot = match (kind, tag) {
            (JobKind::Committed | JobKind::Next, Some(slot)) => slot,
            _ => {
                // A domain 5 SETUP (ADR-0127 decision 2, step 4).
                intake.enc_shard_setup(&context, (outcome, lease), (&header, len), plain);
                return true;
            }
        };
        let done = Done {
            context: EncJob {
                endpoint,
                source,
                alias,
                slot,
                publication,
                fence,
                ticket,
            },
            outcome,
            lease,
            header,
            len,
        };
        intake.enc_verified(done, plain);
        true
    }

    /// The oldest datagram of ring `lane` of `endpoint`'s shards, handled
    /// as the role's own receive would: whether there was one.
    fn enc_shard_other(
        &mut self,
        endpoint: EndpointId,
        lane: usize,
        buffer: &mut [u8],
        sessions: &SessionEnd<T>,
        now: u64,
    ) -> bool {
        let Some((len, source)) = self
            .enc
            .shards
            .iter()
            .find(|held| held.endpoint == endpoint)
            .and_then(|held| held.set.pop_other(lane, buffer))
        else {
            return false;
        };
        self.count(|c| &mut c.datagrams);
        let mut intake = Intake {
            endpoint,
            now,
            role: self,
            sessions,
            work: 0,
        };
        intake.bytes_in(source, buffer.get(..len).unwrap_or_default());
        true
    }

    /// Decides everything `endpoint`'s shards have received: every ring
    /// datagram and every lane job dispatched by now, each lane in its
    /// order. Returns the datagrams decided.
    fn enc_drain_shards(
        &mut self,
        endpoint: EndpointId,
        sessions: &SessionEnd<T>,
        now: u64,
    ) -> u32 {
        let mut served = 0_u32;
        let mut plain = [0_u8; MAX_PLAINTEXT];
        // Each ring and lane once: what arrives meanwhile waits for the
        // next poll.
        let bound = u32::try_from(usize::from(crate::wire_enc::MAX_ENC_SHARD_RING))
            .unwrap_or(u32::MAX)
            .saturating_add(ENC_SHARD_IN_FLIGHT);
        served = served.saturating_add(
            self.enc_serve_shards(endpoint, sessions, now, bound)
                .unwrap_or(0),
        );
        let limit = self
            .enc
            .shards
            .iter()
            .find(|held| held.endpoint == endpoint)
            .map_or(0, |held| held.set.issued());
        while self.enc_shard_job(endpoint, Some(limit), sessions, now, &mut plain) {
            served = served.saturating_add(1);
        }
        zeroize::Zeroize::zeroize(&mut plain);
        served
    }

    /// ADR-0127 decision 7, when the receiver stops: every endpoint's
    /// shards are stopped and joined (their descriptors closed), their
    /// snapshots taken back, every queued job cancelled, and everything
    /// they left in their lanes and rings decided (a cancelled job refused
    /// as withdrawn, its lease returned); then each set goes, joining its
    /// verifiers. Once this returns no thread of the role's shards runs and
    /// no lease is out on their account, so the stopped agent handed back
    /// to its caller holds no running work. Control path.
    pub(in crate::agents) fn enc_shutdown(&mut self, sessions: &SessionEnd<T>, now: u64) {
        if self.enc.shards.is_empty() {
            return;
        }
        #[cfg(test)]
        {
            self.enc.hold = false;
        }
        for held in &mut self.enc.shards {
            held.set.stop_shards();
        }
        self.enc.shards_take_back();
        for held in &self.enc.shards {
            let _ = held.set.cancel_all();
        }
        while let Some(endpoint) = self.enc.shards.last().map(|held| held.endpoint) {
            self.enc_drain_shards(endpoint, sessions, now);
            drop(self.enc.shards.pop());
        }
    }

    /// ADR-0127, a duty that read nothing: waits, briefly, until each
    /// sharded endpoint's shards have found their socket empty, then
    /// decides everything they received. Returns the datagrams decided.
    pub(in crate::agents) fn enc_quiet(&mut self, sessions: &SessionEnd<T>, now: u64) -> u32 {
        let mut served = 0_u32;
        for at in 0..self.enc.shards.len() {
            let Some(endpoint) = self.enc.shards.get(at).map(|held| {
                held.set.quiet(SHARD_QUIET);
                held.endpoint
            }) else {
                continue;
            };
            served = served.saturating_add(self.enc_drain_shards(endpoint, sessions, now));
        }
        served
    }

    /// The leases out on the image at `slot`'s opener, and its current
    /// key, weakly (tests).
    #[cfg(test)]
    pub(crate) fn enc_leases(
        &self,
        slot: SlotRef,
    ) -> Option<(u32, std::sync::Weak<crate::wire_enc::KeyCell>)> {
        self.enc
            .images
            .iter()
            .find(|image| image.slot == slot)
            .map(|image| (image.opener.leases(), image.opener.current_key()))
    }

    /// Removes the domain 1 binding of the image at `slot` from the
    /// encrypted class, as a retirement does (tests).
    #[cfg(test)]
    pub(crate) fn enc_remove_binding(&mut self, slot: SlotRef) {
        self.enc.retire_image(slot);
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
        (nonce, accepted): ([u64; 2], Option<EncAnswer>),
        now: u64,
    ) -> Result<Option<SharedSealer>, EncRejection> {
        let Some(index) = self.enc.subscription(key.endpoint, key.alias.stream_id) else {
            return Ok(None);
        };
        let images = &self.images;
        self.enc.shards_dirty = true;
        self.enc
            .images
            .retain(|held| images.iter().any(|image| image.slot == held.slot));
        // The accepted answer its chain kept (H8-27).
        let Some(answer) = accepted.filter(|answer| {
            answer.answer.identity == identity && answer.answer.challenge.nonce == nonce
        }) else {
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
        self.enc.shards_dirty = true;
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

    /// Makes `length` bytes of lane 0 from `start` the outstanding NAK of
    /// the image at `slot`: a hole observed at `now`, its NAK submitted
    /// once its skew deadline passed. Returns that NAK (tests).
    #[cfg(test)]
    pub(crate) fn awaited_nak(
        &mut self,
        slot: SlotRef,
        start: u64,
        length: u32,
        now: u64,
    ) -> Option<karyos_protocol::network::Nak> {
        use karyos_protocol::frame::Lane;

        let image = self.images.iter_mut().find(|image| image.slot == slot)?;
        let hole = crate::repair::loss::Hole { start, length };
        let _ = image.loss.observe(Lane::ZERO, Some(hole), now);
        let at = now.saturating_add(crate::wire_enc::SECOND_NS);
        let nak = image.loss.due(Lane::ZERO, at)?;
        image.loss.submitted(&nak, at, &image.rtt);
        Some(nak)
    }

    /// Issues a fresh RTTM probe on the first path of the image at `slot`
    /// at `now`, its earlier probes dropped, submitted at `now` when
    /// `submit`, and returns its id (tests).
    #[cfg(test)]
    pub(crate) fn issued_probe(&mut self, slot: SlotRef, now: u64, submit: bool) -> Option<u64> {
        let image = self.images.iter_mut().find(|image| image.slot == slot)?;
        if let Some(probe) = image.probes.get_mut(0) {
            probe.pending = None;
        }
        image.rtt.rebind(0);
        let probe = image.rtt.due(0, now)?;
        if submit {
            image.rtt.submitted(probe, now);
        }
        Some(probe.probe_id)
    }

    /// Issues a probe on path 0 of the image at `slot` and puts its send
    /// in its backend call, started at `start`, as the sender does: its
    /// probe id and that send's guard (tests).
    #[cfg(test)]
    pub(crate) fn sending_probe(
        &mut self,
        slot: SlotRef,
        now: u64,
        start: u64,
    ) -> Option<(u64, super::ReportGuard)> {
        let image = self.images.iter_mut().find(|image| image.slot == slot)?;
        image.rtt.rebind(0);
        let probe = image.rtt.due(0, now)?;
        let path = image.probes.get_mut(0)?;
        path.pending = Some(probe);
        let mut guard = super::ReportGuard::take(&path.slot);
        guard.sending(start);
        Some((probe.probe_id, guard))
    }

    /// Whether path 0's probe of the image at `slot` still awaits its
    /// send's settlement (tests).
    #[cfg(test)]
    pub(crate) fn probe_unsettled(&self, slot: SlotRef) -> bool {
        self.images
            .iter()
            .find(|image| image.slot == slot)
            .and_then(|image| image.probes.first())
            .is_some_and(|probe| probe.pending.is_some())
    }
}

#[cfg(test)]
mod tests;
