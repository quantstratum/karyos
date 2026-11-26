// SPDX-License-Identifier: Apache-2.0

//! The `encrypted` class on a publication's publisher side, unicast
//! (`quantstratum-docs: karyos/adr/0114-encrypted-protection-profile-v1.md`
//! sections 4 to 9; part of quantstratum/karyos#650 and #651).
//!
//! An encrypted publication seals its SETUP ANNOUNCE and ENC ANSWER in
//! domain 5 under its own bootstrap key, and opens its receiver's
//! RSP_SETUP (domain 6) under a scratch derivation from the header's
//! receiver block, its own identity and the receiver's pairwise file:
//! the pairwise trailer must verify before anything else (section 7,
//! "Pairwise proof first"). Only then is the retired boot id table
//! consulted, and only a new binding under the current file epoch derives
//! the receiver's domain 4 opener and the session's domain 1 sealer. A
//! receiver's SM, NAK and RTTM REQUEST open under that committed domain 4
//! key in the receive order of section 8. A refusal changes nothing but
//! its counter. A publication is made encrypted by its admission binding
//! (`Binding::EncPublication`).

use karyos_protocol::network::encrypted::EncAnswer;
use karyos_protocol::network::{
    Alias, Control, Datagram, Identity, Receiver, SetupAnswer, classify,
};
use karyos_protocol::protection::aes_gcm_siv::{
    AesGcmSiv, Domain, EncRejection, KeyContext, MAX_PLAINTEXT, PublicationIdentity,
    ReceiverIdentity, Salt,
};

use super::publish_auth::{Establishing, receiver_control_alias};
use super::{Half, Mode, SenderRole, Sent};
use crate::agents::EndpointId;
use crate::embedded::StreamTerms;
use crate::wire_enc::vm_generation;
use crate::wire_enc::{
    ChannelKeys, EncChannel, EncKeyError, EncOpener, EncRejections, EncSealer, PairwiseFiles,
    Pending, RetiredBoots, VmGenerationWatch, header, id128, open_bootstrap_in, publication_of,
    quiesced,
};
use crate::wire_keys::KeyFile;
use karyos_io::sockets::ops::SocketOps;
use std::net::SocketAddr;

/// How many fresh challenges of one receiver boot may re-key a binding
/// its receiver never confirmed (H8-30); more are refused (fail closed).
const MAX_RECHALLENGES: usize = 4;

/// A receiver's binding: its block, the nonce of the challenge that bound
/// it, and its committed domain 4 keys.
#[derive(Debug)]
struct Bound {
    receiver: ReceiverIdentity,
    nonce: [u8; 16],
    opener: EncOpener,
    /// Whether a control of the receiver opened under `opener`: the
    /// receiver holds the keys of `nonce`, so its answer arrived.
    confirmed: bool,
    /// The nonces of this boot's earlier, never confirmed, bindings: each
    /// one's domain 1 key may have sealed, so none binds again (H8-30).
    superseded: [Option<[u8; 16]>; MAX_RECHALLENGES],
}

/// A new binding a verified RSP_SETUP staged: its domain 4 keys, made
/// but not yet the publication's. [`PublicationEnc::commit`] retires the
/// old boot and binds it; dropped, it changes nothing (H8-25).
#[derive(Debug)]
pub(crate) struct Staged(Bound);

/// What the publisher does after a verified RSP_SETUP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EncEstablishing {
    /// The receiver of the establishment.
    pub(crate) receiver: ReceiverIdentity,
    /// The challenge nonce: with the boot id, the domain 1 salt.
    pub(crate) nonce: [u8; 16],
    /// Whether it is a new binding; the bound one's answer is resent and
    /// neither re-derives a key nor resets a window (section 7).
    pub(crate) bind: bool,
    /// Whether it is the section 6b resynchronisation of a confirmed
    /// binding: answered with no key change, its runtime binding keeps its
    /// receiver id, consumption and liveness (H8-36).
    pub(crate) resync: bool,
}

/// A control that verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EncOpened {
    /// An RSP_SETUP: answer it, and on a new binding install the sealer.
    RspSetup(Control, EncEstablishing),
    /// An SM, NAK or RTTM REQUEST of the bound receiver.
    Receiver(Control),
}

/// The encrypted keys of one publication.
#[derive(Debug)]
pub(crate) struct PublicationEnc {
    pub(crate) endpoint: EndpointId,
    pub(crate) alias: Alias,
    identity: Identity,
    publication: PublicationIdentity,
    keys: ChannelKeys,
    pairwise: PairwiseFiles,
    /// Domain 5: SETUP ANNOUNCE and ENC ANSWER, one key and counter for
    /// the publication's life under its `key_epoch`; `None` once a VM
    /// generation change closed the publication (section 10).
    setup: Option<EncSealer>,
    bound: Option<Bound>,
    retired: RetiredBoots,
    /// The channel's rate counters and rejections by reason.
    pub(crate) channel: EncChannel,
    clock: fn() -> u64,
    /// The scratch slot of its domain 6 opens, made here and re-keyed for
    /// each RSP_SETUP: the data path constructs no key.
    bootstrap: Option<AesGcmSiv>,
}

impl PublicationEnc {
    /// The encrypted keys of the publication `alias` on `endpoint` of
    /// `identity`: `channel` its one or two `profile_id=16` channel files,
    /// `pairwise` the files of the receivers it serves. A publication with
    /// no pairwise file cannot serve an `encrypted` channel.
    ///
    /// # Errors
    ///
    /// [`EncKeyError`] when a file is of the other class or purpose, or
    /// the identity is invalid.
    pub(crate) fn new(
        endpoint: EndpointId,
        alias: Alias,
        identity: Identity,
        channel: &[&KeyFile],
        pairwise: &[&KeyFile],
        clock: fn() -> u64,
    ) -> Result<Self, EncKeyError> {
        let keys = ChannelKeys::new(channel)?;
        let pairwise = PairwiseFiles::new(pairwise)?;
        let mut made = Self {
            endpoint,
            alias,
            identity,
            publication: publication_of(&identity),
            keys,
            pairwise,
            setup: None,
            bound: None,
            retired: RetiredBoots::default(),
            channel: EncChannel::default(),
            clock,
            bootstrap: None,
        };
        made.rekey()?;
        Ok(made)
    }

    /// Makes the domain 5 sealer and the domain 6 scratch slot under the
    /// publication's identity, at construction and after a VM generation
    /// change (section 10 step 4).
    ///
    /// # Errors
    ///
    /// [`EncKeyError`]; nothing changes.
    fn rekey(&mut self) -> Result<(), EncKeyError> {
        let setup = EncSealer::new(
            &self.keys,
            None,
            KeyContext {
                domain: Domain::Setup,
                // Sending takes the signing epoch (H8-06).
                key_epoch: self.keys.signing_epoch().ok_or(EncKeyError::NoKey)?,
                party_epoch: 0,
                session_id: self.alias.session_id,
                stream_id: self.alias.stream_id,
                publication: self.publication,
                receiver: None,
                salt: Salt::Empty,
            },
            self.clock,
        )?;
        let bootstrap = EncSealer::new(&self.keys, None, *setup.context(), self.clock)?.into_key();
        self.setup = Some(setup);
        self.bootstrap = Some(bootstrap);
        Ok(())
    }

    /// Sends under the channel file epoch `epoch`, the one the admission
    /// view signs with (H8-06): its domain 5 keys are made again under it,
    /// before anything was sealed.
    ///
    /// # Errors
    ///
    /// [`EncKeyError::NoKey`] when that epoch is not held; or as
    /// [`Self::rekey`].
    pub(crate) fn sign_with(&mut self, epoch: u32) -> Result<(), EncKeyError> {
        if !self.keys.set_signing(epoch) {
            return Err(EncKeyError::NoKey);
        }
        self.rekey()
    }

    /// Takes `identity`, the fresh incarnation identity of section 10 step
    /// 3: the publication's keys stay dropped until [`Self::rekey`], and
    /// its retired boot ids, which named the old identity, go.
    fn reidentify(&mut self, identity: Identity) {
        self.close();
        self.identity = identity;
        self.publication = publication_of(&identity);
        self.retired = RetiredBoots::default();
    }

    /// The publication's incarnation identity (tests).
    #[cfg(test)]
    pub(crate) fn identity(&self) -> Identity {
        self.identity
    }

    /// Applies the key store's current key set (H8 finding 4): the files
    /// no longer named are erased; the domain 5 sealer and the bound
    /// receiver's domain 4 opener are withdrawn once their key epoch or a
    /// pairwise file is revoked or expired, so the publication neither
    /// announces nor accepts its receiver's controls (fail closed). Its
    /// domain 1 sealer is the `Outbound`'s ([`super::SenderRole::apply_keys`]).
    /// The retired boot ids of a file epoch that no longer verifies go
    /// (section 7, H8-07); those of every epoch still accepted stay.
    pub(crate) fn apply_keys(&mut self, keys: &dyn crate::wire_auth::KeySet) {
        // Rotation: a newly admitted epoch serves the next answers,
        // bindings and scratch derivations, admitted before its
        // predecessor goes.
        self.keys.admit(keys);
        self.pairwise.admit(keys);
        self.keys.retain(keys);
        self.pairwise.retain(keys);
        self.keys.follow_signing(keys);
        self.pairwise.follow_signing(keys);
        // Its domain 6 scratch slot holds the last RSP_SETUP's key, the
        // receiver's pairwise HMAC states with it: erased in place, so no
        // rotated or retired file's schedule survives (H8-05).
        crate::wire_enc::erase_slot(&mut self.bootstrap);
        if let Some(oldest) = self.keys.oldest_epoch() {
            self.retired.expire(oldest);
        }
        if let Some(setup) = &mut self.setup {
            setup.apply_keys(keys);
        }
        if let Some(bound) = self.bound.as_mut() {
            bound.opener.apply_keys(keys);
        }
    }

    /// Opens `datagram`, an envelope for this publication, into `out`
    /// before any inner frame is read, and returns its control, committed
    /// at once as an accepting handler would (tests). The reason of a
    /// refusal is counted and nothing else changes.
    ///
    /// # Errors
    ///
    /// The [`EncRejection`].
    #[cfg(test)]
    pub(crate) fn open(
        &mut self,
        datagram: &[u8],
        out: &mut [u8; MAX_PLAINTEXT],
    ) -> Result<EncOpened, EncRejection> {
        let (opened, staged, pending) = self.open_staged(datagram, out)?;
        if let Some(staged) = staged {
            self.commit(staged)?;
        }
        if let Some(pending) = pending {
            self.commit_receiver(pending)?;
        }
        Ok(opened)
    }

    /// Opens `datagram` as [`Self::open`], committing nothing: a new
    /// binding is only staged, nothing of it the publication's until
    /// [`Self::commit`], which the caller runs once the answer and the
    /// runtime binding are admitted (H8-25); a receiver control (domain 4)
    /// is only verified, its [`Pending`] committed by
    /// [`Self::commit_receiver`] once its handler accepted it (sections 8
    /// and 9): a control its handler refuses marks no sequence and
    /// promotes no epoch.
    ///
    /// # Errors
    ///
    /// The [`EncRejection`].
    pub(crate) fn open_staged(
        &mut self,
        datagram: &[u8],
        out: &mut [u8; MAX_PLAINTEXT],
    ) -> Result<(EncOpened, Option<Staged>, Option<Pending>), EncRejection> {
        let result = self.open_uncounted(datagram, out);
        if let Err(reason) = &result {
            self.channel.rejections.bump(*reason);
        }
        result
    }

    /// Commits a receiver control its handler accepted (section 8 steps 8
    /// and 9): its sequence is marked and a next epoch promoted, and the
    /// binding is confirmed, the receiver holding its keys. A refusal is
    /// counted and changes nothing.
    ///
    /// # Errors
    ///
    /// The [`EncRejection`] of [`EncOpener::commit`], or
    /// [`EncRejection::Party`] with no binding.
    pub(crate) fn commit_receiver(&mut self, pending: Pending) -> Result<(), EncRejection> {
        let now = (self.clock)();
        let result = self
            .bound
            .as_mut()
            .ok_or(EncRejection::Party)
            .and_then(|bound| {
                bound.opener.commit(pending, now)?;
                // Opened under its keys and accepted: the receiver took
                // this binding's answer.
                bound.confirmed = true;
                Ok(())
            });
        if let Err(reason) = result {
            self.channel.rejections.bump(reason);
        }
        result
    }

    /// Commits a staged binding: the bound receiver's boot id is retired
    /// and the staged one bound, all or nothing.
    ///
    /// # Errors
    ///
    /// [`EncRejection::RetiredBoot`] when the retired table is full (the
    /// staging checked it); nothing changes.
    pub(crate) fn commit(&mut self, staged: Staged) -> Result<(), EncRejection> {
        // A re-key of the same boot (H8-30) retires nothing.
        if let Some(old) = self
            .bound
            .as_ref()
            .filter(|old| old.receiver != staged.0.receiver)
        {
            self.retired
                .retire(&old.receiver, self.keys.current_epoch())?;
        }
        self.bound = Some(staged.0);
        Ok(())
    }

    fn open_uncounted(
        &mut self,
        datagram: &[u8],
        out: &mut [u8; MAX_PLAINTEXT],
    ) -> Result<(EncOpened, Option<Staged>, Option<Pending>), EncRejection> {
        // Section 10: nothing is opened after a VM generation change.
        if quiesced() {
            return Err(EncRejection::VmGeneration);
        }
        let head = header(datagram)?;
        if (head.session_id, head.stream_id) != (self.alias.session_id, self.alias.stream_id) {
            return Err(EncRejection::Binding);
        }
        match head.domain {
            Domain::RspSetup => self
                .rsp_setup(datagram, out)
                .map(|(opened, staged)| (opened, staged, None)),
            Domain::Receiver => self
                .receiver(datagram, out, head.receiver)
                .map(|(control, pending)| (EncOpened::Receiver(control), None, Some(pending))),
            Domain::Sender | Domain::Setup => Err(EncRejection::Domain),
        }
    }

    fn rsp_setup(
        &mut self,
        datagram: &[u8],
        out: &mut [u8; MAX_PLAINTEXT],
    ) -> Result<(EncOpened, Option<Staged>), EncRejection> {
        let now = (self.clock)();
        let (alias, identity) = (self.alias, self.identity);
        let mut found = None;
        let opened = open_bootstrap_in(
            &mut self.bootstrap,
            &self.keys,
            Some(&self.pairwise),
            Some(self.publication),
            datagram,
            out,
            &mut self.channel.rate,
            now,
            |_, frames| {
                found = match classify(frames) {
                    Ok(Datagram::Control(control @ Control::Challenge(challenge)))
                        if challenge.alias == alias && challenge.identity == identity =>
                    {
                        Some((control, challenge.challenge))
                    }
                    Ok(Datagram::Control(control @ Control::Solicit(solicit)))
                        if solicit.alias == alias =>
                    {
                        Some((control, solicit.challenge))
                    }
                    _ => None,
                };
                found.map(|_| ()).ok_or(EncRejection::InnerRejected)
            },
        )?;
        let (control, challenge) = found.ok_or(EncRejection::InnerRejected)?;
        let receiver = opened.header.receiver.ok_or(EncRejection::Party)?;
        // The challenge names the boot id the envelope's party carries.
        if id128(challenge.receiver_boot_id) != receiver.receiver_boot_id {
            return Err(EncRejection::InnerRejected);
        }
        // Section 7: only the current file epoch creates or changes a
        // binding; the retired boot ids never come back.
        if !opened.current_epoch {
            return Err(EncRejection::Epoch);
        }
        if self.retired.contains(&receiver) {
            return Err(EncRejection::RetiredBoot);
        }
        let nonce = id128(challenge.nonce);
        let mut superseded = [None; MAX_RECHALLENGES];
        if let Some(bound) = &self.bound {
            let same = bound.receiver == receiver;
            // No earlier nonce of this boot binds or is answered again,
            // whatever the binding's state (H8-36): its domain 1 key may
            // have sealed under a sequence restarted at 0, and a replayed
            // challenge changes nothing.
            if same && bound.superseded.contains(&Some(nonce)) {
                return Err(EncRejection::RetiredBoot);
            }
            let answer = |resync| {
                Ok((
                    EncOpened::RspSetup(
                        control,
                        EncEstablishing {
                            receiver,
                            nonce: bound.nonce,
                            bind: false,
                            resync,
                        },
                    ),
                    None,
                ))
            };
            if same && bound.nonce == nonce {
                // The bound challenge: before confirmation its answer was
                // lost and the receiver, still challenging, gets it again,
                // which re-derives nothing. Once a control opened under the
                // binding the receiver installed it and never sends that
                // challenge again: a copy is a replay, refused, and changes
                // no key, binding or runtime state (H8-36).
                if bound.confirmed {
                    return Err(EncRejection::Duplicate);
                }
                return answer(false);
            }
            if same && bound.confirmed {
                // A confirmed binding keeps its salt (section 6b step 2):
                // the resynchronisation answer changes no key.
                return answer(matches!(control, Control::Solicit(_)));
            }
            if same && !matches!(control, Control::Challenge(_)) {
                // Before confirmation a fresh SOLICIT of the bound boot may
                // be the section 6b resynchronisation of a receiver that
                // installed the bound nonce (its first control delayed or
                // lost): it keeps its salt, so a re-key here would split
                // the two (H8-31), while answering it unchanged would split
                // an unbound one, which takes the nonce it is answered
                // with. Neither is answered; nothing changes. A receiver
                // that lost its answer is unbound and establishes through
                // the ANNOUNCE's CHALLENGE below, which an installed one
                // never sends (it drops its bound identity's ANNOUNCE); an
                // installed one resynchronises once its first SM confirms
                // the binding.
                return Err(EncRejection::ResyncRefused);
            }
            if same {
                // The bound boot's fresh CHALLENGE before confirmation: its
                // answer was lost, so the receiver, unbound, takes the salt
                // of the nonce it is answered with (sections 4 and 7). The
                // binding is re-keyed to it, staged.
                superseded = bound.superseded;
                let free = superseded
                    .iter_mut()
                    .find(|held| held.is_none())
                    .ok_or(EncRejection::RetiredBoot)?;
                *free = Some(bound.nonce);
            } else if bound.receiver.receiver_id != receiver.receiver_id {
                // One receiver per publication (unicast).
                return Err(EncRejection::Party);
            } else if !self.retired.has_room() {
                return Err(EncRejection::RetiredBoot);
            }
        }
        let context = self.receiver_context(&receiver, nonce, opened.header.key_epoch);
        let opener = EncOpener::new(&self.keys, Some(&self.pairwise), context, now)
            .map_err(|_| EncRejection::Pairwise)?;
        // Staged: the old boot is retired and this one bound only by
        // `commit`, once the answer is admitted (H8-25).
        Ok((
            EncOpened::RspSetup(
                control,
                EncEstablishing {
                    receiver,
                    nonce,
                    bind: true,
                    resync: false,
                },
            ),
            Some(Staged(Bound {
                receiver,
                nonce,
                opener,
                confirmed: false,
                superseded,
            })),
        ))
    }

    /// A domain 4 control of the bound receiver, verified and not
    /// committed: its frame must name this binding (alias, boot id and
    /// receiver id) and be one of its receiver controls; whether it takes
    /// effect is its handler's decision, and only then is it committed
    /// ([`Self::commit_receiver`]).
    fn receiver(
        &mut self,
        datagram: &[u8],
        out: &mut [u8; MAX_PLAINTEXT],
        party: Option<ReceiverIdentity>,
    ) -> Result<(Control, Pending), EncRejection> {
        let now = (self.clock)();
        let party = party.ok_or(EncRejection::Party)?;
        if self.retired.contains(&party) {
            return Err(EncRejection::RetiredBoot);
        }
        let alias = self.alias;
        let Some(bound) = self.bound.as_mut().filter(|bound| bound.receiver == party) else {
            // No slot is made for an unverified header identity.
            return Err(EncRejection::Party);
        };
        let mut found = None;
        let pending =
            bound
                .opener
                .verify(datagram, out, &mut self.channel.rate, now, |frames| {
                    found = match classify(frames) {
                        Ok(Datagram::Control(control))
                            if receiver_control_alias(&control) == Some(alias)
                                && !matches!(
                                    control,
                                    Control::Challenge(_) | Control::Solicit(_)
                                )
                                && control_receiver(&control).is_some_and(|receiver| {
                                    id128(receiver.receiver_boot_id) == party.receiver_boot_id
                                        && receiver.receiver_id == party.receiver_id
                                }) =>
                        {
                            Some(control)
                        }
                        _ => None,
                    };
                    found.map(|_| ()).ok_or(EncRejection::InnerRejected)
                })?;
        found
            .map(|control| (control, pending))
            .ok_or(EncRejection::InnerRejected)
    }

    /// The domain 4 context of `receiver` under the challenge `nonce`, at
    /// `key_epoch`, the current one its RSP_SETUP verified under.
    fn receiver_context(
        &self,
        receiver: &ReceiverIdentity,
        nonce: [u8; 16],
        key_epoch: u32,
    ) -> KeyContext {
        KeyContext {
            domain: Domain::Receiver,
            key_epoch,
            party_epoch: 0,
            session_id: self.alias.session_id,
            stream_id: self.alias.stream_id,
            publication: self.publication,
            receiver: Some(*receiver),
            salt: Salt::Challenge {
                receiver_boot_id: receiver.receiver_boot_id,
                nonce,
            },
        }
    }

    /// The session's domain 1 sealer of an establishment: the current file
    /// epoch, `party_epoch` 0, salted with the completed challenge.
    ///
    /// # Errors
    ///
    /// [`EncKeyError`] when the key cannot be derived.
    pub(crate) fn data_sealer(
        &self,
        establishing: &EncEstablishing,
    ) -> Result<EncSealer, EncKeyError> {
        EncSealer::new(
            &self.keys,
            None,
            KeyContext {
                domain: Domain::Sender,
                // Sending takes the signing epoch (H8-06).
                key_epoch: self.keys.signing_epoch().ok_or(EncKeyError::NoKey)?,
                party_epoch: 0,
                session_id: self.alias.session_id,
                stream_id: self.alias.stream_id,
                publication: self.publication,
                receiver: None,
                salt: Salt::Challenge {
                    receiver_boot_id: establishing.receiver.receiver_boot_id,
                    nonce: establishing.nonce,
                },
            },
            self.clock,
        )
    }

    /// Seals `answer` as an ENC ANSWER (variant 3, section 6a) in domain 5
    /// into `out`, stating the epochs the session sealer actually holds
    /// (`session`, its key and party epochs), which must be the domain 5
    /// sealer's own key epoch, so the body and the envelope agree (H8-06);
    /// with no session sealer yet, the domain 5 sealer's key epoch and
    /// `party_epoch` 0. Every answer on an `encrypted` channel is a
    /// variant 3. `None` when the epochs disagree or it does not encode or
    /// seal: nothing is sent.
    pub(crate) fn seal_answer(
        &mut self,
        answer: SetupAnswer,
        session: Option<(u32, u16)>,
        out: &mut [u8],
    ) -> Option<usize> {
        let setup = self.setup.as_mut()?;
        let key_epoch = setup.context().key_epoch;
        let party_epoch = match session {
            None => 0,
            Some((session_epoch, party_epoch)) if session_epoch == key_epoch => party_epoch,
            Some(_) => return None,
        };
        let enc = EncAnswer {
            answer,
            key_epoch,
            party_epoch,
        };
        let length = enc.encode(out).ok()?;
        setup.seal(out, length).ok()
    }

    /// Seals an encoded SETUP ANNOUNCE (the first `frames` bytes of `out`)
    /// in domain 5.
    pub(crate) fn seal_announce(&mut self, out: &mut [u8], frames: usize) -> Option<usize> {
        self.setup.as_mut()?.seal(out, frames).ok()
    }

    /// Section 10 step 2: drops every derived key and sequence of the
    /// publication, which erases them: its domain 5 sealer, its binding's
    /// domain 4 keys and its scratch slot. The entry and its key files
    /// stay, so that it sends nothing bare and opens nothing.
    fn close(&mut self) {
        self.setup = None;
        self.bound = None;
        self.bootstrap = None;
    }

    /// Erases the bound receiver's previous epoch key once its overlap
    /// has passed (H8-16): [`EncOpener::expire_previous`].
    fn expire_previous(&mut self) {
        let now = (self.clock)();
        if let Some(bound) = self.bound.as_mut() {
            bound.opener.expire_previous(now);
        }
    }

    /// The bound receiver's domain 4 epoch pair (tests).
    #[cfg(test)]
    pub(crate) fn bound_epochs(&self) -> Option<(u32, u16)> {
        self.bound.as_ref().map(|bound| bound.opener.epochs())
    }

    /// Whether the bound receiver's opener holds a previous epoch's key
    /// (tests).
    #[cfg(test)]
    pub(crate) fn bound_has_previous(&self) -> bool {
        self.bound
            .as_ref()
            .is_some_and(|bound| bound.opener.has_previous())
    }

    /// The bound receiver (tests).
    #[cfg(test)]
    pub(crate) fn bound_receiver(&self) -> Option<ReceiverIdentity> {
        self.bound.as_ref().map(|bound| bound.receiver)
    }
}

/// The encrypted class of a sender role.
#[derive(Debug, Default)]
pub(crate) struct SenderEnc {
    publications: Vec<PublicationEnc>,
    /// Envelopes for no encrypted publication, by reason.
    pub(crate) unattributed: EncRejections,
    /// The VM generation signal, read once the role has an encrypted
    /// publication (section 10).
    watch: Option<VmGenerationWatch>,
    /// The role's place in the fence, from its first watch on; dropped
    /// with the role, it leaves the fence (H8-21).
    registration: Option<vm_generation::Registration>,
    /// The VM generation the role last redrew its identities for.
    seen: u64,
    /// Per channel key id, the highest file epoch seen to sign this boot:
    /// a publication made again starts at it (H8-17).
    activation: crate::wire_enc::ActivationFloors,
    /// The confirmed binding whose section 6b resynchronisation is being
    /// answered: publication and boot id. Its runtime binding is kept as
    /// it is, receiver id, consumption and liveness included (H8-36). Set
    /// by the open of that SOLICIT, taken by its answer.
    pub(super) keep_binding: Option<(EndpointId, Alias, [u64; 2])>,
}

/// A receiver control verified under its publication's domain 4 keys and
/// not yet committed: its handler decides, then
/// [`SenderRole::settle_enc`] commits it if it accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct EncReceived {
    endpoint: EndpointId,
    alias: Alias,
    pending: Pending,
}

impl SenderEnc {
    /// Applies the key store's current key set to every encrypted
    /// publication (H8 finding 4): see [`PublicationEnc::apply_keys`].
    pub(crate) fn apply_keys(&mut self, keys: &dyn crate::wire_auth::KeySet) {
        for publication in &mut self.publications {
            publication.apply_keys(keys);
            self.activation.hold(&mut publication.keys);
        }
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

    /// Makes the publication `publication` names encrypted, replacing an
    /// earlier one of its key; its `Outbound` must have been made
    /// encrypted too.
    pub(crate) fn publish(&mut self, mut publication: PublicationEnc) {
        self.unpublish(publication.endpoint, publication.alias);
        // It starts at the role's activation floor, not 0 (H8-17).
        self.activation.hold(&mut publication.keys);
        self.publications.push(publication);
    }

    /// Drops the encrypted publication `alias` on `endpoint`, its keys
    /// erased on drop.
    pub(crate) fn unpublish(&mut self, endpoint: EndpointId, alias: Alias) {
        self.publications
            .retain(|publication| (publication.endpoint, publication.alias) != (endpoint, alias));
    }

    /// The rejections of the encrypted publication `alias` on `endpoint`.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "no encrypted channel opens yet")
    )]
    pub(crate) fn rejections(&self, endpoint: EndpointId, alias: Alias) -> Option<EncRejections> {
        self.publications
            .iter()
            .find(|publication| publication.endpoint == endpoint && publication.alias == alias)
            .map(|publication| publication.channel.rejections)
    }
}

impl<T: StreamTerms> SenderRole<T> {
    /// Section 10 on the send side, once per duty at `now`, while the role
    /// has an encrypted publication: reads the VM generation signal and,
    /// on a change seen by this role or any other:
    ///
    /// 1. the fence already stops every key made before the change;
    /// 2. every publication's keys are dropped and every session sealer is
    ///    taken out of its `Outbound`, which erases them;
    /// 3. each publication takes a fresh `driver_id`, the one the fence's
    ///    table gives the embedded driver too, in its SETUP side and in its
    ///    repair path's ERRs, and is no longer established;
    /// 4. once every role has redrawn and the fence releases, its domain 5
    ///    keys are made under the new identity, it announces, and the
    ///    fresh challenge of each receiver binds it again.
    ///
    /// When no fresh `driver_id` can be drawn nothing is redrawn, the
    /// fence stays held and the next duty tries again (fail closed).
    pub(super) fn on_generation_change(&mut self, now: u64) {
        // Each duty erases a bound receiver's previous epoch key past its
        // overlap (H8-16), on the publication's own clock.
        for publication in &mut self.enc.publications {
            publication.expire_previous();
        }
        // A role registered with the fence keeps maintaining, with no
        // publication left too: it still observes every change and reports
        // itself redrawn, so it never holds the fence for others (H8-19).
        if self.enc.publications.is_empty()
            && self.publication_auth.is_empty()
            && self.enc.watch.is_none()
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
        if current != self.enc.seen {
            // Step 2 at once, whether or not step 3 can be done: when no
            // fresh `driver_id` is given (no random word, a full table, or a
            // role too far behind), the role stays closed and unredrawn, so
            // the fence stays held and nothing runs under the old identity.
            for publication in &mut self.enc.publications {
                publication.close();
            }
            for outbound in &mut self.publications {
                outbound.retire_enc_sealer();
            }
            // The authenticated class, closed first as well (ADR-0086
            // section 7, "Snapshot rollback and clones"; karyos#648): every
            // receiver binding and boot id is forgotten and every session
            // sealer is taken out of its `Outbound`, which erases it, and
            // its SETUP side starts again, so it announces and binds only
            // through a fresh challenge once the fence releases. While the
            // fence is held no receiver control of it is opened.
            for auth in &mut self.publication_auth {
                auth.unbind_all();
            }
            for outbound in &mut self.publications {
                outbound.retire_auth_sealer();
            }
            // Every fresh identity, of either class, is drawn before any is
            // applied: a refused successor redraws nothing.
            if self.auth_successors(current) && self.redraw(current) {
                self.reidentify_auth(current);
                self.enc.seen = current;
                if let Some(registration) = self.enc.registration.as_mut() {
                    registration.redrawn(current);
                }
            }
        }
        // Step 4, only under the identity of the current generation.
        if current == self.enc.seen && !vm_generation::quiesced() {
            for publication in &mut self.enc.publications {
                if publication.setup.is_none() {
                    let _ = publication.rekey();
                }
            }
        }
    }

    /// Whether every authenticated publication has a fresh `driver_id`
    /// for each generation up to `current` (drawn now, kept by the fence's
    /// table); nothing is applied.
    fn auth_successors(&self, current: u64) -> bool {
        let first = self.enc.seen.saturating_add(1);
        self.publication_auth.iter().all(|auth| {
            let Some(held) = self.sessions.identity(auth.endpoint, auth.alias) else {
                return true;
            };
            let mut driver = held.driver_id;
            (first..=current).all(|generation| {
                vm_generation::successor(driver, generation).is_some_and(|next| {
                    driver = next;
                    true
                })
            })
        })
    }

    /// Gives each authenticated publication its fresh `driver_id` for
    /// `current` (ADR-0086 section 7 under a fresh identity; karyos#648):
    /// its SETUP side starts again under it, so it announces and binds
    /// only through a fresh challenge, and its repair path's ERRs name it.
    /// A receiver quarantines the retired identity, never this one.
    fn reidentify_auth(&mut self, current: u64) {
        let first = self.enc.seen.saturating_add(1);
        for auth in &self.publication_auth {
            let (endpoint, alias) = (auth.endpoint, auth.alias);
            let Some(held) = self.sessions.publication(endpoint, alias) else {
                continue;
            };
            let mut identity = held.identity;
            for generation in first..=current {
                if let Some(next) = vm_generation::successor(identity.driver_id, generation) {
                    identity.driver_id = next;
                }
            }
            let _ = self.sessions.remove(endpoint, alias);
            let _ = self
                .sessions
                .add(crate::sessions::send::Publication { identity, ..held });
            if let Some(outbound) = self
                .publications
                .iter_mut()
                .find(|outbound| outbound.serves(endpoint) && outbound.alias() == alias)
            {
                outbound.set_repair_identity(identity);
                // Its membership judges the new incarnation's SMs (H8-32).
                if let Some(membership) = outbound.membership_mut() {
                    membership.reidentify(identity);
                }
            }
        }
    }

    /// Step 3 for `current`; `false` when a fresh `driver_id` could not be
    /// drawn, with nothing redrawn.
    fn redraw(&mut self, current: u64) -> bool {
        let first = self.enc.seen.saturating_add(1);
        // Every new identity first, so that a failed draw redraws nothing.
        for publication in &self.enc.publications {
            let mut driver = publication.identity.driver_id;
            for generation in first..=current {
                match vm_generation::successor(driver, generation) {
                    Some(next) => driver = next,
                    None => return false,
                }
            }
        }
        for publication in &mut self.enc.publications {
            let mut identity = publication.identity;
            for generation in first..=current {
                if let Some(next) = vm_generation::successor(identity.driver_id, generation) {
                    identity.driver_id = next;
                }
            }
            let (endpoint, alias) = (publication.endpoint, publication.alias);
            publication.reidentify(identity);
            if let Some(held) = self.sessions.publication(endpoint, alias) {
                let _ = self.sessions.remove(endpoint, alias);
                let _ = self
                    .sessions
                    .add(crate::sessions::send::Publication { identity, ..held });
            }
            if let Some(outbound) = self
                .publications
                .iter_mut()
                .find(|outbound| outbound.serves(endpoint) && outbound.alias() == alias)
            {
                outbound.set_repair_identity(identity);
                // Its membership judges the new incarnation's SMs (H8-32).
                if let Some(membership) = outbound.membership_mut() {
                    membership.reidentify(identity);
                }
            }
        }
        true
    }

    /// The VM generation the role last redrew for (tests).
    #[cfg(test)]
    pub(crate) fn enc_generation(&self) -> u64 {
        self.enc.seen
    }

    /// The incarnation identity of the encrypted publication `alias` on
    /// `endpoint` (tests).
    #[cfg(test)]
    pub(crate) fn enc_identity(&self, endpoint: EndpointId, alias: Alias) -> Option<Identity> {
        self.enc
            .publications
            .iter()
            .find(|publication| publication.endpoint == endpoint && publication.alias == alias)
            .map(PublicationEnc::identity)
    }

    /// Makes the publication `publication` names encrypted; its
    /// `Outbound` must be made encrypted too, before any traffic.
    pub(crate) fn encrypt_publication(&mut self, publication: PublicationEnc) {
        self.enc.publish(publication);
    }

    /// The rejections of the encrypted publication `alias` on `endpoint`
    /// (tests).
    #[cfg(test)]
    pub(crate) fn enc_rejections(
        &self,
        endpoint: EndpointId,
        alias: Alias,
    ) -> Option<EncRejections> {
        self.enc.rejections(endpoint, alias)
    }

    /// Opens an encrypted envelope for a local encrypted publication under
    /// its keys and returns its control; `None` when refused (counted by
    /// reason), with nothing else changed. A verified RSP_SETUP that binds
    /// a new receiver installs the session's domain 1 sealer at once: the
    /// one establishment owns it, and nothing of the previous binding's
    /// key survives.
    ///
    /// A receiver control (SM, NAK, RTTM REQUEST) comes back verified and
    /// uncommitted, with its [`EncReceived`]: the caller hands it to its
    /// handler and commits it ([`SenderRole::settle_enc`]) only if the
    /// handler accepted it, so a control any handler refuses marks no
    /// sequence and promotes no epoch, with no copy of the handler's
    /// checks here (sections 8 and 9).
    ///
    /// Admit, then commit (H8-25): a new binding's CHALLENGE or SOLICIT
    /// is admitted only if its ANSWER would go (route, session, answer
    /// rate) and its runtime binding would be kept, which reserves its
    /// capacity before anything is bound. Only then is the old boot
    /// retired, the domain 4 opener bound and the domain 1 sealer
    /// installed; a refused one changes none of them. `source` is the
    /// datagram's source; `None` (tests only) skips that admission.
    pub(super) fn open_enc(
        &mut self,
        endpoint: EndpointId,
        source: Option<SocketAddr>,
        bytes: &[u8],
        now: u64,
    ) -> Option<(Control, Option<Establishing>, Option<EncReceived>)> {
        // Only the RSP_SETUP of this open may mark its runtime binding as
        // kept (H8-36).
        self.enc.keep_binding = None;
        let alias = header(bytes).map(|head| Alias {
            session_id: head.session_id,
            stream_id: head.stream_id,
        });
        let alias = match alias {
            Ok(alias) => alias,
            Err(reason) => {
                self.enc.unattributed.bump(reason);
                return None;
            }
        };
        let Some(at) =
            self.enc.publications.iter().position(|publication| {
                publication.endpoint == endpoint && publication.alias == alias
            })
        else {
            self.enc.unattributed.bump(EncRejection::Binding);
            return None;
        };
        let publication = self.enc.publications.get_mut(at)?;
        let mut out = [0_u8; MAX_PLAINTEXT];
        match publication.open_staged(bytes, &mut out) {
            Ok((EncOpened::Receiver(control), _, pending)) => {
                let pending = pending?;
                Some((
                    control,
                    None,
                    Some(EncReceived {
                        endpoint,
                        alias,
                        pending,
                    }),
                ))
            }
            Ok((EncOpened::RspSetup(control, establishing), staged, _)) => {
                // Admit the ANSWER and its runtime binding, of a bound
                // receiver too (H8-25): one with no room is not answered.
                let answered = source
                    .is_none_or(|source| self.enc_answer_admitted(endpoint, source, &control, now));
                if !answered {
                    self.count(|c| &mut c.establishment_refused);
                    return None;
                }
                if let Some(staged) = staged {
                    // Admit: everything else that could still refuse it.
                    let sealer = self
                        .enc
                        .publications
                        .get(at)?
                        .data_sealer(&establishing)
                        .ok()?;
                    let installable = self
                        .publications
                        .iter()
                        .find(|outbound| outbound.serves(endpoint) && outbound.alias() == alias)
                        .is_some_and(|outbound| outbound.admits_enc_sealer(&sealer));
                    if !installable {
                        self.count(|c| &mut c.establishment_refused);
                        return None;
                    }
                    // Commit: the binding, then the session sealer.
                    self.enc.publications.get_mut(at)?.commit(staged).ok()?;
                    let fence = std::sync::Arc::clone(&self.key_generation);
                    if let Some(outbound) = self
                        .publications
                        .iter_mut()
                        .find(|outbound| outbound.serves(endpoint) && outbound.alias() == alias)
                    {
                        // Admitted above: it installs.
                        let _ = outbound.install_enc_sealer(sealer);
                        outbound.set_key_fence(fence);
                    }
                }
                if establishing.resync {
                    self.enc.keep_binding = Some((
                        endpoint,
                        alias,
                        match control {
                            Control::Solicit(solicit) => solicit.challenge.receiver_boot_id,
                            _ => return None,
                        },
                    ));
                }
                Some((control, None, None))
            }
            Err(_) => None,
        }
    }

    /// Settles the receiver control `received` once its handler decided:
    /// committed if it `accepted` it ([`PublicationEnc::commit_receiver`]),
    /// else counted as refused (`enc_inner_rejected`) with nothing marked
    /// or promoted. Whether it committed.
    pub(super) fn settle_enc(&mut self, received: EncReceived, accepted: bool) -> bool {
        let Some(publication) = self.enc.publications.iter_mut().find(|publication| {
            publication.endpoint == received.endpoint && publication.alias == received.alias
        }) else {
            return false;
        };
        if !accepted {
            publication
                .channel
                .rejections
                .bump(EncRejection::InnerRejected);
            return false;
        }
        publication.commit_receiver(received.pending).is_ok()
    }

    /// Whether [`SenderRole::answer_for`] would answer the domain 6
    /// CHALLENGE or SOLICIT `control` from `source` at `now`, and
    /// [`SenderRole::bind`] keep its runtime binding, as they decide it
    /// for a static unicast publication, charging nothing (H8-25): its
    /// route, a destination's source on a multi-destination one, the
    /// session's identity, joins and answer rate, and a binding already
    /// held for its tuple or room for one (a free one, or an eviction).
    /// A dynamic publication, whose answer takes a registrant's path,
    /// is refused: an encrypted one never is (fail closed). Only the
    /// bindings due by `now` expire, as `bind` expires them.
    fn enc_answer_admitted(
        &mut self,
        endpoint: EndpointId,
        source: SocketAddr,
        control: &Control,
        now: u64,
    ) -> bool {
        let (alias, boot_id) = match control {
            Control::Challenge(challenge) => {
                (challenge.alias, challenge.challenge.receiver_boot_id)
            }
            Control::Solicit(solicit) => (solicit.alias, solicit.challenge.receiver_boot_id),
            _ => return false,
        };
        let Some((_, joins)) = self.route_of(endpoint, alias) else {
            return false;
        };
        if self.registration_of(endpoint, alias) {
            return false;
        }
        let normal = crate::sessions::rate::normalized(source);
        if self.destinations_of(endpoint, alias) == Some(true)
            && !self.sends_to(endpoint, alias, normal)
        {
            return false;
        }
        if !self
            .sessions
            .would_answer(endpoint, source, now, control, joins.count())
        {
            return false;
        }
        let Some(identity) = self.sessions.identity(endpoint, alias) else {
            return false;
        };
        self.expire_bindings(now);
        let held = self.bindings.iter().any(|held| {
            held.parent.is_none()
                && held.endpoint == endpoint
                && held.alias == alias
                && held.solicited_from == normal
                && held.boot_id == boot_id
                && held.identity == identity
        });
        held || matches!(
            self.room_for(endpoint, alias, None),
            super::Room::Free | super::Room::Evict(_)
        )
    }
}

impl<T: StreamTerms> SenderRole<T> {
    /// Sends a SETUP of an encrypted publication sealed in domain 5, now or
    /// not at all: an ANNOUNCE as it is, an ANSWER as an ENC ANSWER stating
    /// the session's epochs (section 6a). `None` for a publication that is
    /// not encrypted, which takes its own path; never a bare SETUP.
    pub(super) fn send_enc_setup<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        endpoint: EndpointId,
        destination: SocketAddr,
        control: &Control,
    ) -> Option<Sent> {
        let alias = match control {
            Control::SetupAnnounce(announce) => announce.alias,
            Control::SetupAnswer(answer) => answer.alias,
            _ => return None,
        };
        let index = self.enc.publications.iter().position(|publication| {
            publication.endpoint == endpoint && publication.alias == alias
        })?;
        let session = self
            .publications
            .iter()
            .find(|outbound| outbound.serves(endpoint) && outbound.alias() == alias)
            .and_then(|outbound| outbound.enc_epochs());
        let mut bytes = [0_u8; crate::wire_enc::MAX_SEALED];
        let publication = self.enc.publications.get_mut(index)?;
        let length = match control {
            Control::SetupAnswer(answer) => publication.seal_answer(*answer, session, &mut bytes),
            _ => control
                .encode(&mut bytes)
                .ok()
                .and_then(|frames| publication.seal_announce(&mut bytes, frames)),
        };
        let Some(sealed) = length.and_then(|length| bytes.get(..length)) else {
            self.count(|c| &mut c.seal_failures);
            return Some(Sent::NotSubmitted);
        };
        Some(self.send_raw(halves, endpoint, destination, sealed))
    }

    /// Sends a sender control (PATH_HB, ERR, RTTM REPLY) of an encrypted
    /// publication sealed in domain 1 by its session sealer, or not at all
    /// while it has none. `None` for a publication that is not encrypted.
    pub(super) fn send_enc_sender_control<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        endpoint: EndpointId,
        destination: SocketAddr,
        control: &Control,
        alias: Alias,
    ) -> Option<Sent> {
        self.enc.publications.iter().position(|publication| {
            publication.endpoint == endpoint && publication.alias == alias
        })?;
        let index = self
            .publications
            .iter()
            .position(|outbound| outbound.serves(endpoint) && outbound.alias() == alias);
        let sealer = index
            .and_then(|index| self.publications.get_mut(index))
            .and_then(|outbound| outbound.lend_enc_sealer());
        let (Some(index), Some(mut sealer)) = (index, sealer) else {
            self.count(|c| &mut c.seal_failures);
            return Some(Sent::NotSubmitted);
        };
        let sent = self.send_with(
            halves,
            endpoint,
            destination,
            control,
            Mode::Now,
            Some(&mut *sealer),
        );
        if let Some(outbound) = self.publications.get_mut(index) {
            outbound.return_enc_sealer(sealer);
        }
        Some(sent)
    }
}

/// The receiver block a receiver control names.
fn control_receiver(control: &Control) -> Option<Receiver> {
    match control {
        Control::Status(status) => Some(status.receiver),
        Control::Nak(nak) => Some(nak.receiver),
        Control::Rttm(rttm) => Some(rttm.receiver),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
