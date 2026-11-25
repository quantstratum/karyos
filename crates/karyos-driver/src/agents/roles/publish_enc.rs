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
//! its counter. Nothing makes a publication encrypted yet: the class is
//! still refused at parse.

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
use crate::wire_enc::{
    ChannelKeys, EncChannel, EncKeyError, EncOpener, EncRejections, EncSealer, PairwiseFiles,
    RetiredBoots, header, id128, open_bootstrap_in, publication_of,
};
use crate::wire_keys::KeyFile;
use karyos_io::sockets::ops::SocketOps;
use std::net::SocketAddr;

/// A receiver's binding: its block, the nonce of the challenge that bound
/// it, and its committed domain 4 keys.
#[derive(Debug)]
struct Bound {
    receiver: ReceiverIdentity,
    nonce: [u8; 16],
    opener: EncOpener,
}

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
    /// the publication's life under its `key_epoch`.
    setup: EncSealer,
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
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "no encrypted channel opens yet")
    )]
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
        let publication = publication_of(&identity);
        let setup = EncSealer::new(
            &keys,
            None,
            KeyContext {
                domain: Domain::Setup,
                key_epoch: keys.current_epoch(),
                party_epoch: 0,
                session_id: alias.session_id,
                stream_id: alias.stream_id,
                publication,
                receiver: None,
                salt: Salt::Empty,
            },
            clock,
        )?;
        let bootstrap = EncSealer::new(&keys, None, *setup.context(), clock)?.into_key();
        Ok(Self {
            endpoint,
            alias,
            identity,
            publication,
            keys,
            pairwise,
            setup,
            bound: None,
            retired: RetiredBoots::default(),
            channel: EncChannel::default(),
            clock,
            bootstrap: Some(bootstrap),
        })
    }

    /// Applies the key store's current key set (H8 finding 4): the files
    /// no longer named are erased; the domain 5 sealer and the bound
    /// receiver's domain 4 opener are withdrawn once their key epoch or a
    /// pairwise file is revoked or expired, so the publication neither
    /// announces nor accepts its receiver's controls (fail closed). Its
    /// domain 1 sealer is the `Outbound`'s ([`super::SenderRole::apply_keys`]).
    pub(crate) fn apply_keys(&mut self, keys: &dyn crate::wire_auth::KeySet) {
        self.keys.retain(keys);
        self.pairwise.retain(keys);
        self.setup.apply_keys(keys);
        if let Some(bound) = self.bound.as_mut() {
            bound.opener.apply_keys(keys);
        }
    }

    /// Opens `datagram`, an envelope for this publication, into `out`
    /// before any inner frame is read, and returns its control. The
    /// reason of a refusal is counted and nothing else changes.
    ///
    /// # Errors
    ///
    /// The [`EncRejection`].
    pub(crate) fn open(
        &mut self,
        datagram: &[u8],
        out: &mut [u8; MAX_PLAINTEXT],
    ) -> Result<EncOpened, EncRejection> {
        let result = self.open_uncounted(datagram, out);
        if let Err(reason) = result {
            self.channel.rejections.bump(reason);
        }
        result
    }

    fn open_uncounted(
        &mut self,
        datagram: &[u8],
        out: &mut [u8; MAX_PLAINTEXT],
    ) -> Result<EncOpened, EncRejection> {
        let head = header(datagram)?;
        if (head.session_id, head.stream_id) != (self.alias.session_id, self.alias.stream_id) {
            return Err(EncRejection::Binding);
        }
        match head.domain {
            Domain::RspSetup => self.rsp_setup(datagram, out),
            Domain::Receiver => self.receiver(datagram, out, head.receiver),
            Domain::Sender | Domain::Setup => Err(EncRejection::Domain),
        }
    }

    fn rsp_setup(
        &mut self,
        datagram: &[u8],
        out: &mut [u8; MAX_PLAINTEXT],
    ) -> Result<EncOpened, EncRejection> {
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
        if let Some(bound) = &self.bound {
            if bound.receiver == receiver {
                return Ok(EncOpened::RspSetup(
                    control,
                    EncEstablishing {
                        receiver,
                        nonce: bound.nonce,
                        bind: false,
                    },
                ));
            }
            if bound.receiver.receiver_id != receiver.receiver_id {
                // One receiver per publication (unicast).
                return Err(EncRejection::Party);
            }
            if !self.retired.has_room() {
                return Err(EncRejection::RetiredBoot);
            }
        }
        let context = self.receiver_context(&receiver, nonce);
        let opener = EncOpener::new(&self.keys, Some(&self.pairwise), context, now)
            .map_err(|_| EncRejection::Pairwise)?;
        if let Some(old) = self.bound.take() {
            self.retired
                .retire(&old.receiver, self.keys.current_epoch())?;
        }
        self.bound = Some(Bound {
            receiver,
            nonce,
            opener,
        });
        Ok(EncOpened::RspSetup(
            control,
            EncEstablishing {
                receiver,
                nonce,
                bind: true,
            },
        ))
    }

    fn receiver(
        &mut self,
        datagram: &[u8],
        out: &mut [u8; MAX_PLAINTEXT],
        party: Option<ReceiverIdentity>,
    ) -> Result<EncOpened, EncRejection> {
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
        bound
            .opener
            .open(datagram, out, &mut self.channel.rate, now, |frames| {
                found = match classify(frames) {
                    Ok(Datagram::Control(control))
                        if receiver_control_alias(&control) == Some(alias)
                            && !matches!(control, Control::Challenge(_) | Control::Solicit(_))
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
            .map(EncOpened::Receiver)
            .ok_or(EncRejection::InnerRejected)
    }

    /// The domain 4 context of `receiver` under the challenge `nonce`.
    fn receiver_context(&self, receiver: &ReceiverIdentity, nonce: [u8; 16]) -> KeyContext {
        KeyContext {
            domain: Domain::Receiver,
            key_epoch: self.keys.current_epoch(),
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
                key_epoch: self.keys.current_epoch(),
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
    /// into `out`, stating the current file epoch and `party_epoch`, the
    /// session sealer's current one. Every answer on an `encrypted`
    /// channel is a variant 3. `None` when it does not encode or seal:
    /// nothing is sent.
    pub(crate) fn seal_answer(
        &mut self,
        answer: SetupAnswer,
        party_epoch: u16,
        out: &mut [u8],
    ) -> Option<usize> {
        let enc = EncAnswer {
            answer,
            key_epoch: self.keys.current_epoch(),
            party_epoch,
        };
        let length = enc.encode(out).ok()?;
        self.setup.seal(out, length).ok()
    }

    /// Seals an encoded SETUP ANNOUNCE (the first `frames` bytes of `out`)
    /// in domain 5.
    pub(crate) fn seal_announce(&mut self, out: &mut [u8], frames: usize) -> Option<usize> {
        self.setup.seal(out, frames).ok()
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
}

impl SenderEnc {
    /// Applies the key store's current key set to every encrypted
    /// publication (H8 finding 4): see [`PublicationEnc::apply_keys`].
    pub(crate) fn apply_keys(&mut self, keys: &dyn crate::wire_auth::KeySet) {
        for publication in &mut self.publications {
            publication.apply_keys(keys);
        }
    }

    /// Makes the publication `publication` names encrypted (tests); its
    /// `Outbound` must have been made encrypted too.
    #[cfg(test)]
    pub(crate) fn publish(&mut self, publication: PublicationEnc) {
        self.publications.push(publication);
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
    /// Makes the publication `publication` names encrypted (tests); its
    /// `Outbound` must be made encrypted too, before any traffic.
    #[cfg(test)]
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
    pub(super) fn open_enc(
        &mut self,
        endpoint: EndpointId,
        bytes: &[u8],
    ) -> Option<(Control, Option<Establishing>)> {
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
        let Some(publication) = self
            .enc
            .publications
            .iter_mut()
            .find(|publication| publication.endpoint == endpoint && publication.alias == alias)
        else {
            self.enc.unattributed.bump(EncRejection::Binding);
            return None;
        };
        let mut out = [0_u8; MAX_PLAINTEXT];
        match publication.open(bytes, &mut out) {
            Ok(EncOpened::Receiver(control)) => Some((control, None)),
            Ok(EncOpened::RspSetup(control, establishing)) => {
                if establishing.bind {
                    let sealer = publication.data_sealer(&establishing).ok()?;
                    let installed = self
                        .publications
                        .iter_mut()
                        .find(|outbound| outbound.serves(endpoint) && outbound.alias() == alias)
                        .is_some_and(|outbound| outbound.install_enc_sealer(sealer).is_ok());
                    if !installed {
                        return None;
                    }
                }
                Some((control, None))
            }
            Err(_) => None,
        }
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
        let party_epoch = self
            .publications
            .iter()
            .find(|outbound| outbound.serves(endpoint) && outbound.alias() == alias)
            .and_then(|outbound| outbound.enc_party_epoch())
            .unwrap_or(0);
        let mut bytes = [0_u8; crate::wire_enc::MAX_SEALED];
        let publication = self.enc.publications.get_mut(index)?;
        let length = match control {
            Control::SetupAnswer(answer) => {
                publication.seal_answer(*answer, party_epoch, &mut bytes)
            }
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
