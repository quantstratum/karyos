// SPDX-License-Identifier: Apache-2.0

//! The wire authentication of a publication's publisher side, unicast
//! (`quantstratum-docs:
//! karyos/adr/0086-wire-authentication-profile-v1.md` sections 2, 4, 6, 7
//! and 7a; part of quantstratum/karyos#648).
//!
//! An authenticated publication seals its SETUP ANNOUNCE and ANSWER under
//! the channel's SETUP proof (domain 5). Every receiver it may serve is
//! provisioned with a pairwise key: its RSP_SETUP (CHALLENGE or SOLICIT)
//! is verified under that key's RSP_SETUP proof (domain 6) and then judged
//! by the publisher rule for a new `receiver_boot_id` ([`BootTable`]);
//! only a [`BootDecision::Bind`] derives the receiver's domain 4 key and
//! the session's domain 1 sealer. Its SMs, NAKs and RTTM REQUESTs are
//! verified under that domain 4 key, checked and only committed once the
//! inner control is the bound receiver's. Nothing is decoded before its
//! tag verifies, and a refusal changes nothing but its counters. Nothing
//! makes a publication authenticated yet.

use karyos_protocol::network::{Alias, Control, Datagram, Identity, Receiver, RttmKind, classify};
use karyos_protocol::protection::hmac_sha256::Domain;

use super::receive_auth::{AuthReason, AuthRejections, envelope_alias};
use crate::agents::EndpointId;
use crate::wire_auth::{
    BootDecision, BootTable, KeyError, KeySet, Party, Proof, ProofKind, Sealer, Verifier,
};
use crate::wire_keys::KeyFile;

/// One receiver a publication may serve: its pairwise key's RSP_SETUP
/// proof, a prototype of its domain 4 verifier, and its binding.
#[derive(Debug)]
struct ReceiverKeys {
    receiver_id: u64,
    /// Verify only: the publisher never sends an RSP_SETUP.
    rsp: Proof,
    /// The pairwise key's domain 4 verifier for no boot id yet: each
    /// [`BootDecision::Bind`] derives the bound one from it.
    prototype: Verifier,
    bound: Option<Bound>,
}

/// A receiver's binding: the boot id and nonce of the RSP_SETUP that bound
/// it, and the domain 4 verifier of that boot id.
#[derive(Debug)]
struct Bound {
    boot: [u64; 2],
    nonce: [u64; 2],
    verifier: Verifier,
}

/// What the publisher does after a verified RSP_SETUP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Establishing {
    /// The domain 1 party of the establishment: its sealer is installed
    /// only for a new binding.
    pub(crate) party: Party,
    /// Whether it is a new binding (a [`BootDecision::Bind`]).
    pub(crate) bind: bool,
}

/// The authentication of one authenticated publication.
#[derive(Debug)]
pub(crate) struct PublicationAuth {
    pub(crate) endpoint: EndpointId,
    pub(crate) alias: Alias,
    /// Domain 5, signing: SETUP ANNOUNCE and ANSWER.
    pub(crate) setup: Proof,
    /// The channel signing key's sealer for no establishment yet: each
    /// binding derives the session's domain 1 sealer from it. Withdrawn
    /// while a key reload leaves no channel signing key: nothing is
    /// established until a later reload names one again.
    prototype: Sealer,
    receivers: Vec<ReceiverKeys>,
    boots: BootTable,
    /// Refusals by reason: per publication, whose receivers each have
    /// their own key.
    pub(crate) rejections: AuthRejections,
    /// Its abort authority, when this driver may abort its sessions.
    pub(crate) abort: Option<AbortAuthority>,
    /// The guard its aborts name, bound at admission; 0 for none, which
    /// sends no abort on a close.
    pub(crate) abort_guard: u64,
    /// The incarnation whose abort was requested: once each.
    pub(crate) aborted: Option<Identity>,
    /// The monotonic clock in nanoseconds, for the in-band epoch overlap
    /// (H8 finding 7: never the wall clock).
    clock: fn() -> u64,
}

/// A control that verified.
#[derive(Debug)]
pub(crate) enum Opened {
    /// An RSP_SETUP: answer it, and on a new binding install the sealer.
    RspSetup(Control, Establishing),
    /// An SM, NAK or RTTM REQUEST of the bound receiver.
    Receiver(Control),
    /// A SESSION_ABORT_ACK of the bound receiver (domain 4).
    AbortAck(karyos_protocol::network::authenticated::AbortAck),
}

/// The publication's abort authority: its Ed25519 signing key, the
/// `key_id` and `authority_id` its file names, and the per-start envelope
/// sequence of the signed domain (ADR-0086 section 6).
pub(crate) struct AbortAuthority {
    pub(crate) signer: crate::authority::Ed25519Signer,
    pub(crate) key_id: u32,
    pub(crate) authority_id: u64,
    /// The file epoch of its signing key, when known: a key reload that
    /// names another withdraws it.
    pub(crate) file_epoch: Option<u32>,
    seq: u64,
}

impl core::fmt::Debug for AbortAuthority {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AbortAuthority")
            .field("key_id", &self.key_id)
            .field("authority_id", &self.authority_id)
            .finish_non_exhaustive()
    }
}

impl AbortAuthority {
    /// The authority of `signer` under `key_id` for `authority_id`.
    pub(crate) fn new(
        signer: crate::authority::Ed25519Signer,
        key_id: u32,
        authority_id: u64,
    ) -> Self {
        Self {
            signer,
            key_id,
            authority_id,
            file_epoch: None,
            seq: 0,
        }
    }

    /// Whether it still signs under `keys`: its `key_id` has a signing
    /// file, of its own file epoch when that is known.
    fn signs_under(&self, keys: &dyn KeySet) -> bool {
        keys.signing(self.key_id)
            .is_some_and(|file| self.file_epoch.is_none_or(|epoch| epoch == file.file_epoch))
    }

    /// Signs `abort` into `out` in domain 3 and returns its length; `None`
    /// when it does not encode or fit.
    pub(crate) fn sign(
        &mut self,
        abort: &karyos_protocol::network::authenticated::SessionAbort,
        out: &mut [u8],
    ) -> Option<usize> {
        use karyos_protocol::network::authenticated::AuthControl;
        use karyos_protocol::protection::signed::{SignedBinding, SignedDomain, seal_signed};

        let body = AuthControl::Abort(*abort).encode(out).ok()?;
        let binding = SignedBinding {
            domain: SignedDomain::SessionAbort,
            party_epoch: 0,
            session_id: abort.alias.session_id,
            stream_id: abort.alias.stream_id,
            key_id: self.key_id,
        };
        let length = seal_signed(out, body, &binding, self.seq, &self.signer).ok()?;
        self.seq = self.seq.checked_add(1)?;
        Some(length)
    }
}

/// A placeholder boot id and nonce for the prototypes, never bound.
const NO_BOOT: [u64; 2] = [0, 0];

impl PublicationAuth {
    /// The authentication of the publication `alias` on `endpoint` of
    /// `identity` and `lane_count` lanes: `channel` is its channel signing
    /// key (domain 5 SETUP proof and the domain 1 sealer), `pairwise` the
    /// key files of its one receiver: one or two file epochs of one key,
    /// the highest the current one. The boot id table is allocated now.
    ///
    /// An authenticated publication is unicast with a single receiver:
    /// [`crate::agents::data::Outbound::require_auth`] refuses fan-out,
    /// dynamic and routed publications (ADR-0086 open point 6, ADR-0076
    /// clause 4), and the publication has one domain 1 sealer, which a
    /// second receiver's binding would replace. Per-destination sealers
    /// come with karyos#649.
    ///
    /// # Errors
    ///
    /// [`KeyError`] when a file does not fit its purpose.
    pub(crate) fn new(
        endpoint: EndpointId,
        alias: Alias,
        identity: Identity,
        lane_count: u8,
        channel: &KeyFile,
        pairwise: &[&KeyFile],
    ) -> Result<Self, KeyError> {
        let pairwise = [pairwise];
        let setup = Proof::new(
            ProofKind::Setup,
            alias,
            Some(channel),
            [channel],
            channel.file_epoch,
        )?;
        let prototype = Sealer::new(
            channel,
            Party::Sender {
                identity,
                lane_count,
                receiver_boot_id: NO_BOOT,
                nonce: NO_BOOT,
            },
            alias,
        )?;
        let mut receivers = Vec::with_capacity(pairwise.len());
        for files in pairwise {
            let Some(file) = files.iter().max_by_key(|file| file.file_epoch) else {
                return Err(KeyError::NoKey);
            };
            let crate::wire_keys::Scope::Pairwise { receiver_id, .. } = file.scope else {
                return Err(KeyError::Purpose);
            };
            let rsp = Proof::new(
                ProofKind::RspSetup { receiver_id },
                alias,
                None,
                files.iter().copied(),
                file.file_epoch,
            )?;
            let prototype = Verifier::new(
                files.iter().copied(),
                Party::Receiver {
                    identity,
                    receiver_boot_id: NO_BOOT,
                    receiver_id,
                },
                alias,
            )?;
            receivers.push(ReceiverKeys {
                receiver_id,
                rsp,
                prototype,
                bound: None,
            });
        }
        Ok(Self {
            endpoint,
            alias,
            setup,
            prototype,
            boots: BootTable::new(receivers.len()),
            receivers,
            rejections: AuthRejections::default(),
            abort: None,
            abort_guard: 0,
            aborted: None,
            clock: super::receive_auth::monotonic_ns,
        })
    }

    /// Forgets every receiver binding and boot id (a VM generation
    /// change; karyos#648): each receiver binds again only through a fresh
    /// RSP_SETUP, its bound domain 4 verifier erased with it.
    pub(crate) fn unbind_all(&mut self) {
        for receiver in &mut self.receivers {
            receiver.bound = None;
        }
        self.boots = BootTable::new(self.receivers.len());
    }

    /// Uses `clock` as the monotonic clock in nanoseconds (tests).
    #[cfg(test)]
    pub(crate) fn set_clock(&mut self, clock: fn() -> u64) {
        self.clock = clock;
    }

    /// Applies the store's current key set (H8 finding 4), as one change to
    /// every key the publication holds: the SETUP proof and the domain 1
    /// prototype follow the channel signing key (re-keyed, or withdrawn
    /// while there is none); each receiver's RSP_SETUP proof, domain 4
    /// prototype and bound verifier take the pairwise files that now
    /// verify, keeping the windows of retained epochs, and the boot ids of
    /// dropped epochs are forgotten; the abort authority is dropped once
    /// its key no longer signs. The installed session sealer is the sender
    /// role's to withdraw ([`super::SenderRole::apply_keys`]).
    pub(crate) fn apply_keys(&mut self, keys: &dyn KeySet) {
        let now = (self.clock)();
        self.setup.apply(keys);
        let channel = keys.signing(self.setup.key_id());
        if !self.prototype.signs_under(channel) {
            match channel.map(|file| self.prototype.rekeyed(file)) {
                Some(Ok(rekeyed)) => self.prototype = rekeyed,
                Some(Err(_)) | None => self.prototype.withdraw(),
            }
        }
        for receiver in &mut self.receivers {
            receiver.rsp.apply(keys);
            receiver.prototype.apply(keys);
            if let Some(bound) = receiver.bound.as_mut() {
                // A live verifier: a dropped file epoch never returns (H8
                // N1).
                bound.verifier.apply_live(keys);
                bound.verifier.tick(now);
            }
            if let Some(lowest) = keys
                .verifying(receiver.prototype.key_id())
                .into_iter()
                .flatten()
                .map(|file| file.file_epoch)
                .min()
            {
                self.boots.forget_before(receiver.receiver_id, lowest);
            }
        }
        if self
            .abort
            .as_ref()
            .is_some_and(|abort| !abort.signs_under(keys))
        {
            // Dropping the signer erases its key.
            self.abort = None;
        }
    }

    /// The session sealer of an establishment's domain 1 `party`.
    ///
    /// # Errors
    ///
    /// [`KeyError::Scope`] for a party of another kind.
    pub(crate) fn sealer(&self, party: Party) -> Result<Sealer, KeyError> {
        if !self.prototype.can_seal() {
            return Err(KeyError::NoKey);
        }
        self.prototype.with_party(party, self.alias)
    }

    /// Verifies `datagram`, an envelope for this publication, before any
    /// inner frame is read, and returns its control. `identity` and
    /// `lane_count` are the publication's. Allocates nothing.
    ///
    /// # Errors
    ///
    /// The [`AuthReason`]; the reason is counted and nothing else changes.
    pub(crate) fn open(
        &mut self,
        datagram: &[u8],
        identity: Identity,
        lane_count: u8,
    ) -> Result<Opened, AuthReason> {
        let result = self.open_uncounted(datagram, identity, lane_count);
        if let Err(reason) = result {
            self.rejections.bump(reason);
        }
        result
    }

    fn open_uncounted(
        &mut self,
        datagram: &[u8],
        identity: Identity,
        lane_count: u8,
    ) -> Result<Opened, AuthReason> {
        if envelope_alias(datagram) != Some(self.alias) {
            return Err(AuthReason::Binding);
        }
        let key_id = datagram
            .get(20..24)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u32::from_le_bytes)
            .ok_or(AuthReason::Short)?;
        let domain = datagram.get(10).copied().ok_or(AuthReason::Short)?;
        if domain == Domain::RspSetup as u8 {
            self.rsp_setup(datagram, key_id, identity, lane_count)
        } else if domain == Domain::ReceiverToPublisher as u8 {
            self.receiver(datagram, key_id, identity)
        } else {
            Err(AuthReason::Domain)
        }
    }

    fn rsp_setup(
        &mut self,
        datagram: &[u8],
        key_id: u32,
        identity: Identity,
        lane_count: u8,
    ) -> Result<Opened, AuthReason> {
        // Any pairwise key but the single receiver's: another receiver,
        // refused with its own reason, binding and replacing nothing.
        let index = self
            .receivers
            .iter()
            .position(|receiver| receiver.rsp.key_id() == key_id)
            .ok_or(AuthReason::OtherReceiver)?;
        let receiver = self.receivers.get(index).ok_or(AuthReason::Key)?;
        let proved = receiver
            .rsp
            .verify(datagram)
            .map_err(|rejection| AuthReason::of(crate::wire_auth::Refusal::Envelope(rejection)))?;
        let inner = datagram
            .get(proved.opened.start..)
            .and_then(|rest| rest.get(..proved.opened.frames))
            .ok_or(AuthReason::Inner)?;
        // The domain 6 key binds no publication identity (ADR-0086 section
        // 4), so a CHALLENGE's identity is checked here, after its tag and
        // before the boot id table: another incarnation's binds nothing. A
        // SOLICIT carries none; a stale one is bounded by the publisher rule
        // and the nonce, since the domain 1 key is salted with the
        // establishment's boot id and nonce.
        let (control, challenge) = match classify(inner) {
            Ok(Datagram::Control(control @ Control::Challenge(challenge)))
                if challenge.alias == self.alias && challenge.identity == identity =>
            {
                (control, challenge.challenge)
            }
            Ok(Datagram::Control(control @ Control::Solicit(solicit)))
                if solicit.alias == self.alias =>
            {
                (control, solicit.challenge)
            }
            _ => return Err(AuthReason::Inner),
        };
        let receiver_id = receiver.receiver_id;
        let boot = challenge.receiver_boot_id;
        let nonce = challenge.nonce;
        let establishing = |bind| Establishing {
            party: Party::Sender {
                identity,
                lane_count,
                receiver_boot_id: boot,
                nonce,
            },
            bind,
        };
        // A boot id already bound to another nonce would need a new
        // domain 1 key, which only a new binding derives: dropped, so a
        // replayed RSP_SETUP of the bound boot id cannot move the session
        // key (fail closed; the receiver re-establishes under a new boot
        // id). Decided before the table, which it leaves unchanged.
        if let Some(bound) = receiver.bound.as_ref()
            && bound.boot == boot
        {
            return if bound.nonce == nonce {
                Ok(Opened::RspSetup(control, establishing(false)))
            } else {
                Err(AuthReason::Rebind)
            };
        }
        // The binding is committed here, before the sender role answers:
        // if the ANSWER then cannot be sent, the receiver's retry of the
        // same boot id and nonce is `Bound` with that nonce, and the
        // sender role installs the sealer then (`establish` installs one
        // when none is installed), so nothing is lost or re-derived.
        match self.boots.decide(receiver_id, boot, &proved) {
            BootDecision::Bind => {}
            // The table's own bound boot id: the check above saw it.
            BootDecision::Bound => return Err(AuthReason::Rebind),
            BootDecision::Retired => return Err(AuthReason::Retired),
            BootDecision::PreviousEpoch => return Err(AuthReason::PreviousEpoch),
            BootDecision::Full => return Err(AuthReason::Full),
        }
        let receiver = self.receivers.get_mut(index).ok_or(AuthReason::Key)?;
        let verifier = receiver
            .prototype
            .with_party(
                Party::Receiver {
                    identity,
                    receiver_boot_id: boot,
                    receiver_id,
                },
                self.alias,
            )
            .map_err(|_| AuthReason::Key)?;
        receiver.bound = Some(Bound {
            boot,
            nonce,
            verifier,
        });
        Ok(Opened::RspSetup(control, establishing(true)))
    }

    fn receiver(
        &mut self,
        datagram: &[u8],
        key_id: u32,
        identity: Identity,
    ) -> Result<Opened, AuthReason> {
        let now = (self.clock)();
        let receiver = self
            .receivers
            .iter_mut()
            .find(|receiver| receiver.prototype.key_id() == key_id)
            .ok_or(AuthReason::Key)?;
        let receiver_id = receiver.receiver_id;
        let bound = receiver.bound.as_mut().ok_or(AuthReason::Unbound)?;
        let checked = bound
            .verifier
            .check(datagram, now)
            .map_err(AuthReason::of)?;
        let opened = checked.opened();
        let inner = datagram
            .get(opened.start..)
            .and_then(|rest| rest.get(..opened.frames))
            .ok_or(AuthReason::Inner)?;
        let named = Receiver {
            receiver_boot_id: bound.boot,
            receiver_id,
        };
        // A SESSION_ABORT_ACK decodes only here, under its domain 4 key.
        let code = inner
            .get(6..8)
            .and_then(|code| code.try_into().ok())
            .map(u16::from_le_bytes);
        if code == Some(karyos_protocol::frame::FrameType::SessionAbortAck as u16) {
            use karyos_protocol::network::authenticated::AuthControl;
            let Ok(AuthControl::Ack(ack)) = AuthControl::decode(inner) else {
                return Err(AuthReason::Inner);
            };
            if ack.alias != self.alias || ack.receiver != named || ack.identity != identity {
                return Err(AuthReason::Inner);
            }
            bound
                .verifier
                .commit(checked, now)
                .map_err(AuthReason::of)?;
            return Ok(Opened::AbortAck(ack));
        }
        let control = match classify(inner) {
            Ok(Datagram::Control(control)) => control,
            _ => return Err(AuthReason::Inner),
        };
        let fits = match &control {
            Control::Status(status) => status.alias == self.alias && status.receiver == named,
            Control::Nak(nak) => nak.alias == self.alias && nak.receiver == named,
            Control::Rttm(rttm) => {
                rttm.kind == RttmKind::Request && rttm.alias == self.alias && rttm.receiver == named
            }
            _ => false,
        };
        if !fits {
            return Err(AuthReason::Inner);
        }
        bound
            .verifier
            .commit(checked, now)
            .map_err(AuthReason::of)?;
        Ok(Opened::Receiver(control))
    }
}

/// The alias of a control a receiver sends a publication (RSP_SETUP, SM,
/// NAK, RTTM REQUEST); `None` for any other.
pub(crate) fn receiver_control_alias(control: &Control) -> Option<Alias> {
    match control {
        Control::Challenge(challenge) => Some(challenge.alias),
        Control::Solicit(solicit) => Some(solicit.alias),
        Control::Status(status) => Some(status.alias),
        Control::Nak(nak) => Some(nak.alias),
        Control::Rttm(rttm) if rttm.kind == RttmKind::Request => Some(rttm.alias),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use karyos_protocol::network::{
        Alias, ChallengeBlock, Control, Identity, LaneStatus, Lanes, Receiver, RspChallenge,
        StatusMessage, TermParams,
    };

    use super::{Opened, PublicationAuth};
    use crate::agents::EndpointId;
    use crate::agents::roles::receive_auth::AuthReason;
    use crate::wire_auth::{ENVELOPE_LEN, Party, Proof, ProofKind, Sealer};
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

    fn key(name: &str, text: &str) -> KeyFile {
        crate::wire_keys::parse(name, text.as_bytes()).unwrap()
    }

    fn channel() -> KeyFile {
        key(
            "3-1.key",
            "format=karyos-wire-key-v1\nkey_id=3\nfile_epoch=1\npurpose=channel\nprofile_id=1\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret=1111111111111111111111111111111111111111111111111111111111111111\nchannel_id=7\nstream_id=6\n",
        )
    }

    fn pairwise(epoch: u32, fill: char) -> KeyFile {
        let secret: String = core::iter::repeat_n(fill, 64).collect();
        key(
            &format!("9-{epoch}.key"),
            &format!(
                "format=karyos-wire-key-v1\nkey_id=9\nfile_epoch={epoch}\npurpose=pairwise\nprofile_id=1\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret={secret}\nreceiver_id=66\npublisher_id=5\n"
            ),
        )
    }

    fn publication(files: &[&KeyFile]) -> PublicationAuth {
        let mut auth =
            PublicationAuth::new(EndpointId(1), ALIAS, IDENTITY, 1, &channel(), files).unwrap();
        auth.set_clock(|| 1_795_000_000_000_000_000);
        auth
    }

    fn sealed(control: &Control, seal: impl FnOnce(&mut [u8], usize) -> usize) -> Vec<u8> {
        let mut bytes = vec![0u8; karyos_protocol::network::MAX_CONTROL_LENGTH + ENVELOPE_LEN];
        let length = control.encode(&mut bytes).unwrap();
        let length = seal(&mut bytes, length);
        bytes.truncate(length);
        bytes
    }

    /// A CHALLENGE of receiver 66 naming `boot`, sealed under `file`'s
    /// RSP_SETUP proof.
    fn challenge(file: &KeyFile, boot: [u64; 2], nonce: [u64; 2]) -> Vec<u8> {
        let proof = Proof::new(
            ProofKind::RspSetup { receiver_id: 66 },
            ALIAS,
            Some(file),
            [file],
            file.file_epoch,
        )
        .unwrap();
        let control = Control::Challenge(RspChallenge {
            alias: ALIAS,
            identity: IDENTITY,
            challenge: ChallengeBlock {
                receiver_boot_id: boot,
                nonce,
            },
        });
        sealed(&control, |bytes, length| proof.seal(bytes, length).unwrap())
    }

    fn status(boot: [u64; 2]) -> Control {
        Control::Status(StatusMessage {
            alias: ALIAS,
            identity: IDENTITY,
            receiver: Receiver {
                receiver_boot_id: boot,
                receiver_id: 66,
            },
            group_tag: 0,
            lanes: Lanes::new(&[LaneStatus {
                consumption: 0,
                window: 65_536,
            }])
            .unwrap(),
        })
    }

    /// The receiver's domain 4 sealer for `boot`.
    fn receiver_sealer(file: &KeyFile, boot: [u64; 2]) -> Sealer {
        Sealer::new(
            file,
            Party::Receiver {
                identity: IDENTITY,
                receiver_boot_id: boot,
                receiver_id: 66,
            },
            ALIAS,
        )
        .unwrap()
    }

    fn sm(sealer: &mut Sealer, control: &Control) -> Vec<u8> {
        sealed(control, |bytes, length| sealer.seal(bytes, length).unwrap())
    }

    fn open(auth: &mut PublicationAuth, bytes: &[u8]) -> Result<Opened, AuthReason> {
        auth.open(bytes, IDENTITY, 1)
    }

    /// ADR-0086 section 7, publisher rule: a new boot id binds and retires
    /// the old one; a replayed RSP_SETUP of the retired boot id binds
    /// nothing, and the old boot id's SMs never verify again.
    #[test]
    fn a_replayed_rsp_setup_of_a_retired_boot_id_binds_nothing() {
        let file = pairwise(1, '2');
        let mut auth = publication(&[&file]);
        let old = challenge(&file, [1, 1], [9, 9]);
        let Ok(Opened::RspSetup(_, first)) = open(&mut auth, &old) else {
            panic!("the first boot id binds");
        };
        assert!(first.bind);
        let mut old_sealer = receiver_sealer(&file, [1, 1]);
        let old_sm = sm(&mut old_sealer, &status([1, 1]));
        // The same RSP_SETUP again: bound, nothing re-derived.
        let Ok(Opened::RspSetup(_, again)) = open(&mut auth, &old) else {
            panic!("a resend of the bound one is answered");
        };
        assert!(!again.bind);
        // The receiver restarts under a new boot id.
        let Ok(Opened::RspSetup(_, second)) = open(&mut auth, &challenge(&file, [2, 2], [8, 8]))
        else {
            panic!("the new boot id binds");
        };
        assert!(second.bind);
        // The old RSP_SETUP replayed: retired.
        assert_eq!(open(&mut auth, &old).unwrap_err(), AuthReason::Retired);
        // The old SM fails under the new boot id's key; the new one opens.
        assert_eq!(open(&mut auth, &old_sm).unwrap_err(), AuthReason::Tag);
        let mut new_sealer = receiver_sealer(&file, [2, 2]);
        assert!(matches!(
            open(&mut auth, &sm(&mut new_sealer, &status([2, 2]))),
            Ok(Opened::Receiver(Control::Status(_)))
        ));
        assert_eq!(auth.rejections.get(AuthReason::Retired), 1);
        assert_eq!(auth.rejections.get(AuthReason::Tag), 1);
        // The bound boot id under another nonce would move the session
        // key: refused.
        assert_eq!(
            open(&mut auth, &challenge(&file, [2, 2], [7, 7])).unwrap_err(),
            AuthReason::Rebind
        );
    }

    /// The pairwise key of another receiver, 67.
    fn other_receiver() -> KeyFile {
        key(
            "8-1.key",
            "format=karyos-wire-key-v1\nkey_id=8\nfile_epoch=1\npurpose=pairwise\nprofile_id=1\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret=5555555555555555555555555555555555555555555555555555555555555555\nreceiver_id=67\npublisher_id=5\n",
        )
    }

    /// A CHALLENGE of receiver 67 under its own pairwise key.
    fn challenge_of_67(file: &KeyFile) -> Vec<u8> {
        let proof = Proof::new(
            ProofKind::RspSetup { receiver_id: 67 },
            ALIAS,
            Some(file),
            [file],
            file.file_epoch,
        )
        .unwrap();
        let control = Control::Challenge(RspChallenge {
            alias: ALIAS,
            identity: IDENTITY,
            challenge: ChallengeBlock {
                receiver_boot_id: [5, 5],
                nonce: [6, 6],
            },
        });
        sealed(&control, |bytes, length| proof.seal(bytes, length).unwrap())
    }

    /// An authenticated publication serves a single receiver (ADR-0086
    /// open point 6; per-destination sealers are karyos#649): a second
    /// receiver's RSP_SETUP is refused with its own reason, binds nothing
    /// and replaces nothing, and the first receiver's binding, and so its
    /// session key, stays.
    #[test]
    fn a_second_receiver_is_refused_and_binds_nothing() {
        let file = pairwise(1, '2');
        let mut auth = publication(&[&file]);
        let Ok(Opened::RspSetup(_, first)) = open(&mut auth, &challenge(&file, [1, 1], [9, 9]))
        else {
            panic!("the receiver binds");
        };
        assert_eq!(
            open(&mut auth, &challenge_of_67(&other_receiver())).unwrap_err(),
            AuthReason::OtherReceiver
        );
        assert_eq!(auth.rejections.get(AuthReason::OtherReceiver), 1);
        // The first receiver's binding stands: its resend is the same
        // establishment, its SMs open.
        let Ok(Opened::RspSetup(_, again)) = open(&mut auth, &challenge(&file, [1, 1], [9, 9]))
        else {
            panic!("the bound receiver is answered");
        };
        assert_eq!((again.party, again.bind), (first.party, false));
        let mut sealer = receiver_sealer(&file, [1, 1]);
        assert!(matches!(
            open(&mut auth, &sm(&mut sealer, &status([1, 1]))),
            Ok(Opened::Receiver(_))
        ));
    }

    /// ADR-0086 section 4: the domain 6 key binds no publication identity,
    /// so a CHALLENGE of another incarnation is refused after its tag and
    /// binds nothing; the right one then binds.
    #[test]
    fn a_challenge_of_another_incarnation_binds_nothing() {
        let file = pairwise(1, '2');
        let mut auth = publication(&[&file]);
        let proof = Proof::new(
            ProofKind::RspSetup { receiver_id: 66 },
            ALIAS,
            Some(&file),
            [&file],
            1,
        )
        .unwrap();
        let stale = Control::Challenge(RspChallenge {
            alias: ALIAS,
            identity: Identity {
                incarnation: 2,
                ..IDENTITY
            },
            challenge: ChallengeBlock {
                receiver_boot_id: [1, 1],
                nonce: [9, 9],
            },
        });
        let bytes = sealed(&stale, |bytes, length| proof.seal(bytes, length).unwrap());
        assert_eq!(open(&mut auth, &bytes).unwrap_err(), AuthReason::Inner);
        assert!(matches!(
            open(&mut auth, &challenge(&file, [1, 1], [9, 9])),
            Ok(Opened::RspSetup(_, establishing)) if establishing.bind
        ));
    }

    /// ADR-0086 section 7: an RSP_SETUP that verifies only under the
    /// previous file epoch's pairwise key creates no binding.
    #[test]
    fn a_previous_file_epoch_rsp_setup_binds_nothing() {
        let previous = pairwise(1, '2');
        let current = pairwise(2, '4');
        let mut auth = publication(&[&previous, &current]);
        assert_eq!(
            open(&mut auth, &challenge(&previous, [1, 1], [9, 9])).unwrap_err(),
            AuthReason::PreviousEpoch
        );
        // Nothing bound: an SM of that boot id has no key.
        let mut sealer = receiver_sealer(&previous, [1, 1]);
        assert_eq!(
            open(&mut auth, &sm(&mut sealer, &status([1, 1]))).unwrap_err(),
            AuthReason::Unbound
        );
        // Under the current epoch it binds.
        assert!(matches!(
            open(&mut auth, &challenge(&current, [1, 1], [9, 9])),
            Ok(Opened::RspSetup(_, establishing)) if establishing.bind
        ));
    }

    /// ADR-0086 sections 2 and 6: a forged, replayed or misdirected SM of
    /// the bound receiver is refused by reason and moves nothing: the
    /// genuine SM of each refused sequence still opens.
    #[test]
    fn forged_replayed_or_misdirected_sms_move_nothing() {
        let file = pairwise(1, '2');
        let mut auth = publication(&[&file]);
        assert!(open(&mut auth, &challenge(&file, [1, 1], [9, 9])).is_ok());
        // Forged: another secret under the same key id.
        let forged_file = pairwise(1, '3');
        let mut forger = receiver_sealer(&forged_file, [1, 1]);
        assert_eq!(
            open(&mut auth, &sm(&mut forger, &status([1, 1]))).unwrap_err(),
            AuthReason::Tag
        );
        // Sealed under the right key but naming another boot id: refused
        // for its inner control, its sequence not consumed.
        let mut misdirected = receiver_sealer(&file, [1, 1]);
        assert_eq!(
            open(&mut auth, &sm(&mut misdirected, &status([3, 3]))).unwrap_err(),
            AuthReason::Inner
        );
        let mut genuine = receiver_sealer(&file, [1, 1]);
        let first = sm(&mut genuine, &status([1, 1]));
        assert!(matches!(open(&mut auth, &first), Ok(Opened::Receiver(_))));
        // Replayed.
        assert_eq!(open(&mut auth, &first).unwrap_err(), AuthReason::Duplicate);
        // An inner control the receiver never sends a publisher.
        let announce = Control::SetupAnnounce(karyos_protocol::network::SetupAnnounce {
            alias: ALIAS,
            identity: IDENTITY,
            term: TermParams {
                term_length: 65_536,
                initial_term_id: 9,
                mtu: 1408,
            },
            lane_count: 1,
        });
        assert_eq!(
            open(&mut auth, &sm(&mut genuine, &announce)).unwrap_err(),
            AuthReason::Inner
        );
        let counts = auth.rejections;
        assert_eq!(counts.get(AuthReason::Tag), 1);
        assert_eq!(counts.get(AuthReason::Inner), 2);
        assert_eq!(counts.get(AuthReason::Duplicate), 1);
    }

    /// H8 finding 4: a reload that drops the pairwise file erases the
    /// bound receiver's verifier, so its SMs stop verifying; the abort
    /// authority whose key no longer signs is dropped; the channel signing
    /// key gone, nothing is established or sealed.
    #[test]
    fn a_reload_applies_to_every_key_of_a_publication() {
        use crate::authority::Ed25519Signer;
        use crate::wire_auth::FixedKeys;

        let file = pairwise(1, '2');
        let mut auth = publication(&[&file]);
        auth.abort = Some(super::AbortAuthority::new(
            Ed25519Signer::from_seed(&[9; 32]),
            10,
            10,
        ));
        assert!(open(&mut auth, &challenge(&file, [1, 1], [9, 9])).is_ok());
        let mut sealer = receiver_sealer(&file, [1, 1]);
        assert!(matches!(
            open(&mut auth, &sm(&mut sealer, &status([1, 1]))),
            Ok(Opened::Receiver(_))
        ));
        // The pairwise file revoked: the channel key alone remains.
        auth.apply_keys(&FixedKeys {
            files: vec![channel()],
        });
        assert_eq!(
            open(&mut auth, &sm(&mut sealer, &status([1, 1]))).unwrap_err(),
            AuthReason::Epoch
        );
        assert_eq!(
            open(&mut auth, &challenge(&file, [2, 2], [8, 8])).unwrap_err(),
            AuthReason::Key
        );
        assert!(auth.abort.is_none(), "key 10 no longer signs");
        let party = Party::Sender {
            identity: IDENTITY,
            lane_count: 1,
            receiver_boot_id: [1, 1],
            nonce: [9, 9],
        };
        assert!(auth.sealer(party).is_ok());
        // A disabled store: nothing is established or sealed.
        auth.apply_keys(&FixedKeys::default());
        assert!(auth.sealer(party).is_err());
        let mut bytes = vec![0u8; 64 + ENVELOPE_LEN];
        assert!(auth.setup.seal(&mut bytes, 8).is_err());
    }

    /// A channel key file of `epoch` (key 3).
    fn channel_epoch(epoch: u32, fill: char) -> KeyFile {
        let secret: String = core::iter::repeat_n(fill, 64).collect();
        key(
            &format!("3-{epoch}.key"),
            &format!(
                "format=karyos-wire-key-v1\nkey_id=3\nfile_epoch={epoch}\npurpose=channel\nprofile_id=1\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret={secret}\nchannel_id=7\nstream_id=6\n"
            ),
        )
    }

    /// ADR-0086 section 7, a routine file epoch rotation of both keys:
    /// while the previous epochs still verify (the overlap), the session's
    /// domain 1 sealer and the image's domain 4 sealer move to the new
    /// signing files under the same establishment, so DATA and SMs keep
    /// flowing with no re-establishment, and datagrams sealed before the
    /// move still verify; once the overlap ends the previous epochs stop
    /// verifying while the session goes on.
    #[test]
    fn a_rotation_keeps_the_session_delivering_in_both_directions() {
        use crate::agents::control::ControlSeal;
        use crate::agents::roles::receive_auth::ImageAuth;
        use crate::wire_auth::FixedKeys;

        let c1 = channel_epoch(1, '1');
        let p1 = pairwise(1, '2');
        let mut auth =
            PublicationAuth::new(EndpointId(1), ALIAS, IDENTITY, 1, &c1, &[&p1]).unwrap();
        auth.set_clock(|| 1_000);
        let Ok(Opened::RspSetup(_, establishing)) =
            open(&mut auth, &challenge(&p1, [1, 1], [9, 9]))
        else {
            panic!("the receiver binds");
        };
        let mut session = auth.sealer(establishing.party).unwrap();
        let receiver = Party::Receiver {
            identity: IDENTITY,
            receiver_boot_id: [1, 1],
            receiver_id: 66,
        };
        let mut image = ImageAuth::new([&c1], &p1, establishing.party, receiver, ALIAS).unwrap();
        image.set_clock(|| 1_000);
        let mut image_sealer = image.sealer();
        let data = |sealer: &mut Sealer| {
            let mut bytes = vec![0u8; 8 + ENVELOPE_LEN];
            let length = sealer.seal(&mut bytes, 8).unwrap();
            bytes.truncate(length);
            bytes
        };
        let sm_from_image = |sealer: &mut crate::agents::control::SharedSealer| {
            sealed(&status([1, 1]), |bytes, length| {
                sealer.seal_control(bytes, length).unwrap()
            })
        };
        let deliver = |image: &mut ImageAuth, bytes: &[u8]| {
            let checked = image.check(bytes, 1_000)?;
            image.commit(checked, 1_000)
        };
        assert!(deliver(&mut image, &data(&mut session)).is_ok());
        assert!(matches!(
            open(&mut auth, &sm_from_image(&mut image_sealer)),
            Ok(Opened::Receiver(_))
        ));
        let late_data = data(&mut session);
        let late_sm = sm_from_image(&mut image_sealer);
        // Sealed under epoch 1, first seen after the overlap.
        let stale_data = data(&mut session);
        // The rotation: epoch 2 signs, epoch 1 still verifies.
        let overlap = FixedKeys {
            files: vec![
                channel_epoch(1, '1'),
                channel_epoch(2, '7'),
                pairwise(1, '2'),
                pairwise(2, '4'),
            ],
        };
        auth.apply_keys(&overlap);
        image.apply_keys(&overlap);
        session.follow(&overlap);
        assert_eq!(session.key_ref(), (3, 2));
        assert_eq!(image.sealer_key(), (9, 2));
        assert!(!image.withdrawn());
        // Both directions keep flowing under the new keys, with no new
        // establishment, and the old epoch's in-flight datagrams verify.
        let new_data = data(&mut session);
        assert!(deliver(&mut image, &new_data).is_ok());
        let new_sm = sm_from_image(&mut image_sealer);
        assert!(matches!(open(&mut auth, &new_sm), Ok(Opened::Receiver(_))));
        assert!(deliver(&mut image, &late_data).is_ok());
        assert!(matches!(open(&mut auth, &late_sm), Ok(Opened::Receiver(_))));
        // The overlap ends: epoch 1 no longer verifies, the session goes on.
        let after = FixedKeys {
            files: vec![channel_epoch(2, '7'), pairwise(2, '4')],
        };
        auth.apply_keys(&after);
        image.apply_keys(&after);
        session.follow(&after);
        assert!(!image.withdrawn());
        assert!(deliver(&mut image, &stale_data).is_err());
        assert!(deliver(&mut image, &data(&mut session)).is_ok());
        assert!(matches!(
            open(&mut auth, &sm_from_image(&mut image_sealer)),
            Ok(Opened::Receiver(_))
        ));
        let mut old_receiver = receiver_sealer(&p1, [1, 1]);
        assert!(open(&mut auth, &sm(&mut old_receiver, &status([1, 1]))).is_err());
    }

    /// H8 N1: a recoverable store failure (every key withdrawn, then the
    /// same files back) never resets replay state under an unchanged
    /// traffic key. The live verifiers keep the dropped file epochs as
    /// tombstones, so old DATA and old SMs stay refused, and the withdrawn
    /// sealers stay withdrawn; traffic resumes only after a fresh
    /// establishment.
    #[test]
    fn a_restored_key_set_does_not_reopen_replay() {
        use crate::agents::control::ControlSeal;
        use crate::agents::roles::receive_auth::ImageAuth;
        use crate::wire_auth::FixedKeys;

        let c1 = channel_epoch(1, '1');
        let p1 = pairwise(1, '2');
        let all = || FixedKeys {
            files: vec![channel_epoch(1, '1'), pairwise(1, '2')],
        };
        let mut auth =
            PublicationAuth::new(EndpointId(1), ALIAS, IDENTITY, 1, &c1, &[&p1]).unwrap();
        auth.set_clock(|| 1_000);
        let Ok(Opened::RspSetup(_, establishing)) =
            open(&mut auth, &challenge(&p1, [1, 1], [9, 9]))
        else {
            panic!("the receiver binds");
        };
        let mut session = auth.sealer(establishing.party).unwrap();
        let receiver = Party::Receiver {
            identity: IDENTITY,
            receiver_boot_id: [1, 1],
            receiver_id: 66,
        };
        let mut image = ImageAuth::new([&c1], &p1, establishing.party, receiver, ALIAS).unwrap();
        image.set_clock(|| 1_000);
        let mut image_sealer = image.sealer();
        let mut data_bytes = vec![0u8; 8 + ENVELOPE_LEN];
        let length = session.seal(&mut data_bytes, 8).unwrap();
        data_bytes.truncate(length);
        let old_data = data_bytes;
        let old_sm = sealed(&status([1, 1]), |bytes, length| {
            image_sealer.seal_control(bytes, length).unwrap()
        });
        let checked = image.check(&old_data, 1_000).unwrap();
        assert!(image.commit(checked, 1_000).is_ok());
        assert!(matches!(open(&mut auth, &old_sm), Ok(Opened::Receiver(_))));
        // The store fails (every key withdrawn), then reloads the same files.
        for keys in [FixedKeys::default(), all()] {
            auth.apply_keys(&keys);
            image.apply_keys(&keys);
            session.follow(&keys);
        }
        // Old DATA and old SMs stay refused: no empty window came back.
        assert!(image.check(&old_data, 1_000).is_err());
        assert!(open(&mut auth, &old_sm).is_err());
        // The sealers stay withdrawn under the restored key.
        let mut bytes = vec![0u8; 8 + ENVELOPE_LEN];
        assert!(session.seal(&mut bytes, 8).is_err());
        assert!(image.withdrawn());
        // A fresh establishment (a new boot id) binds and works again.
        assert!(matches!(
            open(&mut auth, &challenge(&p1, [2, 2], [8, 8])),
            Ok(Opened::RspSetup(_, fresh)) if fresh.bind
        ));
        let mut fresh = receiver_sealer(&p1, [2, 2]);
        assert!(matches!(
            open(&mut auth, &sm(&mut fresh, &status([2, 2]))),
            Ok(Opened::Receiver(_))
        ));
    }

    /// H8 REV-5: the abort signer is pinned to its admitted file epoch.
    /// With that epoch revoked while a successor of the same key id signs,
    /// it is dropped (and erased), never kept signing under the withdrawn
    /// seed.
    #[test]
    fn a_pinned_abort_signer_is_dropped_when_its_epoch_is_revoked() {
        use crate::authority::Ed25519Signer;
        use crate::wire_auth::FixedKeys;

        let file = pairwise(1, '2');
        let mut auth = publication(&[&file]);
        let mut abort = super::AbortAuthority::new(Ed25519Signer::from_seed(&[9; 32]), 10, 10);
        abort.file_epoch = Some(1);
        auth.abort = Some(abort);
        let successor = key(
            "10-2.key",
            "format=karyos-wire-key-v1\nkey_id=10\nfile_epoch=2\npurpose=authority-signing\nprofile_id=4\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-04-30T00:00:00Z\nsecret=0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a\nauthority_id=10\nguards=11,12\nabort=true\n",
        );
        auth.apply_keys(&FixedKeys {
            files: vec![channel(), pairwise(1, '2'), successor],
        });
        assert!(auth.abort.is_none(), "the withdrawn seed signs nothing");
    }
}

/// The H8 invariants of the publication key holders (karyos#648).
#[cfg(test)]
mod invariants_tests;
