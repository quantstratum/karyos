// SPDX-License-Identifier: Apache-2.0

//! The bindings of an authenticated channel, posted by the conductor at
//! publication and subscription admission (karyos#648; ADR-0086 sections
//! 4, 6 and 7, ADR-0118), and the coordinated key view both roles apply.
//!
//! The conductor checks the keys and the selectors before it posts
//! anything: a binding reaches a role ahead of the publication or
//! subscription it keys, in the same ring, so no establishment of that
//! publication or subscription runs without it. A role replaces an
//! earlier binding of the same key, and refuses (answers `accepted:
//! false`) a binding it cannot hold.

use std::net::SocketAddr;
use std::sync::Arc;

use karyos_protocol::network::Alias;

use super::publish_auth::{AbortAuthority, PublicationAuth};
use super::publish_enc::PublicationEnc;
use super::receive_auth::SubscriptionAuth;
use super::receive_enc::SubscriptionEnc;
use super::{AbortScope, ReceiverRole, SenderRole};
use karyos_io::sockets::ops::SocketOps;

use super::super::ring::Reservation;
use super::super::{AgentCommand, AgentEvent, AgentKind};
use crate::agents::EndpointId;
use crate::embedded::StreamTerms;
use crate::net::wire::KeyView;
use crate::signed_control::SignedIntake;

/// An authenticated channel's keys and selectors, bound at admission for
/// one agent's role.
#[derive(Debug)]
pub struct AuthBinding(pub(crate) Binding);

/// What a binding holds.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "posted once per admission, always boxed in an AuthBinding"
)]
pub(crate) enum Binding {
    /// Sender: the publication's keys and its abort authority.
    Publication {
        auth: PublicationAuth,
        abort: Option<AbortAuthority>,
    },
    /// Receiver: a local authenticated publication, whose receivers'
    /// envelopes go to the sender undecoded.
    Published { endpoint: EndpointId, alias: Alias },
    /// Sender: an encrypted publication's keys (ADR-0114).
    EncPublication { enc: Box<PublicationEnc> },
    /// Receiver: a local encrypted publication, whose receivers'
    /// envelopes go to the sender undecoded (ADR-0114).
    EncPublished { endpoint: EndpointId, alias: Alias },
    /// Receiver: an encrypted subscription's keys and the view to apply at
    /// once (ADR-0114).
    EncSubscription {
        enc: Box<SubscriptionEnc>,
        view: Arc<KeyView>,
        /// Its installation id, which its cleanup names.
        installation: u64,
    },
    /// Receiver: the subscription's keys, the authority whose aborts and
    /// guard it admits, and the view to apply at once.
    Subscription {
        auth: SubscriptionAuth,
        authority: Option<BoundAuthority>,
        view: Arc<KeyView>,
        /// Its installation id, which its cleanup names.
        installation: u64,
        /// The driver's durable abort record, with a subscription that
        /// admits remote aborts (H8 RCV-4): kept from the first.
        aborted: Option<Box<dyn crate::remote_guard::AbortRecord + Send>>,
    },
    /// Receiver: the subscription to `stream_id` on `endpoint` installed
    /// as `installation` ended; its keys, abort scope and control peer
    /// reservation go. Another installation of the key is left as it is.
    Unbind {
        endpoint: EndpointId,
        stream_id: i32,
        installation: u64,
    },
    /// Receiver: follow the remote guard of a local authenticated
    /// publication as `follower_id`, its challenges leaving from
    /// `endpoint` to the authority's control endpoint, its word written to
    /// `mirror` for the publication's admission and gate; `marks` is the
    /// driver's durable mark store, sent with the first follow only.
    Follow {
        authority: BoundAuthority,
        follower_id: u64,
        endpoint: EndpointId,
        marks: Option<Box<dyn crate::remote_guard::MarkStore + Send>>,
        mirror: Arc<karyos_client::HeapWords>,
        view: Arc<KeyView>,
        /// Its installation id, which its cleanup names.
        installation: u64,
    },
    /// Receiver: the last local publication guarded by `guard_id` went:
    /// stop following it and release its control peer's reservation,
    /// unless a later follow (another `installation`) took it over.
    Unfollow {
        guard_id: u64,
        control: SocketAddr,
        installation: u64,
    },
    /// Receiver: be the guard authority, answering only on `endpoints`.
    Authority {
        authority: Box<crate::guard_authority::GuardAuthority>,
        endpoints: Vec<EndpointId>,
        view: Arc<KeyView>,
    },
}

/// The abort and guard authority a subscription admits (ADR-0118 (a)).
#[derive(Debug, Clone, Copy)]
pub(crate) struct BoundAuthority {
    pub(crate) key_id: u32,
    pub(crate) authority_id: u64,
    pub(crate) guard_id: u64,
    /// Its guard control endpoint, whose verify budget is reserved.
    pub(crate) control: SocketAddr,
}

impl<T: StreamTerms> SenderRole<T> {
    /// Holds a publication's binding, replacing any earlier one of its
    /// key; refuses a receiver's.
    pub(super) fn bind_auth(&mut self, binding: Binding) -> bool {
        let (mut auth, abort) = match binding {
            Binding::Publication { auth, abort } => (auth, abort),
            Binding::EncPublication { enc } => {
                self.encrypt_publication(*enc);
                return true;
            }
            _ => return false,
        };
        auth.abort = abort;
        self.publication_auth
            .retain(|held| (held.endpoint, held.alias) != (auth.endpoint, auth.alias));
        self.publication_auth.push(auth);
        true
    }
}

impl<T: StreamTerms> SenderRole<T> {
    /// An authenticated publication's binding and its `AddPublication`,
    /// as one command (H8 R3-5): the binding is held only when the
    /// publication is added, and a refused binding refuses the add.
    pub(super) fn add_authenticated<O: SocketOps>(
        &mut self,
        binding: Binding,
        add: AgentCommand<O, T>,
    ) -> Option<(Reservation, AgentEvent<O, T>)> {
        let key = match &binding {
            Binding::Publication { auth, .. } => Some((auth.endpoint, auth.alias)),
            Binding::EncPublication { enc } => Some((enc.endpoint, enc.alias)),
            _ => None,
        };
        let registration = match &add {
            AgentCommand::AddPublication { publication, .. } => {
                Some(publication.identity.registration_id)
            }
            _ => None,
        };
        if !self.bind_auth(binding) {
            return match add {
                AgentCommand::AddPublication {
                    reply, publication, ..
                } => Some((
                    reply,
                    AgentEvent::PublicationRefused {
                        agent: AgentKind::Sender,
                        endpoint: publication.endpoint,
                        alias: publication.alias,
                        registration: publication.identity.registration_id,
                    },
                )),
                other => self.command(other),
            };
        }
        let answer = self.command(add);
        if let (Some(key), Some((_, AgentEvent::PublicationRefused { .. }))) = (key, &answer) {
            self.publication_auth
                .retain(|held| (held.endpoint, held.alias) != key);
            self.enc.unpublish(key.0, key.1);
        } else if let (Some((endpoint, alias)), Some(registration)) = (key, registration) {
            self.publication_installs
                .retain(|(held, at, _)| (*held, *at) != (endpoint, alias));
            self.publication_installs
                .push((endpoint, alias, registration));
        }
        answer
    }

    /// Drops the binding of the publication `alias` on `endpoint` added
    /// for `registration` (ADM-10): its SETUP proof, domain 1 prototype,
    /// receivers' verifiers, boot table and abort signer, erased on drop.
    /// A later publication's binding of the key is left as it is.
    pub(super) fn unbind_publication(
        &mut self,
        endpoint: EndpointId,
        alias: Alias,
        registration: u64,
    ) {
        if !self
            .publication_installs
            .contains(&(endpoint, alias, registration))
        {
            return;
        }
        self.publication_installs
            .retain(|(held, at, _)| (*held, *at) != (endpoint, alias));
        self.publication_auth
            .retain(|held| (held.endpoint, held.alias) != (endpoint, alias));
        self.enc.unpublish(endpoint, alias);
    }

    /// Whether the publication `alias` on `endpoint` is of the
    /// authenticated class, bound or not (ADM-9).
    pub(super) fn needs_auth_binding(&self, endpoint: EndpointId, alias: Alias) -> bool {
        self.publications.iter().any(|outbound| {
            outbound.serves(endpoint) && outbound.alias() == alias && outbound.needs_auth_binding()
        })
    }
}

impl<T: StreamTerms> ReceiverRole<T> {
    /// An authenticated binding and the `AddSubscription` or
    /// `AddPublishedAlias` it keys, as one command (H8 R3-5): one ring
    /// slot, so neither goes without the other; a refused binding refuses
    /// the add, and a refused add drops the binding it made.
    pub(super) fn add_authenticated<O: SocketOps>(
        &mut self,
        binding: Binding,
        add: AgentCommand<O, T>,
    ) -> Option<(Reservation, AgentEvent<O, T>)> {
        let installed = match &binding {
            Binding::Subscription {
                auth, installation, ..
            } => Some((auth.endpoint, auth.stream_id, *installation)),
            Binding::EncSubscription {
                enc, installation, ..
            } => Some((enc.endpoint, enc.stream_id, *installation)),
            _ => None,
        };
        if !self.bind_auth(binding) {
            let refused = |subscription| AgentEvent::Configured {
                agent: AgentKind::Receiver,
                accepted: false,
                subscription,
            };
            return match add {
                AgentCommand::AddSubscription {
                    reply,
                    endpoint,
                    stream_id,
                    ..
                } => Some((reply, refused(Some((endpoint, stream_id))))),
                AgentCommand::AddPublishedAlias { reply, .. } => Some((reply, refused(None))),
                other => self.command(other),
            };
        }
        let answer = self.command(add);
        if let (
            Some((endpoint, stream_id, installation)),
            Some((
                _,
                AgentEvent::Configured {
                    accepted: false, ..
                },
            )),
        ) = (installed, &answer)
        {
            self.unbind_installation(endpoint, stream_id, installation);
        }
        answer
    }

    /// Drops the binding of `stream_id` on `endpoint` only when it is
    /// `installation`'s.
    fn unbind_installation(&mut self, endpoint: EndpointId, stream_id: i32, installation: u64) {
        if self
            .auth_installs
            .contains(&(endpoint, stream_id, installation))
        {
            self.unbind(endpoint, stream_id);
        }
    }

    /// Holds a receiver binding, replacing any earlier one of its key;
    /// refuses a publication's, and a subscription whose authority's
    /// control budget cannot be reserved (nothing of it is kept then).
    pub(super) fn bind_auth(&mut self, binding: Binding) -> bool {
        match binding {
            Binding::Publication { .. } | Binding::EncPublication { .. } => false,
            Binding::EncPublished { endpoint, alias } => {
                self.encrypt_published(endpoint, alias);
                true
            }
            Binding::EncSubscription {
                enc,
                view,
                installation,
            } => {
                let (endpoint, stream_id) = (enc.endpoint, enc.stream_id);
                self.unbind(endpoint, stream_id);
                self.encrypt_subscription(*enc);
                self.auth_installs.push((endpoint, stream_id, installation));
                // Its keys follow the view they were checked against.
                self.apply_keys(&*view);
                true
            }
            Binding::Unfollow {
                guard_id,
                control,
                installation,
            } => {
                // A later follow of the guard keeps it (H8 R3-5).
                if !self.follow_installs.contains(&(guard_id, installation)) {
                    return true;
                }
                self.follow_installs.retain(|(held, _)| *held != guard_id);
                let before = self.remote_guards.len();
                self.remote_guards
                    .retain(|followed| followed.guard.guard_id() != guard_id);
                if self.remote_guards.len() != before
                    && let Some(intake) = self.signed.as_deref_mut()
                {
                    intake.release(control);
                }
                true
            }
            Binding::Follow {
                authority,
                follower_id,
                endpoint,
                marks,
                mirror,
                view,
                installation,
            } => {
                let followed = self.follow(authority, follower_id, endpoint, marks, mirror, &view);
                if followed {
                    self.follow_installs
                        .retain(|(held, _)| *held != authority.guard_id);
                    self.follow_installs
                        .push((authority.guard_id, installation));
                }
                followed
            }
            Binding::Authority {
                authority,
                endpoints,
                view,
            } => {
                self.guard_authority = Some(authority);
                self.guard_authority_endpoints = endpoints;
                self.apply_keys(&*view);
                true
            }
            Binding::Published { endpoint, alias } => {
                if !self.published_auth.contains(&(endpoint, alias)) {
                    self.published_auth.push((endpoint, alias));
                }
                true
            }
            Binding::Unbind {
                endpoint,
                stream_id,
                installation,
            } => {
                self.unbind_installation(endpoint, stream_id, installation);
                true
            }
            Binding::Subscription {
                auth,
                authority,
                view,
                installation,
                aborted,
            } => {
                let (endpoint, stream_id) = (auth.endpoint, auth.stream_id);
                self.unbind(endpoint, stream_id);
                if self.abort_record.is_none() {
                    self.abort_record = aborted;
                }
                if let Some(authority) = authority {
                    let now = (self.clock)();
                    let retention = self.liveness_timeout;
                    let intake = self.signed.get_or_insert_with(|| {
                        let mut intake = SignedIntake::new(Vec::new(), now);
                        intake.set_retention(retention);
                        Box::new(intake)
                    });
                    if !intake.reserve(authority.control, now) {
                        return false;
                    }
                    self.auth_peers
                        .push((endpoint, stream_id, authority.control));
                    if !self
                        .authority_keys
                        .iter()
                        .any(|(key_id, _)| *key_id == authority.key_id)
                    {
                        self.authority_keys.push((authority.key_id, None));
                    }
                    self.abort_scopes.push((
                        endpoint,
                        stream_id,
                        AbortScope {
                            authority_id: authority.authority_id,
                            guard_id: authority.guard_id,
                        },
                    ));
                }
                self.subscription_auth.push(auth);
                self.auth_installs.push((endpoint, stream_id, installation));
                // The trusted authorities and every key of the receive side
                // follow the view the binding was checked against.
                self.apply_keys(&*view);
                true
            }
        }
    }

    /// Follows a remote guard (karyos#648; design guards-and-abort.md):
    /// trusts its authority's key, reserves its control endpoint's verify
    /// budget and loads its durable mark. Refused, with nothing kept, when
    /// the budget cannot be reserved or no mark store is held; the
    /// publication it guards then stays admission-pending (fail closed).
    /// Following a guard again (a new incarnation) replaces its mirror.
    fn follow(
        &mut self,
        authority: BoundAuthority,
        follower_id: u64,
        endpoint: EndpointId,
        marks: Option<Box<dyn crate::remote_guard::MarkStore + Send>>,
        mirror: Arc<karyos_client::HeapWords>,
        view: &KeyView,
    ) -> bool {
        if self.guard_marks.is_none() {
            self.guard_marks = marks;
        }
        let Some(store) = self.guard_marks.as_deref() else {
            return false;
        };
        let now = (self.clock)();
        if let Some(followed) = self
            .remote_guards
            .iter_mut()
            .find(|followed| followed.guard.guard_id() == authority.guard_id)
        {
            followed.mirror = Some(mirror);
            self.publish_guard_words(now);
            return true;
        }
        let guard = crate::remote_guard::RemoteGuard::load(
            authority.authority_id,
            authority.guard_id,
            store,
        );
        let retention = self.liveness_timeout;
        let intake = self.signed.get_or_insert_with(|| {
            let mut intake = SignedIntake::new(Vec::new(), now);
            intake.set_retention(retention);
            Box::new(intake)
        });
        if !intake.reserve(authority.control, now) {
            return false;
        }
        if !self
            .authority_keys
            .iter()
            .any(|(key_id, _)| *key_id == authority.key_id)
        {
            self.authority_keys.push((authority.key_id, None));
        }
        self.remote_guards.push(super::FollowedGuard {
            guard,
            receiver_id: follower_id,
            endpoint,
            authority: authority.control,
            mirror: Some(mirror),
        });
        self.apply_keys(view);
        self.publish_guard_words(now);
        true
    }

    /// Drops the binding of the subscription to `stream_id` on `endpoint`:
    /// its keys, its abort scope and its control peer reservation.
    fn unbind(&mut self, endpoint: EndpointId, stream_id: i32) {
        let key = (endpoint, stream_id);
        self.subscription_auth
            .retain(|held| (held.endpoint, held.stream_id) != key);
        self.enc.unsubscribe(endpoint, stream_id);
        self.auth_installs
            .retain(|(held, stream, _)| (*held, *stream) != key);
        self.abort_scopes
            .retain(|(held, stream, _)| (*held, *stream) != key);
        let signed = &mut self.signed;
        self.auth_peers.retain(|(held, stream, control)| {
            let mine = (*held, *stream) == key;
            if mine && let Some(intake) = signed.as_deref_mut() {
                intake.release(*control);
            }
            !mine
        });
    }
}

#[cfg(test)]
impl<T: StreamTerms> SenderRole<T> {
    /// Reads the VM generation signal with `watch` (tests).
    pub(crate) fn auth_watch(&mut self, watch: crate::wire_enc::VmGenerationWatch) {
        self.enc.watch(watch);
    }

    /// The authenticated publications bound, the publications whose
    /// session sealer is installed and live, and those waiting for their
    /// remote guard's first open (tests).
    pub(crate) fn auth_state(&self) -> (usize, usize, usize) {
        let sealing = self
            .publications
            .iter()
            .filter(|outbound| outbound.sealer_live())
            .count();
        let pending = self
            .publications
            .iter()
            .filter(|outbound| outbound.admission_pending())
            .count();
        (self.publication_auth.len(), sealing, pending)
    }
}

#[cfg(test)]
impl<T: StreamTerms> ReceiverRole<T> {
    /// The local authenticated publication aliases bound (tests).
    pub(crate) fn published_bound(&self) -> usize {
        self.published_auth.len()
    }

    /// A receiver-only restart of this receive side (tests; H8 round 4):
    /// what a fresh process start loses is lost here, nothing else. Every
    /// image is retired with its keys (the shared sealers withdrawn for
    /// every holder), the signed digest cache is emptied, and a fresh
    /// `receiver_boot_id` is drawn, so earlier challenges match no answer.
    /// Configuration (subscriptions, their keys, trusted authorities and
    /// durable guard marks) stays, as a restart reloads it.
    pub(in crate::agents) fn restart_receive_side(
        &mut self,
        sessions: &super::super::chain::SessionEnd<T>,
        now: u64,
    ) {
        while let Some(installed) = self.images.pop() {
            if let Some(auth) = installed.auth.as_deref() {
                crate::agents::control::ControlSeal::withdraw(&mut auth.sealer());
            }
            self.retire(sessions, installed, false, now);
        }
        if let Some(intake) = self.signed.as_deref_mut() {
            intake.forget(|_| true);
        }
        let old = self.sessions.boot_id();
        let mut boot = [0_u64; 2];
        while boot == [0, 0] || boot == old {
            let _ = karyos_sys::random::fill_u64s(&mut boot);
        }
        self.sessions.set_boot_id(boot);
    }

    /// The remote guards followed (tests).
    pub(crate) fn followed_guards(&self) -> usize {
        self.remote_guards.len()
    }

    /// The authenticated subscriptions bound, the authenticated images,
    /// and those whose sealer a key reload withdrew (tests).
    pub(crate) fn auth_state(&self) -> (usize, usize, usize) {
        let images = self.images.iter().filter_map(|image| image.auth.as_deref());
        (
            self.subscription_auth.len(),
            images.clone().count(),
            images.filter(|auth| auth.withdrawn()).count(),
        )
    }
}
