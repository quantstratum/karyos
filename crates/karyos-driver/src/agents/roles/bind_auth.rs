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
use super::receive_auth::SubscriptionAuth;
use super::{AbortScope, ReceiverRole, SenderRole};
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
    /// Receiver: the subscription's keys, the authority whose aborts and
    /// guard it admits, and the view to apply at once.
    Subscription {
        auth: SubscriptionAuth,
        authority: Option<BoundAuthority>,
        view: Arc<KeyView>,
    },
    /// Receiver: the subscription to `stream_id` on `endpoint` ended; its
    /// keys, abort scope and control peer reservation go.
    Unbind {
        endpoint: EndpointId,
        stream_id: i32,
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
        let Binding::Publication { mut auth, abort } = binding else {
            return false;
        };
        auth.abort = abort;
        self.publication_auth
            .retain(|held| (held.endpoint, held.alias) != (auth.endpoint, auth.alias));
        self.publication_auth.push(auth);
        true
    }
}

impl<T: StreamTerms> ReceiverRole<T> {
    /// Holds a receiver binding, replacing any earlier one of its key;
    /// refuses a publication's, and a subscription whose authority's
    /// control budget cannot be reserved (nothing of it is kept then).
    pub(super) fn bind_auth(&mut self, binding: Binding) -> bool {
        match binding {
            Binding::Publication { .. } => false,
            Binding::Follow {
                authority,
                follower_id,
                endpoint,
                marks,
                mirror,
                view,
            } => self.follow(authority, follower_id, endpoint, marks, mirror, &view),
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
            } => {
                self.unbind(endpoint, stream_id);
                true
            }
            Binding::Subscription {
                auth,
                authority,
                view,
            } => {
                let (endpoint, stream_id) = (auth.endpoint, auth.stream_id);
                self.unbind(endpoint, stream_id);
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
