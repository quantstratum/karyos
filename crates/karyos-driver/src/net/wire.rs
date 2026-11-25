// SPDX-License-Identifier: Apache-2.0

//! The driver's one wire key store and the admission of authenticated
//! channels (karyos#648; `quantstratum-docs:
//! karyos/adr/0086-wire-authentication-profile-v1.md` sections 4, 6 and 7,
//! ADR-0107, ADR-0118; design `wire-key-files.md` sections 2.3 and 2.4).
//!
//! `WireKeys` owns the driver's [`KeyStore`], started once from the
//! configured key and state directories. The conductor reloads it every
//! [`RELOAD_INTERVAL_S`] seconds (the manifest's revocation bound) and
//! re-reads its key set every [`TICK_S`] for expiry; each change is one
//! immutable [`KeyView`] posted to both agents in the same conductor duty,
//! where each role applies it through its `apply_keys`. A store that fails
//! names no key, so every authenticated path stops.
//!
//! Admission binds an authenticated channel's key ids, its single unicast
//! receiver and its abort and guard authority before anything is posted
//! to an agent, and refuses, typed ([`AuthRefusal`]), a missing or invalid
//! key, an ambiguous configuration, or a control peer budget it cannot
//! reserve.

use std::net::SocketAddr;
use std::sync::Arc;

use karyos_protocol::channel::{AuthenticatedChannel, Security};

use crate::error::{AuthRefusal, DriverError};
use crate::wire_auth::{KeySet, MAX_FILE_EPOCHS, StoreKeys};
use crate::wire_keys::store::{FileError, Files, KeyStore, RELOAD_INTERVAL_S, Report};
use crate::wire_keys::{KeyFile, Material, Purpose, Scope};

/// How often the conductor re-reads the key set for expiry, in seconds.
pub const TICK_S: i64 = 1;

/// A key or state directory the driver's store reads.
pub type Dir = Box<dyn Files + Send>;

impl Files for Dir {
    fn names(&self) -> Result<Vec<String>, FileError> {
        (**self).names()
    }

    fn read(&self, name: &str, buf: &mut [u8]) -> Result<usize, FileError> {
        (**self).read(name, buf)
    }

    fn write_atomic(&self, name: &str, bytes: &[u8]) -> Result<(), FileError> {
        (**self).write_atomic(name, bytes)
    }

    fn lock(&self) -> Result<(), FileError> {
        (**self).lock()
    }
}

/// The authenticated channel `security` names; `None` for a trusted one.
///
/// # Errors
///
/// [`DriverError::UnsupportedChannel`] for any other class: never run as
/// trusted (fail closed).
pub(crate) fn authenticated(
    security: Security,
) -> Result<Option<AuthenticatedChannel>, DriverError> {
    match security {
        Security::Trusted => Ok(None),
        #[cfg(feature = "test-hooks")]
        Security::Authenticated(channel) => Ok(Some(channel)),
        _ => Err(DriverError::UnsupportedChannel),
    }
}

fn refused(reason: AuthRefusal) -> DriverError {
    DriverError::AuthenticatedRefused { reason }
}

/// A copy of `file`, its secret erased with it on drop.
fn duplicate(file: &KeyFile) -> KeyFile {
    KeyFile {
        key_id: file.key_id,
        file_epoch: file.file_epoch,
        purpose: file.purpose,
        profile_id: file.profile_id,
        not_before: file.not_before,
        not_after: file.not_after,
        material: match &file.material {
            Material::Secret(secret) => Material::Secret(secret.clone()),
            Material::Public(public) => Material::Public(public.clone()),
        },
        scope: file.scope.clone(),
    }
}

/// One key id's files as a [`KeyView`] holds them.
#[derive(Debug)]
struct ViewKey {
    key_id: u32,
    signing: Option<KeyFile>,
    verifying: [Option<KeyFile>; MAX_FILE_EPOCHS],
    current_epoch: Option<u32>,
}

/// The store's key set at one wall clock second, owned, so both agents
/// apply the same one ([`KeySet`]). Built on the control path; a disabled
/// store's view names no key.
#[derive(Debug, Default)]
pub struct KeyView {
    keys: Vec<ViewKey>,
    /// The store's [`KeySet::fingerprint`] at that second.
    fingerprint: u64,
}

impl KeyView {
    /// The key set of `store` at the wall clock `now`, in seconds.
    #[must_use]
    pub fn of<K: Files, S: Files>(store: &KeyStore<K, S>, now: i64) -> Self {
        let set = StoreKeys { store, now };
        let fingerprint = set.fingerprint();
        if store.is_disabled() {
            return Self {
                keys: Vec::new(),
                fingerprint,
            };
        }
        let mut ids: Vec<u32> = store.loaded().map(|file| file.key_id).collect();
        ids.sort_unstable();
        ids.dedup();
        let keys = ids
            .into_iter()
            .map(|key_id| {
                let [low, high] = set.verifying(key_id);
                ViewKey {
                    key_id,
                    signing: set.signing(key_id).map(duplicate),
                    verifying: [low.map(duplicate), high.map(duplicate)],
                    current_epoch: set.current_epoch(key_id),
                }
            })
            .collect();
        Self { keys, fingerprint }
    }

    fn key(&self, key_id: u32) -> Option<&ViewKey> {
        self.keys.iter().find(|key| key.key_id == key_id)
    }

    /// What each key id signs and verifies with: equal for two views that
    /// every role applies alike.
    fn summary(&self) -> impl Iterator<Item = (u32, Option<u32>, [Option<u32>; 2], Option<u32>)> {
        self.keys.iter().map(|key| {
            let [low, high] = &key.verifying;
            (
                key.key_id,
                key.signing.as_ref().map(|file| file.file_epoch),
                [
                    low.as_ref().map(|file| file.file_epoch),
                    high.as_ref().map(|file| file.file_epoch),
                ],
                key.current_epoch,
            )
        })
    }

    /// A view naming no key, as a failed store's, distinct from any set
    /// applied before (tests).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn withdrawn() -> Self {
        Self {
            keys: Vec::new(),
            fingerprint: u64::MAX,
        }
    }

    /// Whether it names nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

impl KeySet for KeyView {
    fn signing(&self, key_id: u32) -> Option<&KeyFile> {
        self.key(key_id)?.signing.as_ref()
    }

    fn verifying(&self, key_id: u32) -> [Option<&KeyFile>; MAX_FILE_EPOCHS] {
        self.key(key_id).map_or([None, None], |key| {
            let [low, high] = &key.verifying;
            [low.as_ref(), high.as_ref()]
        })
    }

    fn current_epoch(&self, key_id: u32) -> Option<u32> {
        self.key(key_id)?.current_epoch
    }

    fn fingerprint(&self) -> u64 {
        self.fingerprint
    }
}

/// What the key store did, for the CnC and the operator.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WireKeyCounters {
    /// Reloads run.
    pub reloads: u64,
    /// Key views posted to the agents.
    pub applied: u64,
    /// Diagnostic events (refused, disabled or failed keys), each raising
    /// the alarm.
    pub events: u64,
    /// Loads or reloads that left the whole store disabled.
    pub failures: u64,
    /// Views the agents' rings refused, posted again at the next tick.
    pub unposted: u64,
    /// Authenticated admissions refused with `NetworkBusy` because a ring
    /// had no room for a binding: nothing of them runs.
    pub admissions_busy: u64,
    /// Bindings (an unbind or unfollow) a full ring deferred to a later
    /// duty, never dropped.
    pub bindings_deferred: u64,
    /// Authenticated admissions refused for an `etf` declaration.
    pub etf_refused: u64,
}

/// The driver's durable guard marks, shared by every follow binding that
/// carries them, so a binding a full ring refused loses nothing: the
/// receiver keeps the first copy it is given.
#[derive(Clone)]
pub(crate) struct SharedMarks(Arc<std::sync::Mutex<crate::remote_guard::GuardMarks<Dir>>>);

impl core::fmt::Debug for SharedMarks {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SharedMarks").finish_non_exhaustive()
    }
}

impl SharedMarks {
    fn with<R>(
        &self,
        run: impl FnOnce(
            &mut crate::remote_guard::GuardMarks<Dir>,
        ) -> Result<R, crate::remote_guard::MarkError>,
    ) -> Result<R, crate::remote_guard::MarkError> {
        // A poisoned lock is unreadable: nothing opens (fail closed).
        let mut marks = self
            .0
            .lock()
            .map_err(|_| crate::remote_guard::MarkError::Unreadable)?;
        run(&mut marks)
    }
}

impl crate::remote_guard::MarkStore for SharedMarks {
    fn load(&self, guard_id: u64) -> Result<u64, crate::remote_guard::MarkError> {
        self.with(|marks| marks.load(guard_id))
    }

    fn latched(&self, guard_id: u64) -> Result<bool, crate::remote_guard::MarkError> {
        self.with(|marks| marks.latched(guard_id))
    }

    fn persist(&mut self, guard_id: u64, epoch: u64) -> Result<(), crate::remote_guard::MarkError> {
        self.with(|marks| marks.persist(guard_id, epoch))
    }

    fn latch(&mut self, guard_id: u64) -> Result<(), crate::remote_guard::MarkError> {
        self.with(|marks| marks.latch(guard_id))
    }
}

/// The keys an authenticated publication binds.
#[derive(Debug)]
pub(crate) struct PublicationKeys {
    /// The channel signing key.
    pub(crate) channel: KeyFile,
    /// The receiver's pairwise files, one or two epochs.
    pub(crate) pairwise: Vec<KeyFile>,
    /// The abort authority's signing key, with its `authority_id`.
    pub(crate) abort: Option<(KeyFile, u64)>,
    /// The remote guard it follows, through the authority's public key.
    pub(crate) follow: Option<karyos_protocol::channel::ChannelAuthority>,
}

/// What an authenticated publication binds on each role.
#[derive(Debug)]
pub(crate) struct PublicationBinding {
    /// The sender's keys and abort authority.
    pub(crate) sender: crate::agents::roles::Binding,
    /// The receiver's follow of its remote guard, and the word the
    /// publication's admission and gate read.
    pub(crate) follow: Option<(crate::agents::roles::Binding, Arc<karyos_client::HeapWords>)>,
}

/// The keys an authenticated subscription binds.
#[derive(Debug)]
pub(crate) struct SubscriptionKeys {
    /// The channel key's newest verifying file.
    pub(crate) channel: KeyFile,
    /// The pairwise signing key.
    pub(crate) pairwise: KeyFile,
    /// The view the binding applies at once.
    pub(crate) view: Arc<KeyView>,
}

/// The driver's wire key store and its schedule.
pub(crate) struct WireKeys {
    store: KeyStore<Dir, Dir>,
    /// The wall clock in seconds.
    clock: fn() -> i64,
    next_reload: i64,
    next_tick: i64,
    view: Arc<KeyView>,
    /// A view the rings refused: posted again at the next tick.
    unposted: bool,
    /// The control peers whose verify budget the receiver holds, with how
    /// many subscriptions reserved each: the receiver's peer table is
    /// [`crate::signed_control::PEER_SLOTS`] long.
    peers: Vec<(SocketAddr, u32)>,
    counters: WireKeyCounters,
    /// The last diagnostic events, for the operator.
    last_report: Report,
    /// The followed guards' durable marks, shared with the receiver.
    marks: Option<SharedMarks>,
    /// The remote guard each remotely guarded publication follows, by
    /// registration, with its authority's control endpoint: the last one
    /// of a guard to go unfollows it.
    followed: Vec<(u64, u64, SocketAddr)>,
    /// Receiver bindings a full ring refused, posted first at each duty.
    deferred: Vec<Box<crate::agents::roles::AuthBinding>>,
    /// The guard authority's committed epochs, until it starts.
    commits: Option<Dir>,
}

impl core::fmt::Debug for WireKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WireKeys")
            .field("counters", &self.counters)
            .finish_non_exhaustive()
    }
}

/// The host wall clock in seconds since the Unix epoch.
fn wall_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok())
        .unwrap_or(0)
}

impl WireKeys {
    /// Starts the store over `keys` and `state` at the wall `clock`.
    pub(crate) fn start(
        keys: Dir,
        state: Dir,
        clock: Option<fn() -> i64>,
    ) -> Result<(Self, Report), crate::wire_keys::store::StoreError> {
        let clock = clock.unwrap_or(wall_seconds);
        let now = clock();
        let (store, report) = KeyStore::start(keys, state, now)?;
        let counters = WireKeyCounters {
            events: u64::try_from(report.events.len()).unwrap_or(u64::MAX),
            failures: u64::from(store.is_disabled()),
            ..WireKeyCounters::default()
        };
        let view = Arc::new(KeyView::of(&store, now));
        let last_report = Report {
            events: report.events.clone(),
        };
        Ok((
            Self {
                store,
                clock,
                next_reload: now.saturating_add(RELOAD_INTERVAL_S),
                next_tick: now.saturating_add(TICK_S),
                view,
                unposted: false,
                peers: Vec::with_capacity(crate::signed_control::PEER_SLOTS),
                counters,
                last_report,
                marks: None,
                followed: Vec::new(),
                deferred: Vec::new(),
                commits: None,
            },
            report,
        ))
    }

    /// The current view.
    pub(crate) fn view(&self) -> Arc<KeyView> {
        Arc::clone(&self.view)
    }

    /// The counters.
    pub(crate) fn counters(&self) -> WireKeyCounters {
        self.counters
    }

    /// The last reload's diagnostic events.
    pub(crate) fn last_report(&self) -> &Report {
        &self.last_report
    }

    /// The conductor's duty: a reload when due, and the key set re-read
    /// each tick; the new view when it changed (or a refused one is due
    /// again), for both agents at once.
    pub(crate) fn duty(&mut self) -> Option<Arc<KeyView>> {
        let now = (self.clock)();
        if now < self.next_tick && !self.unposted {
            return None;
        }
        self.next_tick = now.saturating_add(TICK_S);
        if now >= self.next_reload {
            self.next_reload = now.saturating_add(RELOAD_INTERVAL_S);
            self.counters.reloads = self.counters.reloads.saturating_add(1);
            let report = self.store.reload(now);
            if report.alarm() {
                let events = u64::try_from(report.events.len()).unwrap_or(u64::MAX);
                self.counters.events = self.counters.events.saturating_add(events);
                self.last_report = report;
            }
            if self.store.is_disabled() {
                self.counters.failures = self.counters.failures.saturating_add(1);
            }
        }
        let view = KeyView::of(&self.store, now);
        if !self.unposted
            && view.fingerprint == self.view.fingerprint
            && view.summary().eq(self.view.summary())
        {
            return None;
        }
        self.view = Arc::new(view);
        Some(Arc::clone(&self.view))
    }

    /// Records whether the view the duty returned reached both agents.
    pub(crate) fn posted(&mut self, both: bool) {
        self.unposted = !both;
        if both {
            self.counters.applied = self.counters.applied.saturating_add(1);
        } else {
            self.counters.unposted = self.counters.unposted.saturating_add(1);
        }
    }

    /// The publication side of `channel` at admission: its channel signing
    /// key, its one receiver's pairwise files and, when it names one, its
    /// abort authority's signing key (ADR-0118: the authority that guards
    /// it).
    pub(crate) fn publication(
        &self,
        channel: &AuthenticatedChannel,
    ) -> Result<PublicationKeys, DriverError> {
        let view = &*self.view;
        if self.store.is_disabled() {
            return Err(refused(AuthRefusal::KeyStoreDisabled));
        }
        let signing = view
            .signing(channel.channel_key_id)
            .filter(|file| file.purpose == Purpose::Channel)
            .ok_or_else(|| refused(AuthRefusal::ChannelKey))?;
        let pairwise: Vec<KeyFile> = view
            .verifying(channel.pairwise_key_id)
            .into_iter()
            .flatten()
            .filter(|file| {
                file.purpose == Purpose::Pairwise
                    && matches!(file.scope, Scope::Pairwise { receiver_id, .. } if receiver_id == channel.receiver_id)
            })
            .map(duplicate)
            .collect();
        if pairwise.is_empty() {
            return Err(refused(AuthRefusal::PairwiseKey));
        }
        // The authority that guards it (ADR-0118 (a)): this driver itself,
        // signing its aborts, or a remote one whose guard it follows
        // through the authority's public key, its marks durable.
        let (abort, follow) = match channel.authority {
            None => (None, None),
            Some(authority) => {
                let signing = view.signing(authority.key_id).filter(|file| {
                    file.purpose == Purpose::AuthoritySigning
                        && serves(file, authority.authority_id, authority.guard_id)
                });
                let public = view
                    .verifying(authority.key_id)
                    .into_iter()
                    .flatten()
                    .max_by_key(|file| file.file_epoch)
                    .filter(|file| {
                        file.purpose == Purpose::AuthorityPublic
                            && serves(file, authority.authority_id, authority.guard_id)
                    });
                match (signing, public) {
                    (Some(file), _) => (Some((duplicate(file), authority.authority_id)), None),
                    (None, Some(_)) if authority.follower_id != 0 => {
                        if !crate::agents::roles::answerable(authority.control) {
                            return Err(refused(AuthRefusal::Ambiguous));
                        }
                        if self.marks.is_none() {
                            return Err(refused(AuthRefusal::GuardState));
                        }
                        (None, Some(authority))
                    }
                    _ => return Err(refused(AuthRefusal::AuthorityKey)),
                }
            }
        };
        Ok(PublicationKeys {
            channel: duplicate(signing),
            pairwise,
            abort,
            follow,
        })
    }

    /// The sender binding of the authenticated `publication` of `channel`:
    /// its keys and, when the channel names one, its abort authority from
    /// the authority's signing key (ADR-0118: the authority that guards
    /// it, under the file epoch it was bound at).
    pub(crate) fn publication_binding(
        &mut self,
        channel: &AuthenticatedChannel,
        publication: &crate::sessions::send::Publication,
    ) -> Result<PublicationBinding, DriverError> {
        use crate::agents::roles::publish_auth::{AbortAuthority, PublicationAuth};

        let keys = self.publication(channel)?;
        let pairwise: Vec<&KeyFile> = keys.pairwise.iter().collect();
        let auth = PublicationAuth::new(
            publication.endpoint,
            publication.alias,
            publication.identity,
            publication.lane_count,
            &keys.channel,
            &pairwise,
        )
        .map_err(|_| refused(AuthRefusal::ChannelKey))?;
        let abort = match keys.abort {
            None => None,
            Some((file, authority_id)) => {
                let Material::Secret(seed) = &file.material else {
                    return Err(refused(AuthRefusal::AuthorityKey));
                };
                let mut abort = AbortAuthority::new(
                    crate::authority::Ed25519Signer::from_seed(seed),
                    file.key_id,
                    authority_id,
                );
                abort.file_epoch = Some(file.file_epoch);
                Some(abort)
            }
        };
        // A remotely guarded publication waits closed for its guard's
        // first open; the mark store goes with the first follow.
        let follow = keys.follow.map(|authority| {
            let mirror = Arc::new(karyos_client::HeapWords::zeroed(1));
            let marks = self
                .marks
                .clone()
                .map(|marks| Box::new(marks) as Box<dyn crate::remote_guard::MarkStore + Send>);
            let registration = publication.identity.registration_id;
            if !self.followed.iter().any(|(held, ..)| *held == registration) {
                self.followed
                    .push((registration, authority.guard_id, authority.control));
            }
            let binding = crate::agents::roles::Binding::Follow {
                authority: crate::agents::roles::BoundAuthority {
                    key_id: authority.key_id,
                    authority_id: authority.authority_id,
                    guard_id: authority.guard_id,
                    control: authority.control,
                },
                follower_id: authority.follower_id,
                endpoint: publication.endpoint,
                marks,
                mirror: Arc::clone(&mirror),
                view: Arc::clone(&self.view),
            };
            (binding, mirror)
        });
        Ok(PublicationBinding {
            sender: crate::agents::roles::Binding::Publication { auth, abort },
            follow,
        })
    }

    /// The guard the removed publication `registration` followed, with its
    /// authority's control endpoint, when no other publication follows it.
    pub(crate) fn unfollow(&mut self, registration: u64) -> Option<(u64, SocketAddr)> {
        let at = self
            .followed
            .iter()
            .position(|(held, ..)| *held == registration)?;
        let (_, guard_id, control) = self.followed.swap_remove(at);
        (!self.followed.iter().any(|(_, held, _)| *held == guard_id)).then_some((guard_id, control))
    }

    /// Keeps `binding`, which a full ring refused, for the next duty.
    pub(crate) fn defer(&mut self, binding: Box<crate::agents::roles::AuthBinding>) {
        self.counters.bindings_deferred = self.counters.bindings_deferred.saturating_add(1);
        self.deferred.push(binding);
    }

    /// The deferred bindings, oldest first, to post again.
    pub(crate) fn take_deferred(&mut self) -> Vec<Box<crate::agents::roles::AuthBinding>> {
        core::mem::take(&mut self.deferred)
    }

    /// Counts an authenticated admission refused for an etf declaration.
    pub(crate) fn count_etf_refused(&mut self) {
        self.counters.etf_refused = self.counters.etf_refused.saturating_add(1);
    }

    /// Counts an authenticated admission a full ring refused.
    pub(crate) fn count_busy(&mut self) {
        self.counters.admissions_busy = self.counters.admissions_busy.saturating_add(1);
    }

    /// Holds the durable guard state: the followed guards' marks and the
    /// authority's committed epochs (design guards-and-abort.md).
    pub(crate) fn set_guard_state(&mut self, marks: Dir, commits: Dir) -> Result<(), DriverError> {
        if self.marks.is_some() || self.commits.is_some() {
            return Err(DriverError::InvalidConfig);
        }
        self.marks = Some(SharedMarks(Arc::new(std::sync::Mutex::new(
            crate::remote_guard::GuardMarks::new(marks),
        ))));
        self.commits = Some(commits);
        Ok(())
    }

    /// The guard authority this driver is, from its signing key `key_id`
    /// in the store, owning `guards`, its committed epochs on the
    /// configured state directory; at the monotonic `now`.
    pub(crate) fn guard_authority(
        &mut self,
        key_id: u32,
        guards: Vec<crate::guard_authority::AuthorityGuard>,
        now: u64,
    ) -> Result<crate::guard_authority::GuardAuthority, DriverError> {
        let file = self
            .view
            .signing(key_id)
            .filter(|file| file.purpose == Purpose::AuthoritySigning)
            .ok_or_else(|| refused(AuthRefusal::AuthorityKey))?;
        let Scope::Authority { authority_id, .. } = file.scope else {
            return Err(refused(AuthRefusal::AuthorityKey));
        };
        if !guards
            .iter()
            .all(|guard| serves(file, authority_id, guard.guard_id))
        {
            return Err(refused(AuthRefusal::AuthorityKey));
        }
        let Material::Secret(seed) = &file.material else {
            return Err(refused(AuthRefusal::AuthorityKey));
        };
        let signer = crate::authority::Ed25519Signer::from_seed(seed);
        let commits = self
            .commits
            .take()
            .ok_or_else(|| refused(AuthRefusal::GuardState))?;
        crate::guard_authority::GuardAuthority::new(
            authority_id,
            key_id,
            signer,
            guards,
            Box::new(crate::remote_guard::GuardMarks::authority(commits)),
            now,
        )
        .map_err(|_| DriverError::InvalidConfig)
    }

    /// The subscription side of `channel` to `stream_id` at admission: the
    /// channel key's newest verifying file, the pairwise signing key of its
    /// receiver and, when it names an authority, that authority's public
    /// key, checked; the authority's control peer budget is reserved.
    pub(crate) fn subscription(
        &mut self,
        channel: &AuthenticatedChannel,
        stream_id: i32,
    ) -> Result<SubscriptionKeys, DriverError> {
        let view = Arc::clone(&self.view);
        if self.store.is_disabled() {
            return Err(refused(AuthRefusal::KeyStoreDisabled));
        }
        let verifying = view
            .verifying(channel.channel_key_id)
            .into_iter()
            .flatten()
            .filter(|file| {
                file.purpose == Purpose::Channel
                    && matches!(file.scope, Scope::Channel { stream_id: stream, .. } if stream == stream_id)
            })
            .max_by_key(|file| file.file_epoch)
            .ok_or_else(|| refused(AuthRefusal::ChannelKey))?;
        let pairwise = view
            .signing(channel.pairwise_key_id)
            .filter(|file| {
                file.purpose == Purpose::Pairwise
                    && matches!(file.scope, Scope::Pairwise { receiver_id, .. } if receiver_id == channel.receiver_id)
            })
            .ok_or_else(|| refused(AuthRefusal::PairwiseKey))?;
        if let Some(authority) = channel.authority {
            let valid = view
                .verifying(authority.key_id)
                .into_iter()
                .flatten()
                .max_by_key(|file| file.file_epoch)
                .is_some_and(|file| {
                    file.purpose == Purpose::AuthorityPublic
                        && serves(file, authority.authority_id, authority.guard_id)
                });
            if !valid {
                return Err(refused(AuthRefusal::AuthorityKey));
            }
            if !crate::agents::roles::answerable(authority.control) {
                return Err(refused(AuthRefusal::Ambiguous));
            }
            self.reserve(authority.control)?;
        }
        Ok(SubscriptionKeys {
            channel: duplicate(verifying),
            pairwise: duplicate(pairwise),
            view,
        })
    }

    /// Reserves the verify budget of the control peer `source`, as the
    /// receiver's bounded peer table will.
    fn reserve(&mut self, source: SocketAddr) -> Result<(), DriverError> {
        if let Some(peer) = self.peers.iter_mut().find(|(held, _)| *held == source) {
            peer.1 = peer.1.saturating_add(1);
            return Ok(());
        }
        if self.peers.len() >= crate::signed_control::PEER_SLOTS {
            return Err(refused(AuthRefusal::ControlBudget));
        }
        self.peers.push((source, 1));
        Ok(())
    }

    /// Releases one reservation of `source`.
    pub(crate) fn release(&mut self, source: SocketAddr) {
        if let Some(index) = self.peers.iter().position(|(held, _)| *held == source) {
            let last = self.peers.get_mut(index).is_some_and(|peer| {
                peer.1 = peer.1.saturating_sub(1);
                peer.1 == 0
            });
            if last {
                self.peers.swap_remove(index);
            }
        }
    }
}

/// Whether the authority key `file` is `authority_id`'s, serves
/// `guard_id` and may abort.
fn serves(file: &KeyFile, authority_id: u64, guard_id: u64) -> bool {
    match &file.scope {
        Scope::Authority {
            authority_id: id,
            guards,
            guard_count,
            abort,
        } => {
            *id == authority_id
                && *abort
                && guard_id != 0
                && guards
                    .get(..*guard_count)
                    .is_some_and(|guards| guards.contains(&guard_id))
        }
        Scope::Channel { .. } | Scope::Pairwise { .. } => false,
    }
}

impl<T: crate::embedded::StreamTerms> crate::embedded::EmbeddedDriver<T> {
    /// Starts the driver's one wire key store at driver start (karyos#648;
    /// design wire-key-files.md sections 2.1 and 2.4): over the key
    /// directory `keys` and the state directory `state`, each a checked
    /// directory (on Linux a `karyos_sys::secure_dir::SecureDir`). From
    /// then on the conductor reloads it every
    /// [`RELOAD_INTERVAL_S`] seconds and re-reads its key set every
    /// [`TICK_S`]; each change reaches both network agents in the same
    /// duty. Authenticated channels are admitted only with a started,
    /// enabled store. Returns the first load's diagnostics.
    ///
    /// # Errors
    ///
    /// [`DriverError::NetworkUnavailable`] without a network,
    /// [`DriverError::KeyStoreStart`] when the store cannot start, and
    /// [`DriverError::InvalidConfig`] when one is started already.
    pub fn start_wire_keys(&mut self, keys: Dir, state: Dir) -> Result<Report, DriverError> {
        self.net
            .as_mut()
            .ok_or(DriverError::NetworkUnavailable)?
            .start_wire_keys(keys, state, None)
    }

    /// [`Self::start_wire_keys`] over the configured key directory
    /// `keys` and state directory `state`, each opened once and checked as
    /// owned by this process's effective user.
    ///
    /// # Errors
    ///
    /// As [`Self::start_wire_keys`]; [`DriverError::KeyStoreStart`] with
    /// [`crate::wire_keys::store::StoreError::Unreadable`] when a
    /// directory is refused.
    #[cfg(target_os = "linux")]
    pub fn start_wire_key_dirs(
        &mut self,
        keys: &std::path::Path,
        state: &std::path::Path,
    ) -> Result<Report, DriverError> {
        use karyos_sys::secure_dir::{SecureDir, effective_uid};

        let unreadable =
            |_| DriverError::KeyStoreStart(crate::wire_keys::store::StoreError::Unreadable);
        let keys = SecureDir::open(keys, effective_uid()).map_err(unreadable)?;
        let state = SecureDir::open(state, effective_uid()).map_err(unreadable)?;
        self.start_wire_keys(Box::new(keys), Box::new(state))
    }

    /// Holds the driver's durable guard state, on the configured state
    /// directory (karyos#648; design guards-and-abort.md): `marks`, the
    /// marks of the guards it follows, and `commits`, the committed epochs
    /// of the guards it is the authority of. A remotely guarded
    /// authenticated publication and [`Self::start_guard_authority`] need
    /// it.
    ///
    /// # Errors
    ///
    /// [`DriverError::AuthenticatedRefused`] with [`AuthRefusal::NoKeyStore`]
    /// before [`Self::start_wire_keys`]; [`DriverError::InvalidConfig`]
    /// when it is held already.
    pub fn start_guard_state(&mut self, marks: Dir, commits: Dir) -> Result<(), DriverError> {
        self.net
            .as_mut()
            .ok_or(DriverError::NetworkUnavailable)?
            .wire_keys_mut()
            .ok_or(refused(AuthRefusal::NoKeyStore))?
            .set_guard_state(marks, commits)
    }

    /// Makes this driver the guard authority of its signing key `key_id`
    /// (karyos#648; design guards-and-abort.md section 4.2): it owns
    /// `guards`, keeps their committed epochs on the durable guard state,
    /// and answers STATUS_CHALLENGEs only on its configured control
    /// endpoints `controls`, which it holds open. Its signer follows the
    /// key view like every other key; a commit or a read of its state that
    /// fails stops its answers, counted
    /// (`ReceiverCounters::authority_commit_failures`).
    ///
    /// # Errors
    ///
    /// [`DriverError::AuthenticatedRefused`]: [`AuthRefusal::NoKeyStore`],
    /// [`AuthRefusal::AuthorityKey`] for no signing key serving every
    /// guard, [`AuthRefusal::GuardState`] without durable guard state (or
    /// once an authority took it); [`DriverError::InvalidConfig`] for a
    /// configuration the authority refuses or no control endpoint;
    /// [`DriverError::NetworkEndpoint`] when one cannot open, and
    /// [`DriverError::NetworkBusy`].
    pub fn start_guard_authority(
        &mut self,
        key_id: u32,
        guards: Vec<crate::guard_authority::AuthorityGuard>,
        controls: &[SocketAddr],
    ) -> Result<(), DriverError> {
        if controls.is_empty() {
            return Err(DriverError::InvalidConfig);
        }
        let net = self.net.as_mut().ok_or(DriverError::NetworkUnavailable)?;
        let now = net.now();
        let wire = net
            .wire_keys_mut()
            .ok_or(refused(AuthRefusal::NoKeyStore))?;
        let authority = wire.guard_authority(key_id, guards, now)?;
        let view = wire.view();
        net.post_guard_authority(authority, controls, view)
    }

    /// What the wire key store did; `None` before it starts.
    #[must_use]
    pub fn wire_key_counters(&self) -> Option<WireKeyCounters> {
        Some(self.net.as_ref()?.wire_keys()?.counters())
    }

    /// The wire key store's last diagnostic events (refused, disabled or
    /// failed keys, each with its `key_id` and `file_epoch` only); empty
    /// before it starts.
    #[must_use]
    pub fn wire_key_events(&self) -> Vec<crate::wire_keys::store::Event> {
        self.net
            .as_ref()
            .and_then(|net| net.wire_keys())
            .map_or_else(Vec::new, |wire| wire.last_report().events.clone())
    }

    /// [`Self::start_wire_keys`] at the wall `clock` in seconds (tests).
    #[cfg(test)]
    pub(crate) fn start_wire_keys_at(
        &mut self,
        keys: Dir,
        state: Dir,
        clock: fn() -> i64,
    ) -> Result<Report, DriverError> {
        self.net
            .as_mut()
            .ok_or(DriverError::NetworkUnavailable)?
            .start_wire_keys(keys, state, Some(clock))
    }
}

#[cfg(test)]
mod tests;
