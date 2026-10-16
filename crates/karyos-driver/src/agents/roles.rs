// SPDX-License-Identifier: Apache-2.0

//! The network work of each agent (`quantstratum-docs:
//! karyos/design/driver-network-agents.md` §3.1, §3.2 and phase 4b-1): the
//! establishment control path. No image is created yet (phase 4b-2).
//!
//! - **Receiver.** For each RX half it holds, the receiver reads up to
//!   `rx_datagrams` datagrams and classifies them.
//!   - SETUP ANNOUNCE is challenged only for a stream this driver
//!     subscribes to on that endpoint (`AddSubscription`,
//!     network-control-schemas.md §6.2 step 2). The challenge goes only to
//!     the announcement's validated source (§7.3), within
//!     `rsp_setup_rate_per_destination` and the per-driver `rsp_setup_rate`
//!     (§7.4); the session table holds each resend to
//!     `challenge_resend_interval`.
//!   - SETUP ANSWER goes to its session table; an accepted one becomes a
//!     [`SessionEvent::CreateImage`] for the conductor, its whole command
//!     chain reserved before the session table commits it (S1). An
//!     announcement above the subscription's `max_image_term_length` is
//!     never challenged.
//!   - RSP_SETUP CHALLENGE and SOLICIT go to the sender ([`ControlItem`],
//!     DN-4), but only for an alias published on that endpoint
//!     (`AddPublishedAlias`): controls for anything else never reach the
//!     ring, so they cannot crowd out the rest.
//!   - SM is dropped and counted: it can only be validated against an
//!     installed binding and its receiver (§6.1), which phase 4b-2 brings.
//!   - DATA waits for phase 5.
//! - **Sender.** It holds the publications it announces
//!   ([`SendSessions`]), their channel destinations and join points. Each
//!   cycle it sends the controls the receiver handed over, answers the
//!   challenges and solicits for its publications toward the channel
//!   destination (never a payload's address), and sends the announcements
//!   due. Its control routes are kept per endpoint in a table allocated at
//!   creation and forgotten when the endpoint is handed back.
//!
//! Every queue and table is allocated when the agents are created; drops
//! are counted, each under its own counter.

use std::net::SocketAddr;
use std::ops::ControlFlow;
use std::sync::Arc;

use karyos_io::backend::{Budget, RxBackend, RxDatagram, RxDrop, RxHandler};
use karyos_io::sockets::ops::SocketOps;
use karyos_protocol::frame::{FRAME_ALIGNMENT, Lane};
use karyos_protocol::network::{
    Alias, Control, Datagram, Identity, LaneStatus, Lanes, MAX_WINDOW, Receiver, SetupAnnounce,
    SetupAnswer, StatusMessage, classify,
};
use karyos_sys::host_clock::age_ns;

use super::chain::{ImageChain, SessionCommand, SessionEnd, SessionEvent};
use super::control::{ControlItem, ControlRoutes, RouteSlot, SmGuard, SmSlot};
use super::ring::{self, Reservation, RingReceiver, RingSender};
use super::{AgentCommand, AgentConfig, AgentError, AgentEvent, AgentKind, EndpointId, Half};
use crate::sessions::OsNonces;
use crate::sessions::rate::{EndpointRates, RateRefused, TotalRate, normalized};
use crate::sessions::receive::{
    AnnounceOutcome, AnswerOutcome, BindingKey, ReadyOutcome as ImageOutcome, ReceiveSessions,
    SessionConfigError, SlotRef,
};
use crate::sessions::send::{SendSessionError, SendSessions};
use karyos_sys::log_buffer::ReceiveOwner;

/// The receiver's counters; checked, sticky on overflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReceiverCounters {
    /// Datagrams read.
    pub datagrams: u64,
    /// Datagrams dropped by the backend.
    pub backend_drops: u64,
    /// Datagrams that did not decode.
    pub decode_errors: u64,
    /// Controls handed to the sender.
    pub forwarded: u64,
    /// RSP_SETUP challenges dropped with the control ring full.
    pub ring_full_rsp_setup: u64,
    /// Received CHALLENGEs dropped with the control ring full.
    pub ring_full_challenge: u64,
    /// Received SOLICITs dropped with the control ring full.
    pub ring_full_solicit: u64,
    /// Challenges not sent: the source is not an answerable unicast
    /// endpoint (network-control-schemas.md §7.3).
    pub unanswerable_source: u64,
    /// Challenges not sent: `rsp_setup_rate_per_destination` (§7.4).
    pub rsp_setup_rate_limited: u64,
    /// Challenges not sent: the destination rate table is full.
    pub rsp_setup_destinations_full: u64,
    /// Challenges not sent: the per-driver `rsp_setup_rate` (§7.4).
    pub rsp_setup_total_limited: u64,
    /// Announcements for a stream not subscribed on the endpoint.
    pub unsubscribed: u64,
    /// Announcements whose term length is above the subscription's
    /// `max_image_term_length`.
    pub term_too_large: u64,
    /// CHALLENGE, SOLICIT and SM for an alias not published on the
    /// endpoint.
    pub not_published: u64,
    /// SMs sent for installed images.
    pub sm_sent: u64,
    /// Periodic SMs skipped: the control ring had no slot for them.
    pub sm_skipped: u64,
    /// Images retired at their liveness timeout.
    pub images_retired: u64,
    /// Installed images not kept (no SM slot, or no binding): retired at
    /// once so their storage is reclaimed.
    pub images_refused: u64,
    /// An image retired without its `RetireImage` unit, or installed without
    /// its binding: a broken invariant, counted.
    pub chain_invariant: u64,
    /// Images asked of the conductor.
    pub create_image: u64,
    /// Later paths bound to installed images (RP-1): no image asked.
    pub paths_bound: u64,
    /// Data and controls this phase does not handle yet.
    pub unhandled: u64,
    /// An increment did not apply.
    pub overflowed: bool,
}

/// The sender's counters; checked, sticky on overflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SenderCounters {
    /// Controls sent.
    pub sent: u64,
    /// Controls not sent (encoding, route, queue or kernel).
    pub send_failures: u64,
    /// Controls for an endpoint whose TX half the sender does not hold.
    pub no_endpoint: u64,
    /// Answers the session table refused (see its counters).
    pub refused: u64,
    /// SMs accepted from a bound receiver.
    pub sm_accepted: u64,
    /// SMs from no receiver this sender answered on that endpoint (source,
    /// alias and receiver boot id), ignored.
    pub sm_unbound: u64,
    /// SMs from a bound receiver whose identity, lane count or receiver id
    /// does not match, ignored.
    pub sm_mismatch: u64,
    /// Answered receivers not recorded: the binding table was full of
    /// confirmed bindings.
    pub bindings_full: u64,
    /// Unconfirmed bindings evicted to make room for a new answer.
    pub bindings_evicted: u64,
    /// Bindings expired: unconfirmed past `setup_challenge_timeout`, or
    /// confirmed with no SM for `image_liveness_timeout`.
    pub bindings_expired: u64,
    /// SMs whose consumption is below one already reported (replayed or
    /// reordered): the higher value is kept.
    pub sm_stale: u64,
    /// An increment did not apply.
    pub overflowed: bool,
}

/// A receiver this sender answered: where its SMs may come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReceiverBinding {
    endpoint: EndpointId,
    alias: Alias,
    /// The challenge's source, normalized.
    source: SocketAddr,
    /// The receiver boot id of the challenge block.
    boot_id: [u64; 2],
    /// The publication incarnation answered.
    identity: Identity,
    /// The receiver id of its first SM since the last answer.
    receiver_id: Option<u64>,
    /// Its highest reported status per lane (consumption and window).
    lanes: Option<Lanes<LaneStatus>>,
    /// When it was last answered.
    answered_at: u64,
    /// When it last sent an accepted SM: `None` while unconfirmed.
    last_sm: Option<u64>,
}

fn bump(value: &mut u64, overflowed: &mut bool) {
    match value.checked_add(1) {
        Some(next) => *value = next,
        None => *overflowed = true,
    }
}

/// The receiver agent's network state.
#[derive(Debug)]
pub struct ReceiverRole {
    sessions: ReceiveSessions,
    nonces: OsNonces,
    to_sender: RingSender<ControlItem>,
    budget: Budget,
    /// Subscribed streams per endpoint, with their largest accepted image
    /// term length.
    subscriptions: Vec<(EndpointId, i32, u32)>,
    /// Aliases published per endpoint.
    published: Vec<(EndpointId, Alias)>,
    max_entries: usize,
    rsp_destinations: EndpointRates,
    rsp_total: TotalRate,
    /// The `RetireImage` unit and geometry of each answered challenge, by
    /// pending slot, until the conductor's reply (S1; at most
    /// `max_images`).
    chains: Vec<Chain>,
    /// Installed images (at most `max_images`, allocated at creation).
    /// DATA admission through them is phase 5c.
    images: Vec<Installed>,
    /// One SM slot flag per image, allocated at creation; an image takes
    /// one only the pool holds.
    sm_slots: Vec<Arc<SmSlot>>,
    sm_interval: u64,
    liveness_timeout: u64,
    counters: ReceiverCounters,
}

/// An answered challenge waiting for the conductor's reply.
#[derive(Debug)]
struct Chain {
    /// The pending slot.
    slot: SlotRef,
    /// Its `RetireImage` unit.
    retire: Reservation,
    lane_count: u8,
    term_length: u32,
}

/// An installed image: its receive owner, binding, SM cadence and
/// liveness.
#[derive(Debug)]
struct Installed {
    /// The installed slot.
    slot: SlotRef,
    owner: Box<ReceiveOwner>,
    /// The `RetireImage` unit reserved at the answer.
    retire: Option<Reservation>,
    key: BindingKey,
    identity: Identity,
    lane_count: u8,
    /// The window each SM grants per lane.
    window: u32,
    /// When the last SM was due; `None` before the first.
    sm_last: Option<u64>,
    /// The control ring slot of its next SM, while none waits (S1: one SM
    /// slot per binding).
    sm_slot: Option<Reservation>,
    /// Whether its previous SM still waits in the ring.
    sm: Arc<SmSlot>,
    /// The last fresh evidence from the binding (DATA and heartbeats, phase
    /// 5c; until then, the install).
    evidence: u64,
}

/// The sender agent's network state.
#[derive(Debug)]
pub struct SenderRole {
    sessions: SendSessions,
    from_receiver: RingReceiver<ControlItem>,
    /// Each publication's channel destination and join points.
    publications: Vec<(EndpointId, Alias, SocketAddr, Lanes<u64>)>,
    /// Control routes, one slot per endpoint the agent can hold.
    routes: Vec<RouteSlot>,
    budget: u32,
    /// The announcements due this cycle (allocated at creation).
    due: Vec<(EndpointId, SetupAnnounce)>,
    /// The receivers answered, at most `receiver_bindings` (allocated at
    /// creation).
    bindings: Vec<ReceiverBinding>,
    max_bindings: usize,
    /// An unconfirmed binding lives this long (`setup_challenge_timeout`).
    unconfirmed_timeout: u64,
    /// A confirmed binding lives this long without an SM
    /// (`image_liveness_timeout`).
    confirmed_timeout: u64,
    counters: SenderCounters,
}

/// Both roles and the control ring between them, sized by `config`.
pub(super) fn roles(config: &AgentConfig) -> Result<(SenderRole, ReceiverRole), AgentError> {
    let capacity = std::num::NonZeroUsize::new(config.control_capacity).ok_or(
        AgentError::InvalidConfig("control_capacity must be at least 1"),
    )?;
    let (to_sender, from_receiver) = ring::ring(capacity);
    let mut boot_id = [0u64; 2];
    karyos_sys::random::fill_u64s(&mut boot_id)
        .map_err(|_| AgentError::InvalidConfig("no random source for receiver_boot_id"))?;
    // An all-zero draw is not a valid boot id; draw once more.
    if boot_id == [0, 0] {
        karyos_sys::random::fill_u64s(&mut boot_id)
            .map_err(|_| AgentError::InvalidConfig("no random source for receiver_boot_id"))?;
    }
    let sessions = ReceiveSessions::new(config.sessions, boot_id)
        .map_err(|SessionConfigError(reason)| AgentError::InvalidConfig(reason))?;
    let send = SendSessions::new(
        config.publications,
        config.setup_interval,
        config.answer_rate,
    )
    .map_err(|_| AgentError::InvalidConfig("invalid sender session configuration"))?;
    let datagrams = config.rx_datagrams;
    let bytes = u64::from(datagrams)
        .checked_mul(u64::from(karyos_io::sockets::endpoint::MAX_DATAGRAM))
        .ok_or(AgentError::InvalidConfig("rx_datagrams too large"))?;
    // One receive call per datagram, plus the one that finds none.
    let ops = datagrams
        .checked_add(1)
        .ok_or(AgentError::InvalidConfig("rx_datagrams too large"))?;
    let rsp_destinations = EndpointRates::new(
        config.rsp_setup_per_destination,
        config.rsp_setup_destinations,
    )
    .ok_or(AgentError::InvalidConfig("rsp_setup rate or table is zero"))?;
    let rsp_total = TotalRate::new(config.rsp_setup_rate, 0)
        .ok_or(AgentError::InvalidConfig("rsp_setup_rate is zero"))?;
    let routes = (0..config.max_endpoints)
        .map(|_| RouteSlot {
            endpoint: None,
            routes: ControlRoutes::new(config.control_routes),
        })
        .collect();
    Ok((
        SenderRole {
            sessions: send,
            from_receiver,
            publications: Vec::with_capacity(config.publications),
            routes,
            budget: u32::try_from(config.control_capacity).unwrap_or(u32::MAX),
            due: Vec::with_capacity(config.publications),
            bindings: Vec::with_capacity(config.receiver_bindings),
            max_bindings: config.receiver_bindings,
            unconfirmed_timeout: config.sessions.setup_challenge_timeout,
            confirmed_timeout: config.image_liveness_timeout,
            counters: SenderCounters::default(),
        },
        ReceiverRole {
            sessions,
            nonces: OsNonces,
            to_sender,
            budget: Budget::new(datagrams, bytes, ops),
            subscriptions: Vec::with_capacity(config.subscriptions),
            published: Vec::with_capacity(config.subscriptions),
            max_entries: config.subscriptions,
            rsp_destinations,
            rsp_total,
            chains: Vec::with_capacity(config.sessions.max_images),
            images: Vec::with_capacity(config.sessions.max_images),
            sm_slots: (0..config.sessions.max_images)
                .map(|_| Arc::new(SmSlot::default()))
                .collect(),
            sm_interval: config.sm_interval,
            liveness_timeout: config.image_liveness_timeout,
            counters: ReceiverCounters::default(),
        },
    ))
}

/// Reserves an image's whole command chain (S1): `CreateImage`, the
/// receiver's `RetireImage` and the conductor's units. `None`, with
/// nothing held, when a ring has no credit.
fn reserve_chain(sessions: &SessionEnd) -> Option<(Reservation, Reservation, ImageChain)> {
    let create = sessions.events.reserve()?;
    let reply = sessions.events.reserve()?;
    let retire = sessions.events.reserve()?;
    let command = sessions.credit.reserve()?;
    let reclaimed = sessions.credit.reserve()?;
    Some((
        create,
        retire,
        ImageChain {
            command,
            reply,
            reclaimed,
        },
    ))
}

/// Whether an RSP_SETUP may answer `source` (network-control-schemas.md
/// §7.3): a unicast address with a nonzero port; never a multicast,
/// broadcast or unspecified address, an IPv4-mapped one included.
fn answerable(source: SocketAddr) -> bool {
    let source = normalized(source);
    let ip = source.ip();
    let broadcast = match ip {
        std::net::IpAddr::V4(v4) => v4.is_broadcast(),
        std::net::IpAddr::V6(_) => false,
    };
    source.port() != 0 && !ip.is_multicast() && !ip.is_unspecified() && !broadcast
}

impl ReceiverRole {
    /// The receiver's commands: `AddSubscription` and `AddPublishedAlias`;
    /// the sender's are refused.
    pub(super) fn command<O: SocketOps>(
        &mut self,
        command: AgentCommand<O>,
    ) -> Option<(Reservation, AgentEvent<O>)> {
        let max = self.max_entries;
        let configured = |accepted| AgentEvent::Configured {
            agent: AgentKind::Receiver,
            accepted,
        };
        match command {
            AgentCommand::AddSubscription {
                reply,
                endpoint,
                stream_id,
                max_term_length,
            } => {
                let held = self
                    .subscriptions
                    .iter()
                    .position(|(held, stream, _)| (*held, *stream) == (endpoint, stream_id));
                let full = self.subscriptions.len() >= max;
                let accepted = match held.and_then(|index| self.subscriptions.get_mut(index)) {
                    // Two subscribers of one stream on one endpoint: the
                    // stricter limit holds for both.
                    Some(entry) => {
                        entry.2 = entry.2.min(max_term_length);
                        true
                    }
                    None if !full => {
                        self.subscriptions
                            .push((endpoint, stream_id, max_term_length));
                        true
                    }
                    None => false,
                };
                Some((reply, configured(accepted)))
            }
            AgentCommand::AddPublishedAlias {
                reply,
                endpoint,
                alias,
            } => {
                let entry = (endpoint, alias);
                let accepted = self.published.contains(&entry)
                    || (self.published.len() < max && {
                        self.published.push(entry);
                        true
                    });
                Some((reply, configured(accepted)))
            }
            AgentCommand::AddPublication {
                reply, publication, ..
            } => Some((
                reply,
                AgentEvent::PublicationRefused {
                    agent: AgentKind::Receiver,
                    endpoint: publication.endpoint,
                    alias: publication.alias,
                },
            )),
            _ => None,
        }
    }

    /// The session table's counters.
    #[must_use]
    pub fn session_counters(&self) -> crate::sessions::receive::SessionCounters {
        self.sessions.counters()
    }

    /// Whether the image installed at `slot` is held.
    #[must_use]
    pub fn has_image(&self, slot: SlotRef) -> bool {
        self.images.iter().any(|image| image.slot == slot)
    }

    /// Serves the conductor's session commands at `now` (S1), before any
    /// other command or datagram; at most one ring's worth per cycle.
    ///
    /// # Errors
    ///
    /// [`AgentError::CountOverflow`].
    pub(super) fn serve_sessions(
        &mut self,
        sessions: &SessionEnd,
        now: u64,
    ) -> Result<u32, AgentError> {
        let mut served = 0u32;
        for _ in 0..sessions.events.capacity() {
            let Ok(Some(command)) = sessions.commands.try_take() else {
                break;
            };
            served = served
                .checked_add(1)
                .ok_or(AgentError::CountOverflow(AgentKind::Receiver))?;
            // An installed image the receiver could not keep: retired right
            // after its `ImageInstalled`, so the conductor reclaims it.
            let mut refused = None;
            let (reply, event) = match command {
                SessionCommand::InstallImage { reply, slot, owner } => {
                    let chain = self.take_chain(slot);
                    let event = match self.sessions.image_ready(slot, now) {
                        ImageOutcome::Installed(installed) => {
                            if let Err(retire) = self.install(installed, owner, chain, now) {
                                refused = Some((installed, retire));
                            }
                            SessionEvent::ImageInstalled { slot, installed }
                        }
                        // Dropping the owner drops the receiver's hold on
                        // the image, and `retire` frees its unit; the
                        // conductor frees the storage.
                        ImageOutcome::Release(_) => SessionEvent::ImageReleased { slot },
                    };
                    (reply, event)
                }
                SessionCommand::RefuseImage { reply, slot } => {
                    self.sessions.image_refused(slot);
                    drop(self.take_chain(slot));
                    (reply, SessionEvent::ImageReleased { slot })
                }
                SessionCommand::StorageReclaimed { slot } => {
                    self.sessions.storage_reclaimed(slot);
                    continue;
                }
            };
            // The conductor gone: the driver is stopping.
            let _ = sessions.events.post(reply, event);
            if let Some((installed, retire)) = refused {
                let _ = self.sessions.retire(installed, now);
                self.count(|c| &mut c.images_refused);
                match retire {
                    Some(unit) => {
                        let _ = sessions
                            .events
                            .post(unit, SessionEvent::RetireImage { slot: installed });
                    }
                    None => self.count(|c| &mut c.chain_invariant),
                }
            }
        }
        Ok(served)
    }

    /// The held chain of the answered challenge at `slot`.
    fn take_chain(&mut self, slot: SlotRef) -> Option<Chain> {
        let index = self.chains.iter().position(|chain| chain.slot == slot)?;
        Some(self.chains.swap_remove(index))
    }

    /// Records the image installed at `installed`: its first SM is due at
    /// once (S1 installation step 3).
    ///
    /// # Errors
    ///
    /// Without its binding, its chain or an SM slot, the image is not kept
    /// (its owner is dropped); the error holds its `RetireImage` unit, if
    /// any, for the caller to retire it.
    fn install(
        &mut self,
        installed: SlotRef,
        owner: Box<ReceiveOwner>,
        chain: Option<Chain>,
        now: u64,
    ) -> Result<(), Option<Reservation>> {
        let Some(chain) = chain else {
            self.count(|c| &mut c.chain_invariant);
            return Err(None);
        };
        let Some((key, identity)) = self.sessions.binding(installed) else {
            self.count(|c| &mut c.chain_invariant);
            return Err(Some(chain.retire));
        };
        // S1: an image whose SM slot cannot be reserved is refused.
        let (Some(sm_slot), Some(sm)) = (
            self.to_sender.reserve(),
            self.sm_slots
                .iter()
                .find(|slot| Arc::strong_count(slot) == 1)
                .cloned(),
        ) else {
            return Err(Some(chain.retire));
        };
        // Half a term per SM: aligned, within the wire's window bound.
        let window = (chain.term_length / 2).min(MAX_WINDOW) & !(FRAME_ALIGNMENT - 1);
        // The table holds a slot for every session, so it has room for
        // every installed image.
        self.images.push(Installed {
            slot: installed,
            owner,
            retire: Some(chain.retire),
            key,
            identity,
            lane_count: chain.lane_count,
            window,
            sm_last: None,
            sm_slot: Some(sm_slot),
            sm,
            evidence: now,
        });
        Ok(())
    }

    /// The installed images' timers at `now`: retirement at the liveness
    /// timeout (S1 retirement), then the SMs due. Returns the work done.
    ///
    /// # Errors
    ///
    /// [`AgentError::CountOverflow`].
    fn image_timers(&mut self, sessions: &SessionEnd, now: u64) -> Result<u32, AgentError> {
        let overflow = AgentError::CountOverflow(AgentKind::Receiver);
        let mut work = 0u32;
        let mut index = 0usize;
        while let Some(image) = self.images.get(index) {
            if age_ns(now, image.evidence) >= self.liveness_timeout {
                let image = self.images.swap_remove(index);
                self.retire(sessions, image, now);
                work = work.checked_add(1).ok_or(overflow.clone())?;
                continue;
            }
            let due = image
                .sm_last
                .is_none_or(|last| age_ns(now, last) >= self.sm_interval);
            if due {
                self.send_sm(index, now);
                work = work.checked_add(1).ok_or(overflow.clone())?;
            }
            index = index.checked_add(1).ok_or(overflow.clone())?;
        }
        Ok(work)
    }

    /// Retires `image` at `now`, in one transition: the binding goes, the
    /// identity is quarantined, the receive owner is dropped, and
    /// `RetireImage` is posted into its reserved unit.
    fn retire(&mut self, sessions: &SessionEnd, image: Installed, now: u64) {
        let Installed {
            slot,
            owner,
            retire,
            ..
        } = image;
        let _ = self.sessions.retire(slot, now);
        drop(owner);
        self.count(|c| &mut c.images_retired);
        match retire {
            // The conductor gone: the driver is stopping.
            Some(unit) => {
                let _ = sessions
                    .events
                    .post(unit, SessionEvent::RetireImage { slot });
            }
            None => self.count(|c| &mut c.chain_invariant),
        }
    }

    /// Sends the SM of the image at `index`: every lane's consumption (its
    /// rebuild position) and window, from the receiver block of this boot.
    fn send_sm(&mut self, index: usize, now: u64) {
        let boot_id = self.sessions.boot_id();
        let Some(image) = self.images.get_mut(index) else {
            return;
        };
        image.sm_last = Some(now);
        let mut entries = [LaneStatus::default(); 4];
        let count = usize::from(image.lane_count);
        for (lane, entry) in entries.iter_mut().take(count).enumerate() {
            let consumption = u8::try_from(lane)
                .ok()
                .and_then(|lane| Lane::try_new(lane).ok())
                .and_then(|lane| image.owner.rebuild_position(lane))
                .unwrap_or(0);
            *entry = LaneStatus {
                consumption,
                window: image.window,
            };
        }
        let Some(lanes) = entries
            .get(..count)
            .and_then(|lanes| Lanes::new(lanes).ok())
        else {
            return;
        };
        // Nonzero: an installed generation is at least 1.
        let receiver_id = (u64::from(image.slot.slot) << 32) | u64::from(image.slot.generation);
        let status = StatusMessage {
            alias: image.key.alias,
            identity: image.identity,
            receiver: Receiver {
                receiver_boot_id: boot_id,
                receiver_id,
            },
            group_tag: 0,
            lanes,
        };
        // One slot per image (S1): a period whose previous SM still waits
        // is skipped, never given a second slot.
        if image.sm.busy() {
            self.count(|c| &mut c.sm_skipped);
            return;
        }
        let slot = image.sm_slot.take().or_else(|| self.to_sender.reserve());
        let Some(slot) = slot else {
            self.count(|c| &mut c.sm_skipped);
            return;
        };
        let item = ControlItem::Outgoing {
            endpoint: image.key.endpoint,
            destination: image.key.source,
            control: Control::Status(status),
            guard: Some(SmGuard::take(&image.sm)),
        };
        // The sender gone: the driver is stopping.
        let _ = self.to_sender.post(slot, item);
        self.count(|c| &mut c.sm_sent);
    }

    /// The counters.
    #[must_use]
    pub fn counters(&self) -> ReceiverCounters {
        self.counters
    }

    fn count(&mut self, field: fn(&mut ReceiverCounters) -> &mut u64) {
        let mut overflowed = self.counters.overflowed;
        bump(field(&mut self.counters), &mut overflowed);
        self.counters.overflowed = overflowed;
    }

    /// One cycle: the session timers, then every held RX half.
    ///
    /// # Errors
    ///
    /// [`AgentError::CountOverflow`].
    pub(super) fn duty<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        sessions: &SessionEnd,
        now: u64,
    ) -> Result<u32, AgentError> {
        let overflow = AgentError::CountOverflow(AgentKind::Receiver);
        let mut work = self.sessions.timers(now);
        work = work
            .checked_add(self.image_timers(sessions, now)?)
            .ok_or(overflow.clone())?;
        for (endpoint, half) in halves.iter_mut() {
            let Half::Rx(rx) = half else {
                continue;
            };
            let budget = self.budget;
            let mut intake = Intake {
                endpoint: *endpoint,
                now,
                role: self,
                sessions,
                work: 0,
            };
            let _ = rx.poll_rx(budget, &mut intake);
            work = work.checked_add(intake.work).ok_or(overflow.clone())?;
        }
        Ok(work)
    }
}

/// The receiver's handler of one endpoint's datagrams.
struct Intake<'a> {
    endpoint: EndpointId,
    now: u64,
    role: &'a mut ReceiverRole,
    sessions: &'a SessionEnd,
    /// Datagrams read; one poll reads at most its budget's.
    work: u32,
}

impl Intake<'_> {
    /// Hands `item` to the sender; a full ring drops it, counted per kind
    /// so that a flood of one kind does not hide another.
    fn forward(&mut self, item: ControlItem) {
        let full: fn(&mut ReceiverCounters) -> &mut u64 = match item {
            ControlItem::Outgoing { .. } => |c| &mut c.ring_full_rsp_setup,
            ControlItem::Incoming {
                control: Control::Solicit(_),
                ..
            } => |c| &mut c.ring_full_solicit,
            ControlItem::Incoming { .. } => |c| &mut c.ring_full_challenge,
        };
        match self.role.to_sender.try_post(item) {
            Ok(()) => self.role.count(|c| &mut c.forwarded),
            Err(_) => self.role.count(full),
        }
    }

    /// Sends `challenge` toward `source` if §7.3 and §7.4 allow it.
    fn challenge(&mut self, source: SocketAddr, control: Control) {
        // §7.3: an RSP_SETUP goes only to the trigger's validated source
        // endpoint, through the socket it arrived on.
        if !answerable(source) {
            self.role.count(|c| &mut c.unanswerable_source);
            return;
        }
        // §7.4: per destination, then per driver.
        match self.role.rsp_destinations.admit(source, self.now) {
            Ok(()) => {}
            Err(RateRefused::Limited) => {
                self.role.count(|c| &mut c.rsp_setup_rate_limited);
                return;
            }
            Err(RateRefused::TableFull) => {
                self.role.count(|c| &mut c.rsp_setup_destinations_full);
                return;
            }
        }
        if !self.role.rsp_total.admit(self.now) {
            self.role.count(|c| &mut c.rsp_setup_total_limited);
            return;
        }
        self.forward(ControlItem::Outgoing {
            endpoint: self.endpoint,
            destination: source,
            control,
            guard: None,
        });
    }

    fn control(&mut self, source: SocketAddr, control: Control) {
        let endpoint = self.endpoint;
        let now = self.now;
        match control {
            Control::SetupAnnounce(announce) => {
                // §6.2 step 2: only a stream subscribed on this endpoint.
                let Some(max_term_length) = self
                    .role
                    .subscriptions
                    .iter()
                    .find(|(held, stream, _)| {
                        (*held, *stream) == (endpoint, announce.alias.stream_id)
                    })
                    .map(|(.., max)| *max)
                else {
                    self.role.count(|c| &mut c.unsubscribed);
                    return;
                };
                // An image larger than the subscription accepts is never
                // challenged, so never allocated (S1 storage budget).
                if announce.term.term_length > max_term_length {
                    self.role.count(|c| &mut c.term_too_large);
                    return;
                }
                let key = BindingKey {
                    endpoint,
                    source,
                    alias: announce.alias,
                };
                let role = &mut *self.role;
                if let AnnounceOutcome::Challenge(challenge) =
                    role.sessions
                        .announce(key, &announce, now, &mut role.nonces)
                {
                    self.challenge(source, Control::Challenge(challenge));
                }
            }
            Control::SetupAnswer(answer) => {
                let key = BindingKey {
                    endpoint,
                    source,
                    alias: answer.alias,
                };
                // S1: the whole chain is reserved before the challenge is
                // marked answered; without it the answer is dropped and the
                // challenge stays pending.
                let mut reserved = None;
                let sessions = self.sessions;
                let outcome = self.role.sessions.answer(key, &answer, now, || {
                    reserved = reserve_chain(sessions);
                    reserved.is_some()
                });
                if let (
                    AnswerOutcome::CreateImage {
                        slot,
                        identity,
                        term,
                        joins,
                    },
                    Some((create, retire, chain)),
                ) = (outcome, reserved)
                {
                    let event = SessionEvent::CreateImage {
                        endpoint,
                        alias: answer.alias,
                        slot,
                        identity,
                        term,
                        joins,
                        chain,
                    };
                    // At most one per session slot, so within `max_images`.
                    self.role.chains.push(Chain {
                        slot,
                        retire,
                        lane_count: joins.count(),
                        term_length: term.term_length,
                    });
                    // The conductor gone: the driver is stopping.
                    let _ = sessions.events.post(create, event);
                    self.role.count(|c| &mut c.create_image);
                }
                if let AnswerOutcome::PathBound { .. } = outcome {
                    self.role.count(|c| &mut c.paths_bound);
                }
            }
            Control::Challenge(_) | Control::Solicit(_) | Control::Status(_) => {
                let alias = match control {
                    Control::Challenge(challenge) => challenge.alias,
                    Control::Solicit(solicit) => solicit.alias,
                    Control::Status(status) => status.alias,
                    _ => return,
                };
                // Only for a publication of this endpoint (DN-4 pre-filter).
                if !self.role.published.contains(&(endpoint, alias)) {
                    self.role.count(|c| &mut c.not_published);
                    return;
                }
                self.forward(ControlItem::Incoming {
                    endpoint,
                    source,
                    control,
                });
            }
            _ => self.role.count(|c| &mut c.unhandled),
        }
    }
}

impl RxHandler for Intake<'_> {
    fn datagram(&mut self, datagram: RxDatagram<'_>) -> ControlFlow<()> {
        // At most the poll budget's datagrams: no overflow.
        self.work += 1;
        self.role.count(|c| &mut c.datagrams);
        let source = datagram.source();
        match classify(datagram.bytes()) {
            Ok(Datagram::Control(control)) => self.control(source, control),
            Ok(Datagram::DataBatch(_) | Datagram::Heartbeat(_)) => {
                self.role.count(|c| &mut c.unhandled);
            }
            Err(_) => self.role.count(|c| &mut c.decode_errors),
        }
        ControlFlow::Continue(())
    }

    fn dropped(&mut self, _drop: RxDrop) {
        self.role.count(|c| &mut c.backend_drops);
    }
}

impl SenderRole {
    /// The counters.
    #[must_use]
    pub fn counters(&self) -> SenderCounters {
        self.counters
    }

    /// The SETUP side's counters.
    #[must_use]
    pub fn session_counters(&self) -> crate::sessions::send::SendCounters {
        self.sessions.counters()
    }

    fn count(&mut self, field: fn(&mut SenderCounters) -> &mut u64) {
        let mut overflowed = self.counters.overflowed;
        bump(field(&mut self.counters), &mut overflowed);
        self.counters.overflowed = overflowed;
    }

    /// The sender's commands: `AddPublication`; the receiver's are
    /// answered `Unsupported`.
    pub(super) fn command<O: SocketOps>(
        &mut self,
        command: AgentCommand<O>,
    ) -> Option<(Reservation, AgentEvent<O>)> {
        let (reply, publication, destination, joins) = match command {
            AgentCommand::AddPublication {
                reply,
                publication,
                destination,
                joins,
            } => (reply, publication, destination, joins),
            AgentCommand::AddSubscription { reply, .. }
            | AgentCommand::AddPublishedAlias { reply, .. } => {
                return Some((
                    reply,
                    AgentEvent::Unsupported {
                        agent: AgentKind::Sender,
                    },
                ));
            }
            _ => return None,
        };
        let event = match self.sessions.add(publication) {
            Ok(()) => {
                self.publications.push((
                    publication.endpoint,
                    publication.alias,
                    destination,
                    joins,
                ));
                AgentEvent::PublicationAdded {
                    endpoint: publication.endpoint,
                    alias: publication.alias,
                }
            }
            Err(
                SendSessionError::Full
                | SendSessionError::DuplicateAlias
                | SendSessionError::InvalidConfig,
            ) => AgentEvent::PublicationRefused {
                agent: AgentKind::Sender,
                endpoint: publication.endpoint,
                alias: publication.alias,
            },
        };
        Some((reply, event))
    }

    /// Frees the route slots of endpoints the agent no longer holds: their
    /// cached ids belong to a half that was handed back.
    fn prune<O: SocketOps>(&mut self, halves: &[(EndpointId, Half<O>)]) {
        for slot in &mut self.routes {
            if let Some(endpoint) = slot.endpoint
                && !halves
                    .iter()
                    .any(|(held, half)| *held == endpoint && matches!(half, Half::Tx(_)))
            {
                slot.endpoint = None;
                slot.routes.clear();
            }
        }
    }

    /// Sends `control` on `endpoint` to `destination`.
    fn send<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        endpoint: EndpointId,
        destination: SocketAddr,
        control: &Control,
    ) {
        let tx = halves.iter_mut().find_map(|(held, half)| match half {
            Half::Tx(tx) if *held == endpoint => Some(tx),
            _ => None,
        });
        let Some(tx) = tx else {
            self.count(|c| &mut c.no_endpoint);
            return;
        };
        let index = self
            .routes
            .iter()
            .position(|slot| slot.endpoint == Some(endpoint))
            .or_else(|| self.routes.iter().position(|slot| slot.endpoint.is_none()));
        let Some(slot) = index.and_then(|index| self.routes.get_mut(index)) else {
            // More held halves than slots: the agent holds at most
            // `max_endpoints`, so this does not happen.
            self.count(|c| &mut c.no_endpoint);
            return;
        };
        slot.endpoint = Some(endpoint);
        match slot.routes.send(tx, destination, control) {
            Ok(()) => self.count(|c| &mut c.sent),
            Err(_) => self.count(|c| &mut c.send_failures),
        }
    }

    /// The publication's channel destination and join points.
    fn route_of(&self, endpoint: EndpointId, alias: Alias) -> Option<(SocketAddr, Lanes<u64>)> {
        self.publications
            .iter()
            .find(|(held, held_alias, ..)| *held == endpoint && *held_alias == alias)
            .map(|(_, _, destination, joins)| (*destination, *joins))
    }

    /// One cycle: the controls the receiver handed over, then the
    /// announcements due.
    ///
    /// # Errors
    ///
    /// [`AgentError::CountOverflow`].
    pub(super) fn duty<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        now: u64,
    ) -> Result<u32, AgentError> {
        let overflow = AgentError::CountOverflow(AgentKind::Sender);
        self.prune(halves);
        let mut work = 0u32;
        for _ in 0..self.budget {
            let Ok(Some(item)) = self.from_receiver.try_take() else {
                break;
            };
            work = work.checked_add(1).ok_or(overflow.clone())?;
            match item {
                // §7.3: an RSP_SETUP to the trigger's validated source,
                // checked by the receiver.
                // An SM's guard drops after the send, freeing its slot.
                ControlItem::Outgoing {
                    endpoint,
                    destination,
                    control,
                    guard,
                } => {
                    self.send(halves, endpoint, destination, &control);
                    drop(guard);
                }
                ControlItem::Incoming {
                    endpoint,
                    source,
                    control: Control::Status(status),
                } => self.status(endpoint, source, &status, now),
                ControlItem::Incoming {
                    endpoint,
                    source,
                    control,
                } => {
                    if let Some((destination, answer)) =
                        self.answer_for(endpoint, source, now, control)
                    {
                        self.send(halves, endpoint, destination, &answer);
                    }
                }
            }
        }
        let mut due = std::mem::take(&mut self.due);
        self.sessions
            .announce_due(now, |endpoint, announce| due.push((endpoint, announce)));
        for (endpoint, announce) in due.drain(..) {
            // An ANNOUNCE goes to the channel's configured destination
            // (§6.2).
            if let Some((destination, _)) = self.route_of(endpoint, announce.alias) {
                work = work.checked_add(1).ok_or(overflow.clone())?;
                self.send(
                    halves,
                    endpoint,
                    destination,
                    &Control::SetupAnnounce(announce),
                );
            }
        }
        // Its capacity stays for the next cycle.
        self.due = due;
        Ok(work)
    }

    /// Records the receiver `answer` goes to: its challenge's `source` on
    /// `endpoint` and its boot id, where its SMs must come from.
    ///
    /// A new answer to a known tuple starts it over: unconfirmed, with no
    /// receiver id or status, so a reinstalled image binds again. A full
    /// table evicts its oldest unconfirmed binding first; one full of
    /// confirmed bindings refuses and counts.
    fn bind(&mut self, endpoint: EndpointId, source: SocketAddr, answer: &SetupAnswer, now: u64) {
        self.expire_bindings(now);
        let binding = ReceiverBinding {
            endpoint,
            alias: answer.alias,
            source: normalized(source),
            boot_id: answer.challenge.receiver_boot_id,
            identity: answer.identity,
            receiver_id: None,
            lanes: None,
            answered_at: now,
            last_sm: None,
        };
        let tuple = |held: &ReceiverBinding| {
            (
                held.endpoint,
                held.alias,
                held.source,
                held.boot_id,
                held.identity,
            )
        };
        if let Some(held) = self
            .bindings
            .iter_mut()
            .find(|held| tuple(held) == tuple(&binding))
        {
            *held = binding;
            return;
        }
        if self.bindings.len() >= self.max_bindings {
            let oldest = self
                .bindings
                .iter()
                .enumerate()
                .filter(|(_, held)| held.last_sm.is_none())
                .min_by_key(|(_, held)| held.answered_at)
                .map(|(index, _)| index);
            let Some(index) = oldest else {
                self.count(|c| &mut c.bindings_full);
                return;
            };
            let _ = self.bindings.swap_remove(index);
            self.count(|c| &mut c.bindings_evicted);
        }
        self.bindings.push(binding);
    }

    /// Removes the bindings past their lifetime at `now`: an unconfirmed
    /// one after `setup_challenge_timeout`, a confirmed one with no SM for
    /// `image_liveness_timeout` (its image is retired by then).
    fn expire_bindings(&mut self, now: u64) {
        let (unconfirmed, confirmed) = (self.unconfirmed_timeout, self.confirmed_timeout);
        let before = self.bindings.len();
        self.bindings.retain(|binding| match binding.last_sm {
            None => age_ns(now, binding.answered_at) < unconfirmed,
            Some(last) => age_ns(now, last) < confirmed,
        });
        // `retain` only removes: no underflow.
        if let Some(expired) = before.checked_sub(self.bindings.len()) {
            for _ in 0..expired {
                self.count(|c| &mut c.bindings_expired);
            }
        }
    }

    /// An SM from `source` on `endpoint` (network-control-schemas.md §6.1):
    /// accepted only from a receiver this sender answered there, with the
    /// answered identity, the publication's lane count and, after the first,
    /// the same receiver id. The first accepted SM establishes the
    /// publication: its SETUP stops.
    fn status(
        &mut self,
        endpoint: EndpointId,
        source: SocketAddr,
        status: &StatusMessage,
        now: u64,
    ) {
        self.expire_bindings(now);
        let source = normalized(source);
        let lane_count = self
            .publications
            .iter()
            .find(|(held, alias, ..)| *held == endpoint && *alias == status.alias)
            .map(|(.., joins)| joins.count());
        let found = self.bindings.iter_mut().find(|binding| {
            binding.endpoint == endpoint
                && binding.alias == status.alias
                && binding.source == source
                && binding.boot_id == status.receiver.receiver_boot_id
        });
        let Some(binding) = found else {
            self.count(|c| &mut c.sm_unbound);
            return;
        };
        let matches = binding.identity == status.identity
            && lane_count == Some(status.lanes.count())
            && binding
                .receiver_id
                .is_none_or(|id| id == status.receiver.receiver_id);
        if !matches {
            self.count(|c| &mut c.sm_mismatch);
            return;
        }
        binding.receiver_id = Some(status.receiver.receiver_id);
        binding.last_sm = Some(now);
        // Consumption only moves forward: a replayed or reordered SM keeps
        // the higher value per lane, and is counted.
        let mut stale = false;
        let lanes = match binding.lanes {
            None => status.lanes,
            Some(held) => {
                let mut kept = [LaneStatus::default(); 4];
                for ((slot, old), new) in kept
                    .iter_mut()
                    .zip(held.as_slice())
                    .zip(status.lanes.as_slice())
                {
                    if new.consumption < old.consumption {
                        stale = true;
                        *slot = *old;
                    } else {
                        *slot = *new;
                    }
                }
                kept.get(..held.as_slice().len())
                    .and_then(|kept| Lanes::new(kept).ok())
                    .unwrap_or(held)
            }
        };
        binding.lanes = Some(lanes);
        let _ = self.sessions.status(endpoint, status);
        self.count(|c| &mut c.sm_accepted);
        if stale {
            self.count(|c| &mut c.sm_stale);
        }
    }

    /// The SETUP ANSWER to a received control, and where it goes: §7.3 and
    /// §6.2/§6.3, an ANSWER follows the channel's configured route (the
    /// unicast endpoint, or the group on multicast), never the trigger's
    /// source, so a spoofed CHALLENGE or SOLICIT cannot steer it.
    fn answer_for(
        &mut self,
        endpoint: EndpointId,
        source: SocketAddr,
        now: u64,
        control: Control,
    ) -> Option<(SocketAddr, Control)> {
        let alias = match control {
            Control::Challenge(challenge) => challenge.alias,
            Control::Solicit(solicit) => solicit.alias,
            _ => return None,
        };
        let Some((destination, joins)) = self.route_of(endpoint, alias) else {
            self.count(|c| &mut c.refused);
            return None;
        };
        let answer = match control {
            Control::Challenge(challenge) => {
                self.sessions
                    .challenge(endpoint, source, now, &challenge, |_| joins)
            }
            Control::Solicit(solicit) => {
                self.sessions
                    .solicit(endpoint, source, now, &solicit, |_| joins)
            }
            _ => return None,
        };
        match answer {
            Ok(answer) => {
                self.bind(endpoint, source, &answer, now);
                Some((destination, Control::SetupAnswer(answer)))
            }
            Err(_) => {
                self.count(|c| &mut c.refused);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests;
