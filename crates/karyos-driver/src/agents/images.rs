// SPDX-License-Identifier: Apache-2.0

//! The conductor's image table (`quantstratum-docs:
//! karyos/design/network-sessions.md` S1 "installation", SN-2; phase
//! 4b-2): it serves the receiver's `CreateImage` from the session ring
//! ([`super::chain`]), charges the storage budget, allocates one image log
//! buffer per lane with the answer's join points, and hands the image's
//! receive owner to the receiver (`InstallImage`, the S1 `ImageReady`). The
//! receiver installs it if its challenge still allows (`ImageInstalled`) or
//! releases it (`ImageReleased`), and the conductor then frees the storage.
//!
//! - **Size (S1 step 2).** The receiver challenges only an announcement
//!   whose term length is within its subscription's
//!   `max_image_term_length` ([`DEFAULT_MAX_IMAGE_TERM_LENGTH`] unless the
//!   channel sets one). The conductor then charges the image's term bytes,
//!   `term_length * (3 + spare_slots) * lanes` (checked), against the
//!   driver's `image_storage_budget` ([`DEFAULT_IMAGE_STORAGE_BUDGET`])
//!   before it allocates anything; an image over the budget, a full table
//!   or a geometry the log buffer refuses is answered `RefuseImage` (S1
//!   `ImageRefused`) and counted, and the receiver removes the challenge.
//!   The charge is released when the image's storage is freed.
//! - **Credit.** Every command of the chain posts into a unit the receiver
//!   reserved at the answer, so no post waits for room.
//! - **Attachment.** Local subscribers may attach to an image only once the
//!   receiver reported it installed ([`ImageTable::installed`]), and never
//!   once it reported it retired.
//! - **Retirement (S1).** On `RetireImage` the image is retiring: no new
//!   attachment. Once nothing but the table holds its lanes (every
//!   subscriber detached and the receiver dropped its owner), the table
//!   frees the storage, releases the charge and posts `StorageReclaimed`
//!   into the unit reserved at the answer.
//! - **Shutdown.** On a stop the conductor drops the table with the agents.
//!   An image whose `InstallImage` was posted but not answered shares its
//!   lanes between the table and the unread command; both are freed when
//!   dropped, and nothing outlives them.
//!
//! - **Lanes (network-shared-terms N-2).** The table builds each lane
//!   from its [`LaneSource`], on the driver thread inside the existing
//!   round trip: on the heap for an embedded driver, and in a new shared
//!   region of the driver's admission, at generation 0, for an IPC
//!   driver. Region ids are never reused, so a remote mapping of an old
//!   image never names a new one. A lane that cannot be created refuses
//!   the image (`refused_storage`) after the lanes already created for it
//!   are dropped; no partial image is ever offered. At the network's close
//!   no lane is built: an image still asked for is refused
//!   (`LaneSource::closing`). An installed image is exposed on either
//!   backing (n3); an IPC driver's remote clients fetch its regions.

use std::sync::Arc;

use karyos_protocol::frame::Lane;
use karyos_protocol::network::{Alias, Identity, Lanes, TermParams};
use karyos_sys::log_buffer::{
    DEFAULT_CLAIM_DEADLINE, LogBuffer, LogBufferConfig, PublicationMode, ReceiveOwner,
};
use karyos_sys::receive::ImageParams;
use karyos_sys::sizing::TermLength;
use karyos_sys::term::TermId;
use karyos_sys::term_bytes::HeapTerms;

use super::EndpointId;
use super::chain::{ImageChain, SessionCommand, SessionEvent, SessionLink};
use super::ring::Reservation;
use crate::embedded::{StreamTerms, sealed};
use crate::sessions::receive::SlotRef;

/// The driver default of a subscription's `max_image_term_length`: 64 MiB.
pub const DEFAULT_MAX_IMAGE_TERM_LENGTH: u32 = 64 << 20;

/// The default `image_storage_budget` of a driver: 2 GiB of image terms.
pub const DEFAULT_IMAGE_STORAGE_BUDGET: u64 = 2 << 30;

/// Rotation slots of every log buffer, before its spares.
const ROTATION_SLOTS: u64 = 3;

/// The image log buffer parameters the answer does not carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageTemplate {
    /// Spare slots beyond the three rotation slots (default 5). They are
    /// also each lane's admission credits (SPEC.md §4: the reservations
    /// never exceed `spare_slots - CLEANING_HEADROOM`): the receive owner
    /// holds three, and every optional or observer reader takes one, so
    /// the default admits one such reader per lane, in process or remote.
    /// Each further spare admits one more and adds a term per lane to the
    /// image's storage charge.
    pub spare_slots: u8,
    /// Local subscribers per image (default 8): subscriber cells, of which
    /// optional and observer readers are bounded by `spare_slots` as
    /// well. Required readers take no credit.
    pub max_subscribers: u8,
    /// Whether the receive owner may seal local gaps (default true:
    /// gaps-and-unreliable-delivery.md).
    pub local_gaps: bool,
    /// Term bytes of every image together (`image_storage_budget`).
    pub storage_budget: u64,
    /// How long a required awaiting cell holds an image at its join for
    /// its subscription's attach (ADR-0100, `image_join_deadline`), in ns;
    /// default 10 s, the image liveness timeout.
    pub image_join_deadline: u64,
}

impl Default for ImageTemplate {
    fn default() -> Self {
        Self {
            spare_slots: 5,
            max_subscribers: 8,
            local_gaps: true,
            storage_budget: DEFAULT_IMAGE_STORAGE_BUDGET,
            image_join_deadline: 10_000_000_000,
        }
    }
}

/// What [`ImageTable::handle`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageEvent {
    /// The receiver installed the image: subscribers may attach.
    Installed {
        /// The installed session slot.
        slot: SlotRef,
        /// The endpoint it arrived on.
        endpoint: EndpointId,
        /// The datagram source its binding names (per-source-images.md,
        /// D2-1).
        source: std::net::SocketAddr,
        /// The publication incarnation.
        identity: Identity,
        /// The alias it arrived under.
        alias: Alias,
    },
    /// The image was not installed; its storage is freed.
    Released {
        /// The pending slot.
        slot: SlotRef,
    },
    /// The image was refused (budget, table or geometry); the receiver
    /// removed the challenge.
    Refused {
        /// The pending slot.
        slot: SlotRef,
    },
    /// The receiver retired the image: no new attachment.
    Retiring {
        /// The installed slot.
        slot: SlotRef,
        /// Whether it ended cleanly at its lanes' EOS bounds
        /// ([`SessionEvent::RetireImage`]).
        complete: bool,
    },
    /// A retired image's storage was freed and `StorageReclaimed` posted.
    Reclaimed {
        /// The installed slot.
        slot: SlotRef,
    },
}

/// The table's counters; checked, sticky on overflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ImageCounters {
    /// Images allocated and offered.
    pub offered: u64,
    /// Images the receiver installed.
    pub installed: u64,
    /// Images the receiver released.
    pub released: u64,
    /// Images the receiver retired.
    pub retired: u64,
    /// Retired images whose storage was reclaimed.
    pub reclaimed: u64,
    /// Refused: the storage budget would be exceeded.
    pub refused_budget: u64,
    /// Refused: the table is full.
    pub refused_full: u64,
    /// Refused: the log buffer refused the geometry.
    pub refused_geometry: u64,
    /// Refused: a lane's storage could not be created (a shared region:
    /// `ENOMEM`, `EMFILE` or region ids exhausted).
    pub refused_storage: u64,
    /// Replies for no image, or for an image in another state; ignored.
    pub stale_replies: u64,
    /// Awaiting cells not registered when an image was built (ADR-0100):
    /// no free cell or spare credit, or export ids exhausted.
    pub start_cells_refused: u64,
    /// An increment did not apply.
    pub overflowed: bool,
}

impl ImageCounters {
    fn bump(&mut self, field: fn(&mut Self) -> &mut u64) {
        let value = field(self);
        match value.checked_add(1) {
            Some(next) => *value = next,
            None => self.overflowed = true,
        }
    }
}

/// One image's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// `InstallImage` posted.
    Offered,
    /// Installed under this slot.
    Installed(SlotRef),
    /// Retired under this installed slot: storage freed once no loan holds
    /// it.
    Retiring(SlotRef),
    /// `RefuseImage` posted.
    Refused,
}

/// A local network subscription that awaits the images of its key
/// (ADR-0100): the driver lends these to the table for a duty cycle, and
/// the table registers one awaiting cell per entry and lane when it builds
/// an image of the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AwaitingEntry {
    /// The subscription's receive endpoint.
    pub(crate) endpoint: EndpointId,
    /// Its stream id.
    pub(crate) stream_id: i32,
    /// The subscription's registration (the attach's `parent`).
    pub(crate) parent: u64,
    /// Its client.
    pub(crate) client: u64,
    /// Its role.
    pub(crate) role: karyos_sys::log_buffer::Role,
}

/// An awaiting cell the table registered on one lane of an image, for the
/// driver to place on that lane's stream at `Installed`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AwaitingLane {
    /// The lane index.
    pub(crate) lane: usize,
    /// The subscription it awaits.
    pub(crate) entry: AwaitingEntry,
    /// The registered cell.
    pub(crate) cell: karyos_sys::log_buffer::AwaitingCell,
}

struct Image<T: StreamTerms> {
    /// The pending slot, at its challenge generation.
    slot: SlotRef,
    endpoint: EndpointId,
    /// The datagram source its binding names.
    source: std::net::SocketAddr,
    identity: Identity,
    alias: Alias,
    lanes: Vec<Arc<LogBuffer<T>>>,
    /// Term bytes charged to the budget.
    charge: u64,
    /// The `StorageReclaimed` unit, posted once a retired image's storage
    /// is reclaimed.
    reclaimed: Reservation,
    state: State,
    /// The conflated lane and the link its view shares with the receiver's
    /// seal gate (conflated-network-images.md (b)), once installed.
    freshness: Option<(Lane, karyos_sys::freshness::FreshnessLink)>,
    /// The awaiting cells registered at the build (ADR-0100), until the
    /// driver takes them at `Installed`.
    awaiting: Vec<AwaitingLane>,
}

/// The conductor's image table.
pub struct ImageTable<T: StreamTerms = HeapTerms> {
    images: Vec<Image<T>>,
    max: usize,
    template: ImageTemplate,
    /// Term bytes charged.
    charged: u64,
    counters: ImageCounters,
    /// Retired images' CnC cells (M2b), for the conductor to free.
    released: Vec<karyos_sys::counters::Counter>,
    /// Calls of `allocate` (tests: no refusal allocates).
    #[cfg(test)]
    allocations: usize,
    /// Tests: the lane index whose creation fails, as a region that cannot
    /// be created would.
    #[cfg(test)]
    pub(crate) fail_lane: Option<usize>,
    /// Tests: the lanes the last allocation created, to show that a
    /// refusal drops them.
    #[cfg(test)]
    pub(crate) last_lanes: Vec<std::sync::Weak<LogBuffer<T>>>,
}

/// Where an image's lanes are created: on the heap, or in new regions of
/// the driver's admission (`network-shared-terms` N-2). The driver lends
/// it to the table for one duty cycle, on its own thread.
#[derive(Debug)]
pub struct LaneSource<'a> {
    /// The instance and region ids of an IPC driver; `None` on the heap.
    #[cfg(target_os = "linux")]
    regions: Option<crate::admission::RegionIds<'a>>,
    /// The network is closing: no lane is built, so an image still asked
    /// for is refused with no region or memory spent on it.
    closing: bool,
    /// The awaiting subscriptions and the driver's export counter, lent
    /// with the lanes (ADR-0100); `None` registers no awaiting cell.
    awaiting: Option<(&'a [AwaitingEntry], &'a mut u64)>,
    _lent: core::marker::PhantomData<&'a mut ()>,
}

impl<'a> LaneSource<'a> {
    /// Heap lanes: no region.
    #[must_use]
    pub(crate) fn heap() -> Self {
        Self {
            #[cfg(target_os = "linux")]
            regions: None,
            closing: false,
            awaiting: None,
            _lent: core::marker::PhantomData,
        }
    }

    /// The same source, also lending the awaiting subscriptions and the
    /// export counter their cells take ids from (ADR-0100).
    #[must_use]
    pub(crate) fn with_awaiting(
        mut self,
        entries: &'a [AwaitingEntry],
        exports: &'a mut u64,
    ) -> Self {
        self.awaiting = Some((entries, exports));
        self
    }

    /// No lanes at all: the network is closing, and every image still asked
    /// for is refused (`refused_storage`).
    #[must_use]
    pub(crate) fn closing() -> Self {
        Self {
            closing: true,
            ..Self::heap()
        }
    }

    /// Lanes in new regions with ids from `regions`.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub(crate) fn regions(regions: crate::admission::RegionIds<'a>) -> Self {
        Self {
            regions: Some(regions),
            closing: false,
            awaiting: None,
            _lent: core::marker::PhantomData,
        }
    }

    /// The instance and a fresh region id; `None` without regions.
    #[cfg(target_os = "linux")]
    pub(crate) fn next_region(&mut self) -> Option<Result<(u128, u64), crate::error::DriverError>> {
        self.regions.as_mut().map(crate::admission::RegionIds::next)
    }
}

impl<T: StreamTerms> std::fmt::Debug for ImageTable<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImageTable")
            .field("images", &self.images.len())
            .field("max", &self.max)
            .field("charged", &self.charged)
            .finish_non_exhaustive()
    }
}

/// An image's lanes and the receive owner over them.
type Built<T> = (Vec<Arc<LogBuffer<T>>>, ReceiveOwner<T>);

/// Why an image was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    Budget,
    Full,
    Geometry,
    Storage,
}

impl<T: StreamTerms> ImageTable<T> {
    /// A table of at most `max` images (the receiver's `max_images`).
    #[must_use]
    pub fn new(max: usize, template: ImageTemplate) -> Self {
        Self {
            images: Vec::with_capacity(max),
            max,
            template,
            charged: 0,
            counters: ImageCounters::default(),
            released: Vec::new(),
            #[cfg(test)]
            allocations: 0,
            #[cfg(test)]
            fail_lane: None,
            #[cfg(test)]
            last_lanes: Vec::new(),
        }
    }

    /// Hands retired images' cells back, for the conductor to free (M2b).
    pub(crate) fn take_released(
        &mut self,
    ) -> impl Iterator<Item = karyos_sys::counters::Counter> + '_ {
        self.released.drain(..)
    }

    /// The images held, installed or not, refusals awaiting their reply
    /// included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.images.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.images.is_empty()
    }

    /// Term bytes charged to the storage budget.
    #[must_use]
    pub fn charged(&self) -> u64 {
        self.charged
    }

    /// The counters.
    #[must_use]
    pub fn counters(&self) -> ImageCounters {
        self.counters
    }

    /// The lanes of the image installed at `slot`, for subscribers to
    /// attach; `None` until the receiver reported it installed.
    #[must_use]
    pub fn installed(&self, slot: SlotRef) -> Option<&[Arc<LogBuffer<T>>]> {
        self.images.iter().find_map(|image| match image.state {
            State::Installed(installed) if installed == slot => Some(image.lanes.as_slice()),
            _ => None,
        })
    }

    /// The conflated lane of the image installed at `slot` and the link
    /// its view shares with the receiver's seal gate; `None` without a
    /// conflated view.
    #[must_use]
    pub fn freshness(
        &self,
        slot: SlotRef,
    ) -> Option<(Lane, &karyos_sys::freshness::FreshnessLink)> {
        self.images
            .iter()
            .find_map(|image| match (&image.state, &image.freshness) {
                (State::Installed(installed), Some((lane, link))) if *installed == slot => {
                    Some((*lane, link))
                }
                _ => None,
            })
    }

    /// Moves the view link of the installed image `slot` to `link`, a
    /// recreated view's (karyos#658). `false` without an installed image
    /// with a conflated view.
    pub fn relink(&mut self, slot: SlotRef, link: karyos_sys::freshness::FreshnessLink) -> bool {
        self.images
            .iter_mut()
            .find_map(|image| match (&image.state, &mut image.freshness) {
                (State::Installed(installed), Some((_, held))) if *installed == slot => {
                    *held = link.clone();
                    Some(())
                }
                _ => None,
            })
            .is_some()
    }

    /// Serves every session event the receiver posted, building lanes from
    /// `lanes`, then reclaims the retired images no loan holds any more,
    /// reporting image events to `on_event`; returns how many events it
    /// served.
    pub fn poll(
        &mut self,
        link: &SessionLink<T>,
        lanes: &mut LaneSource<'_>,
        mut on_event: impl FnMut(ImageEvent),
    ) -> u32 {
        let mut served = 0u32;
        while let Some(event) = link.take_event() {
            self.handle(link, lanes, event, &mut on_event);
            match served.checked_add(1) {
                Some(next) => served = next,
                None => break,
            }
        }
        self.reclaim(link, &mut on_event);
        served
    }

    /// Frees every retiring image whose lanes only the table holds, and
    /// posts its `StorageReclaimed`.
    fn reclaim(&mut self, link: &SessionLink<T>, on_event: &mut impl FnMut(ImageEvent)) {
        let mut index = 0usize;
        while let Some(image) = self.images.get(index) {
            let State::Retiring(slot) = image.state else {
                match index.checked_add(1) {
                    Some(next) => index = next,
                    None => return,
                }
                continue;
            };
            let held = image.lanes.iter().any(|lane| Arc::strong_count(lane) > 1);
            if held {
                match index.checked_add(1) {
                    Some(next) => index = next,
                    None => return,
                }
                continue;
            }
            let image = self.images.swap_remove(index);
            match self.charged.checked_sub(image.charge) {
                Some(charged) => self.charged = charged,
                None => self.counters.overflowed = true,
            }
            self.counters.bump(|c| &mut c.reclaimed);
            // The receiver gone: the driver is stopping.
            let _ = link.post(image.reclaimed, SessionCommand::StorageReclaimed { slot });
            on_event(ImageEvent::Reclaimed { slot });
        }
    }

    /// Serves one session event, building lanes from `lanes`.
    pub fn handle(
        &mut self,
        link: &SessionLink<T>,
        lanes: &mut LaneSource<'_>,
        event: SessionEvent,
        mut on_event: impl FnMut(ImageEvent),
    ) {
        match event {
            SessionEvent::CreateImage {
                endpoint,
                source,
                alias,
                slot,
                identity,
                term,
                joins,
                chain,
            } => {
                if let Some(event) = self.create(
                    link,
                    lanes,
                    (endpoint, source),
                    alias,
                    slot,
                    identity,
                    term,
                    &joins,
                    chain,
                ) {
                    on_event(event);
                }
            }
            SessionEvent::ImageInstalled {
                slot,
                installed,
                freshness,
            } => match self.images.iter_mut().find(|image| image.slot == slot) {
                Some(image) if image.state == State::Offered => {
                    image.state = State::Installed(installed);
                    image.freshness = freshness;
                    self.counters.bump(|c| &mut c.installed);
                    on_event(ImageEvent::Installed {
                        slot: installed,
                        endpoint: image.endpoint,
                        source: image.source,
                        identity: image.identity,
                        alias: image.alias,
                    });
                }
                _ => self.counters.bump(|c| &mut c.stale_replies),
            },
            SessionEvent::RetireImage {
                slot,
                complete,
                cells,
            } => {
                if let Some(mut cells) = cells {
                    self.released.extend(cells.take());
                }
                let found = self
                    .images
                    .iter_mut()
                    .find(|image| image.state == State::Installed(slot));
                match found {
                    Some(image) => {
                        image.state = State::Retiring(slot);
                        self.counters.bump(|c| &mut c.retired);
                        on_event(ImageEvent::Retiring { slot, complete });
                    }
                    None => self.counters.bump(|c| &mut c.stale_replies),
                }
            }
            SessionEvent::ImageReleased { slot } => {
                let found = self.images.iter().position(|image| {
                    image.slot == slot && matches!(image.state, State::Offered | State::Refused)
                });
                let Some(index) = found else {
                    self.counters.bump(|c| &mut c.stale_replies);
                    return;
                };
                let image = self.images.swap_remove(index);
                // Charged by `create`, so never below it.
                match self.charged.checked_sub(image.charge) {
                    Some(charged) => self.charged = charged,
                    None => self.counters.overflowed = true,
                }
                on_event(match image.state {
                    State::Refused => ImageEvent::Refused { slot },
                    State::Offered | State::Installed(_) | State::Retiring(_) => {
                        self.counters.bump(|c| &mut c.released);
                        ImageEvent::Released { slot }
                    }
                });
            }
        }
    }

    /// Serves `CreateImage`: capacity, budget, then allocation, each
    /// refusal answered `RefuseImage` before anything is allocated.
    /// Returns an event only for a refusal that keeps no entry.
    #[allow(clippy::too_many_arguments, reason = "the fields of one CreateImage")]
    fn create(
        &mut self,
        link: &SessionLink<T>,
        lanes_source: &mut LaneSource<'_>,
        (endpoint, source): (EndpointId, std::net::SocketAddr),
        alias: Alias,
        slot: SlotRef,
        identity: Identity,
        term: TermParams,
        joins: &Lanes<u64>,
        chain: ImageChain,
    ) -> Option<ImageEvent> {
        let ImageChain {
            command,
            reply,
            reclaimed,
        } = chain;
        let refuse = |table: &mut Self, refusal: Refusal, command, reply| {
            table.counters.bump(match refusal {
                Refusal::Budget => |c| &mut c.refused_budget,
                Refusal::Full => |c| &mut c.refused_full,
                Refusal::Geometry => |c| &mut c.refused_geometry,
                Refusal::Storage => |c| &mut c.refused_storage,
            });
            // The receiver gone: the driver is stopping.
            let _ = link.post(command, SessionCommand::RefuseImage { reply, slot });
        };
        // Capacity first: a full table allocates nothing. It has no entry
        // to wait for the reply, which is then counted stale.
        if self.images.len() >= self.max {
            refuse(self, Refusal::Full, command, reply);
            return Some(ImageEvent::Refused { slot });
        }
        let image = |state, lanes, charge, reclaimed| Image {
            slot,
            endpoint,
            source,
            identity,
            alias,
            lanes,
            charge,
            reclaimed,
            state,
            freshness: None,
            awaiting: Vec::new(),
        };
        // Then the budget, before any allocation.
        let Some((charge, total)) = self.charge(term, joins).and_then(|charge| {
            self.charged
                .checked_add(charge)
                .filter(|total| *total <= self.template.storage_budget)
                .map(|total| (charge, total))
        }) else {
            refuse(self, Refusal::Budget, command, reply);
            self.images
                .push(image(State::Refused, Vec::new(), 0, reclaimed));
            return None;
        };
        #[cfg(test)]
        if let Some(allocations) = self.allocations.checked_add(1) {
            self.allocations = allocations;
        }
        // A refusal drops every lane already built, its regions included,
        // before the answer.
        let (lanes, owner) = match self.allocate(lanes_source, alias, term, joins) {
            Ok(built) => built,
            Err(refusal) => {
                refuse(self, refusal, command, reply);
                self.images
                    .push(image(State::Refused, Vec::new(), 0, reclaimed));
                return None;
            }
        };
        self.charged = total;
        self.counters.bump(|c| &mut c.offered);
        // The awaiting cells, before the lanes reach the receiver, so its
        // first consumption sample and every frame already see them
        // (ADR-0100). A cell that cannot be registered is counted, and its
        // subscription's attach joins at the head with a loss record.
        let awaiting = self.register_awaiting(lanes_source, endpoint, alias, &lanes);
        let mut built = image(State::Offered, lanes, charge, reclaimed);
        built.awaiting = awaiting;
        self.images.push(built);
        let _ = link.post(
            command,
            SessionCommand::InstallImage {
                reply,
                slot,
                owner: Box::new(owner),
            },
        );
        None
    }

    /// Registers one awaiting cell per lane of a new image for each lent
    /// subscription of its key (ADR-0100), with export ids from the lent
    /// counter; a refused registration is counted and skipped.
    fn register_awaiting(
        &mut self,
        source: &mut LaneSource<'_>,
        endpoint: EndpointId,
        alias: Alias,
        lanes: &[Arc<LogBuffer<T>>],
    ) -> Vec<AwaitingLane> {
        let mut awaiting = Vec::new();
        let Some((entries, exports)) = source.awaiting.as_mut() else {
            return awaiting;
        };
        for entry in entries
            .iter()
            .filter(|entry| entry.endpoint == endpoint && entry.stream_id == alias.stream_id)
        {
            for (lane, buffer) in lanes.iter().enumerate() {
                let export = **exports;
                let registered = export
                    .checked_add(1)
                    .filter(|_| karyos_sys::registration::valid_export(export))
                    .ok_or(karyos_sys::error::SysError::ResourcesUnavailable)
                    .and_then(|next| {
                        let cell = buffer.register_awaiting(entry.role, false, export)?;
                        **exports = next;
                        Ok(cell)
                    });
                match registered {
                    Ok(cell) => awaiting.push(AwaitingLane {
                        lane,
                        entry: *entry,
                        cell,
                    }),
                    Err(_) => self.counters.bump(|c| &mut c.start_cells_refused),
                }
            }
        }
        awaiting
    }

    /// Takes the awaiting cells of the image installed at `slot`, for the
    /// driver to place on its lanes' streams (ADR-0100).
    pub(crate) fn take_awaiting(&mut self, slot: SlotRef) -> Vec<AwaitingLane> {
        self.images
            .iter_mut()
            .find(|image| image.state == State::Installed(slot))
            .map(|image| std::mem::take(&mut image.awaiting))
            .unwrap_or_default()
    }

    /// The image's term bytes, `term_length * (3 + spare_slots) * lanes`;
    /// `None` on overflow.
    fn charge(&self, term: TermParams, joins: &Lanes<u64>) -> Option<u64> {
        let slots = ROTATION_SLOTS.checked_add(u64::from(self.template.spare_slots))?;
        let lanes = u64::try_from(joins.as_slice().len()).ok()?;
        u64::from(term.term_length)
            .checked_mul(slots)?
            .checked_mul(lanes)
    }

    /// Builds the lanes, from `source`, and the receive owner of an
    /// accepted answer. Every lane's geometry is checked before any lane is
    /// created; a lane that cannot be created is `Storage`, and the lanes
    /// already created drop with the refusal.
    fn allocate(
        &mut self,
        source: &mut LaneSource<'_>,
        alias: Alias,
        term: TermParams,
        joins: &Lanes<u64>,
    ) -> Result<Built<T>, Refusal> {
        if source.closing {
            return Err(Refusal::Storage);
        }
        let term_length = TermLength::try_new(term.term_length).map_err(|_| Refusal::Geometry)?;
        let params = ImageParams::new(
            alias.session_id,
            alias.stream_id,
            joins.count(),
            term_length,
            term.mtu,
        )
        .map_err(|_| Refusal::Geometry)?;
        let mut configs = Vec::with_capacity(joins.as_slice().len());
        for (index, &join) in joins.as_slice().iter().enumerate() {
            let lane = u8::try_from(index)
                .ok()
                .and_then(|lane| Lane::try_new(lane).ok())
                .ok_or(Refusal::Geometry)?;
            let config = LogBufferConfig {
                term_length,
                spare_slots: self.template.spare_slots,
                max_subscribers: self.template.max_subscribers,
                mtu: term.mtu,
                max_reserved: term_length.get() / 8,
                initial_term_id: TermId::new(term.initial_term_id.cast_unsigned()),
                lane,
                session_id: alias.session_id,
                stream_id: alias.stream_id,
                publication: PublicationMode::Image {
                    join,
                    local_gaps: self.template.local_gaps,
                },
                claim_deadline: DEFAULT_CLAIM_DEADLINE,
                schedule_capacity: 0,
            };
            LogBuffer::<T>::validate(&config).map_err(|_| Refusal::Geometry)?;
            configs.push(config);
        }
        let mut lanes = Vec::with_capacity(configs.len());
        for config in configs {
            #[cfg(test)]
            if self.fail_lane == Some(lanes.len()) {
                return Err(Refusal::Storage);
            }
            let lane =
                <T as sealed::Create>::image_lane(source, config).map_err(|_| Refusal::Storage)?;
            lanes.push(Arc::new(lane));
            #[cfg(test)]
            {
                self.last_lanes = lanes.iter().map(Arc::downgrade).collect();
            }
        }
        let owner = ReceiveOwner::<T>::new(params, lanes.clone()).map_err(|_| Refusal::Geometry)?;
        Ok((lanes, owner))
    }
}

#[cfg(test)]
mod tests;
