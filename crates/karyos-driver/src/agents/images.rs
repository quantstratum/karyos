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
//! Images are heap-backed in this phase (one process); shared-memory
//! images for subscribers of other processes follow the IPC mapping work.

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
use crate::embedded::StreamTerms;
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
}

impl Default for ImageTemplate {
    fn default() -> Self {
        Self {
            spare_slots: 5,
            max_subscribers: 8,
            local_gaps: true,
            storage_budget: DEFAULT_IMAGE_STORAGE_BUDGET,
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
    /// Replies for no image, or for an image in another state; ignored.
    pub stale_replies: u64,
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

struct Image<T: StreamTerms> {
    /// The pending slot, at its challenge generation.
    slot: SlotRef,
    endpoint: EndpointId,
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
}

/// The conductor's image table.
pub struct ImageTable<T: StreamTerms = HeapTerms> {
    images: Vec<Image<T>>,
    max: usize,
    template: ImageTemplate,
    /// Term bytes charged.
    charged: u64,
    counters: ImageCounters,
    /// Calls of `allocate` (tests: no refusal allocates).
    #[cfg(test)]
    allocations: usize,
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

/// Why an image was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    Budget,
    Full,
    Geometry,
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
            #[cfg(test)]
            allocations: 0,
        }
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
}

/// The image table's session chain, which builds lanes on the heap until
/// the shared lane source of step n2 (network streams over shared terms).
impl ImageTable<HeapTerms> {
    /// Serves every session event the receiver posted, then reclaims the
    /// retired images no loan holds any more, reporting image events to
    /// `on_event`; returns how many events it served.
    pub fn poll(&mut self, link: &SessionLink, mut on_event: impl FnMut(ImageEvent)) -> u32 {
        let mut served = 0u32;
        while let Some(event) = link.take_event() {
            self.handle(link, event, &mut on_event);
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
    fn reclaim(&mut self, link: &SessionLink, on_event: &mut impl FnMut(ImageEvent)) {
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

    /// Serves one session event.
    pub fn handle(
        &mut self,
        link: &SessionLink,
        event: SessionEvent,
        mut on_event: impl FnMut(ImageEvent),
    ) {
        match event {
            SessionEvent::CreateImage {
                endpoint,
                alias,
                slot,
                identity,
                term,
                joins,
                chain,
            } => {
                if let Some(event) =
                    self.create(link, endpoint, alias, slot, identity, term, &joins, chain)
                {
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
                        identity: image.identity,
                        alias: image.alias,
                    });
                }
                _ => self.counters.bump(|c| &mut c.stale_replies),
            },
            SessionEvent::RetireImage { slot } => {
                let found = self
                    .images
                    .iter_mut()
                    .find(|image| image.state == State::Installed(slot));
                match found {
                    Some(image) => {
                        image.state = State::Retiring(slot);
                        self.counters.bump(|c| &mut c.retired);
                        on_event(ImageEvent::Retiring { slot });
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
        link: &SessionLink,
        endpoint: EndpointId,
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
            identity,
            alias,
            lanes,
            charge,
            reclaimed,
            state,
            freshness: None,
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
        let Ok((lanes, owner)) = self.allocate(alias, term, joins) else {
            refuse(self, Refusal::Geometry, command, reply);
            self.images
                .push(image(State::Refused, Vec::new(), 0, reclaimed));
            return None;
        };
        self.charged = total;
        self.counters.bump(|c| &mut c.offered);
        self.images
            .push(image(State::Offered, lanes, charge, reclaimed));
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

    /// The image's term bytes, `term_length * (3 + spare_slots) * lanes`;
    /// `None` on overflow.
    fn charge(&self, term: TermParams, joins: &Lanes<u64>) -> Option<u64> {
        let slots = ROTATION_SLOTS.checked_add(u64::from(self.template.spare_slots))?;
        let lanes = u64::try_from(joins.as_slice().len()).ok()?;
        u64::from(term.term_length)
            .checked_mul(slots)?
            .checked_mul(lanes)
    }

    /// Builds the lanes and the receive owner of an accepted answer.
    fn allocate(
        &self,
        alias: Alias,
        term: TermParams,
        joins: &Lanes<u64>,
    ) -> Result<(Vec<Arc<LogBuffer>>, ReceiveOwner), Refusal> {
        let term_length = TermLength::try_new(term.term_length).map_err(|_| Refusal::Geometry)?;
        let mut lanes = Vec::with_capacity(joins.as_slice().len());
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
            lanes.push(Arc::new(
                LogBuffer::new(config).map_err(|_| Refusal::Geometry)?,
            ));
        }
        let params = ImageParams::new(
            alias.session_id,
            alias.stream_id,
            joins.count(),
            term_length,
            term.mtu,
        )
        .map_err(|_| Refusal::Geometry)?;
        let owner = ReceiveOwner::new(params, lanes.clone()).map_err(|_| Refusal::Geometry)?;
        Ok((lanes, owner))
    }
}

#[cfg(test)]
mod tests;
