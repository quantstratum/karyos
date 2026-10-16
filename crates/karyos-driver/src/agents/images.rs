// SPDX-License-Identifier: Apache-2.0

//! The conductor's image table (`quantstratum-docs:
//! karyos/design/network-sessions.md` S1 "installation", SN-2; phase
//! 4b-2): it serves the receiver's `CreateImage`, allocates one image log
//! buffer per lane with the answer's join points, and hands the image's
//! receive owner to the receiver (`InstallImage`, the S1 `ImageReady`). The
//! receiver installs it if its challenge still allows (`ImageInstalled`) or
//! releases it (`ImageReleased`), and the conductor then frees the storage.
//!
//! - **Geometry.** The term length, MTU and lane count come from the
//!   accepted answer; one that the log buffer refuses is answered
//!   `RefuseImage` (S1 `ImageRefused`), and the receiver removes the
//!   challenge.
//! - **Credit.** A command whose rings have no room now stays pending in
//!   the table and is posted on a later poll; the receiver's challenge keeps
//!   its timeout, so a late `ImageReady` is released, never installed.
//!   (S1 reserves the whole chain at the answer; the agents' rings reserve
//!   each reply when its command is posted, so a pending command waits for
//!   room instead.)
//! - **Attachment.** Local subscribers may attach to an image only once the
//!   receiver reported it installed ([`ImageTable::installed`]). Retirement,
//!   `StorageReclaimed` and the image's first SM come with liveness and DATA
//!   (phase 5).
//!
//! Images are heap-backed in this phase (one process); shared-memory
//! images for subscribers of other processes follow the IPC mapping work.

use std::sync::Arc;

use karyos_io::sockets::ops::SocketOps;
use karyos_protocol::frame::Lane;
use karyos_protocol::network::{Alias, Identity, Lanes, TermParams};
use karyos_sys::log_buffer::{
    DEFAULT_CLAIM_DEADLINE, LogBuffer, LogBufferConfig, PublicationMode, ReceiveOwner,
};
use karyos_sys::receive::ImageParams;
use karyos_sys::sizing::TermLength;
use karyos_sys::term::TermId;

use super::{AgentCommand, AgentEvent, AgentLinks, EndpointId};
use crate::sessions::receive::SlotRef;

/// The image log buffer parameters the answer does not carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageTemplate {
    /// Spare slots beyond the three rotation slots (default 5).
    pub spare_slots: u8,
    /// Local subscribers per image (default 8).
    pub max_subscribers: u8,
    /// Whether the receive owner may seal local gaps (default true:
    /// gaps-and-unreliable-delivery.md).
    pub local_gaps: bool,
}

impl Default for ImageTemplate {
    fn default() -> Self {
        Self {
            spare_slots: 5,
            max_subscribers: 8,
            local_gaps: true,
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
    },
    /// The image was not installed; its storage is freed.
    Released {
        /// The pending slot.
        slot: SlotRef,
    },
    /// The answer's geometry was refused; the challenge is removed.
    Refused {
        /// The pending slot.
        slot: SlotRef,
    },
}

/// One image's state.
enum State {
    /// Allocated; `InstallImage` waiting for ring room.
    Pending(Box<ReceiveOwner>),
    /// `InstallImage` posted.
    Offered,
    /// Installed under this slot.
    Installed(SlotRef),
    /// `RefuseImage` waiting for ring room.
    Refusing,
    /// `RefuseImage` posted.
    RefuseOffered,
}

struct Image {
    /// The pending slot, at its challenge generation.
    slot: SlotRef,
    endpoint: EndpointId,
    identity: Identity,
    lanes: Vec<Arc<LogBuffer>>,
    state: State,
}

/// The conductor's image table.
pub struct ImageTable {
    images: Vec<Image>,
    max: usize,
    template: ImageTemplate,
}

impl std::fmt::Debug for ImageTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImageTable")
            .field("images", &self.images.len())
            .field("max", &self.max)
            .finish_non_exhaustive()
    }
}

/// Why an answer's geometry was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Refused;

impl ImageTable {
    /// A table of at most `max` images (the receiver's `max_images`).
    #[must_use]
    pub fn new(max: usize, template: ImageTemplate) -> Self {
        Self {
            images: Vec::with_capacity(max),
            max,
            template,
        }
    }

    /// The images held, installed or not.
    #[must_use]
    pub fn len(&self) -> usize {
        self.images.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.images.is_empty()
    }

    /// The lanes of the image installed at `slot`, for subscribers to
    /// attach; `None` until the receiver reported it installed.
    #[must_use]
    pub fn installed(&self, slot: SlotRef) -> Option<&[Arc<LogBuffer>]> {
        self.images.iter().find_map(|image| match image.state {
            State::Installed(installed) if installed == slot => Some(image.lanes.as_slice()),
            _ => None,
        })
    }

    /// Builds the lanes and the receive owner of an accepted answer.
    fn allocate(
        &self,
        alias: Alias,
        term: TermParams,
        joins: &Lanes<u64>,
    ) -> Result<(Vec<Arc<LogBuffer>>, ReceiveOwner), Refused> {
        let term_length = TermLength::try_new(term.term_length).map_err(|_| Refused)?;
        let mut lanes = Vec::with_capacity(joins.as_slice().len());
        for (index, &join) in joins.as_slice().iter().enumerate() {
            let lane = u8::try_from(index)
                .ok()
                .and_then(|lane| Lane::try_new(lane).ok())
                .ok_or(Refused)?;
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
            lanes.push(Arc::new(LogBuffer::new(config).map_err(|_| Refused)?));
        }
        let params = ImageParams::new(
            alias.session_id,
            alias.stream_id,
            joins.count(),
            term_length,
            term.mtu,
        )
        .map_err(|_| Refused)?;
        let owner = ReceiveOwner::new(params, lanes.clone()).map_err(|_| Refused)?;
        Ok((lanes, owner))
    }

    /// Applies one of the receiver's agent events: an image event is
    /// served and reported to `on_event`; any other comes back, for the
    /// caller's other consumers (the endpoint table).
    pub fn handle<O: SocketOps>(
        &mut self,
        event: AgentEvent<O>,
        mut on_event: impl FnMut(ImageEvent),
    ) -> Option<AgentEvent<O>> {
        match event {
            AgentEvent::CreateImage {
                endpoint,
                alias,
                slot,
                identity,
                term,
                joins,
            } => self.create(endpoint, alias, slot, identity, term, &joins),
            AgentEvent::ImageInstalled { slot, installed } => {
                if let Some(image) = self.images.iter_mut().find(|image| image.slot == slot) {
                    image.state = State::Installed(installed);
                    on_event(ImageEvent::Installed {
                        slot: installed,
                        endpoint: image.endpoint,
                        identity: image.identity,
                    });
                }
            }
            AgentEvent::ImageReleased { slot } => {
                if let Some(index) = self.images.iter().position(|image| image.slot == slot) {
                    let image = self.images.swap_remove(index);
                    on_event(match image.state {
                        State::RefuseOffered => ImageEvent::Refused { slot },
                        _ => ImageEvent::Released { slot },
                    });
                }
            }
            other => return Some(other),
        }
        None
    }

    fn create(
        &mut self,
        endpoint: EndpointId,
        alias: Alias,
        slot: SlotRef,
        identity: Identity,
        term: TermParams,
        joins: &Lanes<u64>,
    ) {
        // The table is sized like the receiver's session table, which holds
        // a slot for every image it asks for.
        let (lanes, state) = match self.allocate(alias, term, joins) {
            Ok((lanes, owner)) if self.images.len() < self.max => {
                (lanes, State::Pending(Box::new(owner)))
            }
            _ => (Vec::new(), State::Refusing),
        };
        self.images.push(Image {
            slot,
            endpoint,
            identity,
            lanes,
            state,
        });
    }

    /// Posts every pending `InstallImage` and `RefuseImage` that has ring
    /// room now; the others wait for a later call.
    pub fn post<O: SocketOps>(&mut self, links: &AgentLinks<O>) {
        for image in &mut self.images {
            let ready = matches!(image.state, State::Pending(_) | State::Refusing);
            if !ready {
                continue;
            }
            let Ok(prepared) = links.receiver.prepare() else {
                return;
            };
            let slot = image.slot;
            match std::mem::replace(&mut image.state, State::Offered) {
                State::Pending(owner) => {
                    // The agent gone: the driver is stopping.
                    let _ = links
                        .receiver
                        .commit(prepared, |reply| AgentCommand::InstallImage {
                            reply,
                            slot,
                            owner,
                        });
                }
                State::Refusing => {
                    image.state = State::RefuseOffered;
                    let _ = links
                        .receiver
                        .commit(prepared, |reply| AgentCommand::RefuseImage { reply, slot });
                }
                state => image.state = state,
            }
        }
    }
}

#[cfg(test)]
mod tests;
