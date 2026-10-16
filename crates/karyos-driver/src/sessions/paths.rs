// SPDX-License-Identifier: Apache-2.0

//! The path bindings of the receiver's images (`quantstratum-docs:
//! karyos/design/redundant-paths.md`, sections 2 and 3; P2.9, coordinator
//! decisions ACS 15519).
//!
//! An image is bound to one or more paths of its publication: each path is
//! a local endpoint and a source endpoint that completed its own challenge.
//! The receive sessions call this table at three points and own everything
//! else:
//!
//! - **First path.** [`PathBindings::bind_first`] when the image is
//!   installed: the image's identity, term parameters and lane count, and
//!   the first path with the join points the image was installed at.
//! - **Later path (RP-1).** [`PathBindings::offer_later`] when a later
//!   path's answer is accepted. It must name the image's full identity,
//!   term parameters and lane count exactly, or it is refused for that
//!   path and the image is unchanged. Its join points are recorded, for
//!   statistics only, and never applied: no image position, extent or
//!   subscriber cursor moves, whether the later join is above the image's
//!   or below it. The binding is one transition: a refusal leaves no
//!   binding.
//! - **Retirement.** [`PathBindings::image_retired`] when the image
//!   retires.
//!
//! **Liveness (RP-2, as decided).** A binding is live while it receives
//! evidence fresh on that path within `path_liveness_timeout`: the caller
//! refreshes it ([`PathBindings::refresh`]) for a DATA frame that
//! `paths::stats::PathStats::arrived` reports fresh on the path, and for a
//! PATH_HB from the path's source ([`PathBindings::path_hb`]). Path
//! liveness never refreshes the image. At the timeout the binding is
//! removed and counted ([`PathBindings::timers`]); the image stays while
//! another binding is live, and a path loss creates no tombstone. A path
//! that comes back completes a fresh challenge and is reconciled again.
//!
//! The table is preallocated, `max_images` rows of `max_paths` bindings;
//! the data calls do not allocate. Every deadline is an elapsed time from
//! `host_clock::age_ns`, never an addition. Counters are checked and
//! sticky on overflow.

use karyos_protocol::network::{Identity, Lanes, TermParams};
use karyos_sys::host_clock::age_ns;

use super::receive::{BindingKey, SlotRef};

/// A path of an image: the binding key it completed its challenge from
/// (the local endpoint, the source endpoint and the alias; one source
/// endpoint may carry several publications).
pub type PathKey = BindingKey;

/// The largest `max_paths`, as the owner-side components bound it.
pub use crate::paths::MAX_PATHS;

/// The table's limits (redundant-paths.md section 5; provisional).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathBindingsConfig {
    /// Image rows: the receive sessions' slots.
    pub max_images: u32,
    /// Bindings per image (`max_paths`, default 4).
    pub max_paths: u8,
    /// A binding with no fresh evidence for this long is lost, in
    /// nanoseconds (default: the image liveness timeout).
    pub path_liveness_timeout: u64,
}

/// Why a table could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("path bindings need at least one image row and one path")]
pub struct PathBindingsConfigError;

/// Why a binding was refused; the image is unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PathRefusal {
    /// No installed image at that slot and generation.
    #[error("no installed image at that slot")]
    UnknownImage,
    /// The answer names another identity.
    #[error("the path names another identity")]
    Identity,
    /// The answer's term parameters or lane count differ from the image's.
    #[error("the path's term parameters or lane count differ")]
    Parameters,
    /// The image has `max_paths` bindings.
    #[error("the image has no free path")]
    Full,
    /// The key is already bound to this image.
    #[error("the path is already bound")]
    Bound,
}

/// What the table counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PathCounters {
    /// Bindings made, first paths included.
    pub bound: u64,
    /// Later paths refused for another identity.
    pub refused_identity: u64,
    /// Later paths refused for other term parameters or lane count.
    pub refused_parameters: u64,
    /// Later paths refused because the image had no free path.
    pub refused_full: u64,
    /// Bindings lost at the liveness timeout.
    pub lost: u64,
    /// PATH_HB that refreshed a binding.
    pub path_hb: u64,
    /// PATH_HB from a key bound to no image.
    pub path_hb_unbound: u64,
    /// An increment did not apply (sticky).
    pub overflowed: bool,
}

impl PathCounters {
    fn bump(&mut self, field: impl FnOnce(&mut Self) -> &mut u64) {
        let count = field(self);
        match count.checked_add(1) {
            Some(next) => *count = next,
            None => self.overflowed = true,
        }
    }
}

/// One binding.
#[derive(Debug, Clone, Copy)]
struct Binding {
    key: PathKey,
    /// The join points this path's answer stated, per lane: recorded,
    /// never applied (RP-1).
    joins: Lanes<u64>,
    last_fresh: u64,
}

/// The image a row serves.
#[derive(Debug, Clone, Copy)]
struct Image {
    slot: SlotRef,
    identity: Identity,
    term: TermParams,
    lanes: u8,
}

#[derive(Debug)]
struct Row {
    image: Option<Image>,
    paths: Vec<Option<Binding>>,
}

/// The receiver's path bindings.
#[derive(Debug)]
pub struct PathBindings {
    config: PathBindingsConfig,
    rows: Vec<Row>,
    counters: PathCounters,
}

impl PathBindings {
    /// The table for `config`; it allocates only here.
    ///
    /// # Errors
    ///
    /// [`PathBindingsConfigError`] for no row or no path.
    pub fn new(config: PathBindingsConfig) -> Result<Self, PathBindingsConfigError> {
        if config.max_images == 0 || config.max_paths == 0 {
            return Err(PathBindingsConfigError);
        }
        let paths = usize::from(config.max_paths);
        let rows = (0..config.max_images)
            .map(|_| Row {
                image: None,
                paths: vec![None; paths],
            })
            .collect();
        Ok(Self {
            config,
            rows,
            counters: PathCounters::default(),
        })
    }

    /// What the table counted.
    #[must_use]
    pub fn counters(&self) -> PathCounters {
        self.counters
    }

    fn row(&self, slot: SlotRef) -> Option<&Row> {
        let row = self.rows.get(usize::try_from(slot.slot).ok()?)?;
        row.image.filter(|image| image.slot == slot).map(|_| row)
    }

    fn row_mut(&mut self, slot: SlotRef) -> Option<&mut Row> {
        let row = self.rows.get_mut(usize::try_from(slot.slot).ok()?)?;
        if row.image.is_some_and(|image| image.slot == slot) {
            Some(row)
        } else {
            None
        }
    }

    /// The image at `slot` was installed through its first path `key`, at
    /// the image's own `joins`; any earlier row of that slot (an older
    /// generation) is replaced. Returns the path index, 0.
    ///
    /// # Errors
    ///
    /// [`PathRefusal::UnknownImage`] for a slot beyond the table.
    pub fn bind_first(
        &mut self,
        slot: SlotRef,
        identity: Identity,
        term: TermParams,
        key: PathKey,
        joins: Lanes<u64>,
        now: u64,
    ) -> Result<usize, PathRefusal> {
        let row = usize::try_from(slot.slot)
            .ok()
            .and_then(|index| self.rows.get_mut(index))
            .ok_or(PathRefusal::UnknownImage)?;
        row.image = Some(Image {
            slot,
            identity,
            term,
            lanes: joins.count(),
        });
        row.paths.fill(None);
        if let Some(first) = row.paths.first_mut() {
            *first = Some(Binding {
                key,
                joins,
                last_fresh: now,
            });
        }
        self.counters.bump(|c| &mut c.bound);
        Ok(0)
    }

    /// A later path `key` of the image at `slot` answered with `identity`,
    /// `term` and `joins` (RP-1): bound if they name the image exactly and
    /// a path is free. Its joins are recorded, never applied. Returns the
    /// path index.
    ///
    /// # Errors
    ///
    /// See [`PathRefusal`]; the image is unchanged and no binding is made.
    pub fn offer_later(
        &mut self,
        slot: SlotRef,
        key: PathKey,
        identity: Identity,
        term: TermParams,
        joins: Lanes<u64>,
        now: u64,
    ) -> Result<usize, PathRefusal> {
        let Some(row) = self.row_mut(slot) else {
            return Err(PathRefusal::UnknownImage);
        };
        let Some(image) = row.image else {
            return Err(PathRefusal::UnknownImage);
        };
        let refusal = if image.identity != identity {
            Some(PathRefusal::Identity)
        } else if image.term != term || image.lanes != joins.count() {
            Some(PathRefusal::Parameters)
        } else if row.paths.iter().flatten().any(|bound| bound.key == key) {
            Some(PathRefusal::Bound)
        } else {
            None
        };
        let free = row.paths.iter().position(Option::is_none);
        match (refusal, free) {
            (Some(refusal), _) => {
                match refusal {
                    PathRefusal::Identity => self.counters.bump(|c| &mut c.refused_identity),
                    PathRefusal::Parameters => self.counters.bump(|c| &mut c.refused_parameters),
                    _ => {}
                }
                Err(refusal)
            }
            (None, None) => {
                self.counters.bump(|c| &mut c.refused_full);
                Err(PathRefusal::Full)
            }
            (None, Some(index)) => {
                if let Some(binding) = row.paths.get_mut(index) {
                    *binding = Some(Binding {
                        key,
                        joins,
                        last_fresh: now,
                    });
                }
                self.counters.bump(|c| &mut c.bound);
                Ok(index)
            }
        }
    }

    /// Fresh evidence on `path` of the image at `slot` (RP-2): its
    /// liveness is refreshed, never the image's. Returns whether the
    /// binding exists.
    pub fn refresh(&mut self, slot: SlotRef, path: usize, now: u64) -> bool {
        match self
            .row_mut(slot)
            .and_then(|row| row.paths.get_mut(path))
            .and_then(Option::as_mut)
        {
            Some(binding) => {
                binding.last_fresh = now;
                true
            }
            None => false,
        }
    }

    /// The image and path a key is bound to.
    #[must_use]
    pub fn lookup(&self, key: PathKey) -> Option<(SlotRef, usize)> {
        self.rows.iter().find_map(|row| {
            let image = row.image?;
            row.paths
                .iter()
                .position(|binding| binding.is_some_and(|bound| bound.key == key))
                .map(|path| (image.slot, path))
        })
    }

    /// A PATH_HB from `key` at `now`: refreshes that binding only. PATH_HB
    /// carries no freshness field, so under the trusted profile it is
    /// accepted as fresh: the manifest's known limit, "PATH_HB: a dead
    /// path looks alive". It creates nothing; from an unbound key it is
    /// counted and ignored.
    pub fn path_hb(&mut self, key: PathKey, now: u64) -> Option<(SlotRef, usize)> {
        let Some((slot, path)) = self.lookup(key) else {
            self.counters.bump(|c| &mut c.path_hb_unbound);
            return None;
        };
        let _ = self.refresh(slot, path, now);
        self.counters.bump(|c| &mut c.path_hb);
        Some((slot, path))
    }

    /// The join points a path's answer stated (statistics only).
    #[must_use]
    pub fn joins(&self, slot: SlotRef, path: usize) -> Option<Lanes<u64>> {
        self.row(slot)?
            .paths
            .get(path)?
            .as_ref()
            .map(|binding| binding.joins)
    }

    /// The identity, term parameters and lane count of the image at
    /// `slot`, and whether it has a free path.
    #[must_use]
    pub fn image(&self, slot: SlotRef) -> Option<(Identity, TermParams, u8, bool)> {
        let row = self.row(slot)?;
        let image = row.image?;
        let free = row.paths.iter().any(Option::is_none);
        Some((image.identity, image.term, image.lanes, free))
    }

    /// Live bindings of the image at `slot`.
    #[must_use]
    pub fn live(&self, slot: SlotRef) -> usize {
        self.row(slot)
            .map_or(0, |row| row.paths.iter().flatten().count())
    }

    /// Removes up to `limit` bindings with no fresh evidence for
    /// `path_liveness_timeout`, reporting each to `lost` as image, path and
    /// key; the rest wait for the next call. The image stays; the caller
    /// applies the image's own liveness. Returns how many were lost.
    pub fn timers(
        &mut self,
        now: u64,
        limit: u32,
        mut lost: impl FnMut(SlotRef, usize, PathKey),
    ) -> u32 {
        let timeout = self.config.path_liveness_timeout;
        let mut count = 0u32;
        for row in &mut self.rows {
            let Some(image) = row.image else {
                continue;
            };
            for (path, binding) in row.paths.iter_mut().enumerate() {
                let Some(bound) = *binding else {
                    continue;
                };
                if count >= limit {
                    return count;
                }
                if age_ns(now, bound.last_fresh) >= timeout {
                    *binding = None;
                    lost(image.slot, path, bound.key);
                    // Bounded by `limit`, a u32: it cannot overflow.
                    count = count.checked_add(1).unwrap_or(count);
                    self.counters.bump(|c| &mut c.lost);
                }
            }
        }
        count
    }

    /// The image at `slot` retired: its row and bindings go.
    pub fn image_retired(&mut self, slot: SlotRef) {
        if let Some(row) = self.row_mut(slot) {
            row.image = None;
            row.paths.fill(None);
        }
    }
}

#[cfg(test)]
mod tests;
