// SPDX-License-Identifier: Apache-2.0

//! Mapping generations and the cutover of a stream in embedded mode
//! (`quantstratum-docs: karyos/design/mapping-generations.md`, g3).
//!
//! [`EmbeddedDriver::reconfigure_stream`] creates the successor mapping on
//! the control path, marks every handle's generation link pending and seals
//! the current mapping. Once its seal is positioned, a duty cycle opens the
//! cutover: the successor starts at the seal's stream position, each handle
//! is offered a successor capability through its link, and the predecessor
//! is retained while anything still references it. Handles that do not move
//! before the cutover deadline (publishers) or whose progress lease expires
//! (subscribers) are fenced.

use std::sync::{Arc, Weak};

use karyos_client::{GenerationLink, LinkStatus, Successor};
use karyos_sys::error::SysError;
use karyos_sys::log_buffer::{Conductor, LogBuffer, LogBufferConfig, Role, SealState};
use karyos_sys::sizing::TermLength;
use karyos_sys::term::Generation;

use crate::embedded::{EmbeddedDriver, Stream, StreamHandle};
use crate::error::DriverError;

/// What a reconfiguration changes (SPEC.md §4): the term length and the slot
/// count. Everything else is copied from the current mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reconfiguration {
    /// The successor's term length.
    pub term_length: TermLength,
    /// The successor's spare slots.
    pub spare_slots: u8,
}

/// One mapping of a stream in its position table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenerationInfo {
    /// The mapping generation.
    pub generation: Generation,
    /// The stream position where the mapping starts.
    pub base: u64,
    /// The stream position of its seal, once positioned.
    pub seal: Option<u64>,
}

/// A handle on the stream's current mapping, through its generation link.
#[derive(Debug)]
pub(crate) struct Member {
    pub(crate) link: Weak<GenerationLink>,
    pub(crate) kind: MemberKind,
}

/// What a member holds on the current mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MemberKind {
    Exclusive,
    Concurrent,
    Subscriber { role: Role, cell: usize },
}

/// A predecessor mapping, kept while anything references it.
#[derive(Debug)]
pub(crate) struct Retained {
    pub(crate) generation: Generation,
    pub(crate) base: u64,
    /// Its seal position, local to the mapping.
    pub(crate) seal: u64,
    pub(crate) buffer: Arc<LogBuffer>,
    pub(crate) conductor: Conductor<Arc<LogBuffer>>,
}

/// A cutover in progress.
#[derive(Debug)]
pub(crate) enum Cutover {
    /// The successor exists; the predecessor's seal is not positioned yet.
    Pending(Box<Pending>),
    /// The successor is current; offered capabilities wait to be taken.
    Open { opened_at: u64, offers: Vec<Offer> },
}

/// A pending cutover: the successor and the handles waiting for it.
#[derive(Debug)]
pub(crate) struct Pending {
    successor: Arc<LogBuffer>,
    conductor: Conductor<Arc<LogBuffer>>,
    generation: Generation,
    config: LogBufferConfig,
    snapshot: Vec<Member>,
}

/// A successor capability offered to one handle.
#[derive(Debug)]
pub(crate) struct Offer {
    link: Weak<GenerationLink>,
    /// A subscriber's progress lease; `None` for a publisher.
    lease: Option<ProgressLease>,
}

/// A subscriber's progress, as sampled by the driver: its predecessor cell,
/// the position last read there and when.
#[derive(Debug, Clone, Copy)]
struct ProgressLease {
    cell: usize,
    sampled: Option<u64>,
    sampled_at: u64,
}

impl Cutover {
    pub(crate) fn is_pending(&self) -> bool {
        matches!(self, Self::Pending(_))
    }

    /// The stream is removed: every handle still waiting is fenced, and a
    /// successor that is not current yet is dropped.
    pub(crate) fn abandon(self) {
        match self {
            Self::Pending(pending) => {
                for member in pending.snapshot {
                    if let Some(link) = member.link.upgrade() {
                        let _ = link.fence();
                    }
                }
            }
            Self::Open { offers, .. } => {
                for offer in offers {
                    if let Some(link) = offer.link.upgrade() {
                        let _ = link.fence();
                    }
                }
            }
        }
    }
}

/// Whether `deadline` has elapsed since `since` at `now`; never for an
/// expiry past the clock's range.
fn expired(since: u64, deadline: u64, now: u64) -> bool {
    since
        .checked_add(deadline)
        .is_some_and(|expiry| now >= expiry)
}

impl Stream {
    /// One duty cycle of the cutover: opens a pending one once the
    /// predecessor's seal is positioned, then fences the handles whose
    /// deadline or lease expired, and ends the cutover when no offer is
    /// left.
    pub(crate) fn advance_cutover(&mut self, now: u64, deadline: u64) -> Result<(), DriverError> {
        if self.cutover.as_ref().is_some_and(Cutover::is_pending) {
            self.open(now)?;
        }
        let Some(Cutover::Open { opened_at, offers }) = &mut self.cutover else {
            return Ok(());
        };
        let opened_at = *opened_at;
        let predecessor = self.retained.last();
        let spare = &mut self.spare;
        offers.retain_mut(|offer| {
            let Some(link) = offer.link.upgrade() else {
                // The handle is gone, and its reserved capability with it.
                return false;
            };
            if link.status() != LinkStatus::Offered {
                // Moved (admitted) or fenced.
                return false;
            }
            match &mut offer.lease {
                None => {
                    if !expired(opened_at, deadline, now) {
                        return true;
                    }
                    if let Some(Successor::Publication(inner)) = link.fence() {
                        *spare = Some(inner);
                    }
                    false
                }
                Some(lease) => {
                    // The linearization point of a fence: this read, then
                    // the link's compare-exchange.
                    let position = predecessor
                        .and_then(|retained| retained.conductor.cell_position(lease.cell));
                    if position != lease.sampled {
                        lease.sampled = position;
                        lease.sampled_at = now;
                        return true;
                    }
                    if !expired(lease.sampled_at, deadline, now) {
                        return true;
                    }
                    // Dropping the reserved cell detaches it.
                    drop(link.fence());
                    false
                }
            }
        });
        if offers.is_empty() {
            self.cutover = None;
        }
        Ok(())
    }

    /// Opens a pending cutover once the predecessor's seal is positioned.
    fn open(&mut self, now: u64) -> Result<(), DriverError> {
        let position = match self.conductor.seal_state() {
            SealState::Positioned { position } | SealState::Retired { position } => position,
            SealState::Active | SealState::Sealed => return Ok(()),
        };
        let Some(Cutover::Pending(pending)) = self.cutover.take() else {
            return Ok(());
        };
        let Pending {
            successor,
            mut conductor,
            generation,
            config,
            snapshot,
        } = *pending;
        // Checked by `reconfigure_stream` before the cutover started.
        let base = self
            .base
            .checked_add(position)
            .ok_or(DriverError::PositionsExhausted)?;
        // The fallible part first: the successor capabilities. On error the
        // waiting handles are fenced, and everything prepared is dropped.
        let mut prepared = Vec::with_capacity(snapshot.len());
        let mut failure = None;
        for member in &snapshot {
            let Some(link) = member.link.upgrade() else {
                continue;
            };
            let issued = match member.kind {
                MemberKind::Exclusive => successor.publication_owned().map(|inner| {
                    inner.map(|inner| (Successor::Publication(inner), member.kind, None))
                }),
                MemberKind::Concurrent => conductor.concurrent_publication().map(|inner| {
                    inner.map(|inner| (Successor::Concurrent(inner), member.kind, None))
                }),
                MemberKind::Subscriber { role, cell } => conductor.subscribe(role).map(|inner| {
                    let kind = MemberKind::Subscriber {
                        role,
                        cell: inner.cell(),
                    };
                    let scratch =
                        vec![0u8; inner.buffer().max_message_length() as usize].into_boxed_slice();
                    let lease = ProgressLease {
                        cell,
                        sampled: self.conductor.cell_position(cell),
                        sampled_at: now,
                    };
                    Some((
                        Successor::Subscription { inner, scratch },
                        kind,
                        Some(lease),
                    ))
                }),
            };
            match issued {
                Ok(Some(entry)) => prepared.push((link, entry)),
                // The successor has the predecessor's capacity: a refusal
                // is a broken invariant.
                Ok(None) => {
                    failure = Some(DriverError::Sys(SysError::ResourcesUnavailable));
                    break;
                }
                Err(error) => {
                    failure = Some(DriverError::Sys(error));
                    break;
                }
            }
        }
        if let Some(error) = failure {
            drop(prepared);
            Cutover::Pending(Box::new(Pending {
                successor,
                conductor,
                generation,
                config,
                snapshot,
            }))
            .abandon();
            return Err(error);
        }
        // Effect: nothing below fails.
        let mut offers = Vec::with_capacity(prepared.len());
        let mut members = Vec::with_capacity(prepared.len());
        for (link, (capability, kind, lease)) in prepared {
            match link.offer(base, capability) {
                Ok(()) => {
                    offers.push(Offer {
                        link: Arc::downgrade(&link),
                        lease,
                    });
                    members.push(Member {
                        link: Arc::downgrade(&link),
                        kind,
                    });
                }
                Err(Successor::Publication(inner)) => self.spare = Some(inner),
                Err(_) => {}
            }
        }
        let predecessor = Retained {
            generation: self.generation,
            base: self.base,
            seal: position,
            buffer: core::mem::replace(&mut self.buffer, successor),
            conductor: core::mem::replace(&mut self.conductor, conductor),
        };
        self.retained.push(predecessor);
        self.generation = generation;
        self.base = base;
        self.config = config;
        self.members = members;
        self.cutover = Some(Cutover::Open {
            opened_at: now,
            offers,
        });
        Ok(())
    }

    /// Forgets dropped or fenced members and predecessors nothing references
    /// any more (the driver holds two references: the buffer and its
    /// conductor).
    pub(crate) fn forget_unused(&mut self) {
        self.members.retain(|member| {
            member
                .link
                .upgrade()
                .is_some_and(|link| link.status() != LinkStatus::Fenced)
        });
        self.retained
            .retain(|retained| Arc::strong_count(&retained.buffer) > 2);
    }
}

impl EmbeddedDriver {
    /// Replaces the stream's mapping with a successor of another term length
    /// or slot count (SPEC.md §4 mapping generations;
    /// `quantstratum-docs: karyos/design/mapping-generations.md`). Control path: creates the
    /// successor, marks every handle's link pending and seals the current
    /// mapping. Returns the successor's generation. A later duty cycle (or
    /// this call, for a concurrent stream, whose seal is positioned at once)
    /// opens the cutover.
    ///
    /// # Errors
    ///
    /// Without any effect: [`DriverError::UnknownStream`],
    /// [`DriverError::StreamRetiring`], [`DriverError::CutoverPending`] while
    /// a cutover is in progress, `ResourcesUnavailable` when
    /// `max_retained_generations` predecessors are retained,
    /// [`DriverError::GenerationsExhausted`],
    /// [`DriverError::PositionsExhausted`], and the configuration and
    /// allocation errors of the successor. [`DriverError::Sys`] from the
    /// descriptor protocol indicates a broken invariant.
    pub fn reconfigure_stream(
        &mut self,
        stream: StreamHandle,
        reconfiguration: Reconfiguration,
    ) -> Result<Generation, DriverError> {
        let max_retained = self.config.max_retained_generations;
        let deadline = self.config.cutover_deadline;
        let target = self.active_stream_mut(stream)?;
        if target.cutover.is_some() {
            return Err(DriverError::CutoverPending { stream: target.id });
        }
        if target.retained.len() >= max_retained {
            return Err(DriverError::Sys(SysError::ResourcesUnavailable));
        }
        let generation = target
            .generation
            .get()
            .checked_add(1)
            .and_then(|next| Generation::try_new(next).ok())
            .ok_or(DriverError::GenerationsExhausted)?;
        let config = LogBufferConfig {
            term_length: reconfiguration.term_length,
            spare_slots: reconfiguration.spare_slots,
            ..target.config
        };
        // The successor's maximum end: its base is at most the head plus one
        // term (the fence closes the active term), and one mapping spans at
        // most 2^31 terms.
        let old_term = u64::from(target.config.term_length.get());
        let new_span = u64::from(config.term_length.get())
            .checked_mul(1 << 31)
            .ok_or(DriverError::PositionsExhausted)?;
        let maximum = target
            .conductor
            .head()?
            .checked_add(old_term)
            .and_then(|end| end.checked_add(target.base))
            .and_then(|base| base.checked_add(new_span))
            .ok_or(DriverError::PositionsExhausted)?;
        if maximum >= 1 << 63 {
            return Err(DriverError::PositionsExhausted);
        }
        let successor = Arc::new(LogBuffer::new_with_generation(config, generation)?);
        let conductor = successor
            .conductor_owned()
            .ok_or(SysError::ResourcesUnavailable)?;
        // Effect.
        target.conductor.seal()?;
        target.spare = None;
        let snapshot = target
            .members
            .drain(..)
            .filter(|member| member.link.upgrade().is_some_and(|link| link.set_pending()))
            .collect();
        target.cutover = Some(Cutover::Pending(Box::new(Pending {
            successor,
            conductor,
            generation,
            config,
            snapshot,
        })));
        let now = self.clock_now();
        let target = self.active_stream_mut(stream)?;
        target.advance_cutover(now, deadline)?;
        Ok(generation)
    }

    /// The stream's position table: every retained predecessor, oldest
    /// first, then the current mapping.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError::UnknownStream`] for a foreign handle or a
    /// freed stream.
    pub fn generations(&self, stream: StreamHandle) -> Result<Vec<GenerationInfo>, DriverError> {
        let target = self.stream_ref(stream)?;
        let mut table: Vec<GenerationInfo> = target
            .retained
            .iter()
            .map(|retained| GenerationInfo {
                generation: retained.generation,
                base: retained.base,
                seal: retained.base.checked_add(retained.seal),
            })
            .collect();
        let seal = match target.conductor.seal_state() {
            SealState::Positioned { position } | SealState::Retired { position } => {
                target.base.checked_add(position)
            }
            SealState::Active | SealState::Sealed => None,
        };
        table.push(GenerationInfo {
            generation: target.generation,
            base: target.base,
            seal,
        });
        Ok(table)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embedded::StreamConfig;
    use karyos_sys::frame::Lane;
    use karyos_sys::log_buffer::PublicationMode;
    use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH};
    use karyos_sys::term::TermId;

    fn stream(driver: &mut EmbeddedDriver) -> StreamHandle {
        driver
            .add_stream(StreamConfig {
                buffer: LogBufferConfig {
                    term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                    spare_slots: 6,
                    max_subscribers: 2,
                    mtu: DEFAULT_MTU,
                    max_reserved: MIN_TERM_LENGTH / 8,
                    initial_term_id: TermId::new(7),
                    lane: Lane::ZERO,
                    session_id: 1,
                    stream_id: 2,
                    claim_deadline: 100,
                    publication: PublicationMode::Concurrent {
                        publishers: 1,
                        allow_non_lse: true,
                    },
                },
                allow_unconnected: true,
            })
            .unwrap()
    }

    fn reconfiguration() -> Reconfiguration {
        Reconfiguration {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 6,
        }
    }

    #[test]
    fn the_last_generation_is_not_replaced_and_nothing_changes() {
        let mut driver = EmbeddedDriver::new().unwrap();
        let handle = stream(&mut driver);
        let last = Generation::try_new((1 << 24) - 1).unwrap();
        driver.active_stream_mut(handle).unwrap().generation = last;
        assert!(matches!(
            driver.reconfigure_stream(handle, reconfiguration()),
            Err(DriverError::GenerationsExhausted)
        ));
        assert_eq!(driver.seal_state(handle).unwrap(), SealState::Active);
        let target = driver.active_stream_mut(handle).unwrap();
        assert!(target.cutover.is_none());
        assert_eq!(target.generation, last);
        // One below the limit is still replaced.
        target.generation = Generation::try_new((1 << 24) - 2).unwrap();
        assert_eq!(
            driver
                .reconfigure_stream(handle, reconfiguration())
                .unwrap(),
            last
        );
    }

    #[test]
    fn a_successor_that_could_reach_2_pow_63_is_refused() {
        let mut driver = EmbeddedDriver::new().unwrap();
        let handle = stream(&mut driver);
        // One mapping of this term length spans 2^31 × 2^16 = 2^47 bytes.
        let span = (1u64 << 31) * u64::from(MIN_TERM_LENGTH);
        let term = u64::from(MIN_TERM_LENGTH);
        let target = driver.active_stream_mut(handle).unwrap();
        target.base = (1 << 63) - span - term;
        assert!(matches!(
            driver.reconfigure_stream(handle, reconfiguration()),
            Err(DriverError::PositionsExhausted)
        ));
        assert_eq!(driver.seal_state(handle).unwrap(), SealState::Active);
        let target = driver.active_stream_mut(handle).unwrap();
        target.base = (1 << 63) - span - term - 1;
        assert!(driver.reconfigure_stream(handle, reconfiguration()).is_ok());
    }
}
