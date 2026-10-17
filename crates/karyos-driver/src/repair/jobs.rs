// SPDX-License-Identifier: Apache-2.0

//! Repair jobs and coalescing (`quantstratum-docs:
//! karyos/design/reliable-transport.md`, "Coalescing and repair work";
//! R5; RC-11, ACS 15597).
//!
//! [`Jobs`] is one incarnation's table of pending repairs: steps 6
//! (coalescing) and 7 (capacity) of NAK admission for a [`Request`] that
//! passed steps 1 to 5.
//!
//! - **Key.** Lane, exact `start` and `length`, and the response domain
//!   ([`Domain`]); the table belongs to one incarnation, so its identity
//!   is implied. With `requester` the key also holds the receiver and its
//!   membership generation. Overlapping or adjacent intervals are separate
//!   jobs: no wider merging.
//! - **Join.** An exact duplicate of a pending job joins it with no new
//!   copy: its requester is added, up to `requesters_per_job`, the rest
//!   counted (a group repair serves them all anyway).
//! - **Linger.** When the backend reports the job's last frame submitted
//!   ([`Jobs::done`]), a linger entry starts for `repair_linger` (default
//!   1 ms), judged by `age_ns`. An exact duplicate within it is dropped and
//!   counted, with no repair and no ERR; a duplicate never extends it. A
//!   known failure ([`Jobs::failed`]) and an uncertain submission
//!   ([`Jobs::unresolved`]) start none; an uncertain job is not retried,
//!   and a later NAK creates a new job.
//! - **Capacity.** `repair_jobs` pending jobs (default 64) and
//!   `repair_linger_entries` (default 256). A full job table drops the NAK
//!   and counts it; a full linger table of live entries leaves the done
//!   job without one, counted.
//!
//! A job keeps its unsent cursor: a partial submission covers only its
//! submitted subset ([`Jobs::progress`]) and the rest stays pending, so a
//! duplicate still joins it. Slots have a checked generation: [`JobRef`]
//! names a job, and [`Jobs::current`] rechecks it. Nothing allocates after
//! construction; counts are checked with a sticky `overflowed` flag.

use karyos_protocol::network::Receiver;
use karyos_sys::host_clock::age_ns;

use super::admission::Request;

/// Who a repair answers (`repair_domain`, RC-4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    /// The group: one transmission serves every coalesced request.
    Group,
    /// One receiver, at one membership generation.
    Requester {
        /// The receiver.
        receiver: Receiver,
        /// Its membership generation.
        generation: u64,
    },
}

/// A job's coalescing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobKey {
    /// The lane.
    pub lane: u8,
    /// The first requested position.
    pub start: u64,
    /// The length in bytes.
    pub length: u32,
    /// The response domain.
    pub domain: Domain,
}

/// A job: its slot and that slot's generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobRef {
    /// The slot.
    pub slot: u16,
    /// The slot's generation for this job.
    pub generation: u64,
}

/// The result of [`Jobs::join_or_create`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Joined {
    /// A new job.
    Created(JobRef),
    /// An exact duplicate joined this pending job.
    Joined(JobRef),
    /// An exact duplicate within the linger: dropped, no repair, no ERR.
    Lingering,
    /// No free job: dropped and counted; the receiver retries.
    Full,
}

/// Why a [`Jobs`] table was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum JobsError {
    /// A zero count, or more jobs than a slot number holds.
    #[error("repair_jobs, repair_linger_entries or requesters_per_job is 0, or too many jobs")]
    Capacity,
}

/// The table's settings (RC-11; provisional and configurable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobsConfig {
    /// Pending jobs per incarnation (default 64).
    pub repair_jobs: usize,
    /// Linger entries per incarnation (default 256).
    pub repair_linger_entries: usize,
    /// The linger after a job's last submission, in ns (default 1 ms).
    pub repair_linger: u64,
    /// Requesters recorded per job (default 8).
    pub requesters_per_job: usize,
}

impl Default for JobsConfig {
    fn default() -> Self {
        Self {
            repair_jobs: 64,
            repair_linger_entries: 256,
            repair_linger: 1_000_000,
            requesters_per_job: 8,
        }
    }
}

/// What the table counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JobsCounts {
    /// Jobs created.
    pub created: u64,
    /// Duplicates joined to a pending job.
    pub joined: u64,
    /// Requesters beyond `requesters_per_job`, not recorded.
    pub requesters_full: u64,
    /// Duplicates dropped within the linger.
    pub lingering: u64,
    /// NAKs dropped for a full job table.
    pub full: u64,
    /// Jobs whose last frame was submitted.
    pub done: u64,
    /// Done jobs left without a linger entry for a full table.
    pub linger_full: u64,
    /// Jobs ended by a known failure.
    pub failed: u64,
    /// Jobs ended by an uncertain submission.
    pub unresolved: u64,
    /// An increment did not apply (sticky).
    pub overflowed: bool,
}

impl JobsCounts {
    fn bump(&mut self, field: impl FnOnce(&mut Self) -> &mut u64) {
        let count = field(self);
        match count.checked_add(1) {
            Some(next) => *count = next,
            None => self.overflowed = true,
        }
    }
}

/// One slot of the job table.
#[derive(Debug, Clone)]
struct Slot {
    generation: u64,
    /// Exhausted generation: never used again.
    retired: bool,
    job: Option<Job>,
    /// The job's requesters: allocated at construction, cleared at reuse.
    requesters: Vec<Receiver>,
}

#[derive(Debug, Clone, Copy)]
struct Job {
    key: JobKey,
    /// The first position not yet submitted.
    cursor: u64,
    /// Its order of creation, for first-come service.
    order: u64,
}

/// A linger entry: the key of a job done at `since`.
#[derive(Debug, Clone, Copy)]
struct Linger {
    key: JobKey,
    since: u64,
}

/// A pending job, as the scheduler sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pending {
    /// The job.
    pub job: JobRef,
    /// Its key.
    pub key: JobKey,
    /// The first position not yet submitted.
    pub cursor: u64,
}

/// One incarnation's repair jobs and linger.
#[derive(Debug)]
pub struct Jobs {
    config: JobsConfig,
    slots: Vec<Slot>,
    lingers: Vec<Option<Linger>>,
    next_order: u64,
    counts: JobsCounts,
}

impl Jobs {
    /// The table, allocated here.
    ///
    /// # Errors
    ///
    /// [`JobsError::Capacity`].
    pub fn new(config: JobsConfig) -> Result<Self, JobsError> {
        if config.repair_jobs == 0
            || config.repair_linger_entries == 0
            || config.requesters_per_job == 0
            || u16::try_from(config.repair_jobs).is_err()
        {
            return Err(JobsError::Capacity);
        }
        let slots = (0..config.repair_jobs)
            .map(|_| Slot {
                generation: 0,
                retired: false,
                job: None,
                requesters: Vec::with_capacity(config.requesters_per_job),
            })
            .collect();
        Ok(Self {
            config,
            slots,
            lingers: vec![None; config.repair_linger_entries],
            next_order: 0,
            counts: JobsCounts::default(),
        })
    }

    /// The counts.
    #[must_use]
    pub const fn counts(&self) -> &JobsCounts {
        &self.counts
    }

    /// Steps 6 and 7 for `request` answered in `domain` at `now`.
    pub fn join_or_create(&mut self, request: &Request, domain: Domain, now: u64) -> Joined {
        let key = JobKey {
            lane: request.lane,
            start: request.start,
            length: request.length,
            domain,
        };
        let linger = self.config.repair_linger;
        if self
            .lingers
            .iter()
            .flatten()
            .any(|entry| entry.key == key && age_ns(now, entry.since) < linger)
        {
            self.counts.bump(|c| &mut c.lingering);
            return Joined::Lingering;
        }
        let limit = self.config.requesters_per_job;
        let pending = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.job.is_some_and(|job| job.key == key));
        if let Some((at, slot)) = pending {
            let recorded = slot.requesters.contains(&request.receiver);
            let full = !recorded && slot.requesters.len() >= limit;
            if !recorded && !full {
                slot.requesters.push(request.receiver);
            }
            let generation = slot.generation;
            if full {
                self.counts.bump(|c| &mut c.requesters_full);
            }
            self.counts.bump(|c| &mut c.joined);
            return Joined::Joined(job_ref(at, generation));
        }
        let free = self.slots.iter_mut().enumerate().find_map(|(at, slot)| {
            if slot.retired || slot.job.is_some() {
                return None;
            }
            match slot.generation.checked_add(1) {
                Some(next) => {
                    slot.generation = next;
                    Some((at, slot))
                }
                None => {
                    slot.retired = true;
                    None
                }
            }
        });
        let Some((at, slot)) = free else {
            self.counts.bump(|c| &mut c.full);
            return Joined::Full;
        };
        let order = self.next_order;
        slot.requesters.clear();
        slot.requesters.push(request.receiver);
        slot.job = Some(Job {
            key,
            cursor: key.start,
            order,
        });
        let generation = slot.generation;
        // At its end the order stays: later jobs tie, served by slot, and
        // the sticky flag shows it.
        match order.checked_add(1) {
            Some(next) => self.next_order = next,
            None => self.counts.overflowed = true,
        }
        self.counts.bump(|c| &mut c.created);
        Joined::Created(job_ref(at, generation))
    }

    /// Whether `job` is still pending.
    #[must_use]
    pub fn current(&self, job: JobRef) -> bool {
        self.job(job).is_some()
    }

    /// The oldest pending job of `lane`, for the scheduler.
    #[must_use]
    pub fn next_for_lane(&self, lane: u8) -> Option<Pending> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(at, slot)| {
                slot.job
                    .as_ref()
                    .filter(|job| job.key.lane == lane)
                    .map(|job| (at, slot.generation, job))
            })
            .min_by_key(|(_, _, job)| job.order)
            .map(|(at, generation, job)| Pending {
                job: job_ref(at, generation),
                key: job.key,
                cursor: job.cursor,
            })
    }

    /// The receivers recorded on `job`, for an ERR fan-out.
    #[must_use]
    pub fn requesters(&self, job: JobRef) -> &[Receiver] {
        self.slots
            .get(usize::from(job.slot))
            .filter(|slot| slot.generation == job.generation && slot.job.is_some())
            .map_or(&[], |slot| slot.requesters.as_slice())
    }

    /// The backend submitted `job` up to `through`: its cursor moves there,
    /// never back and never past its end.
    pub fn progress(&mut self, job: JobRef, through: u64) {
        if let Some(job) = self.job_mut(job) {
            let end = job
                .key
                .start
                .checked_add(u64::from(job.key.length))
                .unwrap_or(job.key.start);
            job.cursor = job.cursor.max(through.min(end));
        }
    }

    /// The backend submitted `job`'s last frame at `now`: the job ends and
    /// its linger starts.
    pub fn done(&mut self, job: JobRef, now: u64) {
        let Some(key) = self.take(job) else {
            return;
        };
        self.counts.bump(|c| &mut c.done);
        let linger = self.config.repair_linger;
        let entry = self
            .lingers
            .iter_mut()
            .find(|entry| entry.is_none_or(|e| e.key == key || age_ns(now, e.since) >= linger));
        match entry {
            Some(entry) => *entry = Some(Linger { key, since: now }),
            None => self.counts.bump(|c| &mut c.linger_full),
        }
    }

    /// `job` failed with a known outcome (refused at its start boundary,
    /// a known rejection): it ends with no linger.
    pub fn failed(&mut self, job: JobRef) {
        if self.take(job).is_some() {
            self.counts.bump(|c| &mut c.failed);
        }
    }

    /// `job`'s submission is uncertain: it ends unresolved, with no linger
    /// and no retry; a later NAK creates a new job.
    pub fn unresolved(&mut self, job: JobRef) {
        if self.take(job).is_some() {
            self.counts.bump(|c| &mut c.unresolved);
        }
    }

    fn take(&mut self, job: JobRef) -> Option<JobKey> {
        let slot = self.slots.get_mut(usize::from(job.slot))?;
        if slot.generation != job.generation {
            return None;
        }
        slot.job.take().map(|job| job.key)
    }

    fn job(&self, job: JobRef) -> Option<&Job> {
        self.slots
            .get(usize::from(job.slot))
            .filter(|slot| slot.generation == job.generation)
            .and_then(|slot| slot.job.as_ref())
    }

    fn job_mut(&mut self, job: JobRef) -> Option<&mut Job> {
        self.slots
            .get_mut(usize::from(job.slot))
            .filter(|slot| slot.generation == job.generation)
            .and_then(|slot| slot.job.as_mut())
    }
}

fn job_ref(at: usize, generation: u64) -> JobRef {
    JobRef {
        slot: u16::try_from(at).unwrap_or(u16::MAX),
        generation,
    }
}

#[cfg(test)]
mod tests;
