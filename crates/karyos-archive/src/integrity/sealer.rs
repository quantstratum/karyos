// SPDX-License-Identifier: Apache-2.0

//! When to seal: the schedule that bounds an open segment's unsealed
//! window by `seal_interval`, seals a segment's last range when it
//! closes, and counts the sealing backlog (SPEC.md §8.4, "Sealing and
//! tamper evidence"; karyos#662).
//!
//! The schedule runs on the control path and takes the time as an
//! argument, in nanoseconds of whatever monotonic clock the caller uses,
//! so tests drive it on a virtual clock. It holds no bytes: [`run`] asks
//! the caller to read each due range and appends its seal to the
//! [`IntegrityJournal`].
//!
//! The backlog ([`Sealer::backlog`]) is what karyos#663 needs to bound
//! during a signer outage: the ranges and bytes written but not yet
//! sealed, the ranges past their `seal_interval`, and the age of the
//! oldest unsealed byte.

use std::collections::BTreeMap;
use std::io;
use std::num::NonZeroU64;

use super::journal::{IntegrityError, IntegrityJournal};

use crate::disk::Disk;

/// What a tracked recording is, which decides how its ranges are sealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SealSource {
    /// A recording's segments, journals recorded as recordings included.
    Segments,
    /// A Cluster log recording: the caller reports the position of its
    /// commit index as written, never the appended end, and the journal
    /// refuses to seal past it in any case.
    ClusterLog,
}

/// A failure of the schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SealerError {
    /// The recording is already tracked.
    #[error("recording {recording} is already tracked for sealing")]
    Tracked {
        /// The recording.
        recording: u64,
    },
    /// The recording is not tracked.
    #[error("recording {recording} is not tracked for sealing")]
    Untracked {
        /// The recording.
        recording: u64,
    },
    /// A written position moved backwards.
    #[error("recording {recording} written to {got}, below {written}")]
    Backwards {
        /// The recording.
        recording: u64,
        /// The written position known.
        written: u64,
        /// The position reported.
        got: u64,
    },
    /// A due range no longer matches the recording's sealed position.
    #[error("recording {recording} sealed to {sealed}, the due range starts at {start}")]
    Stale {
        /// The recording.
        recording: u64,
        /// Its sealed position.
        sealed: u64,
        /// The due range's start.
        start: u64,
    },
    /// The bytes read for a due range are not exactly its length.
    #[error("recording {recording} read {got} bytes for a due range of {expected}")]
    ReadLength {
        /// The recording.
        recording: u64,
        /// The due range's length.
        expected: u64,
        /// The bytes read.
        got: u64,
    },
}

/// One recording's unsealed window.
#[derive(Debug, Clone, Copy)]
struct Window {
    source: SealSource,
    sealed: u64,
    written: u64,
    /// When the oldest unsealed byte was written, at the latest; `None`
    /// when every written byte is sealed.
    since_ns: Option<u64>,
    closed: bool,
}

/// A range to seal now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealDue {
    /// The recording.
    pub recording: u64,
    /// How to seal it.
    pub source: SealSource,
    /// The range's start, the recording's sealed position.
    pub start: u64,
    /// The range's end, exclusive.
    pub end: u64,
    /// Whether the range is a segment's last, sealed on close.
    pub closes: bool,
    /// When it was found due, in ns.
    pub due_ns: u64,
}

/// The sealing backlog at a moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SealBacklog {
    /// Recordings with bytes written but not sealed, or closed and not
    /// yet sealed on close.
    pub ranges: u64,
    /// The bytes written but not sealed.
    pub bytes: u64,
    /// The ranges past their `seal_interval` or closed: due now.
    pub overdue: u64,
    /// The age of the oldest unsealed byte, in ns; `None` when nothing is
    /// unsealed.
    pub oldest_age_ns: Option<u64>,
}

/// The sealing schedule of an archive.
#[derive(Debug, Clone)]
pub struct Sealer {
    interval_ns: NonZeroU64,
    windows: BTreeMap<u64, Window>,
}

impl Sealer {
    /// A schedule that seals each unsealed byte of an open segment within
    /// `seal_interval_ns` of its being reported written.
    #[must_use]
    pub const fn new(seal_interval_ns: NonZeroU64) -> Self {
        Self {
            interval_ns: seal_interval_ns,
            windows: BTreeMap::new(),
        }
    }

    /// The `seal_interval`, in ns.
    #[must_use]
    #[inline]
    pub const fn seal_interval_ns(&self) -> NonZeroU64 {
        self.interval_ns
    }

    /// Starts tracking `recording`, sealed up to `sealed` (its start, or
    /// where the integrity journal says its sealed ranges end).
    ///
    /// # Errors
    ///
    /// [`SealerError::Tracked`] when it already is.
    pub fn track(
        &mut self,
        recording: u64,
        source: SealSource,
        sealed: u64,
    ) -> Result<(), SealerError> {
        if self.windows.contains_key(&recording) {
            return Err(SealerError::Tracked { recording });
        }
        self.windows.insert(
            recording,
            Window {
                source,
                sealed,
                written: sealed,
                since_ns: None,
                closed: false,
            },
        );
        Ok(())
    }

    fn window(&mut self, recording: u64) -> Result<&mut Window, SealerError> {
        self.windows
            .get_mut(&recording)
            .ok_or(SealerError::Untracked { recording })
    }

    /// Reports `recording` written up to `end` at `now_ns`.
    ///
    /// # Errors
    ///
    /// [`SealerError::Untracked`], or [`SealerError::Backwards`] when `end`
    /// is below the position already reported.
    pub fn written(&mut self, recording: u64, end: u64, now_ns: u64) -> Result<(), SealerError> {
        let window = self.window(recording)?;
        if end < window.written {
            return Err(SealerError::Backwards {
                recording,
                written: window.written,
                got: end,
            });
        }
        if end > window.written && window.since_ns.is_none() {
            window.since_ns = Some(now_ns);
        }
        window.written = end;
        Ok(())
    }

    /// Reports `recording`'s segment closed at `end`: its last range is
    /// due at once.
    ///
    /// # Errors
    ///
    /// As [`Sealer::written`].
    pub fn close(&mut self, recording: u64, end: u64, now_ns: u64) -> Result<(), SealerError> {
        self.written(recording, end, now_ns)?;
        self.window(recording)?.closed = true;
        Ok(())
    }

    fn is_due(&self, window: &Window, now_ns: u64) -> bool {
        if window.closed {
            return true;
        }
        window.since_ns.is_some_and(|since| {
            since
                .checked_add(self.interval_ns.get())
                .is_none_or(|deadline| now_ns >= deadline)
        })
    }

    /// The ranges due at `now_ns`: every closed segment, and every open
    /// one whose oldest unsealed byte is `seal_interval` old.
    #[must_use]
    pub fn due(&self, now_ns: u64) -> Vec<SealDue> {
        self.windows
            .iter()
            .filter(|(_, window)| self.is_due(window, now_ns))
            .map(|(&recording, window)| SealDue {
                recording,
                source: window.source,
                start: window.sealed,
                end: window.written,
                closes: window.closed,
                due_ns: now_ns,
            })
            .collect()
    }

    /// The earliest time something becomes due, for the caller's timer;
    /// `None` when nothing is unsealed. A deadline past `u64::MAX` ns is
    /// reported as `u64::MAX`: saturating is the definition here, since
    /// a time the clock never reaches is the same as the latest one.
    #[must_use]
    pub fn next_deadline_ns(&self) -> Option<u64> {
        self.windows
            .values()
            .filter_map(|window| {
                if window.closed {
                    return Some(0);
                }
                window
                    .since_ns
                    .map(|since| since.saturating_add(self.interval_ns.get()))
            })
            .min()
    }

    /// Records `due` as sealed up to `sealed_end` (its end, or less for a
    /// Cluster log whose commit stopped short). A closed segment sealed to
    /// its end stops being tracked.
    ///
    /// # Errors
    ///
    /// [`SealerError::Untracked`], or [`SealerError::Stale`] when the
    /// recording was sealed past `due`'s start since.
    pub fn sealed(&mut self, due: &SealDue, sealed_end: u64) -> Result<(), SealerError> {
        let recording = due.recording;
        let window = self.window(recording)?;
        if window.sealed != due.start || sealed_end < due.start || sealed_end > window.written {
            return Err(SealerError::Stale {
                recording,
                sealed: window.sealed,
                start: due.start,
            });
        }
        window.sealed = sealed_end;
        // A partial seal leaves bytes of `due` itself unsealed: they have
        // been pending since the window's oldest write, so its age stays.
        // Otherwise the bytes beyond the sealed end were reported written
        // after `due` was found, so `due_ns` is no later than the oldest.
        window.since_ns = if window.written <= sealed_end {
            None
        } else if sealed_end < due.end {
            window.since_ns
        } else {
            Some(due.due_ns)
        };
        // Only a seal that carried the closure untracks the recording; a
        // close reported after `due` was found stays due.
        if window.closed && due.closes && window.written == sealed_end {
            self.windows.remove(&recording);
        }
        Ok(())
    }

    /// The sealing backlog at `now_ns`. Its counts saturate at `u64::MAX`
    /// rather than wrap, a documented exception to checked arithmetic:
    /// they are a report, never a position, and a count that large is
    /// already an alarm. An age is 0 when `now_ns` precedes the write.
    #[must_use]
    pub fn backlog(&self, now_ns: u64) -> SealBacklog {
        let mut backlog = SealBacklog::default();
        for window in self.windows.values() {
            let unsealed = window.written.saturating_sub(window.sealed);
            if unsealed == 0 && !window.closed {
                continue;
            }
            backlog.ranges = backlog.ranges.saturating_add(1);
            backlog.bytes = backlog.bytes.saturating_add(unsealed);
            if self.is_due(window, now_ns) {
                backlog.overdue = backlog.overdue.saturating_add(1);
            }
            if let Some(since) = window.since_ns {
                let age = now_ns.saturating_sub(since);
                backlog.oldest_age_ns = Some(backlog.oldest_age_ns.map_or(age, |old| old.max(age)));
            }
        }
        backlog
    }
}

/// Seals every range due at `now_ns`: `read` returns the bytes of
/// `[start, end)` of a recording, and each range's seal is appended to
/// `journal`. Stops at the first failure, which leaves the failed range
/// and those after it in the backlog. Returns the records appended.
///
/// # Errors
///
/// [`IntegrityError`] from the journal or from `read`.
pub fn run<D: Disk>(
    sealer: &mut Sealer,
    journal: &mut IntegrityJournal<D>,
    now_ns: u64,
    mut read: impl FnMut(u64, u64, u64) -> io::Result<Vec<u8>>,
) -> Result<u64, IntegrityError> {
    let mut appended = 0u64;
    for due in sealer.due(now_ns) {
        let bytes = read(due.recording, due.start, due.end)?;
        let expected = due
            .end
            .checked_sub(due.start)
            .ok_or(IntegrityError::Overflow)?;
        let got = u64::try_from(bytes.len()).map_err(|_| IntegrityError::Overflow)?;
        if got != expected {
            return Err(SealerError::ReadLength {
                recording: due.recording,
                expected,
                got,
            }
            .into());
        }
        let sealed_end = match due.source {
            SealSource::Segments => {
                if due.start == due.end && !due.closes {
                    continue;
                }
                journal
                    .seal_segment(due.recording, due.start, &bytes, due.closes)?
                    .end
            }
            SealSource::ClusterLog => journal
                .seal_cluster_log(due.recording, due.start, &bytes, due.end)?
                .map_or(due.start, |record| record.end),
        };
        if sealed_end != due.start || due.closes {
            appended = appended.checked_add(1).ok_or(IntegrityError::Overflow)?;
        }
        sealer.sealed(&due, sealed_end)?;
    }
    Ok(appended)
}
