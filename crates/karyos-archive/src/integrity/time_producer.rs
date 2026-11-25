// SPDX-License-Identifier: Apache-2.0
//! Producing time evidence entries for a recording group's journal
//! (ADR-0098; quantstratum-docs: karyos/design/trace-clocks.md,
//! "Producing time evidence entries"; karyos#1137).
//!
//! A sealed range of a group journal is a run of events, each with its
//! raw `logical_time` of the host monotonic clock (`clock` 1, SI
//! nanoseconds). [`produce`] partitions them, in position order, into
//! runs of uniform provenance first, then computes each run's smallest and
//! largest timestamps and its bounds, so each entry cites one calibration
//! record and one UTC reference record, or none.
//!
//! Provenance is established from one [`Snapshot`] of the calibration
//! journal, never assumed:
//! - the capture session's declared [`EventClock`]; without one, or for a
//!   timer scheduled in an earlier session, the entry's identity is all
//!   zero and its bounds `no_evidence`;
//! - a completeness boundary the producer confirms: the snapshot holds a
//!   calibration of the clock and a UTC reference record of its target
//!   whose validity starts after the range's largest timestamp;
//! - no loss reported up to the snapshot, exactly one calibration valid at
//!   the timestamp and exactly one UTC reference valid over its converted
//!   interval.
//!
//! Anything missing gives `no_evidence` bounds, never a clamp.

use karyos_trace::clocks::record::ClockRecord;
use karyos_trace::clocks::utc::UtcReference;
use karyos_trace::clocks::{CALIBRATION_WORDS, Calibration, ClockKey};
use karyos_trace::journal::ObserverId;
use sha2::{Digest as _, Sha256};

use super::Digest;
use super::time::{ClusterTime, Source, SyncState, classify_cluster_time};
use super::time_evidence::{Entry, NO_BOUND};

#[cfg(test)]
mod tests;

/// The unit of the group journal's `clock` 1, the host monotonic clock in
/// nanoseconds, in femtoseconds.
pub const HOST_MONOTONIC_TICK_FS: u64 = 1_000_000;

/// The epoch of a host `CLOCK_MONOTONIC` clock declared `boot` (ADR-0117,
/// point 3): the first 8 bytes, little-endian, of SHA-256 over the host's
/// boot id as its 36 ASCII characters followed by the time namespace's
/// inode as 8 bytes little-endian, with 0 replaced by 1 (0 is no epoch).
/// `CLOCK_MONOTONIC` restarts at every boot and differs between time
/// namespaces, so each pair gets its own epoch; two pairs sharing one is a
/// 64-bit hash collision, accepted.
#[must_use]
pub fn boot_epoch(boot_id: &[u8; 36], namespace_inode: u64) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(boot_id);
    hasher.update(namespace_inode.to_le_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut first = [0u8; 8];
    first.copy_from_slice(digest.first_chunk::<8>().unwrap_or(&[0; 8]));
    match u64::from_le_bytes(first) {
        0 => 1,
        epoch => epoch,
    }
}

/// [`boot_epoch`] of this process's host boot and time namespace
/// (`karyos_sys::host_clock::time_identity`), as `karyosd
/// --archive-trace-clock` and `karyos-tools calibrate --epoch boot` both
/// compute it, each in its own process.
///
/// # Errors
///
/// Either identity unreadable (and always off Linux): the caller refuses.
pub fn host_boot_epoch() -> std::io::Result<u64> {
    let (boot, namespace) = karyos_sys::host_clock::time_identity()?;
    Ok(boot_epoch(&boot, namespace))
}

/// A capture session's declared event clock (ADR-0098 item 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventClock {
    /// The calibration `from` identity: driver id low and high, journal,
    /// domain, epoch.
    pub clock: [u64; 5],
    /// Its granularity in nanoseconds; 0 not stated.
    pub granularity: u64,
}

impl EventClock {
    const fn key(&self) -> ClockKey {
        let [low, high, journal, domain, epoch] = self.clock;
        ClockKey {
            observer: ObserverId {
                driver: [low, high],
                journal,
            },
            domain,
            epoch,
        }
    }
}

/// One snapshot of a calibration journal: its known records, each with the
/// SHA-256 of its 144 bytes, and whether the journal reported a loss up to
/// the snapshot.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    calibrations: Vec<(Calibration, Digest)>,
    references: Vec<(UtcReference, Digest)>,
    lossless: bool,
}

impl Snapshot {
    /// The snapshot of `records`, a calibration journal's records read
    /// once at one durable position; `lossless` is false when the journal
    /// reported a loss up to that position. A record this build does not
    /// know, or one its type refuses, is left out: it can only make
    /// coverage incomplete, never prove it.
    #[must_use]
    pub fn new(records: &[[u64; CALIBRATION_WORDS]], lossless: bool) -> Self {
        let mut snapshot = Self {
            lossless,
            ..Self::default()
        };
        for words in records {
            let digest = record_digest(words);
            match ClockRecord::decode(words) {
                // The zero tuple is "provenance unknown": a record naming
                // it is never matched (docs#975).
                Ok(ClockRecord::Calibration(calibration))
                    if !is_zero(&calibration.from) && !is_zero(&calibration.to) =>
                {
                    snapshot.calibrations.push((calibration, digest));
                }
                Ok(ClockRecord::UtcReference(reference)) if !is_zero(&reference.clock) => {
                    snapshot.references.push((reference, digest));
                }
                // A known record that does not decode may be the one that
                // replaces or competes with another: coverage cannot be
                // established from this snapshot.
                Err(_) => snapshot.lossless = false,
                _ => {}
            }
        }
        snapshot
    }
}

/// Whether `clock` is the reserved five word zero tuple.
const fn is_zero(clock: &ClockKey) -> bool {
    matches!(clock.observer.driver, [0, 0])
        && clock.observer.journal == 0
        && clock.domain == 0
        && clock.epoch == 0
}

impl Snapshot {
    /// Whether the producer published past every in-session event of
    /// `events` for the target it would cite: each such event has a
    /// calibration of `clock` valid at its time whose target passes
    /// [`produce`]'s completeness boundary over the largest timestamp.
    /// The agent waits for this before producing a range (ADR-0098 item
    /// 3), on the same target-specific boundary `produce` checks.
    #[must_use]
    pub fn reaches(&self, clock: &EventClock, events: &[Event]) -> bool {
        let largest = events.iter().map(|event| event.time).max().unwrap_or(0);
        self.reaches_at(clock, events, largest, 0)
    }

    /// [`Snapshot::reaches`] for observations (ADR-0117, points 5 and 6):
    /// each in-session event's time is the interval `[time - width, time +
    /// width]`, which a calibration must cover, and the boundary is past
    /// the largest in-session time. Out-of-session events are not of the
    /// clock, so their times count for nothing.
    #[must_use]
    pub fn reaches_observed(&self, clock: &EventClock, events: &[Event], width: u64) -> bool {
        let largest = in_session_largest(events);
        self.reaches_at(clock, events, largest, width)
    }

    fn reaches_at(&self, clock: &EventClock, events: &[Event], largest: u64, width: u64) -> bool {
        let key = clock.key();
        events.iter().filter(|event| event.in_session).all(|event| {
            let (low, high) = widened(event.time, width);
            self.calibrations.iter().any(|(calibration, _)| {
                calibration.from == key
                    && calibration.covers(low, high)
                    && complete(self, &key, &calibration.to, largest)
            })
        })
    }
}

/// The interval of an observation at `time` taken as `[time - width,
/// time + width]`.
fn widened(time: u64, width: u64) -> (i128, i128) {
    let (time, width) = (i128::from(time), i128::from(width));
    (time - width, time + width)
}

/// The largest time of the in-session events, 0 without one.
fn in_session_largest(events: &[Event]) -> u64 {
    events
        .iter()
        .filter(|event| event.in_session)
        .map(|event| event.time)
        .max()
        .unwrap_or(0)
}

/// Where the Archive agent takes its calibration snapshots: the host's
/// view of its calibration journal (ADR-0098 item 3). Each call is one
/// snapshot, read once at one durable position.
pub trait CalibrationSource: Send + core::fmt::Debug {
    /// The journal's records now, and whether it reported no loss.
    fn snapshot(&mut self) -> Snapshot;
}

/// A fixed snapshot, for a host whose calibrations do not change.
impl CalibrationSource for Snapshot {
    fn snapshot(&mut self) -> Snapshot {
        self.clone()
    }
}

/// The SHA-256 of a record's 144 little-endian bytes.
fn record_digest(words: &[u64; CALIBRATION_WORDS]) -> Digest {
    let mut hasher = Sha256::new();
    for word in words {
        hasher.update(word.to_le_bytes());
    }
    hasher.finalize().into()
}

/// One event of a sealed group journal range: the positions its record
/// spans and its raw `logical_time`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event {
    /// Its record's first position.
    pub start: u64,
    /// Its record's end, exclusive.
    pub end: u64,
    /// Its `logical_time`: a raw reading, or a timer's deadline.
    pub time: u64,
    /// False for a timer scheduled in an earlier capture session, or
    /// whose schedule record is not found: its clock is not proven.
    pub in_session: bool,
}

/// What an event's timestamp is evidenced by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provenance {
    /// No declaration applies: identity all zero.
    Unknown,
    /// The declared clock, without authoritative coverage.
    Declared,
    /// The declared clock, the calibration and UTC reference at these
    /// indexes of the snapshot, and the offset from the clock's converted
    /// time to UTC there: a change of it (a leap, a smear, a UTC offset)
    /// starts a new entry.
    Proven(usize, usize, i128),
}

/// The entries of `group`'s sealed events, in position order, tiling
/// `[events[0].start, events[last].end)`. `clock` is the capture
/// session's declaration, if any.
#[must_use]
pub fn produce(
    group: u64,
    events: &[Event],
    clock: Option<&EventClock>,
    snapshot: &Snapshot,
) -> Vec<Entry> {
    let largest = events.iter().map(|event| event.time).max().unwrap_or(0);
    let shape = Shape { width: 0, largest };
    produce_marked(
        group,
        events,
        &vec![false; events.len()],
        clock,
        snapshot,
        shape,
    )
}

/// The entries of a recording whose events are observations (ADR-0117,
/// point 5): as [`produce`], except that each observation's time is the
/// interval `[time - width, time + width]` (the declared granularity, at
/// least the observation's own uncertainty), so a calibration must cover
/// the whole interval and each bound is computed over its ends; and the
/// completeness boundary is past the largest in-session time only, an
/// out-of-session event's time being of no declared clock.
#[must_use]
pub fn produce_observed(
    recording: u64,
    events: &[Event],
    width: u64,
    clock: Option<&EventClock>,
    snapshot: &Snapshot,
) -> Vec<Entry> {
    let shape = Shape {
        width,
        largest: in_session_largest(events),
    };
    produce_marked(
        recording,
        events,
        &vec![false; events.len()],
        clock,
        snapshot,
        shape,
    )
}

/// How the producer reads a run of events: the half-width of each
/// event's interval, and the time the completeness boundary must pass.
#[derive(Debug, Clone, Copy)]
struct Shape {
    width: u64,
    largest: u64,
}

/// The entries of a recording whose events are a Cluster log history's
/// entries, under contract C-TIME (ADR-0111, decision 5): as [`produce`],
/// except that each event is first classified by
/// [`classify_cluster_time`] against the watermark of the history before
/// it, `watermark` (0 at the log's first entry, the snapshot's log time
/// after a snapshot, `None` when the producer cannot establish it) raised
/// by every earlier event. A possibly clamped event, or one whose
/// watermark is unknown, keeps the declared clock but never a bound:
/// its raw value is unknown, so it is `no_evidence`. An event strictly
/// above the watermark is the raw clock's reading and is bounded as
/// [`produce`] bounds it. The two kinds never share an entry, so the
/// entries split where the clamp ends.
#[must_use]
pub fn produce_cluster(
    recording: u64,
    events: &[Event],
    watermark: Option<u64>,
    clock: Option<&EventClock>,
    snapshot: &Snapshot,
) -> Vec<Entry> {
    let mut mark = watermark;
    let clamped: Vec<bool> = events
        .iter()
        .map(|event| {
            let raw = classify_cluster_time(event.time, mark) == ClusterTime::Raw;
            mark = mark.map(|mark| mark.max(event.time));
            !raw
        })
        .collect();
    let largest = events.iter().map(|event| event.time).max().unwrap_or(0);
    let shape = Shape { width: 0, largest };
    produce_marked(recording, events, &clamped, clock, snapshot, shape)
}

/// [`produce`], with the events `clamped` marks never proven.
fn produce_marked(
    group: u64,
    events: &[Event],
    clamped: &[bool],
    clock: Option<&EventClock>,
    snapshot: &Snapshot,
    shape: Shape,
) -> Vec<Entry> {
    // A declaration of the reserved zero tuple declares nothing.
    let clock = clock.filter(|clock| clock.clock != [0; 5]);
    let mut entries: Vec<(Provenance, Entry)> = Vec::new();
    for (event, &clamped) in events.iter().zip(clamped) {
        let provenance = match clock {
            Some(_) if !event.in_session => Provenance::Unknown,
            None => Provenance::Unknown,
            Some(_) if clamped => Provenance::Declared,
            Some(clock) => {
                proven(snapshot, &clock.key(), event.time, shape).unwrap_or(Provenance::Declared)
            }
        };
        match entries.last_mut() {
            Some((last, entry)) if *last == provenance && entry.end == event.start => {
                entry.end = event.end;
                entry.min_time = entry.min_time.min(event.time);
                entry.max_time = entry.max_time.max(event.time);
            }
            _ => entries.push((
                provenance,
                Entry {
                    source: Source::NotStated,
                    sync_state: SyncState::NotStated,
                    clock: [0; 5],
                    recording: group,
                    start: event.start,
                    end: event.end,
                    min_time: event.time,
                    max_time: event.time,
                    granularity: 0,
                    bound_min_ns: NO_BOUND,
                    bound_max_ns: NO_BOUND,
                    calibration: [0; 32],
                    utc_reference: [0; 32],
                    tick_fs: 0,
                },
            )),
        }
    }
    entries
        .into_iter()
        .map(|(provenance, entry)| finish(provenance, entry, clock, snapshot, shape.width))
        .collect()
}

/// Whether the snapshot is lossless and holds, for `clock` into `target`
/// (the target the entry cites), a calibration and a UTC reference record
/// of that target whose validity starts after `largest`: the producer
/// published past the range for that very target.
fn complete(snapshot: &Snapshot, clock: &ClockKey, target: &ClockKey, largest: u64) -> bool {
    snapshot.lossless
        && snapshot.calibrations.iter().any(|(later, _)| {
            later.from == *clock
                && later.to == *target
                && later.valid_from > largest
                && later
                    .convert(i128::from(largest), i128::from(largest))
                    .is_some_and(|(_, high)| {
                        snapshot.references.iter().any(|(reference, _)| {
                            reference.clock == *target && i128::from(reference.valid_from) > high
                        })
                    })
        })
}

/// The unique calibration of `clock` valid over `time`'s interval and the
/// unique UTC reference valid over its converted interval, with the
/// completeness boundary of that calibration's target past the shape's
/// largest time and the UTC conversion defined over the interval, or
/// `None`.
fn proven(snapshot: &Snapshot, clock: &ClockKey, time: u64, shape: Shape) -> Option<Provenance> {
    let (from, to) = widened(time, shape.width);
    let largest = shape.largest;
    let mut calibrations = snapshot
        .calibrations
        .iter()
        .enumerate()
        .filter(|(_, (calibration, _))| calibration.from == *clock && calibration.covers(from, to));
    let (calibration_index, (calibration, _)) = calibrations.next()?;
    if calibrations.next().is_some() {
        return None;
    }
    let (low, high) = calibration.convert(from, to)?;
    let mut references = snapshot
        .references
        .iter()
        .enumerate()
        .filter(|(_, (reference, _))| {
            reference.clock == calibration.to
                && i128::from(reference.valid_from) <= low
                && high <= i128::from(reference.valid_to)
        });
    let (reference_index, (reference, _)) = references.next()?;
    if references.next().is_some() {
        return None;
    }
    if !complete(snapshot, clock, &calibration.to, largest) {
        return None;
    }
    // Defined at this timestamp (not inside an inserted second, nor past
    // the leap table), and the offset to UTC there, which partitions.
    bound(time, shape.width, calibration, reference)?;
    let middle = low.checked_add(high)?.div_euclid(2);
    let offset = reference
        .utc(u64::try_from(middle).ok()?)?
        .checked_sub(middle)?;
    Some(Provenance::Proven(
        calibration_index,
        reference_index,
        offset,
    ))
}

/// The bound at `time`: the interval `[time - width, time + width]`
/// converted through `calibration` (`width` 0: the point), its midpoint as
/// the nominal point, both ends and the midpoint to UTC by `reference`,
/// and the larger distance from that point to the ends of the UTC interval
/// widened by the reference's bound. `None` is `no_evidence`.
fn bound(
    time: u64,
    width: u64,
    calibration: &Calibration,
    reference: &UtcReference,
) -> Option<u64> {
    let (from, to) = widened(time, width);
    let (low, high) = calibration.convert(from, to)?;
    let middle = low.checked_add(high)?.div_euclid(2);
    let utc = |value: i128| reference.utc(u64::try_from(value).ok()?);
    let (low, high, middle) = (utc(low)?, utc(high)?, utc(middle)?);
    let widen = i128::from(reference.bound_ns()?);
    let low = low.checked_sub(widen)?;
    let high = high.checked_add(widen)?;
    let below = middle.checked_sub(low)?;
    let above = high.checked_sub(middle)?;
    u64::try_from(below.max(above)).ok()
}

/// Fills `entry` from its provenance.
fn finish(
    provenance: Provenance,
    mut entry: Entry,
    clock: Option<&EventClock>,
    snapshot: &Snapshot,
    width: u64,
) -> Entry {
    let Some(clock) = clock.filter(|_| provenance != Provenance::Unknown) else {
        return entry;
    };
    entry.clock = clock.clock;
    entry.granularity = clock.granularity;
    entry.tick_fs = HOST_MONOTONIC_TICK_FS;
    let Provenance::Proven(calibration_index, reference_index, _) = provenance else {
        return entry;
    };
    let (Some((calibration, calibration_digest)), Some((reference, reference_digest))) = (
        snapshot.calibrations.get(calibration_index),
        snapshot.references.get(reference_index),
    ) else {
        return entry;
    };
    entry.source = Source::from_code(reference.source as u8).unwrap_or(Source::NotStated);
    entry.sync_state =
        SyncState::from_code(reference.sync_state as u8).unwrap_or(SyncState::NotStated);
    let bounds = bound(entry.min_time, width, calibration, reference).zip(bound(
        entry.max_time,
        width,
        calibration,
        reference,
    ));
    if let Some((at_min, at_max)) = bounds {
        entry.bound_min_ns = at_min;
        entry.bound_max_ns = at_max;
        entry.calibration = *calibration_digest;
        entry.utc_reference = *reference_digest;
    }
    entry
}
