// SPDX-License-Identifier: Apache-2.0

//! A trace recording's time evidence, produced by the agent (ADR-0117,
//! points 5 to 9, Validation): the recording of a trace stream, sealed,
//! gets its entries in the Archive's own store, each observation an
//! interval of the clock's granularity; completeness needs both later
//! records in one snapshot; past the wait, at a stop too, a range is
//! `no_evidence`; a calibration of another epoch covers nothing; a record
//! out of session gets no clock.

use std::time::Instant;

use karyos_trace::clocks::utc::{Scale, Source, SyncState, UtcReference};
use karyos_trace::clocks::{CALIBRATION_WORDS, Calibration, ClockKey};
use karyos_trace::journal::ObserverId;
use karyos_trace::stream::StreamMessage;

use super::*;
use crate::integrity::time_evidence::{DIR, Entry, NO_BOUND, read_sealed};
use crate::integrity::time_producer::Snapshot;
use crate::integrity::trace_evidence::tests::{CLOCK, OWN, facts, frame, record};

/// A source of one chunk, then pending.
struct Once(VecDeque<Vec<u8>>, u64);

impl FrameSource for Once {
    fn position(&self) -> u64 {
        self.1
    }

    fn read(&mut self, out: &mut [u8]) -> Result<Frames, SourceError> {
        let Some(chunk) = self.0.pop_front() else {
            return Ok(Frames::Pending);
        };
        let position = self.1;
        out[..chunk.len()].copy_from_slice(&chunk);
        self.1 += chunk.len() as u64;
        Ok(Frames::Copied {
            position,
            len: chunk.len(),
            next: self.1,
        })
    }

    fn consumed(&mut self, _position: u64) -> Result<(), SourceError> {
        Ok(())
    }

    fn resume(&mut self, to: u64) -> Result<u64, SourceError> {
        self.1 = to;
        Ok(to)
    }
}

fn key(domain: u64, epoch: u64) -> ClockKey {
    ClockKey {
        observer: ObserverId {
            driver: [0, 0],
            journal: 0,
        },
        domain,
        epoch,
    }
}

/// A calibration of the trace clock (domain 5) of `epoch` into
/// `CLOCK_REALTIME` (domain 4), valid over `[from, to]`.
fn calibration(epoch: u64, from: u64, to: u64) -> [u64; CALIBRATION_WORDS] {
    Calibration {
        from: key(5, epoch),
        to: key(4, epoch),
        reference: from,
        offset: 10,
        offset_uncertainty: 2,
        drift: 0,
        drift_uncertainty: 0,
        valid_from: from,
        valid_to: to,
    }
    .encode()
    .unwrap()
}

/// A UTC reference record of `CLOCK_REALTIME` of `epoch` over `[from, to]`.
fn reference(epoch: u64, from: u64, to: u64) -> [u64; CALIBRATION_WORDS] {
    UtcReference {
        clock: key(4, epoch),
        source: Source::Gnss,
        sync_state: SyncState::Synchronised,
        bound: 100,
        valid_from: from,
        valid_to: to,
        tick_fs: 1_000_000,
        scale: Scale::Tai,
        origin: 0,
        origin_scale_ns: 2_000_000_000_000_000_000,
        leap_table: 69,
        transform_uncertainty_ns: 0,
    }
    .encode()
    .unwrap()
}

/// C1 and C2 across the boundary 10 000, C3 later, and UTC references
/// before and after: complete past every observation below 20 000.
fn chain(epoch: u64) -> Vec<[u64; CALIBRATION_WORDS]> {
    vec![
        calibration(epoch, 0, 9_999),
        calibration(epoch, 10_000, 19_999),
        calibration(epoch, 30_000, 40_000),
        reference(epoch, 0, 29_999),
        reference(epoch, 30_000, 40_000),
    ]
}

/// The trace stream: self, facts of journal 7 (`provenance`), and a
/// record at each time.
fn stream(provenance: u64, times: &[u64]) -> Vec<u8> {
    let mut bytes = frame(&StreamMessage::DriverSelf(OWN));
    bytes.extend(frame(&facts(7, 1, 1, provenance)));
    for &time in times {
        bytes.extend(frame(&record(7, 1, time, 500)));
    }
    bytes
}

/// Records `bytes` as the declared trace recording of an Archive with
/// `time-evidence/` and the fixed `snapshot`, waiting `wait`; shuts it
/// down once recorded. Returns the entries, the recording's length and how
/// long the shutdown took.
fn run(
    name: &str,
    bytes: Vec<u8>,
    snapshot: Snapshot,
    wait: Duration,
) -> (Vec<Entry>, u64, Duration) {
    let dir = temp_dir(name);
    std::fs::create_dir(dir.join(DIR)).unwrap();
    let agent = ArchiveHandle::spawn(StdDisk, &dir, sealing()).unwrap();
    agent.set_calibration_source(Box::new(snapshot)).unwrap();
    agent
        .declare_trace_recording(TraceRecording::new(
            10,
            3,
            b"karyos:ipc".to_vec(),
            CLOCK,
            wait,
        ))
        .unwrap();
    let length = bytes.len() as u64;
    let id = agent
        .start(StartRecording {
            stream_id: 10,
            session_id: 3,
            channel: b"karyos:ipc".to_vec(),
            geometry: Geometry::new(4096, 65536).unwrap(),
            policy: SyncPolicy::PerSegment,
            mode: Mode::Required,
            format: format(),
            source: Box::new(Once(vec![bytes].into(), 0)),
            origin: RecordedFrom::Local,
        })
        .unwrap();
    assert_eq!(id, 1);
    std::thread::sleep(Duration::from_millis(50));
    let stopped = Instant::now();
    agent.shutdown().unwrap();
    let took = stopped.elapsed();
    let entries = read_sealed(StdDisk, &dir).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    (entries, length, took)
}

/// The entries tile `[0, length)` of recording 1, in order.
fn assert_tiled(entries: &[Entry], length: u64) {
    assert!(!entries.is_empty());
    let mut at = 0;
    for entry in entries {
        assert_eq!((entry.recording, entry.start), (1, at), "{entries:?}");
        at = entry.end;
    }
    assert_eq!(at, length, "{entries:?}");
}

/// Point 5: observations across a calibration boundary get bounded
/// entries citing C1 and C2, each the interval of the granularity.
#[test]
fn a_trace_recording_gets_bounded_entries_across_a_calibration_boundary() {
    let (entries, length, _) = run(
        "trace-met",
        stream(2, &[5_000, 6_000, 15_000]),
        Snapshot::new(&chain(77), true),
        Duration::from_secs(5),
    );
    assert_tiled(&entries, length);
    let bounded: Vec<&Entry> = entries
        .iter()
        .filter(|entry| entry.bound_max_ns != NO_BOUND)
        .collect();
    assert_eq!(bounded.len(), 2, "{entries:?}");
    assert_ne!(bounded[0].calibration, bounded[1].calibration);
    for entry in &bounded {
        assert_eq!(entry.clock, CLOCK.clock);
        assert_eq!(entry.granularity, 1000);
        // Offset uncertainty 2 and the reference's 100, over the
        // interval of 1000 each side: at least the half-width.
        assert!(
            entry.bound_min_ns >= 1000 && entry.bound_min_ns < 1200,
            "{entry:?}"
        );
    }
    assert_eq!((bounded[0].min_time, bounded[0].max_time), (5_000, 6_000));
    assert_eq!((bounded[1].min_time, bounded[1].max_time), (15_000, 15_000));
}

/// Point 6: a later calibration without a later UTC reference, or the
/// other way round, never completes a range: past the wait (here at the
/// stop) the range is `no_evidence`, with the declared clock.
#[test]
fn completeness_needs_both_later_records_in_one_snapshot() {
    let mut no_reference = chain(77);
    no_reference.remove(4);
    let mut no_calibration = chain(77);
    no_calibration.remove(2);
    for (name, records) in [
        ("trace-noref", no_reference),
        ("trace-nocal", no_calibration),
    ] {
        let wait = Duration::from_millis(200);
        let (entries, length, took) = run(
            name,
            stream(2, &[5_000, 15_000]),
            Snapshot::new(&records, true),
            wait,
        );
        assert_tiled(&entries, length);
        assert!(
            entries
                .iter()
                .all(|entry| entry.bound_max_ns == NO_BOUND && entry.clock == CLOCK.clock),
            "{entries:?}"
        );
        // Point 7: the stop waited for the calibrations first.
        assert!(took >= wait, "{took:?}");
    }
}

/// Point 3: a calibration of another epoch (another boot or namespace)
/// covers nothing.
#[test]
fn a_calibration_of_another_epoch_does_not_cover_the_run() {
    let (entries, length, _) = run(
        "trace-epoch",
        stream(2, &[5_000]),
        Snapshot::new(&chain(78), true),
        Duration::from_millis(50),
    );
    assert_tiled(&entries, length);
    assert!(entries.iter().all(|entry| entry.bound_max_ns == NO_BOUND));
}

/// Point 2: records out of session get the zero identity, never the
/// declared clock, and never a bound.
#[test]
fn a_record_out_of_session_gets_no_clock() {
    let (entries, length, _) = run(
        "trace-opaque",
        stream(0, &[5_000, 6_000]),
        Snapshot::new(&chain(77), true),
        Duration::from_millis(50),
    );
    assert_tiled(&entries, length);
    assert!(
        entries
            .iter()
            .all(|entry| entry.clock == [0; 5] && entry.bound_max_ns == NO_BOUND),
        "{entries:?}"
    );
}

/// The declaration is refused without a store, or for the zero clock.
#[test]
fn a_trace_declaration_needs_a_store_and_a_clock() {
    let dir = temp_dir("trace-refused");
    let agent = ArchiveHandle::spawn(StdDisk, &dir, sealing()).unwrap();
    let declared =
        |clock| TraceRecording::new(10, 3, b"karyos:ipc".to_vec(), clock, Duration::ZERO);
    assert!(matches!(
        agent.declare_trace_recording(declared(CLOCK)),
        Err(AgentError::NoTimeEvidence)
    ));
    let zero = crate::integrity::time_producer::EventClock {
        clock: [0; 5],
        granularity: 1,
    };
    assert!(matches!(
        agent.declare_trace_recording(declared(zero)),
        Err(AgentError::ZeroEventClock)
    ));
    agent.shutdown().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}
