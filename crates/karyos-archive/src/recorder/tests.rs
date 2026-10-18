// SPDX-License-Identifier: Apache-2.0

// The recorder over a scripted source: data, fills, laps and the seal, and
// a crash at every unit of work with a restart through the catalog.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::collections::VecDeque;
use std::path::Path;

use super::*;
use crate::catalog::{Catalog, NewRecording};
use crate::fault::{FaultDisk, Survives};
use crate::segment::{Geometry, SyncPolicy};

const DIR: &str = "/archive";

fn geometry() -> Geometry {
    Geometry::new(64, 128).unwrap()
}

/// One scripted read.
#[derive(Debug, Clone)]
enum Script {
    /// Frames of these bytes.
    Data(Vec<u8>),
    /// A fill of this extent.
    Fill(u32),
    Pending,
    Sealed,
    /// A seal at this position, wherever the source is.
    SealedAt(u64),
    /// The source is lapped: this many bytes are lost.
    Lost(u64),
}

/// A source that plays a script from `position`.
#[derive(Debug)]
struct Scripted {
    position: u64,
    script: VecDeque<Script>,
    consumed: u64,
    resumed: Vec<u64>,
    /// Resumes answered `Busy` before one succeeds.
    busy: u32,
}

impl Scripted {
    fn new(position: u64, script: Vec<Script>) -> Self {
        Self {
            position,
            script: script.into(),
            consumed: position,
            resumed: Vec::new(),
            busy: 0,
        }
    }
}

fn fill_record(position: u64) -> [u8; FILL_RECORD] {
    let mut record = [0u8; FILL_RECORD];
    record[..8].copy_from_slice(&position.to_le_bytes());
    record[8] = 0xCD;
    record
}

impl FrameSource for Scripted {
    fn position(&self) -> u64 {
        self.position
    }

    fn read(&mut self, out: &mut [u8]) -> Result<Frames, SourceError> {
        let position = self.position;
        let Some(next) = self.script.front().cloned() else {
            return Ok(Frames::Pending);
        };
        match next {
            Script::Data(bytes) => {
                let _ = self.script.pop_front();
                out[..bytes.len()].copy_from_slice(&bytes);
                self.position += bytes.len() as u64;
                Ok(Frames::Copied {
                    position,
                    len: bytes.len(),
                    next: self.position,
                })
            }
            Script::Fill(extent) => {
                let _ = self.script.pop_front();
                out[..FILL_RECORD].copy_from_slice(&fill_record(position));
                self.position += u64::from(extent);
                Ok(Frames::Fill {
                    position,
                    next: self.position,
                })
            }
            Script::Pending => {
                let _ = self.script.pop_front();
                Ok(Frames::Pending)
            }
            Script::Sealed => Ok(Frames::Sealed { at: position }),
            Script::SealedAt(at) => Ok(Frames::Sealed { at }),
            Script::Lost(length) => {
                let _ = self.script.pop_front();
                Ok(Frames::Lost {
                    from: position,
                    to: position + length,
                })
            }
        }
    }

    fn consumed(&mut self, position: u64) -> Result<(), SourceError> {
        if position > self.position {
            return Err(SourceError::Invariant);
        }
        self.consumed = position;
        Ok(())
    }

    fn resume(&mut self, to: u64) -> Result<u64, SourceError> {
        if self.busy > 0 {
            self.busy -= 1;
            return Err(SourceError::Busy);
        }
        self.resumed.push(to);
        self.position = to;
        Ok(to)
    }
}

fn data(start: usize, length: usize) -> Vec<u8> {
    (start..start + length)
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect()
}

fn recorder(disk: FaultDisk, mode: Mode, script: Vec<Script>) -> Recorder<FaultDisk, Scripted> {
    let store = SegmentStore::create(
        disk,
        Path::new(DIR),
        1,
        geometry(),
        SyncPolicy::PerSegment,
        0,
    )
    .unwrap();
    Recorder::new(store, Scripted::new(0, script), mode, 256, 1 << 20).unwrap()
}

/// Data and fills are recorded as the log holds them, consumption follows
/// the writes, and the seal ends the recording normally.
#[test]
fn data_and_fills_are_recorded_until_the_seal() {
    let script = vec![
        Script::Data(data(0, 40)),
        Script::Fill(88),
        Script::Pending,
        Script::Data(data(128, 70)),
        Script::Sealed,
    ];
    let mut recorder = recorder(FaultDisk::default(), Mode::Required, script);
    let first = recorder.duty(1).unwrap();
    assert_eq!((first.recorded, first.ended), (128, None));
    assert_eq!(recorder.source.consumed, 128);
    let second = recorder.duty(2).unwrap();
    assert_eq!(
        second.ended,
        Some(Ended {
            position: 198,
            reason: StopReason::Normal,
            incomplete: false
        })
    );
    // Ended: later duties record nothing.
    assert_eq!(recorder.duty(3).unwrap(), Duty::default());
    let mut read = vec![0u8; 40];
    recorder.store.read(0, &mut read).unwrap();
    assert_eq!(read, data(0, 40));
    let mut fill = vec![0u8; 88];
    recorder.store.read(40, &mut fill).unwrap();
    assert_eq!(fill[..FILL_RECORD], fill_record(40));
    let ended = recorder.close(StopReason::Stopped).unwrap();
    assert_eq!(ended.position, 198);
}

/// An async recording lapped with `Resume` records the gap, resumes at the
/// lowest retained position and ends incomplete; with `Stop` it ends
/// there, lapped.
#[test]
fn a_lapped_async_recording_records_the_gap() {
    let script = vec![
        Script::Data(data(0, 30)),
        Script::Lost(100),
        Script::Data(data(130, 20)),
        Script::Sealed,
    ];
    let mut resumed = recorder(
        FaultDisk::default(),
        Mode::Async {
            on_lap: OnLap::Resume,
        },
        script.clone(),
    );
    let duty = resumed.duty(1).unwrap();
    assert_eq!(
        duty.ended,
        Some(Ended {
            position: 150,
            reason: StopReason::Normal,
            incomplete: true
        })
    );
    assert_eq!(resumed.source.resumed, [130]);
    assert_eq!(resumed.store.gaps(), [(30, 130)]);

    let mut stopped = recorder(
        FaultDisk::default(),
        Mode::Async {
            on_lap: OnLap::Stop,
        },
        script,
    );
    let duty = stopped.duty(1).unwrap();
    assert_eq!(
        duty.ended,
        Some(Ended {
            position: 130,
            reason: StopReason::Lapped,
            incomplete: true
        })
    );
    assert!(stopped.source.resumed.is_empty());
}

/// A required recording is never lapped: a loss reported for it is a
/// broken contract, refused.
#[test]
fn a_required_recording_refuses_a_loss() {
    let mut recorder = recorder(FaultDisk::default(), Mode::Required, vec![Script::Lost(10)]);
    assert!(matches!(
        recorder.duty(1),
        Err(RecorderError::RequiredLapped { from: 0, to: 10 })
    ));
}

/// The budget bounds one duty's work.
#[test]
fn a_duty_keeps_to_its_budget() {
    let store = SegmentStore::create(
        FaultDisk::default(),
        Path::new(DIR),
        1,
        geometry(),
        SyncPolicy::None,
        0,
    )
    .unwrap();
    let script = (0..10).map(|i| Script::Data(data(i * 20, 20))).collect();
    let mut recorder =
        Recorder::new(store, Scripted::new(0, script), Mode::Required, 64, 50).unwrap();
    assert_eq!(recorder.duty(1).unwrap().recorded, 60);
    assert_eq!(recorder.store.written(), 60);
}

/// A recorder starts where its store is written.
#[test]
fn a_misaligned_source_is_refused() {
    let store = SegmentStore::create(
        FaultDisk::default(),
        Path::new(DIR),
        1,
        geometry(),
        SyncPolicy::None,
        10,
    )
    .unwrap();
    assert!(matches!(
        Recorder::new(store, Scripted::new(0, Vec::new()), Mode::Required, 64, 64),
        Err(RecorderError::Misaligned { .. })
    ));
}

/// A crash at every unit of a recording with a catalog: the restart settles
/// it at its recovered position, at least what was durable, with the data,
/// fills and gaps intact and the lost range marked.
#[test]
fn every_crash_point_settles_the_recording() {
    settles_at_every_crash_point(SyncPolicy::PerSegment);
}

/// #341 review P2: under no sync, a stop still syncs the store, so a
/// stopped recording's segments hold its stop position after any crash.
#[test]
fn a_stop_without_a_sync_policy_is_durable() {
    settles_at_every_crash_point(SyncPolicy::None);
}

fn settles_at_every_crash_point(policy: SyncPolicy) {
    let script = || {
        vec![
            Script::Data(data(0, 40)),
            Script::Fill(88),
            Script::Data(data(128, 50)),
            Script::Lost(60),
            Script::Data(data(238, 30)),
            Script::Sealed,
        ]
    };
    let run = |disk: FaultDisk| -> u64 {
        let dir = Path::new(DIR);
        let Ok(opened) = Catalog::open(disk.clone(), dir) else {
            return 0;
        };
        let mut catalog = opened.catalog;
        let Ok(id) = catalog.start(NewRecording {
            stream_id: 1,
            session_id: 2,
            channel: b"ipc",
            start: 0,
            start_time_ns: 0,
            geometry: geometry(),
            policy,
            format: crate::catalog::StreamFormat {
                lane: karyos_sys::frame::Lane::ZERO,
                initial_term_id: 0,
                mtu: core::num::NonZeroU32::new(1408).unwrap(),
                source: crate::catalog::SourceIncarnation {
                    driver: [1, 2],
                    registration: 3,
                    incarnation: 1,
                },
            },
        }) else {
            return 0;
        };
        let Ok(store) = SegmentStore::create(disk, dir, id, geometry(), policy, 0) else {
            return 0;
        };
        let mut durable = store.durable();
        let Ok(mut recorder) = Recorder::new(
            store,
            Scripted::new(0, script()),
            Mode::Async {
                on_lap: OnLap::Resume,
            },
            256,
            64,
        ) else {
            return durable;
        };
        for now in 0..20 {
            match recorder.duty(now) {
                Ok(duty) => {
                    durable = recorder.store().durable();
                    if duty.ended.is_some() {
                        break;
                    }
                }
                Err(_) => return durable,
            }
        }
        let Ok(ended) = recorder.close(StopReason::Stopped) else {
            return durable;
        };
        if catalog
            .stop(id, ended.position, 30, ended.reason, ended.incomplete)
            .is_ok()
        {
            return u64::MAX;
        }
        ended.position.min(durable)
    };
    let free = FaultDisk::default();
    let _ = run(free.clone());
    let mut failures = Vec::new();
    for budget in 0..=free.used() {
        let disk = FaultDisk::with_budget(budget);
        let durable = run(disk.clone());
        for survives in [Survives::Everything, Survives::Synced, Survives::TornData] {
            let restarted = disk.after_crash(survives);
            let Ok(opened) = Catalog::open(restarted.clone(), Path::new(DIR)) else {
                failures.push(format!("{policy:?} {budget} {survives:?}: catalog"));
                continue;
            };
            let mut catalog = opened.catalog;
            if catalog.settle(99).is_err() {
                failures.push(format!("{policy:?} {budget} {survives:?}: settle"));
                continue;
            }
            let Some(recording) = catalog.recordings().first() else {
                continue;
            };
            let stop = recording.stop.unwrap();
            // #341 review P2: the segments hold what the catalog's stop
            // says, whatever the policy.
            let recovered = SegmentStore::recover(
                restarted.clone(),
                Path::new(DIR),
                recording.id,
                geometry(),
                policy,
            )
            .map_or(0, |recovered| recovered.store.written());
            if recovered < stop.position {
                failures.push(format!(
                    "{budget} {survives:?}: stopped at {} but the segments hold {recovered}",
                    stop.position
                ));
            }
            if durable == u64::MAX {
                // Stopped durably: the catalog says so, normal and complete
                // but for the gap.
                if (stop.position, stop.reason, stop.incomplete) != (268, StopReason::Normal, true)
                {
                    failures.push(format!("{policy:?} {budget} {survives:?}: stop {stop:?}"));
                }
                continue;
            }
            if stop.position < durable {
                failures.push(format!(
                    "{budget} {survives:?}: stopped at {} below durable {durable}",
                    stop.position
                ));
            }
            if stop.position >= 238 && !stop.incomplete {
                failures.push(format!(
                    "{policy:?} {budget} {survives:?}: the gap is not marked"
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// A source busy at the resume after a lap is retried on later duties;
/// nothing is recorded meanwhile, and nothing is recorded twice.
#[test]
fn a_busy_resume_is_retried() {
    let script = vec![
        Script::Data(data(0, 30)),
        Script::Lost(100),
        Script::Data(data(130, 20)),
    ];
    let mut recorder = recorder(
        FaultDisk::default(),
        Mode::Async {
            on_lap: OnLap::Resume,
        },
        script,
    );
    recorder.source.busy = 2;
    assert_eq!(recorder.duty(1).unwrap().recorded, 130);
    assert_eq!(recorder.duty(2).unwrap().recorded, 0);
    assert!(recorder.source.resumed.is_empty());
    let _ = recorder.duty(3).unwrap();
    assert_eq!(recorder.source.resumed, [130]);
    assert_eq!(recorder.store.written(), 150);
    assert_eq!(recorder.store.gaps(), [(30, 130)]);
}

/// #341 review P3: a seal away from the written position, an empty copy
/// and an empty loss are refused as an invalid source, which ends the
/// recording with its store whole.
#[test]
fn an_invalid_source_is_refused() {
    let cases = [
        (
            vec![Script::Data(data(0, 40)), Script::SealedAt(30)],
            Invalid::SealNotAtWritten {
                at: 30,
                written: 40,
            },
        ),
        (
            vec![Script::Data(Vec::new())],
            Invalid::EmptyCopy { position: 0 },
        ),
        (vec![Script::Lost(0)], Invalid::EmptyLoss { from: 0, to: 0 }),
    ];
    for (script, invalid) in cases {
        let store = SegmentStore::create(
            FaultDisk::default(),
            Path::new(DIR),
            1,
            geometry(),
            SyncPolicy::PerSegment,
            0,
        )
        .unwrap();
        let mut recorder = Recorder::new(
            store,
            Scripted::new(0, script),
            Mode::Async {
                on_lap: OnLap::Resume,
            },
            256,
            1024,
        )
        .unwrap();
        let error = recorder.duty(0).unwrap_err();
        assert!(
            matches!(error, RecorderError::Invalid(found) if found == invalid),
            "{error:?}"
        );
        assert_eq!(error.fail_kind(), Some(FailKind::Invalid));
    }
}

/// #341 review P3: an async recording lapped once more than its store
/// records gaps ends there, lapped and incomplete.
#[test]
fn a_recording_out_of_gaps_ends_lapped() {
    let mut script = Vec::new();
    for _ in 0..=crate::segment::MAX_GAPS {
        script.push(Script::Data(vec![7]));
        script.push(Script::Lost(1));
    }
    let store = SegmentStore::create(
        FaultDisk::default(),
        Path::new(DIR),
        1,
        Geometry::new(64, 64 * 1024).unwrap(),
        SyncPolicy::None,
        0,
    )
    .unwrap();
    let mut recorder = Recorder::new(
        store,
        Scripted::new(0, script),
        Mode::Async {
            on_lap: OnLap::Resume,
        },
        256,
        u64::MAX,
    )
    .unwrap();
    let duty = recorder.duty(0).unwrap();
    let last = 2 * u64::try_from(crate::segment::MAX_GAPS).unwrap() + 1;
    assert_eq!(
        duty.ended,
        Some(Ended {
            position: last,
            reason: StopReason::Lapped,
            incomplete: true,
        })
    );
    assert_eq!(recorder.store().gaps().len(), crate::segment::MAX_GAPS);
}

/// Each duty stamps its writes with its time: a replay at the recorded
/// pace waits the duties' difference between them.
#[test]
fn a_duty_stamps_its_writes_with_its_time() {
    let disk = FaultDisk::default();
    // A frame of 64 bytes, then one of 32: replay checks frame lengths.
    let frame = |length: usize| {
        let mut frame = data(0, length);
        frame[..4].copy_from_slice(&i32::try_from(length).unwrap().to_le_bytes());
        frame
    };
    let script = vec![
        Script::Data(frame(64)),
        Script::Pending,
        Script::Data(frame(32)),
    ];
    let mut recorder = recorder(disk.clone(), Mode::Required, script);
    recorder.duty(500).unwrap();
    recorder.duty(1700).unwrap();
    let mut replay = crate::replay::ReplaySource::open(
        disk,
        Path::new(DIR),
        1,
        geometry(),
        0,
        96,
        crate::replay::Rate::AsRecorded,
        256,
    )
    .unwrap();
    assert!(matches!(
        replay.poll(0),
        Ok(crate::replay::Step::Frames { position: 0, .. })
    ));
    assert_eq!(
        replay.poll(1).unwrap(),
        crate::replay::Step::Wait { until_ns: 1200 }
    );
}
