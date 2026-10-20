// SPDX-License-Identifier: Apache-2.0

// The A3 gate: torn catalog updates and restarts. A workload of starts,
// stops, forgets and a compaction runs on a disk that crashes after every
// possible amount of work; for each crash, under both crash models, the
// reopened catalog must hold the state after the last update reported
// durable (or after the one in flight), and never reuse an id.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::path::Path;

use proptest::prelude::*;

use super::*;
use crate::fault::{FaultDisk, Survives};

const DIR: &str = "/archive";

fn geometry() -> Geometry {
    Geometry::new(64, 128).unwrap()
}

fn new_recording(stream_id: i32, channel: &[u8]) -> NewRecording<'_> {
    NewRecording {
        stream_id,
        session_id: 7,
        channel,
        start: 0,
        start_time_ns: 5,
        geometry: geometry(),
        policy: SyncPolicy::PerSegment,
        format: format(),
        required: false,
    }
}

fn format() -> StreamFormat {
    StreamFormat {
        lane: karyos_sys::frame::Lane::ZERO,
        initial_term_id: -3,
        mtu: core::num::NonZeroU32::new(1408).unwrap(),
        source: crate::catalog::SourceIncarnation {
            driver: [1, 2],
            registration: 3,
            incarnation: 1,
        },
    }
}

#[derive(Debug, Clone, Copy)]
enum Op {
    Start(i32),
    Stop(u64),
    Forget(u64),
    Compact,
}

/// What a workload did before it stopped.
#[derive(Debug, Default)]
struct Done {
    /// Operations that returned `Ok`, in order.
    ok: usize,
    /// The ids `start` returned.
    ids: Vec<u64>,
    /// The recordings after the open and after each operation that
    /// returned `Ok`.
    states: Vec<Vec<Recording>>,
}

fn channel_of(stream_id: i32) -> Vec<u8> {
    format!("aeron:udp?endpoint=host:{stream_id}").into_bytes()
}

/// Opens the catalog on `disk` and runs `ops` until done or failed.
fn run(disk: FaultDisk, ops: &[Op]) -> Done {
    let mut done = Done::default();
    let Ok(opened) = Catalog::open(disk, Path::new(DIR)) else {
        return done;
    };
    let mut catalog = opened.catalog;
    done.states.push(catalog.recordings().to_vec());
    for op in ops {
        let result = match *op {
            Op::Start(stream_id) => {
                let channel = channel_of(stream_id);
                catalog
                    .start(new_recording(stream_id, &channel))
                    .map(|id| done.ids.push(id))
            }
            Op::Stop(id) => catalog.stop(id, 100, 9, StopReason::Normal, false),
            Op::Forget(id) => catalog.forget(id),
            Op::Compact => catalog.compact(),
        };
        if result.is_err() {
            return done;
        }
        done.ok += 1;
        done.states.push(catalog.recordings().to_vec());
    }
    done
}

/// Reopens what `crashed` left under `survives` and checks the gate.
fn check(crashed: &FaultDisk, survives: Survives, done: &Done, model: &Done) -> Result<(), String> {
    let opened = Catalog::open(crashed.after_crash(survives), Path::new(DIR))
        .map_err(|error| format!("open failed: {error}"))?;
    let mut catalog = opened.catalog;
    let recovered = catalog.recordings().to_vec();
    let last = done.ok;
    let allowed: Vec<&Vec<Recording>> = model.states.iter().skip(last).take(2).collect();
    if done.states.is_empty() {
        // The open did not complete: nothing was ever reported.
        if !recovered.is_empty() && recovered != model.states[0] {
            return Err(format!("an unopened catalog holds {recovered:?}"));
        }
    } else if !allowed.contains(&&recovered) {
        return Err(format!(
            "after {last} reported updates the catalog holds {recovered:?}"
        ));
    }
    // Ids never repeat: the next one is above every id ever handed out,
    // including one a compaction dropped with its forgotten recording.
    let highest = done.ids.iter().copied().max().unwrap_or(0);
    let channel = channel_of(99);
    let id = catalog
        .start(new_recording(99, &channel))
        .map_err(|error| format!("start after restart: {error}"))?;
    if id <= highest || recovered.iter().any(|recording| recording.id >= id) {
        return Err(format!("id {id} reused (highest handed out {highest})"));
    }
    Ok(())
}

fn crash_everywhere(ops: &[Op]) -> Vec<String> {
    let free = FaultDisk::default();
    let model = run(free.clone(), ops);
    assert_eq!(
        model.ok,
        ops.len(),
        "the workload runs whole without faults"
    );
    let mut failures = Vec::new();
    for budget in 0..=free.used() {
        let disk = FaultDisk::with_budget(budget);
        let done = run(disk.clone(), ops);
        for survives in [Survives::Everything, Survives::Synced] {
            if let Err(failure) = check(&disk, survives, &done, &model) {
                failures.push(format!("budget {budget}, {survives:?}: {failure}"));
            }
        }
    }
    failures
}

/// The workload. Recording 3 is the highest id when it is forgotten and
/// compacted away: only the watermark keeps its id from coming back.
fn workload() -> Vec<Op> {
    vec![
        Op::Start(10),
        Op::Start(11),
        Op::Stop(1),
        Op::Start(12),
        Op::Stop(3),
        Op::Forget(3),
        Op::Compact,
        Op::Stop(2),
        Op::Forget(1),
        Op::Start(13),
        Op::Compact,
    ]
}

/// The gate: every crash point, both crash models.
#[test]
fn every_crash_point_keeps_the_reported_catalog() {
    let failures = crash_everywhere(&workload());
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Without the watermark, a compaction that drops the highest id would
/// let it come back: the gate sees it.
#[test]
fn the_watermark_keeps_a_compacted_id_used() {
    let disk = FaultDisk::default();
    let dir = Path::new(DIR);
    let mut catalog = Catalog::open(disk.clone(), dir).unwrap().catalog;
    let channel = channel_of(1);
    assert_eq!(catalog.start(new_recording(1, &channel)).unwrap(), 1);
    assert_eq!(catalog.start(new_recording(2, &channel)).unwrap(), 2);
    catalog.stop(2, 64, 9, StopReason::Normal, false).unwrap();
    catalog.forget(2).unwrap();
    catalog.compact().unwrap();
    let mut reopened = Catalog::open(disk.clone(), dir).unwrap().catalog;
    assert_eq!(reopened.next_id(), 3);
    assert_eq!(reopened.start(new_recording(3, &channel)).unwrap(), 3);
    // The compacted log starts with the watermark.
    let mut bytes = [0u8; HEADER + HEAD];
    let mut raw = disk.clone();
    let file = raw.open(&dir.join(CATALOG)).unwrap();
    raw.read_at(&file, 0, &mut bytes).unwrap();
    assert_eq!(
        u16::from_le_bytes([bytes[HEADER], bytes[HEADER + 1]]),
        NEXT_ID
    );
}

/// A torn last record is cut and reported; the records before it stay.
#[test]
fn a_torn_record_is_cut() {
    let free = FaultDisk::default();
    let ops = [Op::Start(1), Op::Start(2)];
    let _ = run(free.clone(), &ops);
    // Stop three bytes into the second record's write.
    let record = Record::Started(Recording {
        id: 2,
        stream_id: 2,
        session_id: 7,
        channel: channel_of(2),
        start: 0,
        start_time_ns: 5,
        geometry: geometry(),
        policy: SyncPolicy::PerSegment,
        format: format(),
        required: false,
        stop: None,
    })
    .encode()
    .unwrap();
    let disk = FaultDisk::with_budget(free.used() - 1 - (u64::try_from(record.len()).unwrap() - 3));
    let done = run(disk.clone(), &ops);
    assert_eq!(done.ok, 1);
    let opened = Catalog::open(disk.after_crash(Survives::Everything), Path::new(DIR)).unwrap();
    assert!(opened.cut.is_some());
    assert_eq!(opened.catalog.recordings().len(), 1);
    assert_eq!(opened.catalog.next_id(), 2);
}

/// The catalog file's bytes.
fn catalog_bytes(disk: &FaultDisk) -> Vec<u8> {
    let mut raw = disk.clone();
    let file = raw.open(&Path::new(DIR).join(CATALOG)).unwrap();
    let mut bytes = vec![0u8; usize::try_from(raw.len(&file).unwrap()).unwrap()];
    raw.read_at(&file, 0, &mut bytes).unwrap();
    bytes
}

/// Writes `bytes` at `offset` of the catalog file.
fn poke(disk: &FaultDisk, offset: u64, bytes: &[u8]) {
    let mut raw = disk.clone();
    let file = raw.open(&Path::new(DIR).join(CATALOG)).unwrap();
    raw.write_at(&file, offset, bytes).unwrap();
}

/// The offsets at which a catalog of three started recordings holds its
/// records.
fn three_started() -> (FaultDisk, [u64; 3]) {
    let disk = FaultDisk::default();
    let done = run(disk.clone(), &[Op::Start(1), Op::Start(2), Op::Start(3)]);
    assert_eq!(done.ok, 3);
    let mut offsets = [HEADER_LEN; 3];
    let mut at = HEADER_LEN;
    for (index, stream_id) in [1, 2, 3].into_iter().enumerate() {
        offsets[index] = at;
        let record = Record::Started(Recording {
            id: u64::try_from(index + 1).unwrap(),
            stream_id,
            session_id: 7,
            channel: channel_of(stream_id),
            start: 0,
            start_time_ns: 5,
            geometry: geometry(),
            policy: SyncPolicy::PerSegment,
            format: format(),
            required: false,
            stop: None,
        })
        .encode()
        .unwrap();
        at += u64::try_from(record.len()).unwrap();
    }
    (disk, offsets)
}

/// #340 review P1: a damaged record with more of the log behind it is
/// corruption, never a torn tail: the open refuses, names the offset and
/// changes nothing, so no id is reused.
#[test]
fn a_damaged_record_mid_log_is_refused() {
    let (disk, offsets) = three_started();
    let before = catalog_bytes(&disk);
    // One flipped payload byte in record 2: its CRC fails.
    let at = offsets[1] + 6;
    poke(&disk, at, &[before[usize::try_from(at).unwrap()] ^ 0x01]);
    let damaged = catalog_bytes(&disk);
    assert!(matches!(
        Catalog::open(disk.clone(), Path::new(DIR)),
        Err(CatalogError::Corrupt { offset }) if offset == offsets[1]
    ));
    assert_eq!(catalog_bytes(&disk), damaged, "nothing is changed");
    // The same flip in the last record, which reaches the end: torn.
    poke(&disk, at, &[before[usize::try_from(at).unwrap()]]);
    let last = offsets[2] + 6;
    poke(
        &disk,
        last,
        &[before[usize::try_from(last).unwrap()] ^ 0x01],
    );
    let opened = Catalog::open(disk, Path::new(DIR)).unwrap();
    assert_eq!(opened.cut, Some(offsets[2]));
    assert_eq!(opened.catalog.next_id(), 3);
}

/// #340 review P1: a whole record that does not decode, or that the state
/// before it rejects, is corruption wherever it is, the last record
/// included.
#[test]
fn a_checked_record_that_does_not_hold_is_refused() {
    let (disk, _) = three_started();
    let end = u64::try_from(catalog_bytes(&disk).len()).unwrap();
    // A Stopped of a recording that never started, with a valid CRC.
    let stray = Record::Stopped {
        id: 9,
        stop: Stop {
            position: 0,
            time_ns: 1,
            reason: StopReason::Normal,
            incomplete: false,
        },
    }
    .encode()
    .unwrap();
    poke(&disk, end, &stray);
    assert!(matches!(
        Catalog::open(disk.clone(), Path::new(DIR)),
        Err(CatalogError::Corrupt { offset }) if offset == end
    ));
    // An unknown kind under a valid CRC.
    let mut unknown = vec![9, 0, 0, 0];
    let crc = crc32c(&unknown);
    unknown.extend_from_slice(&crc.to_le_bytes());
    poke(&disk, end, &unknown);
    assert!(matches!(
        Catalog::open(disk, Path::new(DIR)),
        Err(CatalogError::Corrupt { offset }) if offset == end
    ));
}

/// A log extended over zeros (a crash after the length, before the data)
/// is a torn tail.
#[test]
fn zeros_after_the_last_record_are_a_torn_tail() {
    let (disk, _) = three_started();
    let end = u64::try_from(catalog_bytes(&disk).len()).unwrap();
    poke(&disk, end, &[0u8; 300]);
    let opened = Catalog::open(disk.clone(), Path::new(DIR)).unwrap();
    assert_eq!(opened.cut, Some(end));
    assert_eq!(opened.catalog.recordings().len(), 3);
    assert_eq!(u64::try_from(catalog_bytes(&disk).len()).unwrap(), end);
}

/// What an open must refuse with.
type Expected = fn(&CatalogError) -> bool;

/// #340 review P1: only a header shorter than its length is a catalog
/// being created; another magic or a failing CRC is corruption and
/// another version is unsupported, and the file is kept.
#[test]
fn a_whole_header_that_does_not_match_is_refused() {
    let cases: [(usize, u8, Expected); 3] = [
        (0, b'X', |error| {
            matches!(error, CatalogError::Corrupt { offset: 0 })
        }),
        (13, 0xFF, |error| {
            matches!(error, CatalogError::Corrupt { offset: 0 })
        }),
        // Version 2, the last one without a stream format.
        (4, 2, |error| {
            matches!(error, CatalogError::UnsupportedVersion { version: 2 })
        }),
    ];
    for (at, byte, expected) in cases {
        let (disk, _) = three_started();
        let mut found = catalog_bytes(&disk)[..HEADER].to_vec();
        found[at] = byte;
        if at == 4 {
            // Another version under a valid CRC.
            let crc = crc32c(&found[..12]);
            found[12..16].copy_from_slice(&crc.to_le_bytes());
        }
        poke(&disk, 0, &found);
        let damaged = catalog_bytes(&disk);
        let error = Catalog::open(disk.clone(), Path::new(DIR)).unwrap_err();
        assert!(expected(&error), "byte {at}: {error:?}");
        assert_eq!(catalog_bytes(&disk), damaged, "byte {at}: kept");
    }
    // A short header: the creation did not complete; recreated.
    let disk = FaultDisk::default();
    let mut raw = disk.clone();
    let file = raw.create(&Path::new(DIR).join(CATALOG)).unwrap();
    raw.write_at(&file, 0, &header()[..7]).unwrap();
    let opened = Catalog::open(disk, Path::new(DIR)).unwrap();
    assert_eq!(opened.cut, Some(0));
    assert!(opened.catalog.recordings().is_empty());
}

/// A compaction's leftover file is removed at the open.
#[test]
fn a_leftover_compaction_is_removed() {
    let free = FaultDisk::default();
    let ops = [Op::Start(1), Op::Compact];
    let _ = run(free.clone(), &ops);
    let before = FaultDisk::default();
    let _ = run(before.clone(), &ops[..1]);
    // Crash right after the temporary file's sync, before the rename.
    let budget = before.used() + 3;
    let disk = FaultDisk::with_budget(budget);
    let _ = run(disk.clone(), &ops);
    assert!(disk.has_crashed());
    let opened = Catalog::open(disk.after_crash(Survives::Everything), Path::new(DIR)).unwrap();
    assert!(opened.removed_temporary);
    assert_eq!(opened.catalog.recordings().len(), 1);
}

/// Settling stops a recording a crash left open at its recovered written
/// position, and one whose store never existed as empty at its start.
#[test]
fn settling_stops_what_a_crash_left_open() {
    let disk = FaultDisk::default();
    let dir = Path::new(DIR);
    let mut catalog = Catalog::open(disk.clone(), dir).unwrap().catalog;
    let channel = channel_of(1);
    let recorded = catalog.start(new_recording(1, &channel)).unwrap();
    let mut store = SegmentStore::create(
        disk.clone(),
        dir,
        recorded,
        geometry(),
        SyncPolicy::PerSegment,
        0,
    )
    .unwrap();
    store.append(0, &[5u8; 200]).unwrap();
    store.sync().unwrap();
    let empty = catalog.start(new_recording(2, &channel)).unwrap();
    // The process dies: nothing is stopped.
    drop(store);
    drop(catalog);
    let restarted = disk.after_crash(Survives::Synced);
    let mut catalog = Catalog::open(restarted.clone(), dir).unwrap().catalog;
    let settled = catalog.settle(77).unwrap();
    assert_eq!(
        settled,
        [
            Settled {
                id: recorded,
                position: 200,
                reason: StopReason::Recovered
            },
            Settled {
                id: empty,
                position: 0,
                reason: StopReason::Empty
            }
        ]
    );
    // The reasons are in the records: a reopened catalog shows them.
    let reopened = Catalog::open(restarted, dir).unwrap().catalog;
    assert_eq!(
        reopened.get(recorded).unwrap().stop,
        Some(Stop {
            position: 200,
            time_ns: 77,
            reason: StopReason::Recovered,
            incomplete: false,
        })
    );
    assert_eq!(
        reopened.get(empty).unwrap().stop.map(|stop| stop.reason),
        Some(StopReason::Empty)
    );
}

/// Refusals change nothing.
#[test]
fn refusals_change_nothing() {
    let mut catalog = Catalog::open(FaultDisk::default(), Path::new(DIR))
        .unwrap()
        .catalog;
    let long = vec![b'x'; MAX_CHANNEL + 1];
    assert!(matches!(
        catalog.start(new_recording(1, &long)),
        Err(CatalogError::ChannelTooLong { .. })
    ));
    let channel = channel_of(1);
    let id = catalog.start(new_recording(1, &channel)).unwrap();
    assert!(matches!(
        catalog.forget(id),
        Err(CatalogError::NotStopped { .. })
    ));
    assert!(matches!(
        catalog.stop(9, 0, 0, StopReason::Normal, false),
        Err(CatalogError::UnknownRecording { id: 9 })
    ));
    catalog.stop(id, 0, 0, StopReason::Normal, false).unwrap();
    assert!(matches!(
        catalog.stop(id, 0, 0, StopReason::Normal, false),
        Err(CatalogError::AlreadyStopped { .. })
    ));
    assert_eq!(catalog.next_id(), 2);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Random workloads crashed at a random point keep the gate's
    /// properties under both models.
    #[test]
    fn random_workloads_keep_the_catalog(
        choices in prop::collection::vec(0u8..4, 1..14),
        at in 0.0f64..=1.0,
    ) {
        // Build a valid sequence from the choices against a model.
        let mut ops = Vec::new();
        let mut next = 1u64;
        let mut live: Vec<(u64, bool)> = Vec::new();
        for choice in choices {
            match choice {
                0 => {
                    ops.push(Op::Start(i32::try_from(next).unwrap()));
                    live.push((next, false));
                    next += 1;
                }
                1 => {
                    if let Some(entry) = live.iter_mut().find(|(_, stopped)| !stopped) {
                        entry.1 = true;
                        ops.push(Op::Stop(entry.0));
                    }
                }
                2 => {
                    if let Some(index) = live.iter().position(|(_, stopped)| *stopped) {
                        let (id, _) = live.remove(index);
                        ops.push(Op::Forget(id));
                    }
                }
                _ => ops.push(Op::Compact),
            }
        }
        let free = FaultDisk::default();
        let model = run(free.clone(), &ops);
        prop_assert_eq!(model.ok, ops.len());
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_precision_loss)]
        let budget = (free.used() as f64 * at) as u64;
        let disk = FaultDisk::with_budget(budget);
        let done = run(disk.clone(), &ops);
        for survives in [Survives::Everything, Survives::Synced] {
            let result = check(&disk, survives, &done, &model);
            prop_assert!(result.is_ok(), "{:?}: {:?}", survives, result);
        }
    }
}

/// A4: a lapped stop and the incomplete flag round-trip, and settling a
/// recording whose segments hold a gap marks it incomplete.
#[test]
fn lapped_and_incomplete_stops_are_kept() {
    let disk = FaultDisk::default();
    let dir = Path::new(DIR);
    let mut catalog = Catalog::open(disk.clone(), dir).unwrap().catalog;
    let channel = channel_of(1);
    let lapped = catalog.start(new_recording(1, &channel)).unwrap();
    catalog
        .stop(lapped, 64, 3, StopReason::Lapped, true)
        .unwrap();
    let gapped = catalog.start(new_recording(2, &channel)).unwrap();
    let mut store = SegmentStore::create(
        disk.clone(),
        dir,
        gapped,
        geometry(),
        SyncPolicy::PerSegment,
        0,
    )
    .unwrap();
    store.append(0, &[1; 10]).unwrap();
    store.append_gap(10, 50).unwrap();
    store.append(50, &[2; 10]).unwrap();
    store.sync().unwrap();
    drop(store);
    drop(catalog);
    let restarted = disk.after_crash(Survives::Synced);
    let mut catalog = Catalog::open(restarted.clone(), dir).unwrap().catalog;
    let settled = catalog.settle(8).unwrap();
    assert_eq!(settled.len(), 1);
    let reopened = Catalog::open(restarted, dir).unwrap().catalog;
    let first = reopened.get(lapped).unwrap().stop.unwrap();
    assert_eq!((first.reason, first.incomplete), (StopReason::Lapped, true));
    let second = reopened.get(gapped).unwrap().stop.unwrap();
    assert_eq!(
        (second.position, second.reason, second.incomplete),
        (60, StopReason::Recovered, true)
    );
}

/// A catalog of format version 1 (before A4's stop reasons) is refused as
/// unsupported, and kept.
#[test]
fn a_version_1_catalog_is_unsupported() {
    let (disk, _) = three_started();
    let mut found = catalog_bytes(&disk)[..HEADER].to_vec();
    found[4..8].copy_from_slice(&1u32.to_le_bytes());
    let crc = crc32c(&found[..12]);
    found[12..16].copy_from_slice(&crc.to_le_bytes());
    poke(&disk, 0, &found);
    let kept = catalog_bytes(&disk);
    assert!(matches!(
        Catalog::open(disk.clone(), Path::new(DIR)),
        Err(CatalogError::UnsupportedVersion { version: 1 })
    ));
    assert_eq!(catalog_bytes(&disk), kept);
}

/// A `Stopped` record with a reason byte this version does not know,
/// under a valid CRC, is corruption, never mapped to a known reason.
#[test]
fn an_unknown_stop_reason_is_corrupt() {
    let (disk, _) = three_started();
    let end = u64::try_from(catalog_bytes(&disk).len()).unwrap();
    let mut stopped = Record::Stopped {
        id: 1,
        stop: Stop {
            position: 0,
            time_ns: 1,
            reason: StopReason::Stopped,
            incomplete: false,
        },
    }
    .encode()
    .unwrap();
    // Kind and length, then id, position and time: the reason follows.
    let reason = HEAD + 24;
    stopped[reason] = 0xEE;
    let crc = crc32c(&stopped[..stopped.len() - TAIL]);
    let at = stopped.len() - TAIL;
    stopped[at..].copy_from_slice(&crc.to_le_bytes());
    poke(&disk, end, &stopped);
    assert!(matches!(
        Catalog::open(disk, Path::new(DIR)),
        Err(CatalogError::Corrupt { offset }) if offset == end
    ));
}

/// A recording's stream format survives a reopen, for its replays; a
/// `Started` naming a lane no stream has, or an mtu of 0, is corrupt.
#[test]
fn the_stream_format_is_kept() {
    let disk = FaultDisk::default();
    let dir = Path::new(DIR);
    let mut catalog = Catalog::open(disk.clone(), dir).unwrap().catalog;
    let lane = karyos_sys::frame::Lane::try_new(3).unwrap();
    let format = StreamFormat {
        lane,
        initial_term_id: i32::MIN,
        mtu: core::num::NonZeroU32::new(9000).unwrap(),
        source: crate::catalog::SourceIncarnation {
            driver: [1, 2],
            registration: 3,
            incarnation: 1,
        },
    };
    let channel = channel_of(1);
    let id = catalog
        .start(NewRecording {
            format,
            ..new_recording(1, &channel)
        })
        .unwrap();
    drop(catalog);
    let reopened = Catalog::open(disk.clone(), dir).unwrap().catalog;
    assert_eq!(reopened.get(id).unwrap().format, format);
    drop(reopened);
    // The lane byte follows the policy (1) and interval (8) in the payload,
    // after the head (4): lane 4 is no lane.
    let record = Record::Started(Recording {
        id: 9,
        stream_id: 1,
        session_id: 7,
        channel,
        start: 0,
        start_time_ns: 5,
        geometry: geometry(),
        policy: SyncPolicy::PerSegment,
        format,
        required: false,
        stop: None,
    })
    .encode()
    .unwrap();
    let lane_at = HEAD + 8 + 4 + 4 + 8 + 8 + 4 + 8 + 1 + 8;
    assert_eq!(record[lane_at], 3);
    let mut payload = record[HEAD..record.len() - TAIL].to_vec();
    payload[lane_at - HEAD] = 4;
    assert!(Record::decode(STARTED, &payload).is_none());
    payload[lane_at - HEAD] = 3;
    assert!(Record::decode(STARTED, &payload).is_some());
    // The initial term id (4) follows the lane, then the mtu.
    let mtu_at = lane_at - HEAD + 1 + 4;
    assert_eq!(payload[mtu_at..mtu_at + 4], 9000u32.to_le_bytes());
    payload[mtu_at..mtu_at + 4].fill(0);
    assert!(Record::decode(STARTED, &payload).is_none());
}

/// A7d-1c: a recording's mode is kept: `required` or `async`, read back
/// after a reopen.
#[test]
fn a_recording_keeps_its_mode() {
    let disk = FaultDisk::default();
    let dir = Path::new(DIR);
    let mut catalog = Catalog::open(disk.clone(), dir).unwrap().catalog;
    let channel = channel_of(1);
    let required = catalog
        .start(NewRecording {
            required: true,
            ..new_recording(1, &channel)
        })
        .unwrap();
    let asynchronous = catalog.start(new_recording(2, &channel)).unwrap();
    drop(catalog);
    let reopened = Catalog::open(disk, dir).unwrap().catalog;
    assert!(reopened.get(required).unwrap().required);
    assert!(!reopened.get(asynchronous).unwrap().required);
}

/// The mode is the `Started` record's last payload byte, under the CRC: a
/// record written before it, without the byte, reads back as `async`; a
/// byte that is no mode is refused; and the CRC covers the byte.
#[test]
fn a_started_record_without_its_mode_reads_back_async() {
    let recording = Recording {
        id: 3,
        stream_id: 1,
        session_id: 7,
        channel: channel_of(1),
        start: 0,
        start_time_ns: 5,
        geometry: geometry(),
        policy: SyncPolicy::PerSegment,
        format: format(),
        required: true,
        stop: None,
    };
    let record = Record::Started(recording.clone()).encode().unwrap();
    let (body, crc) = record.split_at(record.len() - TAIL);
    let payload = &body[HEAD..];
    // The mode byte is last, and the CRC covers it.
    assert_eq!(payload.last(), Some(&MODE_REQUIRED));
    assert_eq!(crc, crc32c(body).to_le_bytes());
    let mut flipped = body.to_vec();
    *flipped.last_mut().unwrap() = MODE_ASYNC;
    assert_ne!(crc, crc32c(&flipped).to_le_bytes());
    // Without the byte: async.
    let older = &payload[..payload.len() - 1];
    assert_eq!(
        Record::decode(STARTED, older),
        Some(Record::Started(Recording {
            required: false,
            ..recording.clone()
        }))
    );
    // A byte that is no mode, or one too many.
    for bad in [&[0u8][..], &[3], &[MODE_REQUIRED, 0]] {
        let mut longer = older.to_vec();
        longer.extend_from_slice(bad);
        assert_eq!(Record::decode(STARTED, &longer), None, "{bad:?}");
    }
    assert_eq!(
        Record::decode(STARTED, payload),
        Some(Record::Started(recording))
    );
}

/// A catalog mixing records from before the mode byte with new ones
/// reads each as written, and keeps them through a compaction.
#[test]
fn a_mixed_catalog_keeps_each_mode() {
    let old = |recording: Recording| -> Vec<u8> {
        let record = Record::Started(recording).encode().unwrap();
        let payload = &record[HEAD..record.len() - TAIL - 1];
        let mut out = Vec::new();
        out.extend_from_slice(&STARTED.to_le_bytes());
        out.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_le_bytes());
        out.extend_from_slice(payload);
        let crc = crc32c(&out);
        out.extend_from_slice(&crc.to_le_bytes());
        out
    };
    let recording = |id: u64, required: bool| Recording {
        id,
        stream_id: 1,
        session_id: 7,
        channel: channel_of(1),
        start: 0,
        start_time_ns: 5,
        geometry: geometry(),
        policy: SyncPolicy::PerSegment,
        format: format(),
        required,
        stop: None,
    };
    let disk = FaultDisk::default();
    let dir = Path::new(DIR);
    drop(Catalog::open(disk.clone(), dir).unwrap());
    let mut bytes = old(recording(1, true));
    bytes.extend(Record::Started(recording(2, true)).encode().unwrap());
    bytes.extend(
        Record::Stopped {
            id: 1,
            stop: Stop {
                position: 0,
                time_ns: 9,
                reason: StopReason::Stopped,
                incomplete: false,
            },
        }
        .encode()
        .unwrap(),
    );
    bytes.extend(old(recording(3, true)));
    poke(&disk, HEADER_LEN, &bytes);
    let opened = Catalog::open(disk.clone(), dir).unwrap();
    assert!(opened.cut.is_none());
    let mut catalog = opened.catalog;
    assert!(!catalog.get(1).unwrap().required);
    assert!(catalog.get(2).unwrap().required);
    assert!(!catalog.get(3).unwrap().required);
    assert!(catalog.get(1).unwrap().stop.is_some());
    catalog.compact().unwrap();
    drop(catalog);
    let reopened = Catalog::open(disk, dir).unwrap().catalog;
    assert!(!reopened.get(1).unwrap().required);
    assert!(reopened.get(2).unwrap().required);
    assert!(!reopened.get(3).unwrap().required);
    assert_eq!(reopened.next_id(), 4);
}

/// H4: the read-only listing (archive-host.md) lists what the open lists,
/// through a disk that refuses every write, and changes nothing.
#[test]
fn a_listing_reads_what_the_open_reads_and_writes_nothing() {
    let (disk, _) = three_started();
    let before = catalog_bytes(&disk);
    let listing = list(crate::disk::ReadOnly(disk.clone()), Path::new(DIR)).unwrap();
    assert!(!listing.missing);
    assert_eq!(listing.behind, None);
    let opened = Catalog::open(disk.clone(), Path::new(DIR)).unwrap();
    assert_eq!(listing.recordings, opened.catalog.recordings());
    assert_eq!(listing.recordings.len(), 3);
    assert_eq!(catalog_bytes(&disk), before);
}

/// A torn last record (an Archive appending it, or a crash) is not cut:
/// the listing stops before it and reports where; the file is unchanged.
#[test]
fn a_listing_stops_at_a_torn_last_record_and_reports_it() {
    let (disk, _) = three_started();
    let end = u64::try_from(catalog_bytes(&disk).len()).unwrap();
    // A record's head whose length reaches past the end of the log.
    poke(&disk, end, &[1, 0, 200, 0, 9, 9]);
    let before = catalog_bytes(&disk);
    let listing = list(crate::disk::ReadOnly(disk.clone()), Path::new(DIR)).unwrap();
    assert_eq!(listing.recordings.len(), 3);
    assert_eq!(listing.behind, Some(end));
    assert_eq!(catalog_bytes(&disk), before, "nothing cut");
}

/// Damage before the last record is corruption, as the open judges it.
#[test]
fn a_listing_refuses_a_damaged_record_mid_log() {
    let (disk, offsets) = three_started();
    let before = catalog_bytes(&disk);
    let at = offsets[1] + 6;
    poke(&disk, at, &[before[usize::try_from(at).unwrap()] ^ 0x01]);
    assert!(matches!(
        list(crate::disk::ReadOnly(disk.clone()), Path::new(DIR)),
        Err(CatalogError::Corrupt { offset }) if offset == offsets[1]
    ));
}

/// A compaction's leftover file stays: the listing reads the catalog it
/// would replace, which holds the same recordings.
#[test]
fn a_listing_leaves_a_compactions_leftover_file() {
    let free = FaultDisk::default();
    let ops = [Op::Start(1), Op::Compact];
    let _ = run(free.clone(), &ops);
    let before = FaultDisk::default();
    let _ = run(before.clone(), &ops[..1]);
    let disk = FaultDisk::with_budget(before.used() + 3);
    let _ = run(disk.clone(), &ops);
    assert!(disk.has_crashed());
    let crashed = disk.after_crash(Survives::Everything);
    let listing = list(crate::disk::ReadOnly(crashed.clone()), Path::new(DIR)).unwrap();
    assert_eq!(listing.recordings.len(), 1);
    let mut names = crashed.clone();
    assert!(
        names
            .list(Path::new(DIR))
            .unwrap()
            .iter()
            .any(|name| name == TEMPORARY)
    );
}
