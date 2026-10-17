// SPDX-License-Identifier: Apache-2.0

// The group journal on disk: records read back exactly across segments,
// both kinds of padding, refusals that write nothing, and the torn-write
// gate: at every crash point and under every crash model, recovery keeps
// a prefix of the records appended, at least up to the durable position
// reported, and the journal continues.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::path::Path;

use karyos_sys::frame::Lane;

use super::*;
use crate::fault::{FaultDisk, Survives};
use crate::group::record::{
    Capture, Clock, EndOutcome, EventEnd, MessageEvent, Payload, TimerEvent,
};

const DIR: &str = "/groups";
const GROUP: u64 = 9;

fn config(policy: SyncPolicy) -> JournalConfig {
    JournalConfig {
        segment_length: MIN_SEGMENT_LENGTH,
        policy,
    }
}

fn header() -> JournalHeader<'static> {
    JournalHeader {
        group_id: GROUP,
        first_group_seq: 1,
        inline_threshold: 4096,
        contract_version: 1,
        clock: Clock::HostMonotonic,
        capture: Capture::Strict,
        manifest: b"0123456789",
    }
}

fn encode(record: &GroupRecord<'_>) -> Vec<u8> {
    let mut out = vec![0u8; MAX_RECORD];
    let length = record.encode(&mut out).unwrap();
    out.truncate(length);
    out
}

fn message(seq: u64, payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).unwrap();
    encode(&GroupRecord::Message(MessageEvent {
        group_seq: seq,
        logical_time: seq * 10,
        incarnation: 1,
        position: seq * 4096,
        extent: (length + 32).next_multiple_of(32),
        stream_id: 10,
        session_id: 3,
        lane: Lane::ZERO,
        payload: Payload::Inline(payload),
    }))
}

fn timer(seq: u64) -> Vec<u8> {
    encode(&GroupRecord::Timer(TimerEvent {
        group_seq: seq,
        logical_time: seq,
        timer_id: seq,
    }))
}

fn end(seq: u64) -> Vec<u8> {
    encode(&GroupRecord::End(EventEnd {
        group_seq: seq,
        observations: 0,
        outcome: EndOutcome::Complete,
    }))
}

/// Events of the given payload sizes, each a message then its end, from
/// `group_seq` 1; a payload of `None` is a timer event.
fn events(sizes: &[Option<usize>]) -> Vec<Vec<u8>> {
    let mut records = Vec::new();
    for (seq, size) in (1u64..).zip(sizes) {
        records.push(match size {
            Some(size) => {
                let payload: Vec<u8> = (0..*size)
                    .map(|byte| u8::try_from((byte + usize::try_from(seq).unwrap()) % 251).unwrap())
                    .collect();
                message(seq, &payload)
            }
            None => timer(seq),
        });
        records.push(end(seq));
    }
    records
}

/// Every record in the journal, header included, as bytes.
fn read_back(journal: &mut GroupJournal<FaultDisk>) -> Vec<Vec<u8>> {
    let mut records = Vec::new();
    journal
        .walk(0, |_, _, record| {
            records.push(encode(record));
            true
        })
        .unwrap();
    records
}

/// The header (48 bytes), then two messages that leave 20 bytes in the
/// first segment: the next record is padded with zero bytes. Then
/// messages that leave room for a fill, and a third segment.
fn spanning() -> Vec<Vec<u8>> {
    events(&[
        Some(65_535),
        Some(65_275),
        None,
        Some(60_000),
        Some(65_000),
        Some(100),
        Some(65_535),
        Some(30_000),
    ])
}

#[test]
fn records_read_back_exactly_across_segments() {
    let disk = FaultDisk::default();
    let mut journal = GroupJournal::create(
        disk.clone(),
        Path::new(DIR),
        &header(),
        config(SyncPolicy::PerSegment),
    )
    .unwrap();
    let records = spanning();
    let written = records.iter().fold(48, |at, record| {
        journal.append(record).map(|_| ()).unwrap();
        at + record.len()
    });
    assert_eq!(journal.order().next_seq(), 9);
    // The padding: written runs past the records' bytes by what it took.
    assert!(journal.written() > u64::try_from(written).unwrap());
    let mut expected = vec![encode(&GroupRecord::Header(header()))];
    expected.extend(records.iter().cloned());
    assert_eq!(read_back(&mut journal), expected);
    // Both kinds of padding were used: 20 zero bytes, then a fill.
    let first_end = u64::from(MIN_SEGMENT_LENGTH);
    let mut starts = Vec::new();
    journal
        .walk(0, |position, _, _| {
            starts.push(position);
            true
        })
        .unwrap();
    assert!(starts.contains(&first_end), "{starts:?}");
    assert!(starts.contains(&(2 * first_end)), "{starts:?}");
    // A batch appends as its records do.
    let durable = journal.close().unwrap();
    let mut journal = GroupJournal::recover(
        disk.after_crash(Survives::Synced),
        Path::new(DIR),
        GROUP,
        config(SyncPolicy::PerSegment),
    )
    .unwrap()
    .journal;
    assert_eq!(journal.written(), durable);
    assert_eq!(read_back(&mut journal), expected);
    let batch: Vec<u8> = [timer(9), end(9), timer(10), end(10)].concat();
    journal.append(&batch).unwrap();
    assert_eq!(journal.order().next_seq(), 11);
    assert_eq!(read_back(&mut journal).len(), expected.len() + 4);
}

#[test]
fn a_refused_append_writes_nothing() {
    let mut journal = GroupJournal::create(
        FaultDisk::default(),
        Path::new(DIR),
        &header(),
        config(SyncPolicy::None),
    )
    .unwrap();
    let written = journal.written();
    let order = *journal.order();
    // Out of order: a batch whose second record breaks a rule.
    let batch = [timer(1), timer(2)].concat();
    assert!(matches!(
        journal.append(&batch),
        Err(JournalError::Order(_))
    ));
    // Not whole: a record cut short, and trailing bytes.
    let cut = timer(1);
    assert!(matches!(
        journal.append(&cut[..cut.len() - 1]),
        Err(JournalError::NotWhole { .. })
    ));
    let mut trailing = [timer(1), end(1)].concat();
    trailing.push(0);
    assert!(matches!(
        journal.append(&trailing),
        Err(JournalError::NotWhole { .. })
    ));
    // A record that does not decode.
    let mut bad = timer(1);
    bad[12 + 16..12 + 24].fill(0);
    assert!(matches!(journal.append(&bad), Err(JournalError::Record(_))));
    assert_eq!((journal.written(), *journal.order()), (written, order));
    // The journal still takes valid records.
    journal.append(&[timer(1), end(1)].concat()).unwrap();
}

#[test]
fn a_segment_too_short_is_refused() {
    assert!(matches!(
        GroupJournal::create(
            FaultDisk::default(),
            Path::new(DIR),
            &header(),
            JournalConfig {
                segment_length: MIN_SEGMENT_LENGTH - 1,
                policy: SyncPolicy::None,
            },
        ),
        Err(JournalError::InvalidConfig)
    ));
}

/// Bytes that are no record, under valid CRCs (written straight through
/// the store), are corruption; so is another group's header.
#[test]
fn recovery_refuses_what_is_not_a_journal() {
    let geometry = config(SyncPolicy::None).geometry().unwrap();
    let disk = FaultDisk::default();
    let mut store = SegmentStore::create(
        disk.clone(),
        Path::new(DIR),
        GROUP,
        geometry,
        SyncPolicy::None,
        0,
    )
    .unwrap();
    let header = encode(&GroupRecord::Header(header()));
    store.append(0, &header).unwrap();
    let mut bad = timer(1);
    bad[2] = 99;
    store.append(store.written(), &bad).unwrap();
    store.close_synced().unwrap();
    let recovered = GroupJournal::recover(
        disk.after_crash(Survives::Synced),
        Path::new(DIR),
        GROUP,
        config(SyncPolicy::None),
    );
    assert!(matches!(
        recovered,
        Err(JournalError::Corrupt { position }) if position == u64::try_from(header.len()).unwrap()
    ));
    // Whole records out of order: event 2 first.
    let disk = FaultDisk::default();
    let mut store = SegmentStore::create(
        disk.clone(),
        Path::new(DIR),
        GROUP,
        geometry,
        SyncPolicy::None,
        0,
    )
    .unwrap();
    store.append(0, &header).unwrap();
    store.append(store.written(), &timer(2)).unwrap();
    store.close_synced().unwrap();
    assert!(matches!(
        GroupJournal::recover(
            disk.after_crash(Survives::Synced),
            Path::new(DIR),
            GROUP,
            config(SyncPolicy::None),
        ),
        Err(JournalError::Corrupt { position }) if position == u64::try_from(header.len()).unwrap()
    ));
    // Another group's header under this group's name.
    let disk = FaultDisk::default();
    let mut store = SegmentStore::create(
        disk.clone(),
        Path::new(DIR),
        GROUP,
        geometry,
        SyncPolicy::None,
        0,
    )
    .unwrap();
    let other = encode(&GroupRecord::Header(JournalHeader {
        group_id: GROUP + 1,
        ..self::header()
    }));
    store.append(0, &other).unwrap();
    store.close_synced().unwrap();
    assert!(matches!(
        GroupJournal::recover(
            disk.after_crash(Survives::Synced),
            Path::new(DIR),
            GROUP,
            config(SyncPolicy::None),
        ),
        Err(JournalError::Corrupt { position: 0 })
    ));
}

/// What a workload reported before it stopped.
#[derive(Debug, Clone, Copy)]
struct Reported {
    created: bool,
    durable: u64,
}

/// The workload: records appended one by one or in pairs, with syncs.
fn run(disk: FaultDisk, records: &[Vec<u8>], policy: SyncPolicy) -> Reported {
    let Ok(mut journal) = GroupJournal::create(disk, Path::new(DIR), &header(), config(policy))
    else {
        return Reported {
            created: false,
            durable: 0,
        };
    };
    let mut reported = Reported {
        created: true,
        durable: journal.durable(),
    };
    for (index, pair) in records.chunks(2).enumerate() {
        let result = if index % 2 == 0 {
            journal.append(&pair.concat()).map(drop)
        } else {
            pair.iter()
                .try_for_each(|record| journal.append(record).map(drop))
        };
        let result = result.and_then(|()| {
            if index % 3 == 2 {
                journal.sync().map(drop)
            } else {
                Ok(())
            }
        });
        reported.durable = journal.durable();
        if result.is_err() {
            return reported;
        }
    }
    if let Ok(durable) = journal.close() {
        reported.durable = durable;
    }
    reported
}

/// Recovers what `crashed` left under `survives`; `Err` names the first
/// property that fails.
fn check(
    crashed: &FaultDisk,
    survives: Survives,
    reported: Reported,
    records: &[Vec<u8>],
    policy: SyncPolicy,
) -> Result<(), String> {
    let recovered = match GroupJournal::recover(
        crashed.after_crash(survives),
        Path::new(DIR),
        GROUP,
        config(policy),
    ) {
        Ok(recovered) => recovered,
        Err(JournalError::Segment(SegmentError::NotFound { .. })) if !reported.created => {
            return Ok(());
        }
        Err(error) => return Err(format!("recovery failed: {error}")),
    };
    let mut journal = recovered.journal;
    if journal.written() < reported.durable {
        return Err(format!(
            "written {} below the reported durable {}",
            journal.written(),
            reported.durable
        ));
    }
    let mut expected = vec![encode(&GroupRecord::Header(header()))];
    expected.extend(records.iter().cloned());
    let kept = read_back(&mut journal);
    if kept.len() > expected.len() || kept[..] != expected[..kept.len()] {
        return Err(format!("{} records kept, not a prefix", kept.len()));
    }
    // It continues: the header if it was lost, then the next record.
    let next = if kept.is_empty() {
        encode(&GroupRecord::Header(header()))
    } else {
        match expected.get(kept.len()) {
            Some(record) => record.clone(),
            None => return Ok(()),
        }
    };
    journal
        .append(&next)
        .map_err(|error| format!("append after recovery: {error}"))?;
    Ok(())
}

/// The gate, under the three crash models and two policies: about 1000
/// crash points spread over the whole workload (each byte written costs a
/// unit, so most fall inside a write), and each of the first 64 units.
#[test]
fn crash_points_recover_a_prefix_of_whole_records() {
    let records = events(&[Some(65_535), Some(65_275), None, Some(60_000), Some(200)]);
    for policy in [SyncPolicy::PerSegment, SyncPolicy::None] {
        let free = FaultDisk::default();
        let _ = run(free.clone(), &records, policy);
        let mut failures = Vec::new();
        let step = usize::try_from(free.used() / 1000).unwrap().max(1);
        for budget in (0..=free.used()).step_by(step).chain(0..64) {
            let disk = FaultDisk::with_budget(budget);
            let reported = run(disk.clone(), &records, policy);
            for survives in [Survives::Everything, Survives::Synced, Survives::TornData] {
                if let Err(failure) = check(&disk, survives, reported, &records, policy) {
                    failures.push(format!("budget {budget}, {survives:?}: {failure}"));
                }
            }
        }
        assert!(failures.is_empty(), "{policy:?}: {failures:#?}");
    }
}

/// Two messages that leave 8 bytes in the first segment, fewer than an
/// envelope: the next record is padded with zero bytes, and a reader skips
/// them as padding, before and after recovery.
#[test]
fn a_tail_shorter_than_an_envelope_is_padding() {
    let disk = FaultDisk::default();
    let mut journal = GroupJournal::create(
        disk.clone(),
        Path::new(DIR),
        &header(),
        config(SyncPolicy::None),
    )
    .unwrap();
    let records = events(&[Some(65_535), Some(65_287), None]);
    for record in &records {
        journal.append(record).unwrap();
    }
    let mut starts = Vec::new();
    journal
        .walk(0, |position, _, _| {
            starts.push(position);
            true
        })
        .unwrap();
    // The timer event starts the second segment, 8 bytes after the end.
    assert_eq!(starts[starts.len() - 2], u64::from(MIN_SEGMENT_LENGTH));
    let mut expected = vec![encode(&GroupRecord::Header(header()))];
    expected.extend(records.iter().cloned());
    assert_eq!(read_back(&mut journal), expected);
    journal.close().unwrap();
    let mut journal = GroupJournal::recover(
        disk.after_crash(Survives::Synced),
        Path::new(DIR),
        GROUP,
        config(SyncPolicy::None),
    )
    .unwrap()
    .journal;
    assert_eq!(read_back(&mut journal), expected);
}
