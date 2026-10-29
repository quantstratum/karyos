// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::AtomicBool;

use super::*;
use crate::freshness::{Freshness, FreshnessLink, Terminal, TerminalCell};
use crate::sync::{AtomicU64, Ordering};

const BUDGET: Budget = Budget::new(64, 4);

fn value(key: u32, round: u32, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8) ^ (key as u8).wrapping_mul(7) ^ (round as u8))
        .collect()
}

/// Polls until nothing is pending and no scan runs; returns the deliveries.
fn drain(reader: &mut ConflationReader, budget: Budget) -> Vec<(u32, u64, Vec<u8>)> {
    let mut seen = Vec::new();
    let mut settled = false;
    for _ in 0..1000 {
        let report = reader.poll_changed(budget, |key, version, value, _| {
            seen.push((key, version, value.to_vec()));
        });
        if report.journal_drained && report.pending == 0 && !report.scanning {
            settled = true;
            break;
        }
    }
    assert!(settled, "the reader did not settle");
    seen
}

#[test]
fn configuration_is_checked() {
    assert_eq!(
        conflation(0, 8, 1024).err(),
        Some(ConflationError::InvalidConfig)
    );
    assert_eq!(
        conflation(4, 0, 1024).err(),
        Some(ConflationError::InvalidConfig)
    );
    assert_eq!(
        conflation(4, 8, 1000).err(),
        Some(ConflationError::InvalidConfig)
    );
    assert_eq!(
        conflation(u32::MAX, usize::MAX / 2, 1024).err(),
        Some(ConflationError::InvalidConfig)
    );
}

#[test]
fn publication_config_rejects_invalid_keys_and_oversized_values() {
    let config = ConflationConfig {
        keys: 3,
        value_capacity: 8,
        journal_capacity: 1024,
        refresh: false,
    };
    assert_eq!(config.validate_publication(0, 8), Ok(()));
    assert_eq!(
        config.validate_publication(-1, 1),
        Err(ConflationError::KeyOutOfRange { key: -1 })
    );
    assert_eq!(
        config.validate_publication(i64::from(u32::MAX) + 1, 1),
        Err(ConflationError::KeyOutOfRange {
            key: i64::from(u32::MAX) + 1
        })
    );
    assert_eq!(
        config.validate_publication(3, 1),
        Err(ConflationError::KeyOutOfRange { key: 3 })
    );
    assert_eq!(
        config.validate_publication(1, 9),
        Err(ConflationError::ValueTooLarge { length: 9, max: 8 })
    );
}

/// ADR-0080: with `refresh`, a publication may carry a refresh value of a
/// key in range and a marker of exactly 24 bytes, whatever the value
/// capacity; a refresh value out of range, a marker of another length and
/// a negative value that is neither stay refused. Without it, both are
/// rejected keys, as before.
#[test]
fn a_refresh_table_admits_cycle_traffic() {
    use super::cycle::{CycleId, MARKER_LENGTH, marker, value};
    let plain = ConflationConfig::new(3, 8, 1024);
    let config = plain.with_refresh();
    let cycle = CycleId::MAX;
    let refresh = value(cycle, 2).unwrap();
    assert_eq!(config.validate_publication(refresh, 8), Ok(()));
    assert_eq!(
        config.validate_publication(refresh, 9),
        Err(ConflationError::ValueTooLarge { length: 9, max: 8 })
    );
    let outside = value(cycle, 3).unwrap();
    assert_eq!(
        config.validate_publication(outside, 1),
        Err(ConflationError::KeyOutOfRange { key: outside })
    );
    assert_eq!(
        config.validate_publication(marker(cycle), MARKER_LENGTH),
        Ok(())
    );
    assert_eq!(
        config.validate_publication(marker(cycle), MARKER_LENGTH - 1),
        Err(ConflationError::KeyOutOfRange { key: marker(cycle) })
    );
    assert_eq!(
        config.validate_publication(i64::from(u32::MAX) + 1, 1),
        Err(ConflationError::KeyOutOfRange {
            key: i64::from(u32::MAX) + 1
        })
    );
    for traffic in [refresh, marker(cycle)] {
        assert_eq!(
            plain.validate_publication(traffic, MARKER_LENGTH.min(8)),
            Err(ConflationError::KeyOutOfRange { key: traffic })
        );
    }
    assert!(!plain.refresh && config.refresh);
    assert_eq!(config.shape().map(|shape| shape.refresh), Ok(true));
}

/// SPEC §14: a value capacity past `u32`, which no message carries, has no
/// shape: it is refused, never saturated to `u32::MAX`, and a publication
/// check of such a table fails with that refusal. The capacity `u32::MAX`
/// itself still has one.
#[cfg(target_pointer_width = "64")]
#[test]
fn a_capacity_past_u32_has_no_shape() {
    let largest = usize::try_from(u32::MAX).unwrap();
    let past = largest + 1;
    let config = ConflationConfig {
        keys: 3,
        value_capacity: past,
        journal_capacity: 1024,
        refresh: false,
    };
    let refused = ConflationError::ValueTooLarge {
        length: past,
        max: largest,
    };
    assert_eq!(config.shape(), Err(refused));
    assert_eq!(config.validate_publication(0, 1), Err(refused));
    let largest_config = ConflationConfig {
        value_capacity: largest,
        ..config
    };
    assert_eq!(
        largest_config.shape(),
        Ok(crate::log_buffer::ConflationShape::new(3, u32::MAX))
    );
    assert_eq!(largest_config.validate_publication(0, largest), Ok(()));
}

#[test]
fn every_length_round_trips_and_shorter_values_leave_no_stale_bytes() {
    let mut writer = conflation(2, 40, 1024).unwrap();
    let mut reader = writer.reader();
    for len in (0..=40).rev() {
        let data = value(1, len as u32, len);
        let version = writer.write(1, &data).unwrap();
        let seen = drain(&mut reader, BUDGET);
        assert_eq!(seen, vec![(1, version, data)], "length {len}");
    }
}

#[test]
fn writes_are_bounded_and_refused_without_effect() {
    let mut writer = conflation(2, 16, 1024).unwrap();
    let mut reader = writer.reader();
    assert_eq!(
        writer.write(2, b"x"),
        Err(ConflationError::KeyOutOfRange { key: 2 })
    );
    assert_eq!(
        writer.write(0, &[0; 17]),
        Err(ConflationError::ValueTooLarge {
            length: 17,
            max: 16
        })
    );
    assert!(drain(&mut reader, BUDGET).is_empty());
}

#[test]
fn intermediate_versions_are_skipped_and_never_go_backwards() {
    let mut writer = conflation(3, 8, 1024).unwrap();
    let mut reader = writer.reader();
    for round in 0..5 {
        writer.write(0, &value(0, round, 8)).unwrap();
    }
    let last = writer.write(0, &value(0, 9, 8)).unwrap();
    let seen = drain(&mut reader, BUDGET);
    assert_eq!(seen, vec![(0, last, value(0, 9, 8))]);
    assert_eq!(reader.delivered_version(0), Some(last));
    // Nothing new: nothing delivered again.
    assert!(drain(&mut reader, BUDGET).is_empty());
}

#[test]
fn a_new_reader_scans_existing_values() {
    let mut writer = conflation(70, 8, 1024).unwrap();
    for key in (0..70).step_by(3) {
        writer.write(key, &value(key, 1, 8)).unwrap();
    }
    let mut reader = writer.reader();
    let mut seen: Vec<u32> = drain(&mut reader, Budget::new(5, 1))
        .into_iter()
        .map(|(key, ..)| key)
        .collect();
    seen.sort_unstable();
    assert_eq!(seen, (0..70).step_by(3).collect::<Vec<_>>());
}

/// SPEC §14: the reader's queue holds each key at most once, so its length
/// (a `u32`) reaches `keys` and never passes it. Every slot stuck
/// mid-write keeps every key queued (unstable, requeued); once released,
/// every key is delivered.
#[test]
fn the_pending_count_reaches_the_keys_and_stops() {
    let keys = 4;
    let mut writer = conflation(keys, 8, 1024).unwrap();
    for key in 0..keys {
        writer.write(key, &value(key, 1, 8)).unwrap();
    }
    let mut reader = writer.reader();
    // Every slot is stuck: a writer paused between its odd and even stores.
    let mut stuck = Vec::new();
    for key in 0..keys {
        let word = writer.slot_seq_word(key).unwrap();
        let even = word.load(Ordering::Relaxed);
        word.store(even + 1, Ordering::Relaxed);
        stuck.push((key, even));
    }
    let all = Budget { keys, retries: 1 };
    let mut most = 0;
    for _ in 0..16 {
        let report = reader.poll_changed(all, |_, _, _, _| panic!("a stuck slot was delivered"));
        assert!(report.pending <= keys, "pending {}", report.pending);
        most = most.max(report.pending);
    }
    assert_eq!(most, keys, "every key was queued at once");
    for (key, even) in stuck {
        writer
            .slot_seq_word(key)
            .unwrap()
            .store(even, Ordering::Relaxed);
    }
    let mut seen: Vec<u32> = drain(&mut reader, all)
        .into_iter()
        .map(|(key, ..)| key)
        .collect();
    seen.sort_unstable();
    assert_eq!(seen, (0..keys).collect::<Vec<_>>());
}

/// The journal laps the reader; it scans and still converges.
#[test]
fn a_lapped_reader_scans_and_converges() {
    let mut writer = conflation(200, 8, 1024).unwrap();
    let mut reader = writer.reader();
    let _ = drain(&mut reader, BUDGET);
    for round in 0..3 {
        for key in 0..200 {
            writer.write(key, &value(key, round, 8)).unwrap();
        }
    }
    let mut lapped = false;
    let mut latest = vec![None; 200];
    for _ in 0..1000 {
        let report = reader.poll_changed(Budget::new(7, 2), |key, _, value, _| {
            latest[key as usize] = Some(value.to_vec());
        });
        lapped |= report.lapped;
        if report.journal_drained && report.pending == 0 && !report.scanning {
            break;
        }
    }
    assert!(
        lapped,
        "the journal of 1024 bytes holds far fewer than 600 records"
    );
    for key in 0..200 {
        assert_eq!(latest[key as usize], Some(value(key, 2, 8)), "key {key}");
    }
}

/// ADR-0017 case: journal overflow, a key budget of one, one permanently
/// odd slot and an update to the last key. Every poll is bounded and the
/// other keys converge.
#[test]
fn a_stuck_slot_does_not_starve_the_others() {
    let mut writer = conflation(8, 8, 1024).unwrap();
    let mut reader = writer.reader();
    let _ = drain(&mut reader, BUDGET);
    for round in 0..100 {
        for key in 0..8 {
            writer.write(key, &value(key, round, 8)).unwrap();
        }
    }
    // Key 3 is stuck mid-write: a writer paused between its odd and even
    // stores.
    let odd = writer.slot_seq_word(3).unwrap().load(Ordering::Relaxed) + 1;
    writer
        .slot_seq_word(3)
        .unwrap()
        .store(odd, Ordering::Relaxed);
    writer.write(7, &value(7, 500, 8)).unwrap();
    let mut latest = vec![None; 8];
    for _ in 0..200 {
        let report = reader.poll_changed(Budget::new(1, 1), |key, _, value, _| {
            latest[key as usize] = Some(value.to_vec());
        });
        assert!(report.delivered + report.skipped + report.unstable <= 1);
    }
    for key in [0, 1, 2, 4, 5, 6] {
        assert_eq!(latest[key as usize], Some(value(key, 99, 8)), "key {key}");
    }
    assert_eq!(latest[7], Some(value(7, 500, 8)));
    assert_eq!(latest[3], None);
}

#[test]
fn version_exhaustion_closes_the_table() {
    let mut writer = conflation(2, 8, 1024).unwrap();
    let mut reader = writer.reader();
    writer.seed_version(1, u64::MAX - 1);
    assert_eq!(
        writer.write(1, b"late"),
        Err(ConflationError::VersionsExhausted)
    );
    assert_eq!(writer.write(0, b"other"), Err(ConflationError::Closed));
    // The refused write stored nothing; the reader sees the table closed.
    assert_eq!(
        writer.slot_version_word(1).unwrap().load(Ordering::Relaxed),
        u64::MAX - 1
    );
    let report = reader.poll_changed(BUDGET, |_, _, _, _| {});
    assert!(report.closed);
}

#[test]
fn dropping_the_writer_closes_and_values_stay_readable() {
    let mut writer = conflation(2, 8, 1024).unwrap();
    let mut reader = writer.reader();
    let version = writer.write(1, b"final").unwrap();
    drop(writer);
    let mut seen = Vec::new();
    let report = reader.poll_changed(BUDGET, |key, version, value, _| {
        seen.push((key, version, value.to_vec()));
    });
    assert!(report.closed);
    assert_eq!(seen, vec![(1, version, b"final".to_vec())]);
}

#[test]
fn a_panicking_handler_does_not_lose_its_key() {
    let mut writer = conflation(2, 8, 1024).unwrap();
    let mut reader = writer.reader();
    let version = writer.write(0, b"v").unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        reader.poll_changed(BUDGET, |_, _, _, _| panic!("handler"));
    }));
    assert!(result.is_err());
    assert_eq!(reader.delivered_version(0), Some(0));
    let seen = drain(&mut reader, BUDGET);
    assert_eq!(seen, vec![(0, version, b"v".to_vec())]);
}

/// A writer updating keys while readers poll; after it stops, every reader
/// converges to the final value of every key, and every delivered value is
/// a complete written value.
#[test]
fn concurrent_writer_and_readers_converge() {
    let keys = 16u32;
    let rounds: u32 = if cfg!(miri) { 20 } else { 2000 };
    let mut writer = conflation(keys, 24, 1024).unwrap();
    let readers: Vec<_> = (0..2).map(|_| writer.reader()).collect();
    let done = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let handles: Vec<_> = readers
            .into_iter()
            .map(|mut reader| {
                let done = &done;
                scope.spawn(move || {
                    let mut latest = vec![None; keys as usize];
                    loop {
                        let finished = done.load(Ordering::Acquire);
                        let report =
                            reader.poll_changed(Budget::new(4, 2), |key, version, data, _| {
                                let round = u32::from(data[0] ^ (key as u8).wrapping_mul(7));
                                assert_eq!(data, &value(key, round, 24)[..]);
                                latest[key as usize] = Some((version, data.to_vec()));
                            });
                        if finished
                            && report.journal_drained
                            && report.pending == 0
                            && !report.scanning
                        {
                            // One more full pass after the writer stopped.
                            break latest;
                        }
                        std::thread::yield_now();
                    }
                })
            })
            .collect();
        for round in 0..rounds {
            let key = round % keys;
            writer.write(key, &value(key, round, 24)).unwrap();
        }
        done.store(true, Ordering::Release);
        let finals: Vec<Option<Vec<u8>>> = (0..keys)
            .map(|key| {
                let last = (0..rounds).rev().find(|round| round % keys == key);
                last.map(|round| value(key, round, 24))
            })
            .collect();
        for handle in handles {
            let latest = handle.join().unwrap();
            for key in 0..keys as usize {
                assert_eq!(
                    latest[key].as_ref().map(|(_, data)| data.clone()),
                    finals[key],
                    "key {key}"
                );
            }
        }
    });
}

#[test]
fn slot_words_need_a_value_word() {
    let words: Vec<AtomicU64> = (0..2).map(|_| AtomicU64::new(0)).collect();
    assert!(SlotWords::new(&words).is_none());
}

/// A writer that stops after committing a value but before its journal
/// record (here: the slot written directly, with no record) is still found
/// by the background sweep of a caught-up reader.
#[test]
fn a_value_without_a_journal_record_is_found_by_the_sweep() {
    let writer = conflation(40, 8, 1024).unwrap();
    let mut reader = writer.reader();
    let _ = drain(&mut reader, BUDGET);
    let version = writer.table_slot(33).unwrap().write(b"silent").unwrap();
    let mut seen = Vec::new();
    for _ in 0..40 {
        reader.poll_changed(Budget::new(1, 1), |key, version, value, _| {
            seen.push((key, version, value.to_vec()));
        });
    }
    assert_eq!(seen, vec![(33, version, b"silent".to_vec())]);
}

/// A reader created after the writer stopped delivers every value.
#[test]
fn a_late_reader_after_overflow_delivers_everything() {
    let mut writer = conflation(50, 8, 1024).unwrap();
    for round in 0..4 {
        for key in 0..50 {
            writer.write(key, &value(key, round, 8)).unwrap();
        }
    }
    drop(writer.reader());
    let mut reader = writer.reader();
    let mut latest = vec![None; 50];
    for _ in 0..100 {
        reader.poll_changed(Budget::new(3, 1), |key, _, value, _| {
            latest[key as usize] = Some(value.to_vec());
        });
    }
    for key in 0..50 {
        assert_eq!(latest[key as usize], Some(value(key, 3, 8)));
    }
}

/// Journal positions near exhaustion: the write is refused before the slot
/// changes and the table closes.
#[test]
fn journal_exhaustion_is_refused_before_the_slot_changes() {
    let mut writer = conflation(2, 8, 1024).unwrap();
    let mut reader = writer.reader();
    // Aligned to 8, as every journal position is; 2^64 - 64.
    writer.seed_journal(u64::MAX - 63);
    assert_eq!(
        writer.write(0, b"x"),
        Err(ConflationError::VersionsExhausted)
    );
    assert_eq!(
        writer.slot_version_word(0).unwrap().load(Ordering::Relaxed),
        0
    );
    assert_eq!(writer.write(1, b"y"), Err(ConflationError::Closed));
    let report = reader.poll_changed(BUDGET, |_, _, _, _| {});
    assert!(report.closed);
}

/// Values written before the close are still delivered; `finished` comes
/// only after them.
#[test]
fn closing_delivers_unread_values_before_finishing() {
    let mut writer = conflation(30, 8, 1024).unwrap();
    let mut reader = writer.reader();
    let _ = drain(&mut reader, BUDGET);
    for key in 0..30 {
        writer.write(key, &value(key, 1, 8)).unwrap();
    }
    writer.close();
    let mut delivered = 0;
    let mut finished = false;
    for _ in 0..100 {
        let report = reader.poll_changed(Budget::new(2, 1), |_, _, _, _| {
            delivered += 1;
        });
        assert!(report.closed);
        if report.finished {
            finished = true;
            break;
        }
    }
    assert!(finished);
    assert_eq!(delivered, 30);
}

#[test]
fn a_zero_budget_does_nothing() {
    let mut writer = conflation(2, 8, 1024).unwrap();
    let mut reader = writer.reader();
    writer.write(0, b"v").unwrap();
    let report = reader.poll_changed(Budget::new(0, 5), |_, _, _, _| unreachable!());
    assert_eq!(report.delivered, 0);
    assert!(report.scanning);
}

/// Tables in shared regions (Linux; `quantstratum-docs:
/// karyos/design/conflation-end-to-end.md`, Cross-process views).
#[cfg(target_os = "linux")]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#[allow(clippy::unwrap_used)]
mod region {
    use super::*;
    use crate::error::SysError;
    use crate::ipc::{ReadOnlyRegion, Region, RegionKind, RegionRecord, SealProfile};

    /// The configuration of the tables these tests create.
    // `new`, not a literal: a field added later keeps this Linux-only
    // module compiling.
    const CONFIG: ConflationConfig = ConflationConfig::new(2, 8, 1024);

    fn table() -> ConflationWriter {
        conflation_in(
            7,
            3,
            CONFIG.keys,
            CONFIG.value_capacity,
            CONFIG.journal_capacity,
        )
        .unwrap()
    }

    /// Attaches `region` read-only, as a view does with its grant: the
    /// creator's descriptor reopened read-only, its record, `profile` and
    /// the granted configuration `expected`.
    fn view_of(
        region: &Region,
        record: RegionRecord,
        profile: SealProfile,
        expected: ConflationConfig,
    ) -> Result<ConflationReader, SysError> {
        ConflationReader::attach_read_only(
            ReadOnlyRegion::attach(region.read_only_descriptor()?, record, profile)?,
            expected,
        )
    }

    fn view(writer: &ConflationWriter) -> Result<ConflationReader, SysError> {
        view_expecting(writer, writer.config())
    }

    fn view_expecting(
        writer: &ConflationWriter,
        expected: ConflationConfig,
    ) -> Result<ConflationReader, SysError> {
        let region = writer.region().unwrap();
        view_of(region, region.record(), SealProfile::DriverOnly, expected)
    }

    /// A read-only view delivers what the writer wrote, the latest value
    /// of each key with versions never going backwards, and sees the close.
    #[test]
    fn a_read_only_view_reads_a_table_in_a_region() {
        let mut writer = conflation_in(7, 3, 5, 20, 1024).unwrap();
        let record = writer.region().unwrap().record();
        assert_eq!(record.kind, RegionKind::ConflationTable);
        assert_eq!(record.layout, LAYOUT_VERSION);
        assert!(writer.reader().config() == writer.config());
        writer.write(1, b"before the view").unwrap();
        let mut reader = view(&writer).unwrap();
        assert_eq!(reader.config(), writer.config());
        assert_eq!(reader.config(), ConflationConfig::new(5, 20, 1024));
        // The first scan delivers what was written before the attach.
        let seen = drain(&mut reader, BUDGET);
        assert_eq!(seen, vec![(1, 2, b"before the view".to_vec())]);
        let mut latest = vec![(0u64, Vec::new()); 5];
        let mut delivered = vec![(0u64, Vec::new()); 5];
        delivered[1] = (2, b"before the view".to_vec());
        for round in 0..200u32 {
            let key = round * 3 % 5;
            let value = value(key, round, (round % 20) as usize + 1);
            let version = writer.write(key, &value).unwrap();
            latest[key as usize] = (version, value);
            if round % 37 == 0 || round == 199 {
                for (key, version, value) in drain(&mut reader, BUDGET) {
                    assert!(version > delivered[key as usize].0);
                    delivered[key as usize] = (version, value);
                }
            }
        }
        assert_eq!(delivered, latest);
        // The values delivered last are the latest ones.
        writer.write(4, b"last").unwrap();
        let seen = drain(&mut reader, BUDGET);
        assert_eq!(
            seen.last().map(|(key, _, value)| (*key, value.as_slice())),
            Some((4, &b"last"[..]))
        );
        writer.close();
        let report = reader.poll_changed(BUDGET, |_, _, _, _| {});
        assert!(report.closed);
        let report = reader.poll_changed(BUDGET, |_, _, _, _| unreachable!());
        assert!(report.finished);
    }

    /// A view whose journal laps it scans the slots and still converges on
    /// the latest values.
    #[test]
    fn a_lapped_view_scans_and_converges() {
        let mut writer = conflation_in(7, 3, 8, 8, 1024).unwrap();
        let mut reader = view(&writer).unwrap();
        drain(&mut reader, BUDGET);
        let mut lapped = false;
        for round in 0..200u32 {
            writer.write(round % 8, &round.to_le_bytes()).unwrap();
        }
        let mut seen = Vec::new();
        for _ in 0..1000 {
            let report = reader.poll_changed(BUDGET, |key, _, value, _| {
                seen.push((key, value.to_vec()));
            });
            lapped |= report.lapped;
            if report.journal_drained && report.pending == 0 && !report.scanning {
                break;
            }
        }
        assert!(lapped);
        for key in 0..8u32 {
            let last = 192 + key;
            assert_eq!(
                seen.iter()
                    .rev()
                    .find(|(seen, _)| *seen == key)
                    .map(|(_, v)| v.clone()),
                Some(last.to_le_bytes().to_vec())
            );
        }
    }

    /// The region is driver only (A2): a view that expects the shared seal
    /// profile is refused, and so is a writable attach.
    #[test]
    fn a_table_region_is_driver_only() {
        let writer = table();
        let region = writer.region().unwrap();
        assert!(matches!(
            view_of(region, region.record(), SealProfile::Shared, CONFIG),
            Err(SysError::SealMismatch { .. })
        ));
        let fd = region.descriptor().unwrap().try_clone_to_owned().unwrap();
        assert!(matches!(
            Region::attach(fd, region.record()),
            Err(SysError::SealMismatch { .. })
        ));
    }

    /// A driver-only region whose record is a table's changed by `change`,
    /// holding a valid configuration line for [`CONFIG`]: only the record
    /// differs from a table's.
    fn foreign(change: impl Fn(&mut RegionRecord)) -> (Region, RegionRecord) {
        let mut record = table().region().unwrap().record();
        change(&mut record);
        let region = Region::create_driver_only(record).unwrap();
        for (index, value) in [2, 8, 16, 1024].into_iter().enumerate() {
            region
                .structure()
                .get(index)
                .unwrap()
                .store(value, Ordering::Release);
        }
        (region, record)
    }

    /// The attach checks the record: the kind, the layout version and the
    /// generation, each alone; another layout version is a typed refusal.
    #[test]
    fn attachment_checks_the_record() {
        let (region, record) = foreign(|_| {});
        assert!(view_of(&region, record, SealProfile::DriverOnly, CONFIG).is_ok());
        let changes: [fn(&mut RegionRecord); 2] = [
            |record| record.kind = RegionKind::Counters,
            |record| record.generation = 1,
        ];
        for (case, change) in changes.into_iter().enumerate() {
            let (region, record) = foreign(change);
            assert!(
                matches!(
                    view_of(&region, record, SealProfile::DriverOnly, CONFIG),
                    Err(SysError::InvalidRegion { .. })
                ),
                "record change {case} was accepted"
            );
        }
        // Another layout version, the version-1 table without freshness
        // words among them, is refused with a typed error.
        for layout in [1, LAYOUT_VERSION + 1] {
            let (region, record) = foreign(|record| record.layout = layout);
            assert_eq!(record.layout, layout);
            assert!(
                matches!(
                    view_of(&region, record, SealProfile::DriverOnly, CONFIG),
                    Err(SysError::LayoutVersion { found, expected: LAYOUT_VERSION })
                        if found == layout
                ),
                "layout {layout} was accepted"
            );
        }
        // A region of another kind, attached as a table: the header
        // compare refuses it.
        let (_manager, counters) = crate::counters::counters_in(7, 4, 2).unwrap();
        let other = counters.region().unwrap();
        let mut record = other.record();
        record.kind = RegionKind::ConflationTable;
        assert!(matches!(
            view_of(other, record, SealProfile::DriverOnly, CONFIG),
            Err(SysError::InvalidRegion { .. })
        ));
    }

    /// The attach checks the configuration line: against the granted
    /// configuration, word by word, and against the region's length in
    /// both directions.
    #[test]
    fn attachment_checks_the_configuration() {
        assert!(view(&table()).is_ok());
        // A granted configuration the table does not have, also one with
        // the same geometry (value capacities 8 and 16 both take 16 slot
        // words).
        for expected in [
            ConflationConfig { keys: 3, ..CONFIG },
            ConflationConfig {
                value_capacity: 16,
                ..CONFIG
            },
            ConflationConfig {
                journal_capacity: 2048,
                ..CONFIG
            },
        ] {
            assert!(
                matches!(
                    view_expecting(&table(), expected),
                    Err(SysError::InvalidRegion { .. })
                ),
                "{expected:?} was accepted"
            );
        }
        // A configuration line that disagrees with the grant, its slot
        // words or its unused words.
        for (index, value) in [(1, 200), (2, 32), (4, 1), (15, 1)] {
            let writer = table();
            store(&writer, index, value);
            assert!(
                matches!(view(&writer), Err(SysError::InvalidRegion { .. })),
                "word {index} = {value} was accepted"
            );
        }
        // A line that matches its grant but not the region's length: fewer
        // keys than the region holds, and more.
        for keys in [1, 3] {
            let writer = table();
            store(&writer, 0, u64::from(keys));
            assert!(
                matches!(
                    view_expecting(&writer, ConflationConfig { keys, ..CONFIG }),
                    Err(SysError::InvalidRegion { .. })
                ),
                "{keys} keys were accepted"
            );
        }
        // So does a larger journal.
        let writer = table();
        store(&writer, 3, 2048);
        assert!(matches!(
            view_expecting(
                &writer,
                ConflationConfig {
                    journal_capacity: 2048,
                    ..CONFIG
                }
            ),
            Err(SysError::InvalidRegion { .. })
        ));
    }

    /// Stores `value` into word `index` of `writer`'s configuration line,
    /// through the driver's writable mapping.
    fn store(writer: &ConflationWriter, index: usize, value: u64) {
        writer
            .region()
            .unwrap()
            .structure()
            .get(index)
            .unwrap()
            .store(value, Ordering::Release);
    }

    /// The creation refuses what `conflation` refuses.
    #[test]
    fn creation_checks_the_geometry() {
        for (keys, value_capacity, journal_capacity) in
            [(0, 8, 1024), (2, 0, 1024), (2, 8, 512), (2, 8, 1536)]
        {
            assert!(matches!(
                conflation_in(7, 3, keys, value_capacity, journal_capacity),
                Err(SysError::InvalidRegion { .. })
            ));
            assert!(conflation(keys, value_capacity, journal_capacity).is_err());
        }
    }
}

// Fresh slots (GU-8).

fn fresh_words(value_words: usize) -> Vec<AtomicU64> {
    (0..5 + value_words).map(|_| AtomicU64::new(0)).collect()
}

/// A freshness-only write advances the sequence but not the value version,
/// and a value write keeps the freshness words.
#[test]
fn freshness_writes_keep_the_value_version() {
    use crate::freshness::{STALE, SlotFreshness};
    let words = fresh_words(2);
    let slot = FreshSlotWords::new(&words).unwrap();
    let mut out = [0u8; 16];
    assert_eq!(slot.read(&mut out), FreshRead::Empty);
    let stale = SlotFreshness {
        loss_applied: 1 | STALE,
        stale_since: 8,
    };
    slot.set_freshness(stale).unwrap();
    assert_eq!(slot.read(&mut out), FreshRead::Empty, "no value yet");
    assert_eq!(slot.write(b"first").unwrap(), 2);
    assert_eq!(
        slot.read(&mut out),
        FreshRead::Value {
            version: 2,
            length: 5,
            freshness: stale
        }
    );
    assert_eq!(&out[..5], b"first");
    let fresh = SlotFreshness {
        loss_applied: 1,
        stale_since: 0,
    };
    slot.set_freshness(fresh).unwrap();
    assert_eq!(slot.version(), 2, "freshness is not a value replacement");
    assert_eq!(slot.write(b"second!").unwrap(), 4);
    assert_eq!(
        slot.read(&mut out),
        FreshRead::Value {
            version: 4,
            length: 7,
            freshness: fresh
        }
    );
    // Four seqlock writes: two freshness writes and two values.
    assert_eq!(words[0].load(Ordering::Relaxed), 8);
}

#[test]
fn a_fresh_slot_refuses_what_it_cannot_store() {
    let words = fresh_words(1);
    let slot = FreshSlotWords::new(&words).unwrap();
    assert_eq!(slot.capacity(), 8);
    assert_eq!(
        slot.write(b"123456789"),
        Err(ConflationError::ValueTooLarge { length: 9, max: 8 })
    );
    words[1].store(u64::MAX - 1, Ordering::Relaxed);
    assert!(!slot.can_write());
    assert_eq!(slot.write(b"x"), Err(ConflationError::VersionsExhausted));
    words[1].store(0, Ordering::Relaxed);
    words[0].store(u64::MAX - 1, Ordering::Relaxed);
    assert!(!slot.can_write());
    assert_eq!(slot.write(b"x"), Err(ConflationError::VersionsExhausted));
    assert_eq!(
        slot.set_freshness(crate::freshness::SlotFreshness::default()),
        Err(ConflationError::VersionsExhausted)
    );
    assert_eq!(words[1].load(Ordering::Relaxed), 0, "nothing stored");
    assert!(FreshSlotWords::new(&words[..5]).is_none());
    // Mid-write: unstable.
    words[0].store(3, Ordering::Relaxed);
    assert_eq!(slot.read(&mut [0u8; 8]), FreshRead::Unstable);
}

/// GU-8: a freshness-only write leaves the public version unchanged. A
/// reader that meets it in progress retries the key and then delivers the
/// same version once; the freshness write alone is not a new version.
#[test]
fn a_freshness_write_is_not_a_new_version_and_is_retried() {
    use crate::freshness::{STALE, SlotFreshness};
    let mut writer = conflation(4, 8, 1024).unwrap();
    let mut reader = writer.reader();
    let _ = drain(&mut reader, BUDGET);
    assert_eq!(writer.write(1, b"a").unwrap(), 2);
    // A freshness write in progress: the sequence is odd.
    let seq = writer.slot_seq_word(1).unwrap();
    let even = seq.load(Ordering::Relaxed);
    seq.store(even + 1, Ordering::Relaxed);
    let mut seen = Vec::new();
    let report = reader.poll_changed(BUDGET, |key, version, _, _| seen.push((key, version)));
    assert_eq!((report.delivered, report.unstable), (0, 1));
    // The write completes; the value version stays 2.
    seq.store(even, Ordering::Relaxed);
    writer
        .table_slot(1)
        .unwrap()
        .set_freshness(SlotFreshness {
            loss_applied: 1 | STALE,
            stale_since: 0,
        })
        .unwrap();
    assert_eq!(seq.load(Ordering::Relaxed), even + 2);
    assert_eq!(
        writer.slot_version_word(1).unwrap().load(Ordering::Relaxed),
        2
    );
    let _ = reader.poll_changed(BUDGET, |key, version, _, _| seen.push((key, version)));
    assert_eq!(seen, [(1, 2)], "retried, delivered once");
    let report = reader.poll_changed(BUDGET, |key, version, _, _| seen.push((key, version)));
    assert_eq!(report.delivered, 0);
    // The settled freshness write is not even served: the scan reads the
    // value version, not the sequence.
    assert_eq!(report.skipped, 0);
    assert_eq!(seen, [(1, 2)]);
}

/// A slot left mid-write by a freshness-only write stays queued: the value
/// version did not change, yet a closed table is never reported finished
/// while the slot is unsettled.
#[test]
fn a_slot_stuck_in_a_freshness_write_stays_pending() {
    let mut writer = conflation(4, 8, 1024).unwrap();
    let mut reader = writer.reader();
    writer.write(1, b"a").unwrap();
    let _ = drain(&mut reader, BUDGET);
    let seq = writer.slot_seq_word(1).unwrap();
    seq.store(seq.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
    drop(writer);
    for _ in 0..4 {
        let report = reader.poll_changed(BUDGET, |_, _, _, _| {});
        assert!(report.closed);
        assert!(!report.finished, "an unsettled slot is not finished");
        assert!(report.pending >= 1 || report.unstable >= 1);
    }
}

/// An odd value version is not one the writer stored: unstable.
#[test]
fn an_odd_value_version_is_unstable() {
    let words = fresh_words(1);
    let slot = FreshSlotWords::new(&words).unwrap();
    slot.write(b"x").unwrap();
    words[1].store(5, Ordering::Relaxed);
    assert_eq!(slot.read(&mut [0u8; 8]), FreshRead::Unstable);
}

/// Polls until settled; returns `(key, version, freshness)` of each
/// delivery and the last report.
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helper, as ADR-0007 allows in tests"
)]
fn drain_fresh(reader: &mut ConflationReader) -> (Vec<(u32, u64, Freshness)>, PollReport) {
    let mut seen = Vec::new();
    for _ in 0..1000 {
        let report = reader.poll_changed(BUDGET, |key, version, _, freshness| {
            seen.push((key, version, freshness));
        });
        if report.terminal.is_some()
            || (report.journal_drained && report.pending == 0 && !report.scanning)
        {
            return (seen, report);
        }
    }
    panic!("the reader did not settle");
}

#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helper, as ADR-0007 allows in tests"
)]
fn fresh_table(keys: u32) -> (ConflationWriter, FreshnessLink) {
    let link = FreshnessLink::new();
    (conflation_fresh(keys, 8, 1024, link.clone()).unwrap(), link)
}

/// karyos#658: a closed table still yields the last value of every
/// written key, in key order, for a recreated view to seed from; a buffer
/// shorter than the value capacity, or a table without a barrier, yields
/// nothing.
#[test]
#[allow(clippy::unwrap_used, reason = "test, as ADR-0007 allows in tests")]
fn a_closed_table_yields_its_last_values() {
    let (mut writer, _link) = fresh_table(4);
    writer.write_at(2, &[2, 2], 0).unwrap();
    writer.write_at(0, &[1], 32).unwrap();
    writer.write_at(2, &[7], 64).unwrap();
    writer.close();
    let mut out = [0u8; 8];
    let mut seen = Vec::new();
    let unstable = writer.for_each_value(&mut out, |key, value| seen.push((key, value.to_vec())));
    assert_eq!(unstable, 0);
    assert_eq!(seen, vec![(0, vec![1]), (2, vec![7])]);
    let mut short = [0u8; 7];
    let mut none = 0;
    let _ = writer.for_each_value(&mut short, |_, _| none += 1);
    assert_eq!(none, 0);
    let plain = conflation(4, 8, 1024).unwrap();
    let _ = plain.for_each_value(&mut out, |_, _| none += 1);
    assert_eq!(none, 0);
}

/// GU-8, GU-9: a recorded loss makes every written key Stale since the
/// gap's start at once, before any slot is reconciled, and a reader that
/// already delivered them gets them again, same versions, Stale. The
/// reconciliation keeps them Stale and retires the record only after its
/// last slot. A replacement past the gap restores its own key only.
#[test]
fn a_loss_stales_every_key_until_its_replacement() {
    let (mut writer, _link) = fresh_table(3);
    let mut reader = writer.reader();
    for key in 0..3 {
        assert_eq!(
            writer.write_at(key, &[key as u8], u64::from(key) * 32),
            Ok(2)
        );
    }
    writer.passed(96);
    let (seen, _) = drain_fresh(&mut reader);
    assert_eq!(seen.len(), 3);
    assert!(
        seen.iter()
            .all(|&(_, version, f)| version == 2 && f == Freshness::Fresh)
    );
    assert_eq!(writer.record_loss(96, 160), Ok(1));
    assert!(writer.recorded(96, 160));
    // Before any reconciliation: every key Stale, delivered again.
    let (seen, _) = drain_fresh(&mut reader);
    let stale = Freshness::Stale { since: 96 };
    assert_eq!(seen, [(0, 2, stale), (1, 2, stale), (2, 2, stale)]);
    // A partial pass retires nothing.
    assert_eq!(writer.reconcile(2), Ok(2));
    assert_eq!(writer.retired_through(), Some(0));
    assert!(writer.reconciling());
    assert_eq!(writer.reconcile(2), Ok(1));
    assert_eq!(writer.retired_through(), Some(1));
    assert!(!writer.reconciling());
    // Reconciled: still Stale, so nothing new for the reader; a reader
    // created now reads the reconciled slots Stale too.
    let (seen, _) = drain_fresh(&mut reader);
    assert!(seen.is_empty(), "{seen:?}");
    let (seen, _) = drain_fresh(&mut writer.reader());
    assert_eq!(seen, [(0, 2, stale), (1, 2, stale), (2, 2, stale)]);
    // The feeder passes the gap; a replacement of key 1 past it is Fresh,
    // and only key 1 changes.
    writer.passed(160);
    assert!(!writer.recorded(96, 160));
    assert_eq!(writer.write_at(1, &[9], 160), Ok(4));
    let (seen, _) = drain_fresh(&mut reader);
    assert_eq!(seen, [(1, 4, Freshness::Fresh)]);
    let counters = writer.fresh_counters().unwrap();
    assert_eq!(
        (counters.losses, counters.reconciled, counters.retirements),
        (1, 3, 1)
    );
}

/// ADR-0080: a refresh value keeps its slot's freshness, Stale with its
/// `since` or Fresh, and a restore at the cycle's end turns the key Fresh
/// without changing its value; a key never written stays empty.
#[test]
fn a_refresh_value_waits_for_its_restore() {
    let (mut writer, _link) = fresh_table(3);
    let mut reader = writer.reader();
    assert_eq!(writer.write_at(0, &[1], 0), Ok(2));
    assert_eq!(writer.write_at(1, &[1], 32), Ok(2));
    writer.passed(64);
    assert_eq!(writer.record_loss(64, 128), Ok(1));
    while writer.reconciling() {
        let _ = writer.reconcile(64);
    }
    writer.passed(128);
    let stale = Freshness::Stale { since: 64 };
    let _ = drain_fresh(&mut reader);
    // A refresh value of key 0 past the gap: newer, still Stale since 64.
    assert_eq!(writer.write_refresh_at(0, &[5], 160), Ok(4));
    let (seen, _) = drain_fresh(&mut reader);
    assert_eq!(seen, [(0, 4, stale)]);
    // A live value of key 1 past the gap is Fresh at once, as before, and a
    // refresh value after it keeps it Fresh.
    assert_eq!(writer.write_at(1, &[6], 192), Ok(4));
    assert_eq!(writer.write_refresh_at(1, &[7], 224), Ok(6));
    let (seen, _) = drain_fresh(&mut reader);
    assert_eq!(seen, [(1, 6, Freshness::Fresh)]);
    // The cycle's end restores key 0 only; key 2 was never written.
    writer.passed(256);
    assert_eq!(writer.restore_at(0, 256), Ok(()));
    assert_eq!(writer.restore_at(2, 256), Ok(()));
    let (seen, _) = drain_fresh(&mut reader);
    assert_eq!(seen, [(0, 4, Freshness::Fresh)]);
    let mut out = [0u8; 8];
    assert!(matches!(
        writer.table_slot(2).unwrap().read(&mut out),
        FreshRead::Empty
    ));
}

/// ADR-0080: a restore below the frontier is refused, and a gap already
/// recorded ahead of the cycle's end still covers the restored key: it is
/// Stale since that gap, not Fresh.
#[test]
fn a_restore_respects_a_gap_ahead() {
    let (mut writer, _link) = fresh_table(1);
    let mut reader = writer.reader();
    assert_eq!(writer.write_at(0, &[1], 0), Ok(2));
    writer.passed(32);
    assert_eq!(writer.record_loss(32, 64), Ok(1));
    while writer.reconciling() {
        let _ = writer.reconcile(64);
    }
    writer.passed(64);
    assert_eq!(writer.write_refresh_at(0, &[2], 64), Ok(4));
    // The receive owner posts [160, 192) before the feeder reaches it.
    assert_eq!(writer.record_loss(160, 192), Ok(2));
    while writer.reconciling() {
        let _ = writer.reconcile(64);
    }
    writer.passed(128);
    assert!(matches!(
        writer.restore_at(0, 96),
        Err(ConflationError::BehindFrontier { .. })
    ));
    assert_eq!(writer.restore_at(0, 128), Ok(()));
    let (seen, _) = drain_fresh(&mut reader);
    assert_eq!(seen.last(), Some(&(0, 4, Freshness::Stale { since: 160 })));
    // Without a barrier there is nothing to restore.
    let mut plain = conflation(1, 8, 1024).unwrap();
    assert_eq!(plain.write_refresh_at(0, &[1], 0), Ok(2));
    assert_eq!(
        plain.restore_at(0, 0),
        Err(ConflationError::PositionRequired)
    );
}

/// A table of `keys` keys with a barrier and refresh cycles, keys
/// `0..keys` written at positions `0, 32, ..`, then a loss over
/// `[64 * keys, 64 * keys + 32)` reconciled and passed: every key `Stale`.
#[allow(
    clippy::unwrap_used,
    reason = "test helper, as ADR-0007 allows in tests"
)]
fn stale_cycle_table(keys: u32) -> (ConflationWriter, FreshnessLink, u64) {
    let (mut writer, link) = fresh_table(keys);
    assert!(writer.enable_cycles());
    for key in 0..keys {
        writer.write_at(key, &[1], u64::from(key) * 32).unwrap();
    }
    let gap = u64::from(keys) * 64;
    writer.passed(gap);
    writer.record_loss(gap, gap + 32).unwrap();
    while writer.reconciling() {
        let _ = writer.reconcile(64);
    }
    writer.passed(gap + 32);
    (writer, link, gap + 32)
}

fn id(value: u32) -> cycle::CycleId {
    cycle::CycleId::new(value).unwrap_or_default()
}

fn end(begin: u64, values: u64) -> cycle::Marker {
    cycle::Marker::End {
        scope: cycle::Scope::Refresh,
        begin,
        values,
    }
}

/// The freshness each written key reads now, from a new reader.
fn freshness_now(writer: &ConflationWriter) -> Vec<(u32, Freshness)> {
    let (seen, _) = drain_fresh(&mut writer.reader());
    seen.into_iter().map(|(key, _, f)| (key, f)).collect()
}

/// SPEC §13 "Conflation refresh", ADR-0080: a complete cycle that carries
/// key 0 turns it Fresh; key 1, which it does not carry, stays Stale.
/// Values inside the cycle stay Stale until its end marker.
#[test]
fn a_complete_cycle_restores_only_the_keys_it_carried() {
    let (mut writer, _link, at) = stale_cycle_table(2);
    let stale = Freshness::Stale { since: 128 };
    writer.cycle_begin(id(5), cycle::Scope::Refresh, at);
    writer.passed(at + 32);
    assert_eq!(writer.cycle_value(id(5), 0, &[9], at + 32), Ok(4));
    assert_eq!(freshness_now(&writer), [(0, stale), (1, stale)]);
    writer.passed(at + 64);
    assert_eq!(writer.cycle_end(id(5), end(at, 1), at + 64), Ok(Some(1)));
    assert_eq!(freshness_now(&writer), [(0, Freshness::Fresh), (1, stale)]);
    let counters = writer.fresh_counters().unwrap_or_default();
    assert_eq!(
        (
            counters.cycles_completed,
            counters.keys_restored,
            counters.cycles_aborted
        ),
        (1, 1, 0)
    );
}

/// SPEC §13 "Conflation refresh", ADR-0080: a cycle cut by a gap before its
/// end marker restores no key, not even the ones whose values arrived;
/// so does a gap already recorded ahead of its begin.
#[test]
fn a_cut_cycle_restores_no_key() {
    let (mut writer, _link, at) = stale_cycle_table(2);
    writer.cycle_begin(id(1), cycle::Scope::Refresh, at);
    writer.passed(at + 32);
    assert_eq!(writer.cycle_value(id(1), 0, &[9], at + 32), Ok(4));
    assert_eq!(writer.record_loss(at + 64, at + 96), Ok(2));
    writer.passed(at + 96);
    assert_eq!(writer.cycle_value(id(1), 1, &[9], at + 96), Ok(4));
    writer.passed(at + 128);
    assert_eq!(writer.cycle_end(id(1), end(at, 2), at + 128), Ok(None));
    assert!(
        freshness_now(&writer)
            .iter()
            .all(|&(_, f)| matches!(f, Freshness::Stale { .. }))
    );
    // A gap recorded ahead before the begin cuts the cycle too.
    let (mut writer, _link, at) = stale_cycle_table(1);
    assert_eq!(writer.record_loss(at + 64, at + 96), Ok(2));
    writer.cycle_begin(id(2), cycle::Scope::Refresh, at);
    writer.passed(at + 32);
    assert_eq!(writer.cycle_value(id(2), 0, &[9], at + 32), Ok(4));
    writer.passed(at + 128);
    assert_eq!(writer.cycle_end(id(2), end(at, 1), at + 128), Ok(None));
    assert!(matches!(
        freshness_now(&writer)[..],
        [(0, Freshness::Stale { .. })]
    ));
    assert_eq!(
        writer.fresh_counters().unwrap_or_default().cycles_aborted,
        1
    );
}

/// ADR-0081 (a): a gap the receive owner recorded ahead of the feeder
/// before it read the begin marker, inside the cycle's range, aborts the
/// cycle. Key 0's refresh value lies below the gap and its newer live
/// update was lost in it, so key 0 must not turn Fresh: without the rule,
/// the end (past the gap, which is then behind) would restore it.
#[test]
fn a_gap_recorded_ahead_inside_the_cycle_aborts_it() {
    let (mut writer, _link, at) = stale_cycle_table(1);
    // The gap [at + 64, at + 96) is recorded while the feeder is at `at`.
    assert_eq!(writer.record_loss(at + 64, at + 96), Ok(2));
    writer.cycle_begin(id(1), cycle::Scope::Refresh, at);
    writer.passed(at + 32);
    assert_eq!(writer.cycle_value(id(1), 0, &[9], at + 32), Ok(4));
    while writer.reconciling() {
        let _ = writer.reconcile(64);
    }
    writer.passed(at + 128);
    assert_eq!(writer.cycle_end(id(1), end(at, 1), at + 128), Ok(None));
    assert!(matches!(
        freshness_now(&writer)[..],
        [(0, Freshness::Stale { .. })]
    ));
    let counters = writer.fresh_counters().unwrap_or_default();
    assert_eq!((counters.cycles_completed, counters.cycles_aborted), (0, 1));
}

/// ADR-0081 (b): a gap recorded while the cycle is open that starts at or
/// after the end marker's position does not cut it: the cycle completes,
/// and the restored key reads Stale since that later gap (GU-9), not Fresh.
#[test]
fn a_gap_from_the_end_on_does_not_abort_the_cycle() {
    let (mut writer, _link, at) = stale_cycle_table(1);
    writer.cycle_begin(id(1), cycle::Scope::Refresh, at);
    writer.passed(at + 32);
    assert_eq!(writer.cycle_value(id(1), 0, &[9], at + 32), Ok(4));
    // Recorded ahead, starting exactly at the end marker's position.
    assert_eq!(writer.record_loss(at + 64, at + 96), Ok(2));
    while writer.reconciling() {
        let _ = writer.reconcile(64);
    }
    writer.passed(at + 64);
    assert_eq!(writer.cycle_end(id(1), end(at, 1), at + 64), Ok(Some(1)));
    assert_eq!(
        freshness_now(&writer),
        [(0, Freshness::Stale { since: at + 64 })]
    );
    let counters = writer.fresh_counters().unwrap_or_default();
    assert_eq!((counters.cycles_completed, counters.cycles_aborted), (1, 0));
}

/// ADR-0080: a new begin aborts the open cycle; an end with no begin seen,
/// or with another id, is ignored and leaves the open cycle open; an end
/// whose begin position or count differs aborts it.
#[test]
fn cycles_are_matched_by_id_begin_and_count() {
    let (mut writer, _link, at) = stale_cycle_table(1);
    // No cycle open: ignored.
    assert_eq!(writer.cycle_end(id(3), end(at, 0), at), Ok(None));
    writer.cycle_begin(id(3), cycle::Scope::Refresh, at);
    writer.passed(at + 32);
    assert_eq!(writer.cycle_value(id(3), 0, &[9], at + 32), Ok(4));
    // A new begin aborts cycle 3: its value restores nothing.
    writer.passed(at + 64);
    writer.cycle_begin(id(4), cycle::Scope::Refresh, at + 64);
    writer.passed(at + 96);
    assert_eq!(writer.cycle_end(id(3), end(at, 1), at + 96), Ok(None));
    assert!(matches!(
        freshness_now(&writer)[..],
        [(0, Freshness::Stale { .. })]
    ));
    // Cycle 4 is still open after that foreign end; a wrong count aborts it.
    writer.passed(at + 128);
    assert_eq!(writer.cycle_value(id(4), 0, &[9], at + 128), Ok(6));
    writer.passed(at + 160);
    assert_eq!(writer.cycle_end(id(4), end(at + 64, 2), at + 160), Ok(None));
    // A wrong begin position aborts too.
    writer.cycle_begin(id(5), cycle::Scope::Refresh, at + 160);
    writer.passed(at + 192);
    assert_eq!(writer.cycle_value(id(5), 0, &[9], at + 192), Ok(8));
    writer.passed(at + 224);
    assert_eq!(writer.cycle_end(id(5), end(at, 1), at + 224), Ok(None));
    assert!(matches!(
        freshness_now(&writer)[..],
        [(0, Freshness::Stale { .. })]
    ));
    let counters = writer.fresh_counters().unwrap_or_default();
    assert_eq!((counters.cycles_completed, counters.cycles_aborted), (0, 3));
    // The same id after all that completes when everything matches.
    writer.cycle_begin(id(5), cycle::Scope::Snapshot, at + 224);
    writer.passed(at + 256);
    assert_eq!(writer.cycle_value(id(5), 0, &[9], at + 256), Ok(10));
    writer.passed(at + 288);
    let snapshot = cycle::Marker::End {
        scope: cycle::Scope::Snapshot,
        begin: at + 224,
        values: 1,
    };
    assert_eq!(writer.cycle_end(id(5), snapshot, at + 288), Ok(Some(1)));
    assert_eq!(freshness_now(&writer), [(0, Freshness::Fresh)]);
    let counters = writer.fresh_counters().unwrap_or_default();
    assert_eq!(
        (counters.cycles_completed, counters.snapshots_completed),
        (1, 1)
    );
}

/// ADR-0080: a refresh value of another id is written, keeping its key's
/// freshness, but the open cycle does not count it, so an end with a count
/// of 0 completes and restores nothing; and a loss entirely below the begin
/// position (here the table's own gap, passed before the begin) does not
/// abort a cycle.
#[test]
fn a_value_of_another_cycle_is_not_counted() {
    let (mut writer, _link, at) = stale_cycle_table(1);
    writer.cycle_begin(id(1), cycle::Scope::Refresh, at);
    writer.passed(at + 32);
    assert_eq!(writer.cycle_value(id(2), 0, &[9], at + 32), Ok(4));
    writer.passed(at + 64);
    assert_eq!(writer.cycle_end(id(1), end(at, 0), at + 64), Ok(Some(0)));
    assert!(matches!(
        freshness_now(&writer)[..],
        [(0, Freshness::Stale { .. })]
    ));
    let counters = writer.fresh_counters().unwrap_or_default();
    assert_eq!((counters.cycles_completed, counters.cycles_aborted), (1, 0));
}

/// ADR-0080: a live update during a cycle restores its key at once, as
/// today, even when the cycle is later cut; and without a barrier, a
/// refresh value is a value and markers do nothing.
#[test]
fn live_updates_inside_a_cycle_are_unchanged() {
    let (mut writer, _link, at) = stale_cycle_table(2);
    writer.cycle_begin(id(1), cycle::Scope::Refresh, at);
    writer.passed(at + 32);
    assert_eq!(writer.write_at(1, &[7], at + 32), Ok(4));
    assert_eq!(writer.cycle_value(id(1), 0, &[9], at + 32), Ok(4));
    assert_eq!(
        freshness_now(&writer),
        [(0, Freshness::Stale { since: 128 }), (1, Freshness::Fresh)]
    );
    writer.cycle_abort();
    assert_eq!(
        freshness_now(&writer),
        [(0, Freshness::Stale { since: 128 }), (1, Freshness::Fresh)]
    );
    let mut plain = conflation(1, 8, 1024).unwrap();
    assert!(!plain.enable_cycles());
    plain.cycle_begin(id(1), cycle::Scope::Refresh, 0);
    assert_eq!(plain.cycle_value(id(1), 0, &[1], 0), Ok(2));
    assert_eq!(plain.cycle_end(id(1), end(0, 1), 32), Ok(None));
}

/// A value written between the frontier and a recorded gap ahead lies
/// below the gap's end: it is Stale since the gap's start, never Fresh.
#[test]
fn a_value_below_a_gap_ahead_is_written_stale() {
    let (mut writer, _link) = fresh_table(2);
    let mut reader = writer.reader();
    // The receive owner posted [64, 128) while the feeder is at 0.
    assert_eq!(writer.record_loss(64, 128), Ok(1));
    assert_eq!(writer.write_at(0, &[1], 0), Ok(2));
    writer.passed(32);
    assert_eq!(writer.write_at(1, &[2], 32), Ok(2));
    let (seen, _) = drain_fresh(&mut reader);
    let stale = Freshness::Stale { since: 64 };
    assert_eq!(seen, [(0, 2, stale), (1, 2, stale)]);
    // Past the gap, a replacement restores it.
    writer.passed(128);
    assert_eq!(writer.write_at(0, &[3], 128), Ok(4));
    let (seen, _) = drain_fresh(&mut reader);
    assert_eq!(seen, [(0, 4, Freshness::Fresh)]);
}

/// The frontier rule is enforced, not assumed: a loss below the frontier
/// records nothing, is counted, and publishes the terminal cell; the
/// reader then delivers nothing more and reports the close.
#[test]
fn a_loss_below_the_frontier_closes_the_view() {
    let (mut writer, link) = fresh_table(2);
    let mut reader = writer.reader();
    assert_eq!(writer.write_at(0, &[1], 0), Ok(2));
    writer.passed(64);
    assert_eq!(
        writer.record_loss(32, 96),
        Err(LossError::BelowFrontier {
            start: 32,
            frontier: 64
        })
    );
    assert_eq!(writer.fresh_counters().unwrap().below_frontier, 1);
    let terminal = TerminalCell::read(&link.terminal_words()).unwrap();
    assert_eq!(
        terminal,
        Terminal {
            start: 32,
            end: 96,
            reason: crate::freshness::TERMINAL_BELOW_FRONTIER
        }
    );
    // The table closed with the terminal cell.
    assert_eq!(writer.write_at(1, &[2], 64), Err(ConflationError::Closed));
    let (seen, report) = drain_fresh(&mut reader);
    assert!(seen.is_empty(), "{seen:?}");
    assert_eq!(report.terminal, Some(terminal));
}

/// The receive owner's fail-safe publishes the shared terminal cell: the
/// reader stops delivering and reports it.
#[test]
fn the_owners_terminal_cell_stops_the_reader() {
    let (mut writer, link) = fresh_table(2);
    let mut reader = writer.reader();
    assert_eq!(writer.write_at(0, &[1], 0), Ok(2));
    let (seen, _) = drain_fresh(&mut reader);
    assert_eq!(seen, [(0, 2, Freshness::Fresh)]);
    let terminal = Terminal {
        start: 64,
        end: 128,
        reason: crate::freshness::TERMINAL_BARRIER_TIMEOUT,
    };
    assert!(link.terminal().unwrap().publish(terminal));
    assert!(!writer.publish_terminal(0, 1, 2), "one-shot");
    assert_eq!(writer.write_at(1, &[2], 0), Ok(2));
    let (seen, report) = drain_fresh(&mut reader);
    assert!(seen.is_empty());
    assert_eq!(report.terminal, Some(terminal));
}

/// The gaps ahead and the ring are bounded: past `DEFAULT_RING`
/// unretired records a loss is refused, counted and nothing is stored;
/// a reconciliation and the frontier passing them make room again.
#[test]
fn losses_past_the_ring_wait_for_a_retirement() {
    let (mut writer, _link) = fresh_table(1);
    for i in 0..crate::freshness::DEFAULT_RING as u64 {
        assert_eq!(writer.record_loss(64 * i, 64 * i + 32), Ok(i + 1));
    }
    let ring = crate::freshness::DEFAULT_RING as u64;
    assert_eq!(
        writer.record_loss(64 * ring, 64 * ring + 32),
        Err(LossError::Full)
    );
    assert_eq!(writer.fresh_counters().unwrap().full, 1);
    assert_eq!(writer.reconcile(8), Ok(1));
    // Retired, but still ahead of the frontier: refused.
    assert_eq!(
        writer.record_loss(64 * ring, 64 * ring + 32),
        Err(LossError::Full)
    );
    writer.passed(64 * ring);
    assert_eq!(writer.record_loss(64 * ring, 64 * ring + 32), Ok(ring + 1));
}

/// An exhausted loss sequence publishes the terminal cell.
#[test]
fn an_exhausted_loss_sequence_closes_the_view() {
    let (mut writer, link) = fresh_table(1);
    writer.seed_loss_seq(crate::freshness::STALE - 1);
    assert_eq!(writer.record_loss(0, 32), Err(LossError::Exhausted));
    assert_eq!(writer.fresh_counters().unwrap().exhausted, 1);
    assert_eq!(writer.write_at(0, &[1], 32), Err(ConflationError::Closed));
    assert_eq!(
        TerminalCell::read(&link.terminal_words()).map(|t| t.reason),
        Some(crate::freshness::TERMINAL_FRESHNESS_EXHAUSTED)
    );
}

/// A table without a barrier (IPC) records no loss, and its values read
/// Fresh; `write_at` writes as `write`.
#[test]
fn a_table_without_a_barrier_reads_fresh() {
    let mut writer = conflation(1, 8, 1024).unwrap();
    let mut reader = writer.reader();
    assert_eq!(writer.record_loss(0, 32), Err(LossError::NoBarrier));
    assert_eq!(writer.write_at(0, &[1], 0), Ok(2));
    assert_eq!(writer.reconcile(8), Ok(0));
    assert!(!writer.publish_terminal(0, 32, 1));
    assert_eq!(writer.fresh_counters(), None);
    let (seen, report) = drain_fresh(&mut reader);
    assert_eq!(seen, [(0, 2, Freshness::Fresh)]);
    assert_eq!(report.terminal, None);
}

/// #318 review: a value's freshness needs its position. A table with a
/// barrier refuses a plain write, and a value below the frontier, whose
/// gaps behind may be retired already: record_loss(200, 300), passed(400),
/// write_at(100) would otherwise read Fresh where GU-9 says Stale since
/// 200. Nothing is stored either way.
#[test]
fn a_value_without_its_position_or_behind_the_frontier_is_refused() {
    let (mut writer, _link) = fresh_table(2);
    let mut reader = writer.reader();
    assert_eq!(
        writer.write(0, &[1]),
        Err(ConflationError::PositionRequired)
    );
    assert_eq!(writer.record_loss(200, 300), Ok(1));
    writer.passed(400);
    assert_eq!(
        writer.write_at(0, &[1], 100),
        Err(ConflationError::BehindFrontier {
            position: 100,
            frontier: 400
        })
    );
    let (seen, _) = drain_fresh(&mut reader);
    assert!(seen.is_empty(), "{seen:?}");
    // At the frontier, after the gap: Fresh.
    assert_eq!(writer.write_at(0, &[2], 400), Ok(2));
    let (seen, _) = drain_fresh(&mut reader);
    assert_eq!(seen, [(0, 2, Freshness::Fresh)]);
}

/// #318 review (M2): the terminal cell is checked again after each copy.
/// A terminal published during a poll, by the handler of its first value,
/// stops the poll before the second key's value is delivered.
#[test]
fn a_terminal_published_during_a_poll_stops_it() {
    let (mut writer, link) = fresh_table(2);
    let mut reader = writer.reader();
    assert_eq!(writer.write_at(0, &[1], 0), Ok(2));
    assert_eq!(writer.write_at(1, &[2], 0), Ok(2));
    let terminal = Terminal {
        start: 64,
        end: 128,
        reason: crate::freshness::TERMINAL_BARRIER_TIMEOUT,
    };
    let mut delivered = Vec::new();
    let report = reader.poll_changed(BUDGET, |key, _, _, _| {
        delivered.push(key);
        let _ = link.terminal().unwrap().publish(terminal);
    });
    assert_eq!(delivered.len(), 1, "{delivered:?}");
    assert_eq!(report.terminal, Some(terminal));
}
