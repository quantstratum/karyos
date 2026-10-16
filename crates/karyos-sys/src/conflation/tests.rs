// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::AtomicBool;

use super::*;
use crate::sync::{AtomicU64, Ordering};

const BUDGET: Budget = Budget {
    keys: 64,
    retries: 4,
};

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
        let report = reader.poll_changed(budget, |key, version, value| {
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
    let mut seen: Vec<u32> = drain(
        &mut reader,
        Budget {
            keys: 5,
            retries: 1,
        },
    )
    .into_iter()
    .map(|(key, ..)| key)
    .collect();
    seen.sort_unstable();
    assert_eq!(seen, (0..70).step_by(3).collect::<Vec<_>>());
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
        let report = reader.poll_changed(
            Budget {
                keys: 7,
                retries: 2,
            },
            |key, _, value| {
                latest[key as usize] = Some(value.to_vec());
            },
        );
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
        let report = reader.poll_changed(
            Budget {
                keys: 1,
                retries: 1,
            },
            |key, _, value| {
                latest[key as usize] = Some(value.to_vec());
            },
        );
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
    let report = reader.poll_changed(BUDGET, |_, _, _| {});
    assert!(report.closed);
}

#[test]
fn dropping_the_writer_closes_and_values_stay_readable() {
    let mut writer = conflation(2, 8, 1024).unwrap();
    let mut reader = writer.reader();
    let version = writer.write(1, b"final").unwrap();
    drop(writer);
    let mut seen = Vec::new();
    let report = reader.poll_changed(BUDGET, |key, version, value| {
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
        reader.poll_changed(BUDGET, |_, _, _| panic!("handler"));
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
                        let report = reader.poll_changed(
                            Budget {
                                keys: 4,
                                retries: 2,
                            },
                            |key, version, data| {
                                let round = u32::from(data[0] ^ (key as u8).wrapping_mul(7));
                                assert_eq!(data, &value(key, round, 24)[..]);
                                latest[key as usize] = Some((version, data.to_vec()));
                            },
                        );
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
        reader.poll_changed(
            Budget {
                keys: 1,
                retries: 1,
            },
            |key, version, value| {
                seen.push((key, version, value.to_vec()));
            },
        );
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
        reader.poll_changed(
            Budget {
                keys: 3,
                retries: 1,
            },
            |key, _, value| {
                latest[key as usize] = Some(value.to_vec());
            },
        );
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
    let report = reader.poll_changed(BUDGET, |_, _, _| {});
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
        let report = reader.poll_changed(
            Budget {
                keys: 2,
                retries: 1,
            },
            |_, _, _| {
                delivered += 1;
            },
        );
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
    let report = reader.poll_changed(
        Budget {
            keys: 0,
            retries: 5,
        },
        |_, _, _| unreachable!(),
    );
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
    const CONFIG: ConflationConfig = ConflationConfig {
        keys: 2,
        value_capacity: 8,
        journal_capacity: 1024,
    };

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
        assert_eq!(
            reader.config(),
            ConflationConfig {
                keys: 5,
                value_capacity: 20,
                journal_capacity: 1024
            }
        );
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
        let report = reader.poll_changed(BUDGET, |_, _, _| {});
        assert!(report.closed);
        let report = reader.poll_changed(BUDGET, |_, _, _| unreachable!());
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
            let report = reader.poll_changed(BUDGET, |key, _, value| {
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
    let report = reader.poll_changed(BUDGET, |key, version, _| seen.push((key, version)));
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
    let _ = reader.poll_changed(BUDGET, |key, version, _| seen.push((key, version)));
    assert_eq!(seen, [(1, 2)], "retried, delivered once");
    let report = reader.poll_changed(BUDGET, |key, version, _| seen.push((key, version)));
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
        let report = reader.poll_changed(BUDGET, |_, _, _| {});
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
