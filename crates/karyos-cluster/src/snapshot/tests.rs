// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use super::*;

fn info(id: u64) -> SnapshotInfo {
    SnapshotInfo {
        id,
        index: id * 10,
        term: id + 1,
        length: id * 100,
        digest: 0xDEAD_0000 | u32::try_from(id).unwrap(),
    }
}

#[test]
fn the_defaults_are_the_proposal() {
    let config = SnapshotConfig::default();
    assert_eq!(
        (
            config.keep,
            config.allowance,
            config.every_entries,
            config.every_bytes
        ),
        (2, 1 << 30, 1 << 20, 256 << 20)
    );
}

#[test]
fn keep_must_be_one_to_the_maximum() {
    for keep in [0, MAX_KEEP + 1] {
        assert!(matches!(
            SnapshotConfig::default().with_keep(keep).check(),
            Err(SnapshotError::Keep { .. })
        ));
    }
    for keep in [1, MAX_KEEP] {
        assert!(SnapshotConfig::default().with_keep(keep).check().is_ok());
    }
}

#[test]
fn a_snapshot_is_due_by_entries_or_bytes() {
    let config = SnapshotConfig::default()
        .with_every_entries(10)
        .with_every_bytes(100);
    assert!(!config.due(9, 99));
    assert!(config.due(10, 0));
    assert!(config.due(0, 100));
}

#[test]
fn the_manifest_round_trips_and_refuses_damage() {
    for count in [0, 1, 2, usize::try_from(MAX_KEEP).unwrap()] {
        let kept: Vec<SnapshotInfo> = (1..=u64::try_from(count).unwrap()).map(info).collect();
        let bytes = encode_manifest(&kept);
        assert!(bytes.len() <= MANIFEST_MAX);
        assert_eq!(decode_manifest(&bytes), Some(kept));
    }
    let bytes = encode_manifest(&[info(1), info(2)]);
    for at in 0..bytes.len() {
        let mut damaged = bytes.clone();
        damaged[at] ^= 1;
        assert_eq!(decode_manifest(&damaged), None, "byte {at}");
    }
    for length in 0..bytes.len() {
        assert_eq!(decode_manifest(&bytes[..length]), None, "length {length}");
    }
}

#[test]
fn recordings_are_read_from_segment_names() {
    let names = [
        "0000000000000003-0000000000000000.seg",
        "0000000000000003-0000000000000000.idx",
        "0000000000000001-0000000000001000.seg",
        "snapshot-manifest",
        "snapshot-manifest.tmp",
        "zz-1.seg",
    ]
    .map(String::from);
    assert_eq!(recordings(&names), vec![1, 3]);
}

/// Entry `i` starts at byte `10 × i`.
fn position(index: u64) -> Option<u64> {
    Some(index * 10)
}

#[test]
fn the_log_floor_is_the_oldest_snapshot_without_an_allowance() {
    let config = SnapshotConfig::default().with_allowance(0);
    assert_eq!(config.log_floor(0, 50, position), 51);
}

#[test]
fn the_allowance_keeps_log_bytes_below_the_oldest_snapshot() {
    // Entries 51 - k .. 51 take 10 × k bytes.
    for (allowance, floor) in [
        (9, 51),
        (10, 50),
        (35, 48),
        (500, 1),
        (510, 0),
        (u64::MAX, 0),
    ] {
        let config = SnapshotConfig::default().with_allowance(allowance);
        assert_eq!(config.log_floor(0, 50, position), floor, "{allowance}");
    }
    // Never below the log's first index.
    let config = SnapshotConfig::default().with_allowance(u64::MAX);
    assert_eq!(config.log_floor(20, 50, position), 20);
}

#[test]
fn the_log_floor_stays_put_when_it_cannot_place_an_entry() {
    let config = SnapshotConfig::default().with_allowance(1000);
    assert_eq!(config.log_floor(0, 50, |_| None), 51);
    assert_eq!(config.log_floor(60, 50, position), 60);
    assert_eq!(config.log_floor(0, u64::MAX, position), u64::MAX);
}

#[test]
fn the_byte_trigger_rises_with_the_large_session_profile() {
    let large = DedupConfig::large();
    let sessions = large.reserved_bytes().expect("fits");
    assert!(sessions > DEFAULT_EVERY_BYTES);
    assert_eq!(
        SnapshotConfig::default().check_sessions(&large),
        Err(TriggerBelowSessions {
            every_bytes: DEFAULT_EVERY_BYTES,
            sessions_bytes: sessions,
        })
    );
    assert_eq!(SnapshotConfig::large().check_sessions(&large), Ok(()));
    assert_eq!(
        SnapshotConfig::default().check_sessions(&DedupConfig::default()),
        Ok(())
    );
    // Exactly the sessions bytes is enough; one byte fewer is not.
    let at = SnapshotConfig::default().with_every_bytes(sessions);
    assert_eq!(at.check_sessions(&large), Ok(()));
    let below = SnapshotConfig::default().with_every_bytes(sessions - 1);
    assert!(below.check_sessions(&large).is_err());
}

/// R-CORE-9 (karyos#746): a section of a kind this build does not know is
/// a typed refusal naming the kind, told apart from damage; the snapshot
/// is not used.
#[test]
fn a_section_of_an_unknown_kind_is_told_apart_from_damage() {
    use karyos_archive::disk::StdDisk;

    let dir = std::env::temp_dir().join(format!(
        "karyos-snapshot-unknown-kind-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let geometry = Geometry::new(4096, 4096).unwrap();
    let mut store = SnapshotStore::open(StdDisk, &dir, geometry, SnapshotConfig::default())
        .unwrap()
        .store;
    let mut pending = store.begin(10, 1).unwrap();
    pending.section(SectionKind::Sessions, 1, 2).unwrap();
    pending.write(b"ok").unwrap();
    pending.section_of_code(99, 1, 3).unwrap();
    pending.write(b"new").unwrap();
    let info = store.publish(pending).unwrap();
    let read = store.read(&info);
    assert!(
        matches!(read, Err(SnapshotError::UnknownSection { code: 99, .. })),
        "{read:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
