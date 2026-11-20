// SPDX-License-Identifier: Apache-2.0

//! ADR-0095's vectors T-1 to T-4, byte for byte, the store and the verdict.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use super::*;
use crate::disk::StdDisk;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

const T1: &str = "010001010000000001000000000000000000000000000000020000000000000003000000000000000400000000000000070000000000000000000000000000000010000000000000e803000000000000d00700000000000001000000000000009600000000000000a000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb40420f000000000000000000000000000000000000000000";
const T2: &str = "010001010000000001000000000000000000000000000000020000000000000003000000000000000400000000000000070000000000000000000000000000000010000000000000e803000000000000d0070000000000000100000000000000ffffffffffffffffffffffffffffffffaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000000000000000000000000000000000000000000000000000000000000000040420f000000000000000000000000000000000000000000";
const T3: &str = "010001010000000001000000000000000000000000000000020000000000000003000000000000000400000000000000070000000000000000000000000000000010000000000000d107000000000000d00700000000000001000000000000009600000000000000a000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb40420f000000000000000000000000000000000000000000";
const T4: &str = "0100010000000000000000000000000001000000000000000000000000000000c800000000000000bb96de23da08fee9dafc7720954cebf1e5bd512cd9238e81b5c09c3f29fd11ee00000000000000000000000000000000000000000000000000000000000000001b6ef69a00000000";

fn bytes(text: &str) -> [u8; ENTRY_LENGTH] {
    hex(text).try_into().unwrap()
}

fn t1() -> Entry {
    Entry {
        source: Source::Gnss,
        sync_state: SyncState::Synchronised,
        clock: [1, 0, 2, 3, 4],
        recording: 7,
        start: 0,
        end: 4096,
        min_time: 1000,
        max_time: 2000,
        granularity: 1,
        bound_min_ns: 150,
        bound_max_ns: 160,
        calibration: [0xAA; 32],
        utc_reference: [0xBB; 32],
        tick_fs: 1_000_000,
    }
}

#[test]
fn the_vectors_decode_and_encode_exactly() {
    assert_eq!(Entry::decode(&bytes(T1)), Ok(t1()));
    assert_eq!(t1().encode().unwrap(), bytes(T1));
    let t2 = Entry {
        bound_min_ns: NO_BOUND,
        bound_max_ns: NO_BOUND,
        utc_reference: [0; 32],
        ..t1()
    };
    assert_eq!(Entry::decode(&bytes(T2)), Ok(t2));
    assert_eq!(t2.encode().unwrap(), bytes(T2));
    assert_eq!(Entry::decode(&bytes(T3)), Err(EntryError::Times));
}

#[test]
fn every_refusal_is_typed_in_order() {
    let mut version = bytes(T1);
    version[0] = 2;
    assert_eq!(Entry::decode(&version), Err(EntryError::Version(2)));
    let mut reserved = bytes(T1);
    reserved[199] = 1;
    assert_eq!(Entry::decode(&reserved), Err(EntryError::Reserved));
    let mut code = bytes(T1);
    code[2] = 9;
    assert!(matches!(
        Entry::decode(&code),
        Err(EntryError::Code {
            field: "source",
            ..
        })
    ));
    assert_eq!(
        Entry {
            recording: 0,
            ..t1()
        }
        .encode(),
        Err(EntryError::Recording)
    );
    assert_eq!(
        Entry {
            start: 5,
            end: 4,
            ..t1()
        }
        .encode(),
        Err(EntryError::Range)
    );
    assert_eq!(
        Entry {
            utc_reference: [0; 32],
            ..t1()
        }
        .encode(),
        Err(EntryError::Evidence)
    );
}

/// T-4: the first entry's seal in the entries' own journal; read back,
/// only sealed entries are returned.
#[test]
fn an_appended_entry_is_sealed_as_t4_and_read_back() {
    let archive = std::env::temp_dir().join(format!("karyos-te-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&archive);
    std::fs::create_dir_all(entries_dir(&archive)).unwrap();
    let mut store = EntryStore::open(StdDisk, &archive).unwrap();
    assert_eq!(store.append(&t1()).unwrap(), 0);
    let second = Entry {
        start: 4096,
        end: 8192,
        ..t1()
    };
    assert_eq!(store.append(&second).unwrap(), 200);
    drop(store);
    let mut disk = StdDisk;
    let (records, _) =
        super::super::journal::read_records(&mut disk, &entries_dir(&archive)).unwrap();
    assert_eq!(records[0].encode().to_vec(), hex(T4));
    assert_eq!(records[1].previous, records[0].digest());
    assert_eq!(read_sealed(StdDisk, &archive).unwrap(), [t1(), second]);
    std::fs::remove_dir_all(&archive).unwrap();
}

#[test]
fn the_verdict_follows_the_precedence() {
    let requirement = Requirement {
        max_divergence_ns: 155,
        max_granularity_ns: 1,
    };
    let loose = Requirement {
        max_divergence_ns: 1_000,
        max_granularity_ns: 1,
    };
    assert_eq!(t1().verdict(&loose), Verdict::Met);
    assert_eq!(t1().verdict(&requirement), Verdict::NotMet, "160 > 155");
    let unsynchronised = Entry {
        sync_state: SyncState::Unsynchronised,
        bound_min_ns: NO_BOUND,
        bound_max_ns: NO_BOUND,
        utc_reference: [0; 32],
        ..t1()
    };
    assert_eq!(unsynchronised.verdict(&loose), Verdict::NotMet);
    let no_bound = Entry {
        bound_min_ns: NO_BOUND,
        bound_max_ns: NO_BOUND,
        utc_reference: [0; 32],
        ..t1()
    };
    assert_eq!(no_bound.verdict(&loose), Verdict::NoEvidence);
    let coarse = Entry {
        granularity: 2,
        ..t1()
    };
    assert_eq!(coarse.verdict(&loose), Verdict::NotMet);
}
