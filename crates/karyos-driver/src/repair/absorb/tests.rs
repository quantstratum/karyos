// SPDX-License-Identifier: Apache-2.0

use super::{Absorb, CopyKey};
use karyos_protocol::network::Receiver;

fn key(start: u64) -> CopyKey {
    CopyKey {
        receiver: Receiver::default(),
        lane: 0,
        start,
        length: 128,
    }
}

/// A copy on another route within the window is absorbed; on the same
/// route it is a retry; past the window it is a new NAK.
#[test]
fn a_copy_on_another_route_within_the_window_is_absorbed() {
    let mut table = Absorb::new(4, 1_000);
    table.record(&key(0), 0, 100);
    assert!(table.absorbs(&key(0), 1, 600));
    assert!(table.absorbs(&key(0), 1, 1_100), "the window is inclusive");
    assert!(!table.absorbs(&key(0), 0, 600), "same route: a retry");
    assert!(!table.absorbs(&key(0), 1, 1_101), "past the window");
    assert!(!table.absorbs(&key(128), 1, 600), "another interval");
    let other = CopyKey {
        receiver: Receiver {
            receiver_id: 7,
            ..Receiver::default()
        },
        ..key(0)
    };
    assert!(!table.absorbs(&other, 1, 600), "another receiver");
    assert_eq!(table.counts().absorbed, 2);
}

/// A retry on the same route refreshes its entry, so its copies are
/// absorbed from its own time.
#[test]
fn a_retry_refreshes_its_entry() {
    let mut table = Absorb::new(1, 1_000);
    table.record(&key(0), 0, 100);
    table.record(&key(0), 0, 5_000);
    assert!(table.absorbs(&key(0), 1, 5_500));
    assert_eq!(table.counts().full, 0, "the same entry, refreshed");
}

/// A full table records nothing more, counted, so those copies are served;
/// an entry past the window is free again.
#[test]
fn a_full_table_absorbs_nothing_more_and_frees_old_entries() {
    let mut table = Absorb::new(2, 1_000);
    table.record(&key(0), 0, 100);
    table.record(&key(128), 0, 100);
    table.record(&key(256), 0, 200);
    assert_eq!(table.counts().full, 1);
    assert!(!table.absorbs(&key(256), 1, 300), "not recorded: served");
    table.record(&key(256), 0, 2_000);
    assert!(
        table.absorbs(&key(256), 1, 2_100),
        "an old entry was reused"
    );
    assert_eq!(table.counts().full, 1);
}

/// With no capacity (one path) nothing is recorded or absorbed, and
/// nothing is counted full.
#[test]
fn no_capacity_absorbs_nothing() {
    let mut table = Absorb::new(0, 1_000);
    table.record(&key(0), 0, 100);
    assert!(!table.absorbs(&key(0), 1, 200));
    assert_eq!(table.counts().full, 0);
}

/// A clock read behind an entry is within its window.
#[test]
fn a_clock_behind_an_entry_is_within_its_window() {
    let mut table = Absorb::new(1, 1_000);
    table.record(&key(0), 0, 5_000);
    assert!(table.absorbs(&key(0), 1, 4_000));
}
