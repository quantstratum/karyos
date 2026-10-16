// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::net::{Ipv4Addr, SocketAddr};

use super::*;

const SECOND: u64 = 1_000_000_000;

fn identity(incarnation: u64) -> Identity {
    Identity {
        driver_id: [1, 2],
        registration_id: 3,
        incarnation,
    }
}

fn term() -> TermParams {
    TermParams {
        term_length: 65_536,
        initial_term_id: 9,
        mtu: 1408,
    }
}

fn key(endpoint: u32, port: u16) -> PathKey {
    PathKey {
        endpoint: crate::agents::EndpointId(endpoint),
        source: SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), port)),
        alias: karyos_protocol::network::Alias {
            stream_id: 2,
            session_id: 1,
        },
    }
}

fn joins(positions: &[u64]) -> Lanes<u64> {
    Lanes::new(positions).unwrap()
}

fn table(paths: u8) -> PathBindings {
    PathBindings::new(PathBindingsConfig {
        max_images: 4,
        max_paths: paths,
        path_liveness_timeout: SECOND,
    })
    .unwrap()
}

const SLOT: SlotRef = SlotRef {
    slot: 1,
    generation: 3,
};

fn installed(paths: u8) -> PathBindings {
    let mut table = table(paths);
    assert_eq!(
        table.bind_first(SLOT, identity(1), term(), key(0, 7000), joins(&[640, 0]), 0),
        Ok(0)
    );
    table
}

#[test]
fn a_table_needs_rows_and_paths() {
    for (max_images, max_paths) in [(0, 4), (4, 0)] {
        assert!(
            PathBindings::new(PathBindingsConfig {
                max_images,
                max_paths,
                path_liveness_timeout: SECOND,
            })
            .is_err()
        );
    }
}

/// RP-1: a later path naming the image exactly is bound; its joins are
/// recorded whether above or below the image's, and never applied.
#[test]
fn a_later_path_is_bound_and_its_joins_recorded() {
    let mut table = installed(4);
    // Above the image's join on lane 0, below on lane 1 (a lagging path).
    let later = joins(&[1280, 0]);
    assert_eq!(
        table.offer_later(SLOT, key(1, 7000), identity(1), term(), later, 5),
        Ok(1)
    );
    assert_eq!(table.joins(SLOT, 1), Some(later));
    assert_eq!(table.joins(SLOT, 0), Some(joins(&[640, 0])));
    assert_eq!(table.live(SLOT), 2);
    assert_eq!(table.lookup(key(1, 7000)), Some((SLOT, 1)));
    // The same source on another endpoint is another path.
    assert_eq!(
        table.offer_later(SLOT, key(0, 7001), identity(1), term(), later, 5),
        Ok(2)
    );
    assert_eq!(table.counters().bound, 3);
}

/// RP-1: identity, term parameters and lane count must match exactly;
/// a refusal leaves the image and its bindings unchanged.
#[test]
fn a_mismatched_path_is_refused_and_changes_nothing() {
    let mut table = installed(4);
    let other_term = TermParams {
        mtu: 1200,
        ..term()
    };
    let cases = [
        (
            table.offer_later(SLOT, key(1, 1), identity(2), term(), joins(&[0, 0]), 1),
            PathRefusal::Identity,
        ),
        (
            table.offer_later(SLOT, key(1, 1), identity(1), other_term, joins(&[0, 0]), 1),
            PathRefusal::Parameters,
        ),
        (
            table.offer_later(SLOT, key(1, 1), identity(1), term(), joins(&[0]), 1),
            PathRefusal::Parameters,
        ),
        (
            table.offer_later(SLOT, key(0, 7000), identity(1), term(), joins(&[0, 0]), 1),
            PathRefusal::Bound,
        ),
    ];
    for (result, refusal) in cases {
        assert_eq!(result, Err(refusal));
    }
    assert_eq!(table.live(SLOT), 1);
    assert_eq!(table.joins(SLOT, 0), Some(joins(&[640, 0])));
    let counters = table.counters();
    assert_eq!(
        (counters.refused_identity, counters.refused_parameters),
        (1, 2)
    );
}

/// A full image refuses another path; a stale slot generation is not the
/// image.
#[test]
fn full_and_stale_images_refuse() {
    let mut table = installed(2);
    assert_eq!(
        table.offer_later(SLOT, key(1, 1), identity(1), term(), joins(&[0, 0]), 1),
        Ok(1)
    );
    assert_eq!(
        table.offer_later(SLOT, key(2, 1), identity(1), term(), joins(&[0, 0]), 1),
        Err(PathRefusal::Full)
    );
    assert_eq!(table.counters().refused_full, 1);
    let stale = SlotRef {
        generation: 2,
        ..SLOT
    };
    assert_eq!(
        table.offer_later(stale, key(3, 1), identity(1), term(), joins(&[0, 0]), 1),
        Err(PathRefusal::UnknownImage)
    );
    assert!(!table.refresh(stale, 0, 1));
    assert_eq!(table.live(stale), 0);
    let beyond = SlotRef {
        slot: 9,
        generation: 0,
    };
    assert_eq!(
        table.bind_first(beyond, identity(1), term(), key(0, 1), joins(&[0]), 0),
        Err(PathRefusal::UnknownImage)
    );
}

/// RP-2: a binding with no fresh evidence for the timeout is lost and
/// counted, the image keeps its other bindings, and a refresh or a
/// PATH_HB keeps a binding live.
#[test]
fn a_path_without_fresh_evidence_is_lost() {
    let mut table = installed(4);
    table
        .offer_later(SLOT, key(1, 7000), identity(1), term(), joins(&[640, 0]), 0)
        .unwrap();
    // Path 0 gets fresh DATA, path 1 a PATH_HB, just before the timeout.
    assert!(table.refresh(SLOT, 0, SECOND - 1));
    assert_eq!(table.path_hb(key(1, 7000), SECOND - 1), Some((SLOT, 1)));
    let mut lost = Vec::new();
    assert_eq!(
        table.timers(SECOND, u32::MAX, |slot, path, key| lost
            .push((slot, path, key))),
        0
    );
    // Only path 1 is refreshed again.
    assert!(table.refresh(SLOT, 1, 2 * SECOND - 2));
    assert_eq!(
        table.timers(2 * SECOND - 1, u32::MAX, |slot, path, key| lost
            .push((slot, path, key))),
        1
    );
    assert_eq!(lost, vec![(SLOT, 0, key(0, 7000))]);
    assert_eq!(table.live(SLOT), 1);
    assert_eq!(table.lookup(key(0, 7000)), None);
    assert_eq!(table.counters().lost, 1);
    // A path that comes back binds again, through its fresh challenge.
    assert_eq!(
        table.offer_later(
            SLOT,
            key(0, 7000),
            identity(1),
            term(),
            joins(&[700, 0]),
            2 * SECOND
        ),
        Ok(0)
    );
}

/// PATH_HB creates nothing: from an unbound key it is counted and
/// ignored.
#[test]
fn a_path_hb_creates_nothing() {
    let mut table = installed(4);
    assert_eq!(table.path_hb(key(5, 5), 1), None);
    assert_eq!(table.counters().path_hb_unbound, 1);
    assert_eq!(table.live(SLOT), 1);
}

/// Retirement removes the row; a new image at the slot's next generation
/// starts afresh.
#[test]
fn retirement_clears_the_image() {
    let mut table = installed(4);
    table
        .offer_later(SLOT, key(1, 1), identity(1), term(), joins(&[0, 0]), 1)
        .unwrap();
    table.image_retired(SLOT);
    assert_eq!(table.live(SLOT), 0);
    assert_eq!(table.lookup(key(1, 1)), None);
    let next = SlotRef {
        generation: 4,
        ..SLOT
    };
    assert_eq!(
        table.bind_first(next, identity(2), term(), key(2, 2), joins(&[0]), 5),
        Ok(0)
    );
    assert_eq!(table.live(next), 1);
    assert_eq!(table.live(SLOT), 0);
}

/// A first binding at a slot's new generation drops every binding of the
/// slot's earlier image (#247 review P3).
#[test]
fn a_first_binding_replaces_an_older_generation() {
    let mut table = installed(4);
    table
        .offer_later(SLOT, key(1, 1), identity(1), term(), joins(&[0, 0]), 1)
        .unwrap();
    let next = SlotRef {
        generation: 4,
        ..SLOT
    };
    table
        .bind_first(next, identity(2), term(), key(2, 2), joins(&[0]), 5)
        .unwrap();
    assert_eq!(table.lookup(key(1, 1)), None);
    assert_eq!(table.lookup(key(0, 7000)), None);
    assert_eq!(table.live(next), 1);
}
