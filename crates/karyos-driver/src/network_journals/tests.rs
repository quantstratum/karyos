// SPDX-License-Identifier: Apache-2.0

// The publication's refused count never wraps; the driver tests of the
// network journals are in `trace_journals/tests.rs`, beside their helpers.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use karyos_protocol::trace_hook::PublicationIdentity;

use crate::EmbeddedDriver;
use crate::counters::Event;

#[test]
fn a_publication_refused_count_never_wraps() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let publication = PublicationIdentity::default();
    driver.network.refused.push(super::Refused {
        publication,
        count: u64::MAX,
        gone: false,
    });
    driver.refuse_network_journal(publication);
    assert_eq!(driver.network_journals_refused(&publication), u64::MAX);
    assert_eq!(driver.counters.value(Event::CounterOverflows), 1);
    assert_eq!(driver.counters.value(Event::NetworkTraceJournalsRefused), 1);
}

/// The refused counts never outgrow the table reserved at start: a
/// refusal it cannot hold is untracked, and every publication it does not
/// name reports that count; a gone publication no mirror entry names
/// gives its place to the next.
#[test]
fn the_refused_counts_are_bounded() {
    let mut driver = EmbeddedDriver::with_config(crate::DriverConfig {
        max_trace_journals: 2,
        ..crate::DriverConfig::default()
    })
    .unwrap();
    let publication = |registration| PublicationIdentity {
        registration,
        ..PublicationIdentity::default()
    };
    let capacity = driver.network.refused.capacity();
    assert!(capacity >= 2);
    for registration in 0..capacity as u64 {
        driver.refuse_network_journal(publication(registration));
    }
    assert_eq!(driver.network_journals_refused(&publication(0)), 1);
    assert_eq!(driver.network_journals_refused(&publication(1000)), 0);
    // Full: an unnamed publication is untracked, and so is every other.
    driver.refuse_network_journal(publication(1000));
    assert_eq!(driver.network.refused.len(), capacity);
    assert_eq!(driver.network_journals_refused(&publication(1000)), 1);
    assert_eq!(driver.network_journals_refused(&publication(2000)), 1);
    assert_eq!(driver.network_journals_refused(&publication(0)), 1);
    // Gone, and named by no mirror entry: its place is reused.
    driver.network_publication_gone(&publication(0));
    assert_eq!(driver.network_journals_refused(&publication(0)), 1, "kept");
    driver.refuse_network_journal(publication(3000));
    assert_eq!(driver.network.refused.len(), capacity);
    assert_eq!(driver.network_journals_refused(&publication(3000)), 1);
    assert_eq!(driver.network.refused.capacity(), capacity);
}

/// #332 review P2-2: a publication's refused count outlives it while a
/// mirror entry names it, so a report built after its close never comes
/// out `Complete`; the table being full does not reuse its place then.
#[test]
fn a_refused_count_outlives_its_publication() {
    use karyos_protocol::trace_hook::NetSide;
    use karyos_sys::frame::Lane;

    let mut driver = EmbeddedDriver::with_config(crate::DriverConfig {
        max_trace_journals: 2,
        ..crate::DriverConfig::default()
    })
    .unwrap();
    let publication = PublicationIdentity {
        driver: driver.driver_id(),
        registration: 3,
        incarnation: 1,
        ..PublicationIdentity::default()
    };
    driver.set_network_trace_hook(NetSide::Sender, None);
    driver.network.hooked = [true, true];
    // Lane 0 has a journal; lane 1 is refused.
    let journal = driver
        .open_network_journal(NetSide::Sender, publication, Lane::ZERO, 3, Some(0))
        .unwrap();
    driver.refuse_network_journal(publication);
    driver.network_publication_gone(&publication);
    drop(journal);
    let _ = driver.do_work().unwrap();
    assert_eq!(driver.network_journals_refused(&publication), 1);
    // Full table: the gone publication still named by its mirror entry
    // keeps its place, and the last refusal is untracked. (Reused, its
    // place would take that refusal and leave it reporting none.)
    let other = |registration| PublicationIdentity {
        registration,
        ..PublicationIdentity::default()
    };
    for registration in 100..100 + driver.network.refused.capacity() as u64 {
        driver.refuse_network_journal(other(registration));
    }
    assert_eq!(driver.network.untracked, 1);
    assert_eq!(driver.network_journals_refused(&publication), 1);
}
