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
    driver.network.refused.push((publication, u64::MAX));
    driver.refuse_network_journal(publication);
    assert_eq!(driver.network_journals_refused(&publication), u64::MAX);
    assert_eq!(driver.counters.value(Event::CounterOverflows), 1);
    assert_eq!(driver.counters.value(Event::NetworkTraceJournalsRefused), 1);
}

/// The refused counts never outgrow the table reserved at start: a
/// refusal it cannot hold is untracked, and every publication it does not
/// name reports that count; forgetting a publication frees its place.
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
    driver.forget_network_publication(&publication(0));
    assert_eq!(driver.network.refused.len(), capacity - 1);
    driver.refuse_network_journal(publication(3000));
    assert_eq!(driver.network.refused.len(), capacity);
    assert_eq!(driver.network_journals_refused(&publication(3000)), 1);
    assert_eq!(driver.network.refused.capacity(), capacity);
}
