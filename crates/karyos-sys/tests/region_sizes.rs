// SPDX-License-Identifier: Apache-2.0

//! R-CORE-34, the size functions against the regions (Linux): every kind of
//! shared region the driver creates is created here, and both its record's
//! `structure_length` and the size of its `memfd` are compared with the
//! extracted function and `sizing::region_length`. A sizing report built
//! from those functions therefore states the size each region is mapped
//! with, and cannot drift from the constructors.

#![cfg(all(target_os = "linux", not(loom)))]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

use karyos_sys::conflation::ConflationConfig;
use karyos_sys::frame::Lane;
use karyos_sys::ipc::{Region, RegionKind};
use karyos_sys::log_buffer::{LogBuffer, LogBufferConfig, PublicationMode};
use karyos_sys::record_journal::JournalLayout;
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength, region_length};
use karyos_sys::term::{Generation, TermId};
use karyos_sys::term_bytes::SharedTerms;

const INSTANCE: u128 = 0x5157_0001;

/// The region is of `kind`, its record states `structure`, and its `memfd`
/// is exactly the region length of `structure`.
fn check(region: &Region, kind: RegionKind, structure: Option<usize>) {
    let structure = structure.unwrap_or_else(|| panic!("{kind:?}: no structure length"));
    let record = region.record();
    assert_eq!(record.kind, kind);
    assert_eq!(record.structure_length, structure, "{kind:?}: record");
    let stat = rustix::fs::fstat(region.descriptor().unwrap()).unwrap();
    assert_eq!(
        usize::try_from(stat.st_size).unwrap(),
        region_length(structure).unwrap(),
        "{kind:?}: memfd size"
    );
}

#[test]
fn every_region_kind_is_created_at_its_extracted_size() {
    let mut next = 1u64;
    let mut id = || {
        next += 1;
        next
    };
    for capacity in [1024, 64 * 1024] {
        let ring =
            karyos_sys::command_ring::RingConsumer::create_in(INSTANCE, id(), capacity).unwrap();
        check(
            ring.region().unwrap(),
            RegionKind::CommandRing,
            karyos_sys::command_ring::structure_length(capacity),
        );
        let broadcast =
            karyos_sys::broadcast::BroadcastTransmitter::create_in(INSTANCE, id(), capacity)
                .unwrap();
        check(
            broadcast.region().unwrap(),
            RegionKind::Broadcast,
            karyos_sys::broadcast::structure_length(capacity),
        );
    }
    for capacity in [1, 256, 1024] {
        let (_, reader) = karyos_sys::counters::counters_in(INSTANCE, id(), capacity).unwrap();
        check(
            reader.region().unwrap(),
            RegionKind::Counters,
            karyos_sys::counters::structure_length(capacity),
        );
        let (_, reader, _) =
            karyos_sys::counters::client_counters_in(INSTANCE, id(), capacity).unwrap();
        check(
            reader.region().unwrap(),
            RegionKind::ClientCounters,
            karyos_sys::counters::structure_length(capacity),
        );
    }
    for capacity in [1, 64, 1000] {
        let log = karyos_sys::diag::error_log_in(INSTANCE, id(), capacity, 1).unwrap();
        check(
            log.region().unwrap(),
            RegionKind::ErrorLog,
            karyos_sys::diag::error_log_structure_length(capacity),
        );
        let losses = karyos_sys::diag::loss_report_in(INSTANCE, id(), capacity).unwrap();
        check(
            losses.region().unwrap(),
            RegionKind::LossReport,
            karyos_sys::diag::loss_report_structure_length(capacity),
        );
        let audit = karyos_sys::diag::guard_audit_in(INSTANCE, id(), capacity).unwrap();
        check(
            audit.region().unwrap(),
            RegionKind::GuardAudit,
            karyos_sys::diag::guard_audit_structure_length(capacity),
        );
    }
    for (entries, log, capacity) in [(1, 1, 1), (16, 64, 4096)] {
        let mirror =
            karyos_sys::trace_mirror::trace_mirror_in(INSTANCE, id(), entries, log, capacity)
                .unwrap();
        check(
            mirror.region().unwrap(),
            RegionKind::TraceMirror,
            karyos_sys::trace_mirror::structure_length(entries, log, capacity),
        );
    }
    for config in [
        ConflationConfig {
            keys: 5,
            value_capacity: 20,
            journal_capacity: 1024,
        },
        ConflationConfig {
            keys: 4096,
            value_capacity: 256,
            journal_capacity: 1 << 16,
        },
    ] {
        let writer = karyos_sys::conflation::conflation_in(
            INSTANCE,
            id(),
            config.keys,
            config.value_capacity,
            config.journal_capacity,
        )
        .unwrap();
        check(
            writer.region().unwrap(),
            RegionKind::ConflationTable,
            config.structure_length(),
        );
    }
    for layout in [
        JournalLayout {
            capacity: 8,
            payload_words: 1,
            drop_ranges: 1,
        },
        JournalLayout {
            capacity: 1024,
            payload_words: 6,
            drop_ranges: 16,
        },
    ] {
        let drain = karyos_sys::record_journal::journal_region(INSTANCE, id(), layout).unwrap();
        check(
            drain.region().unwrap(),
            RegionKind::Journal,
            layout.structure_bytes(),
        );
    }
    for (term_length, spare_slots) in [(MIN_TERM_LENGTH, 3), (1 << 20, 6)] {
        let config = LogBufferConfig {
            term_length: TermLength::try_new(term_length).unwrap(),
            spare_slots,
            max_subscribers: 4,
            mtu: DEFAULT_MTU,
            max_reserved: term_length / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id: 2,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication: PublicationMode::Exclusive,
            schedule_capacity: 0,
        };
        let buffer = LogBuffer::<SharedTerms>::create_in(
            INSTANCE,
            id(),
            config,
            Generation::try_new(1).unwrap(),
        )
        .unwrap();
        check(
            buffer.region().unwrap(),
            RegionKind::LogBuffer,
            LogBuffer::<SharedTerms>::structure_length(&config),
        );
    }
}
