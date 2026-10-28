// SPDX-License-Identifier: Apache-2.0

//! R-CORE-34 with `max_stream_bytes` (Linux; karyos#809): a driver filled
//! to `max_streams` with lanes at the cap, one of them conflated, maps no
//! more than the report's bounded steady state, read from
//! `/proc/self/maps` by inode. This test binary holds one test, so no other
//! driver's regions are in the process.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use karyos_driver::sizing::{UNCAPPED_STREAMS, report};
use karyos_driver::{
    DriverConfig, DriverError, EmbeddedDriver, IpcConfig, LossPolicy, StreamConfig, SystemClock,
    stream_lane_bytes,
};
use karyos_sys::conflation::ConflationConfig;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode};
use karyos_sys::sizing::{DEFAULT_MTU, TermLength};
use karyos_sys::term::TermId;
use karyos_sys::term_bytes::SharedTerms;

const TERM: u32 = 64 * 1024;

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "karyos-sizing-bounded-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn ipc(dir: &Path) -> IpcConfig {
    IpcConfig {
        dir: dir.to_path_buf(),
        max_pending_hellos: 4,
        hello_timeout: 5_000_000_000,
        max_outbound_per_client: 8,
        fetch_deadline: 5_000_000_000,
        max_exports_per_client: 16,
        max_fetches_per_client: 4,
        max_regions_per_fetch: 4,
        max_fetch_bytes: 1 << 30,
        max_tools: 1,
    }
}

fn stream(stream_id: i32, term_length: u32) -> StreamConfig {
    StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(term_length).unwrap(),
            spare_slots: 3,
            max_subscribers: 4,
            mtu: DEFAULT_MTU,
            max_reserved: term_length / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication: PublicationMode::Exclusive,
            schedule_capacity: 0,
        },
        allow_unconnected: true,
        on_required_loss: LossPolicy::Hold,
        conflation: None,
    }
}

/// The size of every distinct `karyos-region` memfd mapped by this process,
/// by inode.
fn mapped_regions() -> BTreeMap<u64, u64> {
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    let mut regions = BTreeMap::new();
    for line in maps
        .lines()
        .filter(|line| line.contains("/memfd:karyos-region"))
    {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (start, end) = fields[0].split_once('-').unwrap();
        let length =
            u64::from_str_radix(end, 16).unwrap() - u64::from_str_radix(start, 16).unwrap();
        let inode: u64 = fields[4].parse().unwrap();
        let size = regions.entry(inode).or_insert(0);
        *size = (*size).max(length);
    }
    regions
}

#[test]
fn a_driver_full_of_lanes_at_the_cap_maps_within_the_bounded_figure() {
    let mut conflated = stream(5, TERM);
    conflated.conflation = Some(ConflationConfig::new(64, 32, 4096));
    let cap = stream_lane_bytes(&conflated.buffer, conflated.conflation.as_ref()).unwrap();
    let config = DriverConfig {
        max_streams: 4,
        max_stream_bytes: Some(cap),
        ..DriverConfig::default()
    };
    // Without the cap the report has no bounded figure and says why.
    let uncapped = DriverConfig {
        max_stream_bytes: None,
        ..config
    };
    let page = karyos_sys::ipc::page_size();
    let plain = report(&uncapped, &[], page).unwrap();
    assert_eq!(plain.bounded_bytes, None);
    assert!(plain.excluded.contains(&UNCAPPED_STREAMS));
    // A declared stream above the cap is refused, as add_stream refuses it.
    assert!(report(&config, &[stream(9, TERM * 4)], page).is_err());
    let sizing = report(&config, &[], page).unwrap();
    let bounded = sizing.bounded_bytes.unwrap();
    assert!(sizing.bounded_peak_bytes.unwrap() > bounded);
    assert!(!sizing.excluded.contains(&UNCAPPED_STREAMS));
    let before = mapped_regions();
    assert!(before.is_empty(), "another driver's regions: {before:?}");
    let dir = dir("full");
    let mut driver: EmbeddedDriver<SharedTerms> =
        EmbeddedDriver::with_ipc(config, ipc(&dir), Box::new(SystemClock::new())).unwrap();
    // A lane above the cap is refused, with nothing mapped.
    assert!(matches!(
        driver.add_stream(stream(7, TERM * 2)),
        Err(DriverError::StreamTooLarge { .. })
    ));
    for stream_id in 2..5 {
        let _ = driver.add_stream(stream(stream_id, TERM)).unwrap();
    }
    let _ = driver.add_stream(conflated).unwrap();
    // Full: the count refuses before the cap is looked at.
    assert_eq!(
        driver.add_stream(stream(6, TERM)).map(|_| ()),
        Err(DriverError::TooManyStreams)
    );
    let mapped: u64 = mapped_regions().values().sum();
    assert!(
        mapped <= bounded,
        "mapped {mapped} B above the bounded figure {bounded} B"
    );
}
