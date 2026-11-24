// SPDX-License-Identifier: Apache-2.0

//! R-CORE-34 with `max_stream_bytes` (Linux; karyos#809): a driver filled
//! to `max_streams` with conflated lanes at the cap maps, per lane, no more
//! than the report's lane line and no less than the cap, and a refused
//! `add_stream`, `add_aggregate` or `replay_target` maps nothing. Regions
//! are read from `/proc/self/maps` by inode. This test binary holds one
//! test, so no other driver's regions are in the process.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use karyos_driver::replay::ReplayTargetConfig;
use karyos_driver::sizing::{EXCLUDED, EXCLUDED_CAPPED, report};
use karyos_driver::{
    AggregateConfig, DriverConfig, DriverError, EmbeddedDriver, IpcConfig, LossPolicy,
    StreamConfig, SystemClock, stream_lane_bytes,
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
        client_send_buffer: None,
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

fn conflated(stream_id: i32) -> StreamConfig {
    let mut lane = stream(stream_id, TERM);
    lane.conflation = Some(ConflationConfig::new(64, 32, 4096));
    lane
}

#[test]
fn a_driver_full_of_lanes_at_the_cap_maps_within_the_bounded_figure() {
    let cap = stream_lane_bytes(&conflated(1).buffer, conflated(1).conflation.as_ref()).unwrap();
    let config = DriverConfig {
        max_streams: 4,
        max_stream_bytes: Some(cap),
        ..DriverConfig::default()
    };
    // Without the cap the report is the one it was before the cap.
    let uncapped = DriverConfig {
        max_stream_bytes: None,
        ..config
    };
    let page = karyos_sys::ipc::page_size();
    let plain = report(&uncapped, &[], page).unwrap();
    assert_eq!(plain.bounded_bytes, None);
    assert!(plain.bounded.is_empty());
    assert_eq!(plain.excluded, &EXCLUDED[..]);
    // A declared stream above the cap is refused, as add_stream refuses it.
    assert!(report(&config, &[stream(9, TERM * 4)], page).is_err());
    let sizing = report(&config, &[], page).unwrap();
    assert!(sizing.bounded_peak_bytes.unwrap() > sizing.bounded_bytes.unwrap());
    assert_eq!(sizing.excluded, &EXCLUDED_CAPPED[..]);
    let lane_line = &sizing.bounded[0];
    assert_eq!(lane_line.count, 4);
    assert!(mapped_regions().is_empty(), "another driver's regions");
    let dir = dir("full");
    let mut driver: EmbeddedDriver<SharedTerms> =
        EmbeddedDriver::with_ipc(config, ipc(&dir), Box::new(SystemClock::new())).unwrap();
    let fixed = mapped_regions();
    // The regions that are not streams, mapped at start, are exactly the
    // report's lines that are not streams, less the budgets and the
    // command rings of clients not yet connected, as `tests/sizing.rs`
    // counts them: a report that undercounts or overcounts one fails here
    // (karyos#824).
    let fixed_bytes: u64 = fixed.values().sum();
    let regions: u64 = sizing
        .configured
        .iter()
        .filter(|line| !line.region.contains("(budget") && line.region != "command rings")
        .map(|line| line.total)
        .sum();
    assert_eq!(
        fixed_bytes, regions,
        "the driver maps {fixed_bytes} B before any lane; the report's regions are {regions} B"
    );
    // Every lane-creating call refused above the cap maps nothing.
    let larger = TERM * 2;
    assert!(matches!(
        driver.add_stream(stream(7, larger)),
        Err(DriverError::StreamTooLarge { .. })
    ));
    assert_eq!(mapped_regions(), fixed, "add_stream mapped a region");
    let frame = u64::from(karyos_sys::sizing::align_frame(DEFAULT_MTU).unwrap()) * 4;
    assert!(matches!(
        driver.add_aggregate(AggregateConfig {
            stream: stream(8, larger),
            quanta: vec![frame; 2],
        }),
        Err(DriverError::StreamTooLarge { .. })
    ));
    assert_eq!(mapped_regions(), fixed, "add_aggregate mapped a region");
    assert!(matches!(
        driver.replay_target(ReplayTargetConfig {
            stream_id: 9,
            session_id: 9,
            term_length: larger,
            initial_term_id: 0,
            mtu: DEFAULT_MTU,
            join: 0,
            lane: Lane::ZERO,
            source_stream_id: 2,
            source_session_id: 1,
        }),
        Err(DriverError::StreamTooLarge { .. })
    ));
    assert_eq!(mapped_regions(), fixed, "replay_target mapped a region");
    // max_streams lanes, every one at the cap.
    for stream_id in 2..6 {
        let _ = driver.add_stream(conflated(stream_id)).unwrap();
    }
    // Full: the count refuses before the cap is looked at.
    assert_eq!(
        driver.add_stream(stream(6, TERM)).map(|_| ()),
        Err(DriverError::TooManyStreams)
    );
    let lanes: u64 = mapped_regions()
        .iter()
        .filter(|(inode, _)| !fixed.contains_key(inode))
        .map(|(_, bytes)| bytes)
        .sum();
    assert!(
        lanes <= lane_line.total,
        "the lanes map {lanes} B, above the report's {} B",
        lane_line.total
    );
    assert!(
        lanes >= cap * 4,
        "the lanes map {lanes} B, below 4 lanes at the cap ({cap} B each)"
    );
}
