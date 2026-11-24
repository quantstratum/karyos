// SPDX-License-Identifier: Apache-2.0

//! R-CORE-34 against a running driver (Linux): the sizing report, made from
//! the configuration alone, states exactly the shared regions an IPC driver
//! maps, compared with `/proc/self/maps`. Each region is counted once by its
//! inode, as the memory cgroup charges a shared page once. This test binary
//! holds one test, so no other driver's regions are in the process.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use karyos_driver::sizing::{SizingLine, report};
use karyos_driver::{
    DriverConfig, EmbeddedDriver, IpcConfig, LossPolicy, StreamConfig, SystemClock,
};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode};
use karyos_sys::sizing::{DEFAULT_MTU, TermLength};
use karyos_sys::term::TermId;
use karyos_sys::term_bytes::SharedTerms;

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("karyos-sizing-{}-{name}", std::process::id()));
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

fn stream(stream_id: i32, term_length: u32, spare_slots: u8) -> StreamConfig {
    StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(term_length).unwrap(),
            spare_slots,
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

/// The page size every mapping is rounded up to, as the kernel reports it
/// in smaps; the report takes it from `karyos_sys::ipc::page_size`.
fn kernel_page() -> u64 {
    let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
    let kib: u64 = smaps
        .lines()
        .find_map(|line| line.strip_prefix("KernelPageSize:"))
        .and_then(|rest| rest.trim().strip_suffix("kB"))
        .and_then(|value| value.trim().parse().ok())
        .unwrap();
    kib * 1024
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

/// The report's mapped bytes of the regions a driver with `clients` command
/// rings maps: every configured line but the journal budget. The report
/// already rounds each region up to the page.
fn expected(lines: &[SizingLine], clients: u64) -> u64 {
    lines
        .iter()
        .filter(|line| !line.region.contains("(budget"))
        .map(|line| {
            let count = if line.region == "command rings" {
                clients
            } else {
                line.count
            };
            count * line.bytes_each
        })
        .sum()
}

#[test]
fn the_report_states_exactly_the_regions_a_driver_maps() {
    let page = kernel_page();
    assert_eq!(page, u64::try_from(karyos_sys::ipc::page_size()).unwrap());
    let config = DriverConfig {
        network: Some(karyos_driver::net::NetworkConfig::default()),
        ..DriverConfig::default()
    };
    let mut conflated = stream(4, 64 * 1024, 3);
    conflated.conflation = Some(karyos_sys::conflation::ConflationConfig::new(64, 32, 4096));
    let streams = [stream(2, 64 * 1024, 3), stream(3, 1 << 20, 6), conflated];
    let sizing = report(&config, &streams, karyos_sys::ipc::page_size()).unwrap();
    assert!(
        sizing.peak_bytes > sizing.configured_bytes,
        "a stream retains generations"
    );
    assert_eq!(sizing.heap.len(), 1, "the network journal budget: {sizing}");
    assert!(
        sizing
            .configured
            .iter()
            .any(|line| line.region.contains("conflation table"))
    );
    for line in sizing
        .configured
        .iter()
        .chain(&sizing.heap)
        .chain(&sizing.retained)
    {
        assert!(
            line.region.contains("(budget") || line.bytes_each % page == 0,
            "{} is not in pages",
            line.region
        );
        assert!(!line.inputs.is_empty(), "{} names no input", line.region);
    }
    let before = mapped_regions();
    assert!(before.is_empty(), "another driver's regions: {before:?}");
    let dir = dir("exact");
    let mut driver: EmbeddedDriver<SharedTerms> =
        EmbeddedDriver::with_ipc(config, ipc(&dir), Box::new(SystemClock::new())).unwrap();
    for stream in streams {
        let _ = driver.add_stream(stream).unwrap();
    }
    let mapped: u64 = mapped_regions().values().sum();
    assert_eq!(mapped, expected(&sizing.configured, 0));
    // A client adds its command ring, as the report counts per client.
    let client = std::thread::scope(|scope| {
        let handle =
            scope.spawn(|| karyos_client::ipc::attach(&dir, std::time::Duration::from_secs(5), 16));
        while !handle.is_finished() {
            let _ = driver.do_work().unwrap();
            std::thread::yield_now();
        }
        handle.join().unwrap().unwrap()
    });
    let mapped: u64 = mapped_regions().values().sum();
    assert_eq!(mapped, expected(&sizing.configured, 1));
    drop(client);
}
