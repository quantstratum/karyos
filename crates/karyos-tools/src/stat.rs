// SPDX-License-Identifier: Apache-2.0

//! The logic of `karyos-stat` (`quantstratum-docs:
//! karyos/design/observability-and-tools.md`, Binaries and "Reading a
//! pass"): one report of a driver's counters regions.
//!
//! - The sample: its age (the host `CLOCK_MONOTONIC` now minus `positions
//!   sampled at`) and whether it is consistent. Every allocated cell of the
//!   driver counters is read inside [`read_pass`], so the position cells,
//!   their membership and the timestamp come from one completed sampling
//!   pass, or are marked inconsistent after a bounded number of attempts.
//! - The driver counters, grouped by their key words: the driver-wide
//!   ones first, then those of each stream lane.
//! - Per stream lane, the limit, head and floor, the publisher headroom
//!   (limit minus head), and each subscriber's position and lag (head minus
//!   position). Differences are checked and signed, so a mixed sample
//!   shows an implausible value with its mark, never an underflow.
//! - The client counters, under their client and stream.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use karyos_sys::counters::{
    CellRead, CounterMetadata, CountersReader, KIND_CLIENT, KIND_PUBLICATION, KIND_SUBSCRIBER,
    PassRead, TYPE_POSITION, read_pass,
};

/// The usage text of `karyos-stat --help`.
pub const HELP: &str = "\
karyos-stat: prints a running driver's counters and stream positions (Linux).

Usage: karyos-stat --dir <path> [--once] [--interval <duration>]

  --dir <path>             the driver's admission socket directory (required)
  --once                   print one report and exit
  --interval <duration>    period of the reports, at least 1ms [1s]
  -h, --help               print this text

Exit status: 0 after --once, or when the driver exits; 2 on a
command-line or attach error.
";

/// The flag of `karyos-stat`.
pub const ONCE: &str = "--once";

/// Attempts at a consistent pass before the values are shown as mixed.
const ATTEMPTS: usize = 8;

/// One allocated cell: its metadata and value.
type Cell = (CounterMetadata, u64);

/// A stream lane's key: the stream registration and the lane.
type Lane = (u64, u8);

/// Labels and values of the counters that share one set of key words.
type Group = Vec<(String, u64)>;

/// Key words of a driver counter: stream, lane, kind and participant.
type Keys = (u64, u8, u8, u64);

/// Every allocated cell of `reader`.
fn read_cells(reader: &CountersReader) -> Vec<Cell> {
    (0..reader.capacity())
        .filter_map(|index| match reader.read(index) {
            CellRead::Allocated {
                metadata, value, ..
            } => Some((metadata, value)),
            _ => None,
        })
        .collect()
}

fn label(metadata: &CounterMetadata) -> String {
    String::from_utf8_lossy(metadata.label()).into_owned()
}

/// The index of the driver-wide cell labelled `name`.
fn fixed(reader: &CountersReader, name: &str) -> Option<usize> {
    (0..reader.capacity()).find(|&index| {
        matches!(reader.read(index), CellRead::Allocated { metadata, .. }
            if metadata.label() == name.as_bytes() && metadata.keys.stream == 0)
    })
}

/// `a - b` as a signed difference, `None` when it does not fit.
fn difference(a: u64, b: u64) -> Option<i64> {
    i64::try_from(i128::from(a) - i128::from(b)).ok()
}

fn signed(value: Option<i64>) -> String {
    value.map_or_else(|| "?".to_owned(), |value| value.to_string())
}

/// The positions of one stream lane.
#[derive(Debug, Default)]
struct Positions {
    limit: Option<u64>,
    head: Option<u64>,
    floor: Option<u64>,
    /// Label, subscriber registration and position.
    subscribers: Vec<(String, u64, u64)>,
}

/// One report of `counters` (the driver counters) and `client_counters`,
/// at host time `now` (nanoseconds).
#[must_use]
pub fn report(counters: &CountersReader, client_counters: &CountersReader, now: u64) -> String {
    let mut out = String::new();
    let epoch = fixed(counters, "positions epoch");
    let read = read_pass(
        // No epoch cell (a region from before positions): one read, shown
        // consistent, as nothing can be mixed.
        || {
            epoch
                .and_then(|index| counters.load_value(index))
                .unwrap_or(0)
        },
        || read_cells(counters),
        ATTEMPTS,
    );
    let (consistent, cells) = match read {
        PassRead::Consistent(cells) => (true, cells),
        PassRead::Inconsistent(cells) => (false, cells),
    };
    // Read with the cells, inside the pass. A completed pass has a
    // positive epoch; its time is 0 where the host clock is not
    // available.
    let fixed_value = |name: &str| {
        cells
            .iter()
            .find(|(metadata, _)| metadata.label() == name.as_bytes() && metadata.keys.stream == 0)
            .map(|(_, value)| *value)
    };
    let sampled = fixed_value("positions epoch").is_some_and(|epoch| epoch > 0);
    let age = fixed_value("positions sampled at")
        .filter(|at| *at != 0)
        .and_then(|at| now.checked_sub(at));
    let _ = writeln!(
        out,
        "sample: {}, {}",
        match (sampled, age) {
            (false, _) => "never sampled".to_owned(),
            (true, Some(age)) => format!("age {}.{:06} ms", age / 1_000_000, age % 1_000_000),
            (true, None) => "age unknown".to_owned(),
        },
        if consistent {
            "consistent"
        } else {
            "inconsistent (values may mix passes)"
        }
    );

    let mut groups: BTreeMap<Keys, Group> = BTreeMap::new();
    let mut lanes: BTreeMap<Lane, Positions> = BTreeMap::new();
    for (metadata, value) in &cells {
        let keys = metadata.keys;
        if metadata.type_id != TYPE_POSITION {
            groups
                .entry((keys.stream, keys.lane, keys.kind, keys.participant))
                .or_default()
                .push((label(metadata), *value));
            continue;
        }
        let positions = lanes.entry((keys.stream, keys.lane)).or_default();
        match metadata.label() {
            b"stream limit" => positions.limit = Some(*value),
            b"stream head" => positions.head = Some(*value),
            b"stream floor" => positions.floor = Some(*value),
            _ if keys.kind == KIND_SUBSCRIBER => {
                positions
                    .subscribers
                    .push((label(metadata), keys.participant, *value));
            }
            _ => {}
        }
    }

    let _ = writeln!(out, "driver counters:");
    for ((stream, lane, kind, participant), counters) in &groups {
        if (*stream, *lane, *kind, *participant) != (0, 0, 0, 0) {
            let _ = writeln!(
                out,
                "  stream {stream} lane {lane} kind {kind} participant {participant}:"
            );
        }
        for (label, value) in counters {
            let _ = writeln!(out, "    {label:<40} {value}");
        }
    }

    let _ = writeln!(out, "streams:");
    if lanes.is_empty() {
        let _ = writeln!(out, "  (none sampled)");
    }
    for ((stream, lane), positions) in &lanes {
        let show = |value: Option<u64>| value.map_or_else(|| "?".to_owned(), |v| v.to_string());
        let headroom = positions
            .limit
            .zip(positions.head)
            .and_then(|(limit, head)| difference(limit, head));
        let _ = writeln!(
            out,
            "  stream {stream} lane {lane}: limit {} head {} floor {} headroom {}",
            show(positions.limit),
            show(positions.head),
            show(positions.floor),
            signed(headroom)
        );
        for (label, registration, position) in &positions.subscribers {
            let lag = positions.head.and_then(|head| difference(head, *position));
            let _ = writeln!(
                out,
                "    {label} (registration {registration}): position {position} lag {}",
                signed(lag)
            );
        }
    }

    let _ = writeln!(out, "client counters:");
    // No pass: each client cell is read on its own. A counter keyed to
    // its client names it; one keyed to a participant names that
    // registration.
    let mut clients: BTreeMap<(u8, u64, u64), Group> = BTreeMap::new();
    for (metadata, value) in read_cells(client_counters) {
        let keys = metadata.keys;
        clients
            .entry((keys.kind, keys.participant, keys.stream))
            .or_default()
            .push((label(&metadata), value));
    }
    if clients.is_empty() {
        let _ = writeln!(out, "  (none)");
    }
    for ((kind, participant, stream), counters) in &clients {
        let owner = match *kind {
            KIND_CLIENT => "client",
            KIND_SUBSCRIBER => "subscriber",
            KIND_PUBLICATION => "publication",
            _ => "participant",
        };
        let _ = writeln!(out, "  {owner} {participant} stream {stream}:");
        for (label, value) in counters {
            let _ = writeln!(out, "    {label:<40} {value}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use karyos_driver::{DriverConfig, EmbeddedDriver, LossPolicy, StreamConfig};
    use karyos_sys::frame::Lane as WireLane;
    use karyos_sys::host_clock::host_monotonic_ns;
    use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode, Role};
    use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
    use karyos_sys::term::TermId;

    fn stream_config() -> StreamConfig {
        StreamConfig {
            buffer: LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: 3,
                max_subscribers: 4,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 8,
                initial_term_id: TermId::new(7),
                lane: WireLane::ZERO,
                session_id: 1,
                stream_id: 2,
                claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
                publication: PublicationMode::Exclusive,
            },
            allow_unconnected: true,
            on_required_loss: LossPolicy::Hold,
            conflation: None,
        }
    }

    #[test]
    fn a_report_shows_the_sample_counters_positions_and_lag() {
        let mut driver = EmbeddedDriver::with_config(DriverConfig {
            position_sample_interval: 1,
            ..DriverConfig::default()
        })
        .unwrap();
        let before = report(&driver.counters(), &driver.client_counters(), 0);
        assert!(
            before.starts_with("sample: never sampled, consistent\n"),
            "{before}"
        );
        assert!(before.contains("  (none sampled)"), "{before}");

        let stream = driver.add_stream(stream_config()).unwrap();
        let _reader = driver.subscribe(stream, Role::Required).unwrap();
        let mut publication = driver.publication(stream).unwrap();
        for _ in 0..3 {
            let _ = publication.offer(&[7u8; 100]).unwrap();
        }
        let _ = driver.do_work().unwrap();
        let text = report(
            &driver.counters(),
            &driver.client_counters(),
            host_monotonic_ns(),
        );
        assert!(text.starts_with("sample: age "), "{text}");
        assert!(text.contains(", consistent\n"), "{text}");
        // Driver-wide counters, by label.
        assert!(text.contains("    streams active"), "{text}");
        // The stream lane: three messages of 100 bytes and a 32-byte header,
        // each aligned to 32 bytes, are 3 * 160 = 480 bytes of head; the
        // reader has read nothing, so its lag is the head.
        let registration = driver.trace_identity(stream).unwrap().registration;
        let lane = text
            .lines()
            .find(|line| line.starts_with(&format!("  stream {registration} lane 0: ")))
            .unwrap_or_else(|| panic!("{text}"));
        assert!(lane.contains(" head 480 floor 0 headroom "), "{lane}");
        let subscriber = text
            .lines()
            .find(|line| line.starts_with("    subscriber position generation 0 cell "))
            .unwrap_or_else(|| panic!("{text}"));
        assert!(subscriber.ends_with("position 0 lag 480"), "{subscriber}");
        assert!(text.ends_with("client counters:\n  (none)\n"), "{text}");
    }

    #[test]
    fn differences_are_checked_and_signed() {
        assert_eq!(difference(10, 4), Some(6));
        assert_eq!(difference(4, 10), Some(-6));
        assert_eq!(difference(u64::MAX, 0), None);
        assert_eq!(signed(None), "?");
    }
}
