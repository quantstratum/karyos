// SPDX-License-Identifier: Apache-2.0

//! The logic of `karyos-errors` (`quantstratum-docs:
//! karyos/design/observability-and-tools.md`, Binaries): the error log
//! records in sequence order, with first and last time and occurrences,
//! then the loss report records, marking unverified ones. Overwritten
//! sequences are reported only when a scan's boundary proves them.
//!
//! A [`Follower`] remembers what it printed, so each poll prints only what
//! is new: records past the last one printed, and error records whose
//! occurrences changed in place. A scan that stops at a busy slot resumes
//! there on the next poll. Times are host `CLOCK_MONOTONIC` seconds.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use karyos_sys::diag::{ErrorLogReader, ErrorRecord, LossRecord, LossReportReader};

/// The usage text of `karyos-errors --help`.
pub const HELP: &str = "\
karyos-errors: prints a running driver's error log and loss report (Linux).

Usage: karyos-errors --dir <path> [--follow] [--interval <duration>]

  --dir <path>             the driver's admission socket directory (required)
  --follow                 keep printing new records and changed occurrences
  --interval <duration>    period of --follow, at least 1ms [1s]
  -h, --help               print this text

Exit status: 0 when done, or when the driver exits under --follow; 2 on a
command-line or attach error.
";

/// The flag of `karyos-errors`.
pub const FOLLOW: &str = "--follow";

/// Loss record flag bit 0: the reporter's subscription had already ended.
const UNVERIFIED: u8 = 1;

/// What `karyos-errors` printed so far.
#[derive(Debug, Default)]
pub struct Follower {
    /// The next error sequence not printed yet.
    errors_next: u64,
    /// The occurrences printed for each retained error record.
    occurrences: BTreeMap<u64, u64>,
    /// The next loss sequence not printed yet.
    losses_next: u64,
}

impl Follower {
    /// A follower that has printed nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends to `out` what changed since the last poll: the error log
    /// first, then the loss report.
    pub fn poll(&mut self, errors: &ErrorLogReader, losses: &LossReportReader, out: &mut String) {
        self.poll_errors(errors, out);
        self.poll_losses(losses, out);
    }

    fn poll_errors(&mut self, reader: &ErrorLogReader, out: &mut String) {
        // Rescan from the oldest record printed and still tracked, so that
        // an in-place update of an earlier record is seen.
        let start = self
            .occurrences
            .keys()
            .next()
            .copied()
            .unwrap_or(self.errors_next)
            .min(self.errors_next);
        let mut cursor = start;
        let mut records = Vec::new();
        let scan = reader.scan(&mut cursor, |record| records.push(record));
        // The boundary proved `start..oldest` overwritten; only the part
        // never printed is news.
        let oldest = start.saturating_add(scan.overwritten);
        if oldest > self.errors_next {
            let _ = writeln!(
                out,
                "error log: records {}..{} overwritten before they were read",
                self.errors_next, oldest
            );
            self.errors_next = oldest;
        }
        self.occurrences = self.occurrences.split_off(&oldest);
        for record in records {
            if record.seq >= self.errors_next {
                error_line(&record, out);
                self.errors_next = record.seq.saturating_add(1);
                let _ = self.occurrences.insert(record.seq, record.occurrences);
            } else if let Some(printed) = self.occurrences.get_mut(&record.seq)
                && *printed != record.occurrences
            {
                let _ = writeln!(
                    out,
                    "error #{} now {} occurrences, last at {}",
                    record.seq,
                    record.occurrences,
                    seconds(record.last)
                );
                *printed = record.occurrences;
            }
        }
    }

    fn poll_losses(&mut self, reader: &LossReportReader, out: &mut String) {
        let start = self.losses_next;
        let mut records = Vec::new();
        let scan = reader.scan(&mut self.losses_next, |seq, record| {
            records.push((seq, record))
        });
        if scan.overwritten > 0 {
            let _ = writeln!(
                out,
                "loss report: records {}..{} overwritten before they were read",
                start,
                start.saturating_add(scan.overwritten)
            );
        }
        for (seq, record) in records {
            loss_line(seq, &record, out);
        }
    }
}

/// A host `CLOCK_MONOTONIC` time in nanoseconds, as seconds.
fn seconds(nanos: u64) -> String {
    format!("{}.{:09} s", nanos / 1_000_000_000, nanos % 1_000_000_000)
}

fn error_line(record: &ErrorRecord, out: &mut String) {
    let _ = writeln!(
        out,
        "error #{} code {} source {} key [{}, {}] occurrences {} first at {} last at {}: {}",
        record.seq,
        record.code,
        record.source,
        record.key[0],
        record.key[1],
        record.occurrences,
        seconds(record.first),
        seconds(record.last),
        record.message
    );
}

fn loss_line(seq: u64, record: &LossRecord, out: &mut String) {
    let _ = writeln!(
        out,
        "loss #{seq} kind {} reason {} stream {} (registration {}, incarnation {}) lane {} \
         lost [{}, {}) policy {} applied {} participant {} client {} at {}{}",
        record.kind,
        record.reason,
        record.stream_id,
        record.stream_registration,
        record.incarnation,
        record.lane,
        record.from,
        record.to,
        record.configured_policy,
        record.applied_policy,
        record.participant,
        record.client,
        seconds(record.time),
        if record.flags & UNVERIFIED != 0 {
            " (unverified)"
        } else {
            ""
        }
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use karyos_sys::diag::{error_log, loss_report};

    fn polled(
        follower: &mut Follower,
        errors: &ErrorLogReader,
        losses: &LossReportReader,
    ) -> Vec<String> {
        let mut out = String::new();
        follower.poll(errors, losses, &mut out);
        out.lines().map(str::to_owned).collect()
    }

    fn loss(time: u64, flags: u8) -> LossRecord {
        LossRecord {
            time,
            kind: 1,
            stream_id: 2,
            from: 64,
            to: 128,
            flags,
            ..LossRecord::default()
        }
    }

    #[test]
    fn records_print_once_and_in_place_updates_print_as_changes() {
        let mut log = error_log(8, 1_000).unwrap();
        let mut report = loss_report(8).unwrap();
        let (errors, losses) = (log.reader(), report.reader());
        let mut follower = Follower::new();
        assert!(polled(&mut follower, &errors, &losses).is_empty());

        let _ = log.report(1_000_000_000, 7, 1, [2, 1], "stream rejected");
        let _ = report.record(&loss(5, 0));
        let _ = report.record(&loss(6, UNVERIFIED));
        let lines = polled(&mut follower, &errors, &losses);
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert!(lines[0].starts_with("error #0 code 7 source 1 key [2, 1] occurrences 1"));
        assert!(lines[0].ends_with(": stream rejected"));
        assert!(lines[1].starts_with("loss #0 ") && !lines[1].contains("unverified"));
        assert!(lines[2].starts_with("loss #1 ") && lines[2].ends_with("(unverified)"));

        // Nothing new: nothing printed.
        assert!(polled(&mut follower, &errors, &losses).is_empty());
        // A repeat inside the window updates the record in place.
        let _ = log.report(1_000_000_500, 7, 1, [2, 1], "stream rejected");
        assert_eq!(
            polled(&mut follower, &errors, &losses),
            ["error #0 now 2 occurrences, last at 1.000000500 s"]
        );
        // A different error is a new record.
        let _ = log.report(2_000_000_000, 9, 1, [3, 1], "other");
        let lines = polled(&mut follower, &errors, &losses);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with("error #1 code 9"));
    }

    #[test]
    fn overwritten_records_are_reported_only_when_unread() {
        let mut log = error_log(2, 1).unwrap();
        let mut report = loss_report(2).unwrap();
        let (errors, losses) = (log.reader(), report.reader());
        let mut follower = Follower::new();
        let _ = log.report(10, 1, 1, [1, 0], "a");
        assert_eq!(polled(&mut follower, &errors, &losses).len(), 1);
        // Three more distinct records in a ring of two: #1 is lost unread,
        // #0 was read before it went.
        for code in 2..=4 {
            let _ = log.report(10 * u64::from(code), code, 1, [u64::from(code), 0], "x");
        }
        for time in 0..3 {
            let _ = report.record(&loss(time, 0));
        }
        let lines = polled(&mut follower, &errors, &losses);
        assert_eq!(
            lines[0],
            "error log: records 1..2 overwritten before they were read"
        );
        assert!(lines[1].starts_with("error #2 "));
        assert!(lines[2].starts_with("error #3 "));
        assert_eq!(
            lines[3],
            "loss report: records 0..1 overwritten before they were read"
        );
        assert!(lines[4].starts_with("loss #1 ") && lines[5].starts_with("loss #2 "));
        assert_eq!(lines.len(), 6, "{lines:?}");
        assert!(polled(&mut follower, &errors, &losses).is_empty());
    }
}
