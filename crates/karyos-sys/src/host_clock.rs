// SPDX-License-Identifier: Apache-2.0

//! The host clock of diagnostic timestamps (`quantstratum-docs:
//! karyos/design/observability-and-tools.md`, "Timestamps"): nanoseconds of
//! the host's `CLOCK_MONOTONIC`, one scale for every process on the host, so
//! a tool computes an age as its own reading minus a stored one. Owner
//! decision, 2026-10-15 (ACS 12585): through `rustix` (`time`) on Linux;
//! the standard library elsewhere, where IPC is in-process only (SPEC.md
//! §4).

/// Nanoseconds of the host's monotonic clock.
#[cfg(target_os = "linux")]
#[must_use]
pub fn host_monotonic_ns() -> u64 {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    let seconds = u64::try_from(now.tv_sec).unwrap_or(0);
    let nanos = u64::try_from(now.tv_nsec).unwrap_or(0);
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|ns| ns.checked_add(nanos))
        .unwrap_or(u64::MAX)
}

/// Nanoseconds of this process's monotonic clock: on a host without
/// cross-process IPC, one process is the whole scale. The scale starts at
/// 1 ns, not 0: the first reading of a process is taken at its origin, and
/// a timestamp of 0 would read as unset (karyos #197).
#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn host_monotonic_ns() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;

    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    let origin = *ORIGIN.get_or_init(Instant::now);
    u64::try_from(origin.elapsed().as_nanos())
        .ok()
        .and_then(|ns| ns.checked_add(1))
        .unwrap_or(u64::MAX)
}

/// The age of a stored timestamp at `now`: `now - stored`, or zero when
/// the stored value is ahead of the reader's clock.
#[must_use]
#[expect(
    clippy::implicit_saturating_sub,
    reason = "ADR-0007 keeps saturating_* out of positions and counters; the age of a timestamp ahead of the reader is written out explicitly as zero"
)]
pub fn age_ns(now: u64, stored: u64) -> u64 {
    if stored > now { 0 } else { now - stored }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_clock_never_goes_back() {
        let first = host_monotonic_ns();
        let second = host_monotonic_ns();
        assert!(second >= first);
    }

    /// A reading is never 0, which a stored timestamp would read as unset
    /// (karyos #197): not even the first reading of a process.
    #[test]
    fn a_reading_is_never_zero() {
        assert!(host_monotonic_ns() > 0);
    }

    #[test]
    fn a_timestamp_ahead_of_the_reader_has_age_zero() {
        assert_eq!(age_ns(100, 40), 60);
        assert_eq!(age_ns(40, 100), 0);
        assert_eq!(age_ns(u64::MAX, 0), u64::MAX);
    }

    /// Two processes read one scale (Linux): a child's reading falls between
    /// two readings of the parent taken around it.
    #[cfg(target_os = "linux")]
    #[test]
    fn two_processes_read_one_scale() {
        if std::env::var_os("KARYOS_HOST_CLOCK_CHILD").is_some() {
            use std::io::Write as _;
            let mut stdout = std::io::stdout();
            writeln!(stdout, "child {}", host_monotonic_ns()).unwrap();
            stdout.flush().unwrap();
            return;
        }
        let before = host_monotonic_ns();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "host_clock::tests::two_processes_read_one_scale",
                "--nocapture",
            ])
            .env("KARYOS_HOST_CLOCK_CHILD", "1")
            .output()
            .unwrap();
        let after = host_monotonic_ns();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        let child: u64 = stdout
            .lines()
            .find_map(|line| line.strip_prefix("child "))
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or_else(|| panic!("no child reading in {stdout}"));
        assert!(
            before <= child && child <= after,
            "{before} {child} {after}"
        );
    }
}
