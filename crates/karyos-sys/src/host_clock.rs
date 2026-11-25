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

/// Nanoseconds of the host's `CLOCK_TAI`, the clock domain of timed
/// transmission's `Tai` schedules (`quantstratum-docs:
/// karyos/design/timed-tx.md`, TT-2; Linux only), through the same
/// `rustix` `time` feature (its dynamic clock id, which needs no further
/// feature); `None` when the kernel refuses the clock.
#[cfg(target_os = "linux")]
#[must_use]
pub fn host_tai_ns() -> Option<u64> {
    let now = rustix::time::clock_gettime_dynamic(rustix::time::DynamicClockId::Tai).ok()?;
    let seconds = u64::try_from(now.tv_sec).ok()?;
    let nanos = u64::try_from(now.tv_nsec).ok()?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|ns| ns.checked_add(nanos))
}

/// One bracketed read of a PTP hardware clock against the host's raw
/// monotonic clock (karyos#749): `CLOCK_MONOTONIC_RAW`, then the PHC
/// through its dynamic clock id, then `CLOCK_MONOTONIC_RAW` again, each in
/// nanoseconds. `CLOCK_MONOTONIC_RAW` is never slewed by NTP; on a host
/// whose clock source is `tsc` it is the TSC at a fixed scale, which is how
/// a calibration of it stands for the TSC without reading the counter
/// itself (an instruction `karyos-sys` cannot issue without `unsafe`).
/// `None` when the kernel refuses a read. A control-path call: nothing on
/// the data path reads a PHC.
#[cfg(target_os = "linux")]
#[must_use]
pub fn phc_paired_read(phc: std::os::fd::BorrowedFd<'_>) -> Option<(u64, u64, u64)> {
    fn ns(time: rustix::time::Timespec) -> Option<u64> {
        let seconds = u64::try_from(time.tv_sec).ok()?;
        let nanos = u64::try_from(time.tv_nsec).ok()?;
        seconds
            .checked_mul(1_000_000_000)
            .and_then(|ns| ns.checked_add(nanos))
    }
    let before = rustix::time::clock_gettime(rustix::time::ClockId::MonotonicRaw);
    let target = rustix::time::clock_gettime_dynamic(rustix::time::DynamicClockId::Dynamic(phc));
    let after = rustix::time::clock_gettime(rustix::time::ClockId::MonotonicRaw);
    Some((ns(before)?, ns(target.ok()?)?, ns(after)?))
}

/// [`phc_paired_read`] the other way round (karyos#749): the PHC, then
/// `CLOCK_MONOTONIC_RAW`, then the PHC again, so a fit of the reads has the
/// PHC as its source and the raw clock as its target. A host that receives
/// over a PTP link converts its PHC's times into its own raw clock with it.
#[cfg(target_os = "linux")]
#[must_use]
pub fn phc_paired_read_reversed(phc: std::os::fd::BorrowedFd<'_>) -> Option<(u64, u64, u64)> {
    fn ns(time: rustix::time::Timespec) -> Option<u64> {
        let seconds = u64::try_from(time.tv_sec).ok()?;
        let nanos = u64::try_from(time.tv_nsec).ok()?;
        seconds
            .checked_mul(1_000_000_000)
            .and_then(|ns| ns.checked_add(nanos))
    }
    let read =
        || rustix::time::clock_gettime_dynamic(rustix::time::DynamicClockId::Dynamic(phc)).ok();
    let before = read()?;
    let raw = rustix::time::clock_gettime(rustix::time::ClockId::MonotonicRaw);
    let after = read()?;
    Some((ns(before)?, ns(raw)?, ns(after)?))
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

    /// A descriptor that is no PTP clock is a refused read, not a
    /// panic or a made-up time (karyos#749).
    #[cfg(all(target_os = "linux", not(miri)))]
    #[test]
    fn a_descriptor_that_is_no_phc_is_refused() {
        use std::os::fd::AsFd;

        let file = std::fs::File::open("/dev/null").unwrap();
        assert_eq!(phc_paired_read(file.as_fd()), None);
        assert_eq!(phc_paired_read_reversed(file.as_fd()), None);
    }

    #[test]
    fn a_timestamp_ahead_of_the_reader_has_age_zero() {
        assert_eq!(age_ns(100, 40), 60);
        assert_eq!(age_ns(40, 100), 0);
        assert_eq!(age_ns(u64::MAX, 0), u64::MAX);
    }

    /// Two processes read one scale (Linux): a child's reading falls between
    /// two readings of the parent taken around it. Miri cannot spawn a
    /// process (karyos#924).
    #[cfg(all(target_os = "linux", not(miri)))]
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
