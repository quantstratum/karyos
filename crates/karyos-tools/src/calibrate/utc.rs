// SPDX-License-Identifier: Apache-2.0

//! `karyos-tools calibrate utc` and `calibrate realtime` (karyos#749, the
//! system clock to UTC half).
//!
//! `utc` reads chrony's state, as `chronyc -c tracking` prints it, from a
//! file or standard input ([`parse_tracking`], a pure parser: the tool never
//! runs chronyc), and prints a UTC reference record (ADR-0090;
//! `karyos_trace::clocks::utc::UtcReference`) for the host's
//! `CLOCK_REALTIME`:
//!
//! - the bound is chrony's own error bound at the sample, `|System time| +
//!   Root delay / 2 + Root dispersion`, plus its growth over the whole
//!   validity window as chrony itself grows the root dispersion
//!   (`REF_GetReferenceParams`: `(Skew + |Residual freq| +
//!   maxclockerror) * elapsed`, rates in ppm; `maxclockerror` is not in the
//!   `-c` output and is given by `--max-clock-error-ppm`, chrony's default
//!   1), all rounded up to whole nanoseconds, so the bound covers every
//!   instant of the record's validity;
//! - it is valid from the sample time over a short window the caller gives.
//!   The bound holds **only as sampled**: chrony's dispersion grows between
//!   updates and the clock is slewed, so a record is evidence for the window
//!   right after the sample and nothing else, and a longer claim needs a new
//!   sample;
//! - the source is NTP and the state comes from chrony's leap status and
//!   stratum: "Not synchronised", stratum 0 or 16 and above are
//!   unsynchronised, and an unsynchronised state gives no bound and no
//!   record. A pending leap second is refused too, since the leap table
//!   the record names announces none;
//! - the scale is stepped UTC: `CLOCK_REALTIME` counts Unix nanoseconds,
//!   UTC without leap seconds, so its reading `r` is the UTC coordinate
//!   `r + 4383 days` (1958-01-01 to 1970-01-01).
//!
//! `realtime` (Linux) fits `CLOCK_MONOTONIC_RAW` to `CLOCK_REALTIME` from
//! bracketed reads (`karyos_sys::host_clock::realtime_paired_read`) with
//! the PHC fit (`karyos_trace::calibrate::fit`), so a chain raw clock to
//! `CLOCK_REALTIME` to UTC exists. NTP slews `CLOCK_REALTIME`, so a run
//! must be short; a run no line explains (a step or a slew within it) is
//! refused, as for a PHC.
//!
//! Both change no system setting and need no privilege. A tool, off the
//! data path.

use std::io::{Read, Write};

use karyos_trace::clocks::ClockKey;
use karyos_trace::clocks::utc::{Scale, Source, SyncState, UtcReference};
use karyos_trace::journal::ObserverId;

use super::EXIT_ERROR;

#[cfg(test)]
mod tests;

/// The days from 1958-01-01 to 1970-01-01, the Unix epoch.
const UNIX_EPOCH_DAYS: u64 = 4383;
/// The UTC coordinate of the Unix epoch, in nanoseconds.
pub const UNIX_EPOCH_U_NS: u64 = UNIX_EPOCH_DAYS * 86_400 * 1_000_000_000;
/// The IERS Bulletin C a record names by default: number 72, of 6 July
/// 2026 (no leap second at the end of December 2026).
pub const DEFAULT_LEAP_TABLE: u64 = 72;
/// The default domain word of `CLOCK_REALTIME`, apart from the raw
/// clock's 0 and the PHC's 1.
pub const REALTIME_DOMAIN: u64 = 4;
/// The longest validity window `utc` accepts: ten minutes. The bound holds
/// as sampled; a longer claim needs a new sample.
pub const MAX_WINDOW_MS: u64 = 600_000;

/// The usage text of `karyos-tools calibrate utc --help`.
pub const HELP: &str = "\
karyos-tools calibrate utc: a UTC reference record for CLOCK_REALTIME
from chrony's tracking state.

Usage: chronyc -c tracking | karyos-tools calibrate utc [--window-ms 10000]
           [--sampled-at-ns N] [--domain 4] [--epoch 1] [--leap-table 72]
           [--max-clock-error-ppm 1]
       karyos-tools calibrate utc --tracking <file> ...
       karyos-tools calibrate realtime [--reads 4096] [--keep 25]
           [--interval-us 500] [--extension-ms 0] [--source-domain 0]
           [--domain 4] [--epoch 1]

`utc` reads one line of `chronyc -c tracking` (it never runs chronyc)
and prints a UTC reference record: bound |System time| + Root delay/2 +
Root dispersion + (Skew + |Residual freq| + maxclockerror) x window,
chrony's own dispersion growth (maxclockerror is chrony's setting, 1 ppm
by default), rounded up to ns, so it covers the whole window; source NTP; scale stepped UTC; valid
from the sample time (--sampled-at-ns, CLOCK_REALTIME in ns; by default
this tool's own reading of it, so sample chrony right before) over
--window-ms, at most 600000. The bound holds only as sampled: keep the
window short and sample again for a longer claim. To chain it with a
`realtime` record, their validities must overlap: sample `utc` first, or
run `realtime` with --extension-ms; `calibrate compose <calibration>...
<utc record>` checks that and refuses otherwise. An unsynchronised
state (leap status \"Not synchronised\", stratum 0 or 16 and above), a
pending leap second or a missing field prints no record.

`realtime` (Linux) reads CLOCK_MONOTONIC_RAW, CLOCK_REALTIME and
CLOCK_MONOTONIC_RAW again, --reads times, and fits them like `phc`: the
record converts raw times into CLOCK_REALTIME, the clock `utc` speaks
for. NTP slews CLOCK_REALTIME, so keep the run short; a run no line
explains is refused.
";

/// chrony's tracking state, as far as a UTC reference needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tracking {
    /// The reference's name or address.
    pub reference: String,
    /// The host's stratum.
    pub stratum: u64,
    /// `|System time|`, the clock's offset from chrony's estimate, in
    /// attoseconds.
    pub system_time_as: u128,
    /// Root delay, in attoseconds.
    pub root_delay_as: u128,
    /// Root dispersion, in attoseconds.
    pub root_dispersion_as: u128,
    /// Skew, in ppm times 10^18.
    pub skew_appm: u128,
    /// `|Residual freq|`, in ppm times 10^18.
    pub residual_appm: u128,
    /// The leap status, as chrony prints it.
    pub leap_status: String,
    /// The synchronisation state the leap status and stratum give.
    pub sync_state: SyncState,
}

impl Tracking {
    /// chrony's bound over `window_ns` after the sample, in nanoseconds
    /// rounded up: `|System time| + Root delay / 2 + Root dispersion +
    /// (Skew + |Residual freq| + max_clock_error) * window`, the rates in
    /// ppm (`max_clock_error_appm` in ppm times 10^18); `None` when
    /// unsynchronised (no bound exists) or on overflow.
    #[must_use]
    pub fn bound_ns(&self, window_ns: u64, max_clock_error_appm: u128) -> Option<u64> {
        if self.sync_state != SyncState::Synchronised {
            return None;
        }
        let rate = self
            .skew_appm
            .checked_add(self.residual_appm)?
            .checked_add(max_clock_error_appm)?;
        // window ns * rate (ppm * 10^18) / 10^15 is attoseconds.
        let growth = u128::from(window_ns)
            .checked_mul(rate)?
            .div_ceil(1_000_000_000_000_000);
        let total = self
            .system_time_as
            .checked_add(self.root_delay_as.div_ceil(2))?
            .checked_add(self.root_dispersion_as)?
            .checked_add(growth)?;
        u64::try_from(total.div_ceil(1_000_000_000)).ok()
    }
}

/// A decimal number of seconds, as chronyc prints it (`-0.000012345`), as
/// attoseconds of its magnitude, rounded up past 18 fraction digits.
fn seconds_as(field: &str) -> Option<u128> {
    let unsigned = field
        .strip_prefix('-')
        .or_else(|| field.strip_prefix('+'))
        .unwrap_or(field);
    let (int, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    if int.is_empty() || !int.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let mut value = int
        .parse::<u128>()
        .ok()?
        .checked_mul(1_000_000_000_000_000_000)?;
    let mut scale = 100_000_000_000_000_000_u128;
    let mut rest_nonzero = false;
    for digit in fraction.bytes().map(|byte| u128::from(byte - b'0')) {
        if scale == 0 {
            rest_nonzero |= digit != 0;
        } else {
            value = value.checked_add(digit * scale)?;
            scale /= 10;
        }
    }
    if rest_nonzero {
        value = value.checked_add(1)?;
    }
    Some(value)
}

/// Parses `chronyc -c tracking`: one line of 14 comma-separated fields
/// (reference id, reference name, stratum, reference time, system time,
/// last offset, RMS offset, frequency, residual frequency, skew, root
/// delay, root dispersion, update interval, leap status). Blank lines are
/// skipped; more than one tracking line is refused.
///
/// # Errors
///
/// A message naming the missing or malformed field.
pub fn parse_tracking(text: &str) -> Result<Tracking, String> {
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    let line = lines
        .next()
        .ok_or("no tracking line: give the output of `chronyc -c tracking`")?;
    if lines.next().is_some() {
        return Err("more than one tracking line".to_owned());
    }
    let fields: Vec<&str> = line.trim().split(',').map(str::trim).collect();
    let [
        _id,
        reference,
        stratum,
        _reference_time,
        system_time,
        _last_offset,
        _rms_offset,
        _frequency,
        residual,
        skew,
        root_delay,
        root_dispersion,
        _interval,
        leap_status,
    ] = fields.as_slice()
    else {
        return Err(format!(
            "{} fields: `chronyc -c tracking` prints 14",
            fields.len()
        ));
    };
    let missing = |name: &str| format!("the {name} field is missing or malformed");
    let nonempty = |value: &&str, name: &str| {
        if value.is_empty() {
            Err(missing(name))
        } else {
            Ok(())
        }
    };
    nonempty(leap_status, "leap status")?;
    let stratum: u64 = stratum.parse().map_err(|_| missing("stratum"))?;
    let system_time_as = seconds_as(system_time).ok_or_else(|| missing("system time"))?;
    let root_delay_as = seconds_as(root_delay).ok_or_else(|| missing("root delay"))?;
    let root_dispersion_as =
        seconds_as(root_dispersion).ok_or_else(|| missing("root dispersion"))?;
    let residual_appm = seconds_as(residual).ok_or_else(|| missing("residual frequency"))?;
    let skew_appm = seconds_as(skew).ok_or_else(|| missing("skew"))?;
    let sync_state = match *leap_status {
        "Not synchronised" => SyncState::Unsynchronised,
        "Normal" | "Insert second" | "Delete second" if (1..16).contains(&stratum) => {
            SyncState::Synchronised
        }
        "Normal" | "Insert second" | "Delete second" => SyncState::Unsynchronised,
        other => return Err(format!("unknown leap status {other}")),
    };
    Ok(Tracking {
        reference: (*reference).to_owned(),
        stratum,
        system_time_as,
        root_delay_as,
        root_dispersion_as,
        skew_appm,
        residual_appm,
        leap_status: (*leap_status).to_owned(),
        sync_state,
    })
}

/// What `utc` states besides chrony's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtcSettings {
    /// `CLOCK_REALTIME` at the sample, in ns since the Unix epoch.
    pub sampled_at: u64,
    /// The validity past the sample, in ms.
    pub window_ms: u64,
    /// `CLOCK_REALTIME`'s domain word.
    pub domain: u64,
    /// The calibration epoch.
    pub epoch: u64,
    /// The IERS Bulletin C number.
    pub leap_table: u64,
    /// chrony's `maxclockerror`, in ppm times 10^18.
    pub max_clock_error_appm: u128,
}

/// chrony's default `maxclockerror`, 1 ppm, in ppm times 10^18.
pub const DEFAULT_MAX_CLOCK_ERROR_APPM: u128 = 1_000_000_000_000_000_000;

/// The UTC reference record of `tracking` for `CLOCK_REALTIME`.
///
/// # Errors
///
/// A message for an unsynchronised state, a pending leap second, a window
/// past [`MAX_WINDOW_MS`], an overflow, or a record the codec refuses.
pub fn reference(tracking: &Tracking, settings: &UtcSettings) -> Result<UtcReference, String> {
    if tracking.sync_state != SyncState::Synchronised {
        return Err(format!(
            "chrony is not synchronised (leap status {}, stratum {}): no bound, no record",
            tracking.leap_status, tracking.stratum
        ));
    }
    if tracking.leap_status != "Normal" {
        return Err(format!(
            "a leap second is pending ({}), which leap table {} does not announce: no record",
            tracking.leap_status, settings.leap_table
        ));
    }
    if settings.window_ms == 0 || settings.window_ms > MAX_WINDOW_MS {
        return Err(format!("--window-ms takes 1 to {MAX_WINDOW_MS}"));
    }
    let window_ns = settings.window_ms.saturating_mul(1_000_000);
    let bound = tracking
        .bound_ns(window_ns, settings.max_clock_error_appm)
        .ok_or("the bound overflows")?;
    let valid_to = settings
        .sampled_at
        .checked_add(window_ns)
        .ok_or("the validity overflows")?;
    let origin_scale_ns = settings
        .sampled_at
        .checked_add(UNIX_EPOCH_U_NS)
        .ok_or("the sample time overflows")?;
    let record = UtcReference {
        clock: ClockKey {
            observer: ObserverId {
                driver: [0, 0],
                journal: 0,
            },
            domain: settings.domain,
            epoch: settings.epoch,
        },
        source: Source::Ntp,
        sync_state: SyncState::Synchronised,
        bound,
        valid_from: settings.sampled_at,
        valid_to,
        tick_fs: 1_000_000,
        scale: Scale::UtcStepped,
        origin: settings.sampled_at,
        origin_scale_ns,
        leap_table: settings.leap_table,
        transform_uncertainty_ns: 0,
    };
    record.encode().map_err(|error| error.to_string())?;
    Ok(record)
}

/// `CLOCK_REALTIME` now, in ns since the Unix epoch.
fn realtime_now() -> Option<u64> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    u64::try_from(elapsed.as_nanos()).ok()
}

/// Runs `karyos-tools calibrate utc`, reading `input` without
/// `--tracking`.
pub fn run_utc(
    args: impl Iterator<Item = std::ffi::OsString>,
    input: &mut dyn Read,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let fail = |err: &mut dyn Write, message: &str| {
        let _ = writeln!(err, "karyos-tools calibrate utc: {message}");
        EXIT_ERROR
    };
    let mut args = args;
    let mut tracking_path = None;
    let mut sampled_at = None;
    let mut settings = UtcSettings {
        sampled_at: 0,
        window_ms: 10_000,
        domain: REALTIME_DOMAIN,
        epoch: 1,
        leap_table: DEFAULT_LEAP_TABLE,
        max_clock_error_appm: DEFAULT_MAX_CLOCK_ERROR_APPM,
    };
    while let Some(arg) = args.next() {
        let arg = arg.to_string_lossy().into_owned();
        if arg == "-h" || arg == "--help" {
            let _ = out.write_all(HELP.as_bytes());
            return 0;
        }
        let Some(value) = args
            .next()
            .map(|value| value.to_string_lossy().into_owned())
        else {
            return fail(err, &format!("{arg} needs a value"));
        };
        let number = value.parse::<u64>();
        match (arg.as_str(), number) {
            ("--tracking", _) => tracking_path = Some(value),
            ("--max-clock-error-ppm", _) => match seconds_as(&value) {
                Some(appm) if !value.starts_with('-') => settings.max_clock_error_appm = appm,
                _ => return fail(err, &format!("bad argument {arg} {value}")),
            },
            ("--sampled-at-ns", Ok(number)) => sampled_at = Some(number),
            ("--window-ms", Ok(number)) => settings.window_ms = number,
            ("--domain", Ok(number)) => settings.domain = number,
            ("--epoch", Ok(number)) => settings.epoch = number,
            ("--leap-table", Ok(number)) => settings.leap_table = number,
            _ => return fail(err, &format!("bad argument {arg} {value}")),
        }
    }
    let text = match tracking_path {
        Some(path) => std::fs::read_to_string(&path).map_err(|error| format!("{path}: {error}")),
        None => {
            let mut text = String::new();
            input
                .read_to_string(&mut text)
                .map(|_| text)
                .map_err(|error| format!("standard input: {error}"))
        }
    };
    let Some(sampled_at) = sampled_at.or_else(realtime_now) else {
        return fail(err, "cannot read CLOCK_REALTIME");
    };
    settings.sampled_at = sampled_at;
    let made = text
        .and_then(|text| parse_tracking(&text))
        .and_then(|tracking| reference(&tracking, &settings).map(|record| (tracking, record)));
    let (tracking, record) = match made {
        Ok(made) => made,
        Err(error) => return fail(err, &error),
    };
    let words = match record.encode() {
        Ok(words) => words,
        Err(error) => return fail(err, &error.to_string()),
    };
    let written = writeln!(
        out,
        "utc reference for CLOCK_REALTIME (domain {}, epoch {}): chrony via {} at stratum {}, bound {} ns (|System time| + Root delay/2 + Root dispersion + (Skew + |Residual freq| + maxclockerror) x window), valid realtime {} to {}, scale UTC stepped, leap table {}",
        record.clock.domain,
        record.clock.epoch,
        tracking.reference,
        tracking.stratum,
        record.bound,
        record.valid_from,
        record.valid_to,
        record.leap_table
    )
    .and_then(|()| writeln!(out, "record {}", super::format_record(&words)))
    .and_then(|()| out.flush());
    if written.is_err() {
        return fail(err, "cannot write the result");
    }
    0
}

/// Why a calibration and a UTC reference record do not chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ChainError {
    /// The calibration converts into another clock than the record's.
    #[error(
        "the calibration converts into domain {calibration} epoch {calibration_epoch}, the UTC record is for domain {reference} epoch {reference_epoch}"
    )]
    WrongClock {
        /// The calibration's target domain.
        calibration: u64,
        /// Its epoch.
        calibration_epoch: u64,
        /// The record's domain.
        reference: u64,
        /// Its epoch.
        reference_epoch: u64,
    },
    /// The calibration's validity ends before the record's starts.
    #[error(
        "the calibration ends before the UTC record starts: run `calibrate realtime` with `--extension-ms`, or sample `calibrate utc` first"
    )]
    EndsBefore,
    /// The calibration's validity starts after the record's ends.
    #[error(
        "the calibration starts after the UTC record ends: sample `calibrate utc` again, then run `calibrate realtime` within its --window-ms (or with `--extension-ms` before it)"
    )]
    StartsAfter,
    /// The time is outside the calibration's validity.
    #[error("the time is outside the calibration's validity")]
    NotCovered,
    /// The converted time is outside the record's validity, though the two
    /// overlap.
    #[error("the converted time is outside the UTC record's validity")]
    OutsideReference,
    /// The arithmetic does not fit, or the record's scale cannot say (an
    /// inserted second, a leap table this build does not know).
    #[error("the time does not convert to UTC")]
    NoUtc,
}

/// Checks that `calibration` converts into `reference`'s clock and that
/// its validity, converted, overlaps the record's.
///
/// # Errors
///
/// [`ChainError::WrongClock`], [`ChainError::EndsBefore`],
/// [`ChainError::StartsAfter`], or [`ChainError::NoUtc`] on overflow.
pub fn check_chain(
    calibration: &karyos_trace::clocks::Calibration,
    reference: &UtcReference,
) -> Result<(), ChainError> {
    if calibration.to != reference.clock {
        return Err(ChainError::WrongClock {
            calibration: calibration.to.domain,
            calibration_epoch: calibration.to.epoch,
            reference: reference.clock.domain,
            reference_epoch: reference.clock.epoch,
        });
    }
    let (start, _) = calibration
        .convert(
            i128::from(calibration.valid_from),
            i128::from(calibration.valid_from),
        )
        .ok_or(ChainError::NoUtc)?;
    let (_, end) = calibration
        .convert(
            i128::from(calibration.valid_to),
            i128::from(calibration.valid_to),
        )
        .ok_or(ChainError::NoUtc)?;
    if end < i128::from(reference.valid_from) {
        return Err(ChainError::EndsBefore);
    }
    if start > i128::from(reference.valid_to) {
        return Err(ChainError::StartsAfter);
    }
    Ok(())
}

/// The UTC interval, as `U` nanoseconds, of time `t` of the calibration's
/// source clock: `t` converted, both ends to UTC, widened by the record's
/// bound.
///
/// # Errors
///
/// The [`check_chain`] refusals first, then why this `t` does not convert.
pub fn utc_of(
    t: u64,
    calibration: &karyos_trace::clocks::Calibration,
    reference: &UtcReference,
) -> Result<(i128, i128), ChainError> {
    check_chain(calibration, reference)?;
    let time = i128::from(t);
    if !calibration.covers(time, time) {
        return Err(ChainError::NotCovered);
    }
    let (low, high) = calibration.convert(time, time).ok_or(ChainError::NoUtc)?;
    if low < i128::from(reference.valid_from) || high > i128::from(reference.valid_to) {
        return Err(ChainError::OutsideReference);
    }
    let utc = |value: i128| {
        u64::try_from(value)
            .ok()
            .and_then(|value| reference.utc(value))
            .ok_or(ChainError::NoUtc)
    };
    let widen = i128::from(reference.bound_ns().ok_or(ChainError::NoUtc)?);
    let low = utc(low)?.checked_sub(widen).ok_or(ChainError::NoUtc)?;
    let high = utc(high)?.checked_add(widen).ok_or(ChainError::NoUtc)?;
    Ok((low, high))
}

/// Takes `reads` bracketed reads of `CLOCK_REALTIME`, `interval_us` apart.
///
/// # Errors
///
/// A message when the kernel refuses a read.
#[cfg(target_os = "linux")]
pub fn collect_realtime(
    reads: usize,
    interval_us: u64,
) -> Result<Vec<karyos_trace::calibrate::PairedRead>, String> {
    let mut collected = Vec::with_capacity(reads);
    let pause = std::time::Duration::from_micros(interval_us);
    for _ in 0..reads {
        let (before, target, after) = karyos_sys::host_clock::realtime_paired_read()
            .ok_or("the kernel refused a clock read")?;
        collected.push(karyos_trace::calibrate::PairedRead {
            before,
            target,
            after,
        });
        if !pause.is_zero() {
            std::thread::sleep(pause);
        }
    }
    Ok(collected)
}

/// Runs `karyos-tools calibrate realtime` (Linux).
#[cfg(target_os = "linux")]
pub fn run_realtime(
    args: impl Iterator<Item = std::ffi::OsString>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    // The same options as `phc`, with `--domain` naming CLOCK_REALTIME.
    let rewritten = args.map(|arg| {
        if arg == "--domain" {
            "--target-domain".into()
        } else {
            arg
        }
    });
    let mut list: Vec<std::ffi::OsString> =
        vec!["--target-domain".into(), REALTIME_DOMAIN.to_string().into()];
    list.extend(rewritten);
    if list
        .iter()
        .any(|arg| arg == "--device" || arg == "--reverse")
    {
        let _ = writeln!(
            err,
            "karyos-tools calibrate realtime: --device and --reverse are phc options"
        );
        return EXIT_ERROR;
    }
    let settings = match super::parse(list.into_iter()) {
        Ok(Some(settings)) => settings,
        Ok(None) => {
            let _ = out.write_all(HELP.as_bytes());
            return 0;
        }
        Err(error) => {
            let _ = writeln!(err, "karyos-tools calibrate realtime: {error}");
            return EXIT_ERROR;
        }
    };
    let fitted = collect_realtime(settings.reads, settings.interval_us).and_then(|reads| {
        karyos_trace::calibrate::fit(&reads, &super::fit_config(&settings))
            .map_err(|error| error.to_string())
    });
    let fitted = match fitted {
        Ok(fitted) => fitted,
        Err(error) => {
            let _ = writeln!(err, "karyos-tools calibrate realtime: {error}");
            return EXIT_ERROR;
        }
    };
    let calibration = fitted.calibration;
    super::print_record(
        &calibration,
        &format!(
            "realtime: CLOCK_MONOTONIC_RAW (domain {}) to CLOCK_REALTIME (domain {}), reads {} kept {}, narrowest window {} ns, widest kept {} ns, span {} ns; offset {} ns +/- {} ns at raw {} (largest residual {} ns); drift {} ppb +/- {} ppb (halves {} and {} ppb); valid raw {} to {}",
            calibration.from.domain,
            calibration.to.domain,
            fitted.reads,
            fitted.kept,
            fitted.narrowest_window,
            fitted.widest_kept_window,
            fitted.span,
            calibration.offset,
            calibration.offset_uncertainty,
            calibration.reference,
            fitted.largest_residual,
            calibration.drift,
            calibration.drift_uncertainty,
            fitted.half_drifts.0,
            fitted.half_drifts.1,
            calibration.valid_from,
            calibration.valid_to
        ),
        out,
        err,
    )
}
