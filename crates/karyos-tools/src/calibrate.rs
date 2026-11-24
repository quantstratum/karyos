// SPDX-License-Identifier: Apache-2.0

//! `karyos-tools calibrate phc` (Linux; karyos#749, the single-host
//! half): a calibration from the host's TSC, read as `CLOCK_MONOTONIC_RAW`
//! (`karyos_sys::host_clock::phc_paired_read`), to a PTP hardware clock,
//! with measured uncertainties (`karyos_trace::calibrate::fit`).
//!
//! It opens the PHC device read-only, takes bracketed reads, fits them and
//! prints the fit's evidence and the encoded calibration record
//! (`karyos_trace::clocks::Calibration::encode`, 18 words). It records
//! which host, clock source and PHC the result holds for, and claims
//! nothing for any other: the record's clocks are this host's. It changes
//! no system setting and runs no PTP daemon; reading the device may need
//! the `clock` group or root, which is the operator's choice. A tool, off
//! the data path.
//!
//! The PHC to UTC half, and a calibration between two hosts, need a PTP
//! daemon between hosts and a grandmaster, which is an owner decision
//! (karyos#749); this tool does neither.

use std::io::Write;

use karyos_trace::calibrate::FitConfig;
#[cfg(target_os = "linux")]
use karyos_trace::calibrate::{PairedRead, fit};
use karyos_trace::clocks::ClockKey;
use karyos_trace::journal::ObserverId;

/// The most reads one run takes: 16 MiB of reads, a few minutes at the
/// default interval.
pub const MAX_READS: usize = 1 << 20;

/// The clock source file, read before and after the reads.
#[cfg(target_os = "linux")]
const CLOCK_SOURCE: &str = "/sys/devices/system/clocksource/clocksource0/current_clocksource";

/// A usage error or a failed run.
pub const EXIT_ERROR: u8 = 3;

/// The usage text of `karyos-tools calibrate --help`.
pub const HELP: &str = "\
karyos-tools calibrate phc: a TSC to PTP hardware clock calibration on
this host, with measured uncertainties (Linux).

Usage: karyos-tools calibrate phc [--device /dev/ptp0] [--reads 4096]
           [--keep 25] [--interval-us 500] [--extension-ms 0]
           [--source-domain N] [--target-domain N] [--epoch N] [--reverse]
       karyos-tools calibrate link --samples <file> [--server-domain N]
           [--client-domain N] [--epoch N] [--max-gap-ms 2000]
       karyos-tools calibrate compose <record> <record> [<record>...]

`phc --reverse` reads the PHC, the raw clock and the PHC again, so the
record converts PHC times into the raw clock (the receiving host of a link).
`link` reads a PTP client's samples (one line each: the client PHC's
time, offsetFromMaster and meanPathDelay in ns, as `pmc` prints them; a
header line and a `DONE` line are skipped) and prints a calibration from
the server's PHC to the client's, bounded by the largest offset plus the
whole path delay (any asymmetry) and the largest change between samples,
valid over the samples, which must be no more than --max-gap-ms apart. `compose` chains
records, each starting where the previous ends, into the one direct
record a cross-host latency needs. A record is the 18 words `phc`, `link`
and `compose` print after `record`.

`phc`:

It reads CLOCK_MONOTONIC_RAW (the TSC at a fixed scale on a host whose
clock source is tsc), the PHC, and CLOCK_MONOTONIC_RAW again, --reads
times, --interval-us apart; keeps the --keep percent with the narrowest
windows; and fits an offset and a drift. The offset uncertainty bounds
every kept read; the drift uncertainty is the spread of the two halves'
slopes plus what the offset uncertainty allows over the span. The result
is valid from the first read to the last plus --extension-ms. It changes
no system setting; the device may need the clock group or root to read.
";

/// The run's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// The PHC device.
    pub device: std::path::PathBuf,
    /// Bracketed reads to take.
    pub reads: usize,
    /// Percentage kept, narrowest windows first.
    pub keep: u8,
    /// Microseconds between reads.
    pub interval_us: u64,
    /// Milliseconds the calibration stays valid past the last read.
    pub extension_ms: u64,
    /// The source clock's domain word.
    pub source_domain: u64,
    /// The target clock's domain word.
    pub target_domain: u64,
    /// The calibration epoch.
    pub epoch: u64,
    /// Read the PHC around the raw clock: the record converts PHC times.
    pub reverse: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            device: "/dev/ptp0".into(),
            reads: 4096,
            keep: 25,
            interval_us: 500,
            extension_ms: 0,
            source_domain: 0,
            target_domain: 1,
            epoch: 1,
            reverse: false,
        }
    }
}

/// Parses the arguments after `calibrate phc`; `Ok(None)` for `--help`.
///
/// # Errors
///
/// A message naming the argument at fault.
pub fn parse(args: impl Iterator<Item = std::ffi::OsString>) -> Result<Option<Settings>, String> {
    let mut settings = Settings::default();
    let mut args = args;
    while let Some(arg) = args.next() {
        let arg = arg.to_str().ok_or("an argument is not UTF-8")?.to_owned();
        if arg == "-h" || arg == "--help" {
            return Ok(None);
        }
        if arg == "--reverse" {
            settings.reverse = true;
            continue;
        }
        let value = args
            .next()
            .ok_or_else(|| format!("{arg} needs a value"))?
            .into_string()
            .map_err(|_| format!("the value of {arg} is not UTF-8"))?;
        let number = || {
            value
                .parse::<u64>()
                .map_err(|_| format!("{arg} takes a whole number, not {value}"))
        };
        match arg.as_str() {
            "--device" => settings.device = value.clone().into(),
            "--reads" => {
                settings.reads = usize::try_from(number()?)
                    .ok()
                    .filter(|reads| *reads <= MAX_READS)
                    .ok_or_else(|| format!("--reads takes at most {MAX_READS}"))?;
            }
            "--keep" => {
                settings.keep = u8::try_from(number()?)
                    .ok()
                    .filter(|keep| (1..=100).contains(keep))
                    .ok_or("--keep takes 1 to 100")?;
            }
            "--interval-us" => settings.interval_us = number()?,
            "--extension-ms" => settings.extension_ms = number()?,
            "--source-domain" => settings.source_domain = number()?,
            "--target-domain" => settings.target_domain = number()?,
            "--epoch" => settings.epoch = number()?,
            _ => return Err(format!("unknown argument {arg}")),
        }
    }
    if settings.source_domain == settings.target_domain {
        return Err("the source and target domains must differ".to_owned());
    }
    Ok(Some(settings))
}

/// The fit's clocks: this host's, told apart by domain.
#[must_use]
pub fn fit_config(settings: &Settings) -> FitConfig {
    let key = |domain| ClockKey {
        observer: ObserverId {
            driver: [0, 0],
            journal: 0,
        },
        domain,
        epoch: settings.epoch,
    };
    FitConfig {
        from: key(settings.source_domain),
        to: key(settings.target_domain),
        keep_percent: settings.keep,
        extension: settings.extension_ms.saturating_mul(1_000_000),
    }
}

/// A one-line file's text, trimmed, or `unknown`.
#[cfg(target_os = "linux")]
fn read_line(path: &std::path::Path) -> String {
    std::fs::read_to_string(path)
        .map_or_else(|_| "unknown".to_owned(), |text| text.trim().to_owned())
}

/// Takes `settings.reads` bracketed reads of the PHC open as `phc`.
///
/// # Errors
///
/// A message when the kernel refuses a read.
#[cfg(target_os = "linux")]
pub fn collect(
    phc: std::os::fd::BorrowedFd<'_>,
    settings: &Settings,
) -> Result<Vec<PairedRead>, String> {
    let mut reads = Vec::with_capacity(settings.reads);
    let pause = std::time::Duration::from_micros(settings.interval_us);
    for _ in 0..settings.reads {
        let read = if settings.reverse {
            karyos_sys::host_clock::phc_paired_read_reversed(phc)
        } else {
            karyos_sys::host_clock::phc_paired_read(phc)
        };
        let (before, target, after) = read.ok_or("the kernel refused a clock read")?;
        reads.push(PairedRead {
            before,
            target,
            after,
        });
        if !pause.is_zero() {
            std::thread::sleep(pause);
        }
    }
    Ok(reads)
}

/// Runs `karyos-tools calibrate` with `args` (after `calibrate`).
#[cfg(target_os = "linux")]
pub fn run(
    args: impl Iterator<Item = std::ffi::OsString>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    use std::os::fd::AsFd;

    let mut args = args;
    match args.next().as_ref().and_then(|arg| arg.to_str()) {
        Some("phc") => {}
        Some("link") => return run_link(args, out, err),
        Some("compose") => return run_compose(args, out, err),
        None | Some("-h" | "--help") => {
            let _ = out.write_all(HELP.as_bytes());
            return 0;
        }
        Some(other) => {
            let _ = writeln!(
                err,
                "karyos-tools calibrate: unknown clock {other} (only phc)"
            );
            return EXIT_ERROR;
        }
    }
    let settings = match parse(args) {
        Ok(Some(settings)) => settings,
        Ok(None) => {
            let _ = out.write_all(HELP.as_bytes());
            return 0;
        }
        Err(error) => {
            let _ = writeln!(err, "karyos-tools calibrate: {error}");
            return EXIT_ERROR;
        }
    };
    let file = match std::fs::File::open(&settings.device) {
        Ok(file) => file,
        Err(error) => {
            let _ = writeln!(
                err,
                "karyos-tools calibrate: cannot open {}: {error}",
                settings.device.display()
            );
            return EXIT_ERROR;
        }
    };
    // The raw clock stands for the TSC only on a tsc clock source, for the
    // whole run: checked before and after the reads.
    let source = read_line(std::path::Path::new(CLOCK_SOURCE));
    if source != "tsc" {
        let _ = writeln!(
            err,
            "karyos-tools calibrate: the clock source is {source}, not tsc: CLOCK_MONOTONIC_RAW does not stand for the TSC, no record"
        );
        return EXIT_ERROR;
    }
    let reads = match collect(file.as_fd(), &settings) {
        Ok(reads) => reads,
        Err(error) => {
            let _ = writeln!(err, "karyos-tools calibrate: {error}");
            return EXIT_ERROR;
        }
    };
    let fitted = match fit(&reads, &fit_config(&settings)) {
        Ok(fitted) => fitted,
        Err(error) => {
            let _ = writeln!(err, "karyos-tools calibrate: {error}");
            return EXIT_ERROR;
        }
    };
    let name = settings
        .device
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let class = std::path::Path::new("/sys/class/ptp").join(&name);
    let interfaces = std::fs::read_dir(class.join("device/net")).map_or_else(
        |_| "unknown".to_owned(),
        |entries| {
            entries
                .filter_map(|entry| {
                    entry
                        .ok()
                        .map(|entry| entry.file_name().to_string_lossy().into_owned())
                })
                .collect::<Vec<_>>()
                .join(",")
        },
    );
    let host = read_line(std::path::Path::new("/proc/sys/kernel/hostname"));
    let after = read_line(std::path::Path::new(CLOCK_SOURCE));
    if after != source {
        let _ = writeln!(
            err,
            "karyos-tools calibrate: the clock source changed from {source} to {after} during the reads, no record"
        );
        return EXIT_ERROR;
    }
    let calibration = fitted.calibration;
    let lines = [
        format!(
            "host {host}, clock source {source}; source clock CLOCK_MONOTONIC_RAW in ns (the TSC at the kernel's fixed scale): a consumer converts times of that clock"
        ),
        format!(
            "phc {} ({}), clock name {}, interfaces {interfaces}",
            settings.device.display(),
            name,
            read_line(&class.join("clock_name"))
        ),
        format!(
            "reads {} kept {} ({} %), narrowest window {} ns, widest kept {} ns, span {} ns",
            fitted.reads,
            fitted.kept,
            settings.keep,
            fitted.narrowest_window,
            fitted.widest_kept_window,
            fitted.span
        ),
        format!(
            "offset {} ns +/- {} ns at raw {} (largest residual {} ns)",
            calibration.offset,
            calibration.offset_uncertainty,
            calibration.reference,
            fitted.largest_residual
        ),
        format!(
            "drift {} ppb +/- {} ppb (halves {} and {} ppb)",
            calibration.drift,
            calibration.drift_uncertainty,
            fitted.half_drifts.0,
            fitted.half_drifts.1
        ),
        format!(
            "valid raw {} to {}",
            calibration.valid_from, calibration.valid_to
        ),
    ];
    let record = match calibration.encode() {
        Ok(words) => format_record(&words),
        Err(error) => {
            let _ = writeln!(err, "karyos-tools calibrate: {error}");
            return EXIT_ERROR;
        }
    };
    let written = lines
        .iter()
        .try_for_each(|line| writeln!(out, "{line}"))
        .and_then(|()| writeln!(out, "record {record}"))
        .and_then(|()| out.flush());
    if let Err(error) = written {
        let _ = writeln!(
            err,
            "karyos-tools calibrate: cannot write the result: {error}"
        );
        return EXIT_ERROR;
    }
    0
}

/// A record's text: its 18 words, as `phc` prints them.
#[must_use]
pub fn format_record(words: &[u64; karyos_trace::clocks::CALIBRATION_WORDS]) -> String {
    words
        .iter()
        .map(|word| format!("{word:#018x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// A record from its 18 words (hexadecimal with `0x`, or decimal).
///
/// # Errors
///
/// A message for a word that does not parse, the wrong count, or a record
/// [`karyos_trace::clocks::Calibration::decode`] refuses.
pub fn parse_record(words: &[&str]) -> Result<karyos_trace::clocks::Calibration, String> {
    let mut parsed = [0_u64; karyos_trace::clocks::CALIBRATION_WORDS];
    if words.len() != parsed.len() {
        return Err(format!(
            "a record has {} words, not {}",
            parsed.len(),
            words.len()
        ));
    }
    for (slot, word) in parsed.iter_mut().zip(words) {
        *slot = match word.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16),
            None => word.parse(),
        }
        .map_err(|_| format!("{word} is not a record word"))?;
    }
    karyos_trace::clocks::Calibration::decode(&parsed).map_err(|error| error.to_string())
}

/// Parses `link` samples: lines of the client PHC's time, the offset and
/// the mean path delay; a header line and a `DONE` line are skipped.
///
/// # Errors
///
/// A message naming the line at fault.
pub fn parse_samples(
    text: &str,
) -> Result<Vec<karyos_trace::calibrate::chain::LinkSample>, String> {
    let mut samples = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.is_empty()
            || line.trim() == "DONE"
            || fields
                .first()
                .is_some_and(|first| first.parse::<u64>().is_err() && number == 0)
        {
            continue;
        }
        let [time, offset, delay] = fields.as_slice() else {
            return Err(format!("line {}: three fields expected", number + 1));
        };
        // pmc prints the offset and the delay with a fraction: whole ns,
        // rounded away from zero so the bound never shrinks; anything but
        // digits after the point is refused.
        let whole = |field: &str| -> Option<i64> {
            let (int, fraction) = field.split_once('.').unwrap_or((field, ""));
            if !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            let value: i64 = int.parse().ok()?;
            let up = fraction.bytes().any(|byte| byte != b'0');
            Some(match (up, int.starts_with('-')) {
                (false, _) => value,
                (true, true) => value - 1,
                (true, false) => value + 1,
            })
        };
        let bad = |what: &str| format!("line {}: bad {what}", number + 1);
        samples.push(karyos_trace::calibrate::chain::LinkSample {
            time: time.parse().map_err(|_| bad("time"))?,
            offset: whole(offset).ok_or_else(|| bad("offset"))?,
            path_delay: whole(delay)
                .and_then(|delay| u64::try_from(delay).ok())
                .ok_or_else(|| bad("delay"))?,
        });
    }
    Ok(samples)
}

/// Runs `karyos-tools calibrate link`.
pub fn run_link(
    args: impl Iterator<Item = std::ffi::OsString>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let mut args = args;
    let (mut samples, mut server, mut client, mut epoch) = (None, 2_u64, 3_u64, 1_u64);
    let mut max_gap_ms = 2_000_u64;
    while let Some(arg) = args.next() {
        let arg = arg.to_string_lossy().into_owned();
        let Some(value) = args
            .next()
            .map(|value| value.to_string_lossy().into_owned())
        else {
            let _ = writeln!(err, "karyos-tools calibrate link: {arg} needs a value");
            return EXIT_ERROR;
        };
        let number = value.parse::<u64>();
        match (arg.as_str(), number) {
            ("--samples", _) => samples = Some(value),
            ("--server-domain", Ok(number)) => server = number,
            ("--client-domain", Ok(number)) => client = number,
            ("--epoch", Ok(number)) => epoch = number,
            ("--max-gap-ms", Ok(number)) => max_gap_ms = number,
            _ => {
                let _ = writeln!(
                    err,
                    "karyos-tools calibrate link: bad argument {arg} {value}"
                );
                return EXIT_ERROR;
            }
        }
    }
    let Some(path) = samples else {
        let _ = writeln!(err, "karyos-tools calibrate link: --samples names the file");
        return EXIT_ERROR;
    };
    let parsed = std::fs::read_to_string(&path)
        .map_err(|error| error.to_string())
        .and_then(|text| parse_samples(&text));
    let key = |domain| ClockKey {
        observer: ObserverId {
            driver: [0, 0],
            journal: 0,
        },
        domain,
        epoch,
    };
    let linked = parsed.and_then(|samples| {
        let count = samples.len();
        karyos_trace::calibrate::chain::link(
            key(server),
            key(client),
            &samples,
            max_gap_ms.saturating_mul(1_000_000),
        )
        .map(|calibration| (calibration, count))
        .map_err(|error| error.to_string())
    });
    let (calibration, count) = match linked {
        Ok(linked) => linked,
        Err(error) => {
            let _ = writeln!(err, "karyos-tools calibrate link: {error}");
            return EXIT_ERROR;
        }
    };
    print_record(
        &calibration,
        &format!(
            "link of {count} samples: offset 0 ns +/- {} ns (largest offset plus the whole path delay), valid server PHC {} to {}",
            calibration.offset_uncertainty, calibration.valid_from, calibration.valid_to
        ),
        out,
        err,
    )
}

/// Runs `karyos-tools calibrate compose`.
pub fn run_compose(
    args: impl Iterator<Item = std::ffi::OsString>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let text: Vec<String> = args.map(|arg| arg.to_string_lossy().into_owned()).collect();
    let words: Vec<&str> = text
        .iter()
        .flat_map(|arg| arg.split_whitespace())
        .filter(|word| *word != "record")
        .collect();
    let width = karyos_trace::clocks::CALIBRATION_WORDS;
    if words.len() < 2 * width || !words.len().is_multiple_of(width) {
        let _ = writeln!(
            err,
            "karyos-tools calibrate compose: two or more records of {width} words each"
        );
        return EXIT_ERROR;
    }
    let mut composed: Option<karyos_trace::clocks::Calibration> = None;
    for chunk in words.chunks(width) {
        let next = match parse_record(chunk) {
            Ok(next) => next,
            Err(error) => {
                let _ = writeln!(err, "karyos-tools calibrate compose: {error}");
                return EXIT_ERROR;
            }
        };
        composed = Some(match composed {
            None => next,
            Some(before) => match karyos_trace::calibrate::chain::compose(&before, &next) {
                Ok(joined) => joined,
                Err(error) => {
                    let _ = writeln!(err, "karyos-tools calibrate compose: {error}");
                    return EXIT_ERROR;
                }
            },
        });
    }
    let Some(calibration) = composed else {
        return EXIT_ERROR;
    };
    print_record(
        &calibration,
        &format!(
            "composed: offset {} ns +/- {} ns, drift {} ppb +/- {} ppb at {}, valid {} to {}",
            calibration.offset,
            calibration.offset_uncertainty,
            calibration.drift,
            calibration.drift_uncertainty,
            calibration.reference,
            calibration.valid_from,
            calibration.valid_to
        ),
        out,
        err,
    )
}

/// Prints `summary` and the record, or fails.
fn print_record(
    calibration: &karyos_trace::clocks::Calibration,
    summary: &str,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let record = match calibration.encode() {
        Ok(words) => format_record(&words),
        Err(error) => {
            let _ = writeln!(err, "karyos-tools calibrate: {error}");
            return EXIT_ERROR;
        }
    };
    if writeln!(out, "{summary}")
        .and_then(|()| writeln!(out, "record {record}"))
        .and_then(|()| out.flush())
        .is_err()
    {
        let _ = writeln!(err, "karyos-tools calibrate: cannot write the result");
        return EXIT_ERROR;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::{Settings, fit_config, parse};

    fn args(list: &[&str]) -> impl Iterator<Item = std::ffi::OsString> {
        list.iter()
            .map(std::ffi::OsString::from)
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn the_defaults_and_every_setting_parse() {
        assert_eq!(parse(args(&[])), Ok(Some(Settings::default())));
        assert_eq!(parse(args(&["--help"])), Ok(None));
        let settings = parse(args(&[
            "--device",
            "/dev/ptp1",
            "--reads",
            "100",
            "--keep",
            "50",
            "--interval-us",
            "0",
            "--extension-ms",
            "2000",
            "--source-domain",
            "7",
            "--target-domain",
            "8",
            "--epoch",
            "9",
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(settings.device, std::path::PathBuf::from("/dev/ptp1"));
        assert_eq!(
            (settings.reads, settings.keep, settings.interval_us),
            (100, 50, 0)
        );
        let config = fit_config(&settings);
        assert_eq!(config.extension, 2_000_000_000);
        assert_eq!(
            (config.from.domain, config.to.domain, config.to.epoch),
            (7, 8, 9)
        );
    }

    #[test]
    fn link_samples_parse_as_pmc_prints_them() {
        let samples = super::parse_samples("ingress_ns\toffset_ns\tmean_path_delay_ns\n1795557786352172275\t-8.0\t3219.0\n1795557787476413916\t12.0\t3227.0\nDONE\n").unwrap();
        assert_eq!(samples.len(), 2);
        assert_eq!((samples[0].offset, samples[0].path_delay), (-8, 3219));
        assert!(super::parse_samples("1 2\n").is_err());
        // Fractions round away from zero; anything else is refused.
        let rounded = super::parse_samples("5 0.9 10.9\n6 -0.2 3\n").unwrap();
        assert_eq!((rounded[0].offset, rounded[0].path_delay), (1, 11));
        assert_eq!(rounded[1].offset, -1);
        assert!(super::parse_samples("5 1 10.garbage\n").is_err());
    }

    #[test]
    fn a_record_round_trips_and_compose_chains_records() {
        let key = |domain| karyos_trace::clocks::ClockKey {
            observer: karyos_trace::journal::ObserverId {
                driver: [0, 0],
                journal: 0,
            },
            domain,
            epoch: 1,
        };
        let first = karyos_trace::clocks::Calibration {
            from: key(1),
            to: key(2),
            reference: 1_000,
            offset: 100,
            offset_uncertainty: 5,
            drift: 0,
            drift_uncertainty: 0,
            valid_from: 0,
            valid_to: 10_000,
        };
        let second = karyos_trace::clocks::Calibration {
            from: key(2),
            to: key(3),
            reference: 3_000,
            offset: 0,
            offset_uncertainty: 1,
            drift: 0,
            drift_uncertainty: 0,
            valid_from: 0,
            valid_to: 20_000,
        };
        let text = |calibration: &karyos_trace::clocks::Calibration| {
            super::format_record(&calibration.encode().unwrap())
        };
        let words = text(&first);
        assert_eq!(
            super::parse_record(&words.split(' ').collect::<Vec<_>>()).unwrap(),
            first
        );
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = super::run_compose(
            vec![format!("record {words}").into(), text(&second).into()].into_iter(),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0, "{}", String::from_utf8_lossy(&err));
        let printed = String::from_utf8(out).unwrap();
        assert!(
            printed.contains("composed: offset 100 ns +/- 8 ns"),
            "{printed}"
        );
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(
            super::run_compose(vec![words.into()].into_iter(), &mut out, &mut err),
            super::EXIT_ERROR
        );
    }

    #[test]
    fn bad_arguments_are_refused_by_name() {
        assert!(parse(args(&["--keep", "0"])).is_err());
        assert!(parse(args(&["--keep", "101"])).is_err());
        assert!(parse(args(&["--reads"])).unwrap_err().contains("--reads"));
        assert!(
            parse(args(&["--reads", "x"]))
                .unwrap_err()
                .contains("--reads")
        );
        assert!(
            parse(args(&["--reads", "18446744073709551615"]))
                .unwrap_err()
                .contains("at most")
        );
        let past = (super::MAX_READS + 1).to_string();
        assert!(parse(args(&["--reads", &past])).is_err());
        assert!(parse(args(&["--source-domain", "1"])).is_err());
        assert!(
            parse(args(&["--bogus", "1"]))
                .unwrap_err()
                .contains("--bogus")
        );
    }

    /// Reads the PHC named by `KARYOS_PHC_DEVICE` (opt in: ignored by
    /// default, as reading a PHC may need the clock group or root) and
    /// checks the fit bounds every kept read. Run with
    /// `KARYOS_PHC_DEVICE=/dev/ptp0 cargo test -p karyos-tools --lib --
    /// --ignored calibrate::`, as a user that can read the device.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "reads a PTP hardware clock: opt in with KARYOS_PHC_DEVICE"]
    fn a_real_phc_calibrates_with_bounded_uncertainty() {
        use std::os::fd::AsFd;

        let device =
            std::env::var_os("KARYOS_PHC_DEVICE").expect("KARYOS_PHC_DEVICE names the device");
        let file = std::fs::File::open(&device).expect("the PHC device opens");
        let settings = Settings {
            device: device.into(),
            reads: 1_000,
            interval_us: 200,
            ..Settings::default()
        };
        let reads = super::collect(file.as_fd(), &settings).unwrap();
        let fitted = karyos_trace::calibrate::fit(&reads, &fit_config(&settings)).unwrap();
        let calibration = fitted.calibration;
        // Every kept read's own offset interval lies inside the fit, and a
        // PHC read through the kernel takes microseconds, not milliseconds.
        assert!(calibration.offset_uncertainty < 1_000_000, "{fitted:?}");
        for read in &reads {
            let (low, high) = calibration
                .convert(i128::from(read.before), i128::from(read.after))
                .unwrap();
            if read.after - read.before <= fitted.widest_kept_window {
                assert!(
                    low <= i128::from(read.target) && i128::from(read.target) <= high,
                    "{read:?} outside [{low}, {high}]"
                );
            }
        }
    }
}
