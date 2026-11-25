// SPDX-License-Identifier: Apache-2.0

use karyos_trace::calibrate::{FitConfig, FitError, PairedRead, fit};
use karyos_trace::clocks::ClockKey;
use karyos_trace::clocks::utc::SyncState;
use karyos_trace::journal::ObserverId;

use super::{
    ChainError, DEFAULT_LEAP_TABLE, DEFAULT_MAX_CLOCK_ERROR_APPM, REALTIME_DOMAIN, UNIX_EPOCH_U_NS,
    UtcSettings, check_chain, parse_tracking, reference, run_utc, utc_of,
};

/// A line as chrony 4.8 prints it on swarmer01's shape of setup: stratum
/// 3, 1.4 ms off its estimate, 33.5 ms root delay, 1.25 ms dispersion.
const TRACKING: &str = "C0A80001,ntp.ubuntu.com,3,1795594149.123456789,-0.001400000,0.000012000,0.000300000,-12.345,0.001,0.050,0.033500000,0.001250000,1030.5,Normal\n";

/// A Unix time on 2026-11-25, in ns.
const SAMPLED: u64 = 1_795_594_150_000_000_000;

fn settings() -> UtcSettings {
    UtcSettings {
        sampled_at: SAMPLED,
        window_ms: 10_000,
        domain: REALTIME_DOMAIN,
        epoch: 1,
        leap_table: DEFAULT_LEAP_TABLE,
        max_clock_error_appm: DEFAULT_MAX_CLOCK_ERROR_APPM,
    }
}

/// TRACKING's bound over 10 s: 19.4 ms as sampled plus (0.050 + 0.001 +
/// 1) ppm of 10 s, 10.51 us.
const BOUND_10S: u64 = 19_410_510;

fn key(domain: u64) -> ClockKey {
    ClockKey {
        observer: ObserverId {
            driver: [0, 0],
            journal: 0,
        },
        domain,
        epoch: 1,
    }
}

fn line(system: &str, delay: &str, dispersion: &str, stratum: &str, leap: &str) -> String {
    format!(
        "A29FC87B,ntp1,{stratum},1795594149.0,{system},0.0,0.0,1.0,0.0,0.01,{delay},{dispersion},64.0,{leap}"
    )
}

#[test]
fn a_real_shaped_line_parses_and_bounds() {
    let tracking = parse_tracking(TRACKING).unwrap();
    assert_eq!(tracking.reference, "ntp.ubuntu.com");
    assert_eq!(tracking.stratum, 3);
    assert_eq!(tracking.sync_state, SyncState::Synchronised);
    // 1.4 ms + 33.5 ms / 2 + 1.25 ms, as sampled.
    assert_eq!(tracking.bound_ns(0, 0), Some(19_400_000));
    let record = reference(&tracking, &settings()).unwrap();
    assert_eq!(record.bound, BOUND_10S);
    assert_eq!(record.bound_ns(), Some(BOUND_10S));
    assert_eq!(
        (record.valid_from, record.valid_to),
        (SAMPLED, SAMPLED + 10_000_000_000)
    );
    assert_eq!(record.clock, key(REALTIME_DOMAIN));
    // CLOCK_REALTIME's reading is UTC since 1970, so U is it plus 4383 days.
    assert_eq!(
        record.utc(SAMPLED + 5),
        Some(i128::from(SAMPLED + 5 + UNIX_EPOCH_U_NS))
    );
    assert_eq!(record.utc(SAMPLED - 1), None);
    // The record round-trips through the codec.
    let words = record.encode().unwrap();
    assert_eq!(
        karyos_trace::clocks::utc::UtcReference::decode(&words).unwrap(),
        record
    );
}

#[test]
fn the_bound_rounds_up_to_whole_nanoseconds() {
    let bound = |system, delay, dispersion| {
        parse_tracking(&line(system, delay, dispersion, "2", "Normal"))
            .unwrap()
            .bound_ns(0, 0)
    };
    assert_eq!(bound("0.0", "0.0", "0.0"), Some(0));
    // A sign is dropped: the magnitude counts.
    assert_eq!(bound("-0.000000005", "0.0", "0.0"), Some(5));
    assert_eq!(bound("+0.000000005", "0.0", "0.0"), Some(5));
    // Half a nanosecond of delay rounds up.
    assert_eq!(bound("0.0", "0.000000003", "0.0"), Some(2));
    // Digits past the attosecond still round up.
    assert_eq!(bound("0.0000000000000000001", "0", "0"), Some(1));
    assert_eq!(bound("1", "2", "0.5"), Some(2_500_000_000));
}

#[test]
fn the_bound_grows_over_the_window_as_chrony_grows_dispersion() {
    // Skew 0.01 ppm, residual -0.5 ppm (its magnitude counts).
    let tracking =
        parse_tracking("A,ntp1,2,1.0,0.000001,0.0,0.0,1.0,-0.5,0.01,0.000004,0.000002,64.0,Normal")
            .unwrap();
    // 1 us + 2 us + 2 us as sampled.
    assert_eq!(tracking.bound_ns(0, 0), Some(5_000));
    // Over 1 s with no clock error: 0.51 ppm of 1 s, 510 ns.
    assert_eq!(tracking.bound_ns(1_000_000_000, 0), Some(5_510));
    // chrony's default maxclockerror adds 1 ppm: 1.51 us.
    assert_eq!(
        tracking.bound_ns(1_000_000_000, DEFAULT_MAX_CLOCK_ERROR_APPM),
        Some(6_510)
    );
    // A third of a nanosecond of growth rounds up.
    assert_eq!(tracking.bound_ns(1, 0), Some(5_001));
    // A longer window gives a larger record bound.
    let tracking = parse_tracking(TRACKING).unwrap();
    let bound = |window_ms| {
        reference(
            &tracking,
            &UtcSettings {
                window_ms,
                ..settings()
            },
        )
        .unwrap()
        .bound
    };
    assert_eq!(bound(10_000), BOUND_10S);
    assert_eq!(bound(600_000), 19_400_000 + 630_600);
    assert!(bound(1_000) < bound(10_000) && bound(10_000) < bound(600_000));
}

#[test]
fn missing_and_malformed_fields_are_refused() {
    assert!(parse_tracking("").unwrap_err().contains("no tracking line"));
    assert!(parse_tracking("A,b,3,1.0,0.0").unwrap_err().contains("14"));
    assert!(
        parse_tracking(&format!("{TRACKING}{TRACKING}"))
            .unwrap_err()
            .contains("more than one")
    );
    for (bad, field) in [
        (line("", "0.1", "0.1", "3", "Normal"), "system time"),
        (line("0.1", "x", "0.1", "3", "Normal"), "root delay"),
        (line("0.1", "0.1", "1e-3", "3", "Normal"), "root dispersion"),
        (line("0.1", "0.1", ".5", "3", "Normal"), "root dispersion"),
        (line("0.1", "0.1", "0.1", "", "Normal"), "stratum"),
        (line("0.1", "0.1", "0.1", "3", ""), "leap status"),
    ] {
        let error = parse_tracking(&bad).unwrap_err();
        assert!(error.contains(field), "{bad}: {error}");
    }
    assert!(
        parse_tracking(&line("0", "0", "0", "3", "Sideways"))
            .unwrap_err()
            .contains("unknown leap status")
    );
}

#[test]
fn an_unsynchronised_state_gives_no_bound_and_no_record() {
    for (stratum, leap) in [
        ("0", "Not synchronised"),
        ("3", "Not synchronised"),
        ("0", "Normal"),
        ("16", "Normal"),
    ] {
        let tracking = parse_tracking(&line("0", "0", "0", stratum, leap)).unwrap();
        assert_eq!(tracking.sync_state, SyncState::Unsynchronised);
        assert_eq!(tracking.bound_ns(0, 0), None);
        assert!(
            reference(&tracking, &settings())
                .unwrap_err()
                .contains("not synchronised")
        );
    }
    // A pending leap second is synchronised but refused.
    let pending = parse_tracking(&line("0", "0", "0", "2", "Insert second")).unwrap();
    assert_eq!(pending.sync_state, SyncState::Synchronised);
    assert!(
        reference(&pending, &settings())
            .unwrap_err()
            .contains("leap")
    );
    // So is a window of 0 or past the most.
    let tracking = parse_tracking(TRACKING).unwrap();
    for window_ms in [0, super::MAX_WINDOW_MS + 1] {
        let wide = UtcSettings {
            window_ms,
            ..settings()
        };
        assert!(reference(&tracking, &wide).is_err());
    }
}

#[test]
fn the_command_prints_a_record_append_reads() {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let args = [
        "--sampled-at-ns",
        "1795594150000000000",
        "--window-ms",
        "5000",
    ]
    .map(std::ffi::OsString::from);
    let code = run_utc(
        args.into_iter(),
        &mut TRACKING.as_bytes(),
        &mut out,
        &mut err,
    );
    assert_eq!(code, 0, "{}", String::from_utf8_lossy(&err));
    let printed = String::from_utf8(out).unwrap();
    // 19.4 ms plus 1.051 ppm of 5 s.
    assert!(printed.contains("bound 19405255 ns"), "{printed}");
    let records =
        super::super::journal::input_records(&mut std::io::Cursor::new(printed.as_bytes()))
            .unwrap();
    assert_eq!(records.len(), 1);
    let record = karyos_trace::clocks::utc::UtcReference::decode(&records[0]).unwrap();
    assert_eq!(record.valid_to, SAMPLED + 5_000_000_000);

    // An unsynchronised chrony prints no record.
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let unsynced = "00000000,,0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,1.0,1.0,0.0,Not synchronised\n";
    let code = run_utc(
        std::iter::empty(),
        &mut unsynced.as_bytes(),
        &mut out,
        &mut err,
    );
    assert_eq!(code, super::EXIT_ERROR);
    assert!(out.is_empty());
    assert!(String::from_utf8_lossy(&err).contains("not synchronised"));
}

/// Reads of a realtime clock `offset` ns ahead of the raw clock and
/// `ppb` faster, 1 ms apart, each bracketed by a 100 ns window; `step`
/// ns added to every read from the middle on.
fn reads(offset: u64, ppb: u64, step: u64) -> Vec<PairedRead> {
    (0..1_000_u64)
        .map(|index| {
            let before = 1_000_000_000 + index * 1_000_000;
            let drifted = index * 1_000_000 * ppb / 1_000_000_000;
            let jump = if index >= 500 { step } else { 0 };
            PairedRead {
                before,
                target: before + 50 + offset + drifted + jump,
                after: before + 100,
            }
        })
        .collect()
}

fn config() -> FitConfig {
    FitConfig {
        from: key(0),
        to: key(REALTIME_DOMAIN),
        keep_percent: 25,
        extension: 0,
    }
}

/// The raw clock's 1 s maps to this Unix time.
const OFFSET: u64 = SAMPLED - 1_000_000_000;

#[test]
fn a_realtime_fit_recovers_the_offset_and_drift() {
    let fitted = fit(&reads(OFFSET, 0, 0), &config()).unwrap();
    let calibration = fitted.calibration;
    let (low, high) = calibration.convert(1_500_000_050, 1_500_000_050).unwrap();
    let want = i128::from(1_500_000_050 + OFFSET);
    assert!(low <= want && want <= high, "[{low}, {high}] {want}");
    assert!(calibration.offset_uncertainty <= 100, "{fitted:?}");
    assert_eq!(calibration.drift, 0);

    // NTP's slew shows as a drift: 10 ppm faster.
    let fitted = fit(&reads(OFFSET, 10_000, 0), &config()).unwrap();
    let drift = fitted.calibration.drift;
    assert!((9_990..=10_010).contains(&drift), "{fitted:?}");
}

#[test]
fn a_stepped_realtime_is_refused_as_not_affine() {
    // A 1 ms step in the middle of the run, as NTP's step would make.
    assert!(matches!(
        fit(&reads(OFFSET, 0, 1_000_000), &config()),
        Err(FitError::NotAffine { .. })
    ));
}

/// The whole chain: the raw clock to CLOCK_REALTIME by a fit, CLOCK_REALTIME
/// to UTC by chrony's record, then A10's combined bound of a raw time.
#[test]
fn a_raw_time_reaches_utc_with_a_bound_near_the_inputs() {
    use karyos_archive::integrity::time::{
        self, Coordinate, Gap, Source, SyncState as ArchiveState,
    };

    let calibration = fit(&reads(OFFSET, 0, 0), &config()).unwrap().calibration;
    // chrony sampled 100 ms after the run's first read.
    let sampled = UtcSettings {
        sampled_at: SAMPLED + 100_000_000,
        ..settings()
    };
    let chrony = reference(&parse_tracking(TRACKING).unwrap(), &sampled).unwrap();
    let coordinate = Coordinate::new(1).unwrap();
    let evidence = time::UtcReference {
        clock: chrony.clock,
        bound_ns: chrony.bound_ns().unwrap(),
        valid_from: chrony.valid_from,
        valid_to: chrony.valid_to,
        source: Source::from_code(chrony.source as u8).unwrap(),
        sync_state: ArchiveState::from_code(chrony.sync_state as u8).unwrap(),
        scale_stated: true,
        coordinate: Some(coordinate),
    };
    assert_eq!(evidence.source, Source::Ntp);
    let raw = 1_500_000_050;
    // `combined_bound` measures from `t` itself, so it speaks for a clock
    // that already reads UTC; for the raw clock the bound is the UTC
    // interval's half-width: chrony's 19.4 ms plus the fit's own
    // uncertainty, a few ns.
    let (low, high) = time::utc_interval(raw, coordinate, &calibration, &evidence).unwrap();
    let half = u64::try_from((high - low).div_euclid(2)).unwrap();
    let extra = calibration.offset_uncertainty;
    assert!(
        (BOUND_10S..=BOUND_10S + extra).contains(&half),
        "{half} {calibration:?}"
    );
    let realtime = i128::from(raw + OFFSET);
    let chrony_bound = i128::from(BOUND_10S);
    assert!(low <= realtime - chrony_bound && realtime + chrony_bound <= high);
    // The tool's own helper gives the same interval in U.
    let (u_low, u_high) = utc_of(raw, &calibration, &chrony).unwrap();
    let epoch = i128::from(UNIX_EPOCH_U_NS);
    assert_eq!((u_low - epoch, u_high - epoch), (low, high));
    // The UTC coordinate of the realtime the fit gives.
    assert_eq!(
        chrony.utc(raw + OFFSET),
        Some(realtime + i128::from(UNIX_EPOCH_U_NS))
    );
    // Before chrony's sample, or past the fit's last read: no number.
    assert_eq!(
        time::utc_interval(1_000_000_000, coordinate, &calibration, &evidence),
        Err(Gap::ReferenceNotValid)
    );
    // A clock that reads CLOCK_REALTIME itself: the combined bound is
    // chrony's plus the fit's, from the realtime value.
    let realtime_now = raw + OFFSET;
    let identity = karyos_trace::clocks::Calibration {
        from: key(5),
        to: key(REALTIME_DOMAIN),
        reference: realtime_now,
        offset: 0,
        offset_uncertainty: extra,
        drift: 0,
        drift_uncertainty: 0,
        valid_from: realtime_now,
        valid_to: realtime_now,
    };
    assert_eq!(
        time::combined_bound(realtime_now, coordinate, &identity, &evidence),
        Ok(BOUND_10S + extra)
    );
    assert_eq!(
        time::utc_interval(5_000_000_000, coordinate, &calibration, &evidence),
        Err(Gap::CalibrationNotValid)
    );
}

/// A calibration and a UTC record that do not overlap are a typed error
/// naming `--extension-ms`, never a silent gap.
#[test]
fn a_chain_that_does_not_overlap_is_a_typed_error() {
    let calibration = fit(&reads(OFFSET, 0, 0), &config()).unwrap().calibration;
    let tracking = parse_tracking(TRACKING).unwrap();
    let at = |sampled_at| {
        reference(
            &tracking,
            &UtcSettings {
                sampled_at,
                ..settings()
            },
        )
        .unwrap()
    };
    // The fit's reads end about 1 s after SAMPLED; chrony sampled 5 s on.
    let late = at(SAMPLED + 5_000_000_000);
    assert_eq!(
        check_chain(&calibration, &late),
        Err(ChainError::EndsBefore)
    );
    assert_eq!(
        utc_of(1_500_000_050, &calibration, &late),
        Err(ChainError::EndsBefore)
    );
    assert!(
        ChainError::EndsBefore
            .to_string()
            .contains("--extension-ms"),
        "{}",
        ChainError::EndsBefore
    );
    // An extension reaching the sample makes it chain.
    let extended = FitConfig {
        extension: 5_000_000_000,
        ..config()
    };
    let longer = fit(&reads(OFFSET, 0, 0), &extended).unwrap().calibration;
    assert_eq!(check_chain(&longer, &late), Ok(()));
    // A record whose window ended before the fit's reads began.
    let early = at(SAMPLED - 60_000_000_000);
    assert_eq!(
        check_chain(&calibration, &early),
        Err(ChainError::StartsAfter)
    );
    assert!(
        ChainError::StartsAfter
            .to_string()
            .contains("--extension-ms")
    );
    // Another clock's record.
    let other = UtcSettings {
        domain: 9,
        ..settings()
    };
    assert!(matches!(
        check_chain(&calibration, &reference(&tracking, &other).unwrap()),
        Err(ChainError::WrongClock { .. })
    ));
    // Overlapping, but this time is outside the fit's validity.
    let sampled = at(SAMPLED + 100_000_000);
    assert_eq!(
        utc_of(5_000_000_000, &calibration, &sampled),
        Err(ChainError::NotCovered)
    );
    // Overlapping, but this time converts to before the record starts.
    assert_eq!(
        utc_of(1_000_000_000, &calibration, &sampled),
        Err(ChainError::OutsideReference)
    );

    // `compose` with the UTC record last checks the same.
    let text = |words: &[u64; 18]| super::super::format_record(words);
    let run = |records: Vec<String>| {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = super::super::run_compose(
            records.into_iter().map(std::ffi::OsString::from),
            &mut out,
            &mut err,
        );
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    };
    let (code, out, err) = run(vec![
        format!("record {}", text(&calibration.encode().unwrap())),
        format!("record {}", text(&late.encode().unwrap())),
    ]);
    assert_eq!(code, super::EXIT_ERROR, "{out}");
    assert!(out.is_empty());
    assert!(err.contains("--extension-ms"), "{err}");
    let (code, out, err) = run(vec![
        text(&calibration.encode().unwrap()),
        text(&sampled.encode().unwrap()),
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("overlaps the UTC record"), "{out}");
}
