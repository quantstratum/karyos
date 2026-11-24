### Added

- `karyos-tools calibrate phc` (Linux): a TSC to PTP hardware clock calibration on one host, read as `CLOCK_MONOTONIC_RAW` against the PHC, with an offset and a drift whose uncertainties are measured from the reads, printed with the host, clock source and PHC it holds for and as an encoded `Calibration` record. The fit is `karyos_trace::calibrate::fit`, the paired read `karyos_sys::host_clock::phc_paired_read`. Part of #749 (the calibration between hosts needs a PTP daemon and a grandmaster, an owner decision).
