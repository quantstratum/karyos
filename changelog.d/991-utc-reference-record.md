### Added

- `karyos_trace::clocks::utc::UtcReference`: the UTC reference record of ADR-0090 (type 2 in the calibration journal, 18 words), with every typed refusal, the bound to UTC in nanoseconds and the conversion of a clock time to UTC for TAI, GPS, stepped and smeared (centred included) scales over the IERS Bulletin C leap table (through Bulletin C 72, July 2026), `no_evidence` where the evidence cannot say. Vectors U-1 to U-8 pass byte for byte (karyos#991).
