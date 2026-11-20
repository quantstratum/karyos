### Added

- `karyos_trace::clocks::record::ClockRecord` reads a calibration journal of both record types of ADR-0090, a calibration (type 1) and a UTC reference record (type 2), each as its own, and skips a type it does not know (karyos#1065).
