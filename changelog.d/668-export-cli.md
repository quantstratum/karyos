### Added

- `karyos-catalog export` and `karyos-catalog verify-export` (ADR-0103; karyos#668).
  - `export` writes an export of the named recordings from an Archive's own files. It carries the Archive journal from genesis to the later of the last record sealing exported bytes and its latest anchored head, with the registry rows its key registry seals commit and the heads and anchors over it, the recordings' bytes, and the policy versions and bindings it seals. `--time` adds the time evidence entries' journal and store, `--clock-records` the calibration and UTC reference records, and `--schema` codec schemas.
  - `verify-export` verifies an export offline with the trust file and anchor stores only. It exits 0 when every range verifies, 1 when any does not, and 2 when the export is refused.
  
  An exported recording verifies offline, with the Archive's directory removed, to the same outcomes as online.
