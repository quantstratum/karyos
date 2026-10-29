### Added

- `--versions` on every binary of `karyos-tools` (R-CORE-33, karyos#729):
  one JSON object with its own schema (`karyos-versions`, version 1),
  printed before anything else is parsed and touching no driver. It has
  the core release, the admission and frame protocol versions, the C ABI
  version, the wire schema versions (Archive control, Cluster log, group
  records, capture contract, Archive durability), the backends the core
  knows with whether this build compiled them, and the enabled features,
  each with the id of the rule it is compared under. The C ABI version
  now has one source, `karyos_protocol::versions`, which `karyos-ffi` and
  its header follow. A `libkaryos` package carries the same object as
  `share/karyos/versions.json`, checked against its MANIFEST.
