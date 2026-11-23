### Added

- `integrity::export::assemble`, the exporter's layout of an Archive export (ADR-0103; karyos#668): the journals with their seal records, signed heads, anchors and registry entries, then the manifest, frames, codec schemas, clock records, time evidence, policies and bindings, in the design's order and with its pinned readings (empty sections omitted, one frames chunk per recording, an empty time evidence store carried when asked). Built from the Archive's own record types, it reproduces the blind golden vectors X-5 to X-12 byte for byte.
