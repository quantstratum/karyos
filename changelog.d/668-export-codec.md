### Added

- `integrity::export`, the Archive export file container of ADR-0103 (karyos#668): its 64 byte header, typed sections (kinds 1 to 12) and SHA-256 trailer, encoded and decoded with the design's typed refusals in order (`Trailer`, `Magic`, `Version`, `Reserved`, `Kind`, `SectionVersion`, `Length`, `Order`, `Count`). The golden vectors X-1 to X-4 encode and decode exactly, and X-5 to X-12, derived blind in quantstratum-docs#979, decode and re-encode byte for byte. The exporter and the offline verifier follow.
