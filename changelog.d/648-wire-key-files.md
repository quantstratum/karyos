### Added

- `karyos_driver::wire_keys` parses and validates the wire authentication key files of quantstratum-docs `karyos/design/wire-key-files.md`:
  - the canonical field order, numbers and timestamps;
  - the per-purpose fields, and a profile that matches the purpose;
  - the 90-day and 180-day validity bounds;
  - canonical and not small-order authority public keys.

  It also derives the per-purpose MAC keys with HKDF-SHA-256 over the `info` contexts of ADR-0086 section 4, reproducing the design's blind K-1 to K-5 vectors and its canonical parser files. Secrets and derived keys are erased on drop. The key directory, durable key state and reload are later parts of karyos#648; nothing uses these keys yet.
