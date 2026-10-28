### Changed

- `make pre-push` gains `lint-linux`: clippy for `aarch64-unknown-linux-gnu`
  with every feature, so Linux-only code is checked before a push from any
  host (RELEASING.md; a follow-up of karyos#798). The conflation tests'
  Linux-only module builds its configurations with
  `ConflationConfig::new`, so a field added later no longer breaks it, and
  the ignored probe measurement may print its quantiles.
