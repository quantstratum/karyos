### Changed

- The Cluster's log entries are schema 2 version 1 (SPEC §8.5;
  karyos#797), over the ADR-0036 envelope of `karyos-codec`, instead of
  the unreleased internal version 1 envelope.
  - `karyos_cluster::service::Envelope` encodes and decodes the five
    templates (`Register`, `Close`, `Request`, `TimerFired`,
    `Configuration`) with their value rules and bounds; `to_vec` now
    returns a `Result`.
  - `ApplyError::Envelope` carries the codec's error. A payload that is
    not a schema 2 message is a safety stop: every replica stops at the
    same index.
  - `EnvelopeError` and `ENVELOPE_VERSION` are removed.
