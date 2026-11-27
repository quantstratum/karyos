### Added

- Rolling upgrades activate at a log index (karyos#715; ADR-0122).
  - **Entries:** schema 5 templates 3, `Activation` (service and schema version, an activation offset, an optional configuration), and 4, `CoordinatedStop` (a stop offset and a resume version), with vectors A-1 to A-17 and C-1 to C-7.
  - **Version semantics:** the log's active version starts at service 1, schema 1; an `Activation` is pending at its entry and takes effect at its index on every replica; the service sees only `Context::active_version`.
  - **Refusals:** `ClusteredService::required_version` and `supported_version`; the leader refuses with `ProposeRefused::VersionInactive` or `Stopping`; refused entries apply as `Applied::CoreRefused(CoreRefusal::…)`; the container stops with `ApplyError::VersionUnsupported` at the activation index or `ApplyError::Stopped` past a stop.
  - **Snapshots:** the sessions section is version 2 and carries the version state; version 1 still restores, as the state before any `Activation`.
  - **B-8:** reissued as template 5, since templates 2 to 4 decode.
