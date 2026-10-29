### Added

- The agent keeps a join metadata registry (karyos#736; Insights
  ADR-0022: "Versioned metadata joins through a public, agent-visible
  registry serve stable dimensions"). A product with the new role
  `registrar` (or an administrator) puts versioned `name=value`
  attributes about a driver's stream id, application trace point label or
  application counter label with `join-put DIR KIND KEY NAME=VALUE...`,
  and ends one with `join-retire`; any role reads the version in force at
  an instant with `join-get DIR KIND KEY [AT_NS]` and pages them with
  `join-list DIR [KIND KEY]`. Each version is valid from the agent's host
  monotonic time of its put to the next put or the retire. Bounded, each
  bound in `limits` (`join.*`) with a typed refusal: 1024 keys in all and
  per driver, 4 versions per key, 16 attributes, 32-byte names, 64-byte
  values, a 1024-byte `join-put` line, and a computed worst case of
  6.5 MiB (`join.memory_bytes`). In memory only, with a
  `generation` per agent start. A read gives what the agent observes of
  the identity now: whether a trace point or application counter of that
  label exists and how many clients hold it; for a stream, `null`, as no
  driver cell carries a wire stream id. The `view` is unchanged; the
  `capabilities` list gains `join-registry` and `join-put`.
