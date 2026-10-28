### Added

- Per-datum identity and sample time in the agent's data (R-CORE-17;
  karyos#737). API v1 gains fields only.
  - Each counter now carries `read_ns`, when the agent read it, and
    `changed_ns`, the first pass in which the agent saw its value change.
    That is a lower bound: the change happened after the previous
    pass's `read_ns`. It is `null` until a change has been seen.
  - Each lane carries `sampled_ns`, the driver's sampling time of its
    positions, and each subscriber carries `changed_ns`.
  - The identity a console or collector joins passes on is now stated:
    the driver instance plus a datum's label, type and keys. A new
    instance breaks the join.
  - The agent tracks changes by cell registration, in region order. A
    freed counter leaves no entry, so the tracking is bounded by the
    region's cells, and it allocates nothing in a steady state.
  - `consistent`, `sampled` and `age_ns` are unchanged.
