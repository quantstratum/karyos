### Added

- Per-datum identity and sample time in the agent's data (R-CORE-17;
  karyos#737). API v1 gains fields only.
  - Each counter now carries `cell_registration`, `read_ns` (when the
    agent read it) and `changed_ns`. `changed_ns` is the first pass in
    which the agent saw the value change: an upper bound on the change,
    which happened after the previous pass's `read_ns`. It is `null`
    until a change has been seen.
  - Each lane carries `sampled_ns`, the driver's sampling time of its
    positions. Each subscriber carries `cell_registration` and
    `changed_ns`, stamped with the agent's read in a pass that is not
    consistent.
  - A datum's identity is the driver instance plus its
    `cell_registration`, which a region never reuses. A reallocation
    under the same keys is a new series, and a new instance breaks
    every join.
  - The agent tracks changes by registration, in region order, with an
    index for the cells that churned. A freed counter leaves no entry,
    the tracking allocates nothing in a steady state, and a pass costs
    O(cells).
  - `consistent`, `sampled` and `age_ns` are unchanged.
