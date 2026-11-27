### Added

- The five membership scenarios that need elections run against the custom Raft core (karyos#712; phase-5-cluster-scenarios.md §4).
  - **M2:** a follower, then the leader, is removed. The leader steps down once its removal commits, and the rest elect a new one.
  - **M3:** a change taken in a minority partition is truncated everywhere.
  - **M4:** the leader crashes once a change is durable on it alone, on a majority, or committed, under each crash mode.
  - **M6:** a rolling replacement under load and crashes.
  - **M7:** the single-server errata refuse a second change as `InProgress`. The core uses single-server changes (ADR-0121), so M7 runs.
  - **Harness:** leader-relative actions (`Action::Leader`) and changes retried until they hold (`Action::Ensure`).
  - **New checks:** `one_leader_per_term`, which runs over every case, and `removed_leader_steps_down`.
  - **Mutants:** each new assertion has a mutant it catches.
