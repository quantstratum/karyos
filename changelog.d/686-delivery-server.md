### Added

- The `ClusteredService` delivery path in the harness (C10; karyos#686,
  part 2 of 5). `karyos_sim::harness::delivery`: `DeliveryServer` runs
  any `ConsensusCore` over C4's log and feeds its committed entries to a
  `ServiceContainer`, proposing through `Proposer`, the core's `Propose`.
  `DeliveryClient` registers, then sends its commands under its epoch
  and sequence. `tests/delivery.rs`:
  - requests reach the log and their outcomes return on 3 and 5
    servers, with every replica in the same state and sessions;
  - a request sent twice is applied once;
  - a restarted server rebuilds its container from the log.

  `ServerNode` and `TestService`, which the frozen C5 workloads measure,
  are unchanged. The reference core now stamps its entries with its last
  tick time instead of 0. This changes the event time only, which
  `TestService` ignores, so no measured behaviour changes; a test checks
  it.
