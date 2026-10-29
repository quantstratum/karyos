### Fixed

- A network publication its endpoint cannot hold is no longer accepted
  and silent (karyos#859, plan 168). The driver keeps what each
  publication takes of each endpoint it sends on (a reliable single-lane
  one: a route, 2 queues, 9 TX slots) with a reserve for the sender's
  control routes, and refuses an add past the endpoint's TX slots,
  queues or routes with `DriverError::EndpointCapacity` (`ResourcesUnavailable`
  to a client, the detail word `limit << 56 | capacity << 32 | needed`,
  limit 1 TX slots, 2 queues, 3 routes). The room of a removed
  publication is free once its removal has ended, so a refusal during a
  removal is retryable. With the defaults one endpoint holds 24
  reliable single-lane publications; before, the 25th and later ones
  were accepted and sent nothing, and a late subscriber could not bind
  them (the 19 s of plan 168).
- A refused network publication add leaves nothing behind: its stream
  key is free in the same cycle, so the same add retried at once is never
  `DuplicateStream` (it was for a few cycles).
- A refused open of a publication's route or queues counts in
  `endpoint_limits` for an endpoint limit and is tried again
  `setup_interval` later, not every cycle.

### Added

- `NetworkConfig::endpoint_tables` (`EndpointTables`) sizes each
  endpoint the driver opens: TX slots, queues and routes (defaults 256,
  64, 64).
- `NetworkPublicationState::Limited(EndpointLimit)`: accepted, but its
  sender's open is refused for an endpoint limit; it sends nothing until
  it opens. The sender reports it with `AgentEvent::PublicationLimit`,
  once per epoch, and its end at the open.
- `SocketsTx::commitment` (`TxCommitment`): what a TX half has open.

### Changed

- API: `NetworkPublicationState` is not `#[non_exhaustive]`, so its new
  `Limited` variant breaks an exhaustive `match` in client code, and
  `NetworkConfig` gains a public field, which breaks a struct literal
  without `..NetworkConfig::default()`.
