### Added

- `NetworkConfig::endpoint_tables` (`EndpointTables`) sizes each
  endpoint the driver opens: TX slots, queues and routes (defaults 256,
  64, 64).
- `NetworkPublicationState::Limited(EndpointLimit)`: accepted, but its
  sender's open is refused for an endpoint limit; it sends nothing until
  it opens. The sender reports it with `AgentEvent::PublicationLimit`,
  once per epoch, and its end at the open.
- `SocketsTx::commitment` (`TxCommitment`): what a TX half has open.
