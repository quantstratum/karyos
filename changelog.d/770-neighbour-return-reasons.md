### Changed

- Backend contract (R-CORE-44, karyos#770): `ReturnReason` gains
  `NeighbourUnresolved` and `NeighbourTableFull`, which a backend that
  resolves neighbours itself (a native backend in exclusive mode) returns
  from a flush with the frame intact, never exposed. `ReturnReason` is now
  `#[non_exhaustive]`: the backend contract types have no stable contract
  version yet (R-CORE-26), so a backend's exhaustive `match` over it needs
  a wildcard arm. Sockets never return either reason; the driver counts
  them as any return.
