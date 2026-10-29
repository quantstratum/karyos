### Added

- Application trace point names (R-CORE-1, karyos#722, second part):
  `Client::add_trace_point(label)` registers a point as a client counter
  cell of type id 8 (`TYPE_TRACE_POINT`), whose value is the id the
  driver assigns and publishes with the cell, never reused within the
  instance. Labels are checked by the client and again by the driver
  (1 to 64 bytes, no control character; `ClientError::InvalidLabel`,
  `ErrorCode::InvalidLabel` 27). A client holds at most
  `max_trace_points_per_client` live points (16) and registers at most
  `max_trace_point_registrations_per_client` over its life (256), with
  `karyosd` flags of the same names; once the instance assigned all
  65 535 ids, a registration is refused with
  `ErrorCode::TracePointIdsExhausted` (26) and counted in the driver's
  `trace point ids exhausted`. The agent's Prometheus exposition and
  `karyos-stat` leave trace point cells out: they name records and hold
  an id.
