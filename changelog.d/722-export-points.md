### Added

- The agent's `trace-export` names application trace points (R-CORE-1,
  karyos#722, last part): each page carries `points`, one
  `{"id","label","client"}` per point its records reference, its label
  escaped as every string. A point is named only by the single live
  trace point cell holding its id, of the client of the journals its
  records are in; otherwise its label and client are `null`, never
  another point's. A point counts once in the reply's byte bound, at
  384 bytes. `limits` gains `trace.point_ids` (65 535),
  `trace.points_per_client` (16) and
  `trace.point_registrations_per_client` (256), all fixed.
