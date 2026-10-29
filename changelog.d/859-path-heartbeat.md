### Fixed

- An idle publication keeps its subscribers' paths (karyos#859, plan
  168). Every established publication now sends a PATH_HB on each idle
  path: one on one path, each path of a routed one, and each live
  destination of a multi-destination one, at most one per
  `path_heartbeat_interval`. A path with DATA in the interval sends
  none, nor a publication being removed or whose guard admits no lane.
  Before, an idle publication on one path, or to several destinations,
  lost each subscriber path at `path_liveness_timeout` and bound it
  again by SOLICIT, about one SOLICIT per path every 10 s.
