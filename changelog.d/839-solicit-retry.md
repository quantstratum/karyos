### Changed

- A late multicast subscriber binds faster under loss (karyos#839, plan
  164). An unanswered SOLICIT is retried by the receiver's duty after 50
  ms, the wait doubling up to `setup_challenge_timeout`, for at most 6
  SOLICITs within twice `setup_challenge_timeout` of the first; each
  retry carries the entry's nonce, so an answer to any of its SOLICITs
  binds within that window, as for a resent CHALLENGE. A retry the
  RSP_SETUP rates refuse is not an attempt (`solicit_retries_refused`).
  Measured on Linux netem, 200 late joins: the p99 bind time is 53 ms at
  2% loss, 153 ms at 10% and 353 ms at 20% (about 2 s, 4 s and 8 s
  before), and back-to-back joins show no 2 s steps (p99 153 ms). At an
  RTT of about 200 ms and 2% loss a join takes about one RTT (median 201
  ms, p99 251 ms).
