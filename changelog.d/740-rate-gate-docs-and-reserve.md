### Changed

- The driver validates a policy's control reserve against the same
  aligned charge as its byte burst, the MTU aligned as a frame: on an MTU
  that is not a multiple of 32 the reserve's byte floor is higher than
  before (for an MTU of 1400 and a reserve of 10 messages a second, 14 080
  bytes a second rather than 14 000).
- A policy a sender gate refuses is applied as the stricter of it and the
  policy in force, unvalidated on purpose: a byte bucket no datagram fits
  holds the lanes until a valid version (fail closed). Docs only; the
  behaviour is #841's.
- The CnC counter docs size the region for 6 cells per network
  publication (`network admission` and `network rate policies refused`
  added), not 4.
