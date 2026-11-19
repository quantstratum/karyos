### Fixed

- A dynamic subscription's REGISTER backoff is no longer reset by an ANNOUNCE, only by an accepted ANSWER or a bound image, so a receiver its sender cannot bind backs off up to the 1.6 s cap between REGISTERs instead of retrying at the base interval (karyos#947).
