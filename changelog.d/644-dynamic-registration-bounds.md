### Added

- The two wire additions of dynamic multi-destination registration:
  RSP_SETUP variant 3 REGISTER (56 bytes, the stream and the receiver
  block) and ERR variant 3 REGISTRATION with reason 4 `DESTINATIONS_FULL`
  (40 bytes), as codecs with hand-written vectors (ADR-0056, ADR-0082;
  design MD-4, MD-5; karyos#644, step 1).
- `sessions::register`, the bounded admission of a REGISTER: an explicit
  non-empty `RegistrationAllowlist` (no permissive default; it supplies no
  authentication), per-source and per-driver rates, global and per-source
  pending bounds, one ERR per source per `refusal_interval` on a full
  table, and expiry at `join_timeout`. `control-mode=dynamic` stays
  refused until the sender and receiver paths are implemented and tested
  (karyos#644).
