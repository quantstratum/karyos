### Fixed

- HMAC keys are now held as `karyos_protocol::protection::hmac_key::HmacKey`, whose padded key block is erased: the HMAC profile, HKDF in `wire_keys::Context::derive` and the key state fingerprints all used `hmac`'s key setup, which leaves a padded copy of the key unerased. `hmac` is now a test-only dependency of `karyos-driver` and no longer one of `karyos-protocol`.
