### Added

- `karyos_protocol::protection::signed` seals and opens the signed envelope of the guard and abort authority (Ed25519, `profile_id` 4, ADR-0086 sections 2 and 8). It checks every header field against the binding before the signature. `karyos_driver::authority` provides the Ed25519 signer and verifier. The verifier uses `verify_strict`, and the key loader refuses non-canonical and small-order public keys. Both reproduce the independent Ed25519 envelope vectors byte for byte. No path uses them yet: GUARD and SESSION_ABORT stay gated (part of karyos#648).
