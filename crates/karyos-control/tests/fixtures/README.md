<!-- SPDX-License-Identifier: Apache-2.0 -->

# Test certificates

Test-only keys and certificates for `tests/mtls.rs`, `tests/oidc.rs` and
`src/jwt/tests.rs`. They secure nothing.
All are ECDSA P-256 with named curves, valid for 100 years, and were made
with OpenSSL 3. The CA keys were discarded after signing.

- `ca.pem`: the client and server CA.
- `server.pem`, `server.key`: `localhost` and `127.0.0.1`, signed by `ca.pem`.
- `svc-ops.pem`, `svc-ops.key`: client `svc.ops`, signed by `ca.pem`. The
  tests pin it as service `svc.ops`.
- `svc-other.pem`, `svc-other.key`: client `svc.other`, signed by `ca.pem`.
  It is not pinned.
- `rogue.pem`, `rogue.key`: a client named `svc.ops`, signed by another CA.
- `rsa-signing.der`, `rsa-signing.jwk.json`: an RSA 2048 signing key in
  PKCS#1 DER and its public JWK, for the `RS256` and `PS256` tests of
  `src/jwt/tests.rs`. PKCS#1 is used because `graviola` 0.4.2 refused the
  PKCS#8 form OpenSSL 3 wrote.

The keys must use a named curve: `graviola` refuses explicit curve
parameters, which LibreSSL's `genpkey` writes by default.
