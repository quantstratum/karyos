<!-- SPDX-License-Identifier: Apache-2.0 -->

# Wire authentication profile v1 vectors (gate H5)

Independent vectors of the `authenticated` class (`quantstratum-docs:
karyos/adr/0086-wire-authentication-profile-v1.md`; wire threat model
manifest section 7, gates H1 and H5), produced by a second implementation
and checked against the product byte for byte.

| File | What it is |
| --- | --- |
| `wire_auth_v1.py` | The second implementation: Python 3 standard library only (`hmac`, `hashlib`), with the RFC 8032 section 6 reference arithmetic written out for Ed25519 and its cofactorless strict verification. Written from the documents (ADR-0086 sections 1, 2, 4, 7 and 7a; network-control-schemas.md sections 3 and 4; authenticated-control-schemas.md sections 4 to 6 and 9; SPEC.md section 4), never from the Rust code. It checks itself against RFC 4231, RFC 5869 and RFC 8032 section 7.1 first, and its control bodies against the binary vectors of authenticated-control-schemas.md section 9 |
| `wire-auth-v1.txt` | Its output, one `<vector> <field> <value>` per line (hex bytes) |

The vectors use the shared values of network-control-schemas.md 5.1 and
the canonical key files of wire-key-files.md 2.7. They are:

- `frames *`: every inner frame: SETUP ANNOUNCE and ANSWER (identity, term
  parameters, the echoed challenge and both lanes' join points), RSP_SETUP
  CHALLENGE and SOLICIT, SM, NAK, SESSION_ABORT_ACK (identity and receiver
  fields), GUARD STATE and STATUS, SESSION_ABORT, a DATA batch (a padded
  message, then a traced message with `EXT` as the last record without its
  padding), a heartbeat, and a multicast batch ending a term (`EOS`, then
  PAD with its extent);
- `kdf-*`: the `info`, salt and output of each KDF context of ADR-0086
  section 4 (unicast and multicast DATA, receiver, SETUP proof, RSP_SETUP);
- `env-*`: the complete MAC envelope of each frame, in the order of the
  SETUP transcript (ANNOUNCE, CHALLENGE, ANSWER, SOLICIT under their proof
  keys), then DATA under the key the challenge salts, then SM, NAK and
  SESSION_ABORT_ACK under the receiver key;
- `sig-*`: the signed GUARD STATE, GUARD STATUS and SESSION_ABORT
  envelopes (Ed25519 is deterministic, so the signatures are exact);
- `neg-*`: Ed25519 negative vectors: `S + L`, a non-canonical and a
  small-order `R`, the eight small-order `A` and two non-canonical `A`.

`crates/karyos-driver/src/wire_auth/vectors.rs` builds every frame with
the production codecs and every envelope with the production key paths
(`Sealer`, `Proof`, `Context::derive`, `seal_signed` and
`Ed25519Signer`), compares each with these bytes, and refuses every
single-bit change, truncation and extension of each envelope (H1).

To regenerate (the file must not change):

    python3 crates/karyos-driver/tests/vectors/wire_auth_v1.py \
        > crates/karyos-driver/tests/vectors/wire-auth-v1.txt
