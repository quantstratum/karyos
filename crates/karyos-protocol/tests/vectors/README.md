<!-- SPDX-License-Identifier: Apache-2.0 -->

# Encrypted protection profile v1 vectors (gate H5)

Independent vectors of the `encrypted` class (ADR-0114; wire threat model
manifest section 7, gate H5), produced by a second implementation written
from the frozen encodings only, never from the Rust code, and checked
against the product byte for byte.

| File | What it is |
| --- | --- |
| `enc_vectors.py` | Part 1: the RFC 8452 C.2 check, the KDF `info` and key of every domain, the pairwise trailer key and one sealed datagram per domain (ADR-0114 sections 2, 4 and 5) |
| `enc_vectors-output.txt` | Its output |
| `enc_vectors2.py` | Part 2: the SETUP variant 3 ENC ANSWER transcript sealed in domain 5, the KDF and one envelope per domain at the next `party_epoch` and the next `key_epoch` (sections 2, 4, 5 and 6a; network-control-schemas.md 3.2, 3.3, 4.1 and 5.1), and the key file vectors of wire-key-files.md 2.7, with a parser written from that text |
| `enc_vectors2-output.txt` | Its output |

Both scripts need Python 3 and the `cryptography` package (HKDF-SHA-256,
AES-GCM-SIV, Ed25519) besides the standard `hmac` and `hashlib`. Part 1
was first run with `cryptography` 50.0.2 and part 2 with 46.0.5; either
version gives both outputs byte for byte.

Every expected value the Rust tests embed is tied to these files: the
`h5_*_tracked_output` tests of `src/protection/aes_gcm_siv/tests.rs`,
`src/network/encrypted/tests.rs` and the karyos-driver
`src/wire_keys/tests.rs` look each embedded literal up in the output line
of its vector and fail on any difference.

To regenerate (the files must not change):

    cd crates/karyos-protocol/tests/vectors
    python3 -I enc_vectors.py > enc_vectors-output.txt
    python3 -I enc_vectors2.py > enc_vectors2-output.txt
