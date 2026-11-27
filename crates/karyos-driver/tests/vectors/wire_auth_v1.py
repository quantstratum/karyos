#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independent vectors of the wire authentication profile v1 (gate H5).

A second implementation of `quantstratum-docs:
karyos/adr/0086-wire-authentication-profile-v1.md` sections 1, 2, 4 and 7a,
written from the documents only (ADR-0086, network-control-schemas.md
sections 3 and 4, authenticated-control-schemas.md sections 4 to 6 and
SPEC.md section 4), never from the Rust code. It uses only the Python
standard library: `hmac` and `hashlib` for HMAC-SHA-256 and HKDF-SHA-256
(RFC 5869), and the RFC 8032 section 6 reference arithmetic, written out
below, for Ed25519 with cofactorless strict verification.

It prints `wire-auth-v1.txt`, the file that
`crates/karyos-driver/src/wire_auth/vectors.rs` checks the implementation
against byte for byte:

    python3 crates/karyos-driver/tests/vectors/wire_auth_v1.py \
        > crates/karyos-driver/tests/vectors/wire-auth-v1.txt

Each line is `<vector> <field> <value>`: hex for byte strings, decimal for
integers. Lines starting with `#` are comments.
"""

import hashlib
import hmac
import struct
import sys

# --- Primitives -------------------------------------------------------------

LABEL = b"karyos-wire-auth-v1\x00"


def hkdf_sha256(salt, ikm, info, length):
    """RFC 5869; `salt` None is 32 zero bytes (RFC 5869 section 2.2)."""
    if salt is None:
        salt = bytes(32)
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


# RFC 8032 section 6, reference arithmetic (not constant time: vectors only).
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def sha512(data):
    return hashlib.sha512(data).digest()


def point_add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    aa = (y1 - x1) * (y2 - x2) % P
    bb = (y1 + x1) * (y2 + x2) % P
    cc = t1 * 2 * D * t2 % P
    dd = z1 * 2 * z2 % P
    e, f, g, h = bb - aa, dd - cc, dd + cc, bb + aa
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def point_mul(s, point):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = point_add(q, point)
        point = point_add(point, point)
        s >>= 1
    return q


def point_equal(a, b):
    x1, y1, z1, _ = a
    x2, y2, z2, _ = b
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def recover_x(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


G_Y = 4 * pow(5, P - 2, P) % P
G = (recover_x(G_Y, 0), G_Y, 1, recover_x(G_Y, 0) * G_Y % P)
IDENTITY = (0, 1, 1, 0)


def compress(point):
    x, y, z, _ = point
    zinv = pow(z, P - 2, P)
    x, y = x * zinv % P, y * zinv % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def decompress(data):
    """The point, or None. Like RFC 8032 section 5.1.3, but a y of p or
    more is reduced instead of refused, so that a non-canonical encoding
    decodes; `decode_strict` refuses it."""
    if len(data) != 32:
        return None
    value = int.from_bytes(data, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    x = recover_x(y % P, sign)
    if x is None:
        return None
    y %= P
    return (x, y, 1, x * y % P)


def decode_strict(data):
    """The point only when the encoding is canonical and the point is not
    of small order (ADR-0086 section 8, manifest 4.1)."""
    point = decompress(data)
    if point is None or compress(point) != data:
        return None
    if point_equal(point_mul(8, point), IDENTITY):
        return None
    return point


def secret_expand(seed):
    h = sha512(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(seed):
    a, _ = secret_expand(seed)
    return compress(point_mul(a, G))


def sign(seed, message):
    a, prefix = secret_expand(seed)
    public = compress(point_mul(a, G))
    r = int.from_bytes(sha512(prefix + message), "little") % L
    big_r = compress(point_mul(r, G))
    k = int.from_bytes(sha512(big_r + public + message), "little") % L
    s = (r + k * a) % L
    return big_r + int.to_bytes(s, 32, "little")


def verify_strict(public, message, signature):
    """Cofactorless strict verification: canonical A and R, neither of
    small order, S < L, and [S]B = R + [k]A."""
    if len(signature) != 64:
        return False
    a = decode_strict(public)
    r = decode_strict(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    k = int.from_bytes(sha512(signature[:32] + public + message), "little") % L
    return point_equal(point_mul(s, G), point_add(r, point_mul(k, a)))


def self_test():
    # RFC 4231 test case 2.
    assert hmac.new(b"Jefe", b"what do ya want for nothing?", hashlib.sha256).hexdigest() == (
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    )
    # RFC 5869 appendix A.1.
    assert hkdf_sha256(bytes(range(13)), bytes([0x0B] * 22), bytes(range(0xF0, 0xFA)), 42).hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )
    # RFC 5869 appendix A.3: no salt.
    assert hkdf_sha256(None, bytes([0x0B] * 22), b"", 42).hex() == (
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    )
    # RFC 8032 section 7.1, TEST 1 to TEST 3.
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    assert public_key(seed).hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    sig = sign(seed, b"")
    assert sig.hex() == (
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    assert verify_strict(public_key(seed), b"", sig)
    seed = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    sig = sign(seed, b"\x72")
    assert sig.hex() == (
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    )
    seed = bytes.fromhex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
    assert public_key(seed).hex() == "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
    sig = sign(seed, bytes.fromhex("af82"))
    assert sig.hex() == (
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
    )
    assert verify_strict(public_key(seed), bytes.fromhex("af82"), sig)


# --- Encodings (documents only) --------------------------------------------

u8 = lambda v: struct.pack("<B", v)
u16 = lambda v: struct.pack("<H", v)
u32 = lambda v: struct.pack("<I", v)
i32 = lambda v: struct.pack("<i", v)
u64 = lambda v: struct.pack("<Q", v)
i64 = lambda v: struct.pack("<q", v)
id128 = lambda w: u64(w[0]) + u64(w[1])

# network-control-schemas.md 5.1 shared values.
SESSION_ID = 0x12345678
STREAM_ID = 1001
DRIVER_ID = (0x0123456789ABCDEF, 0xFEDCBA9876543210)
REGISTRATION_ID = 7
INCARNATION = 1
TERM_LENGTH = 65536
INITIAL_TERM_ID = -2
MTU = 1408
BOOT = (0xA1A2A3A4A5A6A7A8, 0xB1B2B3B4B5B6B7B8)
NONCE = (0xC1C2C3C4C5C6C7C8, 0xD1D2D3D4D5D6D7D8)
RECEIVER_ID = 0x42

# The canonical key files of wire-key-files.md section 2.7.
CHANNEL_KEY_ID, CHANNEL_EPOCH = 3, 3
CHANNEL_SECRET = bytes(range(0x00, 0x20))
PAIRWISE_KEY_ID, PAIRWISE_EPOCH = 16909060, 3
PAIRWISE_SECRET = bytes(range(0x20, 0x40))
AUTHORITY_KEY_ID = 10
AUTHORITY_SEED = bytes([0x09] * 32)
AUTHORITY_PUBLIC = "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618"

HMAC_PROFILE, SIGNED_PROFILE = 1, 4
DOMAIN_DATA, DOMAIN_GUARD, DOMAIN_ABORT, DOMAIN_RCV, DOMAIN_SETUP, DOMAIN_RSP = 1, 2, 3, 4, 5, 6
LANES = 2


def identity_block():
    return id128(DRIVER_ID) + u64(REGISTRATION_ID) + u64(INCARNATION)


def receiver_block():
    return id128(BOOT) + u64(RECEIVER_ID)


def challenge_block():
    return id128(BOOT) + id128(NONCE)


def term_params():
    return u32(TERM_LENGTH) + i32(INITIAL_TERM_ID) + u32(MTU) + u32(0)


def control(frame_type, variant, count, session, stream, body):
    """The 24-byte common header (network-control-schemas.md 3.2) and body."""
    length = 24 + len(body)
    return (
        i32(length) + u8(1) + u8(0) + u16(frame_type) + u8(variant) + u8(count) + u16(0)
        + i32(session) + i32(stream) + u32(0) + body
    )


JOINS = (4096, 0)

FRAMES = {
    # SETUP ANNOUNCE and ANSWER (4.1): identity, term parameters, the
    # echoed challenge and every lane's join point.
    "setup-announce": control(5, 1, LANES, SESSION_ID, STREAM_ID, identity_block() + term_params()),
    "setup-answer": control(
        5, 2, LANES, SESSION_ID, STREAM_ID,
        identity_block() + term_params() + challenge_block() + b"".join(u64(j) for j in JOINS),
    ),
    # RSP_SETUP CHALLENGE and SOLICIT (4.2).
    "rsp-challenge": control(7, 1, 0, SESSION_ID, STREAM_ID, identity_block() + challenge_block()),
    "rsp-solicit": control(7, 2, 0, SESSION_ID, STREAM_ID, challenge_block()),
    # SM STATUS (4.3): two lanes.
    "sm": control(
        3, 1, LANES, SESSION_ID, STREAM_ID,
        identity_block() + receiver_block() + u64(0x7A)
        + u64(8192) + u32(32768) + u32(0)
        + u64(256) + u32(4096) + u32(0),
    ),
    # NAK RANGE (4.4).
    "nak": control(
        2, 1, 0, SESSION_ID, STREAM_ID,
        identity_block() + receiver_block() + u8(1) + bytes(3) + u32(1024) + u64(2048),
    ),
    # SESSION_ABORT_ACK, 2 lanes (authenticated-control-schemas.md 6).
    "abort-ack": control(
        0x13, 1, LANES, SESSION_ID, STREAM_ID,
        identity_block() + receiver_block() + u64(3)
        + u64(4096) + u64(8192) + u64(0) + u64(0),
    ),
    # GUARD STATE and STATUS, SESSION_ABORT ABORT (sections 4.1, 4.3, 5).
    "guard-state": control(0x11, 1, 0, 0, 0, u64(0x0A) + u64(0x0B) + u64(9) + u32(5000) + u32(0)),
    "guard-status": control(
        0x11, 3, 0, 0, 0, u64(0x0A) + u64(0x0B) + receiver_block() + id128(NONCE) + u64(6)
    ),
    "session-abort": control(
        0x12, 1, 0, SESSION_ID, STREAM_ID,
        identity_block() + u64(0x0A) + u64(0x0B) + u64(3) + u16(1) + bytes(6),
    ),
}

# The binary vectors of authenticated-control-schemas.md section 9.
DOC_BODIES = {
    "guard-state": "3800000001001100010000000000000000000000000000000a000000000000000b0000000000000009000000000000008813000000000000",
    "guard-status": "5800000001001100030000000000000000000000000000000a000000000000000b00000000000000a8a7a6a5a4a3a2a1b8b7b6b5b4b3b2b14200000000000000c8c7c6c5c4c3c2c1d8d7d6d5d4d3d2d10600000000000000",
    "session-abort": "58000000010012000100000078563412e903000000000000efcdab89674523011032547698badcfe070000000000000001000000000000000a000000000000000b0000000000000003000000000000000100000000000000",
    "abort-ack": "78000000010013000102000078563412e903000000000000efcdab89674523011032547698badcfe07000000000000000100000000000000a8a7a6a5a4a3a2a1b8b7b6b5b4b3b2b1420000000000000003000000000000000010000000000000002000000000000000000000000000000000000000000000",
}


def data_header(length, flags, frame_type, term_offset, term_id, reserved_value):
    """SPEC.md section 4 frame header."""
    return (
        i32(length) + u8(1) + u8(flags) + u16(frame_type) + i32(term_offset)
        + i32(SESSION_ID) + i32(STREAM_ID) + i32(term_id) + i64(reserved_value)
    )


def trace_extension(trace_id, span, parent, message_id):
    """SPEC.md section 4 trace extension (64 bytes)."""
    return (
        u8(1) + u8(0) + u16(0) + u32(64) + id128(trace_id) + u64(span) + u64(parent)
        + u64(message_id) + bytes(16)
    )


def align32(data):
    return data + bytes((-len(data)) % 32)


BEGIN, END, EOS, EXT = 0x01, 0x02, 0x04, 0x08
lane = lambda n: n << 4

payload1 = b"karyos vector"
payload2 = b"hello"
# A batch on lane 1: a whole message padded to 32, then a traced message
# (EXT) as the last record, without its alignment padding.
FRAMES["data-batch"] = align32(
    data_header(32 + len(payload1), BEGIN | END | lane(1), 0x01, 0, INITIAL_TERM_ID, 0x0102030405060708)
    + payload1
) + (
    data_header(32 + 64 + len(payload2), BEGIN | END | EXT | lane(1), 0x01, 64, INITIAL_TERM_ID, 0)
    + trace_extension((0x1111111111111111, 0x2222222222222222), 0x33, 0x44, 0x55)
    + payload2
)
# A heartbeat: one header-only DATA record on lane 2.
FRAMES["heartbeat"] = data_header(32, lane(2), 0x01, 160, INITIAL_TERM_ID, 0)
# A multicast batch on lane 0: the last message of a term (EOS) and the PAD
# record that ends the term, its extent in `reserved_value`.
payload3 = bytes(range(32))
FRAMES["data-multicast"] = data_header(
    64, BEGIN | END | EOS, 0x01, TERM_LENGTH - 128, INITIAL_TERM_ID, 0
) + payload3 + data_header(32, 0, 0x00, TERM_LENGTH - 64, INITIAL_TERM_ID, 64)


# --- KDF (ADR-0086 section 4) -----------------------------------------------

def kdf_data(party_epoch, unicast):
    info = (
        LABEL + b"data" + u32(CHANNEL_EPOCH) + u8(party_epoch) + identity_block()
        + u8(LANES) + u32(CHANNEL_KEY_ID) + u8(HMAC_PROFILE)
    )
    salt = challenge_block() if unicast else None
    return info, salt, hkdf_sha256(salt, CHANNEL_SECRET, info, 32)


def kdf_rcv(party_epoch):
    info = (
        LABEL + b"rcv" + u32(PAIRWISE_EPOCH) + u8(party_epoch) + id128(BOOT) + u64(RECEIVER_ID)
        + identity_block() + u32(PAIRWISE_KEY_ID) + u8(HMAC_PROFILE)
    )
    return info, None, hkdf_sha256(None, PAIRWISE_SECRET, info, 32)


def kdf_setup():
    info = LABEL + b"setup" + u32(CHANNEL_EPOCH) + u32(CHANNEL_KEY_ID) + u8(HMAC_PROFILE)
    return info, None, hkdf_sha256(None, CHANNEL_SECRET, info, 32)


def kdf_rsp():
    info = LABEL + b"rsp" + u32(PAIRWISE_EPOCH) + u64(RECEIVER_ID) + u32(PAIRWISE_KEY_ID) + u8(HMAC_PROFILE)
    return info, None, hkdf_sha256(None, PAIRWISE_SECRET, info, 32)


# --- Envelopes (ADR-0086 section 2) -----------------------------------------

def header(length, profile, tag_len, domain, party_epoch, session, stream, key_id, seq):
    return (
        i32(length) + u8(1) + u8(0) + u16(0x20) + u8(profile) + u8(tag_len) + u8(domain)
        + u8(party_epoch) + i32(session) + i32(stream) + u32(key_id) + u64(seq)
    )


def mac_envelope(key, domain, party_epoch, key_id, seq, frames):
    head = header(32 + len(frames) + 16, HMAC_PROFILE, 16, domain, party_epoch, SESSION_ID, STREAM_ID, key_id, seq)
    tag = hmac.new(key, LABEL + head + frames, hashlib.sha256).digest()[:16]
    return head + frames + tag


def signed_envelope(domain, session, stream, seq, body):
    head = header(32 + len(body) + 64, SIGNED_PROFILE, 64, domain, 0, session, stream, AUTHORITY_KEY_ID, seq)
    return head + body + sign(AUTHORITY_SEED, LABEL + head + body)


# --- Ed25519 negative vectors (ADR-0086 section 8, gate H5) -----------------

def small_order_points():
    """The eight points of order dividing 8, as canonical encodings."""
    found = set()
    # The torsion points: identity, order 2 (0, -1), order 4 (+-sqrt(-1), 0),
    # and the four of order 8, found from the order-8 encoding below.
    eight = bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")
    point = decompress(eight)
    assert point is not None and not point_equal(point_mul(4, point), IDENTITY)
    assert point_equal(point_mul(8, point), IDENTITY)
    for k in range(8):
        found.add(compress(point_mul(k, point)))
    return sorted(found)


def non_canonical_point():
    """`y + p` for the smallest y < 19 on the curve with a point of large
    order: it decodes to a valid point, but is not its canonical encoding."""
    for y in range(2, 19):
        x = recover_x(y, 0)
        if x is None:
            continue
        point = (x, y, 1, x * y % P)
        if point_equal(point_mul(8, point), IDENTITY):
            continue
        return int.to_bytes(y + P, 32, "little"), compress(point)
    raise AssertionError("no non-canonical encoding")


def main():
    self_test()
    out = []
    emit = lambda name, field, value: out.append(
        f"{name} {field} {value.hex() if isinstance(value, bytes) else value}"
    )

    assert public_key(AUTHORITY_SEED).hex() == AUTHORITY_PUBLIC
    for name, hexed in DOC_BODIES.items():
        assert FRAMES[name].hex() == hexed, name
    assert len(FRAMES["setup-announce"]) == 72 and len(FRAMES["setup-answer"]) == 120
    assert len(FRAMES["rsp-challenge"]) == 88 and len(FRAMES["rsp-solicit"]) == 56
    assert len(FRAMES["sm"]) == 120 and len(FRAMES["nak"]) == 96

    out.append("# SPDX-License-Identifier: Apache-2.0")
    out.append("# Generated by wire_auth_v1.py; do not edit (gate H5, ADR-0086).")
    for name, frames in FRAMES.items():
        emit("frames", name, frames)

    keys = {
        "data-unicast": kdf_data(0, True),
        "data-multicast": kdf_data(1, False),
        "rcv": kdf_rcv(0),
        "setup": kdf_setup(),
        "rsp": kdf_rsp(),
    }
    for name, (info, salt, okm) in keys.items():
        emit(f"kdf-{name}", "info", info)
        emit(f"kdf-{name}", "salt", salt if salt is not None else b"")
        emit(f"kdf-{name}", "okm", okm)

    # The SETUP transcript in order (ADR-0086 sections 7 and 7a): the
    # ANNOUNCE under the SETUP proof key, the receiver's CHALLENGE under its
    # RSP_SETUP key, the ANSWER that echoes it with the join points, then
    # the first DATA under the sender key the challenge salts. The SOLICIT
    # is the other RSP_SETUP form. Each proof key counts its own sequence.
    mac = [
        ("setup-announce", "setup", DOMAIN_SETUP, 0, CHANNEL_KEY_ID, 0),
        ("rsp-challenge", "rsp", DOMAIN_RSP, 0, PAIRWISE_KEY_ID, 0),
        ("setup-answer", "setup", DOMAIN_SETUP, 0, CHANNEL_KEY_ID, 1),
        ("rsp-solicit", "rsp", DOMAIN_RSP, 0, PAIRWISE_KEY_ID, 1),
        ("data-batch", "data-unicast", DOMAIN_DATA, 0, CHANNEL_KEY_ID, 0),
        ("heartbeat", "data-unicast", DOMAIN_DATA, 0, CHANNEL_KEY_ID, 1),
        ("data-multicast", "data-multicast", DOMAIN_DATA, 1, CHANNEL_KEY_ID, 7),
        ("sm", "rcv", DOMAIN_RCV, 0, PAIRWISE_KEY_ID, 0),
        ("nak", "rcv", DOMAIN_RCV, 0, PAIRWISE_KEY_ID, 1),
        ("abort-ack", "rcv", DOMAIN_RCV, 0, PAIRWISE_KEY_ID, 2),
    ]
    for frames, key, domain, party_epoch, key_id, seq in mac:
        emit(f"env-{frames}", "datagram", mac_envelope(keys[key][2], domain, party_epoch, key_id, seq, FRAMES[frames]))

    signed = [
        ("guard-state", DOMAIN_GUARD, 0, 0, 0),
        ("guard-status", DOMAIN_GUARD, 0, 0, 1),
        ("session-abort", DOMAIN_ABORT, SESSION_ID, STREAM_ID, 2),
    ]
    public = bytes.fromhex(AUTHORITY_PUBLIC)
    for body, domain, session, stream, seq in signed:
        datagram = signed_envelope(domain, session, stream, seq, FRAMES[body])
        assert verify_strict(public, LABEL + datagram[:-64], datagram[-64:])
        emit(f"sig-{body}", "datagram", datagram)

    # Negative Ed25519 vectors over the SESSION_ABORT message: each must be
    # refused by the key loader (A) or by strict verification (R, S).
    abort = signed_envelope(DOMAIN_ABORT, SESSION_ID, STREAM_ID, 2, FRAMES["session-abort"])
    message, signature = LABEL + abort[:-64], abort[-64:]
    s = int.from_bytes(signature[32:], "little")
    non_canonical_s = signature[:32] + int.to_bytes(s + L, 32, "little")
    assert not verify_strict(public, message, non_canonical_s)
    emit("neg-s-plus-l", "signature", non_canonical_s)
    # R: the non-canonical encoding (y = p + 1) of the identity, and a
    # canonical small-order R; with the matching S for that R both satisfy
    # a cofactored equation only, and strict verification refuses them.
    a, _ = secret_expand(AUTHORITY_SEED)
    for name, big_r in [
        ("neg-r-non-canonical", int.to_bytes(P + 1, 32, "little")),
        ("neg-r-small-order", small_order_points()[1]),
    ]:
        k = int.from_bytes(sha512(big_r + public + message), "little") % L
        forged = big_r + int.to_bytes(k * a % L, 32, "little")
        assert not verify_strict(public, message, forged)
        emit(name, "signature", forged)
    for index, point in enumerate(small_order_points()):
        assert decode_strict(point) is None
        emit(f"neg-a-small-order-{index}", "public", point)
    encoded, canonical = non_canonical_point()
    assert decode_strict(encoded) is None and decompress(encoded) is not None
    emit("neg-a-non-canonical", "public", encoded)
    emit("neg-a-non-canonical", "canonical", canonical)
    # The identity point encoded as y = p + 1: non-canonical and small order.
    emit("neg-a-identity-non-canonical", "public", int.to_bytes(P + 1, 32, "little"))

    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
