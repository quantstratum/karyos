#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independent vectors of the encrypted protection profile v1 (ADR-0114),
part 2 (gate H5).

Every value is computed here from the frozen encodings only, never from
the Rust implementation:

- ADR-0114 sections 2, 4, 5 and 6a (envelope, key schedule, nonce, epoch
  block), with the Python `cryptography` package (HKDF-SHA-256,
  AESGCMSIV, Ed25519) and the standard `hmac` module;
- network-control-schemas.md sections 3.2, 3.3, 4.1 and 5.1 (SETUP
  variant 3 ENC ANSWER);
- wire-key-files.md sections 2.2 and 2.7 (key file grammar and vectors),
  with a parser written here from that text.

Run: python3 -I enc_vectors2.py

Prints (a) a SETUP variant 3 ENC ANSWER transcript sealed in domain 5,
(b) the KDF and one envelope per domain at the next `party_epoch` and the
next `key_epoch`, (c) the key file vectors of wire-key-files.md 2.7, the
`revoked` list ones (grammar of section 2.4) included.
"""
import calendar
import hashlib
import hmac
import re
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

LABEL = b"karyos-wire-enc-v01\0"
PROFILE_ID = 16
DOMAIN = {"snd": 1, "rcv": 4, "setup": 5, "rsp": 6}


def w128(w0, w1):
    return struct.pack("<QQ", w0, w1)


def purpose(tag):
    return tag.encode().ljust(8, b"\0")


def hkdf(ikm, salt, info_bytes):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt or None, info=info_bytes).derive(ikm)


class Ctx:
    """The inputs of one derived key (ADR-0114 section 4)."""

    def __init__(self, ikm, domain, key_epoch, party_epoch, session_id, stream_id, ib, rb, salt):
        self.ikm, self.domain = ikm, domain
        self.key_epoch, self.party_epoch = key_epoch, party_epoch
        self.session_id, self.stream_id = session_id, stream_id
        self.ib, self.rb, self.salt = ib, rb, salt

    def receiver(self):
        return self.domain in ("rcv", "rsp")

    def info(self):
        head = LABEL + purpose(self.domain) + struct.pack("<IH", self.key_epoch, self.party_epoch)
        body = self.rb + self.ib if self.receiver() else self.ib
        return head + body + bytes([PROFILE_ID])

    def key(self):
        return hkdf(self.ikm, self.salt, self.info())

    def header(self, seq, total):
        party = self.rb + bytes(8) if self.receiver() else self.ib
        return (
            struct.pack("<iBBHBBBB", total, 1, 0, 0x21, PROFILE_ID, 16, DOMAIN[self.domain], 0)
            + struct.pack("<IHH", self.key_epoch, self.party_epoch, 0)
            + struct.pack("<iiQ", self.session_id, self.stream_id, seq)
            + party
        )


def pairwise_info(epoch, rb, ib):
    return LABEL + purpose("pauth") + struct.pack("<I", epoch) + rb + ib + bytes([PROFILE_ID])


def seal(ctx, seq, frames, pairwise=None):
    """pairwise: (secret, epoch) in domains 4 and 6."""
    plain_len = len(frames) + (20 if ctx.receiver() else 0)
    total = 68 + plain_len + 16
    head = ctx.header(seq, total)
    plaintext = frames
    if ctx.receiver():
        secret, epoch = pairwise
        kp = hkdf(secret, b"", pairwise_info(epoch, ctx.rb, ctx.ib))
        partial = frames + struct.pack("<I", epoch)
        plaintext = partial + hmac.new(kp, LABEL + head + partial, hashlib.sha256).digest()[:16]
    nonce = bytes([DOMAIN[ctx.domain], 0, 0, 0]) + struct.pack("<Q", seq)
    datagram = head + AESGCMSIV(ctx.key()).encrypt(nonce, plaintext, LABEL + head)
    assert len(datagram) == total
    return datagram


def frames(length, mul, add):
    return bytes((i * mul + add) % 256 for i in range(length))


# ---------------------------------------------------------------------
# (a) SETUP variant 3 ENC ANSWER (network-control-schemas.md 4.1, with
# the field values of 5.1 and V-SETUP-2), sealed in domain 5.
# ---------------------------------------------------------------------
SESSION = 0x12345678
STREAM = 1001
ANSWER_IB = w128(0x0123456789ABCDEF, 0xFEDCBA9876543210) + struct.pack("<QQ", 7, 1)
TP = struct.pack("<IiII", 65536, -2, 1408, 0)
CB = w128(0xA1A2A3A4A5A6A7A8, 0xB1B2B3B4B5B6B7B8) + w128(0xC1C2C3C4C5C6C7C8, 0xD1D2D3D4D5D6D7D8)
ANSWER_KEY_EPOCH = 3
ANSWER_PARTY_EPOCH = 0x0102
JOINS = [200704, 0]


def enc_answer():
    n = len(JOINS)
    length = 112 + 8 * n
    ch = struct.pack("<iBBHBBHiiI", length, 1, 0, 0x05, 3, n, 0, SESSION, STREAM, 0)
    block = struct.pack("<IHH", ANSWER_KEY_EPOCH, ANSWER_PARTY_EPOCH, 0)
    out = ch + ANSWER_IB + TP + CB + block + b"".join(struct.pack("<Q", j) for j in JOINS)
    assert len(out) == length and len(ch) == 24
    return out


ANSWER = enc_answer()
SETUP_IKM = bytes(range(32))
SETUP_SEQ = 4
setup_ctx = Ctx(SETUP_IKM, "setup", ANSWER_KEY_EPOCH, 0, SESSION, STREAM, ANSWER_IB, b"", b"")
transcript = seal(setup_ctx, SETUP_SEQ, ANSWER)
assert len(transcript) >= 120
print("# SPDX-License-Identifier: Apache-2.0")
print("# Generated by enc_vectors2.py; do not edit (gate H5, ADR-0114).")
print(f"enc answer plaintext ({len(ANSWER)}): {ANSWER.hex()}")
print(f"enc answer setup info: {setup_ctx.info().hex()}")
print(f"enc answer setup key: {setup_ctx.key().hex()}")
print(f"enc answer sealed seq {SETUP_SEQ} ({len(transcript)}): {transcript.hex()}")

# ---------------------------------------------------------------------
# (b) Epoch transitions: the inputs of enc_vectors_ref.py, at the next
# party_epoch (5, 3) and the next key_epoch (6, 0), every domain; the
# receiver domains at the next key_epoch also use the next pairwise file
# epoch (10).
# ---------------------------------------------------------------------
IKM = bytes(range(32))
PAIRWISE_SECRET = bytes(0xA0 + i for i in range(32))
IB = w128(0x0102030405060708, 0x1112131415161718) + struct.pack("<QQ", 7, 3)
BOOT = w128(0x2122232425262728, 0x3132333435363738)
RB = BOOT + struct.pack("<Q", 42)
CHALLENGE_SALT = BOOT + w128(0x4142434445464748, 0x5152535455565758)

for name, domain, key_epoch, party_epoch, salted, pw_epoch, seq, body in [
    ("snd next party", "snd", 5, 3, True, None, 0, frames(64, 3, 1)),
    ("snd next key", "snd", 6, 0, True, None, 1, frames(64, 5, 2)),
    ("rcv next party", "rcv", 5, 3, True, 9, 0, frames(32, 7, 3)),
    ("rcv next key", "rcv", 6, 0, True, 10, 2, frames(32, 9, 4)),
    ("setup next key", "setup", 6, 0, False, None, 0, frames(72, 11, 5)),
    ("rsp next key", "rsp", 6, 0, False, 10, 0, frames(88, 13, 6)),
]:
    rb = RB if domain in ("rcv", "rsp") else b""
    ctx = Ctx(IKM, domain, key_epoch, party_epoch, -2, 1001, IB, rb, CHALLENGE_SALT if salted else b"")
    pw = (PAIRWISE_SECRET, pw_epoch) if pw_epoch else None
    print(f"epoch {name}: info {ctx.info().hex()} key {ctx.key().hex()}")
    print(f"epoch {name}: seq {seq} envelope {seal(ctx, seq, body, pw).hex()}")
print(
    "epoch pairwise 10: info "
    f"{pairwise_info(10, RB, IB).hex()} key {hkdf(PAIRWISE_SECRET, b'', pairwise_info(10, RB, IB)).hex()}"
)

# ---------------------------------------------------------------------
# (c) wire-key-files.md 2.7: a parser of section 2.2 written from the
# text, the canonical files, and every refusal vector.
# ---------------------------------------------------------------------
ORDER = [
    ("format", "all"), ("key_id", "all"), ("file_epoch", "all"), ("purpose", "all"),
    ("profile_id", "all"), ("not_before", "all"), ("not_after", "all"),
    ("secret", ("channel", "pairwise", "authority-signing")), ("public", ("authority-public",)),
    ("channel_id", ("channel",)), ("stream_id", ("channel",)),
    ("receiver_id", ("pairwise",)), ("publisher_id", ("pairwise",)),
    ("authority_id", ("authority-signing", "authority-public")),
    ("guards", ("authority-signing", "authority-public")),
    ("abort", ("authority-signing", "authority-public")),
]
P = 2**255 - 19
D = (-121665 * pow(121666, P - 2, P)) % P


def ed_decode(raw):
    """RFC 8032 5.1.3 with canonical y; None when not a point."""
    y = int.from_bytes(raw, "little") & ((1 << 255) - 1)
    sign = raw[31] >> 7
    if y >= P:
        return None
    u, v = (y * y - 1) % P, (D * y * y + 1) % P
    x = (u * pow(v, 3, P) * pow(u * pow(v, 7, P), (P - 5) // 8, P)) % P
    if (v * x * x) % P != u:
        x = (x * pow(2, (P - 1) // 4, P)) % P
        if (v * x * x) % P != u:
            return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = P - x
    return (x, y)


def ed_add(a, b):
    (x1, y1), (x2, y2) = a, b
    t = D * x1 * x2 * y1 * y2 % P
    return ((x1 * y2 + x2 * y1) * pow(1 + t, P - 2, P) % P, (y1 * y2 + x1 * x2) * pow(1 - t, P - 2, P) % P)


def small_order(pt):
    q = pt
    for _ in range(3):
        q = ed_add(q, q)
    return q == (0, 1)


def number(text, lo, hi, signed=False):
    if not re.fullmatch(r"-?(0|[1-9][0-9]*)", text) or (text.startswith("-") and not signed):
        raise ValueError("number")
    if text == "-0":
        raise ValueError("negative zero")
    value = int(text)
    if not lo <= value <= hi:
        raise ValueError("range")
    return value


def timestamp(text):
    m = re.fullmatch(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z", text)
    if not m:
        raise ValueError("time")
    y, mo, d, h, mi, s = map(int, m.groups())
    if not (1 <= mo <= 12 and 1 <= d <= calendar.monthrange(y, mo)[1] and h < 24 and mi < 60 and s < 60):
        raise ValueError("date")
    return calendar.timegm((y, mo, d, h, mi, s))


def hex32(text):
    if not re.fullmatch(r"[0-9a-f]{64}", text):
        raise ValueError("hex")
    return bytes.fromhex(text)


def parse(name, data):
    m = re.fullmatch(r"(0|[1-9][0-9]*)-(0|[1-9][0-9]*)\.key", name)
    if not m:
        raise ValueError("name")
    if not data.endswith(b"\n") or any(b < 0x21 and b != 0x0A or b > 0x7E for b in data):
        raise ValueError("encoding")
    lines = data[:-1].decode("ascii").split("\n")
    if any(line == "" for line in lines):
        raise ValueError("blank line")
    fields = [line.split("=", 1) for line in lines]
    if any(len(f) != 2 for f in fields):
        raise ValueError("field")
    values = dict(fields)
    kind = values.get("purpose")
    if kind not in ("channel", "pairwise", "authority-signing", "authority-public"):
        raise ValueError("purpose")
    want = [n for n, who in ORDER if who == "all" or kind in who]
    if [f[0] for f in fields] != want:
        raise ValueError("order")
    if values["format"] != "karyos-wire-key-v1":
        raise ValueError("format")
    out = {"purpose": kind}
    out["key_id"] = number(values["key_id"], 1, 2**32 - 1)
    out["file_epoch"] = number(values["file_epoch"], 1, 2**32 - 1)
    if (str(out["key_id"]), str(out["file_epoch"])) != m.groups():
        raise ValueError("name mismatch")
    profile = number(values["profile_id"], 0, 2**64 - 1)
    allowed = (1, 16) if kind in ("channel", "pairwise") else (4,)
    if profile not in allowed:
        raise ValueError("profile mismatch")
    out["profile_id"] = profile
    out["not_before"] = timestamp(values["not_before"])
    out["not_after"] = timestamp(values["not_after"])
    bound = 7_776_000 if kind in ("channel", "pairwise") else 15_552_000
    if not 0 < out["not_after"] - out["not_before"] <= bound:
        raise ValueError("validity")
    if "secret" in values:
        out["secret"] = hex32(values["secret"])
    if "public" in values:
        raw = hex32(values["public"])
        pt = ed_decode(raw)
        if pt is None or small_order(pt):
            raise ValueError("public key")
        out["public"] = raw
    if kind == "channel":
        out["channel_id"] = number(values["channel_id"], 1, 2**64 - 1)
        out["stream_id"] = number(values["stream_id"], -(2**31), 2**31 - 1, signed=True)
    if kind == "pairwise":
        out["receiver_id"] = number(values["receiver_id"], 1, 2**64 - 1)
        out["publisher_id"] = number(values["publisher_id"], 1, 2**64 - 1)
    if kind.startswith("authority"):
        out["authority_id"] = number(values["authority_id"], 1, 2**64 - 1)
        guards = [number(g, 1, 2**64 - 1) for g in values["guards"].split(",")]
        if not 1 <= len(guards) <= 16 or any(a >= b for a, b in zip(guards, guards[1:])):
            raise ValueError("guards")
        out["guards"] = guards
        if values["abort"] not in ("true", "false"):
            raise ValueError("abort")
        out["abort"] = values["abort"] == "true"
    return out


def lines(*rows):
    return ("\n".join(rows) + "\n").encode()


COMMON = ["format=karyos-wire-key-v1"]
CHANNEL = lines(*COMMON, "key_id=3", "file_epoch=3", "purpose=channel", "profile_id=1",
                "not_before=2026-11-01T00:00:00Z", "not_after=2027-01-30T00:00:00Z",
                "secret=" + bytes(range(32)).hex(), "channel_id=7", "stream_id=1001")
PAIRWISE = lines(*COMMON, "key_id=16909060", "file_epoch=3", "purpose=pairwise", "profile_id=1",
                 "not_before=2026-11-01T00:00:00Z", "not_after=2027-01-30T00:00:00Z",
                 "secret=" + bytes(range(0x20, 0x40)).hex(), "receiver_id=66", "publisher_id=5")
SEED = bytes([9]) * 32
PUBLIC_KEY = Ed25519PrivateKey.from_private_bytes(SEED).public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw)
assert PUBLIC_KEY.hex() == "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618"
AUTH_TAIL = ["authority_id=10", "guards=11,12", "abort=true"]
AUTH_HEAD = ["key_id=10", "file_epoch=1"]
VALID_AUTH = ["not_before=2026-11-01T00:00:00Z", "not_after=2027-04-30T00:00:00Z"]
SIGNING = lines(*COMMON, *AUTH_HEAD, "purpose=authority-signing", "profile_id=4", *VALID_AUTH,
                "secret=" + SEED.hex(), *AUTH_TAIL)
PUBLIC = lines(*COMMON, *AUTH_HEAD, "purpose=authority-public", "profile_id=4", *VALID_AUTH,
               "public=" + PUBLIC_KEY.hex(), *AUTH_TAIL)
ENC_CHANNEL = CHANNEL.replace(b"profile_id=1\n", b"profile_id=16\n")

valid = [
    ("channel", "3-3.key", CHANNEL),
    ("pairwise", "16909060-3.key", PAIRWISE),
    ("signing", "10-1.key", SIGNING),
    ("public", "10-1.key", PUBLIC),
    ("enc channel", "3-3.key", ENC_CHANNEL),
    ("enc pairwise", "16909060-3.key", PAIRWISE.replace(b"profile_id=1\n", b"profile_id=16\n")),
]
for label, name, data in valid:
    f = parse(name, data)
    fields = " ".join(
        f"{k}={v.hex() if isinstance(v, bytes) else ','.join(map(str, v)) if isinstance(v, list) else v}"
        for k, v in f.items()
    )
    print(f"keyfile valid {label} {name} {data.hex()} {fields}")

ID_POINT = "01" + "00" * 31
NONCANON = "ee" + "ff" * 30 + "7f"
refused = [
    ("swapped", "3-3.key", CHANNEL.replace(b"key_id=3\nfile_epoch=3\n", b"file_epoch=3\nkey_id=3\n")),
    ("key_id=03", "3-3.key", CHANNEL.replace(b"key_id=3\n", b"key_id=03\n")),
    ("crlf", "3-3.key", CHANNEL.replace(b"\n", b"\r\n")),
    ("trailing space", "3-3.key", CHANNEL.replace(b"stream_id=1001\n", b"stream_id=1001 \n")),
    ("one second over", "3-3.key", CHANNEL.replace(b"2027-01-30T00:00:00Z", b"2027-01-30T00:00:01Z")),
    ("no final lf", "3-3.key", CHANNEL[:-1]),
    ("feb 30", "3-3.key", CHANNEL.replace(b"2026-11-01", b"2026-02-30")),
    ("u32 overflow", "3-3.key", CHANNEL.replace(b"key_id=3\n", b"key_id=4294967296\n")),
    ("minus zero", "3-3.key", CHANNEL.replace(b"stream_id=1001", b"stream_id=-0")),
    ("identity point", "10-1.key", PUBLIC.replace(PUBLIC_KEY.hex().encode(), ID_POINT.encode())),
    ("non-canonical y", "10-1.key", PUBLIC.replace(PUBLIC_KEY.hex().encode(), NONCANON.encode())),
    ("enc signing", "10-1.key", SIGNING.replace(b"profile_id=4", b"profile_id=16")),
    ("enc public", "10-1.key", PUBLIC.replace(b"profile_id=4", b"profile_id=16")),
    ("public profile 1", "10-1.key", PUBLIC.replace(b"profile_id=4", b"profile_id=1")),
    ("public in signing", "10-1.key", SIGNING.replace(b"abort=true", b"public=" + PUBLIC_KEY.hex().encode() + b"\nabort=true")),
    ("guards 12,11", "10-1.key", SIGNING.replace(b"guards=11,12", b"guards=12,11")),
    ("guards 11,", "10-1.key", SIGNING.replace(b"guards=11,12", b"guards=11,")),
]
for profile in (2, 3, 17, 18):
    for label, name, data, base in [
        ("channel", "3-3.key", CHANNEL, b"profile_id=1\n"),
        ("pairwise", "16909060-3.key", PAIRWISE, b"profile_id=1\n"),
        ("signing", "10-1.key", SIGNING, b"profile_id=4\n"),
        ("public", "10-1.key", PUBLIC, b"profile_id=4\n"),
    ]:
        refused.append((f"profile {profile} {label}", name, data.replace(base, f"profile_id={profile}\n".encode())))
for label, name, data in refused:
    try:
        parse(name, data)
    except ValueError as reason:
        print(f"keyfile refused {label.replace(' ', '_')} {name} {data.hex()} ({reason})")
    else:
        raise AssertionError(f"{label} parsed")
# The class rule: one secret in two classes is the same IKM; recorded for
# the admission test (wire-key-files.md 2.7, reused secret).
assert parse("3-3.key", CHANNEL)["secret"] == parse("3-3.key", ENC_CHANNEL)["secret"]
print("keyfile reused secret across classes: 3-3.key (profile 1) and 4-3.key (profile 16) share "
      + parse("3-3.key", ENC_CHANNEL)["secret"].hex())


def parse_revoked(data):
    """A `revoked` list (wire-key-files.md 2.4): one canonical
    `<key_id>-<file_epoch>` per line, strictly increasing, LF-terminated,
    at most 4096 bytes; a 0-byte file revokes nothing."""
    if len(data) > 4096:
        raise ValueError("size")
    if data == b"":
        return []
    if not data.endswith(b"\n") or any(b < 0x21 and b != 0x0A or b > 0x7E for b in data):
        raise ValueError("encoding")
    out = []
    for line in data[:-1].decode("ascii").split("\n"):
        m = re.fullmatch(r"(0|[1-9][0-9]*)-(0|[1-9][0-9]*)", line)
        if not m:
            raise ValueError("name")
        ref = (number(m.group(1), 1, 2**32 - 1), number(m.group(2), 1, 2**32 - 1))
        if out and out[-1] >= ref:
            raise ValueError("duplicate or out of order")
        out.append(ref)
    return out


revoked_valid = [
    ("empty", b""),
    ("one", b"3-3\n"),
    ("increasing", b"3-2\n3-3\n16909060-3\n"),
]
for label, data in revoked_valid:
    entries = ",".join(f"{k}-{e}" for k, e in parse_revoked(data)) or "none"
    print(f"revoked valid {label} {data.hex() or '-'} {entries}")
revoked_refused = [
    ("3-03", b"3-03\n"),
    ("3_3", b"3_3\n"),
    ("duplicate_3-3", b"3-3\n3-3\n"),
]
for label, data in revoked_refused:
    try:
        parse_revoked(data)
    except ValueError as reason:
        print(f"revoked refused {label} {data.hex()} ({reason})")
    else:
        raise AssertionError(f"revoked {label} parsed")
