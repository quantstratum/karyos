// SPDX-License-Identifier: Apache-2.0

//! Gates H5 and H1 of the wire threat model manifest (section 7) for the
//! `authenticated` class: the implementation reproduces, byte for byte,
//! the vectors of a second and independent implementation,
//! `tests/vectors/wire_auth_v1.py` (Python standard library and the
//! RFC 8032 reference arithmetic, written from the documents only), and
//! every single-bit change of a complete envelope is refused.
//!
//! The inner frames are built with the production codecs, the keys from
//! the canonical key files through [`Sealer`], [`Proof`] and
//! [`Context::derive`], and the signed controls with
//! [`seal_signed`] and the authority's [`Ed25519Signer`]. Nothing is read
//! from the vectors to build what is compared against them.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::collections::HashMap;

use karyos_protocol::frame::{Flags, FrameHeader, FrameType, Lane, TraceExtension, Word0};
use karyos_protocol::network::authenticated::{
    AbortAck, AckLane, AuthControl, GuardState, GuardStatus, GuardWord, SessionAbort,
};
use karyos_protocol::network::{
    ChallengeBlock, Control, LaneStatus, Lanes, Nak, NakRange, Receiver, RspChallenge, RspSolicit,
    SetupAnnounce, SetupAnswer, StatusMessage, TermParams,
};
use karyos_protocol::protection::hmac_sha256::{LABEL, TAG_LEN};
use karyos_protocol::protection::signed::{
    AuthorityVerifier, SignedBinding, SignedDomain, open_signed, seal_signed,
};

use super::*;
use crate::authority::{Ed25519Signer, Ed25519Verifier};
use crate::wire_keys::parse;

const VECTORS: &str = include_str!("../../tests/vectors/wire-auth-v1.txt");

/// The canonical files of `quantstratum-docs:
/// karyos/design/wire-key-files.md` section 2.7.
const CHANNEL: &str = "format=karyos-wire-key-v1\nkey_id=3\nfile_epoch=3\npurpose=channel\nprofile_id=1\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\nchannel_id=7\nstream_id=1001\n";
const PAIRWISE: &str = "format=karyos-wire-key-v1\nkey_id=16909060\nfile_epoch=3\npurpose=pairwise\nprofile_id=1\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\nreceiver_id=66\npublisher_id=5\n";
const AUTHORITY_SEED: [u8; 32] = [0x09; 32];
const AUTHORITY_PUBLIC: &str = "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618";

/// network-control-schemas.md section 5.1.
const ALIAS: Alias = Alias {
    session_id: 0x1234_5678,
    stream_id: 1001,
};
const IDENTITY: Identity = Identity {
    driver_id: [0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210],
    registration_id: 7,
    incarnation: 1,
};
const BOOT: [u64; 2] = [0xA1A2_A3A4_A5A6_A7A8, 0xB1B2_B3B4_B5B6_B7B8];
const NONCE: [u64; 2] = [0xC1C2_C3C4_C5C6_C7C8, 0xD1D2_D3D4_D5D6_D7D8];
const RECEIVER: Receiver = Receiver {
    receiver_boot_id: BOOT,
    receiver_id: 0x42,
};
const CHALLENGE: ChallengeBlock = ChallengeBlock {
    receiver_boot_id: BOOT,
    nonce: NONCE,
};
const TERM: TermParams = TermParams {
    term_length: 65536,
    initial_term_id: -2,
    mtu: 1408,
};
const NOW: u64 = 1_796_083_200_000_000_000;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

/// `(vector, field)` to bytes.
fn vectors() -> HashMap<(String, String), Vec<u8>> {
    VECTORS
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .map(|line| {
            let mut parts = line.splitn(3, ' ');
            let name = parts.next().unwrap().to_owned();
            let field = parts.next().unwrap().to_owned();
            let value = parts.next().unwrap_or("");
            ((name, field), hex(value))
        })
        .collect()
}

fn get<'a>(all: &'a HashMap<(String, String), Vec<u8>>, name: &str, field: &str) -> &'a [u8] {
    all.get(&(name.to_owned(), field.to_owned()))
        .unwrap_or_else(|| panic!("no vector {name} {field}"))
}

fn control(value: Control) -> Vec<u8> {
    let mut out = [0_u8; 256];
    let len = value.encode(&mut out).unwrap();
    out[..len].to_vec()
}

fn auth_control(value: AuthControl) -> Vec<u8> {
    let mut out = [0_u8; 256];
    let len = value.encode(&mut out).unwrap();
    out[..len].to_vec()
}

fn lane(n: u8) -> Lane {
    Lane::try_new(n).unwrap()
}

fn data_header(
    length: i32,
    flags: Flags,
    frame_type: FrameType,
    term_offset: i32,
    reserved_value: i64,
) -> Vec<u8> {
    let mut out = [0_u8; 32];
    FrameHeader {
        word0: Word0::new(length, flags, frame_type),
        term_offset,
        session_id: ALIAS.session_id,
        stream_id: ALIAS.stream_id,
        term_id: TERM.initial_term_id,
        reserved_value,
    }
    .encode(&mut out)
    .unwrap();
    out.to_vec()
}

/// Every inner frame of the vectors, from the production codecs.
fn frames() -> Vec<(&'static str, Vec<u8>)> {
    let joins = Lanes::new(&[4096, 0]).unwrap();
    let mut batch = data_header(
        45,
        Flags::new(true, true, false, false, lane(1)),
        FrameType::Data,
        0,
        0x0102_0304_0506_0708,
    );
    batch.extend_from_slice(b"karyos vector");
    batch.resize(64, 0);
    batch.extend(data_header(
        101,
        Flags::new(true, true, false, true, lane(1)),
        FrameType::Data,
        64,
        0,
    ));
    let mut ext = [0_u8; 64];
    TraceExtension {
        extension_flags: 0,
        trace_id: [0x1111_1111_1111_1111, 0x2222_2222_2222_2222],
        span_id: 0x33,
        parent_span_id: 0x44,
        message_id: 0x55,
    }
    .encode(&mut ext)
    .unwrap();
    batch.extend_from_slice(&ext);
    batch.extend_from_slice(b"hello");
    let mut multicast = data_header(
        64,
        Flags::new(true, true, true, false, lane(0)),
        FrameType::Data,
        65536 - 128,
        0,
    );
    multicast.extend(0..32_u8);
    multicast.extend(data_header(32, Flags::NONE, FrameType::Pad, 65536 - 64, 64));
    vec![
        (
            "setup-announce",
            control(Control::SetupAnnounce(SetupAnnounce {
                alias: ALIAS,
                identity: IDENTITY,
                term: TERM,
                lane_count: 2,
            })),
        ),
        (
            "setup-answer",
            control(Control::SetupAnswer(SetupAnswer {
                alias: ALIAS,
                identity: IDENTITY,
                term: TERM,
                challenge: CHALLENGE,
                joins,
            })),
        ),
        (
            "rsp-challenge",
            control(Control::Challenge(RspChallenge {
                alias: ALIAS,
                identity: IDENTITY,
                challenge: CHALLENGE,
            })),
        ),
        (
            "rsp-solicit",
            control(Control::Solicit(RspSolicit {
                alias: ALIAS,
                challenge: CHALLENGE,
            })),
        ),
        (
            "sm",
            control(Control::Status(StatusMessage {
                alias: ALIAS,
                identity: IDENTITY,
                receiver: RECEIVER,
                group_tag: 0x7A,
                lanes: Lanes::new(&[
                    LaneStatus {
                        consumption: 8192,
                        window: 32768,
                    },
                    LaneStatus {
                        consumption: 256,
                        window: 4096,
                    },
                ])
                .unwrap(),
            })),
        ),
        (
            "nak",
            control(Control::Nak(Nak {
                alias: ALIAS,
                identity: IDENTITY,
                receiver: RECEIVER,
                range: NakRange {
                    lane: lane(1),
                    length: 1024,
                    start: 2048,
                },
            })),
        ),
        (
            "abort-ack",
            auth_control(AuthControl::Ack(AbortAck {
                alias: ALIAS,
                identity: IDENTITY,
                receiver: RECEIVER,
                guard_epoch: 3,
                lanes: Lanes::new(&[
                    AckLane {
                        delivered: 4096,
                        unresolved_end: 8192,
                    },
                    AckLane::default(),
                ])
                .unwrap(),
            })),
        ),
        (
            "guard-state",
            auth_control(AuthControl::State(GuardState {
                authority_id: 0x0A,
                guard_id: 0x0B,
                word: GuardWord::from_raw(9).unwrap(),
                lifetime_ms: 5000,
            })),
        ),
        (
            "guard-status",
            auth_control(AuthControl::Status(GuardStatus {
                authority_id: 0x0A,
                guard_id: 0x0B,
                receiver: RECEIVER,
                nonce: NONCE,
                word: GuardWord::from_raw(6).unwrap(),
            })),
        ),
        (
            "session-abort",
            auth_control(AuthControl::Abort(SessionAbort {
                alias: ALIAS,
                identity: IDENTITY,
                authority_id: 0x0A,
                guard_id: 0x0B,
                guard_epoch: 3,
                reason: 1,
            })),
        ),
        ("data-batch", batch),
        (
            "heartbeat",
            data_header(
                32,
                Flags::new(false, false, false, false, lane(2)),
                FrameType::Data,
                160,
                0,
            ),
        ),
        ("data-multicast", multicast),
    ]
}

fn frame<'a>(frames: &'a [(&'static str, Vec<u8>)], name: &str) -> &'a [u8] {
    &frames.iter().find(|(n, _)| *n == name).unwrap().1
}

fn sealed(seal: impl FnOnce(&mut [u8], usize) -> usize, frames: &[u8]) -> Vec<u8> {
    let mut buf = vec![0_u8; 512];
    buf[..frames.len()].copy_from_slice(frames);
    let len = seal(&mut buf, frames.len());
    buf.truncate(len);
    buf
}

/// H1: every single-bit change, every truncation and a one-byte extension
/// of `datagram` is refused by `refuses`.
fn every_change_is_refused(name: &str, datagram: &[u8], refuses: impl Fn(&[u8]) -> bool) {
    let mut copy = datagram.to_vec();
    for at in 0..copy.len() {
        for bit in 0..8 {
            copy[at] ^= 1 << bit;
            assert!(refuses(&copy), "{name}: bit {bit} of byte {at} accepted");
            copy[at] ^= 1 << bit;
        }
    }
    for len in 0..datagram.len() {
        assert!(
            refuses(&datagram[..len]),
            "{name}: truncation to {len} accepted"
        );
    }
    let mut longer = datagram.to_vec();
    longer.push(0);
    assert!(refuses(&longer), "{name}: extension accepted");
}

#[test]
fn the_production_codecs_encode_the_independent_inner_frames() {
    let all = vectors();
    for (name, bytes) in frames() {
        assert_eq!(bytes, get(&all, "frames", name), "frames {name}");
    }
}

#[test]
fn the_kdf_contexts_match_the_independent_vectors() {
    let all = vectors();
    let channel = parse("3-3.key", CHANNEL.as_bytes()).unwrap();
    let pairwise = parse("16909060-3.key", PAIRWISE.as_bytes()).unwrap();
    let (Material::Secret(channel_secret), Material::Secret(pairwise_secret)) =
        (&channel.material, &pairwise.material)
    else {
        panic!("symmetric files");
    };
    let contexts = [
        (
            "kdf-data-unicast",
            Context::Data {
                file_epoch: 3,
                party_epoch: 0,
                identity: IDENTITY,
                lane_count: 2,
                key_id: 3,
                profile_id: PROFILE_ID,
                unicast: Some((BOOT, NONCE)),
            },
            channel_secret,
        ),
        (
            "kdf-data-multicast",
            Context::Data {
                file_epoch: 3,
                party_epoch: 1,
                identity: IDENTITY,
                lane_count: 2,
                key_id: 3,
                profile_id: PROFILE_ID,
                unicast: None,
            },
            channel_secret,
        ),
        (
            "kdf-rcv",
            Context::Receiver {
                file_epoch: 3,
                party_epoch: 0,
                receiver_boot_id: BOOT,
                receiver_id: 0x42,
                identity: IDENTITY,
                key_id: 16_909_060,
                profile_id: PROFILE_ID,
            },
            pairwise_secret,
        ),
        (
            "kdf-setup",
            Context::Setup {
                file_epoch: 3,
                key_id: 3,
                profile_id: PROFILE_ID,
            },
            channel_secret,
        ),
        (
            "kdf-rsp",
            Context::RspSetup {
                file_epoch: 3,
                receiver_id: 0x42,
                key_id: 16_909_060,
                profile_id: PROFILE_ID,
            },
            pairwise_secret,
        ),
    ];
    for (name, context, secret) in contexts {
        let (info, len) = context.info_bytes();
        assert_eq!(&info[..len], get(&all, name, "info"), "{name} info");
        assert_eq!(
            context.derive(secret).as_slice(),
            get(&all, name, "okm"),
            "{name} okm"
        );
    }
    // The unicast salt is the challenge block of the transcript: the
    // receiver's boot id and nonce, as RSP_SETUP CHALLENGE carries them.
    let challenge = frame(&frames(), "rsp-challenge").to_vec();
    assert_eq!(get(&all, "kdf-data-unicast", "salt"), &challenge[56..88]);
    for name in ["kdf-data-multicast", "kdf-rcv", "kdf-setup", "kdf-rsp"] {
        assert!(get(&all, name, "salt").is_empty(), "{name} has no salt");
    }
}

/// The SETUP transcript (ADR-0086 sections 7 and 7a) and every MAC domain,
/// sealed by the production key paths from the canonical key files.
#[test]
fn the_mac_envelopes_and_the_setup_transcript_match_the_independent_vectors() {
    let all = vectors();
    let inner = frames();
    let channel = parse("3-3.key", CHANNEL.as_bytes()).unwrap();
    let pairwise = parse("16909060-3.key", PAIRWISE.as_bytes()).unwrap();
    let rsp_kind = ProofKind::RspSetup { receiver_id: 0x42 };
    let setup = Proof::new(ProofKind::Setup, ALIAS, Some(&channel), [&channel], 3).unwrap();
    let rsp = Proof::new(rsp_kind, ALIAS, Some(&pairwise), [&pairwise], 3).unwrap();
    // The receiver's side checks with keys that only verify.
    let setup_check = Proof::new(ProofKind::Setup, ALIAS, None, [&channel], 3).unwrap();
    let rsp_check = Proof::new(rsp_kind, ALIAS, None, [&pairwise], 3).unwrap();
    // In transcript order: ANNOUNCE, CHALLENGE, ANSWER, then SOLICIT.
    for (name, proof, check) in [
        ("setup-announce", &setup, &setup_check),
        ("rsp-challenge", &rsp, &rsp_check),
        ("setup-answer", &setup, &setup_check),
        ("rsp-solicit", &rsp, &rsp_check),
    ] {
        let datagram = sealed(|buf, n| proof.seal(buf, n).unwrap(), frame(&inner, name));
        let expected = get(&all, &format!("env-{name}"), "datagram");
        assert_eq!(datagram, expected, "env-{name}");
        let proved = check.verify(expected).unwrap();
        assert!(proved.current);
        assert_eq!(
            &expected[proved.opened.start..proved.opened.start + proved.opened.frames],
            frame(&inner, name)
        );
        every_change_is_refused(name, expected, |bytes| check.verify(bytes).is_err());
    }
    // The ANSWER echoes the CHALLENGE's boot id and nonce, which salt the
    // sender's DATA key below.
    assert_eq!(
        &frame(&inner, "setup-answer")[72..104],
        &frame(&inner, "rsp-challenge")[56..88]
    );

    let sender = Party::Sender {
        identity: IDENTITY,
        lane_count: 2,
        receiver_boot_id: BOOT,
        nonce: NONCE,
    };
    let receiver = Party::Receiver {
        identity: IDENTITY,
        receiver_boot_id: BOOT,
        receiver_id: 0x42,
    };
    for (party, file, names) in [
        (sender, &channel, &["data-batch", "heartbeat"][..]),
        (receiver, &pairwise, &["sm", "nak", "abort-ack"][..]),
    ] {
        let mut sealer = Sealer::new(file, party, ALIAS).unwrap();
        let mut verifier = Verifier::new([file], party, ALIAS).unwrap();
        for name in names {
            let datagram = sealed(|buf, n| sealer.seal(buf, n).unwrap(), frame(&inner, name));
            let expected = get(&all, &format!("env-{name}"), "datagram");
            assert_eq!(datagram, expected, "env-{name}");
            every_change_is_refused(name, expected, |bytes| verifier.check(bytes, NOW).is_err());
            let opened = verifier.open(expected, NOW).unwrap();
            assert_eq!(
                &expected[opened.start..opened.start + opened.frames],
                frame(&inner, name)
            );
        }
    }

    // Multicast: no salt, in-band epoch 1, envelope sequence 7.
    let Material::Secret(secret) = &channel.material else {
        panic!("a channel file has a secret");
    };
    let key = Context::Data {
        file_epoch: 3,
        party_epoch: 1,
        identity: IDENTITY,
        lane_count: 2,
        key_id: 3,
        profile_id: PROFILE_ID,
        unicast: None,
    }
    .derive(secret);
    let profile = HmacSha256::new(key.as_slice(), binding(Domain::Data, 1, ALIAS, 3), 0).unwrap();
    let datagram = sealed(
        |buf, n| profile.seal_with(buf, n, 7).unwrap(),
        frame(&inner, "data-multicast"),
    );
    let expected = get(&all, "env-data-multicast", "datagram");
    assert_eq!(datagram, expected, "env-data-multicast");
    every_change_is_refused("data-multicast", expected, |bytes| {
        profile.open_envelope(bytes).is_err()
    });
}

/// H1, frame boundaries and order: the two records of the batch swapped
/// keep every length and field check, and only the tag refuses them.
#[test]
fn reordered_records_of_a_batch_are_refused_by_the_tag() {
    let all = vectors();
    let channel = parse("3-3.key", CHANNEL.as_bytes()).unwrap();
    let party = Party::Sender {
        identity: IDENTITY,
        lane_count: 2,
        receiver_boot_id: BOOT,
        nonce: NONCE,
    };
    let verifier = Verifier::new([&channel], party, ALIAS).unwrap();
    let original = get(&all, "env-data-batch", "datagram");
    let frames = &original[HEADER_LEN..original.len() - TAG_LEN];
    let (first, second) = frames.split_at(64);
    let mut swapped = original[..HEADER_LEN].to_vec();
    swapped.extend_from_slice(second);
    swapped.extend_from_slice(first);
    swapped.extend_from_slice(&original[original.len() - TAG_LEN..]);
    assert_eq!(swapped.len(), original.len());
    assert_eq!(
        verifier.check(&swapped, NOW).map(|_| ()),
        Err(Refusal::Envelope(Rejection::Tag))
    );
    assert!(verifier.check(original, NOW).is_ok());
}

/// The signed controls: the authority's signer reproduces the independent
/// Ed25519 signatures, which are deterministic (RFC 8032).
#[test]
fn the_signed_controls_match_the_independent_vectors() {
    let all = vectors();
    let inner = frames();
    let signer = Ed25519Signer::from_seed(&AUTHORITY_SEED);
    let verifier = signer.verifier();
    assert_eq!(verifier.to_bytes().to_vec(), hex(AUTHORITY_PUBLIC));
    for (name, domain, alias, seq) in [
        ("guard-state", SignedDomain::Guard, Alias::default(), 0),
        ("guard-status", SignedDomain::Guard, Alias::default(), 1),
        ("session-abort", SignedDomain::SessionAbort, ALIAS, 2),
    ] {
        let binding = SignedBinding {
            domain,
            party_epoch: 0,
            session_id: alias.session_id,
            stream_id: alias.stream_id,
            key_id: 10,
        };
        let datagram = sealed(
            |buf, n| seal_signed(buf, n, &binding, seq, &signer).unwrap(),
            frame(&inner, name),
        );
        let expected = get(&all, &format!("sig-{name}"), "datagram");
        assert_eq!(datagram, expected, "sig-{name}");
        let opened = open_signed(expected, &binding, &verifier).unwrap();
        assert_eq!(
            &expected[opened.start..opened.start + opened.body],
            frame(&inner, name)
        );
        // One bit in each byte, at both ends of the byte.
        let mut copy = expected.to_vec();
        for at in 0..copy.len() {
            for bit in [0, 7] {
                copy[at] ^= 1 << bit;
                assert!(
                    open_signed(&copy, &binding, &verifier).is_err(),
                    "{name}: bit {bit} of byte {at} accepted"
                );
                copy[at] ^= 1 << bit;
            }
        }
    }
}

/// The Ed25519 negative vectors of ADR-0086 section 8: non-canonical and
/// small-order `A` are refused by the key loader, and a signature with
/// `S + L`, a non-canonical `R` or a small-order `R` by strict
/// verification.
#[test]
fn the_ed25519_negative_vectors_are_refused() {
    let all = vectors();
    let message = {
        let datagram = get(&all, "sig-session-abort", "datagram");
        let mut message = LABEL.to_vec();
        message.extend_from_slice(&datagram[..datagram.len() - 64]);
        message
    };
    let verifier = Ed25519Verifier::from_bytes(&hex(AUTHORITY_PUBLIC).try_into().unwrap()).unwrap();
    let genuine: [u8; 64] = get(&all, "sig-session-abort", "datagram")
        [get(&all, "sig-session-abort", "datagram").len() - 64..]
        .try_into()
        .unwrap();
    assert!(verifier.verify(&message, &genuine));
    for name in ["neg-s-plus-l", "neg-r-non-canonical", "neg-r-small-order"] {
        let signature: [u8; 64] = get(&all, name, "signature").try_into().unwrap();
        assert!(!verifier.verify(&message, &signature), "{name} verified");
    }
    let mut small = 0;
    for ((name, field), public) in &all {
        if field == "public" {
            let public: [u8; 32] = public.as_slice().try_into().unwrap();
            assert!(
                Ed25519Verifier::from_bytes(&public).is_err(),
                "{name} loaded"
            );
            small += usize::from(name.starts_with("neg-a-small-order-"));
        }
    }
    assert_eq!(small, 8, "the eight small-order points");
    let non_canonical: [u8; 32] = get(&all, "neg-a-non-canonical", "public")
        .try_into()
        .unwrap();
    assert_eq!(
        Ed25519Verifier::from_bytes(&non_canonical),
        Err(crate::authority::AuthorityKeyError::NonCanonical)
    );
}
