// SPDX-License-Identifier: Apache-2.0

// The vector helpers are not `#[test]` functions.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use super::*;
use crate::authority::Ed25519Signer;

/// The canonical files of `quantstratum-docs:
/// karyos/design/wire-key-files.md` section 2.7.
const CHANNEL: &str = "format=karyos-wire-key-v1\nkey_id=3\nfile_epoch=3\npurpose=channel\nprofile_id=1\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\nchannel_id=7\nstream_id=1001\n";
const PAIRWISE: &str = "format=karyos-wire-key-v1\nkey_id=16909060\nfile_epoch=3\npurpose=pairwise\nprofile_id=1\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\nreceiver_id=66\npublisher_id=5\n";
const SIGNING: &str = "format=karyos-wire-key-v1\nkey_id=10\nfile_epoch=1\npurpose=authority-signing\nprofile_id=4\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-04-30T00:00:00Z\nsecret=0909090909090909090909090909090909090909090909090909090909090909\nauthority_id=10\nguards=11,12\nabort=true\n";
const PUBLIC: &str = "format=karyos-wire-key-v1\nkey_id=10\nfile_epoch=1\npurpose=authority-public\nprofile_id=4\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-04-30T00:00:00Z\npublic=fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618\nauthority_id=10\nguards=11,12\nabort=true\n";

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

#[test]
fn the_canonical_files_parse() {
    let channel = parse("3-3.key", CHANNEL.as_bytes()).unwrap();
    assert_eq!(
        (channel.key_id, channel.file_epoch, channel.purpose),
        (3, 3, Purpose::Channel)
    );
    assert_eq!(
        channel.scope,
        Scope::Channel {
            channel_id: 7,
            stream_id: 1001
        }
    );
    // 2026-11-01 to 2027-01-30: exactly the 90-day bound.
    assert_eq!(
        channel.not_after - channel.not_before,
        MAX_SYMMETRIC_VALIDITY_S
    );
    assert_eq!(channel.not_before, 1_793_491_200);
    let pairwise = parse("16909060-3.key", PAIRWISE.as_bytes()).unwrap();
    assert_eq!(
        pairwise.scope,
        Scope::Pairwise {
            receiver_id: 66,
            publisher_id: 5
        }
    );
    let signing = parse("10-1.key", SIGNING.as_bytes()).unwrap();
    assert_eq!(
        signing.not_after - signing.not_before,
        MAX_AUTHORITY_VALIDITY_S
    );
    let Scope::Authority {
        guards,
        guard_count,
        abort,
        authority_id,
    } = signing.scope
    else {
        panic!()
    };
    assert_eq!(
        (authority_id, &guards[..guard_count], abort),
        (10, &[11, 12][..], true)
    );
    let public = parse("10-1.key", PUBLIC.as_bytes()).unwrap();
    // The example public key is the seed's (checked, not assumed).
    let Material::Public(verifier) = public.material else {
        panic!()
    };
    assert_eq!(verifier, Ed25519Signer::from_seed(&[9; 32]).verifier());
}

#[test]
fn every_negative_variant_is_refused() {
    let swapped = CHANNEL.replace("key_id=3\nfile_epoch=3\n", "file_epoch=3\nkey_id=3\n");
    let cases: Vec<(&str, String)> = vec![
        ("3-3.key", swapped),
        ("3-3.key", CHANNEL.replace("key_id=3", "key_id=03")),
        ("3-3.key", CHANNEL.replace('\n', "\r\n")),
        ("3-3.key", CHANNEL.replace("channel_id=7", "channel_id=7 ")),
        ("3-3.key", CHANNEL.replace("2027-01-30T00:00:00Z", "2027-01-30T00:00:01Z")),
        ("3-3.key", CHANNEL.trim_end_matches('\n').to_string()),
        ("3-3.key", CHANNEL.replace("2026-11-01", "2026-02-30")),
        ("3-3.key", CHANNEL.replace("key_id=3", "key_id=4294967296")),
        ("3-3.key", CHANNEL.replace("stream_id=1001", "stream_id=-0")),
        ("3-3.key", CHANNEL.replace("profile_id=1", "profile_id=4")),
        ("3-3.key", format!("{CHANNEL}extra=1\n")),
        ("03-3.key", CHANNEL.to_string()),
        ("3-4.key", CHANNEL.to_string()),
        ("10-1.key", PUBLIC.replace("profile_id=4", "profile_id=1")),
        ("10-1.key", SIGNING.replace("abort=true", "public=fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618\nabort=true")),
        ("10-1.key", SIGNING.replace("guards=11,12", "guards=12,11")),
        ("10-1.key", SIGNING.replace("guards=11,12", "guards=11,")),
        ("10-1.key", PUBLIC.replace("fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618", "0100000000000000000000000000000000000000000000000000000000000000")),
        ("10-1.key", PUBLIC.replace("fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")),
    ];
    for (index, (name, text)) in cases.iter().enumerate() {
        assert!(parse(name, text.as_bytes()).is_err(), "case {index}");
    }
    assert!(parse("3-3.key", &[b'a'; MAX_FILE_LEN + 1]).is_err());
}

/// K-1 to K-5 of the design's section 4, derived blind by an independent
/// session and identical to a second implementation.
#[test]
fn the_kdf_vectors_match() {
    let ikm: [u8; 32] = core::array::from_fn(|i| u8::try_from(i).unwrap());
    let identity = Identity {
        driver_id: [0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210],
        registration_id: 7,
        incarnation: 1,
    };
    let boot = [0xA1A2_A3A4_A5A6_A7A8, 0xB1B2_B3B4_B5B6_B7B8];
    let nonce = [0xC1C2_C3C4_C5C6_C7C8, 0xD1D2_D3D4_D5D6_D7D8];
    let data = |unicast| Context::Data {
        file_epoch: 3,
        party_epoch: 0,
        identity,
        lane_count: 2,
        key_id: 0x0102_0304,
        profile_id: 1,
        unicast,
    };
    let cases = [
        (
            data(Some((boot, nonce))),
            "6b6172796f732d776972652d617574682d763100646174610300000000efcdab89674523011032547698badcfe07000000000000000100000000000000020403020101",
            "7411775de7eb337a2d9274edab61b5f65ff00bc41b5e6493e7defaefb1f18cda",
        ),
        (
            data(None),
            "6b6172796f732d776972652d617574682d763100646174610300000000efcdab89674523011032547698badcfe07000000000000000100000000000000020403020101",
            "3e5ce432b51269f83459806dd5b0db979adecea5529e16f7218ea2099c1188b4",
        ),
        (
            Context::Receiver {
                file_epoch: 3,
                party_epoch: 0,
                receiver_boot_id: boot,
                receiver_id: 0x42,
                identity,
                key_id: 0x0102_0304,
                profile_id: 1,
            },
            "6b6172796f732d776972652d617574682d7631007263760300000000a8a7a6a5a4a3a2a1b8b7b6b5b4b3b2b14200000000000000efcdab89674523011032547698badcfe070000000000000001000000000000000403020101",
            "ae99dcbd8a0619070dc22892ff50952ec9ea299709384b5e5eedd4b1e5ca3f2a",
        ),
        (
            Context::Setup {
                file_epoch: 3,
                key_id: 0x0102_0304,
                profile_id: 1,
            },
            "6b6172796f732d776972652d617574682d7631007365747570030000000403020101",
            "dd3c964c62dac729472138934ceec819fac64f90df455ba607584d1c618321d1",
        ),
        (
            Context::RspSetup {
                file_epoch: 3,
                receiver_id: 0x42,
                key_id: 0x0102_0304,
                profile_id: 1,
            },
            "6b6172796f732d776972652d617574682d7631007273700300000042000000000000000403020101",
            "38209b70095cdcf6324481e37df4c3c066af29e71bf1fba8999f73b196a9155a",
        ),
    ];
    for (index, (context, info, okm)) in cases.iter().enumerate() {
        let (buf, len) = context.info_bytes();
        assert_eq!(&buf[..len], hex(info).as_slice(), "K-{}", index + 1);
        assert_eq!(
            &context.derive(&ikm)[..],
            hex(okm).as_slice(),
            "K-{}",
            index + 1
        );
    }
}

#[test]
fn timestamps_follow_the_calendar() {
    assert_eq!(timestamp(b"1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(timestamp(b"2024-02-29T23:59:59Z"), Some(1_709_251_199));
    assert_eq!(timestamp(b"2023-02-29T00:00:00Z"), None);
    assert_eq!(timestamp(b"2026-11-01T00:00:60Z"), None);
    assert_eq!(timestamp(b"2026-11-01 00:00:00Z"), None);
}
