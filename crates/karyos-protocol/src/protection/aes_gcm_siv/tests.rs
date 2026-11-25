// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::protection::{Protection, Rejection, Verdict};
use karyos_sys::alloc_count::count;
use proptest::prelude::*;
use std::collections::HashSet;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

fn words(w0: u64, w1: u64) -> [u8; 16] {
    let mut out = [0_u8; 16];
    out[..8].copy_from_slice(&w0.to_le_bytes());
    out[8..].copy_from_slice(&w1.to_le_bytes());
    out
}

// The inputs of the independent vectors. Every expected value below was
// computed by a separate Python script from the frozen encoding of
// ADR-0114, with the `cryptography` package (HKDF, AESGCMSIV) and the
// standard `hmac` module, and never from this implementation's output.
const IKM: [u8; 32] = {
    let mut out = [0_u8; 32];
    let mut at = 0;
    while at < 32 {
        out[at] = at as u8;
        at += 1;
    }
    out
};
const PAIRWISE_SECRET: [u8; 32] = {
    let mut out = [0_u8; 32];
    let mut at = 0;
    while at < 32 {
        out[at] = 0xa0 + at as u8;
        at += 1;
    }
    out
};
const KEY_EPOCH: u32 = 5;
const PAIRWISE_EPOCH: u32 = 9;

fn publication() -> PublicationIdentity {
    PublicationIdentity {
        driver_id: words(0x0102_0304_0506_0708, 0x1112_1314_1516_1718),
        registration_id: 7,
        incarnation: 3,
    }
}

fn receiver() -> ReceiverIdentity {
    ReceiverIdentity {
        receiver_boot_id: words(0x2122_2324_2526_2728, 0x3132_3334_3536_3738),
        receiver_id: 42,
    }
}

fn challenge() -> Salt {
    Salt::Challenge {
        receiver_boot_id: receiver().receiver_boot_id,
        nonce: words(0x4142_4344_4546_4748, 0x5152_5354_5556_5758),
    }
}

fn context(domain: Domain, party_epoch: u16, salted: bool) -> KeyContext {
    KeyContext {
        domain,
        key_epoch: KEY_EPOCH,
        party_epoch,
        session_id: -2,
        stream_id: 1001,
        publication: publication(),
        receiver: domain.is_receiver().then(receiver),
        salt: if salted { challenge() } else { Salt::Empty },
    }
}

fn pairwise(epoch: u32, secret: &[u8]) -> PairwiseKey {
    PairwiseKey::derive(secret, epoch, &receiver(), &publication()).unwrap()
}

fn profile(domain: Domain, party_epoch: u16, salted: bool) -> AesGcmSiv {
    let keys = if domain.is_receiver() {
        vec![pairwise(PAIRWISE_EPOCH, &PAIRWISE_SECRET)]
    } else {
        Vec::new()
    };
    AesGcmSiv::new(&IKM, context(domain, party_epoch, salted), &keys).unwrap()
}

fn data() -> AesGcmSiv {
    profile(Domain::Sender, 2, true)
}

/// Seals `frames` with sequence `seq` into a fresh buffer.
fn sealed(profile: &AesGcmSiv, frames: &[u8], seq: u64) -> Vec<u8> {
    let mut datagram = vec![0_u8; frames.len() + profile.overhead()];
    datagram[..frames.len()].copy_from_slice(frames);
    profile.set_next_seq(seq);
    let total = profile.seal_next(&mut datagram, frames.len()).unwrap();
    assert_eq!(total, datagram.len());
    datagram
}

/// The state a rejection must leave unchanged.
fn state(profile: &AesGcmSiv) -> (u64, u64, ReplayWindow) {
    (profile.next_seq(), profile.sealed_bytes(), profile.window())
}

/// RFC 8452 Appendix C.2 (AEAD_AES_256_GCM_SIV): key, nonce, associated
/// data, plaintext, and ciphertext with the tag appended. Each was checked
/// against Python `cryptography`'s AESGCMSIV as well.
const RFC_8452: [(&str, &str, &str, &str, &str); 9] = [
    (
        "0100000000000000000000000000000000000000000000000000000000000000",
        "030000000000000000000000",
        "",
        "",
        "07f5f4169bbf55a8400cd47ea6fd400f",
    ),
    (
        "0100000000000000000000000000000000000000000000000000000000000000",
        "030000000000000000000000",
        "",
        "01000000000000000000000000000000",
        "85a01b63025ba19b7fd3ddfc033b3e76c9eac6fa700942702e90862383c6c366",
    ),
    (
        "0100000000000000000000000000000000000000000000000000000000000000",
        "030000000000000000000000",
        "01",
        "020000000000000000000000",
        "163d6f9cc1b346cd453a2e4cc1a4a19ae800941ccdc57cc8413c277f",
    ),
    (
        "0100000000000000000000000000000000000000000000000000000000000000",
        "030000000000000000000000",
        "01",
        "02000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000005000000000000000000000000000000",
        "67fd45e126bfb9a79930c43aad2d36967d3f0e4d217c1e551f59727870beefc98cb933a8fce9de887b1e40799988db1fc3f91880ed405b2dd298318858467c895bde0285037c5de81e5b570a049b62a0",
    ),
    (
        "0100000000000000000000000000000000000000000000000000000000000000",
        "030000000000000000000000",
        "010000000000000000000000000000000200",
        "0300000000000000000000000000000004000000",
        "43dd0163cdb48f9fe3212bf61b201976067f342bb879ad976d8242acc188ab59cabfe307",
    ),
    (
        "e66021d5eb8e4f4066d4adb9c33560e4f46e44bb3da0015c94f7088736864200",
        "e0eaf5284d884a0e77d31646",
        "",
        "",
        "169fbb2fbf389a995f6390af22228a62",
    ),
    (
        "9745b3d1ae06556fb6aa7890bebc18fe6b3db4da3d57aa94842b9803a96e07fb",
        "6de71860f762ebfbd08284e4",
        "f37de21c7ff901cfe8a69615a93fdf7a98cad481796245709f",
        "21702de0de18baa9c9596291b08466",
        "793576dfa5c0f88729a7ed3c2f1bffb3080d28f6ebb5d3648ce97bd5ba67fd",
    ),
    (
        "b18853f68d833640e42a3c02c25b64869e146d7b233987bddfc240871d7576f7",
        "028ec6eb5ea7e298342a94d4",
        "9c2159058b1f0fe91433a5bdc20e214eab7fecef4454a10ef0657df21ac7",
        "b202b370ef9768ec6561c4fe6b7e7296fa85",
        "857e16a64915a787637687db4a9519635cdd454fc2a154fea91f8363a39fec7d0a49",
    ),
    (
        "3c535de192eaed3822a2fbbe2ca9dfc88255e14a661b8aa82cc54236093bbc23",
        "688089e55540db1872504e1c",
        "734320ccc9d9bbbb19cb81b2af4ecbc3e72834321f7aa0f70b7282b4f33df23f167541",
        "ced532ce4159b035277d4dfbb7db62968b13cd4eec",
        "626660c26ea6612fb17ad91e8e767639edd6c9faee9d6c7029675b89eaf4ba1ded1a286594",
    ),
];

#[test]
fn the_rfc_8452_vectors_pass_through_the_detached_in_place_api() {
    for (key, nonce, aad, plaintext, expected) in RFC_8452 {
        let (key, nonce, aad, plaintext, expected) = (
            hex(key),
            hex(nonce),
            hex(aad),
            hex(plaintext),
            hex(expected),
        );
        let aead = Aes256GcmSiv::new(&Key::<Aes256GcmSiv>::try_from(key.as_slice()).unwrap());
        let nonce = Nonce::try_from(nonce.as_slice()).unwrap();
        let mut buffer = plaintext.clone();
        let tag = aead
            .encrypt_inout_detached(&nonce, &aad, InOutBuf::from(buffer.as_mut_slice()))
            .unwrap();
        let mut got = buffer.clone();
        got.extend_from_slice(tag.as_slice());
        assert_eq!(got, expected);
        aead.decrypt_inout_detached(&nonce, &aad, InOutBuf::from(buffer.as_mut_slice()), &tag)
            .unwrap();
        assert_eq!(buffer, plaintext);
        let mut wrong = tag;
        wrong[0] ^= 1;
        let mut ciphertext = expected[..plaintext.len()].to_vec();
        assert!(
            aead.decrypt_inout_detached(
                &nonce,
                &aad,
                InOutBuf::from(ciphertext.as_mut_slice()),
                &wrong
            )
            .is_err()
        );
        assert_eq!(
            ciphertext,
            &expected[..plaintext.len()],
            "restored in place"
        );
    }
}

/// `(name, context, info, key)` of the Python script.
fn kdf_vectors() -> [(&'static str, KeyContext, &'static str, &'static str); 7] {
    [
        (
            "snd unicast",
            context(Domain::Sender, 2, true),
            "6b6172796f732d776972652d656e632d76303100736e640000000000050000000200080706050403020118171615141312110700000000000000030000000000000010",
            "b60cc328bf73eddc5244d8551b65feea9f229c9a1dc628574eb654e82648c540",
        ),
        (
            "snd multicast",
            context(Domain::Sender, 2, false),
            "6b6172796f732d776972652d656e632d76303100736e640000000000050000000200080706050403020118171615141312110700000000000000030000000000000010",
            "47b2554f0b0099b7cf6d2e3d5945af8bfa302694cf328f04ff7c7a34c329d239",
        ),
        (
            "snd next epoch",
            context(Domain::Sender, 3, true),
            "6b6172796f732d776972652d656e632d76303100736e640000000000050000000300080706050403020118171615141312110700000000000000030000000000000010",
            "af6a165458206f3a4341b517b8d6061118943cc431117227abb371e29ebf6718",
        ),
        (
            "rcv unicast",
            context(Domain::Receiver, 2, true),
            "6b6172796f732d776972652d656e632d763031007263760000000000050000000200282726252423222138373635343332312a00000000000000080706050403020118171615141312110700000000000000030000000000000010",
            "d60aad6d6ab9a9a987481b2996c6bfacc352a41f84947d0f885218740fc6721b",
        ),
        (
            "rcv multicast",
            context(Domain::Receiver, 2, false),
            "6b6172796f732d776972652d656e632d763031007263760000000000050000000200282726252423222138373635343332312a00000000000000080706050403020118171615141312110700000000000000030000000000000010",
            "28db5971c8784b6272aff4f9b22fda7c2f0500ba92ff86b6b6d12b04be9ef720",
        ),
        (
            "setup",
            context(Domain::Setup, 0, false),
            "6b6172796f732d776972652d656e632d763031007365747570000000050000000000080706050403020118171615141312110700000000000000030000000000000010",
            "fb74939e2559089db4a35c1549b9f5334d8f3a56890e9cc656d181344c42a557",
        ),
        (
            "rsp",
            context(Domain::RspSetup, 0, false),
            "6b6172796f732d776972652d656e632d763031007273700000000000050000000000282726252423222138373635343332312a00000000000000080706050403020118171615141312110700000000000000030000000000000010",
            "e5ee78e3418854c5d7c1e7002e00e519bea5f1fad5477fb404764d45839bf2b1",
        ),
    ]
}

#[test]
fn the_kdf_of_every_domain_matches_the_independent_vectors() {
    for (name, context, info, key) in kdf_vectors() {
        let (got, len) = context.info();
        assert_eq!(got[..len].to_vec(), hex(info), "{name} info");
        assert_eq!(context.derive(&IKM).to_vec(), hex(key), "{name} key");
    }
    let info = pairwise_info(PAIRWISE_EPOCH, &receiver(), &publication());
    assert_eq!(
        info.to_vec(),
        hex(
            "6b6172796f732d776972652d656e632d76303100706175746800000009000000282726252423222138373635343332312a00000000000000080706050403020118171615141312110700000000000000030000000000000010"
        )
    );
    assert_eq!(
        derive_pairwise(
            &PAIRWISE_SECRET,
            PAIRWISE_EPOCH,
            &receiver(),
            &publication()
        )
        .to_vec(),
        hex("6fb8900d3b80b16283414c0752992f3b56480163473ced4879e361ec4739118e")
    );
}

#[test]
fn the_empty_salt_is_the_rfc_5869_default() {
    for (name, context, _, _) in kdf_vectors() {
        let (info, len) = context.info();
        let salt = context.salt.bytes();
        let mut expected = [0_u8; 32];
        ::hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), &IKM)
            .expand(&info[..len], &mut expected)
            .unwrap();
        assert_eq!(*context.derive(&IKM), expected, "{name}");
        // The empty salt is the RFC 5869 default of 32 zero bytes.
        if context.salt == Salt::Empty {
            let mut unsalted = [0_u8; 32];
            ::hkdf::Hkdf::<sha2::Sha256>::new(None, &IKM)
                .expand(&info[..len], &mut unsalted)
                .unwrap();
            assert_eq!(unsalted, expected, "{name}");
        }
    }
}

/// `(name, profile, seq, frames, datagram)` of the Python script.
fn envelope_vectors() -> Vec<(&'static str, AesGcmSiv, u64, Vec<u8>, &'static str)> {
    let frames = |len: usize, mul: usize, add: usize| -> Vec<u8> {
        (0..len).map(|i| ((i * mul + add) % 256) as u8).collect()
    };
    vec![
        (
            "snd",
            profile(Domain::Sender, 2, true),
            0x0102,
            frames(40, 7, 3),
            "7c00000001002100101001000500000002000000feffffffe903000002010000000000000807060504030201181716151413121107000000000000000300000000000000c98d18f8ed4863521c141569731861f833b5ff7aee42fc345d711e5e3ed42d3c3130d8cc6ba39975ae331da1d84bc6679fba457b9fdefe5e",
        ),
        (
            "snd empty",
            profile(Domain::Sender, 2, false),
            0,
            Vec::new(),
            "5400000001002100101001000500000002000000feffffffe9030000000000000000000008070605040302011817161514131211070000000000000003000000000000003f858a94feceb2f06bac7566d3fec28a",
        ),
        (
            "rsp",
            profile(Domain::RspSetup, 0, false),
            3,
            frames(56, 13, 1),
            "a000000001002100101006000500000000000000feffffffe90300000300000000000000282726252423222138373635343332312a00000000000000000000000000000057d76ed6a59c65d625ba4afc331e4d7d9498e0514c31482d295ba104ca89da1d987d87558320b2a99651d0bc392e60ece70c4e67b82aa791454fb4e7a1b3f25421d6e285a56c966fcfaa09c72f3788a87193f596a5b5da2090eff584",
        ),
        (
            "rcv",
            profile(Domain::Receiver, 2, true),
            77,
            frames(32, 5, 9),
            "8800000001002100101004000500000002000000feffffffe90300004d00000000000000282726252423222138373635343332312a000000000000000000000000000000feadd707cb4e3964369a66ff2aa03dedfcb65c2b573515d5ebd3a3e2f35fee1ef3f5089d772bf2fa00caf4b799320d6e27a45d1b25cee789101f35e8c8cfdb7130258a0f",
        ),
        (
            "setup",
            profile(Domain::Setup, 0, false),
            0,
            frames(72, 11, 0),
            "9c00000001002100101005000500000000000000feffffffe903000000000000000000000807060504030201181716151413121107000000000000000300000000000000b829c66ed175856f10685f070ac7faa9e5b0e3ef33fd632eb5a808d1ab26278f16d684223110789782f803dd0df415b2e3aa2c6a610ed17ce2d919d6e0a76237798b6896b889e46fac82991c2ae2cdbf8401122891c52e34",
        ),
    ]
}

#[test]
fn the_envelope_vectors_seal_byte_for_byte_and_open() {
    for (name, profile, seq, frames, expected) in envelope_vectors() {
        let expected = hex(expected);
        assert_eq!(sealed(&profile, &frames, seq), expected, "{name} seal");
        let mut datagram = expected.clone();
        let opened = profile.open_in_place(&mut datagram).unwrap();
        assert_eq!(opened.start, HEADER_LEN, "{name}");
        assert_eq!(opened.frames, frames.len(), "{name}");
        assert_eq!(opened.seq, seq, "{name}");
        assert_eq!(
            opened.pairwise_epoch,
            profile
                .context()
                .domain
                .is_receiver()
                .then_some(PAIRWISE_EPOCH),
            "{name}"
        );
        assert_eq!(
            &datagram[HEADER_LEN..HEADER_LEN + frames.len()],
            &frames[..]
        );
        let mut out = [0_u8; MAX_PLAINTEXT];
        assert_eq!(profile.open_into(&expected, &mut out), Ok(opened), "{name}");
        assert_eq!(&out[..frames.len()], &frames[..], "{name}");
        assert_eq!(
            profile.open(&expected),
            Verdict::Accept {
                start: HEADER_LEN,
                frames: frames.len()
            }
        );
    }
}

#[test]
fn the_nonce_is_the_domain_then_three_zeros_then_the_sequence() {
    assert_eq!(
        AesGcmSiv::nonce(Domain::RspSetup, 0x0102_0304_0506_0708),
        [6, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1]
    );
}

#[test]
fn every_seal_takes_a_new_sequence_and_the_cap_refuses_without_writing() {
    let profile = data();
    let mut seen = HashSet::new();
    let mut datagram = [0_u8; 128];
    for _ in 0..64 {
        let total = profile.seal_next(&mut datagram, 8).unwrap();
        let seq = u64::from_le_bytes(datagram[28..36].try_into().unwrap());
        assert!(seen.insert(seq));
        assert_eq!(total, 8 + ENVELOPE_LEN);
    }
    assert_eq!(seen.len(), 64);
    assert_eq!(profile.next_seq(), 64);

    profile.set_next_seq(DATA_SEQ_CAP - 1);
    assert!(profile.seal_next(&mut datagram, 8).is_ok());
    assert_eq!(
        u64::from_le_bytes(datagram[28..36].try_into().unwrap()),
        DATA_SEQ_CAP - 1
    );
    let before = datagram;
    let bytes = profile.sealed_bytes();
    assert_eq!(
        profile.seal_next(&mut datagram, 8),
        Err(EncSealError::Exhausted)
    );
    assert_eq!(
        profile.seal(&mut datagram, 8).map_err(|e| e.needed),
        Err(usize::MAX)
    );
    assert_eq!(datagram, before, "an exhausted seal writes nothing");
    assert_eq!(profile.next_seq(), DATA_SEQ_CAP, "the counter never wraps");
    assert_eq!(profile.sealed_bytes(), bytes);

    let setup = profile_of(Domain::Setup);
    setup.set_next_seq(BOOTSTRAP_SEQ_CAP);
    assert_eq!(
        setup.seal_next(&mut datagram, 8),
        Err(EncSealError::Exhausted)
    );
}

fn profile_of(domain: Domain) -> AesGcmSiv {
    match domain {
        Domain::Sender | Domain::Receiver => profile(domain, 2, true),
        Domain::Setup | Domain::RspSetup => profile(domain, 0, false),
    }
}

#[test]
fn the_byte_budget_refuses_without_writing() {
    let profile = data();
    profile
        .sealed_bytes
        .store(DATA_BYTE_BUDGET - 50, Ordering::Relaxed);
    let mut datagram = [0_u8; 128];
    assert_eq!(
        profile.seal_next(&mut datagram, 8),
        Err(EncSealError::BytesExhausted)
    );
    assert_eq!(datagram, [0_u8; 128]);
    assert_eq!(profile.sealed_bytes(), DATA_BYTE_BUDGET - 50);
}

#[test]
fn an_epoch_roll_gives_a_new_key_with_its_own_counter() {
    let current = profile(Domain::Sender, 2, true);
    let next = profile(Domain::Sender, 3, true);
    assert_ne!(
        *current.context().derive(&IKM),
        *next.context().derive(&IKM)
    );
    let a = sealed(&current, &[1; 16], 0);
    let b = sealed(&next, &[1; 16], 0);
    assert_eq!(a[28..36], b[28..36], "both counters start at 0");
    assert_ne!(a[HEADER_LEN..], b[HEADER_LEN..]);
    // Neither key opens the other's datagram.
    let mut cross = a.clone();
    cross[16..18].copy_from_slice(&3_u16.to_le_bytes());
    assert_eq!(next.open_in_place(&mut cross), Err(EncRejection::Tag));
    assert_eq!(
        current.open_in_place(&mut b.clone()),
        Err(EncRejection::Epoch)
    );
}

#[test]
fn concurrent_seals_never_share_a_sequence() {
    let profile = data();
    let seqs = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|_| {
                scope.spawn(|| {
                    let mut datagram = [0_u8; 128];
                    (0..500)
                        .map(|_| {
                            profile.seal_next(&mut datagram, 4).unwrap();
                            u64::from_le_bytes(datagram[28..36].try_into().unwrap())
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    let unique: HashSet<_> = seqs.iter().copied().collect();
    assert_eq!(unique.len(), 2000);
    assert_eq!(profile.next_seq(), 2000);
}

#[test]
fn a_tampered_tag_header_or_ciphertext_is_rejected_with_state_unchanged() {
    for domain in [
        Domain::Sender,
        Domain::Receiver,
        Domain::Setup,
        Domain::RspSetup,
    ] {
        let profile = profile_of(domain);
        let good = sealed(&profile, &[0x5a; 48], 10);
        profile.mark(3).unwrap();
        let before = state(&profile);
        for at in 0..good.len() {
            let mut datagram = good.clone();
            datagram[at] ^= 0x01;
            let tampered = datagram.clone();
            assert!(profile.open_in_place(&mut datagram).is_err(), "byte {at}");
            assert_eq!(datagram, tampered, "byte {at}: received bytes kept");
            let mut out = [0xee_u8; MAX_PLAINTEXT];
            assert!(profile.open_into(&tampered, &mut out).is_err());
            assert!(out[..48].iter().all(|b| *b == 0 || *b == 0xee));
            assert!(matches!(profile.open(&tampered), Verdict::Reject(_)));
            assert_eq!(state(&profile), before, "byte {at}");
        }
        // Covered bytes the header checks do not see reject on the tag.
        for at in (28..36).chain(HEADER_LEN..good.len()) {
            let mut datagram = good.clone();
            datagram[at] ^= 0x80;
            let reason = profile.open_in_place(&mut datagram).unwrap_err();
            assert!(
                matches!(reason, EncRejection::Tag | EncRejection::SequenceCap),
                "byte {at}: {reason:?}"
            );
        }
    }
}

#[test]
fn a_failed_open_into_releases_no_plaintext() {
    let profile = data();
    let mut good = sealed(&profile, &[0x11; 64], 1);
    let last = good.len() - 1;
    good[last] ^= 1;
    let mut out = [0_u8; MAX_PLAINTEXT];
    assert_eq!(profile.open_into(&good, &mut out), Err(EncRejection::Tag));
    assert!(out.iter().all(|b| *b == 0));
}

#[test]
fn every_field_mismatch_fails_closed_with_its_reason() {
    let profile = data();
    let good = sealed(&profile, &[9_u8; 24], 77);
    let cases: [(usize, u8, EncRejection); 16] = [
        (0, 1, EncRejection::Length),
        (4, 1, EncRejection::Version),
        (5, 1, EncRejection::Flags),
        (6, 0x21 ^ 0x22, EncRejection::FrameType),
        (8, 16 ^ 17, EncRejection::Profile),
        (8, 16 ^ 1, EncRejection::Profile),
        (9, 1, EncRejection::TagLength),
        (10, 1 ^ 4, EncRejection::Domain),
        (10, 1 ^ 2, EncRejection::Domain),
        (11, 1, EncRejection::Reserved),
        (12, 1, EncRejection::Epoch),
        (16, 1, EncRejection::Epoch),
        (18, 1, EncRejection::Reserved),
        (20, 1, EncRejection::Binding),
        (24, 1, EncRejection::Binding),
        (36, 1, EncRejection::Party),
    ];
    for (at, flip, reason) in cases {
        let mut datagram = good.clone();
        datagram[at] ^= flip;
        assert_eq!(
            profile.open_in_place(&mut datagram),
            Err(reason),
            "byte {at}"
        );
        assert_eq!(
            profile.open(&datagram),
            Verdict::Reject(Rejection::from(reason))
        );
    }
    // The receiver block padding is checked.
    let rcv = profile_of(Domain::Receiver);
    let mut datagram = sealed(&rcv, &[1; 8], 0);
    datagram[HEADER_LEN - 1] ^= 1;
    assert_eq!(
        rcv.open_in_place(&mut datagram),
        Err(EncRejection::Reserved)
    );
}

#[test]
fn the_sequence_cap_is_checked_before_the_open() {
    let profile = profile_of(Domain::Setup);
    let mut datagram = sealed(&profile, &[1; 8], 5);
    datagram[28..36].copy_from_slice(&BOOTSTRAP_SEQ_CAP.to_le_bytes());
    assert_eq!(
        profile.open_in_place(&mut datagram),
        Err(EncRejection::SequenceCap)
    );
    assert_eq!(
        profile.mark(BOOTSTRAP_SEQ_CAP),
        Err(EncRejection::SequenceCap)
    );
    let data = data();
    let mut datagram = sealed(&data, &[1; 8], 5);
    datagram[28..36].copy_from_slice(&DATA_SEQ_CAP.to_le_bytes());
    assert_eq!(
        data.open_in_place(&mut datagram),
        Err(EncRejection::SequenceCap)
    );
}

#[test]
fn downgrades_are_told_apart() {
    let profile = data();
    let good = sealed(&profile, &[9_u8; 24], 77);
    let with_type = |code: u16| {
        let mut datagram = good.clone();
        datagram[6..8].copy_from_slice(&code.to_le_bytes());
        datagram
    };
    assert_eq!(
        profile.open_in_place(&mut with_type(0x01)),
        Err(EncRejection::BareFrame)
    );
    assert_eq!(
        profile.open_in_place(&mut with_type(0x03)),
        Err(EncRejection::BareFrame)
    );
    assert_eq!(
        profile.open_in_place(&mut with_type(0x20)),
        Err(EncRejection::WrongClass)
    );
    assert_eq!(
        profile.open_in_place(&mut with_type(0x05)),
        Err(EncRejection::PlaintextSetup)
    );
    assert_eq!(
        profile.open_in_place(&mut with_type(0x07)),
        Err(EncRejection::PlaintextSetup)
    );
    assert_eq!(
        profile.open_in_place(&mut with_type(0x99)),
        Err(EncRejection::FrameType)
    );
    // A bare frame shorter than the envelope is still told apart.
    let mut bare = [0_u8; 32];
    bare[6] = 0x05;
    assert_eq!(
        profile.open_in_place(&mut bare),
        Err(EncRejection::PlaintextSetup)
    );
    let mut mixed = good.clone();
    mixed.extend_from_slice(&[0_u8; 32]);
    assert_eq!(
        profile.open_in_place(&mut mixed),
        Err(EncRejection::MixedClass)
    );
    let mut wrong_profile = good.clone();
    wrong_profile[8] = RESERVED_CHACHA20_POLY1305;
    assert_eq!(
        profile.open_in_place(&mut wrong_profile),
        Err(EncRejection::Profile)
    );
    assert_eq!(
        profile.open_in_place(&mut good[..good.len() - 1].to_vec()),
        Err(EncRejection::Length)
    );
    assert_eq!(
        profile.open_in_place(&mut good[..ENVELOPE_LEN - 1].to_vec()),
        Err(EncRejection::Short)
    );
    assert_eq!(
        profile.open_in_place(&mut [0_u8; 4]),
        Err(EncRejection::Short)
    );
}

#[test]
fn replays_are_refused_after_the_mark() {
    let profile = data();
    let good = sealed(&profile, &[3_u8; 16], 2000);
    let opened = profile.open_in_place(&mut good.clone()).unwrap();
    // Opening alone marks nothing.
    assert!(profile.open_in_place(&mut good.clone()).is_ok());
    assert_eq!(profile.mark(opened.seq), Ok(()));
    assert_eq!(profile.mark(opened.seq), Err(EncRejection::Duplicate));
    let before = state(&profile);
    assert_eq!(
        profile.open_in_place(&mut good.clone()),
        Err(EncRejection::Duplicate)
    );
    let old = sealed(&profile, &[3_u8; 16], 2000 - 1024);
    assert_eq!(
        profile.open_in_place(&mut old.clone()),
        Err(EncRejection::TooOld)
    );
    let mut before_seal = before;
    before_seal.0 = profile.next_seq();
    before_seal.1 = profile.sealed_bytes();
    assert_eq!(state(&profile), before_seal, "window unchanged");
}

#[test]
fn the_plaintext_cap_bounds_seal_and_open() {
    let profile = data();
    let mut datagram = vec![0_u8; 2048];
    assert_eq!(
        profile.seal_next(&mut datagram, MAX_PLAINTEXT),
        Ok(MAX_DATAGRAM)
    );
    assert_eq!(
        profile.seal_next(&mut datagram, MAX_PLAINTEXT + 1),
        Err(EncSealError::TooLong {
            plaintext: MAX_PLAINTEXT + 1
        })
    );
    let rcv = profile_of(Domain::Receiver);
    assert_eq!(
        rcv.seal_next(&mut datagram, MAX_PLAINTEXT - TRAILER_LEN),
        Ok(MAX_DATAGRAM)
    );
    assert_eq!(
        rcv.seal_next(&mut datagram, MAX_PLAINTEXT - TRAILER_LEN + 1),
        Err(EncSealError::TooLong {
            plaintext: MAX_PLAINTEXT + 1
        })
    );
    let mut long = sealed(&profile, &[0; 8], 1);
    long.resize(MAX_DATAGRAM + 1, 0);
    let length = i32::try_from(long.len()).unwrap();
    long[..4].copy_from_slice(&length.to_le_bytes());
    assert_eq!(profile.open_in_place(&mut long), Err(EncRejection::TooLong));
    assert_eq!(
        profile.seal_next(&mut [0_u8; 40], 8),
        Err(EncSealError::Buffer(SealError {
            needed: 8 + ENVELOPE_LEN,
            available: 40
        }))
    );
}

/// Seals a receiver-domain datagram whose outer tag is valid but whose
/// plaintext is `plaintext` as given, trailer or not.
fn outer_only(profile: &AesGcmSiv, plaintext: &[u8], seq: u64) -> Vec<u8> {
    let total = plaintext.len() + ENVELOPE_LEN;
    let header = profile.header(i32::try_from(total).unwrap(), seq);
    let key = profile.context().derive(&IKM);
    let aead = Aes256GcmSiv::new(&Key::<Aes256GcmSiv>::from(*key));
    let mut body = plaintext.to_vec();
    let tag = aead
        .encrypt_inout_detached(
            &Nonce::from(AesGcmSiv::nonce(profile.context().domain, seq)),
            &associated_data(&header),
            InOutBuf::from(body.as_mut_slice()),
        )
        .unwrap();
    let mut out = header.to_vec();
    out.extend_from_slice(&body);
    out.extend_from_slice(tag.as_slice());
    out
}

#[test]
fn the_pairwise_trailer_missing_wrong_or_right() {
    for domain in [Domain::Receiver, Domain::RspSetup] {
        let profile = profile_of(domain);
        let before = state(&profile);
        // Missing: a valid outer tag over frames with no trailer.
        let missing = outer_only(&profile, &[7_u8; 40], 1);
        let mut datagram = missing.clone();
        assert_eq!(
            profile.open_in_place(&mut datagram),
            Err(EncRejection::Pairwise)
        );
        assert_eq!(datagram, missing, "ciphertext restored");
        // Too short to hold a trailer at all.
        let tiny = outer_only(&profile, &[7_u8; 4], 2);
        assert_eq!(
            profile.open_in_place(&mut tiny.clone()),
            Err(EncRejection::Pairwise)
        );
        // Wrong: sealed by a group holder with another pairwise secret.
        let forger = AesGcmSiv::new(
            &IKM,
            *profile.context(),
            &[pairwise(PAIRWISE_EPOCH, &[0x55; 32])],
        )
        .unwrap();
        let forged = sealed(&forger, &[7_u8; 40], 3);
        let mut datagram = forged.clone();
        assert_eq!(
            profile.open_in_place(&mut datagram),
            Err(EncRejection::Pairwise)
        );
        assert_eq!(datagram, forged, "ciphertext restored");
        let mut out = [0_u8; MAX_PLAINTEXT];
        assert_eq!(
            profile.open_into(&forged, &mut out),
            Err(EncRejection::Pairwise)
        );
        assert!(out.iter().all(|b| *b == 0));
        // Wrong epoch: a pairwise epoch the verifier does not hold.
        let other_epoch = AesGcmSiv::new(
            &IKM,
            *profile.context(),
            &[pairwise(PAIRWISE_EPOCH + 1, &PAIRWISE_SECRET)],
        )
        .unwrap();
        let stale = sealed(&other_epoch, &[7_u8; 40], 4);
        assert_eq!(
            profile.open_in_place(&mut stale.clone()),
            Err(EncRejection::Pairwise)
        );
        assert_eq!(state(&profile), before, "nothing changed");
        // Right.
        let right = sealed(&profile, &[7_u8; 40], 5);
        let opened = profile.open_in_place(&mut right.clone()).unwrap();
        assert_eq!(opened.frames, 40);
        assert_eq!(opened.pairwise_epoch, Some(PAIRWISE_EPOCH));
        // A verifier that holds both epochs accepts either.
        let both = AesGcmSiv::new(
            &IKM,
            *profile.context(),
            &[
                pairwise(PAIRWISE_EPOCH, &PAIRWISE_SECRET),
                pairwise(PAIRWISE_EPOCH + 1, &PAIRWISE_SECRET),
            ],
        )
        .unwrap();
        assert_eq!(
            both.open_in_place(&mut stale.clone())
                .map(|o| o.pairwise_epoch),
            Ok(Some(PAIRWISE_EPOCH + 1))
        );
    }
}

#[test]
fn invalid_contexts_are_refused() {
    let ok = context(Domain::Sender, 2, true);
    let keys = [pairwise(PAIRWISE_EPOCH, &PAIRWISE_SECRET)];
    let new =
        |context: KeyContext, keys: &[PairwiseKey]| AesGcmSiv::new(&IKM, context, keys).map(|_| ());
    assert_eq!(
        AesGcmSiv::new(&[], ok, &[]).map(|_| ()),
        Err(ContextError::EmptyKey)
    );
    assert_eq!(
        new(KeyContext { key_epoch: 0, ..ok }, &[]),
        Err(ContextError::KeyEpoch)
    );
    assert_eq!(
        new(context(Domain::Setup, 1, false), &[]),
        Err(ContextError::PartyEpoch)
    );
    assert_eq!(
        new(context(Domain::Setup, 0, true), &[]),
        Err(ContextError::Salt)
    );
    assert_eq!(
        new(
            KeyContext {
                receiver: Some(receiver()),
                ..ok
            },
            &[]
        ),
        Err(ContextError::Receiver)
    );
    assert_eq!(
        new(
            KeyContext {
                receiver: None,
                ..context(Domain::Receiver, 2, true)
            },
            &keys
        ),
        Err(ContextError::Receiver)
    );
    let mut zero = ok;
    zero.publication.driver_id = [0; 16];
    assert_eq!(new(zero, &[]), Err(ContextError::Identity));
    assert_eq!(new(ok, &keys), Err(ContextError::Pairwise));
    assert_eq!(
        new(context(Domain::Receiver, 2, true), &[]),
        Err(ContextError::Pairwise)
    );
    let three = [keys[0].clone(), keys[0].clone(), keys[0].clone()];
    assert_eq!(
        new(context(Domain::Receiver, 2, true), &three),
        Err(ContextError::PairwiseSlots)
    );
    assert_eq!(
        PairwiseKey::derive(&[], 1, &receiver(), &publication()).map(|_| ()),
        Err(ContextError::EmptyKey)
    );
}

#[test]
fn seal_and_open_allocate_nothing() {
    let profile = profile_of(Domain::Receiver);
    let mut datagram = [0_u8; MAX_DATAGRAM];
    let mut out = [0_u8; MAX_PLAINTEXT];
    let (_, seen) = count(|| {
        let total = profile.seal(&mut datagram, 1200).unwrap_or(0);
        let copy = datagram;
        let _ = profile.open(&copy[..total]);
        let _ = profile.open_into(&copy[..total], &mut out);
        let opened = profile.open_in_place(&mut datagram[..total]);
        if let Ok(opened) = opened {
            let _ = profile.mark(opened.seq);
        }
    });
    assert_eq!(seen, 0);
}

#[test]
fn the_trait_reports_the_envelope_and_refusals() {
    assert_eq!(data().envelope_len(), ENVELOPE_LEN);
    assert_eq!(
        profile_of(Domain::RspSetup).envelope_len(),
        ENVELOPE_LEN + TRAILER_LEN
    );
    let profile = data();
    let mut datagram = [0_u8; 1408];
    assert_eq!(profile.seal(&mut datagram, MAX_PLAINTEXT), Ok(1408));
}

proptest! {
    /// Across a range of counters and every domain and epoch pair, no
    /// `(key, nonce)` pair repeats.
    #[test]
    fn no_key_and_nonce_pair_repeats(start in 0_u64..(BOOTSTRAP_SEQ_CAP - 256), steps in 1_usize..256) {
        let mut seen = HashSet::new();
        let mut datagram = [0_u8; 256];
        for (domain, party_epoch, salted) in [
            (Domain::Sender, 2, true),
            (Domain::Sender, 3, true),
            (Domain::Sender, 2, false),
            (Domain::Receiver, 2, true),
            (Domain::Setup, 0, false),
            (Domain::RspSetup, 0, false),
        ] {
            let profile = profile(domain, party_epoch, salted);
            let key = *profile.context().derive(&IKM);
            profile.set_next_seq(start);
            for _ in 0..steps {
                profile.seal_next(&mut datagram, 8).unwrap();
                let seq = u64::from_le_bytes(datagram[28..36].try_into().unwrap());
                let nonce = AesGcmSiv::nonce(domain, seq);
                prop_assert!(seen.insert((key, nonce)));
            }
        }
    }

    /// Any frames round trip, and any single bit flip is rejected.
    #[test]
    fn round_trip_and_bit_flips(frames in proptest::collection::vec(any::<u8>(), 0..1304), seq in 0_u64..DATA_SEQ_CAP, bit in any::<usize>()) {
        for profile in [data(), profile_of(Domain::Receiver)] {
            let datagram = sealed(&profile, &frames, seq);
            let mut opened = datagram.clone();
            let result = profile.open_in_place(&mut opened);
            prop_assert_eq!(result.map(|o| (o.frames, o.seq)), Ok((frames.len(), seq)));
            prop_assert_eq!(&opened[HEADER_LEN..HEADER_LEN + frames.len()], &frames[..]);
            let mut flipped = datagram.clone();
            let at = bit % (flipped.len() * 8);
            flipped[at / 8] ^= 1 << (at % 8);
            prop_assert!(profile.open_in_place(&mut flipped).is_err());
        }
    }
}
