// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use hmac::{Hmac, KeyInit, Mac};

use super::*;

fn sample() -> KeyState {
    let mut state = KeyState::default();
    state.tombstones.insert((3, 1));
    state.disabled.insert((4, 2));
    state.retired.insert((3, 2));
    state.lineages.insert(
        3,
        Lineage {
            highest: 4,
            predecessor: Some((3, 1_798_848_000)),
        },
    );
    state.lineages.insert(
        u32::MAX,
        Lineage {
            highest: u32::MAX,
            predecessor: None,
        },
    );
    state.admitted.insert(
        (3, 3),
        Fingerprints {
            file: [0xab; KEY_LEN],
            secret: Some([0xcd; KEY_LEN]),
        },
    );
    state.admitted.insert(
        (u32::MAX, u32::MAX),
        Fingerprints {
            file: [0xff; KEY_LEN],
            secret: None,
        },
    );
    state
}

#[test]
fn a_state_round_trips_canonically() {
    let state = sample();
    let text = state.encode().unwrap();
    assert!(text.starts_with("karyos-wire-key-state-v1\nentries=7\ntombstone=3-1\n"));
    assert!(text.contains("lineage=3 highest=4 predecessor=3 deadline=1798848000\n"));
    assert_eq!(KeyState::decode(text.as_bytes()).unwrap(), state);
    // The longest line stays within the size bound.
    let longest = text.lines().map(str::len).max().unwrap();
    assert!(longest < MAX_LINE, "{longest}");
    let empty = KeyState::default().encode().unwrap();
    assert_eq!(
        KeyState::decode(empty.as_bytes()).unwrap(),
        KeyState::default()
    );
}

fn resealed(body: &str) -> Vec<u8> {
    let digest = Sha256::digest(body.as_bytes());
    let mut text = body.to_owned();
    text.push_str("checksum=");
    hex_into(&mut text, &digest);
    text.push('\n');
    text.into_bytes()
}

fn body_of(text: &str) -> &str {
    &text[..text.rfind("checksum=").unwrap()]
}

#[test]
fn a_corrupt_or_non_canonical_state_is_refused() {
    let text = sample().encode().unwrap();
    // One flipped byte fails the checksum.
    let mut flipped = text.clone().into_bytes();
    flipped[30] ^= 1;
    assert_eq!(KeyState::decode(&flipped), Err(StateError::Checksum));
    // A truncated file, or one without its checksum, is refused.
    assert_eq!(
        KeyState::decode(&text.as_bytes()[..text.len() - 1]),
        Err(StateError::Checksum)
    );
    assert_eq!(
        KeyState::decode(body_of(&text).as_bytes()),
        Err(StateError::Checksum)
    );
    let body = body_of(&text);
    for bad in [
        // A wrong count.
        body.replace("entries=7", "entries=6"),
        // Out of order.
        body.replace(
            "tombstone=3-1\ndisabled=4-2\n",
            "disabled=4-2\ntombstone=3-1\n",
        ),
        // A duplicate.
        body.replace("tombstone=3-1\n", "tombstone=3-1\ntombstone=3-1\n"),
        // A non-canonical number.
        body.replace("tombstone=3-1", "tombstone=03-1"),
        // A zero epoch.
        body.replace("tombstone=3-1", "tombstone=3-0"),
        // A predecessor not below the highest epoch.
        body.replace("highest=4 predecessor=3", "highest=3 predecessor=3"),
        // Upper-case hex.
        body.replace("file=abab", "file=ABAB"),
        // CRLF.
        body.replace("tombstone=3-1\n", "tombstone=3-1\r\n"),
        // An unknown entry, and a wrong header.
        body.replace("retired=3-2", "revived=3-2"),
        body.replace("state-v1", "state-v2"),
    ] {
        assert!(
            matches!(
                KeyState::decode(&resealed(&bad)),
                Err(StateError::Malformed { .. })
            ),
            "{bad}"
        );
    }
}

#[test]
fn the_entry_bound_holds() {
    let mut state = KeyState::default();
    for epoch in 1..=u32::try_from(MAX_ENTRIES).unwrap() {
        state.tombstones.insert((1, epoch));
    }
    let text = state.encode().unwrap();
    assert!(text.len() <= MAX_STATE_LEN);
    assert_eq!(KeyState::decode(text.as_bytes()).unwrap(), state);
    state.tombstones.insert((2, 1));
    assert_eq!(state.encode(), Err(StateError::TooLarge));
}

#[test]
fn fingerprints_are_keyed_and_typed() {
    let one = Zeroizing::new([1_u8; KEY_LEN]);
    let two = Zeroizing::new([2_u8; KEY_LEN]);
    let file = fingerprint(&one, b"file", b"bytes");
    assert_eq!(file, fingerprint(&one, b"file", b"bytes"));
    assert_ne!(file, fingerprint(&two, b"file", b"bytes"));
    assert_ne!(file, fingerprint(&one, b"secret", b"bytes"));
    // HMAC-SHA-256(key, "karyos-key-fp-v1" || "file" || "bytes"), computed
    // without the helper.
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&[1_u8; KEY_LEN]).unwrap();
    mac.update(b"karyos-key-fp-v1filebytes");
    assert_eq!(file.as_slice(), mac.finalize().into_bytes().as_slice());
    // The written-out HMAC agrees with the `hmac` crate past one block of
    // message and for every key byte value.
    let key = Zeroizing::new(core::array::from_fn(|i| u8::try_from(i * 8 + 7).unwrap()));
    let long = [0xa5_u8; 200];
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key.as_slice()).unwrap();
    mac.update(b"karyos-key-fp-v1secret");
    mac.update(&long);
    assert_eq!(
        fingerprint(&key, b"secret", &long).as_slice(),
        mac.finalize().into_bytes().as_slice()
    );
    let encoded = encode_fingerprint_key(&one);
    assert_eq!(&*decode_fingerprint_key(encoded.as_slice()).unwrap(), &*one);
    assert!(decode_fingerprint_key(&encoded.as_slice()[1..]).is_err());
}
