// SPDX-License-Identifier: Apache-2.0

//! H8 invariants of a publication's key holders (karyos#648), unit level:
//! each test names the invariant it proves (the `INV-` id of the round 4
//! invariant list).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

use karyos_protocol::network::{Alias, Identity};

use super::{AbortAuthority, PublicationAuth};
use crate::agents::EndpointId;
use crate::wire_auth::FixedKeys;
use crate::wire_keys::KeyFile;

const ALIAS: Alias = Alias {
    session_id: 5,
    stream_id: 6,
};

const IDENTITY: Identity = Identity {
    driver_id: [1, 2],
    registration_id: 3,
    incarnation: 1,
};

fn key(name: &str, text: &str) -> KeyFile {
    crate::wire_keys::parse(name, text.as_bytes()).unwrap()
}

fn channel() -> KeyFile {
    key(
        "3-1.key",
        "format=karyos-wire-key-v1\nkey_id=3\nfile_epoch=1\npurpose=channel\nprofile_id=1\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret=1111111111111111111111111111111111111111111111111111111111111111\nchannel_id=7\nstream_id=6\n",
    )
}

fn pairwise() -> KeyFile {
    key(
        "9-1.key",
        "format=karyos-wire-key-v1\nkey_id=9\nfile_epoch=1\npurpose=pairwise\nprofile_id=1\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret=2222222222222222222222222222222222222222222222222222222222222222\nreceiver_id=66\npublisher_id=5\n",
    )
}

/// The abort authority 10's signing key file of `epoch`, its secret
/// `fill` repeated.
fn authority(epoch: u32, fill: char) -> KeyFile {
    let secret: String = core::iter::repeat_n(fill, 64).collect();
    key(
        &format!("10-{epoch}.key"),
        &format!(
            "format=karyos-wire-key-v1\nkey_id=10\nfile_epoch={epoch}\npurpose=authority-signing\nprofile_id=4\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-04-30T00:00:00Z\nsecret={secret}\nauthority_id=10\nguards=11\nabort=true\n"
        ),
    )
}

/// A publication whose abort authority is pinned to authority file epoch
/// 1, as admission binds it (`net/wire.rs` `publication_binding`).
fn pinned() -> PublicationAuth {
    let pairwise = pairwise();
    let mut auth =
        PublicationAuth::new(EndpointId(1), ALIAS, IDENTITY, 1, &channel(), &[&pairwise]).unwrap();
    auth.set_clock(|| 1_795_000_000_000_000_000);
    let file = authority(1, '9');
    let crate::wire_keys::Material::Secret(seed) = &file.material else {
        panic!("a signing key");
    };
    let mut abort = AbortAuthority::new(crate::authority::Ed25519Signer::from_seed(seed), 10, 10);
    abort.file_epoch = Some(1);
    auth.abort = Some(abort);
    auth
}

/// INV-REV-4 (ADR-0118 (a); H8 R3-2 applied to the publication's own
/// abort signer): a publication's abort signer is pinned to the file
/// epoch it was admitted under. When that epoch is revoked while a
/// successor of the same `key_id` signs, the pinned signer is dropped (its
/// seed erased), never kept signing under the withdrawn epoch; while its
/// own epoch still signs it is kept.
#[test]
fn inv_an_abort_signer_pinned_to_a_withdrawn_epoch_is_dropped_though_a_successor_signs() {
    let mut auth = pinned();
    auth.apply_keys(&FixedKeys {
        files: vec![channel(), pairwise(), authority(1, '9')],
    });
    assert!(auth.abort.is_some(), "its own epoch still signs");
    // Epoch 1 revoked; the successor, epoch 2, signs under the same id.
    auth.apply_keys(&FixedKeys {
        files: vec![channel(), pairwise(), authority(2, '8')],
    });
    assert!(auth.abort.is_none(), "the withdrawn epoch's signer is gone");
}
