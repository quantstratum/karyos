// SPDX-License-Identifier: Apache-2.0

//! The inner budget of an authenticated publication (ADR-0086 section 5)
//! through production admission: the log is sized at the channel MTU
//! less the 48-byte envelope, so every frame and fragment it writes is
//! sealed and sent in a datagram of at most the channel MTU.

use super::*;

use karyos_client::OfferOutcome;
use karyos_protocol::lanes::drr::Budget;
use karyos_protocol::protection::hmac_sha256::Domain;
use karyos_sys::log_buffer::Role;

use crate::wire_auth::ENVELOPE_LEN;

/// The frame lengths of one sealed datagram's frames, each frame at a
/// 32-byte boundary.
fn frame_lengths(frames: &[u8]) -> Vec<usize> {
    let mut lengths = Vec::new();
    let mut at = 0;
    while at + 4 <= frames.len() {
        let length = i32::from_le_bytes(frames[at..at + 4].try_into().unwrap());
        let length = usize::try_from(length).unwrap();
        lengths.push(length);
        at += length.max(32).next_multiple_of(32);
    }
    lengths
}

/// An established authenticated unicast channel through production
/// admission (`mtu` 1408): each batch of message lengths is offered at
/// once and delivered intact; returns the frame lengths of every domain 1
/// datagram sealed meanwhile, after checking that none exceeds 1408 bytes
/// on the wire (1360 inner bytes).
fn auth_mtu_run(batches: &[Vec<usize>]) -> Vec<Vec<usize>> {
    let (mut publisher, _pub_keys, mut subscriber, _sub_keys, handle) = established_publication();
    let image = subscriber.network_image(STREAM, 1).unwrap();
    let mut reader = subscriber
        .subscribe_aggregate(&image, Role::Required)
        .unwrap();
    let mut lane = publisher
        .publication(handle.lane(Lane::ZERO).unwrap())
        .unwrap();
    let budget = Budget {
        work: 256,
        bytes: 1 << 22,
    };
    crate::wire_auth::record_seals();
    let sealed = || -> Vec<Vec<usize>> {
        crate::wire_auth::take_seals()
            .iter()
            .filter(|record| record.domain == Domain::Data)
            .map(|record| {
                assert!(
                    record.frames.len() + ENVELOPE_LEN <= 1408,
                    "a {}-byte datagram",
                    record.frames.len() + ENVELOPE_LEN
                );
                frame_lengths(&record.frames)
            })
            .collect()
    };
    let mut delivered: Vec<Vec<u8>> = Vec::new();
    let mut offered: Vec<Vec<u8>> = Vec::new();
    for messages in batches {
        for (index, length) in messages.iter().enumerate() {
            let payload: Vec<u8> = (0..*length)
                .map(|at| u8::try_from((at * 31 + index) % 251).unwrap())
                .collect();
            offered.push(payload.clone());
            assert!(matches!(
                lane.offer(&payload).unwrap(),
                OfferOutcome::Accepted { .. }
            ));
        }
        let want = delivered.len() + messages.len();
        let done = pump(&mut [&mut publisher, &mut subscriber], |_| {
            let _ = reader.poll(|bytes, _, _| delivered.push(bytes.to_vec()), budget);
            delivered.len() == want
        });
        if !done {
            let data: Vec<Vec<usize>> = sealed()
                .into_iter()
                .filter(|lengths| lengths.iter().any(|length| *length > 96))
                .collect();
            panic!(
                "{} of {want} delivered; DATA sealed: {data:?}",
                delivered.len()
            );
        }
    }
    assert!(delivered == offered, "a message was not delivered intact");
    sealed()
}

/// ADR-0086 section 5, through production admission at `mtu` 1408 (`E`
/// = 48, inner budget 1360, fragment payload 1312, so fragment frames of
/// 1344 bytes): a 3000-byte message leaves as fragments of 1312, 1312
/// and 376 bytes, and a single message of 1329 bytes, whose 1361-byte
/// frame a log at the channel MTU wrote whole and the sender could never
/// send, as 1312 and 17. Each fragment is one sealed datagram of at most
/// 1408 bytes, and both messages are delivered intact.
#[test]
fn an_authenticated_message_is_fragmented_at_the_inner_budget() {
    let data = auth_mtu_run(&[vec![3000], vec![1329]]);
    let fragments: Vec<usize> = data.into_iter().flatten().collect();
    let data: Vec<usize> = fragments
        .iter()
        .copied()
        .filter(|length| *length > 96)
        .collect();
    assert_eq!(data, vec![32 + 1312, 32 + 1312, 32 + 376, 32 + 1312]);
    assert_eq!(
        fragments
            .iter()
            .filter(|length| **length == 32 + 17)
            .count(),
        1,
        "the 17-byte last fragment: {fragments:?}"
    );
}

/// ADR-0086 section 5: a 1312-byte message, the largest the inner budget
/// leaves unfragmented, goes as one DATA frame of 1344 bytes in a sealed
/// datagram of at most 1408 bytes, and is delivered intact.
#[test]
fn an_authenticated_publication_fills_the_mtu_and_never_exceeds_it() {
    let data = auth_mtu_run(&[vec![1312]]);
    assert!(
        data.iter().flatten().any(|length| *length == 32 + 1312),
        "{data:?}"
    );
}

/// An authenticated publication on a channel whose MTU less the envelope
/// is below the smallest MTU a receiver accepts is refused, typed, and
/// nothing is created.
#[test]
fn an_authenticated_channel_with_no_inner_budget_is_refused_typed() {
    let (mut publisher, _keys) = keyed(&borrowed(&publisher_files()));
    let mut config = aggregate(STREAM);
    config.stream.buffer.mtu = 288;
    let security = Security::Authenticated(auth(None));
    assert_eq!(
        publisher
            .add_network_publication(
                config,
                &udp(Destination::Unicast(SocketAddr::new(LOOPBACK, 9)), security),
            )
            .unwrap_err(),
        refused(AuthRefusal::Mtu)
    );
    let net = publisher.net.as_ref().unwrap();
    assert_eq!(net.publication_count(), 0);
}
