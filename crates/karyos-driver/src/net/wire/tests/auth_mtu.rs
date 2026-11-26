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
    auth_mtu_run_traced(batches, false)
}

/// [`auth_mtu_run`], each message traced when `traced`: every fragment
/// carries the 64-byte `EXT` frame extension (ADR-0035).
fn auth_mtu_run_traced(batches: &[Vec<usize>], traced: bool) -> Vec<Vec<usize>> {
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
            let outcome = if traced {
                let decision =
                    karyos_client::TraceDecision::traced(karyos_protocol::frame::TraceExtension {
                        extension_flags: 0,
                        trace_id: [7, u64::try_from(index).unwrap() + 1],
                        span_id: 3,
                        parent_span_id: 0,
                        message_id: u64::try_from(offered.len()).unwrap(),
                    });
                assert!(decision.is_traced());
                lane.offer_with_trace(&payload, &decision).unwrap()
            } else {
                lane.offer(&payload).unwrap()
            };
            assert!(matches!(outcome, OfferOutcome::Accepted { .. }));
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

// ---------------------------------------------------------------------
// H8 round 6, R5-11 and MP-5 (INV-SS-11, gate H11; wire threat model
// manifest 6.1 and 7): the MTU boundary through production admission with
// traced `EXT` frames, batching and fragmentation, at this profile's
// envelope E = 48 (inner budget 1360). A traced frame's header is 32
// bytes plus the 64-byte `EXT`, in every fragment.
// ---------------------------------------------------------------------

/// The frames of each sealed DATA datagram that carry a message (heartbeats
/// and pads, 32 or 64 bytes, aside).
fn message_frames(data: &[Vec<usize>], at_least: usize) -> Vec<Vec<usize>> {
    data.iter()
        .map(|frames| {
            frames
                .iter()
                .copied()
                .filter(|length| *length >= at_least)
                .collect::<Vec<usize>>()
        })
        .filter(|frames| !frames.is_empty())
        .collect()
}

/// W9 with W1 (manifest 6.1): a traced 32-byte message goes as one frame
/// of 32 + 64 + 32 bytes, sealed and delivered intact.
#[test]
fn h11_w9_a_traced_small_message_carries_its_ext() {
    let data = auth_mtu_run_traced(&[vec![32]], true);
    let frames: Vec<usize> = message_frames(&data, 128).into_iter().flatten().collect();
    assert_eq!(frames, vec![32 + 64 + 32], "{data:?}");
}

/// W9 with W4 at this envelope: a message frame is at most 1344 bytes
/// (`align_down(1360, 32) - 16`, as W4's 32 + 1312), so the largest traced
/// message left unfragmented is 1344 - 96 = 1248 bytes, one frame of
/// 1344 in a datagram of at most 1408; one byte more fragments, each
/// fragment carrying its `EXT`: 1248 and 1.
#[test]
fn h11_w9_a_traced_full_datagram_fills_the_mtu_and_one_more_byte_fragments() {
    let full = auth_mtu_run_traced(&[vec![1248]], true);
    let frames: Vec<usize> = message_frames(&full, 97).into_iter().flatten().collect();
    assert_eq!(frames, vec![96 + 1248], "{full:?}");
    let over = auth_mtu_run_traced(&[vec![1249]], true);
    let frames: Vec<usize> = message_frames(&over, 97).into_iter().flatten().collect();
    assert_eq!(frames, vec![96 + 1248, 96 + 1], "{over:?}");
}

/// W4 untraced at this envelope (manifest 6.1, `L = align_down(1408 - E,
/// 32) - 32`): 1312 bytes is one 1344-byte frame; 1313 fragments.
#[test]
fn h11_w4_the_full_datagram_boundary_at_this_envelope() {
    let full = auth_mtu_run(&[vec![1312]]);
    let frames: Vec<usize> = message_frames(&full, 97).into_iter().flatten().collect();
    assert_eq!(frames, vec![32 + 1312], "{full:?}");
    let over = auth_mtu_run(&[vec![1313]]);
    let frames: Vec<usize> = message_frames(&over, 33).into_iter().flatten().collect();
    assert_eq!(frames, vec![32 + 1312, 32 + 1], "{over:?}");
}

/// W5 (manifest 6.1, `floor((1408 - E) / 64)` frames of `L` = 32): 21
/// messages offered together pack 21 frames of 64 bytes into one sealed
/// datagram, never more, and are delivered intact; traced, a frame is
/// 128 bytes and a datagram packs at most `floor(1360 / 128)` = 10.
#[test]
fn h11_w5_batched_small_messages_pack_to_the_inner_budget() {
    let data = auth_mtu_run(&[vec![32; 21]]);
    let packed = message_frames(&data, 64);
    let most = packed.iter().map(Vec::len).max().unwrap();
    assert_eq!(most, 21, "{data:?}");
    assert_eq!(packed.iter().map(Vec::len).sum::<usize>(), 21);
    let data = auth_mtu_run_traced(&[vec![32; 21]], true);
    let packed = message_frames(&data, 128);
    assert!(packed.iter().all(|frames| frames.len() <= 10), "{data:?}");
    assert_eq!(packed.iter().map(Vec::len).sum::<usize>(), 21);
}

/// W6 (manifest 6.1): a 6000-byte message leaves as `ceil(6000 / c)`
/// fragments, `c` = 1312 here (E = 48 <= 160): 5 datagrams, 4 of 1312
/// and one of 752. Traced, each fragment also carries its `EXT`, so
/// `c` = 1248: still 5, 4 of 1248 and one of 1008.
#[test]
fn h11_w6_a_fragmented_message_takes_the_datagram_count_of_the_manifest() {
    let data = auth_mtu_run(&[vec![6000]]);
    let fragments: Vec<usize> = message_frames(&data, 97).into_iter().flatten().collect();
    assert_eq!(
        fragments,
        vec![32 + 1312, 32 + 1312, 32 + 1312, 32 + 1312, 32 + 752],
        "{data:?}"
    );
    let data = auth_mtu_run_traced(&[vec![6000]], true);
    let fragments: Vec<usize> = message_frames(&data, 97).into_iter().flatten().collect();
    assert_eq!(
        fragments,
        vec![96 + 1248, 96 + 1248, 96 + 1248, 96 + 1248, 96 + 1008],
        "{data:?}"
    );
}
