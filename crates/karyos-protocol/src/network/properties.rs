// SPDX-License-Identifier: Apache-2.0

//! Property harnesses (ADR-0062: proptest and hand-written vectors, no
//! cargo-fuzz) through the dispatcher and through every per-kind decoder:
//! arbitrary bounded datagrams never panic, an accepted control consumes
//! exactly its schema and re-encodes to the same bytes, values round-trip,
//! and a valid prefix never hides an invalid suffix or trailer.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use proptest::prelude::*;

use super::*;

/// The largest datagram the harnesses generate: the jumbo MTU.
const MAX_DATAGRAM: usize = 8192;

/// Decoding through the per-kind decoder of `kind`, as a [`Control`].
fn decode_kind(kind: ControlKind, bytes: &[u8]) -> Result<Control, ControlError> {
    match kind {
        ControlKind::SetupAnnounce => SetupAnnounce::decode(bytes).map(Control::SetupAnnounce),
        ControlKind::SetupAnswer => SetupAnswer::decode(bytes).map(Control::SetupAnswer),
        ControlKind::Challenge => RspChallenge::decode(bytes).map(Control::Challenge),
        ControlKind::Solicit => RspSolicit::decode(bytes).map(Control::Solicit),
        ControlKind::Status => StatusMessage::decode(bytes).map(Control::Status),
        ControlKind::Nak => Nak::decode(bytes).map(Control::Nak),
        ControlKind::NakReply => NakReply::decode(bytes).map(Control::NakReply),
        ControlKind::Unbound => Unbound::decode(bytes).map(Control::Unbound),
        ControlKind::Register => RspRegister::decode(bytes).map(Control::Register),
        ControlKind::Registration => Registration::decode(bytes).map(Control::Registration),
        ControlKind::RttmRequest | ControlKind::RttmReply => Rttm::decode(bytes).map(Control::Rttm),
        ControlKind::PathHeartbeat => PathHeartbeat::decode(bytes).map(Control::PathHeartbeat),
    }
}

fn encoded(control: &Control) -> Result<Vec<u8>, ControlError> {
    let mut out = vec![0u8; MAX_CONTROL_LENGTH];
    let length = control.encode(&mut out)?;
    out.truncate(length);
    Ok(out)
}

/// Whether two kinds share a per-kind decoder.
fn same_codec(a: ControlKind, b: ControlKind) -> bool {
    let rttm = |kind| matches!(kind, ControlKind::RttmRequest | ControlKind::RttmReply);
    a == b || (rttm(a) && rttm(b))
}

/// Classifies `bytes` and checks the result against the control decoder,
/// every per-kind decoder and the encoder. Returns whether it was accepted.
fn check_classified(bytes: &[u8]) -> Result<bool, TestCaseError> {
    let classified = classify(bytes);
    let control = Control::decode(bytes);
    if bytes.len() < 8 {
        prop_assert_eq!(classified, Err(ControlError::Truncated));
    }
    for kind in ControlKind::ALL {
        let by_kind = decode_kind(kind, bytes);
        match (&control, by_kind) {
            (Ok(c), Ok(k)) => {
                prop_assert!(same_codec(c.kind(), kind));
                prop_assert_eq!(*c, k);
            }
            (Ok(c), Err(error)) => {
                prop_assert!(!same_codec(c.kind(), kind));
                prop_assert_eq!(
                    error,
                    ControlError::WrongKind {
                        code: c.kind().frame_type().code()
                    }
                );
            }
            (Err(_), Ok(k)) => prop_assert!(false, "only the kind decoder accepted {:?}", k),
            (Err(_), Err(_)) => {}
        }
    }
    match classified {
        Ok(Datagram::Control(c)) => {
            prop_assert_eq!(control, Ok(c));
            // Exactly the schema: frame_length, the datagram and the
            // encoding are the same bytes.
            prop_assert_eq!(c.encoded_length(), Some(bytes.len()));
            prop_assert_eq!(&encoded(&c).unwrap()[..], bytes);
            prop_assert_eq!(
                i32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize,
                bytes.len()
            );
            Ok(true)
        }
        Ok(Datagram::DataBatch(group) | Datagram::Heartbeat(group)) => {
            prop_assert_eq!(group.bytes(), bytes);
            let code = u16::from_le_bytes([bytes[6], bytes[7]]);
            prop_assert!(matches!(code, 0x00 | 0x01 | 0x08));
            prop_assert_eq!(control, Err(ControlError::WrongKind { code }));
            Ok(true)
        }
        Err(error) => {
            let capacity = matches!(error, ControlError::BufferTooShort { .. });
            prop_assert!(!capacity);
            if let ControlError::UnsupportedVersion {
                version,
                frame_type,
                frame_length,
            } = error
            {
                prop_assert!(version > 1);
                if let Some(reply) = unbound_reply(&error, bytes.len()) {
                    prop_assert!(bytes.len() >= 40);
                    prop_assert_ne!(frame_type, FrameType::Err.code());
                    let reply_bytes = encoded(&Control::Unbound(reply)).unwrap();
                    prop_assert_eq!(reply_bytes.len(), 40);
                    prop_assert_eq!(&reply_bytes[32..36], &frame_length.to_le_bytes());
                }
            }
            match &control {
                // The data scanner refused what the control decoder never
                // reached.
                Err(ControlError::WrongKind { code }) => {
                    prop_assert!(matches!(code, 0x00 | 0x01 | 0x08));
                }
                other => prop_assert_eq!(*other, Err(error)),
            }
            Ok(false)
        }
    }
}

fn id128(valid: bool) -> BoxedStrategy<[u64; 2]> {
    if valid {
        any::<[u64; 2]>()
            .prop_filter("nonzero", |id| *id != [0, 0])
            .boxed()
    } else {
        prop_oneof![3 => any::<[u64; 2]>(), 1 => Just([0, 0])].boxed()
    }
}

fn nonzero(valid: bool) -> BoxedStrategy<u64> {
    if valid {
        (1..=u64::MAX).boxed()
    } else {
        prop_oneof![3 => 1..=u64::MAX, 1 => Just(0u64)].boxed()
    }
}

fn identity(valid: bool) -> impl Strategy<Value = Identity> {
    (id128(valid), nonzero(valid), nonzero(valid)).prop_map(
        |(driver_id, registration_id, incarnation)| Identity {
            driver_id,
            registration_id,
            incarnation,
        },
    )
}

fn receiver(valid: bool) -> impl Strategy<Value = Receiver> {
    (id128(valid), nonzero(valid)).prop_map(|(receiver_boot_id, receiver_id)| Receiver {
        receiver_boot_id,
        receiver_id,
    })
}

fn challenge(valid: bool) -> impl Strategy<Value = ChallengeBlock> {
    (id128(valid), id128(valid)).prop_map(|(receiver_boot_id, nonce)| ChallengeBlock {
        receiver_boot_id,
        nonce,
    })
}

fn term(valid: bool) -> BoxedStrategy<TermParams> {
    let length = (16u32..=30).prop_map(|shift| 1u32 << shift);
    let mtu = MIN_MTU..=MAX_MTU;
    if valid {
        (length, any::<i32>(), mtu)
            .prop_map(|(term_length, initial_term_id, mtu)| TermParams {
                term_length,
                initial_term_id,
                mtu,
            })
            .boxed()
    } else {
        (
            prop_oneof![length, any::<u32>()],
            any::<i32>(),
            prop_oneof![mtu, any::<u32>()],
        )
            .prop_map(|(term_length, initial_term_id, mtu)| TermParams {
                term_length,
                initial_term_id,
                mtu,
            })
            .boxed()
    }
}

/// A position: aligned and bounded, or (when not `valid`) anything near
/// the bounds.
fn position(valid: bool) -> BoxedStrategy<u64> {
    let aligned = (0..=MAX_POSITION / 32).prop_map(|units| units * 32);
    if valid {
        prop_oneof![aligned, Just(MAX_POSITION), Just(0)].boxed()
    } else {
        prop_oneof![aligned, any::<u64>(), Just(MAX_POSITION + 32)].boxed()
    }
}

fn window(valid: bool) -> BoxedStrategy<u32> {
    let aligned = (0..=MAX_WINDOW / 32).prop_map(|units| units * 32);
    if valid {
        aligned.boxed()
    } else {
        prop_oneof![aligned, any::<u32>()].boxed()
    }
}

fn range(valid: bool) -> BoxedStrategy<NakRange> {
    let length = (1..=MAX_NAK_LENGTH / 32).prop_map(|units| units * 32);
    let lane = (0..Lane::COUNT).prop_map(|lane| Lane::try_new(lane).unwrap());
    if valid {
        (
            lane,
            length,
            0..=(MAX_POSITION - u64::from(MAX_NAK_LENGTH)) / 32,
        )
            .prop_map(|(lane, length, units)| NakRange {
                lane,
                length,
                start: units * 32,
            })
            .boxed()
    } else {
        (lane, prop_oneof![length, any::<u32>()], position(false))
            .prop_map(|(lane, length, start)| NakRange {
                lane,
                length,
                start,
            })
            .boxed()
    }
}

fn lanes<T: Copy + Default + core::fmt::Debug>(
    entry: BoxedStrategy<T>,
) -> impl Strategy<Value = Lanes<T>> {
    prop::collection::vec(entry, 1..=MAX_LANES).prop_map(|entries| Lanes::new(&entries).unwrap())
}

fn alias() -> impl Strategy<Value = Alias> {
    any::<(i32, i32)>().prop_map(|(session_id, stream_id)| Alias {
        session_id,
        stream_id,
    })
}

/// A control; `valid` keeps every field decodable, otherwise zeros and
/// out-of-range values are frequent.
fn control(valid: bool) -> BoxedStrategy<Control> {
    let lane_count = if valid {
        (1..=Lane::COUNT).boxed()
    } else {
        (0..=Lane::COUNT + 1).boxed()
    };
    let lane_status = (position(valid), window(valid))
        .prop_map(|(consumption, window)| LaneStatus {
            consumption,
            window,
        })
        .boxed();
    let unbound_versions = if valid {
        (2..=u8::MAX, Just(1u8), Just(1u8)).boxed()
    } else {
        any::<(u8, u8, u8)>().boxed()
    };
    prop_oneof![
        (alias(), identity(valid), term(valid), lane_count).prop_map(
            |(alias, identity, term, lane_count)| Control::SetupAnnounce(SetupAnnounce {
                alias,
                identity,
                term,
                lane_count,
            })
        ),
        (
            alias(),
            identity(valid),
            term(valid),
            challenge(valid),
            lanes(position(valid))
        )
            .prop_map(
                |(alias, identity, term, challenge, joins)| Control::SetupAnswer(SetupAnswer {
                    alias,
                    identity,
                    term,
                    challenge,
                    joins,
                })
            ),
        (alias(), identity(valid), challenge(valid)).prop_map(|(alias, identity, challenge)| {
            Control::Challenge(RspChallenge {
                alias,
                identity,
                challenge,
            })
        }),
        (alias(), challenge(valid))
            .prop_map(|(alias, challenge)| Control::Solicit(RspSolicit { alias, challenge })),
        (any::<i32>(), receiver(valid)).prop_map(|(stream_id, receiver)| {
            Control::Register(RspRegister {
                stream_id,
                receiver,
            })
        }),
        any::<i32>().prop_map(|stream_id| {
            Control::Registration(Registration {
                stream_id,
                reason: RegistrationReason::DestinationsFull,
            })
        }),
        (
            alias(),
            identity(valid),
            receiver(valid),
            any::<u64>(),
            lanes(lane_status)
        )
            .prop_map(|(alias, identity, receiver, group_tag, lanes)| {
                Control::Status(StatusMessage {
                    alias,
                    identity,
                    receiver,
                    group_tag,
                    lanes,
                })
            }),
        (alias(), identity(valid), receiver(valid), range(valid)).prop_map(
            |(alias, identity, receiver, range)| Control::Nak(Nak {
                alias,
                identity,
                receiver,
                range,
            })
        ),
        (
            alias(),
            identity(valid),
            receiver(valid),
            range(valid),
            prop_oneof![
                position(valid).prop_map(|lowest_retained| NakReplyReason::RangeUnavailable {
                    lowest_retained
                }),
                Just(NakReplyReason::RangeInvalid),
            ]
        )
            .prop_map(|(alias, identity, receiver, range, reason)| {
                Control::NakReply(NakReply {
                    alias,
                    identity,
                    receiver,
                    range,
                    reason,
                })
            }),
        (any::<u16>(), unbound_versions, any::<i32>()).prop_map(
            |(rejected_type, (rejected_version, min_supported, max_supported), rejected_length)| {
                Control::Unbound(Unbound {
                    rejected_type,
                    rejected_version,
                    min_supported,
                    max_supported,
                    rejected_length,
                })
            }
        ),
        (
            alias(),
            identity(valid),
            receiver(valid),
            nonzero(valid),
            prop_oneof![
                Just(RttmKind::Request),
                any::<u64>().prop_map(|service_delay_ns| RttmKind::Reply { service_delay_ns }),
            ]
        )
            .prop_map(|(alias, identity, receiver, probe_id, kind)| {
                Control::Rttm(Rttm {
                    alias,
                    identity,
                    receiver,
                    probe_id,
                    kind,
                })
            }),
        (alias(), identity(valid)).prop_map(|(alias, identity)| {
            Control::PathHeartbeat(PathHeartbeat { alias, identity })
        }),
    ]
    .boxed()
}

/// A data record of one alias and lane: DATA with payload, PAD or ABORTED,
/// padded to the stride unless `last`.
fn data_record(alias: Alias, lane: u8, kind: u8, payload: usize, last: bool) -> Vec<u8> {
    let (code, length) = match kind {
        0 => (FrameType::Pad.code(), 32),
        1 => (FrameType::Aborted.code(), 32),
        _ => (FrameType::Data.code(), 32 + payload),
    };
    let mut bytes = vec![0u8; length];
    bytes[..4].copy_from_slice(&(length as i32).to_le_bytes());
    bytes[4] = 1;
    bytes[5] = (lane << 4) | if code == 1 { 0x03 } else { 0 };
    bytes[6..8].copy_from_slice(&code.to_le_bytes());
    bytes[12..16].copy_from_slice(&alias.session_id.to_le_bytes());
    bytes[16..20].copy_from_slice(&alias.stream_id.to_le_bytes());
    if !last {
        bytes.resize(length.next_multiple_of(32), 0);
    }
    bytes
}

/// A valid data batch: one to eight records of one alias and lane.
fn data_batch() -> impl Strategy<Value = Vec<u8>> {
    (
        alias(),
        0..Lane::COUNT,
        prop::collection::vec((0u8..=3, 1usize..=300), 1..=8),
        any::<bool>(),
    )
        .prop_map(|(alias, lane, records, unpadded)| {
            let count = records.len();
            records
                .into_iter()
                .enumerate()
                .flat_map(|(i, (kind, payload))| {
                    data_record(alias, lane, kind, payload, unpadded && i + 1 == count)
                })
                .collect()
        })
}

/// Datagrams: arbitrary bytes up to the jumbo MTU; mutated, cut, extended
/// and concatenated valid controls; a known first word over arbitrary
/// bytes; and data batches with or without a trailer.
fn datagram() -> impl Strategy<Value = Vec<u8>> {
    let control_bytes = control(true).prop_map(|c| encoded(&c).unwrap());
    prop_oneof![
        1 => prop::collection::vec(any::<u8>(), 0..=MAX_DATAGRAM),
        1 => prop::collection::vec(any::<u8>(), 0..=64),
        3 => (
            control_bytes.clone(),
            prop::collection::vec((any::<prop::sample::Index>(), 1u8..=255), 0..=3),
            prop_oneof![Just(None), any::<prop::sample::Index>().prop_map(Some)],
            prop::collection::vec(any::<u8>(), 0..=16),
        )
            .prop_map(|(mut bytes, flips, cut, extra)| {
                for (at, mask) in flips {
                    let at = at.index(bytes.len());
                    bytes[at] ^= mask;
                }
                if let Some(cut) = cut {
                    bytes.truncate(cut.index(bytes.len() + 1));
                }
                bytes.extend_from_slice(&extra);
                bytes
            }),
        1 => (control_bytes.clone(), control_bytes).prop_map(|(a, b)| [a, b].concat()),
        2 => (
            prop::sample::select(&[0x00u16, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x10, 0x11, 0x12, 0x13, 0x09][..]),
            0u8..=4,
            0u8..=2,
            prop::sample::select(&[24usize, 40, 56, 72, 88, 96, 104, 112, 120, 128, 136, 152][..]),
            prop::collection::vec(prop_oneof![3 => Just(0u8), 1 => any::<u8>()], 152),
        )
            .prop_map(|(code, variant, count, length, mut body)| {
                body.truncate(length);
                body[..4].copy_from_slice(&(length as i32).to_le_bytes());
                body[4] = 1;
                body[5] = 0;
                body[6..8].copy_from_slice(&code.to_le_bytes());
                body[8] = variant;
                body[9] = count;
                body
            }),
        2 => (
            data_batch(),
            prop::collection::vec(any::<u8>(), 0..=40),
        )
            .prop_map(|(batch, trailer)| [batch, trailer].concat()),
    ]
}

proptest! {
    /// Arbitrary bounded datagrams never panic; whatever is accepted is
    /// canonical and every decoder agrees.
    #[test]
    fn any_datagram_is_refused_or_canonical(bytes in datagram()) {
        check_classified(&bytes)?;
    }

    /// Valid controls round-trip through the encoder, the dispatcher and
    /// their per-kind decoder; prefixes, suffixes and trailers are refused.
    #[test]
    fn controls_round_trip_and_resist_mutation(
        control in control(true),
        other in control(true),
        flip in any::<prop::sample::Index>(),
        mask in 1u8..=255,
        cut in any::<prop::sample::Index>(),
        extra in prop::collection::vec(any::<u8>(), 1..=64),
        offset in 0usize..8,
    ) {
        let bytes = encoded(&control).unwrap();
        prop_assert_eq!(Some(bytes.len()), control.encoded_length());
        prop_assert_eq!(Control::decode(&bytes), Ok(control));
        prop_assert_eq!(classify(&bytes), Ok(Datagram::Control(control)));
        prop_assert_eq!(decode_kind(control.kind(), &bytes), Ok(control));
        prop_assert!(check_classified(&bytes)?);

        // Unaligned storage.
        let mut storage = vec![0xA5u8; bytes.len() + 8];
        storage[offset..offset + bytes.len()].copy_from_slice(&bytes);
        prop_assert_eq!(Control::decode(&storage[offset..offset + bytes.len()]), Ok(control));

        // No sendable prefix on insufficient capacity.
        let mut short = vec![0xEEu8; bytes.len() - 1];
        prop_assert_eq!(
            control.encode(&mut short),
            Err(ControlError::BufferTooShort {
                required: bytes.len(),
                available: bytes.len() - 1,
            })
        );
        prop_assert!(short.iter().all(|b| *b == 0xEE));

        // A prefix is truncated; any trailer, including a whole second
        // control or a heartbeat, is a grouping error.
        let prefix = &bytes[..cut.index(bytes.len())];
        prop_assert_eq!(classify(prefix), Err(ControlError::Truncated));
        let mut longer = bytes.clone();
        longer.extend_from_slice(&extra);
        prop_assert_eq!(classify(&longer), Err(ControlError::InvalidGrouping));
        let second = [bytes.clone(), encoded(&other).unwrap()].concat();
        prop_assert_eq!(classify(&second), Err(ControlError::InvalidGrouping));
        for kind in ControlKind::ALL {
            prop_assert!(decode_kind(kind, &longer).is_err());
            prop_assert!(decode_kind(kind, &second).is_err());
        }

        // Any single-byte change is refused or canonical.
        let mut flipped = bytes.clone();
        flipped[flip.index(bytes.len())] ^= mask;
        check_classified(&flipped)?;
    }

    /// What encodes decodes to itself: the encoder refuses exactly the
    /// values the decoder could not return, and writes nothing then.
    #[test]
    fn an_encodable_control_decodes_to_itself(control in control(false)) {
        let mut out = [0xEEu8; MAX_CONTROL_LENGTH];
        match control.encode(&mut out) {
            Ok(length) => {
                prop_assert_eq!(Control::decode(&out[..length]), Ok(control));
                prop_assert_eq!(control.check(), Ok(()));
            }
            Err(error) => {
                prop_assert!(matches!(
                    error,
                    ControlError::InvalidCount
                        | ControlError::InvalidIdentity
                        | ControlError::InvalidPosition
                        | ControlError::InvalidValue
                ));
                prop_assert!(out.iter().all(|b| *b == 0xEE));
            }
        }
    }

    /// A data batch of one alias and lane is accepted whole; a trailer that
    /// is not a full record of the same group is refused, as is any control
    /// or heartbeat after it.
    #[test]
    fn data_batches_group_exactly(
        batch in data_batch(),
        trailer in prop::collection::vec(any::<u8>(), 1..=31),
        control in control(true),
    ) {
        let Ok(Datagram::DataBatch(group)) = classify(&batch) else {
            return Err(TestCaseError::fail("valid batch refused"));
        };
        prop_assert_eq!(group.bytes(), &batch[..]);
        prop_assert!(check_classified(&batch)?);

        // When the batch ends on the stride, fewer than 32 trailing bytes
        // can never be a record. After an unpadded last record, trailing
        // bytes are its padding: accepted only if they complete it.
        let with_trailer = [batch.clone(), trailer.clone()].concat();
        let accepted = check_classified(&with_trailer)?;
        if batch.len() % 32 == 0 {
            prop_assert!(!accepted);
        } else {
            prop_assert_eq!(accepted, with_trailer.len() % 32 == 0);
        }

        // A control after a batch that ends on the stride is a grouping
        // error: the next record is a control type.
        let with_control = [batch.clone(), encoded(&control).unwrap()].concat();
        if batch.len() % 32 == 0 {
            prop_assert_eq!(classify(&with_control), Err(ControlError::InvalidGrouping));
        } else {
            check_classified(&with_control)?;
        }
    }
}
