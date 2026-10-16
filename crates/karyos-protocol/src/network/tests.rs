// SPDX-License-Identifier: Apache-2.0

//! The hand-written binary vectors of `quantstratum-docs:
//! karyos/design/network-control-schemas.md` section 5, kept as literals
//! copied from the design and never produced by the encoder, and the
//! systematic mutations of its section 10.

use super::*;

// Shared values (section 5.1).
const ALIAS: Alias = Alias {
    session_id: 0x1234_5678,
    stream_id: 1001,
};
const IDENTITY: Identity = Identity {
    driver_id: [0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210],
    registration_id: 7,
    incarnation: 1,
};
const TERM: TermParams = TermParams {
    term_length: 65536,
    initial_term_id: -2,
    mtu: 1408,
};
const BOOT_ID: [u64; 2] = [0xA1A2_A3A4_A5A6_A7A8, 0xB1B2_B3B4_B5B6_B7B8];
const RECEIVER: Receiver = Receiver {
    receiver_boot_id: BOOT_ID,
    receiver_id: 0x42,
};
const CHALLENGE: ChallengeBlock = ChallengeBlock {
    receiver_boot_id: BOOT_ID,
    nonce: [0xC1C2_C3C4_C5C6_C7C8, 0xD1D2_D3D4_D5D6_D7D8],
};

const V_SETUP_1: [[u8; 8]; 9] = [
    [0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x05, 0x00],
    [0x01, 0x02, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12],
    [0xE9, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01],
    [0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE],
    [0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x00, 0x00, 0x01, 0x00, 0xFE, 0xFF, 0xFF, 0xFF],
    [0x80, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
];

const V_SETUP_2: [[u8; 8]; 15] = [
    [0x78, 0x00, 0x00, 0x00, 0x01, 0x00, 0x05, 0x00],
    [0x02, 0x02, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12],
    [0xE9, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01],
    [0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE],
    [0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x00, 0x00, 0x01, 0x00, 0xFE, 0xFF, 0xFF, 0xFF],
    [0x80, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0xA8, 0xA7, 0xA6, 0xA5, 0xA4, 0xA3, 0xA2, 0xA1],
    [0xB8, 0xB7, 0xB6, 0xB5, 0xB4, 0xB3, 0xB2, 0xB1],
    [0xC8, 0xC7, 0xC6, 0xC5, 0xC4, 0xC3, 0xC2, 0xC1],
    [0xD8, 0xD7, 0xD6, 0xD5, 0xD4, 0xD3, 0xD2, 0xD1],
    [0x00, 0x10, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
];

const V_RSP_1: [[u8; 8]; 11] = [
    [0x58, 0x00, 0x00, 0x00, 0x01, 0x00, 0x07, 0x00],
    [0x01, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12],
    [0xE9, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01],
    [0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE],
    [0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0xA8, 0xA7, 0xA6, 0xA5, 0xA4, 0xA3, 0xA2, 0xA1],
    [0xB8, 0xB7, 0xB6, 0xB5, 0xB4, 0xB3, 0xB2, 0xB1],
    [0xC8, 0xC7, 0xC6, 0xC5, 0xC4, 0xC3, 0xC2, 0xC1],
    [0xD8, 0xD7, 0xD6, 0xD5, 0xD4, 0xD3, 0xD2, 0xD1],
];

const V_RSP_2: [[u8; 8]; 7] = [
    [0x38, 0x00, 0x00, 0x00, 0x01, 0x00, 0x07, 0x00],
    [0x02, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12],
    [0xE9, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0xA8, 0xA7, 0xA6, 0xA5, 0xA4, 0xA3, 0xA2, 0xA1],
    [0xB8, 0xB7, 0xB6, 0xB5, 0xB4, 0xB3, 0xB2, 0xB1],
    [0xC8, 0xC7, 0xC6, 0xC5, 0xC4, 0xC3, 0xC2, 0xC1],
    [0xD8, 0xD7, 0xD6, 0xD5, 0xD4, 0xD3, 0xD2, 0xD1],
];

const V_SM_1: [[u8; 8]; 13] = [
    [0x68, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03, 0x00],
    [0x01, 0x01, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12],
    [0xE9, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01],
    [0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE],
    [0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0xA8, 0xA7, 0xA6, 0xA5, 0xA4, 0xA3, 0xA2, 0xA1],
    [0xB8, 0xB7, 0xB6, 0xB5, 0xB4, 0xB3, 0xB2, 0xB1],
    [0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x00, 0x14, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
];

const V_SM_2: [[u8; 8]; 19] = [
    [0x98, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03, 0x00],
    [0x01, 0x04, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12],
    [0xE9, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01],
    [0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE],
    [0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0xA8, 0xA7, 0xA6, 0xA5, 0xA4, 0xA3, 0xA2, 0xA1],
    [0xB8, 0xB7, 0xB6, 0xB5, 0xB4, 0xB3, 0xB2, 0xB1],
    [0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x00, 0x14, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
];

const V_NAK_1: [[u8; 8]; 12] = [
    [0x60, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00],
    [0x01, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12],
    [0xE9, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01],
    [0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE],
    [0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0xA8, 0xA7, 0xA6, 0xA5, 0xA4, 0xA3, 0xA2, 0xA1],
    [0xB8, 0xB7, 0xB6, 0xB5, 0xB4, 0xB3, 0xB2, 0xB1],
    [0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00],
    [0x00, 0x04, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00],
];

const V_ERR_1: [[u8; 8]; 14] = [
    [0x70, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00],
    [0x01, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12],
    [0xE9, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01],
    [0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE],
    [0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0xA8, 0xA7, 0xA6, 0xA5, 0xA4, 0xA3, 0xA2, 0xA1],
    [0xB8, 0xB7, 0xB6, 0xB5, 0xB4, 0xB3, 0xB2, 0xB1],
    [0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00],
    [0x00, 0x04, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x00, 0x08, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00],
];

const V_ERR_2: [[u8; 8]; 5] = [
    [0x28, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00],
    [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x01, 0x00, 0x03, 0x00, 0x02, 0x01, 0x01, 0x00],
    [0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
];

const V_RTTM_1: [[u8; 8]; 12] = [
    [0x60, 0x00, 0x00, 0x00, 0x01, 0x00, 0x06, 0x00],
    [0x01, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12],
    [0xE9, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01],
    [0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE],
    [0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0xA8, 0xA7, 0xA6, 0xA5, 0xA4, 0xA3, 0xA2, 0xA1],
    [0xB8, 0xB7, 0xB6, 0xB5, 0xB4, 0xB3, 0xB2, 0xB1],
    [0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
];

/// V-RTTM-2 is V-RTTM-1 with rows `08` and `58` replaced (section 5.7);
/// written out in full here.
const V_RTTM_2: [[u8; 8]; 12] = [
    [0x60, 0x00, 0x00, 0x00, 0x01, 0x00, 0x06, 0x00],
    [0x02, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12],
    [0xE9, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01],
    [0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE],
    [0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0xA8, 0xA7, 0xA6, 0xA5, 0xA4, 0xA3, 0xA2, 0xA1],
    [0xB8, 0xB7, 0xB6, 0xB5, 0xB4, 0xB3, 0xB2, 0xB1],
    [0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
    [0xC4, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
];

const V_PHB_1: [[u8; 8]; 7] = [
    [0x38, 0x00, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00],
    [0x01, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12],
    [0xE9, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01],
    [0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE],
    [0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
];

/// A 32-byte header-only DATA heartbeat of the shared alias, lane 0.
const HEARTBEAT: [[u8; 8]; 4] = [
    [0x20, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00],
    [0x00, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12],
    [0xE9, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00],
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
];

fn nak_range() -> NakRange {
    NakRange {
        lane: Lane::try_new(1).unwrap(),
        length: 2048,
        start: 197_632,
    }
}

fn v_nak() -> Nak {
    Nak {
        alias: ALIAS,
        identity: IDENTITY,
        receiver: RECEIVER,
        range: nak_range(),
    }
}

/// Every valid vector with its decoded value.
fn valid_vectors() -> Vec<(&'static str, &'static [u8], Control)> {
    vec![
        (
            "V-SETUP-1",
            V_SETUP_1.as_flattened(),
            Control::SetupAnnounce(SetupAnnounce {
                alias: ALIAS,
                identity: IDENTITY,
                term: TERM,
                lane_count: 2,
            }),
        ),
        (
            "V-SETUP-2",
            V_SETUP_2.as_flattened(),
            Control::SetupAnswer(SetupAnswer {
                alias: ALIAS,
                identity: IDENTITY,
                term: TERM,
                challenge: CHALLENGE,
                joins: Lanes::new(&[200_704, 0]).unwrap(),
            }),
        ),
        (
            "V-RSP-1",
            V_RSP_1.as_flattened(),
            Control::Challenge(RspChallenge {
                alias: ALIAS,
                identity: IDENTITY,
                challenge: CHALLENGE,
            }),
        ),
        (
            "V-RSP-2",
            V_RSP_2.as_flattened(),
            Control::Solicit(RspSolicit {
                alias: ALIAS,
                challenge: CHALLENGE,
            }),
        ),
        (
            "V-SM-1",
            V_SM_1.as_flattened(),
            Control::Status(StatusMessage {
                alias: ALIAS,
                identity: IDENTITY,
                receiver: RECEIVER,
                group_tag: 3,
                lanes: Lanes::new(&[LaneStatus {
                    consumption: 201_728,
                    window: 32768,
                }])
                .unwrap(),
            }),
        ),
        (
            "V-SM-2",
            V_SM_2.as_flattened(),
            Control::Status(StatusMessage {
                alias: ALIAS,
                identity: IDENTITY,
                receiver: RECEIVER,
                group_tag: 0,
                lanes: Lanes::new(&[
                    LaneStatus {
                        consumption: 201_728,
                        window: 32768,
                    },
                    LaneStatus {
                        consumption: 0,
                        window: 32768,
                    },
                    LaneStatus {
                        consumption: 64,
                        window: 0,
                    },
                    LaneStatus {
                        consumption: 32,
                        window: 32768,
                    },
                ])
                .unwrap(),
            }),
        ),
        ("V-NAK-1", V_NAK_1.as_flattened(), Control::Nak(v_nak())),
        (
            "V-ERR-1",
            V_ERR_1.as_flattened(),
            Control::NakReply(NakReply::answering(
                &v_nak(),
                NakReplyReason::RangeUnavailable {
                    lowest_retained: 198_656,
                },
            )),
        ),
        (
            "V-ERR-2",
            V_ERR_2.as_flattened(),
            Control::Unbound(Unbound {
                rejected_type: 3,
                rejected_version: 2,
                min_supported: 1,
                max_supported: 1,
                rejected_length: 64,
            }),
        ),
        (
            "V-RTTM-1",
            V_RTTM_1.as_flattened(),
            Control::Rttm(Rttm {
                alias: ALIAS,
                identity: IDENTITY,
                receiver: RECEIVER,
                probe_id: 0x0102_0304_0506_0708,
                kind: RttmKind::Request,
            }),
        ),
        (
            "V-RTTM-2",
            V_RTTM_2.as_flattened(),
            Control::Rttm(Rttm {
                alias: ALIAS,
                identity: IDENTITY,
                receiver: RECEIVER,
                probe_id: 0x0102_0304_0506_0708,
                kind: RttmKind::Reply {
                    service_delay_ns: 2500,
                },
            }),
        ),
        (
            "V-PHB-1",
            V_PHB_1.as_flattened(),
            Control::PathHeartbeat(PathHeartbeat {
                alias: ALIAS,
                identity: IDENTITY,
            }),
        ),
    ]
}

/// `base` with `bytes` written at `at`.
fn mutate(base: &[u8], at: usize, bytes: &[u8]) -> Vec<u8> {
    let mut out = base.to_vec();
    out[at..at + bytes.len()].copy_from_slice(bytes);
    out
}

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
        ControlKind::RttmRequest | ControlKind::RttmReply => Rttm::decode(bytes).map(Control::Rttm),
        ControlKind::PathHeartbeat => PathHeartbeat::decode(bytes).map(Control::PathHeartbeat),
    }
}

/// The error of the dispatcher, which must equal the control decoder's for
/// any datagram whose first word selects a control.
fn error_of(bytes: &[u8]) -> ControlError {
    let dispatched = classify(bytes).unwrap_err();
    assert_eq!(Control::decode(bytes).unwrap_err(), dispatched);
    dispatched
}

#[test]
fn every_valid_vector_decodes_and_encodes_byte_for_byte() {
    for (name, bytes, control) in valid_vectors() {
        assert_eq!(Control::decode(bytes), Ok(control), "{name}");
        assert_eq!(classify(bytes), Ok(Datagram::Control(control)), "{name}");
        assert_eq!(decode_kind(control.kind(), bytes), Ok(control), "{name}");
        assert_eq!(control.encoded_length(), Some(bytes.len()), "{name}");

        let mut out = [0xEEu8; MAX_CONTROL_LENGTH + 8];
        assert_eq!(control.encode(&mut out), Ok(bytes.len()), "{name}");
        assert_eq!(&out[..bytes.len()], bytes, "{name}");
        assert!(out[bytes.len()..].iter().all(|b| *b == 0xEE), "{name}");

        // Insufficient capacity: an error and nothing written.
        let mut short = vec![0xEEu8; bytes.len() - 1];
        assert_eq!(
            control.encode(&mut short),
            Err(ControlError::BufferTooShort {
                required: bytes.len(),
                available: bytes.len() - 1,
            }),
            "{name}"
        );
        assert!(short.iter().all(|b| *b == 0xEE), "{name}");
    }
}

#[test]
fn per_kind_encoders_match_the_vectors() {
    let mut out = [0u8; MAX_CONTROL_LENGTH];
    for (name, bytes, control) in valid_vectors() {
        let length = match control {
            Control::SetupAnnounce(m) => m.encode(&mut out),
            Control::SetupAnswer(m) => m.encode(&mut out),
            Control::Challenge(m) => m.encode(&mut out),
            Control::Solicit(m) => m.encode(&mut out),
            Control::Status(m) => m.encode(&mut out),
            Control::Nak(m) => m.encode(&mut out),
            Control::NakReply(m) => m.encode(&mut out),
            Control::Unbound(m) => m.encode(&mut out),
            Control::Rttm(m) => m.encode(&mut out),
            Control::PathHeartbeat(m) => m.encode(&mut out),
        }
        .unwrap();
        assert_eq!(&out[..length], bytes, "{name}");
    }
}

#[test]
fn a_per_kind_decoder_refuses_every_other_kind() {
    for (name, bytes, control) in valid_vectors() {
        for kind in ControlKind::ALL {
            let same_codec = kind == control.kind()
                || matches!(
                    (kind, control.kind()),
                    (ControlKind::RttmRequest, ControlKind::RttmReply)
                        | (ControlKind::RttmReply, ControlKind::RttmRequest)
                );
            let decoded = decode_kind(kind, bytes);
            if same_codec {
                assert_eq!(decoded, Ok(control), "{name} as {kind:?}");
            } else {
                assert_eq!(
                    decoded,
                    Err(ControlError::WrongKind {
                        code: control.kind().frame_type().code()
                    }),
                    "{name} as {kind:?}"
                );
            }
        }
    }
    // A data datagram is not a control.
    assert_eq!(
        Control::decode(HEARTBEAT.as_flattened()),
        Err(ControlError::WrongKind { code: 1 })
    );
    assert_eq!(
        Nak::decode(HEARTBEAT.as_flattened()),
        Err(ControlError::WrongKind { code: 1 })
    );
}

#[test]
fn setup_mutations() {
    let v1 = V_SETUP_1.as_flattened();
    let v2 = V_SETUP_2.as_flattened();
    let cases: [(&str, Vec<u8>, ControlError); 9] = [
        (
            "X-SETUP-1",
            mutate(v2, 0x08, &[0x01]),
            ControlError::InvalidLength,
        ),
        (
            "X-SETUP-2",
            mutate(v1, 0x38, &[0x00, 0x80, 0x01, 0x00]),
            ControlError::InvalidValue,
        ),
        (
            "X-SETUP-3",
            mutate(v2, 0x58, &[0; 16]),
            ControlError::InvalidValue,
        ),
        (
            "X-SETUP-4",
            mutate(v2, 0x70, &[0x10]),
            ControlError::InvalidPosition,
        ),
        (
            "X-SETUP-5",
            mutate(v1, 0x09, &[0x05]),
            ControlError::InvalidCount,
        ),
        (
            "X-SETUP-6",
            mutate(v1, 0x09, &[0x00]),
            ControlError::InvalidCount,
        ),
        (
            "X-SETUP-7",
            mutate(v1, 0x05, &[0x10]),
            ControlError::ReservedBits,
        ),
        (
            "X-SETUP-8",
            mutate(v1, 0x14, &[0x01]),
            ControlError::ReservedBits,
        ),
        (
            "X-SETUP-9",
            mutate(v1, 0x18, &[0; 16]),
            ControlError::InvalidIdentity,
        ),
    ];
    for (name, bytes, expected) in cases {
        assert_eq!(error_of(&bytes), expected, "{name}");
    }

    // X-SETUP-10 and X-SETUP-12: boundaries are valid.
    let mtu_256 = mutate(v1, 0x40, &[0x00, 0x01, 0x00, 0x00]);
    let Ok(Control::SetupAnnounce(setup)) = Control::decode(&mtu_256) else {
        panic!("X-SETUP-10");
    };
    assert_eq!(setup.term.mtu, MIN_MTU);
    // X-SETUP-11.
    assert_eq!(
        error_of(&mutate(v1, 0x40, &[0xFF, 0x00, 0x00, 0x00])),
        ControlError::InvalidValue
    );
    let term_2_30 = mutate(v1, 0x38, &[0x00, 0x00, 0x00, 0x40]);
    let Ok(Control::SetupAnnounce(setup)) = Control::decode(&term_2_30) else {
        panic!("X-SETUP-12");
    };
    assert_eq!(setup.term.term_length, MAX_TERM_LENGTH);
    // Just past the boundaries: 2^31 and 2^15 (below 64 KiB).
    assert_eq!(
        error_of(&mutate(v1, 0x38, &[0x00, 0x00, 0x00, 0x80])),
        ControlError::InvalidValue
    );
    assert_eq!(
        error_of(&mutate(v1, 0x38, &[0x00, 0x80, 0x00, 0x00])),
        ControlError::InvalidValue
    );
}

#[test]
fn mtu_8192_is_valid_and_8193_is_not() {
    let v1 = V_SETUP_1.as_flattened();
    // 8192 = 0x2000.
    let Ok(Control::SetupAnnounce(setup)) =
        Control::decode(&mutate(v1, 0x40, &[0x00, 0x20, 0x00, 0x00]))
    else {
        panic!("mtu 8192");
    };
    assert_eq!(setup.term.mtu, MAX_MTU);
    assert_eq!(
        error_of(&mutate(v1, 0x40, &[0x01, 0x20, 0x00, 0x00])),
        ControlError::InvalidValue
    );
}

#[test]
fn rsp_setup_mutations() {
    let v1 = V_RSP_1.as_flattened();
    let v2 = V_RSP_2.as_flattened();
    let cases: [(&str, Vec<u8>, ControlError); 6] = [
        (
            "X-RSP-1",
            mutate(v1, 0x08, &[0x02]),
            ControlError::InvalidLength,
        ),
        (
            "X-RSP-2",
            mutate(v2, 0x08, &[0x01]),
            ControlError::InvalidLength,
        ),
        (
            "X-RSP-3",
            mutate(v1, 0x30, &[0; 8]),
            ControlError::InvalidIdentity,
        ),
        (
            "X-RSP-4",
            mutate(v2, 0x18, &[0; 16]),
            ControlError::InvalidIdentity,
        ),
        (
            "X-RSP-5",
            mutate(v2, 0x09, &[0x01]),
            ControlError::InvalidCount,
        ),
        (
            "X-RSP-6",
            mutate(v1, 0x08, &[0x03]),
            ControlError::InvalidVariant,
        ),
    ];
    for (name, bytes, expected) in cases {
        assert_eq!(error_of(&bytes), expected, "{name}");
    }
}

#[test]
fn sm_mutations() {
    let v1 = V_SM_1.as_flattened();
    let cases: [(&str, Vec<u8>, ControlError); 6] = [
        (
            "X-SM-1",
            mutate(v1, 0x60, &[0x01]),
            ControlError::InvalidPosition,
        ),
        (
            "X-SM-2",
            mutate(v1, 0x64, &[0x01]),
            ControlError::ReservedBits,
        ),
        (
            "X-SM-3",
            mutate(v1, 0x09, &[0x02]),
            ControlError::InvalidLength,
        ),
        (
            "X-SM-4",
            mutate(v1, 0x48, &[0; 8]),
            ControlError::InvalidIdentity,
        ),
        (
            "X-SM-6",
            mutate(v1, 0x60, &[0x20, 0x00, 0x00, 0x20]),
            ControlError::InvalidPosition,
        ),
        (
            "X-SM-8",
            mutate(v1, 0x58, &[0x20, 0, 0, 0, 0, 0, 0, 0x20]),
            ControlError::InvalidPosition,
        ),
    ];
    for (name, bytes, expected) in cases {
        assert_eq!(error_of(&bytes), expected, "{name}");
    }
    // X-SM-5 and X-SM-7: boundaries are valid syntax (the owner's context
    // check rejects them for 64 KiB terms).
    let Ok(Control::Status(sm)) = Control::decode(&mutate(v1, 0x60, &[0x00, 0x00, 0x00, 0x20]))
    else {
        panic!("X-SM-5");
    };
    assert_eq!(sm.lanes.as_slice()[0].window, MAX_WINDOW);
    let Ok(Control::Status(sm)) = Control::decode(&mutate(v1, 0x58, &[0, 0, 0, 0, 0, 0, 0, 0x20]))
    else {
        panic!("X-SM-7");
    };
    assert_eq!(sm.lanes.as_slice()[0].consumption, MAX_POSITION);
    // X-SM-9: V-SM-2 truncated to 151 bytes.
    let v2 = V_SM_2.as_flattened();
    assert_eq!(error_of(&v2[..151]), ControlError::Truncated);
    // The owner computes the lane 0 edge with checked arithmetic.
    let lane0 = sm_lane0(v1);
    assert_eq!(
        lane0.consumption.checked_add(u64::from(lane0.window)),
        Some(234_496)
    );
}

fn sm_lane0(bytes: &[u8]) -> LaneStatus {
    let Ok(Control::Status(sm)) = Control::decode(bytes) else {
        panic!("not an SM");
    };
    sm.lanes.get(Lane::ZERO).unwrap()
}

#[test]
fn nak_mutations() {
    let v1 = V_NAK_1.as_flattened();
    let cases: [(&str, Vec<u8>, ControlError); 4] = [
        (
            "X-NAK-1",
            mutate(v1, 0x54, &[0; 4]),
            ControlError::InvalidPosition,
        ),
        (
            "X-NAK-2",
            mutate(v1, 0x50, &[0x04]),
            ControlError::InvalidValue,
        ),
        (
            "X-NAK-3",
            mutate(v1, 0x58, &[0x10]),
            ControlError::InvalidPosition,
        ),
        (
            "X-NAK-4",
            mutate(v1, 0x51, &[0x01]),
            ControlError::ReservedBits,
        ),
    ];
    for (name, bytes, expected) in cases {
        assert_eq!(error_of(&bytes), expected, "{name}");
    }
    // X-NAK-5: valid syntax, not term-bounded in context.
    let Ok(Control::Nak(nak)) = Control::decode(&mutate(v1, 0x58, &[0x00, 0xFC, 0x03, 0x00]))
    else {
        panic!("X-NAK-5");
    };
    assert_eq!(nak.range.start, 0x3FC00);
    assert!(nak.range.start % 65536 + u64::from(nak.range.length) > 65536);
    // X-NAK-6: lane 3 is valid syntax.
    let Ok(Control::Nak(nak)) = Control::decode(&mutate(v1, 0x50, &[0x03])) else {
        panic!("X-NAK-6");
    };
    assert_eq!(nak.range.lane.get(), 3);
    // X-NAK-7: two NAKs in one datagram.
    let mut twice = v1.to_vec();
    twice.extend_from_slice(v1);
    assert_eq!(error_of(&twice), ControlError::InvalidGrouping);
    // Length bounds: 2^30 is valid, 2^30 + 32 and an unaligned length are
    // not; start + length past 2^61 is refused.
    assert!(Control::decode(&mutate(v1, 0x54, &[0x00, 0x00, 0x00, 0x40])).is_ok());
    assert_eq!(
        error_of(&mutate(v1, 0x54, &[0x20, 0x00, 0x00, 0x40])),
        ControlError::InvalidPosition
    );
    assert_eq!(
        error_of(&mutate(v1, 0x54, &[0x10, 0x00, 0x00, 0x00])),
        ControlError::InvalidPosition
    );
    let at_end = mutate(v1, 0x58, &(MAX_POSITION - 2048).to_le_bytes());
    assert!(Control::decode(&at_end).is_ok());
    let past_end = mutate(v1, 0x58, &(MAX_POSITION - 2016).to_le_bytes());
    assert_eq!(error_of(&past_end), ControlError::InvalidPosition);
}

#[test]
fn err_mutations() {
    let v1 = V_ERR_1.as_flattened();
    let v2 = V_ERR_2.as_flattened();
    let cases: [(&str, Vec<u8>, ControlError); 9] = [
        (
            "X-ERR-1",
            mutate(v1, 0x60, &[0x01, 0x00]),
            ControlError::InvalidValue,
        ),
        (
            "X-ERR-2",
            mutate(v1, 0x60, &[0x03]),
            ControlError::InvalidValue,
        ),
        (
            "X-ERR-4",
            mutate(v1, 0x60, &[0x00, 0x00]),
            ControlError::InvalidValue,
        ),
        (
            "X-ERR-5",
            mutate(v1, 0x60, &[0x04, 0x00]),
            ControlError::InvalidValue,
        ),
        (
            "X-ERR-6",
            mutate(v2, 0x0C, &[0x01]),
            ControlError::ReservedBits,
        ),
        (
            "X-ERR-7",
            mutate(v2, 0x1C, &[0x01]),
            ControlError::InvalidValue,
        ),
        (
            "X-ERR-8",
            mutate(v2, 0x1D, &[0x02]),
            ControlError::InvalidValue,
        ),
        (
            "X-ERR-9",
            mutate(v1, 0x62, &[0x01]),
            ControlError::ReservedBits,
        ),
        (
            "X-ERR-10",
            mutate(v1, 0x50, &[0x04]),
            ControlError::InvalidValue,
        ),
    ];
    for (name, bytes, expected) in cases {
        assert_eq!(error_of(&bytes), expected, "{name}");
    }
    // X-ERR-3: reason 3 with a zero detail.
    let mut x3 = mutate(v1, 0x60, &[0x03]);
    x3[0x68..0x70].fill(0);
    assert_eq!(
        Control::decode(&x3),
        Ok(Control::NakReply(NakReply::answering(
            &v_nak(),
            NakReplyReason::RangeInvalid
        )))
    );
    // Reason 2 with an unaligned detail is a position error.
    assert_eq!(
        error_of(&mutate(v1, 0x68, &[0x10])),
        ControlError::InvalidPosition
    );
    // Bytes 0x38..0x5F of V-ERR-1 equal those of V-NAK-1.
    assert_eq!(&v1[0x38..0x60], &V_NAK_1.as_flattened()[0x38..0x60]);
    // UNBOUND: rejected version 0, min 0, and a range without 1.
    assert_eq!(
        error_of(&mutate(v2, 0x1C, &[0x00])),
        ControlError::InvalidValue
    );
    assert_eq!(
        error_of(&mutate(v2, 0x1D, &[0x00])),
        ControlError::InvalidValue
    );
    assert_eq!(
        error_of(&mutate(v2, 0x1C, &[0x05, 0x02, 0x03])),
        ControlError::InvalidValue
    );
    assert_eq!(
        error_of(&mutate(v2, 0x18, &[0x02])),
        ControlError::InvalidValue
    );
    // A supported range of 1 to 3 rejecting version 4 is valid.
    assert!(Control::decode(&mutate(v2, 0x1C, &[0x04, 0x01, 0x03])).is_ok());
}

#[test]
fn rttm_mutations() {
    let v1 = V_RTTM_1.as_flattened();
    let v2 = V_RTTM_2.as_flattened();
    assert_eq!(
        error_of(&mutate(v1, 0x58, &[0x01])),
        ControlError::InvalidValue
    );
    assert_eq!(
        error_of(&mutate(v1, 0x50, &[0; 8])),
        ControlError::InvalidValue
    );
    assert_eq!(
        error_of(&mutate(v2, 0x08, &[0x03])),
        ControlError::InvalidVariant
    );
    // V-RTTM-2 differs from V-RTTM-1 only in rows 08 and 58.
    let mut from_v1 = mutate(v1, 0x08, &[0x02]);
    from_v1[0x58..0x60].copy_from_slice(&[0xC4, 0x09, 0, 0, 0, 0, 0, 0]);
    assert_eq!(from_v1, v2);
}

#[test]
fn path_heartbeat_mutations() {
    let v1 = V_PHB_1.as_flattened();
    let mut trailing = v1.to_vec();
    trailing.push(0);
    assert_eq!(error_of(&trailing), ControlError::InvalidGrouping);
    let mut x2 = mutate(v1, 0x00, &[0x39]);
    x2.push(0);
    assert_eq!(error_of(&x2), ControlError::InvalidLength);
    assert_eq!(
        error_of(&mutate(v1, 0x00, &[0x40])),
        ControlError::Truncated
    );
}

#[test]
fn dispatcher_vectors() {
    let phb = V_PHB_1.as_flattened();
    let nak = V_NAK_1.as_flattened();
    let heartbeat = HEARTBEAT.as_flattened();
    let unsupported = |first: [u8; 8], length: usize| {
        let mut bytes = first.to_vec();
        bytes.resize(length, 0);
        bytes
    };

    // D-1.
    let d1 = [0x48, 0x00, 0x00, 0x00, 0x01, 0x00];
    assert_eq!(classify(&d1), Err(ControlError::Truncated));
    // D-2.
    assert_eq!(
        classify(&mutate(phb, 0x04, &[0x00])),
        Err(ControlError::InvalidVersion)
    );
    // D-3: answered by V-ERR-2.
    let d3 = unsupported([0x40, 0, 0, 0, 0x02, 0, 0x03, 0], 64);
    let error = classify(&d3).unwrap_err();
    assert_eq!(
        error,
        ControlError::UnsupportedVersion {
            version: 2,
            frame_type: 3,
            frame_length: 64,
        }
    );
    let reply = unbound_reply(&error, d3.len()).unwrap();
    let mut out = [0u8; 40];
    assert_eq!(reply.encode(&mut out), Ok(40));
    assert_eq!(&out, V_ERR_2.as_flattened());
    // D-4: an ERR of any version is never answered.
    let d4 = unsupported([0x40, 0, 0, 0, 0x02, 0, 0x04, 0], 64);
    let error = classify(&d4).unwrap_err();
    assert_eq!(
        error,
        ControlError::UnsupportedVersion {
            version: 2,
            frame_type: 4,
            frame_length: 64,
        }
    );
    assert_eq!(unbound_reply(&error, d4.len()), None);
    // D-5: shorter than the reply.
    let d5 = unsupported([0x10, 0, 0, 0, 0x02, 0, 0x03, 0], 16);
    let error = classify(&d5).unwrap_err();
    assert!(matches!(error, ControlError::UnsupportedVersion { .. }));
    assert_eq!(unbound_reply(&error, d5.len()), None);
    assert!(unbound_reply(&error, 39).is_none());
    assert!(unbound_reply(&error, 40).is_some());
    // D-6 to D-10, none answered.
    let cases: [(&str, Vec<u8>, ControlError); 5] = [
        (
            "D-6",
            mutate(phb, 0x06, &[0x11, 0x00]),
            ControlError::GatedType {
                frame_type: FrameType::Guard,
            },
        ),
        (
            "D-7",
            mutate(phb, 0x06, &[0x09, 0x00]),
            ControlError::UnknownType { code: 9 },
        ),
        (
            "D-8",
            [nak, heartbeat].concat(),
            ControlError::InvalidGrouping,
        ),
        (
            "D-9",
            [heartbeat, phb].concat(),
            ControlError::InvalidGrouping,
        ),
        (
            "D-10",
            mutate(phb, 0x00, &[0x00, 0x00, 0x00, 0x80]),
            ControlError::InvalidLength,
        ),
    ];
    for (name, bytes, expected) in cases {
        let error = classify(&bytes).unwrap_err();
        assert_eq!(error, expected, "{name}");
        assert_eq!(unbound_reply(&error, bytes.len()), None, "{name}");
    }
    // Every other error category gets no reply either.
    for error in [
        ControlError::Truncated,
        ControlError::InvalidVersion,
        ControlError::InvalidGrouping,
        ControlError::ReservedBits,
        ControlError::InvalidValue,
    ] {
        assert_eq!(unbound_reply(&error, 1000), None);
    }
}

#[test]
fn gated_types_are_refused_before_their_body() {
    for frame_type in [
        FrameType::Guard,
        FrameType::SessionAbort,
        FrameType::SessionAbortAck,
    ] {
        let code = frame_type.code().to_le_bytes();
        // Any length, even one too short for a body, and any later byte.
        for bytes in [
            vec![0x08, 0, 0, 0, 1, 0, code[0], code[1]],
            vec![0xFF, 0xFF, 0xFF, 0xFF, 1, 0xFF, code[0], code[1], 0xAB],
            mutate(V_PHB_1.as_flattened(), 6, &code),
        ] {
            let error = ControlError::GatedType { frame_type };
            assert_eq!(classify(&bytes), Err(error));
            assert_eq!(Control::decode(&bytes), Err(error));
            assert_eq!(PathHeartbeat::decode(&bytes), Err(error));
            assert_eq!(unbound_reply(&error, bytes.len()), None);
        }
    }
}

#[test]
fn vectors_parse_at_every_unaligned_offset() {
    for (name, bytes, control) in valid_vectors() {
        let mut storage = vec![0xA5u8; bytes.len() + 8];
        for offset in 0..8 {
            storage[offset..offset + bytes.len()].copy_from_slice(bytes);
            let slice = &storage[offset..offset + bytes.len()];
            assert_eq!(Control::decode(slice), Ok(control), "{name} at {offset}");
            assert_eq!(
                classify(slice),
                Ok(Datagram::Control(control)),
                "{name} at {offset}"
            );
        }
    }
}

#[test]
fn every_truncation_and_extension_is_refused() {
    for (name, bytes, _) in valid_vectors() {
        for length in 0..bytes.len() {
            assert_eq!(
                classify(&bytes[..length]),
                Err(ControlError::Truncated),
                "{name} cut to {length}"
            );
        }
        for extra in 1..=40 {
            let mut longer = bytes.to_vec();
            longer.resize(bytes.len() + extra, 0);
            assert_eq!(
                classify(&longer),
                Err(ControlError::InvalidGrouping),
                "{name} plus {extra}"
            );
        }
    }
}

#[test]
fn every_reserved_and_flag_bit_is_refused() {
    for (name, bytes, control) in valid_vectors() {
        let mut checked = 0;
        for (start, end) in control.kind().reserved(control.count()) {
            for at in start..end {
                for bit in 0..8 {
                    let mut bad = bytes.to_vec();
                    bad[at] ^= 1 << bit;
                    assert_eq!(
                        error_of(&bad),
                        ControlError::ReservedBits,
                        "{name} byte {at:#x} bit {bit}"
                    );
                    checked += 1;
                }
            }
        }
        assert!(checked >= 48, "{name}");
        for bit in 0..8 {
            let bad = mutate(bytes, 5, &[1 << bit]);
            assert_eq!(
                error_of(&bad),
                ControlError::ReservedBits,
                "{name} flag {bit}"
            );
        }
    }
}

#[test]
fn every_version_type_variant_count_and_length_is_classified() {
    for (name, bytes, control) in valid_vectors() {
        let first_word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let frame_length = first_word(0) as i32;
        for version in 0..=u8::MAX {
            let bad = mutate(bytes, 4, &[version]);
            let expected = match version {
                0 => Err(ControlError::InvalidVersion),
                1 => Ok(Datagram::Control(control)),
                _ => Err(ControlError::UnsupportedVersion {
                    version,
                    frame_type: control.kind().frame_type().code(),
                    frame_length,
                }),
            };
            assert_eq!(classify(&bad), expected, "{name} version {version}");
        }
        for code in 0..=u16::MAX {
            let bad = mutate(bytes, 6, &code.to_le_bytes());
            let result = classify(&bad);
            match FrameType::try_from_code(code) {
                Err(_) => assert_eq!(result, Err(ControlError::UnknownType { code })),
                Ok(
                    frame_type @ (FrameType::Guard
                    | FrameType::SessionAbort
                    | FrameType::SessionAbortAck),
                ) => assert_eq!(result, Err(ControlError::GatedType { frame_type })),
                Ok(_) => {
                    // Another group or kind: never this vector's value,
                    // and anything accepted re-encodes to the same bytes.
                    if let Ok(Datagram::Control(other)) = result {
                        assert_eq!(code, control.kind().frame_type().code());
                        assert_eq!(other, control);
                    }
                }
            }
        }
        for variant in 0..=u8::MAX {
            let bad = mutate(bytes, 8, &[variant]);
            let result = Control::decode(&bad);
            match ControlKind::from_parts(control.kind().frame_type(), variant) {
                None => assert_eq!(result, Err(ControlError::InvalidVariant), "{name}"),
                Some(kind) if kind == control.kind() => assert_eq!(result, Ok(control)),
                Some(kind) if kind.length(control.count()) == Some(bytes.len()) => {
                    // RTTM REQUEST and REPLY share a size: a REQUEST read as
                    // a REPLY is valid, a REPLY with a delay is not a REQUEST.
                    match result {
                        Ok(other) => {
                            let mut out = [0u8; MAX_CONTROL_LENGTH];
                            assert_eq!(other.encode(&mut out), Ok(bad.len()));
                            assert_eq!(&out[..bad.len()], &bad[..], "{name} {variant}");
                        }
                        Err(error) => assert_eq!(error, ControlError::InvalidValue, "{name}"),
                    }
                }
                Some(kind) => {
                    let expected = if kind.accepts_count(control.count()) {
                        ControlError::InvalidLength
                    } else {
                        ControlError::InvalidCount
                    };
                    assert_eq!(result, Err(expected), "{name} variant {variant}");
                }
            }
        }
        for count in 0..=u8::MAX {
            let bad = mutate(bytes, 9, &[count]);
            let result = Control::decode(&bad);
            match control.kind().length(count) {
                None => assert_eq!(result, Err(ControlError::InvalidCount), "{name} {count}"),
                Some(length) if length == bytes.len() => {
                    // Only ANNOUNCE has a count that keeps its size.
                    let decoded = result.unwrap();
                    assert_eq!(decoded.count(), count, "{name}");
                    let mut out = [0u8; MAX_CONTROL_LENGTH];
                    assert_eq!(decoded.encode(&mut out), Ok(bad.len()));
                    assert_eq!(&out[..bad.len()], &bad[..]);
                }
                Some(_) => assert_eq!(result, Err(ControlError::InvalidLength), "{name} {count}"),
            }
        }
        for length in [i32::MIN, -1, 0] {
            let bad = mutate(bytes, 0, &length.to_le_bytes());
            assert_eq!(
                error_of(&bad),
                ControlError::InvalidLength,
                "{name} {length}"
            );
        }
        for length in 1..=bytes.len() + 8 {
            let bad = mutate(bytes, 0, &(length as i32).to_le_bytes());
            let expected = match length.cmp(&bytes.len()) {
                core::cmp::Ordering::Greater => ControlError::Truncated,
                core::cmp::Ordering::Less => ControlError::InvalidGrouping,
                core::cmp::Ordering::Equal => continue,
            };
            assert_eq!(error_of(&bad), expected, "{name} length {length}");
        }
    }
}

#[test]
fn a_frame_length_below_the_header_is_an_invalid_length() {
    // Exactly as long as the datagram, flags clear, shorter than 24 bytes.
    for length in 8..24u8 {
        let mut bytes = vec![0u8; usize::from(length)];
        bytes[..8].copy_from_slice(&[length, 0, 0, 0, 1, 0, 0x02, 0]);
        assert_eq!(error_of(&bytes), ControlError::InvalidLength);
        bytes[5] = 0x01;
        assert_eq!(error_of(&bytes), ControlError::ReservedBits);
    }
}

#[test]
fn sizes_and_reply_ratios() {
    use ControlKind::*;
    let fixed = [
        (SetupAnnounce, 72),
        (Challenge, 88),
        (Solicit, 56),
        (Nak, 96),
        (NakReply, 112),
        (Unbound, 40),
        (RttmRequest, 96),
        (RttmReply, 96),
        (PathHeartbeat, 56),
    ];
    for (kind, length) in fixed {
        let count = u8::from(kind == SetupAnnounce);
        assert_eq!(kind.length(count), Some(length), "{kind:?}");
    }
    let answers: Vec<_> = (1..=4).map(|n| SetupAnswer.length(n).unwrap()).collect();
    assert_eq!(answers, [112, 120, 128, 136]);
    let status: Vec<_> = (1..=4).map(|n| Status.length(n).unwrap()).collect();
    assert_eq!(status, [104, 120, 136, 152]);
    let largest = ControlKind::ALL
        .iter()
        .flat_map(|kind| (0..=4).filter_map(|n| kind.length(n)))
        .max();
    assert_eq!(largest, Some(MAX_CONTROL_LENGTH));
    assert!(MAX_CONTROL_LENGTH < MIN_MTU as usize);

    // Section 7.7: CHALLENGE answers a 72-byte ANNOUNCE, SOLICIT a datagram
    // of at least 32 bytes, UNBOUND one of at least its own 40 bytes.
    let challenge = Challenge.length(0).unwrap();
    let solicit = Solicit.length(0).unwrap();
    assert_eq!((challenge, SetupAnnounce.length(1).unwrap()), (88, 72));
    assert!(challenge * 100 <= 72 * 123);
    assert!(solicit * 4 <= HEADER_LENGTH as usize * 7);
    assert_eq!(Unbound.length(0), Some(40));
}

#[test]
fn raw_term_ids_roll_over_inside_the_vectors() {
    use karyos_sys::term::{TermCount, TermId};
    // Join 200704 with initial_term_id -2 and 64 KiB terms: term count 3,
    // offset 4096, raw term id 1.
    let join = 200_704u64;
    let term_length = u64::from(TERM.term_length);
    assert_eq!((join / term_length, join % term_length), (3, 4096));
    let initial = TermId::new(TERM.initial_term_id as u32);
    let term = initial.advanced_by(TermCount::try_new(3).unwrap());
    assert_eq!(term.get(), 1);
    assert_eq!(term.count_from(initial).unwrap().get(), 3);
}

#[test]
fn lanes_hold_one_to_four_entries() {
    assert_eq!(Lanes::<u64>::new(&[]), Err(ControlError::InvalidCount));
    assert_eq!(Lanes::new(&[0u64; 5]), Err(ControlError::InvalidCount));
    let lanes = Lanes::new(&[32u64, 64, 96]).unwrap();
    assert_eq!(lanes.count(), 3);
    assert_eq!(lanes.as_slice(), &[32, 64, 96]);
    assert_eq!(lanes.get(Lane::try_new(2).unwrap()), Some(96));
    assert_eq!(lanes.get(Lane::try_new(3).unwrap()), None);
}

#[test]
fn invalid_values_are_not_encoded() {
    let mut out = [0xEEu8; MAX_CONTROL_LENGTH];
    let announce = |lane_count, identity, term| {
        Control::SetupAnnounce(SetupAnnounce {
            alias: ALIAS,
            identity,
            term,
            lane_count,
        })
    };
    let zero_driver = Identity {
        driver_id: [0, 0],
        ..IDENTITY
    };
    let bad_term = TermParams { mtu: 255, ..TERM };
    let cases = [
        (announce(0, IDENTITY, TERM), ControlError::InvalidCount),
        (announce(5, IDENTITY, TERM), ControlError::InvalidCount),
        (
            announce(1, zero_driver, TERM),
            ControlError::InvalidIdentity,
        ),
        (announce(1, IDENTITY, bad_term), ControlError::InvalidValue),
        (
            Control::Solicit(RspSolicit {
                alias: ALIAS,
                challenge: ChallengeBlock {
                    nonce: [0, 0],
                    ..CHALLENGE
                },
            }),
            ControlError::InvalidValue,
        ),
        (
            Control::Nak(Nak {
                range: NakRange {
                    length: 0,
                    ..nak_range()
                },
                ..v_nak()
            }),
            ControlError::InvalidPosition,
        ),
        (
            Control::NakReply(NakReply::answering(
                &v_nak(),
                NakReplyReason::RangeUnavailable { lowest_retained: 1 },
            )),
            ControlError::InvalidPosition,
        ),
        (
            Control::Unbound(Unbound {
                rejected_type: 3,
                rejected_version: 1,
                min_supported: 1,
                max_supported: 1,
                rejected_length: 64,
            }),
            ControlError::InvalidValue,
        ),
        (
            Control::Rttm(Rttm {
                alias: ALIAS,
                identity: IDENTITY,
                receiver: RECEIVER,
                probe_id: 0,
                kind: RttmKind::Request,
            }),
            ControlError::InvalidValue,
        ),
        (
            Control::Status(StatusMessage {
                alias: ALIAS,
                identity: IDENTITY,
                receiver: Receiver {
                    receiver_id: 0,
                    ..RECEIVER
                },
                group_tag: 0,
                lanes: Lanes::new(&[LaneStatus::default()]).unwrap(),
            }),
            ControlError::InvalidIdentity,
        ),
    ];
    for (control, expected) in cases {
        assert_eq!(control.encode(&mut out), Err(expected), "{control:?}");
        assert!(out.iter().all(|b| *b == 0xEE));
    }
}

/// A DATA record header: `frame_length`, flags, type, alias, lane in flags.
fn record(frame_type: FrameType, frame_length: i32, flags: u8, alias: Alias) -> Vec<u8> {
    let mut bytes = vec![0u8; 32];
    bytes[0..4].copy_from_slice(&frame_length.to_le_bytes());
    bytes[4] = 1;
    bytes[5] = flags;
    bytes[6..8].copy_from_slice(&frame_type.code().to_le_bytes());
    bytes[12..16].copy_from_slice(&alias.session_id.to_le_bytes());
    bytes[16..20].copy_from_slice(&alias.stream_id.to_le_bytes());
    bytes
}

/// A DATA record with `payload` bytes, padded to the 32-byte stride when
/// `pad` is set.
fn data(payload: usize, flags: u8, alias: Alias, pad: bool) -> Vec<u8> {
    let length = 32 + payload;
    let mut bytes = record(FrameType::Data, length as i32, flags, alias);
    bytes.resize(length, 0x5A);
    if pad {
        bytes.resize(length.next_multiple_of(32), 0);
    }
    bytes
}

#[test]
fn data_groups() {
    let heartbeat = HEARTBEAT.as_flattened();
    let Ok(Datagram::Heartbeat(beat)) = classify(heartbeat) else {
        panic!("heartbeat");
    };
    assert_eq!(
        (beat.alias(), beat.lane(), beat.bytes()),
        (ALIAS, Lane::ZERO, heartbeat)
    );

    // A traced heartbeat is 96 bytes.
    let mut traced = record(FrameType::Data, 96, 0x08, ALIAS);
    traced.resize(96, 0);
    assert!(matches!(classify(&traced), Ok(Datagram::Heartbeat(_))));
    assert_eq!(classify(&traced[..95]), Err(ControlError::Truncated));

    // A batch: DATA, PAD and ABORTED of lane 2; the last DATA may omit its
    // padding entirely.
    let lane2 = 0x20;
    let batch = [
        data(5, lane2 | 0x03, ALIAS, true),
        record(FrameType::Aborted, 32, lane2, ALIAS),
        data(40, lane2 | 0x03, ALIAS, true),
        record(FrameType::Pad, 32, lane2, ALIAS),
        data(1, lane2 | 0x03, ALIAS, false),
    ]
    .concat();
    let Ok(Datagram::DataBatch(group)) = classify(&batch) else {
        panic!("batch");
    };
    assert_eq!((group.alias(), group.lane().get()), (ALIAS, 2));
    // With full padding too.
    let padded = [data(1, 0x03, ALIAS, true), data(1, 0x03, ALIAS, true)].concat();
    assert!(matches!(classify(&padded), Ok(Datagram::DataBatch(_))));
    // A single PAD or ABORTED record is a batch.
    for frame_type in [FrameType::Pad, FrameType::Aborted] {
        let one = record(frame_type, 32, 0, ALIAS);
        assert!(matches!(classify(&one), Ok(Datagram::DataBatch(_))));
        let mut long = one.clone();
        long[0] = 64;
        long.resize(64, 0);
        assert_eq!(classify(&long), Err(ControlError::InvalidLength));
    }

    let other = Alias {
        session_id: 1,
        ..ALIAS
    };
    let stream = Alias {
        stream_id: 1,
        ..ALIAS
    };
    let first = data(5, 0x03, ALIAS, true);
    let refused: [(&str, Vec<u8>, ControlError); 12] = [
        (
            "heartbeat in batch",
            [first.clone(), heartbeat.to_vec()].concat(),
            ControlError::InvalidGrouping,
        ),
        (
            "heartbeat first",
            [heartbeat.to_vec(), first.clone()].concat(),
            ControlError::InvalidGrouping,
        ),
        (
            "control in batch",
            [first.clone(), V_PHB_1.as_flattened().to_vec()].concat(),
            ControlError::InvalidGrouping,
        ),
        (
            "second session",
            [first.clone(), data(1, 0x03, other, false)].concat(),
            ControlError::InvalidGrouping,
        ),
        (
            "second stream",
            [first.clone(), data(1, 0x03, stream, false)].concat(),
            ControlError::InvalidGrouping,
        ),
        (
            "second lane",
            [first.clone(), data(1, 0x13, ALIAS, false)].concat(),
            ControlError::InvalidGrouping,
        ),
        (
            "partial padding",
            [data(5, 0x03, ALIAS, false), vec![0; 3]].concat(),
            ControlError::InvalidGrouping,
        ),
        (
            "short trailer",
            [first.clone(), vec![0; 7]].concat(),
            ControlError::Truncated,
        ),
        (
            "short record",
            [first.clone(), vec![0x20, 0, 0, 0, 1, 0, 0, 0]].concat(),
            ControlError::Truncated,
        ),
        (
            "past datagram",
            data(40, 0x03, ALIAS, false)[..60].to_vec(),
            ControlError::Truncated,
        ),
        (
            "below header",
            mutate(&first, 0, &[0x10]),
            ControlError::InvalidLength,
        ),
        (
            "reserved flags",
            mutate(&first, 5, &[0x43]),
            ControlError::ReservedBits,
        ),
    ];
    for (name, bytes, expected) in refused {
        assert_eq!(classify(&bytes), Err(expected), "{name}");
    }
    // A later record of another version is refused by its own first word.
    let later = [first.clone(), mutate(&data(1, 0x03, ALIAS, false), 4, &[2])].concat();
    assert_eq!(
        classify(&later),
        Err(ControlError::UnsupportedVersion {
            version: 2,
            frame_type: 1,
            frame_length: 33,
        })
    );
    // A batch the dispatcher groups is one the receive scanner can then
    // validate against the image: DATA at term offsets 0 and 64, then an
    // ABORTED extent of 64 at 128.
    let mut first_data = data(5, 0x03, ALIAS, true);
    let mut second_data = data(40, 0x03, ALIAS, true);
    second_data[8..12].copy_from_slice(&64i32.to_le_bytes());
    let mut aborted = record(FrameType::Aborted, 32, 0, ALIAS);
    aborted[8..12].copy_from_slice(&160i32.to_le_bytes());
    aborted[24..32].copy_from_slice(&64i64.to_le_bytes());
    first_data[8..12].copy_from_slice(&0i32.to_le_bytes());
    let image_batch = [first_data, second_data, aborted].concat();
    let Ok(Datagram::DataBatch(group)) = classify(&image_batch) else {
        panic!("image batch");
    };
    let params = karyos_sys::receive::ImageParams::new(
        ALIAS.session_id,
        ALIAS.stream_id,
        1,
        karyos_sys::sizing::TermLength::try_new(TERM.term_length).unwrap(),
        TERM.mtu,
    )
    .unwrap();
    let validated = karyos_sys::receive::ValidatedDatagram::parse(group.bytes(), &params).unwrap();
    assert_eq!(validated.items().count(), 3);
}
