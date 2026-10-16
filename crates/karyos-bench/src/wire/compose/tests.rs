// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::manifest::{ExtBase, ILLUSTRATIVE_E_MAX, W6_E_MAX_LIMIT};
use karyos_protocol::frame::FrameHeader;

const SHAPES: [Shape; 9] = [
    Shape::W1,
    Shape::W2,
    Shape::W3,
    Shape::W4,
    Shape::W5,
    Shape::W6,
    Shape::W7,
    Shape::W9(ExtBase::W1),
    Shape::W9(ExtBase::W4),
];

/// A template for a profile whose envelope is `E_max` itself.
fn template(shape: Shape) -> Template {
    Template::new(
        shape,
        ILLUSTRATIVE_E_MAX,
        ILLUSTRATIVE_E_MAX,
        MtuRule::CountsEnvelope,
    )
    .unwrap()
}

/// Every frame header of every datagram of a stamped message.
fn frame_headers(template: &Template, bytes: &[u8]) -> Vec<FrameHeader> {
    let mut headers = Vec::new();
    for index in 0..template.datagrams() {
        let mut rest = template.datagram(bytes, index).unwrap();
        while !rest.is_empty() {
            let header = FrameHeader::decode(rest).unwrap();
            let length = u32::try_from(header.word0.frame_length()).unwrap();
            let reserved = align_frame(length).unwrap() as usize;
            headers.push(header);
            rest = rest.get(reserved..).unwrap_or_default();
        }
    }
    headers
}

#[test]
fn every_shape_fits_its_budget_at_every_e_max_and_rule() {
    for rule in MtuRule::ALL {
        for e_max in [0, 32, 64, 96, 128, 160, 161, 176] {
            for envelope in [0, e_max] {
                for shape in SHAPES {
                    let template =
                        Template::new(shape, e_max, envelope, rule).unwrap_or_else(|error| {
                            panic!("{shape} E_max {e_max} E {envelope}: {error}")
                        });
                    let budget = rule.frame_budget(template.size.mtu, envelope).unwrap();
                    let mut bytes = vec![0_u8; template.len()];
                    template.stamp(7, &mut bytes).unwrap();
                    for index in 0..template.datagrams() {
                        let datagram = template.datagram(&bytes, index).unwrap();
                        assert!(
                            datagram.len() as u32 <= budget,
                            "{shape} E_max {e_max} E {envelope} {rule}: {} bytes",
                            datagram.len()
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn w6_follows_the_profile_envelope_not_e_max() {
    // E_max 176 with the envelope counted: a 176-byte profile needs 6
    // datagrams, the trusted baseline (envelope 0) still 5.
    let large = Template::new(Shape::W6, 176, 176, MtuRule::CountsEnvelope).unwrap();
    assert_eq!(large.datagrams(), 6);
    let trusted = Template::new(Shape::W6, 176, 0, MtuRule::CountsEnvelope).unwrap();
    assert_eq!(trusted.datagrams(), 5);
    let excluded = Template::new(Shape::W6, 176, 176, MtuRule::ExcludesEnvelope).unwrap();
    assert_eq!(excluded.datagrams(), 5);
    let at_160 = Template::new(Shape::W6, 160, 160, MtuRule::CountsEnvelope).unwrap();
    assert_eq!(at_160.datagrams(), 5);
}

#[test]
fn w6_above_its_e_max_limit_is_refused() {
    for rule in MtuRule::ALL {
        assert!(
            Template::new(Shape::W6, W6_E_MAX_LIMIT + 1, W6_E_MAX_LIMIT + 1, rule).is_err(),
            "{rule}"
        );
    }
}

#[test]
fn an_envelope_above_e_max_is_refused() {
    assert!(Template::new(Shape::W1, 64, 65, MtuRule::CountsEnvelope).is_err());
}

#[test]
fn w5_packs_its_frames_and_w6_fragments_its_message() {
    let w5 = template(Shape::W5);
    assert_eq!(w5.datagrams(), 1);
    assert_eq!(w5.frames(), 21, "floor((1408 - 64) / 64) frames of 32");
    let w6 = template(Shape::W6);
    assert_eq!(w6.datagrams(), 5);
    assert_eq!(w6.frames(), 5);
}

#[test]
fn every_frame_of_every_shape_carries_the_sequence() {
    for shape in SHAPES {
        let template = template(shape);
        let mut bytes = vec![0_u8; template.len()];
        template.stamp(0x0102_0304_0506_0708, &mut bytes).unwrap();
        let headers = frame_headers(&template, &bytes);
        assert_eq!(headers.len(), template.frames(), "{shape}");
        for header in headers {
            assert_eq!(header.reserved_value, 0x0102_0304_0506_0708, "{shape}");
        }
        for index in 0..template.datagrams() {
            let datagram = template.datagram(&bytes, index).unwrap();
            assert_eq!(sequence_of(datagram), Some(0x0102_0304_0506_0708));
        }
    }
}

#[test]
fn stamping_needs_the_exact_length() {
    let template = template(Shape::W1);
    let mut short = vec![0_u8; template.len() - 1];
    assert!(template.stamp(1, &mut short).is_err());
    assert!(!template.is_empty());
}

#[test]
fn w8_has_no_template() {
    assert!(
        Template::new(
            Shape::W8(0),
            ILLUSTRATIVE_E_MAX,
            ILLUSTRATIVE_E_MAX,
            MtuRule::CountsEnvelope
        )
        .is_err()
    );
}
