// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::manifest::{ExtBase, ILLUSTRATIVE_E_MAX};
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

fn template(shape: Shape) -> Template {
    Template::new(shape, ILLUSTRATIVE_E_MAX, MtuRule::CountsEnvelope).unwrap()
}

#[test]
fn every_shape_composes_its_datagram_count_within_its_mtu() {
    for shape in SHAPES {
        let template = template(shape);
        let size = template.size;
        assert_eq!(
            template.datagrams(),
            size.datagrams_per_message as usize,
            "{shape}"
        );
        let mut bytes = vec![0_u8; template.len()];
        template.stamp(7, &mut bytes).unwrap();
        for index in 0..template.datagrams() {
            let datagram = template.datagram(&bytes, index).unwrap();
            // Every datagram leaves room for the envelope under the rule.
            assert!(
                datagram.len() as u32 + ILLUSTRATIVE_E_MAX <= size.mtu,
                "{shape}: datagram {index} of {} bytes",
                datagram.len()
            );
        }
    }
}

#[test]
fn w5_packs_its_frames_and_w6_fragments_its_message() {
    let w5 = template(Shape::W5);
    assert_eq!(w5.datagrams(), 1);
    assert_eq!(w5.frames(), 21, "floor((1408 - 64) / 64) frames of 32");
    let w6 = template(Shape::W6);
    assert_eq!(w6.datagrams(), 5);
    assert_eq!(w6.frames(), 5);
    let w6_late = Template::new(Shape::W6, 176, MtuRule::CountsEnvelope).unwrap();
    assert_eq!(
        w6_late.datagrams(),
        6,
        "manifest 2.0: 6 datagrams for E 161 to 176"
    );
    let w6_excl = Template::new(Shape::W6, 176, MtuRule::ExcludesEnvelope).unwrap();
    assert_eq!(w6_excl.datagrams(), 5);
}

#[test]
fn every_frame_carries_the_sequence_and_decodes() {
    for shape in SHAPES {
        let template = template(shape);
        let mut bytes = vec![0_u8; template.len()];
        template.stamp(0x0102_0304_0506_0708, &mut bytes).unwrap();
        for index in 0..template.datagrams() {
            let datagram = template.datagram(&bytes, index).unwrap();
            let header = FrameHeader::decode(datagram).unwrap();
            assert_eq!(header.reserved_value, 0x0102_0304_0506_0708, "{shape}");
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
    assert!(Template::new(Shape::W8(0), ILLUSTRATIVE_E_MAX, MtuRule::CountsEnvelope).is_err());
}
