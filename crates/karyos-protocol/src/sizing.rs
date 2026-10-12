// SPDX-License-Identifier: Apache-2.0

//! Term lengths, MTU and message sizing, re-exported from `karyos_sys::sizing`
//! (SPEC.md §4, message sizes).

pub use karyos_sys::sizing::{
    DEFAULT_MTU, FragmentPlan, MAX_TERM_LENGTH, MIN_TERM_LENGTH, TermLength, align_frame,
    frame_length, reserved_length,
};
