// SPDX-License-Identifier: Apache-2.0

//! The C ABI through its exported symbols (F1): the ABI version and the
//! status text.

// Links the library whose symbols `support::abi` declares.
use karyos_ffi as _;

mod support {
    #[allow(dead_code, reason = "each test binary calls a part of the ABI")]
    pub mod abi;
}

use support::abi;

#[test]
fn the_abi_version_is_0_1_0() {
    assert_eq!(abi::abi_version(), (0, [0, 1, 0]));
}

#[test]
fn a_null_or_misaligned_out_parameter_is_refused_with_nothing_written() {
    // KARYOS_E_INVALID_ARGUMENT.
    assert_eq!(abi::abi_version_null_minor(), (100, [u32::MAX; 2]));
    assert_eq!(abi::abi_version_misaligned_major(), (100, [u32::MAX; 2]));
}

#[test]
fn every_status_has_static_text() {
    assert_eq!(abi::status_message(0), "success");
    assert_eq!(
        abi::status_message(108),
        "the handle is in use by this thread's callback"
    );
    assert_eq!(
        abi::status_message(500),
        "internal error; the handle is poisoned"
    );
    assert_eq!(abi::status_message(-1), "unknown status code");
    assert_eq!(abi::status_message(99), "unknown status code");
    // The same static string every time.
    let first = abi::status_message(1);
    assert_eq!(abi::status_message(1), first);
}
