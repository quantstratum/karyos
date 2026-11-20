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

/// 0.1.6: `KARYOS_PROTOCOL_VERSION` 4 (karyos#740, the rate change
/// command) on 0.1.5's driver options' stream cap (karyos#818), 0.1.4's embedded
/// network (karyos#735), 0.1.3's readiness calls (karyos#794) and 0.1.2's
/// roles calls (karyos#637).
#[test]
fn the_abi_version_is_0_1_6() {
    assert_eq!(abi::abi_version(), (0, [0, 1, 6]));
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

/// The F9c wrappers of the conformance runner's `archive-replay` ops
/// (tests/support/abi.rs) under Miri, with no driver: each passes its
/// pointers and reads what the library wrote for an unknown handle, and
/// the replay options' init fills its defaults.
#[test]
fn the_replay_wrappers_pass_their_pointers() {
    const INVALID_HANDLE: i32 = 101;
    let (status, options) = abi::replay_options();
    assert_eq!((status, options.size, options.rate), (0, 48, 1));
    assert_eq!(options.length, u64::MAX);
    let options = abi::ReplayOptions {
        recording_id: 3,
        target_stream_id: 1041,
        ..options
    };
    assert_eq!(abi::archive_replay(0, &options).0, INVALID_HANDLE);
    assert_eq!(abi::archive_stop_replay(0, 5).0, INVALID_HANDLE);
    assert_eq!(
        abi::client_add_replay_subscription(0, 1041, 9).0,
        INVALID_HANDLE
    );
    let (status, end) = abi::subscription_end_state(0);
    assert_eq!((status, end.reason, end.position), (INVALID_HANDLE, 0, 0));
    // karyos#830: the image change's sized struct and `has` pointer.
    let (status, change) = abi::subscription_next_image_change(0);
    assert_eq!(status, INVALID_HANDLE);
    assert!(change.is_none());
    assert_eq!(abi::subscription_image_changes_lost(0).0, INVALID_HANDLE);
    let (status, kept) = abi::archive_recordings(0, 0, 4);
    assert_eq!(status, INVALID_HANDLE);
    assert!(kept.is_empty());
}
