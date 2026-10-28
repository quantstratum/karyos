// SPDX-License-Identifier: Apache-2.0

//! The embedded driver through its exported symbols (F5): options,
//! create, the two modes, a client of it, streams, and the close, on
//! every platform. Under Miri the tests that reach each unsafe site of
//! the driver's exports run (the options' inits, create with its prefixed
//! read and detail, do_work and connect with their out-parameters, the
//! stream's options and detail); the thread and publication tests are
//! covered natively.

// Links the library whose symbols `support::abi` declares.
use karyos_ffi as _;

mod support {
    #[allow(dead_code, reason = "each test binary calls a part of the ABI")]
    pub mod abi;
}

use support::abi;

const OK: i32 = 0;
const NOT_CONNECTED: i32 = 2;
const INVALID_ARGUMENT: i32 = 100;
const INVALID_HANDLE: i32 = 101;
const BUSY: i32 = 109;
const CLOSED: i32 = 200;
const IDLE_YIELD: u32 = 1;
const IDLE_SLEEP: u32 = 2;

#[test]
fn the_options_carry_their_size_and_the_drivers_defaults() {
    let (status, options) = abi::driver_options();
    assert_eq!(status, OK);
    // ABI 0.1.3 appends startup_timeout_ns to the 56 bytes of 0.1.0, and
    // 0.1.4 the network and its reserved word.
    assert_eq!(options.size, 72);
    assert_eq!((options.network, options.reserved0), (0, 0));
    assert_eq!(options.max_clients, 16);
    assert_eq!(options.startup_timeout_ns, 30_000_000_000);
    assert_eq!(options.reserved, 0);
    assert!(options.heartbeat_interval_ns > 0);
}

#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_driver_runs_by_its_caller_then_on_its_thread() {
    let (status, driver) = abi::driver_create();
    assert_eq!(status, OK);
    assert_ne!(driver, 0);
    assert_eq!(abi::driver_do_work(driver).0, OK);
    assert_eq!(abi::driver_start(driver, IDLE_YIELD, 0), OK);
    assert_eq!(abi::driver_do_work(driver).0, BUSY);
    assert_eq!(abi::driver_stop(driver), OK);
    assert_eq!(abi::driver_stop(driver), BUSY);
    assert_eq!(abi::driver_close(driver), OK);
    assert_eq!(abi::driver_close(driver), CLOSED);
    assert_eq!(abi::driver_do_work(driver).0, CLOSED);
}

#[test]
fn a_client_of_the_driver_is_served_and_follows_its_close() {
    let (_, driver) = abi::driver_create();
    let (status, client) = abi::driver_connect(driver);
    assert_eq!(status, OK);
    assert_eq!(abi::client_poll(client).0, OK);
    // The duty cycle's count is written (the out-parameter's Miri test).
    let (status, work) = abi::driver_do_work(driver);
    assert_eq!(status, OK);
    assert_ne!(work, u32::MAX);
    // A client handle is no driver handle.
    assert_eq!(abi::driver_do_work(client).0, INVALID_HANDLE);
    assert_eq!(abi::driver_close(driver), OK);
    assert_eq!(abi::client_poll(client).0, CLOSED);
    assert_eq!(abi::client_close(client), OK);
    assert_eq!(abi::driver_connect(driver).0, CLOSED);
}

#[test]
fn a_struct_below_the_first_size_is_refused() {
    let (_, mut options) = abi::driver_options();
    options.size = 55;
    let (status, driver, _) = abi::driver_create_with(&options);
    assert_eq!((status, driver), (INVALID_ARGUMENT, 0));
    // A struct from a newer header is read by its prefix.
    options.size = 64;
    let (status, driver, _) = abi::driver_create_with(&options);
    assert_eq!(status, OK);
    assert_eq!(abi::driver_close(driver), OK);
}

#[test]
fn a_refused_configuration_fills_nothing_but_the_status() {
    let (_, mut options) = abi::driver_options();
    options.ring_capacity = 1000;
    let (status, driver, detail) = abi::driver_create_with(&options);
    assert_eq!((status, driver), (INVALID_ARGUMENT, 0));
    assert_eq!((detail.code, detail.value), (0, 0));
    // A nonzero reserved word is refused, so a later minor can use it.
    let (_, mut options) = abi::driver_options();
    options.reserved = 1;
    assert_eq!(abi::driver_create_with(&options).0, INVALID_ARGUMENT);
    // An options' field is read: a zero client bound is refused too.
    let (_, mut options) = abi::driver_options();
    options.max_clients = 0;
    assert_eq!(abi::driver_create_with(&options).0, INVALID_ARGUMENT);
}

#[test]
fn a_stream_is_added_and_removed_through_the_abi() {
    let (_, driver) = abi::driver_create();
    let (status, options) = abi::stream_options(5);
    assert_eq!(status, OK);
    // The init writes the layout with publishers (the concurrent mode).
    assert_eq!(options.size, 88);
    assert_eq!(options.term_length, 64 * 1024);
    assert_eq!(abi::driver_add_stream(driver, &options).0, OK);
    // A duplicate names the stream and the session.
    let (status, detail) = abi::driver_add_stream(driver, &options);
    assert_eq!(
        (status, detail.code, detail.value),
        (INVALID_ARGUMENT, 5, 1)
    );
    assert_eq!(abi::driver_remove_stream(driver, 5), OK);
    assert_eq!(abi::driver_remove_stream(driver, 5), INVALID_ARGUMENT);
    // Below the first size.
    let mut small = options;
    small.size = 63;
    small.stream_id = 6;
    assert_eq!(abi::driver_add_stream(driver, &small).0, INVALID_ARGUMENT);
    // The first layout, 64 bytes, is still accepted (with no conflation
    // table); a size between it and 80 is refused.
    small.size = 72;
    assert_eq!(abi::driver_add_stream(driver, &small).0, INVALID_ARGUMENT);
    small.size = 84;
    assert_eq!(abi::driver_add_stream(driver, &small).0, INVALID_ARGUMENT);
    small.size = 64;
    assert_eq!(abi::driver_add_stream(driver, &small).0, OK);
    assert_eq!(abi::driver_close(driver), OK);
}

/// The conformance runner's claim fill (`publication_claim_filled`, the
/// test support's write into a staged claim's buffer) under Miri: the
/// caller's bytes go into the buffer the claim lent, and the claim stays
/// staged through a retryable commit until its abort.
#[test]
fn a_claim_filled_by_its_caller_is_staged_until_its_abort() {
    let (_, driver) = abi::driver_create();
    let (_, options) = abi::stream_options(9);
    assert_eq!(abi::driver_add_stream(driver, &options).0, OK);
    let (_, client) = abi::driver_connect(driver);
    // Under Miri the driver's thread sleeps between idle cycles, so the
    // test's own thread runs (MIRI.md, The profile).
    let (idle, sleep_ns) = if cfg!(miri) {
        (IDLE_SLEEP, 1_000_000)
    } else {
        (IDLE_YIELD, 0)
    };
    assert_eq!(abi::driver_start(driver, idle, sleep_ns), OK);
    let (status, publication) = abi::client_add_ipc_publication(client, 9);
    assert_eq!(status, OK);
    let (status, claim) = abi::publication_claim_filled(publication, 0, 5, b"hello");
    assert_eq!(status, OK);
    // No subscriber: the commit is retryable and keeps the claim staged.
    assert_eq!(abi::claim_commit(claim, 16).0, NOT_CONNECTED);
    assert_eq!(abi::claim_abort(claim), OK);
    // A message of another length than the claim's is not written.
    let (status, claim) = abi::publication_claim_filled(publication, 0, 4, b"hello");
    assert_eq!(status, OK);
    assert_eq!(abi::claim_abort(claim), OK);
    assert_eq!(abi::driver_close(driver), OK);
    assert_eq!(abi::client_close(client), OK);
}

/// A stream added with `allow_unconnected` 1 grants it to a client's
/// publication, exclusive or concurrent: an offer with no subscriber is
/// accepted. With 0 it answers NOT_CONNECTED (REVIEWER-01's .NET B1b
/// finding: the client's own request, always without it, used to decide).
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_streams_allow_unconnected_reaches_a_clients_publication() {
    let (_, driver) = abi::driver_create();
    let (_, client) = abi::driver_connect(driver);
    assert_eq!(abi::driver_start(driver, IDLE_YIELD, 0), OK);
    let mut stream_id = 20;
    for concurrent in [false, true] {
        for allow in [0, 1] {
            stream_id += 1;
            let (_, mut options) = abi::stream_options(stream_id);
            options.allow_unconnected = allow;
            if concurrent {
                options.publication_mode = 1;
                options.publishers = 1;
            }
            assert_eq!(abi::driver_add_stream(driver, &options).0, OK);
            let (status, publication, _) =
                abi::client_add_publication_of(client, c"karyos:ipc", stream_id, 0, concurrent);
            assert_eq!(status, OK, "{concurrent} {allow}");
            let expected = if allow == 1 { OK } else { NOT_CONNECTED };
            assert_eq!(
                abi::publication_offer(publication, b"alone"),
                expected,
                "concurrent {concurrent}, allow_unconnected {allow}"
            );
        }
    }
    assert_eq!(abi::driver_close(driver), OK);
    assert_eq!(abi::client_close(client), OK);
}

#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_c_caller_publishes_on_a_stream_of_its_own_driver() {
    let (_, driver) = abi::driver_create();
    let (_, options) = abi::stream_options(9);
    assert_eq!(abi::driver_add_stream(driver, &options).0, OK);
    let (_, client) = abi::driver_connect(driver);
    // The driver's own thread serves the control call.
    assert_eq!(abi::driver_start(driver, IDLE_YIELD, 0), OK);
    let (status, publication) = abi::client_add_ipc_publication(client, 9);
    assert_eq!(status, OK);
    // Live, with no subscriber yet (subscriptions come with F4).
    assert_eq!(abi::publication_offer(publication, b"hello"), NOT_CONNECTED);
    // An unguarded lane has no outcome records.
    assert_eq!(
        abi::publication_poll_outcomes(publication, 0, 8),
        (OK, 0, Vec::new())
    );
    // A stream the driver does not have is refused by the driver.
    assert_ne!(abi::client_add_ipc_publication(client, 10).0, OK);
    assert_eq!(abi::driver_close(driver), OK);
    assert_eq!(abi::publication_offer(publication, b"hello"), CLOSED);
    assert_eq!(abi::publication_poll_outcomes(publication, 0, 8).0, CLOSED);
    assert_eq!(abi::client_close(client), OK);
}
