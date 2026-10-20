// SPDX-License-Identifier: Apache-2.0

//! The embedded driver through its exported symbols (F5): options,
//! create, the two modes, a client of it, and the close; on every
//! platform and under Miri.

// Links the library whose symbols `support::abi` declares.
use karyos_ffi as _;

mod support {
    #[allow(dead_code, reason = "each test binary calls a part of the ABI")]
    pub mod abi;
}

use support::abi;

const OK: i32 = 0;
const INVALID_ARGUMENT: i32 = 100;
const INVALID_HANDLE: i32 = 101;
const BUSY: i32 = 109;
const CLOSED: i32 = 200;
const IDLE_YIELD: u32 = 1;

#[test]
fn the_options_carry_their_size_and_the_drivers_defaults() {
    let (status, options) = abi::driver_options();
    assert_eq!(status, OK);
    assert_eq!(options.size, 56);
    assert_eq!(options.max_clients, 16);
    assert_eq!(options.reserved, 0);
    assert!(options.heartbeat_interval_ns > 0);
}

#[test]
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
    // An options' field is read: a zero client bound is refused too.
    let (_, mut options) = abi::driver_options();
    options.max_clients = 0;
    assert_eq!(abi::driver_create_with(&options).0, INVALID_ARGUMENT);
}
