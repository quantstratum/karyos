// SPDX-License-Identifier: Apache-2.0

//! The test kit's fault hook (feature `test-hooks`, karyos#699): its
//! refusals without a driver, which Miri runs, and a pending fault per
//! driver, so that arming one never cancels another's (karyos#883 review).

use std::sync::{Mutex, MutexGuard};

use super::super::test_hooks::karyos_test_panic_next_duty_cycle;
use super::*;

/// The armed slots are the process's: these tests take turns.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// An invoker-mode driver with the defaults.
fn invoker() -> u64 {
    let mut options = core::mem::MaybeUninit::<DriverOptions>::zeroed();
    // SAFETY: a live, aligned, writable `DriverOptions`.
    let status = unsafe {
        karyos_driver_options_init_sized(options.as_mut_ptr(), size_of::<DriverOptions>())
    };
    assert_eq!(status, Status::Ok.code());
    // SAFETY: `karyos_driver_options_init` wrote every field.
    let options = unsafe { options.assume_init() };
    let mut driver = 0;
    // SAFETY: live, aligned pointers; no detail.
    let status = unsafe { karyos_driver_create(&options, &mut driver, core::ptr::null_mut()) };
    assert_eq!(status, Status::Ok.code());
    driver
}

/// One duty cycle of `driver`: its status.
fn cycle(driver: u64) -> i32 {
    let mut work = 0u32;
    // SAFETY: a live, aligned `u32`.
    unsafe { karyos_driver_do_work(driver, &mut work) }
}

/// The export through its boundary, with no driver: a handle that names
/// none is refused with the handle's error, nothing armed; a handle of
/// another kind too.
#[test]
fn the_hook_refuses_a_handle_that_names_no_driver() {
    let _serial = serial();
    assert_eq!(
        karyos_test_panic_next_duty_cycle(0),
        Status::InvalidHandle.code()
    );
    assert_eq!(
        karyos_test_panic_next_duty_cycle(u64::MAX),
        Status::InvalidHandle.code()
    );
}

/// An armed invoker-mode driver panics in its caller's next duty cycle,
/// which answers INTERNAL instead of unwinding, and stays poisoned. Two
/// drivers armed one after the other each take their own fault (the
/// review's reproduction: arming B no longer cancels A's), and arming one
/// twice is one fault.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn each_armed_driver_takes_its_own_fault() {
    let _drivers = crate::test_drivers::drivers(4);
    let _serial = serial();
    let (a, b) = (invoker(), invoker());
    assert_eq!(karyos_test_panic_next_duty_cycle(a), Status::Ok.code());
    assert_eq!(karyos_test_panic_next_duty_cycle(b), Status::Ok.code());
    assert_eq!(karyos_test_panic_next_duty_cycle(b), Status::Ok.code());
    assert_eq!(cycle(a), Status::Internal.code());
    assert_eq!(cycle(b), Status::Internal.code());
    assert_eq!(cycle(a), Status::Internal.code(), "poisoned");
    assert_eq!(cycle(b), Status::Internal.code(), "poisoned");
    let c = invoker();
    assert_eq!(
        cycle(c),
        Status::Ok.code(),
        "an unarmed driver is untouched"
    );
    for driver in [a, b, c] {
        assert_eq!(karyos_driver_close(driver), Status::Ok.code());
    }
    // A driver closed while armed frees its slot.
    let d = invoker();
    assert_eq!(karyos_test_panic_next_duty_cycle(d), Status::Ok.code());
    assert_eq!(karyos_driver_close(d), Status::Ok.code());
    assert!(!crate::api::driver::take_fault(d), "disarmed at its close");
}

/// A close right after the arm's table check, forced through the test
/// seam (karyos#699): the fault, armed inside the table's guard, is
/// disarmed by that close. With the arm after the guard, as before, the
/// close found nothing armed and the fault stayed on the closed driver.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_close_right_after_the_check_leaves_nothing_armed() {
    let _drivers = crate::test_drivers::drivers(1);
    let _serial = serial();
    let driver = invoker();
    crate::api::driver::AFTER_CHECK.with(|hook| {
        hook.set(Some(|driver| {
            assert_eq!(karyos_driver_close(driver), Status::Ok.code());
        }));
    });
    let _ = karyos_test_panic_next_duty_cycle(driver);
    assert!(
        !crate::api::driver::take_fault(driver),
        "armed after its close"
    );
}

/// An arm racing a close is never left on the closed driver (karyos#699),
/// from another thread: a stress check beside the forced case above.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn an_arm_racing_a_close_is_never_left_armed() {
    let _drivers = crate::test_drivers::drivers(1);
    let _serial = serial();
    for _ in 0..200 {
        let driver = invoker();
        std::thread::scope(|scope| {
            let arming = scope.spawn(|| {
                while karyos_test_panic_next_duty_cycle(driver) != Status::Closed.code() {
                    std::hint::spin_loop();
                }
            });
            while karyos_driver_close(driver) != Status::Ok.code() {
                std::hint::spin_loop();
            }
            arming.join().unwrap();
        });
        assert!(
            !crate::api::driver::take_fault(driver),
            "armed after its close"
        );
    }
}

/// The slots are bounded: past [`MAX_ARMED`] distinct drivers an arm is
/// refused with RESOURCES_UNAVAILABLE, typed, and a taken fault frees its
/// slot. Raw handles only: no driver needed, so Miri runs it.
#[test]
fn the_armed_slots_are_bounded_and_freed_when_taken() {
    use crate::api::driver::{MAX_ARMED, arm_fault, take_fault};
    let _serial = serial();
    // Handles no driver has: a generation in the high bits, kind 0.
    let fake = |at: u64| (u64::from(u32::MAX) << 32) | at;
    for at in 0..MAX_ARMED as u64 {
        assert_eq!(arm_fault(fake(at)), Ok(()));
    }
    assert_eq!(arm_fault(fake(0)), Ok(()), "armed again: still one");
    assert_eq!(
        arm_fault(fake(MAX_ARMED as u64)),
        Err(Status::ResourcesUnavailable)
    );
    assert!(take_fault(fake(3)));
    assert!(!take_fault(fake(3)), "taken once");
    assert_eq!(arm_fault(fake(MAX_ARMED as u64)), Ok(()), "a slot is free");
    for at in 0..=MAX_ARMED as u64 {
        let _ = take_fault(fake(at));
    }
    assert!(!take_fault(0), "0 is never armed");
}
