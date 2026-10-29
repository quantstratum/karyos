// SPDX-License-Identifier: Apache-2.0

//! The conformance test kit's fault hook (feature `test-hooks`, declared in
//! `include/karyos_test_hooks.h`, never in `karyos.h`): a call that makes
//! libkaryos panic, so a binding's runner proves the panic row of SPEC.md
//! §13 ("panic poisons the handle and does not unwind") through its own
//! API. No product build has this module; `make test-hooks-absent-check`
//! proves the release library exports none of it.

use crate::api::driver;
use crate::boundary::guard;
use crate::handles::Handle;
use crate::status::Status;

/// Makes `driver`'s next duty cycle panic while it holds the driver: its
/// caller's next `karyos_driver_do_work`, or its thread's next cycle,
/// which this call waits for (`driver::panic_next_duty_cycle`). The
/// driver and every client it connected then answer `KARYOS_E_INTERNAL`
/// until closed.
///
/// Returns `KARYOS_OK`, the handle's error for one that names no open
/// driver, or `KARYOS_E_TIMEOUT` when a driver's thread took no cycle in
/// time.
#[unsafe(no_mangle)]
pub extern "C" fn karyos_test_panic_next_duty_cycle(driver: u64) -> i32 {
    guard(
        || match driver::panic_next_duty_cycle(Handle::from_raw(driver)) {
            Ok(()) => Status::Ok,
            Err(status) => status,
        },
    )
}
