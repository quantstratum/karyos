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

/// Makes the next `karyos_driver_do_work` on `driver` panic while it holds
/// the driver: that call returns `KARYOS_E_INTERNAL`, and the driver and
/// every client it connected answer `KARYOS_E_INTERNAL` until closed.
///
/// Returns `KARYOS_OK`, or the handle's error for one that names no open
/// driver.
#[unsafe(no_mangle)]
pub extern "C" fn karyos_test_panic_next_duty_cycle(driver: u64) -> i32 {
    guard(|| match driver::panic_next_duty_cycle(Handle::from_raw(driver)) {
        Ok(()) => Status::Ok,
        Err(status) => status,
    })
}
