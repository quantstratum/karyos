/* SPDX-License-Identifier: Apache-2.0 */

/*
 * The conformance test kit's fault hook. It exists only in a libkaryos built
 * with the karyos-ffi feature `test-hooks`, which no release enables: a
 * product library has none of these symbols (make test-hooks-absent-check),
 * and karyos.h never declares them. A binding's conformance runner declares
 * the suite's feature `fault-hook` absent unless its library exports them.
 */

#ifndef KARYOS_TEST_HOOKS_H
#define KARYOS_TEST_HOOKS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Makes `driver`'s next duty cycle panic inside libkaryos while it holds
 * the driver: its caller's next karyos_driver_do_work, which returns
 * KARYOS_E_INTERNAL, or, for a driver on its own thread, that thread's
 * next cycle, which this call waits for (up to 10 s, then
 * KARYOS_E_TIMEOUT, disarmed). Either way the driver and every client it
 * connected then answer KARYOS_E_INTERNAL until closed. Returns
 * KARYOS_OK, or the handle's error for one that names no open driver.
 */
int32_t karyos_test_panic_next_duty_cycle(uint64_t driver);

#ifdef __cplusplus
}
#endif

#endif /* KARYOS_TEST_HOOKS_H */
