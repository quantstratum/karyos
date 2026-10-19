/* SPDX-License-Identifier: Apache-2.0 */

/*
 * karyos.h: the C ABI of Karyos (libkaryos), ABI version 0.1.0.
 *
 * Written by hand until cbindgen is admitted; a test in karyos-ffi checks
 * it against the Rust source (quantstratum-docs:
 * karyos/design/ffi-gap-analysis.md, sections 4.3 and 4.6).
 *
 * Rules (karyos/SPEC.md section 10.2):
 * - Every function returns a status code, or static text, and writes its
 *   results through out-parameters. There is no global or thread-local
 *   error state.
 * - Objects are 64-bit handles, never pointers. A closed handle answers
 *   KARYOS_E_CLOSED; a handle in use by another thread answers
 *   KARYOS_E_BUSY, and one reentered from its own callback answers
 *   KARYOS_E_REENTRANT. Calls never block on a handle.
 * - A panic inside Karyos returns KARYOS_E_INTERNAL and poisons the handle
 *   it held.
 * - Callbacks must return normally: an exception, a panic or a longjmp
 *   through Karyos frames is outside this contract.
 * - Call karyos_abi_version first; a different major version is
 *   incompatible.
 */

#ifndef KARYOS_H
#define KARYOS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KARYOS_ABI_VERSION_MAJOR 0
#define KARYOS_ABI_VERSION_MINOR 1
#define KARYOS_ABI_VERSION_PATCH 0

/** No handle names an object with this value. */
#define KARYOS_NULL_HANDLE 0

/*
 * Status codes. 0 is success; 1-99 data-path outcomes, 100-199 usage,
 * 200-299 lifecycle, 300-399 resource and driver, 400-499 compatibility,
 * 500 internal. A code from a newer minor version is classified by its
 * range.
 */
/** success */
#define KARYOS_OK 0
/** back pressured: the subscribers are behind */
#define KARYOS_E_BACK_PRESSURED 1
/** no subscriber is connected */
#define KARYOS_E_NOT_CONNECTED 2
/** an administrative action is in progress; retry */
#define KARYOS_E_ADMIN_ACTION 3
/** the publication is closed */
#define KARYOS_E_CLOSED_PUBLICATION 4
/** the guard is closed */
#define KARYOS_E_GATED 5
/** the rate limit refused the message */
#define KARYOS_E_RATE_LIMITED 6
/** the block was aborted */
#define KARYOS_E_ABORTED 7
/** invalid argument */
#define KARYOS_E_INVALID_ARGUMENT 100
/** not a handle of this kind */
#define KARYOS_E_INVALID_HANDLE 101
/** the message exceeds the maximum length */
#define KARYOS_E_MESSAGE_TOO_LARGE 102
/** empty message */
#define KARYOS_E_EMPTY_MESSAGE 103
/** the lane is not configured */
#define KARYOS_E_INVALID_LANE 104
/** invalid schedule */
#define KARYOS_E_INVALID_SCHEDULE 105
/** invalid channel URI */
#define KARYOS_E_INVALID_CHANNEL 106
/** invalid context */
#define KARYOS_E_INVALID_CONTEXT 107
/** the handle is in use by this thread's callback */
#define KARYOS_E_REENTRANT 108
/** the handle is in use by another thread */
#define KARYOS_E_BUSY 109
/** conflation error */
#define KARYOS_E_CONFLATION 110
/** closed */
#define KARYOS_E_CLOSED 200
/** the subscription was closed by its rejoin policy */
#define KARYOS_E_CLOSED_BY_OVERRUN 201
/** the stream position range is exhausted */
#define KARYOS_E_POSITIONS_EXHAUSTED 202
/** the publication's outcomes were lost */
#define KARYOS_E_OUTCOMES_LOST 203
/** driver events were lost */
#define KARYOS_E_EVENTS_LOST 204
/** the outcome stream failed */
#define KARYOS_E_OUTCOMES 205
/** no free handle of this kind */
#define KARYOS_E_HANDLES_EXHAUSTED 300
/** the command ring is full; retry */
#define KARYOS_E_COMMAND_RING_FULL 301
/** too many pending requests */
#define KARYOS_E_TOO_MANY_PENDING 302
/** the driver did not answer in time */
#define KARYOS_E_TIMEOUT 303
/** the driver refused the request */
#define KARYOS_E_REFUSED 304
/** the driver does not serve this channel */
#define KARYOS_E_UNSUPPORTED_CHANNEL 305
/** unknown failure */
#define KARYOS_E_UNKNOWN 306
/** a system call or a region check failed */
#define KARYOS_E_SYSTEM 307
/** resources unavailable */
#define KARYOS_E_RESOURCES_UNAVAILABLE 308
/** the driver runs another protocol version */
#define KARYOS_E_INCOMPATIBLE_DRIVER 400
/** the driver refused the client */
#define KARYOS_E_ADMISSION_REFUSED 401
/** admission protocol error */
#define KARYOS_E_PROTOCOL 402
/** internal error; the handle is poisoned */
#define KARYOS_E_INTERNAL 500

/**
 * Writes the ABI version this library implements. Returns KARYOS_OK, or
 * KARYOS_E_INVALID_ARGUMENT with nothing written when a pointer is null or
 * misaligned.
 */
int32_t karyos_abi_version(uint32_t *major, uint32_t *minor, uint32_t *patch);

/**
 * The static text of a status code; a fixed text for a code that is none.
 * Never freed.
 */
const char *karyos_status_message(int32_t status);

#ifdef __cplusplus
}
#endif

#endif /* KARYOS_H */
