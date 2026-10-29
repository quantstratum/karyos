/* SPDX-License-Identifier: Apache-2.0 */

/*
 * The compatibility gate's C ABI client (scripts/compat-test.sh, karyos#732):
 * compiled against one tree's karyos.h and linked against the other tree's
 * libkaryos, so a binding of one release meets the library of another. It
 * does what karyos.h tells a caller to do first: karyos_abi_version, and
 * the header's rule (before 1.0, exactly the header's 0.y with at least
 * its patch). A library it accepts then runs a driver through the calls
 * both releases share, with this header's struct sizes. It prints one
 * line, `c_abi <outcome> library <x.y.z> header <x.y.z>`, and exits 0;
 * any call that fails prints `c_abi misbehave ...`.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "karyos.h"

static int accepts(uint32_t major, uint32_t minor, uint32_t patch) {
    if (KARYOS_ABI_VERSION_MAJOR == 0) {
        return major == 0 && minor == KARYOS_ABI_VERSION_MINOR &&
               patch >= KARYOS_ABI_VERSION_PATCH;
    }
    return major == KARYOS_ABI_VERSION_MAJOR &&
           (minor > KARYOS_ABI_VERSION_MINOR ||
            (minor == KARYOS_ABI_VERSION_MINOR && patch >= KARYOS_ABI_VERSION_PATCH));
}

int main(void) {
    uint32_t major = 0, minor = 0, patch = 0;
    char versions[96];
    if (karyos_abi_version(&major, &minor, &patch) != KARYOS_OK) {
        printf("c_abi misbehave karyos_abi_version\n");
        return 0;
    }
    snprintf(versions, sizeof versions, "library %u.%u.%u header %u.%u.%u", major, minor,
             patch, KARYOS_ABI_VERSION_MAJOR, KARYOS_ABI_VERSION_MINOR,
             KARYOS_ABI_VERSION_PATCH);
    if (!accepts(major, minor, patch)) {
        printf("c_abi refused %s\n", versions);
        return 0;
    }
    karyos_driver_options options;
    memset(&options, 0xA5, sizeof options);
    karyos_detail detail;
    memset(&detail, 0, sizeof detail);
    detail.size = (uint32_t)sizeof detail;
    uint64_t driver = KARYOS_NULL_HANDLE;
    uint32_t work = 0;
    int32_t status = karyos_driver_options_init(&options);
    if (status == KARYOS_OK) {
        status = karyos_driver_create(&options, &driver, &detail);
    }
    if (status == KARYOS_OK) {
        status = karyos_driver_do_work(driver, &work);
    }
    if (status == KARYOS_OK) {
        status = karyos_driver_close(driver);
    }
    if (status != KARYOS_OK) {
        printf("c_abi misbehave %s status %d (%s)\n", versions, status,
               karyos_status_message(status));
        return 0;
    }
    printf("c_abi ok %s\n", versions);
    return 0;
}
