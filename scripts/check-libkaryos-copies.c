/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Two copies of libkaryos in one process (C-LINKAGE, karyos.h Rules): a
 * handle of one copy answers KARYOS_E_CLOSED in the other, and stays
 * usable in its own. scripts/check-libkaryos-copies.sh builds it and
 * passes the paths of two file copies of the package's shared library,
 * each loaded with RTLD_LOCAL, so each has its own statics and draws its
 * own base generation.
 *
 * A handle carries its slot's generation in its high 32 bits, so the
 * first handle of a fresh table carries its copy's base. Two bases that
 * collide fail the run with both printed.
 */
#include <dlfcn.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include <karyos.h>

typedef int32_t (*abi_version_fn)(uint32_t *, uint32_t *, uint32_t *);
typedef int32_t (*options_init_fn)(karyos_driver_options *, size_t);
typedef int32_t (*create_fn)(const karyos_driver_options *, uint64_t *,
                             karyos_detail *);
typedef int32_t (*handle_fn)(uint64_t);
typedef int32_t (*work_fn)(uint64_t, uint32_t *);
typedef int32_t (*connect_fn)(uint64_t, uint64_t *, karyos_detail *);

struct copy {
    const char *name;
    void *library;
    abi_version_fn abi_version;
    options_init_fn options_init;
    create_fn create;
    work_fn do_work;
    connect_fn connect;
    work_fn client_poll;
    handle_fn client_close;
    handle_fn driver_close;
    uint64_t driver;
    uint64_t client;
};

static int failures = 0;

static void *symbol(struct copy *copy, const char *name) {
    void *found = dlsym(copy->library, name);
    if (found == NULL) {
        fprintf(stderr, "copy %s: no symbol %s: %s\n", copy->name, name,
                dlerror());
        exit(1);
    }
    return found;
}

static void load(struct copy *copy, const char *name, const char *path) {
    copy->name = name;
    copy->library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (copy->library == NULL) {
        fprintf(stderr, "copy %s: dlopen %s: %s\n", name, path, dlerror());
        exit(1);
    }
    copy->abi_version = (abi_version_fn)symbol(copy, "karyos_abi_version");
    copy->options_init =
        (options_init_fn)symbol(copy, "karyos_driver_options_init_sized");
    copy->create = (create_fn)symbol(copy, "karyos_driver_create");
    copy->do_work = (work_fn)symbol(copy, "karyos_driver_do_work");
    copy->connect = (connect_fn)symbol(copy, "karyos_driver_connect");
    copy->client_poll = (work_fn)symbol(copy, "karyos_client_poll");
    copy->client_close = (handle_fn)symbol(copy, "karyos_client_close");
    copy->driver_close = (handle_fn)symbol(copy, "karyos_driver_close");
}

static void expect(const char *what, int32_t status, int32_t expected) {
    if (status != expected) {
        fprintf(stderr, "%s: status %" PRId32 ", expected %" PRId32 "\n",
                what, status, expected);
        failures++;
    }
}

static void open_copy(struct copy *copy) {
    uint32_t major = 0, minor = 0, patch = 0;
    karyos_driver_options options;
    expect("abi_version", copy->abi_version(&major, &minor, &patch),
           KARYOS_OK);
    expect("driver_options_init_sized",
           copy->options_init(&options, sizeof options), KARYOS_OK);
    expect("driver_create", copy->create(&options, &copy->driver, NULL),
           KARYOS_OK);
    expect("driver_connect", copy->connect(copy->driver, &copy->client, NULL),
           KARYOS_OK);
}

/* `own`'s handles answer CLOSED in `other`, both a use and a close, and
 * stay usable in `own` afterwards. */
static void refused(struct copy *own, struct copy *other) {
    uint32_t count = 0;
    char what[96];
    snprintf(what, sizeof what, "copy %s's driver in copy %s", own->name,
             other->name);
    expect(what, other->do_work(own->driver, &count), KARYOS_E_CLOSED);
    snprintf(what, sizeof what, "copy %s's client polled in copy %s",
             own->name, other->name);
    expect(what, other->client_poll(own->client, &count), KARYOS_E_CLOSED);
    snprintf(what, sizeof what, "copy %s's client closed in copy %s",
             own->name, other->name);
    expect(what, other->client_close(own->client), KARYOS_E_CLOSED);
    snprintf(what, sizeof what, "copy %s's driver after copy %s refused it",
             own->name, other->name);
    expect(what, own->do_work(own->driver, &count), KARYOS_OK);
    snprintf(what, sizeof what, "copy %s's client after copy %s refused it",
             own->name, other->name);
    expect(what, own->client_poll(own->client, &count), KARYOS_OK);
}

int main(int argc, char **argv) {
    struct copy a, b;
    if (argc != 3) {
        fprintf(stderr, "usage: %s COPY_A COPY_B\n", argv[0]);
        return 2;
    }
    load(&a, "A", argv[1]);
    load(&b, "B", argv[2]);
    if (a.create == b.create) {
        fprintf(stderr, "the two paths loaded one copy\n");
        return 1;
    }
    open_copy(&a);
    open_copy(&b);
    if (failures != 0) {
        return 1;
    }
    /* Both copies' first driver sits in slot 0 of the same kind, so only
     * the generation tells them apart. */
    if ((a.driver >> 32) == (b.driver >> 32)) {
        fprintf(stderr, "bases collide: A %#" PRIx64
                        ", B %#" PRIx64 "\n",
                a.driver >> 32, b.driver >> 32);
        return 1;
    }
    refused(&a, &b);
    refused(&b, &a);
    expect("copy A's client close", a.client_close(a.client), KARYOS_OK);
    expect("copy A's driver close", a.driver_close(a.driver), KARYOS_OK);
    expect("copy B's client close", b.client_close(b.client), KARYOS_OK);
    expect("copy B's driver close", b.driver_close(b.driver), KARYOS_OK);
    if (failures != 0) {
        fprintf(stderr, "bases: A %#" PRIx64 ", B %#" PRIx64 "\n",
                a.driver >> 32, b.driver >> 32);
        return 1;
    }
    printf("two copies: bases %#" PRIx64 " and %#" PRIx64
           "; each refuses the other's handles with KARYOS_E_CLOSED\n",
           a.driver >> 32, b.driver >> 32);
    return 0;
}
