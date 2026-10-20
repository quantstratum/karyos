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

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KARYOS_ABI_VERSION_MAJOR 0
#define KARYOS_ABI_VERSION_MINOR 1
#define KARYOS_ABI_VERSION_PATCH 0

/** No handle names an object with this value. */
#define KARYOS_NULL_HANDLE 0

/** The most clients open at once. */
#define KARYOS_MAX_CLIENTS 64
/** The most publications open at once. */
#define KARYOS_MAX_PUBLICATIONS 4096
/** The most claims outstanding at once: one per publication. */
#define KARYOS_MAX_CLAIMS 4096
/**
 * The most subscriptions open at once. Each holds a private copy buffer of
 * the largest message it can deliver, at most the stream's term length / 8.
 */
#define KARYOS_MAX_SUBSCRIPTIONS 4096

/** The most conflated subscriptions open at once. */
#define KARYOS_MAX_CONFLATED_SUBSCRIPTIONS 4096

/** The most Archive connections open at once. */
#define KARYOS_MAX_ARCHIVES 64

/** karyos_recording states. */
#define KARYOS_RECORDING_RECORDING 0
#define KARYOS_RECORDING_STOPPED 1

/**
 * karyos_recording stop reasons; 0 while it records. A newer library may
 * add reasons.
 */
#define KARYOS_STOP_NORMAL 1
#define KARYOS_STOP_RECOVERED 2
#define KARYOS_STOP_EMPTY 3
#define KARYOS_STOP_LAPPED 4
#define KARYOS_STOP_STOPPED 5
#define KARYOS_STOP_SHUTDOWN 6
#define KARYOS_STOP_SOURCE_FAILED 7
#define KARYOS_STOP_REQUIRED_LAPPED 8
#define KARYOS_STOP_INVALID_SOURCE 9

/**
 * The freshness of a conflated value no committed gap covers; any other
 * freshness is the start of the gap that made the value stale.
 */
#define KARYOS_FRESH UINT64_MAX

/** karyos_message_info flags. */
#define KARYOS_MESSAGE_END_OF_STREAM 1
#define KARYOS_MESSAGE_TRACED 2

/**
 * karyos_outcome kinds. A newer library may add kinds: a binding keeps a
 * record of a kind it does not know.
 */
#define KARYOS_OUTCOME_SUBMITTED 1
#define KARYOS_OUTCOME_CONFIRMED_CANCELLED 2
#define KARYOS_OUTCOME_UNKNOWN 3
#define KARYOS_OUTCOME_REJECTED 4
#define KARYOS_OUTCOME_ABORTED 5
#define KARYOS_OUTCOME_RANGE 16
#define KARYOS_OUTCOME_INTERRUPTED 17
#define KARYOS_OUTCOME_ENDED 18
#define KARYOS_OUTCOME_OUTCOMES_LOST 19

/**
 * A subscriber's role (karyos_subscription_options): a required reader
 * bounds its publisher and is never lapped; an optional one does not and
 * may be lapped; an observer is optional and only copies.
 */
#define KARYOS_ROLE_REQUIRED 0
#define KARYOS_ROLE_OPTIONAL 1
#define KARYOS_ROLE_OBSERVER 2

/**
 * What follows an overrun of an optional or observer reader: delivery
 * goes on at the head, or the subscription closes and its polls return
 * KARYOS_E_CLOSED_BY_OVERRUN. Not yet in the C ABI, and the next codes when
 * added: a snapshot rebuild (a C callback on the polling thread) and a
 * replay from a recording (batch F9).
 */
#define KARYOS_REJOIN_AT_HEAD 0
#define KARYOS_REJOIN_CLOSE 1

/** The most embedded drivers open at once. */
#define KARYOS_MAX_DRIVERS 8

/**
 * The protocol version an embedded client and its driver speak: both come
 * from this library's build.
 */
#define KARYOS_PROTOCOL_VERSION 2

/**
 * Publication modes of a stream (karyos_stream_options): one exclusive
 * publication, or up to `publishers` concurrent handles on lane 0
 * (karyos_client_add_concurrent_publication).
 */
#define KARYOS_PUBLICATION_EXCLUSIVE 0
#define KARYOS_PUBLICATION_CONCURRENT 1

/** The clock domains of a timed lane (karyos_clock_now). */
#define KARYOS_CLOCK_MONOTONIC 0
#define KARYOS_CLOCK_TAI 1

/** What a lost required subscriber does (karyos_stream_options). */
#define KARYOS_LOSS_HOLD 0
#define KARYOS_LOSS_CONTINUE 1
#define KARYOS_LOSS_ABORT 2

/**
 * Idle strategies of a control call's wait (karyos_client_options) and of
 * a driver's own thread (karyos_driver_start).
 */
#define KARYOS_IDLE_BUSY_SPIN 0
#define KARYOS_IDLE_YIELD 1
#define KARYOS_IDLE_SLEEP 2

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
/** not supported on this platform */
#define KARYOS_E_UNSUPPORTED 111
/** the publication has a claim outstanding; commit or abort it first */
#define KARYOS_E_CLAIM_OUTSTANDING 112
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
 * What a failed control call adds to its status. The caller sets size to
 * sizeof(karyos_detail) of the header it was built with; the library
 * writes the fields both versions know. A size below that of ABI 0.1.0,
 * or a null pointer, receives nothing. Untouched on success.
 */
typedef struct karyos_detail {
    uint32_t size;
    uint32_t reserved;
    /* A code the status defines, such as the driver's refusal code. */
    uint64_t code;
    /* A value the status defines, such as a length, a version or errno. */
    uint64_t value;
} karyos_detail;

/**
 * A client's options, copied by karyos_client_connect. Fill it with
 * karyos_client_options_init, which sets size and the defaults, then set
 * dir. Zero timeout_ns, max_pending or max_images are invalid. A struct
 * from an older header of the same major version is accepted: the fields
 * it lacks take their defaults. A size below that of ABI 0.1.0 is
 * KARYOS_E_INVALID_ARGUMENT.
 */
typedef struct karyos_client_options {
    uint32_t size;
    /* KARYOS_IDLE_BUSY_SPIN, KARYOS_IDLE_YIELD or KARYOS_IDLE_SLEEP. */
    uint32_t idle_strategy;
    /* The driver's directory, NUL-terminated UTF-8. */
    const char *dir;
    /* The sleep of KARYOS_IDLE_SLEEP, in nanoseconds. */
    uint64_t idle_sleep_ns;
    /* The longest wait of a control call, in nanoseconds. */
    uint64_t timeout_ns;
    /* The most requests in flight. */
    uint32_t max_pending;
    /* The most images a network subscription attaches. */
    uint32_t max_images;
} karyos_client_options;

/**
 * Where an accepted message went. The caller sets size to
 * sizeof(karyos_accepted); the rule of karyos_detail applies.
 */
typedef struct karyos_accepted {
    uint32_t size;
    /* The lane the message was appended to. */
    uint32_t lane;
    /* The message's position in that lane. */
    uint64_t position;
} karyos_accepted;

/**
 * An embedded driver's options, copied by karyos_driver_create. Fill it
 * with karyos_driver_options_init, which sets size and the driver's
 * defaults; every setting it does not carry is the driver's default. A
 * struct from an older header of the same major version is accepted: the
 * fields it lacks take their defaults. A size below that of its first
 * version is KARYOS_E_INVALID_ARGUMENT.
 */
typedef struct karyos_driver_options {
    uint32_t size;
    /* Clients admitted at once. */
    uint32_t max_clients;
    /* Streams configured at once. */
    uint32_t max_streams;
    /* Pending requests per client. */
    uint32_t max_pending_per_client;
    /* Bytes of each client's command ring, a power of two. */
    uint32_t ring_capacity;
    /* Bytes of the broadcast buffer. */
    uint32_t broadcast_capacity;
    /* Cells of the counters region. */
    uint32_t counters_capacity;
    /* Zero; anything else is KARYOS_E_INVALID_ARGUMENT. */
    uint32_t reserved;
    /* How often the driver advances its heartbeat, in nanoseconds. */
    uint64_t heartbeat_interval_ns;
    /* How long a client's heartbeat may stay unchanged, in nanoseconds. */
    uint64_t client_liveness_timeout_ns;
    /* How long a handle has to move to a successor mapping, in ns. */
    uint64_t cutover_deadline_ns;
} karyos_driver_options;

/**
 * A stream's options, copied by karyos_driver_add_stream: the driver's
 * stream configuration and its conflation table. Fill it with
 * karyos_stream_options_init, then set stream_id. This version takes lane
 * 0 only (KARYOS_E_INVALID_LANE otherwise); the driver checks the sizes.
 * The size rule of karyos_driver_options applies, with three layouts: 64
 * bytes up to claim_deadline_ns (an exclusive stream with no conflation
 * table), 80 bytes with the conflation fields, and 88 bytes with
 * publishers. A size between two layouts, or a nonzero reserved, is
 * KARYOS_E_INVALID_ARGUMENT.
 */
typedef struct karyos_stream_options {
    uint32_t size;
    /* The wire stream id. */
    int32_t stream_id;
    /* Bytes of each term, a power of two. */
    uint32_t term_length;
    /* The largest frame, header included. */
    uint32_t mtu;
    /* The most bytes one claim reserves. */
    uint32_t max_reserved;
    /* Term slots beyond the three in use. */
    uint32_t spare_slots;
    /* Subscribers at once. */
    uint32_t max_subscribers;
    /* The session alias. */
    int32_t session_id;
    /* The first term's id. */
    uint32_t initial_term_id;
    /* The lane: 0. */
    uint32_t lane;
    /* KARYOS_PUBLICATION_*. */
    uint32_t publication_mode;
    /* Offers allowed with no subscriber attached: 0 or 1. */
    uint32_t allow_unconnected;
    /* Entries of the stream's schedule ring; 0 for none. */
    uint32_t schedule_capacity;
    /* KARYOS_LOSS_*: what a lost required subscriber does. */
    uint32_t on_required_loss;
    /* How long a claim may stay open, in nanoseconds. */
    uint64_t claim_deadline_ns;
    /*
     * The stream's conflation table (from 80 bytes): its keys, its largest
     * value and its update journal, in bytes. All three 0 for none; a
     * partial set, or a table the driver cannot build, is
     * KARYOS_E_INVALID_ARGUMENT. An offer's reserved value is its key.
     */
    uint32_t conflation_keys;
    uint32_t conflation_value_capacity;
    uint64_t conflation_journal_capacity;
    /*
     * Concurrent handles at once (from 88 bytes): 1 to 255 with
     * KARYOS_PUBLICATION_CONCURRENT, 0 with KARYOS_PUBLICATION_EXCLUSIVE;
     * anything else is KARYOS_E_INVALID_ARGUMENT. Each handle reserves with
     * one atomic fetch_add: on an aarch64 CPU without LSE atomics, as
     * detected at run time (not the build's target features), the driver
     * refuses a concurrent stream, its default.
     */
    uint32_t publishers;
    /* Zero. */
    uint32_t reserved;
} karyos_stream_options;

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

/**
 * Fills options with the defaults and its size. KARYOS_E_INVALID_ARGUMENT
 * for a null or misaligned pointer.
 */
int32_t karyos_client_options_init(karyos_client_options *options);

/**
 * Attaches a client to the driver whose admission socket is in
 * options->dir and writes its handle. The options are copied; a failed
 * connect opens nothing and fills detail (may be null).
 * KARYOS_E_INCOMPATIBLE_DRIVER carries the driver's protocol version in
 * detail->value when it admitted the client at another one, 0 when it
 * refused it. KARYOS_E_UNSUPPORTED where no cross-process client exists
 * (not Linux).
 */
int32_t karyos_client_connect(const karyos_client_options *options,
                              uint64_t *client, karyos_detail *detail);

/**
 * Serves the client once without waiting; writes 1 to served when
 * anything was served, else 0. Call it regularly.
 */
int32_t karyos_client_poll(uint64_t client, uint32_t *served);

/**
 * Closes the client; the driver releases what it granted it. Nothing is
 * closed when the handle is in use (KARYOS_E_BUSY, KARYOS_E_REENTRANT).
 */
int32_t karyos_client_close(uint64_t client);

/**
 * Adds the exclusive publication of stream_id on the channel uri
 * (karyos:ipc or karyos:udp) to the client and writes its handle. A
 * control call: it waits for the driver up to the client's timeout and
 * holds the client handle meanwhile. A failure opens nothing and fills
 * detail (may be null). A guarded stream's publication binds its guard
 * and outcome stream (karyos_publication_poll_outcomes) for a client of a
 * driver in another process; an embedded driver's client is refused one
 * with KARYOS_E_REFUSED, detail code 6 (invalid publication mode).
 */
int32_t karyos_client_add_publication(uint64_t client, const char *uri,
                                      int32_t stream_id, uint64_t *publication,
                                      karyos_detail *detail);

/**
 * Adds a concurrent publication handle of stream_id on the karyos:ipc
 * channel uri to the client and writes its handle. The driver must
 * configure the stream for concurrent publishers; the handle has lane 0
 * only, and the offer and claim calls apply to it. A control call, as
 * karyos_client_add_publication.
 */
int32_t karyos_client_add_concurrent_publication(uint64_t client,
                                                 const char *uri,
                                                 int32_t stream_id,
                                                 uint64_t *publication,
                                                 karyos_detail *detail);

/**
 * Offers length bytes at data on the lane, copied before it returns; data
 * may be null when length is 0. On KARYOS_OK, accepted (may be null)
 * receives the lane and position. Never waits.
 */
int32_t karyos_publication_offer(uint64_t publication, uint32_t lane,
                                 const uint8_t *data, size_t length,
                                 karyos_accepted *accepted);

/**
 * Per-offer options of karyos_publication_offer_with. Fill it with
 * karyos_offer_options_init (reserved_value 0, what
 * karyos_publication_offer sends), then set reserved_value. The size rule
 * of karyos_driver_options applies.
 */
typedef struct karyos_offer_options {
    uint32_t size;
    /* Zero; anything else is KARYOS_E_INVALID_ARGUMENT. */
    uint32_t reserved;
    /*
     * The value every fragment's header carries, which subscribers read as
     * karyos_message_info.reserved_value. On a conflated stream it is the
     * message's key, in 0..keys of the stream's table; see
     * karyos_publication_offer_with.
     */
    int64_t reserved_value;
} karyos_offer_options;

/**
 * Fills options with the defaults and its size. KARYOS_E_INVALID_ARGUMENT
 * for a null or misaligned pointer.
 */
int32_t karyos_offer_options_init(karyos_offer_options *options);

/**
 * As karyos_publication_offer, with options: the reserved value every
 * fragment's header carries. A null options, a size below that of ABI
 * 0.1.0, or a nonzero reserved returns KARYOS_E_INVALID_ARGUMENT.
 *
 * On a conflated stream the driver is authoritative: a key outside the
 * table never enters the conflated view, and the driver counts it as a
 * rejected key. Every publication also refuses such a key, or a value
 * larger than the capacity, before it appends: KARYOS_E_CONFLATION, with
 * nothing reserved. The table's shape comes with the log buffer the
 * publication writes to, for a client of a driver in this process or in
 * another. Conflation is a view over the log, not a filter on it: an
 * appended message reaches the stream's subscribers whatever its key.
 */
int32_t karyos_publication_offer_with(uint64_t publication, uint32_t lane,
                                      const uint8_t *data, size_t length,
                                      const karyos_offer_options *options,
                                      karyos_accepted *accepted);

/**
 * Offers length bytes at data on the timed lane with its requested
 * not-before time tx_time in the lane's clock domain (karyos_clock_now
 * reads it), copied before it returns; data may be null when length is 0.
 * The lane's handle checks the time before anything is reserved; on a
 * network route the driver's sender holds the message until its time.
 * KARYOS_E_INVALID_SCHEDULE for a lane that is not timed, a time below the
 * lane's last, one past the horizon or an overflowing deadline. On
 * KARYOS_OK, accepted (may be null) receives the lane and position. Never
 * waits.
 */
int32_t karyos_publication_offer_at(uint64_t publication, uint32_t lane,
                                    const uint8_t *data, size_t length,
                                    uint64_t tx_time,
                                    karyos_accepted *accepted);

/**
 * Writes the current time of domain (KARYOS_CLOCK_*): the time
 * karyos_publication_offer_at expects for a lane of that domain. Use it on
 * every platform rather than read the clocks: on macOS the monotonic
 * domain has a per-process origin, meaningful only within this process.
 * KARYOS_E_INVALID_ARGUMENT for an unknown domain or a null or misaligned
 * now (nothing is written); KARYOS_E_UNSUPPORTED for a domain this
 * platform cannot read (KARYOS_CLOCK_TAI off Linux). Never waits.
 */
int32_t karyos_clock_now(uint32_t domain, uint64_t *now);

/**
 * Stages a claim of length bytes on the lane: writes its handle and a
 * pointer to length zeroed bytes to fill. The pointer is valid until the
 * commit releases the claim, its abort, or the close of the publication or
 * of its client, and never points into a term or a shared mapping. One
 * claim per publication (KARYOS_E_CLAIM_OUTSTANDING).
 */
int32_t karyos_publication_claim(uint64_t publication, uint32_t lane,
                                 uint32_t length, uint64_t *claim,
                                 uint8_t **buffer);

/**
 * Commits the claim: claims in the term, copies the staged bytes and
 * commits, in one call. KARYOS_OK releases the claim and fills accepted
 * (may be null). KARYOS_E_BACK_PRESSURED, KARYOS_E_NOT_CONNECTED,
 * KARYOS_E_ADMIN_ACTION, KARYOS_E_RATE_LIMITED and KARYOS_E_GATED keep it
 * staged and its buffer valid, to retry or abort; any other failure
 * releases it.
 */
int32_t karyos_claim_commit(uint64_t claim, karyos_accepted *accepted);

/** Aborts the claim: nothing reaches the term. */
int32_t karyos_claim_abort(uint64_t claim);

/**
 * Closes the publication through its client, with its outstanding claim;
 * nothing is closed while the client handle is in use.
 */
int32_t karyos_publication_close(uint64_t publication);

/**
 * One outcome record of a guarded publication, valid during the handler's
 * call. size is the library's sizeof(karyos_outcome): read only the fields
 * it covers.
 */
typedef struct karyos_outcome {
    uint32_t size;
    uint32_t kind;
    uint32_t lane;
    uint32_t receiver;
    uint64_t sequence;
    uint64_t incarnation;
    uint64_t start;
    uint64_t end;
    uint64_t epoch;
    uint64_t reason;
    uint64_t lost;
} karyos_outcome;

/**
 * Called once per outcome record with the caller's context and the
 * record, valid only during the call. It must return normally.
 */
typedef void (*karyos_outcome_handler)(void *context,
                                       const karyos_outcome *outcome);

/**
 * Delivers at most limit outcome records of the publication's lane to
 * handler, in sequence order, and writes their count through delivered
 * (may be null), also when it fails: a failed poll's status follows the
 * records delivered before it. Never waits and never allocates. A lane
 * that is not guarded, and lane 0 of a concurrent handle, deliver 0; a
 * lane the publication does not configure returns KARYOS_E_INVALID_LANE.
 * After the final KARYOS_OUTCOME_OUTCOMES_LOST record, polls deliver 0
 * and offers and claims return KARYOS_E_OUTCOMES_LOST. From the handler,
 * offering, claiming, polling or closing this publication, or closing its
 * client, returns KARYOS_E_REENTRANT. To stop after a failed handler
 * (ADR-0067), poll with a limit of 1 in a loop and stop calling.
 */
int32_t karyos_publication_poll_outcomes(uint64_t publication, uint32_t lane,
                                         karyos_outcome_handler handler,
                                         void *context, uint32_t limit,
                                         uint32_t *delivered);

/**
 * What the poll knows of a message, valid during the handler's call. size
 * is the library's sizeof(karyos_message_info): read only the fields it
 * covers.
 */
typedef struct karyos_message_info {
    uint32_t size;
    uint32_t lane;
    uint64_t position;
    int64_t reserved_value;
    uint32_t extent;
    int32_t session_id;
    uint32_t flags;
    uint32_t reserved;
} karyos_message_info;

/** An image of a network subscription attached (available 1) or retired. */
typedef struct karyos_image_change {
    uint32_t size;
    int32_t session_id;
    uint64_t image_id;
    uint32_t lane;
    uint32_t available;
} karyos_image_change;

/**
 * Called once per message with the caller's context, the message's length
 * bytes at data (a private copy, never a term or a shared mapping, valid
 * only during the call) and its info. It must return normally.
 */
typedef void (*karyos_message_handler)(void *context, const uint8_t *data,
                                       size_t length,
                                       const karyos_message_info *info);

/**
 * Adds a view of the conflation table of the karyos:ipc stream stream_id
 * to the client and writes its handle. A client attached to a driver in
 * another process takes it; a client of a driver in this process is
 * refused by its driver (KARYOS_E_REFUSED): take that view with
 * karyos_driver_subscribe_conflated. The view is the client's: closing the
 * client closes it, and its handle then answers KARYOS_E_CLOSED. There is
 * no options struct: its poll reads with the default retries, its table
 * must be within the default limits (2^20 keys, 64 KiB values, a 64 MiB
 * journal), and the key budget is each poll's. A control call: it waits
 * for the driver up to the client's timeout and holds the client handle
 * meanwhile. A failure opens nothing and fills detail (may be null);
 * another channel is KARYOS_E_UNSUPPORTED_CHANNEL.
 */
int32_t karyos_client_add_conflated_subscription(uint64_t client,
                                                 const char *uri,
                                                 int32_t stream_id,
                                                 uint64_t *conflated,
                                                 karyos_detail *detail);

/**
 * Adds the subscription of stream_id on the channel uri (karyos:ipc or
 * karyos:udp) to the client and writes its handle. A control call: it
 * waits for the driver up to the client's timeout and holds the client
 * handle meanwhile. A failure opens nothing and fills detail (may be
 * null).
 */
int32_t karyos_client_add_subscription(uint64_t client, const char *uri,
                                       int32_t stream_id,
                                       uint64_t *subscription,
                                       karyos_detail *detail);

/**
 * A subscription's role and rejoin policy, read by
 * karyos_client_add_subscription_with. Fill it with
 * karyos_subscription_options_init (KARYOS_ROLE_REQUIRED,
 * KARYOS_REJOIN_AT_HEAD: what karyos_client_add_subscription takes), then
 * set the fields. The size rule of karyos_driver_options applies.
 */
typedef struct karyos_subscription_options {
    uint32_t size;
    /* KARYOS_ROLE_*. */
    uint32_t role;
    /* KARYOS_REJOIN_*. */
    uint32_t rejoin;
    /* Zero; anything else is KARYOS_E_INVALID_ARGUMENT. */
    uint32_t reserved;
} karyos_subscription_options;

/**
 * Fills options with the defaults and its size. KARYOS_E_INVALID_ARGUMENT
 * for a null or misaligned pointer.
 */
int32_t karyos_subscription_options_init(karyos_subscription_options *options);

/**
 * As karyos_client_add_subscription, with the reader's role and rejoin
 * policy; each image of a karyos:udp subscription takes both. A null
 * options, a size below that of ABI 0.1.0, an unknown role or policy, or a
 * nonzero reserved returns KARYOS_E_INVALID_ARGUMENT and opens nothing.
 */
int32_t karyos_client_add_subscription_with(uint64_t client, const char *uri,
                                            int32_t stream_id,
                                            const karyos_subscription_options *options,
                                            uint64_t *subscription,
                                            karyos_detail *detail);

/**
 * Delivers at most limit messages to handler, each from a private copy,
 * and writes their count through delivered (may be null), also when it
 * fails: a failed poll's status follows the messages delivered before it.
 * Never waits; it allocates only when a newly attached image or mapping
 * has a larger message than any before (KARYOS_E_SYSTEM when it cannot,
 * before anything of that round is delivered: the count covers earlier
 * rounds). From the handler, polling or closing this subscription, or
 * closing its client, returns KARYOS_E_REENTRANT. A karyos:ipc
 * subscription's end is its poll's status, after the messages before it,
 * and every later poll's: KARYOS_E_CLOSED_BY_OVERRUN once its rejoin
 * policy closed it, KARYOS_E_CLOSED once its stream's seal is reached or
 * it was revoked with its client. An overrun it rejoined after, an aborted
 * block or a skip is KARYOS_OK and the next poll goes on. A karyos:udp
 * subscription's images end one by one (image changes report them): its
 * poll answers KARYOS_OK. To stop
 * after a failed handler (ADR-0067), poll with a limit of 1 in a loop and
 * stop calling: the failed message is acknowledged, the later ones are
 * not delivered.
 */
int32_t karyos_subscription_poll(uint64_t subscription,
                                 karyos_message_handler handler,
                                 void *context, uint32_t limit,
                                 uint32_t *delivered);

/**
 * Takes the oldest queued image change into change and sets has to 1, or
 * sets has to 0 when none is queued. The queue is bounded. change points
 * to a karyos_image_change whose size is set: a null one, or one smaller
 * than this version's first, returns KARYOS_E_INVALID_ARGUMENT and takes
 * nothing.
 */
int32_t karyos_subscription_next_image_change(uint64_t subscription,
                                              karyos_image_change *change,
                                              uint32_t *has);

/** Writes the image changes a full queue dropped through lost. */
int32_t karyos_subscription_image_changes_lost(uint64_t subscription,
                                               uint64_t *lost);

/**
 * Closes the subscription through its client; nothing is closed while the
 * client handle is in use.
 */
int32_t karyos_subscription_close(uint64_t subscription);

/**
 * Fills options with the driver's defaults and its size.
 * KARYOS_E_INVALID_ARGUMENT for a null or misaligned pointer.
 */
int32_t karyos_driver_options_init(karyos_driver_options *options);

/**
 * Creates an embedded driver and writes its handle. Its caller drives it
 * with karyos_driver_do_work until karyos_driver_start gives it a thread.
 * A failed create creates nothing and fills detail (may be null):
 * KARYOS_E_SYSTEM carries errno in value, or the descriptors needed in
 * code and the soft limit in value.
 */
int32_t karyos_driver_create(const karyos_driver_options *options, uint64_t *driver,
                             karyos_detail *detail);

/**
 * Runs one duty cycle and writes its work count. KARYOS_E_BUSY while the
 * driver runs on its own thread; KARYOS_E_INTERNAL once a panic poisoned
 * it.
 */
int32_t karyos_driver_do_work(uint64_t driver, uint32_t *work);

/**
 * Gives the driver a thread of its own, which runs its duty cycle and
 * idles by idle_strategy (KARYOS_IDLE_*; idle_sleep_ns for
 * KARYOS_IDLE_SLEEP) after a cycle without work. KARYOS_E_BUSY when it
 * already has one.
 */
int32_t karyos_driver_start(uint64_t driver, uint32_t idle_strategy, uint64_t idle_sleep_ns);

/**
 * Stops the driver's thread and gives the driver back to its caller.
 * KARYOS_E_BUSY when it has none; KARYOS_E_INTERNAL when a panic on it
 * poisoned the driver.
 */
int32_t karyos_driver_stop(uint64_t driver);

/**
 * Fills options with a stream's defaults (stream id 0, the smallest term)
 * and its size. KARYOS_E_INVALID_ARGUMENT for a null or misaligned
 * pointer.
 */
int32_t karyos_stream_options_init(karyos_stream_options *options);

/**
 * Adds a stream to the driver, until karyos_driver_remove_stream or the
 * driver's close. A failure adds nothing and fills detail (may be null): a
 * duplicate stream id is KARYOS_E_INVALID_ARGUMENT with the stream id in
 * code and the session id in value.
 */
int32_t karyos_driver_add_stream(uint64_t driver, const karyos_stream_options *options,
                                 karyos_detail *detail);

/**
 * Removes the driver's stream: its publication closes, and its subscribers
 * read up to its seal. KARYOS_E_INVALID_ARGUMENT for a stream id the
 * driver does not have.
 */
int32_t karyos_driver_remove_stream(uint64_t driver, int32_t stream_id);

/**
 * Called once per delivered key with the caller's context, the key, its
 * latest value's length bytes at data (the reader's private copy, never
 * the shared table, valid only during the call), the value's version and
 * its freshness (KARYOS_FRESH, or the start of the gap that made it
 * stale). It must return normally.
 */
typedef void (*karyos_conflated_handler)(void *context, uint32_t key,
                                         const uint8_t *data, size_t length,
                                         uint64_t version, uint64_t freshness);

/**
 * Subscribes to the conflation table of the driver's stream and writes
 * the conflated subscription's handle. The view follows its driver: once
 * the driver is closed it answers KARYOS_E_CLOSED, and is still closed
 * with karyos_conflated_close. KARYOS_E_INVALID_ARGUMENT for a stream id
 * the driver does not have, KARYOS_E_CONFLATION for a stream without a
 * table, KARYOS_E_CLOSED for a stream being removed or a closed driver; a
 * failure opens nothing.
 */
int32_t karyos_driver_subscribe_conflated(uint64_t driver, int32_t stream_id,
                                          uint64_t *conflated);

/**
 * Delivers the latest value of at most key_budget changed keys to handler
 * and writes how many through delivered (may be null), also on failure.
 * Intermediate versions may be skipped; a key_budget of 0 delivers
 * nothing. A data-path call: it never waits and never allocates. Once the
 * table published a terminal invalidation the view is closed: that poll
 * and every later one return KARYOS_E_CLOSED. From the handler, polling
 * or closing this view returns KARYOS_E_REENTRANT.
 */
int32_t karyos_conflated_poll(uint64_t conflated,
                              karyos_conflated_handler handler,
                              void *context, uint32_t key_budget,
                              uint32_t *delivered);

/**
 * Closes the conflated subscription. A client's view is closed through its
 * client: while that is in use (KARYOS_E_BUSY, KARYOS_E_REENTRANT) nothing
 * is closed.
 */
int32_t karyos_conflated_close(uint64_t conflated);

/**
 * Opens a client of the driver in this process and writes its handle. The
 * client follows its driver: KARYOS_E_INTERNAL once the driver is
 * poisoned, KARYOS_E_CLOSED once it is closed. A failed connect opens
 * nothing and fills detail (may be null).
 */
int32_t karyos_driver_connect(uint64_t driver, uint64_t *client, karyos_detail *detail);

/**
 * Closes the driver, stopping its thread first. Its clients stay open,
 * answer KARYOS_E_CLOSED, and are closed with karyos_client_close. A
 * handle in use answers KARYOS_E_BUSY or KARYOS_E_REENTRANT, and nothing
 * is closed.
 */
int32_t karyos_driver_close(uint64_t driver);

/**
 * The control streams of an Archive and how a connection to it waits.
 * size is the caller's sizeof(karyos_archive_options); the library reads
 * the fields it knows of a newer struct, and the defaults past an older
 * one. reserved must be 0. client_id is this requester's id, at most
 * UINT32_MAX and unique among the Archive's requesters. deadline_ns is how
 * long a listing waits; 0 for the client's timeout.
 */
typedef struct karyos_archive_options {
    uint32_t size;
    uint32_t reserved;
    int32_t requests;
    int32_t responses;
    uint64_t client_id;
    uint64_t deadline_ns;
} karyos_archive_options;

/**
 * One recording of a listing, valid only during the handler call. size is
 * this version's sizeof(karyos_recording): a handler built against an
 * older header reads only the fields it knows. state is a
 * KARYOS_RECORDING_* value; stop_reason a KARYOS_STOP_* reason when
 * stopped, 0 while it records; incomplete 1 when the recording lost
 * ranges. start_time_ns is in nanoseconds since the Archive agent
 * started. position is the position written so far, or where it stopped.
 * channel holds channel_length bytes, not NUL-terminated.
 */
typedef struct karyos_recording {
    uint32_t size;
    uint32_t state;
    uint32_t stop_reason;
    uint32_t incomplete;
    int32_t stream_id;
    int32_t session_id;
    uint64_t id;
    uint64_t start;
    uint64_t start_time_ns;
    uint64_t position;
    const char *channel;
    size_t channel_length;
} karyos_recording;

/**
 * Called once per recording with the caller's context and the recording,
 * valid only during the call. It must return normally.
 */
typedef void (*karyos_recording_handler)(void *context,
                                         const karyos_recording *recording);

/**
 * Opens a connection of the client to the Archive whose control streams
 * options names, and writes its handle: a concurrent publication on its
 * request stream and an optional subscription on its response stream,
 * both the client's. Closing the client closes it. A control call: it
 * waits for the driver up to the client's timeout. A failed connect opens
 * nothing and fills detail (may be null); a client_id above UINT32_MAX or
 * a nonzero reserved is KARYOS_E_INVALID_ARGUMENT.
 */
int32_t karyos_archive_connect(uint64_t client,
                               const karyos_archive_options *options,
                               uint64_t *archive, karyos_detail *detail);

/**
 * Lists the recordings of the Archive's catalog whose id is above
 * after_id, at most limit, handing each to handler in id order, and
 * writes how many through delivered (may be null), also on failure. Fewer
 * than limit means the catalog has no more; the next page starts after
 * the last id delivered. A limit of 0 delivers nothing. A control call: it
 * waits for the whole page up to the connection's deadline, then hands it
 * over. A page that does not arrive in time is KARYOS_E_TIMEOUT with
 * nothing delivered; an Archive's refusal is KARYOS_E_REFUSED with its
 * response code in detail's code (1 an error, 2 an unknown recording, 3
 * an unknown replay, 4 an invalid request, 5 an unsupported schema). From
 * the handler, any call on the connection or its client returns
 * KARYOS_E_REENTRANT; another thread's returns KARYOS_E_BUSY.
 */
int32_t karyos_archive_list(uint64_t archive, uint64_t after_id,
                            uint32_t limit, karyos_recording_handler handler,
                            void *context, uint32_t *delivered,
                            karyos_detail *detail);

/**
 * Closes the Archive connection: its two streams are removed from its
 * client. While the client is in use (KARYOS_E_BUSY, KARYOS_E_REENTRANT)
 * nothing is closed.
 */
int32_t karyos_archive_close(uint64_t archive);

#ifdef __cplusplus
}
#endif

#endif /* KARYOS_H */
