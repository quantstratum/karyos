// SPDX-License-Identifier: Apache-2.0

//! The constants of the C header `include/karyos.h`, as cbindgen emits
//! them (`#define KARYOS_* value`; karyos#697, F8 of quantstratum-docs:
//! karyos/design/ffi-gap-analysis.md). Each is the C name and value of a
//! code the boundary uses elsewhere; the tests of `header.rs` compare
//! every one with its source (a status, an enum, a limit). A doc comment
//! on the first constant of a group documents the group in the header.
#![allow(
    missing_docs,
    reason = "a group's comment is on its first constant, as in the header"
)]

/// The ABI version of this header, which karyos_abi_version reports.
pub const KARYOS_ABI_VERSION_MAJOR: u32 = 0;
/// The ABI minor version.
pub const KARYOS_ABI_VERSION_MINOR: u32 = 1;
/// The ABI patch version.
pub const KARYOS_ABI_VERSION_PATCH: u32 = 5;

/// No handle names an object with this value.
pub const KARYOS_NULL_HANDLE: u64 = 0;

/// The most clients open at once.
pub const KARYOS_MAX_CLIENTS: u32 = 64;

/// The most publications open at once.
pub const KARYOS_MAX_PUBLICATIONS: u32 = 4096;

/// The most claims outstanding at once: one per publication.
pub const KARYOS_MAX_CLAIMS: u32 = 4096;

/// The most subscriptions open at once. Each holds a private copy buffer of
/// the largest message it can deliver, at most the stream's term length / 8.
pub const KARYOS_MAX_SUBSCRIPTIONS: u32 = 4096;

/// The most conflated subscriptions open at once.
pub const KARYOS_MAX_CONFLATED_SUBSCRIPTIONS: u32 = 4096;

/// The most Archive connections open at once.
pub const KARYOS_MAX_ARCHIVES: u32 = 64;

/// karyos_recording states.
pub const KARYOS_RECORDING_RECORDING: u32 = 0;
pub const KARYOS_RECORDING_STOPPED: u32 = 1;

/// karyos_recording stop reasons; 0 while it records. A newer library may
/// add reasons.
pub const KARYOS_STOP_NORMAL: u32 = 1;
pub const KARYOS_STOP_RECOVERED: u32 = 2;
pub const KARYOS_STOP_EMPTY: u32 = 3;
pub const KARYOS_STOP_LAPPED: u32 = 4;
pub const KARYOS_STOP_STOPPED: u32 = 5;
pub const KARYOS_STOP_SHUTDOWN: u32 = 6;
pub const KARYOS_STOP_SOURCE_FAILED: u32 = 7;
pub const KARYOS_STOP_REQUIRED_LAPPED: u32 = 8;
pub const KARYOS_STOP_INVALID_SOURCE: u32 = 9;

/// The freshness of a conflated value no committed gap covers; any other
/// freshness is the start of the gap that made the value stale.
pub const KARYOS_FRESH: u64 = u64::MAX;

/// karyos_message_info flags.
pub const KARYOS_MESSAGE_END_OF_STREAM: u32 = 1;
pub const KARYOS_MESSAGE_TRACED: u32 = 2;

/// karyos_outcome kinds. A newer library may add kinds: a binding keeps a
/// record of a kind it does not know.
pub const KARYOS_OUTCOME_SUBMITTED: u32 = 1;
pub const KARYOS_OUTCOME_CONFIRMED_CANCELLED: u32 = 2;
pub const KARYOS_OUTCOME_UNKNOWN: u32 = 3;
pub const KARYOS_OUTCOME_REJECTED: u32 = 4;
pub const KARYOS_OUTCOME_ABORTED: u32 = 5;
pub const KARYOS_OUTCOME_RANGE: u32 = 16;
pub const KARYOS_OUTCOME_INTERRUPTED: u32 = 17;
pub const KARYOS_OUTCOME_ENDED: u32 = 18;
pub const KARYOS_OUTCOME_OUTCOMES_LOST: u32 = 19;

/// A subscriber's role (karyos_subscription_options): a required reader
/// bounds its publisher and is never lapped; an optional one does not and
/// may be lapped; an observer is optional and only copies.
pub const KARYOS_ROLE_REQUIRED: u32 = 0;
pub const KARYOS_ROLE_OPTIONAL: u32 = 1;
pub const KARYOS_ROLE_OBSERVER: u32 = 2;

/// The strategy of a network publication's receivers
/// (karyos_client_add_publication_with_roles; ABI 0.1.2): the slowest live
/// receiver bounds the sender, the fastest, or the receivers of a tagged
/// group. It must be the channel's fc (KARYOS_STRATEGY_MIN without one).
pub const KARYOS_STRATEGY_MIN: u32 = 0;
pub const KARYOS_STRATEGY_MAX: u32 = 1;
pub const KARYOS_STRATEGY_TAGGED: u32 = 2;

/// A network publication's admission state
/// (karyos_publication_network_admission; ABI 0.1.2): unknown (before the
/// driver reports one, after a lap until it does again, or not a network
/// publication), open, a configured required receiver not joined, or one
/// lost.
pub const KARYOS_ADMISSION_UNKNOWN: u32 = 0;
pub const KARYOS_ADMISSION_OPEN: u32 = 1;
pub const KARYOS_ADMISSION_NOT_JOINED: u32 = 2;
pub const KARYOS_ADMISSION_LOST_REQUIRED: u32 = 3;

/// What follows an overrun of an optional or observer reader: delivery
/// goes on at the head; the subscription closes and its polls return
/// KARYOS_E_CLOSED_BY_OVERRUN; or the gap is recovered from an Archive and
/// merged back into the live stream (KARYOS_REJOIN_ARCHIVE, with the
/// options' Archive fields). Not yet in the C ABI: a snapshot rebuild (a C
/// callback on the polling thread).
pub const KARYOS_REJOIN_AT_HEAD: u32 = 0;
pub const KARYOS_REJOIN_CLOSE: u32 = 1;
pub const KARYOS_REJOIN_ARCHIVE: u32 = 2;

/// karyos_subscription_rejoin merge failures: none; an epoch change; a
/// replay that ended short; a mismatch at the cutover; another lane; the
/// replay overrun; the replay revoked; the replay's failure; the live
/// reader overrun; the live reader's failure. KARYOS_MERGE_OTHER is a
/// failure a newer library knows and this header names no code for; a
/// binding keeps a code it does not know.
pub const KARYOS_MERGE_NONE: u32 = 0;
pub const KARYOS_MERGE_EPOCH_CHANGED: u32 = 1;
pub const KARYOS_MERGE_REPLAY_SHORT: u32 = 2;
pub const KARYOS_MERGE_MISMATCH: u32 = 3;
pub const KARYOS_MERGE_LANE: u32 = 4;
pub const KARYOS_MERGE_REPLAY_OVERRUN: u32 = 5;
pub const KARYOS_MERGE_REPLAY_REVOKED: u32 = 6;
pub const KARYOS_MERGE_REPLAY: u32 = 7;
pub const KARYOS_MERGE_LIVE_OVERRUN: u32 = 8;
pub const KARYOS_MERGE_LIVE: u32 = 9;
pub const KARYOS_MERGE_OTHER: u32 = 255;

/// The most embedded drivers open at once.
pub const KARYOS_MAX_DRIVERS: u32 = 8;

/// The protocol version an embedded client and its driver speak: both come
/// from this library's build.
pub const KARYOS_PROTOCOL_VERSION: u32 = 3;

/// Publication modes of a stream (karyos_stream_options): one exclusive
/// publication, or up to `publishers` concurrent handles on lane 0
/// (karyos_client_add_concurrent_publication).
pub const KARYOS_PUBLICATION_EXCLUSIVE: u32 = 0;
pub const KARYOS_PUBLICATION_CONCURRENT: u32 = 1;

/// The clock domains of a timed lane (karyos_clock_now).
pub const KARYOS_CLOCK_MONOTONIC: u32 = 0;
pub const KARYOS_CLOCK_TAI: u32 = 1;

/// What a lost required subscriber does (karyos_stream_options).
pub const KARYOS_LOSS_HOLD: u32 = 0;
pub const KARYOS_LOSS_CONTINUE: u32 = 1;
pub const KARYOS_LOSS_ABORT: u32 = 2;

/// Idle strategies of a control call's wait (karyos_client_options) and of
/// a driver's own thread (karyos_driver_start). KARYOS_IDLE_YIELD_THEN_SLEEP
/// yields for the first 64 consecutive idle waits, then sleeps 1 ms per
/// wait, and starts again after a wait that found work; it is the default
/// (karyos ADR-0066), and busy-spin is an explicit low-latency choice.
pub const KARYOS_IDLE_BUSY_SPIN: u32 = 0;
pub const KARYOS_IDLE_YIELD: u32 = 1;
pub const KARYOS_IDLE_SLEEP: u32 = 2;
pub const KARYOS_IDLE_YIELD_THEN_SLEEP: u32 = 3;

/// An embedded driver's network (karyos_driver_options.network, ABI
/// 0.1.4). ON runs the driver's network agents with their default
/// configuration, on their own threads, so its clients create karyos:udp
/// publications and subscriptions; OFF, the default and an older struct's,
/// serves karyos:ipc only. Only on and off are exposed: the agents' rings
/// and session limits, the threading mode, the image template, the stream
/// defaults, the NAK control groups, the per-client limit, timed network
/// streams and the idle image timeout keep their defaults. That list is
/// the one karyosd --network documents (quantstratum-docs:
/// karyos/design/observability-and-tools.md, Binaries).
pub const KARYOS_NETWORK_OFF: u32 = 0;
pub const KARYOS_NETWORK_ON: u32 = 1;

/// A driver's readiness (R-CORE-35, karyos_driver_readiness), with the
/// values of the admission protocol's readiness probe. STARTING: the host
/// has not called karyos_driver_startup_complete, within its deadline.
/// READY: a client would be admitted now, into no cutover. RECOVERING:
/// admitting, but a stream still retains a predecessor mapping after a
/// cutover. NOT_READY: not admitting a client now, for the reason given.
/// FAILED: startup missed its deadline; it does not end.
pub const KARYOS_READINESS_STARTING: u32 = 1;
pub const KARYOS_READINESS_READY: u32 = 2;
pub const KARYOS_READINESS_RECOVERING: u32 = 3;
pub const KARYOS_READINESS_NOT_READY: u32 = 4;
pub const KARYOS_READINESS_FAILED: u32 = 5;

/// Why a driver is not ready, or why its startup failed: NONE for
/// STARTING, READY and RECOVERING; NOT_ADMITTING, FULL or TERMINAL for
/// NOT_READY; STARTUP_DEADLINE for FAILED.
pub const KARYOS_READINESS_REASON_NONE: u32 = 0;
pub const KARYOS_READINESS_REASON_NOT_ADMITTING: u32 = 1;
pub const KARYOS_READINESS_REASON_FULL: u32 = 2;
pub const KARYOS_READINESS_REASON_TERMINAL: u32 = 3;
pub const KARYOS_READINESS_REASON_STARTUP_DEADLINE: u32 = 4;

/// Status codes. 0 is success; 1-99 data-path outcomes, 100-199 usage,
/// 200-299 lifecycle, 300-399 resource and driver, 400-499 compatibility,
/// 500 internal. A code from a newer minor version is classified by its
/// range.
///
/// success
pub const KARYOS_OK: i32 = 0;

/// back pressured: the subscribers are behind
pub const KARYOS_E_BACK_PRESSURED: i32 = 1;

/// no subscriber is connected
pub const KARYOS_E_NOT_CONNECTED: i32 = 2;

/// an administrative action is in progress; retry
pub const KARYOS_E_ADMIN_ACTION: i32 = 3;

/// the publication is closed
pub const KARYOS_E_CLOSED_PUBLICATION: i32 = 4;

/// the guard is closed
pub const KARYOS_E_GATED: i32 = 5;

/// the rate limit refused the message
pub const KARYOS_E_RATE_LIMITED: i32 = 6;

/// the block was aborted
pub const KARYOS_E_ABORTED: i32 = 7;

/// invalid argument
pub const KARYOS_E_INVALID_ARGUMENT: i32 = 100;

/// not a handle of this kind
pub const KARYOS_E_INVALID_HANDLE: i32 = 101;

/// the message exceeds the maximum length
pub const KARYOS_E_MESSAGE_TOO_LARGE: i32 = 102;

/// empty message
pub const KARYOS_E_EMPTY_MESSAGE: i32 = 103;

/// the lane is not configured
pub const KARYOS_E_INVALID_LANE: i32 = 104;

/// invalid schedule
pub const KARYOS_E_INVALID_SCHEDULE: i32 = 105;

/// invalid channel URI
pub const KARYOS_E_INVALID_CHANNEL: i32 = 106;

/// invalid context
pub const KARYOS_E_INVALID_CONTEXT: i32 = 107;

/// the handle is in use by this thread's callback
pub const KARYOS_E_REENTRANT: i32 = 108;

/// the handle is in use by another thread
pub const KARYOS_E_BUSY: i32 = 109;

/// conflation error
pub const KARYOS_E_CONFLATION: i32 = 110;

/// not supported on this platform
pub const KARYOS_E_UNSUPPORTED: i32 = 111;

/// the publication has a claim outstanding; commit or abort it first
pub const KARYOS_E_CLAIM_OUTSTANDING: i32 = 112;

/// closed
pub const KARYOS_E_CLOSED: i32 = 200;

/// the subscription was closed by its rejoin policy
pub const KARYOS_E_CLOSED_BY_OVERRUN: i32 = 201;

/// the stream position range is exhausted
pub const KARYOS_E_POSITIONS_EXHAUSTED: i32 = 202;

/// the publication's outcomes were lost
pub const KARYOS_E_OUTCOMES_LOST: i32 = 203;

/// driver events were lost
pub const KARYOS_E_EVENTS_LOST: i32 = 204;

/// the outcome stream failed
pub const KARYOS_E_OUTCOMES: i32 = 205;

/// no free handle of this kind
pub const KARYOS_E_HANDLES_EXHAUSTED: i32 = 300;

/// the command ring is full; retry
pub const KARYOS_E_COMMAND_RING_FULL: i32 = 301;

/// too many pending requests
pub const KARYOS_E_TOO_MANY_PENDING: i32 = 302;

/// the driver did not answer in time
pub const KARYOS_E_TIMEOUT: i32 = 303;

/// the driver refused the request; detail.code is its refusal code, which
/// may be one this library does not list (a newer driver's): treat it as a
/// refusal all the same
pub const KARYOS_E_REFUSED: i32 = 304;

/// the driver does not serve this channel
pub const KARYOS_E_UNSUPPORTED_CHANNEL: i32 = 305;

/// unknown failure
pub const KARYOS_E_UNKNOWN: i32 = 306;

/// a system call or a region check failed
pub const KARYOS_E_SYSTEM: i32 = 307;

/// resources unavailable
pub const KARYOS_E_RESOURCES_UNAVAILABLE: i32 = 308;

/// the driver runs another protocol version
pub const KARYOS_E_INCOMPATIBLE_DRIVER: i32 = 400;

/// the driver refused the client
pub const KARYOS_E_ADMISSION_REFUSED: i32 = 401;

/// admission protocol error
pub const KARYOS_E_PROTOCOL: i32 = 402;

/// internal error; the handle is poisoned
pub const KARYOS_E_INTERNAL: i32 = 500;

/// The size of karyos_image_change with its end fields.
pub const KARYOS_IMAGE_CHANGE_SIZE_ENDS: u32 = 48;

/// Replay rates: as fast as the target takes it; at the recorded pace; the
/// recorded pace scaled by scale_ppm (parts per million, 1 to 100000000).
pub const KARYOS_REPLAY_FULL: u32 = 1;
pub const KARYOS_REPLAY_AS_RECORDED: u32 = 2;
pub const KARYOS_REPLAY_SCALED: u32 = 3;

/// How a subscription ended: not yet; its stream ended cleanly (a replay
/// that reached its end, a remote publication's EOS); its image retired
/// without a complete end (a stopped or failed replay); its stream was
/// removed; revoked with its client's loss; closed by its rejoin policy.
/// KARYOS_END_OTHER is any other end, a reason a newer library adds
/// included, with the raw seal reason in seal_code. A binding keeps an end
/// code its header does not define, as it keeps a status code.
pub const KARYOS_END_NONE: u32 = 0;
pub const KARYOS_END_END_OF_STREAM: u32 = 1;
pub const KARYOS_END_IMAGE_RETIRED: u32 = 2;
pub const KARYOS_END_STREAM_REMOVED: u32 = 3;
pub const KARYOS_END_REVOKED: u32 = 4;
pub const KARYOS_END_CLOSED_BY_OVERRUN: u32 = 5;
pub const KARYOS_END_OTHER: u32 = 255;
