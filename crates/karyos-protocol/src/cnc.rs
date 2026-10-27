// SPDX-License-Identifier: Apache-2.0

//! Client commands and driver responses carried by the CnC structures
//! (SPEC.md §3; quantstratum-docs: karyos/design/client-commands.md).
//!
//! Every message is a fixed little-endian layout of 64-bit words, identified
//! by the record type of the command ring or broadcast buffer. Decoding is
//! strict: the length must match the type exactly, and reserved bits and
//! values are rejected, because commands come from untrusted clients.
//!
//! A command carries only the client's request sequence; the driver knows
//! the sender from the ring it read the command from and forms the
//! [`RequestId`]. Responses carry the full [`RequestId`].
//!
//! Layouts (type id: words, each a little-endian `u64`):
//!
//! | Type | Message | Word 0 | Word 1 | Word 2 | Word 3 |
//! | --- | --- | --- | --- | --- | --- |
//! | `0x01` | `AddPublication` | sequence | stream id (low 32) and session id (high 32) | flags: bit 0 allow unconnected, others zero | lane: below 4 |
//! | `0x02` | `AddSubscription` | sequence | stream and session as above | role: 0 required, 1 optional | lane as `AddPublication` |
//! | `0x03` | `RemovePublication` | sequence | registration | | |
//! | `0x04` | `RemoveSubscription` | sequence | registration | | |
//! | `0x05` | `AddConcurrentPublication` | sequence | stream and session as above | flags as `AddPublication` | lane as `AddPublication` |
//! | `0x06` | `AllocateCounter` | sequence | type id | stream registration or 0 | participant registration or 0 |
//! | `0x07` | `ReleaseCounter` | sequence | cell | registration | |
//! | `0x08` | `ReportLoss` | sequence | driver instance id, high word | driver instance id, low word | stream registration |
//! | `0x09` | `TraceJournal` | sequence | capacity in records (a power of two) | payload words (nonzero) | drop ranges (nonzero) |
//! | `0x0A` | `CloseJournal` | sequence | journal number (nonzero) | final delivery boundary | |
//! | `0x0B` | `QueryCutover` | sequence | registration | | |
//! | `0x0C` | `AddConflatedSubscription` | sequence | stream and session as above | | |
//! | `0x0D` | `GuardClose` | sequence | guard | operation id | operator uid, then the parameters digest |
//! | `0x0E` | `GuardReopen` | sequence | guard | expected closed epoch | operation id, operator uid, then the parameters digest |
//! | `0x0F` | `AddNetworkPublication` | sequence | stream id (low 32; high 32 zero) | flags: as `AddPublication`, and bit 1 concurrent | channel URI length |
//! | `0x10` | `AddNetworkSubscription` | sequence | stream id (low 32; high 32 zero) | role as `AddSubscription` | channel URI length |
//! | `0x11` | `AddImageSubscription` | sequence | image registration (nonzero) | role as `AddSubscription` | lane as `AddPublication` |
//! | `0x12` | `AddNetworkPublicationWithRoles` | sequence | stream id as `AddNetworkPublication` | flags as `AddNetworkPublication` | channel URI length |
//! | `0x13` | `AddNetworkSubscriptionAs` | sequence | stream id as `AddNetworkSubscription` | role as `AddSubscription` | channel URI length |
//! | `0x81` | `PublicationReady` | client | sequence | registration | hand-over key |
//! | `0x82` | `SubscriptionReady` | client | sequence | registration | hand-over key |
//! | `0x83` | `OperationSucceeded` | client | sequence | | |
//! | `0x84` | `Error` | client | sequence | code (1 to 17, see [`ErrorCode`]) | detail |
//! | `0x85` | `CounterAllocated` | client | sequence | cell | registration |
//! | `0x86` | `JournalReady` | client | sequence | journal number | hand-over key |
//! | `0x87` | `CutoverState` | client | sequence | registration | state: 0 current, 1 successor, 2 fenced, 3 closed |
//! | `0x88` | `ConflatedReady` | client | sequence | registration | hand-over key |
//! | `0x89` | `GuardState` | client | sequence | guard | guard word (`karyos_sys::guard`) |
//! | `0x8A` | `NetworkSubscriptionReady` | client | sequence | registration | bound family, port and scope (see below) |
//!
//! `NetworkSubscriptionReady` is exactly six words: client, sequence,
//! registration, then the subscription's bound local address in words 3
//! to 5 (decision row 26; added in place under admission `VERSION` 2,
//! before alpha.2 published it, so the three word layout before it has
//! another length and strict decoding refuses it):
//!
//! | Word | Bits | Meaning |
//! | --- | --- | --- |
//! | 3 | 15 to 0 | port |
//! | 3 | 23 to 16 | family: 0 none, 4 IPv4, 6 IPv6; any other value is refused |
//! | 3 | 31 to 24 | reserved, zero |
//! | 3 | 63 to 32 | IPv6 scope id; zero for IPv4 and for family 0 |
//! | 4 | 63 to 0 | address, high word: IPv6 octets 0 to 7 in network order (octet 0 in bits 63 to 56); zero for IPv4 |
//! | 5 | 63 to 0 | address, low word: IPv6 octets 8 to 15 likewise; IPv4 octets 0 to 3 in bits 31 to 0 (octet 0 in bits 31 to 24), bits 63 to 32 zero |
//!
//! The address is the one the driver's socket reports for the
//! subscription after its bind, not the URI's text. A multicast
//! subscription reports the group address and the bound port, not the
//! interface. The IPv6 flow information is not carried: it decodes as
//! zero. Family 0 means no address, and its port, scope and both address
//! words are zero. Any other bit set is refused as reserved.
//!
//! Two vectors, each the whole message in hex, one group of eight bytes
//! per word (client 1, sequence 2, registration 3), each word
//! little-endian as everywhere in the CnC:
//!
//! - `127.0.0.1:40123`: words `1, 2, 3, 0x0000_0000_0004_9CBB, 0,
//!   0x0000_0000_7F00_0001`:
//!   `0100000000000000 0200000000000000 0300000000000000
//!   BB9C040000000000 0000000000000000 0100007F00000000`.
//! - `[fe80::1%3]:40123`, scope id 3: words `1, 2, 3,
//!   0x0000_0003_0006_9CBB, 0xFE80_0000_0000_0000,
//!   0x0000_0000_0000_0001`:
//!   `0100000000000000 0200000000000000 0300000000000000
//!   BB9C060003000000 00000000000080FE 0100000000000000`.
//!
//! `GuardClose` and `GuardReopen` (`quantstratum-docs:
//! karyos/design/guards-and-abort.md`, local guards): a local operator
//! closes a guard, or reopens one closed at the epoch it names, on the
//! driver's control path, authorized by the calling process's credentials
//! (G1). The operation id is the requester's own id for the audit record
//! (Audit A). The operator uid names the person a tool acts for
//! ([`NO_OPERATOR`]: none, the client acts for itself; any other word is a
//! 32-bit uid, root's 0 included, and a word above `u32::MAX` but
//! [`NO_OPERATOR`] is a reserved value), and the parameters digest is
//! [`guard_parameters`] over what was asked (`quantstratum-docs:
//! karyos/design/management-agent-gap-analysis.md`, M10 and owner item 6);
//! both go to the audit record as given. The operator uid is asserted by
//! the admitted client, not verified by the driver: the driver knows only
//! the client, whose uid admission proved equal to its own (G1), and the
//! tool that sets the operator (the management agent) authenticates its
//! own caller. The driver answers `GuardState` with the guard's word after
//! the transition, or `Error` with `UnknownGuard`, `GuardNotClosedAt`
//! (detail: the current guard word), `GuardExhausted` or `NotAuthorized`.
//!
//! The lane word of `AddPublication`, `AddConcurrentPublication` and
//! `AddSubscription` (`quantstratum-docs: karyos/design/aggregate-ownership.md`,
//! The API) selects one lane of the stream's aggregate; a lane the stream
//! does not configure is refused with `Error` and `UnknownStream`.
//!
//! `AddConflatedSubscription` and `ConflatedReady` (`quantstratum-docs:
//! karyos/design/conflation-end-to-end.md`, Cross-process views): a view
//! of a conflated stream's table, which the grant's fetch carries as one
//! `ConflationTable` region reopened read-only. `ConflatedReady` continues
//! after its four words with the table's configuration, which the view
//! checks against its own limits before it maps anything and then requires
//! of the region: word 4 is the key count (it fits 32 bits), word 5 the
//! value capacity and word 6 the journal capacity, in bytes. A stream that
//! is not conflated is refused with `Error` and `UnknownStream`.
//!
//! `QueryCutover` and `CutoverState` (`quantstratum-docs:
//! karyos/design/ipc-data-path.md`, "Resync after a lap"; coordinator
//! decision ACS 13908): a remote client that fell a lap behind the
//! broadcast buffer, and so may have lost a `SuccessorReady`, `Fenced` or
//! `PublicationClosed`, asks the driver about each of its live remote
//! registrations. For a reserved successor the driver emits the
//! registration's `SuccessorReady` again just before the answer, so the
//! answer itself needs only the state and fits the response limit. A
//! registration that is not one of the sender's is refused with `Error`
//! and `UnknownRegistration`.
//!
//! `AddNetworkPublication` and `AddNetworkSubscription` (wiring note W5,
//! coordinator ACS 16021 and 16027) continue after their four words with
//! the channel URI's UTF-8 bytes, padded with zero bytes to a whole word:
//! the only variable-length commands. Word 3 is the URI's length in bytes,
//! 1 to [`MAX_COMMAND_URI`]; a longer URI is refused on the client side,
//! and the driver configuration keeps the longer URIs a channel allows
//! (SPEC §18). The driver parses the URI: a `karyos:ipc` channel resolves
//! the stream as `AddPublication` does, a `karyos:udp` one creates a
//! network publication or subscription. The command names no session id
//! and no lane: the driver draws the publication's session id, its wire
//! alias, and returns it with the grant; the lanes are the URI's `lanes`.
//! A URI that does not parse is refused with `Error` and `InvalidChannel`
//! (the detail names the parse error), one the driver cannot serve with
//! `UnsupportedChannel`, and a subscription whose reliability differs from
//! its endpoint and stream's existing one with `ReliabilityMismatch`.
//! `ReceiverIdentityMismatch` (code 15) answers a subscription whose
//! configured receiver identity differs from its key's existing one.
//! `LaneMismatch` (code 16) answers an exclusive publication whose URI
//! names `lanes` other than the stream configures, granting nothing.
//! Bit 1 of `AddNetworkPublication`'s flags asks for a concurrent handle
//! on lane 0 instead of the exclusive publication (M11; added in place
//! under admission `VERSION` 2, before alpha.2 published it): a
//! `karyos:ipc` URI only, so the stream is shared with its other
//! publishers. A `karyos:udp` one is refused with `UnsupportedChannel`,
//! an exclusive stream with `InvalidPublicationMode`. A driver that does
//! not know the bit fails to decode the command and retires the client as
//! faulty (`ClientProtocolViolation`), with no response.
//!
//! `AddNetworkPublicationWithRoles` and `AddNetworkSubscriptionAs` (owner
//! decisions of 2026-10-21, item 7; karyos#637; layout decided 2026-10-27
//! by QS-COORDINATOR under owner delegation) are new types of admission
//! [`VERSION`](crate::admission::VERSION) 3, carrying a publication's
//! receiver roles and a subscription's receiver identity
//! ([`crate::roles`]). Both continue after their four words with words 4
//! and 5, then the channel URI as above:
//!
//! | Message | Word 4 | Word 5 |
//! | --- | --- | --- |
//! | `AddNetworkPublicationWithRoles` | bits 7 to 0 the strategy (0 `min`, 1 `max`, 2 `tagged`); bits 31 to 16 `R`, the required count; bits 47 to 32 `T`, the tag count; other bits zero | the tagged group: nonzero for `tagged`, zero otherwise |
//! | `AddNetworkSubscriptionAs` | `receiver_id`, nonzero | `group_tag` |
//!
//! `AddNetworkPublicationWithRoles` continues after its URI's padding with
//! `R` words, the required `receiver_id`s (nonzero, distinct), then `T`
//! pairs of words, a `receiver_id` (nonzero, distinct among the pairs) and
//! its tag (nonzero): `6 + ceil(L / 8) + R + 2T` words in all, `L` the URI's length.
//! `AddNetworkSubscriptionAs` is exactly `6 + ceil(L / 8)` words. Flags,
//! role and URI follow their `AddNetworkPublication` and
//! `AddNetworkSubscription` rules; a concurrent handle is refused with
//! `UnsupportedChannel`, since roles are a network publication's. The
//! roles' strategy must be the URI's `fc` (`min` without one): otherwise
//! `Error` with `StrategyConflict`, granting nothing. The only bound on
//! `R + 2T` is the command ring's largest record (`ring_capacity / 8`):
//! a client refuses a command that does not fit before sending it
//! (`CommandTooLarge`), and the driver checks the roles against its
//! membership's `max_receivers`. No other numeric limit applies.
//!
//! `AllocateCounter` (`quantstratum-docs:
//! karyos/design/observability-and-tools.md`, "Client counters") continues
//! after its four words with the label: word 4 is its length in bytes (at
//! most [`MAX_LABEL_LENGTH`], the other bits zero), and words 5 to 12 hold
//! its UTF-8 bytes, padded with zero bytes.
//!
//! `ReportLoss` (`quantstratum-docs:
//! karyos/design/observability-and-tools.md`, "Loss reports from clients")
//! continues after its four words: word 4 is the stream's incarnation,
//! word 5 the subscription's registration, words 6 and 7 the lost range
//! (from and to, half open, `from <= to`), and word 8 packs the lane (bits
//! 7 to 0, below 4), the configured rejoin policy (bits 15 to 8, a
//! [`RejoinPolicyCode`]), the applied outcome (bits 23 to 16, a
//! [`RejoinOutcomeCode`]) and the replay fallback reason (bits 31 to 24, a
//! [`FallbackReasonCode`], nonzero exactly when the configured policy is
//! `replay` and the outcome is not `Replayed`); the other bits are zero.
//! The outcome must be one the configured policy can produce. `Replayed`
//! and the reasons from 4 on were added in place under admission
//! `VERSION` 2, before alpha.2 published it. The driver answers `OperationSucceeded`
//! when it recorded the report, and nothing for a protocol violation.
//!
//! `TraceJournal` continues after its four words with word 4, the
//! observed registration (nonzero), and word 5, the clock provenance
//! word. The two words were added in place under admission `VERSION` 2,
//! before alpha.2 published it (`quantstratum-docs:
//! karyos/design/trace-tool.md`, T2 and T4): the five word layout before
//! them has another length, so strict decoding refuses it.
//!
//! `TraceJournal` and `CloseJournal` (`quantstratum-docs:
//! karyos/design/trace-journal-region.md`, J2 and J3): a client asks the
//! driver for a trace journal of its sizes, which the driver creates and
//! drains, naming the registration the journal observes: a live
//! subscription of the client (a subscriber journal, whose stream and join
//! position the driver takes from its own record) or a live publication of
//! the client (a publisher journal, which has no join position). One
//! counter issues every registration, so the driver derives the kind from
//! what the registration names; anything else is refused with `Error` and
//! `UnknownRegistration`. The provenance word is opaque to the driver,
//! which records it in the journal's table entry for tools; its values are
//! defined by the trace crate. The answer `JournalReady` carries the
//! journal number the driver assigned and the hand-over key under which
//! the client takes it, or `Error` with `TraceJournalsExhausted` when the
//! driver's journal table has no free entry. `CloseJournal` gives the journal's final delivery
//! boundary before the client closes it; the driver answers
//! `OperationSucceeded`, or `Error` with `UnknownRegistration` for a
//! journal that is not an open journal of the client without a boundary.
//!
//! Driver events (record types `0xC0` to `0xFF`, [`Event`]) answer no
//! request and are broadcast to every client:
//!
//! | Type | Event | Word 0 | Word 1 | Word 2 | Word 3 | Word 4 |
//! | --- | --- | --- | --- | --- | --- | --- |
//! | `0xC1` | `ParticipantLost` | stream and session | registration | client | policy: 1 hold, 2 continue, 3 abort | position |
//! | `0xC2` | `RequiredBoundWithdrawn` | stream and session | registration | position | | |
//! | `0xC3` | `PublicationClosed` | stream and session | reason: 1 required participant lost | lane: below 4 | image registration, or 0 | |
//! | `0xC4` | `SuccessorReady` | stream and session | registration | hand-over key of the successor grant | base position | generation |
//! | `0xC5` | `Fenced` | stream and session | registration | | | |
//! | `0xC6` | `ImageAvailable` | stream and session | network subscription registration | image registration (nonzero) | source family, port and scope (see below) | source address, high word |
//! | `0xC7` | `ImageUnavailable` | stream and session | network subscription registration | image registration (nonzero) | | |
//! | `0xC8` | `PublicationAdmission` | stream and session | network publication registration | admission: 1 open, 2 not joined, 3 lost required | | |
//!
//! `ImageAvailable` continues after its five words with word 5, the
//! source address's low word. Its source in words 3 to 5 has exactly
//! `NetworkSubscriptionReady`'s address encoding in its words 3 to 5 (one
//! address encoding under admission `VERSION` 2, aligned before its
//! freeze; the layout before it put an IPv4 address in word 4 and carried
//! no scope, and strict decoding refuses it): word 3 is the port (bits 15
//! to 0), the family (bits 23 to 16: 4 or 6), reserved bits 31 to 24 zero
//! and the IPv6 scope id (bits 63 to 32, zero for IPv4); word 4 is IPv6
//! octets 0 to 7 in network order, zero for IPv4; word 5 is IPv6 octets
//! 8 to 15 likewise, or the IPv4 octets in bits 31 to 0 with bits 63 to
//! 32 zero. An image always has a source, so family 0 is refused here.
//! The IPv6 scope id is carried; the flow information is not and decodes
//! as zero. Any other bit set is refused as reserved.
//!
//! One vector, the whole message in hex as above (stream 7 session 5,
//! registration 2, image 3, source `[fe80::1%3]:40123`, scope id 3):
//! words `0x0000_0005_0000_0007, 2, 3, 0x0000_0003_0006_9CBB,
//! 0xFE80_0000_0000_0000, 0x0000_0000_0000_0001`:
//! `0700000005000000 0200000000000000 0300000000000000
//! BB9C060003000000 00000000000080FE 0100000000000000`.
//!
//! `ImageAvailable` and `ImageUnavailable` (`quantstratum-docs:
//! karyos/design/per-source-images.md`, D2-3): a remote publication's
//! image became a stream of the driver, or retired. Images of one alias
//! from several sources are each announced, named by their aggregate
//! registration and their source. A client of the network subscription
//! attaches to one with `AddImageSubscription` naming its registration;
//! `AddSubscription` naming the alias reaches the oldest live image of it.
//! `PublicationClosed` names the image registration when the closed lane
//! is an image's, and 0 for any other stream.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::SealReason;
use thiserror::Error;

use crate::roles::{PublicationRoles, ReceiverIdentity};

/// Longest counter label, in bytes: the label of a counter cell.
pub const MAX_LABEL_LENGTH: usize = karyos_sys::counters::MAX_LABEL_LENGTH;
/// Words of an encoded counter label.
const LABEL_WORDS: usize = MAX_LABEL_LENGTH / 8;
/// Words of an encoded `AllocateCounter`: four, the label length and the
/// label.
const ALLOCATE_COUNTER_WORDS: usize = 5 + LABEL_WORDS;
/// Words of an encoded `ReportLoss`.
const REPORT_LOSS_WORDS: usize = 9;
/// Longest channel URI a client command carries, in bytes (SPEC §18): an
/// encoded command then fits the default command ring.
pub const MAX_COMMAND_URI: usize = 512;
/// Words of the fixed part of a command carrying a channel URI.
const URI_COMMAND_WORDS: usize = 4;
/// Words of the fixed part of a command carrying a channel URI with
/// receiver roles or a receiver identity (karyos#637).
const ROLES_COMMAND_WORDS: usize = 6;
/// The strategy codes of `AddNetworkPublicationWithRoles` (word 4, bits 7
/// to 0).
const STRATEGY_MIN: u64 = 0;
const STRATEGY_MAX: u64 = 1;
const STRATEGY_TAGGED: u64 = 2;
/// Largest encoded command, in bytes: a command with the longest channel
/// URI.
pub const MAX_COMMAND_LENGTH: usize =
    if URI_COMMAND_WORDS * 8 + MAX_COMMAND_URI > ALLOCATE_COUNTER_WORDS * 8 {
        URI_COMMAND_WORDS * 8 + MAX_COMMAND_URI
    } else {
        ALLOCATE_COUNTER_WORDS * 8
    };
/// Words of an encoded `ConflatedReady`: four, and the configuration.
const CONFLATED_READY_WORDS: usize = 7;
/// Largest encoded response, in bytes: `ConflatedReady`.
pub const MAX_RESPONSE_LENGTH: usize = CONFLATED_READY_WORDS * 8;
/// Largest encoded driver event, in bytes: `ImageAvailable`.
pub const MAX_EVENT_LENGTH: usize = IMAGE_AVAILABLE_WORDS * 8;
/// Words of an encoded `ImageAvailable`.
const IMAGE_AVAILABLE_WORDS: usize = 6;
/// Words of an encoded `NetworkSubscriptionReady`.
const NETWORK_SUBSCRIPTION_READY_WORDS: usize = 6;

const ADD_PUBLICATION: u32 = 0x01;
const ADD_SUBSCRIPTION: u32 = 0x02;
const REMOVE_PUBLICATION: u32 = 0x03;
const REMOVE_SUBSCRIPTION: u32 = 0x04;
const ADD_CONCURRENT_PUBLICATION: u32 = 0x05;
const ALLOCATE_COUNTER: u32 = 0x06;
const RELEASE_COUNTER: u32 = 0x07;
const REPORT_LOSS: u32 = 0x08;
const TRACE_JOURNAL: u32 = 0x09;
const CLOSE_JOURNAL: u32 = 0x0A;
const QUERY_CUTOVER: u32 = 0x0B;
const ADD_CONFLATED_SUBSCRIPTION: u32 = 0x0C;
const GUARD_CLOSE: u32 = 0x0D;
const GUARD_REOPEN: u32 = 0x0E;
const ADD_NETWORK_PUBLICATION: u32 = 0x0F;
const ADD_NETWORK_SUBSCRIPTION: u32 = 0x10;
const ADD_IMAGE_SUBSCRIPTION: u32 = 0x11;
const ADD_NETWORK_PUBLICATION_WITH_ROLES: u32 = 0x12;
const ADD_NETWORK_SUBSCRIPTION_AS: u32 = 0x13;
const PUBLICATION_READY: u32 = 0x81;
const SUBSCRIPTION_READY: u32 = 0x82;
const OPERATION_SUCCEEDED: u32 = 0x83;
const ERROR: u32 = 0x84;
const COUNTER_ALLOCATED: u32 = 0x85;
const JOURNAL_READY: u32 = 0x86;
const CUTOVER_STATE: u32 = 0x87;
const CONFLATED_READY: u32 = 0x88;
const GUARD_STATE: u32 = 0x89;
const NETWORK_SUBSCRIPTION_READY: u32 = 0x8A;

/// Whether `epoch` is one a guard can be closed at (`karyos_sys::guard`).
const fn closed_epoch(epoch: u64) -> bool {
    karyos_sys::guard::encode(karyos_sys::guard::GuardState { epoch, open: false }).is_some()
}
const PARTICIPANT_LOST: u32 = 0xC1;
const REQUIRED_BOUND_WITHDRAWN: u32 = 0xC2;
const PUBLICATION_CLOSED: u32 = 0xC3;
const SUCCESSOR_READY: u32 = 0xC4;
const FENCED: u32 = 0xC5;
const IMAGE_AVAILABLE: u32 = 0xC6;
const IMAGE_UNAVAILABLE: u32 = 0xC7;
const PUBLICATION_ADMISSION: u32 = 0xC8;

const ALLOW_UNCONNECTED: u64 = 1;
/// `AddNetworkPublication`'s flag for a concurrent handle (M11).
const CONCURRENT: u64 = 2;

// Every command fits the bound.
const _: () = assert!(REPORT_LOSS_WORDS * 8 <= MAX_COMMAND_LENGTH);

/// Errors decoding or encoding CnC messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum CncError {
    /// The record type is not a message of this direction.
    #[error("unknown message type {type_id:#x}")]
    UnknownType {
        /// The record type.
        type_id: u32,
    },
    /// The length does not match the type's fixed layout.
    #[error("message type {type_id:#x} has {length} bytes, expected {expected}")]
    WrongLength {
        /// The record type.
        type_id: u32,
        /// The length found.
        length: usize,
        /// The layout's length.
        expected: usize,
    },
    /// A reserved bit or value is set.
    #[error("message type {type_id:#x} sets a reserved value")]
    Reserved {
        /// The record type.
        type_id: u32,
    },
    /// The output buffer is too short.
    #[error("buffer of {available} bytes is shorter than the required {required}")]
    BufferTooShort {
        /// Bytes required.
        required: usize,
        /// Bytes available.
        available: usize,
    },
}

/// A subscriber's role (SPEC.md §4 reader roles).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SubscriberRole {
    /// Bounds the publisher; never lapped.
    Required,
    /// Does not bound the publisher; may be lapped.
    Optional,
    /// Does not bound the publisher, may be lapped, and only copies
    /// (`quantstratum-docs: karyos/design/observer-role.md`).
    Observer,
}

impl From<SubscriberRole> for karyos_sys::log_buffer::Role {
    fn from(role: SubscriberRole) -> Self {
        match role {
            SubscriberRole::Required => Self::Required,
            SubscriberRole::Optional => Self::Optional,
            SubscriberRole::Observer => Self::Observer,
        }
    }
}

/// A request, identified by the client (as known to the driver) and the
/// client's request sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestId {
    /// The driver-assigned client id.
    pub client: u64,
    /// The client's request sequence.
    pub sequence: u64,
}

/// A stream id (SPEC §10): the application's name for a stream on a
/// channel. Every value is valid; a stream's sessions share it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(i32);

impl StreamId {
    /// The stream id `id`.
    #[must_use]
    pub const fn new(id: i32) -> Self {
        Self(id)
    }

    /// The raw id.
    #[must_use]
    pub const fn get(self) -> i32 {
        self.0
    }
}

/// A stream's wire identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamKey {
    /// Wire stream id.
    pub stream_id: i32,
    /// Session id.
    pub session_id: i32,
}

/// The label of a client counter: UTF-8 of at most [`MAX_LABEL_LENGTH`]
/// bytes, stored inline so that [`Command`] stays `Copy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CounterLabel {
    bytes: [u8; MAX_LABEL_LENGTH],
    length: u8,
}

impl CounterLabel {
    /// The label `label`; `None` when it exceeds [`MAX_LABEL_LENGTH`]
    /// bytes.
    #[must_use]
    pub fn new(label: &str) -> Option<Self> {
        Self::from_bytes(label.as_bytes())
    }

    /// The label of `bytes`; `None` unless they are UTF-8 of at most
    /// [`MAX_LABEL_LENGTH`] bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        core::str::from_utf8(bytes).ok()?;
        let length = u8::try_from(bytes.len())
            .ok()
            .filter(|&length| usize::from(length) <= MAX_LABEL_LENGTH)?;
        let mut stored = [0u8; MAX_LABEL_LENGTH];
        stored.get_mut(..bytes.len())?.copy_from_slice(bytes);
        Some(Self {
            bytes: stored,
            length,
        })
    }

    /// The label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Only UTF-8 is ever stored (checked by every constructor).
        self.bytes
            .get(..usize::from(self.length))
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
            .unwrap_or("")
    }
}

/// A channel URI a client command carries: UTF-8 of 1 to
/// [`MAX_COMMAND_URI`] bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChannelUri {
    bytes: [u8; MAX_COMMAND_URI],
    length: u16,
}

impl core::fmt::Debug for ChannelUri {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("ChannelUri").field(&self.as_str()).finish()
    }
}

impl ChannelUri {
    /// The URI `uri`; `None` when it is empty or longer than
    /// [`MAX_COMMAND_URI`] bytes.
    #[must_use]
    pub fn new(uri: &str) -> Option<Self> {
        Self::from_bytes(uri.as_bytes())
    }

    /// The URI of `bytes`; `None` unless they are UTF-8 of 1 to
    /// [`MAX_COMMAND_URI`] bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        core::str::from_utf8(bytes).ok()?;
        if bytes.is_empty() || bytes.len() > MAX_COMMAND_URI {
            return None;
        }
        let length = u16::try_from(bytes.len()).ok()?;
        let mut stored = [0u8; MAX_COMMAND_URI];
        stored.get_mut(..bytes.len())?.copy_from_slice(bytes);
        Some(Self {
            bytes: stored,
            length,
        })
    }

    /// The URI.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Only UTF-8 is ever stored (checked by every constructor).
        self.bytes
            .get(..usize::from(self.length))
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
            .unwrap_or("")
    }

    /// Its bytes padded with zeros to a whole word.
    fn padded(&self) -> &[u8] {
        let length = usize::from(self.length).next_multiple_of(8);
        self.bytes.get(..length).unwrap_or(&self.bytes)
    }
}

/// A subscription's configured rejoin policy, as a loss report carries
/// it: a stable `u8` code, never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum RejoinPolicyCode {
    /// `rejoin at head`.
    RejoinAtHead = 1,
    /// `snapshot`.
    Snapshot = 2,
    /// `close`.
    Close = 3,
    /// `replay`, which falls back to a secondary policy in phase 1.
    Replay = 4,
}

impl RejoinPolicyCode {
    const fn from_code(code: u64) -> Option<Self> {
        Some(match code {
            1 => Self::RejoinAtHead,
            2 => Self::Snapshot,
            3 => Self::Close,
            4 => Self::Replay,
            _ => return None,
        })
    }
}

/// What the rejoin policy actually applied did, as a loss report carries
/// it: a stable `u8` code, never reused. For a `replay` that fell back,
/// it is the secondary policy's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum RejoinOutcomeCode {
    /// Delivery continued at the head.
    ResumedAtHead = 1,
    /// The snapshot source rebuilt the state.
    SnapshotRebuilt = 2,
    /// The snapshot source failed: the subscription closed.
    SnapshotFailed = 3,
    /// The subscription closed.
    Closed = 4,
    /// `replay` recovered the range from a recording and merged back into
    /// the live stream.
    Replayed = 5,
}

impl RejoinOutcomeCode {
    const fn from_code(code: u64) -> Option<Self> {
        Some(match code {
            1 => Self::ResumedAtHead,
            2 => Self::SnapshotRebuilt,
            3 => Self::SnapshotFailed,
            4 => Self::Closed,
            5 => Self::Replayed,
            _ => return None,
        })
    }

    /// Whether the policy `configured` (directly, or as the secondary of
    /// `replay`) can produce this outcome.
    const fn follows(self, configured: RejoinPolicyCode) -> bool {
        matches!(
            (configured, self),
            (RejoinPolicyCode::RejoinAtHead, Self::ResumedAtHead)
                | (
                    RejoinPolicyCode::Snapshot,
                    Self::SnapshotRebuilt | Self::SnapshotFailed
                )
                | (RejoinPolicyCode::Close, Self::Closed)
                | (RejoinPolicyCode::Replay, _)
        )
    }
}

/// Why `replay` fell back to its secondary policy, as a loss report
/// carries it: a stable `u8` code, never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum FallbackReasonCode {
    /// No Archive exists (phase 1).
    NoArchive = 1,
    /// No recording covers the gap (phase 3).
    NoRecording = 2,
    /// The recording's retention does not reach the gap (phase 3).
    RetentionShort = 3,
    /// The recording had not reached the gap's end in time (phase 3).
    RecordingBehind = 4,
    /// The Archive refused the replay (phase 3).
    Refused = 5,
    /// The replay and the live stream did not merge (phase 3).
    MergeFailed = 6,
    /// The gap was given up before it resolved: the rejoin was dropped,
    /// or its live reader taken back, while the gap was asked for or
    /// merging (phase 3).
    Withdrawn = 7,
}

impl FallbackReasonCode {
    const fn from_code(code: u64) -> Option<Self> {
        Some(match code {
            1 => Self::NoArchive,
            2 => Self::NoRecording,
            3 => Self::RetentionShort,
            4 => Self::RecordingBehind,
            5 => Self::Refused,
            6 => Self::MergeFailed,
            7 => Self::Withdrawn,
            _ => return None,
        })
    }
}

/// An overrun as the subscription captured it when it happened
/// (`quantstratum-docs: karyos/design/observability-and-tools.md`, "Loss
/// reports from clients"): the stream's full publication identity, the
/// subscription, the lane, the lost range and the rejoin policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReportedLoss {
    /// The driver instance id of the publication's identity, two words.
    pub driver: [u64; 2],
    /// The stream registration of the publication's identity.
    pub stream_registration: u64,
    /// The incarnation of the publication's identity.
    pub incarnation: u64,
    /// The overrun subscription's registration.
    pub subscription: u64,
    /// The lane, below 4.
    pub lane: u8,
    /// First position lost.
    pub from: u64,
    /// End of the lost range (exclusive), at least `from`.
    pub to: u64,
    /// The configured rejoin policy.
    pub configured: RejoinPolicyCode,
    /// The outcome of the policy applied: for `replay`, the secondary's.
    pub applied: RejoinOutcomeCode,
    /// Why `replay` fell back; `Some` exactly when `configured` is
    /// [`RejoinPolicyCode::Replay`] and `applied` is not
    /// [`RejoinOutcomeCode::Replayed`].
    pub fallback: Option<FallbackReasonCode>,
}

impl ReportedLoss {
    fn packed(&self) -> u64 {
        u64::from(self.lane)
            | u64::from(self.configured as u8) << 8
            | u64::from(self.applied as u8) << 16
            | u64::from(self.fallback.map_or(0, |reason| reason as u8)) << 24
    }

    fn decode(words: [u64; REPORT_LOSS_WORDS - 1]) -> Option<Self> {
        let [
            high,
            low,
            stream_registration,
            incarnation,
            subscription,
            from,
            to,
            packed,
        ] = words;
        if packed >> 32 != 0 || from > to {
            return None;
        }
        let lane = u8::try_from(packed & 0xFF)
            .ok()
            .filter(|&lane| lane < karyos_sys::frame::Lane::COUNT)?;
        let configured = RejoinPolicyCode::from_code((packed >> 8) & 0xFF)?;
        let applied = RejoinOutcomeCode::from_code((packed >> 16) & 0xFF)?;
        let fallback = match (packed >> 24) & 0xFF {
            0 => None,
            code => Some(FallbackReasonCode::from_code(code)?),
        };
        let fell_back =
            configured == RejoinPolicyCode::Replay && applied != RejoinOutcomeCode::Replayed;
        if !applied.follows(configured) || fallback.is_some() != fell_back {
            return None;
        }
        Some(Self {
            driver: [high, low],
            stream_registration,
            incarnation,
            subscription,
            lane,
            from,
            to,
            configured,
            applied,
            fallback,
        })
    }
}

/// A command from a client. Not `Copy`: a command with receiver roles
/// owns their lists.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Command {
    /// Create the stream's exclusive publication.
    AddPublication {
        /// Request sequence.
        sequence: u64,
        /// The stream.
        stream: StreamKey,
        /// The lane of the stream's aggregate.
        lane: Lane,
        /// Accept offers with no subscriber attached.
        allow_unconnected: bool,
    },
    /// Admit a subscriber to the stream.
    AddSubscription {
        /// Request sequence.
        sequence: u64,
        /// The stream.
        stream: StreamKey,
        /// The lane of the stream's aggregate.
        lane: Lane,
        /// The subscriber's role.
        role: SubscriberRole,
    },
    /// Create an exclusive publication of `stream_id` on the channel `uri`
    /// (W5): the driver draws its session id. With `concurrent`, a
    /// concurrent handle on lane 0 of the `karyos:ipc` stream instead.
    AddNetworkPublication {
        /// Request sequence.
        sequence: u64,
        /// The stream.
        stream_id: i32,
        /// Accept offers with no subscriber attached.
        allow_unconnected: bool,
        /// A concurrent handle rather than the exclusive publication.
        concurrent: bool,
        /// The channel.
        uri: ChannelUri,
    },
    /// Admit a subscriber to one lane of the network image whose
    /// aggregate registration is `image` (`quantstratum-docs:
    /// karyos/design/per-source-images.md`, D2-3), as announced by
    /// `ImageAvailable`.
    AddImageSubscription {
        /// Request sequence.
        sequence: u64,
        /// The image's aggregate registration (nonzero).
        image: u64,
        /// The lane of the image's aggregate.
        lane: Lane,
        /// The subscriber's role.
        role: SubscriberRole,
    },
    /// Subscribe `stream_id` on the channel `uri` (W5): its images are
    /// announced with `ImageAvailable`.
    AddNetworkSubscription {
        /// Request sequence.
        sequence: u64,
        /// The stream.
        stream_id: i32,
        /// The role of the subscribers that attach to its images.
        role: SubscriberRole,
        /// The channel.
        uri: ChannelUri,
    },
    /// [`Command::AddNetworkPublication`] of an exclusive publication
    /// whose receivers have the configured `roles` (owner decisions of
    /// 2026-10-21, item 7; karyos#637). The roles' strategy must be the
    /// URI's `fc`. `concurrent` is never granted: a concurrent handle is a
    /// `karyos:ipc` stream's, which has no receivers.
    AddNetworkPublicationWithRoles {
        /// Request sequence.
        sequence: u64,
        /// The stream.
        stream_id: i32,
        /// Accept offers with no subscriber attached.
        allow_unconnected: bool,
        /// A concurrent handle was asked for; refused by the driver.
        concurrent: bool,
        /// The channel.
        uri: ChannelUri,
        /// The receivers' roles.
        roles: PublicationRoles,
    },
    /// [`Command::AddNetworkSubscription`] whose images name the
    /// configured receiver `identity` (MC-1, MC-2; karyos#637).
    AddNetworkSubscriptionAs {
        /// Request sequence.
        sequence: u64,
        /// The stream.
        stream_id: i32,
        /// The role of the subscribers that attach to its images.
        role: SubscriberRole,
        /// The channel.
        uri: ChannelUri,
        /// The receiver identity.
        identity: ReceiverIdentity,
    },
    /// Issue a concurrent publication handle on one of the stream's
    /// publisher slots.
    AddConcurrentPublication {
        /// Request sequence.
        sequence: u64,
        /// The stream.
        stream: StreamKey,
        /// The lane of the stream's aggregate.
        lane: Lane,
        /// Accept offers with no subscriber attached.
        allow_unconnected: bool,
    },
    /// Remove a publication of either kind the client owns.
    RemovePublication {
        /// Request sequence.
        sequence: u64,
        /// The registration.
        registration: u64,
    },
    /// Remove a subscription the client owns.
    RemoveSubscription {
        /// Request sequence.
        sequence: u64,
        /// The registration.
        registration: u64,
    },
    /// Allocate a client counter cell, owned by the client, in the client
    /// counters region (`quantstratum-docs:
    /// karyos/design/observability-and-tools.md`, "Client counters").
    AllocateCounter {
        /// Request sequence.
        sequence: u64,
        /// Application-defined counter type.
        type_id: u64,
        /// The counter's label.
        label: CounterLabel,
        /// Registration of a live stream, or 0.
        stream: u64,
        /// Registration of a live participant of this client, or 0.
        participant: u64,
    },
    /// Release the client counter allocation `registration` in `cell`.
    ReleaseCounter {
        /// Request sequence.
        sequence: u64,
        /// The cell.
        cell: u64,
        /// The allocation's registration.
        registration: u64,
    },
    /// Report an overrun of one of the client's subscriptions, for the
    /// driver's loss report and overrun counters.
    ReportLoss {
        /// Request sequence.
        sequence: u64,
        /// The loss as captured.
        loss: ReportedLoss,
    },
    /// Ask the driver for a trace journal of these sizes, which it creates
    /// and drains into its trace mirror (`quantstratum-docs:
    /// karyos/design/trace-journal-region.md`).
    TraceJournal {
        /// Request sequence.
        sequence: u64,
        /// Records, a nonzero power of two.
        capacity: u64,
        /// Payload words per record, nonzero.
        payload_words: u64,
        /// Drop-range entries, nonzero.
        drop_ranges: u64,
        /// The registration the journal observes (nonzero): one of the
        /// client's live subscriptions (a subscriber journal) or live
        /// publications (a publisher journal, which has no join position).
        registration: u64,
        /// The clock provenance of the journal's observer: a raw word the
        /// driver records in the journal's table entry without
        /// interpreting it (`karyos-trace`'s `ClockProvenance::word`: 0
        /// opaque, 1 the standard library's monotonic clock, 2 the host's
        /// `CLOCK_MONOTONIC`).
        provenance: u64,
    },
    /// The final delivery boundary of one of the client's journals, sent
    /// before the client closes it.
    CloseJournal {
        /// Request sequence.
        sequence: u64,
        /// The journal number (nonzero).
        journal: u64,
        /// The final delivery boundary.
        boundary: u64,
    },
    /// Ask for the cutover state of one of the client's remote
    /// registrations, after a lap of the broadcast buffer.
    QueryCutover {
        /// Request sequence.
        sequence: u64,
        /// The registration.
        registration: u64,
    },
    /// Ask for a read-only view of a conflated stream's table.
    AddConflatedSubscription {
        /// Request sequence.
        sequence: u64,
        /// The stream.
        stream: StreamKey,
    },
    /// Close a guard (local control, G1).
    GuardClose {
        /// Request sequence.
        sequence: u64,
        /// The guard.
        guard: u64,
        /// The requester's operation id, for the audit record.
        operation: u64,
        /// The operator uid the requester acts for; [`NO_OPERATOR`] for none.
        operator: u64,
        /// [`guard_parameters`] of the request, for the audit record.
        parameters: u64,
    },
    /// Reopen a guard closed at `expected` (local control, G1).
    GuardReopen {
        /// Request sequence.
        sequence: u64,
        /// The guard.
        guard: u64,
        /// The closed epoch the reopen replaces.
        expected: u64,
        /// The requester's operation id, for the audit record.
        operation: u64,
        /// The operator uid the requester acts for; [`NO_OPERATOR`] for none.
        operator: u64,
        /// [`guard_parameters`] of the request, for the audit record.
        parameters: u64,
    },
}

/// The operator word of a guard command that acts for no operator: the
/// client acts for itself. Every other word is a uid, at most `u32::MAX`
/// (root's 0 included).
pub const NO_OPERATOR: u64 = u64::MAX;

/// Whether `operator` is an operator word a guard command may carry.
fn operator_word(operator: u64) -> bool {
    operator == NO_OPERATOR || u32::try_from(operator).is_ok()
}

/// The parameters digest of a guard command: 64-bit FNV-1a over the guard,
/// the expected epoch (0 for a close), the operation id and the operator
/// uid, each as eight little-endian bytes, then the operator's reason.
/// It binds the audit record to what was asked, and is nonzero even with
/// no reason; it is a correlation aid, not a security digest
/// (authenticated audit waits on ADR-0035).
#[must_use]
pub fn guard_parameters(
    guard: u64,
    expected: u64,
    operation: u64,
    operator: u64,
    reason: &[u8],
) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0100_0000_01b3;
    [guard, expected, operation, operator]
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .chain(reason.iter().copied())
        .fold(OFFSET, |hash, byte| {
            // FNV-1a multiplies modulo 2^64 by definition. ADR-0007's rule
            // against wrapping covers positions, lengths and counters, whose
            // overflow is an error; a hash has no overflow to report.
            (hash ^ u64::from(byte)).wrapping_mul(PRIME)
        })
}

/// The admission state of a network publication, as its sender last
/// observed it (owner decisions of 2026-10-21, item 7; karyos#637;
/// `quantstratum-docs: karyos/design/multicast-flow-control.md`). Offers
/// keep the existing outcome mapping: under `NotJoined` and `LostRequired`
/// the sender stages nothing, so the publication fills its window and its
/// offers answer `BackPressured`, never a terminal outcome while the
/// policy is stop admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NetworkAdmission {
    /// Every configured required receiver has joined and none is lost (and
    /// a publication with none is open).
    Open,
    /// A configured required receiver has not joined yet.
    NotJoined,
    /// A required receiver is lost: admission stops for the incarnation
    /// (owner decision M5).
    LostRequired,
}

impl NetworkAdmission {
    /// The wire code: 1, 2, 3; 0 is no state reported yet.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            Self::Open => 1,
            Self::NotJoined => 2,
            Self::LostRequired => 3,
        }
    }

    /// The state of a wire code; `None` for 0 (none reported yet) and any
    /// code not defined.
    #[must_use]
    pub const fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(Self::Open),
            2 => Some(Self::NotJoined),
            3 => Some(Self::LostRequired),
            _ => None,
        }
    }
}

/// Why the driver refused a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// Every publication the stream can issue is out: its exclusive
    /// publication, or all publisher slots of a concurrent stream.
    PublicationTaken,
    /// No such stream.
    UnknownStream,
    /// No such registration owned by this client.
    UnknownRegistration,
    /// A limit (cells, credits, pending requests, hand-over) is reached.
    ResourcesUnavailable,
    /// An identity counter is exhausted.
    IdentitiesExhausted,
    /// The requested publication kind does not match the stream's mode.
    InvalidPublicationMode,
    /// Every entry of the driver's journal table is held: by an open
    /// journal, or by an ended one whose records the trace mirror still
    /// retains. Nothing was created.
    TraceJournalsExhausted,
    /// No such guard.
    UnknownGuard,
    /// A reopen named an epoch the guard is not closed at; the detail is
    /// the current guard word.
    GuardNotClosedAt,
    /// A reopen would exceed the guard's last epoch; it stays closed.
    GuardExhausted,
    /// The calling process is not authorized for this guard (G1).
    NotAuthorized,
    /// The channel URI does not parse; the detail is the parse error's
    /// code (W5).
    InvalidChannel,
    /// The driver does not serve this channel: no network, a feature not
    /// wired yet, or shared terms (W5).
    UnsupportedChannel,
    /// A network subscription asks for another reliability than the one
    /// its endpoint and stream are already subscribed with (W5b).
    ReliabilityMismatch,
    /// A network subscription names another receiver identity than the
    /// one its endpoint and stream are already subscribed with (MC-1).
    ReceiverIdentityMismatch,
    /// An exclusive publication's URI names `lanes` other than the stream
    /// configures; nothing is granted (W8). The detail is the stream's lane
    /// count.
    LaneMismatch,
    /// A network publication's roles name another strategy than its URI's
    /// `fc`, the one source of the strategy (owner item 7, karyos#637).
    StrategyConflict,
}

impl ErrorCode {
    /// The code's wire value, as the `Refused` completion carries it.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            Self::PublicationTaken => 1,
            Self::UnknownStream => 2,
            Self::UnknownRegistration => 3,
            Self::ResourcesUnavailable => 4,
            Self::IdentitiesExhausted => 5,
            Self::InvalidPublicationMode => 6,
            Self::TraceJournalsExhausted => 7,
            Self::UnknownGuard => 8,
            Self::GuardNotClosedAt => 9,
            Self::GuardExhausted => 10,
            Self::NotAuthorized => 11,
            Self::InvalidChannel => 12,
            Self::UnsupportedChannel => 13,
            Self::ReliabilityMismatch => 14,
            Self::ReceiverIdentityMismatch => 15,
            Self::LaneMismatch => 16,
            Self::StrategyConflict => 17,
        }
    }

    const fn from_code(code: u64) -> Option<Self> {
        Some(match code {
            1 => Self::PublicationTaken,
            2 => Self::UnknownStream,
            3 => Self::UnknownRegistration,
            4 => Self::ResourcesUnavailable,
            5 => Self::IdentitiesExhausted,
            6 => Self::InvalidPublicationMode,
            7 => Self::TraceJournalsExhausted,
            8 => Self::UnknownGuard,
            9 => Self::GuardNotClosedAt,
            10 => Self::GuardExhausted,
            11 => Self::NotAuthorized,
            12 => Self::InvalidChannel,
            13 => Self::UnsupportedChannel,
            14 => Self::ReliabilityMismatch,
            15 => Self::ReceiverIdentityMismatch,
            16 => Self::LaneMismatch,
            17 => Self::StrategyConflict,
            _ => return None,
        })
    }
}

/// A driver response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Response {
    /// The publication is ready for hand-over.
    PublicationReady {
        /// The request.
        request: RequestId,
        /// The new registration.
        registration: u64,
        /// The hand-over key.
        key: u64,
    },
    /// The subscription is ready for hand-over.
    SubscriptionReady {
        /// The request.
        request: RequestId,
        /// The new registration.
        registration: u64,
        /// The hand-over key.
        key: u64,
    },
    /// The network subscription is created (W5); its images are
    /// announced with `ImageAvailable`, naming `registration`.
    NetworkSubscriptionReady {
        /// The request.
        request: RequestId,
        /// The new registration.
        registration: u64,
        /// The subscription's bound local address as its socket reports
        /// it (a multicast subscription's group and bound port), or
        /// `None` when the driver reports none. An IPv6 address keeps its
        /// scope id; its flow information is not carried.
        bound: Option<SocketAddr>,
    },
    /// The command succeeded and returns nothing.
    OperationSucceeded {
        /// The request.
        request: RequestId,
    },
    /// The command was refused; it had no effect.
    Error {
        /// The request.
        request: RequestId,
        /// Why.
        code: ErrorCode,
        /// A bounded detail value (for example the stream id).
        detail: u64,
    },
    /// A client counter cell was allocated for the client.
    CounterAllocated {
        /// The request.
        request: RequestId,
        /// The cell in the client counters region.
        cell: u64,
        /// The allocation's fresh registration.
        registration: u64,
    },
    /// The trace journal is ready for hand-over.
    JournalReady {
        /// The request.
        request: RequestId,
        /// The journal number, never reused within the driver instance.
        journal: u64,
        /// The hand-over key.
        key: u64,
    },
    /// The cutover state of a registration `QueryCutover` asked about.
    CutoverState {
        /// The request.
        request: RequestId,
        /// The registration.
        registration: u64,
        /// Its state.
        state: CutoverState,
    },
    /// A guard's state after a `GuardClose` or `GuardReopen`.
    GuardState {
        /// The request.
        request: RequestId,
        /// The guard.
        guard: u64,
        /// Its state.
        state: karyos_sys::guard::GuardState,
    },
    /// The view of a conflated stream's table is ready for hand-over.
    ConflatedReady {
        /// The request.
        request: RequestId,
        /// The new registration.
        registration: u64,
        /// The hand-over key.
        key: u64,
        /// The table's key count.
        keys: u32,
        /// The table's value capacity in bytes.
        value_capacity: u64,
        /// The table's journal capacity in bytes.
        journal_capacity: u64,
    },
}

/// Where a remote registration stands in its stream's cutovers, as
/// `CutoverState` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CutoverState {
    /// No cutover waits for it: its handle's current mapping is the
    /// stream's.
    Current,
    /// A successor was reserved for it and is neither adopted nor fenced;
    /// its `SuccessorReady` was emitted again just before this answer.
    Successor,
    /// Its successor was fenced, or none could be reserved.
    Fenced,
    /// Its stream was closed: removed or sealed for good.
    Closed,
}

impl CutoverState {
    const fn code(self) -> u64 {
        match self {
            Self::Current => 0,
            Self::Successor => 1,
            Self::Fenced => 2,
            Self::Closed => 3,
        }
    }

    const fn from_code(code: u64) -> Option<Self> {
        match code {
            0 => Some(Self::Current),
            1 => Some(Self::Successor),
            2 => Some(Self::Fenced),
            3 => Some(Self::Closed),
            _ => None,
        }
    }
}

fn stream_word(stream: StreamKey) -> u64 {
    u64::from(stream.stream_id.cast_unsigned())
        | (u64::from(stream.session_id.cast_unsigned()) << 32)
}

fn stream_from(word: u64) -> StreamKey {
    StreamKey {
        stream_id: (word as u32).cast_signed(),
        session_id: ((word >> 32) as u32).cast_signed(),
    }
}

fn write_words(words: &[u64], out: &mut [u8]) -> Result<usize, CncError> {
    let required = words.len() * 8;
    let available = out.len();
    let target = out.get_mut(..required).ok_or(CncError::BufferTooShort {
        required,
        available,
    })?;
    for (chunk, word) in target.as_chunks_mut::<8>().0.iter_mut().zip(words) {
        *chunk = word.to_le_bytes();
    }
    Ok(required)
}

/// Reads exactly `N` words.
fn read_words<const N: usize>(type_id: u32, bytes: &[u8]) -> Result<[u64; N], CncError> {
    if bytes.len() != N * 8 {
        return Err(CncError::WrongLength {
            type_id,
            length: bytes.len(),
            expected: N * 8,
        });
    }
    let mut words = [0u64; N];
    for (word, chunk) in words.iter_mut().zip(bytes.as_chunks::<8>().0) {
        *word = u64::from_le_bytes(*chunk);
    }
    Ok(words)
}

/// The lane of a command's lane word: a value below 4, the other bits
/// zero.
fn lane_from(type_id: u32, word: u64) -> Result<Lane, CncError> {
    u8::try_from(word)
        .ok()
        .and_then(|lane| Lane::try_new(lane).ok())
        .ok_or(CncError::Reserved { type_id })
}

impl Command {
    /// The record type of this command.
    #[must_use]
    pub const fn type_id(&self) -> u32 {
        match self {
            Self::AddPublication { .. } => ADD_PUBLICATION,
            Self::AddConcurrentPublication { .. } => ADD_CONCURRENT_PUBLICATION,
            Self::AddSubscription { .. } => ADD_SUBSCRIPTION,
            Self::RemovePublication { .. } => REMOVE_PUBLICATION,
            Self::RemoveSubscription { .. } => REMOVE_SUBSCRIPTION,
            Self::AllocateCounter { .. } => ALLOCATE_COUNTER,
            Self::ReleaseCounter { .. } => RELEASE_COUNTER,
            Self::ReportLoss { .. } => REPORT_LOSS,
            Self::TraceJournal { .. } => TRACE_JOURNAL,
            Self::CloseJournal { .. } => CLOSE_JOURNAL,
            Self::QueryCutover { .. } => QUERY_CUTOVER,
            Self::AddConflatedSubscription { .. } => ADD_CONFLATED_SUBSCRIPTION,
            Self::GuardClose { .. } => GUARD_CLOSE,
            Self::GuardReopen { .. } => GUARD_REOPEN,
            Self::AddNetworkPublication { .. } => ADD_NETWORK_PUBLICATION,
            Self::AddNetworkSubscription { .. } => ADD_NETWORK_SUBSCRIPTION,
            Self::AddImageSubscription { .. } => ADD_IMAGE_SUBSCRIPTION,
            Self::AddNetworkPublicationWithRoles { .. } => ADD_NETWORK_PUBLICATION_WITH_ROLES,
            Self::AddNetworkSubscriptionAs { .. } => ADD_NETWORK_SUBSCRIPTION_AS,
        }
    }

    /// The request sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        match *self {
            Self::AddPublication { sequence, .. }
            | Self::AddConcurrentPublication { sequence, .. }
            | Self::AddSubscription { sequence, .. }
            | Self::RemovePublication { sequence, .. }
            | Self::RemoveSubscription { sequence, .. }
            | Self::AllocateCounter { sequence, .. }
            | Self::ReleaseCounter { sequence, .. }
            | Self::ReportLoss { sequence, .. }
            | Self::TraceJournal { sequence, .. }
            | Self::CloseJournal { sequence, .. }
            | Self::QueryCutover { sequence, .. }
            | Self::AddConflatedSubscription { sequence, .. }
            | Self::GuardClose { sequence, .. }
            | Self::GuardReopen { sequence, .. }
            | Self::AddNetworkPublication { sequence, .. }
            | Self::AddNetworkSubscription { sequence, .. }
            | Self::AddImageSubscription { sequence, .. }
            | Self::AddNetworkPublicationWithRoles { sequence, .. }
            | Self::AddNetworkSubscriptionAs { sequence, .. } => sequence,
        }
    }

    /// Encodes the command into `out`; returns the length.
    ///
    /// # Errors
    ///
    /// Returns [`CncError::BufferTooShort`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CncError> {
        match *self {
            Self::AddPublication {
                sequence,
                stream,
                lane,
                allow_unconnected,
            }
            | Self::AddConcurrentPublication {
                sequence,
                stream,
                lane,
                allow_unconnected,
            } => write_words(
                &[
                    sequence,
                    stream_word(stream),
                    u64::from(allow_unconnected),
                    u64::from(lane.get()),
                ],
                out,
            ),
            Self::AddSubscription {
                sequence,
                stream,
                lane,
                role,
            } => {
                let role = match role {
                    SubscriberRole::Required => 0,
                    SubscriberRole::Optional => 1,
                    SubscriberRole::Observer => 2,
                };
                write_words(
                    &[sequence, stream_word(stream), role, u64::from(lane.get())],
                    out,
                )
            }
            Self::RemovePublication {
                sequence,
                registration,
            }
            | Self::RemoveSubscription {
                sequence,
                registration,
            } => write_words(&[sequence, registration], out),
            Self::AllocateCounter {
                sequence,
                type_id,
                label,
                stream,
                participant,
            } => {
                let mut words = [0u64; ALLOCATE_COUNTER_WORDS];
                let (head, tail) = words.split_at_mut(5);
                head.copy_from_slice(&[
                    sequence,
                    type_id,
                    stream,
                    participant,
                    u64::from(label.length),
                ]);
                for (word, chunk) in tail.iter_mut().zip(label.bytes.as_chunks::<8>().0) {
                    *word = u64::from_le_bytes(*chunk);
                }
                write_words(&words, out)
            }
            Self::ReleaseCounter {
                sequence,
                cell,
                registration,
            } => write_words(&[sequence, cell, registration], out),
            Self::ReportLoss { sequence, loss } => write_words(
                &[
                    sequence,
                    loss.driver[0],
                    loss.driver[1],
                    loss.stream_registration,
                    loss.incarnation,
                    loss.subscription,
                    loss.from,
                    loss.to,
                    loss.packed(),
                ],
                out,
            ),
            Self::TraceJournal {
                sequence,
                capacity,
                payload_words,
                drop_ranges,
                registration,
                provenance,
            } => write_words(
                &[
                    sequence,
                    capacity,
                    payload_words,
                    drop_ranges,
                    registration,
                    provenance,
                ],
                out,
            ),
            Self::CloseJournal {
                sequence,
                journal,
                boundary,
            } => write_words(&[sequence, journal, boundary], out),
            Self::QueryCutover {
                sequence,
                registration,
            } => write_words(&[sequence, registration], out),
            Self::AddConflatedSubscription { sequence, stream } => {
                write_words(&[sequence, stream_word(stream)], out)
            }
            Self::GuardClose {
                sequence,
                guard,
                operation,
                operator,
                parameters,
            } => {
                if !operator_word(operator) {
                    return Err(CncError::Reserved {
                        type_id: GUARD_CLOSE,
                    });
                }
                write_words(&[sequence, guard, operation, operator, parameters], out)
            }
            Self::GuardReopen {
                sequence,
                guard,
                expected,
                operation,
                operator,
                parameters,
            } => {
                if !closed_epoch(expected) || !operator_word(operator) {
                    return Err(CncError::Reserved {
                        type_id: GUARD_REOPEN,
                    });
                }
                write_words(
                    &[sequence, guard, expected, operation, operator, parameters],
                    out,
                )
            }
            Self::AddNetworkPublication {
                sequence,
                stream_id,
                allow_unconnected,
                concurrent,
                uri,
            } => write_uri_command(
                [
                    sequence,
                    u64::from(stream_id.cast_unsigned()),
                    u64::from(allow_unconnected) | if concurrent { CONCURRENT } else { 0 },
                    u64::from(uri.length),
                ],
                &uri,
                out,
            ),
            Self::AddNetworkSubscription {
                sequence,
                stream_id,
                role,
                uri,
            } => write_uri_command(
                [
                    sequence,
                    u64::from(stream_id.cast_unsigned()),
                    role_code(role),
                    u64::from(uri.length),
                ],
                &uri,
                out,
            ),
            Self::AddImageSubscription {
                sequence,
                image,
                lane,
                role,
            } => write_words(
                &[sequence, image, role_code(role), u64::from(lane.get())],
                out,
            ),
            Self::AddNetworkPublicationWithRoles {
                sequence,
                stream_id,
                allow_unconnected,
                concurrent,
                uri,
                ref roles,
            } => write_roles_command(
                [
                    sequence,
                    u64::from(stream_id.cast_unsigned()),
                    u64::from(allow_unconnected) | if concurrent { CONCURRENT } else { 0 },
                    u64::from(uri.length),
                ],
                &uri,
                roles,
                out,
            ),
            Self::AddNetworkSubscriptionAs {
                sequence,
                stream_id,
                role,
                uri,
                identity,
            } => write_identity_command(
                [
                    sequence,
                    u64::from(stream_id.cast_unsigned()),
                    role_code(role),
                    u64::from(uri.length),
                    identity.receiver_id.get(),
                    identity.group_tag,
                ],
                &uri,
                out,
            ),
        }
    }

    /// Decodes a command of record type `type_id`.
    ///
    /// # Errors
    ///
    /// Returns [`CncError::UnknownType`], [`CncError::WrongLength`] and
    /// [`CncError::Reserved`].
    pub fn decode(type_id: u32, bytes: &[u8]) -> Result<Self, CncError> {
        match type_id {
            ADD_PUBLICATION | ADD_CONCURRENT_PUBLICATION => {
                let [sequence, stream, flags, lane] = read_words::<4>(type_id, bytes)?;
                if flags & !ALLOW_UNCONNECTED != 0 {
                    return Err(CncError::Reserved { type_id });
                }
                let lane = lane_from(type_id, lane)?;
                let stream = stream_from(stream);
                let allow_unconnected = flags == ALLOW_UNCONNECTED;
                Ok(if type_id == ADD_PUBLICATION {
                    Self::AddPublication {
                        sequence,
                        stream,
                        lane,
                        allow_unconnected,
                    }
                } else {
                    Self::AddConcurrentPublication {
                        sequence,
                        stream,
                        lane,
                        allow_unconnected,
                    }
                })
            }
            ADD_SUBSCRIPTION => {
                let [sequence, stream, role, lane] = read_words::<4>(type_id, bytes)?;
                let role = match role {
                    0 => SubscriberRole::Required,
                    1 => SubscriberRole::Optional,
                    2 => SubscriberRole::Observer,
                    _ => return Err(CncError::Reserved { type_id }),
                };
                Ok(Self::AddSubscription {
                    sequence,
                    stream: stream_from(stream),
                    lane: lane_from(type_id, lane)?,
                    role,
                })
            }
            ADD_IMAGE_SUBSCRIPTION => {
                let [sequence, image, role, lane] = read_words::<4>(type_id, bytes)?;
                if image == 0 {
                    return Err(CncError::Reserved { type_id });
                }
                Ok(Self::AddImageSubscription {
                    sequence,
                    image,
                    lane: lane_from(type_id, lane)?,
                    role: role_from(role).ok_or(CncError::Reserved { type_id })?,
                })
            }
            REMOVE_PUBLICATION => {
                let [sequence, registration] = read_words::<2>(type_id, bytes)?;
                Ok(Self::RemovePublication {
                    sequence,
                    registration,
                })
            }
            REMOVE_SUBSCRIPTION => {
                let [sequence, registration] = read_words::<2>(type_id, bytes)?;
                Ok(Self::RemoveSubscription {
                    sequence,
                    registration,
                })
            }
            ALLOCATE_COUNTER => {
                let words = read_words::<ALLOCATE_COUNTER_WORDS>(type_id, bytes)?;
                let reserved = CncError::Reserved { type_id };
                let [sequence, counter_type, stream, participant, length] =
                    *words.first_chunk::<5>().ok_or(reserved)?;
                let length = usize::try_from(length)
                    .ok()
                    .filter(|&length| length <= MAX_LABEL_LENGTH)
                    .ok_or(reserved)?;
                let mut label = [0u8; MAX_LABEL_LENGTH];
                for (chunk, word) in label
                    .as_chunks_mut::<8>()
                    .0
                    .iter_mut()
                    .zip(words.iter().skip(5))
                {
                    *chunk = word.to_le_bytes();
                }
                // The padding after the label is zero.
                let (text, padding) = label.split_at(length);
                if padding.iter().any(|byte| *byte != 0) {
                    return Err(reserved);
                }
                Ok(Self::AllocateCounter {
                    sequence,
                    type_id: counter_type,
                    label: CounterLabel::from_bytes(text).ok_or(reserved)?,
                    stream,
                    participant,
                })
            }
            RELEASE_COUNTER => {
                let [sequence, cell, registration] = read_words::<3>(type_id, bytes)?;
                Ok(Self::ReleaseCounter {
                    sequence,
                    cell,
                    registration,
                })
            }
            REPORT_LOSS => {
                let words = read_words::<REPORT_LOSS_WORDS>(type_id, bytes)?;
                let reserved = CncError::Reserved { type_id };
                let (sequence, rest) = words.split_first().ok_or(reserved)?;
                let loss = rest
                    .first_chunk::<{ REPORT_LOSS_WORDS - 1 }>()
                    .copied()
                    .and_then(ReportedLoss::decode)
                    .ok_or(reserved)?;
                Ok(Self::ReportLoss {
                    sequence: *sequence,
                    loss,
                })
            }
            TRACE_JOURNAL => {
                let [
                    sequence,
                    capacity,
                    payload_words,
                    drop_ranges,
                    registration,
                    provenance,
                ] = read_words::<6>(type_id, bytes)?;
                if !capacity.is_power_of_two()
                    || payload_words == 0
                    || drop_ranges == 0
                    || registration == 0
                {
                    return Err(CncError::Reserved { type_id });
                }
                Ok(Self::TraceJournal {
                    sequence,
                    capacity,
                    payload_words,
                    drop_ranges,
                    registration,
                    provenance,
                })
            }
            CLOSE_JOURNAL => {
                let [sequence, journal, boundary] = read_words::<3>(type_id, bytes)?;
                if journal == 0 {
                    return Err(CncError::Reserved { type_id });
                }
                Ok(Self::CloseJournal {
                    sequence,
                    journal,
                    boundary,
                })
            }
            QUERY_CUTOVER => {
                let [sequence, registration] = read_words::<2>(type_id, bytes)?;
                Ok(Self::QueryCutover {
                    sequence,
                    registration,
                })
            }
            ADD_CONFLATED_SUBSCRIPTION => {
                let [sequence, stream] = read_words::<2>(type_id, bytes)?;
                Ok(Self::AddConflatedSubscription {
                    sequence,
                    stream: stream_from(stream),
                })
            }
            GUARD_CLOSE => {
                let [sequence, guard, operation, operator, parameters] =
                    read_words::<5>(type_id, bytes)?;
                // A uid, or none: a word no uid can be is malformed.
                if !operator_word(operator) {
                    return Err(CncError::Reserved { type_id });
                }
                Ok(Self::GuardClose {
                    sequence,
                    guard,
                    operation,
                    operator,
                    parameters,
                })
            }
            GUARD_REOPEN => {
                let [sequence, guard, expected, operation, operator, parameters] =
                    read_words::<6>(type_id, bytes)?;
                // Only a closed epoch can be reopened: odd, 1 to MAX_EPOCH;
                // and the operator word is a uid or none.
                if !closed_epoch(expected) || !operator_word(operator) {
                    return Err(CncError::Reserved { type_id });
                }
                Ok(Self::GuardReopen {
                    sequence,
                    guard,
                    expected,
                    operation,
                    operator,
                    parameters,
                })
            }
            ADD_NETWORK_PUBLICATION | ADD_NETWORK_SUBSCRIPTION => {
                let ([sequence, stream, flags, _], uri) = read_uri_command(type_id, bytes)?;
                // The command names the stream only: no session id.
                let stream_id = u32::try_from(stream)
                    .map_err(|_| CncError::Reserved { type_id })?
                    .cast_signed();
                if type_id == ADD_NETWORK_PUBLICATION {
                    if flags & !(ALLOW_UNCONNECTED | CONCURRENT) != 0 {
                        return Err(CncError::Reserved { type_id });
                    }
                    Ok(Self::AddNetworkPublication {
                        sequence,
                        stream_id,
                        allow_unconnected: flags & ALLOW_UNCONNECTED != 0,
                        concurrent: flags & CONCURRENT != 0,
                        uri,
                    })
                } else {
                    Ok(Self::AddNetworkSubscription {
                        sequence,
                        stream_id,
                        role: role_from(flags).ok_or(CncError::Reserved { type_id })?,
                        uri,
                    })
                }
            }
            ADD_NETWORK_PUBLICATION_WITH_ROLES => {
                let ([sequence, stream, flags, _, counts, group], uri, rest) =
                    read_uri_block::<ROLES_COMMAND_WORDS>(type_id, bytes)?;
                let stream_id = u32::try_from(stream)
                    .map_err(|_| CncError::Reserved { type_id })?
                    .cast_signed();
                if flags & !(ALLOW_UNCONNECTED | CONCURRENT) != 0 {
                    return Err(CncError::Reserved { type_id });
                }
                let roles = read_roles(type_id, counts, group, rest)?;
                Ok(Self::AddNetworkPublicationWithRoles {
                    sequence,
                    stream_id,
                    allow_unconnected: flags & ALLOW_UNCONNECTED != 0,
                    concurrent: flags & CONCURRENT != 0,
                    uri,
                    roles,
                })
            }
            ADD_NETWORK_SUBSCRIPTION_AS => {
                let ([sequence, stream, role, _, receiver_id, group_tag], uri, rest) =
                    read_uri_block::<ROLES_COMMAND_WORDS>(type_id, bytes)?;
                if !rest.is_empty() {
                    return Err(CncError::WrongLength {
                        type_id,
                        length: bytes.len(),
                        expected: bytes.len().saturating_sub(rest.len()),
                    });
                }
                let stream_id = u32::try_from(stream)
                    .map_err(|_| CncError::Reserved { type_id })?
                    .cast_signed();
                Ok(Self::AddNetworkSubscriptionAs {
                    sequence,
                    stream_id,
                    role: role_from(role).ok_or(CncError::Reserved { type_id })?,
                    uri,
                    identity: ReceiverIdentity {
                        receiver_id: core::num::NonZeroU64::new(receiver_id)
                            .ok_or(CncError::Reserved { type_id })?,
                        group_tag,
                    },
                })
            }
            _ => Err(CncError::UnknownType { type_id }),
        }
    }
}

/// The wire code of a subscriber role.
const fn role_code(role: SubscriberRole) -> u64 {
    match role {
        SubscriberRole::Required => 0,
        SubscriberRole::Optional => 1,
        SubscriberRole::Observer => 2,
    }
}

/// The subscriber role of a wire code.
const fn role_from(code: u64) -> Option<SubscriberRole> {
    match code {
        0 => Some(SubscriberRole::Required),
        1 => Some(SubscriberRole::Optional),
        2 => Some(SubscriberRole::Observer),
        _ => None,
    }
}

/// Address family codes of an address word.
const FAMILY_V4: u64 = 4;
const FAMILY_V6: u64 = 6;

/// The three words of an address (`NetworkSubscriptionReady`'s bound
/// address, `ImageAvailable`'s source): the family, port and scope word,
/// then the address's high and low words; `None` is family 0.
fn bound_words(bound: Option<SocketAddr>) -> [u64; 3] {
    match bound {
        None => [0, 0, 0],
        Some(SocketAddr::V4(address)) => [
            u64::from(address.port()) | FAMILY_V4 << 16,
            0,
            u64::from(u32::from_be_bytes(address.ip().octets())),
        ],
        Some(SocketAddr::V6(address)) => {
            let bits = u128::from_be_bytes(address.ip().octets());
            // The high and low halves of the address.
            let high = u64::try_from(bits >> 64).unwrap_or(0);
            let low = u64::try_from(bits & u128::from(u64::MAX)).unwrap_or(0);
            [
                u64::from(address.port()) | FAMILY_V6 << 16 | u64::from(address.scope_id()) << 32,
                high,
                low,
            ]
        }
    }
}

/// The address of its three words: `Some(None)` for family 0, `None` for
/// another family or a reserved bit set.
fn bound_from([word, high, low]: [u64; 3]) -> Option<Option<SocketAddr>> {
    let port = u16::try_from(word & 0xFFFF).ok()?;
    let family = (word >> 16) & 0xFF;
    let reserved = (word >> 24) & 0xFF;
    let scope = u32::try_from(word >> 32).ok()?;
    if reserved != 0 {
        return None;
    }
    match family {
        0 if word == 0 && high == 0 && low == 0 => Some(None),
        FAMILY_V4 if scope == 0 && high == 0 => {
            let ip = u32::try_from(low).ok()?;
            Some(Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(ip),
                port,
            ))))
        }
        FAMILY_V6 => {
            let bits = u128::from(high) << 64 | u128::from(low);
            Some(Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(bits),
                port,
                0,
                scope,
            ))))
        }
        _ => None,
    }
}

/// Writes a command's four words and its channel URI, padded to a word.
fn write_uri_command(
    words: [u64; URI_COMMAND_WORDS],
    uri: &ChannelUri,
    out: &mut [u8],
) -> Result<usize, CncError> {
    let head = write_words(&words, out)?;
    let tail = uri.padded();
    let required = head
        .checked_add(tail.len())
        .ok_or(CncError::BufferTooShort {
            required: usize::MAX,
            available: out.len(),
        })?;
    let available = out.len();
    out.get_mut(head..required)
        .ok_or(CncError::BufferTooShort {
            required,
            available,
        })?
        .copy_from_slice(tail);
    Ok(required)
}

/// Reads a command's four words and its channel URI, strictly: the length
/// word names 1 to [`MAX_COMMAND_URI`] bytes of UTF-8, the record is the
/// words and those bytes padded to a word, and the padding is zero.
fn read_uri_command(
    type_id: u32,
    bytes: &[u8],
) -> Result<([u64; URI_COMMAND_WORDS], ChannelUri), CncError> {
    let head = URI_COMMAND_WORDS * 8;
    let words = read_words::<URI_COMMAND_WORDS>(type_id, bytes.get(..head).unwrap_or(bytes))?;
    let [_, _, _, length] = words;
    let length = usize::try_from(length)
        .ok()
        .filter(|length| (1..=MAX_COMMAND_URI).contains(length))
        .ok_or(CncError::Reserved { type_id })?;
    let expected = length
        .checked_next_multiple_of(8)
        .and_then(|padded| head.checked_add(padded))
        .ok_or(CncError::Reserved { type_id })?;
    if bytes.len() != expected {
        return Err(CncError::WrongLength {
            type_id,
            length: bytes.len(),
            expected,
        });
    }
    let (uri, padding) = bytes
        .get(head..)
        .unwrap_or_default()
        .split_at_checked(length)
        .ok_or(CncError::Reserved { type_id })?;
    if padding.iter().any(|&byte| byte != 0) {
        return Err(CncError::Reserved { type_id });
    }
    let uri = ChannelUri::from_bytes(uri).ok_or(CncError::Reserved { type_id })?;
    Ok((words, uri))
}

/// Writes a roles command: its four words, the strategy and counts word,
/// the tagged group word, the channel URI padded to a word, then each
/// required `receiver_id` and each `(receiver_id, tag)` pair. A count that
/// does not fit its 16 bits cannot be carried: reported as a buffer too
/// short for the command.
fn write_roles_command(
    words: [u64; URI_COMMAND_WORDS],
    uri: &ChannelUri,
    roles: &PublicationRoles,
    out: &mut [u8],
) -> Result<usize, CncError> {
    let (strategy, group) = match roles.strategy {
        crate::roles::Strategy::Min => (STRATEGY_MIN, 0),
        crate::roles::Strategy::Max => (STRATEGY_MAX, 0),
        crate::roles::Strategy::Tagged(group) => (STRATEGY_TAGGED, group),
    };
    let tail_words = roles
        .tags
        .len()
        .checked_mul(2)
        .and_then(|tags| tags.checked_add(roles.required.len()));
    let available = out.len();
    let too_large = || CncError::BufferTooShort {
        required: usize::MAX,
        available,
    };
    let (Ok(required), Ok(tags), Some(tail_words)) = (
        u16::try_from(roles.required.len()),
        u16::try_from(roles.tags.len()),
        tail_words,
    ) else {
        return Err(too_large());
    };
    let counts = strategy | u64::from(required) << 16 | u64::from(tags) << 32;
    let [sequence, stream, flags, length] = words;
    let head = write_words(&[sequence, stream, flags, length, counts, group], out)?;
    let padded = uri.padded();
    let roles_at = head.checked_add(padded.len()).ok_or_else(too_large)?;
    let end = tail_words
        .checked_mul(8)
        .and_then(|bytes| roles_at.checked_add(bytes))
        .ok_or_else(too_large)?;
    let short = CncError::BufferTooShort {
        required: end,
        available,
    };
    out.get_mut(head..roles_at)
        .ok_or(short)?
        .copy_from_slice(padded);
    let tail = out.get_mut(roles_at..end).ok_or(short)?;
    let values = roles
        .required
        .iter()
        .copied()
        .chain(roles.tags.iter().flat_map(|&(id, tag)| [id, tag]));
    for (chunk, word) in tail.as_chunks_mut::<8>().0.iter_mut().zip(values) {
        *chunk = word.to_le_bytes();
    }
    Ok(end)
}

/// Writes an identity command: its six words and the channel URI padded
/// to a word.
fn write_identity_command(
    words: [u64; ROLES_COMMAND_WORDS],
    uri: &ChannelUri,
    out: &mut [u8],
) -> Result<usize, CncError> {
    let head = write_words(&words, out)?;
    let padded = uri.padded();
    let end = head
        .checked_add(padded.len())
        .ok_or(CncError::BufferTooShort {
            required: usize::MAX,
            available: out.len(),
        })?;
    let available = out.len();
    out.get_mut(head..end)
        .ok_or(CncError::BufferTooShort {
            required: end,
            available,
        })?
        .copy_from_slice(padded);
    Ok(end)
}

/// Reads a command's `N` words and the channel URI after them, strictly as
/// [`read_uri_command`] does for its URI, and returns the bytes after the
/// URI's padding for the caller to read exactly.
fn read_uri_block<const N: usize>(
    type_id: u32,
    bytes: &[u8],
) -> Result<([u64; N], ChannelUri, &[u8]), CncError> {
    let head = N * 8;
    let Some(head_bytes) = bytes.get(..head) else {
        return Err(CncError::WrongLength {
            type_id,
            length: bytes.len(),
            expected: head,
        });
    };
    let words = read_words::<N>(type_id, head_bytes)?;
    let length = words
        .get(URI_COMMAND_WORDS - 1)
        .and_then(|&length| usize::try_from(length).ok())
        .filter(|length| (1..=MAX_COMMAND_URI).contains(length))
        .ok_or(CncError::Reserved { type_id })?;
    let padded = length
        .checked_next_multiple_of(8)
        .ok_or(CncError::Reserved { type_id })?;
    let after = head
        .checked_add(padded)
        .ok_or(CncError::Reserved { type_id })?;
    let Some(block) = bytes.get(head..after) else {
        return Err(CncError::WrongLength {
            type_id,
            length: bytes.len(),
            expected: after,
        });
    };
    let (uri, padding) = block
        .split_at_checked(length)
        .ok_or(CncError::Reserved { type_id })?;
    if padding.iter().any(|&byte| byte != 0) {
        return Err(CncError::Reserved { type_id });
    }
    let uri = ChannelUri::from_bytes(uri).ok_or(CncError::Reserved { type_id })?;
    Ok((words, uri, bytes.get(after..).unwrap_or_default()))
}

/// Reads the roles of `AddNetworkPublicationWithRoles` from its strategy and
/// counts word, its tagged group word and the words after its URI, which
/// must be exactly the counts' words: required `receiver_id`s, nonzero and
/// distinct, then `(receiver_id, tag)` pairs, each `receiver_id` nonzero
/// and distinct among the pairs, each tag nonzero.
fn read_roles(
    type_id: u32,
    counts: u64,
    group: u64,
    rest: &[u8],
) -> Result<PublicationRoles, CncError> {
    let reserved = CncError::Reserved { type_id };
    // Bits 15 to 8 and 63 to 48 are reserved.
    if counts & 0xFFFF_0000_0000_FF00 != 0 {
        return Err(reserved);
    }
    let strategy = match (counts & 0xFF, group) {
        (STRATEGY_MIN, 0) => crate::roles::Strategy::Min,
        (STRATEGY_MAX, 0) => crate::roles::Strategy::Max,
        (STRATEGY_TAGGED, group) if group != 0 => crate::roles::Strategy::Tagged(group),
        _ => return Err(reserved),
    };
    let required = usize::from((counts >> 16) as u16);
    let tags = usize::from((counts >> 32) as u16);
    let expected = tags
        .checked_mul(2)
        .and_then(|words| words.checked_add(required))
        .and_then(|words| words.checked_mul(8))
        .ok_or(reserved)?;
    if rest.len() != expected {
        return Err(CncError::WrongLength {
            type_id,
            length: rest.len(),
            expected,
        });
    }
    let mut words = rest
        .as_chunks::<8>()
        .0
        .iter()
        .map(|chunk| u64::from_le_bytes(*chunk));
    let required: Vec<u64> = words.by_ref().take(required).collect();
    let tags: Vec<(u64, u64)> = (0..tags)
        .map(|_| (words.next().unwrap_or(0), words.next().unwrap_or(0)))
        .collect();
    let roles = PublicationRoles {
        strategy,
        required,
        tags,
    };
    if !roles.is_well_formed() {
        return Err(reserved);
    }
    Ok(roles)
}

impl Response {
    /// The record type of this response.
    #[must_use]
    pub const fn type_id(&self) -> u32 {
        match self {
            Self::PublicationReady { .. } => PUBLICATION_READY,
            Self::SubscriptionReady { .. } => SUBSCRIPTION_READY,
            Self::OperationSucceeded { .. } => OPERATION_SUCCEEDED,
            Self::Error { .. } => ERROR,
            Self::CounterAllocated { .. } => COUNTER_ALLOCATED,
            Self::JournalReady { .. } => JOURNAL_READY,
            Self::CutoverState { .. } => CUTOVER_STATE,
            Self::ConflatedReady { .. } => CONFLATED_READY,
            Self::GuardState { .. } => GUARD_STATE,
            Self::NetworkSubscriptionReady { .. } => NETWORK_SUBSCRIPTION_READY,
        }
    }

    /// The request answered.
    #[must_use]
    pub const fn request(&self) -> RequestId {
        match *self {
            Self::PublicationReady { request, .. }
            | Self::SubscriptionReady { request, .. }
            | Self::OperationSucceeded { request }
            | Self::Error { request, .. }
            | Self::CounterAllocated { request, .. }
            | Self::JournalReady { request, .. }
            | Self::CutoverState { request, .. }
            | Self::ConflatedReady { request, .. }
            | Self::GuardState { request, .. }
            | Self::NetworkSubscriptionReady { request, .. } => request,
        }
    }

    /// Encodes the response into `out`; returns the length.
    ///
    /// # Errors
    ///
    /// Returns [`CncError::BufferTooShort`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CncError> {
        match *self {
            Self::PublicationReady {
                request,
                registration,
                key,
            }
            | Self::SubscriptionReady {
                request,
                registration,
                key,
            } => write_words(&[request.client, request.sequence, registration, key], out),
            Self::OperationSucceeded { request } => {
                write_words(&[request.client, request.sequence], out)
            }
            Self::NetworkSubscriptionReady {
                request,
                registration,
                bound,
            } => {
                let [family_port, high, low] = bound_words(bound);
                write_words(
                    &[
                        request.client,
                        request.sequence,
                        registration,
                        family_port,
                        high,
                        low,
                    ],
                    out,
                )
            }
            Self::Error {
                request,
                code,
                detail,
            } => write_words(
                &[request.client, request.sequence, code.code(), detail],
                out,
            ),
            Self::CounterAllocated {
                request,
                cell,
                registration,
            } => write_words(&[request.client, request.sequence, cell, registration], out),
            Self::JournalReady {
                request,
                journal,
                key,
            } => write_words(&[request.client, request.sequence, journal, key], out),
            Self::CutoverState {
                request,
                registration,
                state,
            } => write_words(
                &[request.client, request.sequence, registration, state.code()],
                out,
            ),
            Self::ConflatedReady {
                request,
                registration,
                key,
                keys,
                value_capacity,
                journal_capacity,
            } => write_words(
                &[
                    request.client,
                    request.sequence,
                    registration,
                    key,
                    u64::from(keys),
                    value_capacity,
                    journal_capacity,
                ],
                out,
            ),
            Self::GuardState {
                request,
                guard,
                state,
            } => write_words(
                &[
                    request.client,
                    request.sequence,
                    guard,
                    karyos_sys::guard::encode(state).ok_or(CncError::Reserved {
                        type_id: GUARD_STATE,
                    })?,
                ],
                out,
            ),
        }
    }

    /// Decodes a response of record type `type_id`.
    ///
    /// # Errors
    ///
    /// Returns [`CncError::UnknownType`], [`CncError::WrongLength`] and
    /// [`CncError::Reserved`].
    pub fn decode(type_id: u32, bytes: &[u8]) -> Result<Self, CncError> {
        match type_id {
            PUBLICATION_READY | SUBSCRIPTION_READY => {
                let [client, sequence, registration, key] = read_words::<4>(type_id, bytes)?;
                let request = RequestId { client, sequence };
                Ok(if type_id == PUBLICATION_READY {
                    Self::PublicationReady {
                        request,
                        registration,
                        key,
                    }
                } else {
                    Self::SubscriptionReady {
                        request,
                        registration,
                        key,
                    }
                })
            }
            OPERATION_SUCCEEDED => {
                let [client, sequence] = read_words::<2>(type_id, bytes)?;
                Ok(Self::OperationSucceeded {
                    request: RequestId { client, sequence },
                })
            }
            NETWORK_SUBSCRIPTION_READY => {
                let [client, sequence, registration, family_port, high, low] =
                    read_words::<NETWORK_SUBSCRIPTION_READY_WORDS>(type_id, bytes)?;
                Ok(Self::NetworkSubscriptionReady {
                    request: RequestId { client, sequence },
                    registration,
                    bound: bound_from([family_port, high, low])
                        .ok_or(CncError::Reserved { type_id })?,
                })
            }
            ERROR => {
                let [client, sequence, code, detail] = read_words::<4>(type_id, bytes)?;
                let code = ErrorCode::from_code(code).ok_or(CncError::Reserved { type_id })?;
                Ok(Self::Error {
                    request: RequestId { client, sequence },
                    code,
                    detail,
                })
            }
            COUNTER_ALLOCATED => {
                let [client, sequence, cell, registration] = read_words::<4>(type_id, bytes)?;
                Ok(Self::CounterAllocated {
                    request: RequestId { client, sequence },
                    cell,
                    registration,
                })
            }
            JOURNAL_READY => {
                let [client, sequence, journal, key] = read_words::<4>(type_id, bytes)?;
                Ok(Self::JournalReady {
                    request: RequestId { client, sequence },
                    journal,
                    key,
                })
            }
            CUTOVER_STATE => {
                let [client, sequence, registration, state] = read_words::<4>(type_id, bytes)?;
                let state = CutoverState::from_code(state).ok_or(CncError::Reserved { type_id })?;
                Ok(Self::CutoverState {
                    request: RequestId { client, sequence },
                    registration,
                    state,
                })
            }
            CONFLATED_READY => {
                let [
                    client,
                    sequence,
                    registration,
                    key,
                    keys,
                    value_capacity,
                    journal_capacity,
                ] = read_words::<CONFLATED_READY_WORDS>(type_id, bytes)?;
                let keys = u32::try_from(keys).map_err(|_| CncError::Reserved { type_id })?;
                Ok(Self::ConflatedReady {
                    request: RequestId { client, sequence },
                    registration,
                    key,
                    keys,
                    value_capacity,
                    journal_capacity,
                })
            }
            GUARD_STATE => {
                let [client, sequence, guard, word] = read_words::<4>(type_id, bytes)?;
                let state =
                    karyos_sys::guard::decode(word).map_err(|_| CncError::Reserved { type_id })?;
                Ok(Self::GuardState {
                    request: RequestId { client, sequence },
                    guard,
                    state,
                })
            }
            _ => Err(CncError::UnknownType { type_id }),
        }
    }
}

/// What `on_required_loss` did with a lost required participant
/// (quantstratum-docs: `karyos/design/required-participant-loss.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LossPolicyCode {
    /// `hold`: it keeps bounding the publisher until its loan ends.
    Hold,
    /// `continue`: its bound was withdrawn at once.
    Continue,
    /// `abort`: the publication was sealed.
    Abort,
}

impl LossPolicyCode {
    const fn code(self) -> u64 {
        match self {
            Self::Hold => 1,
            Self::Continue => 2,
            Self::Abort => 3,
        }
    }

    const fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(Self::Hold),
            2 => Some(Self::Continue),
            3 => Some(Self::Abort),
            _ => None,
        }
    }
}

/// Why a publication was closed, reported with its `Closed` outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CloseReason {
    /// A required participant was lost under the `abort` policy.
    RequiredParticipantLost,
    /// The stream's keyed conflation table exhausted its versions.
    ConflationVersionsExhausted,
    /// The stream was removed.
    StreamRemoved,
    /// The stream's conflation feeder failed and could not go on.
    ConflationFeederLost,
    /// The stream is an image retired without a complete end: one whose
    /// remote publication the receiver retired, or an Archive replay
    /// stopped or failed before its end.
    ImageRetired,
    /// The stream is an image whose source ended cleanly: a remote
    /// publication whose every lane reached its EOS bound through a
    /// complete prefix, or an Archive replay that reached its end.
    EndOfStream,
}

impl CloseReason {
    // The codes are those of `SealReason`, so the event and the seal line
    // name a closing the same way.
    const fn code(self) -> u64 {
        match self {
            Self::RequiredParticipantLost => 1,
            Self::ConflationVersionsExhausted => 2,
            Self::StreamRemoved => 3,
            Self::ConflationFeederLost => 4,
            Self::ImageRetired => 7,
            Self::EndOfStream => 8,
        }
    }

    const fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(Self::RequiredParticipantLost),
            2 => Some(Self::ConflationVersionsExhausted),
            3 => Some(Self::StreamRemoved),
            4 => Some(Self::ConflationFeederLost),
            7 => Some(Self::ImageRetired),
            8 => Some(Self::EndOfStream),
            _ => None,
        }
    }

    /// The event reason of a seal reason; `None` for an unspecified seal,
    /// which no event reports.
    #[must_use]
    pub const fn from_seal(reason: SealReason) -> Option<Self> {
        match reason {
            SealReason::RequiredParticipantLost => Some(Self::RequiredParticipantLost),
            SealReason::ConflationVersionsExhausted => Some(Self::ConflationVersionsExhausted),
            SealReason::StreamRemoved => Some(Self::StreamRemoved),
            SealReason::ConflationFeederLost => Some(Self::ConflationFeederLost),
            SealReason::ImageRetired => Some(Self::ImageRetired),
            SealReason::EndOfStream => Some(Self::EndOfStream),
            _ => None,
        }
    }
}

/// A driver event on the broadcast buffer: not an answer to a request, so
/// every client sees it (quantstratum-docs:
/// `karyos/design/required-participant-loss.md`, Reporting). A client that
/// does not know an event type skips it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// A participant of a lost client was handled by the stream's
    /// `on_required_loss` policy, at the time out, under every policy.
    ParticipantLost {
        /// The stream.
        stream: StreamKey,
        /// The participant's registration.
        registration: u64,
        /// Its client.
        client: u64,
        /// The policy applied.
        policy: LossPolicyCode,
        /// Its last published position.
        position: u64,
    },
    /// A lost `hold` participant stopped bounding the publisher: a scan
    /// after its revocation found its loan ended. It may never come for a
    /// participant paused with a loan.
    RequiredBoundWithdrawn {
        /// The stream.
        stream: StreamKey,
        /// The participant's registration.
        registration: u64,
        /// Its last published position.
        position: u64,
    },
    /// The publication of one lane of the stream's aggregate was closed
    /// for `reason`.
    PublicationClosed {
        /// The stream.
        stream: StreamKey,
        /// The lane closed; removing an aggregate closes each of its
        /// lanes.
        lane: Lane,
        /// Why.
        reason: CloseReason,
        /// The image's aggregate registration when the closed lane is a
        /// network image's (`quantstratum-docs:
        /// karyos/design/per-source-images.md`, D2-3); 0 for any other
        /// stream.
        image: u64,
    },
    /// A cutover opened on a stream where a remote client holds
    /// `registration` (`quantstratum-docs: karyos/design/ipc-data-path.md`,
    /// Generations across processes): its successor participant is reserved
    /// under a new grant, which the client fetches with `key` and adopts
    /// when its handle reaches the predecessor's seal.
    SuccessorReady {
        /// The stream.
        stream: StreamKey,
        /// The registration whose handle moves.
        registration: u64,
        /// The hand-over key of the successor grant.
        key: u64,
        /// The stream position where the successor starts.
        base: u64,
        /// The successor's mapping generation.
        generation: u64,
    },
    /// The driver fenced `registration`'s successor at the cutover
    /// deadline: its adoption fails and its handle reports `Closed`.
    Fenced {
        /// The stream.
        stream: StreamKey,
        /// The registration fenced.
        registration: u64,
    },
    /// The admission state of a client's network publication
    /// `registration` changed, as its sender last observed it (owner item
    /// 7, karyos#637; admission `VERSION` 3): sent once the sender first
    /// reports it, on each change the conductor sees between two of its
    /// duty cycles, and again before the answer to a `QueryCutover` of the
    /// registration, so a client that lapped resynchronizes. A state that
    /// changes and comes back between two duty cycles sends nothing; the
    /// membership counters count every transition.
    PublicationAdmission {
        /// The publication's stream and session.
        stream: StreamKey,
        /// The network publication's registration.
        registration: u64,
        /// The state.
        admission: NetworkAdmission,
    },
    /// A remote publication's image is a stream of the driver under its
    /// alias `stream`, for the network subscription `registration` (W5),
    /// named by its aggregate registration `image` and its `source`
    /// (`quantstratum-docs: karyos/design/per-source-images.md`, D2-3).
    ImageAvailable {
        /// The image's stream and session.
        stream: StreamKey,
        /// The network subscription.
        registration: u64,
        /// The image's aggregate registration (nonzero).
        image: u64,
        /// The datagram source its binding names.
        source: SocketAddr,
    },
    /// The image `image` of `stream` retired.
    ImageUnavailable {
        /// The image's stream and session.
        stream: StreamKey,
        /// The network subscription.
        registration: u64,
        /// The image's aggregate registration (nonzero).
        image: u64,
    },
}

impl Event {
    /// The record type of this event.
    #[must_use]
    pub const fn type_id(&self) -> u32 {
        match self {
            Self::ParticipantLost { .. } => PARTICIPANT_LOST,
            Self::RequiredBoundWithdrawn { .. } => REQUIRED_BOUND_WITHDRAWN,
            Self::PublicationClosed { .. } => PUBLICATION_CLOSED,
            Self::SuccessorReady { .. } => SUCCESSOR_READY,
            Self::Fenced { .. } => FENCED,
            Self::PublicationAdmission { .. } => PUBLICATION_ADMISSION,
            Self::ImageAvailable { .. } => IMAGE_AVAILABLE,
            Self::ImageUnavailable { .. } => IMAGE_UNAVAILABLE,
        }
    }

    /// Whether `type_id` is an event's record type (as opposed to a
    /// response's).
    #[must_use]
    pub const fn is_event_type(type_id: u32) -> bool {
        type_id & 0xC0 == 0xC0
    }

    /// Encodes the event into `out`; returns the length.
    ///
    /// # Errors
    ///
    /// Returns [`CncError::BufferTooShort`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CncError> {
        match *self {
            Self::ParticipantLost {
                stream,
                registration,
                client,
                policy,
                position,
            } => write_words(
                &[
                    stream_word(stream),
                    registration,
                    client,
                    policy.code(),
                    position,
                ],
                out,
            ),
            Self::RequiredBoundWithdrawn {
                stream,
                registration,
                position,
            } => write_words(&[stream_word(stream), registration, position], out),
            Self::PublicationClosed {
                stream,
                lane,
                reason,
                image,
            } => write_words(
                &[
                    stream_word(stream),
                    reason.code(),
                    u64::from(lane.get()),
                    image,
                ],
                out,
            ),
            Self::SuccessorReady {
                stream,
                registration,
                key,
                base,
                generation,
            } => write_words(
                &[stream_word(stream), registration, key, base, generation],
                out,
            ),
            Self::Fenced {
                stream,
                registration,
            } => write_words(&[stream_word(stream), registration], out),
            Self::PublicationAdmission {
                stream,
                registration,
                admission,
            } => write_words(&[stream_word(stream), registration, admission.code()], out),
            Self::ImageAvailable {
                stream,
                registration,
                image,
                source,
            } => {
                let [family_port, high, low] = bound_words(Some(source));
                write_words(
                    &[
                        stream_word(stream),
                        registration,
                        image,
                        family_port,
                        high,
                        low,
                    ],
                    out,
                )
            }
            Self::ImageUnavailable {
                stream,
                registration,
                image,
            } => write_words(&[stream_word(stream), registration, image], out),
        }
    }

    /// Decodes an event of record type `type_id`.
    ///
    /// # Errors
    ///
    /// Returns [`CncError::UnknownType`], [`CncError::WrongLength`] and
    /// [`CncError::Reserved`].
    pub fn decode(type_id: u32, bytes: &[u8]) -> Result<Self, CncError> {
        match type_id {
            PARTICIPANT_LOST => {
                let [stream, registration, client, policy, position] =
                    read_words::<5>(type_id, bytes)?;
                Ok(Self::ParticipantLost {
                    stream: stream_from(stream),
                    registration,
                    client,
                    policy: LossPolicyCode::from_code(policy)
                        .ok_or(CncError::Reserved { type_id })?,
                    position,
                })
            }
            REQUIRED_BOUND_WITHDRAWN => {
                let [stream, registration, position] = read_words::<3>(type_id, bytes)?;
                Ok(Self::RequiredBoundWithdrawn {
                    stream: stream_from(stream),
                    registration,
                    position,
                })
            }
            PUBLICATION_CLOSED => {
                let [stream, reason, lane, image] = read_words::<4>(type_id, bytes)?;
                Ok(Self::PublicationClosed {
                    stream: stream_from(stream),
                    lane: lane_from(type_id, lane)?,
                    reason: CloseReason::from_code(reason).ok_or(CncError::Reserved { type_id })?,
                    image,
                })
            }
            SUCCESSOR_READY => {
                let [stream, registration, key, base, generation] =
                    read_words::<5>(type_id, bytes)?;
                Ok(Self::SuccessorReady {
                    stream: stream_from(stream),
                    registration,
                    key,
                    base,
                    generation,
                })
            }
            FENCED => {
                let [stream, registration] = read_words::<2>(type_id, bytes)?;
                Ok(Self::Fenced {
                    stream: stream_from(stream),
                    registration,
                })
            }
            PUBLICATION_ADMISSION => {
                let [stream, registration, admission] = read_words::<3>(type_id, bytes)?;
                Ok(Self::PublicationAdmission {
                    stream: stream_from(stream),
                    registration,
                    admission: NetworkAdmission::from_code(admission)
                        .ok_or(CncError::Reserved { type_id })?,
                })
            }
            IMAGE_AVAILABLE => {
                let [stream, registration, image, family_port, high, low] =
                    read_words::<IMAGE_AVAILABLE_WORDS>(type_id, bytes)?;
                if image == 0 {
                    return Err(CncError::Reserved { type_id });
                }
                // An image always has a source: family 0 is refused.
                Ok(Self::ImageAvailable {
                    stream: stream_from(stream),
                    registration,
                    image,
                    source: bound_from([family_port, high, low])
                        .flatten()
                        .ok_or(CncError::Reserved { type_id })?,
                })
            }
            IMAGE_UNAVAILABLE => {
                let [stream, registration, image] = read_words::<3>(type_id, bytes)?;
                if image == 0 {
                    return Err(CncError::Reserved { type_id });
                }
                Ok(Self::ImageUnavailable {
                    stream: stream_from(stream),
                    registration,
                    image,
                })
            }
            _ => Err(CncError::UnknownType { type_id }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A close reason's code is its seal reason's, both ways, the image
    /// retirement included (W3, ACS 15937).
    #[test]
    fn close_reasons_use_the_seal_codes() {
        for reason in [
            SealReason::RequiredParticipantLost,
            SealReason::ConflationVersionsExhausted,
            SealReason::StreamRemoved,
            SealReason::ConflationFeederLost,
            SealReason::ImageRetired,
            SealReason::EndOfStream,
        ] {
            let close = CloseReason::from_seal(reason).unwrap();
            assert_eq!(close.code(), reason.code());
            assert_eq!(CloseReason::from_code(reason.code()), Some(close));
        }
        assert_eq!(CloseReason::from_seal(SealReason::GuardClosed), None);
    }

    /// A `PublicationClosed` whose reason code this build does not know is
    /// a typed decode error (`CncError::Reserved`), never a panic: what a
    /// build from before `EndOfStream` (code 8) decodes for an image's
    /// clean end. The client skips such an event.
    /// Owner item 41: these enums are `#[non_exhaustive]`, and a value
    /// this build does not know is a typed decode error, never a guessed
    /// variant. A `ParticipantLost` whose loss policy is no code of this
    /// build is `Reserved`.
    #[test]
    fn an_unknown_loss_policy_is_a_typed_decode_error() {
        let event = Event::ParticipantLost {
            stream: stream(),
            registration: 7,
            client: 3,
            policy: LossPolicyCode::Hold,
            position: 4096,
        };
        let mut out = [0u8; MAX_EVENT_LENGTH];
        let length = event.encode(&mut out).unwrap();
        for code in [0u64, 4, u64::MAX] {
            let mut bytes = out;
            bytes[24..32].copy_from_slice(&code.to_le_bytes());
            assert_eq!(
                Event::decode(PARTICIPANT_LOST, &bytes[..length]),
                Err(CncError::Reserved {
                    type_id: PARTICIPANT_LOST
                }),
                "{code}"
            );
        }
    }

    /// Owner item 41: a response or event type this build does not know is
    /// `UnknownType`, whatever the bytes.
    #[test]
    fn an_unknown_response_or_event_type_is_a_typed_decode_error() {
        let bytes = [0u8; 16];
        for type_id in [NETWORK_SUBSCRIPTION_READY + 1, ADD_IMAGE_SUBSCRIPTION] {
            assert_eq!(
                Response::decode(type_id, &bytes),
                Err(CncError::UnknownType { type_id })
            );
        }
        for type_id in [IMAGE_UNAVAILABLE + 1, NETWORK_SUBSCRIPTION_READY] {
            assert_eq!(
                Event::decode(type_id, &bytes),
                Err(CncError::UnknownType { type_id })
            );
        }
    }

    /// Owner item 41: an `AddImageSubscription` whose role is no code of
    /// this build is `Reserved`, as for the other subscriptions.
    #[test]
    fn an_image_subscription_with_an_unknown_role_is_a_typed_decode_error() {
        let command = Command::AddImageSubscription {
            sequence: 5,
            image: 12,
            lane: Lane::ZERO,
            role: SubscriberRole::Optional,
        };
        let mut out = [0u8; MAX_COMMAND_LENGTH];
        let length = command.encode(&mut out).unwrap();
        assert!(Command::decode(ADD_IMAGE_SUBSCRIPTION, &out[..length]).is_ok());
        for code in [3u64, u64::MAX] {
            let mut bytes = out;
            bytes[16..24].copy_from_slice(&code.to_le_bytes());
            assert_eq!(
                Command::decode(ADD_IMAGE_SUBSCRIPTION, &bytes[..length]),
                Err(CncError::Reserved {
                    type_id: ADD_IMAGE_SUBSCRIPTION
                }),
                "{code}"
            );
        }
    }

    #[test]
    fn a_close_reason_this_build_does_not_know_is_a_typed_decode_error() {
        let event = Event::PublicationClosed {
            stream: stream(),
            lane: Lane::ZERO,
            reason: CloseReason::StreamRemoved,
            image: 0,
        };
        let mut out = [0u8; MAX_EVENT_LENGTH];
        let length = event.encode(&mut out).unwrap();
        for code in [9u64, 200, u64::MAX] {
            let mut bytes = out;
            bytes[8..16].copy_from_slice(&code.to_le_bytes());
            assert_eq!(
                Event::decode(event.type_id(), &bytes[..length]),
                Err(CncError::Reserved {
                    type_id: event.type_id()
                })
            );
        }
        assert_eq!(CloseReason::from_code(9), None);
        // Code 8 is known to this build.
        assert_eq!(CloseReason::from_code(8), Some(CloseReason::EndOfStream));
    }

    fn stream() -> StreamKey {
        StreamKey {
            stream_id: -2,
            session_id: i32::MAX,
        }
    }

    fn loss() -> ReportedLoss {
        ReportedLoss {
            driver: [0x0102, 0x0304],
            stream_registration: 5,
            incarnation: 1,
            subscription: 6,
            lane: 1,
            from: 4096,
            to: 8192,
            configured: RejoinPolicyCode::Snapshot,
            applied: RejoinOutcomeCode::SnapshotRebuilt,
            fallback: None,
        }
    }

    #[test]
    fn commands_round_trip() {
        let commands = [
            Command::AddPublication {
                sequence: 1,
                stream: stream(),
                lane: Lane::ZERO,
                allow_unconnected: true,
            },
            Command::AddSubscription {
                sequence: u64::MAX,
                stream: stream(),
                lane: Lane::try_new(3).unwrap(),
                role: SubscriberRole::Optional,
            },
            Command::AddSubscription {
                sequence: 5,
                stream: stream(),
                lane: Lane::ZERO,
                role: SubscriberRole::Observer,
            },
            Command::AddConcurrentPublication {
                sequence: 2,
                stream: stream(),
                lane: Lane::try_new(2).unwrap(),
                allow_unconnected: false,
            },
            Command::RemovePublication {
                sequence: 3,
                registration: 9,
            },
            Command::RemoveSubscription {
                sequence: 4,
                registration: 10,
            },
            Command::AllocateCounter {
                sequence: 5,
                type_id: u64::MAX,
                label: CounterLabel::new("loss reports dropped").unwrap(),
                stream: 11,
                participant: 12,
            },
            Command::AllocateCounter {
                sequence: 6,
                type_id: 1,
                label: CounterLabel::new("").unwrap(),
                stream: 0,
                participant: 0,
            },
            Command::AllocateCounter {
                sequence: 7,
                type_id: 2,
                label: CounterLabel::new(&"\u{e9}".repeat(32)).unwrap(),
                stream: 0,
                participant: 0,
            },
            Command::ReleaseCounter {
                sequence: 8,
                cell: 3,
                registration: 13,
            },
            Command::ReportLoss {
                sequence: 9,
                loss: loss(),
            },
            Command::ReportLoss {
                sequence: 10,
                loss: ReportedLoss {
                    driver: [u64::MAX, 0],
                    lane: 3,
                    from: 7,
                    to: 7,
                    configured: RejoinPolicyCode::Replay,
                    applied: RejoinOutcomeCode::SnapshotFailed,
                    fallback: Some(FallbackReasonCode::RetentionShort),
                    ..loss()
                },
            },
            Command::AddConflatedSubscription {
                sequence: 11,
                stream: StreamKey {
                    stream_id: -3,
                    session_id: i32::MIN,
                },
            },
        ];
        for command in commands {
            let mut out = [0u8; MAX_COMMAND_LENGTH];
            let length = command.encode(&mut out).unwrap();
            assert_eq!(
                Command::decode(command.type_id(), &out[..length]),
                Ok(command)
            );
        }
    }

    fn uri(length: usize) -> ChannelUri {
        // Multi-byte UTF-8 included: "é" is two bytes.
        let mut text = String::from("karyos:udp?endpoint=127.0.0.1:40123|é");
        while text.len() < length {
            text.push('a');
        }
        text.truncate(length);
        ChannelUri::new(&text).unwrap()
    }

    /// W5: the URI commands round-trip at every padding remainder and at
    /// the cap, and their record is the four words and the padded URI.
    #[test]
    fn uri_commands_round_trip() {
        for length in [1, 7, 8, 9, 37, MAX_COMMAND_URI] {
            let text = "k".repeat(length);
            let uri = ChannelUri::new(&text).unwrap();
            for command in [
                Command::AddNetworkPublication {
                    sequence: 3,
                    stream_id: -9,
                    allow_unconnected: true,
                    concurrent: false,
                    uri,
                },
                Command::AddNetworkPublication {
                    sequence: 4,
                    stream_id: 9,
                    allow_unconnected: false,
                    concurrent: true,
                    uri,
                },
                Command::AddNetworkSubscription {
                    sequence: u64::MAX,
                    stream_id: i32::MAX,
                    role: SubscriberRole::Observer,
                    uri,
                },
            ] {
                let mut out = [0u8; MAX_COMMAND_LENGTH];
                let encoded = command.encode(&mut out).unwrap();
                assert_eq!(encoded, 32 + length.next_multiple_of(8));
                assert_eq!(
                    Command::decode(command.type_id(), &out[..encoded]),
                    Ok(command)
                );
            }
        }
        let utf8 = uri(40);
        assert!(utf8.as_str().contains('é'));
        assert_eq!(ChannelUri::new(""), None);
        assert_eq!(ChannelUri::new(&"k".repeat(MAX_COMMAND_URI + 1)), None);
    }

    /// W5: decoding a URI command is strict.
    #[test]
    fn uri_commands_are_decoded_strictly() {
        let command = Command::AddNetworkPublication {
            sequence: 1,
            stream_id: 10,
            allow_unconnected: false,
            concurrent: false,
            uri: ChannelUri::new("karyos:udp?endpoint=127.0.0.1:1").unwrap(),
        };
        let type_id = command.type_id();
        let mut out = [0u8; MAX_COMMAND_LENGTH];
        let length = command.encode(&mut out).unwrap();
        let good = out[..length].to_vec();
        let decode = |bytes: &[u8]| Command::decode(type_id, bytes);
        let reserved = Err(CncError::Reserved { type_id });
        // A session id in the stream word.
        let mut session = good.clone();
        session[12] = 1;
        assert_eq!(decode(&session), reserved);
        // A reserved flag: bit 2 and above (bit 1 is concurrent, M11).
        for bit in [4u8, 8, 0x80] {
            let mut flags = good.clone();
            flags[16] = bit;
            assert_eq!(decode(&flags), reserved);
        }
        let mut concurrent = good.clone();
        concurrent[16] = 3;
        assert!(matches!(
            decode(&concurrent),
            Ok(Command::AddNetworkPublication {
                allow_unconnected: true,
                concurrent: true,
                ..
            })
        ));
        // A length of 0, or above the cap.
        for bad in [0u64, MAX_COMMAND_URI as u64 + 1] {
            let mut length = good.clone();
            length[24..32].copy_from_slice(&bad.to_le_bytes());
            assert_eq!(decode(&length), reserved);
        }
        // A record of another length than the URI's padded length.
        assert!(matches!(
            decode(&good[..good.len() - 8]),
            Err(CncError::WrongLength { .. })
        ));
        let mut longer = good.clone();
        longer.extend_from_slice(&[0; 8]);
        assert!(matches!(decode(&longer), Err(CncError::WrongLength { .. })));
        // Nonzero padding, and bytes that are not UTF-8.
        let mut padding = good.clone();
        *padding.last_mut().unwrap() = 1;
        assert_eq!(decode(&padding), reserved);
        let mut utf8 = good.clone();
        utf8[32] = 0xFF;
        assert_eq!(decode(&utf8), reserved);
        // A role that does not exist.
        let subscription = Command::AddNetworkSubscription {
            sequence: 1,
            stream_id: 10,
            role: SubscriberRole::Required,
            uri: ChannelUri::new("karyos:ipc").unwrap(),
        };
        let length = subscription.encode(&mut out).unwrap();
        let mut role = out[..length].to_vec();
        role[16] = 3;
        assert_eq!(
            Command::decode(subscription.type_id(), &role),
            Err(CncError::Reserved {
                type_id: subscription.type_id()
            })
        );
        assert_eq!(decode(&good), Ok(command));
    }

    fn command_words(bytes: &[u8]) -> Vec<u64> {
        bytes
            .as_chunks::<8>()
            .0
            .iter()
            .map(|chunk| u64::from_le_bytes(*chunk))
            .collect()
    }

    fn roles(strategy: crate::roles::Strategy) -> PublicationRoles {
        PublicationRoles {
            strategy,
            required: vec![77, 78],
            tags: vec![(88, 9)],
        }
    }

    /// karyos#637: `PublicationAdmission` is three words, its state code
    /// 1 to 3; 0 (no state reported) and any other code are refused.
    #[test]
    fn publication_admission_round_trips_strictly() {
        let stream = StreamKey {
            stream_id: 10,
            session_id: 3,
        };
        for (admission, code) in [
            (NetworkAdmission::Open, 1),
            (NetworkAdmission::NotJoined, 2),
            (NetworkAdmission::LostRequired, 3),
        ] {
            let event = Event::PublicationAdmission {
                stream,
                registration: 7,
                admission,
            };
            let mut out = [0u8; MAX_EVENT_LENGTH];
            let length = event.encode(&mut out).unwrap();
            assert_eq!(command_words(&out[..length]), [10 | 3 << 32, 7, code]);
            assert_eq!(event.type_id(), 0xC8);
            assert_eq!(Event::decode(0xC8, &out[..length]), Ok(event));
            assert_eq!(NetworkAdmission::from_code(code), Some(admission));
        }
        for code in [0u64, 4, u64::MAX] {
            let mut bytes = Vec::new();
            for word in [10 | 3 << 32, 7, code] {
                bytes.extend_from_slice(&u64::to_le_bytes(word));
            }
            assert_eq!(
                Event::decode(0xC8, &bytes),
                Err(CncError::Reserved { type_id: 0xC8 })
            );
        }
        assert!(matches!(
            Event::decode(0xC8, &[0; 16]),
            Err(CncError::WrongLength { .. })
        ));
    }

    /// karyos#637: the roles and identity commands round-trip, and their
    /// words are the layout the module docs give: six words, the padded
    /// URI, then the required ids and the tag pairs.
    #[test]
    fn roles_commands_round_trip() {
        use crate::roles::Strategy;

        let uri = ChannelUri::new("karyos:udp?group=239.1.1.1:1|fc=tagged:9").unwrap();
        let command = Command::AddNetworkPublicationWithRoles {
            sequence: 3,
            stream_id: 10,
            allow_unconnected: true,
            concurrent: false,
            uri,
            roles: roles(Strategy::Tagged(9)),
        };
        let mut out = [0u8; MAX_COMMAND_LENGTH];
        let length = command.encode(&mut out).unwrap();
        let words = command_words(&out[..length]);
        let padded = uri.padded().len() / 8;
        assert_eq!(words.len(), 6 + padded + 2 + 2);
        assert_eq!(
            words[..6],
            [3, 10, 1, 40, 2 | 2 << 16 | 1 << 32, 9],
            "sequence, stream, flags, URI length, strategy and counts, group"
        );
        assert_eq!(words[6 + padded..], [77, 78, 88, 9]);
        assert_eq!(command.type_id(), 0x12);
        assert_eq!(Command::decode(0x12, &out[..length]), Ok(command.clone()));
        for strategy in [Strategy::Min, Strategy::Max] {
            let empty = Command::AddNetworkPublicationWithRoles {
                sequence: 4,
                stream_id: -1,
                allow_unconnected: false,
                concurrent: true,
                uri,
                roles: PublicationRoles {
                    strategy,
                    required: Vec::new(),
                    tags: Vec::new(),
                },
            };
            let length = empty.encode(&mut out).unwrap();
            assert_eq!(length, 48 + uri.padded().len());
            assert_eq!(Command::decode(0x12, &out[..length]), Ok(empty));
        }
        let identity = Command::AddNetworkSubscriptionAs {
            sequence: 5,
            stream_id: 10,
            role: SubscriberRole::Optional,
            uri,
            identity: ReceiverIdentity {
                receiver_id: core::num::NonZeroU64::new(77).unwrap(),
                group_tag: 9,
            },
        };
        let length = identity.encode(&mut out).unwrap();
        assert_eq!(command_words(&out[..6 * 8]), [5, 10, 1, 40, 77, 9]);
        assert_eq!(length, 48 + uri.padded().len());
        assert_eq!(identity.type_id(), 0x13);
        assert_eq!(Command::decode(0x13, &out[..length]), Ok(identity));
    }

    /// karyos#637: the roles and identity commands are decoded strictly:
    /// reserved bits and strategy codes, a group that does not match the
    /// strategy, a zero or repeated `receiver_id`, a zero tag, a receiver
    /// id of 0 and any length but the counts' are refused.
    #[test]
    fn roles_commands_are_decoded_strictly() {
        use crate::roles::Strategy;

        let uri = ChannelUri::new("karyos:udp?group=239.1.1.1:1").unwrap();
        let command = Command::AddNetworkPublicationWithRoles {
            sequence: 1,
            stream_id: 10,
            allow_unconnected: false,
            concurrent: false,
            uri,
            roles: roles(Strategy::Max),
        };
        let mut out = [0u8; MAX_COMMAND_LENGTH];
        let length = command.encode(&mut out).unwrap();
        let good = out[..length].to_vec();
        let decode = |bytes: &[u8]| Command::decode(0x12, bytes);
        let reserved = Err(CncError::Reserved { type_id: 0x12 });
        let word = |bytes: &mut Vec<u8>, at: usize, value: u64| {
            bytes[at * 8..at * 8 + 8].copy_from_slice(&value.to_le_bytes());
        };
        let tail = 6 + uri.padded().len() / 8;
        let counts = 1 | 2 << 16 | 1 << 32;
        for (at, value) in [
            // Strategy 3, reserved bits 15 to 8 and 63 to 48.
            (4, counts & !0xFF | 3),
            (4, counts | 1 << 8),
            (4, counts | 1 << 48),
            // A group without `tagged`, and `tagged` without one.
            (5, 9),
            (4, counts & !0xFF | 2),
            // A zero or repeated required id.
            (tail, 0),
            (tail + 1, 77),
            // A zero receiver id or a zero tag in a pair.
            (tail + 2, 0),
            (tail + 3, 0),
            // A flag above bit 1.
            (2, 4),
        ] {
            let mut bad = good.clone();
            word(&mut bad, at, value);
            assert_eq!(decode(&bad), reserved, "word {at} = {value:#x}");
        }
        // Counts that do not match the record, both ways.
        for value in [counts + (1 << 16), counts - (1 << 16)] {
            let mut bad = good.clone();
            word(&mut bad, 4, value);
            assert!(
                matches!(decode(&bad), Err(CncError::WrongLength { .. })),
                "counts {value:#x}"
            );
        }
        assert!(matches!(
            decode(&good[..good.len() - 8]),
            Err(CncError::WrongLength { .. })
        ));
        assert_eq!(decode(&good), Ok(command));
        // An identity of receiver 0, a reserved role, a trailing word.
        let identity = Command::AddNetworkSubscriptionAs {
            sequence: 1,
            stream_id: 10,
            role: SubscriberRole::Required,
            uri,
            identity: ReceiverIdentity {
                receiver_id: core::num::NonZeroU64::new(77).unwrap(),
                group_tag: 0,
            },
        };
        let length = identity.encode(&mut out).unwrap();
        let good = out[..length].to_vec();
        let reserved = Err(CncError::Reserved { type_id: 0x13 });
        for (at, value) in [(4, 0), (2, 3)] {
            let mut bad = good.clone();
            word(&mut bad, at, value);
            assert_eq!(Command::decode(0x13, &bad), reserved);
        }
        let mut longer = good.clone();
        longer.extend_from_slice(&[0; 8]);
        assert!(matches!(
            Command::decode(0x13, &longer),
            Err(CncError::WrongLength { .. })
        ));
        assert_eq!(Command::decode(0x13, &good), Ok(identity));
    }

    /// karyos#637: roles are bounded by the buffer they are encoded into
    /// (the command ring's largest record), and by nothing else: a list too
    /// long for the buffer, or for its 16-bit count, is refused as a buffer
    /// too short, never truncated.
    #[test]
    fn roles_are_bounded_by_the_record_only() {
        use crate::roles::Strategy;

        let uri = ChannelUri::new("karyos:udp?group=239.1.1.1:1").unwrap();
        let many = |required: usize| Command::AddNetworkPublicationWithRoles {
            sequence: 1,
            stream_id: 10,
            allow_unconnected: false,
            concurrent: false,
            uri,
            roles: PublicationRoles {
                strategy: Strategy::Min,
                required: (1..=required as u64).collect(),
                tags: Vec::new(),
            },
        };
        // A large record carries a list the default buffer cannot.
        let mut large = vec![0u8; 64 * 1024];
        let command = many(1000);
        let length = command.encode(&mut large).unwrap();
        assert_eq!(length, 48 + uri.padded().len() + 8000);
        assert_eq!(Command::decode(0x12, &large[..length]), Ok(command));
        let mut small = [0u8; MAX_COMMAND_LENGTH];
        assert!(matches!(
            many(1000).encode(&mut small),
            Err(CncError::BufferTooShort { .. })
        ));
        // A count past 16 bits cannot be carried, whatever the buffer.
        let mut huge = vec![0u8; 1024 * 1024];
        assert!(matches!(
            many(usize::from(u16::MAX) + 1).encode(&mut huge),
            Err(CncError::BufferTooShort { .. })
        ));
    }

    /// Decision row 26: the documented `NetworkSubscriptionReady` vectors
    /// decode to their addresses and re-encode identically.
    #[test]
    fn network_subscription_ready_vectors() {
        let request = RequestId {
            client: 1,
            sequence: 2,
        };
        for (text, hex) in [
            (
                "127.0.0.1:40123",
                "0100000000000000 0200000000000000 0300000000000000 \
                 BB9C040000000000 0000000000000000 0100007F00000000",
            ),
            (
                "[fe80::1%3]:40123",
                "0100000000000000 0200000000000000 0300000000000000 \
                 BB9C060003000000 00000000000080FE 0100000000000000",
            ),
        ] {
            let digits: Vec<u8> = hex.bytes().filter(u8::is_ascii_hexdigit).collect();
            let bytes: Vec<u8> = digits
                .chunks(2)
                .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect();
            assert_eq!(bytes.len(), 48);
            let expected = Response::NetworkSubscriptionReady {
                request,
                registration: 3,
                bound: Some(text.parse().unwrap()),
            };
            assert_eq!(
                Response::decode(NETWORK_SUBSCRIPTION_READY, &bytes),
                Ok(expected)
            );
            let mut out = [0u8; MAX_RESPONSE_LENGTH];
            let length = expected.encode(&mut out).unwrap();
            assert_eq!(&out[..length], &bytes[..]);
        }
        let SocketAddr::V6(scoped) = "[fe80::1%3]:40123".parse::<SocketAddr>().unwrap() else {
            panic!("an IPv6 address");
        };
        assert_eq!(scoped.scope_id(), 3);
    }

    /// Decision row 26: decoding `NetworkSubscriptionReady` is strict.
    #[test]
    fn network_subscription_ready_is_decoded_strictly() {
        let type_id = NETWORK_SUBSCRIPTION_READY;
        let words = |family_port: u64, high: u64, low: u64| -> Vec<u8> {
            [1u64, 2, 3, family_port, high, low]
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect()
        };
        let decode = |bytes: &[u8]| Response::decode(type_id, bytes);
        let reserved = Err(CncError::Reserved { type_id });
        let v4 = 40123 | 4 << 16;
        let v6 = 40123 | 6 << 16;
        assert!(decode(&words(v4, 0, 0x7F00_0001)).is_ok());
        assert!(decode(&words(v6 | 3 << 32, 0xFE80 << 48, 1)).is_ok());
        assert!(matches!(
            decode(&words(0, 0, 0)),
            Ok(Response::NetworkSubscriptionReady { bound: None, .. })
        ));
        // Reserved bits 24 to 31, for each family.
        for family_port in [v4, v6, 0] {
            for bit in 24..32 {
                assert_eq!(decode(&words(family_port | 1 << bit, 0, 1)), reserved);
            }
        }
        // An unknown family.
        for family in [1u64, 2, 3, 5, 7, 0x10, 0xFF] {
            assert_eq!(decode(&words(40123 | family << 16, 0, 1)), reserved);
        }
        // IPv4: the high bits of the low word, the high word, a scope id.
        assert_eq!(decode(&words(v4, 0, 1 << 32 | 1)), reserved);
        assert_eq!(decode(&words(v4, 0, u64::MAX)), reserved);
        assert_eq!(decode(&words(v4, 1, 1)), reserved);
        assert_eq!(decode(&words(v4 | 1 << 32, 0, 1)), reserved);
        assert_eq!(
            decode(&words(v4 | u64::from(u32::MAX) << 32, 0, 1)),
            reserved
        );
        // Family 0 with any other field nonzero.
        for (family_port, high, low) in [
            (1, 0, 0),
            (0xFFFF, 0, 0),
            (1 << 32, 0, 0),
            (0, 1, 0),
            (0, 0, 1),
        ] {
            assert_eq!(decode(&words(family_port, high, low)), reserved);
        }
        // Any other length: the three word layout before row 26 included.
        let good = words(v4, 0, 0x7F00_0001);
        for length in [0, 8, 24, 40, 47, 49, 56] {
            let mut bytes = good.clone();
            bytes.resize(length, 0);
            assert_eq!(
                decode(&bytes),
                Err(CncError::WrongLength {
                    type_id,
                    length,
                    expected: 48,
                })
            );
        }
    }

    /// W5: the network subscription grant, the image events and the two
    /// error codes round-trip.
    #[test]
    fn network_responses_and_events_round_trip() {
        let request = RequestId {
            client: 4,
            sequence: 9,
        };
        for response in [
            Response::NetworkSubscriptionReady {
                request,
                registration: 77,
                bound: Some("127.0.0.1:40123".parse().unwrap()),
            },
            Response::NetworkSubscriptionReady {
                request,
                registration: 77,
                bound: Some("[fe80::1%3]:40123".parse().unwrap()),
            },
            Response::NetworkSubscriptionReady {
                request,
                registration: 77,
                bound: Some("[2001:db8::1]:1".parse().unwrap()),
            },
            Response::NetworkSubscriptionReady {
                request,
                registration: 77,
                bound: None,
            },
            Response::Error {
                request,
                code: ErrorCode::InvalidChannel,
                detail: 3,
            },
            Response::Error {
                request,
                code: ErrorCode::UnsupportedChannel,
                detail: 10,
            },
            Response::Error {
                request,
                code: ErrorCode::ReliabilityMismatch,
                detail: 10,
            },
            Response::Error {
                request,
                code: ErrorCode::LaneMismatch,
                detail: 2,
            },
        ] {
            let mut out = [0u8; MAX_RESPONSE_LENGTH];
            let length = response.encode(&mut out).unwrap();
            assert_eq!(
                Response::decode(response.type_id(), &out[..length]),
                Ok(response)
            );
        }
        for event in [
            Event::ImageAvailable {
                stream: stream(),
                registration: 77,
                image: 12,
                source: "10.1.2.3:4000".parse().unwrap(),
            },
            Event::ImageUnavailable {
                stream: stream(),
                registration: 77,
                image: 12,
            },
        ] {
            let mut out = [0u8; MAX_EVENT_LENGTH];
            let length = event.encode(&mut out).unwrap();
            assert_eq!(Event::decode(event.type_id(), &out[..length]), Ok(event));
        }
    }

    /// Per-source images (`quantstratum-docs:
    /// karyos/design/per-source-images.md`, D2-3): `ImageAvailable` names
    /// the image and its IPv4 or IPv6 source in six words, the source in
    /// `NetworkSubscriptionReady`'s address encoding, with golden bytes;
    /// `ImageUnavailable` names the image in three words.
    #[test]
    fn image_events_name_the_image_and_its_source() {
        let v4 = Event::ImageAvailable {
            stream: stream(),
            registration: 77,
            image: 12,
            source: "10.1.2.3:4000".parse().unwrap(),
        };
        let mut out = [0u8; MAX_EVENT_LENGTH];
        let length = v4.encode(&mut out).unwrap();
        assert_eq!(length, 48);
        assert_eq!(
            &out[16..48],
            &[
                12, 0, 0, 0, 0, 0, 0, 0, // image registration
                0xA0, 0x0F, 4, 0, 0, 0, 0, 0, // port 4000, family 4, no scope
                0, 0, 0, 0, 0, 0, 0, 0, // high word zero
                3, 2, 1, 10, 0, 0, 0, 0, // 10.1.2.3 in bits 31 to 0
            ]
        );
        assert_eq!(Event::decode(IMAGE_AVAILABLE, &out[..length]), Ok(v4));
        let v6 = Event::ImageAvailable {
            stream: stream(),
            registration: 77,
            image: 12,
            source: "[2001:db8::1]:9".parse().unwrap(),
        };
        let length = v6.encode(&mut out).unwrap();
        assert_eq!(
            &out[24..48],
            &[
                9, 0, 6, 0, 0, 0, 0, 0, // port 9, family 6
                0, 0, 0, 0, 0xB8, 0x0D, 0x01, 0x20, // 2001:0db8:0000:0000
                1, 0, 0, 0, 0, 0, 0, 0, // 0000:0000:0000:0001
            ]
        );
        assert_eq!(Event::decode(IMAGE_AVAILABLE, &out[..length]), Ok(v6));
        let gone = Event::ImageUnavailable {
            stream: stream(),
            registration: 77,
            image: 12,
        };
        let length = gone.encode(&mut out).unwrap();
        assert_eq!(length, 24);
        assert_eq!(Event::decode(IMAGE_UNAVAILABLE, &out[..length]), Ok(gone));
    }

    /// The image events are decoded strictly: the two-word layouts of a
    /// build before D2 are `WrongLength`, and a family other than 4 or 6
    /// (family 0 included: an image always has a source), a reserved bit,
    /// a high word, high low-word bits or a scope id under IPv4, or an
    /// image of 0 are `Reserved`.
    #[test]
    fn image_events_are_decoded_strictly() {
        let mut out = [0u8; MAX_EVENT_LENGTH];
        let length = Event::ImageAvailable {
            stream: stream(),
            registration: 77,
            image: 12,
            source: "10.1.2.3:4000".parse().unwrap(),
        }
        .encode(&mut out)
        .unwrap();
        for type_id in [IMAGE_AVAILABLE, IMAGE_UNAVAILABLE] {
            assert!(matches!(
                Event::decode(type_id, &out[..16]),
                Err(CncError::WrongLength { .. })
            ));
        }
        let refused = |change: &dyn Fn(&mut [u8; MAX_EVENT_LENGTH])| {
            let mut bytes = out;
            change(&mut bytes);
            matches!(
                Event::decode(IMAGE_AVAILABLE, &bytes[..length]),
                Err(CncError::Reserved { .. })
            )
        };
        assert!(refused(&|bytes| bytes[26] = 5), "family 5");
        assert!(refused(&|bytes| bytes[27] = 1), "a bit above the family");
        assert!(refused(&|bytes| bytes[28] = 1), "a scope id under IPv4");
        assert!(refused(&|bytes| bytes[32] = 1), "a high word under IPv4");
        assert!(
            refused(&|bytes| bytes[44] = 1),
            "an IPv4 address above 32 bits"
        );
        assert!(refused(&|bytes| bytes[16] = 0), "image 0");
        let mut bytes = [0u8; 24];
        bytes[16] = 0;
        assert!(matches!(
            Event::decode(IMAGE_UNAVAILABLE, &bytes),
            Err(CncError::Reserved { .. })
        ));
        // The three-word close of a build before D2 is `WrongLength`.
        let length = Event::PublicationClosed {
            stream: stream(),
            lane: Lane::ZERO,
            reason: CloseReason::ImageRetired,
            image: 12,
        }
        .encode(&mut out)
        .unwrap();
        assert_eq!(length, 32);
        assert!(matches!(
            Event::decode(PUBLICATION_CLOSED, &out[..24]),
            Err(CncError::WrongLength { .. })
        ));
    }

    /// The documented `ImageAvailable` vector, an IPv6 link-local source
    /// with its scope id, decodes to its source and re-encodes
    /// identically: one address encoding with `NetworkSubscriptionReady`.
    #[test]
    fn image_available_vector() {
        let hex = "0700000005000000 0200000000000000 0300000000000000 \
                   BB9C060003000000 00000000000080FE 0100000000000000";
        let digits: Vec<u8> = hex.bytes().filter(u8::is_ascii_hexdigit).collect();
        let bytes: Vec<u8> = digits
            .chunks(2)
            .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(bytes.len(), 48);
        let source: SocketAddr = "[fe80::1%3]:40123".parse().unwrap();
        let SocketAddr::V6(scoped) = source else {
            panic!("an IPv6 address");
        };
        assert_eq!(scoped.scope_id(), 3);
        let expected = Event::ImageAvailable {
            stream: StreamKey {
                stream_id: 7,
                session_id: 5,
            },
            registration: 2,
            image: 3,
            source,
        };
        assert_eq!(Event::decode(IMAGE_AVAILABLE, &bytes), Ok(expected));
        let mut out = [0u8; MAX_EVENT_LENGTH];
        let length = expected.encode(&mut out).unwrap();
        assert_eq!(&out[..length], &bytes[..]);
        // The same address words as `NetworkSubscriptionReady`'s.
        let mut ready = [0u8; MAX_RESPONSE_LENGTH];
        let length = Response::NetworkSubscriptionReady {
            request: RequestId {
                client: 1,
                sequence: 2,
            },
            registration: 3,
            bound: Some(source),
        }
        .encode(&mut ready)
        .unwrap();
        assert_eq!(&ready[24..length], &bytes[24..48]);
    }

    /// `ImageAvailable`'s source words are decoded as strictly as
    /// `NetworkSubscriptionReady`'s, and family 0 is refused.
    #[test]
    fn image_available_source_is_decoded_strictly() {
        let type_id = IMAGE_AVAILABLE;
        let words = |family_port: u64, high: u64, low: u64| -> Vec<u8> {
            [7u64 | 5 << 32, 2, 3, family_port, high, low]
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect()
        };
        let decode = |bytes: &[u8]| Event::decode(type_id, bytes);
        let reserved = Err(CncError::Reserved { type_id });
        let v4 = 40123 | 4 << 16;
        let v6 = 40123 | 6 << 16;
        assert!(decode(&words(v4, 0, 0x7F00_0001)).is_ok());
        assert!(matches!(
            decode(&words(v6 | 3 << 32, 0xFE80 << 48, 1)),
            Ok(Event::ImageAvailable { source: SocketAddr::V6(source), .. })
                if source.scope_id() == 3 && source.flowinfo() == 0
        ));
        // Family 0: an image always has a source, so even all zero.
        assert_eq!(decode(&words(0, 0, 0)), reserved);
        assert_eq!(decode(&words(40123, 0, 1)), reserved);
        // Reserved bits 24 to 31, for each family.
        for family_port in [v4, v6] {
            for bit in 24..32 {
                assert_eq!(decode(&words(family_port | 1 << bit, 0, 1)), reserved);
            }
        }
        // An unknown family.
        for family in [1u64, 2, 3, 5, 7, 0x10, 0xFF] {
            assert_eq!(decode(&words(40123 | family << 16, 0, 1)), reserved);
        }
        // IPv4: the high bits of the low word, the high word, a scope id.
        assert_eq!(decode(&words(v4, 0, 1 << 32 | 1)), reserved);
        assert_eq!(decode(&words(v4, 0, u64::MAX)), reserved);
        assert_eq!(decode(&words(v4, 1, 1)), reserved);
        assert_eq!(decode(&words(v4 | 1 << 32, 0, 1)), reserved);
        assert_eq!(
            decode(&words(v4 | u64::from(u32::MAX) << 32, 0, 1)),
            reserved
        );
        // The layout before the alignment: IPv4 in the high word.
        assert_eq!(decode(&words(v4, 0x7F00_0001, 0)), reserved);
    }

    /// `AddImageSubscription` names one lane of an image by its
    /// registration, never 0.
    #[test]
    fn an_image_subscription_names_its_image() {
        let command = Command::AddImageSubscription {
            sequence: 5,
            image: 12,
            lane: Lane::try_new(1).unwrap(),
            role: SubscriberRole::Optional,
        };
        let mut out = [0u8; MAX_COMMAND_LENGTH];
        let length = command.encode(&mut out).unwrap();
        assert_eq!(command.type_id(), 0x11);
        assert_eq!(
            &out[..length],
            &[
                5, 0, 0, 0, 0, 0, 0, 0, // sequence
                12, 0, 0, 0, 0, 0, 0, 0, // image registration
                1, 0, 0, 0, 0, 0, 0, 0, // optional
                1, 0, 0, 0, 0, 0, 0, 0, // lane 1
            ]
        );
        assert_eq!(Command::decode(0x11, &out[..length]), Ok(command));
        out[8] = 0;
        assert!(matches!(
            Command::decode(0x11, &out[..length]),
            Err(CncError::Reserved { .. })
        ));
    }

    /// The longest event, 48 bytes, fits the broadcast of the smallest
    /// capacity (`MIN_CAPACITY`, 1024 bytes: a 128-byte extent), and every
    /// event fits `MAX_EVENT_LENGTH`.
    #[test]
    fn the_longest_event_fits_the_smallest_broadcast() {
        use karyos_sys::broadcast::{MIN_CAPACITY, Received, broadcast};

        assert_eq!(MAX_EVENT_LENGTH, 48);
        let event = Event::ImageAvailable {
            stream: stream(),
            registration: 77,
            image: 12,
            source: "[2001:db8::1]:9".parse().unwrap(),
        };
        let mut out = [0u8; MAX_EVENT_LENGTH];
        let length = event.encode(&mut out).unwrap();
        assert_eq!(length, MAX_EVENT_LENGTH);
        let mut transmitter = broadcast(MIN_CAPACITY).unwrap();
        assert!(transmitter.max_payload() >= MAX_EVENT_LENGTH);
        let mut receiver = transmitter.receiver();
        let _ = transmitter
            .transmit(event.type_id(), &out[..length])
            .unwrap();
        let Received::Message {
            type_id, payload, ..
        } = receiver.receive()
        else {
            panic!("not received");
        };
        assert_eq!(Event::decode(type_id, payload), Ok(event));
    }

    #[test]
    fn responses_round_trip() {
        let request = RequestId {
            client: 7,
            sequence: 8,
        };
        let responses = [
            Response::PublicationReady {
                request,
                registration: 1,
                key: 2,
            },
            Response::SubscriptionReady {
                request,
                registration: 3,
                key: 4,
            },
            Response::OperationSucceeded { request },
            Response::Error {
                request,
                code: ErrorCode::ResourcesUnavailable,
                detail: 5,
            },
            Response::Error {
                request,
                code: ErrorCode::InvalidPublicationMode,
                detail: 6,
            },
            Response::CounterAllocated {
                request,
                cell: 7,
                registration: 8,
            },
            Response::ConflatedReady {
                request,
                registration: 9,
                key: 10,
                keys: u32::MAX,
                value_capacity: 64,
                journal_capacity: 1 << 20,
            },
        ];
        for response in responses {
            let mut out = [0u8; MAX_RESPONSE_LENGTH];
            let length = response.encode(&mut out).unwrap();
            assert_eq!(
                Response::decode(response.type_id(), &out[..length]),
                Ok(response)
            );
            assert_eq!(response.request(), request);
        }
    }

    /// The conflated view's messages, in literal bytes; a key count that
    /// does not fit 32 bits is refused.
    #[test]
    fn conflated_view_golden_bytes() {
        let mut out = [0u8; MAX_COMMAND_LENGTH];
        let command = Command::AddConflatedSubscription {
            sequence: 0x0102,
            stream: StreamKey {
                stream_id: -2,
                session_id: 7,
            },
        };
        let length = command.encode(&mut out).unwrap();
        assert_eq!(command.type_id(), 0x0C);
        assert_eq!(
            &out[..length],
            &[
                0x02, 0x01, 0, 0, 0, 0, 0, 0, // sequence
                0xfe, 0xff, 0xff, 0xff, 7, 0, 0, 0, // stream -2, session 7
            ]
        );
        let mut out = [0u8; MAX_RESPONSE_LENGTH];
        let response = Response::ConflatedReady {
            request: RequestId {
                client: 3,
                sequence: 4,
            },
            registration: 5,
            key: 6,
            keys: 7,
            value_capacity: 8,
            journal_capacity: 0x0400,
        };
        let length = response.encode(&mut out).unwrap();
        assert_eq!(response.type_id(), 0x88);
        assert_eq!(length, MAX_RESPONSE_LENGTH);
        assert_eq!(
            &out[..length],
            &[
                3, 0, 0, 0, 0, 0, 0, 0, // client
                4, 0, 0, 0, 0, 0, 0, 0, // sequence
                5, 0, 0, 0, 0, 0, 0, 0, // registration
                6, 0, 0, 0, 0, 0, 0, 0, // key
                7, 0, 0, 0, 0, 0, 0, 0, // keys
                8, 0, 0, 0, 0, 0, 0, 0, // value capacity
                0, 4, 0, 0, 0, 0, 0, 0, // journal capacity
            ]
        );
        let mut wide = out;
        wide[32..40].copy_from_slice(&(u64::from(u32::MAX) + 1).to_le_bytes());
        assert_eq!(
            Response::decode(0x88, &wide),
            Err(CncError::Reserved { type_id: 0x88 })
        );
    }

    /// Literal bytes, so a layout change cannot hide behind a matching
    /// encoder and decoder.
    #[test]
    fn golden_bytes() {
        let mut out = [0u8; MAX_COMMAND_LENGTH];
        let length = Command::AddPublication {
            sequence: 0x0102,
            stream: StreamKey {
                stream_id: -2,
                session_id: 7,
            },
            lane: Lane::try_new(1).unwrap(),
            allow_unconnected: true,
        }
        .encode(&mut out)
        .unwrap();
        assert_eq!(
            &out[..length],
            &[
                0x02, 0x01, 0, 0, 0, 0, 0, 0, // sequence
                0xfe, 0xff, 0xff, 0xff, 7, 0, 0, 0, // stream -2, session 7
                1, 0, 0, 0, 0, 0, 0, 0, // allow unconnected
                1, 0, 0, 0, 0, 0, 0, 0, // lane 1
            ]
        );
        let mut out = [0u8; MAX_RESPONSE_LENGTH];
        let length = Response::Error {
            request: RequestId {
                client: 3,
                sequence: 4,
            },
            code: ErrorCode::UnknownRegistration,
            detail: 0x0506,
        }
        .encode(&mut out)
        .unwrap();
        assert_eq!(
            &out[..length],
            &[
                3, 0, 0, 0, 0, 0, 0, 0, // client
                4, 0, 0, 0, 0, 0, 0, 0, // sequence
                3, 0, 0, 0, 0, 0, 0, 0, // code: unknown registration
                0x06, 0x05, 0, 0, 0, 0, 0, 0, // detail
            ]
        );
        assert_eq!(
            Command::AddSubscription {
                sequence: 0,
                stream: StreamKey {
                    stream_id: 0,
                    session_id: 0
                },
                lane: Lane::ZERO,
                role: SubscriberRole::Optional
            }
            .type_id(),
            0x02
        );
        assert_eq!(
            Response::OperationSucceeded {
                request: RequestId {
                    client: 0,
                    sequence: 0
                }
            }
            .type_id(),
            0x83
        );
        let mut out = [0u8; MAX_COMMAND_LENGTH];
        let length = Command::AddConcurrentPublication {
            sequence: 0x0102,
            stream: StreamKey {
                stream_id: -2,
                session_id: 7,
            },
            lane: Lane::try_new(3).unwrap(),
            allow_unconnected: false,
        }
        .encode(&mut out)
        .unwrap();
        assert_eq!(
            &out[..length],
            &[
                0x02, 0x01, 0, 0, 0, 0, 0, 0, // sequence
                0xfe, 0xff, 0xff, 0xff, 7, 0, 0, 0, // stream -2, session 7
                0, 0, 0, 0, 0, 0, 0, 0, // flags
                3, 0, 0, 0, 0, 0, 0, 0, // lane 3
            ]
        );
        let mut out = [0u8; MAX_COMMAND_LENGTH];
        let length = Command::AddSubscription {
            sequence: 0x0102,
            stream: StreamKey {
                stream_id: -2,
                session_id: 7,
            },
            lane: Lane::try_new(2).unwrap(),
            role: SubscriberRole::Observer,
        }
        .encode(&mut out)
        .unwrap();
        assert_eq!(
            &out[..length],
            &[
                0x02, 0x01, 0, 0, 0, 0, 0, 0, // sequence
                0xfe, 0xff, 0xff, 0xff, 7, 0, 0, 0, // stream -2, session 7
                2, 0, 0, 0, 0, 0, 0, 0, // role: observer
                2, 0, 0, 0, 0, 0, 0, 0, // lane 2
            ]
        );
        assert_eq!(ErrorCode::InvalidPublicationMode.code(), 6);
        let mut response = [0u8; 4 * 8];
        response[16] = 6;
        assert!(matches!(
            Response::decode(0x84, &response),
            Ok(Response::Error {
                code: ErrorCode::InvalidPublicationMode,
                ..
            })
        ));
    }

    #[test]
    fn decoding_is_strict() {
        let mut out = [0u8; MAX_COMMAND_LENGTH];
        let command = Command::AddSubscription {
            sequence: 1,
            stream: stream(),
            lane: Lane::ZERO,
            role: SubscriberRole::Required,
        };
        let length = command.encode(&mut out).unwrap();
        // Wrong length, unknown type, reserved role and flag values.
        assert!(matches!(
            Command::decode(command.type_id(), &out[..length - 8]),
            Err(CncError::WrongLength { .. })
        ));
        assert!(matches!(
            Command::decode(0x81, &out[..length]),
            Err(CncError::UnknownType { .. })
        ));
        out[16] = 3;
        assert!(matches!(
            Command::decode(command.type_id(), &out[..length]),
            Err(CncError::Reserved { .. })
        ));
        out[16] = 2;
        assert!(matches!(
            Command::decode(0x01, &out[..length]),
            Err(CncError::Reserved { .. })
        ));
        assert!(matches!(
            Command::decode(0x05, &out[..length]),
            Err(CncError::Reserved { .. })
        ));
        assert!(matches!(
            Command::decode(0x14, &out[..length]),
            Err(CncError::UnknownType { .. })
        ));
        // A lane word of 4 or more, or with any bit above the lane, is
        // reserved in all three commands.
        out[16] = 0;
        for type_id in [0x01, 0x02, 0x05] {
            assert!(Command::decode(type_id, &out[..length]).is_ok());
            for lane in [4u64, 0xFF, 1 << 8, 1 << 63] {
                out[24..32].copy_from_slice(&lane.to_le_bytes());
                assert!(matches!(
                    Command::decode(type_id, &out[..length]),
                    Err(CncError::Reserved { .. })
                ));
            }
            out[24..32].fill(0);
        }
        let mut response = [0u8; 4 * 8];
        response[16] = 99;
        assert!(matches!(
            Response::decode(0x84, &response),
            Err(CncError::Reserved { .. })
        ));
        assert_eq!(
            Command::RemovePublication {
                sequence: 1,
                registration: 1
            }
            .encode(&mut [0u8; 15]),
            Err(CncError::BufferTooShort {
                required: 16,
                available: 15
            })
        );
    }

    #[test]
    fn counter_labels_are_bounded_utf8() {
        assert_eq!(
            CounterLabel::new("bytes sent").unwrap().as_str(),
            "bytes sent"
        );
        assert_eq!(
            CounterLabel::new(&"x".repeat(64)).unwrap().as_str().len(),
            64
        );
        assert!(CounterLabel::new(&"x".repeat(65)).is_none());
        assert!(CounterLabel::from_bytes(&[0xFF, 0xFE]).is_none());
        assert!(CounterLabel::from_bytes(b"ok").is_some());
        // The longest label fits its fixed layout; the bound is the URI
        // command's, the largest (W5).
        let mut out = [0u8; MAX_COMMAND_LENGTH];
        let length = Command::AllocateCounter {
            sequence: 1,
            type_id: 1,
            label: CounterLabel::new(&"x".repeat(64)).unwrap(),
            stream: 0,
            participant: 0,
        }
        .encode(&mut out)
        .unwrap();
        assert_eq!(length, 104);
        assert_eq!(MAX_COMMAND_LENGTH, 32 + MAX_COMMAND_URI);
    }

    /// Literal bytes of the counter messages.
    #[test]
    fn counter_golden_bytes() {
        let mut out = [0u8; MAX_COMMAND_LENGTH];
        let length = Command::AllocateCounter {
            sequence: 0x0102,
            type_id: 4,
            label: CounterLabel::new("ab").unwrap(),
            stream: 5,
            participant: 6,
        }
        .encode(&mut out)
        .unwrap();
        let mut expected = vec![
            0x02, 0x01, 0, 0, 0, 0, 0, 0, // sequence
            4, 0, 0, 0, 0, 0, 0, 0, // type id
            5, 0, 0, 0, 0, 0, 0, 0, // stream
            6, 0, 0, 0, 0, 0, 0, 0, // participant
            2, 0, 0, 0, 0, 0, 0, 0, // label length
            b'a', b'b', 0, 0, 0, 0, 0, 0, // label
        ];
        expected.resize(ALLOCATE_COUNTER_WORDS * 8, 0);
        assert_eq!(&out[..length], &expected[..]);
        let mut out = [0u8; MAX_COMMAND_LENGTH];
        let length = Command::ReleaseCounter {
            sequence: 1,
            cell: 2,
            registration: 3,
        }
        .encode(&mut out)
        .unwrap();
        assert_eq!(
            &out[..length],
            &[
                1, 0, 0, 0, 0, 0, 0, 0, // sequence
                2, 0, 0, 0, 0, 0, 0, 0, // cell
                3, 0, 0, 0, 0, 0, 0, 0, // registration
            ]
        );
        let response = Response::CounterAllocated {
            request: RequestId {
                client: 1,
                sequence: 2,
            },
            cell: 3,
            registration: 4,
        };
        assert_eq!(response.type_id(), 0x85);
        let mut out = [0u8; MAX_RESPONSE_LENGTH];
        assert_eq!(response.encode(&mut out), Ok(4 * 8));
    }

    #[test]
    fn counter_commands_are_decoded_strictly() {
        let mut out = [0u8; MAX_COMMAND_LENGTH];
        let command = Command::AllocateCounter {
            sequence: 1,
            type_id: 1,
            label: CounterLabel::new("abc").unwrap(),
            stream: 0,
            participant: 0,
        };
        let length = command.encode(&mut out).unwrap();
        assert_eq!(Command::decode(0x06, &out[..length]), Ok(command));
        // Wrong lengths.
        assert!(matches!(
            Command::decode(0x06, &out[..length - 8]),
            Err(CncError::WrongLength { .. })
        ));
        let mut longer = [0u8; MAX_COMMAND_LENGTH + 8];
        longer[..length].copy_from_slice(&out[..length]);
        assert!(matches!(
            Command::decode(0x06, &longer),
            Err(CncError::WrongLength { .. })
        ));
        assert!(matches!(
            Command::decode(0x07, &out[..16]),
            Err(CncError::WrongLength { .. })
        ));
        // A label length above 64, or with high bits set.
        for (byte, value) in [(32usize, 65u8), (33, 1)] {
            let mut bad = out;
            bad[byte] = value;
            assert_eq!(
                Command::decode(0x06, &bad[..length]),
                Err(CncError::Reserved { type_id: 0x06 }),
                "byte {byte} = {value}"
            );
        }
        // Nonzero padding after the label.
        let mut bad = out;
        bad[40 + 3] = b'd';
        assert_eq!(
            Command::decode(0x06, &bad[..length]),
            Err(CncError::Reserved { type_id: 0x06 })
        );
        bad[103] = 1;
        bad[40 + 3] = 0;
        assert_eq!(
            Command::decode(0x06, &bad[..length]),
            Err(CncError::Reserved { type_id: 0x06 })
        );
        // A label that is not UTF-8.
        let mut bad = out;
        bad[40] = 0xFF;
        assert_eq!(
            Command::decode(0x06, &bad[..length]),
            Err(CncError::Reserved { type_id: 0x06 })
        );
        // Only the four cutover states exist.
        let state = Response::CutoverState {
            request: RequestId {
                client: 1,
                sequence: 2,
            },
            registration: 3,
            state: CutoverState::Fenced,
        };
        let mut words = [0u8; MAX_RESPONSE_LENGTH];
        let length = state.encode(&mut words).unwrap();
        assert_eq!(Response::decode(0x87, &words[..length]), Ok(state));
        let mut bad = words;
        bad[24] = 4;
        assert_eq!(
            Response::decode(0x87, &bad[..length]),
            Err(CncError::Reserved { type_id: 0x87 })
        );
        // A response type is no command, and a counter response decodes
        // only at its exact length.
        assert!(matches!(
            Command::decode(0x85, &out[..32]),
            Err(CncError::UnknownType { .. })
        ));
        assert!(matches!(
            Response::decode(0x85, &out[..24]),
            Err(CncError::WrongLength { .. })
        ));
    }

    /// Literal bytes of `ReportLoss`.
    #[test]
    fn report_loss_golden_bytes() {
        let mut out = [0u8; MAX_COMMAND_LENGTH];
        let command = Command::ReportLoss {
            sequence: 9,
            loss: ReportedLoss {
                lane: 2,
                configured: RejoinPolicyCode::Replay,
                applied: RejoinOutcomeCode::Closed,
                fallback: Some(FallbackReasonCode::NoArchive),
                ..loss()
            },
        };
        assert_eq!(command.type_id(), 0x08);
        let length = command.encode(&mut out).unwrap();
        assert_eq!(
            &out[..length],
            &[
                9, 0, 0, 0, 0, 0, 0, 0, // sequence
                2, 1, 0, 0, 0, 0, 0, 0, // driver, high word
                4, 3, 0, 0, 0, 0, 0, 0, // driver, low word
                5, 0, 0, 0, 0, 0, 0, 0, // stream registration
                1, 0, 0, 0, 0, 0, 0, 0, // incarnation
                6, 0, 0, 0, 0, 0, 0, 0, // subscription
                0, 0x10, 0, 0, 0, 0, 0, 0, // from
                0, 0x20, 0, 0, 0, 0, 0, 0, // to
                2, 4, 4, 1, 0, 0, 0, 0, // lane, policy, outcome, reason
            ]
        );
    }

    #[test]
    fn report_loss_is_decoded_strictly() {
        let mut out = [0u8; MAX_COMMAND_LENGTH];
        let command = Command::ReportLoss {
            sequence: 1,
            loss: loss(),
        };
        let length = command.encode(&mut out).unwrap();
        assert_eq!(length, 72);
        assert_eq!(Command::decode(0x08, &out[..length]), Ok(command));
        assert!(matches!(
            Command::decode(0x08, &out[..length - 8]),
            Err(CncError::WrongLength { .. })
        ));
        assert!(matches!(
            Command::decode(0x08, &out[..length + 8]),
            Err(CncError::WrongLength { .. })
        ));
        // The packed word: byte 64 lane, 65 policy, 66 outcome, 67
        // reason, 68 to 71 reserved.
        let bad_packed = [
            (64, 4), // lane 4
            (65, 0), // no policy
            (65, 5), // unknown policy
            (66, 0), // no outcome
            (66, 6), // unknown outcome
            (66, 5), // only replay replays
            (66, 1), // snapshot cannot resume at head
            (66, 4), // snapshot cannot close without failing
            (67, 1), // a reason without replay
            (68, 1), // reserved bits
            (71, 0x80),
        ];
        for (byte, value) in bad_packed {
            let mut bad = out;
            bad[byte] = value;
            assert_eq!(
                Command::decode(0x08, &bad[..length]),
                Err(CncError::Reserved { type_id: 0x08 }),
                "byte {byte} = {value}"
            );
        }
        // Replay without a reason, and with an unknown one.
        let mut bad = out;
        bad[65] = 4;
        assert_eq!(
            Command::decode(0x08, &bad[..length]),
            Err(CncError::Reserved { type_id: 0x08 })
        );
        bad[67] = 8;
        assert_eq!(
            Command::decode(0x08, &bad[..length]),
            Err(CncError::Reserved { type_id: 0x08 })
        );
        for reason in 1..=7 {
            bad[67] = reason;
            assert!(
                Command::decode(0x08, &bad[..length]).is_ok(),
                "reason {reason}"
            );
        }
        // Replayed carries no reason.
        bad[66] = 5;
        assert_eq!(
            Command::decode(0x08, &bad[..length]),
            Err(CncError::Reserved { type_id: 0x08 })
        );
        bad[67] = 0;
        assert!(Command::decode(0x08, &bad[..length]).is_ok());
        // A range whose end is below its start.
        let mut bad = out;
        bad[48..56].copy_from_slice(&8193u64.to_le_bytes());
        assert_eq!(
            Command::decode(0x08, &bad[..length]),
            Err(CncError::Reserved { type_id: 0x08 })
        );
        // Each configured policy and the outcomes it can produce.
        let policies = [
            (RejoinPolicyCode::RejoinAtHead, 1u8),
            (RejoinPolicyCode::Snapshot, 2),
            (RejoinPolicyCode::Close, 3),
            (RejoinPolicyCode::Replay, 4),
        ];
        for (policy, code) in policies {
            assert_eq!(policy as u8, code);
            for outcome in 1..=5u8 {
                let mut case = out;
                case[65] = code;
                case[66] = outcome;
                case[67] = u8::from(policy == RejoinPolicyCode::Replay && outcome != 5);
                let expected = matches!((code, outcome), (1, 1) | (2, 2 | 3) | (3, 4) | (4, _));
                assert_eq!(
                    Command::decode(0x08, &case[..length]).is_ok(),
                    expected,
                    "policy {code} outcome {outcome}"
                );
            }
        }
    }

    #[test]
    fn events_round_trip_and_are_told_apart_from_responses() {
        let events = [
            Event::ParticipantLost {
                stream: stream(),
                registration: 7,
                client: 3,
                policy: LossPolicyCode::Continue,
                position: 4096,
            },
            Event::RequiredBoundWithdrawn {
                stream: stream(),
                registration: 7,
                position: 8192,
            },
            Event::PublicationClosed {
                stream: stream(),
                lane: Lane::try_new(2).unwrap(),
                reason: CloseReason::RequiredParticipantLost,
                image: 0,
            },
            Event::PublicationClosed {
                stream: stream(),
                lane: Lane::try_new(1).unwrap(),
                reason: CloseReason::ImageRetired,
                image: 12,
            },
            Event::SuccessorReady {
                stream: stream(),
                registration: 7,
                key: 9,
                base: 1 << 40,
                generation: 3,
            },
            Event::Fenced {
                stream: stream(),
                registration: 7,
            },
        ];
        for event in events {
            let mut out = [0u8; MAX_EVENT_LENGTH];
            let length = event.encode(&mut out).unwrap();
            assert!(Event::is_event_type(event.type_id()));
            assert_eq!(Event::decode(event.type_id(), &out[..length]), Ok(event));
            // A response decoder does not take an event.
            assert!(Response::decode(event.type_id(), &out[..length]).is_err());
        }
        for response_type in [
            PUBLICATION_READY,
            SUBSCRIPTION_READY,
            OPERATION_SUCCEEDED,
            ERROR,
            COUNTER_ALLOCATED,
            JOURNAL_READY,
            CUTOVER_STATE,
            CONFLATED_READY,
        ] {
            assert!(!Event::is_event_type(response_type));
        }
        // Unknown policy and reason codes are refused.
        let mut out = [0u8; 64];
        let length = Event::PublicationClosed {
            stream: stream(),
            lane: Lane::try_new(3).unwrap(),
            reason: CloseReason::RequiredParticipantLost,
            image: 0,
        }
        .encode(&mut out)
        .unwrap();
        assert_eq!(
            &out[8..length],
            &[
                1, 0, 0, 0, 0, 0, 0, 0, // reason: required participant lost
                3, 0, 0, 0, 0, 0, 0, 0, // lane 3
                0, 0, 0, 0, 0, 0, 0, 0, // no image
            ]
        );
        // A lane of 4 or more is refused.
        out[16] = 4;
        assert!(Event::decode(PUBLICATION_CLOSED, &out[..length]).is_err());
        out[16] = 3;
        out[8] = 9;
        assert!(Event::decode(PUBLICATION_CLOSED, &out[..length]).is_err());
    }
}

/// Decoder properties of the client commands, the responses and the driver
/// events (issue #121, the control protocol harness standing in for
/// fuzzing, #11 option B), in the style of the frame parser's. Commands
/// come from untrusted clients and every client parses the broadcast, so
/// for each direction: decoding any record type and bytes never panics;
/// every valid value round-trips within the direction's largest length;
/// decoding is canonical (whatever decodes re-encodes to the same type and
/// bytes); and a flipped byte, a changed length or another record type of
/// the direction is refused unless the result re-encodes to exactly the
/// bytes and type decoded.
/// The trace journal messages (`quantstratum-docs:
/// karyos/design/trace-journal-region.md`): literal bytes and strict
/// decoding.
#[cfg(test)]
mod journal_tests {
    use super::*;

    fn words_of(bytes: &[u8]) -> Vec<u64> {
        bytes
            .as_chunks::<8>()
            .0
            .iter()
            .map(|chunk| u64::from_le_bytes(*chunk))
            .collect()
    }

    fn bytes_of(words: &[u64]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    #[test]
    fn journal_messages_have_their_layouts() {
        let mut out = [0u8; MAX_COMMAND_LENGTH];
        let open = Command::TraceJournal {
            sequence: 3,
            capacity: 64,
            payload_words: 25,
            drop_ranges: 8,
            registration: 11,
            provenance: 2,
        };
        let length = open.encode(&mut out).unwrap();
        assert_eq!(open.type_id(), 0x09);
        assert_eq!(words_of(&out[..length]), [3, 64, 25, 8, 11, 2]);
        assert_eq!(Command::decode(0x09, &out[..length]), Ok(open.clone()));
        // The provenance is a raw word: any value round trips.
        let raw = Command::TraceJournal {
            sequence: 3,
            capacity: 64,
            payload_words: 25,
            drop_ranges: 8,
            registration: 12,
            provenance: u64::MAX,
        };
        let length = raw.encode(&mut out).unwrap();
        assert_eq!(words_of(&out[..length]), [3, 64, 25, 8, 12, u64::MAX]);
        assert_eq!(Command::decode(0x09, &out[..length]), Ok(raw));
        let length = open.encode(&mut out).unwrap();
        assert_eq!(Command::decode(0x09, &out[..length]), Ok(open));
        let close = Command::CloseJournal {
            sequence: 4,
            journal: 9,
            boundary: 4096,
        };
        let length = close.encode(&mut out).unwrap();
        assert_eq!(close.type_id(), 0x0A);
        assert_eq!(words_of(&out[..length]), [4, 9, 4096]);
        assert_eq!(Command::decode(0x0A, &out[..length]), Ok(close));
        let request = RequestId {
            client: 2,
            sequence: 3,
        };
        let ready = Response::JournalReady {
            request,
            journal: 9,
            key: 17,
        };
        let length = ready.encode(&mut out).unwrap();
        assert_eq!(ready.type_id(), 0x86);
        assert_eq!(words_of(&out[..length]), [2, 3, 9, 17]);
        assert_eq!(Response::decode(0x86, &out[..length]), Ok(ready));
        assert_eq!(ready.request(), request);
        let refused = Response::Error {
            request,
            code: ErrorCode::TraceJournalsExhausted,
            detail: 0,
        };
        let length = refused.encode(&mut out).unwrap();
        assert_eq!(words_of(&out[..length]), [2, 3, 7, 0]);
        assert_eq!(Response::decode(ERROR, &out[..length]), Ok(refused));
    }

    #[test]
    fn guard_messages_have_fixed_bytes() {
        let mut out = [0u8; MAX_COMMAND_LENGTH];
        let close = Command::GuardClose {
            sequence: 5,
            guard: 3,
            operation: 77,
            operator: 1000,
            parameters: 0xFEED,
        };
        let length = close.encode(&mut out).unwrap();
        assert_eq!(close.type_id(), 0x0D);
        assert_eq!(close.sequence(), 5);
        assert_eq!(
            &out[..length],
            &[
                5, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 77, 0, 0, 0, 0, 0, 0, 0, 0xE8, 3,
                0, 0, 0, 0, 0, 0, 0xED, 0xFE, 0, 0, 0, 0, 0, 0,
            ]
        );
        assert_eq!(Command::decode(0x0D, &out[..length]), Ok(close));
        let reopen = Command::GuardReopen {
            sequence: 6,
            guard: 3,
            expected: 1,
            operation: 78,
            operator: 1000,
            parameters: 9,
        };
        let length = reopen.encode(&mut out).unwrap();
        assert_eq!(reopen.type_id(), 0x0E);
        assert_eq!(words_of(&out[..length]), [6, 3, 1, 78, 1000, 9]);
        assert_eq!(Command::decode(0x0E, &out[..length]), Ok(reopen));
        let request = RequestId {
            client: 2,
            sequence: 6,
        };
        let state = Response::GuardState {
            request,
            guard: 3,
            state: karyos_sys::guard::GuardState {
                epoch: 2,
                open: true,
            },
        };
        let mut out = [0u8; MAX_RESPONSE_LENGTH];
        let length = state.encode(&mut out).unwrap();
        assert_eq!(state.type_id(), 0x89);
        assert_eq!(state.request(), request);
        // Epoch 2, open: the guard word (2 << 1) | 1.
        assert_eq!(words_of(&out[..length]), [2, 6, 3, 5]);
        assert_eq!(Response::decode(0x89, &out[..length]), Ok(state));
        for (code, word) in [
            (ErrorCode::UnknownGuard, 8),
            (ErrorCode::GuardNotClosedAt, 9),
            (ErrorCode::GuardExhausted, 10),
            (ErrorCode::NotAuthorized, 11),
        ] {
            let refused = Response::Error {
                request,
                code,
                detail: 7,
            };
            let length = refused.encode(&mut out).unwrap();
            assert_eq!(words_of(&out[..length]), [2, 6, word, 7]);
            assert_eq!(Response::decode(ERROR, &out[..length]), Ok(refused));
        }
        assert_eq!(ErrorCode::from_code(18), None);
    }

    /// The operator word is a uid, root's 0 included, or NO_OPERATOR; a
    /// word no uid can be is refused both ways.
    #[test]
    fn a_guard_command_carries_a_uid_or_no_operator() {
        let mut out = [0u8; MAX_COMMAND_LENGTH];
        for operator in [0, 1000, u64::from(u32::MAX), NO_OPERATOR] {
            let close = Command::GuardClose {
                sequence: 1,
                guard: 3,
                operation: 7,
                operator,
                parameters: 0,
            };
            let length = close.encode(&mut out).unwrap();
            assert_eq!(Command::decode(GUARD_CLOSE, &out[..length]), Ok(close));
        }
        for operator in [u64::from(u32::MAX) + 1, NO_OPERATOR - 1] {
            assert_eq!(
                Command::decode(GUARD_CLOSE, &bytes_of(&[1, 3, 7, operator, 0])),
                Err(CncError::Reserved {
                    type_id: GUARD_CLOSE
                }),
                "{operator}"
            );
            assert_eq!(
                Command::decode(GUARD_REOPEN, &bytes_of(&[1, 3, 1, 7, operator, 0])),
                Err(CncError::Reserved {
                    type_id: GUARD_REOPEN
                })
            );
            let close = Command::GuardClose {
                sequence: 1,
                guard: 3,
                operation: 7,
                operator,
                parameters: 0,
            };
            assert_eq!(
                close.encode(&mut out),
                Err(CncError::Reserved {
                    type_id: GUARD_CLOSE
                })
            );
        }
    }

    /// The digest is 64-bit FNV-1a over the four words, little endian,
    /// then the reason: a reference value pins it, and each input moves it.
    #[test]
    fn the_guard_parameters_digest_is_fnv_1a_over_the_request() {
        let digest = guard_parameters(3, 0, 77, 1000, b"drill");
        assert_eq!(digest, 0x9886_bd28_db8b_bca7);
        // No operator: the word as sent, NO_OPERATOR.
        assert_eq!(
            guard_parameters(3, 0, 77, NO_OPERATOR, b""),
            0x24a0_d127_84c9_2c23
        );
        for other in [
            guard_parameters(4, 0, 77, 1000, b"drill"),
            guard_parameters(3, 1, 77, 1000, b"drill"),
            guard_parameters(3, 0, 78, 1000, b"drill"),
            guard_parameters(3, 0, 77, 1001, b"drill"),
            guard_parameters(3, 0, 77, 1000, b"drilL"),
            guard_parameters(3, 0, 77, 1000, b""),
        ] {
            assert_ne!(other, digest);
            assert_ne!(other, 0);
        }
    }

    #[test]
    fn a_reopen_of_an_impossible_epoch_is_refused() {
        // Epoch 0, an open (even) epoch, and one above MAX_EPOCH.
        for expected in [0, 2, karyos_sys::guard::MAX_EPOCH + 1, u64::MAX] {
            assert_eq!(
                Command::decode(
                    GUARD_REOPEN,
                    &bytes_of(&[1, 3, expected, 7, NO_OPERATOR, 0])
                ),
                Err(CncError::Reserved {
                    type_id: GUARD_REOPEN
                }),
                "{expected}"
            );
            let mut out = [0u8; MAX_COMMAND_LENGTH];
            assert_eq!(
                Command::GuardReopen {
                    sequence: 1,
                    guard: 3,
                    expected,
                    operation: 7,
                    operator: NO_OPERATOR,
                    parameters: 0,
                }
                .encode(&mut out),
                Err(CncError::Reserved {
                    type_id: GUARD_REOPEN
                })
            );
        }
        let last = karyos_sys::guard::MAX_EPOCH;
        assert!(Command::decode(GUARD_REOPEN, &bytes_of(&[1, 3, last, 7, NO_OPERATOR, 0])).is_ok());
    }

    #[test]
    fn a_guard_state_that_breaks_the_encoding_is_refused() {
        // Epoch 0, and an open bit on an odd epoch.
        for word in [0, 1, (3 << 1) | 1] {
            assert_eq!(
                Response::decode(GUARD_STATE, &bytes_of(&[2, 6, 3, word])),
                Err(CncError::Reserved {
                    type_id: GUARD_STATE
                }),
                "{word:#x}"
            );
        }
        let broken = Response::GuardState {
            request: RequestId {
                client: 2,
                sequence: 6,
            },
            guard: 3,
            state: karyos_sys::guard::GuardState {
                epoch: 3,
                open: true,
            },
        };
        let mut out = [0u8; MAX_RESPONSE_LENGTH];
        assert_eq!(
            broken.encode(&mut out),
            Err(CncError::Reserved {
                type_id: GUARD_STATE
            })
        );
    }

    #[test]
    fn journal_commands_are_decoded_strictly() {
        // A capacity that is zero or not a power of two, no payload or no
        // drop range, registration 0 (the publisher journal of the layout
        // before T4), and journal 0.
        for words in [
            [1u64, 0, 25, 8, 3, 0],
            [1, 3, 25, 8, 3, 0],
            [1, 4, 0, 8, 3, 0],
            [1, 4, 25, 0, 5, 0],
            [1, 4, 25, 8, 0, 1],
        ] {
            assert_eq!(
                Command::decode(TRACE_JOURNAL, &bytes_of(&words)),
                Err(CncError::Reserved {
                    type_id: TRACE_JOURNAL
                }),
                "{words:?}"
            );
        }
        assert_eq!(
            Command::decode(CLOSE_JOURNAL, &bytes_of(&[1, 0, 5])),
            Err(CncError::Reserved {
                type_id: CLOSE_JOURNAL
            })
        );
        assert!(matches!(
            Command::decode(CLOSE_JOURNAL, &bytes_of(&[1, 2, 3, 4])),
            Err(CncError::WrongLength { .. })
        ));
        // The layouts before the subscription word and before the
        // provenance word (T2) are refused by length, as is a longer one.
        for words in [
            &[1u64, 4, 25, 8][..],
            &[1, 4, 25, 8, 3],
            &[1, 4, 25, 8, 3, 0, 0],
        ] {
            assert!(
                matches!(
                    Command::decode(TRACE_JOURNAL, &bytes_of(words)),
                    Err(CncError::WrongLength { .. })
                ),
                "{words:?}"
            );
        }
        assert!(matches!(
            Response::decode(JOURNAL_READY, &bytes_of(&[1, 2, 3])),
            Err(CncError::WrongLength { .. })
        ));
        // Error code 18 is not defined.
        assert_eq!(
            Response::decode(ERROR, &bytes_of(&[1, 2, 18, 0])),
            Err(CncError::Reserved { type_id: ERROR })
        );
    }
}

#[cfg(test)]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod properties {
    use core::fmt::Debug;
    use std::net::IpAddr;

    use proptest::prelude::*;

    use super::*;

    /// The codec of one direction.
    struct Codec<T> {
        decode: fn(u32, &[u8]) -> Result<T, CncError>,
        encode: fn(&T, &mut [u8]) -> Result<usize, CncError>,
        type_id: fn(&T) -> u32,
        max: usize,
        types: &'static [u32],
    }

    const COMMANDS: Codec<Command> = Codec {
        decode: Command::decode,
        encode: Command::encode,
        type_id: Command::type_id,
        max: MAX_COMMAND_LENGTH,
        types: &[
            ADD_PUBLICATION,
            ADD_SUBSCRIPTION,
            REMOVE_PUBLICATION,
            REMOVE_SUBSCRIPTION,
            ADD_CONCURRENT_PUBLICATION,
            ALLOCATE_COUNTER,
            RELEASE_COUNTER,
            REPORT_LOSS,
            TRACE_JOURNAL,
            CLOSE_JOURNAL,
            QUERY_CUTOVER,
            ADD_CONFLATED_SUBSCRIPTION,
            GUARD_CLOSE,
            GUARD_REOPEN,
            ADD_NETWORK_PUBLICATION,
            ADD_NETWORK_SUBSCRIPTION,
            ADD_IMAGE_SUBSCRIPTION,
        ],
    };

    const RESPONSES: Codec<Response> = Codec {
        decode: Response::decode,
        encode: Response::encode,
        type_id: Response::type_id,
        max: MAX_RESPONSE_LENGTH,
        types: &[
            PUBLICATION_READY,
            SUBSCRIPTION_READY,
            OPERATION_SUCCEEDED,
            ERROR,
            COUNTER_ALLOCATED,
            JOURNAL_READY,
            CUTOVER_STATE,
            CONFLATED_READY,
            GUARD_STATE,
            NETWORK_SUBSCRIPTION_READY,
        ],
    };

    const EVENTS: Codec<Event> = Codec {
        decode: Event::decode,
        encode: Event::encode,
        type_id: Event::type_id,
        max: MAX_EVENT_LENGTH,
        types: &[
            PARTICIPANT_LOST,
            REQUIRED_BOUND_WITHDRAWN,
            PUBLICATION_CLOSED,
            SUCCESSOR_READY,
            FENCED,
            IMAGE_AVAILABLE,
            IMAGE_UNAVAILABLE,
        ],
    };

    impl<T: PartialEq + Debug> Codec<T> {
        fn encoded(&self, value: &T) -> Vec<u8> {
            let mut out = vec![0u8; self.max];
            let length = (self.encode)(value, &mut out).unwrap();
            out.truncate(length);
            out
        }

        /// Canonicality: a decoded value has the record type it was
        /// decoded from, and re-encodes to exactly the bytes.
        fn check_decoded(&self, type_id: u32, bytes: &[u8]) -> Result<bool, TestCaseError> {
            match (self.decode)(type_id, bytes) {
                Ok(value) => {
                    prop_assert_eq!((self.type_id)(&value), type_id);
                    prop_assert!(bytes.len() <= self.max);
                    prop_assert_eq!(&self.encoded(&value)[..], bytes);
                    Ok(true)
                }
                Err(CncError::UnknownType { type_id: found }) => {
                    prop_assert_eq!(found, type_id);
                    prop_assert!(!self.types.contains(&type_id));
                    Ok(false)
                }
                Err(CncError::WrongLength {
                    type_id: found,
                    length,
                    expected,
                }) => {
                    prop_assert_eq!(found, type_id);
                    prop_assert_eq!(length, bytes.len());
                    prop_assert_ne!(length, expected);
                    prop_assert!(expected <= self.max);
                    Ok(false)
                }
                Err(CncError::Reserved { type_id: found }) => {
                    prop_assert_eq!(found, type_id);
                    Ok(false)
                }
                Err(error) => {
                    prop_assert!(false, "decoding returned {error:?}");
                    Ok(false)
                }
            }
        }

        /// Round trip: `value` encodes within the largest length, into no
        /// shorter buffer, and decodes to itself; every single byte flip,
        /// length change or other record type of the direction is refused
        /// or yields a value that re-encodes to the changed input.
        fn check_value(
            &self,
            value: &T,
            flip: prop::sample::Index,
            mask: u8,
            cut: prop::sample::Index,
            other: prop::sample::Index,
        ) -> Result<(), TestCaseError> {
            let bytes = self.encoded(value);
            let type_id = (self.type_id)(value);
            prop_assert!(bytes.len() <= self.max);
            prop_assert!(bytes.len().is_multiple_of(8));
            prop_assert!(self.types.contains(&type_id));
            prop_assert_eq!(&(self.decode)(type_id, &bytes).unwrap(), value);
            let mut short = vec![0u8; bytes.len() - 1];
            prop_assert_eq!(
                (self.encode)(value, &mut short),
                Err(CncError::BufferTooShort {
                    required: bytes.len(),
                    available: bytes.len() - 1,
                })
            );

            let mut flipped = bytes.clone();
            flipped[flip.index(bytes.len())] ^= mask;
            self.check_decoded(type_id, &flipped)?;

            // Every layout has a fixed length: a prefix or an extension is
            // refused.
            let prefix = &bytes[..cut.index(bytes.len())];
            prop_assert!(!self.check_decoded(type_id, prefix)?);
            let mut longer = bytes.clone();
            longer.resize(bytes.len() + 1 + cut.index(16), 0);
            prop_assert!(!self.check_decoded(type_id, &longer)?);

            let other = self.types[other.index(self.types.len())];
            self.check_decoded(other, &bytes)?;
            Ok(())
        }
    }

    /// A record type: one of `types`, a neighbour of one, or anything.
    fn type_id(types: &'static [u32]) -> impl Strategy<Value = u32> {
        prop_oneof![
            4 => prop::sample::select(types),
            1 => prop::sample::select(types).prop_map(|type_id| type_id ^ 0x40),
            1 => 0u32..=0x100,
            1 => any::<u32>(),
        ]
    }

    /// A word biased to the small values the layouts give meaning to.
    fn word() -> impl Strategy<Value = u64> {
        prop_oneof![
            2 => 0u64..=8,
            1 => (0u64..4, 1u64..=4, 1u64..=4, 0u64..=3).prop_map(|(lane, policy, outcome, reason)| {
                lane | policy << 8 | outcome << 16 | reason << 24
            }),
            2 => any::<u64>(),
            1 => any::<u32>().prop_map(u64::from),
        ]
    }

    fn to_bytes(words: Vec<u64>) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    /// A record type and bytes: any type with arbitrary bytes of any length
    /// up to a word past the largest, or with biased words of any count; or
    /// a type of `layouts` with biased words of its layout's count.
    fn input(
        types: &'static [u32],
        max: usize,
        layouts: &'static [(u32, usize)],
    ) -> impl Strategy<Value = (u32, Vec<u8>)> {
        prop_oneof![
            1 => (type_id(types), prop::collection::vec(any::<u8>(), 0..=max + 8)),
            1 => (type_id(types), prop::collection::vec(word(), 0..=max / 8 + 1).prop_map(to_bytes)),
            3 => prop::sample::select(layouts).prop_flat_map(|(type_id, count)| {
                (Just(type_id), prop::collection::vec(word(), count).prop_map(to_bytes))
            }),
        ]
    }

    fn stream() -> impl Strategy<Value = StreamKey> {
        (any::<i32>(), any::<i32>()).prop_map(|(stream_id, session_id)| StreamKey {
            stream_id,
            session_id,
        })
    }

    /// A bound address: none, IPv4, or IPv6 with any scope id (flow
    /// information is not carried, so it stays zero).
    fn bound() -> impl Strategy<Value = Option<SocketAddr>> {
        prop_oneof![
            Just(None),
            (any::<u32>(), any::<u16>())
                .prop_map(|(ip, port)| Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))),
            (any::<u128>(), any::<u16>(), any::<u32>()).prop_map(|(ip, port, scope)| Some(
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, scope))
            )),
        ]
    }

    /// A source address as `ImageAvailable` carries it: IPv4, or IPv6
    /// with any scope id (flow information is not carried, so it stays
    /// zero).
    fn source() -> impl Strategy<Value = SocketAddr> {
        prop_oneof![
            (any::<u32>(), any::<u16>())
                .prop_map(|(ip, port)| SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)),
            (any::<u128>(), any::<u16>(), any::<u32>()).prop_map(|(ip, port, scope)| {
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, scope))
            }),
        ]
    }

    fn request() -> impl Strategy<Value = RequestId> {
        (any::<u64>(), any::<u64>()).prop_map(|(client, sequence)| RequestId { client, sequence })
    }

    /// A label of at most [`MAX_LABEL_LENGTH`] bytes of any characters,
    /// NUL included.
    fn label() -> impl Strategy<Value = CounterLabel> {
        prop::collection::vec(any::<char>(), 0..=MAX_LABEL_LENGTH).prop_map(|chars| {
            let mut text = String::new();
            for c in chars {
                if text.len() + c.len_utf8() <= MAX_LABEL_LENGTH {
                    text.push(c);
                }
            }
            CounterLabel::new(&text).unwrap()
        })
    }

    fn loss() -> impl Strategy<Value = ReportedLoss> {
        use FallbackReasonCode::{
            MergeFailed, NoArchive, NoRecording, RecordingBehind, Refused, RetentionShort,
            Withdrawn,
        };
        use RejoinOutcomeCode::{Closed, Replayed, ResumedAtHead, SnapshotFailed, SnapshotRebuilt};
        use RejoinPolicyCode::{Close, RejoinAtHead, Replay, Snapshot};
        (
            any::<[u64; 5]>(),
            0..karyos_sys::frame::Lane::COUNT,
            any::<(u64, u64)>(),
            prop::sample::select(&[RejoinAtHead, Snapshot, Close, Replay][..]),
            any::<prop::sample::Index>(),
            prop::sample::select(
                &[
                    NoArchive,
                    NoRecording,
                    RetentionShort,
                    RecordingBehind,
                    Refused,
                    MergeFailed,
                    Withdrawn,
                ][..],
            ),
        )
            .prop_map(
                |(
                    [high, low, stream_registration, incarnation, subscription],
                    lane,
                    (a, b),
                    configured,
                    outcome,
                    reason,
                )| {
                    let outcomes: &[RejoinOutcomeCode] = match configured {
                        RejoinAtHead => &[ResumedAtHead],
                        Snapshot => &[SnapshotRebuilt, SnapshotFailed],
                        Close => &[Closed],
                        Replay => &[
                            ResumedAtHead,
                            SnapshotRebuilt,
                            SnapshotFailed,
                            Closed,
                            Replayed,
                        ],
                    };
                    let applied = *outcome.get(outcomes);
                    ReportedLoss {
                        driver: [high, low],
                        stream_registration,
                        incarnation,
                        subscription,
                        lane,
                        from: a.min(b),
                        to: a.max(b),
                        configured,
                        applied,
                        fallback: (configured == Replay && applied != Replayed).then_some(reason),
                    }
                },
            )
    }

    fn lane() -> impl Strategy<Value = Lane> {
        (0..Lane::COUNT).prop_map(|lane| Lane::try_new(lane).unwrap())
    }

    fn command() -> impl Strategy<Value = Command> {
        let role = prop::sample::select(
            &[
                SubscriberRole::Required,
                SubscriberRole::Optional,
                SubscriberRole::Observer,
            ][..],
        );
        prop_oneof![
            (any::<u64>(), stream(), lane(), any::<bool>()).prop_map(
                |(sequence, stream, lane, allow_unconnected)| Command::AddPublication {
                    sequence,
                    stream,
                    lane,
                    allow_unconnected,
                }
            ),
            (any::<u64>(), stream(), lane(), any::<bool>()).prop_map(
                |(sequence, stream, lane, allow_unconnected)| {
                    Command::AddConcurrentPublication {
                        sequence,
                        stream,
                        lane,
                        allow_unconnected,
                    }
                }
            ),
            (any::<u64>(), stream(), lane(), role.clone()).prop_map(
                |(sequence, stream, lane, role)| {
                    Command::AddSubscription {
                        sequence,
                        stream,
                        lane,
                        role,
                    }
                }
            ),
            any::<(u64, u64)>().prop_map(|(sequence, registration)| {
                Command::RemovePublication {
                    sequence,
                    registration,
                }
            }),
            any::<(u64, u64)>().prop_map(|(sequence, registration)| {
                Command::RemoveSubscription {
                    sequence,
                    registration,
                }
            }),
            (
                any::<u64>(),
                any::<i32>(),
                any::<(bool, bool)>(),
                "[ -~]{1,512}"
            )
                .prop_map(
                    |(sequence, stream_id, (allow_unconnected, concurrent), uri)| {
                        Command::AddNetworkPublication {
                            sequence,
                            stream_id,
                            allow_unconnected,
                            concurrent,
                            uri: ChannelUri::new(&uri).unwrap(),
                        }
                    }
                ),
            (any::<u64>(), 1..=u64::MAX, lane(), role.clone()).prop_map(
                |(sequence, image, lane, role)| Command::AddImageSubscription {
                    sequence,
                    image,
                    lane,
                    role,
                }
            ),
            (any::<u64>(), any::<i32>(), role, "\\PC{1,100}").prop_map(
                |(sequence, stream_id, role, uri)| Command::AddNetworkSubscription {
                    sequence,
                    stream_id,
                    role,
                    uri: ChannelUri::new(&uri).unwrap(),
                }
            ),
            (any::<[u64; 4]>(), label()).prop_map(
                |([sequence, type_id, stream, participant], label)| Command::AllocateCounter {
                    sequence,
                    type_id,
                    label,
                    stream,
                    participant,
                }
            ),
            any::<[u64; 3]>().prop_map(|[sequence, cell, registration]| {
                Command::ReleaseCounter {
                    sequence,
                    cell,
                    registration,
                }
            }),
            (any::<u64>(), loss())
                .prop_map(|(sequence, loss)| Command::ReportLoss { sequence, loss }),
            (
                any::<u64>(),
                0u32..64,
                1..=u64::MAX,
                1..=u64::MAX,
                1..=u64::MAX,
                any::<u64>(),
            )
                .prop_map(
                    |(sequence, shift, payload_words, drop_ranges, registration, provenance)| {
                        Command::TraceJournal {
                            sequence,
                            capacity: 1 << shift,
                            payload_words,
                            drop_ranges,
                            registration,
                            provenance,
                        }
                    }
                ),
            (any::<u64>(), 1..=u64::MAX, any::<u64>()).prop_map(|(sequence, journal, boundary)| {
                Command::CloseJournal {
                    sequence,
                    journal,
                    boundary,
                }
            }),
            any::<(u64, u64)>().prop_map(|(sequence, registration)| Command::QueryCutover {
                sequence,
                registration,
            }),
            (any::<u64>(), stream()).prop_map(|(sequence, stream)| {
                Command::AddConflatedSubscription { sequence, stream }
            }),
            (
                any::<(u64, u64, u64, u64)>(),
                prop_oneof![Just(NO_OPERATOR), (0..=u64::from(u32::MAX))]
            )
                .prop_map(|((sequence, guard, operation, parameters), operator)| {
                    Command::GuardClose {
                        sequence,
                        guard,
                        operation,
                        operator,
                        parameters,
                    }
                }),
            (
                any::<(u64, u64, u64, u64)>(),
                prop_oneof![Just(NO_OPERATOR), (0..=u64::from(u32::MAX))],
                0..=(karyos_sys::guard::MAX_EPOCH >> 1)
            )
                .prop_map(
                    |((sequence, guard, operation, parameters), operator, half)| {
                        Command::GuardReopen {
                            sequence,
                            guard,
                            expected: half * 2 + 1,
                            operation,
                            operator,
                            parameters,
                        }
                    }
                ),
        ]
    }

    fn response() -> impl Strategy<Value = Response> {
        let code = prop::sample::select(
            &[
                ErrorCode::PublicationTaken,
                ErrorCode::UnknownStream,
                ErrorCode::UnknownRegistration,
                ErrorCode::ResourcesUnavailable,
                ErrorCode::IdentitiesExhausted,
                ErrorCode::InvalidPublicationMode,
                ErrorCode::TraceJournalsExhausted,
                ErrorCode::UnknownGuard,
                ErrorCode::GuardNotClosedAt,
                ErrorCode::GuardExhausted,
                ErrorCode::NotAuthorized,
                ErrorCode::InvalidChannel,
                ErrorCode::UnsupportedChannel,
                ErrorCode::ReliabilityMismatch,
                ErrorCode::ReceiverIdentityMismatch,
                ErrorCode::LaneMismatch,
            ][..],
        );
        prop_oneof![
            (request(), any::<(u64, u64)>()).prop_map(|(request, (registration, key))| {
                Response::PublicationReady {
                    request,
                    registration,
                    key,
                }
            }),
            (request(), any::<(u64, u64)>()).prop_map(|(request, (registration, key))| {
                Response::SubscriptionReady {
                    request,
                    registration,
                    key,
                }
            }),
            request().prop_map(|request| Response::OperationSucceeded { request }),
            (request(), code, any::<u64>()).prop_map(|(request, code, detail)| {
                Response::Error {
                    request,
                    code,
                    detail,
                }
            }),
            (request(), any::<(u64, u64)>()).prop_map(|(request, (cell, registration))| {
                Response::CounterAllocated {
                    request,
                    cell,
                    registration,
                }
            }),
            (request(), any::<(u64, u64)>()).prop_map(|(request, (journal, key))| {
                Response::JournalReady {
                    request,
                    journal,
                    key,
                }
            }),
            (request(), any::<u64>(), cutover_state()).prop_map(
                |(request, registration, state)| Response::CutoverState {
                    request,
                    registration,
                    state,
                }
            ),
            (request(), any::<(u64, u64, u32, u64, u64)>()).prop_map(
                |(request, (registration, key, keys, value_capacity, journal_capacity))| {
                    Response::ConflatedReady {
                        request,
                        registration,
                        key,
                        keys,
                        value_capacity,
                        journal_capacity,
                    }
                }
            ),
            (request(), any::<u64>(), 1..=karyos_sys::guard::MAX_EPOCH).prop_map(
                |(request, guard, epoch)| Response::GuardState {
                    request,
                    guard,
                    state: karyos_sys::guard::GuardState {
                        epoch,
                        open: epoch.is_multiple_of(2),
                    },
                }
            ),
            (request(), any::<u64>(), bound()).prop_map(|(request, registration, bound)| {
                Response::NetworkSubscriptionReady {
                    request,
                    registration,
                    bound,
                }
            }),
        ]
    }

    fn cutover_state() -> impl Strategy<Value = CutoverState> {
        prop::sample::select(
            &[
                CutoverState::Current,
                CutoverState::Successor,
                CutoverState::Fenced,
                CutoverState::Closed,
            ][..],
        )
    }

    fn event() -> impl Strategy<Value = Event> {
        let policy = prop::sample::select(
            &[
                LossPolicyCode::Hold,
                LossPolicyCode::Continue,
                LossPolicyCode::Abort,
            ][..],
        );
        prop_oneof![
            (stream(), any::<[u64; 3]>(), policy).prop_map(
                |(stream, [registration, client, position], policy)| Event::ParticipantLost {
                    stream,
                    registration,
                    client,
                    policy,
                    position,
                }
            ),
            (stream(), any::<(u64, u64)>()).prop_map(|(stream, (registration, position))| {
                Event::RequiredBoundWithdrawn {
                    stream,
                    registration,
                    position,
                }
            }),
            (stream(), lane(), any::<u64>()).prop_map(|(stream, lane, image)| {
                Event::PublicationClosed {
                    stream,
                    lane,
                    reason: CloseReason::RequiredParticipantLost,
                    image,
                }
            }),
            (stream(), any::<[u64; 4]>()).prop_map(
                |(stream, [registration, key, base, generation])| Event::SuccessorReady {
                    stream,
                    registration,
                    key,
                    base,
                    generation,
                }
            ),
            (stream(), any::<u64>()).prop_map(|(stream, registration)| Event::Fenced {
                stream,
                registration,
            }),
            (stream(), any::<u64>(), 1..=u64::MAX, source()).prop_map(
                |(stream, registration, image, source)| Event::ImageAvailable {
                    stream,
                    registration,
                    image,
                    source,
                }
            ),
            (stream(), any::<u64>(), 1..=u64::MAX).prop_map(|(stream, registration, image)| {
                Event::ImageUnavailable {
                    stream,
                    registration,
                    image,
                }
            }),
        ]
    }

    proptest! {
        #[test]
        fn any_command_input_is_refused_or_canonical(
            (type_id, bytes) in input(
                COMMANDS.types,
                MAX_COMMAND_LENGTH,
                &[
                    (ADD_PUBLICATION, 4),
                    (ADD_SUBSCRIPTION, 4),
                    (REMOVE_PUBLICATION, 2),
                    (REMOVE_SUBSCRIPTION, 2),
                    (ADD_CONCURRENT_PUBLICATION, 4),
                    (ALLOCATE_COUNTER, ALLOCATE_COUNTER_WORDS),
                    (RELEASE_COUNTER, 3),
                    (REPORT_LOSS, REPORT_LOSS_WORDS),
                    (TRACE_JOURNAL, 6),
                    (CLOSE_JOURNAL, 3),
                    (QUERY_CUTOVER, 2),
                    (ADD_CONFLATED_SUBSCRIPTION, 2),
                    (GUARD_CLOSE, 5),
                    (GUARD_REOPEN, 6),
                    (ADD_IMAGE_SUBSCRIPTION, 4),
                ],
            ),
        ) {
            COMMANDS.check_decoded(type_id, &bytes)?;
        }

        #[test]
        fn any_response_input_is_refused_or_canonical(
            (type_id, bytes) in input(
                RESPONSES.types,
                MAX_RESPONSE_LENGTH,
                &[
                    (PUBLICATION_READY, 4),
                    (SUBSCRIPTION_READY, 4),
                    (OPERATION_SUCCEEDED, 2),
                    (ERROR, 4),
                    (COUNTER_ALLOCATED, 4),
                    (JOURNAL_READY, 4),
                    (CUTOVER_STATE, 4),
                    (CONFLATED_READY, CONFLATED_READY_WORDS),
                    (GUARD_STATE, 4),
                ],
            ),
        ) {
            RESPONSES.check_decoded(type_id, &bytes)?;
        }

        #[test]
        fn any_event_input_is_refused_or_canonical(
            (type_id, bytes) in input(
                EVENTS.types,
                MAX_EVENT_LENGTH,
                &[
                    (PARTICIPANT_LOST, 5),
                    (REQUIRED_BOUND_WITHDRAWN, 3),
                    (PUBLICATION_CLOSED, 4),
                    (SUCCESSOR_READY, 5),
                    (FENCED, 2),
                    (IMAGE_AVAILABLE, IMAGE_AVAILABLE_WORDS),
                    (IMAGE_UNAVAILABLE, 3),
                ],
            ),
        ) {
            EVENTS.check_decoded(type_id, &bytes)?;
        }

        #[test]
        fn commands_round_trip_and_resist_mutation(
            command in command(),
            flip in any::<prop::sample::Index>(),
            mask in 1u8..=255,
            cut in any::<prop::sample::Index>(),
            other in any::<prop::sample::Index>(),
        ) {
            COMMANDS.check_value(&command, flip, mask, cut, other)?;
        }

        #[test]
        fn responses_round_trip_and_resist_mutation(
            response in response(),
            flip in any::<prop::sample::Index>(),
            mask in 1u8..=255,
            cut in any::<prop::sample::Index>(),
            other in any::<prop::sample::Index>(),
        ) {
            RESPONSES.check_value(&response, flip, mask, cut, other)?;
        }

        #[test]
        fn events_round_trip_and_resist_mutation(
            event in event(),
            flip in any::<prop::sample::Index>(),
            mask in 1u8..=255,
            cut in any::<prop::sample::Index>(),
            other in any::<prop::sample::Index>(),
        ) {
            EVENTS.check_value(&event, flip, mask, cut, other)?;
        }
    }
}
