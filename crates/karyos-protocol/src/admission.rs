// SPDX-License-Identifier: Apache-2.0

//! Messages of the admission socket (`quantstratum-docs: karyos/design/ipc-admission.md`), the
//! control-path bootstrap through which a client process receives its
//! shared-memory regions from the driver.
//!
//! One message per `SOCK_SEQPACKET` datagram, a fixed little-endian layout
//! of 64-bit words; word 0 holds the message type. Decoding is strict: the
//! length must match the type (or, for a manifest, its record count),
//! reserved bits and values are rejected, and a manifest holds at most
//! [`MAX_RECORDS`] records. Descriptors travel beside the bytes (`Hello`
//! carries the client's pidfd, `Region` the region); this module only
//! encodes the words.
//!
//! Layouts (words):
//!
//! | Type | Message | Words after the type |
//! | --- | --- | --- |
//! | `0x01` | `Hello` | version; flags (bit 0 first profile accepted, bit 1 no fork while holding anything; both required) |
//! | `0x02` | `Fetch` | fetch id (nonzero); hand-over key |
//! | `0x03` | `Detach` | export id (nonzero) |
//! | `0x04` | `Leave` | none |
//! | `0x05` | `ToolHello` | version |
//! | `0x06` | `ProbeHello` | version |
//! | `0x81` | `Admitted` | instance (low, high); protocol version; client id; record count; records |
//! | `0x82` | `Manifest` | fetch id; hand-over key; registration; stream registration; incarnation; base; record count; records |
//! | `0x83` | `Region` | fetch id; record index |
//! | `0x84` | `Refused` | word 1 by code (below); code (nonzero) |
//! | `0x85` | `ToolAdmitted` | instance (low, high); protocol version; record count; records (capability none) |
//! | `0x86` | `ProbeState` | state ([`probe`]); reason ([`probe`]); nanoseconds since the driver started |
//!
//! **Probes** (R-CORE-35). A readiness probe sends `ProbeHello`, without a
//! descriptor; the driver answers one `ProbeState`, or `Refused`, and
//! closes the connection. A probe gets no client id, slot, capability or
//! region, so it maps no shared memory. Both are new types in version 3,
//! added while that version is still open before its first release; a
//! driver that does not know `ProbeHello` closes the connection without an
//! answer, and one of another version answers `INCOMPATIBLE_VERSION`.
//!
//! **Tools** (`quantstratum-docs: karyos/design/observability-and-tools.md`,
//! Tool attach). A tool sends `ToolHello` instead of `Hello`, without a
//! descriptor; the driver answers `ToolAdmitted` with the records of its
//! six diagnostic regions (driver counters, client counters, error log,
//! loss report, trace mirror, guard audit), then one `Region` with fetch id 0 per
//! record, each with a read-only descriptor, or `Refused`. A tool gets no client id, command
//! ring or capability: every record of `ToolAdmitted` carries capability
//! none, and decoding refuses any other. The first two words of
//! `ToolHello` (type, version) are fixed for every version, as `Hello`'s,
//! and [`tool_hello_version`] reads them. Both messages are new types, so
//! adding them changed no existing layout; the two region kinds they need
//! (error log 6, loss report 7) are new record values that an older
//! decoder refuses. The trace mirror (`quantstratum-docs:
//! karyos/design/trace-journal-region.md`) made the set five records, with
//! [`VERSION`] 2 (see "Layout changes within a version").
//!
//! **Journals** (`quantstratum-docs: karyos/design/trace-journal-region.md`,
//! J2). A trace journal grant is fetched as a log buffer grant: one
//! `Manifest` with one `Journal` record, then its `Region`. A journal
//! belongs to no stream, so a manifest whose records are journals carries
//! the journal number as its registration and zero stream registration,
//! incarnation and base; every other manifest carries a nonzero stream
//! registration and incarnation, and a manifest
//! never mixes journal records with others. The `Journal` kind (8) is new,
//! so an older decoder refuses such a manifest.
//!
//! **Versions.** The client announces its protocol version in `Hello`;
//! the driver answers `Admitted` carrying the version it runs (equal to the
//! client's), or `Refused` with [`refusal::INCOMPATIBLE_VERSION`]. The
//! first two words of `Hello` (type, version) and the whole `Refused`
//! layout are fixed for every version, so a driver can read the version of
//! any `Hello` with [`hello_version`] and refuse it in a form every client
//! can decode.
//!
//! **Word 1 of `Refused`, by code** (karyos#879, decided 2026-10-29 by
//! QS-COORDINATOR under owner delegation). For
//! [`refusal::INCOMPATIBLE_VERSION`], the answer to a `Hello`,
//! `ToolHello` or `ProbeHello`, it is the refuser's protocol version, or 0
//! when the refuser does not state it (0.1.0-alpha.2 and earlier); read it
//! with [`Message::refuser_version`], built with
//! [`Message::incompatible_version`]. For every other code it is the
//! fetch id refused, or 0 for a refusal of the bootstrap or a hello. The
//! layout and its length are unchanged, so every decoder of every
//! version reads the refusal as before; one that ignores word 1 (every
//! client of 0.1.0-alpha.2) still classifies it as an incompatible
//! version. A new code states its word 1 here.
//!
//! **Layout changes within a version.** Before the first release, a layout
//! change keeps [`VERSION`] and changes encoder and decoder together, as the
//! client counters record of the bootstrap and the observer capability did;
//! strict decoding makes a peer of another build fail at its first changed
//! message. That holds only because every decoder demands an exact length
//! and the old and new layouts of the changed message can never have the
//! same length for any record count; a change that keeps some length equal
//! (for example one that adds exactly one record's words) must bump
//! [`VERSION`] instead (review of #124). The stream registration and
//! incarnation words of `Manifest` follow that rule (coordinator decision,
//! ACS 13555: they carry the publication identity of the grant, whose
//! driver part is the instance of `Admitted`), and so does its base word
//! (G-d2c, ACS 15268): one word more makes every manifest length `8 + 8n`
//! words against `7 + 8n` before, never equal.
//!
//! **The in-place window closes at a version's first publication**
//! (`quantstratum-docs: owner-decisions/2026-10-21/decisions.md:64` to
//! `:69`, item 4: "Later incompatible format changes require a new
//! version"). Alpha.1 published version 1 and alpha.2 version 2, so both
//! are closed: their released contracts are kept, and an incompatible
//! change needs a new version. Version 3 (karyos#637: new CnC command
//! types for a publication's receiver roles and a subscription's receiver
//! identity) stays open in place until its first publication; the later
//! parts of karyos#637 (the conflated network subscription and the network
//! admission state) enter it too. A client and a driver of different
//! versions, 2 and 3 in either direction, are refused at admission with
//! [`refusal::INCOMPATIBLE_VERSION`] (decided 2026-10-27 by QS-COORDINATOR
//! under owner delegation).
//!
//! **Base.** A manifest's base is the stream position at which the grant's
//! log buffer starts: zero for a stream's first incarnation, the seal
//! position of its predecessor for a later one (`quantstratum-docs:
//! karyos/design/guards-and-abort.md`, Fresh incarnation, On the
//! network). A remote client maps the buffer at that base, so the
//! positions it reports (a loss report, a trace) are absolute stream
//! positions. A position stays below 2^63, so a base with the top bit set
//! is refused; a manifest of other regions (a conflation table, a journal)
//! carries base 0.
//!
//! **Version 2** (coordinator decision, ACS 13677). The trace journal
//! region adds the `Journal` and `TraceMirror` kinds and a fifth
//! `ToolAdmitted` record. `ToolAdmitted` with five records has the length
//! an older `ToolAdmitted` would have with five, so the length rule above
//! does not cover the change: a peer of another build would fail only
//! because its decoder refuses an unknown kind, at whichever message first
//! carries one, with a protocol error rather than a version refusal. The
//! bump to 2 makes a mixed build fail at `Hello` or `ToolHello` with a
//! clean `IncompatibleVersion`; the unknown kind refusal stays as the
//! second line of defence.
//! Still before the first release, version 2 also gains the
//! `ConflationTable` kind (code 10 on both sides) for read-only conflated
//! views (`quantstratum-docs: karyos/design/conflation-end-to-end.md`),
//! under the rule of quantstratum/karyos#112: an addition to the
//! unreleased version, which an older build of it refuses as an unknown
//! kind. Under the same rule it gains the `GuardAudit` kind (code 11 on
//! both sides, `quantstratum-docs:
//! karyos/design/management-agent-gap-analysis.md`, M4) and a sixth
//! `ToolAdmitted` record, and the guard binding's kinds `GuardRegion`,
//! `OutcomeRing` and `ConsumedCell` (codes 12 to 14 on both sides,
//! `quantstratum-docs: karyos/design/guards-and-abort.md`, "The binding
//! across processes", G-x1). A guarded exclusive publication's grant
//! (G-x2) carries them after its log buffer record, exactly
//! `OutcomeRing`, `ConsumedCell`, `GuardRegion` in that order, each with
//! capability none, lane 0 and the log buffer's ids, and its manifest
//! carries a base like a log buffer's; the binding's kinds appear in no
//! other manifest. This is an in-place change of the manifest rule under
//! the unreleased version 2, as owner item 54 allowed for the guard
//! commands.
//!
//! **Instance.** The instance of `Admitted` is the driver's 128-bit
//! `driver_id` (SPEC.md §4), the one id per driver instance (ACS 13555).
//! The `driver_id` is held as two words `[high, low]`; the instance is
//! `u128::from(high) << 64 | u128::from(low)`, the packing of a loss
//! record's instance, and travels low word first.
//!
//! A record is eight words: region id; export id; kind (bits 0..8) and
//! layout version (bits 8..40); structure length; generation; stream id
//! (low 32) and session id (high 32); lane (bits 0..8), capability
//! (bits 8..16: 0 none, 1 required subscriber, 2 optional subscriber, 3
//! exclusive publication, 4 concurrent publication, 5 observer subscriber)
//! and, in bit 16, whether the stream allows offers with no subscriber
//! attached (SPEC.md §4 `allow_unconnected`; set only with capability 3 or
//! 4, reserved otherwise, as bits 17..64 are; quantstratum-docs:
//! karyos/design/ipc-admission.md, Unconnected offers); the cell or
//! publisher slot the capability names (0 when none).

use thiserror::Error;

/// The protocol version a client announces in `Hello`: 3 since
/// karyos#637 added `AddNetworkPublicationWithRoles` and
/// `AddNetworkSubscriptionAs` (`cnc`), after alpha.2 published version 2.
pub const VERSION: u64 = 3;
/// Most records in one manifest.
pub const MAX_RECORDS: usize = 16;
/// The bit of a record's word 6 that says its stream allows offers with
/// no subscriber attached.
const UNCONNECTED_BIT: u32 = 16;
/// Words of one record.
pub const RECORD_WORDS: usize = 8;
/// Largest encoded message, in bytes: `Manifest` with [`MAX_RECORDS`]
/// (eight words before its records; `Admitted` has six).
pub const MAX_MESSAGE_LENGTH: usize = (8 + MAX_RECORDS * RECORD_WORDS) * 8;

/// Refusal codes of `Refused` (nonzero). A client treats a code it does not
/// know as a refusal without a reason.
pub mod refusal {
    /// The driver does not run the protocol version of the `Hello`.
    pub const INCOMPATIBLE_VERSION: u64 = 1;
    /// The `Hello` breaks the first profile: flags, uid, or its pidfd.
    pub const PROFILE: u64 = 2;
    /// A limit is reached: clients, pending hellos, fetches or exports.
    pub const LIMIT: u64 = 3;
    /// The driver failed to create or describe a region.
    pub const RESOURCES: u64 = 4;
    /// The fetch names no hand-over entry held for this client.
    pub const UNKNOWN_KEY: u64 = 5;
    /// The driver is shutting down and admits no new client; retrying
    /// against this instance cannot succeed.
    pub const SHUTTING_DOWN: u64 = 6;
}

/// The protocol version of a `Hello` datagram of any version: its type and
/// version words are fixed. `None` when the datagram is not a `Hello`.
#[must_use]
pub fn hello_version(bytes: &[u8]) -> Option<u64> {
    version_of(HELLO, bytes)
}

/// The protocol version of a `ProbeHello` datagram of any version: its
/// type and version words are fixed. `None` when the datagram is not a
/// `ProbeHello`.
#[must_use]
pub fn probe_hello_version(bytes: &[u8]) -> Option<u64> {
    version_of(PROBE_HELLO, bytes)
}

/// The states and reasons of `ProbeState` (R-CORE-35).
pub mod probe {
    /// The driver has not declared its startup complete, within its
    /// startup deadline.
    pub const STARTING: u64 = 1;
    /// A client `Hello` now would be admitted, into no cutover.
    pub const READY: u64 = 2;
    /// Admitting, but a stream still retains predecessor mappings after a
    /// cutover.
    pub const RECOVERING: u64 = 3;
    /// Not admitting a client now; the reason says why.
    pub const NOT_READY: u64 = 4;
    /// Startup failed; the reason says why. It does not end.
    pub const FAILED: u64 = 5;

    /// No reason: starting, ready or recovering.
    pub const NONE: u64 = 0;
    /// The driver stopped admitting for an orderly shutdown.
    pub const NOT_ADMITTING: u64 = 1;
    /// The driver holds `max_clients` clients.
    pub const FULL: u64 = 2;
    /// The driver is terminal.
    pub const TERMINAL: u64 = 3;
    /// Startup was not declared complete within the startup deadline.
    pub const STARTUP_DEADLINE: u64 = 4;
}

/// The protocol version of a `ToolHello` datagram of any version: its type
/// and version words are fixed. `None` when the datagram is not a
/// `ToolHello`.
#[must_use]
pub fn tool_hello_version(bytes: &[u8]) -> Option<u64> {
    version_of(TOOL_HELLO, bytes)
}

/// The second word of a datagram whose first word is `kind`.
fn version_of(kind: u64, bytes: &[u8]) -> Option<u64> {
    let (chunks, _) = bytes.as_chunks::<8>();
    match chunks {
        [first, version, ..] if u64::from_le_bytes(*first) == kind => {
            Some(u64::from_le_bytes(*version))
        }
        _ => None,
    }
}

const HELLO: u64 = 0x01;
const FETCH: u64 = 0x02;
const DETACH: u64 = 0x03;
const LEAVE: u64 = 0x04;
const TOOL_HELLO: u64 = 0x05;
const PROBE_HELLO: u64 = 0x06;
const ADMITTED: u64 = 0x81;
const MANIFEST: u64 = 0x82;
const REGION: u64 = 0x83;
const REFUSED: u64 = 0x84;
const TOOL_ADMITTED: u64 = 0x85;
const PROBE_STATE: u64 = 0x86;

/// `Hello` flags: the first profile accepted, and no fork while holding the
/// socket, a descriptor or a mapping.
const PROFILE_FLAGS: u64 = 0b11;

/// Errors decoding or encoding admission messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum AdmissionError {
    /// No type word, or an unknown type.
    #[error("unknown admission message")]
    UnknownType,
    /// The length does not match the type.
    #[error("admission message of {length} bytes, expected {expected}")]
    WrongLength {
        /// The length found.
        length: usize,
        /// The length the type and record count require.
        expected: usize,
    },
    /// A reserved bit or value is set, or a required value is zero.
    #[error("admission message with a reserved or missing value")]
    Reserved,
    /// More records than [`MAX_RECORDS`].
    #[error("manifest of {count} records")]
    TooManyRecords {
        /// The record count found.
        count: u64,
    },
    /// The output buffer is too short.
    #[error("buffer of {available} bytes, {required} required")]
    BufferTooShort {
        /// Bytes required.
        required: usize,
        /// Bytes available.
        available: usize,
    },
}

/// What a region holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegionKind {
    /// A client's command ring.
    CommandRing,
    /// The broadcast buffer.
    Broadcast,
    /// The counters.
    Counters,
    /// One log buffer generation.
    LogBuffer,
    /// The client counters, which the client maps writable to update the
    /// cells the driver allocated for it.
    ClientCounters,
    /// The error log, which only the driver writes (tools only).
    ErrorLog,
    /// The loss report, which only the driver writes (tools only).
    LossReport,
    /// A client's trace journal, which the client maps writable to append
    /// its records and the driver drains.
    Journal,
    /// The trace mirror, which only the driver writes (tools only).
    TraceMirror,
    /// A conflated stream's table, which only the driver writes; views
    /// map it read-only.
    ConflationTable,
    /// The guard audit ring, which only the driver writes (tools only).
    GuardAudit,
    /// The guard region, which only the driver writes; a client with a
    /// guarded handle maps it read-only.
    GuardRegion,
    /// A guarded handle's outcome ring, which only the driver writes; its
    /// client maps it read-only.
    OutcomeRing,
    /// A guarded handle's consumed cell, which its own client alone maps
    /// writable to publish its consumed count.
    ConsumedCell,
}

impl RegionKind {
    const fn code(self) -> u64 {
        match self {
            Self::CommandRing => 1,
            Self::Broadcast => 2,
            Self::Counters => 3,
            Self::LogBuffer => 4,
            Self::ClientCounters => 5,
            Self::ErrorLog => 6,
            Self::LossReport => 7,
            Self::Journal => 8,
            Self::TraceMirror => 9,
            Self::ConflationTable => 10,
            Self::GuardAudit => 11,
            Self::GuardRegion => 12,
            Self::OutcomeRing => 13,
            Self::ConsumedCell => 14,
        }
    }

    const fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(Self::CommandRing),
            2 => Some(Self::Broadcast),
            3 => Some(Self::Counters),
            4 => Some(Self::LogBuffer),
            5 => Some(Self::ClientCounters),
            6 => Some(Self::ErrorLog),
            7 => Some(Self::LossReport),
            8 => Some(Self::Journal),
            9 => Some(Self::TraceMirror),
            10 => Some(Self::ConflationTable),
            11 => Some(Self::GuardAudit),
            12 => Some(Self::GuardRegion),
            13 => Some(Self::OutcomeRing),
            14 => Some(Self::ConsumedCell),
            _ => None,
        }
    }
}

/// The wire kinds and the region kinds of `karyos_sys::ipc` they name: the
/// one table both sides map through (Linux). The codes differ on purpose:
/// a region header carries the sys code (`Journal` 5 to `TraceMirror` 9,
/// `quantstratum-docs: karyos/design/trace-journal-region.md`), while wire
/// code 5 was already `ClientCounters` when the journal kind was reserved,
/// so the wire numbers the later kinds after it. Each side keeps its own
/// codes; only this table relates them.
#[cfg(target_os = "linux")]
pub const SYS_KINDS: [(RegionKind, karyos_sys::ipc::RegionKind); 14] = {
    use karyos_sys::ipc::RegionKind as Sys;
    [
        (RegionKind::CommandRing, Sys::CommandRing),
        (RegionKind::Broadcast, Sys::Broadcast),
        (RegionKind::Counters, Sys::Counters),
        (RegionKind::LogBuffer, Sys::LogBuffer),
        (RegionKind::ClientCounters, Sys::ClientCounters),
        (RegionKind::ErrorLog, Sys::ErrorLog),
        (RegionKind::LossReport, Sys::LossReport),
        (RegionKind::Journal, Sys::Journal),
        (RegionKind::TraceMirror, Sys::TraceMirror),
        (RegionKind::ConflationTable, Sys::ConflationTable),
        (RegionKind::GuardAudit, Sys::GuardAudit),
        (RegionKind::GuardRegion, Sys::GuardRegion),
        (RegionKind::OutcomeRing, Sys::OutcomeRing),
        (RegionKind::ConsumedCell, Sys::ConsumedCell),
    ]
};

#[cfg(target_os = "linux")]
impl RegionKind {
    /// The region kind of `karyos_sys::ipc` this wire kind names
    /// ([`SYS_KINDS`]).
    #[must_use]
    pub fn to_sys(self) -> karyos_sys::ipc::RegionKind {
        SYS_KINDS
            .iter()
            .find(|(wire, _)| *wire == self)
            .map_or(karyos_sys::ipc::RegionKind::CommandRing, |(_, sys)| *sys)
    }

    /// The wire kind of a `karyos_sys::ipc` region kind ([`SYS_KINDS`]).
    #[must_use]
    pub fn from_sys(kind: karyos_sys::ipc::RegionKind) -> Self {
        SYS_KINDS
            .iter()
            .find(|(_, sys)| *sys == kind)
            .map_or(Self::CommandRing, |(wire, _)| *wire)
    }
}

/// The capability a record grants in its region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Capability {
    /// None: a control region.
    None,
    /// A required subscriber registered in `cell`.
    RequiredSubscriber {
        /// The registry cell.
        cell: u64,
    },
    /// An optional subscriber registered in `cell`.
    OptionalSubscriber {
        /// The registry cell.
        cell: u64,
    },
    /// An observer subscriber registered in `cell`
    /// (`quantstratum-docs: karyos/design/observer-role.md`).
    ObserverSubscriber {
        /// The registry cell.
        cell: u64,
    },
    /// The exclusive publication.
    ExclusivePublication,
    /// A concurrent handle registered in publisher slot `slot`.
    ConcurrentPublication {
        /// The publisher slot.
        slot: u64,
    },
}

impl Capability {
    const fn words(self) -> (u64, u64) {
        match self {
            Self::None => (0, 0),
            Self::RequiredSubscriber { cell } => (1, cell),
            Self::OptionalSubscriber { cell } => (2, cell),
            Self::ExclusivePublication => (3, 0),
            Self::ConcurrentPublication { slot } => (4, slot),
            Self::ObserverSubscriber { cell } => (5, cell),
        }
    }

    /// Whether it is a publication's: the capabilities a record's
    /// unconnected-offers bit may come with.
    const fn is_publication(self) -> bool {
        matches!(
            self,
            Self::ExclusivePublication | Self::ConcurrentPublication { .. }
        )
    }

    const fn from_words(code: u64, index: u64) -> Option<Self> {
        match (code, index) {
            (0, 0) => Some(Self::None),
            (1, cell) => Some(Self::RequiredSubscriber { cell }),
            (2, cell) => Some(Self::OptionalSubscriber { cell }),
            (3, 0) => Some(Self::ExclusivePublication),
            (4, slot) => Some(Self::ConcurrentPublication { slot }),
            (5, cell) => Some(Self::ObserverSubscriber { cell }),
            _ => None,
        }
    }
}

/// One region of a manifest: what the client must find in the region's
/// header, and the capability its grant carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    /// The region id.
    pub region: u64,
    /// The export id of this grant (nonzero, never reused).
    pub export: u64,
    /// What the region holds.
    pub kind: RegionKind,
    /// The layout version of its structure.
    pub layout: u32,
    /// Bytes of its structure after the header stride.
    pub structure_length: u64,
    /// Its mapping generation.
    pub generation: u64,
    /// Stream id (log buffers; 0 otherwise).
    pub stream_id: i32,
    /// Session id (log buffers; 0 otherwise).
    pub session_id: i32,
    /// Lane (log buffers; 0 otherwise).
    pub lane: u8,
    /// The capability granted.
    pub capability: Capability,
    /// The stream allows offers with no subscriber attached (SPEC.md §4):
    /// carried for a publication's capability only, and ignored with any
    /// other.
    pub allow_unconnected: bool,
}

impl Record {
    fn words(&self) -> [u64; RECORD_WORDS] {
        let (capability, index) = self.capability.words();
        [
            self.region,
            self.export,
            self.kind.code() | (u64::from(self.layout) << 8),
            self.structure_length,
            self.generation,
            u64::from(self.stream_id.cast_unsigned())
                | (u64::from(self.session_id.cast_unsigned()) << 32),
            u64::from(self.lane)
                | (capability << 8)
                | (u64::from(self.allow_unconnected && self.capability.is_publication())
                    << UNCONNECTED_BIT),
            index,
        ]
    }

    fn from_words(words: &[u64]) -> Result<Self, AdmissionError> {
        let &[
            region,
            export,
            kind,
            structure_length,
            generation,
            identity,
            lane,
            index,
        ] = words
        else {
            return Err(AdmissionError::Reserved);
        };
        if export == 0 || kind >> 40 != 0 || lane >> (UNCONNECTED_BIT + 1) != 0 {
            return Err(AdmissionError::Reserved);
        }
        let capability =
            Capability::from_words((lane >> 8) & 0xFF, index).ok_or(AdmissionError::Reserved)?;
        let allow_unconnected = lane >> UNCONNECTED_BIT != 0;
        if allow_unconnected && !capability.is_publication() {
            return Err(AdmissionError::Reserved);
        }
        Ok(Self {
            region,
            export,
            kind: RegionKind::from_code(kind & 0xFF).ok_or(AdmissionError::Reserved)?,
            layout: (kind >> 8) as u32,
            structure_length,
            generation,
            stream_id: (identity as u32).cast_signed(),
            session_id: ((identity >> 32) as u32).cast_signed(),
            lane: (lane & 0xFF) as u8,
            capability,
            allow_unconnected,
        })
    }
}

/// An admission message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Message {
    /// The client's first message, carrying its pidfd.
    Hello {
        /// The protocol version.
        version: u64,
    },
    /// A fetch of the regions waiting for a hand-over key.
    Fetch {
        /// The client's fetch id (nonzero, never reused).
        fetch: u64,
        /// The hand-over key from a `Ready` response.
        key: u64,
    },
    /// The client unmapped the region of an export.
    Detach {
        /// The export id.
        export: u64,
    },
    /// The client is done: every export detached, no fetch open.
    Leave,
    /// A tool's first message: it asks for the diagnostic regions only, and
    /// carries no descriptor.
    ToolHello {
        /// The protocol version.
        version: u64,
    },
    /// A readiness probe's only message (R-CORE-35); it carries no
    /// descriptor.
    ProbeHello {
        /// The protocol version.
        version: u64,
    },
    /// The bootstrap answer: fetch 0, the client's CnC regions.
    Admitted {
        /// The driver instance id.
        instance: u128,
        /// The protocol version the driver runs: the client's.
        version: u64,
        /// The client id.
        client: u64,
        /// The CnC regions.
        records: Vec<Record>,
    },
    /// The regions of a fetch.
    Manifest {
        /// The fetch id it answers.
        fetch: u64,
        /// The hand-over key fetched.
        key: u64,
        /// The registration the regions belong to; the journal number for a
        /// journal grant.
        registration: u64,
        /// The registration of the grant's stream: with the driver instance
        /// of `Admitted` and `incarnation`, the publication identity a loss
        /// report of the grant names (nonzero; zero for a journal grant).
        stream_registration: u64,
        /// The publication incarnation of the grant's stream (nonzero; zero
        /// for a journal grant).
        incarnation: u64,
        /// The stream position at which the grant's log buffer starts (below
        /// 2^63; zero for a journal grant).
        base: u64,
        /// The regions.
        records: Vec<Record>,
    },
    /// One region's descriptor follows with this message.
    Region {
        /// The fetch id (0 for the bootstrap).
        fetch: u64,
        /// The record index in the manifest.
        index: u64,
    },
    /// A refusal.
    Refused {
        /// Word 1, whose meaning depends on `code` (module docs): the fetch
        /// id refused or 0, or for [`refusal::INCOMPATIBLE_VERSION`] the
        /// refuser's protocol version or 0. Read the version with
        /// [`Message::refuser_version`], never this field.
        fetch: u64,
        /// Why (nonzero).
        code: u64,
    },
    /// The answer to `ToolHello`: the diagnostic regions, whose `Region`
    /// messages (fetch id 0) follow in record order.
    ToolAdmitted {
        /// The driver instance id.
        instance: u128,
        /// The protocol version the driver runs: the tool's.
        version: u64,
        /// The diagnostic regions; each carries capability none.
        records: Vec<Record>,
    },
    /// The answer to `ProbeHello`; the connection closes after it.
    ProbeState {
        /// One of [`probe`]'s states.
        state: u64,
        /// One of [`probe`]'s reasons: [`probe::NONE`] unless the state is
        /// not ready or failed.
        reason: u64,
        /// Nanoseconds since the driver started, on its clock.
        uptime_ns: u64,
    },
}

fn records_words(records: &[Record], words: &mut Vec<u64>) -> Result<(), AdmissionError> {
    if records.len() > MAX_RECORDS {
        return Err(AdmissionError::TooManyRecords {
            count: records.len() as u64,
        });
    }
    words.push(records.len() as u64);
    for record in records {
        words.extend_from_slice(&record.words());
    }
    Ok(())
}

fn records_from(header: usize, words: &[u64]) -> Result<Vec<Record>, AdmissionError> {
    let count = *words.get(header).ok_or(AdmissionError::Reserved)?;
    let records = usize::try_from(count)
        .ok()
        .filter(|count| *count <= MAX_RECORDS)
        .ok_or(AdmissionError::TooManyRecords { count })?;
    let expected = header + 1 + records * RECORD_WORDS;
    if words.len() != expected {
        return Err(AdmissionError::WrongLength {
            length: words.len() * 8,
            expected: expected * 8,
        });
    }
    words
        .get(header + 1..)
        .unwrap_or(&[])
        .as_chunks::<RECORD_WORDS>()
        .0
        .iter()
        .map(|record| Record::from_words(record))
        .collect()
}

/// The identity rule of a manifest: records that are all journals carry a
/// zero stream registration, incarnation and base; any other manifest
/// carries a nonzero stream registration and incarnation; journal records
/// never share a manifest with others; a base is below 2^63, and nonzero
/// only for log buffer records, the only regions that start at a stream
/// position, or for a guarded grant ([`guarded_grant`]). The guard
/// binding's kinds appear only in a guarded grant.
fn check_manifest_identity(
    records: &[Record],
    stream_registration: u64,
    incarnation: u64,
    base: u64,
) -> Result<(), AdmissionError> {
    let journals = records
        .iter()
        .filter(|record| record.kind == RegionKind::Journal)
        .count();
    let valid = if journals == 0 {
        stream_registration != 0 && incarnation != 0
    } else {
        journals == records.len() && stream_registration == 0 && incarnation == 0 && base == 0
    };
    let log_buffers = |records: &[Record]| {
        !records.is_empty()
            && records
                .iter()
                .all(|record| record.kind == RegionKind::LogBuffer)
    };
    let guarded = guarded_grant(records);
    let binding_kinds = records.iter().any(|record| {
        matches!(
            record.kind,
            RegionKind::GuardRegion | RegionKind::OutcomeRing | RegionKind::ConsumedCell
        )
    });
    let positioned = log_buffers(records) || guarded;
    if valid && base >> 63 == 0 && (base == 0 || positioned) && (guarded || !binding_kinds) {
        Ok(())
    } else {
        Err(AdmissionError::Reserved)
    }
}

/// Whether `records` are a guarded publication grant (`quantstratum-docs:
/// karyos/design/guards-and-abort.md`, "The binding across processes"):
/// one or more log buffer records, then exactly an `OutcomeRing`, a
/// `ConsumedCell` and a `GuardRegion` record in that order, each of the
/// three with capability none, lane 0 and the stream and session ids of
/// the log buffers.
fn guarded_grant(records: &[Record]) -> bool {
    let Some(split) = records.len().checked_sub(3) else {
        return false;
    };
    let (buffers, binding) = records.split_at(split);
    let Some(first) = buffers.first() else {
        return false;
    };
    buffers
        .iter()
        .all(|record| record.kind == RegionKind::LogBuffer)
        && binding.iter().map(|record| record.kind).eq([
            RegionKind::OutcomeRing,
            RegionKind::ConsumedCell,
            RegionKind::GuardRegion,
        ])
        && binding.iter().all(|record| {
            record.capability == Capability::None
                && record.lane == 0
                && record.stream_id == first.stream_id
                && record.session_id == first.session_id
        })
}

impl Message {
    /// The refusal of a `Hello` of another protocol version, stating the
    /// refuser's `version` in word 1 (karyos#879).
    #[must_use]
    pub const fn incompatible_version(version: core::num::NonZeroU64) -> Self {
        Self::Refused {
            fetch: version.get(),
            code: refusal::INCOMPATIBLE_VERSION,
        }
    }

    /// The protocol version a refusal of [`refusal::INCOMPATIBLE_VERSION`]
    /// states for its refuser, or `None`: for another message, another
    /// code (whose word 1 is a fetch id), or a refuser that states none
    /// (word 1 zero).
    #[must_use]
    pub const fn refuser_version(&self) -> Option<core::num::NonZeroU64> {
        match self {
            Self::Refused {
                fetch,
                code: refusal::INCOMPATIBLE_VERSION,
            } => core::num::NonZeroU64::new(*fetch),
            _ => None,
        }
    }

    /// The words of the message.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::TooManyRecords`].
    fn words(&self) -> Result<Vec<u64>, AdmissionError> {
        let mut words = Vec::new();
        match self {
            Self::Hello { version } => words.extend([HELLO, *version, PROFILE_FLAGS]),
            Self::Fetch { fetch, key } => words.extend([FETCH, *fetch, *key]),
            Self::Detach { export } => words.extend([DETACH, *export]),
            Self::Leave => words.push(LEAVE),
            Self::ToolHello { version } => words.extend([TOOL_HELLO, *version]),
            Self::ProbeHello { version } => words.extend([PROBE_HELLO, *version]),
            Self::ProbeState {
                state,
                reason,
                uptime_ns,
            } => words.extend([PROBE_STATE, *state, *reason, *uptime_ns]),
            Self::Admitted {
                instance,
                version,
                client,
                records,
            } => {
                words.extend([
                    ADMITTED,
                    *instance as u64,
                    (*instance >> 64) as u64,
                    *version,
                    *client,
                ]);
                records_words(records, &mut words)?;
            }
            Self::Manifest {
                fetch,
                key,
                registration,
                stream_registration,
                incarnation,
                base,
                records,
            } => {
                words.extend([
                    MANIFEST,
                    *fetch,
                    *key,
                    *registration,
                    *stream_registration,
                    *incarnation,
                    *base,
                ]);
                records_words(records, &mut words)?;
            }
            Self::Region { fetch, index } => words.extend([REGION, *fetch, *index]),
            Self::Refused { fetch, code } => words.extend([REFUSED, *fetch, *code]),
            Self::ToolAdmitted {
                instance,
                version,
                records,
            } => {
                words.extend([
                    TOOL_ADMITTED,
                    *instance as u64,
                    (*instance >> 64) as u64,
                    *version,
                ]);
                records_words(records, &mut words)?;
            }
        }
        Ok(words)
    }

    /// Refuses a message that [`Message::decode`] would refuse, so that
    /// every encoded message decodes to itself.
    fn check(&self) -> Result<(), AdmissionError> {
        let records = match self {
            Self::Fetch { fetch: 0, .. }
            | Self::Detach { export: 0 }
            | Self::Manifest { fetch: 0, .. }
            | Self::Refused { code: 0, .. } => return Err(AdmissionError::Reserved),
            Self::Manifest {
                stream_registration,
                incarnation,
                base,
                records,
                ..
            } => {
                check_manifest_identity(records, *stream_registration, *incarnation, *base)?;
                records.as_slice()
            }
            Self::Admitted { records, .. } => records.as_slice(),
            Self::ToolAdmitted { records, .. } => {
                if records
                    .iter()
                    .any(|record| record.capability != Capability::None)
                {
                    return Err(AdmissionError::Reserved);
                }
                records.as_slice()
            }
            _ => &[],
        };
        if records.iter().any(|record| record.export == 0) {
            return Err(AdmissionError::Reserved);
        }
        Ok(())
    }

    /// Encodes the message into `out`; returns the length.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::Reserved`] for a message that could not be
    /// decoded (a zero fetch id, export id or refusal code, a manifest that
    /// breaks the identity rule of journal grants, or a `ToolAdmitted`
    /// record with a capability),
    /// [`AdmissionError::TooManyRecords`] and
    /// [`AdmissionError::BufferTooShort`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, AdmissionError> {
        self.check()?;
        let words = self.words()?;
        let required = words.len() * 8;
        let available = out.len();
        let target = out
            .get_mut(..required)
            .ok_or(AdmissionError::BufferTooShort {
                required,
                available,
            })?;
        for (chunk, word) in target.as_chunks_mut::<8>().0.iter_mut().zip(&words) {
            *chunk = word.to_le_bytes();
        }
        Ok(required)
    }

    /// Decodes one message.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::UnknownType`],
    /// [`AdmissionError::WrongLength`], [`AdmissionError::Reserved`] and
    /// [`AdmissionError::TooManyRecords`].
    pub fn decode(bytes: &[u8]) -> Result<Self, AdmissionError> {
        let (chunks, rest) = bytes.as_chunks::<8>();
        if !rest.is_empty() || chunks.len() > MAX_MESSAGE_LENGTH / 8 {
            return Err(AdmissionError::WrongLength {
                length: bytes.len(),
                expected: bytes.len() - rest.len(),
            });
        }
        let words: Vec<u64> = chunks
            .iter()
            .map(|chunk| u64::from_le_bytes(*chunk))
            .collect();
        let exact = |n: usize| {
            if words.len() == n {
                Ok(())
            } else {
                Err(AdmissionError::WrongLength {
                    length: bytes.len(),
                    expected: n * 8,
                })
            }
        };
        let word = |i: usize| words.get(i).copied().unwrap_or(0);
        match words.first().copied().ok_or(AdmissionError::UnknownType)? {
            HELLO => {
                exact(3)?;
                if word(2) != PROFILE_FLAGS {
                    return Err(AdmissionError::Reserved);
                }
                Ok(Self::Hello { version: word(1) })
            }
            FETCH => {
                exact(3)?;
                if word(1) == 0 {
                    return Err(AdmissionError::Reserved);
                }
                Ok(Self::Fetch {
                    fetch: word(1),
                    key: word(2),
                })
            }
            DETACH => {
                exact(2)?;
                if word(1) == 0 {
                    return Err(AdmissionError::Reserved);
                }
                Ok(Self::Detach { export: word(1) })
            }
            LEAVE => {
                exact(1)?;
                Ok(Self::Leave)
            }
            TOOL_HELLO => {
                exact(2)?;
                Ok(Self::ToolHello { version: word(1) })
            }
            PROBE_HELLO => {
                exact(2)?;
                Ok(Self::ProbeHello { version: word(1) })
            }
            PROBE_STATE => {
                exact(4)?;
                let (state, reason) = (word(1), word(2));
                let consistent = match state {
                    probe::STARTING | probe::READY | probe::RECOVERING => reason == probe::NONE,
                    probe::NOT_READY => {
                        matches!(reason, probe::NOT_ADMITTING | probe::FULL | probe::TERMINAL)
                    }
                    probe::FAILED => reason == probe::STARTUP_DEADLINE,
                    _ => false,
                };
                if !consistent {
                    return Err(AdmissionError::Reserved);
                }
                Ok(Self::ProbeState {
                    state,
                    reason,
                    uptime_ns: word(3),
                })
            }
            ADMITTED => Ok(Self::Admitted {
                instance: u128::from(word(1)) | (u128::from(word(2)) << 64),
                version: word(3),
                client: word(4),
                records: records_from(5, &words)?,
            }),
            MANIFEST => {
                if word(1) == 0 {
                    return Err(AdmissionError::Reserved);
                }
                let records = records_from(7, &words)?;
                check_manifest_identity(&records, word(4), word(5), word(6))?;
                Ok(Self::Manifest {
                    fetch: word(1),
                    key: word(2),
                    registration: word(3),
                    stream_registration: word(4),
                    incarnation: word(5),
                    base: word(6),
                    records,
                })
            }
            REGION => {
                exact(3)?;
                Ok(Self::Region {
                    fetch: word(1),
                    index: word(2),
                })
            }
            REFUSED => {
                exact(3)?;
                if word(2) == 0 {
                    return Err(AdmissionError::Reserved);
                }
                Ok(Self::Refused {
                    fetch: word(1),
                    code: word(2),
                })
            }
            TOOL_ADMITTED => {
                let records = records_from(4, &words)?;
                // A tool is granted no capability.
                if records
                    .iter()
                    .any(|record| record.capability != Capability::None)
                {
                    return Err(AdmissionError::Reserved);
                }
                Ok(Self::ToolAdmitted {
                    instance: u128::from(word(1)) | (u128::from(word(2)) << 64),
                    version: word(3),
                    records,
                })
            }
            _ => Err(AdmissionError::UnknownType),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(export: u64, capability: Capability) -> Record {
        Record {
            region: 9,
            export,
            kind: RegionKind::LogBuffer,
            layout: 1,
            structure_length: 4096,
            generation: 2,
            stream_id: -5,
            session_id: 77,
            lane: 3,
            capability,
            allow_unconnected: false,
        }
    }

    /// karyos#879: an INCOMPATIBLE_VERSION refusal states the refuser's
    /// version in word 1, in the fixed three-word layout every decoder
    /// reads; zero states none. Word 1 of any other refusal is a fetch id
    /// and is never read as a version.
    #[test]
    fn a_version_refusal_states_the_refusers_version_and_a_fetch_refusal_does_not() {
        let three = core::num::NonZeroU64::new(3).unwrap();
        let refusal = Message::incompatible_version(three);
        round_trip(&refusal);
        let mut out = [0u8; MAX_MESSAGE_LENGTH];
        let len = refusal.encode(&mut out).unwrap();
        assert_eq!(len, 24, "the fixed layout: type, word 1, code");
        assert_eq!(
            Message::decode(&out[..len]).unwrap().refuser_version(),
            Some(three)
        );
        let unstated = Message::Refused {
            fetch: 0,
            code: refusal::INCOMPATIBLE_VERSION,
        };
        assert_eq!(unstated.refuser_version(), None);
        for code in [
            refusal::PROFILE,
            refusal::LIMIT,
            refusal::RESOURCES,
            refusal::UNKNOWN_KEY,
            refusal::SHUTTING_DOWN,
            99,
        ] {
            let fetch = Message::Refused { fetch: 3, code };
            assert_eq!(fetch.refuser_version(), None, "code {code}");
        }
        assert_eq!(Message::Leave.refuser_version(), None);
    }

    fn round_trip(message: &Message) {
        let mut out = [0u8; MAX_MESSAGE_LENGTH];
        let len = message.encode(&mut out).unwrap();
        assert_eq!(Message::decode(&out[..len]).unwrap(), *message);
    }

    #[test]
    fn every_message_round_trips() {
        round_trip(&Message::Hello { version: VERSION });
        round_trip(&Message::Fetch { fetch: 1, key: 40 });
        round_trip(&Message::Detach { export: 8 });
        round_trip(&Message::Leave);
        round_trip(&Message::Region { fetch: 0, index: 2 });
        round_trip(&Message::Refused { fetch: 3, code: 6 });
        round_trip(&Message::Admitted {
            instance: u128::MAX - 7,
            version: VERSION,
            client: 4,
            records: vec![
                Record {
                    kind: RegionKind::CommandRing,
                    capability: Capability::None,
                    ..record(1, Capability::None)
                },
                Record {
                    kind: RegionKind::ClientCounters,
                    capability: Capability::None,
                    ..record(2, Capability::None)
                },
            ],
        });
        let capabilities = [
            Capability::None,
            Capability::RequiredSubscriber { cell: 4 },
            Capability::OptionalSubscriber { cell: 0 },
            Capability::ExclusivePublication,
            Capability::ConcurrentPublication { slot: 2 },
            Capability::ObserverSubscriber { cell: 3 },
        ];
        let records: Vec<Record> = capabilities
            .iter()
            .enumerate()
            .map(|(i, capability)| record(i as u64 + 1, *capability))
            .collect();
        round_trip(&Message::Manifest {
            fetch: 5,
            key: 6,
            registration: 7,
            stream_registration: 8,
            incarnation: 1,
            base: 0,
            records,
        });
        round_trip(&Message::Manifest {
            fetch: 5,
            key: 6,
            registration: 7,
            stream_registration: 8,
            incarnation: 1,
            base: 0,
            records: vec![record(1, Capability::None); MAX_RECORDS],
        });
    }

    #[test]
    fn decoding_is_strict() {
        let encode = |message: &Message| {
            let mut out = vec![0u8; MAX_MESSAGE_LENGTH];
            let len = message.encode(&mut out).unwrap();
            out.truncate(len);
            out
        };
        let mut hello = encode(&Message::Hello { version: VERSION });
        hello[16] = 1;
        assert_eq!(Message::decode(&hello), Err(AdmissionError::Reserved));
        // Raw words that `encode` refuses to produce.
        let raw = |words: &[u64]| -> Vec<u8> {
            words.iter().flat_map(|word| word.to_le_bytes()).collect()
        };
        for words in [
            vec![FETCH, 0, 1],
            vec![DETACH, 0],
            vec![REFUSED, 1, 0],
            vec![MANIFEST, 0, 1, 2, 3, 1, 0, 0],
            // A zero stream registration or incarnation.
            vec![MANIFEST, 1, 1, 2, 0, 1, 0, 0],
            vec![MANIFEST, 1, 1, 2, 3, 0, 0, 0],
            // A base with the top bit set.
            vec![MANIFEST, 1, 1, 2, 3, 1, 1 << 63, 0],
        ] {
            assert_eq!(
                Message::decode(&raw(&words)),
                Err(AdmissionError::Reserved),
                "{words:?}"
            );
        }
        let mut leave = encode(&Message::Leave);
        leave.extend([0u8; 8]);
        assert!(matches!(
            Message::decode(&leave),
            Err(AdmissionError::WrongLength { .. })
        ));
        assert_eq!(Message::decode(&[]), Err(AdmissionError::UnknownType));
        assert_eq!(Message::decode(&[7u8; 8]), Err(AdmissionError::UnknownType));
        assert!(matches!(
            Message::decode(&[1u8; 9]),
            Err(AdmissionError::WrongLength { .. })
        ));
        // A manifest whose count disagrees with its records.
        let mut manifest = encode(&Message::Manifest {
            fetch: 1,
            key: 2,
            registration: 3,
            stream_registration: 8,
            incarnation: 1,
            base: 0,
            records: vec![record(1, Capability::None); 2],
        });
        manifest[56] = 3;
        assert!(matches!(
            Message::decode(&manifest),
            Err(AdmissionError::WrongLength { .. })
        ));
        manifest[56] = 200;
        assert!(matches!(
            Message::decode(&manifest),
            Err(AdmissionError::TooManyRecords { .. })
        ));
        // A record with export 0, an unknown kind, an unknown capability or
        // an index on a capability without one.
        for (offset, value) in [(72, 0u8), (80, 15), (113, 7), (120, 1)] {
            let mut bad = encode(&Message::Manifest {
                fetch: 1,
                key: 2,
                registration: 3,
                stream_registration: 8,
                incarnation: 1,
                base: 0,
                records: vec![record(1, Capability::None)],
            });
            bad[offset] = value;
            assert_eq!(
                Message::decode(&bad),
                Err(AdmissionError::Reserved),
                "byte {offset}"
            );
        }
        // Too many records to encode.
        let mut out = vec![0u8; MAX_MESSAGE_LENGTH + 64];
        assert!(matches!(
            Message::Manifest {
                fetch: 1,
                key: 2,
                registration: 3,
                stream_registration: 8,
                incarnation: 1,
                base: 0,
                records: vec![record(1, Capability::None); MAX_RECORDS + 1],
            }
            .encode(&mut out),
            Err(AdmissionError::TooManyRecords { .. })
        ));
        assert!(matches!(
            Message::Leave.encode(&mut []),
            Err(AdmissionError::BufferTooShort { .. })
        ));
    }

    #[test]
    fn what_cannot_be_decoded_is_not_encoded() {
        let mut out = [0u8; MAX_MESSAGE_LENGTH];
        for message in [
            Message::Fetch { fetch: 0, key: 0 },
            Message::Detach { export: 0 },
            Message::Refused { fetch: 1, code: 0 },
            Message::Manifest {
                fetch: 0,
                key: 1,
                registration: 2,
                stream_registration: 8,
                incarnation: 1,
                base: 0,
                records: Vec::new(),
            },
            Message::Manifest {
                fetch: 1,
                key: 1,
                registration: 2,
                stream_registration: 8,
                incarnation: 1,
                base: 0,
                records: vec![record(0, Capability::None)],
            },
            Message::Admitted {
                instance: 1,
                version: VERSION,
                client: 1,
                records: vec![record(0, Capability::None)],
            },
            Message::Manifest {
                fetch: 1,
                key: 1,
                registration: 2,
                stream_registration: 0,
                incarnation: 1,
                base: 0,
                records: Vec::new(),
            },
            Message::Manifest {
                fetch: 1,
                key: 1,
                registration: 2,
                stream_registration: 3,
                incarnation: 0,
                base: 0,
                records: Vec::new(),
            },
            Message::Manifest {
                fetch: 1,
                key: 1,
                registration: 2,
                stream_registration: 3,
                incarnation: 1,
                base: 1 << 63,
                records: Vec::new(),
            },
        ] {
            assert_eq!(
                message.encode(&mut out),
                Err(AdmissionError::Reserved),
                "{message:?}"
            );
        }
    }

    #[test]
    fn the_version_of_any_hello_can_be_read() {
        let mut out = [0u8; MAX_MESSAGE_LENGTH];
        let len = Message::Hello { version: 7 }.encode(&mut out).unwrap();
        assert_eq!(hello_version(&out[..len]), Some(7));
        // A longer Hello of a future version still yields its version.
        let mut future = out[..len].to_vec();
        future.extend_from_slice(&[0xAB; 16]);
        assert!(Message::decode(&future).is_err());
        assert_eq!(hello_version(&future), Some(7));
        let len = Message::Leave.encode(&mut out).unwrap();
        assert_eq!(hello_version(&out[..len]), None);
        assert_eq!(hello_version(&[1, 0, 0, 0, 0, 0, 0, 0]), None);
        // The refusal of an incompatible version decodes as any refusal.
        round_trip(&Message::Refused {
            fetch: 0,
            code: refusal::INCOMPATIBLE_VERSION,
        });
        // The largest message is a Manifest with every record; an Admitted
        // with every record fits too.
        let records = vec![record(1, Capability::None); MAX_RECORDS];
        let manifest = Message::Manifest {
            fetch: 1,
            key: 2,
            registration: 3,
            stream_registration: 4,
            incarnation: 1,
            base: 0,
            records: records.clone(),
        };
        assert_eq!(manifest.encode(&mut out), Ok(MAX_MESSAGE_LENGTH));
        let admitted = Message::Admitted {
            instance: 1,
            version: VERSION,
            client: 2,
            records,
        };
        assert_eq!(admitted.encode(&mut out), Ok(MAX_MESSAGE_LENGTH - 16));
    }

    /// Every wire kind and every sys kind appears in the table exactly
    /// once, so the two mappings are inverse bijections.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_kind_table_is_a_bijection() {
        for (wire, sys) in SYS_KINDS {
            assert_eq!(wire.to_sys(), sys);
            assert_eq!(RegionKind::from_sys(sys), wire);
        }
        for code in 1..=14 {
            let wire = RegionKind::from_code(code).unwrap();
            assert_eq!(RegionKind::from_sys(wire.to_sys()), wire);
        }
        assert_eq!(RegionKind::from_code(15), None);
    }

    /// The protocol version is 3 (karyos#637: the roles and identity
    /// commands); 2 was the trace journal kinds' (ACS 13677), published by
    /// alpha.2.
    #[test]
    fn the_version_is_three() {
        let mut out = [0u8; MAX_MESSAGE_LENGTH];
        let length = Message::Hello { version: VERSION }
            .encode(&mut out)
            .unwrap();
        assert_eq!(words_of(&out[..length]), [HELLO, 3, PROFILE_FLAGS]);
    }

    /// The manifest's words, literally: the stream registration, the
    /// incarnation and the base follow the registration, before the record
    /// count.
    #[test]
    fn a_manifest_carries_the_publication_identity_of_its_grant() {
        let message = Message::Manifest {
            fetch: 5,
            key: 6,
            registration: 7,
            stream_registration: 0x0102_0304,
            incarnation: 9,
            base: 0x4000,
            records: vec![record(1, Capability::OptionalSubscriber { cell: 2 })],
        };
        let mut out = [0u8; MAX_MESSAGE_LENGTH];
        let length = message.encode(&mut out).unwrap();
        assert_eq!(length, (8 + RECORD_WORDS) * 8);
        let words: Vec<u64> = out[..length]
            .as_chunks::<8>()
            .0
            .iter()
            .map(|chunk| u64::from_le_bytes(*chunk))
            .collect();
        assert_eq!(words[..8], [MANIFEST, 5, 6, 7, 0x0102_0304, 9, 0x4000, 1]);
        assert_eq!(Message::decode(&out[..length]).unwrap(), message);
        // The layout without these words (the record count after the
        // registration) is refused: a record word is read as the count,
        // here too large.
        let mut short = words.clone();
        short.drain(4..7);
        let bytes: Vec<u8> = short.iter().flat_map(|word| word.to_le_bytes()).collect();
        assert!(matches!(
            Message::decode(&bytes),
            Err(AdmissionError::TooManyRecords { .. })
        ));
        // Nor is the layout without the base alone (G-d2c): one word short.
        let mut short = words.clone();
        short.remove(6);
        let bytes: Vec<u8> = short.iter().flat_map(|word| word.to_le_bytes()).collect();
        assert!(matches!(
            Message::decode(&bytes),
            Err(AdmissionError::WrongLength { .. })
        ));
        // A manifest of the largest size plus one word is refused.
        let mut long = vec![0u8; MAX_MESSAGE_LENGTH + 8];
        long[0] = MANIFEST as u8;
        assert!(matches!(
            Message::decode(&long),
            Err(AdmissionError::WrongLength { .. })
        ));
    }

    /// Review of #218: only a log buffer starts at a stream position, so a
    /// manifest of any other region carries base 0, both ways.
    #[test]
    fn only_a_log_buffer_manifest_carries_a_base() {
        let table = Record {
            kind: RegionKind::ConflationTable,
            ..record(1, Capability::None)
        };
        let manifest = |records: Vec<Record>, base| Message::Manifest {
            fetch: 1,
            key: 2,
            registration: 3,
            stream_registration: 4,
            incarnation: 1,
            base,
            records,
        };
        round_trip(&manifest(vec![table], 0));
        round_trip(&manifest(vec![record(1, Capability::None)], 4096));
        let mut out = [0u8; MAX_MESSAGE_LENGTH];
        for refused in [
            manifest(vec![table], 4096),
            manifest(Vec::new(), 4096),
            manifest(vec![record(1, Capability::None), table], 4096),
        ] {
            assert_eq!(
                refused.encode(&mut out),
                Err(AdmissionError::Reserved),
                "{refused:?}"
            );
        }
        let length = manifest(vec![table], 0).encode(&mut out).unwrap();
        let mut words = words_of(&out[..length]);
        words[6] = 4096;
        assert_eq!(
            Message::decode(&bytes_of(&words)),
            Err(AdmissionError::Reserved)
        );
    }

    /// A guarded grant (G-x2): log buffer records, then exactly an outcome
    /// ring, a consumed cell and the guard region, capability none, lane 0
    /// and the log buffers' ids; it carries a base. Any other place for the
    /// binding's kinds is refused, both ways.
    #[test]
    fn a_guarded_grant_follows_its_record_order() {
        let binding = |kind, export| Record {
            kind,
            lane: 0,
            ..record(export, Capability::None)
        };
        let buffer = record(1, Capability::ExclusivePublication);
        let ring = binding(RegionKind::OutcomeRing, 2);
        let cell = binding(RegionKind::ConsumedCell, 3);
        let guards = binding(RegionKind::GuardRegion, 4);
        let manifest = |records: Vec<Record>, base| Message::Manifest {
            fetch: 1,
            key: 2,
            registration: 3,
            stream_registration: 4,
            incarnation: 1,
            base,
            records,
        };
        round_trip(&manifest(vec![buffer, ring, cell, guards], 4096));
        round_trip(&manifest(vec![buffer, ring, cell, guards], 0));
        let other_stream = Record {
            stream_id: 6,
            ..cell
        };
        let granted = Record {
            capability: Capability::ExclusivePublication,
            ..guards
        };
        let laned = Record { lane: 1, ..ring };
        let mut out = [0u8; MAX_MESSAGE_LENGTH];
        for refused in [
            // No GuardRegion, the wrong order, no log buffer.
            manifest(vec![buffer, ring, cell], 4096),
            manifest(vec![buffer, cell, ring, guards], 4096),
            manifest(vec![ring, cell, guards], 0),
            // A binding kind alone, or after another kind.
            manifest(vec![guards], 0),
            manifest(vec![buffer, ring, cell, guards, buffer], 0),
            // Another stream, a capability, a lane.
            manifest(vec![buffer, ring, other_stream, guards], 4096),
            manifest(vec![buffer, ring, cell, granted], 4096),
            manifest(vec![buffer, laned, cell, guards], 4096),
        ] {
            assert_eq!(
                refused.encode(&mut out),
                Err(AdmissionError::Reserved),
                "{refused:?}"
            );
        }
        // Decoding refuses it too: a binding kind after the guard region.
        let length = manifest(vec![buffer, ring, cell, guards], 0)
            .encode(&mut out)
            .unwrap();
        let mut words = words_of(&out[..length]);
        let kinds: Vec<usize> = (0..words.len())
            .filter(|&index| words[index] & 0xFF == RegionKind::GuardRegion.code())
            .collect();
        assert!(!kinds.is_empty());
        let last = *kinds.last().unwrap();
        words[last] = (words[last] & !0xFF) | RegionKind::OutcomeRing.code();
        assert_eq!(
            Message::decode(&bytes_of(&words)),
            Err(AdmissionError::Reserved)
        );
    }

    /// A journal grant's manifest: journal records only, the journal number
    /// as registration, zero stream registration and incarnation; anything
    /// else with a journal record is refused, both ways.
    #[test]
    fn a_journal_manifest_follows_the_identity_rule() {
        let journal = Record {
            kind: RegionKind::Journal,
            stream_id: 0,
            session_id: 0,
            lane: 0,
            generation: 0,
            ..record(4, Capability::None)
        };
        let manifest = |records: Vec<Record>, stream_registration, incarnation| Message::Manifest {
            fetch: 1,
            key: 2,
            registration: 9,
            stream_registration,
            incarnation,
            base: 0,
            records,
        };
        let valid = manifest(vec![journal], 0, 0);
        round_trip(&valid);
        let mut out = [0u8; MAX_MESSAGE_LENGTH];
        let length = valid.encode(&mut out).unwrap();
        let words = words_of(&out[..length]);
        assert_eq!(words[..8], [MANIFEST, 1, 2, 9, 0, 0, 0, 1]);
        // The journal kind is 8 on the wire, the trace mirror 9.
        assert_eq!(words[8 + 2] & 0xFF, 8);
        for refused in [
            manifest(vec![journal], 3, 0),
            manifest(vec![journal], 0, 1),
            manifest(vec![journal, record(5, Capability::None)], 0, 0),
            manifest(vec![journal, record(5, Capability::None)], 3, 1),
            manifest(vec![record(5, Capability::None)], 0, 0),
            manifest(Vec::new(), 0, 0),
            Message::Manifest {
                fetch: 1,
                key: 2,
                registration: 9,
                stream_registration: 0,
                incarnation: 0,
                base: 4096,
                records: vec![journal],
            },
        ] {
            assert_eq!(
                refused.encode(&mut out),
                Err(AdmissionError::Reserved),
                "{refused:?}"
            );
        }
        // The decoder refuses the same words.
        let mut raw = words.clone();
        raw[4] = 3;
        assert_eq!(
            Message::decode(&bytes_of(&raw)),
            Err(AdmissionError::Reserved)
        );
        let mut raw = words;
        raw[8 + 2] = RegionKind::TraceMirror.code() | 1 << 8;
        assert_eq!(
            Message::decode(&bytes_of(&raw)),
            Err(AdmissionError::Reserved),
            "a mirror record needs a stream identity outside a journal manifest"
        );
    }

    /// The four diagnostic records a driver grants a tool.
    fn tool_records() -> Vec<Record> {
        [
            RegionKind::Counters,
            RegionKind::ClientCounters,
            RegionKind::ErrorLog,
            RegionKind::LossReport,
        ]
        .into_iter()
        .zip(1u64..)
        .map(|(kind, export)| Record {
            kind,
            stream_id: 0,
            session_id: 0,
            lane: 0,
            generation: 0,
            ..record(export, Capability::None)
        })
        .collect()
    }

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

    /// The tool messages, literally: `ToolHello` is its type and version;
    /// `ToolAdmitted` is its type, the instance low word first, the version
    /// and the record count, then the records.
    #[test]
    fn the_tool_messages_round_trip_with_their_layouts() {
        let mut out = [0u8; MAX_MESSAGE_LENGTH];
        let hello = Message::ToolHello { version: VERSION };
        let length = hello.encode(&mut out).unwrap();
        assert_eq!(words_of(&out[..length]), [TOOL_HELLO, VERSION]);
        round_trip(&hello);
        let admitted = Message::ToolAdmitted {
            instance: 0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10,
            version: VERSION,
            records: tool_records(),
        };
        let length = admitted.encode(&mut out).unwrap();
        assert_eq!(length, (5 + 4 * RECORD_WORDS) * 8);
        let words = words_of(&out[..length]);
        assert_eq!(
            words[..5],
            [
                TOOL_ADMITTED,
                0x090A_0B0C_0D0E_0F10,
                0x0102_0304_0506_0708,
                VERSION,
                4
            ]
        );
        // The kinds of the diagnostic regions: error log 6, loss report 7.
        assert_eq!(words[5 + 2], 3 | 1 << 8);
        assert_eq!(words[5 + RECORD_WORDS + 2], 5 | 1 << 8);
        assert_eq!(words[5 + 2 * RECORD_WORDS + 2], 6 | 1 << 8);
        assert_eq!(words[5 + 3 * RECORD_WORDS + 2], 7 | 1 << 8);
        round_trip(&admitted);
        round_trip(&Message::ToolAdmitted {
            instance: 0,
            version: 9,
            records: Vec::new(),
        });
        round_trip(&Message::ToolAdmitted {
            instance: u128::MAX,
            version: VERSION,
            records: vec![tool_records()[0]; MAX_RECORDS],
        });
    }

    /// R-CORE-35: the probe messages, literally, and their strict decoding:
    /// a state with an inconsistent reason, an unknown state or a wrong
    /// length is refused; the version of any `ProbeHello` is readable.
    #[test]
    fn the_probe_messages_round_trip_and_decode_strictly() {
        let mut out = [0u8; MAX_MESSAGE_LENGTH];
        let hello = Message::ProbeHello { version: VERSION };
        let length = hello.encode(&mut out).unwrap();
        assert_eq!(words_of(&out[..length]), [PROBE_HELLO, VERSION]);
        round_trip(&hello);
        assert_eq!(probe_hello_version(&out[..length]), Some(VERSION));
        assert_eq!(
            probe_hello_version(&bytes_of(&[PROBE_HELLO, 9, 0])),
            Some(9)
        );
        assert_eq!(probe_hello_version(&bytes_of(&[TOOL_HELLO, 3])), None);
        for (state, reason) in [
            (probe::STARTING, probe::NONE),
            (probe::READY, probe::NONE),
            (probe::RECOVERING, probe::NONE),
            (probe::NOT_READY, probe::NOT_ADMITTING),
            (probe::NOT_READY, probe::FULL),
            (probe::NOT_READY, probe::TERMINAL),
            (probe::FAILED, probe::STARTUP_DEADLINE),
        ] {
            let message = Message::ProbeState {
                state,
                reason,
                uptime_ns: 42,
            };
            let length = message.encode(&mut out).unwrap();
            assert_eq!(words_of(&out[..length]), [PROBE_STATE, state, reason, 42]);
            round_trip(&message);
        }
        for words in [
            [PROBE_STATE, probe::READY, probe::FULL, 1],
            [PROBE_STATE, probe::NOT_READY, probe::NONE, 1],
            [PROBE_STATE, probe::FAILED, probe::TERMINAL, 1],
            [PROBE_STATE, 6, probe::NONE, 1],
            [PROBE_STATE, 0, probe::NONE, 1],
        ] {
            assert_eq!(
                Message::decode(&bytes_of(&words)),
                Err(AdmissionError::Reserved),
                "{words:?}"
            );
        }
        assert!(Message::decode(&bytes_of(&[PROBE_HELLO, VERSION, 0])).is_err());
        assert!(Message::decode(&bytes_of(&[PROBE_STATE, probe::READY, 0])).is_err());
    }

    #[test]
    fn the_tool_messages_decode_strictly() {
        let mut out = [0u8; MAX_MESSAGE_LENGTH];
        // A ToolHello with a third word, or without its version.
        assert!(matches!(
            Message::decode(&bytes_of(&[TOOL_HELLO, VERSION, 0])),
            Err(AdmissionError::WrongLength { .. })
        ));
        assert!(matches!(
            Message::decode(&bytes_of(&[TOOL_HELLO])),
            Err(AdmissionError::WrongLength { .. })
        ));
        let length = Message::ToolAdmitted {
            instance: 5,
            version: VERSION,
            records: tool_records(),
        }
        .encode(&mut out)
        .unwrap();
        let admitted = out[..length].to_vec();
        // A count that disagrees with the records, or above the bound.
        for (count, short) in [(3u8, true), (5, true), (200, false)] {
            let mut bad = admitted.clone();
            bad[32] = count;
            let decoded = Message::decode(&bad);
            if short {
                assert!(
                    matches!(decoded, Err(AdmissionError::WrongLength { .. })),
                    "{count}"
                );
            } else {
                assert!(matches!(
                    decoded,
                    Err(AdmissionError::TooManyRecords { .. })
                ));
            }
        }
        // A record with export 0, an unknown kind, or any capability: a
        // tool is granted none, even one without an index.
        let first = 40;
        for (offset, value) in [
            (first + 8, 0u8),
            (first + 16, 15),
            (first + 49, 1),
            (first + 49, 3),
            (first + 49, 5),
        ] {
            let mut bad = admitted.clone();
            bad[offset] = value;
            assert_eq!(
                Message::decode(&bad),
                Err(AdmissionError::Reserved),
                "byte {offset}"
            );
        }
        // Too short for its header.
        assert_eq!(
            Message::decode(&bytes_of(&[TOOL_ADMITTED, 1, 2, 3])),
            Err(AdmissionError::Reserved)
        );
        // The encoder refuses what the decoder refuses.
        for capability in [
            Capability::ExclusivePublication,
            Capability::RequiredSubscriber { cell: 0 },
            Capability::ConcurrentPublication { slot: 1 },
        ] {
            let mut records = tool_records();
            records[1].capability = capability;
            assert_eq!(
                Message::ToolAdmitted {
                    instance: 1,
                    version: VERSION,
                    records,
                }
                .encode(&mut out),
                Err(AdmissionError::Reserved)
            );
        }
        let mut records = tool_records();
        records[3].export = 0;
        assert_eq!(
            Message::ToolAdmitted {
                instance: 1,
                version: VERSION,
                records,
            }
            .encode(&mut out),
            Err(AdmissionError::Reserved)
        );
    }

    /// A record's bit 16 (ipc-admission.md, Unconnected offers): it
    /// round-trips with an exclusive or a concurrent publication's
    /// capability, is refused with any other and above it, and is never
    /// encoded with a capability that is not a publication's.
    #[test]
    fn the_unconnected_bit_comes_with_a_publications_capability_only() {
        for capability in [
            Capability::ExclusivePublication,
            Capability::ConcurrentPublication { slot: 2 },
        ] {
            let allowing = Record {
                allow_unconnected: true,
                ..record(7, capability)
            };
            let words = allowing.words();
            assert_eq!(words[6] >> UNCONNECTED_BIT, 1, "{capability:?}");
            assert_eq!(Record::from_words(&words), Ok(allowing));
            let plain = record(7, capability);
            assert_eq!(plain.words()[6] >> UNCONNECTED_BIT, 0);
            assert_eq!(Record::from_words(&plain.words()), Ok(plain));
            // Bits above it stay reserved.
            let mut above = words;
            above[6] |= 1 << (UNCONNECTED_BIT + 1);
            assert_eq!(Record::from_words(&above), Err(AdmissionError::Reserved));
        }
        for capability in [
            Capability::None,
            Capability::RequiredSubscriber { cell: 1 },
            Capability::OptionalSubscriber { cell: 1 },
            Capability::ObserverSubscriber { cell: 1 },
        ] {
            let index = capability.words().1;
            let allowing = Record {
                allow_unconnected: true,
                ..record(7, capability)
            };
            // Never encoded.
            let words = allowing.words();
            assert_eq!(words[6] >> UNCONNECTED_BIT, 0, "{capability:?}");
            assert_eq!(words[7], index);
            // Refused when set.
            let mut set = words;
            set[6] |= 1 << UNCONNECTED_BIT;
            assert_eq!(
                Record::from_words(&set),
                Err(AdmissionError::Reserved),
                "{capability:?}"
            );
        }
    }

    #[test]
    fn the_version_of_any_tool_hello_can_be_read() {
        let mut out = [0u8; MAX_MESSAGE_LENGTH];
        let length = Message::ToolHello { version: 7 }.encode(&mut out).unwrap();
        assert_eq!(tool_hello_version(&out[..length]), Some(7));
        assert_eq!(hello_version(&out[..length]), None);
        // A longer ToolHello of a future version still yields its version.
        let mut future = out[..length].to_vec();
        future.extend_from_slice(&[0xCD; 24]);
        assert!(Message::decode(&future).is_err());
        assert_eq!(tool_hello_version(&future), Some(7));
        // A client Hello is not a tool's.
        let length = Message::Hello { version: 7 }.encode(&mut out).unwrap();
        assert_eq!(tool_hello_version(&out[..length]), None);
        assert_eq!(tool_hello_version(&bytes_of(&[TOOL_HELLO])), None);
    }
}

/// Decoder properties of the admission messages (issue #121, the control
/// protocol harness standing in for fuzzing, #11 option B), in the style
/// of the frame parser's. The driver decodes datagrams from processes it
/// has not admitted yet, so: decoding any bytes never panics; every valid
/// message round-trips within [`MAX_MESSAGE_LENGTH`], and an encodable
/// message always decodes to itself; decoding is canonical (whatever
/// decodes re-encodes to the same bytes); a flipped byte or a changed
/// length is refused unless the result re-encodes to exactly the input;
/// and [`hello_version`] reads the version of a `Hello` of any layout.
#[cfg(test)]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod properties {
    use proptest::prelude::*;

    use super::*;

    const TYPES: [u64; 10] = [
        HELLO,
        FETCH,
        DETACH,
        LEAVE,
        TOOL_HELLO,
        ADMITTED,
        MANIFEST,
        REGION,
        REFUSED,
        TOOL_ADMITTED,
    ];

    fn encoded(message: &Message) -> Result<Vec<u8>, AdmissionError> {
        let mut out = vec![0u8; MAX_MESSAGE_LENGTH];
        let length = message.encode(&mut out)?;
        out.truncate(length);
        Ok(out)
    }

    fn word(bytes: &[u8], index: usize) -> Option<u64> {
        let chunk = bytes.get(index * 8..index * 8 + 8)?;
        Some(u64::from_le_bytes(chunk.try_into().unwrap()))
    }

    /// Canonicality, and [`hello_version`] and [`tool_hello_version`]
    /// against a model: the second word of anything at least two words
    /// long whose first word is the type of `Hello` (or `ToolHello`).
    fn check_decoded(bytes: &[u8]) -> Result<bool, TestCaseError> {
        let version = |kind: u64| match (word(bytes, 0), word(bytes, 1)) {
            (Some(first), Some(version)) if first == kind => Some(version),
            _ => None,
        };
        prop_assert_eq!(hello_version(bytes), version(HELLO));
        prop_assert_eq!(tool_hello_version(bytes), version(TOOL_HELLO));
        match Message::decode(bytes) {
            Ok(message) => {
                prop_assert!(bytes.len() <= MAX_MESSAGE_LENGTH);
                prop_assert_eq!(&encoded(&message).unwrap()[..], bytes);
                match message {
                    Message::Hello { version } => {
                        prop_assert_eq!(hello_version(bytes), Some(version));
                    }
                    Message::ToolHello { version } => {
                        prop_assert_eq!(tool_hello_version(bytes), Some(version));
                    }
                    Message::ToolAdmitted { records, .. } => {
                        prop_assert!(
                            records
                                .iter()
                                .all(|record| record.capability == Capability::None)
                        );
                    }
                    _ => {}
                }
                Ok(true)
            }
            Err(AdmissionError::UnknownType) => {
                prop_assert!(word(bytes, 0).is_none_or(|kind| !TYPES.contains(&kind)));
                Ok(false)
            }
            Err(AdmissionError::WrongLength { length, .. }) => {
                prop_assert_eq!(length, bytes.len());
                Ok(false)
            }
            Err(AdmissionError::TooManyRecords { count }) => {
                prop_assert!(count > MAX_RECORDS as u64);
                Ok(false)
            }
            Err(AdmissionError::Reserved) => Ok(false),
            Err(error) => {
                prop_assert!(false, "decoding returned {error:?}");
                Ok(false)
            }
        }
    }

    /// A word biased to the small values the layouts give meaning to.
    fn small_word() -> impl Strategy<Value = u64> {
        prop_oneof![
            3 => 0u64..=MAX_RECORDS as u64 + 1,
            1 => prop::sample::select(&TYPES[..]),
            1 => (1u64..=9, any::<u32>()).prop_map(|(kind, layout)| kind | u64::from(layout) << 8),
            1 => (any::<u8>(), 0u64..=5).prop_map(|(lane, capability)| u64::from(lane) | capability << 8),
            2 => any::<u64>(),
        ]
    }

    fn to_bytes(words: Vec<u64>) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    /// The words of a record, each shaped like its field (kind and layout,
    /// lane and capability) or, now and then, anything.
    fn record_words() -> impl Strategy<Value = Vec<u64>> {
        let field = |shaped: BoxedStrategy<u64>| prop_oneof![7 => shaped, 1 => any::<u64>()];
        (
            field(any::<u64>().boxed()),
            field((0u64..=3).boxed()),
            field(
                (0u64..=10, 0u64..=3)
                    .prop_map(|(kind, layout)| kind | layout << 8)
                    .boxed(),
            ),
            any::<[u64; 3]>(),
            field(
                (0u64..=4, 0u64..=6)
                    .prop_map(|(lane, capability)| lane | capability << 8)
                    .boxed(),
            ),
            field((0u64..=2).boxed()),
        )
            .prop_map(
                |(region, export, kind, [length, generation, identity], lane, index)| {
                    vec![
                        region, export, kind, length, generation, identity, lane, index,
                    ]
                },
            )
    }

    /// Any bytes up to a word past the largest message; or words with a
    /// known type first, of any count, of the type's fixed count, or (for
    /// `Admitted`, `Manifest` and `ToolAdmitted`) with a record count and
    /// that many record-shaped records.
    fn input() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            1 => prop::collection::vec(any::<u8>(), 0..=MAX_MESSAGE_LENGTH + 8),
            1 => (
                prop::sample::select(&TYPES[..]),
                prop::collection::vec(small_word(), 0..=8),
            )
                .prop_map(|(kind, rest)| to_bytes(core::iter::once(kind).chain(rest).collect())),
            2 => prop::sample::select(
                &[
                    (HELLO, 2),
                    (FETCH, 2),
                    (DETACH, 1),
                    (LEAVE, 0),
                    (TOOL_HELLO, 1),
                    (REGION, 2),
                    (REFUSED, 2),
                ][..],
            )
                .prop_flat_map(|(kind, count)| {
                    prop::collection::vec(small_word(), count).prop_map(move |rest| {
                        to_bytes(core::iter::once(kind).chain(rest).collect())
                    })
                }),
            4 => (
                prop::sample::select(&[ADMITTED, MANIFEST, TOOL_ADMITTED][..]),
                prop::collection::vec(prop_oneof![3 => 1u64..=8, 1 => 0u64..=0], 6),
                prop::collection::vec(record_words(), 0..=MAX_RECORDS),
            )
                .prop_map(|(kind, header, records)| {
                    let header = &header[..match kind {
                        ADMITTED => 4,
                        MANIFEST => 6,
                        _ => 3,
                    }];
                    to_bytes(
                        core::iter::once(kind)
                            .chain(header.iter().copied())
                            .chain(core::iter::once(records.len() as u64))
                            .chain(records.into_iter().flatten())
                            .collect(),
                    )
                }),
        ]
    }

    fn record(nonzero: bool) -> impl Strategy<Value = Record> {
        let kind = prop::sample::select(
            &[
                RegionKind::CommandRing,
                RegionKind::Broadcast,
                RegionKind::Counters,
                RegionKind::LogBuffer,
                RegionKind::ClientCounters,
                RegionKind::ErrorLog,
                RegionKind::LossReport,
                RegionKind::Journal,
                RegionKind::TraceMirror,
                RegionKind::ConflationTable,
                RegionKind::GuardAudit,
                RegionKind::GuardRegion,
                RegionKind::OutcomeRing,
                RegionKind::ConsumedCell,
            ][..],
        );
        let capability = prop_oneof![
            Just(Capability::None),
            any::<u64>().prop_map(|cell| Capability::RequiredSubscriber { cell }),
            any::<u64>().prop_map(|cell| Capability::OptionalSubscriber { cell }),
            any::<u64>().prop_map(|cell| Capability::ObserverSubscriber { cell }),
            Just(Capability::ExclusivePublication),
            any::<u64>().prop_map(|slot| Capability::ConcurrentPublication { slot }),
        ];
        let export = if nonzero {
            (1..=u64::MAX).boxed()
        } else {
            prop_oneof![1..=u64::MAX, Just(0u64)].boxed()
        };
        (
            any::<u64>(),
            export,
            kind,
            any::<u32>(),
            any::<[u64; 2]>(),
            any::<(i32, i32, u8)>(),
            capability,
        )
            .prop_map(
                |(
                    region,
                    export,
                    kind,
                    layout,
                    [structure_length, generation],
                    (stream_id, session_id, lane),
                    capability,
                )| Record {
                    region,
                    export,
                    kind,
                    layout,
                    structure_length,
                    generation,
                    stream_id,
                    session_id,
                    lane,
                    capability,
                    // Set with a publication's capability, for odd lanes:
                    // both values of the bit round-trip.
                    allow_unconnected: capability.is_publication() && lane % 2 == 1,
                },
            )
    }

    /// A message; `valid` keeps every value decodable (nonzero where the
    /// layout requires it, at most [`MAX_RECORDS`] records), otherwise
    /// zeros and long manifests are frequent.
    fn message(valid: bool) -> impl Strategy<Value = Message> {
        let id = move || {
            if valid {
                (1..=u64::MAX).boxed()
            } else {
                prop_oneof![1..=u64::MAX, Just(0u64)].boxed()
            }
        };
        let records = move || {
            let most = if valid { MAX_RECORDS } else { MAX_RECORDS + 2 };
            prop::collection::vec(record(valid), 0..=most)
        };
        prop_oneof![
            any::<u64>().prop_map(|version| Message::Hello { version }),
            (id(), any::<u64>()).prop_map(|(fetch, key)| Message::Fetch { fetch, key }),
            id().prop_map(|export| Message::Detach { export }),
            Just(Message::Leave),
            (any::<u128>(), any::<(u64, u64)>(), records()).prop_map(
                |(instance, (version, client), records)| Message::Admitted {
                    instance,
                    version,
                    client,
                    records,
                }
            ),
            // A valid manifest follows the identity rule: journal records
            // only, with zero stream registration and incarnation, or no
            // journal record.
            (
                id(),
                any::<(u64, u64)>(),
                id(),
                id(),
                records(),
                any::<bool>(),
                any::<u64>()
            )
                .prop_map(
                    move |(
                        fetch,
                        (key, registration),
                        stream_registration,
                        incarnation,
                        mut records,
                        journal,
                        base,
                    )| {
                        // The binding's kinds appear only in a guarded
                        // grant, whose shape a unit test covers.
                        if valid {
                            for record in &mut records {
                                if matches!(
                                    record.kind,
                                    RegionKind::GuardRegion
                                        | RegionKind::OutcomeRing
                                        | RegionKind::ConsumedCell
                                ) {
                                    record.kind = RegionKind::LogBuffer;
                                }
                            }
                        }
                        let positioned = !records.is_empty()
                            && records
                                .iter()
                                .all(|record| record.kind == RegionKind::LogBuffer);
                        let base = match (valid, positioned) {
                            (true, true) => base >> 1,
                            (true, false) => 0,
                            (false, _) => base,
                        };
                        let (stream_registration, incarnation, base) =
                            if valid && journal && !records.is_empty() {
                                for record in &mut records {
                                    record.kind = RegionKind::Journal;
                                }
                                (0, 0, 0)
                            } else {
                                if valid {
                                    for record in &mut records {
                                        if record.kind == RegionKind::Journal {
                                            record.kind = RegionKind::LogBuffer;
                                        }
                                    }
                                }
                                (stream_registration, incarnation, base)
                            };
                        Message::Manifest {
                            fetch,
                            key,
                            registration,
                            stream_registration,
                            incarnation,
                            base,
                            records,
                        }
                    }
                ),
            any::<(u64, u64)>().prop_map(|(fetch, index)| Message::Region { fetch, index }),
            (any::<u64>(), id()).prop_map(|(fetch, code)| Message::Refused { fetch, code }),
            any::<u64>().prop_map(|version| Message::ToolHello { version }),
            // A valid tool record carries capability none; otherwise any
            // capability, which the encoder must refuse.
            (any::<u128>(), any::<u64>(), records()).prop_map(
                move |(instance, version, mut records)| {
                    if valid {
                        for record in &mut records {
                            record.capability = Capability::None;
                            // Carried with a publication's capability only.
                            record.allow_unconnected = false;
                        }
                    }
                    Message::ToolAdmitted {
                        instance,
                        version,
                        records,
                    }
                }
            ),
        ]
    }

    proptest! {
        #[test]
        fn any_datagram_is_refused_or_canonical(bytes in input()) {
            check_decoded(&bytes)?;
        }

        #[test]
        fn messages_round_trip_and_resist_mutation(
            message in message(true),
            flip in any::<prop::sample::Index>(),
            mask in 1u8..=255,
            cut in any::<prop::sample::Index>(),
            extra in prop::collection::vec(any::<u8>(), 1..=16),
        ) {
            let bytes = encoded(&message).unwrap();
            prop_assert!(bytes.len() <= MAX_MESSAGE_LENGTH);
            prop_assert_eq!(Message::decode(&bytes).unwrap(), message.clone());
            prop_assert!(check_decoded(&bytes)?);
            let mut short = vec![0u8; bytes.len() - 1];
            prop_assert_eq!(
                message.encode(&mut short),
                Err(AdmissionError::BufferTooShort {
                    required: bytes.len(),
                    available: bytes.len() - 1,
                })
            );

            let mut flipped = bytes.clone();
            flipped[flip.index(bytes.len())] ^= mask;
            check_decoded(&flipped)?;

            // The type fixes the length (with the record count, which the
            // bytes keep): a prefix or an extension is refused.
            prop_assert!(!check_decoded(&bytes[..cut.index(bytes.len())])?);
            let mut longer = bytes.clone();
            longer.extend_from_slice(&extra);
            prop_assert!(!check_decoded(&longer)?);
        }

        /// What encodes decodes to itself: the encoder refuses exactly the
        /// values the decoder could not return.
        #[test]
        fn an_encodable_message_decodes_to_itself(message in message(false)) {
            match encoded(&message) {
                Ok(bytes) => {
                    prop_assert_eq!(Message::decode(&bytes).unwrap(), message);
                }
                Err(AdmissionError::Reserved) => {}
                Err(AdmissionError::TooManyRecords { count }) => {
                    prop_assert!(count > MAX_RECORDS as u64);
                }
                Err(error) => prop_assert!(false, "encoding returned {error:?}"),
            }
        }

        /// A `Hello` of any version, and of any later layout that keeps its
        /// first two words, yields its version.
        #[test]
        fn hello_version_reads_any_hello(
            version in any::<u64>(),
            rest in prop::collection::vec(any::<u8>(), 0..=64),
        ) {
            let bytes = encoded(&Message::Hello { version }).unwrap();
            prop_assert_eq!(hello_version(&bytes), Some(version));
            let mut later = bytes[..16].to_vec();
            later.extend_from_slice(&rest);
            prop_assert_eq!(hello_version(&later), Some(version));
            prop_assert_eq!(hello_version(&bytes[..15]), None);
            prop_assert_eq!(tool_hello_version(&later), None);
        }

        /// A `ToolHello` of any version, and of any later layout that keeps
        /// its first two words, yields its version; it is never a `Hello`.
        #[test]
        fn tool_hello_version_reads_any_tool_hello(
            version in any::<u64>(),
            rest in prop::collection::vec(any::<u8>(), 0..=64),
        ) {
            let bytes = encoded(&Message::ToolHello { version }).unwrap();
            prop_assert_eq!(tool_hello_version(&bytes), Some(version));
            prop_assert_eq!(hello_version(&bytes), None);
            let mut later = bytes[..16].to_vec();
            later.extend_from_slice(&rest);
            prop_assert_eq!(tool_hello_version(&later), Some(version));
            prop_assert_eq!(tool_hello_version(&bytes[..15]), None);
        }
    }
}
