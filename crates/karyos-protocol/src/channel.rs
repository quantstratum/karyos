// SPDX-License-Identifier: Apache-2.0

//! Channel URIs (SPEC.md §5, "Channel URIs"; `quantstratum-docs:
//! karyos/design/driver-network-agents.md` §4.1, decision DN-5): the
//! validated configuration of a stream's channel.
//!
//! ```text
//! karyos:ipc[?key=value|key=value...]
//! karyos:udp?key=value|key=value...
//! ```
//!
//! [`ChannelConfig::parse`] reads a URI on the control path into a
//! [`ChannelConfig`]. Every parameter is checked: an unknown, repeated,
//! empty or malformed parameter, a parameter that does not apply to the
//! channel, and a missing or ambiguous destination are typed errors, so a
//! misspelt option is never ignored. The work is bounded by
//! [`MAX_URI_LENGTH`]. Nothing here opens a socket or resolves a name: an
//! interface is kept as an address or a name for the driver to resolve.
//!
//! The grammar, and the rules every new key follows (owner decisions of
//! 2026-10-21, "Common URI rule"), are recorded in `CHANNEL-URI.md` beside
//! this crate's manifest. [`parse_duration`] is the duration grammar new
//! keys use.
//!
//! The `trusted` and `encrypted` protection classes parse; `authenticated`
//! is refused with [`ChannelError::SecurityUnsupported`] until its
//! capability gate passes. An `encrypted` channel (ADR-0114) names its
//! channel key, its receiver's pairwise key and that receiver, serves one
//! unicast receiver and takes `mtu` at most 1408; multicast and every
//! multi-receiver form are refused at parse.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::frame::{Flags, Lane};
use crate::sizing::{FragmentPlan, TermLength};

/// The longest URI accepted, in bytes.
pub const MAX_URI_LENGTH: usize = 2048;
/// The largest MTU a channel may configure: jumbo frames up to 8 KiB
/// (SPEC.md §5).
pub const MAX_CHANNEL_MTU: u32 = 8192;
/// The largest MTU an `encrypted` channel may configure (ADR-0114
/// sections 6 and 11): the plaintext bound of its usage budgets.
pub const MAX_ENCRYPTED_MTU: u32 = 1408;
/// The most redundant paths of one channel (network-sessions.md S5,
/// `max_paths`).
pub const MAX_PATHS: usize = 4;
/// The most destinations a URI lists; the driver's `max_destinations`
/// may be lower.
pub const MAX_URI_DESTINATIONS: usize = 64;
/// The longest guard name, in bytes (as the driver's guard registry).
pub const MAX_GUARD_NAME: usize = 64;
/// The longest interface name, in bytes (`IFNAMSIZ - 1` on Linux).
pub const MAX_INTERFACE_NAME: usize = 15;

/// Why a channel URI was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ChannelError {
    /// The URI is longer than [`MAX_URI_LENGTH`].
    #[error("channel URI of {length} bytes exceeds {MAX_URI_LENGTH}")]
    TooLong {
        /// Its length in bytes.
        length: usize,
    },
    /// The URI is not `karyos:ipc` or `karyos:udp`.
    #[error("unknown channel scheme or media")]
    UnknownMedia,
    /// A parameter is not `key=value`, or its value is empty.
    #[error("malformed parameter `{parameter}`")]
    Malformed {
        /// The offending parameter text.
        parameter: String,
    },
    /// The key is not a channel parameter.
    #[error("unknown parameter `{key}`")]
    UnknownParameter {
        /// The key.
        key: String,
    },
    /// The key appears twice.
    #[error("parameter `{key}` repeated")]
    Repeated {
        /// The key.
        key: &'static str,
    },
    /// The parameter does not apply to this channel.
    #[error("parameter `{key}` does not apply to this channel")]
    NotApplicable {
        /// The key.
        key: &'static str,
    },
    /// The value is outside the parameter's syntax or range.
    #[error("invalid value for `{key}`: {reason}")]
    InvalidValue {
        /// The key.
        key: &'static str,
        /// What is wrong.
        reason: &'static str,
    },
    /// A UDP channel names no destination, or more than one of
    /// `endpoint`, `group`, `destinations` and `control`.
    #[error("a udp channel needs exactly one of endpoint, group, destinations or control")]
    Destination,
    /// Two parameters contradict each other.
    #[error("`{first}` conflicts with `{second}`")]
    Conflict {
        /// One parameter.
        first: &'static str,
        /// The other.
        second: &'static str,
    },
    /// A protection class this build does not implement yet.
    #[error("security `{class}` is not supported yet")]
    SecurityUnsupported {
        /// The requested class.
        class: &'static str,
    },
    /// A duration value outside the duration grammar (`CHANNEL-URI.md`).
    #[error("invalid duration for `{key}`: {error}")]
    InvalidDuration {
        /// The key.
        key: &'static str,
        /// What is wrong.
        error: DurationError,
    },
}

impl ChannelError {
    /// A stable code for the error, never reused: the detail of a client's
    /// `InvalidChannel` refusal (`cnc::ErrorCode`, W5).
    #[must_use]
    pub const fn code(&self) -> u64 {
        match self {
            Self::TooLong { .. } => 1,
            Self::UnknownMedia => 2,
            Self::Malformed { .. } => 3,
            Self::UnknownParameter { .. } => 4,
            Self::Repeated { .. } => 5,
            Self::NotApplicable { .. } => 6,
            Self::InvalidValue { .. } => 7,
            Self::Destination => 8,
            Self::Conflict { .. } => 9,
            Self::SecurityUnsupported { .. } => 10,
            Self::InvalidDuration { .. } => 11,
        }
    }
}

/// Why a duration was refused (`CHANNEL-URI.md`, "Durations").
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DurationError {
    /// No unit follows the number.
    #[error("no unit: use ns, us, ms or s")]
    MissingUnit,
    /// The text after the number is not `ns`, `us`, `ms` or `s`.
    #[error("unknown unit: use ns, us, ms or s")]
    UnknownUnit,
    /// The number is missing, signed or has a leading zero.
    #[error("not a decimal integer")]
    NotDecimal,
    /// The duration does not fit in a `u64` of nanoseconds.
    #[error("overflows 2^64 - 1 nanoseconds")]
    Overflow,
}

/// Parses a duration of the URI grammar: a decimal integer and a unit of
/// `ns`, `us`, `ms` or `s`, converted to nanoseconds with checked
/// arithmetic. A key checks its own range on the result.
///
/// # Errors
///
/// A [`DurationError`] when the unit is missing or unknown, the number is
/// not a canonical decimal, or the value overflows a `u64` of nanoseconds.
pub fn parse_duration(value: &str) -> Result<Duration, DurationError> {
    let digits = value.bytes().take_while(u8::is_ascii_digit).count();
    let (number, unit) = value
        .split_at_checked(digits)
        .ok_or(DurationError::NotDecimal)?;
    if number.is_empty() || (number.len() > 1 && number.starts_with('0')) {
        return Err(DurationError::NotDecimal);
    }
    let nanos_per_unit: u64 = match unit {
        "" => return Err(DurationError::MissingUnit),
        "ns" => 1,
        "us" => 1_000,
        "ms" => 1_000_000,
        "s" => 1_000_000_000,
        _ => return Err(DurationError::UnknownUnit),
    };
    // `number` is all digits, so the only way it fails to parse is size.
    let count: u64 = number.parse().map_err(|_| DurationError::Overflow)?;
    count
        .checked_mul(nanos_per_unit)
        .map(Duration::from_nanos)
        .ok_or(DurationError::Overflow)
}

/// A local interface: an address to bind, or a name the driver resolves.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Interface {
    /// An address.
    Address(IpAddr),
    /// An interface name.
    Name(String),
}

/// Message tracing (SPEC.md §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Trace {
    /// No tracing.
    #[default]
    Off,
    /// One message in `n`.
    Sampled(u32),
    /// Every message.
    All,
}

/// Flow control of a multicast or multi-destination channel (SPEC.md §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FlowControl {
    /// The slowest receiver bounds the sender.
    Min,
    /// The fastest receiver bounds the sender.
    Max,
    /// Receivers of the tagged group bound the sender.
    Tagged(u64),
}

/// A channel's protection class (SPEC.md §5). [`Security::Trusted`] and
/// [`Security::Encrypted`] parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Security {
    /// No authentication or encryption.
    #[default]
    Trusted,
    /// The authenticated class (ADR-0086, ADR-0107, ADR-0118) with the key
    /// ids and the single unicast receiver it binds at admission. Built in
    /// code by tests only (`test-hooks`, karyos#648): `security=authenticated`
    /// is still refused at parse until its capability gate passes.
    #[cfg(feature = "test-hooks")]
    Authenticated(AuthenticatedChannel),
    /// The encrypted class (ADR-0114, AES-256-GCM-SIV, `profile_id` 16)
    /// with the key ids and the single unicast receiver it binds at
    /// admission.
    Encrypted(EncryptedChannel),
}

/// What an encrypted channel binds at publication and subscription
/// admission (ADR-0114 section 4a): the key ids each side must find valid
/// in its driver's key store, both `profile_id` 16, and the one unicast
/// receiver the channel serves. No `key_id` travels on the wire; these
/// select the files by configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedChannel {
    /// The channel key (`purpose=channel`, `profile_id` 16): the `IKM` of
    /// every derivation of ADR-0114 section 4 (`channel-key`).
    pub channel_key_id: u32,
    /// The receiver's pairwise key (`purpose=pairwise`, `profile_id` 16):
    /// the trailer of every domain 4 and 6 datagram (`pairwise-key`).
    pub pairwise_key_id: u32,
    /// The single unicast receiver: the pairwise key's `receiver_id`
    /// (`receiver-id`), nonzero.
    pub receiver_id: u64,
}

/// What an authenticated channel binds at publication and subscription
/// admission (karyos#648; ADR-0086 sections 4, 6 and 7, ADR-0118): the
/// key ids each side must find valid in its driver's key store, and the
/// one unicast receiver the channel serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedChannel {
    /// The channel key (`purpose=channel`): SETUP proofs and the session's
    /// DATA.
    pub channel_key_id: u32,
    /// The channel's operator-assigned identity: the channel key file's
    /// `channel_id` must name it (wire-key-files.md section 2.2).
    pub channel_id: u64,
    /// The publishing driver of the pair: the pairwise key file's
    /// `publisher_id` must name it.
    pub publisher_id: u64,
    /// The receiver's pairwise key (`purpose=pairwise`): RSP_SETUP and the
    /// receiver's controls.
    pub pairwise_key_id: u32,
    /// The single unicast receiver: the pairwise key's `receiver_id` and the
    /// subscription's receiver identity.
    pub receiver_id: u64,
    /// The abort and guard authority of the publication (ADR-0118 (a): only
    /// the authority that guards a publication may abort it); `None` when
    /// nothing may abort it remotely.
    pub authority: Option<ChannelAuthority>,
}

/// The abort and guard authority an authenticated channel names
/// (ADR-0118; design guards-and-abort.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelAuthority {
    /// Its key: `authority-signing` at the publisher, which signs the
    /// publication's aborts, and `authority-public` at the receiver.
    pub key_id: u32,
    /// The `authority_id` its key file names.
    pub authority_id: u64,
    /// The guard it serves for this publication, nonzero; its file must
    /// list it.
    pub guard_id: u64,
    /// Its guard control endpoint: the only source of its signed controls,
    /// whose verify budget the receiver reserves at admission.
    pub control: SocketAddr,
    /// At a publisher holding the authority's public key (a remotely
    /// guarded publication): the receiver id it follows the guard as, its
    /// entry in the authority's configuration, nonzero. Unused where the
    /// publisher holds the authority's signing key.
    pub follower_id: u64,
}

/// How a multi-destination channel learns its receivers (ADR-0056).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ControlMode {
    /// Only the configured destinations.
    Manual,
    /// Receivers register at the control endpoint.
    Dynamic,
}

/// Where a UDP channel sends.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Destination {
    /// One unicast receiver.
    Unicast(SocketAddr),
    /// A multicast group, with its optional TTL.
    Multicast {
        /// Group address and port.
        group: SocketAddr,
        /// Hop limit, 1 to 255.
        ttl: Option<u8>,
    },
    /// Multi-destination unicast (ADR-0056).
    MultiDestination {
        /// The configured receivers; empty only under `Dynamic`.
        destinations: Vec<SocketAddr>,
        /// The control endpoint where receivers register and report.
        control: Option<SocketAddr>,
        /// How receivers are learned.
        mode: ControlMode,
    },
    /// Paired unicast paths (owner item 11, karyos#635): one logical
    /// receiver reached over each path, path `i` sending from
    /// `UdpConfig::paths[i]` to `endpoints[i]`. A driver serves it where
    /// its path sockets are isolated (karyos#624, karyos#1043) and refuses
    /// it elsewhere.
    PairedPaths {
        /// Each path's receiver endpoint, in the order of `paths`.
        endpoints: Vec<SocketAddr>,
    },
}

/// Parameters every channel accepts. `None` keeps the stream's or the
/// driver's default.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CommonConfig {
    /// Frame bytes per datagram.
    pub mtu: Option<u32>,
    /// Term partition size.
    pub term_length: Option<TermLength>,
    /// Priority lanes, 1 to 4.
    pub lanes: Option<u8>,
    /// The guard the publication obeys: 1 to 64 bytes of `[A-Za-z0-9._-]`.
    pub guard: Option<String>,
    /// Message tracing.
    pub trace: Trace,
}

/// A UDP channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpConfig {
    /// Where it sends.
    pub destination: Destination,
    /// The local interface to bind; `None` for the default route.
    pub interface: Option<Interface>,
    /// Redundant paths, one interface each (SPEC.md §7.2); empty for one
    /// path.
    pub paths: Vec<Interface>,
    /// `false` for gap-tolerant delivery without NAKs.
    pub reliable: bool,
    /// Flow control; multicast and multi-destination only: the strategy of
    /// a publication's receivers (owner item 7). A driver refuses
    /// `tagged:0`, which names no group.
    pub flow_control: Option<FlowControl>,
    /// The protection class.
    pub security: Security,
    /// How far below its sent position a reliable publication keeps its
    /// lanes for repair, in bytes (`retransmit-window`, owner item 63):
    /// positive and a multiple of 32; at most half the term, which the
    /// URI checks when it gives `term-length` and the driver checks at
    /// channel creation otherwise. `None` keeps the driver's setting,
    /// whose default is half a term.
    pub retransmit_window: Option<u32>,
    /// Each path's NAK control group (`nak-control`, owner item 8): one
    /// per path in the order of `paths`, or one for a channel without
    /// `paths`; multicast only. Empty keeps the driver's control group
    /// table as configured. The driver enters each into that one table,
    /// which refuses a conflicting mapping.
    pub nak_control: Vec<SocketAddr>,
    /// How long a removed publication keeps answering status messages and
    /// NAKs and repeating its EOS (`linger`, owner item 16): 0 to
    /// [`MAX_LINGER`]. `None` keeps the driver's `publication_linger`,
    /// whose default is 5 s. A subscription does not use it.
    pub linger: Option<Duration>,
    /// How long a receiver waits for a gap's datagram on another path
    /// before it NAKs or seals it, and how long the sender absorbs a NAK's
    /// copy on another path (`path-skew`, owner item 17): 0 to
    /// [`MAX_PATH_SKEW`]. Both sides of the channel use it; `None` keeps
    /// the driver's settings, whose default is 1 ms.
    pub path_skew: Option<Duration>,
    /// The `etf` declaration of a timed publication on the `etf` route
    /// (`etf-priority` and `etf-delta`, ADR-0109 point 2): where the
    /// deployment configured the `etf` leaf that releases its timed
    /// datagrams. Unicast `endpoint` with `interface` only; `None` for
    /// every other channel.
    pub etf: Option<EtfDeclaration>,
}

/// A channel's `etf` declaration (ADR-0109 point 2). Karyos changes no
/// qdisc and cannot probe one: the deployment maps `priority` on the
/// channel's `interface` to a TX queue holding an `etf` leaf with
/// `clockid CLOCK_TAI`, no deadline mode, and this `delta`, which the
/// driver checks is at most the publication's declared advance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EtfDeclaration {
    /// The `SO_PRIORITY` the interface's root qdisc maps to the leaf's
    /// queue (`etf-priority`).
    pub priority: u32,
    /// The leaf's `delta` (`etf-delta`): positive, below 2^32 ns.
    pub delta: Duration,
}

/// The longest `linger` (owner item 16): 60 s, the driver's own bound.
pub const MAX_LINGER: Duration = Duration::from_secs(60);

/// The longest `path-skew` (owner item 17): 1 s, the driver's own bound.
pub const MAX_PATH_SKEW: Duration = Duration::from_secs(1);

/// A validated channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelConfig {
    /// The media and its parameters.
    pub media: Media,
    /// Parameters every channel accepts.
    pub common: CommonConfig,
}

/// A channel's media.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[allow(
    clippy::large_enum_variant,
    reason = "a channel is parsed once at admission and never held in bulk; boxing `Udp` would change the public pattern every caller matches"
)]
pub enum Media {
    /// Shared memory on this host.
    Ipc,
    /// UDP.
    Udp(UdpConfig),
}

/// The parameters, as their keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Key {
    Endpoint,
    Group,
    Interface,
    Mtu,
    TermLength,
    Reliable,
    Paths,
    Lanes,
    Guard,
    Trace,
    Fc,
    Security,
    Destinations,
    Control,
    ControlMode,
    Ttl,
    RetransmitWindow,
    RequireAbortAck,
    NakControl,
    Linger,
    PathSkew,
    EtfPriority,
    EtfDelta,
    ChannelKeyId,
    PairwiseKeyId,
    ReceiverId,
}

const KEYS: [(&str, Key); 26] = [
    ("endpoint", Key::Endpoint),
    ("group", Key::Group),
    ("interface", Key::Interface),
    ("mtu", Key::Mtu),
    ("term-length", Key::TermLength),
    ("reliable", Key::Reliable),
    ("paths", Key::Paths),
    ("lanes", Key::Lanes),
    ("guard", Key::Guard),
    ("trace", Key::Trace),
    ("fc", Key::Fc),
    ("security", Key::Security),
    ("destinations", Key::Destinations),
    ("control", Key::Control),
    ("control-mode", Key::ControlMode),
    ("ttl", Key::Ttl),
    ("retransmit-window", Key::RetransmitWindow),
    ("require-abort-ack", Key::RequireAbortAck),
    ("nak-control", Key::NakControl),
    ("linger", Key::Linger),
    ("path-skew", Key::PathSkew),
    ("etf-priority", Key::EtfPriority),
    ("etf-delta", Key::EtfDelta),
    ("channel-key", Key::ChannelKeyId),
    ("pairwise-key", Key::PairwiseKeyId),
    ("receiver-id", Key::ReceiverId),
];

/// Whether `name` is kebab-case (`CHANNEL-URI.md` section 2): words of
/// lower-case letters and digits, each starting with a letter, joined by
/// single hyphens.
const fn kebab_case(name: &str) -> bool {
    let mut rest = name.as_bytes();
    let mut previous = b'-';
    let mut first = true;
    while let [byte, tail @ ..] = rest {
        let valid = match *byte {
            b'a'..=b'z' => true,
            b'0'..=b'9' => !first && previous != b'-',
            b'-' => previous != b'-',
            _ => false,
        };
        if !valid {
            return false;
        }
        previous = *byte;
        first = false;
        rest = tail;
    }
    !first && previous != b'-'
}

/// Whether two names are the same bytes.
const fn same(left: &str, right: &str) -> bool {
    let (mut left, mut right) = (left.as_bytes(), right.as_bytes());
    loop {
        match (left, right) {
            ([], []) => return true,
            ([one, left_tail @ ..], [other, right_tail @ ..]) if *one == *other => {
                left = left_tail;
                right = right_tail;
            }
            _ => return false,
        }
    }
}

/// Every key is kebab-case and has one spelling: no name and no [`Key`]
/// appears twice in [`KEYS`].
const fn keys_follow_the_naming_rule() -> bool {
    let mut rest: &[(&str, Key)] = &KEYS;
    while let [(name, key), tail @ ..] = rest {
        if !kebab_case(name) {
            return false;
        }
        let mut later = tail;
        while let [(other_name, other_key), later_tail @ ..] = later {
            if same(name, other_name) || *key as u8 == *other_key as u8 {
                return false;
            }
            later = later_tail;
        }
        rest = tail;
    }
    true
}

// The common URI rule's naming obligation, checked when the crate builds.
const _: () = assert!(
    keys_follow_the_naming_rule(),
    "a channel URI key is not kebab-case or has two spellings"
);

impl Key {
    fn name(self) -> &'static str {
        KEYS.iter()
            .find(|(_, key)| *key == self)
            .map_or("?", |(name, _)| name)
    }

    /// Whether the key applies to every channel, `ipc` included.
    fn common(self) -> bool {
        matches!(
            self,
            Key::Mtu | Key::TermLength | Key::Lanes | Key::Guard | Key::Trace
        )
    }
}

impl ChannelConfig {
    /// Checks the channel for a publication: an `endpoint` on port 0,
    /// which only a unicast subscription admits (an ephemeral port, owner
    /// decision item 26), is refused. Groups, destinations and `control`
    /// refuse port 0 at parse time already.
    ///
    /// # Errors
    ///
    /// [`ChannelError::InvalidValue`] for `endpoint` on port 0.
    pub fn check_publication(&self) -> Result<(), ChannelError> {
        match &self.media {
            Media::Udp(UdpConfig {
                destination: Destination::Unicast(address),
                ..
            }) if address.port() == 0 => Err(invalid(
                Key::Endpoint,
                "port 0, which only a subscription admits",
            )),
            _ => Ok(()),
        }
    }

    /// Parses and validates a channel URI.
    ///
    /// # Errors
    ///
    /// A [`ChannelError`] naming the first problem found.
    pub fn parse(uri: &str) -> Result<Self, ChannelError> {
        if uri.len() > MAX_URI_LENGTH {
            return Err(ChannelError::TooLong { length: uri.len() });
        }
        let rest = uri
            .strip_prefix("karyos:")
            .ok_or(ChannelError::UnknownMedia)?;
        let (media, query) = rest
            .split_once('?')
            .map_or((rest, None), |(m, q)| (m, Some(q)));
        let udp = match media {
            "ipc" => false,
            "udp" => true,
            _ => return Err(ChannelError::UnknownMedia),
        };
        let mut values: [Option<&str>; KEYS.len()] = [None; KEYS.len()];
        if let Some(query) = query {
            for parameter in query.split('|') {
                let malformed = || ChannelError::Malformed {
                    parameter: parameter.to_owned(),
                };
                let (name, value) = parameter.split_once('=').ok_or_else(malformed)?;
                if value.is_empty() {
                    return Err(malformed());
                }
                let (index, key) = KEYS
                    .iter()
                    .enumerate()
                    .find(|(_, (known, _))| *known == name)
                    .map(|(index, (_, key))| (index, *key))
                    .ok_or_else(|| ChannelError::UnknownParameter {
                        key: name.to_owned(),
                    })?;
                if !udp && !key.common() {
                    return Err(ChannelError::NotApplicable { key: key.name() });
                }
                let slot = values.get_mut(index).ok_or(ChannelError::UnknownMedia)?;
                if slot.replace(value).is_some() {
                    return Err(ChannelError::Repeated { key: key.name() });
                }
            }
        }
        let get = |key: Key| {
            KEYS.iter()
                .position(|(_, known)| *known == key)
                .and_then(|index| values.get(index).copied().flatten())
        };
        let common = CommonConfig {
            mtu: get(Key::Mtu).map(parse_mtu).transpose()?,
            term_length: get(Key::TermLength).map(parse_term_length).transpose()?,
            lanes: get(Key::Lanes).map(parse_lanes).transpose()?,
            guard: get(Key::Guard).map(parse_guard).transpose()?,
            trace: get(Key::Trace)
                .map(parse_trace)
                .transpose()?
                .unwrap_or_default(),
        };
        let media = if udp {
            let udp = parse_udp(&get)?;
            if let (Some(window), Some(term)) = (udp.retransmit_window, common.term_length)
                && u64::from(window) > u64::from(term.get()) / 2
            {
                return Err(invalid(
                    Key::RetransmitWindow,
                    "above half of `term-length`",
                ));
            }
            Media::Udp(udp)
        } else {
            Media::Ipc
        };
        Ok(Self { media, common })
    }
}

fn invalid(key: Key, reason: &'static str) -> ChannelError {
    ChannelError::InvalidValue {
        key: key.name(),
        reason,
    }
}

fn parse_udp<'a>(get: &impl Fn(Key) -> Option<&'a str>) -> Result<UdpConfig, ChannelError> {
    let named = [Key::Endpoint, Key::Group, Key::Destinations, Key::Control]
        .into_iter()
        .filter(|&key| get(key).is_some())
        .count();
    let ttl = get(Key::Ttl)
        .map(|value| {
            value
                .parse::<u8>()
                .ok()
                .filter(|&ttl| ttl >= 1)
                .ok_or_else(|| invalid(Key::Ttl, "an integer from 1 to 255"))
        })
        .transpose()?;
    let mode = get(Key::ControlMode)
        .map(|value| match value {
            "manual" => Ok(ControlMode::Manual),
            "dynamic" => Ok(ControlMode::Dynamic),
            _ => Err(invalid(Key::ControlMode, "`manual` or `dynamic`")),
        })
        .transpose()?;
    // Paired paths (`interface@endpoint` elements) are their own
    // destination form: no other destination key goes with them.
    let paired = get(Key::Paths).is_some_and(|list| list.contains('@'));
    if paired {
        let other = [Key::Endpoint, Key::Group, Key::Destinations, Key::Control]
            .into_iter()
            .find(|&key| get(key).is_some());
        if let Some(other) = other {
            return Err(ChannelError::Conflict {
                first: Key::Paths.name(),
                second: other.name(),
            });
        }
    } else if get(Key::Paths).is_some() && get(Key::Destinations).is_some() {
        // `destinations` fans out to several receivers, `paths` carries
        // one over several routes: never both (owner item 11).
        return Err(ChannelError::Conflict {
            first: Key::Paths.name(),
            second: Key::Destinations.name(),
        });
    }
    let (paired_paths, destination) = match (
        get(Key::Endpoint),
        get(Key::Group),
        get(Key::Destinations),
        get(Key::Control),
    ) {
        (None, None, None, None) if paired => {
            let (paths, endpoints) = get(Key::Paths)
                .map(parse_paired_paths)
                .transpose()?
                .unwrap_or_default();
            (Some(paths), Destination::PairedPaths { endpoints })
        }
        keys => (None, parse_destination(keys, named, mode, ttl)?),
    };
    let multicast = matches!(destination, Destination::Multicast { .. });
    let multi = matches!(destination, Destination::MultiDestination { .. });
    if ttl.is_some() && !multicast {
        return Err(ChannelError::NotApplicable {
            key: Key::Ttl.name(),
        });
    }
    if mode.is_some() && !multi {
        return Err(ChannelError::NotApplicable {
            key: Key::ControlMode.name(),
        });
    }
    let flow_control = get(Key::Fc).map(parse_fc).transpose()?;
    if flow_control.is_some() && !multicast && !multi {
        return Err(ChannelError::NotApplicable {
            key: Key::Fc.name(),
        });
    }
    let interface = get(Key::Interface)
        .map(|value| parse_interface(Key::Interface, value))
        .transpose()?;
    let paths = match paired_paths {
        Some(paths) => Some(paths),
        None => get(Key::Paths).map(parse_paths).transpose()?,
    }
    .unwrap_or_default();
    // Each path binds its own socket: on port 0 each would get another
    // port, and a sender names one (karyos#656).
    if !paths.is_empty()
        && matches!(&destination, Destination::Unicast(address) if address.port() == 0)
    {
        return Err(ChannelError::Conflict {
            first: Key::Endpoint.name(),
            second: Key::Paths.name(),
        });
    }
    let nak_control = get(Key::NakControl)
        .map(|list| parse_nak_control(list, &destination, paths.len()))
        .transpose()?
        .unwrap_or_default();
    if interface.is_some() && !paths.is_empty() {
        return Err(ChannelError::Conflict {
            first: Key::Interface.name(),
            second: Key::Paths.name(),
        });
    }
    let reliable = get(Key::Reliable)
        .map(|value| match value {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(invalid(Key::Reliable, "`true` or `false`")),
        })
        .transpose()?
        .unwrap_or(true);
    let security = get(Key::Security)
        .map(|value| match value {
            "trusted" => Ok(Security::Trusted),
            "authenticated" => Err(ChannelError::SecurityUnsupported {
                class: "authenticated",
            }),
            "encrypted" => parse_encrypted(get, &destination, &paths).map(Security::Encrypted),
            _ => Err(invalid(
                Key::Security,
                "`trusted`, `authenticated` or `encrypted`",
            )),
        })
        .transpose()?
        .unwrap_or_default();
    if !matches!(security, Security::Encrypted(_))
        && let Some(key) = [Key::ChannelKeyId, Key::PairwiseKeyId, Key::ReceiverId]
            .into_iter()
            .find(|&key| get(key).is_some())
    {
        return Err(ChannelError::NotApplicable { key: key.name() });
    }
    // `require-abort-ack` (owner decision item 8) is defined with the
    // authenticated capability. Until that capability is supported a
    // request requiring it is refused, typed, and never downgraded to a
    // channel without the acknowledgement (#648).
    match get(Key::RequireAbortAck) {
        None | Some("false") => {}
        Some("true") => {
            return Err(ChannelError::SecurityUnsupported {
                class: "authenticated",
            });
        }
        Some(_) => return Err(invalid(Key::RequireAbortAck, "`true` or `false`")),
    }
    let path_skew = get(Key::PathSkew)
        .map(|value| {
            let skew = parse_duration(value).map_err(|error| ChannelError::InvalidDuration {
                key: Key::PathSkew.name(),
                error,
            })?;
            if skew > MAX_PATH_SKEW {
                return Err(invalid(Key::PathSkew, "above 1 s"));
            }
            Ok(skew)
        })
        .transpose()?;
    let retransmit_window = get(Key::RetransmitWindow)
        .map(parse_retransmit_window)
        .transpose()?;
    let linger = get(Key::Linger).map(parse_linger).transpose()?;
    if retransmit_window.is_some() && !reliable {
        return Err(ChannelError::Conflict {
            first: Key::Reliable.name(),
            second: Key::RetransmitWindow.name(),
        });
    }
    let etf = parse_etf(get, &destination, interface.as_ref())?;
    Ok(UdpConfig {
        destination,
        interface,
        paths,
        reliable,
        flow_control,
        security,
        retransmit_window,
        nak_control,
        linger,
        path_skew,
        etf,
    })
}

/// An `encrypted` channel (ADR-0114 sections 4a, 6 and 11): `mtu` at most
/// [`MAX_ENCRYPTED_MTU`], refused first whatever else holds; one unicast
/// `endpoint` (no `group`, `destinations`, `control` or `paths`: v1 binds
/// one receiver, and multicast stays refused); and its three key settings,
/// each required. A nonzero key id is not checked here: the key store
/// refuses an unknown one at admission.
fn parse_encrypted<'a>(
    get: &impl Fn(Key) -> Option<&'a str>,
    destination: &Destination,
    paths: &[Interface],
) -> Result<EncryptedChannel, ChannelError> {
    if get(Key::Mtu)
        .map(parse_mtu)
        .transpose()?
        .is_some_and(|mtu| mtu > MAX_ENCRYPTED_MTU)
    {
        return Err(invalid(Key::Mtu, "above 1408 on an `encrypted` channel"));
    }
    if !matches!(destination, Destination::Unicast(_)) || !paths.is_empty() {
        return Err(invalid(
            Key::Security,
            "`encrypted` on a channel other than one unicast `endpoint`",
        ));
    }
    let id = |key: Key, what: &'static str| -> Result<u64, ChannelError> {
        let value = get(key).ok_or(invalid(key, "required on an `encrypted` channel"))?;
        decimal::<u64>(value)
            .filter(|&id| id != 0)
            .ok_or(invalid(key, what))
    };
    let narrow = |key: Key, id: u64| {
        u32::try_from(id).map_err(|_| invalid(key, "an integer from 1 to 4294967295"))
    };
    Ok(EncryptedChannel {
        channel_key_id: narrow(
            Key::ChannelKeyId,
            id(Key::ChannelKeyId, "an integer from 1 to 4294967295")?,
        )?,
        pairwise_key_id: narrow(
            Key::PairwiseKeyId,
            id(Key::PairwiseKeyId, "an integer from 1 to 4294967295")?,
        )?,
        receiver_id: id(Key::ReceiverId, "an integer from 1 to 18446744073709551615")?,
    })
}

/// The `etf` declaration (ADR-0109 point 2): `etf-priority` and
/// `etf-delta` together, on a unicast `endpoint` with an `interface`
/// address, the one the leaf's interface holds.
fn parse_etf<'a>(
    get: &impl Fn(Key) -> Option<&'a str>,
    destination: &Destination,
    interface: Option<&Interface>,
) -> Result<Option<EtfDeclaration>, ChannelError> {
    let (priority, delta) = match (get(Key::EtfPriority), get(Key::EtfDelta)) {
        (None, None) => return Ok(None),
        (Some(priority), Some(delta)) => (priority, delta),
        (Some(_), None) => {
            return Err(invalid(Key::EtfPriority, "without `etf-delta`"));
        }
        (None, Some(_)) => return Err(invalid(Key::EtfDelta, "without `etf-priority`")),
    };
    if !matches!(destination, Destination::Unicast(_)) {
        return Err(ChannelError::NotApplicable {
            key: Key::EtfPriority.name(),
        });
    }
    if !matches!(interface, Some(Interface::Address(_))) {
        return Err(invalid(Key::EtfPriority, "without an `interface` address"));
    }
    let priority = decimal::<u32>(priority)
        .ok_or_else(|| invalid(Key::EtfPriority, "an integer from 0 to 4294967295"))?;
    let delta = parse_duration(delta).map_err(|error| ChannelError::InvalidDuration {
        key: Key::EtfDelta.name(),
        error,
    })?;
    if delta.is_zero() || delta.as_nanos() > u128::from(u32::MAX) {
        return Err(invalid(Key::EtfDelta, "zero, or not below 2^32 ns"));
    }
    Ok(Some(EtfDeclaration { priority, delta }))
}

/// The destination named by `endpoint`, `group`, `destinations` and
/// `control` (`keys`, in that order), without paired paths.
fn parse_destination(
    keys: (Option<&str>, Option<&str>, Option<&str>, Option<&str>),
    named: usize,
    mode: Option<ControlMode>,
    ttl: Option<u8>,
) -> Result<Destination, ChannelError> {
    Ok(match keys {
        (Some(endpoint), None, None, None) => Destination::Unicast(parse_endpoint(endpoint)?),
        (None, Some(group), None, None) => {
            let group = parse_address(Key::Group, group)?;
            if !group.ip().is_multicast() {
                return Err(invalid(Key::Group, "not a multicast address"));
            }
            Destination::Multicast { group, ttl }
        }
        (None, None, destinations, control) if named > 0 => {
            let destinations = destinations
                .map(|list| {
                    let parsed = list
                        .split(';')
                        .map(|one| parse_unicast(Key::Destinations, one))
                        .collect::<Result<Vec<_>, _>>()?;
                    if parsed.len() > MAX_URI_DESTINATIONS {
                        return Err(invalid(Key::Destinations, "too many destinations"));
                    }
                    if repeats(&parsed) {
                        return Err(invalid(Key::Destinations, "a destination repeats"));
                    }
                    Ok(parsed)
                })
                .transpose()?
                .unwrap_or_default();
            let control = control
                .map(|value| parse_unicast(Key::Control, value))
                .transpose()?;
            let mode = match (mode, control.is_some()) {
                (Some(ControlMode::Dynamic), false) => {
                    return Err(ChannelError::Conflict {
                        first: Key::ControlMode.name(),
                        second: Key::Control.name(),
                    });
                }
                (Some(mode), _) => mode,
                (None, true) => ControlMode::Dynamic,
                (None, false) => ControlMode::Manual,
            };
            if mode == ControlMode::Manual && destinations.is_empty() {
                return Err(ChannelError::Conflict {
                    first: Key::ControlMode.name(),
                    second: Key::Destinations.name(),
                });
            }
            Destination::MultiDestination {
                destinations,
                control,
                mode,
            }
        }
        _ => return Err(ChannelError::Destination),
    })
}

/// An unpaired `paths` value: one to [`MAX_PATHS`] interfaces,
/// `;`-separated, none repeated.
fn parse_paths(list: &str) -> Result<Vec<Interface>, ChannelError> {
    let parsed = list
        .split(';')
        .map(|one| parse_interface(Key::Paths, one))
        .collect::<Result<Vec<_>, _>>()?;
    if parsed.len() > MAX_PATHS {
        return Err(invalid(Key::Paths, "more than 4 paths"));
    }
    if repeats(&parsed) {
        return Err(invalid(Key::Paths, "a path repeats"));
    }
    Ok(parsed)
}

/// A paired `paths` value (owner item 11, karyos#635): one to
/// [`MAX_PATHS`] `interface@socket-address` elements, `;`-separated, every
/// element paired. No interface and no endpoint repeats (compared in
/// canonical form), and every endpoint is unicast, of one address family,
/// on a nonzero port and not unspecified.
fn parse_paired_paths(list: &str) -> Result<(Vec<Interface>, Vec<SocketAddr>), ChannelError> {
    let mut paths = Vec::new();
    let mut endpoints = Vec::new();
    for one in list.split(';') {
        let (interface, endpoint) = one
            .split_once('@')
            .ok_or_else(|| invalid(Key::Paths, "paired and unpaired paths"))?;
        paths.push(parse_interface(Key::Paths, interface)?);
        endpoints.push(parse_unicast(Key::Paths, endpoint)?);
    }
    if paths.len() > MAX_PATHS {
        return Err(invalid(Key::Paths, "more than 4 paths"));
    }
    if repeats(&paths) {
        return Err(invalid(Key::Paths, "a path repeats"));
    }
    if repeats(&endpoints) {
        return Err(invalid(Key::Paths, "an endpoint repeats"));
    }
    if endpoints
        .windows(2)
        .any(|pair| matches!(pair, [a, b] if a.is_ipv4() != b.is_ipv4()))
    {
        return Err(invalid(Key::Paths, "endpoints of two address families"));
    }
    Ok((paths, endpoints))
}

/// Whether an item of `items` appears twice, comparing in the canonical
/// form of [`Canonical`].
fn repeats<T: Canonical>(items: &[T]) -> bool {
    items.iter().enumerate().any(|(index, one)| {
        items
            .iter()
            .take(index)
            .any(|earlier| earlier.canonical() == one.canonical())
    })
}

/// A list element's identity for the repetition rule (`CHANNEL-URI.md`
/// section 3): an IPv4-mapped IPv6 address is the IPv4 address it maps,
/// so one receiver or interface written in two spellings is a repetition.
/// The element itself is kept as written.
trait Canonical {
    /// The form two elements are compared in.
    type Form: PartialEq;
    /// This element in that form.
    fn canonical(&self) -> Self::Form;
}

impl Canonical for SocketAddr {
    type Form = (IpAddr, u16, u32);

    fn canonical(&self) -> Self::Form {
        let scope = match self {
            SocketAddr::V4(_) => 0,
            SocketAddr::V6(v6) => v6.scope_id(),
        };
        (self.ip().to_canonical(), self.port(), scope)
    }
}

impl Canonical for Interface {
    type Form = Interface;

    fn canonical(&self) -> Self::Form {
        match self {
            Interface::Address(address) => Interface::Address(address.to_canonical()),
            Interface::Name(name) => Interface::Name(name.clone()),
        }
    }
}

/// A decimal integer without sign, leading zeros or other characters.
fn decimal<T: std::str::FromStr>(value: &str) -> Option<T> {
    let canonical = !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'));
    canonical.then(|| value.parse().ok()).flatten()
}

fn parse_mtu(value: &str) -> Result<u32, ChannelError> {
    let mtu: u32 = decimal(value).ok_or_else(|| invalid(Key::Mtu, "not a decimal integer"))?;
    if mtu > MAX_CHANNEL_MTU {
        return Err(invalid(Key::Mtu, "above 8192"));
    }
    FragmentPlan::new(mtu, Flags::NONE)
        .map(|_| mtu)
        .map_err(|_| invalid(Key::Mtu, "no room for a frame header and payload"))
}

/// A `retransmit-window` value: a positive `decimal`, a multiple of 32
/// (the frame alignment). Its bound of half a term is checked against the
/// term in force.
fn parse_retransmit_window(value: &str) -> Result<u32, ChannelError> {
    let window: u64 =
        decimal(value).ok_or_else(|| invalid(Key::RetransmitWindow, "not a decimal integer"))?;
    u32::try_from(window)
        .ok()
        .filter(|&window| window > 0 && window.is_multiple_of(RETRANSMIT_WINDOW_ALIGNMENT))
        .ok_or_else(|| {
            invalid(
                Key::RetransmitWindow,
                "not a positive multiple of 32 within a term",
            )
        })
}

/// A `linger` value: a duration of the URI grammar, 0 to [`MAX_LINGER`].
fn parse_linger(value: &str) -> Result<Duration, ChannelError> {
    let linger = parse_duration(value).map_err(|error| ChannelError::InvalidDuration {
        key: Key::Linger.name(),
        error,
    })?;
    if linger > MAX_LINGER {
        return Err(invalid(Key::Linger, "above 60 s"));
    }
    Ok(linger)
}

/// The alignment of a `retransmit-window`: a frame's.
pub const RETRANSMIT_WINDOW_ALIGNMENT: u32 = 32;

fn parse_term_length(value: &str) -> Result<TermLength, ChannelError> {
    let length: u32 =
        decimal(value).ok_or_else(|| invalid(Key::TermLength, "not a decimal integer"))?;
    TermLength::try_new(length)
        .map_err(|_| invalid(Key::TermLength, "not a power of two in 65536..=1073741824"))
}

fn parse_lanes(value: &str) -> Result<u8, ChannelError> {
    decimal::<u8>(value)
        .filter(|lanes| (1..=Lane::COUNT).contains(lanes))
        .ok_or_else(|| invalid(Key::Lanes, "an integer from 1 to 4"))
}

fn parse_guard(value: &str) -> Result<String, ChannelError> {
    if value.len() > MAX_GUARD_NAME {
        return Err(invalid(Key::Guard, "longer than 64 bytes"));
    }
    // Guard names appear in tools and logs: a plain identifier only.
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(invalid(Key::Guard, "not made of [A-Za-z0-9._-]"));
    }
    Ok(value.to_owned())
}

fn parse_trace(value: &str) -> Result<Trace, ChannelError> {
    match value {
        "off" => Ok(Trace::Off),
        "all" => Ok(Trace::All),
        _ => value
            .strip_prefix("sampled:")
            .and_then(decimal::<u32>)
            .filter(|&n| n >= 1)
            .map(Trace::Sampled)
            .ok_or_else(|| invalid(Key::Trace, "`off`, `all` or `sampled:<n>`, n at least 1")),
    }
}

fn parse_fc(value: &str) -> Result<FlowControl, ChannelError> {
    match value {
        "min" => Ok(FlowControl::Min),
        "max" => Ok(FlowControl::Max),
        _ => value
            .strip_prefix("tagged:")
            .and_then(decimal::<u64>)
            .map(FlowControl::Tagged)
            .ok_or_else(|| invalid(Key::Fc, "`min`, `max` or `tagged:<group>`")),
    }
}

fn parse_address(key: Key, value: &str) -> Result<SocketAddr, ChannelError> {
    let address: SocketAddr = value
        .parse()
        .map_err(|_| invalid(key, "not an address and port"))?;
    if address.port() == 0 {
        return Err(invalid(key, "port 0"));
    }
    if address.ip().is_unspecified() {
        return Err(invalid(key, "unspecified address"));
    }
    Ok(address)
}

/// An `endpoint` value: a unicast socket address whose port may be 0, the
/// one role that admits it (owner decision item 26, karyos#656). Port 0
/// asks for an ephemeral port on a unicast subscription; a publication
/// refuses it ([`ChannelConfig::check_publication`]).
fn parse_endpoint(value: &str) -> Result<SocketAddr, ChannelError> {
    let address: SocketAddr = value
        .parse()
        .map_err(|_| invalid(Key::Endpoint, "not an address and port"))?;
    if address.port() != 0 {
        return parse_unicast(Key::Endpoint, value);
    }
    if address.ip().is_unspecified() {
        return Err(invalid(Key::Endpoint, "unspecified address"));
    }
    if address.ip().is_multicast() {
        return Err(invalid(Key::Endpoint, "a multicast address"));
    }
    Ok(address)
}

fn parse_unicast(key: Key, value: &str) -> Result<SocketAddr, ChannelError> {
    let address = parse_address(key, value)?;
    if address.ip().is_multicast() {
        return Err(invalid(key, "a multicast address"));
    }
    Ok(address)
}

/// A `nak-control` value: one multicast control group endpoint per path,
/// `;`-separated, in the order of `paths` (one without `paths`), of the
/// data group's family, on a nonzero port, other than the data group, none
/// repeated. Only a multicast channel has one.
fn parse_nak_control(
    list: &str,
    destination: &Destination,
    paths: usize,
) -> Result<Vec<SocketAddr>, ChannelError> {
    let Destination::Multicast { group, .. } = destination else {
        return Err(ChannelError::NotApplicable {
            key: Key::NakControl.name(),
        });
    };
    let parsed = list
        .split(';')
        .map(|one| parse_address(Key::NakControl, one))
        .collect::<Result<Vec<_>, _>>()?;
    if parsed.len() != paths.max(1) {
        return Err(invalid(Key::NakControl, "not one control group per path"));
    }
    for control in &parsed {
        if !control.ip().is_multicast() {
            return Err(invalid(Key::NakControl, "not a multicast address"));
        }
        if control.is_ipv4() != group.is_ipv4() {
            return Err(invalid(Key::NakControl, "not the group's address family"));
        }
        if control == group {
            return Err(invalid(Key::NakControl, "the data group itself"));
        }
    }
    if repeats(&parsed) {
        return Err(invalid(Key::NakControl, "a control group repeats"));
    }
    Ok(parsed)
}

fn parse_interface(key: Key, value: &str) -> Result<Interface, ChannelError> {
    if let Ok(address) = value.parse::<IpAddr>() {
        if address.is_multicast() {
            return Err(invalid(key, "a multicast address"));
        }
        return Ok(Interface::Address(address));
    }
    let valid = !value.is_empty()
        && value.len() <= MAX_INTERFACE_NAME
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if !valid {
        return Err(invalid(key, "not an address or an interface name"));
    }
    Ok(Interface::Name(value.to_owned()))
}

#[cfg(test)]
mod tests;
