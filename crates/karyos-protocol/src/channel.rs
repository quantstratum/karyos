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
//! Phase 2 implements the `trusted` protection class only: `authenticated`
//! and `encrypted` are refused with [`ChannelError::SecurityUnsupported`]
//! until the security profile is accepted.

use std::net::{IpAddr, SocketAddr};

use crate::frame::Flags;
use crate::sizing::{FragmentPlan, TermLength};

/// The longest URI accepted, in bytes.
pub const MAX_URI_LENGTH: usize = 2048;
/// The largest MTU a channel may configure: jumbo frames up to 8 KiB
/// (SPEC.md §5).
pub const MAX_CHANNEL_MTU: u32 = 8192;
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
}

/// A local interface: an address to bind, or a name the driver resolves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Interface {
    /// An address.
    Address(IpAddr),
    /// An interface name.
    Name(String),
}

/// Message tracing (SPEC.md §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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
pub enum FlowControl {
    /// The slowest receiver bounds the sender.
    Min,
    /// The fastest receiver bounds the sender.
    Max,
    /// Receivers of the tagged group bound the sender.
    Tagged(u64),
}

/// A channel's protection class (SPEC.md §5). Only [`Security::Trusted`]
/// parses in Phase 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Security {
    /// No authentication or encryption.
    #[default]
    Trusted,
}

/// How a multi-destination channel learns its receivers (ADR-0056).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlMode {
    /// Only the configured destinations.
    Manual,
    /// Receivers register at the control endpoint.
    Dynamic,
}

/// Where a UDP channel sends.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// The guard the publication obeys.
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
    /// Flow control; multicast and multi-destination only.
    pub flow_control: Option<FlowControl>,
    /// The protection class.
    pub security: Security,
}

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
}

const KEYS: [(&str, Key); 16] = [
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
];

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
            Media::Udp(parse_udp(&get)?)
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
    let destination = match (
        get(Key::Endpoint),
        get(Key::Group),
        get(Key::Destinations),
        get(Key::Control),
    ) {
        (Some(endpoint), None, None, None) => {
            Destination::Unicast(parse_unicast(Key::Endpoint, endpoint)?)
        }
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
    let paths = get(Key::Paths)
        .map(|list| {
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
        })
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
            "encrypted" => Err(ChannelError::SecurityUnsupported { class: "encrypted" }),
            _ => Err(invalid(
                Key::Security,
                "`trusted`, `authenticated` or `encrypted`",
            )),
        })
        .transpose()?
        .unwrap_or_default();
    Ok(UdpConfig {
        destination,
        interface,
        paths,
        reliable,
        flow_control,
        security,
    })
}

/// Whether an item of `items` appears twice.
fn repeats<T: PartialEq>(items: &[T]) -> bool {
    items
        .iter()
        .enumerate()
        .any(|(index, one)| items.iter().take(index).any(|earlier| earlier == one))
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

fn parse_term_length(value: &str) -> Result<TermLength, ChannelError> {
    let length: u32 =
        decimal(value).ok_or_else(|| invalid(Key::TermLength, "not a decimal integer"))?;
    TermLength::try_new(length)
        .map_err(|_| invalid(Key::TermLength, "not a power of two in 65536..=1073741824"))
}

fn parse_lanes(value: &str) -> Result<u8, ChannelError> {
    decimal::<u8>(value)
        .filter(|lanes| (1..=4).contains(lanes))
        .ok_or_else(|| invalid(Key::Lanes, "an integer from 1 to 4"))
}

fn parse_guard(value: &str) -> Result<String, ChannelError> {
    if value.len() > MAX_GUARD_NAME {
        return Err(invalid(Key::Guard, "longer than 64 bytes"));
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

fn parse_unicast(key: Key, value: &str) -> Result<SocketAddr, ChannelError> {
    let address = parse_address(key, value)?;
    if address.ip().is_multicast() {
        return Err(invalid(key, "a multicast address"));
    }
    Ok(address)
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
