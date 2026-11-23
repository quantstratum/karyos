// SPDX-License-Identifier: Apache-2.0

//! The read-only netlink adapter of ADR-0038 for the AF_XDP backend
//! (`quantstratum-docs: karyos/design/af-xdp-backend.md` 4.1 and 7.2):
//! a bounded parser of netlink messages and attributes, and one query,
//! the rtnetlink neighbour dump that gives a next hop's MAC. Control path
//! only; safe code over `rustix` `net`.
//!
//! Every length, alignment and nesting is validated (ADR-0038, "Adapter
//! contract"): a message or attribute that does not fit its slice is an
//! error, never a short read, and an accepted neighbour record consumes
//! exactly its schema. Replies are correlated by sequence number and must
//! come from the kernel (port id 0). A truncated message, an interrupted
//! dump or a budget overrun is [`NetlinkError::Incomplete`], never
//! evidence of absence. The `proptest` harnesses below cover each parser
//! (ADR-0062 decision 1).
//!
//! Link facts (MAC, MTU, operational state) come from sysfs instead, read
//! only ([`link_mac`], [`link_mtu`]).

#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

/// Bytes of `struct nlmsghdr`.
pub const NLMSG_HDR: usize = 16;
/// Bytes of `struct nlattr`.
pub const NLA_HDR: usize = 4;
/// Bytes of `struct ndmsg`.
pub const NDMSG: usize = 12;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const RTM_NEWNEIGH: u16 = 28;
const RTM_GETNEIGH: u16 = 30;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_DUMP_INTR: u16 = 0x10;
const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;
/// The type bits of `nla_type` (`NLA_TYPE_MASK`).
const NLA_TYPE_MASK: u16 = 0x3fff;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// Neighbour states that give a usable MAC (design 7.2).
const NUD_USABLE: u16 = 0x02 | 0x04 | 0x08 | 0x10 | 0x80;

/// The bounds of one dump (ADR-0038: bounded bytes, messages, time).
const RECV_BUFFER: usize = 16384;
const MAX_RECVS: u32 = 64;
const MAX_MESSAGES: u32 = 4096;
const RECV_TIMEOUT: Duration = Duration::from_millis(500);

/// Why a netlink read or parse failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetlinkError {
    /// A header or length that does not fit its slice.
    Malformed,
    /// Truncated, interrupted or over budget: not evidence of absence.
    Incomplete,
    /// The kernel answered with this errno.
    Kernel {
        /// Raw OS error number.
        errno: i32,
    },
    /// A socket call failed.
    Os {
        /// The call.
        operation: &'static str,
        /// Raw OS error number.
        errno: i32,
    },
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(
        bytes.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(
        bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn align4(len: usize) -> Option<usize> {
    len.checked_add(3).map(|len| len & !3)
}

/// One netlink message header and its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message<'a> {
    /// `nlmsg_type`.
    pub kind: u16,
    /// `nlmsg_flags`.
    pub flags: u16,
    /// `nlmsg_seq`.
    pub seq: u32,
    /// `nlmsg_pid`.
    pub pid: u32,
    /// The bytes after the header, `nlmsg_len - 16` of them.
    pub payload: &'a [u8],
}

/// The messages of one datagram, in order; stops at the first malformed
/// header with an error.
#[derive(Debug, Clone)]
pub struct Messages<'a> {
    rest: &'a [u8],
}

/// Iterates the messages of `datagram`.
#[must_use]
pub fn messages(datagram: &[u8]) -> Messages<'_> {
    Messages { rest: datagram }
}

impl<'a> Iterator for Messages<'a> {
    type Item = Result<Message<'a>, NetlinkError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let parsed = (|| {
            let len = usize::try_from(u32_at(self.rest, 0)?).ok()?;
            if len < NLMSG_HDR || len > self.rest.len() {
                return None;
            }
            let message = Message {
                kind: u16_at(self.rest, 4)?,
                flags: u16_at(self.rest, 6)?,
                seq: u32_at(self.rest, 8)?,
                pid: u32_at(self.rest, 12)?,
                payload: self.rest.get(NLMSG_HDR..len)?,
            };
            let advance = align4(len)?.min(self.rest.len());
            Some((message, self.rest.get(advance..)?))
        })();
        match parsed {
            Some((message, rest)) => {
                self.rest = rest;
                Some(Ok(message))
            }
            None => {
                self.rest = &[];
                Some(Err(NetlinkError::Malformed))
            }
        }
    }
}

/// One attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attr<'a> {
    /// The type, without the nested and byte order flags.
    pub kind: u16,
    /// `NLA_F_NESTED`.
    pub nested: bool,
    /// The payload, `nla_len - 4` bytes.
    pub payload: &'a [u8],
}

/// The attributes of one payload, in order; stops at the first malformed
/// header with an error.
#[derive(Debug, Clone)]
pub struct Attrs<'a> {
    rest: &'a [u8],
}

/// Iterates the attributes in `bytes`.
#[must_use]
pub fn attrs(bytes: &[u8]) -> Attrs<'_> {
    Attrs { rest: bytes }
}

impl<'a> Iterator for Attrs<'a> {
    type Item = Result<Attr<'a>, NetlinkError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let parsed = (|| {
            let len = usize::from(u16_at(self.rest, 0)?);
            if len < NLA_HDR || len > self.rest.len() {
                return None;
            }
            let raw = u16_at(self.rest, 2)?;
            let attr = Attr {
                kind: raw & NLA_TYPE_MASK,
                nested: raw & 0x8000 != 0,
                payload: self.rest.get(NLA_HDR..len)?,
            };
            let advance = align4(len)?.min(self.rest.len());
            Some((attr, self.rest.get(advance..)?))
        })();
        match parsed {
            Some((attr, rest)) => {
                self.rest = rest;
                Some(Ok(attr))
            }
            None => {
                self.rest = &[];
                Some(Err(NetlinkError::Malformed))
            }
        }
    }
}

/// One neighbour entry of an `RTM_NEWNEIGH` message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Neighbour {
    /// The interface index.
    pub ifindex: u32,
    /// `ndm_state`.
    pub state: u16,
    /// `NDA_DST`.
    pub destination: IpAddr,
    /// `NDA_LLADDR`, when the entry has a 6-byte one.
    pub mac: Option<[u8; 6]>,
}

impl Neighbour {
    /// Whether the entry gives a usable MAC (design 7.2).
    #[must_use]
    pub fn usable_mac(&self) -> Option<[u8; 6]> {
        if self.state & NUD_USABLE == 0 {
            return None;
        }
        self.mac
    }
}

/// Parses the payload of an `RTM_NEWNEIGH` message: the 12-byte `ndmsg`,
/// then attributes, every one of which must parse. `NDA_DST` is required
/// and must match the family's length; an `NDA_LLADDR` of 6 bytes is the
/// MAC, any other length leaves it `None`.
///
/// # Errors
///
/// [`NetlinkError::Malformed`].
pub fn parse_neighbour(payload: &[u8]) -> Result<Neighbour, NetlinkError> {
    let header = payload.get(..NDMSG).ok_or(NetlinkError::Malformed)?;
    let family = *header.first().ok_or(NetlinkError::Malformed)?;
    let ifindex = u32_at(header, 4).ok_or(NetlinkError::Malformed)?;
    let state = u16_at(header, 8).ok_or(NetlinkError::Malformed)?;
    let mut destination = None;
    let mut mac = None;
    for attr in attrs(payload.get(NDMSG..).ok_or(NetlinkError::Malformed)?) {
        let attr = attr?;
        match attr.kind {
            NDA_DST => {
                destination = Some(match (family, attr.payload.len()) {
                    (AF_INET, 4) => IpAddr::V4(Ipv4Addr::from(
                        <[u8; 4]>::try_from(attr.payload).map_err(|_| NetlinkError::Malformed)?,
                    )),
                    (AF_INET6, 16) => IpAddr::V6(Ipv6Addr::from(
                        <[u8; 16]>::try_from(attr.payload).map_err(|_| NetlinkError::Malformed)?,
                    )),
                    _ => return Err(NetlinkError::Malformed),
                });
            }
            NDA_LLADDR => mac = <[u8; 6]>::try_from(attr.payload).ok(),
            _ => {}
        }
    }
    Ok(Neighbour {
        ifindex,
        state,
        destination: destination.ok_or(NetlinkError::Malformed)?,
        mac,
    })
}

/// The `RTM_GETNEIGH` dump request of `family` with sequence `seq`.
#[must_use]
pub fn neighbour_request(family: u8, seq: u32) -> [u8; NLMSG_HDR + NDMSG] {
    let mut request = [0_u8; NLMSG_HDR + NDMSG];
    let len = u32::try_from(NLMSG_HDR + NDMSG).unwrap_or(0);
    request[0..4].copy_from_slice(&len.to_ne_bytes());
    request[4..6].copy_from_slice(&RTM_GETNEIGH.to_ne_bytes());
    request[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    request[8..12].copy_from_slice(&seq.to_ne_bytes());
    request[NLMSG_HDR] = family;
    request
}

/// Folds the messages of one reply datagram into the search for
/// `next_hop` on `ifindex`: `Ok(true)` once the dump is done.
fn absorb(
    datagram: &[u8],
    seq: u32,
    ifindex: u32,
    next_hop: IpAddr,
    found: &mut Option<[u8; 6]>,
    messages_seen: &mut u32,
) -> Result<bool, NetlinkError> {
    for message in messages(datagram) {
        let message = message?;
        *messages_seen = messages_seen.saturating_add(1);
        if *messages_seen > MAX_MESSAGES {
            return Err(NetlinkError::Incomplete);
        }
        if message.seq != seq {
            continue;
        }
        if message.flags & NLM_F_DUMP_INTR != 0 {
            return Err(NetlinkError::Incomplete);
        }
        match message.kind {
            NLMSG_DONE => return Ok(true),
            NLMSG_ERROR => {
                let error = message
                    .payload
                    .get(..4)
                    .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                    .map(i32::from_ne_bytes)
                    .ok_or(NetlinkError::Malformed)?;
                if error != 0 {
                    return Err(NetlinkError::Kernel {
                        errno: error.checked_neg().unwrap_or(i32::MAX),
                    });
                }
            }
            RTM_NEWNEIGH => {
                let neighbour = parse_neighbour(message.payload)?;
                if neighbour.ifindex == ifindex && neighbour.destination == next_hop {
                    *found = neighbour.usable_mac();
                }
            }
            _ => {}
        }
    }
    Ok(false)
}

/// Looks `next_hop` up in the kernel's neighbour table of `ifindex`: a
/// read-only `RTM_GETNEIGH` dump, bounded in receives, messages and time.
/// `Ok(None)` when the dump completed with no usable entry.
///
/// # Errors
///
/// [`NetlinkError`]; `Incomplete` is never absence.
pub fn lookup_neighbour(ifindex: u32, next_hop: IpAddr) -> Result<Option<[u8; 6]>, NetlinkError> {
    use rustix::net::netlink::SocketAddrNetlink;
    use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType};

    let os = |operation| {
        move |errno: rustix::io::Errno| NetlinkError::Os {
            operation,
            errno: errno.raw_os_error(),
        }
    };
    let socket = rustix::net::socket_with(
        AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(os("netlink_socket"))?;
    rustix::net::bind(&socket, &SocketAddrNetlink::new(0, 0)).map_err(os("netlink_bind"))?;
    rustix::net::sockopt::set_socket_timeout(
        &socket,
        rustix::net::sockopt::Timeout::Recv,
        Some(RECV_TIMEOUT),
    )
    .map_err(os("netlink_timeout"))?;
    let family = match next_hop {
        IpAddr::V4(_) => AF_INET,
        IpAddr::V6(_) => AF_INET6,
    };
    let seq = 1;
    rustix::net::sendto(
        &socket,
        &neighbour_request(family, seq),
        SendFlags::empty(),
        &SocketAddrNetlink::new(0, 0),
    )
    .map_err(os("netlink_send"))?;
    let mut buffer = vec![0_u8; RECV_BUFFER];
    let mut found = None;
    let mut messages_seen = 0;
    for _ in 0..MAX_RECVS {
        let (len, _, from) = rustix::net::recvfrom(&socket, &mut buffer, RecvFlags::empty())
            .map_err(|errno| match errno {
                rustix::io::Errno::AGAIN => NetlinkError::Incomplete,
                errno => os("netlink_recv")(errno),
            })?;
        if len > buffer.len() {
            return Err(NetlinkError::Incomplete);
        }
        let from_kernel = from
            .and_then(|from| SocketAddrNetlink::try_from(from).ok())
            .is_some_and(|from| from.pid() == 0);
        if !from_kernel {
            continue;
        }
        let datagram = buffer.get(..len).ok_or(NetlinkError::Incomplete)?;
        if absorb(
            datagram,
            seq,
            ifindex,
            next_hop,
            &mut found,
            &mut messages_seen,
        )? {
            return Ok(found);
        }
    }
    Err(NetlinkError::Incomplete)
}

fn sysfs(interface: &str, file: &str) -> Option<String> {
    if interface.is_empty() || interface.contains('/') || interface.starts_with('.') {
        return None;
    }
    std::fs::read_to_string(format!("/sys/class/net/{interface}/{file}"))
        .ok()
        .map(|text| text.trim().to_owned())
}

/// The interface's MAC from `/sys/class/net/<if>/address` (design 4.1).
#[must_use]
pub fn link_mac(interface: &str) -> Option<[u8; 6]> {
    let text = sysfs(interface, "address")?;
    let mut mac = [0_u8; 6];
    let mut parts = text.split(':');
    for byte in &mut mac {
        *byte = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(mac)
}

/// The interface's MTU from `/sys/class/net/<if>/mtu`.
#[must_use]
pub fn link_mtu(interface: &str) -> Option<u32> {
    sysfs(interface, "mtu")?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn attr(kind: u16, payload: &[u8]) -> Vec<u8> {
        let len = u16::try_from(NLA_HDR + payload.len()).unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(&len.to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(payload);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }

    fn neighbour_payload(neighbour: &Neighbour) -> Vec<u8> {
        let mut out = vec![0_u8; NDMSG];
        out[0] = match neighbour.destination {
            IpAddr::V4(_) => AF_INET,
            IpAddr::V6(_) => AF_INET6,
        };
        out[4..8].copy_from_slice(&neighbour.ifindex.to_ne_bytes());
        out[8..10].copy_from_slice(&neighbour.state.to_ne_bytes());
        let destination = match neighbour.destination {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        out.extend(attr(NDA_DST, &destination));
        if let Some(mac) = neighbour.mac {
            out.extend(attr(NDA_LLADDR, &mac));
        }
        out
    }

    fn message(kind: u16, flags: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
        let len = u32::try_from(NLMSG_HDR + payload.len()).unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(&len.to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(&flags.to_ne_bytes());
        out.extend_from_slice(&seq.to_ne_bytes());
        out.extend_from_slice(&0_u32.to_ne_bytes());
        out.extend_from_slice(payload);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }

    fn any_neighbour() -> impl Strategy<Value = Neighbour> {
        (
            any::<u32>(),
            any::<u16>(),
            prop_oneof![
                any::<[u8; 4]>().prop_map(|b| IpAddr::V4(Ipv4Addr::from(b))),
                any::<[u8; 16]>().prop_map(|b| IpAddr::V6(Ipv6Addr::from(b))),
            ],
            proptest::option::of(any::<[u8; 6]>()),
        )
            .prop_map(|(ifindex, state, destination, mac)| Neighbour {
                ifindex,
                state,
                destination,
                mac,
            })
    }

    proptest! {
        #[test]
        fn message_and_attribute_parsing_never_panics_or_overreads(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let mut consumed = 0_usize;
            for message in messages(&bytes) {
                let Ok(message) = message else { break };
                consumed += NLMSG_HDR + message.payload.len();
                prop_assert!(consumed <= bytes.len());
                for attr in attrs(message.payload) {
                    let Ok(attr) = attr else { break };
                    prop_assert!(attr.payload.len() <= message.payload.len());
                }
                let _ = parse_neighbour(message.payload);
            }
            for attr in attrs(&bytes) {
                let Ok(attr) = attr else { break };
                prop_assert!(attr.payload.len() + NLA_HDR <= bytes.len());
            }
            let _ = parse_neighbour(&bytes);
        }

        #[test]
        fn an_accepted_neighbour_record_consumes_exactly_its_schema(neighbour in any_neighbour()) {
            let payload = neighbour_payload(&neighbour);
            prop_assert_eq!(parse_neighbour(&payload), Ok(neighbour));
            // One byte short of the last attribute's declared length (its
            // padding excluded) is refused, never read past.
            let padding = if neighbour.mac.is_some() { 2 } else { 0 };
            let declared_end = payload.len() - padding;
            prop_assert_eq!(parse_neighbour(&payload[..declared_end - 1]).is_err(), true);
        }

        #[test]
        fn a_reply_dump_finds_the_entry_it_names(neighbour in any_neighbour(), seq in any::<u32>()) {
            let mut datagram = message(RTM_NEWNEIGH, 2, seq, &neighbour_payload(&neighbour));
            datagram.extend(message(NLMSG_DONE, 2, seq, &[0; 4]));
            let mut found = None;
            let mut seen = 0;
            let done = absorb(&datagram, seq, neighbour.ifindex, neighbour.destination, &mut found, &mut seen);
            prop_assert_eq!(done, Ok(true));
            prop_assert_eq!(found, neighbour.usable_mac());
        }
    }

    #[test]
    fn an_interrupted_dump_is_incomplete_not_absence() {
        let datagram = message(RTM_NEWNEIGH, NLM_F_DUMP_INTR, 7, &[0; NDMSG]);
        let mut found = None;
        let mut seen = 0;
        assert_eq!(
            absorb(
                &datagram,
                7,
                1,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                &mut found,
                &mut seen
            ),
            Err(NetlinkError::Incomplete)
        );
        let error = message(NLMSG_ERROR, 0, 7, &(-13_i32).to_ne_bytes());
        assert_eq!(
            absorb(
                &error,
                7,
                1,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                &mut found,
                &mut seen
            ),
            Err(NetlinkError::Kernel { errno: 13 })
        );
    }

    #[test]
    fn the_request_is_a_dump_of_the_family() {
        let request = neighbour_request(AF_INET6, 9);
        let parsed: Vec<_> = messages(&request).collect();
        assert_eq!(parsed.len(), 1);
        let message = parsed[0].unwrap();
        assert_eq!(
            (message.kind, message.flags, message.seq),
            (RTM_GETNEIGH, NLM_F_REQUEST | NLM_F_DUMP, 9)
        );
        assert_eq!(message.payload[0], AF_INET6);
    }
}
