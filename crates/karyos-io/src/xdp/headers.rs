// SPDX-License-Identifier: Apache-2.0

//! Ethernet, IP and UDP headers of the AF_XDP copy-mode backend
//! (`quantstratum-docs: karyos/design/af-xdp-backend.md` 7.1 and 8.2):
//! written on TX with software checksums, validated on RX. Safe code over
//! byte slices; every position is checked.

#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::backend::RxDropReason;

/// Ethernet header bytes.
pub const ETH: usize = 14;
/// IPv4 header bytes without options.
pub const IPV4: usize = 20;
/// IPv6 header bytes without extension headers.
pub const IPV6: usize = 40;
/// UDP header bytes.
pub const UDP: usize = 8;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const IPPROTO_UDP: u8 = 17;

/// The headers before the payload of a datagram to or from `address`.
#[must_use]
pub const fn header_len(address: &SocketAddr) -> usize {
    match address {
        SocketAddr::V4(_) => ETH + IPV4 + UDP,
        SocketAddr::V6(_) => ETH + IPV6 + UDP,
    }
}

/// What one TX route writes in front of every payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Addressing {
    /// The interface's MAC.
    pub source_mac: [u8; 6],
    /// The next hop's MAC.
    pub destination_mac: [u8; 6],
    /// The endpoint's address and port.
    pub source: SocketAddr,
    /// The route's destination.
    pub destination: SocketAddr,
    /// TTL or hop limit.
    pub hop_limit: u8,
}

fn put(frame: &mut [u8], at: usize, bytes: &[u8]) -> Option<()> {
    frame
        .get_mut(at..at.checked_add(bytes.len())?)?
        .copy_from_slice(bytes);
    Some(())
}

fn get<const N: usize>(frame: &[u8], at: usize) -> Option<[u8; N]> {
    frame.get(at..at.checked_add(N)?)?.try_into().ok()
}

fn u16_at(frame: &[u8], at: usize) -> Option<u16> {
    get::<2>(frame, at).map(u16::from_be_bytes)
}

/// The one's complement sum of `bytes` as 16-bit big endian words, added
/// to `sum`.
fn sum_words(mut sum: u32, bytes: &[u8]) -> u32 {
    let (words, rest) = bytes.as_chunks::<2>();
    for word in words {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes(*word)));
    }
    if let [last] = rest {
        sum = sum.wrapping_add(u32::from(*last) << 8);
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum > 0xffff {
        sum = (sum & 0xffff).wrapping_add(sum >> 16);
    }
    // At most 16 bits remain.
    u16::try_from(sum).unwrap_or(u16::MAX)
}

fn pseudo_sum(source: IpAddr, destination: IpAddr, udp_len: u32) -> u32 {
    let mut sum = 0_u32;
    match (source, destination) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            sum = sum_words(sum, &s.octets());
            sum = sum_words(sum, &d.octets());
        }
        (s, d) => {
            sum = sum_words(sum, &to_v6(s).octets());
            sum = sum_words(sum, &to_v6(d).octets());
        }
    }
    sum = sum.wrapping_add(u32::from(IPPROTO_UDP));
    sum.wrapping_add(udp_len >> 16)
        .wrapping_add(udp_len & 0xffff)
}

fn to_v6(address: IpAddr) -> Ipv6Addr {
    match address {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

/// Writes the Ethernet, IP and UDP headers for `payload_len` bytes already
/// in place after them (design 7.1): IPv4 with DF, identification 0 and
/// its header checksum, or IPv6; the UDP checksum in software. Returns the
/// frame length, or `None` when the frame is too short or the families
/// differ.
pub fn write_headers(
    frame: &mut [u8],
    addressing: &Addressing,
    payload_len: usize,
) -> Option<usize> {
    let header = header_len(&addressing.destination);
    let total = header.checked_add(payload_len)?;
    if frame.len() < total {
        return None;
    }
    put(frame, 0, &addressing.destination_mac)?;
    put(frame, 6, &addressing.source_mac)?;
    let udp_len = UDP.checked_add(payload_len)?;
    let udp_len16 = u16::try_from(udp_len).ok()?;
    let (ip_end, source_ip, destination_ip) = match (addressing.source, addressing.destination) {
        (SocketAddr::V4(source), SocketAddr::V4(destination)) => {
            put(frame, 12, &ETH_P_IP.to_be_bytes())?;
            let total_len = u16::try_from(IPV4.checked_add(udp_len)?).ok()?;
            let mut ip = [0_u8; IPV4];
            ip[0] = 0x45;
            ip[2..4].copy_from_slice(&total_len.to_be_bytes());
            // DF; identification and offset zero.
            ip[6] = 0x40;
            ip[8] = addressing.hop_limit;
            ip[9] = IPPROTO_UDP;
            ip[12..16].copy_from_slice(&source.ip().octets());
            ip[16..20].copy_from_slice(&destination.ip().octets());
            let checksum = !fold(sum_words(0, &ip));
            ip[10..12].copy_from_slice(&checksum.to_be_bytes());
            put(frame, ETH, &ip)?;
            (
                ETH + IPV4,
                IpAddr::V4(*source.ip()),
                IpAddr::V4(*destination.ip()),
            )
        }
        (SocketAddr::V6(source), SocketAddr::V6(destination)) => {
            put(frame, 12, &ETH_P_IPV6.to_be_bytes())?;
            let mut ip = [0_u8; IPV6];
            ip[0] = 0x60;
            ip[4..6].copy_from_slice(&udp_len16.to_be_bytes());
            ip[6] = IPPROTO_UDP;
            ip[7] = addressing.hop_limit;
            ip[8..24].copy_from_slice(&source.ip().octets());
            ip[24..40].copy_from_slice(&destination.ip().octets());
            put(frame, ETH, &ip)?;
            (
                ETH + IPV6,
                IpAddr::V6(*source.ip()),
                IpAddr::V6(*destination.ip()),
            )
        }
        _ => return None,
    };
    put(frame, ip_end, &addressing.source.port().to_be_bytes())?;
    put(
        frame,
        ip_end + 2,
        &addressing.destination.port().to_be_bytes(),
    )?;
    put(frame, ip_end + 4, &udp_len16.to_be_bytes())?;
    put(frame, ip_end + 6, &[0, 0])?;
    let udp = frame.get(ip_end..total)?;
    let sum = sum_words(
        pseudo_sum(source_ip, destination_ip, u32::from(udp_len16)),
        udp,
    );
    let mut checksum = !fold(sum);
    if checksum == 0 {
        checksum = 0xffff;
    }
    put(frame, ip_end + 6, &checksum.to_be_bytes())?;
    Some(total)
}

/// The Ethernet group MAC of a multicast address: `01:00:5e` and the low
/// 23 bits for IPv4 (RFC 1112), `33:33` and the low 32 bits for IPv6
/// (RFC 2464); `None` for a unicast address.
#[must_use]
pub fn group_mac(address: IpAddr) -> Option<[u8; 6]> {
    match address {
        IpAddr::V4(v4) if v4.is_multicast() => {
            let [_, b, c, d] = v4.octets();
            Some([0x01, 0x00, 0x5e, b & 0x7f, c, d])
        }
        IpAddr::V6(v6) if v6.is_multicast() => {
            let o = v6.octets();
            Some([0x33, 0x33, o[12], o[13], o[14], o[15]])
        }
        _ => None,
    }
}

/// What RX validation established about one frame (design 8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Checked {
    /// A datagram for the endpoint: its UDP payload, at `offset` for
    /// `len` bytes, and its source.
    Datagram {
        /// The payload's offset in the frame.
        offset: usize,
        /// The payload's length.
        len: usize,
        /// The sender.
        source: SocketAddr,
    },
    /// Dropped, with the reason.
    Drop(RxDropReason, Option<SocketAddr>),
}

/// Validates one received frame against the endpoint `local` on the
/// interface `local_mac` (design 8.2): Ethernet to the interface, an
/// untagged IPv4 (version 4, IHL 5, valid header checksum, no fragment,
/// DF permitted) or IPv6 UDP datagram to `local`'s address and port with
/// lengths that fit the frame and a valid UDP checksum (zero accepted for
/// IPv4 only), and a payload of at most `max_datagram`.
#[must_use]
pub fn validate(frame: &[u8], local: SocketAddr, local_mac: [u8; 6], max_datagram: u16) -> Checked {
    validate_inner(frame, local, local_mac, max_datagram)
        .unwrap_or(Checked::Drop(RxDropReason::Malformed, None))
}

fn validate_inner(
    frame: &[u8],
    local: SocketAddr,
    local_mac: [u8; 6],
    max_datagram: u16,
) -> Option<Checked> {
    // The interface's own MAC, or the group MAC of a multicast endpoint
    // (design 8.2: "the interface or a joined group MAC").
    let destination_mac = get::<6>(frame, 0)?;
    if destination_mac != local_mac && Some(destination_mac) != group_mac(local.ip()) {
        return Some(Checked::Drop(RxDropReason::NotLocal, None));
    }
    let (source_ip, destination_ip, udp_at, ip_payload) = match u16_at(frame, 12)? {
        ETH_P_IP => {
            let ip: [u8; IPV4] = get(frame, ETH)?;
            let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
            let fragment = u16::from_be_bytes([ip[6], ip[7]]);
            // Reserved bit, MF and offset zero; DF permitted.
            if ip[0] != 0x45 || fragment & 0xbfff != 0 || ip[9] != IPPROTO_UDP || total < IPV4 + UDP
            {
                return Some(Checked::Drop(RxDropReason::Malformed, None));
            }
            if fold(sum_words(0, &ip)) != 0xffff {
                return Some(Checked::Drop(RxDropReason::Checksum, None));
            }
            if ETH.checked_add(total)? > frame.len() {
                return Some(Checked::Drop(RxDropReason::Malformed, None));
            }
            let source = IpAddr::V4(Ipv4Addr::from([ip[12], ip[13], ip[14], ip[15]]));
            let destination = IpAddr::V4(Ipv4Addr::from([ip[16], ip[17], ip[18], ip[19]]));
            (source, destination, ETH + IPV4, total - IPV4)
        }
        ETH_P_IPV6 => {
            let ip: [u8; IPV6] = get(frame, ETH)?;
            let payload = usize::from(u16::from_be_bytes([ip[4], ip[5]]));
            if ip[0] >> 4 != 6 || ip[6] != IPPROTO_UDP || payload < UDP {
                return Some(Checked::Drop(RxDropReason::Malformed, None));
            }
            if (ETH + IPV6).checked_add(payload)? > frame.len() {
                return Some(Checked::Drop(RxDropReason::Malformed, None));
            }
            let source = IpAddr::V6(Ipv6Addr::from(get::<16>(&ip, 8)?));
            let destination = IpAddr::V6(Ipv6Addr::from(get::<16>(&ip, 24)?));
            (source, destination, ETH + IPV6, payload)
        }
        _ => return Some(Checked::Drop(RxDropReason::Malformed, None)),
    };
    let source_port = u16_at(frame, udp_at)?;
    let destination_port = u16_at(frame, udp_at + 2)?;
    let udp_len = usize::from(u16_at(frame, udp_at + 4)?);
    let checksum = u16_at(frame, udp_at + 6)?;
    let source = SocketAddr::new(source_ip, source_port);
    if udp_len != ip_payload {
        return Some(Checked::Drop(RxDropReason::Malformed, Some(source)));
    }
    if destination_ip != local.ip() || destination_port != local.port() {
        return Some(Checked::Drop(RxDropReason::NotLocal, Some(source)));
    }
    let udp = frame.get(udp_at..udp_at.checked_add(udp_len)?)?;
    let zero_ok = matches!(source_ip, IpAddr::V4(_));
    if checksum == 0 {
        if !zero_ok {
            return Some(Checked::Drop(RxDropReason::Checksum, Some(source)));
        }
    } else {
        let len = u32::try_from(udp_len).ok()?;
        if fold(sum_words(pseudo_sum(source_ip, destination_ip, len), udp)) != 0xffff {
            return Some(Checked::Drop(RxDropReason::Checksum, Some(source)));
        }
    }
    let len = udp_len - UDP;
    if len > usize::from(max_datagram) {
        return Some(Checked::Drop(
            RxDropReason::Oversize {
                limit: max_datagram,
                received: Some(len),
            },
            Some(source),
        ));
    }
    Some(Checked::Datagram {
        offset: udp_at + UDP,
        len,
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const MAC_A: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const MAC_B: [u8; 6] = [2, 0, 0, 0, 0, 2];

    fn addressing(source: SocketAddr, destination: SocketAddr) -> Addressing {
        Addressing {
            source_mac: MAC_A,
            destination_mac: MAC_B,
            source,
            destination,
            hop_limit: 64,
        }
    }

    fn round_trip(source: SocketAddr, destination: SocketAddr, payload: &[u8]) -> Checked {
        let mut frame = vec![0_u8; 2048];
        let header = header_len(&destination);
        frame[header..header + payload.len()].copy_from_slice(payload);
        let len =
            write_headers(&mut frame, &addressing(source, destination), payload.len()).unwrap();
        validate(&frame[..len], destination, MAC_B, 1408)
    }

    #[test]
    fn written_ipv4_and_ipv6_frames_validate_back() {
        let v4 = round_trip(
            "10.0.0.1:4000".parse().unwrap(),
            "10.0.0.2:5000".parse().unwrap(),
            b"karyos",
        );
        assert!(matches!(v4, Checked::Datagram { len: 6, .. }), "{v4:?}");
        let v6 = round_trip(
            "[fd00::1]:4000".parse().unwrap(),
            "[fd00::2]:5000".parse().unwrap(),
            b"karyos6",
        );
        assert!(matches!(v6, Checked::Datagram { len: 7, .. }), "{v6:?}");
    }

    #[test]
    fn a_corrupted_checksum_or_another_port_is_dropped() {
        let source: SocketAddr = "10.0.0.1:4000".parse().unwrap();
        let destination: SocketAddr = "10.0.0.2:5000".parse().unwrap();
        let mut frame = vec![0_u8; 128];
        let len = write_headers(&mut frame, &addressing(source, destination), 4).unwrap();
        let mut bad = frame.clone();
        bad[len - 1] ^= 0xff;
        assert_eq!(
            validate(&bad[..len], destination, MAC_B, 1408),
            Checked::Drop(RxDropReason::Checksum, Some(source))
        );
        let other: SocketAddr = "10.0.0.2:5001".parse().unwrap();
        assert!(matches!(
            validate(&frame[..len], other, MAC_B, 1408),
            Checked::Drop(RxDropReason::NotLocal, _)
        ));
        assert!(matches!(
            validate(&frame[..len], destination, MAC_A, 1408),
            Checked::Drop(RxDropReason::NotLocal, None)
        ));
    }

    #[test]
    fn a_multicast_endpoint_accepts_its_group_mac() {
        let group: SocketAddr = "239.1.2.3:5000".parse().unwrap();
        let source: SocketAddr = "10.0.0.1:4000".parse().unwrap();
        let mac = group_mac(group.ip()).unwrap();
        assert_eq!(mac, [0x01, 0x00, 0x5e, 0x01, 0x02, 0x03]);
        let mut frame = vec![0_u8; 128];
        let addressing = Addressing {
            source_mac: MAC_A,
            destination_mac: mac,
            source,
            destination: group,
            hop_limit: 1,
        };
        let len = write_headers(&mut frame, &addressing, 4).unwrap();
        assert!(matches!(
            validate(&frame[..len], group, MAC_B, 1408),
            Checked::Datagram { len: 4, .. }
        ));
        assert_eq!(
            group_mac("[ff02::1:ff00:1]:1".parse::<SocketAddr>().unwrap().ip()),
            Some([0x33, 0x33, 0xff, 0x00, 0x00, 0x01])
        );
        assert_eq!(group_mac(source.ip()), None);
    }

    proptest! {
        #[test]
        fn validation_never_panics_on_any_frame(frame in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = validate(&frame, "10.0.0.2:5000".parse().unwrap(), MAC_B, 1408);
        }
    }
}
