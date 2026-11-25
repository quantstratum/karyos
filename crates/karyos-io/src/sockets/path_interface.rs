// SPDX-License-Identifier: Apache-2.0

//! The interface a multicast path joins on (karyos#624): the kernel joins
//! a group on the interface that owns the path's address, or, for the
//! unspecified address, on the interface of the route to the group. Two
//! paths that resolve to one interface would be one physical path counted
//! twice, since both sockets then hold a membership on that interface and
//! receive every datagram even with `IP_MULTICAST_ALL` off; the driver
//! refuses such a channel.
//!
//! On Linux the interface is resolved from `/proc/net/route` by longest
//! prefix match, which is safe code over a text file: no `libc`, no
//! netlink. Loopback addresses, routed in the local table only, resolve to
//! `lo`. Elsewhere, and on a host without the file, nothing resolves.

use std::net::Ipv4Addr;

/// The name of the interface a path of `address` joins `group` on: the
/// interface owning `address`, or, when `address` is unspecified, the one
/// of the route to `group`. `None` when it cannot be resolved here.
#[must_use]
pub fn path_interface(address: Ipv4Addr, group: Ipv4Addr) -> Option<String> {
    let target = if address.is_unspecified() {
        group
    } else {
        address
    };
    #[cfg(target_os = "linux")]
    {
        let table = std::fs::read_to_string("/proc/net/route").ok();
        resolve(table.as_deref().unwrap_or(""), target)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = target;
        None
    }
}

/// The interface of `target` in a `/proc/net/route` `table`, by longest
/// prefix match; a loopback `target` is `lo`.
#[cfg_attr(
    not(any(target_os = "linux", test)),
    expect(dead_code, reason = "Linux only")
)]
fn resolve(table: &str, target: Ipv4Addr) -> Option<String> {
    // Loopback addresses are routed in the local table, which this file
    // does not list; the main table's default route would match them too.
    if target.is_loopback() {
        return Some("lo".to_owned());
    }
    let target = u32::from_ne_bytes(target.octets());
    let mut best: Option<(u32, &str)> = None;
    for line in table.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let (Some(name), Some(destination)) = (fields.next(), fields.next()) else {
            continue;
        };
        // Gateway, flags, refcount, use, metric, then the mask.
        let Some(mask) = fields.nth(5) else {
            continue;
        };
        let (Ok(destination), Ok(mask)) = (
            u32::from_str_radix(destination, 16),
            u32::from_str_radix(mask, 16),
        ) else {
            continue;
        };
        if target & mask != destination {
            continue;
        }
        let length = mask.count_ones();
        if best.is_none_or(|(held, _)| length > held) {
            best = Some((length, name));
        }
    }
    best.map(|(_, name)| name.to_owned())
}

/// The index of the interface that owns `address` (an etf leaf's
/// interface, ADR-0109 point 2), resolved without `libc` or netlink: an
/// IPv4 address by [`path_interface`] and the interface's name, an IPv6
/// one from `/proc/net/if_inet6`, which lists each address with its
/// interface index. `None` when it cannot be resolved here (off Linux,
/// an unassigned address, or the unspecified address).
#[must_use]
pub fn interface_index(address: std::net::IpAddr) -> Option<u32> {
    if address.is_unspecified() {
        return None;
    }
    #[cfg(target_os = "linux")]
    {
        match address {
            std::net::IpAddr::V4(v4) => {
                let name = path_interface(v4, v4)?;
                let socket = rustix::net::socket(
                    rustix::net::AddressFamily::INET,
                    rustix::net::SocketType::DGRAM,
                    None,
                )
                .ok()?;
                rustix::net::netdevice::name_to_index(socket, &name).ok()
            }
            std::net::IpAddr::V6(v6) => {
                let table = std::fs::read_to_string("/proc/net/if_inet6").ok()?;
                inet6_index(&table, v6)
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// The interface index of `address` in a `/proc/net/if_inet6` `table`:
/// lines of the address in 32 hex digits, then the index in hex.
#[cfg_attr(
    not(any(target_os = "linux", test)),
    expect(dead_code, reason = "Linux only")
)]
fn inet6_index(table: &str, address: std::net::Ipv6Addr) -> Option<u32> {
    let wanted = u128::from(address);
    table.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let listed = u128::from_str_radix(fields.next()?, 16).ok()?;
        let index = u32::from_str_radix(fields.next()?, 16).ok()?;
        (listed == wanted).then_some(index)
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{inet6_index, resolve};

    /// `/proc/net/if_inet6` lists an address with its interface index in
    /// hex; another address, or a malformed line, resolves nothing.
    #[test]
    fn an_ipv6_address_resolves_to_its_listed_index() {
        let table = "00000000000000000000000000000001 01 80 10 80       lo\n\
                     fe80000000000000021122fffe334455 0a 40 20 80     eth0\n\
                     garbage\n";
        assert_eq!(inet6_index(table, std::net::Ipv6Addr::LOCALHOST), Some(1));
        assert_eq!(
            inet6_index(
                table,
                std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0x0211, 0x22ff, 0xfe33, 0x4455)
            ),
            Some(10)
        );
        assert_eq!(
            inet6_index(table, std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            None
        );
    }

    /// The loopback address resolves to `lo`'s index on Linux.
    #[cfg(target_os = "linux")]
    #[test]
    fn loopback_resolves_to_an_index() {
        assert!(super::interface_index(Ipv4Addr::LOCALHOST.into()).is_some());
        assert_eq!(super::interface_index(Ipv4Addr::UNSPECIFIED.into()), None);
    }

    /// A `/proc/net/route` table as Linux prints it on a little-endian
    /// host: the default route and 172.17.0.0/16 on `eth0`, 10.1.0.0/24 on
    /// `eth1`, and 224.0.0.0/4 on `eth1`.
    fn table() -> String {
        let row = |name: &str, destination: [u8; 4], mask: [u8; 4]| {
            format!(
                "{name}\t{:08X}\t00000000\t0001\t0\t0\t0\t{:08X}\t0\t0\t0\n",
                u32::from_ne_bytes(destination),
                u32::from_ne_bytes(mask)
            )
        };
        let mut table = String::from(
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n",
        );
        table.push_str(&row("eth0", [0, 0, 0, 0], [0, 0, 0, 0]));
        table.push_str(&row("eth0", [172, 17, 0, 0], [255, 255, 0, 0]));
        table.push_str(&row("eth1", [10, 1, 0, 0], [255, 255, 255, 0]));
        table.push_str(&row("eth1", [224, 0, 0, 0], [240, 0, 0, 0]));
        table
    }

    #[test]
    fn an_address_resolves_to_the_interface_of_its_longest_prefix() {
        let table = table();
        assert_eq!(
            resolve(&table, Ipv4Addr::new(172, 17, 0, 2)).as_deref(),
            Some("eth0")
        );
        assert_eq!(
            resolve(&table, Ipv4Addr::new(10, 1, 0, 5)).as_deref(),
            Some("eth1")
        );
        // A group follows the multicast route, longer than the default.
        assert_eq!(
            resolve(&table, Ipv4Addr::new(239, 1, 2, 3)).as_deref(),
            Some("eth1")
        );
        assert_eq!(resolve(&table, Ipv4Addr::LOCALHOST).as_deref(), Some("lo"));
        assert_eq!(resolve("", Ipv4Addr::new(10, 1, 0, 5)), None);
    }

    /// Codex's example: the unspecified address and the explicit address of
    /// the interface the group routes through are one interface.
    #[test]
    fn the_unspecified_path_resolves_through_the_groups_route() {
        let table = table();
        let group = Ipv4Addr::new(239, 1, 2, 3);
        assert_eq!(
            resolve(&table, group),
            resolve(&table, Ipv4Addr::new(10, 1, 0, 5))
        );
    }
}
