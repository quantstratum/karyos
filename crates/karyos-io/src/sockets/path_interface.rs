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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::resolve;

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
