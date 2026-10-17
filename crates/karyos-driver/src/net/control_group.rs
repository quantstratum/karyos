// SPDX-License-Identifier: Apache-2.0

//! The NAK control groups of multicast channels (`quantstratum-docs:
//! karyos/design/reliable-transport.md`, "Control group configuration";
//! RC-7, RC-15). The design makes `nak_control_group` a channel setting;
//! until the owner approves a URI key for it, the driver holds the
//! mapping in [`NetworkConfig::nak_control_groups`](super::NetworkConfig)
//! (coordinator decision, ACS 16103), and a URI key will map onto the same
//! table.
//!
//! - **Entries.** Each maps a data group endpoint, on a path's interface,
//!   to its control group endpoint. A data group with no entry runs with
//!   no peer suppression input, as RC-15 allows.
//! - **Validation.** A control group is a multicast address of the data
//!   group's family with a nonzero port, and differs from every data
//!   group endpoint of the table; a data group is a multicast address.
//!   Two entries of one data group and interface are refused.

use std::net::{IpAddr, SocketAddr};

use crate::error::DriverError;

/// The most entries of the control group table.
pub const MAX_CONTROL_GROUPS: usize = 8;

/// A data group's NAK control group on one path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlGroup {
    /// The channel's data group endpoint: its group address and port.
    pub data_group: SocketAddr,
    /// The path's interface, as the channel's `interface`; `None` for
    /// any.
    pub interface: Option<IpAddr>,
    /// The control group endpoint receivers exchange NAKs on.
    pub control_group: SocketAddr,
}

/// The control group table: at most [`MAX_CONTROL_GROUPS`] entries.
pub type ControlGroups = [Option<ControlGroup>; MAX_CONTROL_GROUPS];

/// Checks the table (module docs).
///
/// # Errors
///
/// [`DriverError::InvalidConfig`].
pub(crate) fn validate(table: &ControlGroups) -> Result<(), DriverError> {
    let entries = || table.iter().flatten();
    for (at, entry) in entries().enumerate() {
        let data = entry.data_group;
        let control = entry.control_group;
        let valid = data.ip().is_multicast()
            && control.ip().is_multicast()
            && control.is_ipv4() == data.is_ipv4()
            && control.port() != 0
            && entries().all(|other| other.data_group != control);
        let unique = entries()
            .skip(at.checked_add(1).ok_or(DriverError::InvalidConfig)?)
            .all(|other| (other.data_group, other.interface) != (data, entry.interface));
        if !valid || !unique {
            return Err(DriverError::InvalidConfig);
        }
    }
    Ok(())
}

/// The control group of `data_group` on `interface`: an entry for that
/// interface, or else one for any interface.
pub(crate) fn lookup(
    table: &ControlGroups,
    data_group: SocketAddr,
    interface: Option<IpAddr>,
) -> Option<SocketAddr> {
    let entries = || table.iter().flatten();
    entries()
        .find(|entry| entry.data_group == data_group && entry.interface == interface)
        .or_else(|| {
            entries().find(|entry| entry.data_group == data_group && entry.interface.is_none())
        })
        .map(|entry| entry.control_group)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(data: [u8; 4], control: [u8; 4], port: u16) -> Option<ControlGroup> {
        Some(ControlGroup {
            data_group: SocketAddr::from((data, 4000)),
            interface: None,
            control_group: SocketAddr::from((control, port)),
        })
    }

    #[test]
    fn a_valid_table_is_accepted() {
        let mut table: ControlGroups = [None; MAX_CONTROL_GROUPS];
        table[0] = group([239, 1, 1, 1], [239, 1, 1, 2], 4001);
        table[1] = group([239, 1, 2, 1], [239, 1, 2, 2], 4001);
        assert_eq!(validate(&table), Ok(()));
        assert_eq!(validate(&[None; MAX_CONTROL_GROUPS]), Ok(()));
    }

    #[test]
    fn an_invalid_entry_is_refused() {
        for (entry, what) in [
            (group([10, 0, 0, 1], [239, 1, 1, 2], 4001), "unicast data"),
            (
                group([239, 1, 1, 1], [10, 0, 0, 2], 4001),
                "unicast control",
            ),
            (group([239, 1, 1, 1], [239, 1, 1, 2], 0), "zero port"),
            (
                group([239, 1, 1, 1], [239, 1, 1, 1], 4000),
                "the data group",
            ),
            (
                Some(ControlGroup {
                    data_group: SocketAddr::from(([239, 1, 1, 1], 4000)),
                    interface: None,
                    control_group: "[ff02::1]:4001".parse().unwrap(),
                }),
                "another family",
            ),
        ] {
            let mut table: ControlGroups = [None; MAX_CONTROL_GROUPS];
            table[0] = entry;
            assert_eq!(validate(&table), Err(DriverError::InvalidConfig), "{what}");
        }
    }

    /// A control group that is another entry's data group, and two entries
    /// of one data group and interface, are refused.
    #[test]
    fn entries_must_not_collide() {
        let mut table: ControlGroups = [None; MAX_CONTROL_GROUPS];
        table[0] = group([239, 1, 1, 1], [239, 1, 1, 2], 4001);
        table[1] = Some(ControlGroup {
            data_group: SocketAddr::from(([239, 1, 2, 1], 4000)),
            interface: None,
            control_group: SocketAddr::from(([239, 1, 1, 1], 4000)),
        });
        assert_eq!(validate(&table), Err(DriverError::InvalidConfig));
        table[1] = group([239, 1, 1, 1], [239, 1, 1, 3], 4001);
        assert_eq!(validate(&table), Err(DriverError::InvalidConfig));
    }

    #[test]
    fn a_lookup_prefers_the_interface() {
        let mut table: ControlGroups = [None; MAX_CONTROL_GROUPS];
        table[0] = group([239, 1, 1, 1], [239, 1, 1, 2], 4001);
        table[1] = Some(ControlGroup {
            data_group: SocketAddr::from(([239, 1, 1, 1], 4000)),
            interface: Some(IpAddr::from([10, 0, 0, 5])),
            control_group: SocketAddr::from(([239, 1, 1, 3], 4001)),
        });
        let data = SocketAddr::from(([239, 1, 1, 1], 4000));
        assert_eq!(
            lookup(&table, data, Some(IpAddr::from([10, 0, 0, 5]))),
            Some(SocketAddr::from(([239, 1, 1, 3], 4001)))
        );
        assert_eq!(
            lookup(&table, data, Some(IpAddr::from([10, 0, 0, 6]))),
            Some(SocketAddr::from(([239, 1, 1, 2], 4001)))
        );
        assert_eq!(
            lookup(&table, SocketAddr::from(([239, 9, 9, 9], 4000)), None),
            None
        );
    }
}
