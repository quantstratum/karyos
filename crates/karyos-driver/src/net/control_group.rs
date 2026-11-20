// SPDX-License-Identifier: Apache-2.0

//! The NAK control groups of multicast channels (`quantstratum-docs:
//! karyos/design/reliable-transport.md`, "Control group configuration";
//! RC-7, RC-15). The driver holds one mapping, seeded from
//! [`NetworkConfig::nak_control_groups`](super::NetworkConfig); a
//! channel's `nak-control` key (owner item 8, karyos#654) adds its paths'
//! entries to that same table (`merge`), so two subscribers of one
//! driver never disagree about its topology. Cross-host agreement on the
//! groups is the deployment's: there is no discovery.
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

/// Adds `entries` (data group, path interface, control group) to `table`,
/// all or none: an entry the table already holds is kept, one that maps
/// a held data group and interface to another control group is a
/// conflict, and the rest take free slots. The result must still
/// [`validate`].
///
/// # Errors
///
/// [`DriverError::ControlGroupConflict`], [`DriverError::ControlGroupsFull`],
/// or [`DriverError::InvalidConfig`] when the merged table does not
/// validate.
pub(crate) fn merge(
    table: &mut ControlGroups,
    entries: impl IntoIterator<Item = ControlGroup>,
) -> Result<(), DriverError> {
    let mut merged = *table;
    for entry in entries {
        let held = merged
            .iter()
            .flatten()
            .find(|held| (held.data_group, held.interface) == (entry.data_group, entry.interface));
        match held {
            Some(held) if held.control_group == entry.control_group => continue,
            Some(_) => {
                return Err(DriverError::ControlGroupConflict {
                    data_group: entry.data_group,
                });
            }
            None => {}
        }
        let slot = merged
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(DriverError::ControlGroupsFull)?;
        *slot = Some(entry);
    }
    validate(&merged)?;
    *table = merged;
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

    /// karyos#654: a merge keeps held entries, refuses a conflict and a
    /// ninth entry, and changes nothing when it refuses.
    #[test]
    fn a_merge_is_all_or_none() {
        let mut table: ControlGroups = [None; MAX_CONTROL_GROUPS];
        table[0] = group([239, 1, 1, 1], [239, 1, 1, 2], 4001);
        let entry = |data: [u8; 4], control: [u8; 4]| ControlGroup {
            data_group: SocketAddr::from((data, 4000)),
            interface: None,
            control_group: SocketAddr::from((control, 4001)),
        };
        merge(&mut table, [entry([239, 1, 1, 1], [239, 1, 1, 2])]).unwrap();
        assert_eq!(table.iter().flatten().count(), 1);
        let before = table;
        // A new entry first, then a conflict: neither lands.
        assert_eq!(
            merge(
                &mut table,
                [
                    entry([239, 1, 3, 1], [239, 1, 3, 2]),
                    entry([239, 1, 1, 1], [239, 1, 1, 9]),
                ]
            ),
            Err(DriverError::ControlGroupConflict {
                data_group: SocketAddr::from(([239, 1, 1, 1], 4000)),
            })
        );
        assert_eq!(table, before);
        // An entry the table refuses on validation (a unicast control).
        assert_eq!(
            merge(&mut table, [entry([239, 1, 4, 1], [10, 0, 0, 1])]),
            Err(DriverError::InvalidConfig)
        );
        assert_eq!(table, before);
        for n in 2..=8 {
            merge(&mut table, [entry([239, 2, n, 1], [239, 2, n, 2])]).unwrap();
        }
        assert_eq!(table.iter().flatten().count(), MAX_CONTROL_GROUPS);
        assert_eq!(
            merge(&mut table, [entry([239, 3, 0, 1], [239, 3, 0, 2])]),
            Err(DriverError::ControlGroupsFull)
        );
    }
}
