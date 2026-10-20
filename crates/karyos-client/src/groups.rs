// SPDX-License-Identifier: Apache-2.0

//! Groups of counters a driver writes together inside a sampling pass on
//! a pass cell of the same keys, read as one (`quantstratum-docs:
//! karyos/design/management-agent-gap-analysis.md`, M6b and M4b): an
//! endpoint's capabilities ([`crate::capabilities`]) and a guard's close
//! acknowledgement ([`crate::guard_acks`]). Never waits.

use karyos_sys::counters::{CellRead, CountersReader, PassRead, read_pass};

/// Reads of a group before it is reported inconsistent.
const ATTEMPTS: usize = 8;

/// One participant's group of gauges.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Group {
    /// The participant (`key2`): an endpoint's instance id, a guard id.
    pub participant: u64,
    /// Whether the values come from one completed pass. `false` when every
    /// attempt overlapped a write, when no pass completed yet (the pass
    /// cell still 0: the gauges hold their allocation zeros), or when the
    /// participant has no pass cell (the region had no room for it).
    pub consistent: bool,
    /// Label and value of each member gauge, in cell order.
    pub gauges: Vec<(String, u64)>,
}

/// One participant's cells as the scan finds them.
struct Found {
    participant: u64,
    pass: Option<usize>,
    cells: Vec<(usize, String)>,
}

/// Every group of participant kind `kind` in `reader`, in the order of
/// their first cells: the cells labelled `pass_label` are the passes, and
/// those whose label `member` accepts are the gauges. A participant with
/// neither is left out.
#[must_use]
pub fn read_groups(
    reader: &CountersReader,
    kind: u8,
    pass_label: &str,
    member: impl Fn(&str) -> bool,
) -> Vec<Group> {
    let mut found: Vec<Found> = Vec::new();
    for index in 0..reader.capacity() {
        let CellRead::Allocated { metadata, .. } = reader.read(index) else {
            continue;
        };
        if metadata.keys.kind != kind {
            continue;
        }
        let participant = metadata.keys.participant;
        let label = String::from_utf8_lossy(metadata.label()).into_owned();
        let is_pass = label == pass_label;
        if !is_pass && !member(&label) {
            continue;
        }
        if !found.iter().any(|group| group.participant == participant) {
            found.push(Found {
                participant,
                pass: None,
                cells: Vec::new(),
            });
        }
        let Some(group) = found
            .iter_mut()
            .find(|group| group.participant == participant)
        else {
            continue;
        };
        if is_pass {
            group.pass = Some(index);
        } else {
            group.cells.push((index, label));
        }
    }
    found
        .into_iter()
        .map(
            |Found {
                 participant,
                 pass,
                 cells,
             }| {
                let values = || {
                    cells
                        .iter()
                        .map(|(index, label)| {
                            (label.clone(), reader.load_value(*index).unwrap_or(0))
                        })
                        .collect::<Vec<_>>()
                };
                let (consistent, gauges) = match pass {
                    // An unreadable pass cell reads odd: never consistent.
                    // The pass value read with the gauges tells a completed
                    // pass (even and nonzero) from none yet (0).
                    Some(pass) => {
                        let epoch = || reader.load_value(pass).unwrap_or(1);
                        match read_pass(epoch, || (epoch(), values()), ATTEMPTS) {
                            PassRead::Consistent((passes, gauges)) => (passes > 0, gauges),
                            PassRead::Inconsistent((_, gauges)) => (false, gauges),
                        }
                    }
                    None => (false, values()),
                };
                Group {
                    participant,
                    consistent,
                    gauges,
                }
            },
        )
        .collect()
}
