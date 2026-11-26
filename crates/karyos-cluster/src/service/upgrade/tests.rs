// SPDX-License-Identifier: Apache-2.0

//! ADR-0122 (karyos#715): vectors A-1 to A-17 and C-1 to C-7 of the
//! design note §4.1, the leader's and the apply-time refusals, semantics
//! by the active version, and snapshots carrying it.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use super::super::{
    Applied, ApplyError, ClusteredService, ContainerConfig, Context, Envelope, NotLeader, Propose,
    ProposeRefused, RestoreError, SESSIONS_SECTION_VERSION, SESSIONS_SECTION_VERSION_1,
    ServiceContainer, ServiceSnapshot,
};
use super::*;
use crate::dedup::Request;
use crate::log::Entry;
use crate::snapshot::{SectionKind, SectionRead};

fn hex(text: &str) -> Vec<u8> {
    text.split_whitespace()
        .map(|byte| u8::from_str_radix(byte, 16).unwrap())
        .collect()
}

const A1: &str = "05 00 03 00 02 00 0e 00 1c 00 00 00
    02 00 00 00 01 00 64 00 00 00 00 00 00 00 00 00";
const A2: &str = "05 00 03 00 02 00 0e 00 1f 00 00 00
    02 00 00 00 01 00 64 00 00 00 00 00 00 00 03 00 01 02 03";
const C1: &str = "05 00 04 00 02 00 0c 00 18 00 00 00
    f4 01 00 00 00 00 00 00 03 00 00 00";

fn a1() -> Activation<'static> {
    Activation::new(ActiveVersion::new(2, 1), 100, &[])
}

/// A-1 to A-10: `Activation` encodes and decodes byte for byte, and each
/// refusal breaks one rule.
#[test]
fn test_activation_vectors_a1_to_a10() {
    assert_eq!(a1().to_vec().unwrap(), hex(A1), "A-1 encode");
    assert_eq!(Activation::decode(&hex(A1)), Ok(a1()), "A-1 decode");
    let a2 = Activation::new(ActiveVersion::new(2, 1), 100, &[1, 2, 3]);
    assert_eq!(a2.to_vec().unwrap(), hex(A2), "A-2 encode");
    assert_eq!(Activation::decode(&hex(A2)), Ok(a2), "A-2 decode");
    let zeros = vec![0; 4096];
    let a3 = Activation::new(ActiveVersion::new(2, 1), 100, &zeros);
    let mut a3_bytes = hex("05 00 03 00 02 00 0e 00 1c 10 00 00
        02 00 00 00 01 00 64 00 00 00 00 00 00 00 00 10");
    a3_bytes.extend_from_slice(&zeros);
    assert_eq!(a3.to_vec().unwrap(), a3_bytes, "A-3 encode");
    assert_eq!(Activation::decode(&a3_bytes), Ok(a3), "A-3 decode");
    // A-4 to A-6: one field of 0, on decoding and on encoding.
    for (label, at, field, broken) in [
        (
            "A-4",
            12,
            "service_version",
            Activation::new(ActiveVersion::new(0, 1), 100, &[]),
        ),
        (
            "A-5",
            16,
            "schema_version",
            Activation::new(ActiveVersion::new(2, 0), 100, &[]),
        ),
        (
            "A-6",
            18,
            "activation_offset",
            Activation::new(ActiveVersion::new(2, 1), 0, &[]),
        ),
    ] {
        let mut bytes = hex(A1);
        let width = match field {
            "service_version" => 4,
            "schema_version" => 2,
            _ => 8,
        };
        bytes[at..at + width].fill(0);
        let refused = Err(CodecError::ValueOutOfRange { field });
        assert_eq!(Activation::decode(&bytes), refused, "{label} decode");
        assert_eq!(
            broken.to_vec().map(|_| ()),
            refused.map(|_| ()),
            "{label} encode"
        );
    }
    // A-7: a 4097-byte configuration.
    let long = vec![0; 4097];
    let mut a7 = hex("05 00 03 00 02 00 0e 00 1d 10 00 00
        02 00 00 00 01 00 64 00 00 00 00 00 00 00 01 10");
    a7.extend_from_slice(&long);
    let length_out = CodecError::LengthOutOfRange {
        field: "configuration",
        length: 4097,
        min: 0,
        max: 4096,
    };
    assert_eq!(Activation::decode(&a7), Err(length_out), "A-7 decode");
    assert_eq!(
        Activation::new(ActiveVersion::new(2, 1), 100, &long).to_vec(),
        Err(length_out),
        "A-7 encode"
    );
    // A-8: another block length.
    let mut a8 = hex(A1);
    a8[6] = 12;
    let unsupported = Err(CodecError::UnsupportedSchema {
        schema: 5,
        template: 3,
        version: 2,
    });
    assert_eq!(Activation::decode(&a8), unsupported, "A-8");
    // A-9: A-2 short by its last byte, lengths unchanged.
    let a9 = hex(A2);
    assert_eq!(
        Activation::decode(&a9[..a9.len() - 1]),
        Err(CodecError::MessageLength {
            declared: 31,
            actual: 30
        }),
        "A-9"
    );
    // A-10: not a schema 2 template.
    assert_eq!(
        Envelope::decode(&hex(A1)).map(|_| ()),
        unsupported.map(|_: Activation<'_>| ()),
        "A-10"
    );
}

/// C-1 to C-4: `CoordinatedStop` encodes and decodes byte for byte.
#[test]
fn test_coordinated_stop_vectors_c1_to_c4() {
    let c1 = CoordinatedStop::new(500, 3);
    assert_eq!(c1.to_vec().unwrap(), hex(C1), "C-1 encode");
    assert_eq!(CoordinatedStop::decode(&hex(C1)), Ok(c1), "C-1 decode");
    let c2 = CoordinatedStop::new(0, 3);
    let c2_bytes = hex("05 00 04 00 02 00 0c 00 18 00 00 00
        00 00 00 00 00 00 00 00 03 00 00 00");
    assert_eq!(c2.to_vec().unwrap(), c2_bytes, "C-2 encode");
    assert_eq!(CoordinatedStop::decode(&c2_bytes), Ok(c2), "C-2 decode");
    let mut c3 = hex(C1);
    c3[20..24].fill(0);
    let refused = Err(CodecError::ValueOutOfRange {
        field: "resume_version",
    });
    assert_eq!(CoordinatedStop::decode(&c3), refused, "C-3 decode");
    assert_eq!(
        CoordinatedStop::new(500, 0).to_vec().map(|_| ()),
        refused.map(|_| ()),
        "C-3 encode"
    );
    let mut c4 = hex(C1);
    c4[6] = 8;
    assert_eq!(
        CoordinatedStop::decode(&c4),
        Err(CodecError::UnsupportedSchema {
            schema: 5,
            template: 4,
            version: 2
        }),
        "C-4"
    );
}

/// What the test service saw: each command's and configuration's index
/// and active version.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Versioned {
    /// [`ClusteredService::supported_version`].
    supported: u32,
    seen: Vec<(u64, ActiveVersion, Vec<u8>)>,
}

impl Versioned {
    fn new(supported: u32) -> Self {
        Self {
            supported,
            seen: Vec::new(),
        }
    }
}

impl ClusteredService for Versioned {
    fn on_command(
        &mut self,
        context: &mut Context<'_>,
        _client: u64,
        command: &[u8],
        _reply: &mut [u8],
    ) -> Option<usize> {
        self.seen
            .push((context.index(), context.active_version(), command.to_vec()));
        Some(0)
    }

    fn on_timer(&mut self, _context: &mut Context<'_>, _timer: u64) {}

    fn on_configuration(&mut self, context: &mut Context<'_>, configuration: &[u8]) {
        let mut seen = vec![0xc0];
        seen.extend_from_slice(configuration);
        self.seen
            .push((context.index(), context.active_version(), seen));
    }

    /// Command `[9]` needs version 2, and a binary that supports only
    /// version 1 does not know it; `[8]` is a type no version knows;
    /// every other runs from version 1.
    fn required_version(&self, command: &[u8]) -> Option<u32> {
        match command.first() {
            Some(9) if self.supported >= 2 => Some(2),
            Some(9) => None,
            Some(8) => None,
            _ => Some(1),
        }
    }

    fn supported_version(&self) -> u32 {
        self.supported
    }
}

fn container(supported: u32) -> ServiceContainer<Versioned> {
    ServiceContainer::new(Versioned::new(supported), ContainerConfig::default()).unwrap()
}

fn raw(index: u64, payload: Vec<u8>) -> Entry {
    Entry {
        index,
        term: 1,
        event_time: index,
        payload,
    }
}

/// Client 7's request `sequence` (from 0) carrying `command`.
fn request(index: u64, sequence: u64, command: &[u8]) -> Entry {
    raw(
        index,
        Envelope::Request {
            request: Request::new(7, 1, sequence, sequence),
            command,
        }
        .to_vec()
        .unwrap(),
    )
}

/// A container with client 7 registered at index 1 and empty entries up
/// to `to`.
fn up_to(supported: u32, to: u64) -> ServiceContainer<Versioned> {
    let mut container = container(supported);
    container
        .apply(&raw(1, Envelope::Register { client: 7 }.to_vec().unwrap()))
        .unwrap();
    fill(&mut container, 2, to);
    container
}

fn fill(container: &mut ServiceContainer<Versioned>, from: u64, to: u64) {
    for index in from..=to {
        assert_eq!(
            container.apply(&raw(index, Vec::new())),
            Ok(Applied::Nothing)
        );
    }
}

fn activation(service: u32, schema: u16, configuration: &[u8]) -> Vec<u8> {
    Activation::new(ActiveVersion::new(service, schema), 100, configuration)
        .to_vec()
        .unwrap()
}

/// A-11: pending at its entry; service 2 active from the entry at index
/// 107, never before, and that entry runs under it.
#[test]
fn test_a11_an_activation_changes_the_version_at_its_index() {
    let mut container = up_to(2, 6);
    assert_eq!(container.active_version(), ActiveVersion::INITIAL);
    assert_eq!(
        container.apply(&raw(7, activation(2, 1, &[]))),
        Ok(Applied::Nothing)
    );
    assert_eq!(
        container.pending_activation(),
        Some((ActiveVersion::new(2, 1), 107))
    );
    assert_eq!(container.active_version(), ActiveVersion::INITIAL);
    container.apply(&request(8, 0, &[1])).unwrap();
    fill(&mut container, 9, 106);
    assert_eq!(container.active_version(), ActiveVersion::INITIAL);
    container.apply(&request(107, 1, &[1])).unwrap();
    assert_eq!(container.active_version(), ActiveVersion::new(2, 1));
    assert_eq!(container.pending_activation(), None);
    assert_eq!(
        container.service().seen,
        vec![
            (8, ActiveVersion::INITIAL, vec![1]),
            (107, ActiveVersion::new(2, 1), vec![1]),
        ]
    );
}

/// A-12 and A-13: a configuration-only and a schema-only change are
/// pending changes; the configuration reaches the service right before
/// the entry at the activation index, with its context.
#[test]
fn test_a12_a13_configuration_only_and_schema_only_changes() {
    let mut container = up_to(1, 6);
    assert_eq!(
        container.apply(&raw(7, activation(1, 1, &[1]))),
        Ok(Applied::Nothing)
    );
    fill(&mut container, 8, 106);
    assert!(container.service().seen.is_empty());
    container.apply(&request(107, 0, &[1])).unwrap();
    assert_eq!(
        container.service().seen,
        vec![
            (107, ActiveVersion::INITIAL, vec![0xc0, 1]),
            (107, ActiveVersion::INITIAL, vec![1]),
        ]
    );
    let mut container = up_to(1, 6);
    assert_eq!(
        container.apply(&raw(7, activation(1, 2, &[]))),
        Ok(Applied::Nothing)
    );
    fill(&mut container, 8, 107);
    assert_eq!(container.active_version(), ActiveVersion::new(1, 2));
}

/// A-14 to A-16, and an index past `u64::MAX`: each refused activation
/// changes nothing, the same on every replica.
#[test]
fn test_a14_to_a16_a_refused_activation_changes_nothing() {
    let mut container = up_to(2, 6);
    assert_eq!(
        container.apply(&raw(7, activation(1, 1, &[]))),
        Ok(Applied::CoreRefused(CoreRefusal::NoChange)),
        "A-14"
    );
    assert_eq!(container.pending_activation(), None);
    assert_eq!(container.applied(), Some(7));
    // A-15: active service 2, then service 1.
    assert_eq!(
        container.apply(&raw(8, activation(2, 1, &[]))),
        Ok(Applied::Nothing)
    );
    fill(&mut container, 9, 108);
    assert_eq!(container.active_version(), ActiveVersion::new(2, 1));
    assert_eq!(
        container.apply(&raw(109, activation(1, 1, &[]))),
        Ok(Applied::CoreRefused(CoreRefusal::Falls)),
        "A-15"
    );
    let mut container = up_to(2, 6);
    assert_eq!(
        container.apply(&raw(7, activation(2, 1, &[]))),
        Ok(Applied::Nothing)
    );
    assert_eq!(
        container.apply(&raw(8, activation(2, 1, &[]))),
        Ok(Applied::CoreRefused(CoreRefusal::Pending)),
        "A-16"
    );
    assert_eq!(
        container.pending_activation(),
        Some((ActiveVersion::new(2, 1), 107))
    );
    // A schema version below the active one falls too.
    let mut container = up_to(2, 6);
    assert_eq!(
        container.apply(&raw(7, activation(1, 2, &[]))),
        Ok(Applied::Nothing)
    );
    fill(&mut container, 8, 107);
    assert_eq!(container.active_version(), ActiveVersion::new(1, 2));
    assert_eq!(
        container.apply(&raw(108, activation(2, 1, &[]))),
        Ok(Applied::CoreRefused(CoreRefusal::Falls)),
        "a schema that falls"
    );
    let mut container = up_to(2, 6);
    let far = Activation::new(ActiveVersion::new(2, 1), u64::MAX, &[])
        .to_vec()
        .unwrap();
    assert_eq!(
        container.apply(&raw(7, far)),
        Ok(Applied::CoreRefused(CoreRefusal::Overflow))
    );
    assert_eq!(container.pending_activation(), None);
}

/// A-17: an activation above the binary's version applies as pending; the
/// container stops at the activation index, not before.
#[test]
fn test_a17_a_binary_below_the_activated_version_stops_at_the_index() {
    let mut container = up_to(2, 6);
    assert_eq!(
        container.apply(&raw(7, activation(9, 1, &[]))),
        Ok(Applied::Nothing)
    );
    fill(&mut container, 8, 106);
    assert_eq!(
        container.apply(&raw(107, Vec::new())),
        Err(ApplyError::VersionUnsupported {
            required: 9,
            supported: 2
        })
    );
    assert_eq!(container.applied(), Some(106));
    assert_eq!(container.active_version(), ActiveVersion::INITIAL);
}

/// Rule 1 at the leader: a command needing more than the active version,
/// or of a type no version knows, is refused before anything is
/// appended, even while a higher activation is pending.
#[test]
fn test_the_leader_refuses_a_command_the_active_version_cannot_run() {
    #[derive(Default)]
    struct Core(Vec<Vec<u8>>);
    impl Propose for Core {
        fn propose(&mut self, payload: Vec<u8>) -> Result<(), NotLeader> {
            self.0.push(payload);
            Ok(())
        }
    }
    let mut container = up_to(2, 6);
    let mut core = Core::default();
    let command = |command: &'static [u8]| Envelope::Request {
        request: Request::new(7, 1, 0, 0),
        command,
    };
    assert_eq!(
        container.propose(&command(&[9]), &mut core),
        Err(ProposeRefused::VersionInactive {
            required: Some(2),
            active: ActiveVersion::INITIAL
        })
    );
    assert_eq!(
        container.propose(&command(&[8]), &mut core),
        Err(ProposeRefused::VersionInactive {
            required: None,
            active: ActiveVersion::INITIAL
        })
    );
    container.propose(&command(&[1]), &mut core).unwrap();
    assert_eq!(core.0.len(), 1);
    assert_eq!(
        container.apply(&raw(7, activation(2, 1, &[]))),
        Ok(Applied::Nothing)
    );
    assert!(matches!(
        container.propose(&command(&[9]), &mut core),
        Err(ProposeRefused::VersionInactive { .. })
    ));
    fill(&mut container, 8, 107);
    container.propose(&command(&[9]), &mut core).unwrap();
    assert_eq!(core.0.len(), 2);
}

/// Rule 1 when applied: a command logged past the leader's check (a
/// direct proposal, an older leader) reaches no service code and applies
/// as the same refusal on every replica.
#[test]
fn test_a_command_the_active_version_cannot_run_is_refused_when_applied() {
    let mut container = up_to(2, 6);
    assert_eq!(
        container.apply(&request(7, 0, &[9])),
        Ok(Applied::CoreRefused(CoreRefusal::VersionInactive {
            active: ActiveVersion::INITIAL
        }))
    );
    assert_eq!(
        container.apply(&request(8, 0, &[8])),
        Ok(Applied::CoreRefused(CoreRefusal::VersionInactive {
            active: ActiveVersion::INITIAL
        }))
    );
    assert!(container.service().seen.is_empty());
    assert_eq!(container.applied(), Some(8));
    assert_eq!(container.sessions().log_time(), 8);
}

/// Rule 2: before activation, a binary newer than the active version
/// gives byte-identical state to an old one.
#[test]
fn test_a_newer_binary_runs_the_old_semantics_before_activation() {
    let log: Vec<Entry> = (2..=40)
        .map(|index| match index {
            7 => raw(7, activation(2, 1, &[5])),
            index if index % 3 == 0 => {
                request(index, index / 3 - 1, &[1, u8::try_from(index).unwrap()])
            }
            index => raw(index, Vec::new()),
        })
        .collect();
    let run = |supported| {
        let mut container = container(supported);
        container
            .apply(&raw(1, Envelope::Register { client: 7 }.to_vec().unwrap()))
            .unwrap();
        for entry in &log {
            container.apply(entry).unwrap();
        }
        let mut parts = ServiceSnapshot::new(64, 1);
        let sections: Vec<Vec<u8>> = container
            .snapshot(&mut parts)
            .unwrap()
            .sections()
            .iter()
            .map(|section| section.bytes.to_vec())
            .collect();
        (container.service().seen.clone(), sections)
    };
    assert_eq!(run(1), run(2));
}

fn stop(offset: u64, resume: u32) -> Vec<u8> {
    CoordinatedStop::new(offset, resume).to_vec().unwrap()
}

fn reads(container: &ServiceContainer<Versioned>) -> Vec<SectionRead> {
    let mut parts = ServiceSnapshot::new(64, 1);
    container
        .snapshot(&mut parts)
        .unwrap()
        .sections()
        .iter()
        .map(|section| SectionRead {
            kind: section.kind,
            version: section.version,
            bytes: section.bytes.to_vec(),
        })
        .collect()
}

/// C-5 and C-6: every replica applies up to the stop index, snapshots
/// there, and stops at the next entry; the leader refuses proposals once
/// the stop is logged.
#[test]
fn test_c5_c6_a_coordinated_stop_stops_after_its_index() {
    for (offset, at) in [(500, 510), (0, 10)] {
        let mut container = up_to(1, 9);
        assert_eq!(
            container.apply(&raw(10, stop(offset, 3))),
            Ok(Applied::Nothing)
        );
        assert_eq!(container.stop(), Some((at, 3)));
        struct Core;
        impl Propose for Core {
            fn propose(&mut self, _: Vec<u8>) -> Result<(), NotLeader> {
                Ok(())
            }
        }
        assert_eq!(
            container.propose(
                &Envelope::TimerFired {
                    timer: 1,
                    deadline: 1
                },
                &mut Core
            ),
            Err(ProposeRefused::Stopping)
        );
        assert_eq!(
            container.propose_stop(&CoordinatedStop::new(1, 4), &mut Core),
            Err(ProposeRefused::Stopping)
        );
        fill(&mut container, 11, at);
        assert_eq!(container.applied(), Some(at));
        let _ = reads(&container);
        assert_eq!(
            container.apply(&request(at + 1, 0, &[1])),
            Err(ApplyError::Stopped { at, resume: 3 }),
            "stopped at {}",
            at + 1
        );
        assert_eq!(container.applied(), Some(at));
    }
}

/// C-7, and the other refused stops: each stops nothing.
#[test]
fn test_c7_a_refused_stop_stops_nothing() {
    let mut container = up_to(2, 9);
    assert_eq!(
        container.apply(&raw(10, stop(500, 1))),
        Ok(Applied::CoreRefused(CoreRefusal::NoChange)),
        "C-7"
    );
    assert_eq!(
        container.apply(&raw(11, stop(u64::MAX, 3))),
        Ok(Applied::CoreRefused(CoreRefusal::Overflow))
    );
    assert_eq!(container.stop(), None);
    container.apply(&request(12, 0, &[1])).unwrap();
    assert_eq!(
        container.apply(&raw(13, activation(2, 1, &[]))),
        Ok(Applied::Nothing)
    );
    fill(&mut container, 14, 113);
    assert_eq!(
        container.apply(&raw(114, stop(0, 1))),
        Ok(Applied::CoreRefused(CoreRefusal::Falls))
    );
    assert_eq!(container.apply(&raw(115, stop(5, 3))), Ok(Applied::Nothing));
    assert_eq!(
        container.apply(&raw(116, stop(0, 4))),
        Ok(Applied::CoreRefused(CoreRefusal::Pending))
    );
}

/// Resuming: a binary that runs the resume version restores from the
/// stop's snapshot; every schema 2 entry past the stop is `PastStop` until
/// the resuming `Activation` applies, and then runs again.
#[test]
fn test_a_resumed_cluster_refuses_old_entries_until_its_activation() {
    let mut old = up_to(1, 9);
    assert_eq!(old.apply(&raw(10, stop(0, 3))), Ok(Applied::Nothing));
    let snapshot = reads(&old);
    let mut new = container(3);
    new.restore(10, &snapshot).unwrap();
    assert_eq!(new.stop(), Some((10, 3)));
    assert_eq!(
        new.apply(&request(11, 0, &[1])),
        Ok(Applied::CoreRefused(CoreRefusal::PastStop))
    );
    assert_eq!(
        new.apply(&raw(12, activation(3, 1, &[]))),
        Ok(Applied::Nothing)
    );
    assert_eq!(new.stop(), None);
    new.apply(&request(13, 0, &[1])).unwrap();
    assert_eq!(
        new.service().seen,
        vec![(13, ActiveVersion::INITIAL, vec![1])]
    );
    fill(&mut new, 14, 112);
    assert_eq!(new.active_version(), ActiveVersion::new(3, 1));
}

/// Decision 5: the sessions section of version 2 carries the active
/// version, a pending activation and a logged stop; version 1 restores
/// as the state before any `Activation`.
#[test]
fn test_a_snapshot_carries_the_version_state() {
    let mut source = up_to(2, 6);
    assert_eq!(
        source.apply(&raw(7, activation(2, 1, &[4]))),
        Ok(Applied::Nothing)
    );
    fill(&mut source, 8, 107);
    assert_eq!(
        source.apply(&raw(108, activation(2, 3, &[7, 7]))),
        Ok(Applied::Nothing)
    );
    assert_eq!(source.apply(&raw(109, stop(5, 3))), Ok(Applied::Nothing));
    let sections = reads(&source);
    let sessions = sections
        .iter()
        .find(|section| section.kind == SectionKind::Sessions)
        .unwrap();
    assert_eq!(sessions.version, SESSIONS_SECTION_VERSION);
    let mut restored = container(2);
    restored.restore(109, &sections).unwrap();
    assert_eq!(restored.active_version(), ActiveVersion::new(2, 1));
    assert_eq!(
        restored.pending_activation(),
        Some((ActiveVersion::new(2, 3), 208))
    );
    assert_eq!(restored.stop(), Some((114, 3)));
    assert_eq!(restored.versions, source.versions);
    // The pending configuration activates on the restored replica.
    fill(&mut restored, 110, 114);
    assert_eq!(
        restored.apply(&raw(115, Vec::new())),
        Err(ApplyError::Stopped { at: 114, resume: 3 })
    );
    // Version 1: the session table alone, as before any `Activation`.
    let fresh = up_to(1, 6);
    let mut v1 = reads(&fresh);
    for section in &mut v1 {
        if section.kind == SectionKind::Sessions {
            section.version = SESSIONS_SECTION_VERSION_1;
            section.bytes.drain(..7);
        }
    }
    let mut restored = container(1);
    restored.restore(6, &v1).unwrap();
    assert_eq!(restored.active_version(), ActiveVersion::INITIAL);
    assert_eq!(restored.versions, Versions::default());
    // A snapshot whose active version is above the binary's.
    let mut target = container(1);
    assert_eq!(
        target.restore(109, &sections),
        Err(RestoreError::VersionUnsupported {
            active: 2,
            supported: 1
        })
    );
    // A pending activation at or before the snapshot's index.
    assert_eq!(
        container(2).restore(208, &sections),
        Err(RestoreError::Versions)
    );
    // Unknown flags.
    let mut flags = sections.clone();
    for section in &mut flags {
        if section.kind == SectionKind::Sessions {
            section.bytes[6] |= 8;
        }
    }
    assert_eq!(
        container(2).restore(109, &flags),
        Err(RestoreError::Versions)
    );
}

/// The version state's bytes, field by field.
#[test]
fn test_the_version_state_layout() {
    let versions = Versions {
        active: ActiveVersion::new(2, 1),
        configured: true,
        pending: Some(Pending {
            version: ActiveVersion::new(3, 2),
            at: 0x0102,
            configuration: vec![0xaa],
        }),
        stop: Some(Stop { at: 9, resume: 4 }),
    };
    let mut out = Vec::new();
    versions.encode(&mut out);
    assert_eq!(
        out,
        hex("02 00 00 00 01 00 07
             03 00 00 00 02 00 02 01 00 00 00 00 00 00 01 00 aa
             09 00 00 00 00 00 00 00 04 00 00 00")
    );
    out.push(0xee);
    assert_eq!(Versions::decode(&out, 9), Some((versions, &[0xee][..])));
}

/// B-8 as ADR-0122 reissued it, through the container's own decoder:
/// template 5 is the first one unknown, and it stops the replica.
#[test]
fn test_b8_reissued_template_5_stops_the_container() {
    let b8 = hex("05 00 05 00 01 00 14 00 20 00 00 00
        40 00 00 00 40 00 00 00 00 20 00 00 00 58 47 f8 0d 00 00 00");
    let mut container = container(1);
    assert_eq!(
        container.apply(&raw(1, b8)),
        Err(ApplyError::Envelope(CodecError::UnsupportedSchema {
            schema: 5,
            template: 5,
            version: 1
        }))
    );
}

/// The input bytes of the applied vectors A-11 to A-17 and C-5 to C-7,
/// as a session without the code derived them from the design note §4.1
/// (ADR-0087's golden rule): the helpers above encode exactly these.
#[test]
fn test_applied_vector_inputs_are_the_golden_bytes() {
    let head = "05 00 03 00 02 00 0e 00";
    for (label, bytes, golden) in [
        (
            "A-11",
            activation(2, 1, &[]),
            format!("{head} 1c 00 00 00 02 00 00 00 01 00 64 00 00 00 00 00 00 00 00 00"),
        ),
        (
            "A-12",
            activation(1, 1, &[1]),
            format!("{head} 1d 00 00 00 01 00 00 00 01 00 64 00 00 00 00 00 00 00 01 00 01"),
        ),
        (
            "A-13",
            activation(1, 2, &[]),
            format!("{head} 1c 00 00 00 01 00 00 00 02 00 64 00 00 00 00 00 00 00 00 00"),
        ),
        (
            "A-14",
            activation(1, 1, &[]),
            format!("{head} 1c 00 00 00 01 00 00 00 01 00 64 00 00 00 00 00 00 00 00 00"),
        ),
        (
            "A-17",
            activation(9, 1, &[]),
            format!("{head} 1c 00 00 00 09 00 00 00 01 00 64 00 00 00 00 00 00 00 00 00"),
        ),
        (
            "C-5",
            stop(500, 3),
            "05 00 04 00 02 00 0c 00 18 00 00 00 f4 01 00 00 00 00 00 00 03 00 00 00".to_owned(),
        ),
        (
            "C-6",
            stop(0, 3),
            "05 00 04 00 02 00 0c 00 18 00 00 00 00 00 00 00 00 00 00 00 03 00 00 00".to_owned(),
        ),
        (
            "C-7",
            stop(500, 1),
            "05 00 04 00 02 00 0c 00 18 00 00 00 f4 01 00 00 00 00 00 00 01 00 00 00".to_owned(),
        ),
    ] {
        assert_eq!(bytes, hex(&golden), "{label}");
    }
}

/// Templates 3 and 4 exist only at version 2: at version 1 each is
/// `UnsupportedSchema` with the input's own tuple (design note §4.1).
#[test]
fn test_templates_3_and_4_at_version_1_are_unsupported() {
    let mut a1 = hex(A1);
    a1[4] = 1;
    assert_eq!(
        Activation::decode(&a1),
        Err(CodecError::UnsupportedSchema {
            schema: 5,
            template: 3,
            version: 1
        })
    );
    let mut c1 = hex(C1);
    c1[4] = 1;
    assert_eq!(
        CoordinatedStop::decode(&c1),
        Err(CodecError::UnsupportedSchema {
            schema: 5,
            template: 4,
            version: 1
        })
    );
}

/// ADR-0122 decision 6 at the leader: once it appended a
/// `CoordinatedStop`, before it applies, the leader refuses every
/// proposal, the resuming `Activation` and the core's own entries
/// included. A node that knows the stop only from the log, as the first
/// leader after the restart does, still proposes the `Activation`.
#[test]
fn test_the_leader_that_appended_a_stop_refuses_every_proposal() {
    #[derive(Default)]
    struct Core(usize);
    impl Propose for Core {
        fn propose(&mut self, _: Vec<u8>) -> Result<(), NotLeader> {
            self.0 += 1;
            Ok(())
        }
    }
    let mut leader = up_to(2, 9);
    let mut core = Core::default();
    leader
        .propose_stop(&CoordinatedStop::new(5, 3), &mut core)
        .unwrap();
    assert_eq!(core.0, 1);
    assert_eq!(leader.stop(), None, "appended, not applied");
    let resume = Activation::new(ActiveVersion::new(3, 1), 1, &[]);
    assert_eq!(
        leader.propose_activation(&resume, &mut core),
        Err(ProposeRefused::Stopping)
    );
    assert_eq!(
        leader.propose(
            &Envelope::TimerFired {
                timer: 1,
                deadline: 1
            },
            &mut core
        ),
        Err(ProposeRefused::Stopping)
    );
    assert_eq!(
        leader.propose_stop(&CoordinatedStop::new(5, 3), &mut core),
        Err(ProposeRefused::Stopping)
    );
    assert_eq!(leader.propose_bounds(&mut core), Ok(false));
    assert_eq!(leader.propose_guard_bounds(&mut core), Ok(false));
    assert_eq!(core.0, 1, "nothing more proposed");
    // The resumed node: the stop is in its log, it appended none.
    let mut old = up_to(1, 9);
    assert_eq!(old.apply(&raw(10, stop(0, 3))), Ok(Applied::Nothing));
    let mut new = container(3);
    new.restore(10, &reads(&old)).unwrap();
    assert_eq!(new.propose_activation(&resume, &mut core), Ok(()));
    assert_eq!(core.0, 2);
}

/// While versions are mixed, a command only the new version knows applies
/// as the same refusal on an old and a new binary: the outcome carries
/// only the log's active version, not each binary's reading of the
/// version the command needs (ADR-0122 decision 3).
#[test]
fn test_a_new_command_type_applies_identically_on_an_old_and_a_new_binary() {
    let mut old = up_to(1, 6);
    let mut new = up_to(2, 6);
    let left = old.apply(&request(7, 0, &[9]));
    let right = new.apply(&request(7, 0, &[9]));
    assert_eq!(
        left,
        Ok(Applied::CoreRefused(CoreRefusal::VersionInactive {
            active: ActiveVersion::INITIAL
        }))
    );
    assert_eq!(left, right);
    assert_eq!(format!("{left:?}"), format!("{right:?}"));
    assert_eq!(old.applied(), new.applied());
    assert!(old.service().seen.is_empty() && new.service().seen.is_empty());
}

/// An entry at the activation index that stops the container (here
/// different bounds under a session) stops it before the activation:
/// the version, the pending activation and the service are unchanged, so
/// a snapshot never holds the next version under the previous index.
#[test]
fn test_an_entry_that_stops_at_the_activation_index_changes_no_version() {
    let mut container = up_to(2, 6);
    assert_eq!(
        container.apply(&raw(7, activation(2, 1, &[5]))),
        Ok(Applied::Nothing)
    );
    fill(&mut container, 8, 106);
    let logged = container.sessions().config().with_window(2);
    let bounds = super::super::SessionBounds::new(logged).to_vec().unwrap();
    assert!(matches!(
        container.apply(&raw(107, bounds)),
        Err(ApplyError::BoundsDiffer { .. })
    ));
    assert_eq!(container.applied(), Some(106));
    assert_eq!(container.active_version(), ActiveVersion::INITIAL);
    assert_eq!(
        container.pending_activation(),
        Some((ActiveVersion::new(2, 1), 107))
    );
    assert!(container.service().seen.is_empty(), "no on_configuration");
}
