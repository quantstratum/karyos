// SPDX-License-Identifier: Apache-2.0

// karyos#716: the rolling-upgrade evidence. The generator draws unknown
// inputs; a version 1 and a version 2 binary handle a log at version 1
// identically; each deliberate semantic change (a result, an accept where
// the other refuses, a typed refusal) is a divergence, in process and
// through the journals karyos-replay diff compares.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::sync::atomic::{AtomicU64, Ordering};

use karyos_archive::group::diff::{DiffRequest, Journal, Report, diff};

use super::*;

/// Seeds the tests run: the evidence names its seeds the same way.
const SEEDS: std::ops::Range<u64> = 1..33;
const COUNT: u64 = 400;

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "karyos-upgrade-evidence-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A deliberate semantic change of the reference service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Change {
    /// An add's result is one more.
    Result,
    /// Command type 3 runs from version 1: accepted where the other
    /// binary refuses.
    Accepts,
    /// Command type 2 is unknown: refused where the other runs it.
    Refuses,
    /// A timer is not counted: only the snapshot tells.
    State,
}

struct Changed {
    inner: Reference,
    change: Change,
}

impl ClusteredService for Changed {
    fn on_command(
        &mut self,
        context: &mut Context<'_>,
        client: u64,
        command: &[u8],
        reply: &mut [u8],
    ) -> Option<usize> {
        let mut command = command.to_vec();
        if self.change == Change::Result && command.first() == Some(&1) && command.len() > 2 {
            command[2] = command[2].wrapping_add(1);
        }
        self.inner.on_command(context, client, &command, reply)
    }

    fn on_timer(&mut self, context: &mut Context<'_>, timer: u64) {
        if self.change != Change::State {
            self.inner.on_timer(context, timer);
        }
    }

    fn on_configuration(&mut self, context: &mut Context<'_>, configuration: &[u8]) {
        self.inner.on_configuration(context, configuration);
    }

    fn snapshot(&self, parts: &mut ServiceSnapshot) -> Result<(), SnapshotFull> {
        self.inner.snapshot(parts)
    }

    fn required_version(&self, command: &[u8]) -> Option<u32> {
        match (self.change, command.first()) {
            (Change::Accepts, Some(3)) => Some(1),
            (Change::Refuses, Some(2)) => None,
            _ => self.inner.required_version(command),
        }
    }

    fn supported_version(&self) -> u32 {
        self.inner.supported_version()
    }
}

fn changed(change: Change) -> Changed {
    Changed {
        inner: Reference::new(2),
        change,
    }
}

/// The generator is a function of its seed, and draws every kind the
/// rule names, unknown ones included.
#[test]
fn test_the_generator_draws_known_and_unknown_inputs() {
    assert_eq!(generate(7, COUNT, 1), generate(7, COUNT, 1));
    assert_ne!(generate(7, COUNT, 1), generate(8, COUNT, 1));
    let mut unknown_schema = 0;
    let mut unknown_version = 0;
    let mut unknown_template = 0;
    let mut unknown_command = 0;
    let mut garbage = 0;
    let mut core = 0;
    // The unknown inputs end each sequence: many short ones.
    let probes = (1..257).filter_map(|seed| generate(seed, 20, 2).pop());
    let body = SEEDS.flat_map(|seed| generate(seed, COUNT - 1, 2));
    for entry in probes.chain(body) {
        {
            let bytes = &entry.payload;
            if bytes.len() < 12 {
                if !bytes.is_empty() {
                    garbage += 1;
                }
                continue;
            }
            let field = |at: usize| u16::from_le_bytes([bytes[at], bytes[at + 1]]);
            let (schema, template, version) = (field(0), field(2), field(4));
            match (schema, template, version) {
                (2, 3, 1) => {
                    if let Ok(Envelope::Request { command, .. }) = Envelope::decode(bytes)
                        && !matches!(command.first(), Some(1..=3))
                    {
                        unknown_command += 1;
                    }
                }
                (2, 6.., _) | (5, 6.., _) => unknown_template += 1,
                (2, _, 2..) | (5, 3, 3..) => unknown_version += 1,
                (2 | 5 | 6, _, _) => core += 1,
                _ => unknown_schema += 1,
            }
        }
    }
    for (label, count) in [
        ("unknown schemas", unknown_schema),
        ("unknown schema versions", unknown_version),
        ("unknown templates", unknown_template),
        ("unknown command types", unknown_command),
        ("bytes that are no message", garbage),
        ("core entries", core),
    ] {
        assert!(count > 5, "{label}: only {count}");
    }
}

/// A version 1 binary and a version 2 binary of the reference service
/// handle every generated sequence at version 1 identically, stops and
/// refusals included.
#[test]
fn test_a_version_1_and_a_version_2_binary_agree_on_every_seed() {
    let mut stops = 0;
    for seed in SEEDS {
        let steps = differential(Reference::new(1), Reference::new(2), seed, COUNT, 1);
        assert!(steps.is_ok(), "seed {seed}: {steps:?}");
        let mut container =
            ServiceContainer::new(Reference::new(1), ContainerConfig::default()).unwrap();
        let replayed = replay(&mut container, generate(seed, COUNT, 1)).unwrap();
        // Each sequence ends at its unknown input's stop, compared too.
        let last = &replayed[replayed.len() - 2].outcome;
        assert!(last.starts_with("Err("), "seed {seed}: {last}");
        if replayed.len() == usize::try_from(COUNT).unwrap() + 1 {
            stops += 1;
        }
    }
    // Most run their whole length: the body is known inputs.
    assert!(stops > 16, "only {stops} sequences ran whole");
    // And timers fire: the timer path is compared too.
    let fired = SEEDS
        .clone()
        .flat_map(|seed| {
            let mut container =
                ServiceContainer::new(Reference::new(1), ContainerConfig::default()).unwrap();
            replay(&mut container, generate(seed, COUNT, 1)).unwrap()
        })
        .filter(|step| step.outcome.starts_with("Ok(Fired"))
        .count();
    assert!(fired > 10, "only {fired} timers fired");
}

/// Each deliberate semantic change between the two revisions is found.
#[test]
fn test_each_semantic_change_is_a_divergence() {
    for change in [
        Change::Result,
        Change::Accepts,
        Change::Refuses,
        Change::State,
    ] {
        let found = SEEDS.clone().find_map(|seed| {
            differential(Reference::new(2), changed(change), seed, COUNT, 1).err()
        });
        let divergence = found.unwrap_or_else(|| panic!("{change:?} not found"));
        assert_ne!(divergence.old, divergence.new, "{change:?}");
        if change == Change::Accepts {
            let old = divergence.old.unwrap().outcome;
            let new = divergence.new.unwrap().outcome;
            assert!(old.contains("VersionInactive"), "{old}");
            assert!(new.contains("Answered"), "{new}");
        }
    }
}

/// A command type only the new version knows is refused by both binaries
/// with byte-identical outcomes, with no normalisation.
#[test]
fn test_a_new_command_type_is_refused_alike_by_both() {
    let entries = vec![
        Entry {
            index: 1,
            term: 1,
            event_time: 1,
            payload: Envelope::Register { client: 1 }.to_vec().unwrap(),
        },
        Entry {
            index: 2,
            term: 1,
            event_time: 2,
            payload: Envelope::Request {
                request: Request::new(1, 1, 0, 0),
                command: &[3, 1],
            }
            .to_vec()
            .unwrap(),
        },
    ];
    let mut old = ServiceContainer::new(Reference::new(1), ContainerConfig::default()).unwrap();
    let mut new = ServiceContainer::new(Reference::new(2), ContainerConfig::default()).unwrap();
    let left = replay(&mut old, entries.clone()).unwrap();
    let right = replay(&mut new, entries).unwrap();
    assert_eq!(compare(&left, &right), Ok(3));
    assert_eq!(left[1].outcome, right[1].outcome);
    assert!(left[1].outcome.contains("VersionInactive { active"));
}

fn journals(scratch: &Scratch, name: &str, steps: &[Step], manifest: &str) -> Journal {
    let dir = scratch.0.join(name);
    write_journal(&dir, manifest, steps).unwrap();
    Journal { dir, group: 1 }
}

fn request(left: Journal, right: Journal) -> DiffRequest {
    DiffRequest {
        left,
        right,
        from: None,
        to: None,
        accept_manifest: true,
        from_checkpoint: None,
    }
}

/// Through the journals: the same replay is identical under
/// karyos-replay diff's comparison, and a semantic change diverges.
#[test]
fn test_the_journals_compare_clean_and_a_change_diverges() {
    let scratch = Scratch::new("journals");
    let entries = generate(3, COUNT, 1);
    let run = |service: Reference| {
        let mut container = ServiceContainer::new(service, ContainerConfig::default()).unwrap();
        replay(&mut container, entries.clone()).unwrap()
    };
    let old = journals(&scratch, "old", &run(Reference::new(1)), "old");
    let new = journals(&scratch, "new", &run(Reference::new(2)), "new");
    let report = diff(&request(old.clone(), new));
    assert!(matches!(report, Report::Identical { .. }), "{report:?}");
    let mut container =
        ServiceContainer::new(changed(Change::Result), ContainerConfig::default()).unwrap();
    let changed = journals(
        &scratch,
        "changed",
        &replay(&mut container, entries.clone()).unwrap(),
        "changed",
    );
    let report = diff(&request(old, changed));
    assert!(matches!(report, Report::Diverged { .. }), "{report:?}");
}

/// `record`, then `replay` of the recorded log, from the command line:
/// two binaries' journals of one log compare clean.
#[test]
fn test_the_command_replays_a_recorded_log() {
    let scratch = Scratch::new("command");
    let log = scratch.0.join("log");
    let path = |name: &str| scratch.0.join(name).into_os_string();
    let run_args = |args: Vec<OsString>| {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run(args, &mut out, &mut err);
        assert_eq!(code, 0, "{}", String::from_utf8_lossy(&err));
    };
    let strings = |args: &[&str]| args.iter().map(OsString::from).collect::<Vec<_>>();
    let mut record = strings(&[
        "record",
        "--seed",
        "5",
        "--count",
        "300",
        "--geometry",
        "65536,65536",
        "--log",
    ]);
    record.push(log.clone().into_os_string());
    run_args(record);
    for (name, supported) in [("old", "1"), ("new", "2")] {
        let mut args = strings(&[
            "replay",
            "--geometry",
            "65536,65536",
            "--supported",
            supported,
            "--manifest",
            name,
            "--log",
        ]);
        args.push(log.clone().into_os_string());
        args.push("--out".into());
        args.push(path(name));
        run_args(args);
    }
    let report = diff(&request(
        Journal {
            dir: scratch.0.join("old"),
            group: 1,
        },
        Journal {
            dir: scratch.0.join("new"),
            group: 1,
        },
    ));
    assert!(matches!(report, Report::Identical { .. }), "{report:?}");
    // The log replayed is the recorded one, whole.
    let entries = read_log(&log, Geometry::new(65_536, 65_536).unwrap()).unwrap();
    assert_eq!(entries, generate(5, 300, 1));
}

/// Bad arguments are an error, never a journal.
#[test]
fn test_bad_arguments_are_an_error() {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    assert_eq!(
        run([OsString::from("nope")], &mut out, &mut err),
        EXIT_ERROR
    );
    assert_eq!(
        run(
            [OsString::from("replay"), OsString::from("--log")],
            &mut out,
            &mut err
        ),
        EXIT_ERROR
    );
    assert_eq!(
        run([OsString::from("generate")], &mut out, &mut err),
        EXIT_ERROR
    );
    assert_eq!(run(Vec::<OsString>::new(), &mut out, &mut err), 0);
    assert!(String::from_utf8_lossy(&out).contains("upgrade-evidence"));
}

/// A value over a record's inline limit is refused, never cut: a cut
/// value would compare clean on its prefix alone.
#[test]
fn test_an_outcome_over_the_record_limit_is_refused_not_cut() {
    let scratch = Scratch::new("oversize");
    let steps = vec![Step {
        entry: None,
        outcome: "x".repeat(MAX_INLINE + 1),
    }];
    let refused = write_journal(&scratch.0.join("j"), "m", &steps).unwrap_err();
    assert!(refused.contains("not recorded"), "{refused}");
    let fits = vec![Step {
        entry: None,
        outcome: "x".repeat(MAX_INLINE),
    }];
    write_journal(&scratch.0.join("k"), "m", &fits).unwrap();
}

/// A log that does not start at index 1 is refused before any replay:
/// both binaries would otherwise record the same `OutOfOrder`.
#[test]
fn test_a_log_that_starts_above_index_1_is_refused() {
    let scratch = Scratch::new("compacted");
    let dir = scratch.0.join("log");
    std::fs::create_dir_all(&dir).unwrap();
    let geometry = Geometry::new(65_536, 65_536).unwrap();
    let entries: Vec<Entry> = generate(5, 10, 1)
        .into_iter()
        .map(|mut entry| {
            entry.index += 4;
            entry
        })
        .collect();
    let mut log = RaftLog::create(StdDisk, &dir, geometry, 5).unwrap();
    let _ = log.append(&entries).unwrap();
    let _ = log.sync().unwrap();
    log.close().unwrap();
    let refused = read_log(&dir, geometry).unwrap_err();
    assert!(refused.contains("starts at index 5"), "{refused}");
}

/// A closing snapshot that cannot be taken makes the replay an error,
/// not a comparable outcome; the default budget holds the reference.
#[test]
fn test_a_snapshot_that_cannot_be_taken_is_not_evidence() {
    let entries = generate(2, 50, 1);
    let mut container =
        ServiceContainer::new(Reference::new(1), ContainerConfig::default()).unwrap();
    let refused =
        replay_with(&mut container, entries.clone(), ServiceSnapshot::new(8, 1)).unwrap_err();
    assert!(refused.contains("closing snapshot"), "{refused}");
    let mut container =
        ServiceContainer::new(Reference::new(1), ContainerConfig::default()).unwrap();
    let steps = replay(&mut container, entries).unwrap();
    let closing = steps.last().unwrap();
    assert!(
        closing.entry.is_none() && !closing.outcome.contains("Full"),
        "{}",
        closing.outcome
    );
}
