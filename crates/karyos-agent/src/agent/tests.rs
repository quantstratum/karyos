// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

use std::time::Instant;

use karyos_driver::{DriverConfig, EmbeddedDriver, IpcConfig, SystemClock};
use karyos_sys::term_bytes::SharedTerms;

use super::*;
use crate::api::AlertKind;
use crate::operations::GuardAnswer;

type IpcDriver = EmbeddedDriver<SharedTerms>;

fn driver(dir: &Path) -> IpcDriver {
    EmbeddedDriver::with_ipc(
        DriverConfig::default(),
        IpcConfig {
            dir: dir.to_path_buf(),
            max_pending_hellos: 4,
            hello_timeout: 5_000_000_000,
            max_outbound_per_client: 8,
            fetch_deadline: 5_000_000_000,
            max_exports_per_client: 16,
            max_fetches_per_client: 4,
            max_regions_per_fetch: 4,
            max_fetch_bytes: 1 << 30,
            max_tools: 4,
        },
        Box::new(SystemClock::new()),
    )
    .unwrap()
}

/// Runs `call` on another thread while this one serves `driver`.
fn serving<R: Send>(driver: &mut IpcDriver, call: impl FnOnce() -> R + Send) -> R {
    std::thread::scope(|scope| {
        let handle = scope.spawn(call);
        let start = Instant::now();
        while !handle.is_finished() {
            assert!(start.elapsed() < Duration::from_secs(30), "stuck");
            let _ = driver.do_work().unwrap();
            std::thread::sleep(Duration::from_micros(200));
        }
        handle.join().unwrap()
    })
}

/// The Audited operations row's local remainder (phase-5-gate-status.md):
/// a guard close while the journal is down, then the agent host fails.
/// The close reaches the driver anyway (failing toward safety), audited
/// for the operator; the journal's alert is raised at once; a reopen is
/// refused. After the crash, the next start finds no clean stop and
/// records an unclean stop, which is an alert until acknowledged: the
/// close made unrecorded falls in that interval.
#[test]
fn a_close_while_the_journal_is_down_then_a_crash_leaves_an_unclean_stop() {
    let dir = std::env::temp_dir().join(format!("karyos-agent-down-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let driver_dir = dir.join("driver");
    let mut driver = driver(&driver_dir);
    let guard = driver.add_guard("orders").unwrap();
    let config = AgentConfig::new(vec![driver_dir.clone()])
        .with_attach_timeout(Duration::from_secs(5))
        .with_journal(dir.join("journal"));
    let mut agent = Agent::new(config.clone());
    assert_eq!(agent.view().journal.unwrap().gap, None);
    // The journal goes down: its next append fails.
    agent.journal.as_mut().unwrap().break_recorder();
    let answer = serving(&mut driver, || {
        agent.guard_close(&driver_dir, guard.id(), 1000, b"halt")
    });
    // Sent anyway: the guard was created closed, and stays closed.
    assert!(
        matches!(answer, GuardAnswer::State { state, .. } if !state.open),
        "{answer:?}"
    );
    let audited = driver.guard_audit();
    assert!(matches!(
        audited.records.last().unwrap().requester,
        karyos_driver::Requester::Operator { uid: 1000, .. }
    ));
    let journal = agent.view().journal.unwrap();
    assert!(journal.unavailable);
    assert!(journal.failed_appends >= 1);
    assert!(
        journal
            .alerts
            .iter()
            .any(|alert| alert.kind == AlertKind::JournalGap && alert.participant == u64::MAX)
    );
    // A reopen fails closed.
    let answer = serving(&mut driver, || {
        agent.guard_reopen(&driver_dir, guard.id(), 1, 1000, b"")
    });
    assert_eq!(answer, GuardAnswer::JournalUnavailable);
    // The host fails: no clean stop.
    drop(agent);
    let agent = Agent::new(config);
    let journal = agent.view().journal.unwrap();
    let gap = journal.gap.unwrap();
    assert_eq!(gap.reason, "unclean_stop");
    assert!(
        journal
            .alerts
            .iter()
            .any(|alert| alert.kind == AlertKind::JournalGap && alert.participant == gap.position)
    );
    drop(agent);
    let _ = std::fs::remove_dir_all(&dir);
}
