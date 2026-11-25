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
            client_send_buffer: None,
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

/// A journal that cannot be opened at start is an unknown interval the
/// journal can never record (#497): the view shows it with its alert
/// until an administrator acknowledges it, in memory only.
#[test]
fn a_journal_that_cannot_open_is_an_alert_until_acknowledged() {
    let dir = std::env::temp_dir().join(format!("karyos-agent-unopened-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // A file where the journal directory should be: the open fails.
    let journal_dir = dir.join("journal");
    std::fs::write(&journal_dir, b"not a directory").unwrap();
    let config = AgentConfig::new(Vec::new()).with_journal(journal_dir);
    let mut agent = Agent::new(config);
    let journal = agent.view().journal.unwrap();
    assert!(journal.unavailable);
    assert!(journal.error.is_some());
    let gap = journal.gap.unwrap();
    assert_eq!(gap.reason, "journal_unavailable_at_start");
    assert_eq!(gap.position, UNOPENED_POSITION);
    assert!(gap.to > 0);
    assert!(
        journal
            .alerts
            .iter()
            .any(|alert| alert.kind == AlertKind::JournalGap && alert.participant == gap.position)
    );
    // Only its own position acknowledges it.
    assert!(matches!(
        agent.acknowledge_gap(0, 0),
        Err(JournalError::NoGap)
    ));
    agent.acknowledge_gap(UNOPENED_POSITION, 0).unwrap();
    let journal = agent.view().journal.unwrap();
    assert_eq!(journal.gap, None);
    assert!(journal.alerts.is_empty());
    // Still unavailable, and still why.
    assert!(journal.unavailable);
    assert!(journal.error.is_some());
    assert!(matches!(
        agent.acknowledge_gap(UNOPENED_POSITION, 0),
        Err(JournalError::NoGap)
    ));
    drop(agent);
    let _ = std::fs::remove_dir_all(&dir);
}

/// R-CORE-24, QS-REVIEWER on #795: a journal that opened and then failed an
/// append refuses reopens and acknowledgements, so `capabilities` reports
/// both unavailable (`journal_unavailable`), whatever the role, rather than
/// served and then refused.
#[test]
fn a_journal_down_at_run_time_makes_reopen_and_gap_ack_unavailable() {
    use crate::api::CapabilityState;

    let dir = std::env::temp_dir().join(format!("karyos-agent-caps-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut agent = Agent::new(AgentConfig::new(Vec::new()).with_journal(dir.join("journal")));
    let state = |agent: &Agent, name: &str| {
        agent
            .capabilities(true, true, true, true)
            .into_iter()
            .find(|capability| capability.name == name)
            .unwrap()
            .state
    };
    assert_eq!(state(&agent, "guard-reopen"), CapabilityState::Served);
    assert_eq!(state(&agent, "gap-ack"), CapabilityState::Served);
    agent.journal.as_mut().unwrap().break_recorder();
    let down = CapabilityState::Unavailable {
        reason: "journal_unavailable",
    };
    assert_eq!(state(&agent, "guard-reopen"), down);
    assert_eq!(state(&agent, "gap-ack"), down);
    assert_eq!(state(&agent, "guard-close"), CapabilityState::Served);
    let _ = std::fs::remove_dir_all(&dir);
}

/// R-CORE-24: `with_agent_id` takes only what `--agent-id` takes.
#[test]
fn an_agent_id_outside_the_rule_is_not_taken() {
    let id = |given: &str| {
        Agent::new(AgentConfig::new(Vec::new()).with_agent_id(given.to_owned()))
            .view()
            .agent
            .id
    };
    assert_eq!(id("ns/pod-0").as_deref(), Some("ns/pod-0"));
    assert_eq!(id(""), None);
    assert_eq!(id("has space"), None);
    assert_eq!(id(&"x".repeat(65)), None);
}

/// A cell of a sample: `label` on `stream` lane `lane`, holding `value`.
fn cell(label: &str, stream: u64, lane: u8, value: u64) -> crate::api::Counter {
    crate::api::Counter {
        label: label.to_owned(),
        type_id: karyos_sys::counters::TYPE_GAUGE,
        stream,
        lane,
        kind: 0,
        participant: 0,
        cell_registration: 0,
        value,
        read_ns: 0,
        changed_ns: None,
    }
}

fn sample(counters: Vec<crate::api::Counter>) -> Sample {
    Sample {
        consistent: true,
        sampled: true,
        age_ns: Some(0),
        counters,
        lanes: Vec::new(),
    }
}

/// karyos#885: a stream's holders are, over every lane with its wire id,
/// the client publication cells plus the embedded count; another wire id
/// counts for nothing, and a negative id is read back.
#[test]
fn a_streams_holders_are_its_lanes_publications() {
    use karyos_sys::counters::{
        LABEL_EMBEDDED_PUBLICATIONS, LABEL_PUBLICATION, LABEL_STREAM_WIRE_ID, wire_stream_id_value,
    };

    let counters = vec![
        cell("counters unavailable", 0, 0, 0),
        // Stream registration 11, lanes 0 and 1, wire id -7.
        cell(LABEL_STREAM_WIRE_ID, 11, 0, wire_stream_id_value(-7)),
        cell(LABEL_EMBEDDED_PUBLICATIONS, 11, 0, 1),
        cell(LABEL_PUBLICATION, 11, 0, 900),
        cell(LABEL_STREAM_WIRE_ID, 11, 1, wire_stream_id_value(-7)),
        cell(LABEL_EMBEDDED_PUBLICATIONS, 11, 1, 0),
        cell(LABEL_PUBLICATION, 11, 1, 901),
        // Stream registration 12, wire id 8: one publication.
        cell(LABEL_STREAM_WIRE_ID, 12, 0, wire_stream_id_value(8)),
        cell(LABEL_EMBEDDED_PUBLICATIONS, 12, 0, 0),
        cell(LABEL_PUBLICATION, 12, 0, 902),
    ];
    let seen = stream_presence(true, Some(&sample(counters.clone())), "-7");
    assert_eq!((seen.present, seen.holders), (Some(true), Some(3)));
    let seen = stream_presence(true, Some(&sample(counters.clone())), "8");
    assert_eq!(
        (seen.present, seen.holders, seen.shared()),
        (Some(true), Some(1), Some(false))
    );
    let seen = stream_presence(true, Some(&sample(counters)), "9");
    assert_eq!((seen.present, seen.holders), (Some(false), Some(0)));
    // One embedded handle and one client publication make it shared.
    let counters = vec![
        cell(LABEL_STREAM_WIRE_ID, 13, 0, wire_stream_id_value(4)),
        cell(LABEL_EMBEDDED_PUBLICATIONS, 13, 0, 1),
        cell(LABEL_PUBLICATION, 13, 0, 903),
    ];
    let seen = stream_presence(true, Some(&sample(counters)), "4");
    assert_eq!((seen.holders, seen.shared()), (Some(2), Some(true)));
}

/// karyos#885: the conditions under which a stream's holders are unknown,
/// never undercounted: a cell the driver could not allocate, no pass of
/// the driver yet, a count that overflows, no sample of the agent yet,
/// and no attachment.
#[test]
fn a_streams_holders_are_unknown_while_cells_are_missing() {
    use karyos_sys::counters::{
        LABEL_EMBEDDED_PUBLICATIONS, LABEL_PUBLICATION, LABEL_STREAM_WIRE_ID, wire_stream_id_value,
    };

    let counters = vec![
        cell("counters unavailable", 0, 0, 1),
        cell(LABEL_STREAM_WIRE_ID, 11, 0, wire_stream_id_value(7)),
        cell(LABEL_PUBLICATION, 11, 0, 900),
    ];
    assert_eq!(
        stream_presence(true, Some(&sample(counters.clone())), "7"),
        registry::Presence::default()
    );
    let mut unsampled = sample(counters);
    unsampled.counters[0].value = 0;
    unsampled.sampled = false;
    assert_eq!(
        stream_presence(true, Some(&unsampled), "7"),
        registry::Presence::default()
    );
    unsampled.sampled = true;
    // Two lanes whose embedded counts sum past u64::MAX: unknown.
    let overflowing = sample(vec![
        cell(LABEL_STREAM_WIRE_ID, 11, 0, wire_stream_id_value(5)),
        cell(LABEL_EMBEDDED_PUBLICATIONS, 11, 0, u64::MAX),
        cell(LABEL_STREAM_WIRE_ID, 11, 1, wire_stream_id_value(5)),
        cell(LABEL_EMBEDDED_PUBLICATIONS, 11, 1, 1),
    ]);
    assert_eq!(
        stream_presence(true, Some(&overflowing), "5"),
        registry::Presence::default()
    );
    assert_eq!(
        stream_presence(true, Some(&unsampled), "7").holders,
        Some(1)
    );
    assert_eq!(
        stream_presence(true, None, "7"),
        registry::Presence::default()
    );
    assert_eq!(
        stream_presence(false, Some(&unsampled), "7"),
        registry::Presence::default()
    );
}

/// The log line of an acknowledgement with no journal names the relay and
/// does not call a relayed principal's operator id a uid; a local one
/// reads as before (karyos#708 review).
#[test]
fn an_acknowledgement_log_names_the_relay() {
    assert_eq!(acknowledger(Requester::local(1000)), "uid 1000");
    assert_eq!(
        acknowledger(Requester::relayed(50_001, 7)),
        "operator 50001 relay 7"
    );
}

/// R-CORE-18 (karyos#738): a preview gives the guard's state and a token,
/// and a submit with it performs exactly the previewed operation under the
/// caller's operation id; another principal, a reused id, an unknown state
/// and a guard that moved since are each refused, the last by the driver
/// atomically with the close.
#[test]
fn a_previewed_close_is_submitted_under_the_callers_operation_id() {
    use crate::preview::{PreviewAnswer, PreviewKind, SubmitRefusal, Token};

    let dir = std::env::temp_dir().join(format!("karyos-agent-preview-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let driver_dir = dir.join("driver");
    let mut driver = driver(&driver_dir);
    let guard = driver.add_guard("orders").unwrap();
    let config = AgentConfig::new(vec![driver_dir.clone()])
        .with_attach_timeout(Duration::from_secs(5))
        .with_journal(dir.join("journal"));
    let mut agent = Agent::new(config);
    let operator = Requester::local(1000);
    serving(&mut driver, || agent.refresh());
    // No transition followed yet: the state, and so the token, are
    // unavailable, never a default (RR-CON-0008).
    let unknown = agent.guard_preview_for(
        PreviewKind::Close,
        &driver_dir,
        guard.id(),
        operator,
        b"halt",
    );
    assert!(
        matches!(
            unknown,
            PreviewAnswer::Previewed {
                state: None,
                epoch_after: None,
                token: None,
                ..
            }
        ),
        "{unknown:?}"
    );
    let text = crate::json::preview_answer(&unknown);
    assert!(text.contains(r#""state":"unavailable""#), "{text}");
    assert!(text.contains(r#""token":"unavailable""#), "{text}");
    // Open it, and let the agent follow the transition.
    let reopened = serving(&mut driver, || {
        agent.guard_reopen(&driver_dir, guard.id(), 1, 1000, b"")
    });
    assert!(matches!(reopened, GuardAnswer::State { state, .. } if state.open));
    serving(&mut driver, || agent.refresh());
    let preview = |agent: &mut Agent| match agent.guard_preview_for(
        PreviewKind::Close,
        &driver_dir,
        guard.id(),
        operator,
        b"halt",
    ) {
        PreviewAnswer::Previewed {
            state: Some(state),
            epoch_after: Some(after),
            token: Some(token),
            ..
        } => (state, after, token),
        other => panic!("{other:?}"),
    };
    let (state, after, token) = preview(&mut agent);
    assert_eq!((state.epoch, state.open, after), (2, true, 3));
    // Another principal cannot submit it.
    assert_eq!(
        agent.guard_submit_for(
            (4242, Some(token)),
            PreviewKind::Close,
            &driver_dir,
            guard.id(),
            Requester::local(1001),
            b"halt",
        ),
        Err(SubmitRefusal::PrincipalMismatch)
    );
    // The previewed close, under the caller's id.
    let answer = serving(&mut driver, || {
        agent.guard_submit_for(
            (4242, Some(token)),
            PreviewKind::Close,
            &driver_dir,
            guard.id(),
            operator,
            b"halt",
        )
    });
    assert!(
        matches!(
            answer,
            Ok(GuardAnswer::State { operation: 4242, state, .. }) if state.epoch == 3 && !state.open
        ),
        "{answer:?}"
    );
    assert_eq!(driver.guard_audit().records.last().unwrap().operation, 4242);
    // The token is used up, and the id too.
    assert_eq!(
        agent.guard_submit_for(
            (4243, Some(token)),
            PreviewKind::Close,
            &driver_dir,
            guard.id(),
            operator,
            b"halt",
        ),
        Err(SubmitRefusal::TokenUnknown)
    );
    // A retry of 4242, whatever its token: the retained outcome, unsent.
    let garbage = Token::parse(&"0".repeat(32)).unwrap();
    let audited = driver.guard_audit().records.len();
    let retried = agent.guard_submit_for(
        (4242, Some(garbage)),
        PreviewKind::Close,
        &driver_dir,
        guard.id(),
        operator,
        b"halt",
    );
    assert_eq!(retried, answer);
    assert_eq!(driver.guard_audit().records.len(), audited);
    // The same id for anything else: a conflict, unsent.
    assert_eq!(
        agent.guard_submit_for(
            (4242, Some(garbage)),
            PreviewKind::Close,
            &driver_dir,
            guard.id(),
            Requester::local(1001),
            b"halt",
        ),
        Err(SubmitRefusal::OperationConflict)
    );
    assert_eq!(
        agent.guard_submit_for(
            (4242, Some(garbage)),
            PreviewKind::Close,
            &driver_dir,
            guard.id(),
            operator,
            b"other",
        ),
        Err(SubmitRefusal::OperationConflict)
    );
    // A guard that moved after the preview: the driver refuses the close at
    // the previewed epoch, atomically, and audits the refusal.
    let reopened = serving(&mut driver, || {
        agent.guard_reopen(&driver_dir, guard.id(), 3, 1000, b"")
    });
    assert!(matches!(reopened, GuardAnswer::State { state, .. } if state.epoch == 4));
    serving(&mut driver, || agent.refresh());
    let (_, _, token) = preview(&mut agent);
    let closed = serving(&mut driver, || {
        agent.guard_close(&driver_dir, guard.id(), 1000, b"other")
    });
    assert!(matches!(closed, GuardAnswer::State { state, .. } if state.epoch == 5));
    let moved = serving(&mut driver, || {
        agent.guard_submit_for(
            (4244, Some(token)),
            PreviewKind::Close,
            &driver_dir,
            guard.id(),
            operator,
            b"halt",
        )
    });
    assert!(
        matches!(
            moved,
            Ok(GuardAnswer::Refused {
                operation: 4244,
                code,
                ..
            }) if code == karyos_protocol::cnc::ErrorCode::GuardNotOpenAt.code()
        ),
        "{moved:?}"
    );
    // karyos#738 review: one id accounting across the paths. A direct
    // operation's id cannot be submitted again, and the agent's own ids
    // skip one a caller took.
    let direct = serving(&mut driver, || {
        agent.guard_reopen(&driver_dir, guard.id(), 5, 1000, b"")
    });
    let GuardAnswer::State {
        operation: taken, ..
    } = direct
    else {
        panic!("{direct:?}");
    };
    assert_eq!(
        agent.guard_submit_for(
            (taken, Some(garbage)),
            PreviewKind::Close,
            &driver_dir,
            guard.id(),
            operator,
            b"halt",
        ),
        Err(SubmitRefusal::OperationConflict)
    );
    serving(&mut driver, || agent.refresh());
    let (_, _, token) = preview(&mut agent);
    let claimed = agent.next_operation;
    let submitted = serving(&mut driver, || {
        agent.guard_submit_for(
            (claimed, Some(token)),
            PreviewKind::Close,
            &driver_dir,
            guard.id(),
            operator,
            b"halt",
        )
    });
    assert!(matches!(submitted, Ok(GuardAnswer::State { operation, .. }) if operation == claimed));
    let next = serving(&mut driver, || {
        agent.guard_close(&driver_dir, guard.id(), 1000, b"")
    });
    assert!(matches!(next, GuardAnswer::State { operation, .. } if operation != claimed));
    // karyos#738 review: a driver that restarted between the preview and
    // the submit's attach is another target: refused unsent, even with the
    // agent's cached instance still the previewed one.
    let reopened = serving(&mut driver, || {
        agent.guard_reopen(&driver_dir, guard.id(), 7, 1000, b"")
    });
    assert!(matches!(reopened, GuardAnswer::State { state, .. } if state.open));
    serving(&mut driver, || agent.refresh());
    let (_, _, token) = preview(&mut agent);
    drop(driver);
    let mut replacement = super::tests::driver(&driver_dir);
    let _ = replacement.add_guard("orders").unwrap();
    let elsewhere = serving(&mut replacement, || {
        agent.guard_submit_for(
            (777_777, Some(token)),
            PreviewKind::Close,
            &driver_dir,
            guard.id(),
            operator,
            b"halt",
        )
    });
    assert_eq!(elsewhere, Ok(GuardAnswer::InstanceChanged));
    drop(replacement);
    // A restart keeps the outcomes: rebuilt from the journal, a retry of
    // 4242 still answers its outcome, and 4244's refusal too.
    drop(agent);
    let mut agent = Agent::new(
        AgentConfig::new(vec![driver_dir.clone()])
            .with_attach_timeout(Duration::from_secs(5))
            .with_journal(dir.join("journal")),
    );
    // A retry needs no token (karyos#738 review).
    let again = agent.guard_submit_for(
        (4242, None),
        PreviewKind::Close,
        &driver_dir,
        guard.id(),
        operator,
        b"halt",
    );
    assert_eq!(again, answer);
    // The whole reply survives the restart, the refusal's detail too.
    assert_eq!(
        agent.guard_submit_for(
            (4244, None),
            PreviewKind::Close,
            &driver_dir,
            guard.id(),
            operator,
            b"halt",
        ),
        moved
    );
    // The same id on another driver is a conflict, not that outcome.
    assert_eq!(
        agent.guard_submit_for(
            (4244, None),
            PreviewKind::Close,
            &dir.join("other"),
            guard.id(),
            operator,
            b"halt",
        ),
        Err(SubmitRefusal::OperationConflict)
    );
    drop(agent);
    let _ = std::fs::remove_dir_all(&dir);
}

/// karyos#702: the view reports the journal's integrity under the
/// verifier's names, a damaged range named rather than a clean trail, and
/// `unsealed` computed from the seals.
#[test]
fn the_view_reports_the_journals_integrity_and_a_damaged_range() {
    use crate::journal::{JournalRecord, Kind};

    let dir = std::env::temp_dir().join(format!("karyos-agent-integrity-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut agent = Agent::new(AgentConfig::new(Vec::new()).with_journal(dir.join("journal")));
    let view = agent.view().journal.unwrap();
    assert!(!view.unsealed);
    assert!(!view.integrity_truncated);
    let ranges = view.integrity.unwrap();
    assert_eq!(ranges.len(), 1, "{ranges:?}");
    assert_eq!(ranges[0].outcome, "inconsistent");
    assert_eq!(
        ranges[0].reasons,
        ["untrusted_evidence", "missing_evidence"]
    );

    // A record past the seals: unsealed until a durable append.
    let journal = agent.journal.as_mut().unwrap();
    let _ = journal
        .append(&JournalRecord::new(Kind::CloseOutcome, 5), 5)
        .unwrap();
    assert!(agent.view().journal.unwrap().unsealed);

    let journal = agent.journal.as_mut().unwrap();
    journal.damage(u64::from(karyos_sys::frame::HEADER_LENGTH) + 16);
    journal.verify(6);
    let view = agent.view().journal.unwrap();
    let ranges = view.integrity.unwrap();
    assert_eq!(ranges[0].start, 0);
    assert_eq!(ranges[0].outcome, "inconsistent");
    assert_eq!(ranges[0].reasons, ["corruption"]);
    assert!(ranges.iter().all(|range| range.outcome != "verified"));
    assert_eq!(ranges.last().unwrap().outcome, "unsealed");
    let _ = std::fs::remove_dir_all(&dir);
}
