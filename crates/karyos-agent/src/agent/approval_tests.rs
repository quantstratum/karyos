// SPDX-License-Identifier: Apache-2.0

//! The two-person flow (R-CORE-20, karyos#739): one test per Validation
//! bullet of ADR-0112.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

use std::sync::{Arc, Mutex};
use std::time::Instant;

use karyos_driver::{DriverConfig, EmbeddedDriver, IpcConfig, SystemClock};
use karyos_sys::term_bytes::SharedTerms;

use super::*;
use crate::approval::{ApprovalAnswer, Refusal};
use crate::cluster_admin::{
    AdminCommand, Authority, Clearance, ClusterAnswer, ClusterGateway, ClusterReply, Evidence,
    Submission,
};
use crate::journal::{JournalRecord, Kind};
use crate::preview::{PreviewAnswer, PreviewKind, SubmitRefusal, Token};
use crate::two_person::TwoPersonClass;

type IpcDriver = EmbeddedDriver<SharedTerms>;

/// The requester, and another principal.
const REQUESTER: Requester = Requester::local(1000);
const OTHER: Requester = Requester::local(1001);
/// A risk officer's grants: reopens and operator commands.
const RISK_OFFICER: (bool, Clearance) = (true, Clearance::Operator);

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

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "karyos-agent-approval-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// What reached the product: command, parameters, operation, operator
/// and relay.
type Sent = Arc<Mutex<Vec<(String, Vec<u8>, u64, u32, u64)>>>;

/// A product gateway that records what reached it and sequences it.
#[derive(Debug)]
struct Product {
    sent: Sent,
}

impl ClusterGateway for Product {
    fn commands(&self) -> Vec<AdminCommand> {
        vec![
            AdminCommand::new("kill", Authority::Operator).unwrap(),
            AdminCommand::new("activate-upgrade", Authority::Administrator).unwrap(),
        ]
    }

    fn submit(&mut self, submission: &Submission<'_>) -> ClusterReply {
        self.sent.lock().unwrap().push((
            submission.command.to_owned(),
            submission.parameters.to_vec(),
            submission.operation,
            submission.operator,
            submission.relay,
        ));
        ClusterReply::sequenced(
            12,
            3,
            b"ok",
            Some(Evidence::new("sha256", &[0xab; 32]).unwrap()),
        )
        .unwrap()
    }
}

fn marked_kill() -> TwoPersonClass {
    TwoPersonClass::parse("cluster-command:orders/kill").unwrap()
}

/// An agent journalling in `dir` with `orders/kill` marked, waiting
/// `wait`, and the product attached as `orders`.
fn cluster_agent(dir: &Path, wait: Duration) -> (Agent, Sent) {
    let mut agent = Agent::new(
        AgentConfig::new(Vec::new())
            .with_journal(dir.join("journal"))
            .with_two_person(vec![marked_kill()])
            .with_approval_wait(wait),
    );
    let sent = attach(&mut agent);
    (agent, sent)
}

fn attach(agent: &mut Agent) -> Sent {
    let sent = Sent::default();
    agent
        .attach_cluster(
            "orders",
            Box::new(Product {
                sent: Arc::clone(&sent),
            }),
        )
        .unwrap();
    sent
}

/// `cluster-command OPID orders kill 0102 halt` for `requester`.
fn kill(agent: &mut Agent, operation: u64, requester: Requester) -> ApprovalAnswer {
    agent.cluster_command_answer_for(
        ("orders", "kill", &[1, 2]),
        operation,
        (requester, Clearance::Operator),
        b"halt",
    )
}

/// The journal's records in `dir`, read by an open of it.
fn records(dir: &Path) -> Vec<JournalRecord> {
    crate::journal::Journal::open(&dir.join("journal"), host_monotonic_ns())
        .unwrap()
        .scanned
        .clone()
}

fn of(records: &[JournalRecord], kind: Kind, operation: u64) -> Vec<JournalRecord> {
    records
        .iter()
        .filter(|record| record.kind == kind && record.operation == operation)
        .cloned()
        .collect()
}

/// A driver with guard `orders` closed at epoch 3, followed by an agent
/// that journals in `dir` and marks guard reopens.
struct GuardSetup {
    dir: PathBuf,
    driver_dir: PathBuf,
    driver: IpcDriver,
    guard: u64,
    agent: Agent,
}

fn guard_setup(name: &str) -> GuardSetup {
    let dir = temp(name);
    let driver_dir = dir.join("driver");
    let mut driver = driver(&driver_dir);
    let guard = driver.add_guard("orders").unwrap().id();
    let mut agent = Agent::new(
        AgentConfig::new(vec![driver_dir.clone()])
            .with_attach_timeout(Duration::from_secs(5))
            .with_journal(dir.join("journal")),
    );
    serving(&mut driver, || agent.refresh());
    let reopened = serving(&mut driver, || {
        agent.guard_reopen(&driver_dir, guard, 1, 1000, b"")
    });
    assert!(matches!(reopened, GuardAnswer::State { state, .. } if state.open));
    let closed = serving(&mut driver, || {
        agent.guard_close(&driver_dir, guard, 1000, b"")
    });
    assert!(matches!(closed, GuardAnswer::State { state, .. } if state.epoch == 3));
    serving(&mut driver, || agent.refresh());
    // From here on, reopens need two people.
    agent.config.two_person = vec![TwoPersonClass::GuardReopen];
    GuardSetup {
        dir,
        driver_dir,
        driver,
        guard,
        agent,
    }
}

impl GuardSetup {
    /// A reopen preview's token for `requester`.
    fn token(&mut self, requester: Requester) -> Token {
        match self.agent.guard_preview_for(
            PreviewKind::Reopen,
            &self.driver_dir,
            self.guard,
            requester,
            b"drill over",
        ) {
            PreviewAnswer::Previewed {
                token: Some(token),
                epoch_after: Some(4),
                ..
            } => token,
            other => panic!("{other:?}"),
        }
    }

    /// `submit OPID TOKEN guard-reopen DIR GUARD drill over`.
    fn submit(&mut self, operation: u64, token: Option<Token>, reason: &[u8]) -> ApprovalAnswer {
        self.agent.submit_for(
            (operation, token),
            PreviewKind::Reopen,
            &self.driver_dir,
            self.guard,
            REQUESTER,
            reason,
        )
    }

    fn audited(&self) -> usize {
        self.driver.guard_audit().records.len()
    }
}

/// ADR-0112 Validation: a marked submit or `cluster-command` answers
/// `pending_approval` and sends nothing; the journal shows its durable
/// `ApprovalRequested` and no dispatch record. A retry of the exact request
/// is pending again, with no token; the same id with anything else is a
/// conflict.
#[test]
fn a_marked_submit_or_cluster_command_pends_and_sends_nothing() {
    let mut setup = guard_setup("pends");
    let audited = setup.audited();
    let token = setup.token(REQUESTER);
    let answer = setup.submit(41, Some(token), b"drill over");
    assert_eq!(
        answer,
        ApprovalAnswer::Pending {
            operation: 41,
            expires_in_ms: 600_000
        }
    );
    assert_eq!(
        crate::json::approval_answer(&answer),
        r#"{"operation":41,"outcome":"pending_approval","expires_in_ms":600000}"#
    );
    assert!(matches!(
        setup.submit(41, None, b"drill over"),
        ApprovalAnswer::Pending { operation: 41, .. }
    ));
    assert_eq!(
        setup.submit(41, None, b"other"),
        ApprovalAnswer::Refused(Refusal::OperationConflict)
    );
    let sent = attach(&mut setup.agent);
    setup.agent.config.two_person.push(marked_kill());
    assert!(matches!(
        kill(&mut setup.agent, 51, REQUESTER),
        ApprovalAnswer::Pending { operation: 51, .. }
    ));
    assert!(matches!(
        kill(&mut setup.agent, 51, REQUESTER),
        ApprovalAnswer::Pending { operation: 51, .. }
    ));
    assert_eq!(setup.audited(), audited);
    assert!(sent.lock().unwrap().is_empty());
    drop(setup.agent);
    let records = records(&setup.dir);
    let requested = of(&records, Kind::ApprovalRequested, 41);
    assert_eq!(requested.len(), 1);
    assert_eq!(
        (
            requested[0].parameters,
            requested[0].guard,
            requested[0].expected
        ),
        (1, setup.guard, 3)
    );
    assert_ne!(requested[0].instance, 0);
    assert!(of(&records, Kind::ReopenRequest, 41).is_empty());
    let requested = of(&records, Kind::ApprovalRequested, 51);
    assert_eq!(
        (requested[0].parameters, requested[0].bytes.as_slice()),
        (2, &[1u8, 2][..])
    );
    assert_eq!(requested[0].target, b"orders");
    assert!(of(&records, Kind::ClusterRequest, 51).is_empty());
    let _ = std::fs::remove_dir_all(&setup.dir);
}

/// ADR-0112 point 2: a direct reopen of a marked class is refused
/// `two-person required`, unsent and unjournalled, on every path but the
/// flow's; a marked Cluster command too.
#[test]
fn a_direct_reopen_of_a_marked_class_is_refused() {
    let mut setup = guard_setup("direct");
    let audited = setup.audited();
    let (dir, guard) = (setup.driver_dir.clone(), setup.guard);
    let answer = setup.agent.guard_reopen_for(&dir, guard, 3, OTHER, b"now");
    assert_eq!(answer, GuardAnswer::TwoPersonRequired);
    assert_eq!(
        crate::json::guard_answer(&answer),
        r#"{"error":"two-person required"}"#
    );
    assert_eq!(
        setup.agent.guard_reopen(&dir, guard, 3, 1000, b""),
        GuardAnswer::TwoPersonRequired
    );
    let token = setup.token(REQUESTER);
    assert_eq!(
        setup.agent.guard_submit_for(
            (41, Some(token)),
            PreviewKind::Reopen,
            &dir,
            guard,
            REQUESTER,
            b"drill over",
        ),
        Ok(GuardAnswer::TwoPersonRequired)
    );
    let sent = attach(&mut setup.agent);
    setup.agent.config.two_person.push(marked_kill());
    assert_eq!(
        setup.agent.cluster_command_for(
            ("orders", "kill", &[1]),
            51,
            (REQUESTER, Clearance::Operator),
            b""
        ),
        ClusterAnswer::TwoPersonRequired
    );
    assert_eq!(setup.audited(), audited);
    assert!(sent.lock().unwrap().is_empty());
    drop(setup.agent);
    let records = records(&setup.dir);
    // The setup's reopen at epoch 1 only.
    assert_eq!(
        records
            .iter()
            .filter(|record| record.kind == Kind::ReopenRequest)
            .count(),
        1
    );
    assert!(of(&records, Kind::ClusterRefused, 51).is_empty());
    let _ = std::fs::remove_dir_all(&setup.dir);
}

/// ADR-0112 point 4: an approval by a second principal sends exactly the
/// bound operation, for the requester, under its id: the guard at the
/// bound epoch, the command with its bytes; the journal shows the request,
/// the approval, the dispatch record and the outcome, in that order.
#[test]
fn a_second_principals_approval_sends_exactly_the_bound_operation() {
    let mut setup = guard_setup("approve");
    let token = setup.token(REQUESTER);
    assert!(matches!(
        setup.submit(41, Some(token), b"drill over"),
        ApprovalAnswer::Pending { .. }
    ));
    let agent = &mut setup.agent;
    let approved = serving(&mut setup.driver, || {
        agent.approve_for(41, OTHER, RISK_OFFICER)
    });
    assert!(
        matches!(
            approved,
            ApprovalAnswer::Guard(GuardAnswer::State { operation: 41, state, .. })
                if state.open && state.epoch == 4
        ),
        "{approved:?}"
    );
    assert_eq!(
        setup.driver.guard_audit().records.last().unwrap().operation,
        41
    );
    let sent = attach(&mut setup.agent);
    setup.agent.config.two_person.push(marked_kill());
    assert!(matches!(
        kill(&mut setup.agent, 51, REQUESTER),
        ApprovalAnswer::Pending { .. }
    ));
    let approved = setup.agent.approve_for(51, OTHER, RISK_OFFICER);
    assert!(
        matches!(
            &approved,
            ApprovalAnswer::Cluster(ClusterAnswer::Sequenced {
                operation: 51,
                index: 12,
                ..
            })
        ),
        "{approved:?}"
    );
    assert_eq!(
        *sent.lock().unwrap(),
        [("kill".to_owned(), vec![1, 2], 51, 1000, 0)]
    );
    drop(setup.agent);
    let records = records(&setup.dir);
    for (operation, dispatch, outcome) in [
        (41, Kind::ReopenRequest, Kind::Submitted),
        (51, Kind::ClusterRequest, Kind::ClusterOutcome),
    ] {
        let kinds: Vec<Kind> = records
            .iter()
            .filter(|record| record.operation == operation)
            .map(|record| record.kind)
            .filter(|kind| {
                [
                    Kind::ApprovalRequested,
                    Kind::ApprovalGranted,
                    dispatch,
                    outcome,
                ]
                .contains(kind)
            })
            .collect();
        assert_eq!(
            kinds,
            [
                Kind::ApprovalRequested,
                Kind::ApprovalGranted,
                dispatch,
                outcome
            ]
        );
        let granted = of(&records, Kind::ApprovalGranted, operation);
        assert_eq!(granted[0].operator, 1001);
        // The dispatch is the requester's.
        assert_eq!(of(&records, dispatch, operation)[0].operator, 1000);
    }
    let _ = std::fs::remove_dir_all(&setup.dir);
}

/// ADR-0112 point 4: the same operator, locally or through any relay, is
/// refused `same principal`; a role that may not make the operation is
/// `forbidden`; neither sends anything nor ends the operation.
#[test]
fn the_same_principal_locally_or_relayed_is_refused() {
    let dir = temp("same");
    let (mut agent, sent) = cluster_agent(&dir, crate::two_person::DEFAULT_WAIT);
    assert!(matches!(
        kill(&mut agent, 51, REQUESTER),
        ApprovalAnswer::Pending { .. }
    ));
    for approver in [REQUESTER, Requester::relayed(1000, 7)] {
        assert_eq!(
            agent.approve_for(51, approver, RISK_OFFICER),
            ApprovalAnswer::Refused(Refusal::SamePrincipal)
        );
    }
    // A relayed requester, approved locally or through another relay.
    assert!(matches!(
        kill(&mut agent, 52, Requester::relayed(50_002, 7)),
        ApprovalAnswer::Pending { .. }
    ));
    for approver in [Requester::local(50_002), Requester::relayed(50_002, 9)] {
        assert_eq!(
            agent.approve_for(52, approver, RISK_OFFICER),
            ApprovalAnswer::Refused(Refusal::SamePrincipal)
        );
    }
    assert_eq!(
        agent.approve_for(51, OTHER, (false, Clearance::None)),
        ApprovalAnswer::Refused(Refusal::Forbidden)
    );
    assert_eq!(
        crate::json::approval_answer(&ApprovalAnswer::Refused(Refusal::SamePrincipal)),
        r#"{"error":"same principal"}"#
    );
    assert!(sent.lock().unwrap().is_empty());
    // Still pending: a distinct principal with the role approves it.
    assert!(matches!(
        agent.approve_for(51, OTHER, RISK_OFFICER),
        ApprovalAnswer::Cluster(ClusterAnswer::Sequenced { operation: 51, .. })
    ));
    drop(agent);
    let _ = std::fs::remove_dir_all(&dir);
}

/// ADR-0112 point 4: a Cluster whose gateway attached again since the
/// request ends the operation `target changed`, unsent and journalled.
#[test]
fn a_changed_target_ends_it_target_changed() {
    let dir = temp("changed");
    let (mut agent, sent) = cluster_agent(&dir, crate::two_person::DEFAULT_WAIT);
    assert!(matches!(
        kill(&mut agent, 51, REQUESTER),
        ApprovalAnswer::Pending { .. }
    ));
    assert!(agent.detach_cluster("orders"));
    let again = attach(&mut agent);
    assert_eq!(
        agent.approve_for(51, OTHER, RISK_OFFICER),
        ApprovalAnswer::Refused(Refusal::TargetChanged)
    );
    // Ended: a second approver gets the same.
    assert_eq!(
        agent.approve_for(51, Requester::local(1002), RISK_OFFICER),
        ApprovalAnswer::Refused(Refusal::TargetChanged)
    );
    assert!(sent.lock().unwrap().is_empty());
    assert!(again.lock().unwrap().is_empty());
    drop(agent);
    let records = records(&dir);
    let ended = of(&records, Kind::ApprovalExpired, 51);
    assert_eq!(ended.len(), 1);
    assert_eq!(
        ended[0].code,
        crate::approval::EndCode::TargetChanged.code()
    );
    assert!(of(&records, Kind::ApprovalGranted, 51).is_empty());
    assert!(of(&records, Kind::ClusterRequest, 51).is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// ADR-0112 point 6: the requester withdraws, locally or relayed under its
/// operator id; anyone else is refused `not requester`; a withdrawn
/// operation is not approved, and a retry of it answers withdrawn.
#[test]
fn withdrawal_by_the_requester_ends_it_and_by_another_is_refused() {
    let dir = temp("withdraw");
    let (mut agent, sent) = cluster_agent(&dir, crate::two_person::DEFAULT_WAIT);
    assert!(matches!(
        kill(&mut agent, 51, REQUESTER),
        ApprovalAnswer::Pending { .. }
    ));
    assert_eq!(
        agent.withdraw_for(51, OTHER),
        ApprovalAnswer::Refused(Refusal::NotRequester)
    );
    let withdrawn = agent.withdraw_for(51, Requester::relayed(1000, 7));
    assert_eq!(withdrawn, ApprovalAnswer::Withdrawn { operation: 51 });
    assert_eq!(
        crate::json::approval_answer(&withdrawn),
        r#"{"operation":51,"outcome":"withdrawn"}"#
    );
    assert_eq!(
        agent.approve_for(51, OTHER, RISK_OFFICER),
        ApprovalAnswer::Refused(Refusal::NotPending)
    );
    assert_eq!(
        agent.withdraw_for(51, REQUESTER),
        ApprovalAnswer::Refused(Refusal::NotPending)
    );
    assert_eq!(kill(&mut agent, 51, REQUESTER), withdrawn);
    assert_eq!(
        agent.withdraw_for(77, REQUESTER),
        ApprovalAnswer::Refused(Refusal::OperationIdUnknown)
    );
    assert!(sent.lock().unwrap().is_empty());
    drop(agent);
    let records = records(&dir);
    let ended = of(&records, Kind::ApprovalWithdrawn, 51);
    assert_eq!(
        (ended.len(), ended[0].operator, ended[0].relay),
        (1, 1000, 7)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// ADR-0112 point 7: past its deadline an operation is expired, journalled
/// at the periodic sweep or when next touched, and a later approval or
/// withdrawal is `operation expired`; nothing is sent.
#[test]
fn expiry_ends_it_and_a_later_approval_is_operation_expired() {
    let dir = temp("expiry");
    let (mut agent, sent) = cluster_agent(&dir, Duration::from_millis(50));
    assert!(matches!(
        kill(&mut agent, 51, REQUESTER),
        ApprovalAnswer::Pending {
            expires_in_ms: 50,
            ..
        }
    ));
    std::thread::sleep(Duration::from_millis(120));
    // The periodic sweep.
    agent.refresh();
    assert!(matches!(
        agent.approvals.get(51).unwrap().state,
        crate::approval::State::Ended { .. }
    ));
    assert_eq!(
        agent.approve_for(51, OTHER, RISK_OFFICER),
        ApprovalAnswer::Refused(Refusal::OperationExpired)
    );
    // Touched first: expired at the approval.
    assert!(matches!(
        kill(&mut agent, 52, REQUESTER),
        ApprovalAnswer::Pending { .. }
    ));
    std::thread::sleep(Duration::from_millis(120));
    assert_eq!(
        agent.approve_for(52, OTHER, RISK_OFFICER),
        ApprovalAnswer::Refused(Refusal::OperationExpired)
    );
    assert_eq!(
        agent.withdraw_for(52, REQUESTER),
        ApprovalAnswer::Refused(Refusal::OperationExpired)
    );
    assert_eq!(
        kill(&mut agent, 52, REQUESTER),
        ApprovalAnswer::Refused(Refusal::OperationExpired)
    );
    assert!(sent.lock().unwrap().is_empty());
    drop(agent);
    let records = records(&dir);
    for operation in [51, 52] {
        let ended = of(&records, Kind::ApprovalExpired, operation);
        assert_eq!(ended.len(), 1, "{operation}");
        assert_eq!(ended[0].code, crate::approval::EndCode::Expired.code());
        assert!(of(&records, Kind::ApprovalGranted, operation).is_empty());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// ADR-0112 point 5: a second approver gets the operation's outcome, and
/// nothing is sent again.
#[test]
fn a_second_approver_gets_the_outcome() {
    let dir = temp("second");
    let (mut agent, sent) = cluster_agent(&dir, crate::two_person::DEFAULT_WAIT);
    assert!(matches!(
        kill(&mut agent, 51, REQUESTER),
        ApprovalAnswer::Pending { .. }
    ));
    let first = agent.approve_for(51, OTHER, RISK_OFFICER);
    assert!(matches!(
        first,
        ApprovalAnswer::Cluster(ClusterAnswer::Sequenced { .. })
    ));
    assert_eq!(
        agent.approve_for(51, Requester::local(1002), RISK_OFFICER),
        first
    );
    // A retry of the request gets it too.
    assert_eq!(kill(&mut agent, 51, REQUESTER), first);
    assert_eq!(sent.lock().unwrap().len(), 1);
    assert_eq!(
        agent.approve_for(77, OTHER, RISK_OFFICER),
        ApprovalAnswer::Refused(Refusal::OperationIdUnknown)
    );
    drop(agent);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A completed operation's outcome goes only to a role that may approve
/// it: a role without the clearance, or that may not reopen guards, is
/// refused `forbidden` whatever id it names (karyos#739 review).
#[test]
fn test_approve_checks_the_role_before_a_completed_outcome() {
    let dir = temp("completed-role");
    let (mut agent, _) = cluster_agent(&dir, crate::two_person::DEFAULT_WAIT);
    assert!(matches!(
        kill(&mut agent, 51, REQUESTER),
        ApprovalAnswer::Pending { .. }
    ));
    let first = agent.approve_for(51, OTHER, RISK_OFFICER);
    assert!(matches!(
        first,
        ApprovalAnswer::Cluster(ClusterAnswer::Sequenced { .. })
    ));
    let viewer = Requester::local(1002);
    for role in [(true, Clearance::None), (false, Clearance::None)] {
        assert_eq!(
            agent.approve_for(51, viewer, role),
            ApprovalAnswer::Refused(Refusal::Forbidden),
            "{role:?}"
        );
    }
    assert_eq!(agent.approve_for(51, viewer, RISK_OFFICER), first);
    drop(agent);
    let _ = std::fs::remove_dir_all(&dir);

    let mut setup = guard_setup("completed-role-guard");
    let token = setup.token(REQUESTER);
    assert!(matches!(
        setup.submit(41, Some(token), b"drill over"),
        ApprovalAnswer::Pending { .. }
    ));
    let agent = &mut setup.agent;
    let approved = serving(&mut setup.driver, || {
        agent.approve_for(41, OTHER, RISK_OFFICER)
    });
    assert!(matches!(approved, ApprovalAnswer::Guard(_)), "{approved:?}");
    assert_eq!(
        setup
            .agent
            .approve_for(41, viewer, (false, Clearance::Administrator)),
        ApprovalAnswer::Refused(Refusal::Forbidden)
    );
    assert_eq!(setup.agent.approve_for(41, viewer, RISK_OFFICER), approved);
    let dir = setup.dir.clone();
    drop(setup);
    let _ = std::fs::remove_dir_all(&dir);
}

/// ADR-0112 point 3: the pending operation consumes its preview's token:
/// one preview cannot create two pending operations.
#[test]
fn one_preview_cannot_pend_twice() {
    let mut setup = guard_setup("twice");
    let token = setup.token(REQUESTER);
    assert!(matches!(
        setup.submit(41, Some(token), b"drill over"),
        ApprovalAnswer::Pending { operation: 41, .. }
    ));
    assert_eq!(
        setup.submit(42, Some(token), b"drill over"),
        ApprovalAnswer::Submit(SubmitRefusal::TokenUnknown)
    );
    assert!(setup.agent.approvals.get(42).is_none());
    assert_eq!(
        setup.agent.approve_for(42, OTHER, RISK_OFFICER),
        ApprovalAnswer::Refused(Refusal::OperationIdUnknown)
    );
    drop(setup.agent);
    let _ = std::fs::remove_dir_all(&setup.dir);
}

/// ADR-0112 point 3: without a durable journal a marked request is refused
/// `journal unavailable`, nothing is pending, and the token and the id
/// stay as they were.
#[test]
fn without_a_durable_journal_nothing_is_pending() {
    let mut setup = guard_setup("nojournal");
    let token = setup.token(REQUESTER);
    setup.agent.journal.as_mut().unwrap().break_recorder();
    for _ in 0..2 {
        // The same token again: still the preview's, not used up.
        assert_eq!(
            setup.submit(41, Some(token), b"drill over"),
            ApprovalAnswer::Refused(Refusal::JournalUnavailable)
        );
    }
    assert!(!setup.agent.used_ids.contains(&41));
    assert_eq!(
        setup.agent.approve_for(41, OTHER, RISK_OFFICER),
        ApprovalAnswer::Refused(Refusal::OperationIdUnknown)
    );
    drop(setup.agent);
    let _ = std::fs::remove_dir_all(&setup.dir);

    // No journal configured at all.
    let mut agent = Agent::new(AgentConfig::new(Vec::new()).with_two_person(vec![marked_kill()]));
    let sent = attach(&mut agent);
    assert_eq!(
        kill(&mut agent, 51, REQUESTER),
        ApprovalAnswer::Refused(Refusal::JournalUnavailable)
    );
    assert!(!agent.used_ids.contains(&51));
    assert_eq!(
        agent.approve_for(51, OTHER, RISK_OFFICER),
        ApprovalAnswer::Refused(Refusal::OperationIdUnknown)
    );
    assert!(sent.lock().unwrap().is_empty());
}

/// ADR-0112 point 1: a guard close cannot be marked, here or on the
/// command line; an unmarked deployment's close and Cluster command
/// behave as before.
#[test]
fn a_guard_close_class_is_refused() {
    assert_eq!(TwoPersonClass::parse("guard-close"), None);
    let line: Vec<String> =
        "--api-dir /a --driver /d --role 0=administrator --two-person guard-close"
            .split(' ')
            .map(str::to_owned)
            .collect();
    assert_eq!(crate::cli::parse(&line), None);
    let dir = temp("unmarked");
    let mut agent = Agent::new(AgentConfig::new(Vec::new()).with_journal(dir.join("journal")));
    let sent = attach(&mut agent);
    assert!(matches!(
        kill(&mut agent, 51, REQUESTER),
        ApprovalAnswer::Cluster(ClusterAnswer::Sequenced { operation: 51, .. })
    ));
    assert_eq!(sent.lock().unwrap().len(), 1);
    drop(agent);
    let _ = std::fs::remove_dir_all(&dir);
}

/// ADR-0112 point 10: a restart expires a pending operation ("agent
/// restarted"), ends a granted but undispatched one "agent restarted before
/// dispatch", never as unknown, and answers a dispatched one without
/// outcome as unknown; a second restart changes nothing.
#[test]
fn a_restart_expires_a_pending_operation_and_ends_an_undispatched_one() {
    use crate::approval::{EndCode, Request, Target, principal_record, requested_record};
    let dir = temp("restart");
    let (mut agent, _) = cluster_agent(&dir, crate::two_person::DEFAULT_WAIT);
    assert!(matches!(
        kill(&mut agent, 51, REQUESTER),
        ApprovalAnswer::Pending { .. }
    ));
    let instance = agent.clusters.find("orders").unwrap().instance();
    drop(agent);
    // Granted, then the agent stopped: before its dispatch (52), and after
    // its kind 20 (53).
    {
        let mut journal =
            crate::journal::Journal::open(&dir.join("journal"), host_monotonic_ns()).unwrap();
        let boot = crate::preview::boot_id();
        for operation in [52, 53] {
            let request = Request {
                requester: REQUESTER,
                target: Target::Cluster {
                    cluster: "orders".to_owned(),
                    instance,
                    command: "kill".to_owned(),
                    parameters: vec![1, 2],
                },
                reason: b"halt".to_vec(),
            };
            let now = host_monotonic_ns();
            let records = [
                requested_record(
                    operation,
                    &request,
                    crate::two_person::DEFAULT_WAIT,
                    (now, &boot),
                ),
                principal_record(Kind::ApprovalGranted, operation, OTHER, (now, &boot)),
            ];
            for record in &records {
                let _ = journal.append_durable(record, now).unwrap();
            }
        }
        let mut dispatched = JournalRecord::new(Kind::ClusterRequest, host_monotonic_ns());
        dispatched.operation = 53;
        dispatched.target = b"orders".to_vec();
        dispatched.command = b"kill".to_vec();
        let _ = journal
            .append_durable(&dispatched, dispatched.time)
            .unwrap();
    }
    let (mut agent, sent) = cluster_agent(&dir, crate::two_person::DEFAULT_WAIT);
    assert_eq!(
        agent.approve_for(51, OTHER, RISK_OFFICER),
        ApprovalAnswer::Refused(Refusal::OperationExpired)
    );
    let before = agent.approve_for(52, Requester::local(1002), RISK_OFFICER);
    assert_eq!(before, ApprovalAnswer::Refused(Refusal::BeforeDispatch));
    assert_eq!(
        crate::json::approval_answer(&before),
        r#"{"error":"agent restarted before dispatch"}"#
    );
    assert_eq!(
        agent.approve_for(53, Requester::local(1002), RISK_OFFICER),
        ApprovalAnswer::Cluster(ClusterAnswer::NoAnswer {
            operation: 53,
            journalled: false
        })
    );
    assert!(sent.lock().unwrap().is_empty());
    drop(agent);
    let count = |records: &[JournalRecord]| {
        records
            .iter()
            .filter(|record| record.kind == Kind::ApprovalExpired)
            .count()
    };
    let after_one = records(&dir);
    let restarted = of(&after_one, Kind::ApprovalExpired, 51);
    assert_eq!(restarted[0].code, EndCode::Restarted.code());
    assert_eq!(restarted[0].reason, b"agent restarted");
    let undispatched = of(&after_one, Kind::ApprovalExpired, 52);
    assert_eq!(undispatched[0].code, EndCode::BeforeDispatch.code());
    assert_eq!(undispatched[0].reason, b"agent restarted before dispatch");
    assert!(of(&after_one, Kind::ApprovalExpired, 53).is_empty());
    assert_eq!(count(&after_one), 2);
    // Again: nothing further.
    let (agent, _) = cluster_agent(&dir, crate::two_person::DEFAULT_WAIT);
    drop(agent);
    assert_eq!(count(&records(&dir)), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

/// ADR-0112 points 9 and 10: the ids, the retained outcomes and the
/// tombstones survive a restart; an ending record of another boot is a
/// tombstone.
#[test]
fn ids_and_tombstones_survive_a_restart() {
    let dir = temp("ids");
    let (mut agent, _) = cluster_agent(&dir, crate::two_person::DEFAULT_WAIT);
    assert!(matches!(
        kill(&mut agent, 51, REQUESTER),
        ApprovalAnswer::Pending { .. }
    ));
    let ApprovalAnswer::Cluster(ClusterAnswer::Sequenced {
        index,
        term,
        evidence,
        ..
    }) = agent.approve_for(51, OTHER, RISK_OFFICER)
    else {
        panic!("not sequenced");
    };
    assert!(matches!(
        kill(&mut agent, 52, REQUESTER),
        ApprovalAnswer::Pending { .. }
    ));
    assert_eq!(
        agent.withdraw_for(52, REQUESTER),
        ApprovalAnswer::Withdrawn { operation: 52 }
    );
    drop(agent);
    let (mut agent, sent) = cluster_agent(&dir, crate::two_person::DEFAULT_WAIT);
    let rebuilt = ApprovalAnswer::Cluster(ClusterAnswer::Sequenced {
        operation: 51,
        index,
        term,
        reply: Vec::new(),
        evidence,
        journalled: true,
    });
    assert_eq!(
        agent.approve_for(51, Requester::local(1002), RISK_OFFICER),
        rebuilt
    );
    assert_eq!(kill(&mut agent, 51, REQUESTER), rebuilt);
    assert_eq!(
        kill(&mut agent, 52, REQUESTER),
        ApprovalAnswer::Withdrawn { operation: 52 }
    );
    assert_eq!(
        agent.cluster_command_answer_for(
            ("orders", "kill", &[9]),
            51,
            (REQUESTER, Clearance::Operator),
            b"halt",
        ),
        ApprovalAnswer::Refused(Refusal::OperationConflict)
    );
    assert!(sent.lock().unwrap().is_empty());
    drop(agent);
    // Unmarked now: the ids are still used.
    let mut agent = Agent::new(AgentConfig::new(Vec::new()).with_journal(dir.join("journal")));
    let _ = attach(&mut agent);
    assert!(matches!(
        kill(&mut agent, 52, REQUESTER),
        ApprovalAnswer::Cluster(ClusterAnswer::Rejected { .. })
    ));
    drop(agent);
    // Another boot's records: tombstones.
    let mut journal =
        crate::journal::Journal::open(&dir.join("journal"), host_monotonic_ns()).unwrap();
    let operations = journal.take_operations();
    let (approvals, added) =
        crate::approval::Approvals::rebuild(&operations, (host_monotonic_ns(), b"another-boot"));
    assert!(added.is_empty());
    for operation in [51, 52] {
        let entry = approvals.get(operation).unwrap();
        assert_eq!(
            crate::approval::Approvals::state_answer(
                operation,
                &entry.state,
                host_monotonic_ns(),
                true
            ),
            ApprovalAnswer::Refused(Refusal::OperationExpired)
        );
    }
    drop(journal);
    let _ = std::fs::remove_dir_all(&dir);
}

/// ADR-0112 point 4: a guard reopen pending approval whose driver became a
/// new instance before the approval ends `target changed`, unsent and
/// journalled.
#[test]
fn a_guard_whose_driver_restarted_ends_target_changed() {
    let mut setup = guard_setup("guardchanged");
    let token = setup.token(REQUESTER);
    assert!(matches!(
        setup.submit(41, Some(token), b"drill over"),
        ApprovalAnswer::Pending { operation: 41, .. }
    ));
    let before = setup.agent.drivers[0].instance;
    drop(setup.driver);
    let mut replacement = driver(&setup.driver_dir);
    let _ = replacement.add_guard("orders").unwrap();
    let agent = &mut setup.agent;
    let start = Instant::now();
    while agent.drivers[0].instance == before || agent.drivers[0].instance.is_none() {
        assert!(start.elapsed() < Duration::from_secs(30), "no new instance");
        serving(&mut replacement, || agent.refresh());
    }
    let audited = replacement.guard_audit().records.len();
    let approved = serving(&mut replacement, || {
        agent.approve_for(41, OTHER, RISK_OFFICER)
    });
    assert_eq!(approved, ApprovalAnswer::Refused(Refusal::TargetChanged));
    assert_eq!(
        agent.approve_for(41, Requester::local(1002), RISK_OFFICER),
        ApprovalAnswer::Refused(Refusal::TargetChanged)
    );
    assert_eq!(replacement.guard_audit().records.len(), audited);
    drop(setup.agent);
    let records = records(&setup.dir);
    let ended = of(&records, Kind::ApprovalExpired, 41);
    assert_eq!(ended.len(), 1);
    assert_eq!(
        ended[0].code,
        crate::approval::EndCode::TargetChanged.code()
    );
    assert!(of(&records, Kind::ApprovalGranted, 41).is_empty());
    assert!(of(&records, Kind::ReopenRequest, 41).is_empty());
    let _ = std::fs::remove_dir_all(&setup.dir);
}
