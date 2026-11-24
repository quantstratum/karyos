// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use super::*;
use crate::journal::{GapReason, Journal};

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "karyos-cluster-admin-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// How the fake product answers.
#[derive(Debug, Clone)]
enum Mode {
    Sequence,
    Refuse,
    Silent,
    Slow,
}

/// What reached the product: command, parameters, operation, operator
/// and relay.
type Sent = (String, Vec<u8>, u64, u32, u64);

/// A product gateway that records what reached it.
#[derive(Debug, Clone)]
struct Product {
    sent: Arc<Mutex<Vec<Sent>>>,
    mode: Mode,
}

impl Product {
    fn new(mode: Mode) -> Self {
        Self {
            sent: Arc::default(),
            mode,
        }
    }
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
        match self.mode {
            Mode::Sequence => ClusterReply::sequenced(
                12,
                3,
                b"ok",
                Some(Evidence::new("sha256", &[0xab; 32]).unwrap()),
            )
            .unwrap(),
            Mode::Refuse => ClusterReply::refused(ProductCode::new(7).unwrap(), "already killed"),
            Mode::Silent => ClusterReply::NoAnswer,
            Mode::Slow => {
                std::thread::sleep(Duration::from_millis(300));
                ClusterReply::sequenced(1, 1, b"", None).unwrap()
            }
        }
    }
}

fn clusters(product: &Product) -> Clusters {
    let mut clusters = Clusters::default();
    clusters.attach("seq", Box::new(product.clone())).unwrap();
    clusters
}

fn command<'a>(name: &'a str, operation: u64, clearance: Clearance) -> Command<'a> {
    Command {
        cluster: "seq",
        command: name,
        parameters: &[1, 2, 3],
        operation,
        operator: 1000,
        relay: 0,
        clearance,
        reason: b"drill",
    }
}

/// Runs `command` with a fresh id set and a fixed clock.
fn run(
    journal: Option<&mut Journal>,
    clusters: &Clusters,
    command: &Command<'_>,
    used: &mut HashSet<u64>,
) -> ClusterAnswer {
    cluster_command(
        journal,
        clusters,
        command,
        (Duration::from_millis(100), |id, take| {
            if take {
                !used.insert(id)
            } else {
                used.contains(&id)
            }
        }),
        || 50,
    )
}

/// The records the journal in `dir` holds, its own start records apart.
fn records(dir: &std::path::Path) -> Vec<JournalRecord> {
    let journal = Journal::open(dir, 100).unwrap();
    journal
        .scanned
        .into_iter()
        .filter(|record| record.kind.is_cluster())
        .collect()
}

#[test]
fn an_authorised_registered_command_is_journalled_before_and_after_with_its_evidence() {
    let dir = dir("sequenced");
    let product = Product::new(Mode::Sequence);
    let clusters = clusters(&product);
    let mut used = HashSet::new();
    {
        let mut journal = Journal::open(&dir, 10).unwrap();
        let answer = run(
            Some(&mut journal),
            &clusters,
            &command("kill", 41, Clearance::Operator),
            &mut used,
        );
        assert_eq!(
            answer,
            ClusterAnswer::Sequenced {
                operation: 41,
                index: 12,
                term: 3,
                reply: b"ok".to_vec(),
                evidence: Some(Evidence::new("sha256", &[0xab; 32]).unwrap()),
            }
        );
    }
    assert_eq!(
        *product.sent.lock().unwrap(),
        vec![("kill".to_owned(), vec![1, 2, 3], 41, 1000, 0)]
    );
    let records = records(&dir);
    assert_eq!(records.len(), 2);
    let (request, outcome) = (&records[0], &records[1]);
    assert_eq!(request.kind, Kind::ClusterRequest);
    assert_eq!(request.target, b"seq");
    assert_eq!(request.command, b"kill");
    assert_eq!(request.operation, 41);
    assert_eq!(request.reason, b"drill");
    assert_eq!(outcome.kind, Kind::ClusterOutcome);
    assert_eq!((outcome.code, outcome.word, outcome.expected), (0, 12, 3));
    assert_eq!(outcome.parameters, request.parameters);
    let mut evidence = b"sha256:".to_vec();
    evidence.extend_from_slice("ab".repeat(32).as_bytes());
    assert_eq!(outcome.evidence, evidence);
}

#[test]
fn a_caller_without_the_commands_authority_is_refused_and_journalled_unsent() {
    let dir = dir("forbidden");
    let product = Product::new(Mode::Sequence);
    let clusters = clusters(&product);
    let mut used = HashSet::new();
    {
        let mut journal = Journal::open(&dir, 10).unwrap();
        for (name, clearance) in [
            ("kill", Clearance::None),
            ("activate-upgrade", Clearance::None),
            ("activate-upgrade", Clearance::Operator),
        ] {
            let answer = run(
                Some(&mut journal),
                &clusters,
                &command(name, 5, clearance),
                &mut used,
            );
            assert_eq!(answer, ClusterAnswer::Rejected(RefusalCode::Forbidden));
        }
    }
    assert!(product.sent.lock().unwrap().is_empty());
    assert!(used.is_empty(), "a refused id is not used up");
    let records = records(&dir);
    assert_eq!(records.len(), 3);
    assert!(
        records
            .iter()
            .all(|record| record.kind == Kind::ClusterRefused
                && record.code == RefusalCode::Forbidden.code()
                && record.operator == 1000)
    );
}

#[test]
fn only_registered_commands_of_attached_clusters_are_forwarded() {
    let dir = dir("unregistered");
    let product = Product::new(Mode::Sequence);
    let clusters = clusters(&product);
    let mut used = HashSet::new();
    let mut journal = Journal::open(&dir, 10).unwrap();
    let answer = run(
        Some(&mut journal),
        &clusters,
        &command("drop-tables", 5, Clearance::Administrator),
        &mut used,
    );
    assert_eq!(
        answer,
        ClusterAnswer::Rejected(RefusalCode::UnregisteredCommand)
    );
    let mut other = command("kill", 5, Clearance::Administrator);
    other.cluster = "venue";
    assert_eq!(
        run(Some(&mut journal), &clusters, &other, &mut used),
        ClusterAnswer::Rejected(RefusalCode::UnknownCluster)
    );
    assert!(product.sent.lock().unwrap().is_empty());
    drop(journal);
    let codes: Vec<u64> = records(&dir).iter().map(|record| record.code).collect();
    assert_eq!(codes, [2, 3]);
}

#[test]
fn a_lost_outcome_is_journalled_as_unknown_never_as_success() {
    for (name, mode) in [("silent", Mode::Silent), ("slow", Mode::Slow)] {
        let dir = dir(name);
        let product = Product::new(mode);
        let clusters = clusters(&product);
        let mut used = HashSet::new();
        {
            let mut journal = Journal::open(&dir, 10).unwrap();
            let answer = run(
                Some(&mut journal),
                &clusters,
                &command("kill", 9, Clearance::Operator),
                &mut used,
            );
            assert_eq!(answer, ClusterAnswer::NoAnswer { operation: 9 }, "{name}");
        }
        let records = records(&dir);
        let outcome = records.last().unwrap();
        assert_eq!(outcome.kind, Kind::ClusterOutcome);
        assert_eq!(outcome.code, UNKNOWN_OUTCOME, "{name}");
        assert!(outcome.evidence.is_empty());
        assert!(
            used.contains(&9),
            "a sent id is used up whatever came of it"
        );
    }
}

#[test]
fn a_product_refusal_is_returned_and_journalled_verbatim() {
    let dir = dir("refused");
    let clusters = clusters(&Product::new(Mode::Refuse));
    let mut used = HashSet::new();
    {
        let mut journal = Journal::open(&dir, 10).unwrap();
        let answer = run(
            Some(&mut journal),
            &clusters,
            &command("kill", 9, Clearance::Operator),
            &mut used,
        );
        assert_eq!(
            answer,
            ClusterAnswer::Refused {
                operation: 9,
                code: 7,
                reason: "already killed".to_owned()
            }
        );
    }
    assert_eq!(records(&dir).last().unwrap().code, 7);
}

#[test]
fn without_a_durable_request_record_nothing_is_sent() {
    let product = Product::new(Mode::Sequence);
    let clusters = clusters(&product);
    let mut used = HashSet::new();
    let answer = run(
        None,
        &clusters,
        &command("kill", 9, Clearance::Operator),
        &mut used,
    );
    assert_eq!(answer, ClusterAnswer::JournalUnavailable);
    assert!(product.sent.lock().unwrap().is_empty());
    assert!(used.is_empty());
}

#[test]
fn a_used_operation_id_is_a_conflict_unsent() {
    let dir = dir("conflict");
    let product = Product::new(Mode::Sequence);
    let clusters = clusters(&product);
    let mut used = HashSet::from([9]);
    let mut journal = Journal::open(&dir, 10).unwrap();
    let answer = run(
        Some(&mut journal),
        &clusters,
        &command("kill", 9, Clearance::Operator),
        &mut used,
    );
    assert_eq!(
        answer,
        ClusterAnswer::Rejected(RefusalCode::OperationConflict)
    );
    assert!(product.sent.lock().unwrap().is_empty());
}

#[test]
fn a_request_without_its_outcome_opens_an_unknown_interval_at_the_next_start() {
    let dir = dir("crash");
    {
        let mut journal = Journal::open(&dir, 10).unwrap();
        let record = command("kill", 9, Clearance::Operator).record(Kind::ClusterRequest, 20);
        let _ = journal.append_durable(&record, 20).unwrap();
    }
    let mut journal = Journal::open(&dir, 30).unwrap();
    assert_eq!(
        journal.gap().map(|gap| gap.reason),
        Some(GapReason::RequestWithoutOutcome)
    );
    let ids: Vec<u64> = journal
        .take_operations()
        .iter()
        .map(|record| record.operation)
        .collect();
    assert_eq!(ids, [9], "the id is rebuilt as used");
}

#[test]
fn cluster_records_round_trip_with_their_fields() {
    let mut record =
        command("activate-upgrade", 3, Clearance::Administrator).record(Kind::ClusterOutcome, 8);
    record.relay = 77;
    record.evidence = b"sha256:00ff".to_vec();
    assert_eq!(
        JournalRecord::decode(&record.encode()),
        Some(record.clone())
    );
    for kind in [Kind::ClusterRequest, Kind::ClusterRefused] {
        let mut other = record.clone();
        other.kind = kind;
        other.relay = 0;
        assert_eq!(JournalRecord::decode(&other.encode()), Some(other));
    }
    let mut trailing = record.encode();
    trailing.push(0);
    assert_eq!(JournalRecord::decode(&trailing), None);
}

#[test]
fn a_registration_and_its_values_are_checked() {
    assert!(valid_name("activate-upgrade"));
    for name in ["", "Kill", "kill now", &"k".repeat(MAX_NAME + 1)] {
        assert!(!valid_name(name), "{name}");
    }
    assert_eq!(ProductCode::new(0), None);
    assert_eq!(ProductCode::new(UNKNOWN_OUTCOME), None);
    assert_eq!(Evidence::new("sha256", &[]), None);
    assert_eq!(Evidence::new("sha256", &[0; MAX_EVIDENCE + 1]), None);
    assert_eq!(
        ClusterReply::sequenced(1, 1, &[0; MAX_REPLY + 1], None),
        None
    );
    let ClusterReply::Refused { reason, .. } = ClusterReply::refused(
        ProductCode::new(1).unwrap(),
        &"é".repeat(MAX_PRODUCT_REASON),
    ) else {
        panic!("a refusal");
    };
    assert!(reason.len() <= MAX_PRODUCT_REASON);

    #[derive(Debug)]
    struct Twice;
    impl ClusterGateway for Twice {
        fn commands(&self) -> Vec<AdminCommand> {
            vec![AdminCommand::new("kill", Authority::Operator).unwrap(); 2]
        }
        fn submit(&mut self, _: &Submission<'_>) -> ClusterReply {
            ClusterReply::NoAnswer
        }
    }
    let mut clusters = Clusters::default();
    assert_eq!(
        clusters.attach("seq", Box::new(Twice)),
        Err(AttachError::Registration)
    );
    assert_eq!(
        clusters.attach("Seq", Box::new(Product::new(Mode::Silent))),
        Err(AttachError::Name)
    );
    clusters
        .attach("seq", Box::new(Product::new(Mode::Silent)))
        .unwrap();
    assert_eq!(
        clusters.attach("seq", Box::new(Product::new(Mode::Silent))),
        Err(AttachError::Duplicate)
    );
}

#[test]
fn parameters_parse_as_bounded_hex() {
    assert_eq!(parse_parameters("-"), Some(Vec::new()));
    assert_eq!(parse_parameters("00Ff"), Some(vec![0, 0xff]));
    for text in ["", "0", "+f", "zz", &"00".repeat(MAX_PARAMETERS + 1)] {
        assert_eq!(parse_parameters(text), None, "{text}");
    }
    assert_eq!(hex(&[0, 0xab]), "00ab");
}
