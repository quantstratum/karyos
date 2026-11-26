// SPDX-License-Identifier: Apache-2.0

//! The simulated network delivers the message a node sent, and copies it
//! only on a link that can duplicate it (karyos#691): a change that must
//! leave every run exactly as it was. The digests, trace lengths and
//! trace fingerprints below were taken at karyos main `c931ab55`, before
//! the change, for the reference core over W1, W3's lossy links (loss,
//! reordering and duplication) and W6, on two seeds; the same runs must
//! give the same values after it. A fingerprint is the standard library's
//! `DefaultHasher` over the trace, stable for the pinned toolchain.
//!
//! ADR-0123 (karyos#717) adds the cluster identity to the harness's
//! messages, so their trace lines and the digest over them changed: the
//! fingerprints are taken over the lines without the identity
//! ([`without_identity`]) and still match `c931ab55`'s, the same runs;
//! the digests were taken again after the change.

#![allow(clippy::unwrap_used)]

use std::hash::{DefaultHasher, Hash, Hasher};

use karyos_sim::harness::reference::Reference;
use karyos_sim::harness::workloads::{self, Case, W1, W3, W6};

/// (case, seed, digest, trace length, trace fingerprint): the lengths and
/// fingerprints at `c931ab55`, the digests after ADR-0123's identity.
const PINS: [(&str, &str, u64, u64, usize, u64); 10] = [
    (
        "reference",
        "W1 n=3 payload=32 clients=32",
        1,
        2057160540107451554,
        4652,
        4515903557072254432,
    ),
    (
        "reference",
        "W1 n=3 payload=32 clients=32",
        197,
        2083501468584757909,
        4652,
        721071963992488187,
    ),
    (
        "reference",
        "W3 LossyLinks",
        1,
        3268717310218551103,
        5716,
        7983990786191126927,
    ),
    (
        "reference",
        "W3 LossyLinks",
        197,
        13898090748390604250,
        5545,
        8250583751649907274,
    ),
    (
        "reference",
        "W6 healthy",
        1,
        1436070265102998718,
        3572,
        3733450088145696619,
    ),
    (
        "reference",
        "W6 healthy",
        197,
        13579684997249760940,
        3571,
        15856803296958591797,
    ),
    (
        "reference",
        "W6 follower crash",
        1,
        16088964270496793968,
        3533,
        7795352283634982567,
    ),
    (
        "reference",
        "W6 follower crash",
        197,
        6068855122827888028,
        3533,
        2970509763244006329,
    ),
    (
        "reference",
        "W6 slow replies",
        1,
        5291008113695081532,
        6635,
        452389225336645796,
    ),
    (
        "reference",
        "W6 slow replies",
        197,
        1738565470971562853,
        6635,
        16072666636110002461,
    ),
];

/// `line` without the cluster identities ADR-0123 added to the harness's
/// messages (karyos#717): every run's servers and clients share one, so
/// the messages are otherwise the ones pinned before it.
fn without_identity(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(at) = rest.find("ClusterId(") {
        let (head, tail) = rest.split_at(at);
        let head = head.strip_suffix("cluster: ").unwrap_or(head);
        out.push_str(head);
        let end = tail.find(')').unwrap() + 1;
        rest = tail[end..].strip_prefix(", ").unwrap_or(&tail[end..]);
    }
    out.push_str(rest);
    out
}

fn case(name: &str) -> Case {
    let mut cases = vec![W1::skeleton().cases().into_iter().nth(1).unwrap()];
    cases.extend(W3::skeleton().cases());
    cases.extend(W6::skeleton().cases());
    cases.into_iter().find(|case| case.name == name).unwrap()
}

#[test]
fn delivering_the_sent_message_changes_no_run() {
    for (core, name, seed, digest, length, fingerprint) in PINS {
        assert_eq!(core, "reference");
        let outcome = workloads::run::<Reference>(&case(name), seed).unwrap();
        let mut hasher = DefaultHasher::new();
        outcome
            .trace
            .iter()
            .map(|line| without_identity(line))
            .collect::<Vec<_>>()
            .hash(&mut hasher);
        assert_eq!(
            (outcome.digest, outcome.trace.len(), hasher.finish()),
            (digest, length, fingerprint),
            "{name} seed {seed}"
        );
    }
}
