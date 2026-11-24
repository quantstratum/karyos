// SPDX-License-Identifier: Apache-2.0

//! The simulated network delivers the message a node sent, and copies it
//! only on a link that can duplicate it (karyos#691): a change that must
//! leave every run exactly as it was. The digests, trace lengths and
//! trace fingerprints below were taken at karyos main `c931ab55`, before
//! the change, for the reference core over W1, W3's lossy links (loss,
//! reordering and duplication) and W6, on two seeds; the same runs must
//! give the same values after it. A fingerprint is the standard library's
//! `DefaultHasher` over the trace, stable for the pinned toolchain.

#![allow(clippy::unwrap_used)]

use std::hash::{DefaultHasher, Hash, Hasher};

use karyos_sim::harness::reference::Reference;
use karyos_sim::harness::workloads::{self, Case, W1, W3, W6};

/// (case, seed, digest, trace length, trace fingerprint), at `c931ab55`.
const PINS: [(&str, &str, u64, u64, usize, u64); 10] = [
    (
        "reference",
        "W1 n=3 payload=32 clients=32",
        1,
        3870280429767755220,
        4652,
        4515903557072254432,
    ),
    (
        "reference",
        "W1 n=3 payload=32 clients=32",
        197,
        10042015232006514441,
        4652,
        721071963992488187,
    ),
    (
        "reference",
        "W3 LossyLinks",
        1,
        3460237000934403327,
        5716,
        7983990786191126927,
    ),
    (
        "reference",
        "W3 LossyLinks",
        197,
        17074906916917617820,
        5545,
        8250583751649907274,
    ),
    (
        "reference",
        "W6 healthy",
        1,
        13310963725907585884,
        3572,
        3733450088145696619,
    ),
    (
        "reference",
        "W6 healthy",
        197,
        18011967804706849590,
        3571,
        15856803296958591797,
    ),
    (
        "reference",
        "W6 follower crash",
        1,
        7720224497874407356,
        3533,
        7795352283634982567,
    ),
    (
        "reference",
        "W6 follower crash",
        197,
        16170177256630086682,
        3533,
        2970509763244006329,
    ),
    (
        "reference",
        "W6 slow replies",
        1,
        4951684887188531338,
        6635,
        452389225336645796,
    ),
    (
        "reference",
        "W6 slow replies",
        197,
        17177291544644625391,
        6635,
        16072666636110002461,
    ),
];

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
        outcome.trace.hash(&mut hasher);
        assert_eq!(
            (outcome.digest, outcome.trace.len(), hasher.finish()),
            (digest, length, fingerprint),
            "{name} seed {seed}"
        );
    }
}
