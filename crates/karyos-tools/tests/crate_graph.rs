// SPDX-License-Identifier: Apache-2.0

//! The crate graph stays as SPEC.md §14 and the owner decision of ACS 11410
//! set it (`quantstratum-docs: karyos/design/trace-network.md` §1 and §8,
//! "Crate graph"): the driver and the client never depend on karyos-trace,
//! which the application or karyosd builds the hooks from. A permanent gate
//! (ACS 15498).

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(
    clippy::unwrap_used,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::process::Command;

/// The normal dependencies of `package`, one crate per line.
fn dependencies(package: &str) -> String {
    // The cargo running the tests, at run time; every feature, so no
    // feature can bring the crate in. The host target only: `--target all`
    // needs other targets' dependencies, which an offline build does not
    // have.
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let output = Command::new(cargo)
        .args([
            "tree",
            "-p",
            package,
            "-e",
            "normal",
            "--all-features",
            "--prefix",
            "none",
            "--offline",
            "--locked",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "cargo tree -p {package}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn neither_the_driver_nor_the_client_depends_on_karyos_trace() {
    for package in ["karyos-driver", "karyos-client"] {
        let tree = dependencies(package);
        assert!(tree.lines().any(|line| line.starts_with(package)), "{tree}");
        assert!(
            !tree.lines().any(|line| line.starts_with("karyos-trace ")),
            "{package} depends on karyos-trace:\n{tree}"
        );
    }
    // The check sees the crate when it is there.
    assert!(
        dependencies("karyos-tools")
            .lines()
            .any(|line| line.starts_with("karyos-trace "))
    );
}

/// The management agent (owner item 52; quantstratum-docs:
/// karyos/design/management-agent-gap-analysis.md, M6): the driver and
/// the client never depend on it, and it depends on neither the driver nor
/// the tools.
#[test]
fn the_agent_stays_outside_the_driver_and_the_client() {
    for package in ["karyos-driver", "karyos-client"] {
        let tree = dependencies(package);
        assert!(
            !tree.lines().any(|line| line.starts_with("karyos-agent ")),
            "{package} depends on karyos-agent:\n{tree}"
        );
    }
    let agent = dependencies("karyos-agent");
    assert!(
        agent.lines().any(|line| line.starts_with("karyos-client ")),
        "{agent}"
    );
    for crate_name in ["karyos-driver ", "karyos-tools "] {
        assert!(
            !agent.lines().any(|line| line.starts_with(crate_name)),
            "karyos-agent depends on {crate_name}:\n{agent}"
        );
    }
}
