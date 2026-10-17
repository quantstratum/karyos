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
    let output = Command::new(env!("CARGO"))
        .args([
            "tree",
            "-p",
            package,
            "-e",
            "normal",
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
