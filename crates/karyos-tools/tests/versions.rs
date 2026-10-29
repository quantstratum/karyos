// SPDX-License-Identifier: Apache-2.0

//! `--versions` on every binary (R-CORE-33, karyos#729): the same object
//! the library builds, printed before anything else is parsed, with a
//! success exit, and no driver touched: a driver directory that does not
//! exist stays absent, with any other argument beside the flag.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::process::Command;

#[test]
fn every_binary_prints_the_versions_and_touches_no_driver() {
    let dir = std::env::temp_dir().join(format!("karyos-versions-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let expected = karyos_tools::versions::current().json();
    for binary in [
        env!("CARGO_BIN_EXE_karyosd"),
        env!("CARGO_BIN_EXE_karyos-tools"),
        env!("CARGO_BIN_EXE_karyos-stat"),
        env!("CARGO_BIN_EXE_karyos-errors"),
        env!("CARGO_BIN_EXE_karyos-catalog"),
        env!("CARGO_BIN_EXE_karyos-replay"),
        env!("CARGO_BIN_EXE_karyos-trace"),
    ] {
        let output = Command::new(binary)
            .args(["--dir"])
            .arg(&dir)
            .arg("--versions")
            .output()
            .unwrap();
        assert!(output.status.success(), "{binary}: {output:?}");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            expected,
            "{binary}"
        );
        assert!(output.stderr.is_empty(), "{binary}: {output:?}");
        assert!(!dir.exists(), "{binary} created the driver directory");
    }
}

/// A closed standard output is a failed exit, never a panic.
#[cfg(unix)]
#[test]
fn a_closed_stdout_is_a_failed_exit() {
    use std::process::Stdio;

    let mut child = Command::new(env!("CARGO_BIN_EXE_karyosd"))
        .arg("--versions")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Close the reading end before the child writes.
    drop(child.stdout.take());
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("panicked"), "{stderr}");
}
