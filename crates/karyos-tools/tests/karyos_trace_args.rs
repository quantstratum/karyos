// SPDX-License-Identifier: Apache-2.0

//! The `karyos-trace` command line on every platform (`quantstratum-docs:
//! karyos/design/trace-tool.md`, "The command", T3): `--help` exits 0, a
//! usage error prints one line on standard error and exits 1, and a
//! directory without a driver exits 2. Reports against a driver are tested
//! on Linux in `karyos_trace.rs`.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used)]

use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_karyos-trace"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn karyos_trace_exit_codes() {
    let help = run(&["--help"]);
    assert_eq!(help.status.code(), Some(0), "{help:?}");
    assert!(String::from_utf8(help.stdout).unwrap().contains("--follow"));
    for usage in [&["--bogus"][..], &[], &["--dir", "/d", "--interval", "0"]] {
        let output = run(usage);
        assert_eq!(output.status.code(), Some(1), "{usage:?} {output:?}");
        assert_eq!(String::from_utf8(output.stderr).unwrap().lines().count(), 1);
    }
    let dir = std::env::temp_dir().join(format!("karyos-trace-none-{}", std::process::id()));
    let output = run(&["--dir", dir.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    assert!(stderr.starts_with("karyos-trace: "), "{stderr}");
}
