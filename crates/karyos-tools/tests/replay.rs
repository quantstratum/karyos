// SPDX-License-Identifier: Apache-2.0

//! `karyos-replay` and its alias `karyos-tools replay diff` as binaries
//! (quantstratum-docs: karyos/design/archive-host.md, H5): the help under
//! each name, the same argument error status, and an unknown subcommand
//! refused. The diff itself is tested in `karyos_tools::replay`.

#![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

use std::process::Command;

fn run(binary: &str, args: &[&str]) -> (Option<i32>, String, String) {
    let output = Command::new(binary).args(args).output().unwrap();
    (
        output.status.code(),
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

const REPLAY: &str = env!("CARGO_BIN_EXE_karyos-replay");
const TOOLS: &str = env!("CARGO_BIN_EXE_karyos-tools");

#[test]
fn karyos_replay_lists_diff_and_names_its_alias() {
    let (status, out, _) = run(REPLAY, &["--help"]);
    assert_eq!(status, Some(0));
    assert!(out.contains("Usage: karyos-replay diff"), "{out}");
    assert!(out.contains("karyos-tools replay diff"), "{out}");
    let (status, _, err) = run(REPLAY, &["frobnicate"]);
    assert_eq!(status, Some(3));
    assert!(
        err.starts_with("karyos-replay: unknown subcommand"),
        "{err}"
    );
}

#[test]
fn both_names_give_the_diff_help_and_its_argument_errors() {
    let (status, out, _) = run(REPLAY, &["diff", "--help"]);
    assert_eq!(status, Some(0));
    assert!(
        out.contains("Usage: karyos-replay diff <left-dir>"),
        "{out}"
    );
    let (status, out, _) = run(TOOLS, &["replay", "diff", "--help"]);
    assert_eq!(status, Some(0));
    assert!(
        out.contains("Usage: karyos-tools replay diff <left-dir>"),
        "{out}"
    );
    for (binary, args) in [
        (REPLAY, &["diff", "--bogus"][..]),
        (TOOLS, &["replay", "diff", "--bogus"][..]),
    ] {
        let (status, out, err) = run(binary, args);
        assert_eq!(status, Some(3), "{binary}");
        assert!(out.is_empty(), "{out}");
        assert!(err.contains("unknown option --bogus"), "{err}");
    }
}
