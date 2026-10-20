// SPDX-License-Identifier: Apache-2.0

//! `karyos-catalog` as a binary (quantstratum-docs:
//! karyos/design/archive-host.md, H4): its help, an unknown subcommand
//! refused, and `list` of a directory with no catalog, which creates
//! nothing. The listing itself is tested in `karyos_tools::catalog`.

#![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

use std::process::Command;

const CATALOG: &str = env!("CARGO_BIN_EXE_karyos-catalog");

fn run(args: &[&std::ffi::OsStr]) -> (Option<i32>, String, String) {
    let output = Command::new(CATALOG).args(args).output().unwrap();
    (
        output.status.code(),
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

#[test]
fn the_binary_lists_reads_only_and_refuses_what_it_does_not_know() {
    let (status, out, _) = run(&["--help".as_ref()]);
    assert_eq!(status, Some(0));
    assert!(
        out.contains("Usage: karyos-catalog list <dir> [--json]"),
        "{out}"
    );
    let (status, _, err) = run(&["frobnicate".as_ref()]);
    assert_eq!(status, Some(2));
    assert!(
        err.starts_with("karyos-catalog: unknown subcommand"),
        "{err}"
    );
    let dir = std::env::temp_dir().join(format!("karyos-catalog-bin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (status, out, _) = run(&["list".as_ref(), dir.as_os_str()]);
    assert_eq!(status, Some(0));
    assert!(out.starts_with("no catalog in "), "{out}");
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "nothing created"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
