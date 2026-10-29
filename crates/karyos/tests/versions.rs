// SPDX-License-Identifier: Apache-2.0

//! The facade's public versions (R-CORE-33, karyos#752): the admission
//! protocol version equals the one the client announces, and the core
//! release is the workspace version.

/// Fails if the facade's protocol version and the admission protocol's
/// differ.
#[test]
fn the_protocol_version_is_the_admission_version() {
    assert_eq!(
        karyos::PROTOCOL_VERSION,
        karyos_protocol::admission::VERSION
    );
}

/// The core release is the workspace version, as the root manifest's
/// `[workspace.package]` states it, which a `libkaryos` package's manifest
/// reports as `core_version` too.
#[test]
fn the_core_version_is_the_workspace_version() {
    let manifest = include_str!("../../../Cargo.toml");
    let workspace = manifest
        .split("[workspace.package]")
        .nth(1)
        .and_then(|table| table.lines().find(|line| line.starts_with("version = ")))
        .and_then(|line| line.split('"').nth(1));
    assert_eq!(workspace, Some(karyos::CORE_VERSION));
}
