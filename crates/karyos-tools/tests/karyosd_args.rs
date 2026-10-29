// SPDX-License-Identifier: Apache-2.0

//! The `karyosd` command line on every platform (`quantstratum-docs:
//! karyos/design/observability-and-tools.md`, Binaries): `--help` exits 0,
//! and a configuration error prints one line on standard error and exits
//! 2. The daemon itself is tested on Linux in `karyosd.rs`.

use std::process::Command;

#[test]
fn karyosd_exits_2_on_a_configuration_error_and_0_on_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_karyosd"))
        .arg("--bogus")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert_eq!(String::from_utf8(output.stderr).unwrap().lines().count(), 1);
    let output = Command::new(env!("CARGO_BIN_EXE_karyosd"))
        .arg("--help")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("--shutdown-linger")
    );
}

/// R-CORE-43: `karyosd --config` reads the `[io]` table and refuses a
/// backend this build does not have, in one line with exit status 2;
/// sockets stays selectable.
#[test]
fn karyosd_refuses_an_unsupported_io_backend_from_its_config_file() {
    let path = std::env::temp_dir().join(format!("karyosd-args-{}.toml", std::process::id()));
    std::fs::write(&path, "[io]\nbackend = \"dpdk\"\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_karyosd"))
        .args(["--dir", "/nonexistent", "--network", "on", "--config"])
        .arg(&path)
        .output()
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    assert!(stderr.contains("\"dpdk\" needs karyosd-native"), "{stderr}");
    assert!(stderr.contains("this driver has sockets"), "{stderr}");
}
