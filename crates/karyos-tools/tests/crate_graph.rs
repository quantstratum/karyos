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
    cargo_tree(package, "normal")
}

/// The dependencies of `package` along `edges` (`cargo tree -e`), one
/// crate per line.
fn cargo_tree(package: &str, edges: &str) -> String {
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
            edges,
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
/// karyos/design/management-agent-gap-analysis.md, M6, M11): the driver,
/// the client and the Archive never depend on it, and it depends on
/// neither the driver nor the tools; it lists the Archive's catalog
/// through karyos-archive's client.
#[test]
fn the_agent_stays_outside_the_driver_and_the_client() {
    for package in ["karyos-driver", "karyos-client", "karyos-archive"] {
        let tree = dependencies(package);
        assert!(
            !tree.lines().any(|line| line.starts_with("karyos-agent ")),
            "{package} depends on karyos-agent:\n{tree}"
        );
    }
    let agent = dependencies("karyos-agent");
    for crate_name in ["karyos-client ", "karyos-archive "] {
        assert!(
            agent.lines().any(|line| line.starts_with(crate_name)),
            "{agent}"
        );
    }
    for crate_name in ["karyos-driver ", "karyos-tools "] {
        assert!(
            !agent.lines().any(|line| line.starts_with(crate_name)),
            "karyos-agent depends on {crate_name}:\n{agent}"
        );
    }
}

/// The C ABI (#549): karyos-ffi's tests use the production Archive host
/// (karyos-tools' `DriverHost`) as a dev-dependency only. The published
/// crate never depends on karyos-tools, which sits above it.
#[test]
fn the_c_abi_depends_on_the_tools_for_its_tests_only() {
    let tree = dependencies("karyos-ffi");
    assert!(
        tree.lines().any(|line| line.starts_with("karyos-ffi")),
        "{tree}"
    );
    assert!(
        !tree.lines().any(|line| line.starts_with("karyos-tools ")),
        "karyos-ffi depends on karyos-tools:\n{tree}"
    );
    // The check sees the crate when it is there: as a dev-dependency.
    let dev = cargo_tree("karyos-ffi", "dev");
    assert!(
        dev.lines().any(|line| line.starts_with("karyos-tools ")),
        "{dev}"
    );
}

/// The packages of the encrypted class's graph: `karyos-protocol` and
/// `karyos-driver`, every feature, normal and build edges, on the host
/// target, as `(name, version)`. CI runs it on each of its targets
/// (x86_64 and aarch64 Linux, aarch64 macOS).
fn encrypted_class_graph() -> Vec<(String, String)> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let output = Command::new(cargo)
        .args([
            "tree",
            "-p",
            "karyos-protocol",
            "-p",
            "karyos-driver",
            "-e",
            "normal,build",
            "--all-features",
            "--prefix",
            "none",
            "--format",
            "{p}",
            "--offline",
            "--locked",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "cargo tree: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut packages: Vec<(String, String)> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let name = words.next()?.to_owned();
            let version = words.next()?.trim_start_matches('v').to_owned();
            Some((name, version))
        })
        .collect();
    packages.sort();
    packages.dedup();
    packages
}

/// What builds C or links a C library: the build helpers, the native
/// crypto libraries, and any `-sys` crate but `linux-raw-sys` (Rust
/// declarations of the Linux ABI, no build script) and the workspace's
/// own `karyos-sys` (pure Rust, no build script).
const C_BUILDS: [&str; 12] = [
    "cc",
    "cmake",
    "bindgen",
    "pkg-config",
    "vcpkg",
    "autocfg-c",
    "ring",
    "aws-lc-rs",
    "openssl",
    "boring",
    "nasm-rs",
    "cxx-build",
];

/// The cryptographic crates admitted for the encrypted class's graph, at
/// their resolved versions (ADR-0114 section 12: `aes-gcm-siv` and `aes`
/// with the rest of their graph, per
/// reviews/dependency-admission-aead-gcm-siv.md; `hkdf`, `hmac`, `sha2`
/// and `zeroize` under D51; ADMITTED_SIGNATURES below).
const ADMITTED_CRYPTO: [(&str, &str); 22] = [
    ("aes-gcm-siv", "0.12.1"),
    ("aes", "0.9.4"),
    ("polyval", "0.7.3"),
    ("ctutils", "0.4.8"),
    ("cpufeatures", "0.3.1"),
    ("aead", "0.6.1"),
    ("cipher", "0.5.2"),
    ("ctr", "0.10.1"),
    ("universal-hash", "0.6.1"),
    ("inout", "0.2.6"),
    ("crypto-common", "0.2.2"),
    ("block-buffer", "0.12.1"),
    ("digest", "0.11.3"),
    ("hybrid-array", "0.4.15"),
    ("subtle", "2.6.1"),
    ("cmov", "0.5.4"),
    ("cpubits", "0.1.1"),
    ("zeroize", "1.9.2"),
    ("hkdf", "0.13.0"),
    ("hmac", "0.13.0"),
    ("sha2", "0.11.1"),
    ("typenum", "1.20.1"),
];

/// Every cryptographic crate the check knows: a package of the graph with
/// one of these names must be admitted, at its admitted version.
const CRYPTO: [&str; 44] = [
    "aes-gcm-siv",
    "aes",
    "polyval",
    "ctutils",
    "cpufeatures",
    "aead",
    "cipher",
    "ctr",
    "universal-hash",
    "inout",
    "crypto-common",
    "block-buffer",
    "digest",
    "hybrid-array",
    "subtle",
    "cmov",
    "cpubits",
    "zeroize",
    "hkdf",
    "hmac",
    "sha2",
    "typenum",
    "ed25519-dalek",
    "ed25519",
    "signature",
    "curve25519-dalek",
    "curve25519-dalek-derive",
    "aes-gcm",
    "ghash",
    "chacha20",
    "chacha20poly1305",
    "poly1305",
    "sha1",
    "sha3",
    "md-5",
    "blake2",
    "blake3",
    "x25519-dalek",
    "p256",
    "k256",
    "rsa",
    "rustls",
    "ring",
    "aws-lc-rs",
];

/// H6 and H12 of the encrypted protection profile (ADR-0114, hard gates):
/// the protocol's and the driver's graph builds no C (no build helper,
/// no native library) and holds only the admitted cryptographic crates.
#[test]
fn the_encrypted_class_graph_has_no_c_build_and_only_admitted_crypto() {
    let graph = encrypted_class_graph();
    assert!(
        graph.iter().any(|(name, _)| name == "karyos-protocol"),
        "{graph:?}"
    );
    let native: Vec<&(String, String)> = graph
        .iter()
        .filter(|(name, _)| {
            C_BUILDS.contains(&name.as_str())
                || name.starts_with("aws-lc")
                || name.starts_with("openssl")
                || (name.ends_with("-sys")
                    && name != "linux-raw-sys"
                    && !name.starts_with("karyos-"))
        })
        .collect();
    assert!(native.is_empty(), "H6: C builds in the graph: {native:?}");
    let admitted: Vec<(&str, &str)> = ADMITTED_CRYPTO
        .iter()
        .chain(ADMITTED_SIGNATURES.iter())
        .copied()
        .collect();
    let unadmitted: Vec<&(String, String)> = graph
        .iter()
        .filter(|(name, _)| CRYPTO.contains(&name.as_str()))
        .filter(|(name, version)| !admitted.contains(&(name.as_str(), version.as_str())))
        .collect();
    assert!(
        unadmitted.is_empty(),
        "H12: cryptographic crates not admitted at these versions: {unadmitted:?}"
    );
    // The profile's own AEAD is there: the check reads the real graph.
    assert!(
        graph
            .iter()
            .any(|(name, version)| name == "aes-gcm-siv" && version == "0.12.1"),
        "{graph:?}"
    );
}

/// The signature crates admitted for the driver's signed authority
/// (owner decision D51, owner-decisions/2026-11-23: `ed25519-dalek` 3.0.0
/// with its graph; first reviewed in
/// reviews/dependency-admission-ed25519-archival.md).
const ADMITTED_SIGNATURES: [(&str, &str); 5] = [
    ("ed25519-dalek", "3.0.0"),
    ("ed25519", "3.0.0"),
    ("signature", "3.0.0"),
    ("curve25519-dalek", "5.0.0"),
    ("curve25519-dalek-derive", "0.1.1"),
];
