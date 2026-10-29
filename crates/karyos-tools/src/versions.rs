// SPDX-License-Identifier: Apache-2.0

//! The machine-readable versions of every contract surface (R-CORE-33,
//! karyos#729; `quantstratum-docs: karyos/design/versions.md`): what
//! `--versions` prints on every binary of this crate, as one JSON object
//! with a schema of its own, read from the constants each surface is
//! defined by, so the output cannot drift from them.
//!
//! `--versions` is looked for before anything else is parsed: the binary
//! prints the object and exits, opening no CnC and touching no driver. The
//! object is written through a locked standard output, and a failed write
//! (a closed pipe) is a nonzero exit, never a panic.
//!
//! Each version carries the id of the rule a reader compares it under,
//! defined in `versions.md`: `exact` (the same number on both sides) and
//! `exact-0y-min-patch` (owner item 48: the exact `0.y` line and a
//! library patch at least the header's). A new field is additive and
//! keeps [`SCHEMA_VERSION`]; removing a field or changing its meaning
//! increments it.

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::io::Write as _;
use std::process::ExitCode;

/// The name of the output's own schema.
pub const SCHEMA: &str = "karyos-versions";
/// The version of the output's own schema.
pub const SCHEMA_VERSION: u32 = 1;
/// The flag that asks for the versions.
pub const FLAG: &str = "--versions";

/// Every backend `[io] backend` can name (Karyos SPEC 16.9): `io_uring`
/// and `af_xdp` are planned, and `ef_vi` and `dpdk` are built by
/// `karyosd-native` only (ADR-0050).
pub const BACKENDS: [&str; 5] = ["sockets", "io_uring", "af_xdp", "ef_vi", "dpdk"];

/// A backend the core knows, and whether this build compiled it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backend {
    /// Its name, as `[io] backend` names it.
    pub name: &'static str,
    /// Whether this build holds it.
    pub compiled: bool,
}

/// The versions this build reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Versions {
    /// The core release (`karyos::CORE_VERSION`).
    pub core: &'static str,
    /// The admission protocol version a client announces
    /// (`karyos::PROTOCOL_VERSION`).
    pub admission: u64,
    /// The frame protocol version in every frame header.
    pub frame: u8,
    /// The C ABI version, major, minor and patch.
    pub c_abi: (u32, u32, u32),
    /// The Archive control schema (schema 1) version.
    pub archive_control: u16,
    /// The Cluster log schema (schema 2) version.
    pub cluster_log: u16,
    /// The group record schema (schema 3) version.
    pub group_record: u16,
    /// The capture contract version of group journals.
    pub capture_contract: u16,
    /// The Archive durability schema (schema 4) version.
    pub archive_durable: u16,
    /// The `karyosd` configuration file schema version.
    pub config: u32,
    /// The backends the core knows, compiled or not.
    pub backends: [Backend; 5],
    /// The cargo features of this crate enabled in the build.
    pub features: &'static [&'static str],
}

/// The versions of this build, from their source constants.
#[must_use]
pub fn current() -> Versions {
    // What this build's daemon can select: the backends its schema
    // registers (the sockets backend on Linux and macOS).
    let registered = crate::config::IoSchema::core().names();
    Versions {
        core: karyos::CORE_VERSION,
        admission: karyos::PROTOCOL_VERSION,
        frame: karyos_sys::frame::PROTOCOL_VERSION,
        c_abi: (
            karyos_protocol::versions::C_ABI_MAJOR,
            karyos_protocol::versions::C_ABI_MINOR,
            karyos_protocol::versions::C_ABI_PATCH,
        ),
        archive_control: karyos_archive::control::VERSION,
        cluster_log: karyos_cluster::service::VERSION,
        group_record: karyos_archive::group::record::VERSION,
        capture_contract: karyos_archive::group::record::CONTRACT_VERSION,
        archive_durable: karyos_archive::durable::VERSION,
        config: crate::config::SCHEMA_VERSION,
        backends: BACKENDS.map(|name| Backend {
            name,
            compiled: registered.contains(&name),
        }),
        features: if cfg!(feature = "test-hooks") {
            &["test-hooks"]
        } else {
            &[]
        },
    }
}

impl Versions {
    /// The JSON object, on one line, with its newline.
    #[must_use]
    pub fn json(&self) -> String {
        let (major, minor, patch) = self.c_abi;
        let mut out = String::new();
        let _ = write!(
            out,
            concat!(
                r#"{{"schema":"{}","schema_version":{},"#,
                r#""core":{{"release":"{}"}},"#,
                r#""protocol":{{"admission":{},"frame":{},"rule":"exact"}},"#,
                r#""c_abi":{{"version":"{}.{}.{}","rule":"exact-0y-min-patch"}},"#,
                r#""wire":{{"frame":{},"archive_control":{},"cluster_log":{},"group_record":{},"capture_contract":{},"archive_durable":{},"rule":"exact"}},"#,
                r#""config":{{"schema_version":{},"rule":"exact"}},"#,
                r#""backends":["#
            ),
            SCHEMA,
            SCHEMA_VERSION,
            self.core,
            self.admission,
            self.frame,
            major,
            minor,
            patch,
            self.frame,
            self.archive_control,
            self.cluster_log,
            self.group_record,
            self.capture_contract,
            self.archive_durable,
            self.config,
        );
        for (index, backend) in self.backends.iter().enumerate() {
            let separator = if index == 0 { "" } else { "," };
            let _ = write!(
                out,
                r#"{separator}{{"name":"{}","compiled":{}}}"#,
                backend.name, backend.compiled
            );
        }
        out.push_str(r#"],"features":["#);
        for (index, feature) in self.features.iter().enumerate() {
            let separator = if index == 0 { "" } else { "," };
            let _ = write!(out, r#"{separator}"{feature}""#);
        }
        out.push_str("]}\n");
        out
    }
}

/// Whether `args` ask for the versions.
pub fn asked<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    args.into_iter().any(|arg| arg.as_ref() == FLAG)
}

/// Writes the versions to standard output when `args` ask for them, and
/// returns the exit code: success, or failure when the write failed. `None`
/// when they do not ask, and nothing was done.
pub fn intercept<I, S>(args: I) -> Option<ExitCode>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    if !asked(args) {
        return None;
    }
    let mut out = std::io::stdout().lock();
    let written = out
        .write_all(current().json().as_bytes())
        .and_then(|()| out.flush());
    Some(if written.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every reported number is its source constant's.
    #[test]
    fn each_version_is_its_source_constant() {
        let versions = current();
        assert_eq!(versions.core, karyos::CORE_VERSION);
        assert_eq!(
            versions.admission,
            karyos_protocol::admission::VERSION,
            "the admission version a client announces"
        );
        assert_eq!(versions.frame, karyos_sys::frame::PROTOCOL_VERSION);
        assert_eq!(versions.archive_control, karyos_archive::control::VERSION);
        assert_eq!(versions.cluster_log, karyos_cluster::service::VERSION);
        assert_eq!(
            versions.group_record,
            karyos_archive::group::record::VERSION
        );
        assert_eq!(
            versions.capture_contract,
            karyos_archive::group::record::CONTRACT_VERSION
        );
        assert_eq!(versions.archive_durable, karyos_archive::durable::VERSION);
        assert_eq!(versions.config, crate::config::SCHEMA_VERSION);
    }

    /// The C ABI version is the header's, as the package script reads it.
    #[test]
    fn the_c_abi_version_is_the_headers() {
        let header = include_str!("../../karyos-ffi/include/karyos.h");
        let define = |name: &str| {
            header
                .lines()
                .find_map(|line| line.strip_prefix(&format!("#define {name} ")))
                .and_then(|value| value.trim().parse::<u32>().ok())
        };
        let (major, minor, patch) = current().c_abi;
        assert_eq!(define("KARYOS_ABI_VERSION_MAJOR"), Some(major));
        assert_eq!(define("KARYOS_ABI_VERSION_MINOR"), Some(minor));
        assert_eq!(define("KARYOS_ABI_VERSION_PATCH"), Some(patch));
    }

    /// The object names its schema, every rule and every backend, the
    /// ones this build lacks included.
    #[test]
    fn the_object_is_versioned_and_names_the_missing_backends() {
        let json = current().json();
        assert!(
            json.starts_with(r#"{"schema":"karyos-versions","schema_version":1,"#),
            "{json}"
        );
        assert!(json.ends_with("]}\n"), "{json}");
        assert_eq!(json.lines().count(), 1);
        for field in [
            r#""rule":"exact""#,
            r#""rule":"exact-0y-min-patch""#,
            r#"{"name":"io_uring","compiled":false}"#,
            r#"{"name":"af_xdp","compiled":false}"#,
            r#"{"name":"ef_vi","compiled":false}"#,
            r#"{"name":"dpdk","compiled":false}"#,
            r#""config":{"schema_version":1,"rule":"exact"}"#,
        ] {
            assert!(json.contains(field), "{field} in {json}");
        }
        // Compiled exactly when this build's schema registers it.
        let registered = crate::config::IoSchema::core().names();
        assert!(registered.contains(&"sockets"));
        for backend in current().backends {
            assert_eq!(
                backend.compiled,
                registered.contains(&backend.name),
                "{}",
                backend.name
            );
        }
        assert!(
            json.contains(r#"{"name":"sockets","compiled":true}"#),
            "{json}"
        );
    }

    #[test]
    fn the_flag_is_found_anywhere() {
        assert!(asked(["--dir", "/d", "--versions"]));
        assert!(!asked(["--dir", "/d"]));
        assert!(!asked(["--version"]));
    }
}
