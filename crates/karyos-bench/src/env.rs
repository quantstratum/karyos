// SPDX-License-Identifier: Apache-2.0

//! Environment labels: every report says where and how it was measured, and
//! that the host is not qualified for the SPEC.md §12 targets.

use std::process::Command;

/// Where a run was measured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Labels {
    /// Host name.
    pub host: String,
    /// Operating system.
    pub os: &'static str,
    /// Architecture.
    pub arch: &'static str,
    /// CPU model, where readable.
    pub cpu: String,
    /// Available parallelism.
    pub cores: usize,
    /// Build profile.
    pub profile: &'static str,
    /// The commit, where known.
    pub commit: String,
    /// Always `unqualified`: no host is listed as qualified in SPEC.md §17,
    /// so no result here establishes a SPEC.md §12 target.
    pub qualification: &'static str,
}

/// Keeps only characters that need no escaping in the history file.
#[must_use]
pub fn clean(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || " .-_@()/".contains(*c))
        .collect::<String>()
        .trim()
        .to_string()
}

fn command(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|value| !value.is_empty())
}

fn cpu_model() -> Option<String> {
    if cfg!(target_os = "linux") {
        let info = std::fs::read_to_string("/proc/cpuinfo").ok()?;
        info.lines()
            .find(|line| line.starts_with("model name"))
            .and_then(|line| line.split_once(':'))
            .map(|(_, model)| model.trim().to_string())
    } else if cfg!(target_os = "macos") {
        command("sysctl", &["-n", "machdep.cpu.brand_string"])
    } else {
        None
    }
}

impl Labels {
    /// The labels of this process's environment. The commit comes from
    /// `KARYOS_COMMIT`, else `git rev-parse --short HEAD`.
    #[must_use]
    pub fn detect() -> Self {
        let unknown = || "unknown".to_string();
        Self {
            host: clean(
                &std::env::var("HOSTNAME")
                    .ok()
                    .or_else(|| command("hostname", &[]))
                    .unwrap_or_else(unknown),
            ),
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            cpu: clean(&cpu_model().unwrap_or_else(unknown)),
            cores: std::thread::available_parallelism().map_or(1, usize::from),
            profile: if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            },
            commit: clean(
                &std::env::var("KARYOS_COMMIT")
                    .ok()
                    .or_else(|| command("git", &["rev-parse", "--short", "HEAD"]))
                    .unwrap_or_else(unknown),
            ),
            qualification: "unqualified",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_clean_and_never_qualified() {
        let labels = Labels::detect();
        assert_eq!(labels.qualification, "unqualified");
        assert!(labels.cores >= 1);
        assert_eq!(clean(" a\"b,c{d}: e "), "abcd e");
        for value in [&labels.host, &labels.cpu, &labels.commit] {
            assert_eq!(&clean(value), value);
        }
    }
}
