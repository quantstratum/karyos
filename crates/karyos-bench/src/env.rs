// SPDX-License-Identifier: Apache-2.0

//! Environment labels, classification and decision eligibility
//! (`quantstratum-docs: karyos/design/measurement-harness.md` 4.2): every
//! report says where and how it was measured, which environment class of
//! manifest 6.3 that is, and whether the host is decision eligible.

use std::fmt;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::inventory::{
    Inventory, Reading, Scope, parse_lscpu, record_enabled_idle, record_node_and_release,
};
use crate::manifest::Fanout;

/// The environments of manifest 6.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Environment {
    /// Physical Linux host, x86_64: the decision metric.
    E1,
    /// Two physical Linux hosts on one switch: round trip and fan-out.
    E2,
    /// aarch64: reported as Not demonstrated in this version (Q-5).
    E3,
    /// macOS workspace, Linux VMs and containers: functional only, never
    /// decides.
    E4,
}

impl Environment {
    /// Whether a result from this environment may decide (6.3, 8.8).
    #[must_use]
    pub const fn decides(self) -> bool {
        matches!(self, Self::E1 | Self::E2)
    }

    /// What a result from this environment is for.
    #[must_use]
    pub const fn usage(self) -> &'static str {
        match self {
            Self::E1 => "decision metric, if eligible",
            Self::E2 => "round trip and fan-out, if eligible",
            Self::E3 => "not demonstrated (manifest 6.3, Q-5)",
            Self::E4 => "functional only, non-decision",
        }
    }
}

impl fmt::Display for Environment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::E1 => "E1",
            Self::E2 => "E2",
            Self::E3 => "E3",
            Self::E4 => "E4",
        })
    }
}

/// The class of one host and the facts it rests on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    /// The class.
    pub environment: Environment,
    /// Why, one fact per entry.
    pub basis: Vec<String>,
}

/// Classifies one host (measurement-harness.md 4.2, H-6). macOS, any
/// other non-Linux system, a container, a VM or a cloud instance is E4,
/// whatever the architecture; a physical Linux aarch64 host is E3; a
/// physical Linux x86_64 host is E1. A host is physical only when
/// `systemd-detect-virt` reports `none` for both VM and container, no
/// container marker is present, `lscpu` names no hypervisor,
/// `/sys/hypervisor/type` is absent and no DMI string names a cloud
/// provider; an unavailable `systemd-detect-virt` leaves it E4. The
/// architecture is the running kernel's (`uname -m`).
#[must_use]
pub fn classify(inventory: &Inventory) -> Classification {
    let mut basis = Vec::new();
    if inventory.os != "linux" {
        basis.push(format!(
            "operating system {}: functional only (SPEC §17)",
            inventory.os
        ));
        return Classification {
            environment: Environment::E4,
            basis,
        };
    }
    let reported = |reading: &Reading| match reading {
        Ok(value) => Some(value.trim().to_string()),
        Err(_) => None,
    };
    match &inventory.virt_container {
        Ok(value) if value.trim() != "none" => basis.push(format!(
            "systemd-detect-virt --container reports {}",
            value.trim()
        )),
        Ok(_) => {}
        Err(reason) => basis.push(format!(
            "container status not confirmed: systemd-detect-virt --container unavailable ({reason})"
        )),
    }
    if let Some(kind) = reported(&inventory.hypervisor_type).filter(|v| !v.is_empty()) {
        basis.push(format!("/sys/hypervisor/type reports {kind}"));
    }
    for vendor in [
        &inventory.dmi_sys_vendor,
        &inventory.dmi_board_vendor,
        &inventory.dmi_product,
    ]
    .into_iter()
    .filter_map(reported)
    {
        if let Some(cloud) = cloud_vendor(&vendor) {
            basis.push(format!("DMI names cloud provider {cloud} ({vendor})"));
        }
    }
    for marker in &inventory.container_markers {
        basis.push(format!("container marker {marker}"));
    }
    match &inventory.virt {
        Ok(value) if value.trim() != "none" => {
            basis.push(format!("systemd-detect-virt reports {}", value.trim()));
        }
        Ok(_) => {}
        Err(reason) => basis.push(format!(
            "virtualization not confirmed: systemd-detect-virt unavailable ({reason})"
        )),
    }
    if let Some(vendor) = inventory
        .lscpu
        .as_deref()
        .ok()
        .and_then(|text| parse_lscpu(text).hypervisor)
    {
        basis.push(format!("lscpu reports hypervisor vendor {vendor}"));
    }
    if !basis.is_empty() {
        return Classification {
            environment: Environment::E4,
            basis,
        };
    }
    basis.push(
        "systemd-detect-virt reports none for VM and container; no container marker".to_string(),
    );
    let environment = match inventory.arch.as_str() {
        "x86_64" => {
            basis.push("physical Linux x86_64".to_string());
            Environment::E1
        }
        "aarch64" => {
            basis.push("physical Linux aarch64: excluded from the comparison (Q-5)".to_string());
            Environment::E3
        }
        other => {
            basis.push(format!("architecture {other} is outside manifest 6.3"));
            Environment::E4
        }
    };
    Classification { environment, basis }
}

/// Cloud providers recognized in DMI strings: an instance of any of them,
/// bare metal included, is E4 (measurement-harness.md 4.2).
const CLOUD_VENDORS: [(&str, &str); 10] = [
    ("amazon", "Amazon Web Services"),
    ("google", "Google Cloud"),
    ("microsoft corporation", "Microsoft Azure"),
    ("alibaba", "Alibaba Cloud"),
    ("oraclecloud", "Oracle Cloud"),
    ("digitalocean", "DigitalOcean"),
    ("openstack", "OpenStack"),
    ("linode", "Linode"),
    ("vultr", "Vultr"),
    ("scaleway", "Scaleway"),
];

/// The cloud provider a DMI string names, if any.
fn cloud_vendor(value: &str) -> Option<&'static str> {
    let lower = value.to_ascii_lowercase();
    CLOUD_VENDORS
        .iter()
        .find(|(needle, _)| lower.contains(needle))
        .map(|(_, name)| *name)
}

/// The class of a pair of hosts: E2 when both are E1 and a switch
/// topology is recorded, else the class of the weaker host. Orchestration
/// over two hosts is batch B5; this is the hook.
#[must_use]
pub fn classify_pair(a: Environment, b: Environment, topology: Option<&str>) -> Environment {
    let rank = |environment: Environment| match environment {
        Environment::E1 | Environment::E2 => 0,
        Environment::E3 => 1,
        Environment::E4 => 2,
    };
    if rank(a) == 0 && rank(b) == 0 {
        if topology.is_some_and(|text| !text.trim().is_empty()) {
            Environment::E2
        } else {
            Environment::E1
        }
    } else if rank(a) >= rank(b) {
        a
    } else {
        b
    }
}

/// The fan-outs a run can need cores for: F1, and F2 with 4 and 16
/// receivers (F2 with 16 is reported only).
pub const FANOUTS: [Fanout; 3] = [
    Fanout::F1,
    Fanout::F2 { receivers: 4 },
    Fanout::F2 { receivers: 16 },
];

/// The processes of a run, each on its own isolated core: one sender and
/// each receiver (2 for F1, 5 for F2 with 4, 17 for F2 with 16).
#[must_use]
pub fn processes(fanout: Fanout) -> usize {
    1 + usize::from(fanout.receivers())
}

/// A short name of a fan-out with its process count.
#[must_use]
pub fn fanout_label(fanout: Fanout) -> String {
    match fanout {
        Fanout::F1 => format!("F1 ({} processes)", processes(fanout)),
        Fanout::F2 { receivers } => {
            format!("F2 x{receivers} ({} processes)", processes(fanout))
        }
    }
}

/// One failed condition of decision eligibility (measurement-harness.md
/// 4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ineligible {
    /// The class is not E1 or E2.
    Class(Environment),
    /// No record of this host was supplied.
    NoHostRecord {
        /// The host.
        host: String,
    },
    /// The record names another host, or none could be read.
    RecordHost {
        /// The node name in the record.
        recorded: String,
        /// The running node name.
        running: String,
    },
    /// The record was taken on another kernel release.
    RecordKernel {
        /// The release in the record.
        recorded: String,
        /// The running release.
        running: String,
    },
    /// Fewer isolated cores than processes.
    IsolatedCores {
        /// Processes of the run.
        needed: usize,
        /// Isolated cores.
        isolated: usize,
    },
    /// Fewer isolated cores in `nohz_full` than processes.
    NohzFull {
        /// Processes of the run.
        needed: usize,
        /// Isolated cores that are also in `nohz_full`.
        cores: usize,
    },
    /// CPUs whose governor is not `performance` and whose frequency is not
    /// fixed (the isolated cores, or every CPU when none is isolated).
    Governor {
        /// Each such CPU with its governor.
        cpus: Vec<String>,
    },
    /// The clock source is not `tsc`.
    ClockSource(String),
    /// cpuidle states enabled on the run's cores that the host record
    /// does not enable (deeper than the record allows), or unreadable.
    CpuIdle {
        /// Each such state, as `cpuN stateM (name)`.
        states: Vec<String>,
    },
}

impl Ineligible {
    /// A one-line form that [`Ineligible::decode`] reads back: the kind,
    /// then each field, separated by tabs (a list field takes the rest).
    #[must_use]
    pub fn encode(&self) -> String {
        let fields: Vec<String> = match self {
            Self::Class(environment) => vec!["class".into(), environment.to_string()],
            Self::NoHostRecord { host } => vec!["no_host_record".into(), host.clone()],
            Self::RecordHost { recorded, running } => {
                vec!["record_host".into(), recorded.clone(), running.clone()]
            }
            Self::RecordKernel { recorded, running } => {
                vec!["record_kernel".into(), recorded.clone(), running.clone()]
            }
            Self::IsolatedCores { needed, isolated } => vec![
                "isolated_cores".into(),
                needed.to_string(),
                isolated.to_string(),
            ],
            Self::NohzFull { needed, cores } => {
                vec!["nohz_full".into(), needed.to_string(), cores.to_string()]
            }
            Self::Governor { cpus } => std::iter::once("governor".to_string())
                .chain(cpus.iter().cloned())
                .collect(),
            Self::ClockSource(source) => vec!["clock_source".into(), source.clone()],
            Self::CpuIdle { states } => std::iter::once("cpuidle".to_string())
                .chain(states.iter().cloned())
                .collect(),
        };
        fields.join("\t")
    }

    /// The inverse of [`Ineligible::encode`].
    ///
    /// # Errors
    ///
    /// An unknown kind or a malformed field.
    pub fn decode(text: &str) -> Result<Self, String> {
        let bad = || format!("bad eligibility reason {text:?}");
        let mut fields = text.split('\t');
        let kind = fields.next().ok_or_else(bad)?;
        let rest: Vec<String> = fields.map(ToString::to_string).collect();
        let one = |index: usize| rest.get(index).cloned().ok_or_else(bad);
        let number =
            |index: usize| -> Result<usize, String> { one(index)?.parse().map_err(|_| bad()) };
        let exactly = |count: usize| (rest.len() == count).then_some(()).ok_or_else(bad);
        Ok(match kind {
            "class" => {
                exactly(1)?;
                Self::Class(match one(0)?.as_str() {
                    "E1" => Environment::E1,
                    "E2" => Environment::E2,
                    "E3" => Environment::E3,
                    "E4" => Environment::E4,
                    _ => return Err(bad()),
                })
            }
            "no_host_record" => {
                exactly(1)?;
                Self::NoHostRecord { host: one(0)? }
            }
            "record_host" => {
                exactly(2)?;
                Self::RecordHost {
                    recorded: one(0)?,
                    running: one(1)?,
                }
            }
            "record_kernel" => {
                exactly(2)?;
                Self::RecordKernel {
                    recorded: one(0)?,
                    running: one(1)?,
                }
            }
            "isolated_cores" => {
                exactly(2)?;
                Self::IsolatedCores {
                    needed: number(0)?,
                    isolated: number(1)?,
                }
            }
            "nohz_full" => {
                exactly(2)?;
                Self::NohzFull {
                    needed: number(0)?,
                    cores: number(1)?,
                }
            }
            "governor" => Self::Governor { cpus: rest },
            "clock_source" => {
                exactly(1)?;
                Self::ClockSource(one(0)?)
            }
            "cpuidle" => Self::CpuIdle { states: rest },
            _ => return Err(bad()),
        })
    }
}

impl fmt::Display for Ineligible {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Class(environment) => {
                write!(f, "class {environment} does not decide")
            }
            Self::NoHostRecord { host } => {
                write!(f, "no environment record for host {host}")
            }
            Self::RecordHost { recorded, running } => {
                write!(
                    f,
                    "record host {recorded} differs from running host {running}"
                )
            }
            Self::RecordKernel { recorded, running } => write!(
                f,
                "record kernel {recorded} differs from running kernel {running}"
            ),
            Self::IsolatedCores { needed, isolated } => {
                write!(f, "isolated cores: {isolated} of {needed} needed")
            }
            Self::NohzFull { needed, cores } => {
                write!(f, "isolated cores in nohz_full: {cores} of {needed} needed")
            }
            Self::Governor { cpus } => write!(
                f,
                "governor not performance and frequency not fixed: {}",
                cpus.join(", ")
            ),
            Self::ClockSource(source) => write!(f, "clock source {source}, not tsc"),
            Self::CpuIdle { states } => write!(
                f,
                "cpuidle states enabled beyond the record: {}",
                states.join(", ")
            ),
        }
    }
}

/// Decision eligibility of a host for a run of `fanout`
/// (measurement-harness.md 4.2, conditions 1 to 3; condition 4, the
/// preflight snapshot against the record, is deferred to batch B4 with
/// the run plan): class E1 or E2; a
/// record of this host (`record`, the text of its
/// `environments/<host>.md`) taken on the running kernel; an isolated core
/// per process, each in `nohz_full`; the `performance` governor or a fixed
/// frequency on those cores; no cpuidle state enabled on those cores that
/// the record does not enable; and the `tsc` clock source. Every failed
/// condition is listed. The manifest hash, `E_max` and the sample count
/// (conditions 5 to 7) belong to the run and are checked by
/// [`crate::decision::grade`].
///
/// # Errors
///
/// Every failed condition.
pub fn decision_eligible(
    inventory: &Inventory,
    record: Option<&str>,
    fanout: Fanout,
) -> Result<(), Vec<Ineligible>> {
    let mut reasons = Vec::new();
    let environment = classify(inventory).environment;
    if !environment.decides() {
        reasons.push(Ineligible::Class(environment));
    }
    let running = inventory.node_and_release();
    match record {
        None => reasons.push(Ineligible::NoHostRecord {
            host: inventory.host.clone(),
        }),
        Some(text) => {
            let recorded = record_node_and_release(text);
            let unreadable = || "unavailable".to_string();
            let (running_node, running_release) = running
                .clone()
                .unwrap_or_else(|| (unreadable(), unreadable()));
            match recorded {
                None => reasons.push(Ineligible::RecordHost {
                    recorded: "unreadable".to_string(),
                    running: running_node,
                }),
                Some((node, release)) => {
                    if running.is_none() || node != running_node {
                        reasons.push(Ineligible::RecordHost {
                            recorded: node,
                            running: running_node,
                        });
                    }
                    if running.is_none() || release != running_release {
                        reasons.push(Ineligible::RecordKernel {
                            recorded: release,
                            running: running_release,
                        });
                    }
                }
            }
        }
    }
    let needed = processes(fanout);
    let isolated = inventory.isolated_cores();
    if isolated.len() < needed {
        reasons.push(Ineligible::IsolatedCores {
            needed,
            isolated: isolated.len(),
        });
    }
    let nohz = inventory.nohz_full_cores();
    let quiet = isolated.iter().filter(|cpu| nohz.contains(cpu)).count();
    if quiet < needed {
        reasons.push(Ineligible::NohzFull {
            needed,
            cores: quiet,
        });
    }
    match &inventory.cpus {
        Err(reason) => reasons.push(Ineligible::Governor {
            cpus: vec![format!("unavailable ({reason})")],
        }),
        Ok(cpus) => {
            let slow: Vec<String> = cpus
                .iter()
                .filter(|cpu| isolated.is_empty() || isolated.contains(&cpu.index))
                .filter(|cpu| !cpu.fixed_frequency())
                .map(|cpu| {
                    let governor = match &cpu.governor {
                        Ok(value) => value.clone(),
                        Err(_) => "unavailable".to_string(),
                    };
                    format!("cpu{} {governor}", cpu.index)
                })
                .collect();
            if !slow.is_empty() || cpus.is_empty() {
                reasons.push(Ineligible::Governor {
                    cpus: if slow.is_empty() {
                        vec!["no CPU listed".to_string()]
                    } else {
                        slow
                    },
                });
            }
        }
    }
    if let Some(text) = record {
        let mut deeper = Vec::new();
        let allowed = record_enabled_idle(text).unwrap_or_else(|| {
            deeper.push("record has no readable cpuidle block".to_string());
            Vec::new()
        });
        if let Ok(cpus) = &inventory.cpus {
            for cpu in cpus
                .iter()
                .filter(|cpu| isolated.is_empty() || isolated.contains(&cpu.index))
            {
                match &cpu.idle {
                    Err(reason) => deeper.push(format!("cpu{} unavailable ({reason})", cpu.index)),
                    Ok(states) => {
                        for state in states {
                            if state.disable.as_deref().map(str::trim) == Ok("0")
                                && !allowed.contains(&(cpu.index, state.state.clone()))
                            {
                                let name = state.name.as_deref().map_or("unnamed", str::trim);
                                deeper.push(format!("cpu{} {} ({name})", cpu.index, state.state));
                            }
                        }
                    }
                }
            }
        }
        if !deeper.is_empty() {
            reasons.push(Ineligible::CpuIdle { states: deeper });
        }
    }
    match inventory.clocksource.as_deref().map(str::trim) {
        Ok("tsc") => {}
        Ok(other) => reasons.push(Ineligible::ClockSource(other.to_string())),
        Err(reason) => reasons.push(Ineligible::ClockSource(format!("unavailable ({reason})"))),
    }
    if reasons.is_empty() {
        Ok(())
    } else {
        Err(reasons)
    }
}

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
    /// The environment class of manifest 6.3.
    pub environment: Environment,
    /// The class with its verdict: `E4 non-decision`, `E3 not
    /// demonstrated`, or `E1 eligible` or `E1 ineligible` for an F1 run
    /// (measurement-harness.md 4.2). No result labelled otherwise than
    /// eligible establishes a SPEC.md §12 target.
    pub qualification: String,
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

/// Runs a command and returns its trimmed standard output when that is
/// not empty, whatever the exit status (`systemd-detect-virt` prints
/// `none` and exits 1).
///
/// # Errors
///
/// `<program> not found`, or the exit status with the first line of
/// standard error.
pub fn run(program: &str, args: &[&str]) -> Reading {
    run_bounded(program, args, RUN_TIMEOUT, RUN_OUTPUT_LIMIT)
}

/// How long [`run`] waits for a command before killing it.
pub const RUN_TIMEOUT: Duration = Duration::from_secs(10);

/// The most bytes [`run`] keeps from each output stream.
pub const RUN_OUTPUT_LIMIT: u64 = 1 << 20;

/// [`run`] with an explicit time limit and output bound: a command still
/// running after `timeout` is killed and reported as timed out; at most
/// `limit` bytes of each stream are kept, and more is reported as
/// truncated, so a wedged or flooding tool never stalls the inventory.
///
/// # Errors
///
/// As [`run`], plus a timeout.
pub fn run_bounded(program: &str, args: &[&str], timeout: Duration, limit: u64) -> Reading {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|cause| {
            if cause.kind() == std::io::ErrorKind::NotFound {
                format!("{program} not found")
            } else {
                format!("{program}: {cause}")
            }
        })?;
    let drain = |stream: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut kept = Vec::new();
            let mut more = false;
            if let Some(mut stream) = stream {
                let _ = (&mut stream).take(limit).read_to_end(&mut kept);
                let mut rest = [0_u8; 1];
                more = matches!(stream.read(&mut rest), Ok(n) if n > 0);
                // Discard the rest so the child never blocks on a full pipe.
                let _ = std::io::copy(&mut stream, &mut std::io::sink());
            }
            (kept, more)
        })
    };
    let stdout = drain(
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let stderr = drain(
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if started.elapsed() >= timeout => {
                // The child of this call, by its own handle, never by name.
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(cause) => return Err(format!("{program}: {cause}")),
        }
    };
    let (out, out_more) = stdout.join().unwrap_or_default();
    let (err, _) = stderr.join().unwrap_or_default();
    let Some(status) = status else {
        return Err(format!(
            "{program}: timed out after {} s",
            timeout.as_secs()
        ));
    };
    let stdout = String::from_utf8_lossy(&out).trim().to_string();
    if !stdout.is_empty() {
        return Ok(if out_more {
            format!("{stdout}\n(output truncated at {limit} bytes)")
        } else {
            stdout
        });
    }
    let stderr = String::from_utf8_lossy(&err);
    let first = stderr.lines().next().unwrap_or("").trim();
    Err(if first.is_empty() {
        format!("{program}: {status} with no output")
    } else {
        format!("{program}: {status}: {first}")
    })
}

/// The output of a command that succeeded with output.
#[must_use]
pub fn command(program: &str, args: &[&str]) -> Option<String> {
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

/// The label of a class and an F1 eligibility verdict.
#[must_use]
pub fn qualification(environment: Environment, eligible: bool) -> String {
    match (environment, eligible) {
        (Environment::E3, _) => "E3 not demonstrated".to_string(),
        (Environment::E4, _) => "E4 non-decision".to_string(),
        (decides, true) => format!("{decides} eligible"),
        (decides, false) => format!("{decides} ineligible"),
    }
}

/// The text of this host's record in the directory named by
/// `KARYOS_ENVIRONMENTS` (a checkout of `quantstratum-docs:
/// karyos/environments`), if any.
#[must_use]
pub fn host_record(host: &str) -> Option<String> {
    let dir = std::env::var_os("KARYOS_ENVIRONMENTS")?;
    std::fs::read_to_string(std::path::Path::new(&dir).join(format!("{host}.md"))).ok()
}

impl Labels {
    /// The labels of this process's environment. The commit comes from
    /// `KARYOS_COMMIT`, else `git rev-parse --short HEAD`. The class and
    /// F1 eligibility come from a short inventory, with the host record
    /// read from `KARYOS_ENVIRONMENTS` when set.
    #[must_use]
    pub fn detect() -> Self {
        let unknown = || "unknown".to_string();
        let inventory = Inventory::detect(Scope::Classification);
        let environment = classify(&inventory).environment;
        let record = host_record(&inventory.host);
        let eligible = decision_eligible(&inventory, record.as_deref(), Fanout::F1).is_ok();
        Self {
            host: clean(&inventory.host),
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
            environment,
            qualification: qualification(environment, eligible),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::tests::{Canned, LSCPU_VM, Tree, UNAME, capture, tuned};
    use crate::inventory::{Eligibility, render};

    #[test]
    fn labels_are_clean_and_classified() {
        let labels = Labels::detect();
        assert!(labels.cores >= 1);
        assert_eq!(clean(" a\"b,c{d}: e "), "abcd e");
        for value in [
            &labels.host,
            &labels.cpu,
            &labels.commit,
            &labels.qualification,
        ] {
            assert_eq!(&clean(value), value);
        }
        assert!(
            labels
                .qualification
                .starts_with(&labels.environment.to_string())
        );
        if cfg!(target_os = "macos") {
            assert_eq!(labels.environment, Environment::E4);
            assert_eq!(labels.qualification, "E4 non-decision");
        }
    }

    #[test]
    fn a_missing_program_is_not_found() {
        assert_eq!(
            run("karyos-no-such-program", &[]),
            Err("karyos-no-such-program not found".to_string())
        );
    }

    fn record_of(inventory: &Inventory) -> String {
        let classification = classify(inventory);
        render(inventory, &classification, &[] as &[Eligibility])
    }

    #[test]
    fn eligibility_reasons_survive_their_one_line_form() {
        let reasons = [
            Ineligible::Class(Environment::E4),
            Ineligible::NoHostRecord { host: "h".into() },
            Ineligible::RecordHost {
                recorded: "a".into(),
                running: "b".into(),
            },
            Ineligible::RecordKernel {
                recorded: "6.8".into(),
                running: "6.9".into(),
            },
            Ineligible::IsolatedCores {
                needed: 2,
                isolated: 0,
            },
            Ineligible::NohzFull {
                needed: 5,
                cores: 1,
            },
            Ineligible::Governor {
                cpus: vec!["cpu2 powersave".into(), "cpu3 ondemand".into()],
            },
            Ineligible::ClockSource("hpet".into()),
            Ineligible::CpuIdle { states: Vec::new() },
        ];
        for reason in reasons {
            assert_eq!(Ineligible::decode(&reason.encode()), Ok(reason.clone()));
        }
        for bad in [
            "",
            "class",
            "class\tE9",
            "isolated_cores\t2",
            "nohz_full\tx\t1",
            "other\t1",
        ] {
            assert!(Ineligible::decode(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_tuned_physical_x86_64_host_is_e1_and_eligible() {
        let (tree, canned) = tuned();
        let inventory = capture(&tree, &canned, "linux", "x86_64");
        assert_eq!(classify(&inventory).environment, Environment::E1);
        let record = record_of(&inventory);
        assert_eq!(
            decision_eligible(&inventory, Some(&record), Fanout::F1),
            Ok(())
        );
        assert_eq!(
            decision_eligible(&inventory, Some(&record), Fanout::F2 { receivers: 4 }),
            Ok(())
        );
        // Six isolated cores cannot hold 17 processes.
        assert_eq!(
            decision_eligible(&inventory, Some(&record), Fanout::F2 { receivers: 16 }),
            Err(vec![
                Ineligible::IsolatedCores {
                    needed: 17,
                    isolated: 6
                },
                Ineligible::NohzFull {
                    needed: 17,
                    cores: 6
                },
            ])
        );
    }

    #[test]
    fn docker_is_e4_and_never_decides() {
        let (tree, canned) = tuned();
        tree.file("/.dockerenv", "")
            .file("/proc/1/cgroup", "0::/docker/0123abcd\n");
        let canned = canned
            .without("systemd-detect-virt")
            .without("systemd-detect-virt --container");
        let inventory = capture(&tree, &canned, "linux", "x86_64");
        let classification = classify(&inventory);
        assert_eq!(classification.environment, Environment::E4);
        assert!(
            classification
                .basis
                .iter()
                .any(|b| b == "container marker /.dockerenv")
        );
        assert!(
            classification
                .basis
                .iter()
                .any(|b| b == "container marker /proc/1/cgroup mentions docker")
        );
        let record = record_of(&inventory);
        let reasons = decision_eligible(&inventory, Some(&record), Fanout::F1).unwrap_err();
        assert_eq!(reasons, [Ineligible::Class(Environment::E4)]);
        assert!(!classification.environment.decides());
        assert_eq!(qualification(Environment::E4, false), "E4 non-decision");

        // A container reported by systemd-detect-virt alone.
        let (tree, canned) = tuned();
        let canned = canned
            .with("systemd-detect-virt", "docker")
            .with("systemd-detect-virt --container", "docker");
        let inventory = capture(&tree, &canned, "linux", "x86_64");
        assert_eq!(classify(&inventory).environment, Environment::E4);
    }

    #[test]
    fn a_vm_is_e4() {
        let (tree, canned) = tuned();
        let inventory = capture(
            &tree,
            &canned.with("systemd-detect-virt", "kvm"),
            "linux",
            "x86_64",
        );
        let classification = classify(&inventory);
        assert_eq!(classification.environment, Environment::E4);
        assert_eq!(classification.basis, ["systemd-detect-virt reports kvm"]);
        // A hypervisor named by lscpu alone also makes the host a VM.
        let (tree, canned) = tuned();
        let inventory = capture(&tree, &canned.with("lscpu", LSCPU_VM), "linux", "x86_64");
        assert_eq!(classify(&inventory).environment, Environment::E4);
    }

    #[test]
    fn macos_is_e4_on_any_architecture() {
        let tree = Tree::new();
        for arch in ["aarch64", "x86_64"] {
            let inventory = capture(&tree, &Canned::default(), "macos", arch);
            let classification = classify(&inventory);
            assert_eq!(classification.environment, Environment::E4);
            let reasons = decision_eligible(&inventory, None, Fanout::F1).unwrap_err();
            assert_eq!(reasons.first(), Some(&Ineligible::Class(Environment::E4)));
        }
    }

    #[test]
    fn physical_aarch64_is_e3() {
        let (tree, canned) = tuned();
        let inventory = capture(&tree, &canned, "linux", "aarch64");
        assert_eq!(classify(&inventory).environment, Environment::E3);
        let record = record_of(&inventory);
        assert_eq!(
            decision_eligible(&inventory, Some(&record), Fanout::F1),
            Err(vec![Ineligible::Class(Environment::E3)])
        );
        assert_eq!(qualification(Environment::E3, true), "E3 not demonstrated");
    }

    #[test]
    fn an_untuned_host_lists_every_reason() {
        let (tree, canned) = tuned();
        tree.file("/sys/devices/system/cpu/isolated", "\n")
            .file("/sys/devices/system/cpu/nohz_full", "(null)\n")
            .file(
                "/sys/devices/system/clocksource/clocksource0/current_clocksource",
                "hpet\n",
            );
        for cpu in [0, 5] {
            tree.file(
                &format!("/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor"),
                "powersave\n",
            );
        }
        let inventory = capture(&tree, &canned, "linux", "x86_64");
        assert_eq!(classify(&inventory).environment, Environment::E1);
        assert_eq!(
            decision_eligible(&inventory, None, Fanout::F1),
            Err(vec![
                Ineligible::NoHostRecord {
                    host: "flumix.secureless.net".into()
                },
                Ineligible::IsolatedCores {
                    needed: 2,
                    isolated: 0
                },
                Ineligible::NohzFull {
                    needed: 2,
                    cores: 0
                },
                Ineligible::Governor {
                    cpus: vec!["cpu0 powersave".into(), "cpu5 powersave".into()]
                },
                Ineligible::ClockSource("hpet".into()),
            ])
        );
        let text: Vec<String> = decision_eligible(&inventory, None, Fanout::F1)
            .unwrap_err()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            text,
            [
                "no environment record for host flumix.secureless.net",
                "isolated cores: 0 of 2 needed",
                "isolated cores in nohz_full: 0 of 2 needed",
                "governor not performance and frequency not fixed: cpu0 powersave, cpu5 powersave",
                "clock source hpet, not tsc",
            ]
        );
    }

    #[test]
    fn fewer_isolated_cores_than_processes_and_a_fixed_frequency() {
        let (tree, canned) = tuned();
        tree.file("/sys/devices/system/cpu/isolated", "6-7\n");
        // Governor powersave on an isolated core whose frequency is fixed
        // is accepted; on one whose frequency moves it is not.
        let base = "/sys/devices/system/cpu";
        tree.file(
            &format!("{base}/cpu6/cpufreq/scaling_governor"),
            "powersave",
        )
        .file(&format!("{base}/cpu6/cpufreq/scaling_min_freq"), "3000000")
        .file(&format!("{base}/cpu6/cpufreq/scaling_max_freq"), "3000000")
        .file(
            &format!("{base}/cpu7/cpufreq/scaling_governor"),
            "schedutil",
        );
        let inventory = capture(&tree, &canned, "linux", "x86_64");
        let record = record_of(&inventory);
        assert_eq!(
            decision_eligible(&inventory, Some(&record), Fanout::F2 { receivers: 4 }),
            Err(vec![
                Ineligible::IsolatedCores {
                    needed: 5,
                    isolated: 2
                },
                Ineligible::NohzFull {
                    needed: 5,
                    cores: 2
                },
                Ineligible::Governor {
                    cpus: vec!["cpu7 schedutil".into()]
                },
            ])
        );
    }

    #[test]
    fn an_aarch64_container_or_vm_is_e4_not_e3() {
        for (virt, container) in [("kvm", "none"), ("none", "docker")] {
            let (tree, canned) = tuned();
            let canned = canned
                .with("systemd-detect-virt", virt)
                .with("systemd-detect-virt --container", container);
            let inventory = capture(&tree, &canned, "linux", "aarch64");
            assert_eq!(
                classify(&inventory).environment,
                Environment::E4,
                "{virt} {container}"
            );
        }
        let (tree, canned) = tuned();
        let inventory = capture(&tree, &canned, "linux", "aarch64");
        assert_eq!(classify(&inventory).environment, Environment::E3);
    }

    #[test]
    fn a_cloud_or_hypervisor_host_is_e4() {
        let (tree, canned) = tuned();
        tree.file("/sys/class/dmi/id/sys_vendor", "Amazon EC2\n");
        let inventory = capture(&tree, &canned, "linux", "x86_64");
        let classification = classify(&inventory);
        assert_eq!(classification.environment, Environment::E4);
        assert!(
            classification
                .basis
                .iter()
                .any(|b| b.contains("Amazon Web Services"))
        );
        let (tree, canned) = tuned();
        tree.file("/sys/hypervisor/type", "xen\n");
        let inventory = capture(&tree, &canned, "linux", "x86_64");
        assert_eq!(classify(&inventory).environment, Environment::E4);
    }

    #[test]
    fn an_unconfirmed_container_status_is_e4() {
        let (tree, canned) = tuned();
        let canned = canned.without("systemd-detect-virt --container");
        let inventory = capture(&tree, &canned, "linux", "x86_64");
        let classification = classify(&inventory);
        assert_eq!(classification.environment, Environment::E4);
        assert!(
            classification
                .basis
                .iter()
                .any(|b| b.starts_with("container status not confirmed"))
        );
    }

    #[test]
    fn a_deeper_cpuidle_state_than_the_record_is_ineligible() {
        let (tree, canned) = tuned();
        let recorded = capture(&tree, &canned, "linux", "x86_64");
        let record = record_of(&recorded);
        tree.file("/sys/devices/system/cpu/cpu3/cpuidle/state2/disable", "0");
        let inventory = capture(&tree, &canned, "linux", "x86_64");
        assert_eq!(
            decision_eligible(&inventory, Some(&record), Fanout::F1),
            Err(vec![Ineligible::CpuIdle {
                states: vec!["cpu3 state2 (C6)".into()]
            }])
        );
    }

    #[test]
    fn a_wedged_or_flooding_command_is_bounded() {
        let slow = run_bounded("sleep", &["5"], Duration::from_millis(100), 1024);
        assert_eq!(slow, Err("sleep: timed out after 0 s".to_string()));
        let flood = run_bounded("seq", &["1", "100000"], Duration::from_secs(10), 64);
        let text = flood.unwrap_or_default();
        assert!(text.ends_with("(output truncated at 64 bytes)"), "{text}");
        assert!(text.len() < 200, "{text}");
    }

    #[test]
    fn the_record_must_match_host_and_kernel() {
        let (tree, canned) = tuned();
        let inventory = capture(&tree, &canned, "linux", "x86_64");
        let record = record_of(&inventory);
        let other = record.replace("6.8.0-45-generic #45", "6.8.0-47-generic #47");
        assert_eq!(
            decision_eligible(&inventory, Some(&other), Fanout::F1),
            Err(vec![Ineligible::RecordKernel {
                recorded: "6.8.0-47-generic".into(),
                running: "6.8.0-45-generic".into()
            }])
        );
        let elsewhere = record.replace(UNAME, &UNAME.replace("flumix", "other"));
        assert_eq!(
            decision_eligible(&inventory, Some(&elsewhere), Fanout::F1),
            Err(vec![Ineligible::RecordHost {
                recorded: "other".into(),
                running: "flumix".into()
            }])
        );
        let empty = decision_eligible(&inventory, Some("# empty"), Fanout::F1);
        assert_eq!(
            empty.as_ref().map_err(|reasons| reasons.first().cloned()),
            Err(Some(Ineligible::RecordHost {
                recorded: "unreadable".into(),
                running: "flumix".into()
            }))
        );
        assert!(
            matches!(empty, Err(ref reasons) if matches!(reasons.last(), Some(Ineligible::CpuIdle { states }) if states.first().map(String::as_str) == Some("record has no readable cpuidle block"))),
            "{empty:?}"
        );
    }

    #[test]
    fn unconfirmed_virtualization_is_e4() {
        let (tree, canned) = tuned();
        let inventory = capture(
            &tree,
            &canned.without("systemd-detect-virt"),
            "linux",
            "x86_64",
        );
        let classification = classify(&inventory);
        assert_eq!(classification.environment, Environment::E4);
        assert_eq!(
            classification.basis,
            [
                "virtualization not confirmed: systemd-detect-virt unavailable (systemd-detect-virt not found)"
            ]
        );
    }

    #[test]
    fn pairs_and_processes() {
        use Environment::{E1, E3, E4};
        assert_eq!(
            classify_pair(E1, E1, Some("switch X, one hop")),
            Environment::E2
        );
        assert_eq!(classify_pair(E1, E1, None), E1);
        assert_eq!(classify_pair(E1, E3, Some("t")), E3);
        assert_eq!(classify_pair(E3, E4, Some("t")), E4);
        assert_eq!(FANOUTS.map(processes), [2, 5, 17]);
        assert_eq!(fanout_label(FANOUTS[1]), "F2 x4 (5 processes)");
    }
}
