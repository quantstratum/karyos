// SPDX-License-Identifier: Apache-2.0

//! Host inventory (`quantstratum-docs: karyos/design/measurement-harness.md`
//! 4.3): the fields of the environments README, captured by running
//! commands and reading procfs and sysfs, and rendered as
//! `environments/<host>.md`.
//!
//! Every reading is either the verbatim output or the reason it is
//! unavailable; the record writes the latter as `unavailable (<reason>)`
//! and never leaves a field out. Files are read below a root directory
//! and commands go through a [`Runner`], so tests use fixture trees and
//! canned outputs.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::env::{self, Classification, Ineligible};
use crate::manifest::Fanout;

/// A value read from the host, or why it could not be read.
pub type Reading = Result<String, String>;

/// Runs a command and returns its standard output.
pub trait Runner {
    /// Runs `program` with `args`.
    ///
    /// # Errors
    ///
    /// The reason the output is unavailable.
    fn run(&self, program: &str, args: &[&str]) -> Reading;
}

/// Runs commands on this host through [`env::run`].
#[derive(Debug, Clone, Copy, Default)]
pub struct System;

impl Runner for System {
    fn run(&self, program: &str, args: &[&str]) -> Reading {
        env::run(program, args)
    }
}

/// Where readings come from: files below `root`, commands through a
/// runner.
pub struct Probe<'a> {
    root: PathBuf,
    runner: &'a dyn Runner,
}

impl<'a> Probe<'a> {
    /// A probe of the files below `root` (`/` for this host).
    #[must_use]
    pub fn new(root: impl Into<PathBuf>, runner: &'a dyn Runner) -> Self {
        Self {
            root: root.into(),
            runner,
        }
    }

    fn path(&self, path: &str) -> PathBuf {
        self.root.join(path.trim_start_matches('/'))
    }

    /// The contents of `path`, trimmed of the final newline.
    ///
    /// # Errors
    ///
    /// The path and the I/O error.
    pub fn read(&self, path: &str) -> Reading {
        std::fs::read_to_string(self.path(path))
            .map(|text| text.trim_end_matches('\n').to_string())
            .map_err(|cause| format!("{path}: {cause}"))
    }

    /// The sorted entry names of the directory `path`.
    ///
    /// # Errors
    ///
    /// The path and the I/O error.
    pub fn list(&self, path: &str) -> Result<Vec<String>, String> {
        let entries =
            std::fs::read_dir(self.path(path)).map_err(|cause| format!("{path}: {cause}"))?;
        let mut names: Vec<String> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort_by_key(|name| natural(name));
        Ok(names)
    }

    /// Whether `path` exists.
    #[must_use]
    pub fn exists(&self, path: &str) -> bool {
        self.path(path).exists()
    }

    /// Runs a command.
    ///
    /// # Errors
    ///
    /// The reason the output is unavailable.
    pub fn run(&self, program: &str, args: &[&str]) -> Reading {
        self.runner.run(program, args)
    }
}

/// Orders `cpu10` after `cpu9`: the name split into its text and numeric
/// suffix.
fn natural(name: &str) -> (String, u64, String) {
    let digits = name
        .find(|c: char| c.is_ascii_digit())
        .unwrap_or(name.len());
    let (head, tail) = name.split_at(digits);
    let end = tail
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(tail.len());
    let (number, rest) = tail.split_at(end);
    (
        head.to_string(),
        number.parse().unwrap_or(0),
        rest.to_string(),
    )
}

/// The readings of one network interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    /// The interface name.
    pub name: String,
    /// `ethtool -i <if>`.
    pub driver: Reading,
    /// `ethtool -T <if>`.
    pub timestamping: Reading,
    /// `ethtool -k <if>`.
    pub features: Reading,
}

/// One cpuidle state of one CPU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdleState {
    /// The state directory, such as `state2`.
    pub state: String,
    /// `name`.
    pub name: Reading,
    /// `disable`.
    pub disable: Reading,
    /// `latency`, in microseconds.
    pub latency: Reading,
}

/// The readings of one CPU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cpu {
    /// The CPU number.
    pub index: usize,
    /// `cpufreq/scaling_governor`.
    pub governor: Reading,
    /// `cpufreq/scaling_min_freq`, in kHz.
    pub min_freq: Reading,
    /// `cpufreq/scaling_max_freq`, in kHz.
    pub max_freq: Reading,
    /// The cpuidle states.
    pub idle: Result<Vec<IdleState>, String>,
}

impl Cpu {
    /// Whether the governor is `performance` or the frequency is fixed.
    #[must_use]
    pub fn fixed_frequency(&self) -> bool {
        self.governor.as_deref() == Ok("performance")
            || matches!((&self.min_freq, &self.max_freq), (Ok(min), Ok(max)) if min == max)
    }
}

/// The interrupts of one interface and their affinity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrqAffinity {
    /// The interface.
    pub interface: String,
    /// Per interrupt: number, description and `smp_affinity_list`.
    pub irqs: Vec<(u32, String, Reading)>,
}

/// How much to capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Every field of the record.
    Full,
    /// What classification and eligibility need: no `ethtool` or IRQ
    /// scan (cpuidle is read, for the eligibility of 4.2). Used for the labels of every report.
    Classification,
}

/// The inventory of one host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    /// The host's fully qualified name, cleaned for a file name.
    pub host: String,
    /// Operating system (`std::env::consts::OS` for this host).
    pub os: String,
    /// Architecture (`std::env::consts::ARCH` for this host).
    pub arch: String,
    /// The capture date, UTC, `YYYY-MM-DD`.
    pub date: String,
    /// The commit of the capturing tool.
    pub commit: String,
    /// `id -u`.
    pub user: Reading,
    /// `uname -a`.
    pub uname: Reading,
    /// `lscpu`.
    pub lscpu: Reading,
    /// `systemd-detect-virt`.
    pub virt: Reading,
    /// `systemd-detect-virt --container`.
    pub virt_container: Reading,
    /// Container markers found on the file system or in PID 1's cgroup.
    pub container_markers: Vec<String>,
    /// `/sys/class/dmi/id/sys_vendor`.
    pub dmi_sys_vendor: Reading,
    /// `/sys/class/dmi/id/board_vendor`.
    pub dmi_board_vendor: Reading,
    /// `/sys/class/dmi/id/product_name`.
    pub dmi_product: Reading,
    /// `/sys/hypervisor/type`, present under a hypervisor such as Xen.
    pub hypervisor_type: Reading,
    /// `/proc/cmdline`.
    pub cmdline: Reading,
    /// The interfaces of `/sys/class/net` except `lo`.
    pub interfaces: Result<Vec<Interface>, String>,
    /// The CPUs of `/sys/devices/system/cpu`.
    pub cpus: Result<Vec<Cpu>, String>,
    /// The boost setting.
    pub boost: Reading,
    /// `/sys/devices/system/cpu/isolated`.
    pub isolated: Reading,
    /// `/sys/devices/system/cpu/nohz_full`.
    pub nohz_full: Reading,
    /// `/dev/ptp*`.
    pub ptp_devices: Result<Vec<String>, String>,
    /// `/sys/class/ptp/*/clock_name`.
    pub ptp_clocks: Result<Vec<(String, Reading)>, String>,
    /// The interface interrupts and their affinity.
    pub irq_affinity: Result<Vec<IrqAffinity>, String>,
    /// Whether `irqbalance` runs.
    pub irqbalance: Reading,
    /// `transparent_hugepage/enabled`.
    pub thp_enabled: Reading,
    /// `transparent_hugepage/defrag`.
    pub thp_defrag: Reading,
    /// `current_clocksource`.
    pub clocksource: Reading,
    /// `available_clocksource`.
    pub clocksource_available: Reading,
}

const CPU: &str = "/sys/devices/system/cpu";
const CLOCKSOURCE: &str = "/sys/devices/system/clocksource/clocksource0";
const THP: &str = "/sys/kernel/mm/transparent_hugepage";
const SKIPPED: &str = "not captured for labels";

impl Inventory {
    /// Captures the inventory through `probe`. `os` and `arch` are the
    /// target's (`std::env::consts`), passed in so tests can vary them.
    #[must_use]
    pub fn capture(probe: &Probe<'_>, os: &str, arch: &str, scope: Scope) -> Self {
        let full = scope == Scope::Full;
        let mut inventory = Self {
            host: host_name(probe),
            os: os.to_string(),
            arch: if os == "linux" {
                probe
                    .run("uname", &["-m"])
                    .map(|machine| machine.trim().to_string())
                    .ok()
                    .filter(|machine| !machine.is_empty())
                    .unwrap_or_else(|| arch.to_string())
            } else {
                arch.to_string()
            },
            date: today(),
            commit: env::clean(
                &std::env::var("KARYOS_COMMIT")
                    .ok()
                    .or_else(|| env::command("git", &["rev-parse", "--short", "HEAD"]))
                    .unwrap_or_else(|| "unknown".to_string()),
            ),
            user: probe.run("id", &["-u"]),
            uname: probe.run("uname", &["-a"]),
            lscpu: probe.run("lscpu", &[]),
            virt: probe.run("systemd-detect-virt", &[]),
            virt_container: probe.run("systemd-detect-virt", &["--container"]),
            container_markers: container_markers(probe),
            dmi_sys_vendor: probe.read("/sys/class/dmi/id/sys_vendor"),
            dmi_board_vendor: probe.read("/sys/class/dmi/id/board_vendor"),
            dmi_product: probe.read("/sys/class/dmi/id/product_name"),
            hypervisor_type: probe.read("/sys/hypervisor/type"),
            cmdline: probe.read("/proc/cmdline"),
            interfaces: Err(SKIPPED.to_string()),
            cpus: cpus(probe),
            boost: boost(probe),
            isolated: probe.read(&format!("{CPU}/isolated")),
            nohz_full: probe.read(&format!("{CPU}/nohz_full")),
            ptp_devices: Err(SKIPPED.to_string()),
            ptp_clocks: Err(SKIPPED.to_string()),
            irq_affinity: Err(SKIPPED.to_string()),
            irqbalance: Err(SKIPPED.to_string()),
            thp_enabled: probe.read(&format!("{THP}/enabled")),
            thp_defrag: probe.read(&format!("{THP}/defrag")),
            clocksource: probe.read(&format!("{CLOCKSOURCE}/current_clocksource")),
            clocksource_available: probe.read(&format!("{CLOCKSOURCE}/available_clocksource")),
        };
        if full {
            inventory.interfaces = interfaces(probe);
            inventory.ptp_devices = probe.list("/dev").map(|names| {
                names
                    .into_iter()
                    .filter(|name| name.starts_with("ptp"))
                    .map(|name| format!("/dev/{name}"))
                    .collect()
            });
            inventory.ptp_clocks = probe.list("/sys/class/ptp").map(|names| {
                names
                    .into_iter()
                    .map(|name| {
                        let clock = probe.read(&format!("/sys/class/ptp/{name}/clock_name"));
                        (name, clock)
                    })
                    .collect()
            });
            let names: Vec<String> = inventory
                .interfaces
                .as_ref()
                .map(|list| list.iter().map(|i| i.name.clone()).collect())
                .unwrap_or_default();
            inventory.irq_affinity = irq_affinity(probe, &names);
            inventory.irqbalance = irqbalance(probe);
        }
        inventory
    }

    /// Captures this host's inventory.
    #[must_use]
    pub fn detect(scope: Scope) -> Self {
        Self::capture(
            &Probe::new("/", &System),
            std::env::consts::OS,
            std::env::consts::ARCH,
            scope,
        )
    }

    /// The node name and kernel release of `uname -a`.
    #[must_use]
    pub fn node_and_release(&self) -> Option<(String, String)> {
        self.uname.as_deref().ok().and_then(parse_uname)
    }

    /// The isolated cores, empty where unavailable.
    #[must_use]
    pub fn isolated_cores(&self) -> Vec<usize> {
        self.isolated
            .as_deref()
            .map(parse_cpu_list)
            .unwrap_or_default()
    }

    /// The `nohz_full` cores, empty where unavailable.
    #[must_use]
    pub fn nohz_full_cores(&self) -> Vec<usize> {
        self.nohz_full
            .as_deref()
            .map(parse_cpu_list)
            .unwrap_or_default()
    }
}

/// The host's fully qualified name: `hostname -f`, else `hostname`, else
/// `/proc/sys/kernel/hostname`; only characters safe in a file name.
fn host_name(probe: &Probe<'_>) -> String {
    let name = probe
        .run("hostname", &["-f"])
        .or_else(|_| probe.run("hostname", &[]))
        .or_else(|_| probe.read("/proc/sys/kernel/hostname"))
        .unwrap_or_else(|_| "unknown".to_string());
    let safe: String = name
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || ".-_".contains(*c))
        .collect();
    if safe.is_empty() || safe.chars().all(|c| c == '.') {
        "unknown".to_string()
    } else {
        safe
    }
}

fn container_markers(probe: &Probe<'_>) -> Vec<String> {
    let mut markers = Vec::new();
    for path in ["/.dockerenv", "/run/.containerenv"] {
        if probe.exists(path) {
            markers.push(path.to_string());
        }
    }
    if let Ok(cgroup) = probe.read("/proc/1/cgroup") {
        for word in ["docker", "kubepods", "containerd", "lxc", "libpod"] {
            if cgroup.contains(word) {
                markers.push(format!("/proc/1/cgroup mentions {word}"));
            }
        }
    }
    markers
}

fn cpus(probe: &Probe<'_>) -> Result<Vec<Cpu>, String> {
    let names = probe.list(CPU)?;
    let mut cpus = Vec::new();
    for name in names {
        let Some(index) = name
            .strip_prefix("cpu")
            .and_then(|number| number.parse::<usize>().ok())
        else {
            continue;
        };
        let base = format!("{CPU}/{name}");
        let idle = probe.list(&format!("{base}/cpuidle")).map(|states| {
            states
                .into_iter()
                .filter(|state| state.starts_with("state"))
                .map(|state| {
                    let dir = format!("{base}/cpuidle/{state}");
                    IdleState {
                        name: probe.read(&format!("{dir}/name")),
                        disable: probe.read(&format!("{dir}/disable")),
                        latency: probe.read(&format!("{dir}/latency")),
                        state,
                    }
                })
                .collect()
        });
        cpus.push(Cpu {
            index,
            governor: probe.read(&format!("{base}/cpufreq/scaling_governor")),
            min_freq: probe.read(&format!("{base}/cpufreq/scaling_min_freq")),
            max_freq: probe.read(&format!("{base}/cpufreq/scaling_max_freq")),
            idle,
        });
    }
    Ok(cpus)
}

fn boost(probe: &Probe<'_>) -> Reading {
    let generic = probe.read(&format!("{CPU}/cpufreq/boost"));
    let Err(generic) = generic else {
        return generic.map(|value| format!("cpufreq/boost {value}"));
    };
    probe
        .read(&format!("{CPU}/intel_pstate/no_turbo"))
        .map(|value| format!("intel_pstate/no_turbo {value}"))
        .map_err(|pstate| format!("{generic}; {pstate}"))
}

fn interfaces(probe: &Probe<'_>) -> Result<Vec<Interface>, String> {
    Ok(probe
        .list("/sys/class/net")?
        .into_iter()
        .filter(|name| name != "lo")
        .map(|name| Interface {
            driver: probe.run("ethtool", &["-i", &name]),
            timestamping: probe.run("ethtool", &["-T", &name]),
            features: probe.run("ethtool", &["-k", &name]),
            name,
        })
        .collect())
}

fn irq_affinity(probe: &Probe<'_>, interfaces: &[String]) -> Result<Vec<IrqAffinity>, String> {
    let table = probe.read("/proc/interrupts")?;
    let lines = parse_interrupts(&table);
    Ok(interfaces
        .iter()
        .map(|interface| IrqAffinity {
            interface: interface.clone(),
            irqs: lines
                .iter()
                .filter(|(_, description)| {
                    description.split_whitespace().any(|word| {
                        word == interface
                            || word
                                .strip_prefix(interface.as_str())
                                .is_some_and(|rest| rest.starts_with(['-', ':', '@']))
                    })
                })
                .map(|(irq, description)| {
                    (
                        *irq,
                        description.clone(),
                        probe.read(&format!("/proc/irq/{irq}/smp_affinity_list")),
                    )
                })
                .collect(),
        })
        .collect())
}

fn irqbalance(probe: &Probe<'_>) -> Reading {
    let pids = probe.list("/proc")?;
    let running = pids
        .iter()
        .filter(|pid| pid.chars().all(|c| c.is_ascii_digit()))
        .any(|pid| probe.read(&format!("/proc/{pid}/comm")).as_deref() == Ok("irqbalance"));
    Ok(if running {
        "irqbalance running".to_string()
    } else {
        "irqbalance not running (in this PID namespace)".to_string()
    })
}

/// Today's date, UTC, `YYYY-MM-DD`.
fn today() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let (year, month, day) = civil(i64::try_from(seconds / 86_400).unwrap_or(0));
    format!("{year:04}-{month:02}-{day:02}")
}

/// The proleptic Gregorian date of a day count since 1970-01-01.
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (
        year,
        u32::try_from(month).unwrap_or(0),
        u32::try_from(day).unwrap_or(0),
    )
}

// Parsers.

/// `key: value` lines (`lscpu`, `ethtool -i`), keys trimmed, in order.
#[must_use]
pub fn parse_key_values(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim().to_string(), value.trim().to_string()))
        .filter(|(key, _)| !key.is_empty())
        .collect()
}

fn value<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.as_str())
}

/// The summary of `lscpu`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Lscpu {
    /// `Model name`.
    pub model: Option<String>,
    /// `Architecture`.
    pub architecture: Option<String>,
    /// `CPU(s)`.
    pub cpus: Option<usize>,
    /// `Socket(s)`.
    pub sockets: Option<usize>,
    /// `Thread(s) per core`.
    pub threads_per_core: Option<usize>,
    /// `Hypervisor vendor`, present only under a hypervisor.
    pub hypervisor: Option<String>,
}

/// Parses `lscpu`.
#[must_use]
pub fn parse_lscpu(text: &str) -> Lscpu {
    let pairs = parse_key_values(text);
    let number = |key| value(&pairs, key).and_then(|v| v.parse().ok());
    Lscpu {
        model: value(&pairs, "Model name").map(str::to_string),
        architecture: value(&pairs, "Architecture").map(str::to_string),
        cpus: number("CPU(s)"),
        sockets: number("Socket(s)"),
        threads_per_core: number("Thread(s) per core"),
        hypervisor: value(&pairs, "Hypervisor vendor").map(str::to_string),
    }
}

/// The summary of `ethtool -i`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Driver {
    /// `driver`.
    pub driver: Option<String>,
    /// `version`.
    pub version: Option<String>,
    /// `firmware-version`.
    pub firmware: Option<String>,
    /// `bus-info`.
    pub bus: Option<String>,
}

/// Parses `ethtool -i`.
#[must_use]
pub fn parse_ethtool_driver(text: &str) -> Driver {
    let pairs = parse_key_values(text);
    let get = |key| {
        value(&pairs, key)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    };
    Driver {
        driver: get("driver"),
        version: get("version"),
        firmware: get("firmware-version"),
        bus: get("bus-info"),
    }
}

/// The summary of `ethtool -T`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Timestamping {
    /// The PHC index, `None` when the output says `none`.
    pub phc_index: Option<u32>,
    /// The capabilities, such as `hardware-transmit`.
    pub capabilities: Vec<String>,
}

impl Timestamping {
    /// Whether both hardware transmit and receive stamps are offered.
    #[must_use]
    pub fn hardware(&self) -> bool {
        ["hardware-transmit", "hardware-receive"]
            .iter()
            .all(|cap| self.capabilities.iter().any(|c| c == cap))
    }
}

/// Parses `ethtool -T`, in the older (`PTP Hardware Clock`) and newer
/// (`Hardware timestamp provider index`) formats.
#[must_use]
pub fn parse_ethtool_timestamping(text: &str) -> Timestamping {
    let mut result = Timestamping::default();
    let mut in_capabilities = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some((key, value)) = trimmed.split_once(':') {
            let key = key.trim();
            if key == "PTP Hardware Clock" || key == "Hardware timestamp provider index" {
                result.phc_index = value.trim().parse().ok();
            }
            in_capabilities = key == "Capabilities";
            continue;
        }
        if in_capabilities && let Some(name) = trimmed.split_whitespace().next() {
            result.capabilities.push(name.to_string());
        }
    }
    result
}

/// One netdev feature of `ethtool -k`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Feature {
    /// Whether it is on.
    pub on: bool,
    /// Whether it is `[fixed]`.
    pub fixed: bool,
}

/// Parses `ethtool -k` into feature name and state.
#[must_use]
pub fn parse_ethtool_features(text: &str) -> BTreeMap<String, Feature> {
    text.lines()
        .filter_map(|line| line.split_once(':'))
        .filter_map(|(name, state)| {
            let state = state.trim();
            let on = if state.starts_with("on") {
                true
            } else if state.starts_with("off") {
                false
            } else {
                return None;
            };
            Some((
                name.trim().to_string(),
                Feature {
                    on,
                    fixed: state.contains("[fixed]"),
                },
            ))
        })
        .collect()
}

/// The kernel command line as `(name, value)` pairs, a bare flag having
/// no value.
#[must_use]
pub fn parse_cmdline(text: &str) -> Vec<(String, Option<String>)> {
    text.split_whitespace()
        .map(|word| match word.split_once('=') {
            Some((name, value)) => (name.to_string(), Some(value.to_string())),
            None => (word.to_string(), None),
        })
        .collect()
}

/// A kernel CPU list such as `1-3,8` (also with `isolcpus` flags such as
/// `managed_irq,domain,2-5`), sorted and without repeats.
#[must_use]
pub fn parse_cpu_list(text: &str) -> Vec<usize> {
    let mut cpus = Vec::new();
    for part in text.trim().split(',') {
        let part = part.trim();
        if let Some((from, to)) = part.split_once('-') {
            if let (Ok(from), Ok(to)) = (from.parse::<usize>(), to.parse::<usize>()) {
                cpus.extend(from..=to);
            }
        } else if let Ok(cpu) = part.parse() {
            cpus.push(cpu);
        }
    }
    cpus.sort_unstable();
    cpus.dedup();
    cpus
}

/// The node name and kernel release of a `uname -a` line.
#[must_use]
pub fn parse_uname(text: &str) -> Option<(String, String)> {
    let mut words = text.split_whitespace();
    let _system = words.next()?;
    let node = words.next()?;
    let release = words.next()?;
    Some((node.to_string(), release.to_string()))
}

/// The interrupt number and description (the text after the per-CPU
/// counters) of each numbered line of `/proc/interrupts`.
#[must_use]
pub fn parse_interrupts(text: &str) -> Vec<(u32, String)> {
    let mut lines = text.lines();
    let cpus = lines
        .next()
        .map_or(0, |header| header.split_whitespace().count());
    lines
        .filter_map(|line| {
            let (irq, rest) = line.trim().split_once(':')?;
            let irq = irq.trim().parse().ok()?;
            let description: Vec<&str> = rest.split_whitespace().skip(cpus).collect();
            Some((irq, description.join(" ")))
        })
        .collect()
}

/// The node name and kernel release of a filed record: the `uname -a`
/// output in the first fenced block under `### Kernel and host`.
#[must_use]
pub fn record_node_and_release(record: &str) -> Option<(String, String)> {
    let (_, section) = record.split_once("### Kernel and host")?;
    first_block(section)?.lines().find_map(parse_uname)
}

/// The cpuidle states enabled in a record (`disable` 0), as CPU number
/// and state directory, or `None` when the record has no readable
/// cpuidle block.
#[must_use]
pub fn record_enabled_idle(record: &str) -> Option<Vec<(usize, String)>> {
    let (_, section) = record.split_once("### cpuidle states, per CPU")?;
    let section = section.split("\n### ").next()?;
    let body = first_block(section)?;
    let mut enabled = Vec::new();
    for line in body.lines() {
        let Some((head, rest)) = line.split_once(':') else {
            continue;
        };
        let mut words = head.split_whitespace();
        let (Some(cpu), Some(state)) = (words.next(), words.next()) else {
            continue;
        };
        let Some(index) = cpu
            .strip_prefix("cpu")
            .and_then(|number| number.parse::<usize>().ok())
        else {
            continue;
        };
        if rest.split(';').any(|part| part.trim() == "disable 0") {
            enabled.push((index, state.to_string()));
        }
    }
    Some(enabled)
}

// Rendering.

/// The fields of SPEC line 1303, as the environments README names them.
pub const SPEC_FIELDS: [&str; 7] = [
    "Kernel and host",
    "CPU",
    "Virtualization",
    "Boot settings",
    "NIC driver and firmware, per interface",
    "Timestamping and PHC index, per interface",
    "Netdev features, per interface",
];

/// The fields the measurement methodology adds, as the environments
/// README names them.
pub const METHOD_FIELDS: [&str; 9] = [
    "Frequency governor, per CPU",
    "Boost",
    "cpuidle states, per CPU",
    "Isolated cores",
    "`nohz_full`",
    "PHC devices",
    "IRQ affinity",
    "Transparent huge pages",
    "Clock source",
];

/// The rendered form of an unavailable reading.
#[must_use]
pub fn unavailable(reason: &str) -> String {
    format!("unavailable ({reason})")
}

/// The longest run of backticks in `text`.
fn longest_backtick_run(text: &str) -> usize {
    let mut longest = 0;
    let mut run = 0_usize;
    for c in text.chars() {
        run = if c == '`' { run.saturating_add(1) } else { 0 };
        longest = longest.max(run);
    }
    longest
}

/// A fenced block whose fence is longer than any backtick run in `text`,
/// so command output can never close it early.
fn block(out: &mut String, text: &str) {
    if text.is_empty() {
        out.push_str("(empty)\n\n");
    } else {
        let fence = "`".repeat(longest_backtick_run(text).max(2).saturating_add(1));
        let _ = write!(out, "{fence}text\n{text}\n{fence}\n\n");
    }
}

/// The body of the first fenced block in `section`, whatever the length
/// of its fence.
fn first_block(section: &str) -> Option<&str> {
    let start = section.find("```")?;
    let after = section.get(start..)?;
    let fence_len = after.chars().take_while(|c| *c == '`').count();
    let fence = after.get(..fence_len)?;
    let body_start = after.find('\n')?.saturating_add(1);
    let body = after.get(body_start..)?;
    let close = body.find(&format!("\n{fence}"))?;
    body.get(..close)
}

fn reading(out: &mut String, value: &Reading) {
    match value {
        Ok(text) => block(out, text),
        Err(reason) => {
            let _ = write!(out, "{}\n\n", unavailable(reason));
        }
    }
}

fn field(out: &mut String, name: &str, source: &str) {
    let _ = write!(out, "### {name}\n\nSource: {source}\n\n");
}

fn labelled(out: &mut String, label: &str, value: &Reading) {
    let _ = write!(out, "{label}:\n\n");
    reading(out, value);
}

fn per_interface(
    out: &mut String,
    interfaces: &Result<Vec<Interface>, String>,
    pick: impl Fn(&Interface) -> (&Reading, Option<String>),
) {
    match interfaces {
        Err(reason) => {
            let _ = write!(out, "{}\n\n", unavailable(reason));
        }
        Ok(list) if list.is_empty() => out.push_str("No interface other than `lo`.\n\n"),
        Ok(list) => {
            for interface in list {
                let (value, summary) = pick(interface);
                let _ = write!(out, "#### {}\n\n", interface.name);
                if let Some(summary) = summary {
                    let _ = write!(out, "{summary}\n\n");
                }
                reading(out, value);
            }
        }
    }
}

fn opt(value: Option<&String>) -> &str {
    value.map_or("not reported", String::as_str)
}

/// The eligibility of the host for one fan-out.
pub type Eligibility = (Fanout, Result<(), Vec<Ineligible>>);

/// Renders the record in the format of the environments README.
#[must_use]
pub fn render(
    inventory: &Inventory,
    classification: &Classification,
    eligibility: &[Eligibility],
) -> String {
    let mut out = String::new();
    let privileges = match inventory.user.as_deref() {
        Ok("0") => "with root".to_string(),
        Ok(_) => "without root".to_string(),
        Err(reason) => unavailable(reason),
    };
    let _ = write!(
        out,
        "<!-- SPDX-License-Identifier: Apache-2.0 -->\n\n# {}\n\n\
         - Date: {} (UTC)\n\
         - Captured by: `karyos-bench inventory` at commit {}\n\
         - Privileges: {privileges}\n\
         - Target: {} {}\n\
         - Environment class: {} ({})\n\n",
        inventory.host,
        inventory.date,
        inventory.commit,
        inventory.os,
        inventory.arch,
        classification.environment,
        classification.environment.usage(),
    );

    out.push_str("## SPEC line 1303 fields\n\n");
    field(&mut out, "Kernel and host", "`uname -a`");
    if let Some((node, release)) = inventory.node_and_release() {
        let _ = write!(out, "Host {node}, kernel release {release}.\n\n");
    }
    reading(&mut out, &inventory.uname);

    field(&mut out, "CPU", "`lscpu`");
    if let Ok(text) = &inventory.lscpu {
        let cpu = parse_lscpu(text);
        let _ = write!(
            out,
            "Model {}, {} CPUs, {} sockets, {} threads per core, hypervisor {}.\n\n",
            opt(cpu.model.as_ref()),
            cpu.cpus.map_or("not reported".into(), |n| n.to_string()),
            cpu.sockets.map_or("not reported".into(), |n| n.to_string()),
            cpu.threads_per_core
                .map_or("not reported".into(), |n| n.to_string()),
            cpu.hypervisor.as_deref().unwrap_or("none reported"),
        );
    }
    reading(&mut out, &inventory.lscpu);

    field(
        &mut out,
        "Virtualization",
        "`systemd-detect-virt` and `systemd-detect-virt --container`; container markers",
    );
    labelled(&mut out, "`systemd-detect-virt`", &inventory.virt);
    labelled(
        &mut out,
        "`systemd-detect-virt --container`",
        &inventory.virt_container,
    );
    labelled(
        &mut out,
        "`/sys/class/dmi/id/sys_vendor`",
        &inventory.dmi_sys_vendor,
    );
    labelled(
        &mut out,
        "`/sys/class/dmi/id/board_vendor`",
        &inventory.dmi_board_vendor,
    );
    labelled(
        &mut out,
        "`/sys/class/dmi/id/product_name`",
        &inventory.dmi_product,
    );
    match &inventory.hypervisor_type {
        Ok(_) => labelled(
            &mut out,
            "`/sys/hypervisor/type`",
            &inventory.hypervisor_type,
        ),
        // Absent on a host that runs on no hypervisor: a fact, not a gap.
        Err(reason) => {
            let _ = write!(out, "`/sys/hypervisor/type`: absent ({reason})\n\n");
        }
    }
    if inventory.container_markers.is_empty() {
        out.push_str(
            "Container markers (`/.dockerenv`, `/run/.containerenv`, `/proc/1/cgroup`): none\n\n",
        );
    } else {
        let _ = write!(
            out,
            "Container markers: {}\n\n",
            inventory.container_markers.join("; ")
        );
    }

    field(&mut out, "Boot settings", "`/proc/cmdline`");
    if let Ok(text) = &inventory.cmdline {
        let params = parse_cmdline(text);
        let shown: Vec<String> = [
            "isolcpus",
            "nohz_full",
            "rcu_nocbs",
            "intel_idle.max_cstate",
            "processor.max_cstate",
            "idle",
            "intel_pstate",
            "transparent_hugepage",
            "clocksource",
            "tsc",
        ]
        .iter()
        .map(|name| {
            let value = params
                .iter()
                .find(|(param, _)| param == name)
                .map_or("absent".to_string(), |(_, value)| {
                    value.clone().unwrap_or_else(|| "set".to_string())
                });
            format!("`{name}` {value}")
        })
        .collect();
        let _ = write!(out, "{}.\n\n", shown.join(", "));
    }
    reading(&mut out, &inventory.cmdline);

    field(
        &mut out,
        "NIC driver and firmware, per interface",
        "`ethtool -i <if>`",
    );
    per_interface(&mut out, &inventory.interfaces, |interface| {
        let summary = interface.driver.as_ref().ok().map(|text| {
            let driver = parse_ethtool_driver(text);
            format!(
                "Driver {}, version {}, firmware {}, bus {}.",
                opt(driver.driver.as_ref()),
                opt(driver.version.as_ref()),
                opt(driver.firmware.as_ref()),
                opt(driver.bus.as_ref()),
            )
        });
        (&interface.driver, summary)
    });
    field(
        &mut out,
        "Timestamping and PHC index, per interface",
        "`ethtool -T <if>`",
    );
    per_interface(&mut out, &inventory.interfaces, |interface| {
        let summary = interface.timestamping.as_ref().ok().map(|text| {
            let stamps = parse_ethtool_timestamping(text);
            format!(
                "PHC index {}, hardware transmit and receive stamps {}.",
                stamps
                    .phc_index
                    .map_or("none".to_string(), |index| index.to_string()),
                if stamps.hardware() { "yes" } else { "no" },
            )
        });
        (&interface.timestamping, summary)
    });
    field(
        &mut out,
        "Netdev features, per interface",
        "`ethtool -k <if>`",
    );
    per_interface(&mut out, &inventory.interfaces, |interface| {
        let summary = interface.features.as_ref().ok().map(|text| {
            let features = parse_ethtool_features(text);
            let on = features.values().filter(|feature| feature.on).count();
            format!("{on} of {} features on.", features.len())
        });
        (&interface.features, summary)
    });

    out.push_str("## Measurement methodology fields\n\n");
    field(
        &mut out,
        "Frequency governor, per CPU",
        "`/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor` (with `scaling_min_freq` and `scaling_max_freq`, kHz)",
    );
    match &inventory.cpus {
        Err(reason) => {
            let _ = write!(out, "{}\n\n", unavailable(reason));
        }
        Ok(cpus) => {
            let lines: Vec<String> = cpus
                .iter()
                .map(|cpu| {
                    let show = |value: &Reading| match value {
                        Ok(text) => text.clone(),
                        Err(reason) => unavailable(reason),
                    };
                    format!(
                        "cpu{}: governor {}; min {}; max {}",
                        cpu.index,
                        show(&cpu.governor),
                        show(&cpu.min_freq),
                        show(&cpu.max_freq)
                    )
                })
                .collect();
            block(&mut out, &lines.join("\n"));
        }
    }

    field(
        &mut out,
        "Boost",
        "`/sys/devices/system/cpu/cpufreq/boost`, else `/sys/devices/system/cpu/intel_pstate/no_turbo`",
    );
    reading(&mut out, &inventory.boost);

    field(
        &mut out,
        "cpuidle states, per CPU",
        "`/sys/devices/system/cpu/cpu*/cpuidle/state*/{name,disable,latency}` (latency in µs)",
    );
    match &inventory.cpus {
        Err(reason) => {
            let _ = write!(out, "{}\n\n", unavailable(reason));
        }
        Ok(cpus) => {
            let mut lines = Vec::new();
            for cpu in cpus {
                match &cpu.idle {
                    Err(reason) => lines.push(format!("cpu{}: {}", cpu.index, unavailable(reason))),
                    Ok(states) if states.is_empty() => {
                        lines.push(format!("cpu{}: no states", cpu.index));
                    }
                    Ok(states) => {
                        for state in states {
                            let show = |value: &Reading| match value {
                                Ok(text) => text.clone(),
                                Err(reason) => unavailable(reason),
                            };
                            lines.push(format!(
                                "cpu{} {}: name {}; disable {}; latency {}",
                                cpu.index,
                                state.state,
                                show(&state.name),
                                show(&state.disable),
                                show(&state.latency)
                            ));
                        }
                    }
                }
            }
            block(&mut out, &lines.join("\n"));
        }
    }

    field(
        &mut out,
        "Isolated cores",
        "`/sys/devices/system/cpu/isolated`",
    );
    reading(&mut out, &inventory.isolated);
    field(
        &mut out,
        "`nohz_full`",
        "`/sys/devices/system/cpu/nohz_full`",
    );
    reading(&mut out, &inventory.nohz_full);

    field(
        &mut out,
        "PHC devices",
        "`/dev/ptp*` and `/sys/class/ptp/*/clock_name`",
    );
    match &inventory.ptp_devices {
        Err(reason) => {
            let _ = write!(out, "`/dev/ptp*`: {}\n\n", unavailable(reason));
        }
        Ok(devices) if devices.is_empty() => out.push_str("`/dev/ptp*`: none\n\n"),
        Ok(devices) => {
            let _ = write!(out, "`/dev/ptp*`: {}\n\n", devices.join(", "));
        }
    }
    match &inventory.ptp_clocks {
        Err(reason) => {
            let _ = write!(out, "`/sys/class/ptp`: {}\n\n", unavailable(reason));
        }
        Ok(clocks) if clocks.is_empty() => out.push_str("`/sys/class/ptp`: none\n\n"),
        Ok(clocks) => {
            let lines: Vec<String> = clocks
                .iter()
                .map(|(name, clock)| match clock {
                    Ok(text) => format!("{name}: {text}"),
                    Err(reason) => format!("{name}: {}", unavailable(reason)),
                })
                .collect();
            block(&mut out, &lines.join("\n"));
        }
    }

    field(
        &mut out,
        "IRQ affinity",
        "`/proc/interrupts` and `/proc/irq/*/smp_affinity_list` for the NIC's queues; whether `irqbalance` runs",
    );
    match &inventory.irq_affinity {
        Err(reason) => {
            let _ = write!(out, "{}\n\n", unavailable(reason));
        }
        Ok(list) if list.is_empty() => out.push_str("No interface other than `lo`.\n\n"),
        Ok(list) => {
            let mut lines = Vec::new();
            for entry in list {
                if entry.irqs.is_empty() {
                    lines.push(format!(
                        "{}: no interrupt named after it in /proc/interrupts",
                        entry.interface
                    ));
                }
                for (irq, description, affinity) in &entry.irqs {
                    let affinity = match affinity {
                        Ok(text) => text.clone(),
                        Err(reason) => unavailable(reason),
                    };
                    lines.push(format!(
                        "{}: irq {irq} ({description}) -> {affinity}",
                        entry.interface
                    ));
                }
            }
            block(&mut out, &lines.join("\n"));
        }
    }
    labelled(&mut out, "`irqbalance`", &inventory.irqbalance);

    field(
        &mut out,
        "Transparent huge pages",
        "`/sys/kernel/mm/transparent_hugepage/enabled` and `defrag`",
    );
    labelled(&mut out, "`enabled`", &inventory.thp_enabled);
    labelled(&mut out, "`defrag`", &inventory.thp_defrag);

    field(
        &mut out,
        "Clock source",
        "`/sys/devices/system/clocksource/clocksource0/current_clocksource` and `available_clocksource`",
    );
    labelled(&mut out, "`current_clocksource`", &inventory.clocksource);
    labelled(
        &mut out,
        "`available_clocksource`",
        &inventory.clocksource_available,
    );

    out.push_str("## Environment class\n\n");
    let _ = write!(
        out,
        "Class {}: {}.\n\n",
        classification.environment,
        classification.environment.usage()
    );
    for basis in &classification.basis {
        let _ = writeln!(out, "- {basis}");
    }
    out.push('\n');
    out.push_str("Decision eligibility (measurement-harness.md 4.2, conditions 1 to 3; condition 4, the preflight snapshot, is deferred to batch B4; the manifest hash, `E_max` and the sample count are checked per run):\n\n");
    for (fanout, verdict) in eligibility {
        let what = env::fanout_label(*fanout);
        match verdict {
            Ok(()) => {
                let _ = writeln!(out, "- {what}: eligible");
            }
            Err(reasons) => {
                let reasons: Vec<String> = reasons.iter().map(ToString::to_string).collect();
                let _ = writeln!(out, "- {what}: ineligible: {}", reasons.join("; "));
            }
        }
    }
    out.push('\n');
    out.push_str(
        "Switch model and topology (E2): not recorded by this capture; an E2 record adds them by hand (batch B5).\n",
    );
    out
}

/// Writes the record to `<dir>/environments/<host>.md` and returns its
/// path.
///
/// # Errors
///
/// The I/O error.
pub fn write(dir: &Path, inventory: &Inventory, text: &str) -> std::io::Result<PathBuf> {
    let environments = dir.join("environments");
    std::fs::create_dir_all(&environments)?;
    let path = environments.join(format!("{}.md", inventory.host));
    std::fs::write(&path, text)?;
    Ok(path)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    /// A temporary fixture tree, removed on drop.
    pub(crate) struct Tree(pub PathBuf);

    impl Tree {
        pub(crate) fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "karyos-bench-inventory-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        pub(crate) fn file(&self, path: &str, text: &str) -> &Self {
            let full = self.0.join(path.trim_start_matches('/'));
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, text).unwrap();
            self
        }

        pub(crate) fn remove(&self, path: &str) -> &Self {
            let full = self.0.join(path.trim_start_matches('/'));
            let _ = std::fs::remove_file(&full);
            let _ = std::fs::remove_dir_all(&full);
            self
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Canned command outputs keyed by `program args`; anything else is
    /// not found.
    #[derive(Default)]
    pub(crate) struct Canned(pub HashMap<String, String>);

    impl Canned {
        pub(crate) fn with(mut self, command: &str, output: &str) -> Self {
            self.0.insert(command.to_string(), output.to_string());
            self
        }

        pub(crate) fn without(mut self, command: &str) -> Self {
            self.0.remove(command);
            self
        }
    }

    impl Runner for Canned {
        fn run(&self, program: &str, args: &[&str]) -> Reading {
            let key = std::iter::once(program)
                .chain(args.iter().copied())
                .collect::<Vec<_>>()
                .join(" ");
            self.0
                .get(&key)
                .cloned()
                .ok_or_else(|| format!("{program} not found"))
        }
    }

    pub(crate) const LSCPU: &str = "\
Architecture:                       x86_64
CPU op-mode(s):                     32-bit, 64-bit
Byte Order:                         Little Endian
CPU(s):                             8
On-line CPU(s) list:                0-7
Model name:                         Intel(R) Xeon(R) E-2378G CPU @ 2.80GHz
Thread(s) per core:                 1
Core(s) per socket:                 8
Socket(s):                          1
NUMA node0 CPU(s):                  0-7";

    pub(crate) const LSCPU_VM: &str = "\
Architecture:            x86_64
CPU(s):                  4
Model name:              AMD EPYC 7B13
Hypervisor vendor:       KVM
Virtualization type:     full";

    const ETHTOOL_I: &str = "\
driver: ixgbe
version: 6.8.0-45-generic
firmware-version: 0x800003e2
expansion-rom-version:
bus-info: 0000:01:00.0
supports-statistics: yes";

    const ETHTOOL_T_OLD: &str = "\
Time stamping parameters for enp1s0:
Capabilities:
\thardware-transmit     (SOF_TIMESTAMPING_TX_HARDWARE)
\tsoftware-transmit     (SOF_TIMESTAMPING_TX_SOFTWARE)
\thardware-receive      (SOF_TIMESTAMPING_RX_HARDWARE)
\tsoftware-receive      (SOF_TIMESTAMPING_RX_SOFTWARE)
\tsoftware-system-clock (SOF_TIMESTAMPING_SOFTWARE)
\thardware-raw-clock    (SOF_TIMESTAMPING_RAW_HARDWARE)
PTP Hardware Clock: 0
Hardware Transmit Timestamp Modes:
\toff                   (HWTSTAMP_TX_OFF)
\ton                    (HWTSTAMP_TX_ON)
Hardware Receive Filter Modes:
\tnone                  (HWTSTAMP_FILTER_NONE)
\tall                   (HWTSTAMP_FILTER_ALL)";

    const ETHTOOL_T_NEW: &str = "\
Time stamping parameters for eth0:
Capabilities:
\tsoftware-transmit
\tsoftware-receive
\tsoftware-system-clock
Hardware timestamp provider index: none
Hardware Transmit Timestamp Modes: none
Hardware Receive Filter Modes: none";

    const ETHTOOL_K: &str = "\
Features for enp1s0:
rx-checksumming: on
tx-checksumming: on
\ttx-checksum-ipv4: off [fixed]
\ttx-checksum-ip-generic: on
scatter-gather: on
tcp-segmentation-offload: off
generic-receive-offload: on
large-receive-offload: off [fixed]
rx-vlan-filter: on [fixed]";

    const INTERRUPTS: &str = "\
           CPU0       CPU1       CPU2       CPU3
  0:         34          0          0          0   IO-APIC   2-edge      timer
 24:          0       1234          0          0   PCI-MSI 524288-edge      enp1s0-TxRx-0
 25:          0          0       5678          0   PCI-MSI 524289-edge      enp1s0-TxRx-1
 26:          1          0          0          0   PCI-MSI 524290-edge      enp1s0
 27:          1          0          0          0   PCI-MSI 524291-edge      enp1s0x-other
NMI:          0          0          0          0   Non-maskable interrupts";

    pub(crate) const UNAME: &str = "Linux flumix 6.8.0-45-generic #45-Ubuntu SMP PREEMPT_DYNAMIC Fri Aug 30 12:02:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux";

    /// A physical, tuned x86_64 host with 8 CPUs, cores 2 to 7 isolated.
    pub(crate) fn tuned() -> (Tree, Canned) {
        let tree = Tree::new();
        tree.file("/proc/cmdline", "BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro isolcpus=managed_irq,domain,2-7 nohz_full=2-7 rcu_nocbs=2-7 quiet\n")
            .file("/sys/devices/system/cpu/isolated", "2-7\n")
            .file("/sys/devices/system/cpu/nohz_full", "2-7\n")
            .file("/sys/devices/system/cpu/intel_pstate/no_turbo", "1\n")
            .file("/sys/devices/system/clocksource/clocksource0/current_clocksource", "tsc\n")
            .file("/sys/devices/system/clocksource/clocksource0/available_clocksource", "tsc hpet acpi_pm \n")
            .file("/sys/kernel/mm/transparent_hugepage/enabled", "always [madvise] never\n")
            .file("/sys/kernel/mm/transparent_hugepage/defrag", "always defer defer+madvise [madvise] never\n")
            .file("/sys/class/net/lo/type", "772\n")
            .file("/sys/class/net/enp1s0/type", "1\n")
            .file("/sys/class/ptp/ptp0/clock_name", "enp1s0\n")
            .file("/dev/ptp0", "")
            .file("/proc/interrupts", INTERRUPTS)
            .file("/proc/irq/24/smp_affinity_list", "1\n")
            .file("/proc/irq/25/smp_affinity_list", "0-1\n")
            .file("/proc/irq/26/smp_affinity_list", "0\n")
            .file("/proc/1/comm", "systemd\n")
            .file("/proc/1/cgroup", "0::/init.scope\n")
            .file("/proc/812/comm", "irqbalance\n")
            .file("/sys/class/dmi/id/sys_vendor", "Supermicro\n")
            .file("/sys/class/dmi/id/board_vendor", "Supermicro\n")
            .file("/sys/class/dmi/id/product_name", "SYS-5019C-M\n");
        for cpu in 0..8 {
            let base = format!("/sys/devices/system/cpu/cpu{cpu}");
            tree.file(&format!("{base}/cpufreq/scaling_governor"), "performance\n")
                .file(&format!("{base}/cpufreq/scaling_min_freq"), "800000\n")
                .file(&format!("{base}/cpufreq/scaling_max_freq"), "5100000\n");
            for (state, name, disable, latency) in [
                (0, "POLL", "0", "0"),
                (1, "C1", "0", "2"),
                (2, "C6", "1", "170"),
            ] {
                let dir = format!("{base}/cpuidle/state{state}");
                tree.file(&format!("{dir}/name"), name)
                    .file(&format!("{dir}/disable"), disable)
                    .file(&format!("{dir}/latency"), latency);
            }
        }
        let canned = Canned::default()
            .with("hostname -f", "flumix.secureless.net")
            .with("id -u", "1000")
            .with("uname -a", UNAME)
            .with("lscpu", LSCPU)
            .with("systemd-detect-virt", "none")
            .with("systemd-detect-virt --container", "none")
            .with("ethtool -i enp1s0", ETHTOOL_I)
            .with("ethtool -T enp1s0", ETHTOOL_T_OLD)
            .with("ethtool -k enp1s0", ETHTOOL_K);
        (tree, canned)
    }

    pub(crate) fn capture(tree: &Tree, canned: &Canned, os: &str, arch: &str) -> Inventory {
        Inventory::capture(&Probe::new(&tree.0, canned), os, arch, Scope::Full)
    }

    #[test]
    fn lscpu_fixture_parses() {
        let cpu = parse_lscpu(LSCPU);
        assert_eq!(
            cpu.model.as_deref(),
            Some("Intel(R) Xeon(R) E-2378G CPU @ 2.80GHz")
        );
        assert_eq!(cpu.architecture.as_deref(), Some("x86_64"));
        assert_eq!(cpu.cpus, Some(8));
        assert_eq!(cpu.sockets, Some(1));
        assert_eq!(cpu.threads_per_core, Some(1));
        assert_eq!(cpu.hypervisor, None);
        assert_eq!(parse_lscpu(LSCPU_VM).hypervisor.as_deref(), Some("KVM"));
    }

    #[test]
    fn ethtool_fixtures_parse() {
        let driver = parse_ethtool_driver(ETHTOOL_I);
        assert_eq!(driver.driver.as_deref(), Some("ixgbe"));
        assert_eq!(driver.version.as_deref(), Some("6.8.0-45-generic"));
        assert_eq!(driver.firmware.as_deref(), Some("0x800003e2"));
        assert_eq!(driver.bus.as_deref(), Some("0000:01:00.0"));

        let old = parse_ethtool_timestamping(ETHTOOL_T_OLD);
        assert_eq!(old.phc_index, Some(0));
        assert!(old.hardware());
        assert_eq!(old.capabilities.len(), 6);
        let new = parse_ethtool_timestamping(ETHTOOL_T_NEW);
        assert_eq!(new.phc_index, None);
        assert!(!new.hardware());
        assert_eq!(
            new.capabilities,
            [
                "software-transmit",
                "software-receive",
                "software-system-clock"
            ]
        );

        let features = parse_ethtool_features(ETHTOOL_K);
        assert_eq!(features.len(), 9);
        assert_eq!(
            features["tx-checksum-ipv4"],
            Feature {
                on: false,
                fixed: true
            }
        );
        assert_eq!(
            features["generic-receive-offload"],
            Feature {
                on: true,
                fixed: false
            }
        );
        assert!(features["rx-vlan-filter"].fixed);
        assert!(!features.contains_key("Features for enp1s0"));
    }

    #[test]
    fn cmdline_and_cpu_lists_parse() {
        let params =
            parse_cmdline("BOOT_IMAGE=/vmlinuz ro isolcpus=managed_irq,domain,2-5,8 quiet");
        assert_eq!(params[0], ("BOOT_IMAGE".into(), Some("/vmlinuz".into())));
        assert_eq!(params[1], ("ro".into(), None));
        let isolcpus = params[2].1.as_deref().unwrap();
        assert_eq!(parse_cpu_list(isolcpus), [2, 3, 4, 5, 8]);
        assert_eq!(parse_cpu_list(""), Vec::<usize>::new());
        assert_eq!(parse_cpu_list("0-1,1,3\n"), [0, 1, 3]);
        assert_eq!(
            parse_uname(UNAME),
            Some(("flumix".into(), "6.8.0-45-generic".into()))
        );
    }

    #[test]
    fn interrupts_parse_and_match_queues() {
        let lines = parse_interrupts(INTERRUPTS);
        assert_eq!(lines[1], (24, "PCI-MSI 524288-edge enp1s0-TxRx-0".into()));
        let (tree, canned) = tuned();
        let inventory = capture(&tree, &canned, "linux", "x86_64");
        let affinity = inventory.irq_affinity.unwrap();
        assert_eq!(affinity.len(), 1);
        let irqs: Vec<(u32, &str)> = affinity[0]
            .irqs
            .iter()
            .map(|(irq, _, value)| (*irq, value.as_deref().unwrap()))
            .collect();
        // enp1s0x-other is another interface.
        assert_eq!(irqs, [(24, "1"), (25, "0-1"), (26, "0")]);
        assert_eq!(inventory.irqbalance.as_deref(), Ok("irqbalance running"));
    }

    #[test]
    fn sysfs_tree_reads() {
        let (tree, canned) = tuned();
        let inventory = capture(&tree, &canned, "linux", "x86_64");
        assert_eq!(inventory.host, "flumix.secureless.net");
        assert_eq!(inventory.isolated_cores(), [2, 3, 4, 5, 6, 7]);
        assert_eq!(inventory.nohz_full_cores(), [2, 3, 4, 5, 6, 7]);
        assert_eq!(inventory.clocksource.as_deref(), Ok("tsc"));
        assert_eq!(inventory.boost.as_deref(), Ok("intel_pstate/no_turbo 1"));
        assert_eq!(
            inventory.ptp_devices.as_deref(),
            Ok(&["/dev/ptp0".to_string()][..])
        );
        let cpus = inventory.cpus.as_ref().unwrap();
        assert_eq!(cpus.len(), 8);
        assert!(cpus.iter().all(Cpu::fixed_frequency));
        let idle = cpus[3].idle.as_ref().unwrap();
        assert_eq!(idle.len(), 3);
        assert_eq!(idle[2].name.as_deref(), Ok("C6"));
        assert_eq!(idle[2].disable.as_deref(), Ok("1"));
        let interfaces = inventory.interfaces.as_ref().unwrap();
        assert_eq!(interfaces.len(), 1, "lo is left out");
        assert_eq!(interfaces[0].name, "enp1s0");
        assert!(inventory.container_markers.is_empty());
        assert_eq!(
            inventory.node_and_release(),
            Some(("flumix".into(), "6.8.0-45-generic".into()))
        );
    }

    #[test]
    fn cpus_sort_numerically() {
        let tree = Tree::new();
        for cpu in [10, 2, 1, 0] {
            tree.file(
                &format!("/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor"),
                "powersave",
            );
        }
        tree.file("/sys/devices/system/cpu/cpufreq/boost", "1");
        let inventory = capture(&tree, &Canned::default(), "linux", "x86_64");
        let order: Vec<usize> = inventory
            .cpus
            .unwrap()
            .iter()
            .map(|cpu| cpu.index)
            .collect();
        assert_eq!(order, [0, 1, 2, 10]);
        assert_eq!(inventory.boost.as_deref(), Ok("cpufreq/boost 1"));
    }

    fn sections(text: &str) -> Vec<&str> {
        text.lines()
            .filter_map(|line| line.strip_prefix("### "))
            .collect()
    }

    fn rendered(inventory: &Inventory) -> String {
        let classification = env::classify(inventory);
        let eligibility: Vec<Eligibility> = env::FANOUTS
            .iter()
            .map(|fanout| (*fanout, env::decision_eligible(inventory, None, *fanout)))
            .collect();
        render(inventory, &classification, &eligibility)
    }

    #[test]
    fn command_output_with_backticks_cannot_close_its_fence() {
        let mut out = String::new();
        block(&mut out, "a ``` b\n````");
        assert!(out.starts_with("`````text\n"), "{out}");
        assert_eq!(first_block(&out), Some("a ``` b\n````"));
    }

    #[test]
    fn record_has_every_readme_field_in_order() {
        let (tree, canned) = tuned();
        let text = rendered(&capture(&tree, &canned, "linux", "x86_64"));
        let expected: Vec<&str> = SPEC_FIELDS.iter().chain(&METHOD_FIELDS).copied().collect();
        assert_eq!(sections(&text), expected, "{text}");
        assert!(text.contains("## Environment class"));
        assert!(text.contains("Switch model and topology (E2)"));
        assert!(text.contains("Host flumix, kernel release 6.8.0-45-generic."));
        assert!(text.contains("Driver ixgbe, version 6.8.0-45-generic, firmware 0x800003e2"));
        assert!(text.contains("PHC index 0, hardware transmit and receive stamps yes."));
        assert!(text.contains("enp1s0: irq 24 (PCI-MSI 524288-edge enp1s0-TxRx-0) -> 1"));
        assert!(text.contains("cpu7 state2: name C6; disable 1; latency 170"));
        assert!(text.contains("`isolcpus` managed_irq,domain,2-7"));
        assert!(text.contains("Privileges: without root"));
        assert!(!text.contains("unavailable"), "{text}");
        // The record names itself so the eligibility check can find the
        // kernel it was taken on.
        assert_eq!(
            record_node_and_release(&text),
            Some(("flumix".into(), "6.8.0-45-generic".into()))
        );
    }

    #[test]
    fn a_missing_tool_or_file_is_unavailable_never_omitted() {
        let (tree, canned) = tuned();
        let canned = canned
            .without("lscpu")
            .without("ethtool -T enp1s0")
            .without("systemd-detect-virt")
            .without("systemd-detect-virt --container");
        tree.remove("/sys/devices/system/cpu/nohz_full")
            .remove("/sys/class/ptp")
            .remove("/sys/devices/system/clocksource");
        let text = rendered(&capture(&tree, &canned, "linux", "x86_64"));
        let expected: Vec<&str> = SPEC_FIELDS.iter().chain(&METHOD_FIELDS).copied().collect();
        assert_eq!(sections(&text), expected);
        assert!(text.contains("unavailable (lscpu not found)"), "{text}");
        assert!(text.contains("unavailable (ethtool not found)"), "{text}");
        assert!(text.contains("unavailable (systemd-detect-virt not found)"));
        assert!(text.contains("unavailable (/sys/devices/system/cpu/nohz_full: "));
        assert!(text.contains("`/sys/class/ptp`: unavailable (/sys/class/ptp: "));
        assert!(text.contains(
            "unavailable (/sys/devices/system/clocksource/clocksource0/current_clocksource: "
        ));
    }

    #[test]
    fn an_empty_host_renders_every_field_as_unavailable() {
        let tree = Tree::new();
        let inventory = capture(&tree, &Canned::default(), "macos", "aarch64");
        assert_eq!(inventory.host, "unknown");
        let text = rendered(&inventory);
        let expected: Vec<&str> = SPEC_FIELDS.iter().chain(&METHOD_FIELDS).copied().collect();
        assert_eq!(sections(&text), expected);
        // Each field section holds at least one unavailable line.
        for section in text.split("\n### ").skip(1) {
            let name = section.lines().next().unwrap();
            assert!(section.contains("unavailable ("), "{name}: {section}");
        }
        assert!(text.contains("Environment class: E4"));
    }

    #[test]
    fn writes_under_environments() {
        let (tree, canned) = tuned();
        let inventory = capture(&tree, &canned, "linux", "x86_64");
        let out = Tree::new();
        let path = write(&out.0, &inventory, "x").unwrap();
        assert_eq!(
            path,
            out.0.join("environments").join("flumix.secureless.net.md")
        );
        assert_eq!(std::fs::read_to_string(path).unwrap(), "x");
    }

    #[test]
    fn civil_dates() {
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(20_742), (2026, 10, 16));
        assert_eq!(civil(11_016), (2000, 2, 29));
    }
}
