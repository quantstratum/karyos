// SPDX-License-Identifier: Apache-2.0

//! Every workload in a short smoke mode, and the history format. No timing
//! is asserted.

use karyos_bench::env::{Environment, Labels};
use karyos_bench::inventory;
use karyos_bench::{Config, Workload, defaults, report, run};

fn smoke(config: Config) -> Config {
    Config {
        iterations: 200,
        warmup: 20,
        ..config
    }
}

#[test]
fn every_workload_runs_and_reports() {
    let labels = Labels::detect();
    for config in defaults(200).into_iter().map(smoke) {
        let measurement = run(config).unwrap_or_else(|cause| panic!("{config}: {cause}"));
        assert!(measurement.rate > 0.0, "{config}");
        let text = report::text(&measurement, &labels);
        assert!(
            text.contains(&format!("environment: {}\n", labels.qualification)),
            "{text}"
        );
        let line = report::history_line(&measurement, &labels);
        assert_eq!(
            report::field(&line, "workload"),
            Some(config.workload.name())
        );
        if matches!(
            config.workload,
            Workload::Throughput | Workload::CleanerThroughput | Workload::IpcThroughput
        ) {
            assert!(measurement.latency.is_none());
        } else {
            assert!(report::field(&line, "p50_ns").is_some(), "{line}");
        }
        if matches!(config.workload, Workload::PingPong | Workload::IpcPingPong) {
            assert!(text.contains("round trip"), "{text}");
            assert!(text.contains("symmetric paths"), "{text}");
        }
        if config.workload == Workload::OpenLoop {
            assert!(
                text.contains("scheduled latency (due time to delivery)"),
                "{text}"
            );
            assert_eq!(
                report::field(&line, "target_rate"),
                Some(
                    config
                        .target_rate
                        .map_or_else(|| "none".to_string(), |rate| rate.to_string())
                        .as_str()
                )
            );
            assert!(measurement.producer_lateness.is_some());
            assert!(report::field(&line, "producer_lateness_p50_ns").is_some());
            assert!(text.contains("producer lateness (scheduled time to accepted offer,"));
        }
        if config.workload == Workload::CleanerThroughput {
            assert!(measurement.cleaned_slots_per_second.is_some());
            assert!(measurement.term_rotations_per_second.is_some());
            assert!(text.contains("term production"), "{text}");
            assert!(text.contains("cleaner"), "{text}");
            assert!(report::field(&line, "cleaned_slots_per_second").is_some());
            assert!(report::field(&line, "term_rotations_per_second").is_some());
        }
    }
}

/// The environment label replaces `unqualified`: a class of manifest 6.3
/// with its verdict, in the text and in the history line. macOS and the
/// Docker runs of `scripts/linux-test.sh` are E4, never decision grade.
#[test]
fn reports_carry_the_environment_class() {
    let labels = Labels::detect();
    assert!(
        [
            "E1 eligible",
            "E1 ineligible",
            "E3 not demonstrated",
            "E4 non-decision"
        ]
        .contains(&labels.qualification.as_str()),
        "{}",
        labels.qualification
    );
    if cfg!(target_os = "macos") || std::path::Path::new("/.dockerenv").exists() {
        assert_eq!(labels.environment, Environment::E4);
        assert_eq!(labels.qualification, "E4 non-decision");
    }
    let measurement = run(smoke(defaults(200)[0])).unwrap_or_else(|cause| panic!("{cause}"));
    let line = report::history_line(&measurement, &labels);
    assert_eq!(
        report::field(&line, "environment"),
        Some(labels.qualification.as_str())
    );
}

/// `karyos-bench inventory --out <dir>` writes the record with every
/// field of the environments README, present or `unavailable`, and
/// prints the class.
#[test]
fn the_inventory_command_writes_a_complete_record() {
    let dir = std::env::temp_dir().join(format!("karyos-bench-smoke-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_karyos-bench"))
        .args(["inventory", "--out"])
        .arg(&dir)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let environments = dir.join("environments");
    let records: Vec<_> = std::fs::read_dir(&environments)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(records.len(), 1, "{records:?}");
    let text = std::fs::read_to_string(&records[0]).unwrap();
    let headings: Vec<&str> = text
        .lines()
        .filter_map(|line| line.strip_prefix("### "))
        .collect();
    let fields: Vec<&str> = inventory::SPEC_FIELDS
        .iter()
        .chain(&inventory::METHOD_FIELDS)
        .copied()
        .collect();
    assert_eq!(headings, fields, "{text}");
    for section in text.split("\n### ").skip(1) {
        let body: Vec<&str> = section
            .lines()
            .skip(1)
            .filter(|line| !line.is_empty() && !line.starts_with("Source:"))
            .collect();
        assert!(!body.is_empty(), "empty field: {section}");
    }
    let labels = Labels::detect();
    assert!(
        stdout.contains(&format!("class {}", labels.environment)),
        "{stdout}"
    );
    assert!(text.contains(&format!("Environment class: {}", labels.environment)));
    if labels.environment != Environment::E1 {
        assert!(stdout.contains("does not decide"), "{stdout}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn only_records_with_the_same_key_are_compared() {
    let labels = Labels::detect();
    let config = smoke(defaults(200)[0]);
    let measurement = run(config).unwrap_or_else(|cause| panic!("{cause}"));
    let line = report::history_line(&measurement, &labels);
    assert_eq!(report::compare("", &line), None);
    let other = report::history_line(
        &run(Config {
            message: 1024,
            ..config
        })
        .unwrap_or_else(|cause| panic!("{cause}")),
        &labels,
    );
    assert_eq!(report::compare(&other, &line), None);
    let history = format!("{line}\n{other}\n");
    let comparison = report::compare(&history, &line).unwrap_or_default();
    assert!(comparison.contains("p50_ns +0.0%"), "{comparison}");
}

#[test]
fn history_fields_read_back() {
    let line = "{\"key\":\"a b|host=x\",\"rate\":12,\"p50_ns\":300}";
    assert_eq!(report::field(line, "key"), Some("a b|host=x"));
    assert_eq!(report::field(line, "rate"), Some("12"));
    assert_eq!(report::field(line, "p50_ns"), Some("300"));
    assert_eq!(report::field(line, "p99_ns"), None);
}

#[test]
fn existing_workload_configuration_key_keeps_its_original_shape() {
    let config = defaults(200)[0];
    assert_eq!(
        config.to_string(),
        "offer-poll message=32 publishers=1 iterations=200 warmup=20 term=65536"
    );

    let labels = Labels::detect();
    let measurement = run(config).unwrap_or_else(|cause| panic!("{config}: {cause}"));
    let line = report::history_line(&measurement, &labels);
    let previous = format!(
        "{{\"key\":\"{}\",\"commit\":\"prior\",\"rate\":100,\"p50_ns\":100}}",
        report::key(&measurement, &labels)
    );
    assert!(report::compare(&previous, &line).is_some());
}

#[test]
fn cleaner_workload_observes_term_rotation_and_reclamation() {
    let config = Config {
        workload: Workload::CleanerThroughput,
        message: 32,
        publishers: 2,
        iterations: 6_000,
        warmup: 1_000,
        term_length: 64 * 1024,
        target_rate: None,
    };
    let measurement = run(config).unwrap_or_else(|cause| panic!("{config}: {cause}"));
    assert!(measurement.term_rotations_per_second.unwrap_or_default() > 0.0);
    assert!(measurement.cleaned_slots_per_second.unwrap_or_default() > 0.0);
}

#[test]
fn cleaner_defaults_cover_at_least_a_thousand_term_rotations() {
    let configs: Vec<_> = defaults(20_000)
        .into_iter()
        .filter(|config| config.workload == Workload::CleanerThroughput)
        .collect();
    assert_eq!(configs.len(), 3);
    for config in configs {
        let message_block = u64::try_from(config.message + 32)
            .unwrap_or(u64::MAX)
            .div_ceil(32)
            .saturating_mul(32);
        let estimated_rotations =
            config.iterations.saturating_mul(message_block) / u64::from(config.term_length);
        assert!(estimated_rotations >= 1_000, "{config}");
        assert!(config.warmup >= config.iterations / 10, "{config}");
    }
}

/// Trace-on refills nothing inside the timed loop: with the id buffer
/// refilled per message the run grows with the square of its length, so a
/// long run would far exceed this bound.
#[test]
fn a_long_trace_on_run_takes_bounded_time() {
    let config = defaults(200)
        .into_iter()
        .find(|config| config.workload == Workload::TraceOn)
        .unwrap_or_else(|| panic!("no trace-on workload"));
    let config = Config {
        iterations: 50_000,
        warmup: 0,
        ..config
    };
    let started = std::time::Instant::now();
    let measurement = run(config).unwrap_or_else(|cause| panic!("{cause}"));
    let elapsed = started.elapsed();
    assert!(measurement.rate > 0.0);
    assert!(
        elapsed < std::time::Duration::from_secs(60),
        "trace-on took {elapsed:?} for {} messages",
        config.iterations
    );
}

/// The child part of the wire workloads: the run starts this binary
/// again with `--exact wire_child`, and the environment names the role.
#[test]
fn wire_child() {
    if let Some(result) = karyos_bench::wire::process::child() {
        result.unwrap_or_else(|cause| panic!("{cause}"));
    }
}

/// A temporary directory removed on drop, whatever the test's outcome.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        Self(std::env::temp_dir().join(format!("karyos-{name}-{}", std::process::id())))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn wire_run(
    shape: karyos_bench::manifest::Shape,
    load: karyos_bench::wire::stage::StageLoad,
    messages: u64,
) -> karyos_bench::wire::stage::StageRun {
    karyos_bench::wire::stage::StageRun {
        shape,
        e_max: 64,
        rule: karyos_bench::manifest::MtuRule::CountsEnvelope,
        load,
        messages,
        warmup: 20,
    }
}

/// Each wire role runs in its own process and both sample files come
/// back complete (B3c-2).
#[test]
fn wire_roles_run_in_their_own_processes() {
    use karyos_bench::manifest::Shape;
    use karyos_bench::samples::MISSING;
    use karyos_bench::wire::process::{ProcessOptions, run_processes};
    use karyos_bench::wire::stage::StageLoad;
    let dir = TempDir::new("wire");
    let options = ProcessOptions {
        run_index: 3,
        ..ProcessOptions::default()
    };
    for (shape, load) in [
        (Shape::W1, StageLoad::Closed),
        (Shape::W6, StageLoad::Closed),
        (Shape::W1, StageLoad::Open { rate: 100_000 }),
    ] {
        let run = wire_run(shape, load, 200);
        let samples = run_processes(&run, &dir.0, &options)
            .unwrap_or_else(|cause| panic!("{shape}: {cause}"));
        assert_eq!(samples.send.len(), 200);
        assert_eq!(samples.receive.len(), 200);
        assert!(
            samples.send.iter().all(|sample| *sample != MISSING),
            "{shape}"
        );
        if load == StageLoad::Closed {
            assert!(
                samples.receive.iter().all(|sample| *sample != MISSING),
                "{shape}"
            );
        }
        assert_eq!(samples.receive_callback.len(), 200);
        assert_eq!(samples.ack_timeouts, 0);
        // Unpinned children are never decision eligible (ACS 15273).
        assert!(samples.functional_only);
        assert_eq!(
            samples.functional_reasons.get(..2),
            Some(&["rx not pinned".to_string(), "tx not pinned".to_string()][..])
        );
    }
}

/// Runs W1 under R1 with `faults`, returning the error and the time the
/// run took.
fn faulty_run(
    name: &str,
    messages: u64,
    faults: karyos_bench::wire::process::Faults,
    deadline: Option<std::time::Duration>,
) -> (Option<String>, std::time::Duration) {
    use karyos_bench::manifest::Shape;
    use karyos_bench::wire::process::{ProcessOptions, run_processes};
    use karyos_bench::wire::stage::StageLoad;
    let dir = TempDir::new(name);
    let started = std::time::Instant::now();
    let result = run_processes(
        &wire_run(Shape::W1, StageLoad::Closed, messages),
        &dir.0,
        &ProcessOptions {
            deadline,
            faults,
            ..ProcessOptions::default()
        },
    );
    (result.err().map(|error| error.0), started.elapsed())
}

/// Lost hellos are repeated: no message waits for an acknowledgement
/// that cannot come.
#[test]
fn lost_hellos_are_repeated() {
    use karyos_bench::manifest::Shape;
    use karyos_bench::wire::process::{Faults, ProcessOptions, run_processes};
    use karyos_bench::wire::stage::StageLoad;
    let dir = TempDir::new("wire-hello");
    let started = std::time::Instant::now();
    let samples = run_processes(
        &wire_run(Shape::W1, StageLoad::Closed, 200),
        &dir.0,
        &ProcessOptions {
            faults: Faults {
                drop_hellos: 3,
                ..Faults::default()
            },
            ..ProcessOptions::default()
        },
    )
    .unwrap_or_else(|cause| panic!("{cause}"));
    assert_eq!(samples.ack_timeouts, 0);
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

/// A sender that crashes ends the run quickly: the parent repeats its
/// notice to the receiver until the receiver exits.
#[test]
fn a_crashed_sender_ends_the_run() {
    use karyos_bench::wire::process::Faults;
    let (error, took) = faulty_run(
        "wire-tx-crash",
        200,
        Faults {
            tx_crash_at: Some(50),
            drop_dones: 3,
            ..Faults::default()
        },
        Some(std::time::Duration::from_secs(20)),
    );
    let error = error.unwrap_or_default();
    assert!(error.contains("tx child failed"), "{error}");
    assert!(took < std::time::Duration::from_secs(5), "{took:?}");
}

/// A receiver that crashes ends the run at once, without waiting for
/// the sender.
#[test]
fn a_crashed_receiver_ends_the_run() {
    use karyos_bench::wire::process::Faults;
    let (error, took) = faulty_run(
        "wire-rx-crash",
        200,
        Faults {
            rx_crash_at: Some(50),
            ..Faults::default()
        },
        None,
    );
    let error = error.unwrap_or_default();
    assert!(error.contains("rx child failed"), "{error}");
    assert!(took < std::time::Duration::from_secs(3), "{took:?}");
}

/// A receiver that ends at its deadline while the R1 sender still runs
/// tells the sender, which stops; without that notice the parent stops a
/// sender that outlives the receiver.
#[test]
fn a_finished_receiver_stops_the_sender() {
    use karyos_bench::wire::process::Faults;
    let finish = Faults {
        rx_deadline_ms: Some(300),
        ..Faults::default()
    };
    // A million R1 messages take far longer than 300 ms.
    let (error, took) = faulty_run("wire-finish", 1_000_000, finish, None);
    let error = error.unwrap_or_default();
    assert!(error.contains("tx child failed"), "{error}");
    // The sender stops on the notice, not after an acknowledgement
    // timeout: 300 ms of receiving plus ACK_TIMEOUT is the bound.
    assert!(took < std::time::Duration::from_millis(1_300), "{took:?}");
    let (error, took) = faulty_run(
        "wire-no-stop",
        1_000_000,
        Faults {
            no_stop: true,
            ..finish
        },
        None,
    );
    let error = error.unwrap_or_default();
    assert!(error.contains("outlived"), "{error}");
    assert!(took < std::time::Duration::from_secs(6), "{took:?}");
}

/// A sender that stops responding meets the run deadline, and both
/// children are killed.
#[test]
fn a_frozen_sender_meets_the_deadline() {
    use karyos_bench::wire::process::Faults;
    let (error, took) = faulty_run(
        "wire-freeze",
        200,
        Faults {
            tx_freeze_at: Some(50),
            ..Faults::default()
        },
        Some(std::time::Duration::from_secs(3)),
    );
    let error = error.unwrap_or_default();
    assert!(error.contains("deadline"), "{error}");
    assert!(
        (std::time::Duration::from_secs(3)..std::time::Duration::from_secs(6)).contains(&took),
        "{took:?}"
    );
}

/// Children started under `taskset` read their own core back, so a
/// pinned run carries no pinning reason (B4a). Skipped, with a line on
/// stderr, without `taskset` or with one CPU.
#[cfg(target_os = "linux")]
#[test]
fn pinned_wire_children_read_their_core_back() {
    use karyos_bench::manifest::Shape;
    use karyos_bench::wire::process::{Cores, ProcessOptions, run_processes};
    use karyos_bench::wire::stage::StageLoad;
    let cpus = std::thread::available_parallelism().map_or(1, usize::from);
    if karyos_bench::env::command("taskset", &["--version"]).is_none() || cpus < 2 {
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr(),
            "skipped: taskset unavailable or {cpus} CPU"
        );
        return;
    }
    let dir = TempDir::new("wire-pin");
    let samples = run_processes(
        &wire_run(Shape::W1, StageLoad::Closed, 200),
        &dir.0,
        &ProcessOptions {
            cores: Some(Cores {
                receiver: 0,
                sender: 1,
            }),
            ..ProcessOptions::default()
        },
    )
    .unwrap_or_else(|cause| panic!("{cause}"));
    assert!(
        !samples
            .functional_reasons
            .iter()
            .any(|reason| reason.contains("pinned") || reason.contains("affinity")),
        "{:?}",
        samples.functional_reasons
    );
}

/// A wire child exits on its own once its parent's end of its standard
/// input closes, so a parent that dies leaves no orphan.
#[test]
fn an_orphaned_wire_child_exits() {
    use karyos_bench::manifest::Shape;
    use karyos_bench::wire::process::{
        CHILD_TEST, INDEX, NONCE, ORPHANED, OUT, ROLE, RUN, encode_run,
    };
    use karyos_bench::wire::stage::StageLoad;
    use std::io::BufRead;
    let dir = TempDir::new("wire-orphan");
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", CHILD_TEST, "--nocapture", "--test-threads", "1"])
        .env(ROLE, "rx")
        .env(
            RUN,
            encode_run(&wire_run(Shape::W1, StageLoad::Closed, 200)),
        )
        .env(OUT, dir.0.join("receive.samples"))
        .env(NONCE, "1")
        .env(INDEX, "0")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut lines = std::io::BufReader::new(stdout).lines();
    assert!(lines.any(|line| line.is_ok_and(|line| line.contains("WIRE_READY"))));
    drop(child.stdin.take());
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() > std::time::Duration::from_secs(5) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the orphaned child kept running");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    assert_eq!(status.code(), Some(ORPHANED));
}

/// The child part of the IPC workloads: the workload runs this binary
/// again with `--exact ipc_child`, and the environment says what to do.
#[cfg(target_os = "linux")]
#[test]
fn ipc_child() {
    if let Some(result) = karyos_bench::ipc::child() {
        result.unwrap_or_else(|cause| panic!("{cause}"));
    }
}

/// A child that fails makes the IPC workloads fail promptly instead of
/// waiting for it (review of #146).
#[cfg(target_os = "linux")]
#[test]
fn a_failing_ipc_child_fails_the_workload_promptly() {
    use karyos_bench::ipc::{CHILD_FAIL, ping_pong_with, throughput_with};
    let config = |workload| Config {
        workload,
        message: 32,
        publishers: 1,
        iterations: 200,
        warmup: 20,
        term_length: 64 * 1024,
        target_rate: None,
    };
    for (name, run) in [
        (
            "ipc-ping-pong",
            ping_pong_with as fn(Config, &[(&str, &str)]) -> _,
        ),
        ("ipc-throughput", throughput_with),
    ] {
        let workload = Workload::parse(name).unwrap();
        let start = std::time::Instant::now();
        let failed = run(config(workload), &[(CHILD_FAIL, "1")]);
        assert!(failed.is_err(), "{name} succeeded with a failing child");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "{name} took {:?}",
            start.elapsed()
        );
    }
}
