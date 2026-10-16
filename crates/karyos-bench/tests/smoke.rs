// SPDX-License-Identifier: Apache-2.0

//! Every workload in a short smoke mode, and the history format. No timing
//! is asserted.

use karyos_bench::env::Labels;
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
        assert!(text.contains("environment: unqualified"), "{text}");
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

/// The child part of the IPC workloads: the workload runs this binary
/// again with `--exact ipc_child`, and the environment says what to do.
#[cfg(target_os = "linux")]
#[test]
fn ipc_child() {
    if let Some(result) = karyos_bench::ipc::child() {
        result.unwrap_or_else(|cause| panic!("{cause}"));
    }
}
