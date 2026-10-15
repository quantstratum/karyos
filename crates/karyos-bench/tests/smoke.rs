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
        if config.workload == Workload::Throughput {
            assert!(measurement.latency.is_none());
        } else {
            assert!(report::field(&line, "p50_ns").is_some(), "{line}");
        }
        if config.workload == Workload::PingPong {
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
