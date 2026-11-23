### Added

- OTLP metrics export (karyos#706): `karyos-exporter-otlp`, in the new `karyos-otlp` crate, pushes the agent's view of each driver to an OpenTelemetry collector over OTLP/HTTP (binary protobuf, HTTP/1.1, in clear).
  - **Same metrics as Prometheus:** the metric families of `karyos-exporter`'s Prometheus endpoint, from one definition, `karyos_agent::exporter::families`, so names, labels and values match. A counter is a cumulative monotonic sum.
  - **Off by default:** it runs only when started with `--otlp-endpoint`, which must be a loopback address unless `--otlp-allow-remote`, which warns at start.
  - **Collector down:** an unavailable collector blocks nothing, and a failed export is dropped, not queued.
  - **Dependencies:** under the opentelemetry admission record, the new crate is outside the default build. `scripts/check-otlp-graph.sh`, run by `make pre-push`, checks that no library crate and not the default build gains its dependencies.
