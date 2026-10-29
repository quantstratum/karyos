### Added

- The metrics exporter's capabilities for its first release (R-CORE-39,
  karyos#734).
  - **Attachment:** `karyos_exporter_info{id,pid}` and
    `karyos_exporter_started_ns` give its identity as an agent's
    (`--agent-id`, as `karyos-agent` has). Per driver,
    `karyos_driver_up`, `karyos_driver_state{state}`,
    `karyos_driver_info{instance}`, `karyos_driver_attaches_total` and
    `karyos_driver_attached_since_ns`. A driver that is not attached is
    reported as a state: no alert count, no counters and no last values,
    so a dashboard never reads zeros as healthy.
  - **Security:** still loopback only, now refused with a message that
    points to a TLS-terminating sidecar or mesh. An optional
    `--token-file` (mode 0600, 32 to 256 bytes) makes every scrape carry
    `Authorization: Bearer`, compared in constant time. A request without
    the token, or with another, is answered `401` with a `Bearer`
    challenge, and a malformed request head `400`.
  - **Metric families:** `exporter::FAMILIES` lists each family with its
    type and stability, and a test keeps the exposition to it. The
    per-cell families keyed by a driver's internal counter label are
    unstable.
  - No OTLP.
