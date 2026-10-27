### Added

- R-CORE-3, application counters (karyos#723). `Client::add_counter(label,
  CounterKind)` registers a named counter of the driver's client counters
  region, keyed to the client and to no stream: `CounterKind::Event` (type
  id 6, `TYPE_APPLICATION_EVENT`) or `CounterKind::Gauge` (type id 7,
  `TYPE_APPLICATION_GAUGE`). The bound is the driver's
  `max_counters_per_client`, shared with the client's other counters, and
  past it registration is refused with `ClientError::Refused`
  (`ResourcesUnavailable`); a label of more than 64 bytes is refused, never
  truncated. The cells are freed when the handle is released or the client
  goes. The agent's exporter shows them as `karyos_application_events_total`
  and `karyos_application_gauge`, labelled with the name and the client, and
  `karyos-stat` lists them under "application counters:". Updating one
  allocates nothing.
