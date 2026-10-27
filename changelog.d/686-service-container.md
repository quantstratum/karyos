### Added

- The Cluster's service container, core neutral (SPEC §9, C10;
  karyos#686, part 1 of 5). `karyos_cluster::service::ClusteredService`
  is the user's state machine: `on_command`, `on_timer` and
  `on_configuration`, each seeing only a `Context` of the entry's index,
  term and log time, with timers scheduled and cancelled through it.
  `ServiceContainer` applies committed entries in order. Requests go
  through C7a's `SessionTable`, so a retry gets its retained reply and the
  command runs once. Timer firings and configuration changes are entries,
  delivered only when applied, and a firing proposed twice delivers once;
  `ServiceContainer::due` lists the firings a leader proposes. Entries are
  a versioned `Envelope`, version 1, not frozen. `Propose` is the core
  boundary a core's adapter implements. `SessionTable::observe` moves the
  log time for an entry that holds no session operation.
