### Fixed

- Four tests no longer fail on a loaded host (karyos#1067):
  - `the_view_shows_the_retention_state_of_a_running_archive` gives the agent's listing a deadline above the test's own wait. Its driver and Archive are served by the test thread, which a loaded host slows, and a listing cut at 5 s ended its session and started over until the wait ran out.
  - `dropping_the_driver_joins_a_late_agent` checks that the drop returned after the instant the agent was released, not after a fixed 50 ms: the release timer started before a 20 ms wait that load stretched (diagnosed by impl-d).
  - `every_threading_mode_serves_stops_and_returns_the_agents` waits for its events, and for an agent's failure, up to 30 s, not for a count of yields or sleeps.
  - `a_purged_prefix_exports_only_the_retained_span` opens its journal through the test helper that waits, at most 30 s, while it is `Locked`; the helper waited for a count of tries before.
