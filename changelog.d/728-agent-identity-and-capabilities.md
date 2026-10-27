### Added

- R-CORE-24, the management agent's identity, attachment and capability
  discovery (karyos#728), all additions to API v1:
  - `karyos-agent --agent-id NAME` names the agent, as its deployment
    calls it (for example `namespace/pod`). It is taken from configuration
    only; the agent looks up no host or orchestrator name.
  - The view gains `agent`: `id`, `pid` and `started_ns`. The pair (pid,
    started_ns) identifies the agent's incarnation; `started_ns` is host
    `CLOCK_MONOTONIC`, not a wall-clock time.
  - Each driver gains `attachment`: `since_ns`, `attaches`, and `previous`,
    the end of the last attach (its instance, `ended_ns`, and
    `driver_gone` or `detached`).
  - New request `KARYOS-AGENT 1 capabilities`, answered for the caller's
    role. Each capability of a closed v1 list (`view`, `guard-close`,
    `guard-reopen`, `gap-ack`, `catalog`, `trace-window`) is `served`,
    `unavailable` (off in this deployment: `not_configured` or
    `journal_unavailable`) or `forbidden` (`role`).
  - The request with arguments answers
    `{"error":"bad arguments","request":"capabilities"}`. An older agent
    answers `bad request`, which a client reads as no discovery.
