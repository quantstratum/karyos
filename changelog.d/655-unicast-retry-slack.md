### Added

- `AgentConfig.unicast_retry_slack` (karyos#655): a unicast NAK is
  retried only once its age exceeds the RTT estimate plus this slack.
  The default is 0, which keeps the previous rule; values above 1 s are
  refused (`LossConfigError::UnicastRetrySlack`). The rule cannot
  underflow when the age is below the RTT.
- An early RTT probe: a NAK on a path that has no RTT sample yet moves
  that path's next probe ahead of `rtt_probe_interval`, once per path
  binding generation and never once per NAK; a sampled path, or one
  whose probe is still on its way, is left alone. `RttCounts.early_probes`
  counts them.
