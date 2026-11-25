### Added

- The Cluster client's failover state (`karyos_cluster::client::ClusterClient`, karyos#720).
  - **Bounds.** It reads the session bounds the cluster advertises at registration and holds to its window. Registrations are ordered by epoch.
  - **Correlation.** Every send carries a key (epoch, sequence, attempt), so an answer or a timer of another session or an older attempt steers nothing, and only a correlated answer raises the generation.
  - **Resends.** It resends the same request only after a redirect of its current attempt.
  - **Unknown outcomes.** A request outstanding across a leader change, a timeout or a new session is reported unknown, keeps its place, and is never resent unless its caller retries it.
  - **Refusals.** It refuses a lower generation. Expiry, an out-of-order refusal and a payload mismatch reach the caller typed.
  - **Allocation.** After registration it allocates nothing.
