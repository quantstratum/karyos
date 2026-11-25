### Added

- The Cluster client's failover state (`karyos_cluster::client::ClusterClient`, karyos#720). It reads the session bounds the cluster advertises at registration and holds to its window (`SubmitError::WindowFull`). It resends the same request (identity, epoch, sequence) only after a redirect, and reports a request outstanding across a leader change or a timeout as unknown, never resent unless its caller retries it. It refuses a reply or an announcement of a generation below the highest seen, and surfaces a session expiry as a typed event. After registration it allocates nothing.
