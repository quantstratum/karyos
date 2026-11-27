### Added

- Clusters tell each other apart by a durable 32-byte cluster identity (ADR-0123, karyos#717):
  - `karyos_cluster::cluster_identity` is the write-once `cluster-identity` record kept next to the hard state.
  - A backup rebuild writes a new identity, derived with SHA-256 from the source's identity, its top and a nonce supplied by the caller, and marks the node isolated from its source.
  - `karyos_cluster::peer_frame` is the `KRPF` v1 envelope around the core's messages. Its `PeerGate` drops a frame of another identity before the core sees it, and counts it.
  - `ClusterClient` takes the identities it accepts (`Accepted`). Registrations, replies and announcements arrive with a `Stamp` of identity and generation, and one from another cluster is refused as `Event::ForeignCluster`. Each `Send` names the cluster it is for.
  - An isolated standby refuses promotion (`PromotionRefused::Isolated`), and its effects stay off.
  - The simulation harness carries the identity on every peer frame, request and reply, and gives the standby group its own identity.
