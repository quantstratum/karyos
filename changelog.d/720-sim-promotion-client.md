### Added

- The simulator runs the Cluster client (`ClusterClient`) through a standby promotion: a harness client whose failover is the Cluster client's reaches the old primary and the promoted standby, with no command applied twice, each request in flight at the change reported unknown and sent again only by its caller's retry, and generation 1 answers refused once generation 2 is seen (karyos#720).
