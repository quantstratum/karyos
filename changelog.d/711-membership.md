### Added

- Dynamic membership and learners in the custom Raft core (`karyos_cluster::membership`, karyos#711).
  - **Mechanism.** Single-server changes with Ongaro's errata. `Core::propose_change` adds a learner, promotes one, or removes a member. It refuses with `ChangeError::InProgress` while a change is uncommitted or before the leader has committed an entry of its own term. It refuses with `Lagging` while the learner is further behind the commit than the given lag, and with `Invalid` for a change that does not apply.
  - **When it takes effect.** A configuration applies as soon as its entry is in the log, committed or not. A follower's driver reports the entry (`Core::configured`), and a truncation restores the configuration before it.
  - **Learners.** Learners receive every append and snapshot, count toward no quorum, and never stand for election.
  - **Removed leader.** A leader steps down once its own removal commits.
  - **Snapshots.** The membership at a snapshot's base is restored with it (`Core::restore_membership`).
  - **Log entry.** A configuration entry is the core's own entry, schema 5 template 2 (`MembershipEntry`), and the service container delivers nothing for it.
  - **Simulator.** Its custom-core adapter runs the P5-S1 scenarios against this code. That includes a learner that learns its membership from a snapshot after a purge.
