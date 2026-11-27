### Fixed

- A node takes an append of at least its own term from any sender, voter, learner or outside its configuration, as from that term's leader, so a leader elected without a minority's uncommitted change truncates it and the cluster stops diverging; every other message from outside the configuration is still refused (ADR-0125, karyos#711).
