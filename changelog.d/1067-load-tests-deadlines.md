### Fixed

- Four tests that failed only on a loaded host now wait by deadline, not by a count of cycles, with their assertions kept:
  - `the_facade_removes_a_retired_images_subscription`: its rig waits for the driver to forget the registration, its waits are bounded at 120 s, and its client's liveness timeout matches them. The assertion now reports the stage, registrations and image count.
  - `colliding_aliases_on_one_multicast_group_keep_two_images_apart` and `a_client_sees_the_admission_change_by_event`: the e2e `pump` deadline is 120 s.
  - `a_shutdown_releases_the_group_integrity_journal_lock`: it waits for the agent's first record, written only under the lock, rather than for the file and a 1 ms sleep.
