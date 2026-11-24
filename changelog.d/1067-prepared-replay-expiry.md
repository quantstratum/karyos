### Fixed

- `a_prepared_replay_never_attached_expires` no longer fails on a loaded host (karyos#1067): it reads its clock before posting the replay that expires, so the agent stamps that replay after the read on the same monotonic clock, and it checks that the slot comes back no earlier than the 200 ms timeout. It used to read the clock after two round trips to the agent and check for 100 ms, which a slow test thread could eat.
