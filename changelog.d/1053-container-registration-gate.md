### Added

- `ServiceContainer::propose` enforces ADR-0087's registration gate for every host: a leader whose log has not applied the session bounds proposes no `Register` and gets `ProposeRefused::BoundsPending` (retryable; the host holds or refuses it), so no registration precedes the first `SessionBounds` entry. `Propose` gains a provided `leads` method, `true` by default, so a follower's registration still reaches its core and is refused with the leader's hint. The simulator's delivery harness now goes through this gate instead of its own check (karyos#1053).
