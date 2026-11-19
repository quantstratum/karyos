<!-- SPDX-License-Identifier: Apache-2.0 -->

# Raft candidates: evaluation workspace

Adapters of ADR-0043's Raft candidates behind the C5 harness's
`ConsensusCore` (`crates/karyos-sim/src/harness/core.rs`). **Evaluation
only**: this crate is its own workspace with its own `Cargo.lock` and
`deny.toml`, is never published, and no crate of the core depends on it
(quantstratum-docs:
karyos/reviews/dependency-admission-raft-candidates-evaluation.md;
`make shipped-graph-check` proves it). Nothing here selects a core, and
the runtime admission of the selected core is a separate record.

Run it with `make raft-eval` from the repository root (part of
`make pre-push`), which runs `check.sh`: format, clippy, docs and tests,
all `--locked`.

**Its lockfile follows the workspace.** This workspace depends on
workspace crates (`karyos-sim`, `karyos-cluster`), so a PR that changes
the workspace dependency graph also refreshes `Cargo.lock` here, offline,
to the workspace's exact pins (`cargo metadata --offline` in this
directory); `make raft-eval` runs `--locked` and fails otherwise
(`rules/global_rules.md`, Dependencies).

## Evaluation manifest

| Item | Value |
| --- | --- |
| `raft` | `=0.7.0`, default features off, `protobuf-codec` (`raft-proto` 0.7.0, `protobuf` 2.28.0) |
| `openraft` | `=0.10.0-alpha.37`, default features off (no `tokio-rt`), with `openraft-rt` `=0.10.0-alpha.37`; `openraft-macros` pinned to 0.10.0-alpha.37 in `Cargo.lock` |
| Runtime | `executor::SimRuntime`: the bounded, manually pumped executor behind `openraft-rt`'s `AsyncRuntime`; no Tokio anywhere in the graph (`check.sh` fails if one appears) |
| Variant | baseline for both: the crates.io releases, no local patch (`raft_rs::VARIANT`, `openraft_core::VARIANT`) |
| Patch records | none |
| `protoc` (condition 5) | 3.9.0, the prebuilt binary bundled in `protobuf-build` 0.14.1 from crates.io (checksum pinned by `Cargo.lock`); `protoc-osx-x86_64` (SHA-256 `5baf2162793b6608f2361c083c53e276ea84c2ed2adcf400ec07bb524399f4dc`), on macOS aarch64 a native protoc 3.x is preferred (Homebrew's `protobuf@21`, libprotoc 3.21, then a 3.x `protoc` on `PATH`), then that x86_64 binary under Rosetta 2; with none of them `check.sh` fails and says how to get one, it never skips; `protoc-linux-x86_64` or `protoc-linux-aarch_64` on Linux. `PROTOC` overrides it (a path or a command on `PATH`, resolved to an absolute file). `check.sh` refuses anything but 3.1 or later in 3.x before building and prints the version, path and SHA-256 it used. A system `protoc` 4.x or later is refused by `raft-proto` |
| Toolchain | the repository's `rust-toolchain.toml` (1.99.0) |
| Advisories ignored here only (condition 4) | RUSTSEC-2024-0437 (`protobuf` 2.28.0), RUSTSEC-2025-0057 (`fxhash` 0.2.1) |
| Advisory amended in (karyos#690) | RUSTSEC-2026-0543, see below |

## Findings, `raft` 0.7.0 (karyos#678)

| Gate or workload | Finding |
| --- | --- |
| W1 | passes, every skeleton case, four seeds |
| W2 | not demonstrated: the adapter takes no declared limits yet (karyos#679) |
| W3 | safety holds for every fault; every case but the leader crash completes. The leader crash is a liveness gap of the harness's client (it re-targets only on a redirect, and the crashed server 0 never restarts), allowed by the case |
| W4 | passes; repeated failed flushes (a lost durable majority) are a no-leader gap, as for the reference |
| W5 | snapshot cases not demonstrated (no compaction or install yet, karyos#679); the retry after a leader change keeps safety and does not show the deduplicated retry |
| W6 | passes, every case, four seeds |
| Determinism | a seed reproduces its run, observations included: the election timeout range is one tick wide, so raft-rs's `thread_rng` draw has one value; timeouts are staggered by each node's position in the voter set, so no two voters share one |
| Pre-vote | raft-rs's `pre_vote`, tested against a control without it, which a returning follower deposes |
| Allocation | **fails the gate**, measured in the simulator only: W1, 32 clients, seed 1: 113 entries past the warm-up, 5,701 allocations and 2,547 frees, 51 and 23 per entry. Messages pass in memory there, so raft-rs's protobuf encoding and decoding, which ADR-0043's replication boundary includes and the real-process path performs (`src/raft_rs.rs`, `Wire`), is not counted: the full-boundary figure is outstanding |
| Durability, recovery | the harness's C4 checks pass under W4's crashes and torn writes |
| Storage | raft-rs reads a `MemStorage` mirror of what C4 made durable, so the harness's metered log reads do not see its reads |
| Real processes | demonstrated: `tests/real_processes.rs` runs three `raft-eval-node` processes, each running `RaftRs` (the type the simulator tests drive, unchanged) through the harness's `drive`, over C4's log on real files (`StdDisk`) and UDP on the loopback; they elect a leader and all apply the same 20 commands in the same order. The runner maps 10 ms of the process clock to a tick: at 1 ms a tick an election times out before a vote's `fsync` and no leader is elected |
| Panics | raft-rs asserts its own invariants and unwraps its storage lock; none fired in these runs |

## Findings, `openraft` 0.10.0-alpha.37 on the manual executor (karyos#690)

| Gate or workload | Finding |
| --- | --- |
| Executor | feasible: every OpenRaft task runs on the node's executor inside the harness's calls, at most 4,096 polls a call; the virtual clock moves only on a tick; no call in the tests hit the budget |
| W1, W3, W4, W6 | the same results as `raft`, the same cases and seeds: W1, W4 and W6 pass, W3 keeps safety with the leader crash the harness client's gap, W4's lost durable majority a no-leader gap |
| W2, W5 | as for `raft`: not demonstrated yet (karyos#679) |
| Determinism | a seed reproduces its run, and the same calls reproduce every node's executor interleaving (trace digest), asserted |
| Pre-vote | OpenRaft's own pre-vote handler on the receiving node, reached through the adapter's RPC; never the trait's default, which synthesises a grant; tested against a control without it |
| Restart of a leader | the durable vote is C4's `HardState`, which has no place for OpenRaft's `committed` bit, so `enable_leader_restore` is off: a restarted leader always stands for a new election, as in standard Raft (a finding for the comparison) |
| Allocation | **fails the gate**, measured in the simulator only, at head 44dc4c88 (`tests/allocation.rs`, studiom4): W1, 32 clients, seed 1: 114 entries past the warm-up, 38,853 allocations and 32,521 frees, 341 and 286 per entry. All of OpenRaft's tasks run on the calling thread inside the core's calls, so the probe counts them. It also counts the adapter's request encoding in `step`, where `Request::eq` serializes both requests (`openraft_wire::request_bytes`) to correlate an answer; it does not count the real-process path's datagram framing and decoding. The figure moves with the adapter: earlier heads measured 44,710 and 41,035 allocations |
| Adapter settings | RPC answers wait at least 20 ticks (OpenRaft's sequential append stream does not time an RPC out, and its own 2-tick TTL is shorter than a round trip on the slower links); retries back off 2, 4, 8 then up to 20 ticks, scaled to the 2-tick heartbeat instead of OpenRaft's 200 ms default. The same for every workload |
| Real processes | demonstrated: three `raft-eval-node openraft` processes run `OpenRaft`, unchanged, on its executor inside the core's calls (no runtime of the process's own), over real files and UDP; its RPCs are encoded by the adapter (`openraft_wire`), since OpenRaft's `serde` feature is not admitted. They elect a leader and apply the same 20 commands in the same order |

## Amendment: RUSTSEC-2026-0543 (`chrono` unmaintained), karyos#690

Published after the admission record, which found no advisory in the
`openraft` graph. Handled as an explicitly reviewed amendment of that
evaluation admission, never as a workspace waiver.

- **Path.** `chrono` 0.4.45 is a **non-optional** `[dependencies]` entry
  of `openraft` 0.10.0-alpha.37 and of its proc macro `openraft-macros`
  0.10.0-alpha.37 (requirement `0.4`, default features).
  `cargo tree -i chrono -e normal,build` shows those two as the only paths
  (verified at 0.10.0-alpha.37). `Cargo.lock` resolves `display-more`
  0.2.7, which has no dependency on `chrono`. Features resolved: `default`, `std`, `alloc`,
  `clock`, `now`, `oldtime`, `iana-time-zone`, `wasmbind`, `winapi`,
  `windows-link` (the last three only on wasm32 and Windows targets).
  Targets: every target; on the supported Linux and macOS ones it builds
  `chrono` and `iana-time-zone` (with `core-foundation-sys` on macOS).
- **Why evaluation still needs it.** `openraft` and `openraft-macros` depend on `chrono` directly
  and unconditionally, with no feature to turn it off. Removing it means
  replacing or patching `openraft`, which would no longer be the admitted
  baseline. The evaluation keeps the baseline and records the advisory as
  a finding of the comparison and an input to the runtime admission (plan
  issue 074).
- **Isolation.** Only this workspace resolves it: no crate of the core
  depends on `karyos-raft-eval`, and `make shipped-graph-check` refuses
  `openraft`, `openraft-macros` and `openraft-rt` in every shipped graph.
- **The exception.** `deny.toml` here ignores exactly RUSTSEC-2026-0543,
  with this reason; the core's `deny.toml` is untouched.
- **Provenance.** Codex agreed the route (process only) in ACS 77218;
  the owner admitted the evaluation graph with `chrono`, evaluation scope
  only, in karyos#959 (issuecomment-6976562162).
- **Upstream.** databendlabs/openraft#2387, "remove the chrono
  dependency", merged to main on 2026-11-18 (closes #2384), is not yet
  released: `openraft` 0.10.0 on crates.io still depends on `chrono`. This
  stack keeps the admitted baseline, 0.10.0-alpha.37, and does not move to
  0.10.0.
- **Expiry.** The owner's admission, and with it the ignore, ends at the
  first of: `openraft` dropping `chrono` (a release containing #2387,
  expected 0.10.1, confirmed by an empty
  `cargo tree -i chrono -e normal,build`); any change of the `openraft`
  version, which re-reviews the advisory against the new graph rather
  than carrying the ignore over; or the comparison's freeze (plan issue
  062).
