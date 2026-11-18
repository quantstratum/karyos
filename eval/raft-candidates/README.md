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

## Evaluation manifest

| Item | Value |
| --- | --- |
| `raft` | `=0.7.0`, default features off, `protobuf-codec` (`raft-proto` 0.7.0, `protobuf` 2.28.0) |
| Variant | baseline: the crates.io release, no local patch (`raft_rs::VARIANT`) |
| Patch records | none |
| `protoc` (condition 5) | 3.9.0, the prebuilt binary bundled in `protobuf-build` 0.14.1 from crates.io (checksum pinned by `Cargo.lock`); `protoc-osx-x86_64` (SHA-256 `5baf2162793b6608f2361c083c53e276ea84c2ed2adcf400ec07bb524399f4dc`), on macOS aarch64 a native protoc 3.x is preferred (Homebrew's `protobuf@21`, libprotoc 3.21, then a 3.x `protoc` on `PATH`), then that x86_64 binary under Rosetta 2; with none of them `check.sh` fails and says how to get one, it never skips; `protoc-linux-x86_64` or `protoc-linux-aarch_64` on Linux. `PROTOC` overrides it (a path or a command on `PATH`, resolved to an absolute file). `check.sh` refuses anything but 3.1 or later in 3.x before building and prints the version, path and SHA-256 it used. A system `protoc` 4.x or later is refused by `raft-proto` |
| Toolchain | the repository's `rust-toolchain.toml` (1.99.0) |
| Advisories ignored here only (condition 4) | RUSTSEC-2024-0437 (`protobuf` 2.28.0), RUSTSEC-2025-0057 (`fxhash` 0.2.1) |

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
| Allocation | **fails the gate**: W1, 32 clients, seed 1: 113 entries past the warm-up, 5,701 allocations and 2,547 frees, 51 and 23 per entry |
| Durability, recovery | the harness's C4 checks pass under W4's crashes and torn writes |
| Storage | raft-rs reads a `MemStorage` mirror of what C4 made durable, so the harness's metered log reads do not see its reads |
| Real processes | demonstrated: `tests/real_processes.rs` runs three `raft-eval-node` processes, each running `RaftRs` (the type the simulator tests drive, unchanged) through the harness's `drive`, over C4's log on real files (`StdDisk`) and UDP on the loopback; they elect a leader and all apply the same 20 commands in the same order. The runner maps 10 ms of the process clock to a tick: at 1 ms a tick an election times out before a vote's `fsync` and no leader is elected |
| Panics | raft-rs asserts its own invariants and unwraps its storage lock; none fired in these runs |
