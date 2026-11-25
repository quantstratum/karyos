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
| W2 | see karyos#679 below |
| W3 | safety holds for every fault; every case but the leader crash completes. The leader crash is a liveness gap of the harness's client (it re-targets only on a redirect, and the crashed server 0 never restarts), allowed by the case |
| W4 | passes; repeated failed flushes (a lost durable majority) are a no-leader gap, as for the reference |
| W5 | snapshot cases not demonstrated (no compaction or install yet, karyos#679); the retry after a leader change keeps safety and does not show the deduplicated retry |
| W6 | passes, every case, four seeds |
| Determinism | a seed reproduces its run, observations included: both adapters run the C5 v2 manifest's timing, heartbeat 5 ticks and election timeouts in [15, 30) ticks. OpenRaft draws its timeout at every reset from the runtime's `thread_rng`, which the adapter seeds per node; raft-rs draws from an unseeded `rand::thread_rng`, so its range is one tick wide and each server has a fixed value in [15, 30), spread by its position in the voter set, no two equal (the manifest's fallback, reported as raft-rs's timing deviation) |
| Pre-vote | raft-rs's `pre_vote`, tested against a control without it, which a returning follower deposes |
| Allocation | **fails the gate**, measured in the simulator only: W1, 32 clients, seed 1: 113 entries past the warm-up, 5,701 allocations and 2,547 frees, 51 and 23 per entry. Messages pass in memory there, so raft-rs's protobuf encoding and decoding, which ADR-0043's replication boundary includes and the real-process path performs (`src/raft_rs.rs`, `Wire`), is not counted: the full-boundary figure is outstanding |
| Durability, recovery | the harness's C4 checks pass under W4's crashes and torn writes |
| Storage | raft-rs reads a `MemStorage` mirror of what C4 made durable; under declared limits the adapter reads each append's logged entries again through the harness's metered log before it leaves, and holds it back when the duty's budget cannot cover them (karyos#975) |
| Real processes | demonstrated: `tests/real_processes.rs` runs three `raft-eval-node` processes, each running `RaftRs` (the type the simulator tests drive, unchanged) through the harness's `drive`, over C4's log on real files (`StdDisk`) and UDP on the loopback; they elect a leader and all apply the same 20 commands in the same order. The runner maps 10 ms of the process clock to a tick: at 1 ms a tick an election times out before a vote's `fsync` and no leader is elected |
| Panics | raft-rs asserts its own invariants and unwraps its storage lock; none fired in these runs |

## Findings, `openraft` 0.10.0-alpha.37 on the manual executor (karyos#690)

| Gate or workload | Finding |
| --- | --- |
| Executor | feasible: every OpenRaft task runs on the node's executor inside the harness's calls, at most 4,096 polls a call; the virtual clock moves only on a tick; no call in the tests hit the budget |
| W1, W3, W4, W6 | the same results as `raft`, the same cases and seeds: W1, W4 and W6 pass, W3 keeps safety with the leader crash the harness client's gap, W4's lost durable majority a no-leader gap |
| W2, W5 | see karyos#679 below |
| Determinism | a seed reproduces its run, and the same calls reproduce every node's executor interleaving (trace digest), asserted |
| Pre-vote | OpenRaft's own pre-vote handler on the receiving node, reached through the adapter's RPC; never the trait's default, which synthesises a grant; tested against a control without it |
| Restart of a leader | the durable vote is C4's `HardState`, which has no place for OpenRaft's `committed` bit, so `enable_leader_restore` is off: a restarted leader always stands for a new election, as in standard Raft (a finding for the comparison) |
| Allocation | **fails the gate**, measured in the simulator only, at head 44dc4c88 (`tests/allocation.rs`, studiom4): W1, 32 clients, seed 1: 114 entries past the warm-up, 38,853 allocations and 32,521 frees, 341 and 286 per entry. All of OpenRaft's tasks run on the calling thread inside the core's calls, so the probe counts them. It also counts the adapter's request encoding in `step`, where `Request::eq` serializes both requests (`openraft_wire::request_bytes`) to correlate an answer; it does not count the real-process path's datagram framing and decoding. The figure moves with the adapter: earlier heads measured 44,710 and 41,035 allocations |
| Adapter settings | RPC answers wait at least 30 ticks, the longest election timeout (OpenRaft's sequential append stream does not time an RPC out, and its own 5-tick TTL is shorter than a round trip on the slower links); retries back off 5, 10, 20 then up to 30 ticks, scaled to the 5-tick heartbeat instead of OpenRaft's 200 ms default. The same for every workload |
| Real processes | demonstrated for every variant (C5 v2, "Processes"; karyos#691): `raft-eval-node` servers and `raft-eval-client` clients run raft-rs, OpenRaft (on its executor, inside the core's calls, its RPCs encoded by `openraft_wire` since OpenRaft's `serde` feature is not admitted) and the custom core (`custom_wire`) over real files, UDP between servers and TCP from clients. `tests/real_processes.rs` runs W1 on 3 and 5 processes and W2 on 3, each judged by `workloads::pass` over the merged, stamped histories (Linux: one host's `CLOCK_MONOTONIC`), and a 3- and 5-process smoke run of every variant on every platform, judged per server; each run reports the allocation probe per stage |

## Findings, W2 and W5 on both adapters (karyos#679)

The same cases, limits, schedules and seeds for both; nothing is tuned per
candidate (the parameters are plan issue 062's to freeze).

| Workload | `raft` 0.7.0 | `openraft` 0.10.0-alpha.37 |
| --- | --- | --- |
| W2 limits taken | `recover_with`: one entry per append and at most `in_flight_entries` appends unacknowledged; queue and in-flight bytes refused in `propose`; `in_flight_entries = 0` refused as `Unsupported` | `recover_with`: `max_payload_entries = in_flight_entries`, one append in flight per follower (its sequential stream); queue and in-flight bytes refused in `propose`; `in_flight_entries = 0` refused as `Unsupported` |
| W2 queue burst | refused with typed `Backpressure(Queue)`, nothing else refused; passes | the same; passes |
| W2 in-flight burst, nominal | pass | pass |
| W2 in-flight caps under delayed acknowledgements | **not strict**: raft-rs frees a full window's slot when a heartbeat answer arrives (its recovery from lost acknowledgements), so a second append can leave before the first is acknowledged, past both caps; pinned by `window::a_heartbeat_answer_frees_a_full_window_slot`; left to the candidate, since holding it in the adapter would stall a follower whose acknowledgements were lost (karyos#975) | **not strict across RPC timeouts**: one append in flight per follower while it is answered (its sequential stream), but the adapter fails an RPC after `RPC_TIMEOUT` ticks and OpenRaft then sends the next append while the first may still be in flight or unacknowledged; documented, not tested (karyos#975) |
| W2 slow follower | pass | **fail, typed**: `NotBehind`: the leader commits 787 of the 1,000 entries required while the follower is cut off, so the case cannot establish its slow follower |
| W2 log-read burst | **pass** on the metered bytes (karyos#975): the follower catches up under the 64 KiB per-duty budget, appends the budget cannot cover held back and resent by raft-rs | **fail, typed `NotBehind`** (karyos#1040): judged on the metered bytes, but the run commits only 842 of the 1,024 entries required while the follower is cut off, so the lag the burst reads back is never established |
| W2 log-read limit | **honoured through the harness's metered log** (karyos#975): each append's logged entries are read back through it and charged | **honoured through the harness's metered log** (karyos#1040): each append's logged entries are read back through it and charged; an append the budget cannot cover is lost and its RPC retried after the timeout |
| W2 in-flight bytes | not reached at 256 B payloads by W2 v1 (`W2::IN_FLIGHT_BYTES`). Neither candidate meters a follower's bytes in flight, so the adapter keeps the cap by entry size: a command over `in_flight_bytes / in_flight_entries` is refused with typed `Backpressure(InFlightBytes)`, even within the cap; asserted with 256 B values against 8 entries and 1 KiB | the same |
| W5 snapshot cases | `NotYet`: no compaction or install through the core; refused as `Unsupported`, follow-up plan issue 065 | the same |
| W5 lost reply, leader change, retry | runs, keeps safety, **retry not shown**: the frozen schedule assumes the reference's leader, server 0 from step 0; moved 30 steps later it shows the retry | runs, keeps safety, **retry not shown**: OpenRaft's first leader need not be server 0 |
| Reproducibility | every W2 case reproduces from its seed, asserted | the same |

**The custom core (ADR-0105).** W5's install part, `NotYet` for both
candidates above, runs through the custom core, which compacts, installs
and recovers over a snapshot (karyos#682): every W5 snapshot case passes on
every seed, each with a compaction, and only version 1's handover retry is
not demonstrated, since the core takes no handover
(`crates/karyos-sim/tests/custom.rs`,
`w5_snapshots_pass_and_the_handover_retry_is_not_demonstrated`); version 2's
retry relative to whoever leads is its own case
(`lost_reply_whoever_leads`). W2 under declared limits passes
(`tests/workloads.rs`, `custom_w2_honours_its_limits`), and the v2 byte
case reaches its bound within the cap (`tests/w2_bytes.rs`). On real
processes every W2 case passes for all three variants, raft-rs and
OpenRaft refusing the v2 byte case with a typed `InFlightBytes`
(`tests/real_processes.rs`, `w2_full`).

**Inputs to the C5 decision (karyos#691).** Weigh, besides the gates
above: the in-flight caps are **strict on neither candidate**: not on
`raft` 0.7.0 under acknowledgements delayed past a heartbeat (pinned by a
test), and not on OpenRaft across an RPC timeout (pinned by `tests/in_flight.rs`, karyos#1040); log
reads are metered through the harness for both (karyos#975,
karyos#1040); the log-read burst passes for raft-rs and fails typed
`NotBehind` for OpenRaft, which never builds the lag; the byte cap is kept by entry size in both (a command over its
share is refused even within the cap). Tracked in
karyos#975 (the first two).

## Candidate-backed negative cases of the harness checks (karyos#976)

`tests/checks.rs` wraps the `raft` adapter in mutants, each breaking one rule, and asserts the check that names it. Where no mutant exists, the check keeps its fixture negative case in `crates/karyos-sim/tests/harness.rs`, for the reason below. The C5 decision (#691) is asked to accept these reasons, or to name the fault injection that closes each.

| Check (`Violation`) | Candidate-backed | Reason when not |
| --- | --- | --- |
| `DivergentPrefix`, `ReplyBeforeDurableMajority`, `Contract` (gap), `OldTermCommit`, `Contract` (`TruncateBelowCommit`) | yes (karyos#678) | |
| `PositionsOutOfOrder` | yes: a core that reports no last index over a written log | |
| `CorePanicked` (karyos#976) | yes: a core that panics at its tenth Ready, caught at the harness's core boundary whatever the core; reported only when no other check names a cause | |
| `AppliedNotDurable` | yes, fault-injected (karyos#1038): a driver that applies a Ready's fresh entries before it writes them | |
| `ReleasedBeforePersisted` | yes, fault-injected (karyos#1038): a driver that releases `after_persist` before the sync | |
| `DivergentResponse` | yes, fault-injected (karyos#1038): one server's service alters its answers | |
| `NotLinearizable` | yes, fault-injected (karyos#1038): a client that records a read with a value no one wrote | |
| `DurableLost` | yes, fault-injected (karyos#976): a disk that acknowledges file syncs without making them durable, crashed and restarted; the restarted log no longer holds what was reported durable. The real core panics over the loss afterwards, and the harness now catches a core's panic at its core boundary (`Observation::CorePanicked`), so the run completes and the check sees what came before | |
| `CommittedTruncated` | yes (karyos#976): a server that never stores a commit, so C4's log has none to refuse, truncates entries the cluster applied. The run's first verdict is the contract breach that follows (its next append is not the next index), so the test asks `durable_kept` directly over the same run's observations | |
| `Undecided`, `MalformedHistory` | no | properties of C3 and of the client history the harness records, not of a core |
| `Unverified` | no | a run property (a crashed server never restarted), set by the case, not the core |
| `QuorumOfVoters`, `ConfigurationNotFromLog`, `ConfigurationConflict`, `LearnerBehind` | no | membership changes: ADR-0105 excludes them from the custom core, and neither candidate adapter takes a configuration change, so no core under evaluation can be driven to break them; they become reachable with dynamic membership (#711, with its own ADR) |
| `StandbyEffect`, `ReplyAfterFencing`, `OldGenerationReply`, `FeedMismatch`, `VerifiedLost`, `GapMisreported`, `GenerationBack` | no | the standby, lease and promotion path (W6) runs the harness's primary/standby feed and fencing around the core, not inside it; a core-side mutant cannot change what the feed or the lease releases |

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
