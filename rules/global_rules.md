<!-- SPDX-License-Identifier: Apache-2.0 -->

# Global rules for karyos

Rules for writing Rust in the Karyos core: a low-latency messaging
transport over shared memory and UDP (`karyos-sys`, `karyos-io`,
`karyos-protocol`, `karyos-codec`, `karyos-client`, `karyos-driver`,
`karyos-trace`, `karyos-archive`, `karyos-cluster`, `karyos-feed`,
`karyos-sim`, `karyos`, `karyos-agent`, `karyos-tools`, `karyos-ffi`,
`karyos-bench`). The specification and the ADRs live in
`quantstratum-docs` (`karyos/SPEC.md`, `karyos/adr/`, `karyos/design/`);
this file cites them as `SPEC.md §N` and `ADR-NNNN`. `make pre-push`
enforces what a tool can check; review enforces the rest.

---

## Language and writing

- Everything in English: code, comments, docs, commit messages, PR
  descriptions and issue text (SPEC.md §14).
- No em dashes or en dashes in prose, and no hyphen joining two clauses.
  Use a period, a colon or a semicolon. Hyphens stay valid in code,
  paths, CLI flags, compound words and Markdown list markers.
- Every file starts with its SPDX line: `// SPDX-License-Identifier:
  Apache-2.0` in Rust, `# SPDX-License-Identifier: Apache-2.0` in TOML,
  shell and Makefiles, `<!-- SPDX-License-Identifier: Apache-2.0 -->` in
  Markdown.
  Exception: a changelog fragment, `changelog.d/<issue>-<slug>.md`, starts
  with its section header and carries no SPDX line, because
  `scripts/changelog-assemble.sh` requires the header first and folds the
  fragment into `CHANGELOG.md` (which has its own SPDX line) and deletes it
  at release. `changelog.d/README.md` keeps its SPDX line.
- Live documents cite the specification by section and paragraph name
  (`SPEC.md §10.2`, "Versioning"), never by an unpinned line number.
  Design documents are cited as `quantstratum-docs: karyos/design/<file>.md`.
- An Accepted ADR changes only through a later ADR in `quantstratum-docs`
  that amends named text; code and docs here never restate an ADR as if
  it said something else.

---

## Panics: only in tests (owner rule)

Panics are allowed ONLY in tests: `#[cfg(test)]` modules, the `tests/`
directories, and test-only helpers behind a `test-hooks` feature. Library
code, binaries (`karyosd`, `karyos-agent`, `karyos-exporter`, the
`karyos-tools` binaries), `karyos-bench` outside its tests, and build
scripts never panic. A malformed frame, a corrupt mapping, a hostile peer
or an exhausted table is a typed error, a counter and a refusal; never a
panic (ADR-0007, SPEC.md §2 principle 11).

Forbidden outside tests:

- `unwrap()`, `expect()`, `unwrap_unchecked` on `Option` and `Result`.
- `panic!`, `unreachable!`, `todo!`, `unimplemented!`.
- `assert!`, `assert_eq!`, `assert_ne!` and every `debug_assert*!` at run
  time. A compile-time check in a const item, `const _: () = {
  assert!(...); };` (the layout checks of
  `karyos-sys/src/log_buffer/storage.rs`), fails the build, not the
  process, and is allowed.
- Unchecked indexing or slicing: `buf[i]`, `buf[a..b]`, `map[&key]`. Use
  `.get()`, `.get_mut()`, `.split_at_checked()`, `.first()`, `chunks_exact`
  and pattern matching.
- APIs that panic on a violated precondition: `split_at`,
  `copy_from_slice` on lengths not proven equal, `Duration` arithmetic
  operators, `Vec::remove` and `insert` out of range, integer `/` and `%`
  with a divisor that can be zero.
- Arithmetic that can overflow: `+`, `-`, `*`, `<<` on positions, lengths,
  offsets and counters (see Arithmetic).
- `RefCell::borrow` and `borrow_mut`: use `try_borrow` and
  `try_borrow_mut` and map the failure to an error.
- `as` casts that truncate or change sign on values that can be out of
  range: use `u32::try_from` and friends.

How the lint configuration enforces it:

- `[workspace.lints.clippy]` in `Cargo.toml` denies `unwrap_used`,
  `expect_used`, `indexing_slicing`, `panic`, `todo`, `unimplemented`,
  `dbg_macro`, `print_stdout` and `print_stderr`. Every crate inherits it
  with `[lints] workspace = true`, except `karyos-sys`, `karyos-io` and
  `karyos-ffi`, which repeat the same clippy set in their own `[lints.clippy]`
  because they cannot inherit `unsafe_code = "forbid"`. `make lint-sync`
  (`scripts/check-lint-sync.sh`) fails if any workspace clippy lint is
  missing from one of those three crates; a lint added to the workspace is
  added to all three in the same change.
- `make lint` and `make lint-linux` run clippy with `-D warnings`, so a
  denied lint fails the gate.
- `clippy.toml` sets `allow-unwrap-in-tests`, `allow-expect-in-tests`,
  `allow-indexing-slicing-in-tests` and `allow-panic-in-tests` (ADR-0007).
  These exemptions cover `#[test]` functions. Helper functions in a test
  module and integration test files outside a `#[test]` function are not
  covered: they carry an explicit `#![allow(clippy::unwrap_used,
  reason = "tests, as ADR-0007 allows")]` (or the needed subset with
  `clippy::panic`, `clippy::indexing_slicing`) on a module that is itself
  `#[cfg(test)]`, or at the top of a file under `tests/`.
- NOT linted, enforced in review: `unreachable!`, `assert!` and
  `assert_eq!` / `assert_ne!`, `debug_assert*!`, overflowing arithmetic
  (`arithmetic_side_effects` is not enabled), panicking std APIs
  (`split_at`, `copy_from_slice`), `RefCell::borrow_mut`, truncating `as`
  casts and `map[&key]`. ADR-0007 states the same limit: lints see direct
  constructs, not a panic inside a called API.
- SPEC.md §14 and ADR-0007 still name `debug_assert!` for internal
  invariants. The owner rule is stricter and governs new code: express
  the invariant in a type, or return a typed error. Existing
  `debug_assert!` and `unreachable!` sites in library code are debt; do
  not add more, and replace one when you change the code around it.
- An `#[allow]` or `#[expect]` of `unwrap_used`, `expect_used`, `panic` or
  `indexing_slicing` on non-test code is a review blocker.
- `karyos-ffi` catches unwinding at every exported function
  (`src/boundary.rs`, `catch_unwind`), returns `KARYOS_E_INTERNAL` and
  poisons the handle (SPEC.md §10.2). That is a last line of defence, not
  permission to panic. It works only if `libkaryos` unwinds: no workspace
  profile ever sets `panic = "abort"`, and `make lint-sync` checks it.

---

## Compiler Attributes

### #[must_use]
- Every pure function, every constructor and conversion, and every
  `Result` or outcome a caller must handle: `offer`, `try_claim`,
  `commit`, `poll` results, `Accepted`, refusals (SPEC.md §10, ADR-0007).
- Builder methods; SPEC.md §14 gives the message
  `"builders do nothing unless .build() is called"`.

### #[inline] / #[inline(always)] / #[inline(never)] / #[cold]
- `#[inline]`: accessors, newtype conversions, flyweight field reads and
  writes, small validation helpers.
- `#[inline(always)]`: only the copy loops and the frame-scan loops
  (SPEC.md §14), and only with a `karyos-bench` or Criterion result.
- `#[inline(never)]` and `#[cold]`: error construction, logging and I/O
  setup on the control path.

### #[repr]
- `#[repr(u8)]` / `#[repr(u16)]` on enums with stable wire values.
- No `#[repr(C)]` wire structs, no transmutes: wire fields are
  little-endian at fixed offsets, read and written through flyweights
  (SPEC.md §2 principle 10, ADR-0014).
- `#[repr(C)]` is used for exactly two things: the C ABI structs of
  `karyos-ffi/src/abi.rs`, and the shared-memory overlays of `karyos-sys`
  whose layout is pinned by const assertions.

### #[derive] order
```
Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default
```
then `thiserror::Error` last on error enums. Derive only what is needed:
no `Ord` without a meaningful order, no `Default` without a sensible
default, `Copy` only on small plain values.

### #[non_exhaustive]
- On public error enums, outcome enums and option structs that may grow
  (`karyos::Error`, `ErrorCode`). A public input struct marked
  `#[non_exhaustive]` gets a constructor.

---

## Type Safety

- Every identifier and size is a newtype with private fields and `new` /
  `try_new` returning `Result`: `StreamId`, `SessionId`, `Position`,
  `TermId`, `TermLength`, `Lane`, `MessageLength`, `FragmentLimit`
  (SPEC.md §10).
- `NonZero*` where zero is structurally invalid: term length, MTU, lanes,
  fragment limits, counts of slots and paths.
- No magic numbers: named constants (`FRAME_ALIGNMENT`, `HEADER_LENGTH`,
  `DEFAULT_MTU`).
- Karyos carries encoded bytes and holds no monetary values:
  `rust_decimal` does not apply. Prices travel as the application codec's
  fixed-point integers.
- The data path API is synchronous; there is no `async` or `tokio` in the
  workspace.

---

## Arithmetic

- Positions, lengths, offsets, term ids, counters and anything read from
  the wire or from a shared mapping: `checked_add`, `checked_sub`,
  `checked_mul`, `checked_div`, with overflow surfaced as a typed error
  (ADR-0007, SPEC.md §2 principle 5).
- Release builds do not check overflow: an unchecked `+` there wraps
  silently, which is worse than a panic. Never rely on it.
- SPEC.md §14 forbids `saturating_*` and `wrapping_*` for these values.
  The deliberate exceptions are documented at their site: term id
  rollover in `karyos-sys/src/term.rs`, hashes and the RNG of
  `karyos-sim`. A new exception carries a comment that names why
  modular or saturating arithmetic is the definition.
- Check at the edges: validate a frame's lengths and offsets once, then
  inner loops work on the validated range with no per-element checks.

---

## Error Handling

- `thiserror` enums per module (`SysError`, `DriverError`,
  `ArchiveError`, `OfferError`, `CncError`, ...), aggregated in the
  `karyos` facade into `karyos::Error` with `#[from]` (SPEC.md §10, §14).
  Lower layers never depend on the facade.
- No `anyhow`, no `Box<dyn Error>` in public signatures, no stringly
  errors.
- Messages: lowercase, include the offending value
  (`"message type {type_id:#x} sets a reserved value"`).
- Hot-path errors carry bounded `Copy` fields; formatting happens on the
  control path.
- `.ok_or_else()` / `.ok_or()` for `Option` to `Result`.
- CnC wire codes (`karyos-protocol/src/cnc.rs`: `ErrorCode`,
  `RejoinPolicyCode`, `FallbackReasonCode`, ...) are stable and never
  reused or renumbered. A new `ErrorCode` value is reserved first in the
  team note `karyos/cnc-error-code-reservations`, so that open PRs do not
  collide (codes 19 to 23 were held for the rate errors while 24 went to
  `StreamTooLarge`).
- C ABI status codes keep their ranges (`include/karyos.h`): 0 success,
  1 to 99 data-path outcomes, 100 to 199 usage, 200 to 299 lifecycle,
  300 to 399 resource and driver, 400 to 499 compatibility, 500 internal.
  A new code goes in its range; a value is never reused.

---

## unsafe

- `unsafe` lives only in `karyos-sys` and `karyos-io`, and in the boundary
  module `karyos-ffi/src/abi.rs` (SPEC.md §2 principle 1, §14; ADR-0006,
  ADR-0053). Every other crate inherits `unsafe_code = "forbid"`.
- `karyos-sys`, `karyos-io` and `karyos-ffi` deny
  `unsafe_op_in_unsafe_fn`, `undocumented_unsafe_blocks`,
  `multiple_unsafe_ops_per_block` and `missing_safety_doc`: every `unsafe`
  block has a `// SAFETY:` comment stating the invariant it relies on and
  holds a single unsafe operation.
- No `unsafe fn` in a public API. Unsafe code sits in small named modules
  (`mmap.rs`, `atomic_view.rs`, ...) a reviewer can read in full.
- `karyos-ffi` sets `unsafe_code = "deny"` and `#![deny(unsafe_code)]`;
  only `mod abi` (and `tests/support/abi.rs`) carries
  `#[expect(unsafe_code, reason = "...")]`. `#[allow(unsafe_code)]` is
  never used. `make lint-sync` checks all of it.
- A PR touching `karyos-sys`, `karyos-io` or `karyos-ffi/src/abi.rs` needs
  an ADR-0034 review record: exact revision, reviewer or review session
  (an AI review is named as one), affected safety invariants, evidence
  inspected, each finding and its disposition. A material change after
  review needs renewed review; an unresolved safety finding blocks merge.
- A PR that touches `karyos-ffi/src/abi.rs` runs Miri per
  `crates/karyos-ffi/MIRI.md` on its head and posts the output; a new
  unsafe site class adds its row to MIRI.md and a test that runs under
  Miri, or states why none can.
- `make unsafe-report` tracks the unsafe surface; it is a report, not a
  gate.

---

## Data Path Discipline

The data path is offer, claim, commit, poll, send, receive and
completion handling (ADR-0008).

- Zero allocation: buffers, rings, term slots and tables are created and
  prefaulted on the control path. The data path never allocates,
  reallocates, frees or maps, on error, rotation, backpressure, abort and
  cutover paths included (SPEC.md §2 principle 4).
- That is tested, not assumed: `karyos_sys::alloc_count::CountingAllocator`
  is installed as the test binary's global allocator and the call is
  wrapped in `alloc_count::count` (karyos-client, -driver, -protocol, -io,
  -feed, -archive and karyos-sys tests). A change to a data-path call
  keeps its no-allocation test green, and a new data-path call gets one.
- No blocking locks on the data path; one writer per mutable payload
  range; shared words use verified atomic protocols.
- Bounded work: every data-path operation has a budget of frames, bytes
  and retries. `offer` never blocks and has no unbounded loop; it returns
  a result the caller must handle (SPEC.md §2 principle 6).
- Nothing logs on the data path. Failures increment counters and publish
  bounded diagnostic records (principle 11).
- Prefer monomorphized generics over `dyn` on hot paths; pad hot atomics
  against false sharing.
- A performance claim comes with a `karyos-bench` or Criterion result
  (principle 2). Timing runs use a timing build: `make
  timing-build-check` refuses an `alloc-count` or `synthetic` build.

---

## Concurrency and Verification

- Atomics in `karyos-sys` come from `crate::sync`, which re-exports Loom's
  atomics under `--cfg loom` and `std`'s otherwise. A new concurrent
  protocol gets a Loom model in `crates/karyos-sys/tests/loom_*.rs`.
- `make loom` runs the Loom models (part of `make pre-push`). A PR that
  touches the counters seqlock or its layout (`crates/*/src/counters*`,
  `crates/karyos-sys/tests/loom_counters.rs`) cites a green
  `make loom-full` run on its exact head (Makefile).
- `make miri` runs `karyos-sys --lib` and `karyos-ffi` under the nightly
  pinned as `MIRI_TOOLCHAIN` in the Makefile. Tests that cannot run under
  Miri say why: `#[cfg_attr(miri, ignore = "...")]` or `not(miri)`.
- Agents own their threads; the default idle strategy is
  `YieldThenSleep` (ADR-0066); busy-spin is an explicit choice.

---

## C ABI (karyos-ffi)

- Every object is a 64-bit handle (table index plus generation), never a
  pointer; a stale handle returns `KARYOS_E_CLOSED`, never undefined
  behaviour (SPEC.md §10.2).
- Functions return an `int32_t` status; outputs go through out-parameters
  checked for null and alignment before any write. No global or
  thread-local error state.
- `include/karyos.h` is hand-written; `src/header.rs` checks it against
  `abi.rs` (functions, C types, status codes, ABI version). Change both
  together.
- The ABI has its own version (`KARYOS_ABI_VERSION_*`, today 0.1.5).
  `crates/karyos-ffi/abi/manifest.txt` records every struct's size,
  alignment and offsets, every constant and every declaration.
  `make abi-manifest-check` (in pre-push) fails when the header no longer
  matches it; regenerate it with
  `scripts/abi-manifest.sh | grep -v '^target=' > crates/karyos-ffi/abi/manifest.txt`
  in the same change. A manifest that differs from the last released one
  (`abi/released/<abi>.txt`) needs a higher ABI version; removing or
  changing an exported symbol needs a new major version. Structs that may
  grow carry a leading `size` field.
- The conformance suite lives in `crates/karyos-ffi/conformance/`
  (ADR-0067, ADR-0073); a behaviour change visible through the ABI updates
  its scenarios.

---

## Logging and Output

- Library crates do not log and never install a `tracing` subscriber.
  `tracing` and `tracing-subscriber` are admitted for `karyos-tools` only
  (`deps/dependencies.md`): control-path logs of the binaries, with
  structured fields.
- `println!`, `eprintln!`, `print!` and `dbg!` are denied
  (`print_stdout`, `print_stderr`, `dbg_macro`). Binaries write through
  `std::io::stdout()` / `stderr()` with `writeln!`, and handle the result.
- Never log or record secrets, signing keys or personal data. HTTP
  requests to registries carry a User-Agent that names the project
  (`https://github.com/quantstratum/karyos`), never an email
  (RELEASING.md, Registry check).

---

## Documentation

- `missing_docs = "deny"`: every `pub` item has a `///` doc comment with a
  one-line summary, a `# Errors` section on fallible functions and units
  (ns, bytes, frames). `make doc` builds the docs with
  `RUSTDOCFLAGS="-D warnings"`.
- `unsafe fn` and unsafe traits carry `# Safety` (`missing_safety_doc`).
- Doc examples use `?`, never `.unwrap()`.
- Module docs cite their design source (`quantstratum-docs:
  karyos/design/<file>.md`) and the issue or decision that shaped them.

---

## Testing

- Unit tests next to the code: `#[cfg(test)] mod tests` inline or in a
  `tests.rs` beside the module. Cross-crate and process tests under
  `tests/`.
- Test names are sentences of the behaviour checked:
  `a_null_or_misaligned_out_parameter_is_refused_with_nothing_written`,
  not `test_connect`.
- Every error path a function documents is tested, and a bug fix comes
  with a test that fails without it.
- Malformed input: proptest properties for every parser and frame helper
  that takes untrusted lengths or offsets (ADR-0007, ADR-0062).
- Test-only hooks live behind each crate's `test-hooks` feature, enabled
  only from `dev-dependencies`, never in a release build.
- The simulator is deterministic: `make sim` sweeps seeds 1 to 2000
  (`KARYOS_SIM_SEED`, `KARYOS_SIM_SEEDS`).
- Linux-only code (`cfg(target_os = "linux")`) is compiled out of the
  macOS gate. `make lint-linux` lints it from any host; a PR that touches
  karyos-sys, -driver, -client, -agent or -tools also runs
  `scripts/linux-test.sh --workspace --all-features --locked --no-fail-fast`
  in Docker.
- A Linux or netem run that counts for a PR uses an empty target volume of
  its own: `docker volume rm karyos-linux-target-pr<N>-<sha8>`, then
  `KARYOS_LINUX_TARGET=karyos-linux-target-pr<N>-<sha8> scripts/linux-test.sh ...`
  (the issue number before the PR exists), and the PR names the volume.
  Never `docker system prune` or `docker volume prune`; remove only your
  own volume, by exact name.
- One heavy gate (`make pre-push`, a linux-test, a netem run) at a time per
  session on a shared host. Never stop another session's gate by name
  (`pkill -f`); stop your own by PID.
- An unavailable environment is recorded as untested, never as a pass
  (ADR-0034).

---

## Dependencies

- A new direct dependency family, a scope widening or a policy exception
  is admitted only by consensus of the Claude and Codex review sessions,
  with evidence under performance, licence, maintenance, security and
  supply chain, and need (R8, ADR-0070, amending ADR-0033). Ask before
  adding any dependency.
- Before code using it merges: its exact version, source, features,
  targets and scope are recorded in `deps/dependencies.md`,
  `make deps-inventory` regenerates `deps/dependency-inventory.json`, and
  `Cargo.lock` is committed. `make deps-check` (in pre-push) fails on a
  stale inventory.
- Every cargo build, lint and test command of the gate runs with `--locked`.
- `deny.toml` holds the licence allowlist, source policy and advisory
  policy (`make deny`). CI checks licences, bans and sources in one job
  and RustSec advisories in a separate `Advisories` job, because the
  advisory database changes without a repository change; `make pre-push`
  stays offline and does not run `cargo deny` (karyos#933). No C or C++ toolchain in the workspace build (ADR-0006):
  a crate whose build script compiles C is refused.
- `loom`, `proptest` and `criterion` are dev only; `loom` builds only
  under `--cfg loom`.

---

## Changelog and Releases

- PRs never edit `CHANGELOG.md` (CONTRIBUTING.md). A change adds
  `changelog.d/<issue>-<slug>.md` holding exactly one section header
  (`### Added`, `Changed`, `Deprecated`, `Removed`, `Fixed` or
  `Security`) and its entries, written as they will read in the
  changelog. A change with entries in two sections uses two files.
- A change with no issue gets no fragment until it has one. A change with
  nothing for users (process docs, these rules) needs none.
- `make changelog-check` (in pre-push) rejects a misnamed fragment, a
  fragment without exactly one header, and a branch that adds lines to
  `CHANGELOG.md`. Only the release PR folds fragments, with
  `scripts/changelog-assemble.sh` and `CHANGELOG_RELEASE=1 make pre-push`.
- Releases follow RELEASING.md: every gate (pre-push, loom-full, both Miri
  halves, sim, Linux tests, netem, libkaryos packaging, conformance) has an
  Evidence row at the release head before the tag. Published release notes
  only gain dated rows and errata.

---

## Git and Review

- One task, one branch, one PR. Branches `<type>/<issue>-<slug>`
  (`feat/834-routed-heartbeat`, `fix/829-review-follow-up`).
- Worktrees only under `/Users/joaquin/tmp/worktrees/karyos/<name>`;
  never inside the repository. `/Users/joaquin/tmp` itself is immutable;
  write only inside `worktrees/`. Remove a worktree when done.
- CI runs on push and pull request, but merges never wait for it
  (ADR-0046; karyos#623). The merge gate is local: `make pre-push`
  passes on the exact PR head, the reviewer reruns it in a clean
  worktree, and approves that head. A new commit voids the verdict;
  warn the reviewer before pushing after a review handoff.
- A PR closes only issues whose acceptance criteria it meets in full. A
  partial PR says "Part of #N" and carries no closing keyword. Review
  follow-ups go in small PRs ("Follow-up to the #N review").
- Never force-push `main`; never rewrite another agent's branch.

---

## Pre-Submission Checklist

All must pass; failing any means not ready:

- `make pre-push`: `fmt-check`, `changelog-check`, `lint-sync`,
  `deps-check`, `abi-manifest-check`, `lint`, `lint-linux` (needs
  `rustup target add aarch64-unknown-linux-gnu`), `doc`, `test`, `loom`,
  `build-release` (`RUSTFLAGS="-D warnings"`), `timing-build-check`.
- Linux tests in Docker from an empty target volume when the PR touches
  Linux code or karyos-sys, -driver, -client, -agent or -tools.
- `make loom-full` when the counters seqlock changes; `make miri` (per
  MIRI.md) when `karyos-ffi/src/abi.rs` or `karyos-sys` unsafe changes.
- ADR-0034 review record for `karyos-sys`, `karyos-io` and the ffi
  boundary.
- No `unwrap`, `expect`, `panic!`, `unreachable!`, runtime `assert!`,
  `debug_assert!`, unchecked indexing or unchecked arithmetic outside
  tests.
- No allocation added to a data-path call; its `alloc_count` test passes.
- Typed errors with `thiserror`; new wire or status codes reserved and
  never reused.
- ABI manifest regenerated and ABI version raised when the C layout or a
  constant changes.
- Changelog fragment in `changelog.d/`, `CHANGELOG.md` untouched.
- New dependency admitted under ADR-0070 and recorded in
  `deps/dependencies.md`.

---

## DO NOT

- Panic outside tests, in any form listed above.
- Add `#[allow]` or `#[expect]` for `unwrap_used`, `expect_used`, `panic`
  or `indexing_slicing` on non-test code, or `#[allow(unsafe_code)]`
  anywhere.
- Add `unsafe` outside `karyos-sys`, `karyos-io` and `karyos-ffi/src/abi.rs`.
- Allocate, block, lock or log on the data path.
- Use `anyhow`, `println!`, `eprintln!`, `dbg!` or the `log` crate.
- Use `#[repr(C)]` structs or transmutes for wire formats.
- Reuse or renumber a CnC code or a C ABI status code.
- Change the C header layout without the manifest and the ABI version.
- Set `panic = "abort"` in any workspace profile.
- Edit `CHANGELOG.md` outside the release PR.
- Add a dependency, a feature of one or a wider scope without an ADR-0070
  admission.
- Prune Docker volumes, or reuse a shared Linux target volume for evidence.
- Claim a capability, a latency or a hardware result that was not
  measured and recorded (SPEC.md §2 principle 12).
- Commit secrets, keys or personal data.
