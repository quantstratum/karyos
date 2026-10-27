<!-- SPDX-License-Identifier: Apache-2.0 -->

# Releasing Karyos

A Karyos release is a tag `v<version>` on `main`, with its
`RELEASE-NOTES-<version>.md` and its `CHANGELOG.md` section. This file
lists the gates a release runs and how their results are recorded. It
decides nothing about publishing crates to crates.io: which gate run
authorises a publication is still open, with the other points of the
first crates.io publication, and waits on the owner (quantstratum-docs:
`karyos/issues/M01-safe-ipc-core/005-first-crates-io-alpha-publication.md`,
point 4, "Release procedure while hosted CI is off").

## Evidence

Hosted CI is not running (karyos#623), so every gate below is run
locally and recorded as a row of the "Evidence" table of the release
notes: the check with its exact command, the platform (with the kernel
for a Linux run), the head, and the result with its counts, its wall
time and its exit code.

A gate is run at the release head. The 0.1.0-alpha.2 notes also accept
a release tree that differs from the tagged head only in documentation,
provided the notes name that tree and list every file that differs. A
row run at any other head is marked "not run at the release head" and
names its head and what changed since; it is historical evidence, not a
release gate.

## Changelog

The author of the release pull request assembles the changelog, in that
pull request, before the release section of `CHANGELOG.md` is cut: run
`scripts/changelog-assemble.sh` on the release branch. It folds every
fragment of `changelog.d/` into `[Unreleased]` and deletes them; commit
both. The fold is deterministic: fragments in file name order, after the
entries already in each section, and sections in Keep a Changelog order.
That pull request is the only one that edits `CHANGELOG.md`, so its gate
runs with `CHANGELOG_RELEASE=1 make pre-push`; for any other branch
`make changelog-check` fails when it adds more lines to `CHANGELOG.md` than it removes. Then
rename `[Unreleased]` to the release's heading and open a new,
empty `[Unreleased]` above it. Pull requests never edit `CHANGELOG.md`
directly (`CONTRIBUTING.md`). Decided 2026-10-27 by QS-COORDINATOR under
owner delegation (Joaquín, 2026-10-26).

## Release gates

The gates the 0.1.0-alpha.2 Evidence table records, and `make loom-full`:

| Gate | Command | Platform |
| --- | --- | --- |
| The local gate | `make pre-push` (fmt-check, lint-sync, deps-check, lint, doc, test, loom, build-release, timing-build-check) | macOS arm64 |
| The Loom models marked `#[ignore]` | `make loom-full`. Required at every release head, because `make loom` leaves out the ignored models (`a_transferred_gauge_is_never_mixed`) and the per pull request rule of the `Makefile` covers only changes to the counters seqlock. Decided 2026-10-27 by QS-COORDINATOR under owner delegation (Joaquín, 2026-10-26), [karyos#758](https://github.com/quantstratum/karyos/pull/758) | macOS arm64 |
| Miri, `karyos-sys` | `cargo +<MIRI_TOOLCHAIN> miri test -p karyos-sys --lib --locked`, the first half of `make miri`; it may run in parallel shards of `--exact` test names, which the row then lists | macOS arm64 |
| Miri, `karyos-ffi` | `cargo +<MIRI_TOOLCHAIN> miri test -p karyos-ffi --locked`, the second half of `make miri`, per `crates/karyos-ffi/MIRI.md` | macOS arm64 |
| The simulator sweep | `make sim` (seeds 1 to 2000) | macOS arm64 |
| The Linux tests | `scripts/linux-test.sh --workspace --all-features --locked --no-fail-fast` | Docker, Linux |
| Clippy with every feature | `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | Docker, Linux |
| The network impairment suite | `scripts/netem-test.sh` | Docker with `--cap-add NET_ADMIN`, Linux |
| The C library package | `make libkaryos`, `make libkaryos-static-check`, `make libkaryos-copies-check` | macOS arm64 |
| The binding conformance suite | `scripts/linux-test.sh -p karyos-ffi --all-features --locked --test conformance` | Docker, Linux |

`MIRI_TOOLCHAIN` is the nightly pinned in the `Makefile`; the row names
it, with the Miri version.

A gate that fails gets an issue of its own, linked from its row; the
fix is not folded into the pull request that records the evidence.

## After the tag

After a release is tagged, its release notes on `main` only gain dated
Evidence rows and dated errata below the Evidence table; published rows
and statements are never rewritten. Behaviour corrections go in
`CHANGELOG.md`. Decided 2026-10-27 by QS-COORDINATOR under owner
delegation (Joaquín, 2026-10-26),
[karyos#758](https://github.com/quantstratum/karyos/pull/758).
