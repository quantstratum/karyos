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

A release is not tagged until every gate below has an Evidence row for
its release head or its documented release tree; a missing row blocks
the tag. A historical row, or an argument that nothing changed since the
last run, does not stand in for one. Decided 2026-10-27 by
QS-COORDINATOR under owner delegation (Joaquín, 2026-10-26),
[karyos#767](https://github.com/quantstratum/karyos/pull/767).

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
| The local gate | `make pre-push` (fmt-check, changelog-check, lint-sync, deps-check, lint, lint-linux, doc, test, loom, build-release, timing-build-check); `lint-linux` is clippy with every feature for `aarch64-unknown-linux-gnu`, which needs that rustup target | macOS arm64 |
| The Loom models marked `#[ignore]` | `make loom-full`. Required at every release head, because `make loom` leaves out the ignored models (`a_transferred_gauge_is_never_mixed`) and the per pull request rule of the `Makefile` covers only changes to the counters seqlock. Decided 2026-10-27 by QS-COORDINATOR under owner delegation (Joaquín, 2026-10-26), [karyos#758](https://github.com/quantstratum/karyos/pull/758) | macOS arm64 |
| Miri, `karyos-sys` | `cargo +<MIRI_TOOLCHAIN> miri test -p karyos-sys --lib --locked`, the first half of `make miri`; it may run in parallel shards of `--exact` test names, which the row then lists | macOS arm64 |
| Miri, `karyos-ffi` | `cargo +<MIRI_TOOLCHAIN> miri test -p karyos-ffi --locked`, the second half of `make miri`, per `crates/karyos-ffi/MIRI.md` | macOS arm64 |
| The simulator sweep | `make sim` (seeds 1 to 2000) | macOS arm64 |
| The Linux tests | `scripts/linux-test.sh --workspace --all-features --locked --no-fail-fast` | Docker, Linux |
| Clippy with every feature | `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | Docker, Linux |
| The network impairment suite | `scripts/netem-test.sh` | Docker with `--cap-add NET_ADMIN`, Linux |
| The C library package | `make libkaryos`, `make libkaryos-static-check`, `make libkaryos-copies-check` | macOS arm64 |
| The binding conformance suite | `scripts/linux-test.sh -p karyos-ffi --all-features --locked --test conformance` | Docker, Linux |
| The wire compatibility matrix | `scripts/compat-test.sh <worktree of the previous release tag>` (R-CORE-36, karyos#732): the previous release's builds and this head's run against each other, every outcome compared with `crates/karyos-tools/compat/matrix.toml`; the release adds its own column to the matrix first. First run at karyos#878 (head d67f6be6, v0.1.0-alpha.2 against main, aarch64, kernel 6.8: 0 failures) | Docker, Linux |

`MIRI_TOOLCHAIN` is the nightly pinned in the `Makefile`; the row names
it, with the Miri version.

Before the release is cut, also check:

- **Forward-compatible error codes present; see karyos#819.** The release
  contains `ErrorCode::Unknown`, so a client of this release reads a CnC
  refusal code it does not define as a refusal. The admission `VERSION`
  stays 3 only because no VERSION 3 peer is released without it
  (QS-COORDINATOR, 2026-10-28). Check it on the release commit with
  `cargo test -p karyos-protocol --lib an_undefined_refusal_code_decodes_as_unknown every_defined_code_round_trips_to_its_variant`:
  an `Error` of code 1000 decodes as `Unknown` and re-encodes to its
  bytes, and every defined code decodes to itself.

A gate that fails gets an issue of its own, linked from its row; the
fix is not folded into the pull request that records the evidence.

## libkaryos and karyosd artifacts

`libkaryos` and `karyosd` are released as two separate artifacts (owner
item 44; karyos#700). At the release head, on each host:

1. `scripts/release-libkaryos.sh` builds, from a clean tree, the library
   package (`libkaryos-<abi>-<core>-<triple>.tar.gz`: header, static and
   shared libraries, pkg-config files, the conformance suite's files,
   `MANIFEST` with `contents=library` and `excludes=karyosd`, and the ABI
   manifest), the daemon alone (`karyosd-<core>-<triple>.tar.gz`), and
   `SHA256SUMS`. It refuses a library artifact holding `karyosd` or a
   daemon artifact holding the library, and a DEST that is `/`, `$HOME`,
   or anything but an unsigned release directory of its own. The archives
   are deterministic on a host; `scripts/check-release-reproducible.sh`
   builds twice under different `TZ` and umask and compares.
2. `scripts/conformance-package.sh <libkaryos tarball>` runs the
   conformance suite against the artifact itself, which it checks against
   `SHA256SUMS` first, from a clean tree at the package's `core_commit`
   (the suite is the tree's); its last line, with the artifact's SHA-256,
   is the Evidence row, pass or fail. The cross-process scenarios run on
   Linux only.
3. `scripts/sign-release.sh` signs exactly the artifacts `SHA256SUMS`
   lists with key-based `cosign` and verifies each (karyos-deploy
   ADR-0003); it refuses a directory holding an archive it does not list.
   The release key's custodian runs it; it refuses without the key's
   `pkcs11:` URI (a key file's path included) and has no fallback. Until
   karyos-deploy's D1 gates (the R8 record for `cosign`, the custody
   procedure) are met, there is no key, and no signed artifact is
   published.

The soname policy is owner item 48's ruling: the soname carries `0.y`
before 1.0 and the major from 1.0 on (`scripts/package-libkaryos.sh`).
The ABI manifest, `share/karyos/abi-manifest.txt` in the package and
`crates/karyos-ffi/abi/manifest.txt` in the tree, gives every public
struct's size, alignment and field offsets, every constant's value, and
every other declaration of the header (prototypes, inline functions'
signatures, callback and other typedefs) as written; a header it cannot
parse is an error. `make abi-manifest-check` (in pre-push) fails when the
header no longer matches the committed manifest, and when the manifest
differs from the last released one, `crates/karyos-ffi/abi/released/<abi>.txt`,
without a higher ABI version (owner item 48). At each release, the
manifest is copied there as the released ABI version's and committed.

The conformance test kit (`make libkaryos-testkit`) is not a release
package: its `MANIFEST` says `release_package=no` and its `README` says
so. It is never put in a release directory.

### Registry check

Owner item 44 asks for a check of registry control and policy before
publication, under the candidate names of
`quantstratum-docs: owner-decisions/2026-10-21/decisions.md:214` to
`:226`. It is read-only: anonymous requests with a User-Agent naming the
project, no account, and nothing reserved. "Free" means the registry
lists nothing under the name; it is not a reservation, and the names stay
open to anyone until they are published.

| Checked | Registry | Name | Result |
| --- | --- | --- | --- |
| 2026-10-28 | PyPI | `karyos` | free |
| 2026-10-28 | PyPI | `quantstratum-karyos` (fallback) | free |
| 2026-10-28 | NuGet | `Karyos` | free |
| 2026-10-28 | NuGet | `QuantStratum.Karyos` (fallback) | free |
| 2026-10-28 | Maven Central | `com.quantstratum:karyos` | free (no artifact); control of the `com.quantstratum` namespace, which Central verifies by domain, is unknown |
| 2026-10-28 | Maven Central | `io.github.quantstratum` (fallback) | free (no artifact); its control is unknown |
| 2026-10-28 | Go module proxy | `github.com/quantstratum/karyos-go` | free (no public module) |
| 2026-10-28 | GitHub | `quantstratum/karyos-go` | unknown: an anonymous request cannot tell a missing repository from a private one |
| 2026-10-28 | crates.io | `karyos`, `libkaryos` | free |

The C++ names (CMake `karyos`; Conan and vcpkg deferred) are not
registry names and are not checked. Each binding's own release repeats
the check for its names before it publishes.

## After the tag

After a release is tagged, its release notes on `main` only gain dated
Evidence rows and dated errata below the Evidence table; published rows
and statements are never rewritten. Behaviour corrections go in
`CHANGELOG.md`. Decided 2026-10-27 by QS-COORDINATOR under owner
delegation (Joaquín, 2026-10-26),
[karyos#758](https://github.com/quantstratum/karyos/pull/758).
