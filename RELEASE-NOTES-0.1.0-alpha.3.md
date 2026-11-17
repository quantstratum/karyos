<!-- SPDX-License-Identifier: Apache-2.0 -->

# Karyos 0.1.0-alpha.3

Released 2026-11-17. The first public release: the repository is public and
the core crates are on crates.io (karyos#622, owner decision of 2026-11-17).

## Published crates

In dependency order: `karyos-sys`, `karyos-protocol`, `karyos-codec`,
`karyos-client`, `karyos-io`, `karyos-archive`, `karyos-cluster`, `karyos`.
Depend on them by the exact pre-release, for example
`karyos = "=0.1.0-alpha.3"`; a Cargo pre-release does not match a plain `0.1`
requirement. Every other crate keeps `publish = false`.

## Supported API

As in 0.1.0-alpha.2: the `karyos` facade, `karyos-client` and
`karyos-archive`, plus the C ABI under its own `0.y.z` rule. Every other
published crate is internal and unstable in alpha with no compatibility
promise. APIs, wire formats, shared-memory layouts and the C ABI will change.

## Changes

See the `0.1.0-alpha.3` section of `CHANGELOG.md`.

## Evidence

| Check | Command | Platform | Head | Result |
| --- | --- | --- | --- | --- |
| The local gate | `CHANGELOG_RELEASE=1 make pre-push` | macOS arm64 | release PR head | see the pull request |
| Package dry run | `cargo publish --dry-run` of the eight crates in one invocation | macOS arm64 | release PR head | packaged and verified, exit 0 |

The other release gates of `RELEASING.md` (loom-full, Miri, sim sweep, Linux,
netem, libkaryos, conformance, compat matrix) were not run for this release:
the owner ordered the publication on 2026-11-17 with `make pre-push` as its
gate while hosted CI is off (karyos#623).
