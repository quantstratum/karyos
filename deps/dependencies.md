<!-- SPDX-License-Identifier: Apache-2.0 -->

# Dependency admission record

Every external dependency is recorded here before code using it is merged
(ADR-0033, SPEC.md §14). The resolved graph is pinned by the committed
`Cargo.lock`; builds use `--locked`. `cargo deny check` enforces the licence
allowlist and sources in `deny.toml`. Build scripts and native linkage are
reviewed by hand, because `cargo deny` does not establish their absence.

## Direct dependencies

| Crate | Version | Source | Features | Scope | Targets | Licence | Family approval |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `thiserror` | 2.0.21 | crates.io | default features off | runtime, `karyos-sys`, `karyos-protocol`, `karyos-client`, `karyos-driver`, `karyos-trace`, `karyos` | all | MIT OR Apache-2.0 | ADR-0033 (`thiserror`, all crates) |
| `rustix` | 1.1.5 | crates.io | default features off; `std`, `event`, `fs`, `mm`, `net`, `param`, `process` (`net` and `process` owner approved 2026-10-15 for IPC, quantstratum-docs: karyos/design/ipc-implementation.md; `event`, for polling the client's pidfd, owner approved 2026-10-15 for i3) | runtime, `karyos-sys` | Linux only (`cfg(target_os = "linux")`) | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | ADR-0033 (`rustix`, sys and io) |
| `loom` | 0.7.2 | crates.io | default features off | model checking, only under `--cfg loom` | all | MIT | ADR-0033 (`loom`, dev only) |
| `proptest` | 1.11.0 | crates.io | default features off; `std` | dev-dependency of `karyos-sys` and `karyos-protocol` (tests only; `karyos-protocol` added for the layout properties of issue #10, coordinator approved 2026-10-15) | all | MIT OR Apache-2.0 | ADR-0033 (`proptest`, dev only); owner confirmed phase 1 on 2026-10-15 (Q25, issue #40) |

`loom` is declared as a `cfg(loom)` target dependency of `karyos-sys`, so it is
absent from every normal and release build and from the graph shipped to
users; it is compiled only by `make loom`.

## Resolved graph

[`dependency-inventory.json`](dependency-inventory.json) lists every external
package in the resolved graph: package id, version, raw source, licence,
build script and proc macro flags, resolved features, every incoming edge
(dependent package id, kind, exact target condition, `uses_default_features`
and requested features of the declaration), and for each reach class the
minimal target conditions along the paths that reach it. Only an edge whose
condition is exactly `cfg(loom)` makes a path `loom-*`; any other condition is
kept verbatim. Generation writes a temporary file and replaces the committed
one only on success. Its `evaluated` section lists, for x86_64 and aarch64
Linux and aarch64 macOS, the target-filtered dependency graph that
`cargo tree --target --edges normal,build` reports for default features: an
approximation of what a normal build compiles there, not a build record. It is generated from `Cargo.lock` by
`scripts/dependency-inventory.py` (`make deps-inventory`); `make deps-check`
runs in CI and fails when the committed file is stale, so a lockfile, feature
or build-script change cannot reuse old admission evidence. Reach classes:

- `runtime`: may be linked into Karyos builds. On the supported targets the
  evaluated runtime graph is `thiserror`, plus `rustix`, `bitflags` and
  `linux-raw-sys` on Linux. The raw edges also list `libc` and `errno` under
  `rustix`, either as optional dependencies of the `linux_raw` backend that
  only the unused `use-libc` feature enables, or behind `rustix_use_libc` or
  `miri`; neither applies to normal builds.
- `build`: runs only at compile time, as a proc macro or its dependency
  (`thiserror-impl`, `syn`, `quote`, `proc-macro2`, `unicode-ident`).
  ADR-0033 approves `syn`, `quote` and `proc-macro2` for the codec; here they
  enter through `thiserror`'s derive.
- `dev`: reached only through a dev-dependency, compiled for tests and
  never linked into a library or binary build: `proptest` 1.11.0 and its
  graph (`rand`, `rand_core`, `rand_chacha`, `rand_xorshift`, `getrandom`,
  `zerocopy`, `ppv-lite86`, `num-traits`, `unarray`, `regex-syntax`, and
  `libc` under `getrandom` on macOS and on Linux with the `gnu` or `musl`
  environment). `zerocopy-derive` and `syn` 2 appear only
  behind `cfg(any())`, which is never true, and `r-efi`, `wasip2` and
  `wit-bindgen` only for UEFI or `wasm32-wasip2` targets.
- `loom-runtime` and `loom-build`: the same classes reached only through the
  `cfg(loom)` dependency, compiled only by `make loom`, never in normal, test
  or release builds.

Counts per class change with the lockfile and are read from the JSON
rather than repeated here.

On x86_64 and aarch64 Linux `rustix` uses its `linux_raw` backend: system
calls through Rust inline assembly and the pure-Rust `linux-raw-sys`
bindings, with no `libc`. Its `libc` backend (`errno`, `libc`) is selected
only by `--cfg rustix_use_libc`, which Karyos never sets, or under Miri.

Effective target conditions that exclude packages from the supported
targets: `windows-sys`, `windows-result` and `windows-link` (`cfg(windows)`)
and `valuable` (`cfg(tracing_unstable)`, a flag Karyos never sets).

## Build scripts

Twelve packages in the graph have build scripts. None compiles C or C++ on a
supported target (x86_64 and aarch64 Linux, aarch64 macOS):

| Package | Reach | What the build script does |
| --- | --- | --- |
| `thiserror` 2.0.21 | runtime | Runs `rustc --version` and a probe compile to set cfgs |
| `proc-macro2` 1.0.107 | build | Runs `rustc --version` and a probe compile to set cfgs |
| `rustix` 1.1.5 | runtime (Linux) | Runs `rustc` probes to select the backend and set cfgs; no build dependencies |
| `quote` 1.0.47 | build | Runs `rustc --version` to set cfgs |
| `rustversion` 1.0.23 | loom | Runs `rustc --version` to generate version constants |
| `libc` 0.2.190 | loom; dev, under `getrandom` on macOS and Linux `gnu`/`musl` (tests only); also behind `rustix`'s libc backend (`rustix_use_libc` or Miri), never in normal builds on supported targets | Runs `rustc --version`; queries `freebsd-version` or `emcc` only on FreeBSD or Emscripten targets; compiles nothing |
| `generator` 0.8.10 | loom | Invokes `cc` to assemble `asm_ppc64le_elf.S` only when the target architecture is `powerpc64`, which Karyos does not support |
| `valuable` 0.1.1 | loom | Emits atomic-support cfgs from the target name |
| `getrandom` 0.3.4 | dev | Runs `rustc --version` to choose cfgs (sanitizer and old Windows backends); compiles nothing |
| `num-traits` 0.2.19 | dev | `autocfg` probe compile of one Rust expression to set a cfg |
| `zerocopy` 0.8.63 | dev | Runs `rustc --version` to emit version cfgs |
| `wit-bindgen` 0.57.1 | dev, `wasm32-wasip2` only | Never built for a supported target |

`cc` 1.8.0 and its dependencies are in the graph only as `generator`'s
build dependency and do nothing on supported targets.
