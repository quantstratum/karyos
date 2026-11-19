<!-- SPDX-License-Identifier: Apache-2.0 -->

# Dependency admission record

Every external dependency is recorded here before code using it is merged
(ADR-0033, SPEC.md §14). The resolved graph is pinned by the committed
`Cargo.lock`; builds use `--locked`. `cargo deny check` enforces the licence
allowlist and sources in `deny.toml` and refuses crates with an open RustSec
advisory; CI runs the advisory check in its own job (karyos#933). Build scripts and native linkage are
reviewed by hand, because `cargo deny` does not establish their absence.

## Direct dependencies

| Crate | Version | Source | Features | Scope | Targets | Licence | Family approval |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `thiserror` | 2.0.21 | crates.io | default features off | runtime, `karyos-sys`, `karyos-io` (the backend error types, quantstratum-docs: karyos/design/sockets-backend.md 11.0 O-1; coordinator approved 2026-10-16, ACS 14546), `karyos-protocol`, `karyos-client`, `karyos-driver`, `karyos-trace`, `karyos-archive` (the segment store's errors, A2), `karyos-cluster` (the Raft log's errors, C4), `karyos-agent` (the management agent, M6a), `karyos` | all | MIT OR Apache-2.0 | ADR-0033 (`thiserror`, all crates) |
| `rustix` | 1.1.6 | crates.io | default features off; `std`, `event`, `fs`, `mm`, `net`, `param`, `process`, `rand`, `time` (`net` and `process` owner approved 2026-10-15 for IPC, quantstratum-docs: karyos/design/ipc-implementation.md; `event`, for polling the client's pidfd, owner approved 2026-10-15 for i3; `rand`, for `getrandom` behind `karyos_sys::random` and the driver's random `driver_id`, owner decision 2026-10-15, ACS 11410, confirmed by the coordinator in ACS 12439; `time`, for `host_monotonic_ns` over `clock_gettime(CLOCK_MONOTONIC)` (quantstratum-docs: karyos/design/observability-and-tools.md, Timestamps), owner decision 2026-10-15, ACS 12585) | runtime, `karyos-sys`; `karyos-io` (sockets backend datagram send and receive, Linux only, declared directly with `std` and `net` only, no `event`; owner decision 2026-10-16 O-1, quantstratum-docs: karyos/design/sockets-backend.md 11.0) | Linux only (`cfg(target_os = "linux")`) | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | ADR-0033 (`rustix`, sys and io) |
| `loom` | 0.7.2 | crates.io | default features off | model checking, only under `--cfg loom` | all | MIT | ADR-0033 (`loom`, dev only) |
| `proptest` | 1.11.0 | crates.io | default features off; `std` | dev-dependency of `karyos-sys`, `karyos-protocol`, `karyos-io`, `karyos-archive`, `karyos-tools` and `karyos-agent` (tests only; `karyos-agent` for the properties of the join request parser, the join registry and the exporter's HTTP head parser, untrusted-input parsers under ADR-0062, karyos#893, coordinator approved 2026-10-30, ACS 37404; `karyos-tools` for the properties of the compat JSON reader, an untrusted-input parser under ADR-0062, karyos#732, coordinator approved 2026-10-29, ACS 37060; `karyos-archive` for the segment store's crash-point properties of A2, quantstratum-docs: karyos/design/archive-gap-analysis.md, coordinator approved 2026-10-17, ACS 16727; `karyos-protocol` added for the layout properties of issue #10, coordinator approved 2026-10-15; `karyos-io` for the backend slot, queue and report properties of P2.3, quantstratum-docs: karyos/design/sockets-backend.md section 12, coordinator approved 2026-10-16, ACS 14546) | all | MIT OR Apache-2.0 | ADR-0033 (`proptest`, dev only); owner confirmed phase 1 on 2026-10-15 (Q25, issue #40) |
| `criterion` | 0.7.0 (pinned `=0.7.0`) | crates.io | default features off; `cargo_bench_support` | microbenchmarks only, dev-dependency of `karyos-bench` | all | Apache-2.0 OR MIT | owner approved 2026-10-15 (Q25, issue #12); exact resolution 0.7.0 under ADR-0033, coordinator decision 2026-10-15 (ACS 13315) |
| `signal-hook` | 0.4.5 | crates.io | default features off (no `channel`, `iterator` or `extended-siginfo`); only the safe `signal_hook::flag::register` is used | runtime, `karyos-tools` only (the `karyosd` binary: `SIGTERM` and `SIGINT` set a flag) | all | MIT OR Apache-2.0 | owner decision ACS 13810 (2026-10-16), under ADR-0033 |
| `tracing` | 0.1.44 | crates.io | default features off (no `std` request, no `attributes` proc macro) | runtime, `karyos-tools` only (control-path logs of `karyosd`, SPEC.md §11) | all | MIT | owner approved phase 1 on 2026-10-15 (Q25, ACS 11869, issue #40); exact resolution owner decision ACS 13810 (2026-10-16), under ADR-0033 |
| `tracing-subscriber` | 0.3.23 | crates.io | default features off; `fmt`, `std` (no `ansi`, `env-filter`, `regex`, `tracing-log`, `smallvec`) | runtime, `karyos-tools` only (the subscriber the `karyosd` binary installs; no library installs one) | all | MIT | owner decision ACS 13810 (2026-10-16), under ADR-0033 |
| `serde` | 1.0.229 | crates.io | default features off; `std`, `derive` | runtime, `karyos-tools` (the `karyosd` configuration file, R-CORE-43; re-exported by `karyos_tools::config`); `karyos-control` (the token header, claims and key set, the JWT verification and JWKS retrieval records (quantstratum-docs: karyos/reviews/dependency-admission-jwt-verification.md, dependency-admission-jwks-retrieval.md), owner decision on quantstratum-docs#899 with the Codex half ACS 77226, 2026-11-18) | all | MIT OR Apache-2.0 | ADR-0033 (`serde`, `toml`: Configuration, tools); exact resolution under ADR-0033, coordinator decision 2026-10-29 (ACS 35711); the JWT verification record for `karyos-control` |
| `toml` | 1.1.8+spec-1.1.0 | crates.io | default features off; `std`, `serde`, `parse` (no `display`: nothing is written) | runtime, `karyos-tools` only (parses the `karyosd` configuration file, R-CORE-43; re-exported by `karyos_tools::config`) | all | MIT OR Apache-2.0 | ADR-0033 (`serde`, `toml`: Configuration, tools); exact resolution under ADR-0033, coordinator decision 2026-10-29 (ACS 35711) |
| `hyper` | 1.12.0 | crates.io | default features off; `server`, `http1`; `client` for the issuer's discovery document and key set (the JWKS retrieval record) | runtime and dev, `karyos-control` only (the control-plane component, karyos#708; not a default member, nothing depends on it) | all (x86_64 and aarch64 through `graviola`) | MIT | the agent HTTP stack's record (quantstratum-docs: karyos/reviews/dependency-admission-agent-http-stack.md), owner decision ACS 71206, 2026-11-12, under ADR-0083 |
| `hyper-util` | 0.1.21 | crates.io | default features off; `tokio` | runtime and dev, `karyos-control` only (the control-plane component, karyos#708; not a default member, nothing depends on it) | all | MIT | the agent HTTP stack's record (quantstratum-docs: karyos/reviews/dependency-admission-agent-http-stack.md), owner decision ACS 71206, 2026-11-12, under ADR-0083 |
| `tokio` | 1.54.1 | crates.io | default features off; `rt`, `net`, `time` (`hyper` turns on `sync`) | runtime and dev, `karyos-control` only (the control-plane component, karyos#708; not a default member, nothing depends on it) | all | MIT | the agent HTTP stack's record (quantstratum-docs: karyos/reviews/dependency-admission-agent-http-stack.md), owner decision ACS 71206, 2026-11-12, under ADR-0083 |
| `tokio-rustls` | 0.26.6 | crates.io | default features off | runtime and dev, `karyos-control` only (the control-plane component, karyos#708; not a default member, nothing depends on it) | all | MIT OR Apache-2.0 | the agent HTTP stack's record (quantstratum-docs: karyos/reviews/dependency-admission-agent-http-stack.md), owner decision ACS 71206, 2026-11-12, under ADR-0083 |
| `rustls` | 0.23.46 | crates.io | default features off; `std` (`rustls-graviola` turns on `tls12`; TLS 1.3 only is configured) | runtime and dev, `karyos-control` only (the control-plane component, karyos#708; not a default member, nothing depends on it) | all | Apache-2.0 OR ISC OR MIT | the agent HTTP stack's record (quantstratum-docs: karyos/reviews/dependency-admission-agent-http-stack.md), owner decision ACS 71206, 2026-11-12, under ADR-0083 |
| `graviola` | 0.4.2 | crates.io | default features off (its `default` is empty); signature verification and hashing only, no randomness | runtime and dev, `karyos-control` only (karyos#708) | x86_64 and aarch64 only | Apache-2.0 OR ISC OR MIT-0 | the JWT verification and JWKS retrieval records (quantstratum-docs: karyos/reviews/dependency-admission-jwt-verification.md, dependency-admission-jwks-retrieval.md), owner decision on quantstratum-docs#899 with the Codex half ACS 77226, 2026-11-18 |
| `rustls-graviola` | 0.4.0 | crates.io | default features off | runtime and dev, `karyos-control` only (the control-plane component, karyos#708; not a default member, nothing depends on it) | x86_64 and aarch64 only | Apache-2.0 OR ISC OR MIT-0 | the agent HTTP stack's record (quantstratum-docs: karyos/reviews/dependency-admission-agent-http-stack.md), owner decision ACS 71206, 2026-11-12, under ADR-0083 |
| `serde_json` | 1.0.154 | crates.io | default features off; `std` | runtime and dev, `karyos-control` only (karyos#708) | all | MIT OR Apache-2.0 | the JWT verification and JWKS retrieval records (quantstratum-docs: karyos/reviews/dependency-admission-jwt-verification.md, dependency-admission-jwks-retrieval.md), owner decision on quantstratum-docs#899 with the Codex half ACS 77226, 2026-11-18 |

The control-plane component `karyos-control` (karyos#708) holds the agent
HTTP stack admitted by its record (quantstratum-docs:
karyos/reviews/dependency-admission-agent-http-stack.md; owner decision
ACS 71206, 2026-11-12, under ADR-0083), pinned with `=` at the record's
versions and features. It is a workspace member but not a default member
(`default-members` in the root `Cargo.toml`, condition 2), and nothing
depends on it, so `cargo tree -p karyos-agent -e normal` and the default
build's `cargo tree -e normal` contain none of these crates;
`make control-plane-graph-check` (in pre-push) checks that and that no
`ring`, `aws-lc-rs`, `aws-lc-sys` or `cc` is built for it on any target
(conditions 3 and 4). `graviola` is pinned at 0.4.2 in `Cargo.lock`
(condition 6): the record's evidence was taken at 0.4.2, it is now three
weeks old with no advisory in the RustSec database and no yank; 0.4.3,
0.4.4 and 0.4.5 have appeared since, and moving to any of them needs the
independent review of condition 7. Its transitive crates, admitted under
the same record, resolve to `atomic-waker` 1.1.2, `bytes` 1.12.2,
`futures-core` 0.3.34, `getrandom` 0.4.3, `graviola` 0.4.2, `http` 1.5.0,
`http-body` 1.1.0, `httparse` 1.10.1, `httpdate` 1.0.3, `mio` 1.2.5,
`rustls-pki-types` 1.16.0, `rustls-webpki` 0.103.17, `socket2` 0.6.5,
`subtle` 2.6.1, `untrusted` 0.9.0 and `zeroize` 1.9.2, besides `libc`,
`once_cell`, `pin-project-lite`, `cfg-if`, `itoa` and `smallvec` already in
the graph; `bytes`, `mio`, `rustls-pki-types`, `rustls-webpki` and
`zeroize` are patch releases after the record's evidence, under ADR-0033's
ordinary policy within its scope. `ring` 0.17.14, `getrandom` 0.2.17,
`r-efi`, `wasi` and the `windows-sys` 0.52 family are in the lockfile only:
`ring` as `rustls-webpki`'s optional dependency behind a weak feature,
never enabled, and the others for targets Karyos does not support; none
is built. `graviola` panics at its first operation on a CPU without its
required features; the component checks them at start and refuses with a
typed error (condition 5). That record (condition 8) admits neither JWT
verification, JWKS retrieval, OIDC support, an outbound TLS client, `axum`
nor HTTP/2; under it alone the component's tests use `rustls`'s client
side, compiled in the admitted `rustls` already, as a test client only.
The production outbound TLS client and JWKS retrieval are admitted by the
later records below, which are the authority for them.

`karyos-control` also verifies OIDC access tokens and fetches its issuer's
key set (karyos#708), under the JWT verification and JWKS retrieval
records (quantstratum-docs:
karyos/reviews/dependency-admission-jwt-verification.md and
dependency-admission-jwks-retrieval.md; owner decision on
quantstratum-docs#899, Codex half ACS 77226, 2026-11-18). That adds
`graviola` 0.4.2 as a direct dependency, for signature verification and
hashing only, `serde` and `serde_json` in this crate, and `hyper`'s
`client` feature. The new transitive crates are `memchr` 2.8.3 (Unlicense
OR MIT) and `zmij` 1.0.23 (MIT) under `serde_json`, and `try-lock` 0.2.5
and `want` 0.3.2 (MIT) under `hyper`'s client; `serde_derive`'s graph was
already in the lockfile. The first implementation's measurements
(condition 5 of each record) are in those records. No `ring`, `aws-lc-rs`,
`aws-lc-sys` or `cc` is built: `make control-plane-graph-check`.

`criterion` is pinned to `=0.7.0`. The owner admitted the criterion family
(Q25), and ADR-0033 allows a compliant exact resolution within an admitted
family without a new approval. The 0.8 line is excluded by ADR-0006 (no C or
C++ toolchain): from 0.8.0 criterion depends unconditionally, for every
`unix` and `windows` target and whatever its features, on `alloca`, whose
build script compiles C with `cc` on every build. A move to 0.8 or later
therefore needs a deliberate change and a fresh check of this rule.

`signal-hook`, `tracing` and `tracing-subscriber` are dependencies of
`karyos-tools` only, so they reach the operational binaries and no library
crate (owner decision ACS 13810, 2026-10-16). Their transitive runtime
crates, all admitted under the same decision and ADR-0033, are:
`signal-hook-registry` 1.4.8 (MIT OR Apache-2.0), `libc` 0.2.190 (MIT OR
Apache-2.0) and `errno` 0.3.14 (MIT OR Apache-2.0) under `signal-hook`;
`tracing-core` 0.1.36 (MIT), `pin-project-lite` 0.2.17 (Apache-2.0 OR MIT)
and `once_cell` 1.21.4 (MIT OR Apache-2.0) under `tracing`; and
`sharded-slab` 0.1.7 (MIT), `lazy_static` 1.5.1 (MIT OR Apache-2.0),
`thread_local` 1.1.10 (MIT OR Apache-2.0) and `cfg-if` 1.0.5 (MIT OR
Apache-2.0) under `tracing-subscriber`'s `fmt` registry. Every one of them
was already in the lockfile through `loom` or a dev-dependency except
`signal-hook` and `signal-hook-registry`. The lockfile's resolved feature
list for `tracing-subscriber` is the union with `loom`'s request
(`ansi`, `env-filter`, `tracing-log` and others); a normal build of
`karyos-tools` enables only `alloc`, `fmt`, `registry`, `sharded-slab`,
`std` and `thread_local` (`cargo tree -e normal,features`).

`serde` and `toml` are dependencies of `karyos-tools` only, so no library
crate of the core gains them; `karyos_tools::config` re-exports both, so
a backend outside the core (`karyosd-native`) derives its configuration
table against these versions, and a major version of either is a
breaking change of `karyos-tools` (coordinator decision ACS 35711,
2026-10-29). Their transitive crates, admitted under the same decision and
ADR-0033, are `serde_core` 1.0.229 and `serde_derive` 1.0.229 (proc macro;
MIT OR Apache-2.0) under `serde`; and `serde_spanned` 1.1.2,
`toml_datetime` 1.1.2+spec-1.1.0, `toml_parser` 1.1.5+spec-1.1.0 (MIT OR
Apache-2.0) and `winnow` 1.0.4 (MIT) under `toml`. `serde_derive`'s
`proc-macro2`, `quote`, `syn` and `unicode-ident` were already in the
lockfile through `thiserror`. `serde` and `serde_core` have build scripts,
reviewed by hand at 1.0.229: each writes a generated module into `OUT_DIR`
and emits `cfg` flags from `rustc --version`; neither compiles C nor links
anything.

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
  evaluated runtime graph of the library crates is `thiserror`, plus
  `rustix`, `bitflags` and `linux-raw-sys` on Linux. The `karyos-tools`
  binaries add `signal-hook`, `signal-hook-registry`, `libc`, `errno`,
  `tracing`, `tracing-core`, `pin-project-lite`, `once_cell`,
  `tracing-subscriber`, `sharded-slab`, `lazy_static`, `thread_local` and
  `cfg-if` on every supported target. The raw edges also list `libc` and
  `errno` under `rustix`, either as optional dependencies of the
  `linux_raw` backend that only the unused `use-libc` feature enables, or
  behind `rustix_use_libc` or `miri`; neither applies to normal builds.
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
bindings, with no `libc`. The `karyosd` binary links `libc` through
`signal-hook-registry`, which installs the `sigaction` handler; no library
crate does. Its `libc` backend (`errno`, `libc`) is selected
only by `--cfg rustix_use_libc`, which Karyos never sets, or under Miri.

Effective target conditions that exclude packages from the supported
targets: `windows-sys`, `windows-result` and `windows-link` (`cfg(windows)`)
and `valuable` (`cfg(tracing_unstable)`, a flag Karyos never sets).

## Build scripts

The packages below have build scripts (the inventory's `build_script` flag lists every one, including those of unsupported targets), besides `ring` 0.17.14, which is in the lockfile only and never built (see the control-plane paragraph above). None compiles C or C++ on a
supported target (x86_64 and aarch64 Linux, aarch64 macOS):

| Package | Reach | What the build script does |
| --- | --- | --- |
| `thiserror` 2.0.21 | runtime | Runs `rustc --version` and a probe compile to set cfgs |
| `proc-macro2` 1.0.107 | build | Runs `rustc --version` and a probe compile to set cfgs |
| `rustix` 1.1.6 | runtime (Linux) | Runs `rustc` probes to select the backend and set cfgs; no build dependencies |
| `quote` 1.0.47 | build | Runs `rustc --version` to set cfgs |
| `signal-hook` 0.4.5 | runtime, `karyos-tools` only | Empty `main` unless the `extended-siginfo-raw` feature is on, which would compile `extract.c` with the optional `cc` build dependency; Karyos leaves it off, so `cc` is not requested |
| `rustversion` 1.0.23 | loom | Runs `rustc --version` to generate version constants |
| `libc` 0.2.190 | runtime, `karyos-tools` only, under `signal-hook` and `signal-hook-registry` on every supported target; loom; dev, under `getrandom` on macOS and Linux `gnu`/`musl` (tests only); also behind `rustix`'s libc backend (`rustix_use_libc` or Miri), never in library builds on supported targets | Runs `rustc --version`; queries `freebsd-version` or `emcc` only on FreeBSD or Emscripten targets; compiles nothing |
| `generator` 0.8.10 | loom | Invokes `cc` to assemble `asm_ppc64le_elf.S` only when the target architecture is `powerpc64`, which Karyos does not support |
| `valuable` 0.1.1 | loom | Emits atomic-support cfgs from the target name |
| `getrandom` 0.3.4 | dev | Runs `rustc --version` to choose cfgs (sanitizer and old Windows backends); compiles nothing |
| `num-traits` 0.2.19 | dev | `autocfg` probe compile of one Rust expression to set a cfg |
| `zerocopy` 0.8.63 | dev | Runs `rustc --version` to emit version cfgs |
| `wit-bindgen` 0.57.1 | dev, `wasm32-wasip2` only | Never built for a supported target |
| `rustls` 0.23.46 | runtime, `karyos-control` only | Empty `main` unless the `read_buf` feature is on (off here), which emits one cfg on nightly; compiles nothing |
| `httparse` 1.10.1 | runtime, `karyos-control` only | Runs `rustc --version` to set SIMD cfgs; compiles nothing |
| `getrandom` 0.4.3 | runtime, `karyos-control` only | Emits a cfg under the memory sanitizer; compiles nothing |
| `serde_json` 1.0.154 | runtime, `karyos-control` only; dev, under `criterion` | Emits arithmetic-width cfgs from the target; compiles nothing |
| `zmij` 1.0.23 | runtime, `karyos-control` only, under `serde_json`; dev | Runs `rustc --version` to set cfgs; compiles nothing |

`cc` 1.8.0 and its dependencies are in the graph only as `generator`'s
build dependency and do nothing on supported targets.
