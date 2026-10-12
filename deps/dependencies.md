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
| `thiserror` | 2.0.21 | crates.io | default features off | runtime, `karyos-sys` | all | MIT OR Apache-2.0 | ADR-0033 (`thiserror`, all crates) |
| `loom` | 0.7.2 | crates.io | default features off | model checking, only under `--cfg loom` | all | MIT | ADR-0033 (`loom`, dev only) |

`loom` is declared as a `cfg(loom)` target dependency of `karyos-sys`, so it is
absent from every normal and release build and from the graph shipped to
users; it is compiled only by `make loom`.

## Transitive additions

| Crate | Version | Pulled in by | Licence | Build script |
| --- | --- | --- | --- | --- |
| `thiserror-impl` | 2.0.21 | `thiserror` (proc macro) | MIT OR Apache-2.0 | none |
| `proc-macro2` | 1.0.107 | `thiserror-impl` | MIT OR Apache-2.0 | rustc version probe; compiles no C |
| `quote` | 1.0.47 | `thiserror-impl` | MIT OR Apache-2.0 | rustc version probe; compiles no C |
| `syn` | 3.0.8 | `thiserror-impl` | MIT OR Apache-2.0 | none |
| `unicode-ident` | 1.0.26 | `proc-macro2` | (MIT OR Apache-2.0) AND Unicode-3.0 | none |

`thiserror` itself has a build script that probes the compiler version and
compiles no C. `syn`, `quote` and `proc-macro2` run only at compile time inside
the proc macro; ADR-0033 approves them for the codec, and here they enter
transitively through `thiserror`'s derive.

Under `--cfg loom` only, `loom` adds `generator`, `scoped-tls`, `cfg-if`,
`tracing`, `tracing-subscriber` and their dependencies (all MIT or
MIT OR Apache-2.0, Unlicense OR MIT for `memchr` and `aho-corasick`).
`generator` 0.8.10 has a build script that invokes the `cc` crate to assemble
`asm_ppc64le_elf.S` only when the target architecture is `powerpc64`; on the
supported targets (x86_64, aarch64) it compiles nothing. Powerpc64 is not a
Karyos target.
