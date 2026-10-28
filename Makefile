# SPDX-License-Identifier: Apache-2.0

CARGO ?= cargo
# Pinned nightly for Miri: rustc 1.101.0-nightly (6f5da406b 2026-10-10).
MIRI_TOOLCHAIN ?= nightly-2026-10-11

.PHONY: fmt fmt-check lint doc test netem loom loom-full sim sim-arch unsafe-report bench measure timing-build-check miri build-release libkaryos libkaryos-static-check libkaryos-copies-check libkaryos-testkit abi-manifest-check deny deps-inventory deps-check lint-sync changelog-check lint-linux pre-push

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

lint:
	$(CARGO) clippy --workspace --all-targets --locked -- -D warnings

# Clippy for Linux with every feature, from any host: the Linux-only code
# (cfg(target_os = "linux")) is checked before a push, not first in Docker.
# Needs `rustup target add aarch64-unknown-linux-gnu`.
lint-linux:
	$(CARGO) clippy --workspace --all-targets --all-features --locked --target aarch64-unknown-linux-gnu -- -D warnings

doc:
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --workspace --no-deps --locked

test:
	$(CARGO) test --workspace --locked

loom:
	RUSTFLAGS="--cfg loom" $(CARGO) test -p karyos-sys --release --locked --test 'loom_*'

# loom plus the slow models marked #[ignore] (about 11 minutes more). Hosted
# CI is off, so this is a merge gate: a PR that touches the counters seqlock
# or its layout (crates/*/src/counters*, crates/karyos-sys/tests/loom_counters.rs)
# cites a green `make loom-full` run on its exact head as review evidence
# (coordinator decision, ACS 12607). It is also a release gate, run at every
# release head (RELEASING.md).
loom-full:
	RUSTFLAGS="--cfg loom" $(CARGO) test -p karyos-sys --release --locked --test 'loom_*' -- --include-ignored

sim:
	@start=$$(date +%s); \
	KARYOS_SIM_SEED= KARYOS_SIM_SEEDS=2000 $(CARGO) test -p karyos-sim --release --locked --test scenarios; status=$$?; \
	end=$$(date +%s); \
	printf 'simulator sweep elapsed: %s seconds (fixed seeds 1..=2000)\n' "$$((end - start))"; \
	exit $$status

# aarch64 native against emulated linux/amd64 (issue #11): timings and
# outcomes only, never a gate; an emulated run that cannot complete is
# reported as not verifiable on this host.
sim-arch:
	scripts/sim-arch-compare.sh

# The workspace's `unsafe` surface from the source (issue #11): a report,
# never a gate.
unsafe-report:
	scripts/unsafe-report.sh

bench:
	$(CARGO) run -p karyos-bench --release --locked -- $(BENCH_ARGS)

measure:
	scripts/measure.sh $(MEASURE_ARGS)

# The bench binary built as measure.sh builds it must be a timing build
# (no alloc-count; an --all-features build never is one).
timing-build-check:
	$(CARGO) build -p karyos-bench --release --locked
	test "$$($${CARGO_TARGET_DIR:-target}/release/karyos-bench build-info)" = "build timing"
	! $${CARGO_TARGET_DIR:-target}/release/karyos-bench measure --plan synthetic --plan-only >/dev/null 2>&1
	$${CARGO_TARGET_DIR:-target}/release/karyos-bench measure --plan synthetic --plan-only 2>&1 | grep -q "needs the synthetic build"

miri:
	$(CARGO) +$(MIRI_TOOLCHAIN) miri test -p karyos-sys --lib --locked
	$(CARGO) +$(MIRI_TOOLCHAIN) miri test -p karyos-ffi --locked

build-release:
	RUSTFLAGS="-D warnings" $(CARGO) build --workspace --release --locked

# libkaryos packaged for the language bindings (include, lib, pkg-config,
# the conformance suite and a MANIFEST) into LIBKARYOS_DIR, by default
# target/libkaryos (quantstratum-docs: karyos/design/bindings-plan.md, B1).
# Not part of pre-push.
libkaryos:
	CARGO="$(CARGO)" scripts/package-libkaryos.sh $(LIBKARYOS_DIR)

# A C program linked statically through the package's karyos-static.pc.
# It compiles C, so it is not part of pre-push.
libkaryos-static-check: libkaryos
	scripts/check-libkaryos-static.sh $(LIBKARYOS_DIR)

# Two copies of the package's library in one process each refuse the
# other's handles (C-LINKAGE). It compiles C, so it is not part of
# pre-push.
libkaryos-copies-check: libkaryos
	scripts/check-libkaryos-copies.sh $(LIBKARYOS_DIR)

# The C header's ABI manifest (sizes, offsets, constants) matches the
# committed one, crates/karyos-ffi/abi/manifest.txt: a layout change
# without a new ABI version fails (owner item 48; karyos#700).
abi-manifest-check:
	scripts/check-abi-manifest.sh

# The conformance test kit beside the package: karyosd from the same
# commit, for the suite's archive-replay scenarios (Linux only). Not part
# of the release package (owner item 44), and not part of pre-push.
libkaryos-testkit: libkaryos
	CARGO="$(CARGO)" scripts/package-testkit.sh $(LIBKARYOS_DIR)

deny:
	$(CARGO) deny check

deps-inventory:
	python3 scripts/dependency-inventory.py deps/dependency-inventory.json

deps-check:
	@tmp=$$(mktemp) && python3 scripts/dependency-inventory.py $$tmp && diff -u deps/dependency-inventory.json $$tmp; status=$$?; rm -f $$tmp; exit $$status

lint-sync:
	scripts/check-lint-sync.sh

# Each fragment of changelog.d/ starts with exactly one section header.
changelog-check:
	scripts/changelog-assemble.sh --check

# The network fault tests under tc netem in Linux Docker (W6). Needs
# Docker with NET_ADMIN; not part of pre-push. KARYOS_NETEM sets the
# profile.
netem:
	scripts/netem-test.sh

pre-push: fmt-check changelog-check lint-sync deps-check abi-manifest-check lint lint-linux doc test loom build-release timing-build-check
