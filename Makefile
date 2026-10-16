# SPDX-License-Identifier: Apache-2.0

CARGO ?= cargo
# Pinned nightly for Miri: rustc 1.101.0-nightly (6f5da406b 2026-10-10).
MIRI_TOOLCHAIN ?= nightly-2026-10-11

.PHONY: fmt fmt-check lint doc test loom loom-full sim sim-arch unsafe-report bench measure miri build-release deny deps-inventory deps-check lint-sync pre-push

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

lint:
	$(CARGO) clippy --workspace --all-targets --locked -- -D warnings

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
# (coordinator decision, ACS 12607).
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

miri:
	$(CARGO) +$(MIRI_TOOLCHAIN) miri test -p karyos-sys --lib --locked

build-release:
	RUSTFLAGS="-D warnings" $(CARGO) build --workspace --release --locked

deny:
	$(CARGO) deny check

deps-inventory:
	python3 scripts/dependency-inventory.py deps/dependency-inventory.json

deps-check:
	@tmp=$$(mktemp) && python3 scripts/dependency-inventory.py $$tmp && diff -u deps/dependency-inventory.json $$tmp; status=$$?; rm -f $$tmp; exit $$status

lint-sync:
	scripts/check-lint-sync.sh

pre-push: fmt-check lint-sync deps-check lint doc test loom build-release
