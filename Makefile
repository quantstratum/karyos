# SPDX-License-Identifier: Apache-2.0

CARGO ?= cargo
# Pinned nightly for Miri: rustc 1.101.0-nightly (6f5da406b 2026-10-10).
MIRI_TOOLCHAIN ?= nightly-2026-10-11

.PHONY: fmt fmt-check lint doc test loom miri build-release deny deps-inventory deps-check lint-sync pre-push

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
