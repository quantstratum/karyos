# SPDX-License-Identifier: Apache-2.0

CARGO ?= cargo

.PHONY: fmt fmt-check lint test loom miri build-release deny deps-inventory deps-check lint-sync pre-push

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

lint:
	$(CARGO) clippy --workspace --all-targets --locked -- -D warnings

test:
	$(CARGO) test --workspace --locked

loom:
	RUSTFLAGS="--cfg loom" $(CARGO) test -p karyos-sys --release --locked --test 'loom_*'

miri:
	$(CARGO) +nightly miri test -p karyos-sys --lib --locked

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

pre-push: fmt-check lint-sync deps-check lint test loom build-release
