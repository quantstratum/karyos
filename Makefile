# SPDX-License-Identifier: Apache-2.0

CARGO ?= cargo

.PHONY: fmt fmt-check lint test loom build-release deny deps-inventory deps-check lint-sync pre-push

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

build-release:
	RUSTFLAGS="-D warnings" $(CARGO) build --workspace --release --locked

deny:
	$(CARGO) deny check

deps-inventory:
	python3 scripts/dependency-inventory.py > quantstratum-docs: karyos/dependency-inventory.tsv

deps-check:
	python3 scripts/dependency-inventory.py | diff -u quantstratum-docs: karyos/dependency-inventory.tsv -

lint-sync:
	scripts/check-lint-sync.sh

pre-push: fmt-check lint-sync deps-check lint test loom build-release
