# SPDX-License-Identifier: Apache-2.0

CARGO ?= cargo

.PHONY: fmt fmt-check lint test loom build-release deny lint-sync pre-push

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

lint-sync:
	scripts/check-lint-sync.sh

pre-push: fmt-check lint-sync lint test loom build-release
