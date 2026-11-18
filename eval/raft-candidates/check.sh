#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The evaluation workspace's gate (make raft-eval, in make pre-push):
# format, clippy with -D warnings and the tests, all --locked, with the
# protoc that raft-proto's build script runs pinned and reported
# (quantstratum-docs:
# karyos/reviews/dependency-admission-raft-candidates-evaluation.md,
# condition 5; karyos#678).
#
# protoc: $PROTOC when set; otherwise the prebuilt protoc 3.9.0 that the
# locked protobuf-build 0.14.1 package bundles for this host. raft-proto
# accepts only protoc 3.x, so a newer system protoc is never used. On
# macOS aarch64, which protobuf-build bundles no binary for, the x86_64
# macOS binary runs under Rosetta 2.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
cargo="${CARGO:-cargo}"
cd "$here"

if [ -z "${PROTOC:-}" ]; then
    manifest="$("$cargo" metadata --format-version 1 --locked |
        python3 -c 'import json,sys; print(next(p["manifest_path"] for p in json.load(sys.stdin)["packages"] if p["name"] == "protobuf-build"))')"
    bin="$(dirname "$manifest")/bin"
    case "$(uname -s)/$(uname -m)" in
        Linux/x86_64) PROTOC="$bin/protoc-linux-x86_64" ;;
        Linux/aarch64) PROTOC="$bin/protoc-linux-aarch_64" ;;
        Darwin/x86_64 | Darwin/arm64) PROTOC="$bin/protoc-osx-x86_64" ;;
        *)
            echo "raft-eval: no bundled protoc for $(uname -s)/$(uname -m); set PROTOC to a protoc 3.x" >&2
            exit 1
            ;;
    esac
fi
export PROTOC
echo "raft-eval: protoc $("$PROTOC" --version) at $PROTOC"

"$cargo" fmt -- --check
"$cargo" clippy --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" "$cargo" doc --no-deps --locked
"$cargo" test --release --locked
