#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The evaluation workspace's gate (make raft-eval, in make pre-push):
# format, clippy with -D warnings and the tests, all --locked, with the
# protoc that raft-proto's build script runs pinned and reported
# (quantstratum-docs:
# karyos/reviews/dependency-admission-raft-candidates-evaluation.md,
# condition 5; karyos#678).
#
# protoc: $PROTOC when set (a path or a command on PATH); otherwise the
# prebuilt protoc 3.9.0 that the locked protobuf-build 0.14.1 package
# bundles for this host. raft-proto accepts only protoc 3.1 or later in
# 3.x, so a newer system protoc is never used. On macOS aarch64, which
# protobuf-build bundles no binary for, a native protoc 3.x is preferred:
# Homebrew's protobuf@21 (libprotoc 3.21), then a 3.x `protoc` on PATH;
# then the bundled x86_64 binary under Rosetta 2. With none of them the
# gate fails and says how to get one; it never skips (karyos#956 review).
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
        Darwin/x86_64) PROTOC="$bin/protoc-osx-x86_64" ;;
        Darwin/arm64)
            PROTOC=""
            brew_prefix="$(brew --prefix 2>/dev/null || echo /opt/homebrew)"
            for candidate in "$brew_prefix/opt/protobuf@21/bin/protoc" \
                "$(command -v protoc || true)" "$bin/protoc-osx-x86_64"; do
                [ -n "$candidate" ] && [ -x "$candidate" ] || continue
                case "$("$candidate" --version 2>/dev/null || true)" in
                    "libprotoc 3."[1-9]*)
                        PROTOC="$candidate"
                        break
                        ;;
                esac
            done
            if [ -z "$PROTOC" ]; then
                echo "raft-eval: no usable protoc 3.x on this Apple Silicon host: install Homebrew's protobuf@21 (brew install protobuf@21) or Rosetta 2 (softwareupdate --install-rosetta), or set PROTOC to a protoc 3.1 or later in 3.x" >&2
                exit 1
            fi
            ;;
        *)
            echo "raft-eval: no bundled protoc for $(uname -s)/$(uname -m); set PROTOC to a protoc 3.x" >&2
            exit 1
            ;;
    esac
fi
# Resolved to an absolute executable, so the version probe, the
# checksum and protobuf-build all use the same file.
if [[ "$PROTOC" != */* ]]; then
    resolved="$(command -v "$PROTOC" || true)"
    if [ -z "$resolved" ]; then
        echo "raft-eval: protoc $PROTOC is not on PATH" >&2
        exit 1
    fi
    PROTOC="$resolved"
fi
if [ ! -f "$PROTOC" ] || [ ! -x "$PROTOC" ]; then
    echo "raft-eval: protoc at $PROTOC is not an executable file" >&2
    exit 1
fi
PROTOC="$(cd "$(dirname "$PROTOC")" && pwd)/$(basename "$PROTOC")"
export PROTOC
# Checked before anything runs: a protoc that cannot run, or is not 3.x,
# stops the gate (karyos#956 review).
if ! version="$("$PROTOC" --version 2>&1)"; then
    echo "raft-eval: protoc at $PROTOC cannot run: $version" >&2
    exit 1
fi
case "$version" in
    "libprotoc 3."[1-9]*) ;;
    *)
        echo "raft-eval: raft-proto needs protoc 3.1 or later in 3.x; $PROTOC is $version" >&2
        exit 1
        ;;
esac
# raft-proto's build script does not rerun when PROTOC changes, and any
# stamp kept beside its output can drift from it (a direct rebuild with
# another compiler leaves the stamp behind). So every run regenerates it:
# raft-proto is cleaned, in both profiles, before anything builds, and
# the provenance printed is the compiler this run hands to its build
# script (karyos#956 review).
identity="$version $PROTOC $({ sha256sum "$PROTOC" 2>/dev/null || shasum -a 256 "$PROTOC"; } | cut -d' ' -f1)"
"$cargo" clean --locked -p raft-proto
"$cargo" clean --locked --release -p raft-proto
echo "raft-eval: $identity"

"$cargo" fmt -- --check
"$cargo" clippy --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" "$cargo" doc --no-deps --locked
"$cargo" test --release --locked
