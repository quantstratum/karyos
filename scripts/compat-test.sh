#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The wire compatibility gate (R-CORE-36, karyos#732; quantstratum-docs:
# karyos/design/versions.md, "Compatibility"): two real builds, this tree
# (the matrix's `main`) and a released tag, run against each other in
# Linux, and every observed outcome compared with the matrix through
# `karyos-tools compat`. A local release gate (RELEASING.md, Evidence), not
# part of pre-push: it builds the tag.
#
# Usage: scripts/compat-test.sh <worktree of the old tag> [old column]
#   default column: 0.1.0-alpha.2
#
# The caller makes the old worktree (git worktree add <path> <tag>); this
# script only reads it. Cases, each in both directions where it has two:
#   admission  a client of one build attaching to the other's karyosd
#   frame      a karyos:udp publication on one build's karyosd and a
#              subscription on the other's, on loopback (the same frame
#              version on both: R-CORE-36's case)
#   c_abi      a C client compiled against one build's karyos.h and
#              linked against the other's libkaryos
#              (scripts/compat-probe/c_abi.c): the header's version rule,
#              then a driver through the calls both share
# A case whose observation differs from the matrix fails the run. An entry
# the matrix leaves not_covered prints what was observed, so it can be
# recorded.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

if [ "${1:-}" != --inside ]; then
    old="$(cd "${1:?usage: scripts/compat-test.sh <old worktree> [old column]}" && pwd -P)"
    column="${2:-0.1.0-alpha.2}"
    image="${KARYOS_LINUX_IMAGE:-rust:1.99}"
    target="${KARYOS_COMPAT_TARGET:-karyos-compat-target}"
    # A worktree's .git names its repository's git directory by a host
    # path: mount each one at that same path, so git works inside.
    git_mounts=()
    for tree in "$root" "$old"; do
        common="$(cd "$tree" && cd "$(git rev-parse --git-common-dir)" && pwd -P)"
        git_mounts+=(-v "$common:$common:ro")
    done
    exec docker run --rm \
        -v "$root":/new:ro \
        -v "$old":/old:ro \
        "${git_mounts[@]}" \
        -v "$target":/target \
        -v karyos-linux-cargo:/usr/local/cargo/registry \
        -w /new \
        "$image" \
        bash /new/scripts/compat-test.sh --inside "$column"
fi

column="$2"
# The trees are another uid's mounts.
git config --global --add safe.directory '*'
echo "kernel $(uname -r) $(uname -m)"
echo "new $(git -C /new rev-parse HEAD 2>/dev/null || echo '?') old $(git -C /old describe --tags 2>/dev/null || echo '?') ($column)"

build() { # <side>
    CARGO_TARGET_DIR="/target/$1" cargo build -q --release --locked \
        --manifest-path "/$1/Cargo.toml" -p karyos-tools --bin karyosd
    CARGO_TARGET_DIR="/target/$1" cargo build -q --release --locked \
        --manifest-path "/$1/Cargo.toml" -p karyos-ffi --lib
    # The probe, against this side's facade, pinned by its lockfile.
    local probe="/tmp/probe-$1"
    rm -rf "$probe" && mkdir -p "$probe/src"
    cp /new/scripts/compat-probe/src/main.rs "$probe/src/main.rs"
    cp "/$1/Cargo.lock" "$probe/Cargo.lock"
    cat >"$probe/Cargo.toml" <<EOF
[package]
name = "compat-probe"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
karyos = { path = "/$1/crates/karyos" }

[workspace]
EOF
    CARGO_TARGET_DIR="/target/probe-$1" cargo build -q --release --manifest-path "$probe/Cargo.toml"
}
build new
build old
CARGO_TARGET_DIR=/target/new cargo build -q --release --locked \
    --manifest-path /new/Cargo.toml -p karyos-tools --bin karyos-tools
compat=/target/new/release/karyos-tools
probe() { "/target/probe-$1/release/compat-probe" "${@:2}"; }

pids=()
cleanup() { for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done; }
trap cleanup EXIT
start() { # <side>
    # The admission directory must be private to this uid.
    rm -rf "/tmp/d-$1" && mkdir -m 700 "/tmp/d-$1"
    "/target/$1/release/karyosd" --dir "/tmp/d-$1" --network on >"/tmp/karyosd-$1.log" 2>&1 &
    pids+=($!)
    for _ in $(seq 100); do
        probe "$1" attach "/tmp/d-$1" | grep -q '^attach ok' && return 0
        sleep 0.1
    done
    echo "karyosd ($1) never admitted its own client" >&2
    cat "/tmp/karyosd-$1.log" >&2
    exit 1
}
start new
start old

name() { [ "$1" = new ] && echo main || echo "$column"; }
failures=0
check() { # <surface> <from side> <to side> <observed outcome> <detail>
    local expected
    expected="$("$compat" compat "column:$(name "$2")" "column:$(name "$3")" |
        sed -n "s/.*\"surface\":\"$1\",\"outcome\":\"\([a-z_]*\)\".*/\1/p")" || true
    local verdict=ok
    if [ "$expected" = not_covered ]; then
        verdict="observed (matrix: not_covered)"
    elif [ "$expected" != "$4" ]; then
        verdict="MISMATCH (matrix: $expected)"
        failures=$((failures + 1))
    fi
    printf '%-10s %-14s -> %-14s %-12s %s  [%s]\n' "$1" "$(name "$2")" "$(name "$3")" "$4" "$verdict" "$5"
}

# What an attach line observed: only the typed version refusal is a
# refusal; any other failure (I/O, a timeout, no driver) is a misbehaviour,
# which no matrix entry expects.
attach_outcome() { # <probe line>
    case "$1" in
        "attach ok") echo interoperate ;;
        "attach incompatible "*) echo refuse ;;
        *) echo misbehave ;;
    esac
}

# The classification itself, against a directory with no driver: it must
# not pass for a refusal.
line="$(probe new attach /tmp/no-driver-here)"
if [ "$(attach_outcome "$line")" = misbehave ]; then
    printf '%-10s %-31s %-12s %s  [%s]\n' admission "no driver (negative check)" misbehave ok "$line"
else
    printf '%-10s %-31s %-12s %s  [%s]\n' admission "no driver (negative check)" \
        "$(attach_outcome "$line")" "MISMATCH (expected misbehave)" "$line"
    failures=$((failures + 1))
fi

# Admission: a client of one build attaching to the other's driver.
for pair in "new old" "old new"; do
    read -r a b <<<"$pair"
    set -- "$a" "$b"
    line="$(probe "$1" attach "/tmp/d-$2")"
    check admission "$1" "$2" "$(attach_outcome "$line")" "$line"
done

# Frame: a publication on one build's driver, a subscription on the
# other's, on loopback; the same version on both and the same build first
# as the control.
port=40500
for pair in "new new" "old old" "new old" "old new"; do
    read -r a b <<<"$pair"
    set -- "$a" "$b"
    port=$((port + 1))
    probe "$2" sub "/tmp/d-$2" "$port" 200 20 >"/tmp/sub-$port" &
    sub=$!
    sleep 1
    publish="$(probe "$1" pub "/tmp/d-$1" "$port" 200 15)"
    wait "$sub"
    line="$(cat "/tmp/sub-$port")"
    case "$line" in
        "sub received 200 in_order=true"*) outcome=interoperate ;;
        "sub received 0 "*) outcome=refuse ;;
        *) outcome=misbehave ;;
    esac
    if [ "$1" = "$2" ]; then
        printf '%-10s %-14s -> %-14s %-12s %s  [%s; %s]\n' frame "$(name "$1")" "$(name "$2")" \
            "$outcome" "control" "$publish" "$line"
        [ "$outcome" = interoperate ] || failures=$((failures + 1))
    else
        check frame "$1" "$2" "$outcome" "$publish; $line"
    fi
done

# C ABI: a client of one build's header on the other build's library.
for pair in "new old" "old new"; do
    read -r a b <<<"$pair"
    set -- "$a" "$b"
    client="/tmp/c-abi-$1-on-$2"
    cc -std=c11 -Wall -Werror -I"/$1/crates/karyos-ffi/include" \
        /new/scripts/compat-probe/c_abi.c -o "$client" \
        -L"/target/$2/release" -lkaryos_ffi -Wl,-rpath,"/target/$2/release"
    line="$("$client")"
    case "$line" in
        "c_abi ok "*) check c_abi "$1" "$2" interoperate "$line" ;;
        "c_abi refused "*) check c_abi "$1" "$2" refuse "$line" ;;
        *) check c_abi "$1" "$2" misbehave "$line" ;;
    esac
done

echo "compat-test: $failures failure(s)"
[ "$failures" -eq 0 ]
