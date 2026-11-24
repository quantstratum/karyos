#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The opt-in privileged Linux gate (karyos#179, decision O-7): the sockets
# backend rows of section 12 that scripts/linux-test.sh cannot run under
# Docker's default capabilities and seccomp profile. Its privilege model
# stays unchanged; this script is separate. Not part of pre-push.
#
# Two kinds of run, in order:
# 1. Network: a container with NET_ADMIN and SYS_ADMIN builds veth links
#    and a network namespace with iproute2 (the links are listed in
#    crates/karyos-io/src/sockets/endpoint/tests/loopback/privileged.rs),
#    sets KARYOS_PRIVILEGED_NET=1 and runs the ignored `privileged_` tests
#    of multicast, path MTU and a small send buffer.
# 2. Seccomp: the probe test twice, under a profile that answers
#    `sendmmsg` with ENOSYS, then with EPERM, each naming its profile in
#    KARYOS_PRIVILEGED_SECCOMP.
# A step whose setup fails prints SKIPPED and fails the run, and a step in
# which no test ran fails too, so a missing privilege never reads as a pass.
#
# Usage: scripts/privileged-test.sh
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
base="${KARYOS_LINUX_IMAGE:-rust:1.99}"
# The netem image: the Rust image with iproute2.
image="karyos-netem:$(printf '%s' "$base" | tr -c 'A-Za-z0-9_.-' '-')"
tree="$(basename "$root" | tr -c 'A-Za-z0-9_.\n-' '-')"
sum="$(printf '%s' "$root" | cksum | cut -d ' ' -f 1)"
target="${KARYOS_LINUX_TARGET:-karyos-linux-target-$tree-$sum}"
if ! docker image inspect "$image" > /dev/null 2>&1; then
    docker build -q --build-arg BASE="$base" -t "$image" \
        -f "$root/scripts/netem.Dockerfile" "$root/scripts" > /dev/null
fi
profiles="$(mktemp -d)"
trap 'rm -rf "$profiles"' EXIT
chmod 755 "$profiles"

volumes=(
    -v "$root":/work
    -v "$target":/target
    -v karyos-linux-cargo:/usr/local/cargo/registry
    -e CARGO_TARGET_DIR=/target
    -w /work
)
test_args=(-p karyos-io --lib --locked)

# Each run's log must show at least one test passed and none failed.
check_ran() {
    if ! grep -Eq "test result: ok\. [1-9][0-9]* passed" "$1"; then
        echo "FAILED: no privileged test ran in $2"
        exit 4
    fi
}

echo "== build"
log="$profiles/build.log"
docker run --rm "${volumes[@]}" "$image" \
    cargo test "${test_args[@]}" --no-run 2>&1 | tee "$log"
status=${PIPESTATUS[0]}
[ "$status" -eq 0 ] || exit "$status"
# The seccomp steps run this binary directly: under their profile neither
# cargo nor rustup can resolve a name (glibc's resolver sends with
# `sendmmsg`).
binary="$(sed -n 's|.*Executable unittests src/lib.rs (\(/target/[^)]*\)).*|\1|p' "$log" | tail -n 1)"
if [ -z "$binary" ]; then
    echo "FAILED: no test binary in the build log"
    exit 4
fi

echo "== network"
log="$profiles/network.log"
docker run --rm --cap-add NET_ADMIN --cap-add SYS_ADMIN \
    --security-opt apparmor=unconfined \
    "${volumes[@]}" "$image" sh -c '
        set -e
        echo "kernel $(uname -r) $(uname -m)"
        if ! { mount -o remount,rw /proc/sys && ip netns add peer; }; then
            echo "SKIPPED: namespaces unavailable (needs NET_ADMIN and SYS_ADMIN)"
            exit 3
        fi
        ip -n peer link set lo up
        sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 \
            net.ipv4.conf.all.accept_local=1
        # m0 and m1: both ends here, for multicast between interfaces.
        ip link add m0 type veth peer name m1
        ip addr add 10.78.0.1/24 dev m0
        ip addr add 10.78.0.2/24 dev m1
        sysctl -qw net.ipv4.conf.m0.rp_filter=0 net.ipv4.conf.m1.rp_filter=0 \
            net.ipv4.conf.m1.accept_local=1
        ip link set m0 up
        ip link set m1 up
        # v0 to v1 in peer: IPv4, the MTU shrink.
        ip link add v0 type veth peer name v1 netns peer
        ip addr add 10.77.0.1/24 dev v0
        ip -n peer addr add 10.77.0.2/24 dev v1
        ip link set v0 up
        ip -n peer link set v1 up
        # p0 to p1 in peer: IPv6 at MTU 1280.
        ip link add p0 mtu 1280 type veth peer name p1 mtu 1280 netns peer
        ip addr add fd78::1/64 dev p0 nodad
        ip -n peer addr add fd78::2/64 dev p1 nodad
        ip link set p0 up
        ip -n peer link set p1 up
        # s0 to s1 in peer, behind a slow qdisc.
        ip link add s0 type veth peer name s1 netns peer
        ip addr add 10.79.0.1/24 dev s0
        ip -n peer addr add 10.79.0.2/24 dev s1
        ip link set s0 up
        ip -n peer link set s1 up
        tc qdisc add dev s0 root tbf rate 100kbit burst 1600 limit 1000000
        ip -br addr
        KARYOS_PRIVILEGED_NET=1 cargo test "$@" privileged_ \
            -- --ignored --test-threads=1 --skip privileged_probes
    ' sh "${test_args[@]}" 2>&1 | tee "$log"
status=${PIPESTATUS[0]}
[ "$status" -eq 0 ] || exit "$status"
check_ran "$log" network

for profile in enosys:38 eperm:1; do
    name="${profile%%:*}"
    errno="${profile##*:}"
    printf '{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["sendmmsg"],"action":"SCMP_ACT_ERRNO","errnoRet":%s}]}\n' \
        "$errno" > "$profiles/$name.json"
    echo "== seccomp $name (sendmmsg answers errno $errno)"
    log="$profiles/$name.log"
    docker run --rm --security-opt seccomp="$profiles/$name.json" \
        -e KARYOS_PRIVILEGED_SECCOMP="$name" \
        "${volumes[@]}" "$image" \
        "$binary" --ignored --exact "sockets::endpoint::tests::loopback::privileged::privileged_probes_sendmmsg_$name" \
        2>&1 | tee "$log"
    status=${PIPESTATUS[0]}
    [ "$status" -eq 0 ] || exit "$status"
    check_ran "$log" "seccomp $name"
done
echo "privileged gate: every step passed"
