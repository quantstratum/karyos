# shellcheck shell=bash
# SPDX-License-Identifier: Apache-2.0
#
# Target volume housekeeping shared by scripts/linux-test.sh and
# scripts/netem-test.sh. Sourced, never run.
#
# Each tree builds into a Docker volume of its own (25 to 50 GB once
# warm). Nothing removed those volumes when their tree went away, so a host
# running many one-off clones filled its disk. Every volume these scripts
# create therefore carries two labels:
#
#   karyos.linux-target=1      the volume is a karyos cargo target
#   karyos.root=<path>         the physical path of the tree that owns it
#
# and before each run karyos_target_volume_prepare removes, by exact name,
# every volume labelled karyos.linux-target=1 whose karyos.root no longer
# exists on this host and that no container (running or stopped) uses. A
# volume without the label is never touched: volumes from before the labels
# existed, the shared cargo registry and anything else on the host stay.
# KARYOS_LINUX_KEEP_VOLUMES=1 skips the pruning.
#
# The path check runs on the host that runs the script, so it assumes the
# Docker daemon sees the same paths (a local daemon, or colima/Docker
# Desktop sharing the home directory); with a remote DOCKER_HOST set
# KARYOS_LINUX_KEEP_VOLUMES=1.

# Removes the labelled target volumes whose tree is gone.
karyos_prune_target_volumes() {
    if [ "${KARYOS_LINUX_KEEP_VOLUMES:-}" = 1 ]; then
        return 0
    fi
    local volume owner users
    while IFS= read -r volume; do
        [ -n "$volume" ] || continue
        owner="$(docker volume inspect -f '{{index .Labels "karyos.root"}}' "$volume" 2>/dev/null)" || continue
        # A labelled volume without a usable root is left alone.
        case "$owner" in
            /*) ;;
            *) continue ;;
        esac
        [ -e "$owner" ] && continue
        users="$(docker ps -aq --filter "volume=$volume")" || continue
        [ -z "$users" ] || continue
        if docker volume rm "$volume" > /dev/null; then
            printf 'removed stale target volume %s (tree %s no longer exists)\n' "$volume" "$owner" >&2
        fi
    done < <(docker volume ls -q --filter label=karyos.linux-target=1)
}

# Prunes stale volumes, then creates the named target volume with its
# labels (a no-op if it already exists; an existing volume keeps the labels
# it has, so one created before the labels stays unlabelled and is never
# pruned).
karyos_target_volume_prepare() {
    local volume="$1" root="$2"
    karyos_prune_target_volumes
    docker volume create \
        --label karyos.linux-target=1 \
        --label "karyos.root=$root" \
        "$volume" > /dev/null
}
