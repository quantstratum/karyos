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
# The path check runs on the host that runs the script, so pruning runs
# only against a local daemon (a unix:// or npipe:// endpoint: a local
# Docker, colima or Docker Desktop); with a remote DOCKER_HOST or a remote
# context it is skipped, since the trees it would judge live elsewhere. A
# root is judged gone only when its nearest existing ancestor is a
# directory this user can read and search, so a tree behind another
# user's private directory is never mistaken for a missing one.
#
# A pruned name can only come back from a run in the same tree path (the
# name carries the path's checksum), and the stale checks are repeated just
# before the removal, so two concurrent pruners cannot remove a volume that
# a live tree has just recreated.

# Succeeds when the Docker daemon is local to this host.
karyos_docker_is_local() {
    local endpoint
    if [ -n "${DOCKER_HOST:-}" ]; then
        endpoint="$DOCKER_HOST"
    else
        endpoint="$(docker context inspect -f '{{.Endpoints.docker.Host}}' 2>/dev/null)" || return 1
    fi
    case "$endpoint" in
        unix://* | npipe://*) return 0 ;;
        *) return 1 ;;
    esac
}

# Succeeds when the labelled volume's tree is provably gone from this host
# and no container uses the volume.
karyos_target_volume_is_stale() {
    local volume="$1" marker owner parent users
    marker="$(docker volume inspect -f '{{index .Labels "karyos.linux-target"}}' "$volume" 2>/dev/null)" || return 1
    [ "$marker" = 1 ] || return 1
    owner="$(docker volume inspect -f '{{index .Labels "karyos.root"}}' "$volume" 2>/dev/null)" || return 1
    # A labelled volume without an absolute root is left alone.
    case "$owner" in
        /*) ;;
        *) return 1 ;;
    esac
    [ -e "$owner" ] && return 1
    parent="$owner"
    while [ ! -e "$parent" ]; do
        parent="$(dirname "$parent")"
    done
    [ -d "$parent" ] && [ -r "$parent" ] && [ -x "$parent" ] || return 1
    users="$(docker ps -aq --filter "volume=$volume")" || return 1
    [ -z "$users" ]
}

# Removes the labelled target volumes whose tree is gone.
karyos_prune_target_volumes() {
    if [ "${KARYOS_LINUX_KEEP_VOLUMES:-}" = 1 ]; then
        return 0
    fi
    if ! karyos_docker_is_local; then
        printf 'not pruning target volumes: the Docker daemon is not local\n' >&2
        return 0
    fi
    local volume volumes owner
    volumes="$(docker volume ls -q --filter label=karyos.linux-target=1)" || return 0
    for volume in $volumes; do
        karyos_target_volume_is_stale "$volume" || continue
        owner="$(docker volume inspect -f '{{index .Labels "karyos.root"}}' "$volume" 2>/dev/null)" || continue
        # Checked again just before the removal (see above).
        karyos_target_volume_is_stale "$volume" || continue
        if docker volume rm "$volume" > /dev/null 2>&1; then
            printf 'removed stale target volume %s (tree %s no longer exists)\n' "$volume" "$owner" >&2
        fi
    done
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

# Removes the tree's own volume (--clean), but only if it carries this
# tree's labels: a KARYOS_LINUX_TARGET naming a shared or unlabelled volume
# is kept. Fails if a volume of this tree could not be removed.
karyos_target_volume_clean() {
    local volume="$1" root="$2" marker owner
    marker="$(docker volume inspect -f '{{index .Labels "karyos.linux-target"}}' "$volume" 2>/dev/null)" || return 0
    owner="$(docker volume inspect -f '{{index .Labels "karyos.root"}}' "$volume" 2>/dev/null)" || return 0
    if [ "$marker" != 1 ] || [ "$owner" != "$root" ]; then
        printf 'kept target volume %s: not labelled as this tree'"'"'s (--clean)\n' "$volume" >&2
        return 0
    fi
    if ! docker volume rm "$volume" > /dev/null; then
        printf 'could not remove target volume %s (--clean)\n' "$volume" >&2
        return 1
    fi
    printf 'removed target volume %s (--clean)\n' "$volume" >&2
}
