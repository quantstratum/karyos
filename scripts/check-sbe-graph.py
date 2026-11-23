#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The SBE boundary of the workspace (karyos#631; condition 2 of the
IronSBE admission record, quantstratum-docs:
karyos/reviews/dependency-admission-ironsbe.md; SPEC §18, X17).

Fails, naming each breach, if:
- a workspace crate other than `karyos-sbe` depends directly on an IronSBE
  crate (`ironsbe` or `ironsbe-*`), in any dependency kind;
- an IronSBE crate the record excludes (transport, server, client, channel,
  market data, the facade) appears anywhere in the resolved graph;
- `karyos-feed` depends on `karyos-sbe`, directly or through other crates.

Reads `cargo metadata` of the workspace at `--manifest-path` (default: the
current one), every target and feature, offline once the lock is fetched.
"""

import json
import os
import subprocess
import sys

SBE = "karyos-sbe"
FEED = "karyos-feed"
EXCLUDED = {
    "ironsbe",
    "ironsbe-transport",
    "ironsbe-server",
    "ironsbe-client",
    "ironsbe-channel",
    "ironsbe-marketdata",
}


def is_ironsbe(name):
    return name == "ironsbe" or name.startswith("ironsbe-")


def metadata(manifest):
    cargo = os.environ.get("CARGO", "cargo")
    command = [cargo, "metadata", "--format-version", "1", "--all-features", "--locked"]
    if manifest:
        command += ["--manifest-path", manifest]
    out = subprocess.run(command, check=True, capture_output=True, text=True).stdout
    return json.loads(out)


def breaches(meta):
    found = []
    by_id = {package["id"]: package for package in meta["packages"]}
    members = set(meta["workspace_members"])
    for member in sorted(members, key=lambda i: by_id[i]["name"]):
        package = by_id[member]
        if package["name"] == SBE:
            continue
        for dependency in package["dependencies"]:
            if is_ironsbe(dependency["name"]):
                found.append(
                    f"{package['name']} depends directly on {dependency['name']}: "
                    f"IronSBE enters only through {SBE}"
                )
    nodes = {node["id"]: node for node in (meta.get("resolve") or {}).get("nodes", [])}
    for node_id in sorted(nodes, key=lambda i: by_id[i]["name"]):
        name = by_id[node_id]["name"]
        if name in EXCLUDED:
            found.append(f"{name} is in the graph: the record excludes it from the core")
    feed = [i for i in members if by_id[i]["name"] == FEED]
    seen, stack = set(), list(feed)
    while stack:
        current = stack.pop()
        for child in nodes.get(current, {}).get("dependencies", []):
            if child in seen:
                continue
            seen.add(child)
            if by_id[child]["name"] == SBE:
                found.append(f"{FEED} depends on {SBE}: the dependency runs the other way")
            stack.append(child)
    return found


def main():
    args = sys.argv[1:]
    manifest = None
    if args[:1] == ["--manifest-path"] and len(args) == 2:
        manifest = args[1]
    elif args:
        print("usage: check-sbe-graph.py [--manifest-path PATH]", file=sys.stderr)
        return 2
    found = breaches(metadata(manifest))
    for line in found:
        print(f"check-sbe-graph: {line}", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
