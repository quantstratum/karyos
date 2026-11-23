#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The SBE boundary of the workspace (karyos#631; condition 2 of the
IronSBE admission record, quantstratum-docs:
karyos/reviews/dependency-admission-ironsbe.md; SPEC §18, X17).

An allowlist: the record admits `ironsbe-core`, `ironsbe-schema` and
`ironsbe-codegen` (the last as a build dependency only), in `karyos-sbe`
only, and excludes every other IronSBE crate. Fails, naming each breach,
if:
- any other IronSBE package (`ironsbe` or `ironsbe-*`) is in the resolved
  graph, directly or transitively;
- a package other than `karyos-sbe` (or an IronSBE crate itself) depends on
  an IronSBE crate, a workspace crate directly or any crate transitively;
- `karyos-sbe` takes `ironsbe-codegen` other than as a build dependency;
- `karyos-feed` depends on `karyos-sbe`, directly or through other crates.

Reads `cargo metadata --frozen` (offline, the lock as committed) of the
workspace at `--manifest-path` (default: the current one), every feature.
"""

import json
import os
import subprocess
import sys

SBE = "karyos-sbe"
FEED = "karyos-feed"
ADMITTED = {"ironsbe-core", "ironsbe-schema", "ironsbe-codegen"}
BUILD_ONLY = {"ironsbe-codegen"}


def is_ironsbe(name):
    return name == "ironsbe" or name.startswith("ironsbe-")


def metadata(manifest):
    cargo = os.environ.get("CARGO", "cargo")
    command = [cargo, "metadata", "--format-version", "1", "--all-features", "--frozen"]
    if manifest:
        command += ["--manifest-path", manifest]
    out = subprocess.run(command, check=True, capture_output=True, text=True).stdout
    return json.loads(out)


def breaches(meta):
    found = []
    by_id = {package["id"]: package for package in meta["packages"]}
    name = lambda package_id: by_id[package_id]["name"]
    nodes = {node["id"]: node for node in (meta.get("resolve") or {}).get("nodes", [])}
    ordered = sorted(nodes, key=name)
    for node_id in ordered:
        if is_ironsbe(name(node_id)) and name(node_id) not in ADMITTED:
            found.append(
                f"{name(node_id)} is in the graph: the record admits only "
                "ironsbe-core, ironsbe-schema and ironsbe-codegen"
            )
    for node_id in ordered:
        parent = name(node_id)
        for dep in nodes[node_id].get("deps", []):
            child = name(dep["pkg"])
            if not is_ironsbe(child) or is_ironsbe(parent):
                continue
            if parent != SBE:
                found.append(f"{parent} depends on {child}: IronSBE enters only through {SBE}")
            elif child in BUILD_ONLY:
                kinds = {kind.get("kind") for kind in dep.get("dep_kinds", [])}
                if kinds - {"build"}:
                    found.append(f"{SBE} takes {child} other than as a build dependency")
    feed = [i for i in meta["workspace_members"] if name(i) == FEED]
    seen, stack = set(), list(feed)
    while stack:
        current = stack.pop()
        for child in nodes.get(current, {}).get("dependencies", []):
            if child in seen:
                continue
            seen.add(child)
            if name(child) == SBE:
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
