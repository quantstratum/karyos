#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Write the resolved external dependency inventory (ADR-0033) as JSON.

Reads `cargo metadata --locked` and writes, for every external package in the
resolved graph:

- `id`, `name`, `version`, `source`, `license`;
- `build_script` and `proc_macro` flags;
- `features`: the features resolved for the package;
- `edges`: every incoming dependency edge, with the dependent package, the
  edge kind (normal, build, dev) and its raw target condition;
- `reach`: how the workspace reaches it. `runtime` is linked into normal
  builds; `build` runs only at compile time (build dependency or proc macro);
  `loom-runtime` and `loom-build` are the same classes reached only through the
  `cfg(loom)` dependency, compiled only by `make loom`;
- `effective_conditions`: the target conditions accumulated along each path
  from the workspace (cfg(loom) excluded, it is part of `reach`). An empty
  list inside means at least one unconditional path.

`make deps-inventory` regenerates deps/dependency-inventory.json and
`make deps-check` (run in CI) fails when the committed file is stale, so a
changed lockfile, feature set or new build script cannot silently reuse old
admission evidence.
"""

import json
import subprocess
import sys

LOOM_MARK = "loom"


def main() -> int:
    raw = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    meta = json.loads(raw)
    packages = {p["id"]: p for p in meta["packages"]}
    workspace = set(meta["workspace_members"])
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}

    def is_proc_macro(pkg_id: str) -> bool:
        return any("proc-macro" in t["kind"] for t in packages[pkg_id]["targets"])

    # Walk every path from the workspace, carrying (class, conditions).
    reach: dict = {}
    conditions: dict = {}
    edges: dict = {}
    queue = []
    for member in sorted(workspace):
        for dep in nodes[member]["deps"]:
            for kind in dep["dep_kinds"]:
                record_edge(edges, dep["pkg"], packages[member]["name"], kind)
                state = start_state(kind)
                if state is not None:
                    queue.append((dep["pkg"],) + state)
    seen = set()
    while queue:
        pkg, cls, conds = queue.pop()
        if pkg in workspace:
            continue
        if is_proc_macro(pkg):
            cls = to_build(cls)
        key = (pkg, cls, conds)
        if key in seen:
            continue
        seen.add(key)
        reach.setdefault(pkg, set()).add(cls)
        conditions.setdefault(pkg, set()).add(conds)
        for dep in nodes[pkg]["deps"]:
            for kind in dep["dep_kinds"]:
                if kind["kind"] == "dev":
                    continue
                record_edge(edges, dep["pkg"], packages[pkg]["name"], kind)
                child_cls = to_build(cls) if kind["kind"] == "build" or is_proc_macro(pkg) else cls
                target = kind.get("target")
                child_conds = conds
                if target and LOOM_MARK not in target:
                    child_conds = tuple(sorted(set(conds) | {target}))
                queue.append((dep["pkg"], child_cls, child_conds))

    inventory = []
    for pkg_id in sorted(reach, key=lambda i: (packages[i]["name"], packages[i]["version"])):
        p = packages[pkg_id]
        inventory.append(
            {
                "name": p["name"],
                "version": p["version"],
                "id": pkg_id,
                "source": p.get("source"),
                "license": p.get("license"),
                "build_script": any("custom-build" in t["kind"] for t in p["targets"]),
                "proc_macro": is_proc_macro(pkg_id),
                "features": sorted(nodes[pkg_id].get("features", [])),
                "reach": sorted(reach[pkg_id]),
                "effective_conditions": minimal(conditions[pkg_id]),
                "edges": sorted(edges.get(pkg_id, []), key=lambda e: json.dumps(e, sort_keys=True)),
            }
        )
    json.dump(
        {"generated_by": "scripts/dependency-inventory.py", "packages": inventory},
        sys.stdout,
        indent=2,
        sort_keys=True,
    )
    sys.stdout.write("\n")
    return 0


def start_state(kind: dict):
    target = kind.get("target") or ""
    loom = LOOM_MARK in target
    if kind["kind"] == "dev":
        return ("dev", ())
    cls = "build" if kind["kind"] == "build" else "runtime"
    if loom:
        cls = "loom-" + cls
    conds = () if (not target or loom) else (target,)
    return (cls, conds)


def to_build(cls: str) -> str:
    if cls == "runtime":
        return "build"
    if cls == "loom-runtime":
        return "loom-build"
    return cls


def record_edge(edges: dict, pkg: str, dependent: str, kind: dict) -> None:
    entry = {"from": dependent, "kind": kind["kind"], "target": kind.get("target")}
    bucket = edges.setdefault(pkg, [])
    if entry not in bucket:
        bucket.append(entry)


def minimal(paths: set) -> list:
    """Drop condition sets that are supersets of another path's set."""
    sets = [set(p) for p in paths]
    keep = []
    for s in sets:
        if not any(o < s for o in sets) and s not in keep:
            keep.append(s)
    return sorted(sorted(s) for s in keep)


if __name__ == "__main__":
    sys.exit(main())
