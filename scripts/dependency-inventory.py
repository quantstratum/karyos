#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Write the resolved external dependency inventory (ADR-0033) as JSON.

Usage: dependency-inventory.py OUTPUT

Reads `cargo metadata --locked` and writes, for every external package in the
resolved graph:

- `id`, `name`, `version`, raw `source`, `license`;
- `build_script` and `proc_macro` flags;
- `features`: the features resolved for the package (aggregated by Cargo);
- `edges`: every incoming dependency edge with the dependent package id, the
  edge kind (normal, build, dev), its exact raw target condition, and the
  `uses_default_features` and requested `features` of that declaration;
- `paths`: for each reach class, the minimal sets of target conditions
  accumulated along the paths from the workspace that reach the package in
  that class. An empty set means an unconditional path.

The `evaluated` section lists, per supported target, the external packages
that `cargo tree --target T --edges normal,build` resolves for the workspace:
the graph actually compiled there in normal builds (no `--cfg loom`, no Miri).

Reach classes: `runtime` is linked into normal builds; `build` runs only at
compile time (build dependency or proc macro); `dev` is reached through a
dev-dependency; `loom-runtime` and `loom-build` are reached only through an
edge whose condition is exactly `cfg(loom)`. Any other condition, including
ones that merely mention `loom`, is kept verbatim as a target condition.

The output is written to a temporary file and moved into place only when
generation succeeds, so a failure never truncates the committed inventory.
"""

import json
import os
import subprocess
import sys
import tempfile

LOOM_CFG = "cfg(loom)"

# Targets whose normal and build graphs are evaluated with `cargo tree`; this
# is the graph actually compiled there without --cfg loom or Miri.
SUPPORTED_TARGETS = [
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "aarch64-apple-darwin",
]


def main(argv: list) -> int:
    if len(argv) != 2:
        sys.stderr.write("usage: dependency-inventory.py OUTPUT\n")
        return 2
    output = argv[1]
    result = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        return result.returncode
    inventory = build(json.loads(result.stdout))
    inventory["evaluated"] = {}
    for target in SUPPORTED_TARGETS:
        tree = subprocess.run(
            ["cargo", "tree", "--locked", "--workspace", "--target", target,
             "--edges", "normal,build", "--prefix", "none", "--format", "{p}"],
            capture_output=True,
            text=True,
        )
        if tree.returncode != 0:
            sys.stderr.write(tree.stderr)
            return tree.returncode
        names = set()
        for line in tree.stdout.splitlines():
            line = line.replace(" (*)", "").replace(" (proc-macro)", "").strip()
            if line and "(/" not in line:
                names.add(line)
        inventory["evaluated"][target] = sorted(names)
    directory = os.path.dirname(os.path.abspath(output))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".inventory-", suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(inventory, f, indent=2, sort_keys=True)
            f.write("\n")
        os.replace(tmp, output)
    except BaseException:
        os.unlink(tmp)
        raise
    return 0


def build(meta: dict) -> dict:
    packages = {p["id"]: p for p in meta["packages"]}
    workspace = set(meta["workspace_members"])
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}

    def is_proc_macro(pkg_id: str) -> bool:
        return any("proc-macro" in t["kind"] for t in packages[pkg_id]["targets"])

    def declaration(dependent: str, dep_name: str, kind: dict) -> dict:
        """The manifest declaration behind one resolved edge."""
        for d in packages[dependent]["dependencies"]:
            if (
                (d.get("rename") or d["name"]).replace("-", "_") == dep_name
                and (d.get("kind") or "normal") == kind["kind"]
                and d.get("target") == kind.get("target")
            ):
                return d
        return {}

    edges: dict = {}
    paths: dict = {}
    queue = []

    def visit_edges(dependent: str, cls, conds):
        for dep in nodes[dependent]["deps"]:
            for raw_kind in dep["dep_kinds"]:
                kind = {"kind": raw_kind.get("kind") or "normal", "target": raw_kind.get("target")}
                if dependent not in workspace and kind["kind"] == "dev":
                    continue
                decl = declaration(dependent, dep["name"], kind)
                record(edges, dep["pkg"], {
                    "from": stable_id(dependent, packages),
                    "kind": kind["kind"],
                    "target": kind.get("target"),
                    "uses_default_features": decl.get("uses_default_features"),
                    "features": sorted(decl.get("features", [])),
                })
                target = kind.get("target")
                if cls is None:
                    child_cls = {"dev": "dev", "build": "build"}.get(kind["kind"], "runtime")
                else:
                    child_cls = cls
                    if kind["kind"] == "build" or is_proc_macro(dependent):
                        child_cls = to_build(cls)
                child_conds = set(conds)
                if target == LOOM_CFG:
                    child_cls = to_loom(child_cls)
                elif target:
                    child_conds.add(target)
                queue.append((dep["pkg"], child_cls, frozenset(child_conds)))

    for member in sorted(workspace):
        visit_edges(member, None, frozenset())
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
        paths.setdefault(pkg, {}).setdefault(cls, set()).add(conds)
        visit_edges(pkg, cls, conds)

    out = []
    for pkg_id in sorted(paths, key=lambda i: (packages[i]["name"], packages[i]["version"], i)):
        p = packages[pkg_id]
        out.append({
            "name": p["name"],
            "version": p["version"],
            "id": pkg_id,
            "source": p.get("source"),
            "license": p.get("license"),
            "build_script": any("custom-build" in t["kind"] for t in p["targets"]),
            "proc_macro": is_proc_macro(pkg_id),
            "features": sorted(nodes[pkg_id].get("features", [])),
            "paths": {cls: minimal(sets) for cls, sets in sorted(paths[pkg_id].items())},
            "edges": sorted(edges.get(pkg_id, []), key=lambda e: json.dumps(e, sort_keys=True)),
        })
    return {"generated_by": "scripts/dependency-inventory.py", "packages": out}


def stable_id(pkg_id: str, packages: dict) -> str:
    """External ids are kept verbatim; workspace ids embed the checkout path,
    so they become `workspace:<name>@<version>`."""
    if pkg_id.startswith("path+file://"):
        p = packages[pkg_id]
        return "workspace:" + p["name"] + "@" + p["version"]
    return pkg_id


def to_build(cls: str) -> str:
    return {"runtime": "build", "loom-runtime": "loom-build"}.get(cls, cls)


def to_loom(cls: str) -> str:
    return {"runtime": "loom-runtime", "build": "loom-build"}.get(cls, cls)


def record(edges: dict, pkg: str, entry: dict) -> None:
    bucket = edges.setdefault(pkg, [])
    if entry not in bucket:
        bucket.append(entry)


def minimal(sets: set) -> list:
    """Drop condition sets that are supersets of another path's set."""
    keep = [s for s in sets if not any(o < s for o in sets)]
    return sorted(sorted(s) for s in set(keep))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
