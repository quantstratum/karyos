#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Folds the changelog fragments of changelog.d/ into the [Unreleased]
# section of CHANGELOG.md and deletes them; RELEASING.md runs it before the
# release section is cut. A fragment is changelog.d/<issue>-<slug>.md: one
# "### Added", "### Changed", "### Deprecated", "### Removed", "### Fixed"
# or "### Security" header, then its entries. Fragments are appended after
# the section's existing entries, in file name order, and the sections come
# out in Keep a Changelog order. --check only validates the fragments.
set -euo pipefail

cd "$(dirname "$0")/.."
check=0
if [[ ${1:-} == --check ]]; then
	check=1
fi

shopt -s nullglob
fragments=(changelog.d/*.md)
fragments=("${fragments[@]/#changelog.d\/README.md/}")
list=()
for f in "${fragments[@]}"; do
	[[ -n $f ]] && list+=("$f")
done
if ((${#list[@]} == 0)); then
	echo "changelog-assemble: no fragments"
	exit 0
fi

status=0
for f in "${list[@]}"; do
	headers=$(grep -c '^### ' "$f" || true)
	first=$(grep -m1 -v '^[[:space:]]*$' "$f" || true)
	if [[ $headers != 1 ]] || ! [[ $first =~ ^\#\#\#\ (Added|Changed|Deprecated|Removed|Fixed|Security)$ ]]; then
		echo "changelog-assemble: $f must start with one section header" >&2
		status=1
	fi
done
if ((status != 0 || check)); then
	exit "$status"
fi

tmp=$(mktemp)
awk -v nfrag="${#list[@]}" '
function trim(s) { sub(/^\n+/, "", s); sub(/\n+$/, "", s); return s }
function flush(   i, s, out) {
	for (i = 1; i <= ncanon; i++) emitted[canon[i]] = 0
	out = ""
	for (i = 1; i <= ncanon; i++) {
		s = canon[i]
		if ((s in body) || (s in frag)) out = out emit(s)
	}
	for (i = 1; i <= norder; i++) {
		s = order[i]
		if (!(s in canonset)) out = out emit(s)
	}
	printf "%s", out
}
function emit(s,   t) {
	t = trim(body[s])
	if (s in frag) t = t == "" ? trim(frag[s]) : t "\n\n" trim(frag[s])
	return "### " s "\n\n" t "\n\n"
}
BEGIN {
	ncanon = split("Added Changed Deprecated Removed Fixed Security", canon, " ")
	for (i = 1; i <= ncanon; i++) canonset[canon[i]] = 1
}
FNR == 1 { file++ }
file <= nfrag {
	if ($0 ~ /^### /) { cur = substr($0, 5); next }
	frag[cur] = frag[cur] "\n" $0
	next
}
/^## \[Unreleased\]/ { print; print ""; inside = 1; sect = ""; next }
inside && /^## \[/ { flush(); inside = 0 }
inside && /^### / { sect = substr($0, 5); order[++norder] = sect; body[sect] = body[sect] ""; next }
inside { if (sect != "") body[sect] = body[sect] "\n" $0; next }
{ print }
END { if (inside) flush() }
' "${list[@]}" CHANGELOG.md >"$tmp"
mv "$tmp" CHANGELOG.md
rm -- "${list[@]}"
echo "changelog-assemble: folded ${#list[@]} fragment(s) into CHANGELOG.md"
