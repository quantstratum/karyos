<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog fragments

A pull request records its changelog entry here, never in `CHANGELOG.md`,
so that open pull requests do not conflict in `[Unreleased]`. Each change
is one file, `changelog.d/<issue>-<slug>.md`, for example
`changelog.d/634-refresh-cycles.md`:

```markdown
### Added

- Conflation refresh and snapshot cycles (SPEC §7.1; karyos#634).
```

The file holds exactly one section header (`Added`, `Changed`,
`Deprecated`, `Removed`, `Fixed` or `Security`) and the entries under it,
written as they will read in `CHANGELOG.md`. A change with entries in two
sections uses two files, both named after the issue
(`634-refresh-cycles.md`, `634-refresh-cycles-fix.md`). A change with no
issue does not get a fragment until it has one. `make changelog-check`,
which `make pre-push` runs, rejects a fragment with another name or
without exactly one header, and a branch that adds more lines to
`CHANGELOG.md` than it removes. A pull request may still correct an
existing entry in `CHANGELOG.md` in place, as long as the entry does not
grow; a correction that needs more lines goes in a fragment.

At a release, `scripts/changelog-assemble.sh` folds the fragments into
`[Unreleased]` in file name order, after the entries already there, and
deletes them
(`RELEASING.md`). Decided 2026-10-27 by QS-COORDINATOR under owner
delegation (Joaquín, 2026-10-26).
