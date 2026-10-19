<!-- SPDX-License-Identifier: Apache-2.0 -->

# Conformance scenarios, interim format 1

The language-neutral conformance suite of the C ABI (SPEC.md §10.2, §13;
ADR-0053, ADR-0067) lives here, beside `karyos-ffi`. Its final format is
an owner decision (owner item 46); this is the interim format the
`karyos-ffi` runner and the bindings use until then (quantstratum-docs:
`karyos/design/ffi-gap-analysis.md`, F6). It needs no parser library: a
binding reads it with its standard library.

## Files

- `scenarios/*.kcs`: one scenario per file, UTF-8, read line by line.
- `index.txt`: the coverage map from the §13 contract rows to scenario
  ids, with the rows no scenario covers yet and the batch that brings
  them.
- The status names come from `../include/karyos.h` (`#define KARYOS_OK`,
  `#define KARYOS_E_*`); a runner reads them from the header of the
  library it tests, never from a copy.

## Lines

A `#` starts a comment that runs to the end of the line; blank lines are
ignored. Every other line is a keyword and its tokens, separated by
spaces. A token is a bare word, or a double-quoted string in which `\"`
and `\\` are the only escapes.

| Keyword | Tokens | Meaning |
| --- | --- | --- |
| `format` | `1` | The format version; the first line that is not a comment |
| `id` | a dotted name | The scenario's id, unique in the suite |
| `abi` | `MAJOR.MINOR` | The ABI version the scenario needs |
| `covers` | a quoted string | The §13 contract row it checks, as `index.txt` names it |
| `call` | a function name, then `name=value` arguments | Calls the C function |
| `expect` | an optional status name, then `name=value` results | Checks the last call |

`format`, `id`, `abi` and `covers` come once each, before the first
`call`. Every `call` is followed by exactly one `expect`.

## Values

- An integer, decimal, optionally negative: `108`, `-1`.
- `null`: a null pointer for a pointer argument.
- A quoted string.
- `$name`: a variable. In an `expect`, an unbound variable binds to the
  result; a bound one is compared with it. In a `call`, a variable must
  be bound.

## Calls

A runner passes every pointer argument a scenario does not name as a
valid pointer to a value it owns, and reads the results from there. A
scenario names an argument only to pass something else, such as `null`.
The arguments and results of each function are those of the header:

| Function | Arguments | Results |
| --- | --- | --- |
| `karyos_abi_version` | `major`, `minor`, `patch` (`null` only) | status, `major`, `minor`, `patch` |
| `karyos_status_message` | `status` | `text` (no status) |

An `expect` without a status name checks a call that returns no status.
A result named in an `expect` that the call did not write is a failure.

## Versions

A runner compares each scenario's `abi` with `karyos_abi_version()` of
the library: a different major, or a newer minor than the library's, is
reported as skipped, never as passed. A scenario whose `format` the
runner does not know is a failure.
