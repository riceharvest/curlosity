# Specification

This document is normative for the `curlosity` command. Behavior not
specified here is not promised by the current release.

## Command contract

The command reads a batch JSON request from stdin (or `--input FILE`) and
writes one JSON response object to stdout. `--help`, `--version`, `--man`,
`--completions <SHELL>`, `--tool-manifest`, and `--update` are self-sufficient
and succeed without stdin input. Any other invocation requires a non-empty
batch object with at least one search or fetch.

Invalid arguments, unreadable input, or unparsable JSON produce a
human-readable error on stderr and exit code 1. A batch that executed but
contains per-item failures prints the full JSON envelope and exits 2.

## Batch schema

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `searches` | `[{query: string, count?: u32}]` | no | Web searches (needs a provider) |
| `fetches` | `[{url: string, extract?: bool}]` | no | Page fetches; `extract` defaults to `true` |
| `extract_top` | `u32` | no | Auto-fetch the top N results of each search |

Without provider configuration every search is reported as
`"skipped": true` with an explanatory error. Search results are never
synthesized. Fetches run in all modes.

## Defaults

| Option | Default |
| --- | --- |
| `--input` | `-` (stdin) |
| `--concurrency` | `8` |
| `--per-host-concurrency` | `2` |
| `--timeout` | `30s` |
| `--retries` | `2` |
| `--max-body-size` | `10MiB` |
| `--max-markdown-bytes` | `2MiB` |
| `--allow-private-network` | off |
| `--include` / `--exclude` | (none) / (none) |
| `--cache-path` | `~/.cache/curlosity/state.sqlite` |
| `--no-cache` | off |

Counts must be greater than zero; `--per-host-concurrency` must not exceed
`--concurrency`. Durations accept integer `ms`, `s`, or `m`; byte sizes
accept integer `B`, `KiB`, `MiB`, or `GiB`.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Batch succeeded, every item ok |
| `1` | Usage or configuration error |
| `2` | Batch executed with per-item errors |
| `130` | Interrupted |

## Security contract

The implementation must not silently weaken private-network protection,
origin checks, redirect limits, or body bounds. `--allow-private-network`
is an explicit unsafe opt-in for trusted local fixtures and disables the
re-fetch cache. See README.md for the full security model.
