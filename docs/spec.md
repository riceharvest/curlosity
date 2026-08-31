# Specification

This document is normative for the `recurlsively` command. Behavior not specified here is not promised by the current release.

## Command contract

The command accepts `recurlsively [crawl] <START_URL>`. The `crawl` word is optional for compatibility with the planned subcommand layout. `--help` and `--version` succeed without a URL. Other invocations require exactly one start URL.

The first slice validates HTTP and HTTPS URLs, rejects whitespace and missing hosts, rejects URL userinfo, and rejects obvious localhost/LAN IPv4 targets by default. `--allow-private-network` is an explicit unsafe opt-in for trusted local fixtures and local documentation. DNS resolution and complete special-address validation belong to the fetcher and must remain deny-by-default.

Invalid arguments or configuration produce a human-readable error and a non-zero exit status. Help and version are written to standard output. The current successful run only validates configuration; fetching is not implemented.

## Defaults

| Option | Default |
| --- | --- |
| `--output` | `./recurlsively-out` |
| `--max-depth` | `3` (`0` means start only) |
| `--max-pages` | `1000` |
| `--concurrency` | `8` |
| `--per-host-concurrency` | `2` |
| `--delay` | `250ms` |
| `--timeout` | `30s` |
| `--retries` | `2` |
| `--max-body-size` | `10MiB` |
| `--max-total-bytes` | `500MiB` |
| `--query-mode` | `drop` |
| `--redirect-policy` | `same-origin` |
| `--sitemap` | `auto` |
| `--report` | `text` |
| `--progress` | `auto` |

Counts and byte budgets must be greater than zero, per-host concurrency must not exceed global concurrency, timeout must be positive, and the per-response body limit must not exceed the total byte budget. Zero is valid for depth and retries; zero delay is accepted by the parser for local tests.

## Policy vocabulary

- Query mode: `drop` or `preserve`.
- Redirect policy: `same-origin` in the MVP contract.
- Sitemap mode: `auto`, `on`, or `off`.
- Report format: `text` or `json`.
- Progress mode: `auto`, `text`, `json`, or `none`.
- Durations: integer `ms`, `s`, or `m` values.
- Byte sizes: integer `B`, `KiB`, `MiB`, or `GiB` values.

## MVP boundaries

The MVP fetches only HTTP(S) resources and produces Markdown snapshots. JavaScript execution, browser automation, authentication/session capture, arbitrary assets, and cross-origin crawling are out of scope. Robots handling, sitemap discovery, redirects, query normalization, and link extraction must be explicit and testable when implemented.

The implementation must not silently weaken bounds, origin checks, or private-network protection. Any unsafe opt-in must be visible in help and documentation.

## Compatibility

The supported host targets are Linux, macOS, and Windows. The command-line names and defaults in this document are public contract; changes require updating tests and this specification together.
