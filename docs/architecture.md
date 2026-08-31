# Architecture

`recurlsively` is designed as a local Rust binary with deterministic, bounded behavior. The repository currently implements only the CLI/configuration boundary. Planned components are described here without placeholder module declarations or fake implementations.

## Boundaries

1. **CLI and configuration** parse arguments, apply defaults, validate bounds, and expose policy choices.
2. **URL/policy layer** will normalize URLs, enforce exact-origin scope, apply query and redirect policy, and classify special/private addresses.
3. **Fetcher** will implement bounded HTTP(S) requests, timeouts, delays, retries, response-size limits, and robots behavior.
4. **Scheduler** will persist a queue and page state in SQLite, enforce global/per-host concurrency, and support resumable/fresh runs.
5. **Extractor** will convert supported HTML documents into deterministic Markdown and discover links.
6. **Snapshot/output layer** will write stable files, manifests, and reports under the configured output directory.

Each boundary should have contract tests before implementation. Network and filesystem effects must be injected or isolated in tests; production code must not depend on a browser runtime.

## Planned flow

```text
START_URL + options
        |
        v
  CLI/config validation
        |
        v
  URL policy + scheduler
        |
        +--> bounded fetcher --> HTML response
        |                         |
        |                         v
        +<-- discovered links <-- Markdown extractor
        |
        v
  SQLite state + deterministic snapshot output
```

The scheduler is the source of truth for queue, visit status, retry count, byte budget, and run identity. Output files are derived artifacts and must be safe to regenerate from durable state.

## Security model

The default scope is exact origin. Redirects must be checked against the configured policy before following. Private, loopback, link-local, multicast, and other special destinations are denied by default at resolution/connect time, not only by string inspection. `--allow-private-network` is an explicit unsafe opt-in and must be surfaced in run metadata.

All work is bounded by depth, page count, global bytes, per-body bytes, timeout, retries, delay, and concurrency. No credentials are read implicitly. Authentication and browser state are out of scope for the MVP.

## Determinism

Stable URL normalization, deterministic queue ordering, canonical Markdown formatting, and explicit report schemas are required. Concurrency must not change the selected corpus or output ordering. Any unavoidable source nondeterminism must be recorded in the report rather than hidden.

## Delivery stages

- **Stage 1 (current):** CLI/configuration, validation, help/version, public docs, and CI.
- **Stage 2:** URL policy, HTTP fetcher, robots/redirect/query behavior, and focused fixtures.
- **Stage 3:** SQLite scheduler, bounded concurrency, resumability, and fresh runs.
- **Stage 4:** HTML-to-Markdown extraction, deterministic output, manifests, and reports.
- **Stage 5:** cross-platform release binaries, checksums, and installers.
