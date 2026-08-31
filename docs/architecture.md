# Architecture

`curlosity` is a single static Rust binary (tokio + reqwest rustls) with
deterministic, bounded behavior. No browser runtime, no shell-outs, no
dynamic configuration beyond flags and environment variables.

## Modules

- `src/lib.rs` - batch engine: URL policy, IP classification, safe DNS
  resolver, bounded fetcher, HTML-to-Markdown extraction, include/exclude
  glob filter, sqlite cache, Brave search provider, concurrency control.
- `src/main.rs` - clap CLI: flags, input handling, exit codes, shell
  completions, man page, tool manifest, update dispatch.
- `src/update.rs` - self-update from GitHub Releases with checksum
  verification and atomic replacement.

## Data flow

```text
stdin batch JSON
      |
      v
config validation (concurrency, globs, provider)
      |
      +--> searches --> provider (Brave API) or "skipped" envelope
      |
      +--> fetches --> per-URL: glob filter -> canonicalize + private-IP deny
              |         -> SafeResolver DNS check -> bounded GET
              |         -> manual redirect loop (<=10, same-host, no downgrades)
              |         -> content-type gate -> streamed body cap
              |         -> htmd extraction (2MiB cap)
              v
      sqlite cache (etag/last-modified conditional GETs)
      |
      v
JSON envelope {searches, fetches, fetch_only_mode, ok}
```

All fetches run under a global semaphore plus a per-host semaphore. Retries
use exponential backoff on 408/425/429/5xx and connect errors only.

## Security posture

Private, loopback, link-local, and other special-use IPv4/IPv6 ranges are
denied by default, including IPv4-mapped IPv6. DNS results are re-checked
inside a custom resolver at connect time, closing the DNS-rebinding gap.
Redirects are followed manually so every hop re-validates. Bodies are
capped against both `Content-Length` and streamed bytes. Extracted
markdown is page-controlled untrusted data.

`--allow-private-network` skips all address checks for trusted local
fixtures and also disables the cache so private-network responses are
never persisted.
