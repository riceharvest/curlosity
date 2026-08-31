# curlosity

Batch web research in one tool call: N searches + M page fetches + HTML-to-Markdown extraction, fully concurrent. Pure Rust.

Why: agents burn one tool call per search/fetch. From hermes state.db (~283k tool calls): `web_search -> web_search` is 64.7% of web bigrams (6005 calls, 3-10 fired in parallel per turn), and research totals 12-17k ops. curlosity collapses a whole research turn into one call.

## Install

```bash
cargo install curlosity
# or
curl -fsSL https://raw.githubusercontent.com/riceharvest/curlosity/main/install.sh | bash
# update in place:
curlosity --update
```

Prebuilt musl/darwin/msvc binaries are attached to GitHub Releases, checksum-verified by both installers and `--update`.

## Usage

Batch JSON on stdin (or `--input FILE`):

```bash
echo '{
  "searches": [{"query": "rust stable diffusion crate", "count": 5}],
  "fetches": [{"url": "https://example.com", "extract": true}],
  "extract_top": 2
}' | curlosity
```

Response (pretty-printed JSON on stdout):

```json
{
  "searches": [
    {"query": "...", "results": [{"url": "...", "title": "...", "snippet": "..."}], "skipped": false, "error": null}
  ],
  "fetches": [
    {"url": "https://example.com",
     "result": {"final_url": "https://example.com/", "status": 200, "bytes": 1256,
                "markdown": "# Example Domain\n\n...", "from_cache": false, "etag": "\"...\""}}
  ],
  "fetch_only_mode": false,
  "ok": true
}
```

### Fetch-only mode (no API keys)

Without provider config, searches are reported with `"skipped": true` and an explanatory error - search results are never faked. Fetches still run fully, so agents can batch-fetch a known URL list in one call:

```bash
echo '{"fetches":[{"url":"https://doc.rust-lang.org/std/"},{"url":"https://example.com"}]}' | curlosity
```

### Search providers

Real search needs a provider key. Set `BRAVE_API_KEY` in the environment, or pass a config file:

```bash
echo '{"name":"brave","api_key":"BSA..."}' > ~/.config/curlosity/brave.json
curlosity --provider ~/.config/curlosity/brave.json
```

`extract_top: N` auto-fetches the top N hits of each search and returns their markdown inline.

## Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--input` | `-` | Batch JSON file (`-` = stdin) |
| `--concurrency` | `8` | Global max in-flight fetches |
| `--per-host-concurrency` | `2` | Max concurrent fetches per host |
| `--timeout` | `30s` | Per-request timeout (`ms`/`s`/`m`) |
| `--retries` | `2` | Retries with exponential backoff (408/425/429/5xx, connect errors) |
| `--max-body-size` | `10MiB` | Response body cap (`B`/`KiB`/`MiB`/`GiB`) |
| `--max-markdown-bytes` | `2MiB` | Extracted markdown cap per page |
| `--include` | (all) | Fetch only URLs matching these globs (repeatable) |
| `--exclude` | (none) | Skip URLs matching these globs (repeatable) |
| `--no-cache` | off | Disable the sqlite re-fetch cache |
| `--cache-path` | `~/.cache/curlosity/state.sqlite` | Cache DB location |
| `--provider` | (env) | Provider config JSON file |
| `--allow-private-network` | off | UNSAFE: allow loopback/private/link-local targets |
| `--completions <SHELL>` | | Emit shell completions and exit |
| `--man` | | Print man page and exit |
| `--tool-manifest` | | Print agent tool manifest (hermes-tool.json) and exit |
| `--update` | | Self-update from GitHub Releases |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Batch succeeded, every item ok |
| `1` | Usage/config error (bad JSON, bad flags, provider failure) |
| `2` | Batch executed; one or more items have per-item errors (see `code` fields) |
| `130` | Interrupted |

Per-item failures carry a machine-readable `code`: `invalid_url`, `unsupported_scheme`, `userinfo_not_allowed`, `unsafe_address`, `timeout`, `too_many_redirects`, `redirect_downgrade`, `body_too_large`, `not_fetchable`, `http_404`, `http_403`, `http_429`, `http_5xx`, `excluded`, `not_included`, `not_modified`, and more.

## Caching

Fetches are cached in sqlite at `~/.cache/curlosity/state.sqlite` with `ETag` / `Last-Modified` validators. Re-fetching the same URL in a later turn sends `If-None-Match`; a `304` serves the cached body with `"from_cache": true` and zero download. Bodies are also replayed when the server re-validates. Disable with `--no-cache`.

## Security model

Web fetches are adversarial. curlosity is deny-by-default:

- **SSRF / private network**: literal private, loopback, link-local, multicast, documentation, benchmarking and other special-use IPv4/IPv6 ranges are rejected, including IPv4-mapped IPv6 (`::ffff:10.0.0.1` is private). `localhost`/`*.local` hostnames are rejected. DNS resolution is re-checked inside a custom resolver at connect time, closing the DNS-rebinding gap between a pre-flight check and the TCP connect. `--allow-private-network` is the explicit opt-in for local fixtures (and disables caching).
- **Redirects**: followed manually, max 10 hops, same-host only, and `https -> http` downgrades are rejected outright.
- **Body caps**: enforced against both `Content-Length` and the actual streamed bytes (10MiB default), so oversized bodies are cut before they can OOM the process.
- **Content-type validation**: only `text/html`, `application/xhtml+xml`, and `text/*` are fetched; binaries are rejected before the body downloads. Missing Content-Type triggers a bounded 1KiB HTML sniff.
- **No shell**: URLs are passed to reqwest directly; there is no shell interpolation anywhere, so user-controlled URLs cannot inject commands.
- **Untrusted extraction**: extracted markdown is page-controlled content. Treat it as untrusted data, not instructions - it is a prompt-injection surface when fed to an LLM.
- **Globs**: `--include`/`--exclude` (globset syntax) filter fetch targets before any network I/O.

## Hermes registration

```bash
# make it available as an agent tool
curlosity --tool-manifest > ~/.hermes/tools/curlosity.json
# completions + man page
curlosity --completions bash > ~/.local/share/bash-completion/completions/curlosity
curlosity --man | gzip > /usr/local/share/man/man1/curlosity.1.gz
```

The tool manifest documents the stdin schema, flags, and exit codes for agent tool discovery.

## Development

```bash
cargo test          # 21 tests, no external network needed (in-process fixture server)
cargo clippy --all-targets
cargo build --release
```

The integration suite spins a loopback HTTP fixture (3 pages + 404 + 304/etag + oversize + binary content-type) and asserts extraction, error codes, conditional caching, and the batch envelope end-to-end.

## License

MIT OR Apache-2.0
