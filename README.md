# curlosity

Batch web research in one tool call: N searches + M page fetches + HTML-to-Markdown extraction, fully concurrent. Pure Rust.

Why: agents burn one tool call per search/fetch. From hermes state.db (~283k tool calls): `web_search -> web_search` is 64.7% of web bigrams (6005 calls, 3-10 fired in parallel per turn), and research totals 12-17k ops. curlosity collapses a whole research turn into one call.

## Install

```bash
cargo install curlosity
# or
curl -fsSL https://raw.githubusercontent.com/riceharvest/curlosity/main/install.sh | sh
# update in place:
curlosity --update
```

Prebuilt musl/darwin/msvc binaries are attached to GitHub Releases (checksum-verified, `hermes-tool.json` included in every archive). See docs/install.md.

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

## Fetch-only mode for agents (no API keys, fully runnable example)

Without provider config, searches are reported with `"skipped": true` and an explanatory error - search results are never faked. Fetches always run, so agents can batch-fetch any URL list in one call.

Run this as-is; it starts a local fixture server and extracts markdown from it:

```bash
# 1. start a 3-page localhost fixture
python3 - <<'EOF' &
import http.server
PAGES = {
    "/": "<html><body><h1>Fixture</h1><p>home page</p></body></html>",
    "/docs": "<html><body><h1>Docs</h1><p>api documentation</p></body></html>",
    "/pricing": "<html><body><h1>Pricing</h1><p>free tier available</p></body></html>",
}
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = PAGES.get(self.path, b"<html><body>missing</body></html>").encode()
        code = 200 if self.path in PAGES else 404
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
import socketserver
socketserver.TCPServer.allow_reuse_address = True
socketserver.TCPServer(("127.0.0.1", 8500), H).serve_forever()
EOF
FIXTURE_PID=$!; sleep 0.5

# 2. batch-fetch all three pages in one call (--allow-private-network is
#    required because the fixture is loopback; never needed for public URLs)
echo '{"fetches": [
  {"url": "http://127.0.0.1:8500/"},
  {"url": "http://127.0.0.1:8500/docs"},
  {"url": "http://127.0.0.1:8500/pricing"}
]}' | curlosity --allow-private-network --cache-status --cache-path /tmp/fixture-cache.sqlite

kill $FIXTURE_PID
```

Each result comes back with extracted markdown (`# Fixture`, `# Docs`, `# Pricing`) and `cache_status: miss` on first fetch.

Caching is skipped for private-network runs (responses never persisted), so hit behavior is visible on public URLs:

```bash
echo '{"fetches":[{"url":"https://example.com"}]}' | curlosity --cache-status
# first run: "cache_status": "miss"   second run: "cache_status": "hit" (304, zero download)
```

## Search providers

Real search needs a provider key. Three ways, in priority order:

```bash
# 1. explicit switch (env var read for you, error message names the var)
BRAVE_API_KEY=BSA... curlosity --brave --input batch.json
SERPER_API_KEY=... curlosity --serper --input batch.json

# 2. env vars picked up automatically (Brave wins if both set)
BRAVE_API_KEY=BSA... curlosity

# 3. config file for custom endpoints
echo '{"name":"brave","api_key":"BSA...","endpoint":"https://api.search.brave.com/res/v1/web/search"}' \
  > ~/.config/curlosity/brave.json
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
| `--cache-status` | off | Add explicit `cache_status: hit/miss` per fetch result |
| `--provider` | (env) | Provider config JSON file |
| `--brave` | off | Use Brave Search (reads `BRAVE_API_KEY`) |
| `--serper` | off | Use Serper.dev Google search (reads `SERPER_API_KEY`) |
| `--allow-private-network` | off | UNSAFE: allow loopback/private/link-local targets |
| `--completions <SHELL>` | | Emit shell completions and exit |
| `--man` | | Print man page and exit |
| `--tool-manifest` | | Print agent tool manifest (hermes-tool.json) and exit |
| `--update` | | Self-update from GitHub Releases |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Batch succeeded, every item ok |
| `1` | Usage/config error (bad JSON, bad flags, missing provider key) |
| `2` | Batch executed; one or more items have per-item errors (see `code` fields) |
| `130` | Interrupted |

Per-item failures carry a machine-readable `code`: `invalid_url`, `unsupported_scheme`, `userinfo_not_allowed`, `unsafe_address`, `timeout`, `too_many_redirects`, `redirect_downgrade`, `body_too_large`, `not_fetchable`, `http_404`, `http_403`, `http_429`, `http_5xx`, `excluded`, `not_included`, `not_modified`, and more.

## Caching

Fetches are cached in sqlite at `~/.cache/curlosity/state.sqlite` with `ETag` / `Last-Modified` validators. Re-fetching the same URL in a later turn sends `If-None-Match`; a `304` serves the cached body with `"from_cache": true` and zero download. Add `--cache-status` for an explicit `hit`/`miss` per result. Disable with `--no-cache`. Private-network runs (`--allow-private-network`) never touch the cache.

## Security model

Web fetches are adversarial. curlosity is deny-by-default; every item below is covered by a regression test:

- **SSRF / private network**: literal private, loopback, link-local, multicast, documentation, benchmarking and other special-use IPv4/IPv6 ranges are rejected, including IPv4-mapped IPv6 (`::ffff:10.0.0.1` is private). Decimal/hex/octal IP spellings (`2130706433`, `0x7f.0.0.1`, `017700000001`) are normalized by the URL parser and then caught by the same classifier. `localhost`/`*.local` hostnames are rejected. DNS resolution is re-checked inside a custom resolver at connect time, closing the DNS-rebinding gap between a pre-flight check and the TCP connect. `--allow-private-network` is the explicit opt-in for local fixtures (and disables caching).
- **Non-HTTP schemes**: `data:`, `file:`, `javascript:` are rejected before any I/O.
- **Redirects**: followed manually, max 10 hops (hop 11 rejected, hop 10 fine), same-host only, and `https -> http` downgrades are rejected outright.
- **Body bombs**: a server claiming `Content-Length: 50MB` and streaming more is cut at the cap (`--max-body-size`, default 10MiB) against both the header and the actual streamed bytes, before the process can OOM.
- **Content-type validation**: only `text/html`, `application/xhtml+xml`, and `text/*` are fetched; binaries are rejected before the body downloads. Missing Content-Type triggers a bounded 1KiB HTML sniff.
- **No shell**: URLs are passed to reqwest directly; there is no shell interpolation anywhere, so user-controlled URLs cannot inject commands.
- **Untrusted extraction**: extracted markdown is page-controlled content. A page containing "Ignore previous instructions..." comes back as verbatim inert text inside the JSON envelope - curlosity never interprets it. Treat it as untrusted data, not instructions, when feeding it to an LLM.
- **Globs**: `--include`/`--exclude` (globset syntax) filter fetch targets before any network I/O.

## Hermes registration

```bash
# make it available as an agent tool
curlosity --tool-manifest > ~/.hermes/tools/curlosity.json
# completions + man page
curlosity --completions bash > ~/.local/share/bash-completion/completions/curlosity
curlosity --man | gzip > /usr/local/share/man/man1/curlosity.1.gz
```

The tool manifest documents the stdin schema, output envelope, fetch-only mode, provider env vars, concurrency defaults, security model, flags, and exit codes for agent tool discovery.

## Development

```bash
cargo test          # 25 tests, no external network needed (in-process fixtures)
cargo clippy --all-targets
cargo build --release
```

The integration suite spins in-process loopback HTTP fixtures (3 pages + 404 + 304/etag + oversize body + binary content-type + 10-hop redirect chain + injection page) and asserts extraction, error codes, conditional caching, redirect limits, and the batch envelope end-to-end.

docs/: spec.md (normative contract), architecture.md (module map + data flow), install.md (all install paths).

## License

MIT OR Apache-2.0
