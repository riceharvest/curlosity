# Changelog

## 0.1.0 (2026-08-31)

### Agentic QOL log (friction → fix)

| # | Friction (observed while dogfooding) | Fix |
|---|---|---|
| 1 | CSS text from `<style>` blocks leaked into extracted markdown and summaries (example.com), wasting agent context | Added `--strip-style` (default on): `<style>`/`<script>` blocks stripped before HTML→Markdown conversion |
| 2 | Agents had to guess which env var enables search | `--brave`/`--serper` switches read `BRAVE_API_KEY`/`SERPER_API_KEY`; missing-key error names the exact var |
| 3 | Cache hits invisible in output | `--cache-status` adds explicit `cache_status: hit/miss` per result |
| 4 | Full markdown floods context for long pages | `--summarize` adds a local extractive summary per page (`--summary-sentences N`, default 5) |
| 5 | Search silently skipped in fetch-only mode looked like a bug | Search envelope includes explicit `skipped: true` + explanation; `fetch_only_mode: true` in envelope |
| 6 | MCP toolset name had to be guessed (`--toolsets mcp` fails) | MCP server name is the toolset name: use `--toolsets curlosity`; documented here and in hermes-tool.json |
| 7 | Summary quality degraded by CSS text from `<style>` blocks | `--strip-style` (default on) strips `<style>`/`<script>` before conversion |
| 8 | Duplicate/near-identical sentences repeated in summaries | `--dedupe-sentences` (default on) skips token-identical duplicate sentences |
| 9 | One-word fragments ("Go.", "Stop.") waste summary slots | `--min-sentence-len N` (default 4) drops non-heading sentences shorter than N chars |
| 8 | Duplicate/near-identical sentences repeated in summaries | `--dedupe-sentences` (default on) skips token-identical duplicate sentences |
| 9 | One-word fragments ("Go.", "Stop.") waste summary slots | `--min-sentence-len N` (default 4) drops non-heading sentences shorter than N chars |
