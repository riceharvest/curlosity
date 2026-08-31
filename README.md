# agentic-web
Batch web research: web_search + web_extract + curl in one tool call (web->web 64.7%). Pure Rust.

Why: 284 searches/session max. 64.7% web_search->web_search chained.

## Bigram evidence (from hermes state.db ~283k tool calls)
See `cargo test` and `src/lib.rs` for batch API. Pure Rust, tokio.

## Usage
```bash
cargo build --release
echo '{"items":[{}]}' | ./target/release/agentic-web --input -
```
```bash
cargo test
```
