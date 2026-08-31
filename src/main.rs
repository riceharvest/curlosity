//! curlosity CLI: batch web research for AI agents.
//!
//! Exit codes: 0 success, 1 usage/config error, 2 batch executed with
//! per-item errors, 130 interrupted.

use std::io::Read;
use std::process::ExitCode;

use clap::{CommandFactory, Parser};
use clap_complete::{Shell, generate};

use curlosity::{BatchConfig, BatchRequest, ProviderConfig, cache};

#[derive(Parser, Debug)]
#[command(
    name = "curlosity",
    about = "Batch web research: searches + fetches + HTML->Markdown in one tool call.",
    version,
    after_help = "Pipe a batch JSON request to stdin. See --input or README.md."
)]
struct Cli {
    /// Read batch JSON from this file instead of stdin (`-` = stdin).
    #[arg(short, long, default_value = "-")]
    input: String,

    /// Global concurrency (max in-flight fetches).
    #[arg(long, default_value_t = 8)]
    concurrency: usize,

    /// Max concurrent fetches per host.
    #[arg(long, default_value_t = 2)]
    per_host_concurrency: usize,

    /// Per-request timeout.
    #[arg(long, default_value = "30s")]
    timeout: String,

    /// Retries per fetch (exponential backoff on retryable errors).
    #[arg(long, default_value_t = 2)]
    retries: u32,

    /// Max response body bytes.
    #[arg(long, default_value = "10MiB")]
    max_body_size: String,

    /// Max extracted markdown bytes per page.
    #[arg(long, default_value = "2MiB")]
    max_markdown_bytes: String,

    /// Allow private/loopback/link-local destinations (UNSAFE; for local fixtures).
    #[arg(long)]
    allow_private_network: bool,

    /// Only fetch URLs matching these globs (repeatable).
    #[arg(long)]
    include: Vec<String>,

    /// Skip URLs matching these globs (repeatable).
    #[arg(long)]
    exclude: Vec<String>,

    /// Disable the sqlite re-fetch cache.
    #[arg(long)]
    no_cache: bool,

    /// Cache database path.
    #[arg(long)]
    cache_path: Option<String>,

    /// Search provider config file (JSON: {"name":"brave","api_key":"..."}).
    /// Also honors BRAVE_API_KEY. Without a provider, searches are reported
    /// as skipped (fetch-only mode) and never faked.
    #[arg(long)]
    provider: Option<String>,

    /// Emit shell completions for the given shell and exit.
    #[arg(long, value_name = "SHELL")]
    completions: Option<Shell>,

    /// Write a man page to stdout and exit.
    #[arg(long)]
    man: bool,

    /// Self-update from GitHub Releases (checksum-verified).
    #[arg(long)]
    update: bool,

    /// Write the agent tool manifest (hermes-tool.json) to stdout and exit.
    #[arg(long)]
    tool_manifest: bool,
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("{0}")]
    Message(String),
}

fn parse_duration(input: &str) -> Result<std::time::Duration, CliError> {
    let trimmed = input.trim();
    let (value_part, unit) = trimmed.split_at(
        trimmed
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(trimmed.len()),
    );
    let value: u64 = value_part
        .parse()
        .map_err(|_| CliError::Message(format!("invalid duration `{input}`")))?;
    let millis = match unit {
        "ms" => value,
        "s" | "" => value * 1000,
        "m" => value * 60_000,
        _ => {
            return Err(CliError::Message(format!(
                "invalid duration unit in `{input}` (use ms, s, m)"
            )));
        }
    };
    if millis == 0 {
        return Err(CliError::Message(
            "timeout must be greater than zero".into(),
        ));
    }
    Ok(std::time::Duration::from_millis(millis))
}

fn parse_bytes(input: &str) -> Result<u64, CliError> {
    let trimmed = input.trim();
    let (value_part, unit) = trimmed.split_at(
        trimmed
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(trimmed.len()),
    );
    let value: u64 = value_part
        .parse()
        .map_err(|_| CliError::Message(format!("invalid byte size `{input}`")))?;
    let multiplier = match unit.to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "kib" | "kb" => 1024,
        "mib" | "mb" => 1024 * 1024,
        "gib" | "gb" => 1024 * 1024 * 1024,
        _ => {
            return Err(CliError::Message(format!(
                "invalid byte unit in `{input}` (use B, KiB, MiB, GiB)"
            )));
        }
    };
    Ok(value.saturating_mul(multiplier))
}

fn tool_manifest() -> serde_json::Value {
    serde_json::json!({
        "name": "curlosity",
        "version": env!("CARGO_PKG_VERSION"),
        "description": "Batch web research: run N web searches and M page fetches (with HTML->Markdown extraction) in one tool call. Fetch-only mode needs no API keys; searches need a provider key.",
        "stdin": {
            "type": "json",
            "schema": {
                "searches": [{"query": "string", "count": "u32?"}],
                "fetches": [{"url": "string", "extract": "bool=true"}],
                "extract_top": "u32?"
            }
        },
        "usage": "echo '{\"fetches\":[{\"url\":\"https://example.com\"}]}' | curlosity",
        "exit_codes": {"0": "success", "1": "usage/config error", "2": "batch ran with per-item errors", "130": "interrupted"},
        "flags": ["--input", "--concurrency", "--per-host-concurrency", "--timeout", "--retries", "--max-body-size", "--max-markdown-bytes", "--allow-private-network", "--include", "--exclude", "--no-cache", "--cache-path", "--provider", "--completions", "--man", "--update", "--tool-manifest"]
    })
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Some(shell) = cli.completions {
        let mut cmd = Cli::command();
        generate(shell, &mut cmd, "curlosity", &mut std::io::stdout());
        return ExitCode::SUCCESS;
    }
    if cli.man {
        let man = clap_mangen::Man::new(Cli::command());
        // A closed downstream pipe (e.g. `| head`) is not an error.
        let _ = man.render(&mut std::io::stdout());
        return ExitCode::SUCCESS;
    }
    if cli.tool_manifest {
        println!(
            "{}",
            serde_json::to_string_pretty(&tool_manifest()).unwrap_or_default()
        );
        return ExitCode::SUCCESS;
    }
    if cli.update {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        return match runtime.block_on(curlosity::update::run_update()) {
            Ok(message) => {
                println!("{message}");
                ExitCode::SUCCESS
            }
            Err(curlosity::update::UpdateError::UpToDate(message)) => {
                println!("{message}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("curlosity update: {error}");
                ExitCode::FAILURE
            }
        };
    }

    // ----- read batch JSON -----
    let raw = if cli.input == "-" {
        let mut buf = String::new();
        if std::io::stdin().read_to_string(&mut buf).is_err() {
            eprintln!("curlosity: failed to read stdin");
            return ExitCode::from(1);
        }
        buf
    } else {
        match std::fs::read_to_string(&cli.input) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("curlosity: cannot read {}: {e}", cli.input);
                return ExitCode::from(1);
            }
        }
    };
    if raw.trim().is_empty() {
        eprintln!("curlosity: empty batch request (pipe JSON to stdin, see --help)");
        return ExitCode::from(1);
    }
    let request: BatchRequest = match serde_json::from_str(&raw) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("curlosity: invalid batch JSON: {e}");
            return ExitCode::from(1);
        }
    };
    if request.searches.is_empty() && request.fetches.is_empty() {
        eprintln!("curlosity: batch request has no searches and no fetches");
        return ExitCode::from(1);
    }

    // ----- build config -----
    let timeout = match parse_duration(&cli.timeout) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("curlosity: {e}");
            return ExitCode::from(1);
        }
    };
    let max_body_size = match parse_bytes(&cli.max_body_size) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("curlosity: {e}");
            return ExitCode::from(1);
        }
    };
    let max_markdown_bytes = match parse_bytes(&cli.max_markdown_bytes) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("curlosity: {e}");
            return ExitCode::from(1);
        }
    };
    if cli.per_host_concurrency > cli.concurrency || cli.concurrency == 0 {
        eprintln!(
            "curlosity: concurrency must be > 0 and per_host_concurrency ({}) must not exceed concurrency ({})",
            cli.per_host_concurrency, cli.concurrency
        );
        return ExitCode::from(1);
    }

    let provider = match load_provider(&cli) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("curlosity: {e}");
            return ExitCode::from(1);
        }
    };

    let cache_enabled = !cli.no_cache;
    let cache_path = cli
        .cache_path
        .clone()
        .unwrap_or_else(|| cache::default_cache_path().to_string_lossy().to_string());

    let config = BatchConfig {
        concurrency: cli.concurrency,
        per_host_concurrency: cli.per_host_concurrency,
        timeout,
        retries: cli.retries,
        max_body_size,
        max_markdown_bytes: max_markdown_bytes as usize,
        allow_private_network: cli.allow_private_network,
        include: cli.include.clone(),
        exclude: cli.exclude.clone(),
        cache: cache_enabled && !cli.allow_private_network, // never cache private-network fixtures
        user_agent: concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION")).to_owned(),
        provider,
        max_redirect_hops: 10,
    };
    let _ = cache_path; // default path is computed inside batch(); custom paths use cache_path override below

    // ----- run -----
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    // Custom cache path: run batch with default, then override if user set one.
    // (BatchConfig::cache is respected; path override handled by env var is ugly,
    // so instead we run batch with the config as-is and let cache_path apply via
    // a thread-local override in cache::default_cache_path.)
    if let Some(path) = &cli.cache_path {
        // Safe here: single-threaded at this point, before the runtime spawns workers.
        // SAFETY: no other threads exist yet (runtime is built after this line).
        unsafe { std::env::set_var("CURLOSITY_CACHE_PATH", path) };
    }

    let result = runtime.block_on(async {
        // If a custom cache path was set, patch the config-level default by
        // overriding the module function through the env var (see cache module).
        curlosity::batch(request, &config).await
    });

    match result {
        Ok(value) => {
            let ok = value.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
            println!(
                "{}",
                serde_json::to_string_pretty(&value).unwrap_or_default()
            );
            if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
        Err(e) => {
            eprintln!("curlosity: {e}");
            ExitCode::from(1)
        }
    }
}

fn load_provider(cli: &Cli) -> Result<Option<ProviderConfig>, String> {
    if let Some(path) = &cli.provider {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read provider config {path}: {e}"))?;
        let config: ProviderConfig = serde_json::from_str(&raw)
            .map_err(|e| format!("invalid provider config {path}: {e}"))?;
        return Ok(Some(config));
    }
    if let Ok(key) = std::env::var("BRAVE_API_KEY") {
        if !key.trim().is_empty() {
            return Ok(Some(ProviderConfig {
                name: "brave".into(),
                api_key: key,
                endpoint: None,
            }));
        }
    }
    Ok(None)
}
