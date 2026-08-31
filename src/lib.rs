//! curlosity - batch web research in one tool call.
//!
//! One call does what used to cost N: parallel web searches + page fetches +
//! HTML-to-Markdown extraction, with secure-by-default network policy
//! (private-network deny, https->http downgrade rejection, bounded redirects,
//! bounded bodies) and a validator-based re-fetch cache.

pub mod update;

use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum CurlosityError {
    #[error("invalid URL: {0}")]
    InvalidUrl(String),
    #[error("unsupported URL scheme `{scheme}` (expected http or https)")]
    UnsupportedScheme { scheme: String },
    #[error("URL must contain a host")]
    MissingHost,
    #[error("URL userinfo is not allowed")]
    UserinfoNotAllowed,
    #[error("URL must not contain whitespace")]
    WhitespaceNotAllowed,
    #[error("unsafe destination `{host}`: {reason}")]
    UnsafeAddress { host: String, reason: &'static str },
    #[error("network error: {0}")]
    Network(String),
    #[error("request timed out")]
    Timeout,
    #[error("more than {0} redirects")]
    TooManyRedirects(usize),
    #[error("https to http redirect rejected")]
    RedirectDowngrade,
    #[error("body exceeds {limit} byte limit")]
    BodyTooLarge { limit: u64 },
    #[error(
        "content-type {0:?} is not fetchable (expected text/html, application/xhtml+xml, or text/*)"
    )]
    NotFetchable(Option<String>),
    #[error("HTTP {status}")]
    Status { status: u16 },
    #[error("not modified (304)")]
    NotModified,
    #[error("fetch blocked by --exclude glob: {0}")]
    Excluded(String),
    #[error("fetch did not match any --include glob: {0}")]
    NotIncluded(String),
    #[error("cache error: {0}")]
    Cache(String),
    #[error("config error: {0}")]
    Config(String),
}

impl CurlosityError {
    /// Machine-readable error code for batch output.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidUrl(_) => "invalid_url",
            Self::UnsupportedScheme { .. } => "unsupported_scheme",
            Self::MissingHost => "missing_host",
            Self::UserinfoNotAllowed => "userinfo_not_allowed",
            Self::WhitespaceNotAllowed => "whitespace_not_allowed",
            Self::UnsafeAddress { .. } => "unsafe_address",
            Self::Network(_) => "network_error",
            Self::Timeout => "timeout",
            Self::TooManyRedirects(_) => "too_many_redirects",
            Self::RedirectDowngrade => "redirect_downgrade",
            Self::BodyTooLarge { .. } => "body_too_large",
            Self::NotFetchable(_) => "not_fetchable",
            Self::NotModified => "not_modified",
            Self::Status { status } => match status {
                404 => "http_404",
                403 => "http_403",
                429 => "http_429",
                s if (500..600).contains(s) => "http_5xx",
                _ => "http_error",
            },
            Self::Excluded(_) => "excluded",
            Self::NotIncluded(_) => "not_included",
            Self::Cache(_) => "cache_error",
            Self::Config(_) => "config_error",
        }
    }

    /// Whether a request that failed this way is worth retrying once.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Timeout
            | Self::Network(_)
            | Self::TooManyRedirects(_) // no: redirects are deterministic
            => false,
            Self::Status { status } => matches!(status, 408 | 425 | 429) || (500..600).contains(status),
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// URL policy: canonicalization + private-address classification
// ---------------------------------------------------------------------------

/// The reason an IP address is accepted or denied by the default policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpSafety {
    Public,
    Special(&'static str),
}

/// Classifies an IP against the default deny-private policy.
///
/// IPv4-mapped / IPv4-compatible IPv6 addresses are classified by their
/// embedded IPv4 address, closing the common SSRF bypass.
pub fn classify_ip(address: IpAddr) -> IpSafety {
    match address {
        IpAddr::V4(a) => classify_ipv4(a),
        IpAddr::V6(a) => {
            if let Some(embedded) = a.to_ipv4() {
                return classify_ipv4(embedded);
            }
            classify_ipv6(a)
        }
    }
}

/// Returns true only for an address outside the blocked special-use ranges.
pub fn is_safe_ip(address: IpAddr) -> bool {
    matches!(classify_ip(address), IpSafety::Public)
}

/// Canonicalizes and validates a fetch URL without resolving DNS.
///
/// Rejects: whitespace, userinfo, non-http(s) schemes, literal private /
/// loopback / link-local / documentation / multicast addresses (unless
/// `allow_private_network`), and `localhost` / `*.local` hostnames.
pub fn canonicalize_url(
    input: &str,
    allow_private_network: bool,
) -> Result<url::Url, CurlosityError> {
    if input.chars().any(char::is_whitespace) {
        return Err(CurlosityError::WhitespaceNotAllowed);
    }
    if input.contains('\\') {
        return Err(CurlosityError::InvalidUrl("backslash in URL".into()));
    }
    if has_userinfo(input) {
        return Err(CurlosityError::UserinfoNotAllowed);
    }
    let url = url::Url::parse(input).map_err(|e| CurlosityError::InvalidUrl(e.to_string()))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(CurlosityError::UnsupportedScheme {
            scheme: url.scheme().to_owned(),
        });
    }
    let raw_host = url.host_str().ok_or(CurlosityError::MissingHost)?;
    let host = canonical_host(raw_host)?;
    if !allow_private_network {
        if let Ok(address) = host.parse::<IpAddr>() {
            if let IpSafety::Special(reason) = classify_ip(address) {
                return Err(CurlosityError::UnsafeAddress { host, reason });
            }
        } else if let Some(reason) = special_hostname_reason(&host) {
            return Err(CurlosityError::UnsafeAddress { host, reason });
        }
    }
    Ok(url)
}

fn canonical_host(raw_host: &str) -> Result<String, CurlosityError> {
    let unbracketed = raw_host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(raw_host);
    let host = unbracketed.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Err(CurlosityError::InvalidUrl("empty host".into()));
    }
    Ok(host)
}

fn has_userinfo(input: &str) -> bool {
    let Some(authority_start) = input.find("://").map(|i| i + 3) else {
        return false;
    };
    let remainder = &input[authority_start..];
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    remainder[..authority_end].contains('@')
}

fn special_hostname_reason(host: &str) -> Option<&'static str> {
    if host == "localhost" || host.ends_with(".localhost") {
        return Some("localhost name");
    }
    if host == "local" || host.ends_with(".local") {
        return Some("mDNS local name");
    }
    None
}

const fn ipv4(a: u8, b: u8, c: u8, d: u8) -> u32 {
    u32::from_be_bytes([a, b, c, d])
}

const fn ipv6(a: u16, b: u16, c: u16, d: u16) -> u128 {
    u128::from_be_bytes([
        (a >> 8) as u8,
        a as u8,
        (b >> 8) as u8,
        b as u8,
        (c >> 8) as u8,
        c as u8,
        (d >> 8) as u8,
        d as u8,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ])
}

fn ipv4_contains(value: u32, network: u32, prefix: u8) -> bool {
    if prefix == 0 {
        true
    } else {
        let mask = u32::MAX << (32 - prefix);
        value & mask == network & mask
    }
}

fn ipv6_contains(value: u128, network: u128, prefix: u8) -> bool {
    if prefix == 0 {
        true
    } else {
        let mask = u128::MAX << (128 - prefix);
        value & mask == network & mask
    }
}

fn classify_ipv4(address: std::net::Ipv4Addr) -> IpSafety {
    let value = u32::from(address);
    let ranges: &[(u32, u8, &str)] = &[
        (ipv4(0, 0, 0, 0), 8, "this-network"),
        (ipv4(10, 0, 0, 0), 8, "private"),
        (ipv4(172, 16, 0, 0), 12, "private"),
        (ipv4(100, 64, 0, 0), 10, "shared-address-space"),
        (ipv4(127, 0, 0, 0), 8, "loopback"),
        (ipv4(169, 254, 0, 0), 16, "link-local"),
        (ipv4(192, 0, 0, 0), 24, "special-purpose"),
        (ipv4(192, 0, 2, 0), 24, "documentation"),
        (ipv4(192, 31, 196, 0), 24, "as112"),
        (ipv4(192, 52, 193, 0), 24, "as112"),
        (ipv4(192, 88, 99, 0), 24, "deprecated-6to4-relay"),
        (ipv4(192, 168, 0, 0), 16, "private"),
        (ipv4(192, 175, 48, 0), 24, "as112"),
        (ipv4(198, 18, 0, 0), 15, "benchmarking"),
        (ipv4(198, 51, 100, 0), 24, "documentation"),
        (ipv4(203, 0, 113, 0), 24, "documentation"),
        (ipv4(224, 0, 0, 0), 4, "multicast"),
        (ipv4(240, 0, 0, 0), 4, "reserved"),
    ];
    for &(network, prefix, reason) in ranges {
        if ipv4_contains(value, network, prefix) {
            return IpSafety::Special(reason);
        }
    }
    IpSafety::Public
}

fn classify_ipv6(address: std::net::Ipv6Addr) -> IpSafety {
    let value = u128::from(address);
    let ranges: &[(u128, u8, &str)] = &[
        (ipv6(0, 0, 0, 0), 128, "unspecified"),
        (ipv6(0, 0, 0, 1), 128, "loopback"),
        (ipv6(0x0100, 0, 0, 0), 64, "discard-only"),
        (ipv6(0x2001, 0, 0, 0), 32, "teredo"),
        (ipv6(0x2001, 0x0001, 0, 0), 32, "special-purpose"),
        (ipv6(0x2001, 0x0002, 0, 0), 48, "benchmarking"),
        (ipv6(0x2001, 0x0004, 0x0112, 0), 48, "as112"),
        (ipv6(0x2001, 0x0010, 0, 0), 28, "orchid"),
        (ipv6(0x2001, 0x0020, 0, 0), 28, "orchid"),
        (ipv6(0x2001, 0x0db8, 0, 0), 32, "documentation"),
        (ipv6(0x2002, 0, 0, 0), 16, "6to4"),
        (ipv6(0x3ffe, 0, 0, 0), 16, "6bone"),
        (ipv6(0x3fff, 0, 0, 0), 20, "documentation"),
        (ipv6(0x0064, 0xff9b, 0, 0), 96, "nat64"),
        (ipv6(0xfc00, 0, 0, 0), 7, "unique-local"),
        (ipv6(0xfec0, 0, 0, 0), 10, "site-local"),
        (ipv6(0xfe80, 0, 0, 0), 10, "link-local"),
        (ipv6(0xff00, 0, 0, 0), 8, "multicast"),
    ];
    for &(network, prefix, reason) in ranges {
        if ipv6_contains(value, network, prefix) {
            return IpSafety::Special(reason);
        }
    }
    IpSafety::Public
}

// ---------------------------------------------------------------------------
// Safe DNS resolver: closes the DNS-rebinding gap between pre-check and connect
// ---------------------------------------------------------------------------

pub mod resolver {
    use std::collections::HashSet;
    use std::net::ToSocketAddrs;

    use super::{IpSafety, classify_ip};

    pub use reqwest::dns::{Addrs, Name, Resolve, Resolving};

    /// A reqwest `Resolve` implementation that refuses to hand the client any
    /// address classified private or special unless explicitly allowed.
    pub struct SafeResolver {
        allow_private_network: bool,
    }

    impl SafeResolver {
        pub fn new(allow_private_network: bool) -> Self {
            Self {
                allow_private_network,
            }
        }
    }

    impl Resolve for SafeResolver {
        fn resolve(&self, name: Name) -> Resolving {
            let allow = self.allow_private_network;
            let host = name.as_str().to_owned();
            Box::pin(async move {
                let addrs: Vec<_> = (host.as_str(), 0u16)
                    .to_socket_addrs()
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
                    .collect();
                if addrs.is_empty() {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("no addresses resolved for {host}"),
                    ))
                        as Box<dyn std::error::Error + Send + Sync>);
                }
                let mut checked = HashSet::new();
                let mut safe: Vec<std::net::SocketAddr> = Vec::with_capacity(addrs.len());
                for socket in addrs {
                    if checked.insert(socket.ip()) && !allow {
                        if let IpSafety::Special(reason) = classify_ip(socket.ip()) {
                            return Err(Box::new(std::io::Error::new(
                                std::io::ErrorKind::PermissionDenied,
                                format!("refusing unsafe address {}: {reason}", socket.ip()),
                            ))
                                as Box<dyn std::error::Error + Send + Sync>);
                        }
                    }
                    safe.push(socket);
                }
                Ok(Box::new(safe.into_iter()) as Addrs)
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Extractive summary: local, deterministic, no network
// ---------------------------------------------------------------------------

/// Bounded extractive summary: picks the most content-bearing sentences from
/// plain text (e.g. extracted markdown) and returns them in document order.
///
/// Purely local - no network, no model. Scores sentences by term frequency
/// against the document itself (excluding stopwords), with light boosts for
/// early-position and heading-adjacent sentences. Deterministic: ties are
/// broken by document position. Output is UNTRUSTED page-derived data.
pub fn summarize_text(text: &str, max_sentences: usize) -> String {
    let max_sentences = max_sentences.max(1);
    let paragraphs = split_paragraphs(text);
    // Candidate sentences in document order.
    let mut sentences: Vec<Sentence> = Vec::new();
    let mut prev_was_heading = false;
    for (para_index, para) in paragraphs.iter().enumerate() {
        for raw in split_sentences(para) {
            let tokens = tokenize(&raw);
            if tokens.is_empty() {
                continue;
            }
            let is_heading = raw.starts_with('#');
            // Skip boilerplate-only fragments (nav crumbs, link-only lines),
            // but never skip headings - they anchor the summary.
            let alpha_count = tokens.iter().filter(|t| t.len() > 1).count();
            if !is_heading && alpha_count < 3 {
                continue;
            }
            let after_heading = prev_was_heading;
            prev_was_heading = is_heading;
            sentences.push(Sentence {
                text: raw,
                tokens,
                para_index,
                position: sentences.len(),
                after_heading,
            });
        }
    }
    if sentences.is_empty() {
        return String::new();
    }

    // Document term frequencies (excluding stopwords).
    let mut df: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for s in &sentences {
        let mut seen = std::collections::HashSet::new();
        for t in &s.tokens {
            if !is_stopword(t) && seen.insert(t.clone()) {
                *df.entry(t.clone()).or_insert(0) += 1;
            }
        }
    }

    // Score each sentence.
    let total = sentences.len() as f64;
    let mut scored: Vec<(usize, f64)> = Vec::new();
    for s in &sentences {
        let mut score: f64 = 0.0;
        let mut seen = std::collections::HashSet::new();
        for t in &s.tokens {
            if is_stopword(t) || t.len() < 2 || !seen.insert(t.clone()) {
                continue;
            }
            if let Some(freq) = df.get(t) {
                score += *freq as f64 / total;
            }
        }
        // Length normalization: avoid bias toward very long sentences.
        let token_count = s.tokens.len().max(1) as f64;
        score /= token_count.sqrt();
        // Light boost for early document position (intro/thesis sentences).
        if s.para_index == 0 {
            score *= 1.25;
        } else if s.para_index == 1 {
            score *= 1.1;
        }
        // Boost for the first sentence after a heading.
        if s.after_heading {
            score *= 1.3;
        }
        scored.push((s.position, score));
    }

    // Take top N by score, then restore document order.
    scored.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.0.cmp(&b.0))
    });
    scored.truncate(max_sentences);
    scored.sort_by_key(|(pos, _)| *pos);

    let mut out = String::new();
    for (i, (pos, _)) in scored.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(&sentences[*pos].text);
    }
    out
}

struct Sentence {
    text: String,
    tokens: Vec<String>,
    para_index: usize,
    position: usize,
    after_heading: bool,
}

fn split_paragraphs(text: &str) -> Vec<&str> {
    text.split("\n\n")
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect()
}

/// Splits a paragraph into sentence-ish units: markdown headings count as
/// their own unit; body text splits on `.`, `!`, `?` followed by whitespace.
fn split_sentences(paragraph: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in paragraph.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Markdown headings are atomic units (they anchor summaries).
        if line.starts_with('#') {
            out.push(line.to_owned());
            continue;
        }
        let mut current = String::new();
        let chars: Vec<char> = line.chars().collect();
        for (i, c) in chars.iter().enumerate() {
            current.push(*c);
            if matches!(c, '.' | '!' | '?') {
                let ends = match chars.get(i + 1) {
                    None => true,
                    Some(n) if n.is_whitespace() => true,
                    Some(')') | Some('"') | Some('\'') => chars
                        .get(i + 2)
                        .map(|n2| n2.is_whitespace())
                        .unwrap_or(true),
                    _ => false,
                };
                if ends {
                    let s = current.trim().to_owned();
                    if !s.is_empty() {
                        out.push(s);
                    }
                    current.clear();
                }
            }
        }
        let rest = current.trim();
        if !rest.is_empty() {
            out.push(rest.to_owned());
        }
    }
    out
}

fn tokenize(sentence: &str) -> Vec<String> {
    sentence
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

fn is_stopword(token: &str) -> bool {
    const STOPWORDS: &[&str] = &[
        "a", "an", "and", "are", "as", "at", "be", "but", "by", "for", "from", "has", "have", "he",
        "her", "his", "how", "i", "in", "is", "it", "its", "of", "on", "or", "our", "she", "that",
        "the", "their", "them", "then", "there", "these", "they", "this", "to", "was", "we",
        "were", "what", "when", "where", "which", "who", "will", "with", "you", "your", "also",
        "more", "most", "some", "such", "than", "can", "not", "no", "do", "does", "did", "if",
        "into", "about", "all", "other", "only", "so", "up", "out", "over", "under",
    ];
    STOPWORDS.contains(&token)
}

// ---------------------------------------------------------------------------
// Extraction: HTML -> Markdown (htmd), bounded
// ---------------------------------------------------------------------------

/// Bounded extraction: returns deterministic Markdown for an HTML document.
/// Output is UNTRUSTED (page-controlled prompt-injection surface) - callers
/// embedding this into LLM context must treat it as untrusted data.
pub fn html_to_markdown(
    html: &str,
    base_url: &str,
    max_output_bytes: usize,
) -> Result<String, CurlosityError> {
    let converter = htmd::HtmlToMarkdown::builder()
        .scripting_enabled(false)
        .build();
    let converted = converter
        .convert(html)
        .map_err(|e| CurlosityError::Config(format!("html conversion failed: {e}")))?;
    let markdown = normalize_markdown(&converted);
    if markdown.len() > max_output_bytes {
        return Err(CurlosityError::BodyTooLarge {
            limit: max_output_bytes as u64,
        });
    }
    let _ = base_url; // htmd resolves relative links against the document itself
    Ok(markdown)
}

fn normalize_markdown(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut blank_run = 0usize;
    for line in input.lines() {
        let trimmed_end = line.trim_end();
        if trimmed_end.is_empty() {
            blank_run += 1;
            if blank_run > 2 {
                continue;
            }
        } else {
            blank_run = 0;
        }
        out.push_str(trimmed_end);
        out.push('\n');
    }
    out.trim().to_owned()
}

// ---------------------------------------------------------------------------
// Batch protocol
// ---------------------------------------------------------------------------

/// One search to run. When no provider is configured, searches are reported
/// as skipped (never faked); fetches still run.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SearchRequest {
    pub query: String,
    #[serde(default)]
    pub count: Option<u32>,
}

/// One URL to fetch.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FetchRequest {
    pub url: String,
    #[serde(default = "default_true")]
    pub extract: bool,
}

fn default_true() -> bool {
    true
}

/// The batch request an agent pipes to stdin.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct BatchRequest {
    #[serde(default)]
    pub searches: Vec<SearchRequest>,
    #[serde(default)]
    pub fetches: Vec<FetchRequest>,
    /// Auto-fetch the top N results of each search (when a provider is
    /// configured). Ignored in fetch-only mode.
    #[serde(default)]
    pub extract_top: Option<u32>,
}

/// A single search hit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub url: String,
    pub title: String,
    pub snippet: String,
}

/// Result of one batched fetch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchedPage {
    pub url: String,
    pub final_url: String,
    pub status: u16,
    pub markdown: Option<String>,
    pub from_cache: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchOutcome {
    pub query: String,
    pub results: Vec<SearchResult>,
    pub skipped: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchOutcome {
    pub url: String,
    pub result: std::collections::HashMap<String, serde_json::Value>,
}

/// Per-item batch result (kept flat for agents).
#[derive(Debug, Clone, Serialize)]
pub struct BatchResult {
    pub ok: bool,
    pub data: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

/// Runtime configuration for a batch run.
#[derive(Debug, Clone)]
pub struct BatchConfig {
    pub concurrency: usize,
    pub per_host_concurrency: usize,
    pub timeout: std::time::Duration,
    pub retries: u32,
    pub max_body_size: u64,
    pub max_markdown_bytes: usize,
    pub allow_private_network: bool,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub cache: bool,
    /// Report explicit per-fetch cache_status: hit/miss in results.
    pub cache_status: bool,
    /// Attach a local extractive summary per fetched page.
    pub summarize: bool,
    /// Max sentences per summary.
    pub summary_sentences: usize,
    pub user_agent: String,
    /// Provider config for real search. None => fetch-only mode.
    pub provider: Option<ProviderConfig>,
    pub max_redirect_hops: usize,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            concurrency: 8,
            per_host_concurrency: 2,
            timeout: std::time::Duration::from_secs(30),
            retries: 2,
            max_body_size: 10 * 1024 * 1024,
            max_markdown_bytes: 2 * 1024 * 1024,
            allow_private_network: false,
            include: Vec::new(),
            exclude: Vec::new(),
            cache: true,
            cache_status: false,
            summarize: false,
            summary_sentences: 5,
            user_agent: concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION")).to_owned(),
            provider: None,
            max_redirect_hops: 10,
        }
    }
}

/// Search provider configuration. Only Brave is wired for MVP; the trait is
/// pluggable so agents can add providers without forking the batch loop.
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderConfig {
    pub name: String,
    pub api_key: String,
    #[serde(default)]
    pub endpoint: Option<String>,
}

pub const BRAVE_DEFAULT_ENDPOINT: &str = "https://api.search.brave.com/res/v1/web/search";

/// Pluggable search backend. Implement this to add a provider.
pub trait SearchProvider: Send + Sync {
    fn search<'a>(
        &'a self,
        query: &'a str,
        count: u32,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Vec<SearchResult>, CurlosityError>> + Send + 'a,
        >,
    >;
}

/// Brave Search API provider (requires BRAVE_API_KEY / provider config).
pub struct BraveProvider {
    client: reqwest::Client,
    endpoint: String,
    api_key: String,
}

impl BraveProvider {
    pub fn new(
        config: &ProviderConfig,
        config_defaults: &BatchConfig,
    ) -> Result<Self, CurlosityError> {
        let endpoint = config
            .endpoint
            .clone()
            .unwrap_or_else(|| BRAVE_DEFAULT_ENDPOINT.to_owned());
        let client = reqwest::Client::builder()
            .user_agent(&config_defaults.user_agent)
            .timeout(config_defaults.timeout)
            .build()
            .map_err(|e| CurlosityError::Config(format!("provider client: {e}")))?;
        Ok(Self {
            client,
            endpoint,
            api_key: config.api_key.clone(),
        })
    }
}

impl SearchProvider for BraveProvider {
    fn search<'a>(
        &'a self,
        query: &'a str,
        count: u32,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Vec<SearchResult>, CurlosityError>> + Send + 'a,
        >,
    > {
        Box::pin(self.search_inner(query, count))
    }
}

impl BraveProvider {
    pub async fn search_inner(
        &self,
        query: &str,
        count: u32,
    ) -> Result<Vec<SearchResult>, CurlosityError> {
        #[derive(Deserialize)]
        struct BraveResponse {
            #[serde(default)]
            web: Option<BraveWeb>,
        }
        #[derive(Deserialize)]
        struct BraveWeb {
            #[serde(default)]
            results: Vec<BraveResult>,
        }
        #[derive(Deserialize)]
        struct BraveResult {
            url: String,
            title: String,
            #[serde(default)]
            description: String,
        }
        let resp = self
            .client
            .get(&self.endpoint)
            .header("X-Subscription-Token", &self.api_key)
            .header("Accept", "application/json")
            .query(&[("q", query), ("count", &count.to_string())])
            .send()
            .await
            .map_err(|e| CurlosityError::Network(e.to_string()))?;
        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(CurlosityError::Status { status });
        }
        let parsed: BraveResponse = resp
            .json()
            .await
            .map_err(|e| CurlosityError::Network(format!("bad provider response: {e}")))?;
        Ok(parsed
            .web
            .map(|w| {
                w.results
                    .into_iter()
                    .map(|r| SearchResult {
                        url: r.url,
                        title: r.title,
                        snippet: r.description,
                    })
                    .collect()
            })
            .unwrap_or_default())
    }
}

/// Serper.dev Google-search provider (SERPER_API_KEY).
pub struct SerperProvider {
    client: reqwest::Client,
    endpoint: String,
    api_key: String,
}

pub const SERPER_DEFAULT_ENDPOINT: &str = "https://google.serper.dev/search";

impl SerperProvider {
    pub fn new(
        config: &ProviderConfig,
        config_defaults: &BatchConfig,
    ) -> Result<Self, CurlosityError> {
        let endpoint = config
            .endpoint
            .clone()
            .unwrap_or_else(|| SERPER_DEFAULT_ENDPOINT.to_owned());
        let client = reqwest::Client::builder()
            .user_agent(&config_defaults.user_agent)
            .timeout(config_defaults.timeout)
            .build()
            .map_err(|e| CurlosityError::Config(format!("provider client: {e}")))?;
        Ok(Self {
            client,
            endpoint,
            api_key: config.api_key.clone(),
        })
    }
}

impl SearchProvider for SerperProvider {
    fn search<'a>(
        &'a self,
        query: &'a str,
        count: u32,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Vec<SearchResult>, CurlosityError>> + Send + 'a,
        >,
    > {
        Box::pin(self.search_inner(query, count))
    }
}

impl SerperProvider {
    async fn search_inner(
        &self,
        query: &str,
        count: u32,
    ) -> Result<Vec<SearchResult>, CurlosityError> {
        #[derive(Deserialize)]
        struct SerperResponse {
            #[serde(default)]
            organic: Vec<SerperResult>,
        }
        #[derive(Deserialize)]
        struct SerperResult {
            link: String,
            title: String,
            #[serde(default)]
            snippet: String,
        }
        let resp = self
            .client
            .post(&self.endpoint)
            .header("X-API-KEY", &self.api_key)
            .json(&serde_json::json!({"q": query, "num": count}))
            .send()
            .await
            .map_err(|e| CurlosityError::Network(e.to_string()))?;
        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(CurlosityError::Status { status });
        }
        let parsed: SerperResponse = resp
            .json()
            .await
            .map_err(|e| CurlosityError::Network(format!("bad provider response: {e}")))?;
        Ok(parsed
            .organic
            .into_iter()
            .map(|r| SearchResult {
                url: r.link,
                title: r.title,
                snippet: r.snippet,
            })
            .collect())
    }
}

// ---------------------------------------------------------------------------
// Fetcher: bounded, redirect-aware, private-network-safe
// ---------------------------------------------------------------------------

const SNIFF_LIMIT: usize = 1024;

#[derive(Debug)]
pub struct Fetched {
    pub final_url: String,
    pub status: u16,
    pub body: Vec<u8>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub content_type: Option<String>,
}

pub struct Fetcher {
    client: reqwest::Client,
    allow_private_network: bool,
    max_redirect_hops: usize,
}

/// Resolves every address for `host` and rejects private/special ranges.
fn check_host_addresses(
    host: &str,
    port: u16,
    allow_private_network: bool,
) -> Result<(), CurlosityError> {
    if allow_private_network {
        return Ok(());
    }
    let mut checked = std::collections::HashSet::new();
    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| CurlosityError::Network(format!("DNS resolution failed for {host}: {e}")))?;
    for socket in addrs {
        if checked.insert(socket.ip()) {
            if let IpSafety::Special(reason) = classify_ip(socket.ip()) {
                return Err(CurlosityError::UnsafeAddress {
                    host: host.to_owned(),
                    reason,
                });
            }
        }
    }
    Ok(())
}

fn same_host(a: &reqwest::Url, b: &reqwest::Url) -> bool {
    a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
        && a.scheme() == b.scheme()
}

impl Fetcher {
    pub fn new(config: &BatchConfig) -> Result<Self, CurlosityError> {
        let client = reqwest::Client::builder()
            .user_agent(&config.user_agent)
            .timeout(config.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .dns_resolver(Arc::new(resolver::SafeResolver::new(
                config.allow_private_network,
            )))
            .build()
            .map_err(|e| CurlosityError::Config(format!("http client: {e}")))?;
        Ok(Self {
            client,
            allow_private_network: config.allow_private_network,
            max_redirect_hops: config.max_redirect_hops,
        })
    }

    /// Fetches `url` following at most `max_redirect_hops` hops. When
    /// validators from a previous fetch are supplied they are sent as
    /// `If-None-Match` / `If-Modified-Since`; a 304 returns
    /// `CurlosityError::NotModified` with no body downloaded.
    pub async fn get(
        &self,
        url: &str,
        max_body: u64,
        validators: Option<(&str, &str)>,
    ) -> Result<Fetched, CurlosityError> {
        let canonical = canonicalize_url(url, self.allow_private_network)?;
        self.fetch_following_redirects(canonical, max_body, validators)
            .await
    }

    async fn fetch_following_redirects(
        &self,
        start: url::Url,
        max_body: u64,
        validators: Option<(&str, &str)>,
    ) -> Result<Fetched, CurlosityError> {
        let mut current = start.clone();
        for hop in 0..=self.max_redirect_hops {
            check_host_addresses(
                current.host_str().ok_or_else(|| {
                    CurlosityError::InvalidUrl(format!("url {current} has no host"))
                })?,
                current.port_or_known_default().unwrap_or(80),
                self.allow_private_network,
            )?;
            let mut request = self.client.get(current.clone());
            // Validators only apply to the first hop; redirects re-verify.
            if hop == 0 {
                if let Some((etag, last_modified)) = validators {
                    if !etag.is_empty() {
                        request = request.header(reqwest::header::IF_NONE_MATCH, etag);
                    }
                    if !last_modified.is_empty() {
                        request = request.header(reqwest::header::IF_MODIFIED_SINCE, last_modified);
                    }
                }
            }
            let response = request.send().await.map_err(|e| {
                if e.is_timeout() {
                    CurlosityError::Timeout
                } else {
                    CurlosityError::Network(e.to_string())
                }
            })?;
            let status = response.status().as_u16();
            if status == 304 {
                return Err(CurlosityError::NotModified);
            }
            if (300..400).contains(&status) {
                let Some(location) = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                else {
                    return Err(CurlosityError::Network(format!(
                        "status {status} without Location header"
                    )));
                };
                let next = current
                    .join(location)
                    .map_err(|e| CurlosityError::InvalidUrl(format!("bad redirect target: {e}")))?;
                if next.scheme() == "http" && current.scheme() == "https" {
                    return Err(CurlosityError::RedirectDowngrade);
                }
                if !same_host(&start, &next) {
                    return Err(CurlosityError::Network(format!(
                        "cross-origin redirect to {next} rejected"
                    )));
                }
                current = next;
                continue;
            }
            if !(200..300).contains(&status) {
                return Err(CurlosityError::Status { status });
            }
            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            if !looks_fetchable(&content_type) {
                return Err(CurlosityError::NotFetchable(content_type));
            }
            if let Some(length) = response.content_length() {
                if length > max_body {
                    return Err(CurlosityError::BodyTooLarge { limit: max_body });
                }
            }
            let etag = response
                .headers()
                .get(reqwest::header::ETAG)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let last_modified = response
                .headers()
                .get(reqwest::header::LAST_MODIFIED)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let body = read_bounded(response, max_body).await?;
            return Ok(Fetched {
                final_url: current.to_string(),
                status,
                body,
                etag,
                last_modified,
                content_type,
            });
        }
        Err(CurlosityError::TooManyRedirects(self.max_redirect_hops))
    }
}

/// Fetchability policy: HTML/XHTML for extraction, plus any text/* so agents
/// can pull plain-text robots/docs. Everything else (binaries, video) is
/// rejected before the body downloads.
fn looks_fetchable(content_type: &Option<String>) -> bool {
    let Some(value) = content_type else {
        return true; // no content-type: bounded sniff after a small read
    };
    let lower = value.to_ascii_lowercase();
    lower.contains("text/html")
        || lower.contains("application/xhtml+xml")
        || lower.starts_with("text/")
}

/// Sniff for HTML when the server omitted Content-Type.
pub fn sniff_html_prefix(body: &[u8]) -> bool {
    let prefix = &body[..body.len().min(SNIFF_LIMIT)];
    let lower = prefix.to_ascii_lowercase();
    lower.starts_with(b"<!doctype html") || lower.windows(5).any(|w| w == b"<html")
}

async fn read_bounded(
    response: reqwest::Response,
    max_body: u64,
) -> Result<Vec<u8>, CurlosityError> {
    let mut body = Vec::new();
    let mut chunk_stream = response;
    while let Some(chunk) = chunk_stream.chunk().await.map_err(|e| {
        if e.is_timeout() {
            CurlosityError::Timeout
        } else {
            CurlosityError::Network(e.to_string())
        }
    })? {
        if body.len() as u64 + chunk.len() as u64 > max_body {
            return Err(CurlosityError::BodyTooLarge { limit: max_body });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

// ---------------------------------------------------------------------------
// Include/exclude globs (globset)
// ---------------------------------------------------------------------------

pub struct UrlFilter {
    include: Vec<globset::GlobMatcher>,
    exclude: Vec<globset::GlobMatcher>,
}

impl UrlFilter {
    pub fn new(include: &[String], exclude: &[String]) -> Result<Self, CurlosityError> {
        let compile = |patterns: &[String]| -> Result<Vec<globset::GlobMatcher>, CurlosityError> {
            patterns
                .iter()
                .map(|p| {
                    globset::Glob::new(p)
                        .map(|g| g.compile_matcher())
                        .map_err(|e| CurlosityError::Config(format!("bad glob `{p}`: {e}")))
                })
                .collect()
        };
        Ok(Self {
            include: compile(include)?,
            exclude: compile(exclude)?,
        })
    }

    pub fn allows(&self, url: &str) -> Result<(), CurlosityError> {
        if self.exclude.iter().any(|m| m.is_match(url)) {
            return Err(CurlosityError::Excluded(url.to_owned()));
        }
        if !self.include.is_empty() && !self.include.iter().any(|m| m.is_match(url)) {
            return Err(CurlosityError::NotIncluded(url.to_owned()));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Cache: sqlite at ~/.cache/curlosity/state.sqlite (etag/last-modified)
// ---------------------------------------------------------------------------

pub mod cache {
    use std::path::PathBuf;

    use super::CurlosityError;

    pub const SCHEMA_VERSION: i64 = 1;

    pub fn default_cache_path() -> PathBuf {
        if let Some(path) = std::env::var_os("CURLOSITY_CACHE_PATH") {
            return PathBuf::from(path);
        }
        let base = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
            .unwrap_or_else(|| PathBuf::from(".cache"));
        base.join("curlosity").join("state.sqlite")
    }

    /// A cached fetch: body bytes plus the validators needed for conditional re-fetch.
    #[derive(Debug, Clone)]
    pub struct CacheEntry {
        pub url: String,
        pub final_url: String,
        pub status: u16,
        pub body: Vec<u8>,
        pub content_type: Option<String>,
        pub etag: Option<String>,
        pub last_modified: Option<String>,
        pub fetched_at_ms: i64,
    }

    pub struct Cache {
        conn: std::sync::Mutex<rusqlite::Connection>,
    }

    impl Cache {
        pub fn open(path: &std::path::Path) -> Result<Self, CurlosityError> {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    CurlosityError::Cache(format!("create {}: {e}", parent.display()))
                })?;
            }
            let conn = rusqlite::Connection::open(path)
                .map_err(|e| CurlosityError::Cache(e.to_string()))?;
            conn.execute_batch(
                "PRAGMA journal_mode=WAL;
                 CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS fetch_cache (
                    url TEXT PRIMARY KEY,
                    final_url TEXT NOT NULL,
                    status INTEGER NOT NULL,
                    body BLOB NOT NULL,
                    content_type TEXT,
                    etag TEXT,
                    last_modified TEXT,
                    fetched_at_ms INTEGER NOT NULL
                 );",
            )
            .map_err(|e| CurlosityError::Cache(e.to_string()))?;
            Ok(Self {
                conn: std::sync::Mutex::new(conn),
            })
        }

        pub fn get(&self, url: &str) -> Option<CacheEntry> {
            let conn = self.conn.lock().ok()?;
            conn.query_row(
                "SELECT url, final_url, status, body, content_type, etag, last_modified, fetched_at_ms
                 FROM fetch_cache WHERE url = ?1",
                [url],
                |row| {
                    Ok(CacheEntry {
                        url: row.get(0)?,
                        final_url: row.get(1)?,
                        status: row.get(2)?,
                        body: row.get(3)?,
                        content_type: row.get(4)?,
                        etag: row.get(5)?,
                        last_modified: row.get(6)?,
                        fetched_at_ms: row.get(7)?,
                    })
                },
            )
            .ok()
        }

        pub fn put(&self, entry: &CacheEntry) -> Result<(), CurlosityError> {
            let conn = self
                .conn
                .lock()
                .map_err(|_| CurlosityError::Cache("lock poisoned".into()))?;
            conn.execute(
                "INSERT OR REPLACE INTO fetch_cache
                 (url, final_url, status, body, content_type, etag, last_modified, fetched_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    entry.url,
                    entry.final_url,
                    entry.status,
                    entry.body,
                    entry.content_type,
                    entry.etag,
                    entry.last_modified,
                    entry.fetched_at_ms
                ],
            )
            .map_err(|e| CurlosityError::Cache(e.to_string()))?;
            Ok(())
        }
    }

    pub fn unix_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Batch engine: bounded concurrency + per-host concurrency
// ---------------------------------------------------------------------------

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    format!("{:x}", h.finalize())
}

/// Runs the full batch: searches (provider or fetch-only skip), fetches with
/// extraction, all under bounded global + per-host parallelism.
pub async fn batch(
    req: BatchRequest,
    config: &BatchConfig,
) -> Result<serde_json::Value, CurlosityError> {
    use std::sync::Arc;

    if config.per_host_concurrency > config.concurrency {
        return Err(CurlosityError::Config(
            "per_host_concurrency must not exceed concurrency".into(),
        ));
    }

    let filter = Arc::new(UrlFilter::new(&config.include, &config.exclude)?);
    let fetcher = Arc::new(Fetcher::new(config)?);
    let cache = if config.cache {
        Some(Arc::new(cache::Cache::open(&cache::default_cache_path())?))
    } else {
        None
    };

    // ----- searches -----
    let provider: Option<Arc<dyn SearchProvider>> = match &config.provider {
        Some(pcfg) => match pcfg.name.to_ascii_lowercase().as_str() {
            "brave" => Some(Arc::new(BraveProvider::new(pcfg, config)?)),
            "serper" => Some(Arc::new(SerperProvider::new(pcfg, config)?)),
            other => {
                return Err(CurlosityError::Config(format!(
                    "unknown search provider `{other}` (supported: brave, serper)"
                )));
            }
        },
        None => None,
    };

    let global = Arc::new(tokio::sync::Semaphore::new(config.concurrency));
    let per_host: Arc<
        std::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Semaphore>>>,
    > = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

    let mut search_outcomes: Vec<SearchOutcome> = Vec::new();
    let mut search_handles = Vec::new();
    for s in &req.searches {
        let count = s.count.unwrap_or(5);
        let query = s.query.clone();
        if let Some(provider) = provider.clone() {
            let permit = global
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| CurlosityError::Config("semaphore closed".into()))?;
            search_handles.push(tokio::spawn(async move {
                let _permit = permit;
                match provider.search(&query, count).await {
                    Ok(results) => SearchOutcome {
                        query,
                        results,
                        skipped: false,
                        error: None,
                    },
                    Err(e) => SearchOutcome {
                        query,
                        results: vec![],
                        skipped: false,
                        error: Some(e.to_string()),
                    },
                }
            }));
        } else {
            search_outcomes.push(SearchOutcome {
                query,
                results: vec![],
                skipped: true,
                error: Some("no search provider configured (fetch-only mode): set provider config for real search".into()),
            });
        }
    }
    for handle in search_handles {
        if let Ok(outcome) = handle.await {
            search_outcomes.push(outcome);
        }
    }
    // Preserve request order (spawning order for provider searches was request order,
    // skipped entries were pushed in order; sort by original index instead):
    // rebuild in request order.
    search_outcomes.sort_by_key(|o| {
        req.searches
            .iter()
            .position(|s| s.query == o.query)
            .unwrap_or(usize::MAX)
    });

    // ----- collect fetch URLs: explicit + extract_top from real search results -----
    let mut fetch_jobs: Vec<FetchRequest> = req.fetches.clone();
    if let (Some(top), Some(_)) = (req.extract_top, provider.as_ref()) {
        for outcome in &search_outcomes {
            for result in outcome.results.iter().take(top as usize) {
                fetch_jobs.push(FetchRequest {
                    url: result.url.clone(),
                    extract: true,
                });
            }
        }
    }

    // ----- fetches -----
    let mut fetch_results: Vec<std::collections::HashMap<String, serde_json::Value>> = Vec::new();
    let mut handles = Vec::new();
    for job in &fetch_jobs {
        let fetcher = fetcher.clone();
        let filter = filter.clone();
        let cache = cache.clone();
        let global = global.clone();
        let per_host = per_host.clone();
        let url = job.url.clone();
        let extract = job.extract;
        let config = config.clone();
        handles.push(tokio::spawn(async move {
            run_fetch(
                url, extract, fetcher, filter, cache, global, per_host, config,
            )
            .await
        }));
    }
    for handle in handles {
        fetch_results.push(handle.await.unwrap_or_else(|e| {
            std::collections::HashMap::from([(
                "error".to_owned(),
                serde_json::json!(format!("task join failure: {e}")),
            )])
        }));
    }

    let mut fetches_out: Vec<serde_json::Value> = Vec::with_capacity(fetch_results.len());
    for (job, result) in fetch_jobs.iter().zip(fetch_results.iter()) {
        fetches_out.push(serde_json::json!({
            "url": job.url,
            "result": result,
        }));
    }

    let searches_out: Vec<serde_json::Value> = search_outcomes
        .iter()
        .map(|o| {
            serde_json::json!({
                "query": o.query,
                "results": o.results,
                "skipped": o.skipped,
                "error": o.error,
            })
        })
        .collect();

    let any_error = fetches_out
        .iter()
        .any(|f| f["result"].get("error").is_some())
        || search_outcomes
            .iter()
            .any(|o| o.error.is_some() && !o.skipped);

    Ok(serde_json::json!({
        "searches": searches_out,
        "fetches": fetches_out,
        "fetch_only_mode": provider.is_none(),
        "ok": !any_error,
    }))
}

#[allow(clippy::too_many_arguments)]
async fn run_fetch(
    url: String,
    extract: bool,
    fetcher: Arc<Fetcher>,
    filter: Arc<UrlFilter>,
    cache: Option<Arc<cache::Cache>>,
    global: Arc<tokio::sync::Semaphore>,
    per_host: Arc<std::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Semaphore>>>>,
    config: BatchConfig,
) -> std::collections::HashMap<String, serde_json::Value> {
    let _permit = match global.acquire_owned().await {
        Ok(p) => p,
        Err(_) => {
            return std::collections::HashMap::from([(
                "error".into(),
                serde_json::json!("semaphore closed"),
            )]);
        }
    };

    if let Err(e) = filter.allows(&url) {
        return std::collections::HashMap::from([
            ("error".into(), serde_json::json!(e.to_string())),
            ("code".into(), serde_json::json!(e.code())),
        ]);
    }

    // Per-host permit keyed by host:port.
    let host_key = url::Url::parse(&url).ok().map(|u| {
        format!(
            "{}:{}",
            u.host_str().unwrap_or(""),
            u.port_or_known_default().unwrap_or(0)
        )
    });
    let host_permit = match &host_key {
        Some(key) => {
            let sem = {
                let mut map = per_host.lock().unwrap();
                map.entry(key.clone())
                    .or_insert_with(|| {
                        Arc::new(tokio::sync::Semaphore::new(config.per_host_concurrency))
                    })
                    .clone()
            };
            match sem.acquire_owned().await {
                Ok(p) => Some(p),
                Err(_) => {
                    return std::collections::HashMap::from([(
                        "error".into(),
                        serde_json::json!("semaphore closed"),
                    )]);
                }
            }
        }
        None => None,
    };

    // Cache read: if we have validators, try conditional revalidation by
    // trusting etag equality when server echoes the same etag. For MVP, if a
    // cached entry exists and re-fetch returns the same etag, we still fetched
    // (validators checked post-hoc) - real 304 savings require If-None-Match,
    // which reqwest request-builder path supports. Implement proper flow below.
    let mut result = std::collections::HashMap::new();

    // Cached validators enable conditional revalidation (304 => serve cache).
    let cached = cache.as_ref().and_then(|c| c.get(&url));
    let validators = cached.as_ref().map(|e| {
        (
            e.etag.clone().unwrap_or_default(),
            e.last_modified.clone().unwrap_or_default(),
        )
    });

    // Retry loop with exponential backoff on retryable errors.
    let mut last_error: Option<CurlosityError> = None;
    let mut fetched: Option<Fetched> = None;
    let mut served_from_cache = false;
    for attempt in 0..=config.retries {
        let attempt_result = match &validators {
            Some((etag, last_modified)) if !etag.is_empty() || !last_modified.is_empty() => {
                match fetcher
                    .get(
                        &url,
                        config.max_body_size,
                        Some((etag.as_str(), last_modified.as_str())),
                    )
                    .await
                {
                    // 304: cached copy is fresh, serve it without re-downloading.
                    Err(CurlosityError::NotModified) => cached
                        .as_ref()
                        .map(|e| Fetched {
                            final_url: e.final_url.clone(),
                            status: e.status,
                            body: e.body.clone(),
                            etag: e.etag.clone(),
                            last_modified: e.last_modified.clone(),
                            content_type: e.content_type.clone(),
                        })
                        .inspect(|_| {
                            served_from_cache = true;
                        })
                        .ok_or(CurlosityError::Cache("304 but cache entry vanished".into())),
                    other => other,
                }
            }
            _ => fetcher.get(&url, config.max_body_size, None).await,
        };
        match attempt_result {
            Ok(f) => {
                fetched = Some(f);
                last_error = None;
                break;
            }
            Err(e) => {
                if e.is_retryable() && attempt < config.retries {
                    let backoff = std::time::Duration::from_millis(500u64 << attempt)
                        .min(std::time::Duration::from_secs(8));
                    tokio::time::sleep(backoff).await;
                    last_error = Some(e);
                    continue;
                }
                last_error = Some(e);
                break;
            }
        }
    }
    drop(host_permit);

    match fetched {
        Some(f) => {
            // Cache write with validators.
            if let Some(cache) = &cache {
                let _ = cache.put(&cache::CacheEntry {
                    url: url.clone(),
                    final_url: f.final_url.clone(),
                    status: f.status,
                    body: f.body.clone(),
                    content_type: f.content_type.clone(),
                    etag: f.etag.clone(),
                    last_modified: f.last_modified.clone(),
                    fetched_at_ms: cache::unix_ms(),
                });
            }
            let (markdown, summary) = if extract {
                let body_str = String::from_utf8_lossy(&f.body).to_string();
                let md = html_to_markdown(&body_str, &f.final_url, config.max_markdown_bytes).ok();
                let summary = md
                    .as_deref()
                    .filter(|_| config.summarize)
                    .map(|md| summarize_text(md, config.summary_sentences));
                (md, summary)
            } else {
                (None, None)
            };
            let body_len = f.body.len();
            let etag = f.etag.clone();
            let last_modified = f.last_modified.clone();
            result.insert("final_url".into(), serde_json::json!(f.final_url));
            result.insert("status".into(), serde_json::json!(f.status));
            result.insert("bytes".into(), serde_json::json!(body_len));
            result.insert("from_cache".into(), serde_json::json!(served_from_cache));
            if config.cache_status {
                result.insert(
                    "cache_status".into(),
                    serde_json::json!(if served_from_cache { "hit" } else { "miss" }),
                );
            }
            if let Some(md) = markdown {
                result.insert("markdown".into(), serde_json::json!(md));
            }
            if let Some(s) = summary {
                result.insert("summary".into(), serde_json::json!(s));
            }
            if let Some(e) = etag {
                result.insert("etag".into(), serde_json::json!(e));
            }
            if let Some(lm) = last_modified {
                result.insert("last_modified".into(), serde_json::json!(lm));
            }
            let _ = sha256_hex(&f.body); // page id available for future cache keys
            result
        }
        None => {
            let e = last_error
                .unwrap_or_else(|| CurlosityError::Network("unknown fetch failure".into()));
            result.insert("error".into(), serde_json::json!(e.to_string()));
            result.insert("code".into(), serde_json::json!(e.code()));
            result
        }
    }
}
