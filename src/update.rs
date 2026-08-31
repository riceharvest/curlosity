//! `agentic-web --update` — self-update from GitHub Releases.

const REPO: &str = "riceharvest/curlosity";
const BIN: &str = "curlosity";

#[derive(Debug)]
pub enum UpdateError {
    Network(String),
    NoAsset(String),
    Checksum { expected: String, actual: String },
    Io(std::io::Error),
    UpToDate(String),
}
impl std::fmt::Display for UpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network(e) => write!(f, "network error: {e}"),
            Self::NoAsset(m) => write!(f, "{m}"),
            Self::Checksum { expected, actual } => {
                write!(f, "checksum mismatch: expected {expected}, got {actual}")
            }
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::UpToDate(v) => write!(f, "already up to date ({v})"),
        }
    }
}
impl std::error::Error for UpdateError {}

fn client() -> Result<reqwest::Client, UpdateError> {
    reqwest::Client::builder()
        .user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ))
        .timeout(std::time::Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .map_err(|e| UpdateError::Network(e.to_string()))
}

#[derive(serde::Deserialize)]
struct LatestRelease {
    tag_name: String,
}

fn target_triple() -> Result<&'static str, UpdateError> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    return Ok("x86_64-unknown-linux-musl");
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    return Ok("aarch64-unknown-linux-musl");
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    return Ok("x86_64-apple-darwin");
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    return Ok("aarch64-apple-darwin");
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return Ok("x86_64-pc-windows-msvc");
    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "windows", target_arch = "x86_64")
    )))]
    return Err(UpdateError::NoAsset(
        "no prebuilt asset for this platform; build from source instead".to_owned(),
    ));
}

fn extract_tarball(archive: &[u8], dir: &std::path::Path) -> Result<(), UpdateError> {
    let dec = flate2::read::GzDecoder::new(archive);
    let mut tar = tar::Archive::new(dec);
    tar.unpack(dir).map_err(UpdateError::Io)
}
#[cfg(target_os = "windows")]
fn extract_zip(archive: &[u8], dir: &std::path::Path) -> Result<(), UpdateError> {
    let r = std::io::Cursor::new(archive);
    let mut z = zip::ZipArchive::new(r).map_err(|e| {
        UpdateError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            e.to_string(),
        ))
    })?;
    z.extract(dir).map_err(|e| {
        UpdateError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            e.to_string(),
        ))
    })
}

pub async fn run_update() -> Result<String, UpdateError> {
    let current = env!("CARGO_PKG_VERSION");
    let triple = target_triple()?;
    let cli = client()?;
    let rel: LatestRelease = cli
        .get(format!(
            "https://api.github.com/repos/{}/releases/latest",
            REPO
        ))
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await
        .map_err(|e| UpdateError::Network(e.to_string()))?
        .error_for_status()
        .map_err(|e| UpdateError::Network(e.to_string()))?
        .json()
        .await
        .map_err(|e| UpdateError::Network(e.to_string()))?;
    let tag = rel.tag_name.clone();
    let ver = tag.trim_start_matches('v');
    if ver == current {
        return Err(UpdateError::UpToDate(format!("{} v{}", BIN, current)));
    }
    let archive = if triple == "x86_64-pc-windows-msvc" {
        format!("{}-{}-{}.zip", BIN, ver, triple)
    } else {
        format!("{}-{}-{}.tar.gz", BIN, ver, triple)
    };
    let base = format!("https://github.com/{}/releases/download/{}", REPO, tag);
    let sums: String = cli
        .get(format!("{}/SHA256SUMS", base))
        .send()
        .await
        .map_err(|e| UpdateError::Network(e.to_string()))?
        .error_for_status()
        .map_err(|e| UpdateError::Network(e.to_string()))?
        .text()
        .await
        .map_err(|e| UpdateError::Network(e.to_string()))?;
    let expected = sums
        .lines()
        .find(|l| l.contains(&archive))
        .ok_or_else(|| UpdateError::NoAsset(format!("no checksum for {}", archive)))?
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_owned();
    let bytes = cli
        .get(format!("{}/{}", base, archive))
        .send()
        .await
        .map_err(|e| UpdateError::Network(e.to_string()))?
        .error_for_status()
        .map_err(|e| UpdateError::Network(e.to_string()))?
        .bytes()
        .await
        .map_err(|e| UpdateError::Network(e.to_string()))?;
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(&bytes);
    let actual = format!("{:x}", h.finalize());
    if actual != expected {
        return Err(UpdateError::Checksum { expected, actual });
    }
    let tmp = tempfile::tempdir().map_err(UpdateError::Io)?;
    if triple == "x86_64-pc-windows-msvc" {
        #[cfg(target_os = "windows")]
        {
            extract_zip(&bytes, tmp.path())?;
        }
        #[cfg(not(target_os = "windows"))]
        return Err(UpdateError::NoAsset(
            "windows archive on non-windows".to_owned(),
        ));
    } else {
        extract_tarball(&bytes, tmp.path())?;
    }
    let exe = std::env::current_exe().map_err(UpdateError::Io)?;
    let extracted = tmp.path().join(format!("{}-{}-{}", BIN, ver, triple)).join(
        if triple == "x86_64-pc-windows-msvc" {
            format!("{}.exe", BIN)
        } else {
            BIN.to_owned()
        },
    );
    let data = std::fs::read(&extracted).map_err(UpdateError::Io)?;
    // atomic replace via temp file + rename
    let tmp_exe = exe.with_extension("tmp_update");
    std::fs::write(&tmp_exe, &data).map_err(UpdateError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut p = std::fs::metadata(&tmp_exe)
            .map_err(UpdateError::Io)?
            .permissions();
        p.set_mode(0o755);
        std::fs::set_permissions(&tmp_exe, p).map_err(UpdateError::Io)?;
    }
    std::fs::rename(&tmp_exe, &exe).map_err(UpdateError::Io)?;
    Ok(format!(
        "updated {} v{} -> v{} ({})",
        BIN, current, ver, triple
    ))
}
