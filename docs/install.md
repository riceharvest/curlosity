# Installing recurlsively

Prebuilt binaries are published on the
[GitHub Releases](https://github.com/riceharvest/recurlsively/releases) page
for every tagged version. You do not need Rust installed.

## One-line install

macOS / Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/riceharvest/recurlsively/main/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/riceharvest/recurlsively/main/install.ps1 | iex
```

The installer detects your OS and architecture, downloads the matching
release asset, verifies its SHA-256 checksum, installs to
`~/.local/bin` (or `%USERPROFILE%\.local\bin`), and refuses to leave a
partial install on any failure.

Pin a specific version:

```sh
RECURSIVELY_VERSION=v0.1.0 sh install.sh        # macOS / Linux
$env:RECURSIVELY_VERSION = "v0.1.0"; irm .../install.ps1 | iex   # Windows
```

## Manual install

1. Download `recurlsively-<version>-<target>.tar.gz` (or `.zip` on Windows)
   from the releases page for your platform:

   | Target | Platform |
   |---|---|
   | `x86_64-unknown-linux-musl` | Linux, 64-bit (static) |
   | `aarch64-unknown-linux-musl` | Linux, ARM64 (static) |
   | `x86_64-apple-darwin` | macOS, Intel |
   | `aarch64-apple-darwin` | macOS, Apple Silicon |
   | `x86_64-pc-windows-msvc` | Windows, 64-bit |

2. Verify the checksum against `SHA256SUMS`:

   ```sh
   sha256sum -c SHA256SUMS          # Linux
   shasum -a 256 -c SHA256SUMS      # macOS
   Get-FileHash ... -Algorithm SHA256   # Windows
   ```

3. Extract and move the binary somewhere on your `PATH`.

## Build from source

```sh
git clone https://github.com/riceharvest/recurlsively
cd recurlsively
cargo install --path .
```

Rust 1.85 or newer is required.
