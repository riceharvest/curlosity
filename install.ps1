# recurlsively installer for Windows — fail-closed.
# Usage: irm https://raw.githubusercontent.com/riceharvest/curlosity/main/install.ps1 | iex
# Override version: $env:CURLOSITY_VERSION = "v0.1.0"
$ErrorActionPreference = "Stop"

$Repo = "riceharvest/curlosity"
$Bin = "curlosity"
$InstallDir = if ($env:CURLOSITY_INSTALL_DIR) { $env:CURLOSITY_INSTALL_DIR } else { "$env:USERPROFILE\.local\bin" }

function Fail($message) {
    Write-Error "curlosity-installer: ERROR: $message"
    exit 1
}

# OS check: this script targets Windows only.
if (-not $IsWindows -and $env:OS -ne "Windows_NT") {
    Fail "unsupported OS (use install.sh on Linux/macOS)"
}

# Architecture.
$Arch = $env:PROCESSOR_ARCHITECTURE
switch ($Arch) {
    "AMD64" { $Target = "x86_64-pc-windows-msvc" }
    "ARM64" { Fail "unsupported architecture '$Arch'" }
    default { Fail "unsupported architecture '$Arch' (supported: x86_64)" }
}

# Version resolution.
if ($env:CURLOSITY_VERSION) {
    $Version = $env:CURLOSITY_VERSION
} else {
    Write-Host "curlosity-installer: resolving latest release..."
    try {
        $Release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -ErrorAction Stop
        $Version = $Release.tag_name
    } catch {
        Fail "could not determine latest release (set `$env:CURLOSITY_VERSION to pin one): $_"
    }
}
if (-not $Version) { Fail "could not determine release version" }

$ShortVersion = $Version.Substring(1)
$Archive = "$Bin-$ShortVersion-$Target.zip"
$BaseUrl = "https://github.com/$Repo/releases/download/$Version"
$Tmp = New-Item -ItemType Directory -Force -Path (Join-Path $env:TEMP "recurlsively-install-$PID")

try {
    Write-Host "curlosity-installer: downloading $Version for $Target..."
    $ArchivePath = Join-Path $Tmp $Archive
    $ChecksumPath = Join-Path $Tmp "SHA256SUMS"
    try {
        Invoke-WebRequest -Uri "$BaseUrl/$Archive" -OutFile $ArchivePath -ErrorAction Stop | Out-Null
        Invoke-WebRequest -Uri "$BaseUrl/SHA256SUMS" -OutFile $ChecksumPath -ErrorAction Stop | Out-Null
    } catch {
        Fail "download failed: $_"
    }

    Write-Host "curlosity-installer: verifying checksum..."
    $ExpectedLine = (Get-Content $ChecksumPath) | Where-Object { $_ -match [regex]::Escape($Archive) }
    if (-not $ExpectedLine) { Fail "no checksum found for $Archive" }
    $Expected = ($ExpectedLine -split '\s+')[0].ToLower()
    $Actual = (Get-FileHash -Path $ArchivePath -Algorithm SHA256).Hash.ToLower()
    if ($Actual -ne $Expected) { Fail "checksum mismatch: expected $Expected, got $Actual" }

    Write-Host "curlosity-installer: extracting..."
    Expand-Archive -Path $ArchivePath -DestinationPath $Tmp -Force
    $Binary = Join-Path $Tmp "$Bin-$ShortVersion-$Target" "$Bin.exe"
    if (-not (Test-Path $Binary)) { Fail "archive did not contain $Bin.exe" }

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item -Path $Binary -Destination (Join-Path $InstallDir "$Bin.exe") -Force

    & (Join-Path $InstallDir "$Bin.exe") --version | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "installed binary failed to run --version" }

    Write-Host "curlosity-installer: installed $Version to $InstallDir\$Bin.exe"
    if ($env:PATH -notlike "*$InstallDir*") {
        Write-Host "curlosity-installer: NOTE: $InstallDir is not on your PATH"
    }
} finally {
    Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}
