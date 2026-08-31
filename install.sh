#!/bin/sh
# curlosity installer — POSIX, fail-closed.
# Usage: curl -fsSL https://raw.githubusercontent.com/riceharvest/curlosity/main/install.sh | sh
# Override version: CURLOSITY_VERSION=v0.1.0 sh install.sh
set -eu

REPO="riceharvest/curlosity"
BIN="curlosity"
INSTALL_DIR="${CURLOSITY_INSTALL_DIR:-$HOME/.local/bin}"

log() { printf 'curlosity-installer: %s\n' "$1" >&2; }
fail() { log "ERROR: $1"; exit 1; }

command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 ||
  fail "need curl or wget to download"

fetch() {
  url=$1
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url"
  else
    wget -qO- "$url"
  fi
}

fetch_to() {
  url=$1
  dest=$2
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$dest" "$url" || fail "download failed: $url"
  else
    wget -qO "$dest" "$url" || fail "download failed: $url"
  fi
}

OS=$(uname -s)
ARCH=$(uname -m)

case "$OS" in
  Linux) os_component="unknown-linux-musl" ;;
  Darwin) os_component="apple-darwin" ;;
  *) fail "unsupported OS '$OS' (supported: Linux, macOS)" ;;
esac

case "$ARCH" in
  x86_64 | amd64) arch_component="x86_64" ;;
  aarch64 | arm64) arch_component="aarch64" ;;
  *) fail "unsupported architecture '$ARCH' (supported: x86_64, aarch64)" ;;
esac

TARGET="${arch_component}-${os_component}"

if [ -n "${CURLOSITY_VERSION:-}" ]; then
  VERSION="$CURLOSITY_VERSION"
else
  log "resolving latest release..."
  VERSION=$(fetch "https://api.github.com/repos/$REPO/releases/latest" |
    sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
  [ -n "$VERSION" ] || fail "could not determine latest release (set CURLOSITY_VERSION to pin one)"
fi

BASE_URL="https://github.com/$REPO/releases/download/$VERSION"
ARCHIVE="${BIN}-${VERSION#v}-${TARGET}.tar.gz"
TMPDIR_INST=$(mktemp -d)
trap 'rm -rf "$TMPDIR_INST"' EXIT

log "downloading $VERSION for $TARGET..."
fetch_to "$BASE_URL/$ARCHIVE" "$TMPDIR_INST/$ARCHIVE"
fetch_to "$BASE_URL/SHA256SUMS" "$TMPDIR_INST/SHA256SUMS"

log "verifying checksum..."
EXPECTED=$(grep " $ARCHIVE\$" "$TMPDIR_INST/SHA256SUMS" | awk '{print $1}')
[ -n "$EXPECTED" ] || fail "no checksum found for $ARCHAVE"
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL=$(sha256sum "$TMPDIR_INST/$ARCHIVE" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL=$(shasum -a 256 "$TMPDIR_INST/$ARCHIVE" | awk '{print $1}')
else
  fail "need sha256sum or shasum to verify checksum"
fi
[ "$ACTUAL" = "$EXPECTED" ] || fail "checksum mismatch: expected $EXPECTED, got $ACTUAL"

log "extracting..."
tar xzf "$TMPDIR_INST/$ARCHIVE" -C "$TMPDIR_INST" ||
  fail "archive extraction failed"
mkdir -p "$INSTALL_DIR"
mv "$TMPDIR_INST/${BIN}-${VERSION#v}-${TARGET}/$BIN" "$INSTALL_DIR/$BIN" ||
  fail "install to $INSTALL_DIR failed"
chmod +x "$INSTALL_DIR/$BIN"

"$INSTALL_DIR/$BIN" --version >/dev/null 2>&1 ||
  fail "installed binary failed to run --version"

log "installed $VERSION to $INSTALL_DIR/$BIN"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) log "NOTE: $INSTALL_DIR is not on your PATH" ;;
esac
