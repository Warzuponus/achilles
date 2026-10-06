#!/bin/sh
# Install the `achilles` CLI from a GitHub Release.
#
#   curl -fsSLO https://raw.githubusercontent.com/Warzuponus/achilles/main/scripts/install.sh
#   less install.sh                       # read it before you run it
#   sh install.sh                         # latest release -> ~/.local/bin
#   VERSION=v0.1.0 INSTALL_DIR=/usr/local/bin sh install.sh
#
# Environment:
#   VERSION      release tag to install, e.g. v0.1.0 (default or "latest": the latest release)
#   INSTALL_DIR  where to put the binary (default: $HOME/.local/bin)
#   ACHILLES_DOWNLOAD_BASE
#                override the release download URL prefix (mirrors, offline tests);
#                the archive is still verified against checksums.txt from there
#
# What it does: downloads achilles_<version>_<os>_<arch>.tar.gz and checksums.txt
# from github.com/Warzuponus/achilles/releases, verifies the archive's sha256 (and the
# cosign signature of checksums.txt when `cosign` is installed), extracts ONLY the
# `achilles` binary, and installs it. It runs nothing it downloaded.
#
# Scanners are separate: afterwards run `achilles tools install` and `achilles doctor`.

set -eu

REPO="Warzuponus/achilles"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

say() { printf '%s\n' "$*"; }
die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v tar >/dev/null 2>&1 || die "tar is required"

# --- platform ---------------------------------------------------------------
case "$(uname -s)" in
  Linux)  os=linux ;;
  Darwin) os=darwin ;;
  MINGW*|MSYS*|CYGWIN*)
    die "on Windows, download achilles_<version>_windows_amd64.zip from https://github.com/$REPO/releases and put achilles.exe on your PATH" ;;
  *) die "unsupported OS: $(uname -s)" ;;
esac
case "$(uname -m)" in
  x86_64|amd64)  arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

# --- curl flags: https only (file:// only when a base override is given) ----
if [ -n "${ACHILLES_DOWNLOAD_BASE:-}" ]; then
  proto='=https,file'
else
  proto='=https'
fi
fetch() { curl --proto "$proto" --tlsv1.2 -fsSL --retry 3 -o "$2" "$1"; }

# --- version ----------------------------------------------------------------
tag="${VERSION:-}"
if [ "$tag" = "latest" ]; then tag=""; fi
if [ -z "$tag" ]; then
  # /releases/latest redirects to /releases/tag/<tag>; no API token or rate limit.
  final="$(curl --proto '=https' --tlsv1.2 -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest")" \
    || die "could not look up the latest release (none published yet, or the repository is private); set VERSION=vX.Y.Z"
  tag="${final##*/}"
  case "$final" in
    */releases/tag/*) ;;
    *) die "no published release found at https://github.com/$REPO/releases" ;;
  esac
fi
case "$tag" in v*) ;; *) tag="v$tag" ;; esac
case "$tag" in
  *[!A-Za-z0-9._+-]*) die "refusing odd-looking version: $tag" ;;
esac
ver="${tag#v}"

archive="achilles_${ver}_${os}_${arch}.tar.gz"
base="${ACHILLES_DOWNLOAD_BASE:-https://github.com/$REPO/releases/download/$tag}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
trap 'exit 1' INT TERM HUP

say "Installing achilles $tag ($os/$arch)"
fetch "$base/$archive" "$tmp/$archive" || die "download failed: $base/$archive"
fetch "$base/checksums.txt" "$tmp/checksums.txt" || die "download failed: $base/checksums.txt"

# --- verify -----------------------------------------------------------------
if command -v sha256sum >/dev/null 2>&1; then
  sha() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  die "need sha256sum or shasum to verify the download"
fi

want="$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1; exit }' "$tmp/checksums.txt")"
[ -n "$want" ] || die "$archive is not listed in checksums.txt"
got="$(sha "$tmp/$archive")"
if [ "$got" != "$want" ]; then
  die "sha256 mismatch for $archive (expected $want, got $got); refusing to install"
fi
say "sha256 ok"

if command -v cosign >/dev/null 2>&1; then
  if fetch "$base/checksums.txt.sigstore.json" "$tmp/checksums.txt.sigstore.json" 2>/dev/null; then
    cosign verify-blob \
      --certificate-identity "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$tag" \
      --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
      --bundle "$tmp/checksums.txt.sigstore.json" "$tmp/checksums.txt" >/dev/null 2>&1 \
      || die "cosign signature verification of checksums.txt FAILED; refusing to install"
    say "cosign signature ok"
  else
    say "note: no signature bundle published for $tag; relying on sha256 only"
  fi
else
  say "note: cosign not installed; skipping signature check (sha256 verified)"
fi

# --- install ----------------------------------------------------------------
mkdir -p "$tmp/x"
tar -xzf "$tmp/$archive" -C "$tmp/x" achilles || die "archive does not contain the achilles binary"
mkdir -p "$INSTALL_DIR" || die "cannot create $INSTALL_DIR (set INSTALL_DIR to a writable directory)"
# Copy beside the destination, then rename, so an interrupted install never leaves
# a half-written binary on PATH.
cp "$tmp/x/achilles" "$INSTALL_DIR/.achilles.new.$$" || die "cannot write to $INSTALL_DIR"
chmod 0755 "$INSTALL_DIR/.achilles.new.$$"
mv -f "$INSTALL_DIR/.achilles.new.$$" "$INSTALL_DIR/achilles"

say "Installed: $INSTALL_DIR/achilles"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) say "note: $INSTALL_DIR is not on your PATH; add it, e.g.  export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac
say ""
say "Next steps:"
say "  achilles tools install   # download the pinned, checksum-verified scanners"
say "  achilles doctor          # confirm everything is in place"
say "  achilles .               # scan the current directory"
