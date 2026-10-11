#!/bin/sh
# Collect the license and notice files of everything linked into a Go binary.
#
#   scripts/collect-licenses.sh OUTDIR PACKAGE...
#   scripts/collect-licenses.sh --check DIR PACKAGE...
#
# Run it from inside a Go module. For each module that the named packages link
# (transitively, for the current GOOS/GOARCH), it copies the module's LICENSE,
# COPYING, NOTICE and PATENTS files to OUTDIR/<module path>@<version>/, and the Go
# standard library's own to OUTDIR/go/. MIT, BSD and Apache-2.0 all require that
# their text travels with a binary; this is how it gets into the release archives
# and the container image.
#
# --check regenerates into a temporary directory and fails if DIR differs, so CI
# catches a dependency bump that forgot to refresh the committed copy.
#
# A linked module with no license file is an error. Set ALLOW_MISSING=1 to record
# such modules in OUTDIR/MISSING.txt instead (used for third-party scanners built in
# the image, whose dependency trees we do not control).
set -eu

die() { printf 'collect-licenses: %s\n' "$*" >&2; exit 1; }

check=""
if [ "${1:-}" = "--check" ]; then
  check=1
  shift
fi
[ "$#" -ge 2 ] || die "usage: collect-licenses.sh [--check] DIR PACKAGE..."
dest="$1"
shift

if [ -n "$check" ]; then
  [ -d "$dest" ] || die "$dest does not exist; generate it first"
  out="$(mktemp -d)"
  trap 'rm -rf "$out"' EXIT
else
  out="$dest"
  rm -rf "$out"
  mkdir -p "$out"
fi

# copy_notices SRC DST: copy every license-like file at the top of SRC. Prints the
# number copied.
copy_notices() {
  n=0
  for f in "$1"/*; do
    [ -f "$f" ] || continue
    base="$(basename "$f")"
    case "$(printf '%s' "$base" | tr '[:lower:]' '[:upper:]')" in
      LICENSE*|LICENCE*|COPYING*|NOTICE*|PATENTS*|UNLICENSE*)
        mkdir -p "$2"
        cp "$f" "$2/$base"
        chmod 0644 "$2/$base"
        n=$((n + 1)) ;;
    esac
  done
  printf '%s' "$n"
}

mods="$(go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}}	{{.Version}}	{{.Dir}}{{end}}{{end}}' "$@" | sort -u)"

missing=""
tab="$(printf '\t')"
# The here-document keeps the loop in this shell, so `missing` survives it.
while IFS="$tab" read -r path version dir; do
  [ -n "$path" ] || continue
  [ -n "$dir" ] || die "module $path@$version is not downloaded (run: go mod download)"
  if [ "$(copy_notices "$dir" "$out/$path@$version")" = 0 ]; then
    missing="$missing$path@$version
"
  fi
done <<LIST
$mods
LIST

[ "$(copy_notices "$(go env GOROOT)" "$out/go")" != 0 ] || die "no LICENSE in GOROOT ($(go env GOROOT))"

if [ -n "$missing" ]; then
  if [ "${ALLOW_MISSING:-}" = 1 ]; then
    printf '%s' "$missing" > "$out/MISSING.txt"
  else
    die "no license file found for:
$missing"
  fi
fi

if [ -n "$check" ]; then
  diff -r "$dest" "$out" >&2 \
    || die "$dest is out of date; run: scripts/collect-licenses.sh $dest $*"
  echo "ok: $dest matches the linked modules"
fi
