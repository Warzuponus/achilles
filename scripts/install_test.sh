#!/bin/sh
# Tests scripts/install.sh against a fake release served from a local directory
# (ACHILLES_DOWNLOAD_BASE=file://...), with a stand-in `cosign` whose verdict the
# test controls. No network, no real release, nothing installed outside a temp dir.
#
#   sh scripts/install_test.sh
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail=0
ok()   { printf 'ok    %s\n' "$1"; }
bad()  { printf 'FAIL  %s\n' "$1"; fail=1; }

if command -v sha256sum >/dev/null 2>&1; then
  sha() { sha256sum "$1" | awk '{print $1}'; }
else
  sha() { shasum -a 256 "$1" | awk '{print $1}'; }
fi

# --- a fake release: one archive holding an `achilles` file, and its checksums ---
rel="$work/release"
mkdir -p "$rel" "$work/payload"
printf '#!/bin/sh\necho fake achilles\n' > "$work/payload/achilles"
for arch in amd64 arm64; do
  for os in linux darwin; do
    tar -czf "$rel/achilles_9.9.9_${os}_${arch}.tar.gz" -C "$work/payload" achilles
    printf '%s  %s\n' "$(sha "$rel/achilles_9.9.9_${os}_${arch}.tar.gz")" "achilles_9.9.9_${os}_${arch}.tar.gz" >> "$rel/checksums.txt"
  done
done

# --- stand-ins on PATH ---------------------------------------------------------
# uname: the installer refuses Windows shells, where this test also has to run.
tools="$work/tools"
mkdir -p "$tools"
cat > "$tools/uname" <<'EOF'
#!/bin/sh
case "${1:-}" in -m) echo x86_64 ;; *) echo Linux ;; esac
EOF
chmod +x "$tools/uname"

# cosign: exits with $FAKE_COSIGN_EXIT, and records that it was asked to verify.
cosign_dir="$work/cosign"
mkdir -p "$cosign_dir"
cat > "$cosign_dir/cosign" <<'EOF'
#!/bin/sh
echo "$*" >> "$FAKE_COSIGN_LOG"
exit "${FAKE_COSIGN_EXIT:-0}"
EOF
chmod +x "$cosign_dir/cosign"

real_cosign=""
if command -v cosign >/dev/null 2>&1; then real_cosign=1; fi

# run NAME WANT(pass|fail) COSIGN(with|without) [ENV=VALUE...]
run() {
  name="$1"; want="$2"; cosign="$3"; shift 3
  dest="$work/dest-$$-$(echo "$name" | tr -c 'A-Za-z0-9' '_')"
  rm -rf "$dest"; : > "$work/cosign.log"
  path="$tools:$PATH"
  if [ "$cosign" = with ]; then
    path="$cosign_dir:$path"
  elif [ -n "$real_cosign" ]; then
    printf 'skip  %s (a real cosign is on PATH)\n' "$name"; return
  fi
  if env "$@" PATH="$path" FAKE_COSIGN_LOG="$work/cosign.log" \
       VERSION=v9.9.9 INSTALL_DIR="$dest" ACHILLES_DOWNLOAD_BASE="$relurl" \
       sh "$here/install.sh" > "$work/out.txt" 2>&1; then got=pass; else got=fail; fi
  if [ "$got" = pass ] && [ ! -x "$dest/achilles" ]; then got="pass-but-nothing-installed"; fi
  if [ "$got" = fail ] && [ -e "$dest/achilles" ]; then got="fail-but-installed"; fi
  if [ "$got" = "$want" ]; then ok "$name"; else bad "$name: want $want, got $got"; sed 's/^/        /' "$work/out.txt"; fi
}

bundle="$rel/checksums.txt.sigstore.json"

# curl on Windows (Git Bash) wants a drive-letter path in a file:// URL.
relurl="file://$rel"
if command -v cygpath >/dev/null 2>&1; then relurl="file:///$(cygpath -m "$rel")"; fi

# No cosign: installs on the checksum alone and says the signature was not checked;
# with ACHILLES_REQUIRE_SIGNATURE=1 that is refused.
run "no cosign: installs, with a note"                    pass without
if [ -z "$real_cosign" ]; then
  grep -q "NOT checked" "$work/out.txt" && ok "no cosign: says the signature was not checked" || bad "no cosign: no warning printed"
fi
run "no cosign, signature required: refused"              fail without ACHILLES_REQUIRE_SIGNATURE=1

# cosign present and the bundle published.
echo '{}' > "$bundle"
run "signature verifies: installs"                        pass with FAKE_COSIGN_EXIT=0
grep -q "verify-blob" "$work/cosign.log" && ok "cosign was asked to verify" || bad "cosign was never run"
grep -q "refs/tags/v9.9.9" "$work/cosign.log" && ok "the identity is pinned to the release workflow at this tag" || bad "identity not pinned to the tag"
run "signature does not verify: refused"                  fail with FAKE_COSIGN_EXIT=1
run "signature does not verify, required: refused"        fail with FAKE_COSIGN_EXIT=1 ACHILLES_REQUIRE_SIGNATURE=1

# cosign present but no bundle: this used to install with a note. Leaving the
# bundle out is exactly what a tampered mirror would do.
rm -f "$bundle"
run "cosign present, no bundle: refused"                  fail with FAKE_COSIGN_EXIT=0
run "cosign present, no bundle, required: refused"        fail with FAKE_COSIGN_EXIT=0 ACHILLES_REQUIRE_SIGNATURE=1
run "explicit opt-out: installs without the signature"    pass with FAKE_COSIGN_EXIT=1 ACHILLES_REQUIRE_SIGNATURE=0
run "a value other than 0 or 1 is an error"               fail with ACHILLES_REQUIRE_SIGNATURE=yes

# The checksum is still checked in every mode.
echo '{}' > "$bundle"
printf 'tampered' >> "$rel/achilles_9.9.9_linux_amd64.tar.gz"
run "archive does not match checksums.txt: refused"       fail with FAKE_COSIGN_EXIT=0
run "...even with the signature check off"                fail with ACHILLES_REQUIRE_SIGNATURE=0

if [ "$fail" != 0 ]; then echo "install_test: FAILED"; exit 1; fi
echo "install_test: ok"
