#!/bin/sh
# QuantmLayer installer.
#
#   curl -fsSL https://raw.githubusercontent.com/quantmlayer/quantmlayer/main/scripts/install.sh | sh
#
# Downloads the static `ql` binary (x86_64 or aarch64, auto-detected) from the
# Release, verifies its SHA-256, installs it to /usr/local/bin, and — on a
# hardened kernel — installs the AppArmor profile that lets `ql` use
# unprivileged user namespaces. Static musl binary: no runtime dependencies.
#
# Environment overrides:
#   QL_VERSION   pin a release tag (default: latest)   e.g. QL_VERSION=v0.1.0
#   QL_PREFIX    install prefix (default: /usr/local)  -> $QL_PREFIX/bin/ql
#   QL_NO_APPARMOR=1  skip the AppArmor step
#
# The script is POSIX sh, fails closed (`set -eu`), and never pipes untrusted
# content into a shell.

set -eu

REPO="quantmlayer/quantmlayer"
PREFIX="${QL_PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"
RAW="https://raw.githubusercontent.com/$REPO"

say()  { printf 'ql-install: %s\n' "$*"; }
die()  { printf 'ql-install: error: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# --- preflight ---------------------------------------------------------------
# Map the host arch to the release asset triple. The release ships a native
# static binary per arch (see .github/workflows/musl-static.yml).
arch="$(uname -m)"
case "$arch" in
  x86_64)           ASSET="ql-x86_64-unknown-linux-musl";  ELF_GREP='x86-64' ;;
  aarch64|arm64)    ASSET="ql-aarch64-unknown-linux-musl"; ELF_GREP='aarch64|ARM aarch64' ;;
  *) die "no prebuilt binary for arch '$arch' (have: x86_64, aarch64). Build from source: https://github.com/$REPO" ;;
esac

os="$(uname -s)"
[ "$os" = "Linux" ] || die "QuantmLayer enforces via the Linux kernel; detected '$os'."

if have curl; then DL="curl -fsSL -o"; DLO="curl -fsSL"; else
  have wget || die "need curl or wget to download."
  DL="wget -qO"; DLO="wget -qO-"
fi

# sudo only if we can't write the target dirs ourselves.
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if have sudo; then SUDO="sudo"; else
    die "not root and sudo not found; re-run as root or install sudo."
  fi
fi

# --- resolve the version -----------------------------------------------------
if [ -n "${QL_VERSION:-}" ]; then
  TAG="$QL_VERSION"
else
  # Ask the GitHub API for the latest release tag. No jq dependency: parse the
  # tag_name field with sed. Fail loudly if there is no published release yet.
  say "resolving latest release..."
  TAG="$($DLO "https://api.github.com/repos/$REPO/releases/latest" \
         | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
         | head -n1)"
  [ -n "$TAG" ] || die "no published release found. Pin one with QL_VERSION=vX.Y.Z, or build from source."
fi
say "installing $TAG"

BASE="https://github.com/$REPO/releases/download/$TAG"

# --- download + verify -------------------------------------------------------
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

say "downloading $ASSET..."
$DL "$TMP/ql" "$BASE/$ASSET" || die "download failed: $BASE/$ASSET"

# Verify the SHA-256 if the checksum asset is present and a checker exists.
if $DL "$TMP/ql.sha256" "$BASE/$ASSET.sha256" 2>/dev/null; then
  want="$(cut -d' ' -f1 "$TMP/ql.sha256")"
  if have sha256sum; then got="$(sha256sum "$TMP/ql" | cut -d' ' -f1)"
  elif have shasum;   then got="$(shasum -a 256 "$TMP/ql" | cut -d' ' -f1)"
  else got=""; say "warning: no sha256 tool; skipping checksum verification."; fi
  if [ -n "$got" ]; then
    [ "$got" = "$want" ] || die "checksum mismatch (expected $want, got $got). Aborting."
    say "checksum verified."
  fi
else
  say "warning: no published checksum for this asset; skipping verification."
fi

# Sanity: it should be a static ELF of the detected arch.
if have file; then
  file "$TMP/ql" | grep -Eq "$ELF_GREP" || die "downloaded file is not a $arch binary."
fi

# --- install the binary ------------------------------------------------------
say "installing to $BINDIR/ql (may prompt for sudo)..."
$SUDO install -d "$BINDIR"
$SUDO install -m755 "$TMP/ql" "$BINDIR/ql"
say "installed $BINDIR/ql"

# --- AppArmor (hardened kernels) ---------------------------------------------
# On Ubuntu 24.04 (or 22.04 HWE 6.8+), an unconfined binary may create a user
# namespace but is denied capabilities inside it, which breaks the mount wall.
# The profile grants `ql` (at this exact path) userns rights. Skip cleanly when
# AppArmor isn't in use or the user opted out.
if [ "${QL_NO_APPARMOR:-}" = "1" ]; then
  say "skipping AppArmor (QL_NO_APPARMOR=1)."
elif [ "$BINDIR" != "/usr/local/bin" ]; then
  # The shipped profile attaches to /usr/local/bin/ql specifically. A custom
  # prefix needs a hand-edited profile; don't silently install a mismatched one.
  say "note: custom prefix ($BINDIR) — AppArmor profile targets /usr/local/bin/ql."
  say "      if 'ql run' mounts fail on a hardened kernel, adjust packaging/apparmor/usr.local.bin.ql."
elif have apparmor_parser && [ -d /sys/kernel/security/apparmor ]; then
  say "hardened kernel detected; installing AppArmor profile..."
  $DL "$TMP/ql.apparmor" "$RAW/$TAG/packaging/apparmor/usr.local.bin.ql" \
    || die "could not fetch the AppArmor profile for $TAG."
  $SUDO install -d /etc/apparmor.d
  $SUDO install -m644 "$TMP/ql.apparmor" /etc/apparmor.d/usr.local.bin.ql
  $SUDO apparmor_parser -r /etc/apparmor.d/usr.local.bin.ql
  say "AppArmor profile loaded; rootless 'ql run' should work on this host."
else
  say "no AppArmor on this host; nothing to load (fine on non-hardened kernels)."
fi

# --- done --------------------------------------------------------------------
say "done. Verifying:"
if "$BINDIR/ql" --version >/dev/null 2>&1; then
  "$BINDIR/ql" --version 2>/dev/null || true
else
  say "installed, but '$BINDIR/ql --version' did not run — is $BINDIR on your PATH?"
fi
cat <<EOF

Next:
  ql doctor                 # check what this host can enforce
  ql agent claude -- claude # contain a coding agent (see: ql agent list)

Docs: https://github.com/$REPO
EOF
