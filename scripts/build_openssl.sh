#!/bin/sh
# build_openssl.sh — reproducible minimal OpenSSL libcrypto for Secraxis's
# AES-256-GCM-SIV backend (SEIS-AEAD-2, the default profile).
#
# Linux/macOS/BSD: the system OpenSSL >= 3.2 usually suffices — you likely do
# NOT need this script; just point -DSECRAXIS_OPENSSL_ROOT at /usr (or brew).
# This script exists mainly for Windows/MinGW, where OpenSSL's Configure needs
# an MSYS-flavored Perl.
#
# Usage:
#   sh scripts/build_openssl.sh [work_dir]
# Prereqs on Windows: an MSYS2 bash with `perl` and `make` (build-time only;
# never linked). Set SECRAXIS_MSYS2_BASH to its bash.exe, or the script probes
# D:\OTHER_ENV\msys64. On Unix, a native perl+make is used directly.
set -eu

OPENSSL_VERSION=3.5.1
OPENSSL_SHA256=529043b15cffa5f36077a4d0af83f3de399807181d607441d734196d889b641f
WORK="${1:-$(pwd)/buildtools}"
TARBALL="$WORK/openssl-$OPENSSL_VERSION.tar.gz"
PREFIX="$WORK/openssl-install"

CONFIG_ARGS="no-shared no-tests no-apps no-docs no-deprecated no-legacy \
no-engine no-module no-autoload-config --prefix=$PREFIX --libdir=lib"

mkdir -p "$WORK"
if [ ! -f "$TARBALL" ]; then
  curl -sSL -o "$TARBALL" \
    "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz"
fi
ACTUAL=$(sha256sum "$TARBALL" | cut -d' ' -f1)
if [ "$ACTUAL" != "$OPENSSL_SHA256" ]; then
  echo "FATAL: openssl tarball hash mismatch" >&2
  echo "  expected: $OPENSSL_SHA256" >&2
  echo "  actual:   $ACTUAL" >&2
  exit 1
fi

cd "$WORK"
[ -d "openssl-$OPENSSL_VERSION" ] || tar xzf "$TARBALL"
SRC="$WORK/openssl-$OPENSSL_VERSION"

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*|Windows_NT)
    MB="${SECRAXIS_MSYS2_BASH:-/d/OTHER_ENV/msys64/usr/bin/bash.exe}"
    if [ ! -x "$MB" ]; then
      echo "FATAL: MSYS2 bash not found at $MB." >&2
      echo "Install MSYS2 (pacman -S perl make) and set SECRAXIS_MSYS2_BASH." >&2
      exit 1
    fi
    GCC_BIN="$(dirname "$(command -v gcc)")"
    "$MB" -lc "export PATH=\"$GCC_BIN:\$PATH\"; cd '$SRC' && perl Configure mingw64 $CONFIG_ARGS && make -j\$(nproc) build_libs && make install_dev"
    ;;
  *)
    ( cd "$SRC" && ./Configure $CONFIG_ARGS && make -j"$(nproc)" build_libs && make install_dev )
    ;;
esac

test -f "$PREFIX/lib/libcrypto.a" || { echo "FATAL: libcrypto.a not built" >&2; exit 1; }
echo ""
echo "OpenSSL libcrypto ready."
echo "Configure Secraxis with:"
echo "  -DSECRAXIS_OPENSSL_ROOT=$PREFIX"
