#!/bin/sh
# build_awslc.sh — reproducible AWS-LC libcrypto build for Secraxis.
# Usage: sh scripts/build_awslc.sh [work_dir]
# Verifies the pinned hash, builds ONLY libcrypto (no ssl/tool/tests), and
# prints the -DSECRAXIS_AWSLC_ROOT value to pass to the Secraxis configure.
set -eu

AWSLC_VERSION=5.1.0
AWSLC_SHA256=a6bf6adfc5f9bba559d28554b7d3581b15f2813f03bc9f2ae19f0d915e97dadf
WORK="${1:-$(pwd)/buildtools}"
TARBALL="$WORK/aws-lc-$AWSLC_VERSION.tar.gz"

mkdir -p "$WORK"
if [ ! -f "$TARBALL" ]; then
  curl -sSL -o "$TARBALL" \
    "https://github.com/aws/aws-lc/archive/refs/tags/v$AWSLC_VERSION.tar.gz"
fi

ACTUAL=$(sha256sum "$TARBALL" | cut -d' ' -f1)
if [ "$ACTUAL" != "$AWSLC_SHA256" ]; then
  echo "FATAL: aws-lc tarball hash mismatch" >&2
  echo "  expected: $AWSLC_SHA256" >&2
  echo "  actual:   $ACTUAL" >&2
  exit 1
fi

cd "$WORK"
[ -d "aws-lc-$AWSLC_VERSION" ] || tar xzf "$TARBALL"
cd "aws-lc-$AWSLC_VERSION"

cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DDISABLE_GO=ON -DDISABLE_PERL=ON -DBUILD_TESTING=OFF -DBUILD_TOOL=OFF \
  -DBUILD_SHARED_LIBS=OFF
ninja -C build crypto

echo ""
echo "AWS-LC libcrypto ready."
echo "Configure Secraxis with:"
echo "  -DSECRAXIS_AWSLC_ROOT=$WORK/aws-lc-$AWSLC_VERSION"
