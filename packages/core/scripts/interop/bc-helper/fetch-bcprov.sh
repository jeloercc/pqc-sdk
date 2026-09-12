#!/usr/bin/env bash
# Downloads the pinned BouncyCastle provider jar and verifies its checksum —
# the equivalent of circl-helper/go.sum's cryptographic pinning, for a single
# jar dependency with no package manager in the loop. The jar itself is
# gitignored (never committed, same as circl-helper's compiled binary); this
# script is the reproducible way to get it back.
set -euo pipefail

VERSION="1.86"
JAR="bcprov-jdk18on-${VERSION}.jar"
URL="https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/${VERSION}/${JAR}"
EXPECTED_SHA256="2af190b300cbb0b35e248ccf5f4a06b6072030aeb3da7a98ec73abe5b4cb371f"

cd "$(dirname "$0")"

if [ ! -f "$JAR" ]; then
  echo "fetch-bcprov: downloading ${JAR}..."
  curl -sL -o "$JAR" "$URL"
fi

ACTUAL_SHA256="$(shasum -a 256 "$JAR" | cut -d' ' -f1)"
if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
  echo "fetch-bcprov: checksum mismatch for ${JAR}" >&2
  echo "  expected: ${EXPECTED_SHA256}" >&2
  echo "  actual:   ${ACTUAL_SHA256}" >&2
  rm -f "$JAR"
  exit 1
fi

echo "fetch-bcprov: ${JAR} present and verified (sha256 ${EXPECTED_SHA256})."
