#!/usr/bin/env bash
# Build XML harnesses (mxml, libxml2, expat, tinyxml2) with AddressSanitizer, ThreadSanitizer, or MemorySanitizer.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SANITIZER="${1:-asan}"

case "$SANITIZER" in
  asan) SAN_FLAGS="-g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all" ;;
  tsan) SAN_FLAGS="-g -O1 -fno-omit-frame-pointer -fsanitize=thread" ;;
  msan) SAN_FLAGS="-g -O1 -fno-omit-frame-pointer -fsanitize=memory" ;;
  *) echo "Unknown sanitizer: $SANITIZER (supported: asan, tsan, msan)" >&2; exit 1 ;;
esac

# 1. mxml
if [ -d "$ROOT/third_party/mxml" ]; then
  echo "[build] Building mxml harness ($SANITIZER)..."
  "$ROOT/harness/build.sh" "$SANITIZER" || true
fi

# 2. expat
if pkg-config --exists expat 2>/dev/null || [ -f /usr/include/expat.h ]; then
  echo "[build] Building expat harness ($SANITIZER)..."
  mkdir -p "$ROOT/build/expat"
  gcc $SAN_FLAGS -I/usr/include -o "$ROOT/build/expat/harness" "$ROOT/harness/expat/harness.c" -lexpat || true
fi

# 3. libxml2
if pkg-config --exists libxml-2.0 2>/dev/null || [ -f /usr/include/libxml2/libxml/parser.h ]; then
  echo "[build] Building libxml2 harness ($SANITIZER)..."
  mkdir -p "$ROOT/build/libxml2"
  XML2_CFLAGS="$(pkg-config --cflags libxml-2.0 2>/dev/null || echo '-I/usr/include/libxml2')"
  XML2_LIBS="$(pkg-config --libs libxml-2.0 2>/dev/null || echo '-lxml2')"
  gcc $SAN_FLAGS $XML2_CFLAGS -o "$ROOT/build/libxml2/harness" "$ROOT/harness/libxml2/harness.c" $XML2_LIBS || true
fi

# 4. tinyxml2
if [ -f "$ROOT/third_party/tinyxml2/tinyxml2.cpp" ] || pkg-config --exists tinyxml2 2>/dev/null; then
  echo "[build] Building tinyxml2 harness ($SANITIZER)..."
  mkdir -p "$ROOT/build/tinyxml2"
  g++ $SAN_FLAGS -o "$ROOT/build/tinyxml2/harness" "$ROOT/harness/tinyxml2/harness.cpp" -ltinyxml2 || true
fi

echo "[build] Done ($SANITIZER)"
