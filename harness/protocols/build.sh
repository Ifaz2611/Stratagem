#!/usr/bin/env bash
# Build protocol harnesses (HTTP, DNS, SMTP) with AddressSanitizer and UndefinedBehaviorSanitizer.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ASAN_FLAGS="-g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all"
OUT_DIR="$ROOT/build/protocols"

mkdir -p "$OUT_DIR"

echo "[build] Compiling HTTP harness..."
gcc $ASAN_FLAGS -o "$OUT_DIR/http_harness" "$ROOT/harness/protocols/http_harness.c" || true

echo "[build] Compiling DNS harness..."
gcc $ASAN_FLAGS -o "$OUT_DIR/dns_harness" "$ROOT/harness/protocols/dns_harness.c" || true

echo "[build] Compiling SMTP harness..."
gcc $ASAN_FLAGS -o "$OUT_DIR/smtp_harness" "$ROOT/harness/protocols/smtp_harness.c" || true

echo "[build] Done"
