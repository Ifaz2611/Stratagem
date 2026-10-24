#!/usr/bin/env bash
# Build the fuzzing harness against the pinned mxml.
#
# Produces two independent binaries:
#
#   build/asan/harness   AddressSanitizer + UndefinedBehaviorSanitizer.
#                        This is the one the agentic loop runs against.
#
#   build/cov/harness    gcov line-coverage instrumentation, no sanitizers.
#                        EVALUATION ONLY. Never executed inside the loop and
#                        never fed back into refinement. Used after the run to
#                        test whether the proxy signals actually tracked real
#                        coverage. See docs/design-decisions.md D3 and D7.
#
# Usage: ./harness/build.sh [asan|cov|all]     (default: all)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/third_party/mxml"
WHICH="${1:-all}"

if [ ! -f "$SRC/mxml.h" ]; then
  echo "[build] target missing; running fetch_target.sh" >&2
  "$ROOT/scripts/fetch_target.sh"
fi

# Why OPTIM and not CFLAGS: mxml's Makefile.in defines
#     CFLAGS  = @CFLAGS@ $(CPPFLAGS) $(OPTIM) $(WARNINGS)
#     LDFLAGS = @LDFLAGS@ $(OPTIM)
# so $(OPTIM) lands in both compile and link, and it comes AFTER @CFLAGS@.
# Passing our flags as CFLAGS would let OPTIM's default -Os silently override
# our -O1. Overriding OPTIM is the only handle that controls both stages.
#
# Flag notes:
#   -fno-sanitize-recover=all  UBSan otherwise prints "runtime error:" and
#                              CONTINUES, exiting 0. Without this the harness
#                              records "no crash" for every UB finding and the
#                              whole exercise silently reports nothing.
#   -fno-omit-frame-pointer    Crash signatures are hashed from sanitizer stack
#                              frames. Omitted frame pointers drop frames and
#                              would merge distinct bugs into one signature.
#   -O1                        Enough optimisation to be realistic, little
#                              enough that frames stay legible.
ASAN_OPTIM="-g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all"
COV_OPTIM="-g -O0 --coverage"

build_one() {
  local name="$1" optim="$2"
  local dir="$ROOT/build/$name"

  echo "[build] === $name ==="
  rm -rf "$dir"
  mkdir -p "$dir"
  cp -r "$SRC"/* "$dir"/

  ( cd "$dir"
    ./configure --disable-shared >/dev/null 2>&1
    make OPTIM="$optim" libmxml4.a >/dev/null 2>&1
    gcc $optim -I. -o harness "$ROOT/harness/harness.c" libmxml4.a
  )

  echo "[build] $dir/harness"
}

case "$WHICH" in
  asan) build_one asan "$ASAN_OPTIM" ;;
  cov)  build_one cov  "$COV_OPTIM"  ;;
  all)  build_one asan "$ASAN_OPTIM"; build_one cov "$COV_OPTIM" ;;
  *)    echo "usage: $0 [asan|cov|all]" >&2; exit 2 ;;
esac

# Prove the sanitizers are genuinely linked in, rather than assuming the flags
# took effect. A silently non-instrumented build is the failure mode that makes
# a fuzzer report "no bugs found" no matter what it generates.
if [ -x "$ROOT/build/asan/harness" ]; then
  n=$(nm "$ROOT/build/asan/harness" 2>/dev/null | grep -cE '__asan|__ubsan' || true)
  echo "[build] asan/ubsan symbols in harness: $n"
  [ "$n" -gt 0 ] || { echo "[build] FATAL: sanitizers not linked" >&2; exit 1; }
fi

echo "[build] done"
