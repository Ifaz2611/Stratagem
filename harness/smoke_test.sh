#!/usr/bin/env bash
# Regression check that the harness behaves correctly on a handful of valid and
# invalid sample inputs before anything is built on top of it.
#
# Written as assertions rather than a demo, so it can be re-run as a regression
# check. Every input in harness/samples/ has a declared expected exit code:
#
#   valid/*    -> 0  parsed cleanly
#   invalid/*  -> 1  rejected (a well-formed rejection, NOT a crash)
#   diag/*     -> 3  parsed, but the parser emitted a diagnostic
#
# The last of those is the important one. mxml can complain and still return a
# tree, so "the error callback fired" is not the same as "the input was
# rejected". If this case ever reports 1, the harness has regressed to
# classifying on diagnostics instead of on mxmlLoadString's return value, and
# the acceptance-rate signal the agentic loop steers by would be wrong.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/build/asan/harness"

export ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:symbolize=1:print_stacktrace=1"
export UBSAN_OPTIONS="halt_on_error=1:abort_on_error=1:print_stacktrace=1"

if [ ! -x "$BIN" ]; then
  echo "harness not built; run ./harness/build.sh" >&2
  exit 2
fi

pass=0; fail=0

check() {  # check <expected_rc> <file>
  local want="$1" f="$2" got out
  out="$(timeout 5 "$BIN" "$f" 2>/dev/null)"; got=$?
  local result; result="$(printf '%s' "$out" | grep '^RESULT' | cut -f2)"
  local ndiag; ndiag="$(printf '%s' "$out" | grep '^RESULT' | cut -f3)"
  if [ "$got" = "$want" ]; then
    printf '  ok    %-38s rc=%s %-8s diags=%s\n' "$(basename "$f")" "$got" "${result:-?}" "${ndiag:-0}"
    pass=$((pass+1))
  else
    printf '  FAIL  %-38s rc=%s (expected %s)\n' "$(basename "$f")" "$got" "$want"
    fail=$((fail+1))
  fi
}

echo "== valid: expect rc=0 (parsed, no diagnostics) =="
for f in "$ROOT"/harness/samples/valid/*.xml; do check 0 "$f"; done

echo "== invalid: expect rc=1 (well-formed rejection, not a crash) =="
for f in "$ROOT"/harness/samples/invalid/*.xml; do check 1 "$f"; done

echo "== diagnostics: expect rc=3 (parsed AND complained) =="
for f in "$ROOT"/harness/samples/diag/*.xml; do check 3 "$f"; done

echo "== harness error: expect rc=2 =="
timeout 5 "$BIN" /nonexistent/path.xml >/dev/null 2>&1
if [ $? = 2 ]; then echo "  ok    missing file                          rc=2"; pass=$((pass+1))
else echo "  FAIL  missing file"; fail=$((fail+1)); fi

echo "== stdin path: expect rc=0 =="
printf '<r/>' | timeout 5 "$BIN" >/dev/null 2>&1
if [ $? = 0 ]; then echo "  ok    stdin                                rc=0"; pass=$((pass+1))
else echo "  FAIL  stdin"; fail=$((fail+1)); fi

echo "== raw UTF-16 bytes: expect rc=1, never a crash =="
printf '\xff\xfe<\x00r\x00/\x00>\x00' | timeout 5 "$BIN" >/dev/null 2>&1
if [ $? = 1 ]; then echo "  ok    UTF-16LE BOM via stdin                rc=1"; pass=$((pass+1))
else echo "  FAIL  UTF-16LE BOM input"; fail=$((fail+1)); fi

# The single most important assertion here. Everything above proves the harness
# classifies non-crashing inputs correctly, but a build with the sanitizers
# silently absent would pass all of it and then report "no bugs found" forever.
#
# So: feed it a known real bug. Upstream issue #350 is a heap under-read in
# index_sort(), present in v4.0.4 and fixed only afterwards. The cause is
# unsigned arithmetic: templ/tempr are size_t, so when tempr reaches 0 the
# expression (tempr - 1) wraps to SIZE_MAX and the recursion indexes far out of
# bounds. Triggering it needs the first indexed node to sort strictly smallest,
# which is why <a><b/></a> crashes and <a><a/><a/></a> does not.
#
# Reached only via mxmlIndexNew, so the parse-only fuzzing runs never touch it.
# It exists purely as a positive control for crash detection and, later, for
# signature extraction and minimisation.
echo "== positive control: known bug (upstream #350) must be DETECTED =="
printf '<a><b/></a>' > /tmp/.pc_crash.xml
out="$(timeout 5 "$BIN" --index /tmp/.pc_crash.xml 2>&1 >/dev/null)"; rc=$?
if [ "$rc" -ge 128 ] && printf '%s' "$out" | grep -q 'AddressSanitizer: heap-buffer-overflow'; then
  echo "  ok    <a><b/></a> --index                  rc=$rc heap-buffer-overflow in index_sort"
  pass=$((pass+1))
else
  echo "  FAIL  positive control did not fire (rc=$rc)"
  echo "        sanitizers may not be linked; a fuzzer on this build would find nothing"
  fail=$((fail+1))
fi

echo "== negative control: same code path, must NOT crash =="
printf '<a><a/><a/></a>' > /tmp/.pc_ok.xml
timeout 5 "$BIN" --index /tmp/.pc_ok.xml >/dev/null 2>&1
if [ $? = 0 ]; then echo "  ok    <a><a/><a/></a> --index              rc=0"; pass=$((pass+1))
else echo "  FAIL  negative control crashed"; fail=$((fail+1)); fi
rm -f /tmp/.pc_crash.xml /tmp/.pc_ok.xml

echo
echo "passed=$pass failed=$fail"
[ "$fail" = 0 ]
