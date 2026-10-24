#!/usr/bin/env bash
# Verify a recorded run reproduces, in two independent senses.
#
#   1. INPUTS. Each iteration ships corpus.jsonl.gz: the exact bytes fed to the
#      harness, base64-encoded. Replay feeds those bytes back and compares every
#      classification against the recorded results.jsonl, plus a digest over the
#      whole ordered corpus. Nothing is regenerated, so this is insensitive to
#      changes in the generator, in Hypothesis, or in the measurement code.
#
#   2. GENERATORS. Replaying the recorded LLM transcript must produce
#      byte-identical strategy.py for every iteration, which is what shows the
#      transcript is a faithful record of the loop's output.
#
# Usage: ./scripts/verify_replay.sh <run-id>
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN="${1:-loop}"
SRC="$ROOT/runs/$RUN"
# A local venv is convenient outside the container; inside it the interpreter
# is on PATH. Falling back keeps the documented quick-start command working in
# both places.
if [ -x "$ROOT/.venv/bin/python" ]; then
  PY="$ROOT/.venv/bin/python"
else
  PY="${PYTHON:-$(command -v python3 || command -v python)}"
fi
# The heredoc and `-m agent.loop` both need the repo root on the import path,
# and the caller may invoke this from anywhere.
cd "$ROOT"
fail=0

[ -d "$SRC/iterations" ] || { echo "no run at $SRC" >&2; exit 2; }

echo "[replay] === 1/2  inputs: replaying each recorded corpus through the harness ==="
"$PY" - "$SRC" "$ROOT" <<'PYEOF'
import sys
from pathlib import Path
# The heredoc is run as `python -`, so __file__ is unavailable and the current
# directory is wherever the caller happened to be. Import from the repo root
# explicitly, otherwise `from fuzzer import corpus` only works when the script
# is invoked from there.
sys.path.insert(0, sys.argv[2])
from fuzzer import corpus

src = Path(sys.argv[1])
bad = 0
for d in sorted(src.glob("iterations/iter-*")):
    cf = d / corpus.CORPUS_NAME
    if not cf.exists():
        print(f"  skip     {d.name}: no corpus recorded"); continue
    r = corpus.replay_and_verify(d)
    tag = "ok      " if r.ok else "MISMATCH"
    print(f"  {tag} {d.name}: {r.outcome_matches}/{r.inputs} classifications match, "
          f"digest {r.replayed_digest}"
          + ("" if r.recorded_digest == r.replayed_digest else
             f" != recorded {r.recorded_digest}"))
    if not r.ok:
        bad += 1
        for m in (r.outcome_mismatches or [])[:3]:
            print(f"           input {m['i']} recorded={m['recorded']} replayed={m['replayed']}")
sys.exit(1 if bad else 0)
PYEOF
[ $? -ne 0 ] && fail=1

echo
echo "[replay] === 2/2  generators: replaying the transcript ==="
if [ ! -d "$SRC/transcript" ]; then
  echo "  skip: no transcript"
else
  n_iters=$(find "$SRC/iterations" -mindepth 1 -maxdepth 1 -type d -name 'iter-*' | wc -l)
  REPLAY_ID="${RUN}-replay"
  rm -rf "$ROOT/runs/$REPLAY_ID"; mkdir -p "$ROOT/runs/$REPLAY_ID"
  cp -r "$SRC/transcript" "$ROOT/runs/$REPLAY_ID/transcript"
  LLM_BACKEND=replay "$PY" -m agent.loop --backend replay --run-id "$REPLAY_ID" \
      -n 1 -i "$n_iters" >/dev/null 2>&1
  for d in "$SRC"/iterations/iter-*; do
    it="$(basename "$d")"
    b="$ROOT/runs/$REPLAY_ID/iterations/$it/strategy.py"
    if [ -f "$b" ] && cmp -s "$d/strategy.py" "$b"; then
      echo "  ok       $it strategy.py byte-identical"
    else
      echo "  FAIL     $it strategy.py differs or missing"; fail=1
    fi
  done
fi

echo
if [ "$fail" = 0 ]; then
  echo "[replay] PASS: recorded inputs reproduce their classifications, and the"
  echo "               transcript reproduces every generator byte-for-byte."
else
  echo "[replay] FAIL"
fi
exit "$fail"
