#!/usr/bin/env bash
# Fetch the ANTLR XML grammar from antlr/grammars-v4 at a pinned commit.
#
# The grammar's provenance matters: which grammar was used, where it came from,
# and what was adapted. Pinning the grammars-v4 commit makes the source half
# precise: grammars-v4 is a living repo, and an unpinned fetch would leave the
# report describing a grammar that no longer matches the file on disk.
#
# Fetched by raw URL at the pinned SHA rather than by git clone: grammars-v4
# carries enough history that a clone takes minutes for two small files. The
# raw URL is SHA-addressed, so it is exactly as reproducible, and the checksums
# below make that machine-checked rather than assumed.
set -euo pipefail

PINNED_SHA="e756f2a2ee5565a9300666f100ba6acd874664f7"   # 2026-07-20
BASE="https://raw.githubusercontent.com/antlr/grammars-v4/${PINNED_SHA}/xml"

# sha256 of each file as served at the pinned commit, verified after download.
declare -A EXPECTED=(
  [XMLLexer]="2d14f11025d66bec1d881caa5a3b15fde81bd35846c05c306694f742897b8762"
  [XMLParser]="3ad2a88464138a73e821b47bfd6236f456e090e8961b5a91014b4cf31410b5f7"
)

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/grammar"

check_one() {  # $1 = basename; echoes nothing, returns non-zero on mismatch
  [ -f "$DEST/$1.g4" ] || return 1
  [ "$(sha256sum "$DEST/$1.g4" | cut -d' ' -f1)" = "${EXPECTED[$1]}" ]
}

# Verify what is already on disk rather than trusting its presence. A locally
# modified grammar would otherwise silently become the thing we fuzz against
# while the report still claims the pinned upstream version.
if [ "${1:-}" != "--force" ]; then
  if check_one XMLLexer && check_one XMLParser; then
    echo "[fetch_grammar] grammar present and checksums match"
    exit 0
  elif [ -f "$DEST/XMLLexer.g4" ] || [ -f "$DEST/XMLParser.g4" ]; then
    echo "[fetch_grammar] local grammar missing or modified, refetching" >&2
  fi
fi

mkdir -p "$DEST"
for f in XMLLexer XMLParser; do
  echo "[fetch_grammar] fetching $f.g4"
  curl -sSfL -o "$DEST/$f.g4" "$BASE/$f.g4"
  got="$(sha256sum "$DEST/$f.g4" | cut -d' ' -f1)"
  if [ "$got" != "${EXPECTED[$f]}" ]; then
    echo "[fetch_grammar] FATAL: $f.g4 checksum mismatch" >&2
    echo "  expected ${EXPECTED[$f]}" >&2
    echo "  got      $got" >&2
    exit 1
  fi
done

cat > "$DEST/SOURCE.txt" <<EOF
Source:        https://github.com/antlr/grammars-v4
Path:          xml/XMLLexer.g4, xml/XMLParser.g4
Pinned commit: $PINNED_SHA  (2026-07-20)
Fetched via:   $BASE
Fetched by:    scripts/fetch_grammar.sh

sha256:
  XMLLexer.g4   $(sha256sum "$DEST/XMLLexer.g4"  | cut -d' ' -f1)
  XMLParser.g4  $(sha256sum "$DEST/XMLParser.g4" | cut -d' ' -f1)
EOF

echo "[fetch_grammar] OK  XMLLexer.g4 + XMLParser.g4 @ $PINNED_SHA"
cat "$DEST/SOURCE.txt"
