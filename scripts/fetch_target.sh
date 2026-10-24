#!/usr/bin/env bash
# Fetch the target library at the exact pinned commit.
#
# Building against a pinned commit, not upstream HEAD, is what makes the target
# reproducible. This script makes the pin machine-checkable: it clones, checks
# out the SHA, and then re-reads it back out of git to prove we got what we
# asked for.
# If upstream ever force-pushes or the SHA is mistyped, this fails loudly here
# instead of silently fuzzing the wrong code.
set -euo pipefail

REPO_URL="https://github.com/michaelrsweet/mxml"
PINNED_TAG="v4.0.4"
PINNED_SHA="0d5afc4278d7a336d554602b951c2979c3f8f296"

# Why this pin: v4.0.4 (2025-01-19) is the latest stable release. The only
# change to the parser (mxml-file.c) between this tag and upstream main as of
# 2026-03-21 is a copyright year and a moved #include -- zero functional
# difference. So any parser bug found here is also present in current main.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/third_party/mxml"

if [ -d "$DEST/.git" ]; then
  actual="$(git -C "$DEST" rev-parse HEAD)"
  if [ "$actual" = "$PINNED_SHA" ]; then
    echo "[fetch_target] already at pinned commit $PINNED_SHA"
    exit 0
  fi
  echo "[fetch_target] wrong commit ($actual), re-fetching" >&2
  rm -rf "$DEST"
fi

mkdir -p "$(dirname "$DEST")"
echo "[fetch_target] cloning $REPO_URL"
git clone --quiet "$REPO_URL" "$DEST"
git -C "$DEST" checkout --quiet "$PINNED_SHA"

actual="$(git -C "$DEST" rev-parse HEAD)"
if [ "$actual" != "$PINNED_SHA" ]; then
  echo "[fetch_target] FATAL: expected $PINNED_SHA, got $actual" >&2
  exit 1
fi

echo "[fetch_target] OK  mxml $PINNED_TAG @ $PINNED_SHA"
echo "[fetch_target] $(git -C "$DEST" log -1 --format='%cs  %s')"
