#!/usr/bin/env bash
# Build and enter the reproducible Stratagem container.
#
# Usage:
#   ./run.sh build            # build the image (harness + replay/api capable)
#   ./run.sh build --with-cli # also install the Claude Code CLI (subscription mode)
#   ./run.sh shell            # interactive shell in the container
#   ./run.sh <cmd...>         # run one command in the container
set -euo pipefail

IMAGE="${IMAGE:-stratagem:latest}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Flags that make sanitizers behave the same inside the container as outside.
#
#   seccomp=unconfined : AddressSanitizer maps a large fixed "shadow memory"
#     region at startup and calls personality() to reduce address-space
#     randomisation. Docker's default seccomp profile blocks that call, and
#     ASan then dies with "Shadow memory range interleaves with an existing
#     memory mapping" before main() ever runs.
#
#   cap-add SYS_PTRACE : lets the sanitizer's symbolizer read the process it
#     is reporting on, so crash reports carry function names instead of bare
#     hex addresses. Our crash signatures are built from function names, so
#     without this every crash would look identical.
#
#   ulimit stack=8388608 : pin the stack to the usual Linux 8 MiB. tomlc99
#     recurses without any depth limit, so "how deep can nesting go before it
#     crashes" is a direct function of stack size. Leaving it to the host's
#     default would make stack-overflow reproducers machine-dependent.
DOCKER_RUN_FLAGS=(
  --rm
  --security-opt seccomp=unconfined
  --cap-add SYS_PTRACE
  --ulimit stack=8388608:8388608
  -v "$ROOT/runs:/app/runs"
)

# Secrets come from .env, never from the image and never from the command line
# (a key on the command line lands in shell history and in `docker inspect`).
# Absent .env, replay mode still works, which is the point of the default.
#
# .env is NOT handed to --env-file directly. Docker's parser is stricter than a
# shell's: it does not strip surrounding quotes and does not understand an
# `export ` prefix, so OPENAI_API_KEY="sk-x" would arrive inside the container
# with the quote characters still attached and fail authentication in a way
# that looks like a bad key. Normalise into a private temp file instead.
ENV_FLAGS=()
CLEAN_ENV=""
if [ -f "$ROOT/.env" ]; then
  CLEAN_ENV="$(mktemp)"; chmod 600 "$CLEAN_ENV"
  trap 'rm -f "$CLEAN_ENV"' EXIT
  sed -e 's/[[:space:]]*#.*$//' -e 's/^[[:space:]]*export[[:space:]]\+//' \
      -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$ROOT/.env" \
    | grep -E '^[A-Za-z_][A-Za-z0-9_]*=' \
    | sed -E 's/^([A-Za-z_][A-Za-z0-9_]*)=["'"'"']?(.*[^"'"'"'])?["'"'"']?$/\1=\2/' \
    > "$CLEAN_ENV"
  ENV_FLAGS+=(--env-file "$CLEAN_ENV")
fi

cmd="${1:-shell}"; shift || true

case "$cmd" in
  build)
    build_args=()
    if [ "${1:-}" = "--with-cli" ]; then
      build_args+=(--build-arg WITH_CLAUDE_CLI=1)
      echo "[run.sh] building WITH Claude Code CLI (subscription mode)"
    else
      echo "[run.sh] building without Claude Code CLI (replay/openai backends)"
    fi
    docker build "${build_args[@]}" -t "$IMAGE" "$ROOT"
    ;;

  shell)
    docker run -it "${DOCKER_RUN_FLAGS[@]}" "${ENV_FLAGS[@]}" "$IMAGE" bash
    ;;

  *)
    docker run "${DOCKER_RUN_FLAGS[@]}" "${ENV_FLAGS[@]}" "$IMAGE" "$cmd" "$@"
    ;;
esac
