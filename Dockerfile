# Reproducible environment for Stratagem, an agentic grammar fuzzer.
#
# ubuntu:24.04 ships gcc 13.3, which is what this was developed against.
# The compiler version matters more than usual here: sanitizer behaviour and
# the exact stack frames in a crash report both depend on it, and crash
# deduplication keys off those frames.
FROM ubuntu:24.04

# Set to 1 to also install Node + the Claude Code CLI, needed only for
# LLM_BACKEND=cli (driving the loop from a Claude subscription).
# The default 0 keeps the image small: replay needs no LLM at all, and the
# openai backend needs only the `openai` Python package, already installed.
ARG WITH_CLAUDE_CLI=0

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
      git \
      ca-certificates \
      curl \
      python3 \
      python3-venv \
      gcovr \
    && rm -rf /var/lib/apt/lists/*

RUN if [ "$WITH_CLAUDE_CLI" = "1" ]; then \
      curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
      apt-get install -y --no-install-recommends nodejs && \
      npm install -g @anthropic-ai/claude-code && \
      rm -rf /var/lib/apt/lists/*; \
    fi

WORKDIR /app

# Dependencies first, so edits to our own source don't invalidate this layer.
COPY requirements.txt ./
RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt
ENV PATH="/opt/venv/bin:$PATH"

# Bake the pinned target into the image. Doing this at build time (not run
# time) means `docker run` needs no network, so a reader can reproduce the
# fuzzing half fully offline.
COPY scripts/fetch_target.sh ./scripts/
RUN bash ./scripts/fetch_target.sh

COPY . .

# Build the sanitizer harness here too. Replay mode needs a real binary to run
# recorded inputs through; without this step the image would start, accept a
# replay command, and then fail when the campaign looked for build/asan/harness.
RUN bash ./harness/build.sh asan

# .env is gitignored and .dockerignored: secrets are injected at run time by
# run.sh via --env-file, never baked into the image.

# Sanitizer behaviour is part of the experiment, so it is configured here
# rather than left to whatever the shell happens to export.
#   halt_on_error / abort_on_error : make UBSan fatal. Without this it prints
#     "runtime error:" and exits 0, and we would detect nothing.
#   detect_leaks=0 : leaks are a separate concern from the memory-safety bugs
#     we are hunting, and mxml abandons partially-built node trees when it
#     rejects an input, so leaving this on would report a leak for most of our
#     500 inputs and drown real crashes. Run a dedicated leak pass separately.
#   print_stacktrace : we need frames to build crash signatures.
ENV ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:symbolize=1:print_stacktrace=1"
ENV UBSAN_OPTIONS="halt_on_error=1:abort_on_error=1:print_stacktrace=1"

CMD ["bash"]
