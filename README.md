# Stratagem

**Agentic grammar fuzzing for C parsers.**

Stratagem is a blackbox fuzzer whose test-case generator is written by a
language model. On each iteration the model receives a pinned formal grammar and
the measured results of the previous batch, and returns a Hypothesis strategy.
The strategy is validated, run against a sanitizer-instrumented target, and
measured; that measurement becomes the next prompt. The loop stops on an
iteration cap or a spend cap.

A *stratagem* is a plan or scheme. Here the plans are Hypothesis strategies, and
the model is the strategist.

This repository contains the full pipeline, the recorded transcripts and
corpora of the reported campaigns, and the evaluation code. The target used for
the published results is [Mini-XML (mxml)](https://github.com/michaelrsweet/mxml)
v4.0.4, but the loop is target-agnostic apart from the harness and the grammar
in `grammar/`.

---

## How it works

```
formal grammar ──► LLM writes strategy ──► validate ──► run 500 inputs
                          ▲                                   │
                          │                                   ▼
                    refine prompt ◄──── summary ◄──── harness + measurement
```

1. **Seed.** The model gets `XMLParser.g4` / `XMLLexer.g4` (pinned by commit and
   checksum) plus the measured differences between that grammar and the real
   parser. It returns one fenced Python module exposing
   `documents() -> SearchStrategy[str]`.
2. **Gate.** The response is checked for a complete code block, compiled,
   imported in a subprocess, and sampled. A 50-document smoke run rejects
   generators that bounce off the parser's front door or drift outside the
   required mix of well-formed, near-miss, and byte-hostile inputs.
3. **Campaign.** The accepted strategy runs for up to 500 documents (10-minute
   wall-clock cap). Each input goes through the ASan/UBSan harness; outcomes,
   parser diagnostics, structural features, timing, and crash signatures are
   recorded.
4. **Refine.** The next prompt carries the previous source, per-class
   acceptance, new diagnostics and productions, boundary distributions, and a
   rotating directive. The model returns a revised strategy.

Everything the model sees and says is written to `runs/<id>/transcript/`, and
every input is written to `runs/<id>/iterations/iter-N/corpus.jsonl.gz`, so a
run can be audited and replayed without credentials.

### Feedback is blackbox

The loop never receives code coverage. It works from:

- process outcomes (parsed, parsed-with-diagnostics, rejected, crash, timeout),
- the parser's own diagnostics, normalised into stable templates,
- structural properties of the generated input (27 grammar- and
  parser-specific productions, nesting depth, boundary sizes),
- acceptance rate overall and per input class.

Coverage is measured **after** a campaign, by separate scripts, and is never fed
back to the model. See `docs/design-decisions.md` (D2, D6).

---

## Quick start

The supported environment is the container: it pins the compiler and sets the
sanitizer options the measurements depend on.

```sh
cp .env.example .env          # optional; replay needs no credentials
./run.sh build                # target + ASan harness + Python deps
./run.sh shell
```

Inside the container:

```sh
# 1. Unit checks for the measurement layer (no harness needed)
python -m fuzzer.selftest

# 2. Harness regression checks (needs the ASan build)
./harness/smoke_test.sh

# 3. One campaign against the baseline generator
python -m fuzzer.campaign baseline -n 100

# 4. The agentic loop, replaying the recorded run (no API key)
cp -r runs/loop-c runs/demo
python -m agent.loop --backend replay --run-id demo

# 5. Verify a recorded run reproduces, inputs and generators
./scripts/verify_replay.sh loop-c
```

`verify_replay.sh` writes its comparison copy to `runs/<id>-replay/`, which is
gitignored; it never overwrites the run being verified.

### Driving it with a model

Set `LLM_BACKEND` in `.env` (or pass `--backend`):

| backend | what it uses | credentials |
|---|---|---|
| `replay` | recorded transcript, no network | none (default) |
| `openai` | any OpenAI-compatible `/v1/chat/completions` endpoint | `OPENAI_API_KEY`, `OPENAI_BASE_URL` |
| `cli` | Claude Code headless (`claude -p`), billed to a subscription | `CLAUDE_CODE_OAUTH_TOKEN` (or an interactive login) |

```sh
python -m agent.loop --backend openai --run-id trial-1 --max-usd 5
```

`--max-usd` is enforced when the backend reports a price (`cli`, and `replay`
from the recorded costs). The OpenAI-compatible backend reports tokens but no
per-call price, so the cap is advisory there; the summary records
`cost_cap_enforced: false` rather than pretending otherwise.

The `cli` backend needs an image built with the CLI included:

```sh
./run.sh build --with-cli
```

---

## What the published runs found

Across 10,000 historical inputs from 19 generated strategies plus a random-text
baseline, the campaigns found **no memory-safety crash and no timeout**. They did
produce:

- **F1 — a real diagnostic defect, fixed upstream.** mxml formatted a decoded
  code point with `%c`, which truncated some error messages and emitted invalid
  UTF-8 for others. Reported in
  [mxml PR #357](https://github.com/michaelrsweet/mxml/pull/357), fixed in
  commit `d986100`. Details in `docs/findings.md`.
- **F2 — a known index bug used as a positive control.** Upstream issue #350 is
  reachable only through `mxmlIndexNew`, so the harness exposes it behind
  `--index`. The smoke test requires the sanitizer build to catch it; a build
  with sanitizers silently missing would otherwise report "no bugs found"
  forever.
- **F3 — an independent reproduction of a known leak.** Upstream issue #354,
  reached by 8.2% of the historical corpus. Leak detection runs as a separate
  pass so it does not bury fatal memory errors.

The reported five-iteration run (`runs/loop-c`) cost $4.51. Coverage and the
proxy signals are compared in `docs/comparison.md`; the main result is that
distinct parser diagnostics tracked line coverage far better than production
count (pooled correlation +0.76 across 19 strategies).

Read more:

| document | contents |
|---|---|
| `docs/REPORT.md` | the full write-up: design, findings, limitations |
| `docs/design-decisions.md` | why each engineering choice was made |
| `docs/findings.md` | the defects and controls in detail |
| `docs/comparison.md` | run-to-run comparison and coverage study |
| `grammar/ADAPTATIONS.md` | measured differences between the grammar and mxml |

---

## Layout

```
agent/                 the agentic loop
  loop.py              budget, prompts, validation/repair, campaign, summary
  llm.py               cli / openai-compatible / replay backends
  validate.py          four validation gates
  env.py               .env loader (real environment wins)
  prompts/             v1..v5 prompt sets; v2 is the loop default
fuzzer/                the fuzzing and measurement half
  campaign.py          Hypothesis driver, budgets, summarisation
  runner.py            runs the harness and classifies the outcome
  features.py          structural production/depth/boundary analysis
  diagnostics.py       normalises parser messages into templates
  triage.py            sanitizer report parsing and crash signatures
  corpus.py            byte-exact corpus recording and replay
  minimize.py          Hypothesis shrinking plus determinism check
  selftest.py          regression suite for the measurement layer
  strategies/          baseline, byte probe, and generated strategies
harness/               C harness, build script, smoke test, sample inputs
grammar/               pinned ANTLR grammar and adaptation notes
scripts/               fetch pins, coverage studies, leak pass, replay check
runs/                  recorded campaigns, transcripts, corpora, analysis
docs/                  report, design decisions, findings, comparison
```

### Recorded runs

| run | prompt set | model | iterations | cost |
|---|---|---|---:|---:|
| `runs/loop` (A) | v1 | Sonnet | 5 | $2.01 |
| `runs/loop-b` (B) | v2 | Opus | 2 | $1.84 |
| `runs/loop-c` (C) | v2 | Sonnet | 5 | $4.51 |
| `runs/loop-d` (D) | v3 | Sonnet | 1 | $4.18 |
| `runs/loop-e` (E) | v4 | Sonnet | 1 | $4.22 |
| `runs/loop-f` (F) | v5 | Sonnet | 4 | $5.45 |

Runs B, D, and E stopped at an account usage limit; F exceeded the $5 cap and is
kept for analysis only.

---

## Reproducibility

- The target is pinned to mxml v4.0.4 at
  `0d5afc4278d7a336d554602b951c2979c3f8f296`; `scripts/fetch_target.sh` checks
  the commit after checkout.
- The grammar is fetched from a pinned grammars-v4 commit and verified against
  SHA-256 checksums (`scripts/fetch_grammar.sh`, `grammar/SOURCE.txt`).
- `requirements.txt` pins Hypothesis, because its shrinker and draw sequence
  change between releases.
- Each iteration records the exact bytes fed to the harness, base64-encoded, in
  `corpus.jsonl.gz`, plus a digest over the ordered corpus.
- `scripts/verify_replay.sh` replays those bytes and compares every
  classification and digest; it also replays the transcript and requires each
  regenerated `strategy.py` to be byte-identical.
- The harness build is checked for linked sanitizer symbols, and the smoke test
  requires a known real bug to be detected.

The historical corpora predate the serializer correction described in
`docs/design-decisions.md` D13. They still replay exactly; the corrected
coverage study re-runs the saved strategy code instead of the old bytes.

---

## Scope and limitations

- This is containment against accidental hangs, not a security sandbox. The
  generated Python is validated and run in subprocesses with timeouts, but it is
  model-authored code.
- Stack-hash crash signatures are an estimate of root cause: they can merge
  distinct bugs or split one bug (Klees et al., CCS 2018). The full normalised
  trace is stored beside each signature.
- Each LLM revision sequence was generated once. Three-seed coverage trials
  measure input-sampling noise, not variation between model generations.
- The published results cover one XML parser. Other parsers may respond
  differently to the same feedback signals.
