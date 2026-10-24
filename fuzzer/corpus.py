"""Record and replay the exact inputs a campaign fed to the harness.

Recording the corpus means a run can be replayed without regenerating anything,
so replay does not depend on Hypothesis producing an identical draw sequence
across versions or environments.

Documents are stored as base64 of the bytes written to the harness's stdin, not
as text. Generated documents can contain raw-byte surrogateescape sentinels,
other lone surrogates, and embedded NULs, so a text round-trip could silently
alter what was tested.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

CORPUS_NAME = "corpus.jsonl.gz"


def write_corpus(path: Path, payloads: list[bytes]) -> dict:
    """Write the campaign's inputs. Returns a manifest for the summary."""
    path.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        for i, p in enumerate(payloads):
            total += len(p)
            fh.write(json.dumps({
                "i": i,
                "sha": hashlib.sha256(p).hexdigest()[:16],
                "b64": base64.b64encode(p).decode("ascii"),
            }) + "\n")
    # A digest over the whole ordered corpus, so a reader can verify in one
    # comparison that they have the same inputs we did.
    digest = hashlib.sha256()
    for p in payloads:
        digest.update(hashlib.sha256(p).digest())
    return {
        "file": path.name,
        "count": len(payloads),
        "raw_bytes": total,
        "stored_bytes": path.stat().st_size,
        "corpus_digest": digest.hexdigest()[:16],
    }


def read_corpus(path: Path) -> list[bytes]:
    out: list[bytes] = []
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(base64.b64decode(json.loads(line)["b64"]))
    return out


def corpus_digest(payloads: list[bytes]) -> str:
    d = hashlib.sha256()
    for p in payloads:
        d.update(hashlib.sha256(p).digest())
    return d.hexdigest()[:16]


@dataclass
class ReplayReport:
    inputs: int = 0
    outcome_matches: int = 0
    outcome_mismatches: list[dict] = field(default_factory=list)
    recorded_digest: str = ""
    replayed_digest: str = ""

    @property
    def ok(self) -> bool:
        return (self.inputs > 0
                and self.outcome_matches == self.inputs
                and self.recorded_digest == self.replayed_digest)


def replay_and_verify(iteration_dir: Path, harness: Path | None = None,
                      extra_args: tuple[str, ...] = ()) -> ReplayReport:
    """Feed the recorded corpus back through the harness and compare outcomes.

    This is the actual reproducibility check: it does not regenerate anything,
    so it is insensitive to changes in the generator or in Hypothesis.
    """
    from fuzzer.runner import DEFAULT_HARNESS, run_one

    harness = harness or DEFAULT_HARNESS
    payloads = read_corpus(iteration_dir / CORPUS_NAME)
    recorded = [json.loads(l) for l in
                (iteration_dir / "results.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]

    rep = ReplayReport(inputs=len(payloads), outcome_mismatches=[])
    rep.recorded_digest = json.loads((iteration_dir / "summary.json").read_text(encoding="utf-8")) \
        .get("corpus", {}).get("corpus_digest", "")
    rep.replayed_digest = corpus_digest(payloads)

    for i, payload in enumerate(payloads):
        r = run_one(payload, harness=harness, extra_args=extra_args)
        want = recorded[i]["outcome"] if i < len(recorded) else None
        if r.outcome.value == want:
            rep.outcome_matches += 1
        else:
            rep.outcome_mismatches.append(
                {"i": i, "recorded": want, "replayed": r.outcome.value,
                 "sha": r.input_sha256[:16]})
    return rep
