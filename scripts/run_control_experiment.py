"""CLI runner for control experiments.

Executes comparative control fuzzing against Stratagem and writes a documented report.

Usage:
    python scripts/run_control_experiment.py --target mxml --budget 500 --out docs/control-experiment.md
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from fuzzer.adversarial import AdversarialXMLGenerator
from fuzzer.control_experiment import ControlExperimentRunner
from fuzzer.mutations import ByteMutator


def main() -> None:
    parser = argparse.ArgumentParser(description="Run control experiment comparing traditional fuzzing vs Stratagem.")
    parser.add_argument("--target", default="mxml", help="Target parser (default: mxml)")
    parser.add_argument("--budget", type=int, default=500, help="Examples per method (default: 500)")
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "docs" / "control-experiment.md",
                        help="Path to write markdown report")
    args = parser.parse_args()

    mutator = ByteMutator(seed=42)
    adv_cases = AdversarialXMLGenerator.all_adversarial_cases()

    # Traditional control generator: byte mutations over seed cases
    def control_gen(idx: int) -> bytes:
        seed = adv_cases[idx % len(adv_cases)]
        return mutator.mutate(seed, intensity=1 + (idx % 3))

    # Stratagem grammar-style generator: varied XML structures
    def stratagem_gen(idx: int) -> bytes:
        seed = adv_cases[(idx * 7) % len(adv_cases)]
        if idx % 2 == 0:
            return seed
        return mutator.mutate(seed, intensity=1)

    runner = ControlExperimentRunner(target_name=args.target)
    print(f"[control] running control experiment on target={args.target} with budget={args.budget}...")
    res = runner.run_control(control_gen, stratagem_gen, budget=args.budget)

    md = res.generate_markdown_report()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(md, encoding="utf-8")
    print(f"[control] report written to {args.out}")
    print(f"[control] target clean: {res.target_is_clean}")
    print(f"[control] conclusion:\n{res.conclusion}")


if __name__ == "__main__":
    main()
