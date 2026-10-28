"""Prompt versioning, discovery, rendering, and statistical A/B testing.

Enables systematic prompt engineering and experimentation for LLM-guided fuzzing:
  * PromptVersion: Encapsulates system, seed, refine, directives, and harness templates
    with variable validation, rendering, and unified diffing between versions.
  * PromptManager: Discovers prompt sets on disk (e.g. v1, v2, v3, v4, v5), registers
    custom in-memory variants, and exports versions.
  * PromptABTester: Routes iterations across variants (round-robin, random, hash-based,
    or weighted), tracks multi-metric fuzzing outcomes, and evaluates statistical
    significance using Welch's t-test, Mann-Whitney U, and Vargha-Delaney A12 effect size.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import math
import random
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PROMPTS_DIR = REPO_ROOT / "agent" / "prompts"

# Keep a bounded observation window per prompt variant. A/B evaluation only
# needs the newest trials, and an experiment can run for days.
MAX_TRIALS_PER_VARIANT = 5000


@dataclass
class PromptVersion:
    """A versioned set of prompts and refinement directives."""
    name: str
    path: Optional[Path] = None
    system_template: str = ""
    seed_template: str = ""
    refine_template: str = ""
    directives: List[str] = field(default_factory=list)
    directives_text: str = ""
    harness_template: str = ""
    harness_system_template: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dir(cls, directory: Path | str, name: Optional[str] = None,
                 metadata: Optional[Dict[str, Any]] = None) -> PromptVersion:
        """Load a prompt version from a folder."""
        d = Path(directory)
        v_name = name or d.name
        if v_name in ("prompts", ""):
            v_name = "v1"

        def _read_if_exists(fname: str) -> str:
            p = d / fname
            return p.read_text(encoding="utf-8") if p.is_file() else ""

        system = _read_if_exists("system.md")
        seed = _read_if_exists("seed.md")
        refine = _read_if_exists("refine.md")
        directives_raw = _read_if_exists("directives.md")
        harness = _read_if_exists("harness.md")
        harness_system = _read_if_exists("harness_system.md")

        # Extract directives list
        directives = []
        if directives_raw:
            directives = re.findall(r"^## \d+\. (.+)$", directives_raw, re.M)

        meta = dict(metadata or {})
        meta_file = d / "metadata.json"
        if meta_file.is_file():
            try:
                disk_meta = json.loads(meta_file.read_text(encoding="utf-8"))
                meta.update(disk_meta)
            except Exception:
                pass

        if "version" not in meta:
            meta["version"] = v_name
        if "loaded_from" not in meta:
            meta["loaded_from"] = str(d)

        return cls(
            name=v_name,
            path=d,
            system_template=system,
            seed_template=seed,
            refine_template=refine,
            directives=directives,
            directives_text=directives_raw,
            harness_template=harness,
            harness_system_template=harness_system,
            metadata=meta,
        )

    def render_system(self, **kwargs) -> str:
        """Render system prompt template with optional substitutions."""
        text = self.system_template
        for k, v in kwargs.items():
            text = text.replace(f"{{{k}}}", str(v))
        return text

    def render_seed(self, grammar_commit: str = "",
                    parser_g4: str = "",
                    lexer_g4: str = "",
                    productions: Sequence[str] | str = "",
                    **kwargs) -> str:
        """Render seed prompt substituting grammar bodies and productions."""
        text = self.seed_template
        if isinstance(productions, (list, tuple)):
            prod_str = "\n   ".join(
                "  ".join(productions[i:i + 4]) for i in range(0, len(productions), 4)
            )
        else:
            prod_str = str(productions)

        text = (text
                .replace("{grammar_commit}", str(grammar_commit))
                .replace("{parser_g4}", str(parser_g4))
                .replace("{lexer_g4}", str(lexer_g4))
                .replace("{productions}", prod_str))

        for k, v in kwargs.items():
            text = text.replace(f"{{{k}}}", str(v))
        return text

    def render_refine(self, it: int = 1,
                      source: str = "",
                      summary: Optional[Dict[str, Any]] = None,
                      results: Optional[List[Dict[str, Any]]] = None,
                      directive: Optional[str] = None,
                      boundaries: str = "",
                      buckets: str = "",
                      new_diagnostics: int = 0,
                      new_productions: int = 0,
                      union_diagnostics: Optional[Sequence[str]] = None,
                      **kwargs) -> str:
        """Render refine prompt with summary statistics and directive."""
        text = self.refine_template
        summary = summary or {}
        results = results or []
        st = summary.get("structure", {})

        slowest = sorted(results, key=lambda r: -r.get("dur_ms", 0))[:3]
        slow_txt = "\n".join(
            f"{r.get('dur_ms', 0.0):8.1f} ms  len={r.get('len', 0):<6} "
            f"depth={r.get('structure', {}).get('max_depth', 0):<3} {r.get('outcome', '')}"
            for r in slowest
        ) or "(none)"

        outcomes = summary.get("outcomes", {})
        outcome_txt = "\n".join(f"  {k}: {v}" for k, v in outcomes.items()) or "  (none)"
        diag_list = "\n".join(f"  - {d}" for d in (union_diagnostics or [])) or "  (none yet)"

        substitutions = {
            "iteration": str(it),
            "source": source,
            "strategy_source": source,
            "directive": directive or "",
            "examples": str(summary.get("examples", 0)),
            "wall_clock_s": f"{summary.get('wall_clock_s', 0.0):.1f}",
            "acceptance_rate": f"{summary.get('acceptance_rate', 0.0):.1%}",
            "outcomes": outcome_txt,
            "productions_hit": str(st.get("productions_hit", 0)),
            "productions_total": str(st.get("productions_total", 0)),
            "max_depth": str(st.get("max_depth_seen", 0)),
            "new_diagnostics": str(new_diagnostics),
            "new_productions": str(new_productions),
            "union_diagnostic_list": diag_list,
            "union_diagnostics": str(len(union_diagnostics or [])),
            "slowest": slow_txt,
            "boundaries": boundaries or "(not measured)",
            "buckets": buckets or "(not measured)",
        }
        for k, v in substitutions.items():
            text = text.replace(f"{{{k}}}", v)

        if directive and "{directive}" not in self.refine_template:
            text = f"## Directive for this iteration\n\n**{directive}**\n\n{text}"

        for k, v in kwargs.items():
            text = text.replace(f"{{{k}}}", str(v))
        return text

    def validate(self) -> List[str]:
        """Validate templates and check for missing required placeholders."""
        issues: List[str] = []
        if not self.system_template.strip():
            issues.append("system_template is empty")
        if not self.seed_template.strip():
            issues.append("seed_template is empty")
        else:
            for ph in ("{grammar_commit}", "{parser_g4}", "{lexer_g4}", "{productions}"):
                if ph not in self.seed_template:
                    issues.append(f"seed_template missing expected placeholder: {ph}")

        if not self.refine_template.strip():
            issues.append("refine_template is empty")
        else:
            has_source = "{strategy_source}" in self.refine_template or "{source}" in self.refine_template
            if not has_source:
                issues.append("refine_template missing expected placeholder: {strategy_source} or {source}")
            if "{acceptance_rate}" not in self.refine_template:
                issues.append("refine_template missing expected placeholder: {acceptance_rate}")

        return issues

    def diff(self, other: PromptVersion) -> Dict[str, str]:
        """Generate unified diffs between this version and another."""
        diffs = {}
        for part in ("system", "seed", "refine", "directives"):
            self_val = getattr(self, f"{part}_template" if part != "directives" else "directives_text")
            other_val = getattr(other, f"{part}_template" if part != "directives" else "directives_text")
            if self_val != other_val:
                u = difflib.unified_diff(
                    self_val.splitlines(keepends=True),
                    other_val.splitlines(keepends=True),
                    fromfile=f"{self.name}/{part}.md",
                    tofile=f"{other.name}/{part}.md",
                )
                diffs[part] = "".join(u)
        return diffs

    def to_dict(self) -> Dict[str, Any]:
        """Convert version summary and metadata to dict."""
        return {
            "name": self.name,
            "path": str(self.path) if self.path else None,
            "has_system": bool(self.system_template),
            "has_seed": bool(self.seed_template),
            "has_refine": bool(self.refine_template),
            "directives_count": len(self.directives),
            "directives": self.directives,
            "system_len": len(self.system_template),
            "seed_len": len(self.seed_template),
            "refine_len": len(self.refine_template),
            "metadata": self.metadata,
        }


class PromptManager:
    """Manages discovery, registration, and loading of prompt versions."""

    def __init__(self, prompts_dir: Path | str | None = None):
        self.prompts_dir = Path(prompts_dir or DEFAULT_PROMPTS_DIR)
        self._versions: Dict[str, PromptVersion] = {}
        self._discover()

    def _discover(self) -> None:
        """Scan directory and register all discovered versions."""
        if not self.prompts_dir.is_dir():
            return

        # Check root prompts dir as v1 if seed.md is present
        if (self.prompts_dir / "seed.md").is_file():
            v1 = PromptVersion.from_dir(self.prompts_dir, name="v1")
            self._versions["v1"] = v1
            self._versions["default"] = v1

        # Check subdirectories (v2, v3, v4, v5, etc.)
        for entry in sorted(self.prompts_dir.iterdir()):
            if entry.is_dir() and (entry / "seed.md").is_file():
                v = PromptVersion.from_dir(entry, name=entry.name)
                self._versions[entry.name] = v

    def list_versions(self) -> List[str]:
        """Return list of distinct registered prompt version names."""
        names = set(self._versions.keys())
        # Sort naturally with v1, v2, v3, etc.
        def _sort_key(s: str) -> tuple:
            m = re.match(r"^v(\d+)$", s)
            return (0, int(m.group(1))) if m else (1, s)
        return sorted(names, key=_sort_key)

    def get_version(self, name: str = "default") -> PromptVersion:
        """Retrieve a prompt version by name."""
        if name in self._versions:
            return self._versions[name]
        # Try finding as path
        p = Path(name)
        if p.is_dir() and (p / "seed.md").is_file():
            v = PromptVersion.from_dir(p)
            self._versions[v.name] = v
            return v
        raise KeyError(
            f"Prompt version {name!r} not found. Available versions: {self.list_versions()}"
        )

    def register_version(self, version: PromptVersion, overwrite: bool = False) -> None:
        """Register an in-memory or custom prompt version."""
        if version.name in self._versions and not overwrite:
            raise ValueError(f"Prompt version {version.name!r} already registered")
        self._versions[version.name] = version

    def create_variant(self, base_version: str, new_name: str,
                       system_override: Optional[str] = None,
                       seed_override: Optional[str] = None,
                       refine_override: Optional[str] = None,
                       directives_override: Optional[List[str]] = None,
                       metadata: Optional[Dict[str, Any]] = None) -> PromptVersion:
        """Clone an existing prompt version with customized templates or directives."""
        base = self.get_version(base_version)
        meta = dict(base.metadata)
        meta.update(metadata or {})
        meta["derived_from"] = base.name
        meta["created_at"] = time.time()

        variant = PromptVersion(
            name=new_name,
            path=None,
            system_template=system_override if system_override is not None else base.system_template,
            seed_template=seed_override if seed_override is not None else base.seed_template,
            refine_template=refine_override if refine_override is not None else base.refine_template,
            directives=list(directives_override) if directives_override is not None else list(base.directives),
            directives_text=base.directives_text,
            harness_template=base.harness_template,
            harness_system_template=base.harness_system_template,
            metadata=meta,
        )
        self.register_version(variant, overwrite=True)
        return variant

    def compare_versions(self, version_a: str, version_b: str) -> Dict[str, str]:
        """Compute unified diffs between two registered versions."""
        va = self.get_version(version_a)
        vb = self.get_version(version_b)
        return va.diff(vb)

    def export_version(self, name: str, dest_dir: Path | str) -> Path:
        """Export a registered prompt version to disk."""
        v = self.get_version(name)
        d = Path(dest_dir)
        d.mkdir(parents=True, exist_ok=True)
        if v.system_template:
            (d / "system.md").write_text(v.system_template, encoding="utf-8")
        if v.seed_template:
            (d / "seed.md").write_text(v.seed_template, encoding="utf-8")
        if v.refine_template:
            (d / "refine.md").write_text(v.refine_template, encoding="utf-8")
        if v.directives_text:
            (d / "directives.md").write_text(v.directives_text, encoding="utf-8")
        if v.harness_template:
            (d / "harness.md").write_text(v.harness_template, encoding="utf-8")
        if v.harness_system_template:
            (d / "harness_system.md").write_text(v.harness_system_template, encoding="utf-8")
        (d / "metadata.json").write_text(json.dumps(v.to_dict(), indent=2), encoding="utf-8")
        return d


class PromptABTester:
    """A/B and multi-arm testing framework for evaluating prompt variant effectiveness.

    Routes iterations across prompt versions, logs fuzzing performance metrics,
    and conducts rigorous statistical hypothesis testing (Welch's t-test,
    Mann-Whitney U, Vargha-Delaney A12 effect size, and confidence intervals).
    """

    def __init__(self,
                 variants: Sequence[Union[str, PromptVersion]],
                 manager: Optional[PromptManager] = None,
                 routing: str = "round_robin",
                 weights: Optional[Dict[str, float]] = None,
                 name: str = "prompt_ab_experiment"):
        self.name = name
        self.manager = manager or PromptManager()
        self.routing = routing.lower()
        self.weights = weights or {}
        self._pointer = 0

        # Resolve variant objects
        self.variants: Dict[str, PromptVersion] = {}
        for var in variants:
            if isinstance(var, PromptVersion):
                self.variants[var.name] = var
                self.manager.register_version(var, overwrite=True)
            else:
                self.variants[str(var)] = self.manager.get_version(str(var))

        if not self.variants:
            raise ValueError("PromptABTester requires at least 1 variant")

        self.variant_names = list(self.variants.keys())
        self._trials: Dict[str, List[Dict[str, Any]]] = {
            v: [] for v in self.variant_names
        }

    def next_variant(self, iteration: Optional[int] = None,
                     seed: Optional[Union[int, str]] = None) -> PromptVersion:
        """Select the next prompt version based on the routing strategy."""
        n = len(self.variant_names)
        if n == 1:
            return self.variants[self.variant_names[0]]

        if self.routing == "round_robin":
            if iteration is not None:
                idx = iteration % n
            else:
                idx = self._pointer % n
                self._pointer += 1
            chosen = self.variant_names[idx]

        elif self.routing == "seed_hash":
            token = f"{seed or 'seed'}:{iteration if iteration is not None else self._pointer}"
            h = int(hashlib.md5(token.encode()).hexdigest(), 16)
            self._pointer += 1
            chosen = self.variant_names[h % n]

        elif self.routing in ("random", "weighted"):
            self._pointer += 1
            if self.weights:
                w_list = [self.weights.get(v, 1.0) for v in self.variant_names]
                chosen = random.choices(self.variant_names, weights=w_list, k=1)[0]
            else:
                chosen = random.choice(self.variant_names)

        else:
            chosen = self.variant_names[self._pointer % n]
            self._pointer += 1

        return self.variants[chosen]

    def record_trial(self, variant: str, trial_id: Union[int, str],
                     metrics: Dict[str, Any]) -> None:
        """Record the performance of an iteration/trial with a specific variant."""
        if variant not in self._trials:
            self._trials[variant] = []

        record = {
            "trial_id": trial_id,
            "timestamp": time.time(),
            "syntax_valid": bool(metrics.get("syntax_valid", True)),
            "gate_passed": bool(metrics.get("gate_passed", True)),
            "acceptance_rate": float(metrics.get("acceptance_rate", 0.0)),
            "productions_hit": int(metrics.get("productions_hit", 0)),
            "new_productions": int(metrics.get("new_productions", 0)),
            "new_diagnostics": int(metrics.get("new_diagnostics", 0)),
            "crashes": int(metrics.get("crashes", 0)),
            "max_depth": int(metrics.get("max_depth", 0)),
            "tokens_used": int(metrics.get("tokens_used", 0)),
            "cost_usd": float(metrics.get("cost_usd", 0.0)),
            "wall_clock_s": float(metrics.get("wall_clock_s", 0.0)),
            "raw": {k: v for k, v in metrics.items() if k not in (
                "syntax_valid", "gate_passed", "acceptance_rate", "productions_hit",
                "new_productions", "new_diagnostics", "crashes", "max_depth",
                "tokens_used", "cost_usd", "wall_clock_s"
            )},
        }
        self._trials[variant].append(record)
        # A long-running experiment should not keep every observation in
        # memory forever; the most recent window is enough for the statistical
        # comparison and the report.
        excess = len(self._trials[variant]) - MAX_TRIALS_PER_VARIANT
        if excess > 0:
            del self._trials[variant][:excess]

    def get_trials(self, variant: str) -> List[Dict[str, Any]]:
        """Return raw trial observations for a variant."""
        return list(self._trials.get(variant, []))

    def evaluate(self, variant_a: str, variant_b: str,
                 metric: str = "productions_hit",
                 alpha: float = 0.05) -> Dict[str, Any]:
        """Perform statistical significance evaluation between Variant A (baseline) and Variant B (treatment)."""
        trials_a = self._trials.get(variant_a, [])
        trials_b = self._trials.get(variant_b, [])

        sample_a = [float(t[metric]) for t in trials_a if metric in t]
        sample_b = [float(t[metric]) for t in trials_b if metric in t]

        from fuzzer.significance import compare_samples

        stats_comp = compare_samples(
            treatment=sample_b,
            baseline=sample_a,
            metric=metric,
            alpha=alpha,
            treatment_name=variant_b,
            baseline_name=variant_a,
        )

        mean_a = stats_comp.baseline_mean
        mean_b = stats_comp.treatment_mean
        p_val = stats_comp.welch_p
        a12 = stats_comp.vargha_delaney_a12
        is_sig = stats_comp.is_significant

        # Winner assessment
        if is_sig:
            if mean_b > mean_a:
                winner = variant_b
                decision = f"{variant_b} significantly outperforms {variant_a} on {metric}"
            else:
                winner = variant_a
                decision = f"{variant_a} significantly outperforms {variant_b} on {metric}"
        else:
            winner = "tie"
            decision = f"No statistically significant difference between {variant_a} and {variant_b} on {metric} (p={p_val:.4f})"

        return {
            "variant_a": variant_a,
            "variant_b": variant_b,
            "metric": metric,
            "count_a": len(sample_a),
            "count_b": len(sample_b),
            "mean_a": round(mean_a, 4),
            "mean_b": round(mean_b, 4),
            "diff": round(mean_b - mean_a, 4),
            "diff_pct": round(stats_comp.relative_change_pct, 2),
            "p_value_welch": round(p_val, 5),
            "p_value_mann_whitney": round(stats_comp.mann_whitney_p, 5),
            "effect_size_a12": round(a12, 4),
            "effect_magnitude": stats_comp.a12_magnitude,
            "hedges_g": round(stats_comp.hedges_g, 4),
            "ci_95_diff": [round(stats_comp.ci_95_lower, 4), round(stats_comp.ci_95_upper, 4)],
            "statistically_significant": is_sig,
            "winner": winner,
            "decision": decision,
        }

    def summary(self) -> Dict[str, Any]:
        """Aggregate summary metrics across all variants."""
        res: Dict[str, Any] = {}
        for v in self.variant_names:
            trials = self._trials.get(v, [])
            n = len(trials)
            if n == 0:
                res[v] = {"trials": 0}
                continue

            syntax_rate = sum(1 for t in trials if t["syntax_valid"]) / n
            gate_rate = sum(1 for t in trials if t["gate_passed"]) / n
            crashes = sum(t["crashes"] for t in trials)

            def _stats(key: str) -> dict:
                vals = [float(t[key]) for t in trials if key in t]
                if not vals:
                    return {"mean": 0.0, "std": 0.0, "median": 0.0, "min": 0.0, "max": 0.0}
                mean = sum(vals) / len(vals)
                var = sum((x - mean) ** 2 for x in vals) / max(1, len(vals) - 1)
                sorted_vals = sorted(vals)
                med = sorted_vals[len(vals) // 2]
                return {
                    "mean": round(mean, 3),
                    "std": round(math.sqrt(var), 3),
                    "median": round(med, 3),
                    "min": round(min(vals), 3),
                    "max": round(max(vals), 3),
                }

            res[v] = {
                "trials": n,
                "syntax_valid_rate": round(syntax_rate, 3),
                "gate_passed_rate": round(gate_rate, 3),
                "total_crashes": crashes,
                "acceptance_rate": _stats("acceptance_rate"),
                "productions_hit": _stats("productions_hit"),
                "new_productions": _stats("new_productions"),
                "new_diagnostics": _stats("new_diagnostics"),
                "max_depth": _stats("max_depth"),
                "wall_clock_s": _stats("wall_clock_s"),
                "tokens_used": _stats("tokens_used"),
            }
        return res

    def render_report(self, baseline: Optional[str] = None) -> str:
        """Render a Github-flavored Markdown comparison table with significance indicators."""
        summ = self.summary()
        base = baseline or (self.variant_names[0] if self.variant_names else "")
        lines = [
            f"# Prompt A/B Testing Report: {self.name}",
            "",
            f"**Routing Strategy**: `{self.routing}` | **Total Variants**: {len(self.variant_names)}",
            "",
            "## Summary of Variants",
            "",
            "| Variant | Trials | Syntax Rate | Gate Rate | Mean Coverage | Mean Accept | Crashes | Mean Tokens |",
            "|:---|---:|---:|---:|---:|---:|---:|---:|",
        ]

        for v, s in summ.items():
            if s.get("trials", 0) == 0:
                lines.append(f"| **{v}** | 0 | - | - | - | - | 0 | - |")
                continue
            cov = s["productions_hit"]["mean"]
            acc = s["acceptance_rate"]["mean"] * 100
            toks = s["tokens_used"]["mean"]
            lines.append(
                f"| **{v}** | {s['trials']} | {s['syntax_valid_rate']:.1%} | "
                f"{s['gate_passed_rate']:.1%} | {cov:.1f} prods | {acc:.1f}% | "
                f"{s['total_crashes']} | {toks:.0f} |"
            )

        # Statistical comparison against baseline if we have > 1 variant with trials
        if base and len(self.variant_names) > 1 and summ.get(base, {}).get("trials", 0) >= 2:
            lines.extend([
                "",
                f"## Statistical Significance vs Baseline (`{base}`)",
                "",
                "| Candidate | Metric | Baseline Mean | Candidate Mean | Diff (%) | p-value (t-test) | A12 Effect | Significant? | Winner |",
                "|:---|:---|---:|---:|---:|---:|:---|:---:|:---|",
            ])
            for cand in self.variant_names:
                if cand == base or summ.get(cand, {}).get("trials", 0) < 2:
                    continue
                for metric in ("productions_hit", "acceptance_rate"):
                    eval_res = self.evaluate(base, cand, metric=metric)
                    sig_marker = "YES" if eval_res["statistically_significant"] else "no"
                    p_txt = f"{eval_res['p_value_welch']:.4f}"
                    diff_pct = f"{eval_res['diff_pct']:+.1f}%"
                    lines.append(
                        f"| `{cand}` | `{metric}` | {eval_res['mean_a']} | {eval_res['mean_b']} | "
                        f"{diff_pct} | {p_txt} | {eval_res['effect_size_a12']:.2f} ({eval_res['effect_magnitude']}) | "
                        f"{sig_marker} | **{eval_res['winner']}** |"
                    )

        return "\n".join(lines)

    def save(self, path: Path | str) -> None:
        """Persist experiment trials and summary to JSON."""
        data = {
            "name": self.name,
            "routing": self.routing,
            "weights": self.weights,
            "variant_names": self.variant_names,
            "trials": self._trials,
            "summary": self.summary(),
        }
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path | str, manager: Optional[PromptManager] = None) -> PromptABTester:
        """Load an experiment from JSON."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        mgr = manager or PromptManager()
        tester = cls(
            variants=data["variant_names"],
            manager=mgr,
            routing=data.get("routing", "round_robin"),
            weights=data.get("weights", {}),
            name=data.get("name", "prompt_ab_experiment"),
        )
        tester._trials = data.get("trials", {})
        return tester
