#!/usr/bin/env python3
"""Statistics over repeated trials: mean, 95% CI, Mann-Whitney U, Vargha-Delaney Â12.

Answers the reviewers' rigor ask (report variance and a non-parametric test with
effect size, not best-of). Dependency-free. Groups runs by (API, tool) and, per
metric, compares PrediQL against each baseline across their trials.

Most informative once the ablation/depth reruns give PrediQL >=5 trials; until
then it reports whatever samples exist (n shown per group).

Usage:
    python scripts/stats.py [--metric element_coverage] [--ablation]
"""
from __future__ import annotations

import argparse
import json
import math
import random
from collections import defaultdict
from pathlib import Path

RUNS = Path(__file__).resolve().parents[1] / "runs"


def _runs():
    for d in RUNS.iterdir():
        if not d.is_dir():
            continue
        man = _read(d / "manifest.json")
        cov = _read(d / "artifacts" / "coverage.json")
        if man and cov:
            yield man.get("config", {}), cov


def _read(p: Path):
    try:
        return json.loads(p.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def _tool(cfg) -> str:
    gen = (cfg.get("providers") or {}).get("generator", "")
    return gen.split(":", 1)[1] if gen.startswith("baseline:") else "prediql"


def _api(cfg) -> str:
    alias, abl = cfg.get("alias", ""), cfg.get("ablation", "")
    return alias[:-(len(abl) + 1)] if abl and alias.endswith(f"-{abl}") else alias


# -- statistics (no scipy) --------------------------------------------------

def mann_whitney_u(a: list[float], b: list[float]) -> tuple[float, float, float]:
    """Return (U1, p_two_sided, A12). Normal approx with tie correction."""
    n1, n2 = len(a), len(b)
    if n1 == 0 or n2 == 0:
        return (0.0, 1.0, 0.5)
    combined = sorted([(v, 0) for v in a] + [(v, 1) for v in b])
    # average ranks with ties
    ranks = [0.0] * len(combined)
    i = 0
    while i < len(combined):
        j = i
        while j + 1 < len(combined) and combined[j + 1][0] == combined[i][0]:
            j += 1
        r = (i + j) / 2 + 1  # 1-based average rank
        for k in range(i, j + 1):
            ranks[k] = r
        i = j + 1
    r1 = sum(rk for rk, (_, g) in zip(ranks, combined) if g == 0)
    u1 = r1 - n1 * (n1 + 1) / 2
    a12 = u1 / (n1 * n2)
    mu = n1 * n2 / 2
    # tie-corrected variance
    from collections import Counter
    tie = Counter(v for v, _ in combined)
    n = n1 + n2
    tie_term = sum(t**3 - t for t in tie.values())
    var = n1 * n2 / 12 * ((n + 1) - tie_term / (n * (n - 1))) if n > 1 else 0.0
    if var <= 0:
        return (u1, 1.0, a12)
    z = (u1 - mu) / math.sqrt(var)
    p = 2 * (1 - _phi(abs(z)))
    return (u1, max(0.0, min(1.0, p)), a12)


def _phi(x: float) -> float:
    return 0.5 * (1 + math.erf(x / math.sqrt(2)))


def mean_ci(xs: list[float], boots: int = 2000, seed: int = 0) -> tuple[float, float, float]:
    if not xs:
        return (0.0, 0.0, 0.0)
    m = sum(xs) / len(xs)
    if len(xs) == 1:
        return (m, m, m)
    rng = random.Random(seed)
    means = sorted(sum(rng.choice(xs) for _ in xs) / len(xs) for _ in range(boots))
    lo = means[int(0.025 * boots)]
    hi = means[int(0.975 * boots)]
    return (m, lo, hi)


def effect_label(a12: float) -> str:
    d = abs(a12 - 0.5)
    return "negligible" if d < 0.06 else "small" if d < 0.14 else "medium" if d < 0.21 else "large"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--metric", default="element_coverage")
    ap.add_argument("--ablation", action="store_true",
                    help="group PrediQL by ablation tag instead of pooling full")
    args = ap.parse_args()

    # samples[(api, group)] = [metric values across trials]
    samples: dict[tuple[str, str], list[float]] = defaultdict(list)
    for cfg, cov in _runs():
        tool = _tool(cfg)
        if tool == "prediql" and not args.ablation and cfg.get("ablation") != "full":
            continue
        group = f"prediql:{cfg.get('ablation')}" if (tool == "prediql" and args.ablation) else tool
        v = cov.get(args.metric)
        if v is not None:
            samples[(_api(cfg), group)].append(float(v))

    apis = sorted({api for api, _ in samples})
    groups = sorted({g for _, g in samples})
    ref = "prediql" if "prediql" in groups else next((g for g in groups if g.startswith("prediql")), None)

    print(f"Metric: {args.metric}   (reference group for tests: {ref})\n")
    for api in apis:
        print(f"== {api} ==")
        ref_xs = samples.get((api, ref), []) if ref else []
        for g in groups:
            xs = samples.get((api, g), [])
            if not xs:
                continue
            m, lo, hi = mean_ci(xs)
            line = f"  {g:<18} n={len(xs):<2} mean={m:.3f}  95%CI[{lo:.3f},{hi:.3f}]"
            if ref and g != ref and ref_xs:
                _, p, a12 = mann_whitney_u(ref_xs, xs)
                line += f"   vs {ref}: Â12={a12:.2f} ({effect_label(a12)}), p={p:.3f}"
            print(line)
        print()
    print("Â12 = P(reference run > comparison run); >0.5 favors the reference (PrediQL). "
          "Small n (single-trial imports) widens CIs — rerun with >=5 trials for tight intervals.")


if __name__ == "__main__":
    main()
