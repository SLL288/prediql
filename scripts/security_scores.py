#!/usr/bin/env python3
"""Per-backbone security detection scores (RQ3).

Reads every run that has a score.json, groups by (model, app), and prints the
confirmed-only confusion matrix + precision/recall/F1 and the false-positive rate
on the labeled negatives. The confirmed+potential matrix is shown too, so the
precision cost of trusting LLM potentials is explicit (the answer to v1's
"2,130 findings").
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

RUNS = Path(__file__).resolve().parents[1] / "runs"


def _read(p: Path):
    try:
        return json.loads(p.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def _rows():
    for d in sorted(RUNS.iterdir()):
        if not d.is_dir():
            continue
        man = _read(d / "manifest.json")
        score = _read(d / "artifacts" / "score.json")
        if not man or not score or "confirmed" not in score:
            continue
        cfg = man.get("config", {})
        model = (cfg.get("providers") or {}).get("generator", "?").split(":")[-1]
        yield model, cfg.get("alias", d.name), score


def _fpr(m):
    return m["fp"] / (m["fp"] + m["tn"]) if (m["fp"] + m["tn"]) else None


def main() -> None:
    by_model: dict[str, list] = defaultdict(list)
    for model, app, score in _rows():
        by_model[model].append((app, score))

    for model in sorted(by_model):
        print(f"\n=== {model} ===")
        hdr = f"  {'app':<14}{'TP':>3}{'FP':>3}{'FN':>3}{'TN':>3}  {'P':>5} {'R':>5} {'F1':>5}  FPrate  | +pot P/R/FP"
        print(hdr); print("  " + "-" * (len(hdr) - 2))
        agg = defaultdict(int)
        for app, score in sorted(by_model[model]):
            c, p = score["confirmed"], score["with_potential"]
            for k in ("tp", "fp", "fn", "tn"):
                agg[k] += c[k]
            fpr = _fpr(c); fprp = _fpr(p)
            print(f"  {app:<14}{c['tp']:>3}{c['fp']:>3}{c['fn']:>3}{c['tn']:>3}  "
                  f"{_f(c['precision'])} {_f(c['recall'])} {_f(c['f1'])}  "
                  f"{_pct(fpr):>6}  | {_f(p['precision'])}/{_f(p['recall'])}/{_pct(fprp)}")
        T, FP, FN, TN = agg["tp"], agg["fp"], agg["fn"], agg["tn"]
        P = T / (T + FP) if T + FP else None
        R = T / (T + FN) if T + FN else None
        print(f"  {'AGG':<14}{T:>3}{FP:>3}{FN:>3}{TN:>3}  {_f(P)} {_f(R)} {'':>5}  "
              f"{_pct(_fpr({'fp':FP,'tn':TN})):>6}")


def _f(v):
    return f"{v:.2f}" if isinstance(v, (int, float)) else "  — "


def _pct(v):
    return f"{v:.2f}" if isinstance(v, (int, float)) else "—"


if __name__ == "__main__":
    main()
