#!/usr/bin/env python3
"""Score GraphQLer's own detections against our labeled benchmark.

Reads GraphQLer's confirmed findings from its Zenodo artifact
(``rq2/graphqler/<app>/detections/<class>/<operation>/``), maps them to our
canonical classes, and runs the *same* scorer against the *same* ground truth
used for PrediQL — so precision/recall/FP are directly comparable. GraphQLer's
findings are all its "confirmed" detections (it has no potential tier).

Usage:
    python scripts/score_graphqler.py --graphqler <.../rq2/graphqler>
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from prediql.scoring.groundtruth import load  # noqa: E402
from prediql.scoring.score import score  # noqa: E402

# GraphQLer app dir -> our truth file.
APP_TRUTH = {
    "injection-api": "security_benchmark/truth/injection.yaml",
    "idor-api": "security_benchmark/truth/idor.yaml",
    "vvsm-api": "security_benchmark/truth/vvsm.yaml",
}
# GraphQLer class dir -> our canonical class id.
CLASS_MAP = {
    "SQL_Injection__SQLi__Injection": "sql_injection",
    "OS_Command_Injection": "os_command_injection",
    "Path_Injection": "path_traversal",
    "Cross-Site_Scripting__XSS__Injection": "xss_stored",
    "Introspection_Enabled": "introspection_enabled",
    "IDOR_CHAIN": "idor",
    "UAF_CHAIN": "uaf",
}


def graphqler_findings(app_dir: Path) -> list[dict]:
    """Every (class, operation) GraphQLer confirmed, in our findings shape."""
    findings = []
    det = app_dir / "detections"
    if not det.is_dir():
        return findings
    for class_dir in det.iterdir():
        cid = CLASS_MAP.get(class_dir.name)
        if cid is None or not class_dir.is_dir():
            continue
        for op_dir in class_dir.iterdir():
            if not op_dir.is_dir():
                continue
            op = "__schema" if cid == "introspection_enabled" else op_dir.name
            findings.append({"operation": op, "class": cid, "state": "confirmed"})
    return findings


# GraphQLer app dir -> the alias our PrediQL runs use for the same app, so the
# dashboard can line GraphQLer up against PrediQL on the identical target+truth.
APP_ALIAS = {"injection-api": "injection", "idor-api": "idor", "vvsm-api": "vvsm"}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--graphqler", required=True, type=Path, help=".../rq2/graphqler")
    ap.add_argument("--out", type=Path, help="Persist the scored comparison as JSON "
                    "(read by the dashboard Security page)")
    args = ap.parse_args()

    agg = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    apps: dict[str, dict] = {}
    print(f"{'app':<14}{'TP':>3}{'FP':>3}{'FN':>3}{'TN':>3}   {'P':>5} {'R':>5}   FP-rate")
    for app, truth_path in APP_TRUTH.items():
        app_dir = args.graphqler / app
        if not app_dir.is_dir():
            continue
        truth = load(truth_path)
        findings = graphqler_findings(app_dir)
        r = score(findings, truth)["confirmed"]
        for k in agg:
            agg[k] += r[k]
        fpr = r["fp"] / (r["fp"] + r["tn"]) if (r["fp"] + r["tn"]) else None
        apps[APP_ALIAS.get(app, app)] = {
            "tp": r["tp"], "fp": r["fp"], "fn": r["fn"], "tn": r["tn"],
            "precision": r["precision"], "recall": r["recall"], "f1": r["f1"],
            "fp_rate": fpr, "fp_cells": r["fp_cells"], "fn_cells": r["fn_cells"],
        }
        print(f"{app:<14}{r['tp']:>3}{r['fp']:>3}{r['fn']:>3}{r['tn']:>3}   "
              f"{_f(r['precision'])} {_f(r['recall'])}   {_pct(fpr)}")
        if r["fp_cells"]:
            print(f"    FP: {', '.join(r['fp_cells'])}")
    T, FP, FN, TN = agg["tp"], agg["fp"], agg["fn"], agg["tn"]
    P = T / (T + FP) if T + FP else 0
    R = T / (T + FN) if T + FN else 0
    print(f"\nGraphQLer AGGREGATE  TP={T} FP={FP} FN={FN} TN={TN}  "
          f"Precision={P:.2f}  Recall={R:.2f}  FP-rate={FP/(FP+TN) if FP+TN else 0:.2f}")

    if args.out:
        import json
        out = {
            "tool": "GraphQLer",
            "source": "GraphQLer Zenodo artifact (record 22051026), rq2/graphqler detections, "
                      "scored with PrediQL's scorer against the identical ground truth.",
            "scored_apps": sorted(apps),
            "apps": apps,
            "aggregate": {
                "tp": T, "fp": FP, "fn": FN, "tn": TN,
                "precision": P, "recall": R,
                "fp_rate": (FP / (FP + TN) if FP + TN else None),
            },
        }
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(out, indent=2))
        print(f"\nwrote {args.out}")


def _f(v):
    return f"{v:.2f}" if isinstance(v, (int, float)) else "  — "


def _pct(v):
    return f"{v:.2f}" if isinstance(v, (int, float)) else "—"


if __name__ == "__main__":
    main()
