"""Command-line entry point.

Only commands whose steps exist are exposed. A subcommand that would print
"not implemented" is worse than its absence: it suggests a capability the
pipeline does not have.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from prediql.engine import provenance
from prediql.engine.config import Budgets, Identity, Limits, RunConfig, Strategy
from prediql.engine.stepgraph import MODES


def _parse_identities(values: list[str] | None) -> tuple[Identity, ...]:
    """Parse ``name[:role][=Header: value]`` specifications.

    Examples::

        --identity anon:anonymous
        --identity user='Authorization: Bearer abc'
    """
    identities: list[Identity] = []
    for raw in values or []:
        spec, _, header = raw.partition("=")
        name, _, role = spec.partition(":")
        headers: dict[str, str] = {}
        if header:
            key, _, value = header.partition(":")
            headers[key.strip()] = value.strip()
        identities.append(Identity(name=name.strip(), role=(role or "user").strip(),
                                   headers=headers))
    return tuple(identities)


def _parse_auth_args(values: list[str] | None) -> dict[str, str]:
    """Parse ``NAME=VALUE`` authenticated-scan credentials into a mapping.

    ``--auth-arg username=admin --auth-arg password=changeme`` →
    ``{"username": "admin", "password": "changeme"}``.
    """
    out: dict[str, str] = {}
    for raw in values or []:
        name, sep, value = raw.partition("=")
        if not sep or not name.strip():
            raise ValueError(f"--auth-arg expects NAME=VALUE, got {raw!r}")
        out[name.strip()] = value
    return out


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="predql", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Execute a run")
    run.add_argument("--target", required=True, help="GraphQL endpoint URL")
    run.add_argument("--alias", help="Friendly name for this target (used in the run directory)")
    run.add_argument("--trial", type=int, default=1, help="Replicate index (default 1)")
    run.add_argument("--trials", type=int, help="Run trials 1..N sequentially")
    run.add_argument("--mode", default="coverage", choices=sorted(MODES))
    run.add_argument("--steps", help="Comma-separated step override")
    run.add_argument("--force-step", help="Re-run this step and its dependents")
    run.add_argument("--runs-root", default="runs", type=Path)
    run.add_argument("--rounds", type=int, default=3)
    run.add_argument("--requests", type=int, default=10,
                     help="HTTP requests per operation per round")
    run.add_argument("--depth", type=int, default=5,
                     help="Depth bound D for the field-coverage denominator")
    run.add_argument("--seed", type=int, default=42)
    run.add_argument("--arms", default="", help="Ablation arms: +HierMAB (hierarchical bandit), +RandomArm (no bandit, uniform control), +NoBucket (no value reuse), +NoFeedback (no self-correction), +Base (minimal-prompt LLM: one fixed arm, no value reuse, no self-correction, no seed/fallback). Default = Thompson bandit + value reuse + self-correction.")
    run.add_argument("--judge-samples", type=int, default=1,
                     help="LLM-judge samples per potential (>1 = ensemble)")
    run.add_argument("--max-operations", type=int, help="Cap operations covered (large schemas)")
    run.add_argument("--families", help="Comma-separated probe families to run in isolation "
                     "(e.g. sqli,ssrf); default = all applicable")
    run.add_argument("--identity", action="append", help="name[:role][='Header: value']")
    run.add_argument("--budget-tokens", type=int)
    run.add_argument("--budget-usd", type=float)
    run.add_argument("--max-http", type=int, default=8)
    run.add_argument("--max-llm", type=int, default=4)
    run.add_argument("--request-timeout", type=float, default=120.0)
    run.add_argument("--delay-ms", type=int, default=1)
    run.add_argument("--provider", action="append", metavar="ROLE=VENDOR:MODEL",
                     help="Provider per role, e.g. generator=zai:glm-5.3-flash (repeatable)")
    run.add_argument("--api-key", help="Override LLM_API_KEY from .env")
    run.add_argument("--model-price", action="append", metavar="VENDOR:MODEL=IN,OUT",
                     help="USD per 1M tokens for a model absent from the catalog (repeatable)")
    run.add_argument("--allow-destructive", action="store_true",
                     help="Permit DELETE mutations (UAF chains); off by default")
    run.add_argument("--truth", help="Ground-truth YAML (enables the score step)")
    run.add_argument("--oob-host", help="Host the target uses to reach the OOB collaborator (e.g. host.docker.internal); enables SSRF + blind OS-command")
    run.add_argument("--auth-arg", action="append", metavar="NAME=VALUE",
                     help="Authenticated-scan credential: a known argument value the probe "
                          "supplies for a matching non-injected required argument so it can "
                          "pass a resolver gate (e.g. --auth-arg username=admin --auth-arg "
                          "password=changeme). Repeatable. Values stay out of run signatures.")
    run.add_argument("--json", action="store_true", help="Emit the report as JSON")
    run.add_argument("--require-clean", action="store_true",
                     help="Refuse to run with uncommitted engine changes (use for paper runs)")

    show = sub.add_parser("show", help="Summarize a finished run")
    show.add_argument("run_id")
    show.add_argument("--runs-root", default="runs", type=Path)
    show.add_argument("--artifact", help="Print one artifact instead of the summary")

    steps = sub.add_parser("steps", help="List steps and modes")
    steps.add_argument("--mode", help="Show one mode's step list")

    score = sub.add_parser("score", help="Score a finished run against ground truth")
    score.add_argument("run_id")
    score.add_argument("--truth", required=True, help="Ground-truth YAML file")
    score.add_argument("--operations", help="Comma-separated subset to score (partial)")
    score.add_argument("--runs-root", default="runs", type=Path)

    truth = sub.add_parser("truth", help="Ground-truth file management")
    truth.add_argument("action", choices=["certify"])
    truth.add_argument("--truth", required=True, help="Ground-truth YAML file")
    truth.add_argument("--run", help="Run whose introspected schema the labels describe "
                                      "(pins the schema fingerprint)")
    truth.add_argument("--runs-root", default="runs", type=Path)

    report = sub.add_parser("report", help="(Re)render a finished run's reports")
    report.add_argument("run_id")
    report.add_argument("--runs-root", default="runs", type=Path)
    return parser


def _config_from_args(args: argparse.Namespace) -> RunConfig:
    arms = tuple(a.strip() for a in args.arms.split(",") if a.strip())
    providers: dict[str, str] = {}
    for item in getattr(args, "provider", None) or []:
        role, _, spec = item.partition("=")
        providers[role.strip()] = spec.strip()
    prices: dict[str, tuple[float, float]] = {}
    for item in getattr(args, "model_price", None) or []:
        ref, _, rate = item.partition("=")
        parts = rate.split(",")
        if len(parts) == 2:
            prices[ref.strip()] = (float(parts[0]), float(parts[1]))
    return RunConfig(
        target_url=args.target,
        alias=getattr(args, "alias", "") or "",
        trial=getattr(args, "trial", 1),
        mode=args.mode,
        allow_destructive=getattr(args, "allow_destructive", False),
        providers=providers,
        model_prices=prices,
        truth_path=getattr(args, "truth", None),
        oob_host=getattr(args, "oob_host", None),
        auth_args=_parse_auth_args(getattr(args, "auth_arg", None)),
        code_version=provenance.code_version(),
        steps=tuple(s.strip() for s in args.steps.split(",")) if args.steps else (),
        identities=_parse_identities(args.identity),
        families=tuple(f.strip() for f in args.families.split(",") if f.strip())
                 if getattr(args, "families", None) else (),
        limits=Limits(
            max_http=args.max_http,
            max_llm=args.max_llm,
            request_timeout=args.request_timeout,
            delay_ms=args.delay_ms,
        ),
        budgets=Budgets(max_tokens=args.budget_tokens, max_usd=args.budget_usd),
        strategy=Strategy(
            arms=arms,
            rounds=args.rounds,
            requests_per_operation=args.requests,
            seed=args.seed,
            coverage_depth=args.depth,
            judge_samples=getattr(args, "judge_samples", 1),
            max_operations=getattr(args, "max_operations", None),
        ),
    )


def _cmd_run(args: argparse.Namespace) -> int:
    import os

    from prediql.providers.env import API_KEY_VAR, load_dotenv
    from prediql.runner import execute

    load_dotenv()
    if getattr(args, "api_key", None):
        os.environ[API_KEY_VAR] = args.api_key
    if getattr(args, "require_clean", False) and provenance.is_dirty():
        dirty = ", ".join(provenance.collect()["dirty_files"])
        print(f"refusing to run: uncommitted engine changes ({dirty}). "
              "Commit them, or drop --require-clean.", file=sys.stderr)
        return 2
    config = _config_from_args(args)
    force = {args.force_step} if args.force_step else None

    # --trials N runs replicates 1..N sequentially (repeated trials for variance,
    # docs/09 §6). Sequential, not parallel: concurrent runs contend for the same
    # target and distort the latency baselines the oracles depend on.
    trials = getattr(args, "trials", None)
    if trials and trials > 1:
        reports = []
        for index in range(1, trials + 1):
            trial_config = config.with_(trial=index)
            print(f"\n=== trial {index}/{trials} ===")
            reports.append(asyncio.run(
                execute(trial_config, runs_root=args.runs_root, force=force)))
            _print_report(reports[-1], args)
        ok = all(r.ok for r in reports)
        print(f"\n{sum(r.ok for r in reports)}/{trials} trials succeeded")
        return 0 if ok else 1

    report = asyncio.run(execute(config, runs_root=args.runs_root, force=force))

    _print_report(report, args)
    return 0 if report.ok else 1


def _print_report(report, args: argparse.Namespace) -> None:
    if args.json:
        print(json.dumps({
            "run_id": report.run_id,
            "ok": report.ok,
            "stopped_reason": report.stopped_reason,
            "steps": [
                {"name": s.name, "outcome": str(s.outcome), "seconds": round(s.seconds, 2),
                 "note": s.note, "metrics": s.metrics, "error": s.error}
                for s in report.steps
            ],
            "budget": report.budget,
        }, indent=2))
    else:
        print(f"\nrun {report.run_id}")
        print(f"  {args.runs_root / report.run_id}\n")
        for step in report.steps:
            mark = {"ok": "OK  ", "skipped": "SKIP", "failed": "FAIL"}[str(step.outcome)]
            print(f"  [{mark}] {step.name:<16} {step.seconds:6.2f}s  {step.note or ''}")
            if step.error:
                print(f"         {step.error.splitlines()[0]}")
        total = report.budget.get("total", {})
        print(f"\n  stopped: {report.stopped_reason}")
        print(f"  tokens:  {total.get('total_tokens', 0)}   usd: {total.get('usd', 0)}")


def _cmd_show(args: argparse.Namespace) -> int:
    run_dir = Path(args.runs_root) / args.run_id
    if not run_dir.exists():
        print(f"no such run: {run_dir}", file=sys.stderr)
        return 1
    if args.artifact:
        path = run_dir / "artifacts" / f"{args.artifact}.json"
        if not path.exists():
            available = sorted(p.stem for p in (run_dir / "artifacts").glob("*.json"))
            print(f"no artifact {args.artifact!r}; available: {', '.join(available)}",
                  file=sys.stderr)
            return 1
        print(path.read_text(encoding="utf-8"))
        return 0

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    print(f"run {manifest['run_id']}")
    print(f"  target: {manifest['config']['target']}")
    print(f"  mode:   {manifest['config']['mode']}")
    print(f"  plan:   {' -> '.join(manifest.get('plan', []))}")
    coverage_path = run_dir / "artifacts" / "coverage.json"
    if coverage_path.exists():
        cov = json.loads(coverage_path.read_text(encoding="utf-8"))
        print(f"\n  operation coverage: {cov['operation_coverage']:.1%} "
              f"({cov['operations_covered']}/{cov['operations_total']})")
        print(f"  element coverage:   {cov['element_coverage']:.1%} "
              f"({cov['elements_covered']}/{cov['elements_total']} Type.field pairs)")
        print(f"  field-path coverage:{cov['field_path_coverage']:.2%} "
              f"({cov['field_paths_covered']}/{cov['field_paths_reachable']} at depth {cov['depth']})")

    findings_path = run_dir / "artifacts" / "findings.json"
    if findings_path.exists():
        data = json.loads(findings_path.read_text(encoding="utf-8"))
        print(f"\n  findings: {data['confirmed']} confirmed, {data['potential']} potential")
        for finding in data["findings"]:
            mark = "CONFIRMED" if finding["state"] == "confirmed" else "potential"
            print(f"    [{mark:<9}] {finding['severity']:<8} {finding['class']:<22} "
                  f"{finding['operation']}")
            matched = finding.get("witness", {}).get("matched", "")
            if matched:
                print(f"                {matched[:88]}")
    return 0


def _cmd_steps(args: argparse.Namespace) -> int:
    import prediql.engine.steps  # noqa: F401
    from prediql.engine.stepgraph import STEP_REGISTRY

    if args.mode:
        print(" -> ".join(MODES[args.mode]))
        return 0
    print("steps:")
    for name, cls in sorted(STEP_REGISTRY.items()):
        needs = ", ".join(sorted(cls.requires)) or "-"
        gives = ", ".join(sorted(cls.produces)) or "-"
        print(f"  {name:<16} requires[{needs}]  produces[{gives}]")
    print("\nmodes:")
    for name, steps in sorted(MODES.items()):
        print(f"  {name:<12} {' -> '.join(steps)}")
    return 0


def _cmd_score(args: argparse.Namespace) -> int:
    from prediql.engine.config import RunConfig
    from prediql.runner import execute

    run_dir = Path(args.runs_root) / args.run_id
    if not run_dir.exists():
        print(f"no such run: {run_dir}", file=sys.stderr)
        return 1
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    config = RunConfig(target_url=manifest["config"]["target"], mode="score",
                       truth_path=args.truth)
    operations = [o.strip() for o in args.operations.split(",")] if args.operations else None
    report = asyncio.run(execute(config, runs_root=args.runs_root, truth_path=args.truth,
                                 score_operations=operations, force={"score"},
                                 run_id=args.run_id))
    print((run_dir / "score.md").read_text(encoding="utf-8") if (run_dir / "score.md").exists()
          else f"score: {report.stopped_reason}")
    return 0 if report.ok else 1


def _cmd_truth(args: argparse.Namespace) -> int:
    from prediql.scoring.groundtruth import certify, load

    if args.action == "certify":
        from prediql.engine.fingerprint import fingerprint
        from prediql.scoring.groundtruth import GroundTruthError

        schema_fp = None
        if args.run:
            schema_file = Path(args.runs_root) / args.run / "artifacts" / "schema.normalized.json"
            if not schema_file.exists():
                print(f"no schema artifact in run {args.run}: {schema_file}", file=sys.stderr)
                return 1
            schema_fp = fingerprint(json.loads(schema_file.read_text(encoding="utf-8")))
        before = load(args.truth)
        try:
            certified = certify(args.truth, schema_fingerprint=schema_fp)
        except GroundTruthError as exc:
            print(f"not certified: {exc}", file=sys.stderr)
            return 1
        print(f"certified {certified.slug}: {before.certification_status()} -> "
              f"{certified.certification_status()}")
        print(f"  content_hash: {certified.content_hash}")
        print(f"  schema_fingerprint: {certified.schema_fingerprint}")
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    from prediql.engine.config import RunConfig
    from prediql.runner import execute

    run_dir = Path(args.runs_root) / args.run_id
    if not run_dir.exists():
        print(f"no such run: {run_dir}", file=sys.stderr)
        return 1
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    config = RunConfig(target_url=manifest["config"]["target"], mode="report")
    report = asyncio.run(execute(config, runs_root=args.runs_root, force={"report"},
                                 run_id=args.run_id))
    formats = (run_dir / "report")
    print(f"wrote {', '.join(sorted(p.name for p in formats.iterdir()))}"
          if formats.exists() else f"report: {report.stopped_reason}")
    return 0 if report.ok else 1


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    handler = {"run": _cmd_run, "show": _cmd_show, "steps": _cmd_steps,
               "score": _cmd_score, "truth": _cmd_truth, "report": _cmd_report}[args.command]
    return handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
