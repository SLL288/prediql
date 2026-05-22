"""
Aggregate LLM usage and wall-clock cost for one PrediQL API run.

Token counts are recorded by ``get_llm_model`` (and should reflect provider
responses when available, else char-based estimates).
"""

from __future__ import annotations

import csv
import os
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, DefaultDict, Dict

from tabulate import tabulate

from config import Config


@dataclass
class RunCostState:
    llm_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    llm_wall_seconds: float = 0.0
    by_node_input: DefaultDict[str, int] = field(default_factory=lambda: defaultdict(int))
    by_node_output: DefaultDict[str, int] = field(default_factory=lambda: defaultdict(int))
    by_node_wall: DefaultDict[str, float] = field(default_factory=lambda: defaultdict(float))


_STATE = RunCostState()


def _resolve_model_pricing() -> tuple[float, float, str]:
    """
    Resolve per-1M token rates for the active ``Config.PRIMARY_LLM_MODEL``.

    Priority:
    1) Exact key match in ``Config.LLM_MODEL_PRICING_PER_1M``.
    2) Longest prefix key match (case-insensitive).
    3) Fallback to ``Config.LLM_USD_PER_MILLION_*``.
    """
    model = str(getattr(Config, "PRIMARY_LLM_MODEL", "") or "").strip().lower()
    raw_map = getattr(Config, "LLM_MODEL_PRICING_PER_1M", {}) or {}

    parsed: dict[str, tuple[float, float]] = {}
    if isinstance(raw_map, dict):
        for k, v in raw_map.items():
            try:
                if isinstance(v, (list, tuple)) and len(v) == 2:
                    parsed[str(k).strip().lower()] = (float(v[0]), float(v[1]))
            except Exception:
                continue

    if model and model in parsed:
        inp, out = parsed[model]
        return inp, out, f"model-map:{model} (exact)"

    best_prefix = ""
    for key in parsed.keys():
        if model.startswith(key) and len(key) > len(best_prefix):
            best_prefix = key
    if best_prefix:
        inp, out = parsed[best_prefix]
        return inp, out, f"model-map:{best_prefix} (prefix for {model})"

    inp = float(getattr(Config, "LLM_USD_PER_MILLION_INPUT_TOKENS", 0.0))
    out = float(getattr(Config, "LLM_USD_PER_MILLION_OUTPUT_TOKENS", 0.0))
    ref = str(getattr(Config, "LLM_COST_PRICING_REFERENCE", "") or "config-fallback")
    return inp, out, f"fallback:{ref}"


def reset_run_cost_tracker() -> None:
    global _STATE
    _STATE = RunCostState()


def record_llm_usage(
    prompt_tokens: int,
    completion_tokens: int,
    wall_seconds: float,
    node_label: str = "",
) -> None:
    """Called after each successful LLM completion."""
    _STATE.llm_calls += 1
    pt = max(0, int(prompt_tokens or 0))
    ct = max(0, int(completion_tokens or 0))
    _STATE.input_tokens += pt
    _STATE.output_tokens += ct
    _STATE.llm_wall_seconds += max(0.0, float(wall_seconds or 0.0))
    label = (node_label or "").strip() or "_unlabeled"
    _STATE.by_node_input[label] += pt
    _STATE.by_node_output[label] += ct
    _STATE.by_node_wall[label] += max(0.0, float(wall_seconds or 0.0))


def estimate_usd(input_tokens: int, output_tokens: int) -> float:
    """USD from resolved per-million-token rates for active model."""
    inp, out, _ = _resolve_model_pricing()
    return (input_tokens / 1_000_000.0) * inp + (output_tokens / 1_000_000.0) * out


def get_run_cost_snapshot() -> Dict[str, Any]:
    s = _STATE
    total_tok = s.input_tokens + s.output_tokens
    usd_in, usd_out, pricing_ref = _resolve_model_pricing()
    return {
        "llm_calls": s.llm_calls,
        "input_tokens": s.input_tokens,
        "output_tokens": s.output_tokens,
        "total_tokens": total_tok,
        "llm_wall_seconds": round(s.llm_wall_seconds, 3),
        "estimated_usd": round(estimate_usd(s.input_tokens, s.output_tokens), 6),
        "pricing_model_label": pricing_ref,
        "usd_per_million_input": usd_in,
        "usd_per_million_output": usd_out,
        "by_node": {
            n: {
                "input_tokens": s.by_node_input[n],
                "output_tokens": s.by_node_output[n],
                "llm_wall_seconds": round(s.by_node_wall[n], 3),
                "estimated_usd": round(
                    estimate_usd(s.by_node_input[n], s.by_node_output[n]), 6
                ),
            }
            for n in sorted(set(s.by_node_input.keys()) | set(s.by_node_output.keys()))
        },
    }


def write_cost_tables(
    output_dir: str,
    main_wall_seconds: float,
    run_started_at: str,
    run_ended_at: str,
) -> tuple[str, str]:
    """
    Write ``cost_table_run.csv`` (single run summary) and ``cost_table_by_node.csv``.

    Returns (run_csv_path, by_node_csv_path).
    """
    os.makedirs(output_dir, exist_ok=True)
    snap = get_run_cost_snapshot()
    run_path = os.path.join(output_dir, "cost_table_run.csv")
    node_path = os.path.join(output_dir, "cost_table_by_node.csv")

    usd_in = snap["usd_per_million_input"]
    usd_out = snap["usd_per_million_output"]

    with open(run_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "run_started_at",
                "run_ended_at",
                "main_wall_clock_seconds",
                "llm_wall_clock_seconds",
                "llm_calls",
                "total_input_tokens",
                "total_output_tokens",
                "total_tokens",
                "pricing_reference",
                "usd_per_million_input",
                "usd_per_million_output",
                "estimated_usd_total",
            ],
        )
        w.writeheader()
        w.writerow(
            {
                "run_started_at": run_started_at,
                "run_ended_at": run_ended_at,
                "main_wall_clock_seconds": f"{main_wall_seconds:.3f}",
                "llm_wall_clock_seconds": f"{snap['llm_wall_seconds']:.3f}",
                "llm_calls": snap["llm_calls"],
                "total_input_tokens": snap["input_tokens"],
                "total_output_tokens": snap["output_tokens"],
                "total_tokens": snap["total_tokens"],
                "pricing_reference": snap["pricing_model_label"],
                "usd_per_million_input": usd_in,
                "usd_per_million_output": usd_out,
                "estimated_usd_total": f"{snap['estimated_usd']:.6f}",
            }
        )

    with open(node_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "node",
                "input_tokens",
                "output_tokens",
                "total_tokens",
                "llm_wall_seconds",
                "estimated_usd",
            ],
        )
        w.writeheader()
        for node, row in snap["by_node"].items():
            w.writerow(
                {
                    "node": node,
                    "input_tokens": row["input_tokens"],
                    "output_tokens": row["output_tokens"],
                    "total_tokens": row["input_tokens"] + row["output_tokens"],
                    "llm_wall_seconds": f"{row['llm_wall_seconds']:.3f}",
                    "estimated_usd": f"{row['estimated_usd']:.6f}",
                }
            )

    print(f"\n✅ Cost table (run): {run_path}")
    print(f"✅ Cost table (by node): {node_path}")

    rows = [
        ["Main wall-clock (seconds)", f"{main_wall_seconds:.3f}"],
        ["LLM wall-clock sum (seconds)", f"{snap['llm_wall_seconds']:.3f}"],
        ["LLM calls", snap["llm_calls"]],
        ["Total input tokens", snap["input_tokens"]],
        ["Total output tokens", snap["output_tokens"]],
        ["Total tokens", snap["total_tokens"]],
        ["Pricing reference", snap["pricing_model_label"]],
        [f"USD / 1M input (Config)", usd_in],
        [f"USD / 1M output (Config)", usd_out],
        ["Estimated USD total", f"{snap['estimated_usd']:.6f}"],
    ]
    if usd_in == 0 and usd_out == 0:
        rows.append(
            [
                "Note",
                "LLM_USD_PER_* are 0 in config (typical for local Ollama). Set rates in config.py for paid API estimates.",
            ]
        )
    print(tabulate(rows, headers=["Metric", "Value"], tablefmt="grid"))

    return run_path, node_path
