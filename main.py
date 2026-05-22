import argparse
import os
import sys
import json
import subprocess
import requests
from urllib.parse import urlparse
from config import Config, configure_run_artifacts, run_node_dir

from graphql_send_payload import (
    send_payload,
    is_successful_graphql_response,
    normalize_vulnerability_type,
)
from ollama_runtime import ensure_ollama_running

from compiled_nodes_reader import getnodefromcompiledfile

from parse_endpoint_results import ParseEndpointResults, loadjsonfile, embedding

from tabulate import tabulate
import shutil
import yaml

from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

import time
import random
from datetime import datetime
from load_introspection.load_snippet import get_node_info

from embed_retrieve.retrieve_from_index import search, MissingEmbeddingIndexError
from embed_retrieve.embed_and_index import embed_real_data



from save_real_data import flatten_real_data

from simple_vulnerability_detector import SimpleVulnerabilityDetector
from dual_vulnerability_detector import DualVulnerabilityDetector

from collections import defaultdict, deque
import csv

from llm_graphql_prompts import (
    prompt_llm_with_context,
    append_run_prompt_log_csv,
    compact_newly_processed_meta,
)

import numpy as np
from delta_coverage import compute_delta_coverage
from sub_schema_extractor import build_llm_schema_text
from llm_cost_tracker import reset_run_cost_tracker, write_cost_tables
from pipeline_known_good import save_known_good, load_known_good, validate_repeatable_graphql

_REPO_ROOT = os.path.dirname(os.path.abspath(__file__))


def _min_int(minimum: int, name: str):
    def _coerce(value: str) -> int:
        try:
            v = int(value, 10)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"{name} must be an integer (got {value!r})") from exc
        if v < minimum:
            raise argparse.ArgumentTypeError(f"{name} must be >= {minimum} (got {v})")
        return v

    return _coerce


def _graphql_url(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        raise argparse.ArgumentTypeError("--url must be a non-empty string")
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise argparse.ArgumentTypeError(
            f"--url must use http or https (got scheme {parsed.scheme!r})"
        )
    if not parsed.netloc:
        raise argparse.ArgumentTypeError("--url must include a host, e.g. https://api.example.com/graphql")
    return raw


def default_node_stats():
    """Default per-node stats fields (one round or template for errors)."""
    return {
        "requests": 0,
        "token": 0.0,
        "succeed": False,
        "basic_call_success": False,
        "vulnerability_detections": 0,
        "simple_detections": 0,
        "llm_detections": 0,
        "detector_agreement": 0.0,
        "consensus_breakdown": {},
        "simple_potential_detections": 0,
        "llm_potential_detections": 0,
        "potential_agreement": 0.0,
        "potential_consensus_breakdown": {},
        "confirmed_vulnerabilities": 0,
        "potential_vulnerabilities": 0,
        "vulnerability_categories": [],
        "high_severity_vulns": 0,
        "termination_reason": "",
        "termination_detail": "",
        "retrieval_context_error": "",
        "round_index": "",
        "pipeline_mode": "",
        "stage1_coverage_reached": False,
        "stage2_validation_pass": False,
        "stage3_vulnerability_rounds": 0,
        "validation_http_trips": 0,
        "known_good_saved": False,
    }


def extract_known_good_query_text(newly_processed_responses):
    """Return GraphQL source from the first successful response, preferring basic_call."""
    if not newly_processed_responses:
        return None
    preferred = None
    fallback = None
    for p in newly_processed_responses:
        if not is_successful_graphql_response(p):
            continue
        q = p.get("query")
        text = None
        if isinstance(q, dict):
            text = q.get("query")
        elif isinstance(q, str):
            text = q
        if not text:
            continue
        vt = normalize_vulnerability_type(p.get("vulnerability_type"), default="unknown")
        if vt == "basic_call":
            preferred = text
            break
        if fallback is None:
            fallback = text
    return preferred or fallback


def annotate_final_round_outcomes(overall_stats, successful_nodes, all_nodes):
    """After all rounds: mark whether each node ever succeeded or exhausted rounds."""
    for node in all_nodes:
        if node not in overall_stats:
            continue
        if node in successful_nodes:
            overall_stats[node]["final_rounds_outcome"] = "succeeded_before_max_rounds"
        else:
            overall_stats[node]["final_rounds_outcome"] = "exhausted_max_rounds_without_succeed"


def append_all_detector_findings(output_dir, node_name, comparison_results):
    """Append one row per detector finding to a run-wide CSV."""
    if not comparison_results:
        return
    out_path = os.path.join(output_dir, "all_detector_detections_final.csv")
    os.makedirs(output_dir, exist_ok=True)
    fieldnames = [
        "timestamp",
        "node_name",
        "response_status",
        "detector",
        "detection_name",
        "detection",
        "category",
        "description",
        "confidence",
        "comparison_consensus",
        "comparison_agreement",
        "potential_consensus",
        "potential_agreement",
    ]
    exists = os.path.exists(out_path) and os.path.getsize(out_path) > 0
    with open(out_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not exists:
            writer.writeheader()
        for comp in comparison_results:
            c = comp.get("comparison", {}) or {}
            pa = c.get("potential_analysis", {}) or {}
            for detector_name, bucket in (
                ("simple", comp.get("simple_detector", {}) or {}),
                ("llm", comp.get("llm_detector", {}) or {}),
            ):
                for finding in bucket.get("results", []) or []:
                    writer.writerow(
                        {
                            "timestamp": comp.get("timestamp"),
                            "node_name": node_name,
                            "response_status": comp.get("response_status"),
                            "detector": detector_name,
                            "detection_name": finding.get("detection_name", ""),
                            "detection": finding.get("detection", ""),
                            "category": finding.get("category", ""),
                            "description": finding.get("description", ""),
                            "confidence": finding.get("confidence", ""),
                            "comparison_consensus": c.get("consensus", ""),
                            "comparison_agreement": c.get("agreement_score", 0.0),
                            "potential_consensus": pa.get("potential_consensus", ""),
                            "potential_agreement": pa.get("potential_agreement_score", 0.0),
                        }
                    )


def log_stats_to_csv(stats, output_path):
    """Write flattened node stats including termination fields (UTF-8 CSV)."""
    if not stats:
        print("⚠️ log_stats_to_csv: no stats to write")
        return
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    fieldnames = [
        "Node",
        "RoundIndex",
        "Requests",
        "Tokens",
        "Succeed",
        "BasicCallSuccess",
        "TotalVulns",
        "SimpleDet",
        "LLMDet",
        "Agreement",
        "SimplePot",
        "LLMPot",
        "PotAgreement",
        "Confirmed",
        "Potential",
        "HighSeverity",
        "Categories",
        "Consensus",
        "TerminationReason",
        "TerminationDetail",
        "RetrievalContextError",
        "FinalRoundsOutcome",
        "PipelineMode",
        "Stage1Coverage",
        "Stage2Validation",
        "Stage3VulnRounds",
        "ValidationHttpTrips",
        "KnownGoodSaved",
    ]
    rows = []
    for node, values in stats.items():
        categories = ", ".join(values.get("vulnerability_categories", [])) if values.get("vulnerability_categories") else "None"
        consensus = values.get("consensus_breakdown", {}) or {}
        consensus_str = ", ".join(f"{k}:{v}" for k, v in consensus.items()) if consensus else "None"
        rows.append({
            "Node": node,
            "RoundIndex": values.get("round_index", ""),
            "Requests": values.get("requests", 0),
            "Tokens": values.get("token", 0.0),
            "Succeed": values.get("succeed", False),
            "BasicCallSuccess": values.get("basic_call_success", False),
            "TotalVulns": values.get("vulnerability_detections", 0),
            "SimpleDet": values.get("simple_detections", 0),
            "LLMDet": values.get("llm_detections", 0),
            "Agreement": values.get("detector_agreement", 0.0),
            "SimplePot": values.get("simple_potential_detections", 0),
            "LLMPot": values.get("llm_potential_detections", 0),
            "PotAgreement": values.get("potential_agreement", 0.0),
            "Confirmed": values.get("confirmed_vulnerabilities", 0),
            "Potential": values.get("potential_vulnerabilities", 0),
            "HighSeverity": values.get("high_severity_vulns", 0),
            "Categories": categories,
            "Consensus": consensus_str,
            "TerminationReason": values.get("termination_reason", ""),
            "TerminationDetail": values.get("termination_detail", ""),
            "RetrievalContextError": values.get("retrieval_context_error", ""),
            "FinalRoundsOutcome": values.get("final_rounds_outcome", ""),
            "PipelineMode": values.get("pipeline_mode", ""),
            "Stage1Coverage": values.get("stage1_coverage_reached", False),
            "Stage2Validation": values.get("stage2_validation_pass", False),
            "Stage3VulnRounds": values.get("stage3_vulnerability_rounds", 0),
            "ValidationHttpTrips": values.get("validation_http_trips", 0),
            "KnownGoodSaved": values.get("known_good_saved", False),
        })
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"\n✅ Final stats CSV written to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="PrediQL: LLM-guided GraphQL fuzzing and vulnerability analysis.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog=(
            "Example:\n  python main.py --url https://example.com/graphql --requests 5 --rounds 2"
        ),
    )
    parser.add_argument(
        "--url",
        type=_graphql_url,
        required=True,
        metavar="URL",
        help="GraphQL HTTP(S) endpoint (POST with JSON {\"query\": ...})",
    )
    parser.add_argument(
        "--requests",
        type=_min_int(1, "--requests"),
        required=True,
        metavar="N",
        help="Per-node request budget in round 1 (multiplied by round index each round)",
    )
    parser.add_argument(
        "--rounds",
        type=_min_int(1, "--rounds"),
        required=True,
        metavar="R",
        help="Number of fuzzing rounds",
    )
    parser.add_argument(
        "--graphql-api-key",
        default=None,
        metavar="TOKEN",
        help="Optional secret for the target GraphQL API (sent as Authorization; raw token becomes Bearer).",
    )
    parser.add_argument(
        "--llm-api-url",
        default=None,
        metavar="URL",
        help="Optional override for the primary LLM chat HTTP endpoint (Ollama-compatible /api/chat).",
    )
    parser.add_argument(
        "--llm-model",
        default=None,
        metavar="NAME",
        help="Optional override for the primary LLM model name.",
    )
    parser.add_argument(
        "--llm-api-key",
        default=None,
        metavar="TOKEN",
        help="Optional secret for the LLM HTTP API (Authorization header; raw token becomes Bearer).",
    )
    parser.add_argument(
        "--llm-temperature",
        type=float,
        default=0.0,
        metavar="T",
        help="LLM sampling temperature in chat JSON (default 0).",
    )
    parser.add_argument(
        "--thompson-seed",
        type=int,
        default=42,
        metavar="N",
        help="RNG seed for Thompson arm sampling (default 42).",
    )

    args = parser.parse_args()

    url = args.url
    requests = args.requests
    rounds = args.rounds
    if args.graphql_api_key is not None and str(args.graphql_api_key).strip():
        Config.AUTHORIZATION = str(args.graphql_api_key).strip()
    if args.llm_api_url is not None:
        Config.PRIMARY_LLM_API_URL = str(args.llm_api_url).strip()
    if args.llm_model is not None and str(args.llm_model).strip():
        Config.PRIMARY_LLM_MODEL = str(args.llm_model).strip()
    if args.llm_api_key is not None and str(args.llm_api_key).strip():
        Config.LLM_API_KEY = str(args.llm_api_key).strip()
    Config.LLM_TEMPERATURE = float(args.llm_temperature)
    Config.THOMPSON_SEED = int(args.thompson_seed)
    set_thompson_seed(Config.THOMPSON_SEED)

    configure_run_artifacts(url, Config.PRIMARY_LLM_MODEL)

    output_folder = Config.OUTPUT_DIR
    # Wipe previous run *before* introspection so we do not delete freshly written YAML/JSON.
    if os.path.exists(output_folder):
        print(f"🗑️  Removing existing folder: {output_folder}")
        shutil.rmtree(output_folder)
    else:
        print(f"✅ No existing folder to remove: {output_folder}")
    os.makedirs(Config.OUTPUT_DIR, exist_ok=True)
    os.makedirs(Config.RUN_LOAD_INTROSPECTION_DIR, exist_ok=True)
    os.makedirs(Config.EMBED_INDEX_DIR, exist_ok=True)

    intro_cmd = [
        sys.executable,
        os.path.join(_REPO_ROOT, "load_introspection", "save_introspection.py"),
        "--url",
        url,
        "--output-file",
        Config.INTROSPECTION_RESULT_JSON,
    ]
    if Config.AUTHORIZATION:
        intro_cmd.extend(["--graphql-api-key", str(Config.AUTHORIZATION)])
    load_intro_cmd = [
        sys.executable,
        os.path.join(_REPO_ROOT, "load_introspection", "load_introspection.py"),
        "--introspection-json",
        Config.INTROSPECTION_RESULT_JSON,
        "--yaml-output-dir",
        Config.RUN_LOAD_INTROSPECTION_DIR,
    ]
    try:
        subprocess.run(
            intro_cmd,
            check=True,
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            load_intro_cmd,
            check=True,
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        print(f"❌ Introspection pipeline failed (exit {e.returncode}). Command: {e.cmd}")
        if e.stdout:
            print("--- stdout ---\n", e.stdout, sep="")
        if e.stderr:
            print("--- stderr ---\n", e.stderr, sep="")
        sys.exit(e.returncode if e.returncode else 1)

    index_dir = Config.EMBED_INDEX_DIR
    if os.path.exists(index_dir):
        print(f"🗑️  Removing existing folder: {index_dir}")
        shutil.rmtree(index_dir)
    else:
        print(f"✅ No existing folder to remove: {index_dir}")
    generated_query_info_file = Config.GENERATED_QUERY_INFO_JSON
    real_data = Config.REAL_DATA_JSON
    errors = Config.ERRORS_CSV

    if os.path.exists(generated_query_info_file):
        os.remove(generated_query_info_file)
    else:
        print(f"No existing folder to remove: {generated_query_info_file}")
    if os.path.exists(real_data):
        os.remove(real_data)
    else:
        print(f"No existing folder to remove: {real_data}")
    if os.path.exists(errors):
        os.remove(errors)
    else:
        print(f"No existing folder to remove: {errors}")
    try:
        nodes = getnodefromcompiledfile()
    except FileNotFoundError as e:
        print(f"❌ Missing YAML node lists (run introspection scripts first): {e}")
        sys.exit(2)
    except Exception as e:
        print(f"❌ Failed to load node list from load_introspection/*.yml: {e}")
        sys.exit(2)

    if nodes is None or getattr(nodes, "empty", False) or "Node" not in getattr(nodes, "columns", []):
        print("❌ No GraphQL nodes found in load_introspection/query_parameter_list.yml / mutation_parameter_list.yml.")
        sys.exit(2)

    from save_query_info import save_query_info

    save_query_info()

    reset_run_cost_tracker()
    run_started_at = datetime.now().isoformat()
    run_wall_t0 = time.perf_counter()

    _ollama_model = (getattr(Config, "PRIMARY_LLM_MODEL", None) or "llama3").strip() or "llama3"
    ensure_ollama_running(_ollama_model)
    stats_allrounds = {}
    run_all_nodes(url, nodes['Node'], requests, rounds, stats_allrounds)
    generate_vulnerability_summary_report(stats_allrounds)

    run_ended_at = datetime.now().isoformat()
    main_wall_seconds = time.perf_counter() - run_wall_t0
    write_cost_tables(Config.OUTPUT_DIR, main_wall_seconds, run_started_at, run_ended_at)

    _sub_env = os.environ.copy()
    _sub_env["PREDIQL_OUTPUT_DIR"] = Config.OUTPUT_DIR
    for script in ("reorganize_json_records.py", "analysis_prediql.py"):
        path = os.path.join(_REPO_ROOT, script)
        try:
            subprocess.run(
                [sys.executable, path],
                check=True,
                cwd=_REPO_ROOT,
                capture_output=True,
                text=True,
                env=_sub_env,
            )
        except subprocess.CalledProcessError as e:
            print(f"⚠️ Post-run script failed: {script} (exit {e.returncode})")
            if e.stderr:
                print(e.stderr)



def run_all_nodes(url, nodes, max_requests, rounds, stats_allrounds):
    successful_nodes = set()

    for i in range(1, rounds + 1):
        print(f"\n{'=' * 60}\nRound {i}/{rounds} — per-node request budget = max_requests × round = {max_requests * i}\n{'=' * 60}")
        all_stats = {}
        for node in nodes:
            if node in successful_nodes:
                print(f"⏭️  Skipping {node} - already succeeded in a previous round")
                continue

            print(f"\n── Node: {node} (round {i}) ──")
            try:
                result = process_node(url, node, max_requests * i, round_index=i)
            except Exception as e:
                print(f"❌ Uncaught error processing node {node} in round {i}: {e}")
                result = {node: default_node_stats()}
                result[node]["termination_reason"] = "process_node_uncaught_error"
                result[node]["termination_detail"] = repr(e)
                result[node]["round_index"] = i
            all_stats.update(result)

            if result.get(node, {}).get("succeed", False):
                successful_nodes.add(node)
                print(f"✅ {node} succeeded in round {i} - will be skipped in future rounds")
        log_to_table(all_stats, Config.OUTPUT_DIR + f"/stats_table_round_{i}.txt")
        try:
            data_length = flatten_real_data()
            if data_length > 0:
                embed_real_data()
        except json.JSONDecodeError:
                print(f"⚠️ cannot process embedding")
        print(all_stats)
        write_to_all_rounds(stats_allrounds, all_stats)
        log_to_table(stats_allrounds, Config.OUTPUT_DIR + "/stats_table_allrounds.txt")

    annotate_final_round_outcomes(stats_allrounds, successful_nodes, nodes)
    final_csv = os.path.join(Config.OUTPUT_DIR, "node_stats_final.csv")
    log_stats_to_csv(stats_allrounds, final_csv)
    log_to_table(stats_allrounds, Config.OUTPUT_DIR + "/stats_table_allrounds.txt")


def write_to_all_rounds(overall_stats, round_stats):
    for node_name, round_data in round_stats.items():
        if node_name not in overall_stats:
            overall_stats[node_name] = default_node_stats()

        overall_stats[node_name]["requests"] = round_data.get("requests", 0)
        overall_stats[node_name]["token"] += round_data.get("token", 0.0)

        overall_stats[node_name]["succeed"] = (
            overall_stats[node_name]["succeed"] or round_data.get("succeed", False))

        overall_stats[node_name]["basic_call_success"] = (
            overall_stats[node_name]["basic_call_success"] or round_data.get("basic_call_success", False))

        overall_stats[node_name]["vulnerability_detections"] += round_data.get("vulnerability_detections", 0)
        overall_stats[node_name]["simple_detections"] += round_data.get("simple_detections", 0)
        overall_stats[node_name]["llm_detections"] += round_data.get("llm_detections", 0)
        overall_stats[node_name]["simple_potential_detections"] += round_data.get("simple_potential_detections", 0)
        overall_stats[node_name]["llm_potential_detections"] += round_data.get("llm_potential_detections", 0)
        overall_stats[node_name]["potential_agreement"] = round_data.get("potential_agreement", 0.0)
        overall_stats[node_name]["potential_consensus_breakdown"] = round_data.get("potential_consensus_breakdown", {})
        overall_stats[node_name]["confirmed_vulnerabilities"] += round_data.get("confirmed_vulnerabilities", 0)
        overall_stats[node_name]["potential_vulnerabilities"] += round_data.get("potential_vulnerabilities", 0)
        overall_stats[node_name]["high_severity_vulns"] += round_data.get("high_severity_vulns", 0)

        current_agreement = overall_stats[node_name]["detector_agreement"]
        round_agreement = round_data.get("detector_agreement", 0.0)
        if current_agreement == 0.0:
            overall_stats[node_name]["detector_agreement"] = round_agreement
        else:
            overall_stats[node_name]["detector_agreement"] = (current_agreement + round_agreement) / 2

        round_consensus = round_data.get("consensus_breakdown", {})
        existing_consensus = overall_stats[node_name]["consensus_breakdown"]
        for key, value in round_consensus.items():
            existing_consensus[key] = existing_consensus.get(key, 0) + value
        overall_stats[node_name]["consensus_breakdown"] = existing_consensus

        round_categories = round_data.get("vulnerability_categories", [])
        existing_categories = overall_stats[node_name]["vulnerability_categories"]
        overall_stats[node_name]["vulnerability_categories"] = list(set(existing_categories + round_categories))

        overall_stats[node_name]["termination_reason"] = round_data.get("termination_reason", "")
        overall_stats[node_name]["termination_detail"] = round_data.get("termination_detail", "")
        overall_stats[node_name]["retrieval_context_error"] = round_data.get("retrieval_context_error", "")
        overall_stats[node_name]["round_index"] = round_data.get("round_index", "")

        overall_stats[node_name]["pipeline_mode"] = round_data.get("pipeline_mode", "") or overall_stats[node_name].get("pipeline_mode", "")
        overall_stats[node_name]["stage1_coverage_reached"] = (
            overall_stats[node_name].get("stage1_coverage_reached", False)
            or round_data.get("stage1_coverage_reached", False)
        )
        overall_stats[node_name]["stage2_validation_pass"] = (
            overall_stats[node_name].get("stage2_validation_pass", False)
            or round_data.get("stage2_validation_pass", False)
        )
        overall_stats[node_name]["stage3_vulnerability_rounds"] = (
            overall_stats[node_name].get("stage3_vulnerability_rounds", 0)
            + round_data.get("stage3_vulnerability_rounds", 0)
        )
        overall_stats[node_name]["validation_http_trips"] = (
            overall_stats[node_name].get("validation_http_trips", 0)
            + round_data.get("validation_http_trips", 0)
        )
        overall_stats[node_name]["known_good_saved"] = (
            overall_stats[node_name].get("known_good_saved", False)
            or round_data.get("known_good_saved", False)
        )


BETA = defaultdict(lambda: {"alpha": 1.0, "beta": 1.0})
GAMMA = 1.0

# Seeded once for Thompson sampling (``pick_arm_thompson``); lazy-init from ``Config.THOMPSON_SEED``.
_thompson_rng = None


def set_thompson_seed(seed: int) -> None:
    """Reset the Thompson arm sampler RNG (call from ``main`` after CLI / config)."""
    global _thompson_rng
    _thompson_rng = np.random.default_rng(int(seed))


def _thompson_rng_get():
    global _thompson_rng
    if _thompson_rng is None:
        set_thompson_seed(int(getattr(Config, "THOMPSON_SEED", 42)))
    return _thompson_rng


def pick_arm_thompson(node, arms):
    rng = _thompson_rng_get()
    samples = []
    for arm in arms:
        key = (node, arm["name"])
        a, b = BETA[key]["alpha"], BETA[key]["beta"]
        theta = rng.beta(a, b)
        samples.append((theta, arm))
    samples.sort(reverse=True, key=lambda x: x[0])
    return samples[0][1]

def update_bandit(node, arm_name, reward, gamma=GAMMA):
    """Thompson-style Beta update; ``gamma`` down-weights past evidence when < 1."""
    key = (node, arm_name)
    BETA[key]["alpha"] = gamma * BETA[key]["alpha"] + reward
    BETA[key]["beta"]  = gamma * BETA[key]["beta"]  + (1 - reward)


def run_dual_detectors_on_responses(
    node, vuln_detector, newly_processed_responses, https200, run_round_index=None
):
    """Run rule-based + LLM detectors on each non-basic_call response (any HTTP status in the batch)."""
    try:
        if newly_processed_responses:
            all_comparison_results = []
            filtered_responses = [
                r
                for r in newly_processed_responses
                if normalize_vulnerability_type(
                    r.get("vulnerability_type"), default="unknown"
                )
                != "basic_call"
            ]
            basic_call_count = len(newly_processed_responses) - len(filtered_responses)

            print(
                f"🔍 Running dual vulnerability detection on {len(filtered_responses)} newly processed responses "
                f"(skipped {basic_call_count} basic_call) | batch_http200={https200}"
            )

            for ri, response in enumerate(newly_processed_responses, 1):
                if normalize_vulnerability_type(
                    response.get("vulnerability_type"), default="unknown"
                ) == "basic_call":
                    print(f"   Skipping basic_call response {ri}")
                    continue

                comparison_result = vuln_detector.detect_vulnerabilities(
                    response,
                    f"{node}_response_{ri}",
                    artifact_endpoint=node,
                    run_round_index=run_round_index,
                )
                if comparison_result:
                    all_comparison_results.append(comparison_result)

                    simple_count = comparison_result["simple_detector"]["count"]
                    llm_count = comparison_result["llm_detector"]["count"]
                    consensus = comparison_result["comparison"]["consensus"]
                    agreement = comparison_result["comparison"]["agreement_score"]

                    simple_vulnerable = comparison_result["simple_detector"]["vulnerable_count"]
                    simple_potential = comparison_result["simple_detector"]["potential_count"]
                    llm_vulnerable = comparison_result["llm_detector"]["vulnerable_count"]
                    llm_potential = comparison_result["llm_detector"]["potential_count"]
                    potential_consensus = comparison_result["comparison"]["potential_analysis"]["potential_consensus"]
                    potential_agreement = comparison_result["comparison"]["potential_analysis"]["potential_agreement_score"]

                    print(
                        f"   Response {ri}: Simple={simple_count} (V:{simple_vulnerable}, P:{simple_potential}), "
                        f"LLM={llm_count} (V:{llm_vulnerable}, P:{llm_potential})"
                    )
                    print(f"     Consensus: {consensus} (Agreement: {agreement:.2f})")
                    print(f"     Potential: {potential_consensus} (Agreement: {potential_agreement:.2f})")

                    if simple_count > 0:
                        print(f"     Simple Detector:")
                        for vuln in comparison_result["simple_detector"]["results"]:
                            print(f"       - {vuln['detection_name']} ({vuln['detection']}) - {vuln['category']}")

                    if llm_count > 0:
                        print(f"     LLM Detector:")
                        for vuln in comparison_result["llm_detector"]["results"]:
                            print(f"       - {vuln['detection_name']} ({vuln['detection']}) - {vuln['category']}")
                            if "confidence" in vuln:
                                print(f"         Confidence: {vuln['confidence']:.2f}")

            if all_comparison_results:
                print(
                    f"🔍 Dual vulnerability detection completed for {node}: {len(all_comparison_results)} comparisons "
                    f"across {len(filtered_responses)} newly processed responses (skipped {basic_call_count} basic_call)"
                )
            else:
                print(
                    f"✅ No vulnerabilities detected by either detector in {len(filtered_responses)} newly processed "
                    f"responses for {node} (skipped {basic_call_count} basic_call)"
                )
        elif not newly_processed_responses:
            print(f"⏭️ Skipping vulnerability detection for {node} - no newly processed responses")
    except Exception as e:
        print(f"⚠️ Dual vulnerability detection failed for {node}: {e}")


def process_node(url, node, max_request, round_index=None):

    stats = {node: default_node_stats()}
    if round_index is not None:
        stats[node]["round_index"] = round_index

    try:
        input, output, relevant_object, source, node_type = get_node_info(node)
    except ValueError as e:
        msg = str(e)
        stats[node]["termination_reason"] = "node_definition_context_error"
        stats[node]["termination_detail"] = msg
        print(f"❌ get_node_info failed for {node}: {msg}")
        return stats
    except Exception as e:
        stats[node]["termination_reason"] = "node_schema_load_error"
        stats[node]["termination_detail"] = repr(e)
        print(f"❌ Unexpected error loading schema for node {node}: {e}")
        return stats

    totaltoken = 0
    requests = 0
    jsonfile_path = os.path.join(run_node_dir(node), "llama_queries.json")
    vuln_detector = DualVulnerabilityDetector(url)
    top_matches = ""
    # Use "args" wording (not "input") to avoid priming models toward fictitious `input:` wrapper arguments.
    input_args = f"{node}, args: {input}"
    ARM_STATS = defaultdict(lambda: {"succ": 0, "tot": 0})
    FAIL_STREAK = defaultdict(int)   
    covered = False
    ARMS = [
    {"name":"schema_min_known",   "include_schema":True,  "arg_mode":"known",   "depth":1, "top_k":3},
    {"name":"schema_min_real",    "include_schema":True,  "arg_mode":"real",    "depth":1, "top_k":3},
    {"name":"schema_mod_known",   "include_schema":True,  "arg_mode":"known",   "depth":2, "top_k":5},
    {"name":"noschema_min_known", "include_schema":False, "arg_mode":"known",   "depth":1, "top_k":3},
    {"name":"noschema_min_real",  "include_schema":False, "arg_mode":"real",    "depth":1, "top_k":0},
    {"name":"schema_min_nulls",   "include_schema":True,  "arg_mode":"nulls",   "depth":1, "top_k":3},
    {"name":"schema_deep_known",  "include_schema": True,  "arg_mode":"known",   "depth":3, "top_k":5},
    {"name":"schema_deep_real",   "include_schema": True,  "arg_mode":"real",    "depth":3, "top_k":5},
    ]

    max_k_needed = max([arm["top_k"] for arm in ARMS] + [5])

    retrieval_context_error = ""
    try:
        base_query = f"{node}, input: {input}"
        pre_results = search(base_query, top_k=max_k_needed)
        pre_texts = ["{}".format(record["text"]) for score, record in pre_results]
    except MissingEmbeddingIndexError as e:
        print(f"ℹ️ [{node}] {e}")
        pre_texts = []
        # Expected cold-start state before first successful ``flatten_real_data`` + ``embed_real_data``.
        # Keep this informational in console only; do not mark node stats as errored.
        retrieval_context_error = ""
    except Exception as e:
        print(f"⚠️ retrieve error for {node}: {e}")
        pre_texts = []
        retrieval_context_error = repr(e)

    def build_top_matches(k: int) -> str:
        if not k or not pre_texts:
            return ""
        k = min(k, len(pre_texts))
        return "\n".join(pre_texts[:k])


    https200 = False
    basic_call_success = False
    termination_reason = None
    termination_detail = ""
    sequential = bool(getattr(Config, "PIPELINE_SEQUENTIAL_ENABLED", False))
    known_query_text = None
    stage2_validation_pass = False
    validation_http_trips = 0
    stage3_vulnerability_rounds = 0
    stats[node]["pipeline_mode"] = "sequential" if sequential else "combined"
    pline = (
        "sequential: discover → validate → fuzz"
        if sequential
        else "combined: coverage + vulns in one phase"
    )
    print(f"\n▶ [{node}] {pline} | request budget={max_request}")

    prompt_round_seq = 0

    def run_prompt_arm_round(pipeline_stage, known_good_graphql=None, run_vuln=False, update_bandit_after=True):
        """LLM prompt + send batch. Returns False (callers continue until budget / stage caps)."""
        nonlocal totaltoken, requests, https200, basic_call_success, covered
        nonlocal known_query_text, termination_reason, termination_detail
        nonlocal prompt_round_seq
        prompt_round_seq += 1
        arm = pick_arm_thompson(node, ARMS)
        k = arm["top_k"]
        if arm["include_schema"] and FAIL_STREAK[node] >= 2 and k < 5:
            k = 5
        top_matches = build_top_matches(k)
        print(
            f"  [{node}] LLM+send | stage={pipeline_stage} | arm={arm['name']} | "
            f"payload_index={requests} | budget={max_request}"
        )
        if arm["include_schema"]:
            schema_to_use = build_llm_schema_text(
                endpoint=node,
                source=source,
                inputs=input,
                output=output,
                full_relevant_objects=relevant_object,
                selection_depth=arm["depth"],
            )
        else:
            schema_to_use = None

        second_res, token, llm_trace = prompt_llm_with_context(
            top_matches=top_matches,
            endpoint=node,
            schema=schema_to_use,
            input=input_args,
            output=output,
            source=source,
            MAX_REQUESTS=max_request,
            node_type=node_type,
            include_schema=arm["include_schema"],
            arg_mode=arm["arg_mode"],
            depth=arm["depth"],
            n_variants=1,
            pipeline_stage=pipeline_stage,
            known_good_graphql=known_good_graphql,
            run_round_index=round_index,
        )
        totaltoken += token

        queries = second_res.get("query") or []
        mutations = second_res.get("mutation") or []
        parsed_vuln_types = []
        for q in queries:
            if isinstance(q, dict):
                parsed_vuln_types.append(str(q.get("vulnerability_type") or "unknown"))
        for m in mutations:
            if isinstance(m, dict):
                parsed_vuln_types.append(str(m.get("vulnerability_type") or "unknown"))
        parsed_vulnerability_types = ";".join(parsed_vuln_types)
        parse_ok = bool(queries or mutations)

        if not queries and not mutations:
            msg = (
                "Could not parse LLM output into GraphQL operations "
                "(no ```graphql blocks, empty output, or parse failure); will retry if budget allows."
            )
            print(f"⚠️ [{node}] {msg}")
            append_run_prompt_log_csv(
                endpoint=node,
                pipeline_stage=pipeline_stage,
                bandit_arm_name=arm["name"],
                arm_include_schema=bool(arm["include_schema"]),
                arm_arg_mode=str(arm["arg_mode"]),
                arm_depth=int(arm["depth"]),
                arm_top_k=int(k),
                node_round_seq=prompt_round_seq,
                llm_trace=llm_trace,
                parsed_queries_n=len(queries),
                parsed_mutations_n=len(mutations),
                parsed_vulnerability_types=parsed_vulnerability_types,
                parse_ok=False,
                skipped_send=True,
                http200_batch="",
                payload_index_after_send=requests,
                newly_n=0,
                newly_success_n=0,
                newly_graphql_errors_n=0,
            )
            if update_bandit_after:
                update_bandit(node, arm["name"], 0.0)
                FAIL_STREAK[node] += 1
            return False

        save_json_to_file(second_res, node)
        https200, requests, _negative_success, newly_processed_responses = send_payload(url, jsonfile_path)
        print(f"  [{node}] After send: last_payload_index={requests} | http200_batch={https200}")
        nn, ns, ng = compact_newly_processed_meta(newly_processed_responses)
        append_run_prompt_log_csv(
            endpoint=node,
            pipeline_stage=pipeline_stage,
            bandit_arm_name=arm["name"],
            arm_include_schema=bool(arm["include_schema"]),
            arm_arg_mode=str(arm["arg_mode"]),
            arm_depth=int(arm["depth"]),
            arm_top_k=int(k),
            node_round_seq=prompt_round_seq,
            llm_trace=llm_trace,
            parsed_queries_n=len(queries),
            parsed_mutations_n=len(mutations),
            parsed_vulnerability_types=parsed_vulnerability_types,
            parse_ok=parse_ok,
            skipped_send=False,
            http200_batch=str(bool(https200)),
            payload_index_after_send=int(requests),
            newly_n=nn,
            newly_success_n=ns,
            newly_graphql_errors_n=ng,
        )

        if newly_processed_responses:
            for response in newly_processed_responses:
                vt = normalize_vulnerability_type(
                    response.get("vulnerability_type"),
                    default="unknown",
                )
                ok = bool(response.get("success", False))
                if ok and (
                    vt == "basic_call"
                    or (
                        pipeline_stage == "coverage"
                        and is_successful_graphql_response(response)
                    )
                ):
                    basic_call_success = True
                    print(f"✅ Basic call successful for {node}")
                    break

            if pipeline_stage == "coverage" and not known_query_text:
                qt = extract_known_good_query_text(newly_processed_responses)
                if qt:
                    known_query_text = qt.strip()
                    save_known_good(
                        node,
                        known_query_text,
                        {"stage": "discovery_any_success", "arm": arm["name"]},
                    )
                    stats[node]["known_good_saved"] = True

        if run_vuln:
            run_dual_detectors_on_responses(
                node, vuln_detector, newly_processed_responses, https200, round_index
            )

        delta_cov = compute_delta_coverage(node)
        clean_graphql = any(
            is_successful_graphql_response(p) for p in (newly_processed_responses or [])
        )
        reward = 1.0 if (clean_graphql and delta_cov > 0) else 0.0

        if update_bandit_after:
            update_bandit(node, arm["name"], reward)
            if reward > 0:
                FAIL_STREAK[node] = 0
                covered = True
            else:
                FAIL_STREAK[node] += 1

        if reward > 0 and pipeline_stage == "coverage":
            qt = extract_known_good_query_text(newly_processed_responses)
            if qt and not known_query_text:
                known_query_text = qt.strip()
                save_known_good(
                    node,
                    known_query_text,
                    {"stage": "discovery", "arm": arm["name"]},
                )
                stats[node]["known_good_saved"] = True

        return False

    if sequential:
        discovery_attempt = 0
        print(f"  [{node}] Stage 1 — discovery (coverage reward, no vuln scan yet)")
        while (not covered) and (not basic_call_success) and (requests < max_request):
            if discovery_attempt >= max_request:
                if termination_reason is None:
                    termination_reason = "discovery_llm_attempts_exhausted"
                    termination_detail = (
                        f"Stage 1 LLM attempt cap ({max_request}) reached without coverage "
                        f"(payload_index={requests})."
                    )
                print(f"  [{node}] {termination_detail}")
                break
            discovery_attempt += 1
            print(
                f"  [{node}] Stage 1 attempt {discovery_attempt} | covered={covered} | "
                f"last_payload_index={requests}/{max_request}"
            )
            try:
                run_prompt_arm_round("coverage", None, False, True)
            except Exception as e:
                termination_reason = "runtime_error"
                termination_detail = repr(e)
                print(f"⚠️ Runtime error in discovery loop for {node}: {e}")
                break
        print(
            f"  [{node}] Stage 1 finished | covered={covered} | known_good_in_memory={bool(known_query_text)}"
        )

        stage1_ready = bool(covered or basic_call_success or https200)
        if stage1_ready:
            if not known_query_text:
                kg = load_known_good(node)
                if kg and kg.get("query"):
                    known_query_text = kg["query"].strip()
            if known_query_text:
                print(
                    f"  [{node}] Stage 2 — repeatability ({len(known_query_text)} chars, 2 identical HTTP POSTs)"
                )
                stage2_validation_pass, vmsg = validate_repeatable_graphql(url, known_query_text, attempts=2)
                validation_http_trips = 2
                stats[node]["stage2_validation_pass"] = stage2_validation_pass
                stats[node]["validation_http_trips"] = validation_http_trips
                print(f"  [{node}] Stage 2 {'PASS' if stage2_validation_pass else 'FAIL'} — {vmsg}")
                if not stage2_validation_pass and termination_reason is None:
                    termination_reason = "stage2_validation_failed"
                    termination_detail = vmsg
            elif termination_reason is None:
                termination_reason = "stage2_validation_skipped"
                termination_detail = "Stage 1 succeeded, but no extractable known-good query text."
                print(f"  [{node}] Stage 2 skipped — {termination_detail}")

        if stage1_ready and stage2_validation_pass and known_query_text:
            max_v = int(getattr(Config, "VULNERABILITY_PHASE_MAX_ROUNDS", 6))
            target_vuln_rounds = 1
            retry_errors = 0
            last_stage3_error = None
            print(
                f"  [{node}] Stage 3 — vulnerability fuzz (anchored mutations), "
                f"target={target_vuln_rounds} successful round, retry-on-error up to {max_v} time(s)"
            )
            while stage3_vulnerability_rounds < target_vuln_rounds and retry_errors < max_v:
                try:
                    run_prompt_arm_round("vulnerability", known_query_text, True, False)
                except Exception as e:
                    retry_errors += 1
                    last_stage3_error = repr(e)
                    print(
                        f"⚠️ Runtime error in vulnerability loop for {node}: {e} "
                        f"(retry {retry_errors}/{max_v})"
                    )
                    continue
                stage3_vulnerability_rounds += 1
                print(
                    f"  [{node}] Stage 3 round {stage3_vulnerability_rounds}/{max_v} done | "
                    f"payload_index={requests}"
                )
            if stage3_vulnerability_rounds < target_vuln_rounds and termination_reason is None:
                termination_reason = "runtime_error"
                termination_detail = (
                    f"Stage 3 failed after {retry_errors} retries: {last_stage3_error or 'unknown error'}"
                )
            stats[node]["stage3_vulnerability_rounds"] = stage3_vulnerability_rounds
            print(f"  [{node}] Stage 3 finished after {stage3_vulnerability_rounds} round(s)")
    else:
        print(f"  [{node}] Combined phase — coverage + vuln prompts until coverage or clean exit")
        combined_attempt = 0
        while (not covered) and (requests < max_request) and (not https200):
            if combined_attempt >= max_request:
                if termination_reason is None:
                    termination_reason = "combined_llm_attempts_exhausted"
                    termination_detail = (
                        f"Combined-phase LLM attempt cap ({max_request}) reached "
                        f"(payload_index={requests})."
                    )
                print(f"  [{node}] {termination_detail}")
                break
            combined_attempt += 1
            try:
                run_prompt_arm_round("combined", None, True, True)
            except Exception as e:
                termination_reason = "runtime_error"
                termination_detail = repr(e)
                print(f"⚠️ Runtime error in fuzzing loop for {node}: {e}")
                break

    if termination_reason is None:
        if sequential:
            if stage1_ready and stage2_validation_pass:
                termination_reason = "success_sequential_pipeline"
                termination_detail = (
                    f"Stage1 coverage; Stage2 repeatable ({validation_http_trips} HTTP); "
                    f"Stage3 vuln rounds={stage3_vulnerability_rounds}."
                )
            elif stage1_ready and known_query_text and not stage2_validation_pass:
                termination_reason = "stage2_validation_failed"
                termination_detail = termination_detail or "Known-good query not repeatable."
            elif stage1_ready:
                termination_reason = "stage2_validation_skipped"
                termination_detail = termination_detail or "No known-good text for validation."
            elif requests >= max_request:
                termination_reason = "max_requests_exhausted"
                termination_detail = f"Reached per-node request budget (requests={requests}, max_request={max_request})."
            else:
                termination_reason = "discovery_no_coverage"
                termination_detail = (
                    f"covered={covered} https200={https200} requests={requests} max_request={max_request}"
                )
        elif covered:
            termination_reason = "success_bandit_reward_coverage"
            termination_detail = "Clean GraphQL response plus new schema path coverage (MAB reward)."
        elif https200:
            termination_reason = "success_clean_graphql_exit"
            termination_detail = "HTTP 200 with usable GraphQL data; loop exited before bandit coverage reward."
        elif requests >= max_request:
            termination_reason = "max_requests_exhausted"
            termination_detail = f"Reached per-node request budget (requests={requests}, max_request={max_request})."
        else:
            termination_reason = "unknown_exit_state"
            termination_detail = (
                f"covered={covered} https200={https200} requests={requests} max_request={max_request}"
            )

    stats[node]["termination_reason"] = termination_reason
    stats[node]["termination_detail"] = termination_detail
    stats[node]["retrieval_context_error"] = retrieval_context_error
    stats[node]["stage1_coverage_reached"] = covered
    print(f"🏁 [{node}] Termination: {termination_reason} — {termination_detail}")

    stats[node]["requests"] = requests
    stats[node]['token'] = totaltoken
    stats[node]['succeed'] = bool(https200 or covered or stage2_validation_pass)
    stats[node]['basic_call_success'] = basic_call_success

    try:
        if not vuln_detector.comparison_results:
            print(
                f"⏭️ Skipping dual detector export for {node}: "
                "no vulnerability-phase responses were analyzed (detectors not run on this node)."
            )
        else:
            _node_dir = run_node_dir(node)
            comparison_csv_path = os.path.join(_node_dir, "dual_detection_comparison.csv")
            vuln_detector.save_comparison_results_to_csv(comparison_csv_path)

            comparison_report_path = os.path.join(_node_dir, "dual_detection_report.json")
            vuln_detector.generate_comparison_report(comparison_report_path)
            append_all_detector_findings(
                Config.OUTPUT_DIR,
                node,
                vuln_detector.comparison_results,
            )

            dual_summary = vuln_detector.get_summary_stats()
            total_detections = dual_summary.get('simple_detections', 0) + dual_summary.get('llm_detections', 0)
            agreement_rate = dual_summary.get('agreement_rate', 0.0)
            consensus_breakdown = dual_summary.get('consensus_breakdown', {})

            stats[node]['vulnerability_detections'] = total_detections
            stats[node]['simple_detections'] = dual_summary.get('simple_detections', 0)
            stats[node]['llm_detections'] = dual_summary.get('llm_detections', 0)
            stats[node]['detector_agreement'] = agreement_rate
            stats[node]['consensus_breakdown'] = consensus_breakdown

            potential_analysis = dual_summary.get('potential_analysis', {})
            stats[node]['simple_potential_detections'] = potential_analysis.get('simple_potential_detections', 0)
            stats[node]['llm_potential_detections'] = potential_analysis.get('llm_potential_detections', 0)
            stats[node]['potential_agreement'] = potential_analysis.get('potential_agreement_rate', 0.0)
            stats[node]['potential_consensus_breakdown'] = potential_analysis.get('potential_consensus_breakdown', {})

            stats[node]['confirmed_vulnerabilities'] = dual_summary.get('simple_detections', 0)
            stats[node]['potential_vulnerabilities'] = dual_summary.get('llm_detections', 0)

            all_categories = set()
            for comparison in vuln_detector.comparison_results:
                all_categories.update(comparison['simple_detector']['categories'])
                all_categories.update(comparison['llm_detector']['categories'])
            stats[node]['vulnerability_categories'] = list(all_categories)

            high_severity_count = 0
            for comparison in vuln_detector.comparison_results:
                for vuln in comparison['simple_detector']['results']:
                    if vuln['detection'] == 'vulnerable':
                        high_severity_count += 1
                for vuln in comparison['llm_detector']['results']:
                    if vuln['detection'] == 'vulnerable':
                        high_severity_count += 1
            stats[node]['high_severity_vulns'] = high_severity_count

            print(f"🔍 Dual Detector Summary for {node}:")
            print(f"   Simple Detector: {dual_summary.get('simple_detections', 0)} detections")
            print(f"   LLM Detector: {dual_summary.get('llm_detections', 0)} detections")
            print(f"   Agreement Rate: {agreement_rate:.2f}")
            print(f"   Consensus: {consensus_breakdown}")
            print(f"   Categories: {', '.join(all_categories) if all_categories else 'None'}")
            print(f"   High Severity: {high_severity_count}")

            potential_analysis = dual_summary.get('potential_analysis', {})
            if potential_analysis:
                print(f"   Potential Analysis:")
                print(f"     Simple Potential: {potential_analysis.get('simple_potential_detections', 0)}")
                print(f"     LLM Potential: {potential_analysis.get('llm_potential_detections', 0)}")
                print(f"     Potential Agreement: {potential_analysis.get('potential_agreement_rate', 0.0):.2f}")
                print(f"     Potential Consensus: {potential_analysis.get('potential_consensus_breakdown', {})}")

    except Exception as e:
        print(f"⚠️ Failed to save dual detector results for {node}: {e}")
        stats[node]['vulnerability_detections'] = 0
        stats[node]['simple_detections'] = 0
        stats[node]['llm_detections'] = 0
        stats[node]['detector_agreement'] = 0.0
        stats[node]['consensus_breakdown'] = {}
        stats[node]['confirmed_vulnerabilities'] = 0
        stats[node]['potential_vulnerabilities'] = 0
        stats[node]['vulnerability_categories'] = []
        stats[node]['high_severity_vulns'] = 0
        extra = f" | dual_detector_persist_error: {repr(e)}"
        stats[node]["termination_detail"] = (stats[node].get("termination_detail") or "") + extra

    print(stats)
    print(f"[{node}] Attempt {requests+1}/{max_request}")

    return stats

def embedding_responses_from_graphqler():
    pfr = ParseEndpointResults()
    payload_resp_pair = pfr.parse_result_to_json_with_status()
    natural_text = loadjsonfile()
    index_file_path = embedding(natural_text)

def save_json_to_file(generated_payload, node):
    payload_list = [{"query": q} for q in generated_payload["query"]]
    payload_list += [{"mutation": m} for m in generated_payload.get("mutation", [])]

    filedir = run_node_dir(node)

    if not os.path.exists(filedir):
        os.makedirs(filedir)

    filepath = os.path.join(filedir, "llama_queries.json")

    existing_data = []
    if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
        with open(filepath, 'r') as f:
            try:
                existing_data = json.load(f)
                if not isinstance(existing_data, list):
                    print(f"⚠️ Warning: Existing JSON was not a list. Overwriting.")
                    existing_data = []
            except json.JSONDecodeError:
                print(f"⚠️ Warning: Existing JSON was invalid. Overwriting.")
                existing_data = []

    existing_data.extend(payload_list)

    with open(filepath, 'w') as f:
        json.dump(existing_data, f, indent=4)

    print(f"✅ Saved {len(payload_list)} new queries. Total in file: {len(existing_data)}")
    return True

def log_to_table(stats, output_file):
    rows = []
    for node, values in stats.items():
        categories = ', '.join(values.get('vulnerability_categories', [])) if values.get('vulnerability_categories') else 'None'

        consensus = values.get('consensus_breakdown', {})
        consensus_str = ', '.join([f"{k}:{v}" for k, v in consensus.items()]) if consensus else 'None'
        
        term_detail = values.get("termination_detail") or ""
        if len(term_detail) > 100:
            term_detail = term_detail[:97] + "..."

        rows.append([
            node,
            values.get("round_index", ""),
            values.get('requests', 0),
            f"{values.get('token', 0):,}",
            values.get('succeed', False),
            values.get('basic_call_success', False),
            values.get('vulnerability_detections', 0),
            values.get('simple_detections', 0),
            values.get('llm_detections', 0),
            values.get('detector_agreement', 0.0),
            values.get('simple_potential_detections', 0),
            values.get('llm_potential_detections', 0),
            values.get('potential_agreement', 0.0),
            values.get('confirmed_vulnerabilities', 0),
            values.get('potential_vulnerabilities', 0),
            values.get('high_severity_vulns', 0),
            categories,
            consensus_str,
            values.get("termination_reason", ""),
            term_detail,
            (values.get("retrieval_context_error") or "")[:80],
            values.get("final_rounds_outcome", ""),
            values.get("pipeline_mode", ""),
            values.get("stage1_coverage_reached", False),
            values.get("stage2_validation_pass", False),
            values.get("stage3_vulnerability_rounds", 0),
            values.get("validation_http_trips", 0),
            values.get("known_good_saved", False),
        ])

    table_str = tabulate(
        rows,
        headers=[
            "Node", "Round", "Requests", "Tokens", "Succeed", "Basic Call Success",
            "Total Vulns", "Simple Det", "LLM Det", "Agreement", "Simple Pot", "LLM Pot", "Pot Agreement",
            "Confirmed", "Potential", "High Severity", "Categories", "Consensus",
            "Termination", "Term. detail", "Retr. err", "Final rounds",
            "Pipeline", "S1 cov", "S2 val", "S3 rnd", "Val HTTP", "KG saved",
        ],
        tablefmt="grid"
    )

    print(table_str)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(table_str)

    print(f"\n✅ Table written to {output_file}")

def generate_vulnerability_summary_report(stats_allrounds, output_file=None):
    """Generate a comprehensive vulnerability classification summary report with dual detector analysis"""
    if not output_file:
        output_file = os.path.join(Config.OUTPUT_DIR, "dual_detector_vulnerability_summary_report.json")
    
    # Collect all vulnerability data
    total_vulnerabilities = 0
    total_simple_detections = 0
    total_llm_detections = 0
    total_simple_potential = 0
    total_llm_potential = 0
    total_confirmed = 0
    total_potential = 0
    total_high_severity = 0
    all_categories = set()
    detector_breakdown = {}
    agreement_rates = []
    potential_agreement_rates = []
    consensus_summary = {}
    potential_consensus_summary = {}
    
    for node, values in stats_allrounds.items():
        total_vulnerabilities += values.get('vulnerability_detections', 0)
        total_simple_detections += values.get('simple_detections', 0)
        total_llm_detections += values.get('llm_detections', 0)
        total_simple_potential += values.get('simple_potential_detections', 0)
        total_llm_potential += values.get('llm_potential_detections', 0)
        total_confirmed += values.get('confirmed_vulnerabilities', 0)
        total_potential += values.get('potential_vulnerabilities', 0)
        total_high_severity += values.get('high_severity_vulns', 0)
        
        # Track agreement rates
        agreement = values.get('detector_agreement', 0.0)
        if agreement > 0:
            agreement_rates.append(agreement)
        
        # Track potential agreement rates
        potential_agreement = values.get('potential_agreement', 0.0)
        if potential_agreement > 0:
            potential_agreement_rates.append(potential_agreement)
        
        # Track consensus breakdown
        consensus = values.get('consensus_breakdown', {})
        for consensus_type, count in consensus.items():
            consensus_summary[consensus_type] = consensus_summary.get(consensus_type, 0) + count
        
        # Track potential consensus breakdown
        potential_consensus = values.get('potential_consensus_breakdown', {})
        for consensus_type, count in potential_consensus.items():
            potential_consensus_summary[consensus_type] = potential_consensus_summary.get(consensus_type, 0) + count
        
        categories = values.get('vulnerability_categories', [])
        all_categories.update(categories)
    
    # Calculate average agreement rates
    avg_agreement = sum(agreement_rates) / len(agreement_rates) if agreement_rates else 0.0
    avg_potential_agreement = sum(potential_agreement_rates) / len(potential_agreement_rates) if potential_agreement_rates else 0.0
    
    # Create summary report
    summary_report = {
        'report_timestamp': datetime.utcnow().isoformat(),
        'overall_summary': {
            'total_nodes_tested': len(stats_allrounds),
            'total_vulnerability_detections': total_vulnerabilities,
            'simple_detector_detections': total_simple_detections,
            'llm_detector_detections': total_llm_detections,
            'simple_potential_detections': total_simple_potential,
            'llm_potential_detections': total_llm_potential,
            'total_confirmed_vulnerabilities': total_confirmed,
            'total_potential_vulnerabilities': total_potential,
            'total_high_severity_vulnerabilities': total_high_severity,
            'vulnerability_categories_found': list(all_categories),
            'detector_agreement_rate': avg_agreement,
            'potential_agreement_rate': avg_potential_agreement,
            'consensus_breakdown': consensus_summary,
            'potential_consensus_breakdown': potential_consensus_summary
        },
        'detector_comparison': {
            'simple_detector': {
                'total_detections': total_simple_detections,
                'potential_detections': total_simple_potential,
                'detection_rate': total_simple_detections / len(stats_allrounds) if stats_allrounds else 0,
                'potential_detection_rate': total_simple_potential / len(stats_allrounds) if stats_allrounds else 0,
                'description': 'Rule-based detector using predefined patterns'
            },
            'llm_detector': {
                'total_detections': total_llm_detections,
                'potential_detections': total_llm_potential,
                'detection_rate': total_llm_detections / len(stats_allrounds) if stats_allrounds else 0,
                'potential_detection_rate': total_llm_potential / len(stats_allrounds) if stats_allrounds else 0,
                'description': 'AI-powered detector using language model analysis'
            },
            'agreement_analysis': {
                'average_agreement': avg_agreement,
                'nodes_with_agreement': len(agreement_rates),
                'consensus_distribution': consensus_summary
            },
            'potential_agreement_analysis': {
                'average_potential_agreement': avg_potential_agreement,
                'nodes_with_potential_agreement': len(potential_agreement_rates),
                'potential_consensus_distribution': potential_consensus_summary
            }
        },
        'node_breakdown': stats_allrounds,
            'vulnerability_classification_info': {
                'categories': {
                    'Injection Attacks': 'VULNERABLE detection - Code injection vulnerabilities',
                    'Information Disclosure': 'POTENTIAL detection - API structure exposure',
                    'Access Control': 'VULNERABLE detection - Authorization bypass'
                },
                'detection_levels': {
                    'vulnerable': 'Confirmed vulnerability detected',
                    'potential': 'Potential vulnerability detected',
                    'safe': 'No vulnerability detected'
                }
            }
    }
    
    # Save report
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(summary_report, f, indent=2, ensure_ascii=False)
    
    print(f"✅ Vulnerability summary report saved to {output_file}")
    
    # Print summary to console
    print("\n" + "="*80)
    print("🔍 DUAL DETECTOR VULNERABILITY CLASSIFICATION SUMMARY")
    print("="*80)
    print(f"Total Nodes Tested: {len(stats_allrounds)}")
    print(f"Total Vulnerability Detections: {total_vulnerabilities}")
    print(f"  - Simple Detector: {total_simple_detections}")
    print(f"  - LLM Detector: {total_llm_detections}")
    print(f"Detector Agreement Rate: {avg_agreement:.2f}")
    print(f"Consensus Breakdown: {consensus_summary}")
    print(f"Confirmed Vulnerabilities: {total_confirmed}")
    print(f"Potential Vulnerabilities: {total_potential}")
    print(f"High Severity Vulnerabilities: {total_high_severity}")
    print(f"Categories Found: {', '.join(all_categories) if all_categories else 'None'}")
    print("="*80)
    
    return output_file

def find_node_parameter(node_name):

    query_parameter_path = os.path.join("graphqler-output", "extracted", "query_parameter_list.yml")
    mutation_parameter_path = os.path.join("graphqler-output", "extracted", "mutation_parameter_list.yml")
    filepaths = [query_parameter_path, mutation_parameter_path]
    for path in filepaths:
        if not os.path.exists(path):
            print(f"parameter file not found: {path}")
            continue

        with open(path, 'r') as f:
            try:
                data = yaml.safe_load(f)
            except yaml.YAMLError as e:
                print(f"⚠️ Error parsing YAML in {path}: {e}")
                continue

            if not data:
                continue

            for key, value in data.items():
                if key == node_name:
                    print(f"✅ Exact match on key in {path}: {key}")
                    return value

                # Check for internal 'name' field match
                if isinstance(value, dict):
                    internal_name = value.get("name")
                    if internal_name == node_name:
                        print(f"✅ Match on internal 'name' field in {path}: {internal_name}")
                        return value

    print(f"❌ Node '{node_name}' not found in any provided files.")
    return None



if __name__ == "__main__":
    main()