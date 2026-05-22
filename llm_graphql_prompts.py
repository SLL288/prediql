import faiss
import numpy as np
import json
import re
import csv
from sentence_transformers import SentenceTransformer
from config import Config, run_node_dir
import os
from ollama_runtime import ensure_ollama_running
from llm_http_client import get_llm_model
from parse_endpoint_results import getnodefromcompiledfile
from graphql_query_normalize import fix_endpoint_case
from graphql_send_payload import normalize_vulnerability_type
from datetime import datetime


import yaml

_retrieval_sets = ()

def find_node_definition(node_name):
    """
    Search YAML files for a node definition matching node_name.
    Matches either:
      - the top-level key
      - the internal 'name' field in the value
    Returns the node definition (dict) if found, or None if not found.
    """
    li = Config.RUN_LOAD_INTROSPECTION_DIR
    queries_path = os.path.join(li, "query_parameter_list.yml")
    mutations_path = os.path.join(li, "mutation_parameter_list.yml")
    file_paths = [queries_path, mutations_path]
    for path in file_paths:
        if not os.path.exists(path):
            print(f"Schema_File not found: {path}")
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

                if isinstance(value, dict):
                    internal_name = value.get("name")
                    if internal_name == node_name:
                        print(f"✅ Match on internal 'name' field in {path}: {internal_name}")
                        return value

    print(f"❌ Node '{node_name}' not found in any provided files.")
    return None


def extract_request_response_pairs(json_file_path):
    """Build (query, errors_or_none) pairs from llama_queries.json-style logs."""
    if not os.path.exists(json_file_path):
        print(f"File not found: {json_file_path}")
        return []

    if os.path.getsize(json_file_path) == 0:
        print(f"File is empty: {json_file_path}")
        return []

    try:
        with open(json_file_path, "r") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON format: {e}")
        return []

    pairs = []
    for item in data:
        query = item.get("query")
        success = item.get("success", True)

        if success:
            pairs.append((query, None))
        else:
            response_body = item.get("response_body", {})
            if isinstance(response_body, dict):
                errors = response_body.get("errors", [])
                if errors and isinstance(errors, list) and len(errors) > 0:
                    cleaned_errors = []
                    for error in errors:
                        if isinstance(error, dict):
                            cleaned_error = {k: v for k, v in error.items() if k != "extensions"}
                            cleaned_errors.append(cleaned_error)
                        else:
                            cleaned_errors.append(error)
                    pairs.append((query, cleaned_errors))
    return pairs


def load_index_and_model():
    print("[INFO] Loading FAISS index and model...")
    index = faiss.read_index(Config.INDEX_FILE)
    with open(Config.MODEL_NAME_FILE, "r") as f:
        model_name = f.read().strip()
    model = SentenceTransformer(model_name)
    return index, model

def load_texts():
    with open(Config.JSON_FILE, "r", encoding="utf-8") as f:
        records = json.load(f)
    texts = [
        f"Query: {r['query']} | Response: {r['response']} | Status: {r.get('status', 'N/A')}"
        for r in records
    ]
    return texts, records


def retrieve_similar(node, model, index, texts, top_k=5):
    query_embedding = model.encode([node])
    distances, indices = index.search(np.array(query_embedding), top_k)
    results = [texts[i] for i in indices[0]]
    return results


RUN_PROMPT_LOG_SUBDIR = "run_logs"
RUN_PROMPT_LOG_CSV = "run_prompt_log.csv"
_LLM_ERR_CSV_MAX = 320
_VTYPES_CSV_MAX = 400


def run_prompt_log_csv_path() -> str:
    """Per-run CSV under ``Config.OUTPUT_DIR/run_logs/`` (resolved at call time)."""
    return os.path.join(Config.OUTPUT_DIR, RUN_PROMPT_LOG_SUBDIR, RUN_PROMPT_LOG_CSV)


_RUN_PROMPT_LOG_FIELDNAMES = [
    "timestamp_iso",
    "endpoint",
    "pipeline_stage",
    "bandit_arm_name",
    "arm_include_schema",
    "arm_arg_mode",
    "arm_depth",
    "arm_top_k",
    "node_round_seq",
    "llm_ok",
    "llm_error",
    "prompt_chars",
    "llm_response_chars",
    "llm_prompt_tokens",
    "llm_completion_tokens",
    "llm_wall_seconds",
    "parsed_query_blocks",
    "parsed_mutation_blocks",
    "parsed_vulnerability_types",
    "parse_ok",
    "skipped_send",
    "http200_batch",
    "payload_index_after_send",
    "newly_n",
    "newly_success_n",
    "newly_graphql_errors_n",
]


def append_run_prompt_log_csv(
    *,
    endpoint: str,
    pipeline_stage: str,
    bandit_arm_name: str,
    arm_include_schema: bool,
    arm_arg_mode: str,
    arm_depth: int,
    arm_top_k: int,
    node_round_seq: int,
    llm_trace: dict,
    parsed_queries_n: int,
    parsed_mutations_n: int,
    parsed_vulnerability_types: str,
    parse_ok: bool,
    skipped_send: bool,
    http200_batch: str,
    payload_index_after_send: int,
    newly_n: int,
    newly_success_n: int,
    newly_graphql_errors_n: int,
) -> None:
    """
    Append one metadata-only row to ``run_logs/run_prompt_log.csv`` (no full prompt/response).
    Creates the subfolder and file with a header on first write.
    """
    path = run_prompt_log_csv_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    write_header = not (os.path.exists(path) and os.path.getsize(path) > 0)
    err = (llm_trace.get("llm_error") or "") or ""
    if len(err) > _LLM_ERR_CSV_MAX:
        err = err[: _LLM_ERR_CSV_MAX - 3] + "..."
    vt = parsed_vulnerability_types or ""
    if len(vt) > _VTYPES_CSV_MAX:
        vt = vt[: _VTYPES_CSV_MAX - 3] + "..."
    row = {
        "timestamp_iso": datetime.now().isoformat(),
        "endpoint": endpoint,
        "pipeline_stage": pipeline_stage,
        "bandit_arm_name": bandit_arm_name,
        "arm_include_schema": arm_include_schema,
        "arm_arg_mode": arm_arg_mode,
        "arm_depth": arm_depth,
        "arm_top_k": arm_top_k,
        "node_round_seq": node_round_seq,
        "llm_ok": llm_trace.get("llm_ok", False),
        "llm_error": err,
        "prompt_chars": len(llm_trace.get("prompt_text") or ""),
        "llm_response_chars": len(llm_trace.get("llm_response_text") or ""),
        "llm_prompt_tokens": llm_trace.get("prompt_tokens", 0),
        "llm_completion_tokens": llm_trace.get("completion_tokens", 0),
        "llm_wall_seconds": llm_trace.get("wall_time_seconds", 0.0),
        "parsed_query_blocks": parsed_queries_n,
        "parsed_mutation_blocks": parsed_mutations_n,
        "parsed_vulnerability_types": vt,
        "parse_ok": parse_ok,
        "skipped_send": skipped_send,
        "http200_batch": http200_batch,
        "payload_index_after_send": payload_index_after_send,
        "newly_n": newly_n,
        "newly_success_n": newly_success_n,
        "newly_graphql_errors_n": newly_graphql_errors_n,
    }
    try:
        with open(path, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=_RUN_PROMPT_LOG_FIELDNAMES, extrasaction="ignore")
            if write_header:
                w.writeheader()
            w.writerow(row)
    except Exception as e:
        print(f"⚠️ Warning: Failed to append run prompt log CSV: {e}")


def compact_newly_processed_meta(responses):
    """
    Small tuple for CSV: (batch_size, n_success_flag, n_payloads_with_nonempty_graphql_errors).
    """
    if not responses:
        return 0, 0, 0
    n = len(responses)
    sn = sum(1 for p in responses if p.get("success"))
    gn = 0
    for p in responses:
        rb = p.get("response_body")
        if isinstance(rb, dict):
            errs = rb.get("errors")
            if isinstance(errs, list) and len(errs) > 0:
                gn += 1
    return n, sn, gn


def _graphql_prompt_category_dir(pipeline_stage: str) -> str:
    """Filesystem folder under ``prompts/<endpoint>/`` for GraphQL LLM prompts."""
    st = (pipeline_stage or "combined").lower()
    if st == "coverage":
        return "coverage_fuzzing"
    if st == "vulnerability":
        return "security_fuzzing"
    return "security_fuzzing"


def _prompt_round_dirname(run_round_index) -> str:
    r = int(run_round_index) if run_round_index is not None else 1
    if r < 1:
        r = 1
    return f"round_{r}"


def save_prompt_response_pair(
    endpoint,
    prompt,
    llm_response,
    query_json,
    approx_tokens,
    *,
    pipeline_stage: str = "combined",
    run_round_index=None,
):
    """
    Save prompt/response under
    ``OUTPUT_DIR/nodes/<endpoint>/prompts/<coverage_fuzzing|security_fuzzing>/round_<n>/``.
    """
    category_dir = _graphql_prompt_category_dir(pipeline_stage)
    round_dir = _prompt_round_dirname(run_round_index)
    endpoint_dir = os.path.join(
        run_node_dir(endpoint), "prompts", category_dir, round_dir
    )
    os.makedirs(endpoint_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"prompt_response_{timestamp}.json"
    filepath = os.path.join(endpoint_dir, filename)

    prompt_data = {
        "timestamp": timestamp,
        "endpoint": endpoint,
        "pipeline_stage": pipeline_stage,
        "run_round_index": run_round_index,
        "prompt": prompt,
        "llm_response": llm_response,
        "parsed_queries": query_json,
        "approx_tokens": approx_tokens,
        "request_time": datetime.now().isoformat()
    }

    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(prompt_data, f, indent=2, ensure_ascii=False)
        print(f"✅ Saved prompt-response pair to: {filepath}")
    except Exception as e:
        print(f"⚠️ Warning: Failed to save prompt-response pair: {e}")


def prompt_llm_with_context(
    top_matches,
    endpoint,
    schema,
    input,
    output,
    source,
    MAX_REQUESTS,
    node_type,
    include_schema=True,
    arg_mode="known",
    depth=1,
    n_variants=1,
    pipeline_stage="combined",
    known_good_graphql=None,
    run_round_index=None,
):
    """
    pipeline_stage:
      - "combined": legacy single-phase prompt (coverage + all vuln types).
      - "coverage": Stage 1 discovery — Basic_Call only, same context as legacy (schema + known real values + prior attempts).
      - "vulnerability": Stage 3 — anchor on known_good_graphql, mutate args for vuln classes.
    run_round_index:
      Multi-round index from ``main`` (saved under ``prompts/<endpoint>/.../round_<n>/``); ``None`` → ``round_1``.
    """
    previous_response_pairs = extract_request_response_pairs(
        os.path.join(run_node_dir(endpoint), "llama_queries.json")
    )
    formatted_previous_pairs = []
    for query, error_msg in previous_response_pairs:
        pair_obj = {
            "query": query,
            "error": error_msg if error_msg else None
        }
        formatted_previous_pairs.append(pair_obj)
    
    previous_pairs_text = json.dumps(formatted_previous_pairs, indent=2) if formatted_previous_pairs else "[]"

    stage = pipeline_stage if pipeline_stage in ("combined", "coverage", "vulnerability") else "combined"
    # Always pass retrieval snippets into the prompt (including Stage 1), matching legacy retrieve_and_prompt context.
    top_for_prompt = ""
    if arg_mode == "known":
        top_for_prompt = (top_matches or "") or ""

    if stage == "coverage":
        header = f"""
    You are an expert GraphQL API tester (safe offline environment).

    Stage: DISCOVERY / COVERAGE ONLY — do not optimize for vulnerability findings.

    Goal: reach new fields, arguments, or return paths for operation **{endpoint}** with a valid query that the server accepts (HTTP 200, empty GraphQL errors, non-empty data when possible).

    Strict requirements:
    1) Syntactically valid GraphQL for this operation only.
    2) No placeholders like <id> or "value" — use concrete literals compatible with the schema.
    3) Do not use the words "edges" or "node".
    4) GraphQL is case-sensitive; match the exact operation name: {endpoint}.
    5) Learn from previous failed attempts (pairs below): fix errors and extend coverage.
    """
    elif stage == "vulnerability":
        kg = (known_good_graphql or "").strip()
        header = f"""
    You are an expert in GraphQL API security testing.

    Here is a **known-good** query that already succeeded against the endpoint. KEEP the same overall structure
    (operation name, field selection shape, nesting depth) and change **only** scalar/string/list arguments where it makes sense
    to probe injection and abuse patterns (SQLi, XSS, SSRF, command injection, path/HTML injection, introspection, field suggestions, query-deny alias patterns).

    Known-good baseline:
    ```graphql
    {kg}
    ```

    CRITICAL REQUIREMENT: Output queries labeled for a **basic call** plus EACH of the following vulnerability types:
    - SQL Injection
    - XSS Injection
    - SSRF Injection
    - OS Command Injection
    - Path Injection
    - HTML Injection
    - Query Deny Bypass (TWO queries: non-aliased and aliased)
    - Introspection
    - Field Suggestions

    Strict requirements:
    1) Queries must be syntactically valid GraphQL.
    2) No placeholders like <id>, "ID!", "value". Use realistic literals or values derived from the baseline.
    3) You may use injected strings, nulls, overlong strings, and type mismatches where appropriate.
    4) You may output {n_variants} query(ies) per type where needed but MUST cover all vulnerability types listed above.
    5) Do not use the words "edges" or "node".
    6) GraphQL is case-sensitive. Match the exact operation name: {endpoint}.
    7) CRITICAL: Label each query with: ***<vulnerability_type>*** before each ```graphql block (use the same label tokens as in the output format section).
    8) For Query Deny Bypass, generate TWO queries: non-aliased then aliased, as specified in the format section.
    """
    else:
        header = f"""
    You are an expert in GraphQL API security testing.

    Goal: generate valid GraphQL queries for the operation shown, to get successful responses (HTTP 200) quickly while exploring robustness and testing for specific vulnerability types.

    
    CRITICAL REQUIREMENT: You MUST include at least one query for a basic call and EACH of the following vulnerability types:
    - SQL Injection
    - XSS Injection
    - SSRF Injection
    - OS Command Injection
    - Path Injection
    - HTML Injection
    - Query Deny Bypass (REQUIRES TWO QUERIES: non-aliased and aliased)
    - Introspection
    - Field Suggestions

    Strict Requirements:
    1) Queries must be syntactically valid GraphQL.
    2) No placeholders like <id>, "ID!", "value". Use realistic literals or known real values.
    3) You may attempt injected strings, nulls, overlong strings, and type mismatches where appropriate.
    4) You may output {n_variants} query(ies) but MUST cover all vulnerability types listed above.
    5) Do not use the words "edges" or "node".
    6) GraphQL is case-sensitive. Match the exact operation name: {endpoint}.
    7) If there are previous response pairs, use them to generate the query.
    8) For each vulnerability type, craft queries that specifically test for that vulnerability pattern.
    9) CRITICAL: Label each query with its vulnerability type using the format: ***<vulnerability_type>*** before each ```graphql block.
    10) SPECIAL CASE: For Query Deny Bypass, you MUST generate TWO queries:
        - First query: Non-aliased version (normal query structure)
        - Second query: Aliased version (using query aliases like "s: queryName")
        Both queries should test the same operation but with different structures to test access control bypass.
    """
    if include_schema:
        if isinstance(schema, (dict, list)):
            schema_text = json.dumps(schema, indent=2, ensure_ascii=False)
        else:
            schema_text = schema if schema is not None else ""
        schema_block = f"""
        SCHEMA (authoritative, operation-local fragment as JSON):
        {schema_text}
        - declared return type string (reference): {output}
        Use only fields/args compatible with this schema.
        """
        fallback_block = ""
    else:
        schema_block = ""
        fallback_block = """
        Schema not provided: explore plausibly.
        - Prefer fields/args seen in prior successful responses or known real values.
        - Introduce at most 1–2 new fields per query.
        - Keep selection depth minimal to maximize validity.
        """

    if arg_mode == "known":
        arg_block = "Argument strategy: reuse known-good values from context and previous 200 responses."
    elif arg_mode == "real":
        arg_block = ("Argument strategy: synthesize realistic literals by type "
                     "(e.g., ISO dates, small integers, emails, UUIDv4), avoid placeholders.")
    elif arg_mode == "nulls":
        arg_block = ("Argument strategy: use null/empty for OPTIONAL inputs only; "
                     "never for non-null (!) fields.")
    else:
        arg_block = "Argument strategy: default."

    depth_block = f"Selection depth target: {depth}. Keep nested selections no deeper than {depth} levels."

    context = f"""
    Context:
    - operation: {endpoint}
    - input (declared): {input}
    - node type: {source}
    - known real values: {top_for_prompt}
    - previous attempts (query + errors, JSON): {previous_pairs_text}

    {arg_block}
    {depth_block}
    """
    
    if stage == "coverage":
        format_block = f"""
    Output format (exactly ONE query):
    ***Basic_Call***
    ```graphql
    <single valid query for {endpoint}>
    ```
    """
    else:
        format_block = f"""
    Output format:
    Each query must be in its own fenced block with a vulnerability type label:
    Vulnerability Type Labels Are:
    - SQL_Injection
    - XSS_Injection
    - SSRF_Injection
    - OS_Command_Injection
    - Path_Injection
    - HTML_Injection
    - Query_Deny_Bypass_Non_Aliased
    - Query_Deny_Bypass_Aliased
    - Introspection
    - Field_Suggestions

    ***<Vulnerability Type>***
    ```graphql
    <your query>
    ```
    
    Example:
    ***SQL_Injection***
    ```graphql
    query {{
      users(filter: "1' OR '1'='1") {{
        id
        name
      }}
    }}
    ```
    
    ***XSS_Injection***
    ```graphql
    query {{
      search(term: "<script>alert('xss')</script>") {{
        results
      }}
    }}
    ```
    """

    prompt_arms = header + schema_block + fallback_block + context + format_block
    print(f"[LLM] endpoint={endpoint} stage={stage} | built_prompt_chars={len(prompt_arms)}")

    try:
        llm_out = get_llm_model(prompt_arms, node_label=endpoint, provider="primary")
        llama_res = llm_out.text
        llm_response_full = llama_res
        approx_tokens = float(llm_out.prompt_tokens + llm_out.completion_tokens)
        print(
            f"LLM tokens (prompt / completion): {llm_out.prompt_tokens} / {llm_out.completion_tokens} "
            f"(wall {llm_out.wall_time_seconds:.2f}s)"
        )
    except Exception as e:
        print(f"⚠️ Error calling get_llm_model: {e}")
        trace = {
            "llm_ok": False,
            "prompt_text": prompt_arms,
            "llm_response_text": "",
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "wall_time_seconds": 0.0,
            "llm_error": str(e),
        }
        return {"query": []}, 0, trace

    query_json = {"query": []}
    flag = "```graphql"
    parse_time = 0

    while flag in llama_res and parse_time < 12:
        parse_time += 1
        try:
            sidx = llama_res.find(flag)
            if sidx == -1:
                break

            vulnerability_type = "unknown"
            label_pattern = r"\*\*\*([^*]+)\*\*\*"
            text_before_query = llama_res[:sidx]
            label_match = re.search(label_pattern, text_before_query)
            if label_match:
                vulnerability_type = normalize_vulnerability_type(
                    label_match.group(1), default="unknown"
                )
            # Coverage stage is discovery-only; ignore hallucinated labels (e.g. country_query_1)
            # so downstream stats, known-good selection, and detectors see canonical basic_call.
            if stage == "coverage":
                vulnerability_type = "basic_call"

            j_start = llama_res[sidx+len(flag):]
            j_end = j_start.find("```")
            if j_end == -1:
                break
                
            query_str = j_start[:j_end]
            llama_res = j_start[j_end:]

            if not llama_res:
                break

            query_str = fix_endpoint_case(query_str, endpoint)

            query_entry = {
                "query": query_str,
                "vulnerability_type": vulnerability_type
            }

            if not any(q["query"] == query_str for q in query_json["query"]):
                query_json["query"].append(query_entry)
        except Exception as e:
            print(e)
            continue

    save_prompt_response_pair(
        endpoint,
        prompt_arms,
        llm_response_full,
        query_json,
        approx_tokens,
        pipeline_stage=stage,
        run_round_index=run_round_index,
    )

    trace = {
        "llm_ok": True,
        "prompt_text": prompt_arms,
        "llm_response_text": llm_response_full,
        "prompt_tokens": llm_out.prompt_tokens,
        "completion_tokens": llm_out.completion_tokens,
        "wall_time_seconds": llm_out.wall_time_seconds,
        "llm_error": "",
    }
    return query_json, approx_tokens, trace


def get_llm_first_response(node, objects):
    """Load embedding index, retrieve similar snippets, then call ``prompt_llm_with_context`` (demo path)."""
    global _retrieval_sets
    index, model = load_index_and_model()
    texts, records = load_texts()
    _retrieval_sets = (node, model, index, texts)
    ensure_ollama_running("llama3")
    top_matches = retrieve_similar(node, model, index, texts)
    res, tok, _trace = prompt_llm_with_context(top_matches, node, objects)
    return res, tok


def get_llm_response(node, objects):
    """Uses retrieval context from the last ``get_llm_first_response`` call on this process."""
    global _retrieval_sets
    if not _retrieval_sets:
        raise RuntimeError("Call get_llm_first_response before get_llm_response (no retrieval context).")
    cached_node, model, index, texts = _retrieval_sets
    top_matches = retrieve_similar(cached_node, model, index, texts)
    res, tok, _trace = prompt_llm_with_context(top_matches, node, objects)
    return res, tok



if __name__ == "__main__":
    endpoint, objects = getnodefromcompiledfile()
    node = "charactersByIds"
    for key in endpoint:
        print(endpoint[key])
    node = "episodesByIds"
    get_llm_first_response(node, objects)
