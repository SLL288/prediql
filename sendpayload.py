import os
import json
import time
import requests
from datetime import datetime
from graphql import parse
from graphql.language.ast import FieldNode, OperationDefinitionNode


import random

def send_payload(GRAPHQL_URL, jsonfile_path, output_jsonfile_path=None):
    HEADERS = {"Content-Type": "application/json"}
    DEFAULT_FALLBACK_QUERY = """
    query {
      episodesByIds(ids: [1]) {
        id
        name
      }
    }
    """

    if not os.path.exists(jsonfile_path) or os.path.getsize(jsonfile_path) == 0:
        print(f"❌ File not found or empty: {jsonfile_path}")
        return False, 0

    try:
        with open(jsonfile_path, "r") as f:
            payloads = json.load(f)
    except json.JSONDecodeError as e:
        print(f"❌ Error reading JSON: {e}")
        return False, 0

    updated_payloads = []
    https200 = False
    requests_count = 0

    for i, payload in enumerate(payloads, start=1):
        # ✅ Skip if already has response
        if "response_status" in payload and "response_body" in payload:
            updated_payloads.append(payload)
            continue

        try:
            # Pick payload type
            if "query" in payload:
                request_payload = {"query": payload["query"]}
            elif "mutation" in payload:
                request_payload = {"query": payload["mutation"]}
            else:
                print(f"⚠️ Skipping payload {i}: No 'query' or 'mutation' found.")
                updated_payloads.append(payload)
                continue

            # Send request
            start_time = time.time()
            response = requests.post(GRAPHQL_URL, headers=HEADERS, json=request_payload, timeout=10)
            request_time = time.time() - start_time
            query_text = payload.get("query") or payload.get("mutation")

            payload.update({
                "response_status": response.status_code,
                "request_time_seconds": round(request_time, 3),
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "count": i
            })

            try:
                payload["response_body"] = response.json()
            except ValueError:
                payload["response_body"] = {"error": "Invalid JSON", "raw": response.text}

            if response.status_code in [429, 503]:
                time.sleep(10)
            else:
                time.sleep(random.uniform(1.5, 3.0))

            success = is_successful_graphql_response(payload)
            payload["success"] = success

            if success:
                print(f"✅ Valid 200 response with data for payload {i}")
                https200 = True
            requests_count = i

        except requests.exceptions.RequestException as e:
            payload.update({
                "response_status": None,
                "request_time_seconds": round(time.time() - start_time, 3),
                "response_body": {"error": str(e)},
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "count": i
            })

        # 🔁 Retry if response body is empty
        is_empty = (
            payload.get("response_body") in [None, {}, []]
        )
        if is_empty:
            print(f"⚠️ Empty response for payload {i}, retrying with fallback query.")
            retry_payload = {"query": DEFAULT_FALLBACK_QUERY}
            try:
                retry_start = time.time()
                retry_response = requests.post(GRAPHQL_URL, headers=HEADERS, json=retry_payload, timeout=10)
                retry_time = time.time() - retry_start
                payload.update({
                    "retry_query": DEFAULT_FALLBACK_QUERY,
                    "retry_status": retry_response.status_code,
                    "retry_time_seconds": round(retry_time, 3)
                })
                try:
                    payload["retry_response_body"] = retry_response.json()
                except ValueError:
                    payload["retry_response_body"] = {
                        "error": "Invalid JSON",
                        "raw": retry_response.text
                    }
            except requests.exceptions.RequestException as e:
                payload.update({
                    "retry_query": DEFAULT_FALLBACK_QUERY,
                    "retry_status": None,
                    "retry_time_seconds": 0,
                    "retry_response_body": {"error": str(e)}
                })

        # ✅ Append exactly once
        updated_payloads.append(payload)

    # ✅ Deduplicate before writing
    def to_key(d): return json.dumps(d, sort_keys=True)
    seen = set()
    unique_payloads = []
    for p in updated_payloads:
        key = to_key(p)
        if key not in seen:
            seen.add(key)
            unique_payloads.append(p)

    # ✅ Write output
    if not output_jsonfile_path:
        output_jsonfile_path = jsonfile_path

    with open(output_jsonfile_path, "w", encoding="utf-8") as f:
        json.dump(unique_payloads, f, indent=2, ensure_ascii=False)

    print(f"✅ Finished. {len(unique_payloads)} unique payloads written to {output_jsonfile_path}")
    return https200, requests_count

def extract_fields_edges_nodes(query_string):
    try:
        ast = parse(query_string)
    except Exception as e:
        print(f"⚠️ Could not parse query: {e}")
        return [], [], None

    fields = set()
    edges = set()
    operations = set()

    def traverse_selection(selection_set, path):
        for selection in selection_set.selections:
            if isinstance(selection, FieldNode):
                field_name = selection.name.value
                fields.add(field_name)

                if path:
                    edges.add(".".join(path + [field_name]))

                if selection.selection_set:
                    traverse_selection(selection.selection_set, path + [field_name])

    for definition in ast.definitions:
        if isinstance(definition, OperationDefinitionNode):
            if definition.name:
                operations.add(definition.name.value)

            if definition.selection_set:
                traverse_selection(definition.selection_set, [])

    return list(fields), list(edges), list(operations)[0] if operations else None


def is_successful_graphql_response(payload):
    if payload.get("response_status") != 200:
        return False

    body = payload.get("response_body")
    if not isinstance(body, dict):
        return False

    # Fail if GraphQL "errors" array exists
    if "errors" in body and body["errors"]:
        return False

    # Must have non-empty, non-null data
    data = body.get("data")
    if not data:
        return False

    # ✅ Correct indentation here
    for key, value in data.items():
        if value is None:
            continue

        # Handle list of results (common GraphQL pattern)
        if isinstance(value, list):
            if not value:
                continue  # Empty list = fail
            # Check if any item has at least one non-null field
            for item in value:
                if isinstance(item, dict) and any(v is not None for v in item.values()):
                    return True
                if item is not None:
                    return True
            continue

        # Handle single object with fields
        if isinstance(value, dict):
            if any(v is not None for v in value.values()):
                return True

        # Handle scalar non-null value
        if value is not None:
            return True

    # If none of the data values were "real", fail
    return False
