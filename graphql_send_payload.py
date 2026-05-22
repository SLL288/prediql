import os
import json
import time
import random
import requests
from datetime import datetime
from graphql import parse
from graphql.language.ast import FieldNode, OperationDefinitionNode

from config import Config

def normalize_vulnerability_type(raw, default="unknown") -> str:
    """Normalize vulnerability labels from LLM output into canonical snake_case tokens."""
    if raw is None:
        return default
    s = str(raw).strip().lower()
    if not s:
        return default
    s = s.replace("-", "_").replace(" ", "_")
    aliases = {
        "basiccall": "basic_call",
        "basic_call": "basic_call",
        "field_suggestions": "field_suggestions",
        "fieldsuggestions": "field_suggestions",
        "none": "basic_call",
        "baseline": "basic_call",
    }
    if s in aliases:
        return aliases[s]
    if "query_deny_bypass_non_aliased" in s:
        return "query_deny_bypass_non_aliased"
    if "query_deny_bypass_aliased" in s:
        return "query_deny_bypass_aliased"
    if "query_deny_bypass" in s:
        return "query_deny_bypass"
    return s


def graphql_request_headers() -> dict:
    """JSON POST headers for the target GraphQL API, including optional auth from ``Config``."""
    h = {"Content-Type": "application/json"}
    custom = getattr(Config, "CUSTOM_HEADERS", None) or {}
    if isinstance(custom, dict):
        h.update(custom)
    auth = getattr(Config, "AUTHORIZATION", None)
    if auth:
        s = str(auth).strip()
        low = s.lower()
        if low.startswith("bearer ") or low.startswith("basic "):
            h["Authorization"] = s
        else:
            h["Authorization"] = f"Bearer {s}"
    return h


def send_payload(GRAPHQL_URL, jsonfile_path, output_jsonfile_path=None):
    if not os.path.exists(jsonfile_path) or os.path.getsize(jsonfile_path) == 0:
        print(f"❌ File not found or empty: {jsonfile_path}")
        return False, 0, False, []

    req_headers = graphql_request_headers()

    try:
        with open(jsonfile_path, "r") as f:
            payloads = json.load(f)
    except json.JSONDecodeError as e:
        print(f"❌ Error reading JSON: {e}")
        return False, 0, False, []

    updated_payloads = []
    newly_processed_responses = []  # Track only newly processed responses
    https200 = False
    negative_success = False
    requests_count = 0

    for i, payload in enumerate(payloads, start=1):
        # ✅ Skip if already has response
        if "response_status" in payload and "response_body" in payload:
            updated_payloads.append(payload)
            continue
        
        if "retry_status" in payload and "retry_response_body" in payload:
            updated_payloads.append(payload)
            continue
        
        # Track that we're processing a new payload
        is_newly_processed = True

        try:
            # Handle new query format with vulnerability type
            query_text = None
            vulnerability_type = "unknown"
            
            if "query" in payload:
                if isinstance(payload["query"], dict):
                    # New format: {"query": "actual_query", "vulnerability_type": "sql_injection"}
                    query_text = payload["query"].get("query")
                    vulnerability_type = payload["query"].get("vulnerability_type", "unknown")
                else:
                    # Old format: {"query": "actual_query"}
                    query_text = payload["query"]
            elif "mutation" in payload:
                if isinstance(payload["mutation"], dict):
                    query_text = payload["mutation"].get("query")
                    vulnerability_type = payload["mutation"].get("vulnerability_type", "unknown")
                else:
                    query_text = payload["mutation"]
            else:
                print(f"⚠️ Skipping payload {i}: No 'query' or 'mutation' found.")
                updated_payloads.append(payload)
                continue

            vulnerability_type = normalize_vulnerability_type(vulnerability_type, default="unknown")

            if not query_text:
                print(f"⚠️ Skipping payload {i}: Empty query text.")
                updated_payloads.append(payload)
                continue

            # Special handling for query deny bypass - requires two queries
            if vulnerability_type in ["query_deny_bypass_non_aliased", "query_deny_bypass_aliased"]:
                # Find the corresponding query for query deny bypass
                non_aliased_query = None
                aliased_query = None
                
                # Look for both queries in the payloads
                for p in payloads:
                    if isinstance(p.get("query"), dict):
                        p_vuln_type = normalize_vulnerability_type(
                            p["query"].get("vulnerability_type", "unknown"),
                            default="unknown",
                        )
                        if p_vuln_type == "query_deny_bypass_non_aliased":
                            non_aliased_query = p["query"].get("query")
                        elif p_vuln_type == "query_deny_bypass_aliased":
                            aliased_query = p["query"].get("query")
                
                if not non_aliased_query or not aliased_query:
                    print(f"⚠️ Skipping payload {i}: Missing query deny bypass pair.")
                    updated_payloads.append(payload)
                    continue
                
                # Send both queries and store responses
                responses = {}
                
                # Send non-aliased query
                request_payload = {"query": non_aliased_query}
                start_time = time.time()
                non_aliased_response = requests.post(GRAPHQL_URL, headers=req_headers, json=request_payload, timeout=10)
                non_aliased_time = time.time() - start_time
                
                responses["non_aliased"] = {
                    "response_status": non_aliased_response.status_code,
                    "request_time_seconds": round(non_aliased_time, 3),
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
                
                try:
                    responses["non_aliased"]["response_body"] = non_aliased_response.json()
                except ValueError:
                    responses["non_aliased"]["response_body"] = {"error": "Invalid JSON", "raw": non_aliased_response.text}
                
                # Send aliased query
                request_payload = {"query": aliased_query}
                start_time = time.time()
                aliased_response = requests.post(GRAPHQL_URL, headers=req_headers, json=request_payload, timeout=10)
                aliased_time = time.time() - start_time
                
                responses["aliased"] = {
                    "response_status": aliased_response.status_code,
                    "request_time_seconds": round(aliased_time, 3),
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
                
                try:
                    responses["aliased"]["response_body"] = aliased_response.json()
                except ValueError:
                    responses["aliased"]["response_body"] = {"error": "Invalid JSON", "raw": aliased_response.text}
                
                # Update payload with both responses
                payload.update({
                    "query_deny_bypass_responses": responses,
                    "vulnerability_type": "query_deny_bypass",
                    "count": i,
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                })
                
                # Use the non-aliased response for success checking
                response = non_aliased_response
                request_time = non_aliased_time
                
            else:
                # Normal single query handling
                request_payload = {"query": query_text}

                # Send request
                start_time = time.time()
                response = requests.post(GRAPHQL_URL, headers=req_headers, json=request_payload, timeout=10)
                request_time = time.time() - start_time

                payload.update({
                    "response_status": response.status_code,
                    "request_time_seconds": round(request_time, 3),
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "count": i,
                    "vulnerability_type": vulnerability_type
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

            # Check for negative_success: valid GraphQL but server error
            is_negative_success = is_negative_success_response(payload)
            if success:
                print(f"✅ Valid 200 response with data for payload {i}")
                https200 = True
            elif is_negative_success:
                print(f"⚠️ Negative success: Valid GraphQL but server error for payload {i}")
                negative_success = True
            requests_count = i

        except requests.exceptions.RequestException as e:
            payload.update({
                "response_status": None,
                "request_time_seconds": round(time.time() - start_time, 3),
                "response_body": {"error": str(e)},
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "count": i
            })

        if payload.get("response_body") in (None, {}, []):
            print(f"⚠️ Empty response body for payload {i} (no fallback retry).")

        # ✅ Append exactly once
        updated_payloads.append(payload)
        
        # Add to newly processed responses if this was a new payload
        if is_newly_processed:
            newly_processed_responses.append(payload)

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
    print(f"🔍 Newly processed responses: {len(newly_processed_responses)}")
    return https200, requests_count, negative_success, newly_processed_responses

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
        if key == "_":
            return True

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

def is_negative_success_response(payload):
    """
    Check if this is a negative_success case:
    - Query is valid GraphQL (syntactically correct)
    - But results in server error (non-200 status or 200 with non-schema related errors)
    """
    # First check if the query is valid GraphQL
    query_text = payload.get("query") or payload.get("mutation")
    if not query_text:
        return False
    
    # Check if query is syntactically valid GraphQL
    try:
        from graphql import parse
        parse(query_text)
    except Exception:
        return False  # Invalid GraphQL syntax, not negative_success
    
    # Check response status
    status = payload.get("response_status")
    if status is None:
        return False  # No response received
    
    # Case 1: Non-200 status code - check if errors are schema-related
    if status != 200:
        # Check response body for error details
        body = payload.get("response_body")
        if isinstance(body, dict) and "errors" in body and body["errors"]:
            # Check if any errors are schema-related
            for error in body["errors"]:
                if isinstance(error, dict):
                    message = error.get("message", "").lower()
                    # Check if it's a schema-related error
                    schema_related_keywords = [
                        "cannot query field", "field does not exist", "unknown field",
                        "field is not defined", "cannot return null", "non-null field",
                        "required field", "invalid argument", "argument does not exist",
                        "expected", "got", "syntax error", "parse error", "did you mean"
                    ]
                    
                    is_schema_error = any(keyword in message for keyword in schema_related_keywords)
                    if is_schema_error:
                        return False  # Schema-related error, not negative success
        # If no errors field or non-schema errors, it's a server error (negative success)
        return True
    
    # Case 2: 200 status but with non-schema related errors
    body = payload.get("response_body")
    if not isinstance(body, dict):
        return False
    
    # Check for GraphQL errors that are not schema-related
    if "errors" in body and body["errors"]:
        for error in body["errors"]:
            if isinstance(error, dict):
                message = error.get("message", "").lower()
                # Check if it's not a schema-related error
                schema_related_keywords = [
                    "cannot query field", "field does not exist", "unknown field",
                    "field is not defined", "cannot return null", "non-null field",
                    "required field", "invalid argument", "argument does not exist",
                    "expected", "got", "syntax error", "parse error", "did you mean"
                ]
                
                is_schema_error = any(keyword in message for keyword in schema_related_keywords)
                if not is_schema_error:
                    return True  # Non-schema related error
    
    return False
