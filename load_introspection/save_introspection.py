import argparse
import json
import requests

from introspection_query import introspection_query


def _graphql_headers_from_optional_key(api_key):
    h = {"Content-Type": "application/json"}
    if not api_key or not str(api_key).strip():
        return h
    s = str(api_key).strip()
    low = s.lower()
    if low.startswith("bearer ") or low.startswith("basic "):
        h["Authorization"] = s
    else:
        h["Authorization"] = f"Bearer {s}"
    return h


def fetch_introspection_schema(graphql_endpoint, headers=None, output_file="load_introspection/introspection_result.json"):
    # 1️⃣ The standard Introspection Query
    # 2️⃣ Prepare request
    payload = {"query": introspection_query}
    headers = headers or {"Content-Type": "application/json"}

    # 3️⃣ Make POST request
    print(f"✅ Sending introspection query to {graphql_endpoint} ...")
    response = requests.post(graphql_endpoint, json=payload, headers=headers)
    response.raise_for_status()

    result_json = response.json()
    print("✅ Introspection query successful!")

    # 4️⃣ Save to file
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(result_json, f, indent=2, ensure_ascii=False)

    print(f"✅ Introspection result saved to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch GraphQL introspection schema.")
    parser.add_argument("--url", required=True, help="GraphQL endpoint URL")
    parser.add_argument(
        "--graphql-api-key",
        default=None,
        help="Optional Authorization secret (raw token becomes Bearer …).",
    )
    parser.add_argument(
        "--output-file",
        default="introspection_result.json",
        help="Where to write introspection JSON (default: ./introspection_result.json).",
    )

    args = parser.parse_args()

    GRAPHQL_ENDPOINT = args.url
    # ======= EDIT THIS ========
    # GRAPHQL_ENDPOINT = "https://api.react-finland.fi/graphql"
    # GRAPHQL_ENDPOINT = "https://portal.ehri-project.eu/api/graphql"
    # GRAPHQL_ENDPOINT = "https://rickandmortyapi.com/graphql"
    # GRAPHQL_ENDPOINT = "https://swapi-graphql.netlify.app/graphql"

    HEADERS = _graphql_headers_from_optional_key(args.graphql_api_key)
    OUTPUT_FILE = args.output_file
    # ===========================

    fetch_introspection_schema(
        graphql_endpoint=GRAPHQL_ENDPOINT,
        headers=HEADERS,
        output_file=OUTPUT_FILE
    )
