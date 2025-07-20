import requests
import json
from introspection_query import introspection_query
import argparse

def fetch_introspection_schema(graphql_endpoint, headers=None, output_file="load_introspection/introspection_result.json"):
    # 1️⃣ The standard Introspection Query
    import requests


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

    args = parser.parse_args()

    GRAPHQL_ENDPOINT = args.url
    # ======= EDIT THIS ========
    # GRAPHQL_ENDPOINT = "https://api.react-finland.fi/graphql"
    # GRAPHQL_ENDPOINT = "https://portal.ehri-project.eu/api/graphql"
    # GRAPHQL_ENDPOINT = "https://rickandmortyapi.com/graphql"
    # GRAPHQL_ENDPOINT = "https://swapi-graphql.netlify.app/graphql"

    HEADERS = {
        "Authorization": "Bearer YOUR_TOKEN_IF_NEEDED"
    }
    OUTPUT_FILE = "introspection_result.json"
    # ===========================

    fetch_introspection_schema(
        graphql_endpoint=GRAPHQL_ENDPOINT,
        headers=HEADERS,
        output_file=OUTPUT_FILE
    )
