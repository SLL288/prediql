import os
import json
from config import Config, run_node_dir
# Paths resolved at call time via ``Config`` (see ``configure_run_artifacts`` / ``PREDIQL_OUTPUT_DIR``).

# Load QUERY_INFO
# with open(QUERY_INFO_PATH) as f:
#     QUERY_INFO = json.load(f)
# all_records = []
def flatten_record_to_text(record):
    lines = []
    lines.append(f"GraphQL source: {record.get('source')}")
    lines.append(f"Query: {record.get('query_name')}")
    lines.append(f"Node Type: {record.get('node_type')}")
    lines.append("")
    lines.append("Fields:")
    record_data = record.get("record", {})
    if isinstance(record_data, dict):
        for k, v in record_data.items():
            lines.append(f"- {k}: {v}")
    else:
        # If record is not a dict (e.g., string, list, etc.), just show its value
        lines.append(f"- data: {record_data}")
    
    return "\n".join(lines)

def flatten_real_data():
    # Load QUERY_INFO dynamically to ensure it's fresh
    query_path = Config.GENERATED_QUERY_INFO_JSON
    raw_base = Config.OUTPUT_DIR
    out_path = Config.REAL_DATA_JSON
    try:
        with open(query_path, encoding="utf-8") as f:
            query_info = json.load(f)
    except FileNotFoundError:
        print(f"❌ File not found: {query_path}")
        return 0
    except json.JSONDecodeError:
        print(f"❌ Invalid JSON format in: {query_path}")
        return 0

    all_records = []

    for node_name in query_info.keys():
        print(node_name)
        # Per-node payloads live under OUTPUT_DIR/nodes/<node>/ (legacy: OUTPUT_DIR/<node>/).
        folder_path = run_node_dir(node_name)
        if not os.path.isdir(folder_path):
            legacy = os.path.join(os.path.abspath(raw_base), node_name)
            if os.path.isdir(legacy):
                folder_path = legacy
            else:
                print(f"⚠️ Skipping {node_name}: folder not found")
                continue

        if os.path.isfile(os.path.join(folder_path, "llama_queries.json")):
            json_names = ["llama_queries.json"]
        else:
            json_names = [f for f in os.listdir(folder_path) if f.endswith(".json")]

        for filename in json_names:
            file_path = os.path.join(folder_path, filename)
            try:
                with open(file_path) as f:
                    raw_list = json.load(f)
            except Exception as e:
                print(f"⚠️ Failed to load {file_path}: {e}")
                continue

            # Should be a list of entries (each is a single query run)
            if not isinstance(raw_list, list):
                print(f"⚠️ Skipping {file_path}: not a list")
                continue

            # Extract records from each query response
            for entry in raw_list:
                if not entry.get("success", False):
                    continue

                response_body = entry.get("response_body", {})
                data = response_body.get("data", {})
                if not data or node_name not in data:
                    continue

                top_level_data = data.get(node_name)
                if not top_level_data:
                    continue

                # ✅ Handle edges (Relay-style)
                if isinstance(top_level_data, dict):
                    edges = top_level_data.get("edges")
                    if edges and isinstance(edges, list):
                        for edge in edges:
                            node = edge.get("node")
                            if node:
                                single_record = {
                                    "source": query_info[node_name]["source"],
                                    "query_name": node_name,
                                    "node_type": query_info[node_name]["node_type"],
                                    "record": node,
                                }
                                single_record["text"] = flatten_record_to_text(single_record)
                                all_records.append(single_record)
                        continue  # done with this entry

                    # ✅ Handle results (Offset-style)
                    results = top_level_data.get("results")
                    if results and isinstance(results, list):
                        for item in results:
                            single_record = {
                                "source": query_info[node_name]["source"],
                                "query_name": node_name,
                                "node_type": query_info[node_name]["node_type"],
                                "record": item,
                            }
                            single_record["text"] = flatten_record_to_text(single_record)
                            all_records.append(single_record)
                        continue  # done with this entry

                    # ✅ Handle top-level list directly
                    if isinstance(top_level_data, list):
                        for item in top_level_data:
                            single_record = {
                                "source": query_info[node_name]["source"],
                                "query_name": node_name,
                                "node_type": query_info[node_name]["node_type"],
                                "record": item,
                            }
                            single_record["text"] = flatten_record_to_text(single_record)
                            all_records.append(single_record)
                        continue

                    # ✅ Handle single object
                    if isinstance(top_level_data, dict):
                        single_record = {
                            "source": query_info[node_name]["source"],
                            "query_name": node_name,
                            "node_type": query_info[node_name]["node_type"],
                            "record": top_level_data,
                        }
                        single_record["text"] = flatten_record_to_text(single_record)
                        all_records.append(single_record)
                elif isinstance(top_level_data, list):
                    # Top-level list (array of records)
                    for item in top_level_data:
                        single_record = {
                            "source": query_info[node_name]["source"],
                            "query_name": node_name,
                            "node_type": query_info[node_name]["node_type"],
                            "record": item,
                        }
                        single_record["text"] = flatten_record_to_text(single_record)
                        all_records.append(single_record)
                    continue
                    
    

    # ✅ Save to real_data.json
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(all_records, f, indent=2)
    print(f"✅ Saved {len(all_records)} records to {out_path}")
    return len(all_records)
