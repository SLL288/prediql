import os
import json
from config import Config

# PATHS
RAW_DATA_BASE = Config.OUTPUT_DIR
QUERY_INFO_PATH = "generated_query_info.json"
REAL_DATA_OUTPUT_PATH = "real_data.json"
ERROR_PATH = "errors.json"

all_records = []

def flatten_record_to_text(record):
    lines = []
    lines.append(f"GraphQL source: {record.get('source')}")
    lines.append(f"Query: {record.get('query_name')}")
    lines.append(f"Node Type: {record.get('node_type')}")
    if record.get("has_error", False):
        lines.append(f"Error: {record.get('error')}")
        return "\n".join(lines)
    lines.append(f"Has Error: {record.get('has_error', False)}")
    lines.append("")
    lines.append("Fields:")
    for k, v in record.get("record", {}).items():
        lines.append(f"- {k}: {v}")
    return "\n".join(lines)

def flatten_real_data():
    # Load QUERY_INFO inside the function
    try:
        with open(QUERY_INFO_PATH) as f:
            QUERY_INFO = json.load(f)
    except FileNotFoundError:
        print(f"❌ Error: {QUERY_INFO_PATH} not found. Please generate it first.")
        return 0
    except json.JSONDecodeError:
        print(f"❌ Error: Could not decode JSON from {QUERY_INFO_PATH}.")
        return 0

    # Clear global all_records
    global all_records
    all_records = []
    errors = []

    for node_name in QUERY_INFO.keys():
        print(node_name)
        # Determine which folder to look in
        folder_path = os.path.join(RAW_DATA_BASE, node_name)
        if not os.path.isdir(folder_path):
            print(f"⚠️ Skipping {node_name}: folder not found")
            continue

        # Load all JSON files in the folder
        for filename in os.listdir(folder_path):
            if not filename.endswith(".json"):
                continue

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
                response_body = entry.get("response_body", {})
                round = entry.get("round",-1)
                
                if  not entry.get("success", False):
                    errors = response_body.get("errors", [])
                    if len(errors) < 1:
                        single_record = {
                            "source": QUERY_INFO[node_name]["source"],
                            "query_name": node_name,
                            "node_type": QUERY_INFO[node_name]["node_type"],
                            "error": "Response body is empty, invalid input filters",
                            "has_error": True,
                            "round": round
                        }
                        errors.append(single_record)
                        # single_record["text"] = flatten_record_to_text(single_record)
                        # all_records.append(single_record)   
                        continue
                    for error in errors:
                        print("ERROR in flatten_real_data", error)
                        message = error.get("message", "")
                        single_record = {
                            "source": QUERY_INFO[node_name]["source"],
                            "query_name": node_name,
                            "node_type": QUERY_INFO[node_name]["node_type"],
                            "error": message,
                            "has_error": True,
                            "round": round
                        }
                        errors.append(single_record)
                        # single_record["text"] = flatten_record_to_text(single_record)
                        # all_records.append(single_record)
                    continue
                
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
                                    "source": QUERY_INFO[node_name]["source"],
                                    "query_name": node_name,
                                    "node_type": QUERY_INFO[node_name]["node_type"],
                                    "record": node,
                                    "has_error": False,
                                    "round": round
                                }
                                single_record["text"] = flatten_record_to_text(single_record)
                                all_records.append(single_record)
                        continue  # done with this entry

                    # ✅ Handle results (Offset-style)
                    results = top_level_data.get("results")
                    if results and isinstance(results, list):
                        for item in results:
                            single_record = {
                                "source": QUERY_INFO[node_name]["source"],
                                "query_name": node_name,
                                "node_type": QUERY_INFO[node_name]["node_type"],
                                "record": item,
                                "has_error": False,
                                "round": round
                            }
                            single_record["text"] = flatten_record_to_text(single_record)
                            all_records.append(single_record)
                        continue  # done with this entry

                    # ✅ Handle top-level list directly
                    if isinstance(top_level_data, list):
                        for item in top_level_data:
                            single_record = {
                                "source": QUERY_INFO[node_name]["source"],
                                "query_name": node_name,
                                "node_type": QUERY_INFO[node_name]["node_type"],
                                "record": item,
                                "has_error": False,
                                "round": round
                            }
                            single_record["text"] = flatten_record_to_text(single_record)
                            all_records.append(single_record)
                        continue

                    # ✅ Handle single object
                    if isinstance(top_level_data, dict):
                        single_record = {
                            "source": QUERY_INFO[node_name]["source"],
                            "query_name": node_name,
                            "node_type": QUERY_INFO[node_name]["node_type"],
                            "record": top_level_data,
                            "has_error": False,
                            "round": round
                        }
                        single_record["text"] = flatten_record_to_text(single_record)
                        all_records.append(single_record)
                elif isinstance(top_level_data, list):
                    # Top-level list (array of records)
                    for item in top_level_data:
                        single_record = {
                            "source": QUERY_INFO[node_name]["source"],
                            "query_name": node_name,
                            "node_type": QUERY_INFO[node_name]["node_type"],
                            "record": item,
                            "has_error": False,
                            "round": round
                        }
                        single_record["text"] = flatten_record_to_text(single_record)
                        all_records.append(single_record)
                    continue
                    
    

    # ✅ Save to real_data.json
    with open(REAL_DATA_OUTPUT_PATH, "w") as f:
        json.dump(all_records, f, indent=2)
    with open(ERROR_PATH, "w") as f:
        json.dump(errors, f, indent=2)
   
    print(f"✅ Saved {len(all_records)} records to {REAL_DATA_OUTPUT_PATH}")
    print(f"✅ Saved {len(errors)} errors to {ERROR_PATH}")
    return len(all_records)


if __name__ == "__main__":
    flatten_real_data()