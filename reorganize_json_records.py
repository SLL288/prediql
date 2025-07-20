import os
import json
import re
from config import Config

# ROOT_DIR = "prediql-output"
ROOT_DIR = Config.OUTPUT_DIR
LLAMA_FILENAME = "llama_queries.json"

def extract_top_level_field(query_text):
    """
    Extracts first field after '{' in GraphQL query.
    E.g., query { charactersByIds { ... } } → 'charactersByIds'
    """
    match = re.search(r'\{\s*([a-zA-Z0-9_]+)', query_text)
    if match:
        return match.group(1)
    return None

def append_json_to_file(folder_path, filename, data):
    """
    Appends `data` as an element in a JSON array file.
    Creates the file with an array if it doesn't exist yet.
    """
    os.makedirs(folder_path, exist_ok=True)
    path = os.path.join(folder_path, filename)

    # Load existing JSON array if file exists
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            try:
                existing_data = json.load(f)
                if not isinstance(existing_data, list):
                    raise ValueError("File does not contain a JSON array")
            except json.JSONDecodeError:
                existing_data = []
    else:
        existing_data = []

    # Append the new data
    print(f"length of data before editing: {len(existing_data)}")
    existing_data.append(data)
    print(f"length of data after editing: {len(existing_data)}")
    # Write back the full array
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(existing_data, f, indent=2)
    except Exception as e:
        print(f"❌ Failed to write JSON to {path}: {e}")


def process_records(node):
    input_file = os.path.join(ROOT_DIR, node, LLAMA_FILENAME)
    if not os.path.isfile(input_file):
        print(f"⚠️ Skipping: {input_file} does not exist.")
        return

    print(f"📂 Processing: {input_file}")
    with open(input_file, encoding='utf-8') as f:
        try:
            records = json.load(f)
        except json.JSONDecodeError as e:
            print(f"❌ Failed to parse JSON lines in {input_file}: {e}")
            return

    filtered_records = []

    for record in records:
        if not record.get("success"):
            filtered_records.append(record)
            continue

        query_text = record.get("query")
        if not query_text:
            filtered_records.append(record)
            continue

        folder_name = node
        top_level_field = extract_top_level_field(query_text)
        if not top_level_field:
            print(f"⚠️ Could not extract top-level field from query in {node}")
            filtered_records.append(record)
            continue

        if top_level_field != folder_name:
            print(f"❗ Mismatch in {node}: top_level_field={top_level_field} vs folder_name={folder_name}")
            append_json_to_file(os.path.join(ROOT_DIR, top_level_field), LLAMA_FILENAME, record)
            # Do not add to filtered list (remove from this file)
        else:
            filtered_records.append(record)

    # Overwrite with filtered list (as NDJSON)
    with open(input_file, 'w', encoding='utf-8') as f:
        json.dump(filtered_records, f, indent=2)


def process_all_nodes():
    """
    Find all subfolders under ROOT_DIR and process their llama_queries.json.
    """
    if not os.path.isdir(ROOT_DIR):
        print(f"❌ Root directory does not exist: {ROOT_DIR}")
        return

    for node in os.listdir(ROOT_DIR):
        node_path = os.path.join(ROOT_DIR, node)
        if os.path.isdir(node_path):
            process_records(node)

if __name__ == "__main__":
    process_all_nodes()
