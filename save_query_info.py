import yaml
import json

def unwrap_type(type_str):
    """Remove GraphQL wrappers to get base type name."""
    return type_str.replace('!', '').replace('[', '').replace(']', '')

def collect_relevant_objects(root_type, all_objects):
    """Recursively collect all nested objects needed for the output type."""
    collected = {}

    def recurse(type_name):
        if type_name in collected:
            return
        obj_def = all_objects.get(type_name)
        if not obj_def:
            return
        collected[type_name] = obj_def
        for field in obj_def.get("fields", []):
            nested_type = unwrap_type(field["type"])
            recurse(nested_type)

    recurse(root_type)
    return collected

def trace_final_node_type(output_type, objects):
    """Follow edges → node to find final node type."""
    current_type = unwrap_type(output_type)
    visited = set()

    while True:
        if current_type in visited:
            # Prevent cycles
            return current_type
        visited.add(current_type)

        obj_def = objects.get(current_type)
        if not obj_def or "fields" not in obj_def:
            return current_type

        # Try to follow edges -> node
        next_type = None
        for field in obj_def["fields"]:
            if field["name"] == "edges":
                next_type = unwrap_type(field["type"])
                break
            if field["name"] == "node":
                next_type = unwrap_type(field["type"])
                break

        if not next_type or next_type == current_type:
            return current_type
        current_type = next_type

def save_query_info():
    """
    Generate and save enriched QUERY_INFO with:
    - source
    - parameters
    - output_type
    - node_type
    - relevant_schema
    """
    with open("load_introspection/query_parameter_list.yml") as f:
        query_params = yaml.safe_load(f) or {}

    with open("load_introspection/mutation_parameter_list.yml") as f:
        mutation_params = yaml.safe_load(f) or {}

    with open("load_introspection/object_list.yml") as f:
        objects = yaml.safe_load(f) or {}

    all_query_info = {}

    # Process queries
    for node_name, node_info in query_params.items():
        print(f"Processing query: {node_name}")
        inputs = node_info.get("inputs", {})
        output = node_info.get("output")
        root_type = unwrap_type(output)
        relevant_objects = collect_relevant_objects(root_type, objects)
        node_type = trace_final_node_type(output, relevant_objects)

        all_query_info[node_name] = {
            "source": "query",
            "parameters": inputs,
            "output_type": output,
            "node_type": node_type,
            "relevant_schema": relevant_objects
        }

    # Process mutations
    for node_name, node_info in mutation_params.items():
        print(f"Processing mutation: {node_name}")
        inputs = node_info.get("inputs", {})
        output = node_info.get("output")
        root_type = unwrap_type(output)
        relevant_objects = collect_relevant_objects(root_type, objects)
        node_type = trace_final_node_type(output, relevant_objects)

        all_query_info[node_name] = {
            "source": "mutation",
            "parameters": inputs,
            "output_type": output,
            "node_type": node_type,
            "relevant_schema": relevant_objects
        }

    # Save all collected info to a single JSON file
    with open("generated_query_info.json", "w") as f:
        json.dump(all_query_info, f, indent=2)

    print(f"✅ Saved enriched query info for {len(all_query_info)} nodes to generated_query_info.json")

save_query_info()
