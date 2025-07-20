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


def get_final_node_type_from_objects(output, relevant_objects):
    """
    Walk relevant_objects from output to deepest node type
    """
    current = unwrap_type(output)
    while True:
        obj_def = relevant_objects.get(current)
        if not obj_def:
            return current
        next_type = None
        for field in obj_def.get("fields", []):
            if field["name"] == "edges":
                next_type = unwrap_type(field["type"])
                break
            if field["name"] == "node":
                next_type = unwrap_type(field["type"])
                break
        if not next_type or next_type == current:
            return current
        current = next_type


def get_node_info_generated(node_name):
    with open("generated_query_info.json") as f:
        query_params = json.load(f) or {}

    if node_name in query_params:
        node_info = query_params[node_name]
        inputs = node_info[""]
    # print(node_info)
    return node_info

def get_node_info(node_name):
    """
    Given a node name, find it in either query or mutation parameter list,
    and return its inputs, output type, and all relevant objects.
    """
    # Load all parameter lists
    with open("load_introspection/query_parameter_list.yml") as f:
        query_params = yaml.safe_load(f) or {}

    with open("load_introspection/mutation_parameter_list.yml") as f:
        mutation_params = yaml.safe_load(f) or {}

    with open("load_introspection/object_list.yml") as f:
        objects = yaml.safe_load(f) or {}

    # Determine source (query or mutation)
    if node_name in query_params:
        node_info = query_params[node_name]
        source = "query"
    elif node_name in mutation_params:
        node_info = mutation_params[node_name]
        source = "mutation"
    else:
        raise ValueError(f"❌ Node '{node_name}' not found in query or mutation parameter list.")

    # Extract inputs and output
    inputs = node_info["inputs"]
    output = node_info["output"]
    root_type = unwrap_type(output)
    # root_type = node_info["output"]["name"]

    # Recursively collect all needed objects
    relevant_objects = collect_relevant_objects(root_type, objects)

    #collect node type returned
    node_type = get_final_node_type_from_objects(output, relevant_objects)

    print(f"✅ Node '{node_name}' found in {source} parameter list.")
    return inputs, output, relevant_objects, source, node_type
