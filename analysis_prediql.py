import os
import json
import yaml
import re
from config import Config
# CONFIG
# DATA_DIR = "prediql-output/"  # current folder with all node folders
DATA_DIR = Config.OUTPUT_DIR
OUTPUT_REPORT = os.path.join(DATA_DIR,"coverage_report.txt")

# QUERY_YAML = "load_introspection/query_parameter_list_graphqler.yml"
QUERY_YAML = "generated_query_info.json"
OBJECT_YAML = "load_introspection/object_list.yml"

# Load schema files
with open(QUERY_YAML, encoding="utf-8") as f:
    query_params = yaml.safe_load(f)
with open(OBJECT_YAML, encoding="utf-8") as f:
    object_list = yaml.safe_load(f)

# Helper to flatten GraphQL Type
def flatten_type(t):
    if not t:
        return ""
    if isinstance(t, str):
        # Remove GraphQL list and non-null syntax
        t = t.replace("[", "").replace("]", "").replace("!", "").strip()
        return t
    if t.get("kind") == "NON_NULL":
        return flatten_type(t.get("ofType"))
    if t.get("kind") == "LIST":
        return flatten_type(t.get("ofType"))
    return t.get("name") or ""


# Compute all fields/edges from schema
def get_total_fields_edges_for_node(node_name, query_param_list, object_dict):
    if node_name not in query_param_list:
        return set(), set()
    output_type = query_param_list[node_name].get("output") or query_param_list[node_name].get("output_type")
    if not output_type:
        # Try to guess from relevant_schema if present
        if "relevant_schema" in query_param_list[node_name]:
            relevant_schema = query_param_list[node_name]["relevant_schema"]
            if relevant_schema:
                output_type = next(iter(relevant_schema.keys()), None)
                if output_type:
                    print(f"⚠️ No output_type for {node_name}, guessing: {output_type}")
        if not output_type:
            print(f"❌ Cannot determine output_type for {node_name}")
            return set(), set()     
    base_type = flatten_type(output_type)
    fields, edges, visited = set(), set(), set()
    def traverse(curr, path):
        if curr in visited:
            return
        visited.add(curr)
        if curr not in object_dict:
            return
        for field in object_dict[curr].get("fields", []):
            fname = field["name"]
            fields.add(fname)
            edge_path = ".".join(path + [fname])
            edges.add(edge_path)
            next_type = flatten_type(field["type"])
            if next_type in object_dict:
                traverse(next_type, path + [fname])
    traverse(base_type, [node_name])
    return fields, edges

def analyze_node(node_folder, out_lines, covered_nodes):
    node_name = os.path.basename(node_folder)
    json_path = os.path.join(node_folder, "llama_queries.json")
    if not os.path.isfile(json_path):
        return

    try:
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        out_lines.append(f"❌ Failed to read {json_path}: {e}\n")
        return

    total_requests = len(data)
    num_successes = sum(1 for r in data if r.get("success"))

    # Node-level coverage
    node_success = num_successes > 0
    if node_success:
        covered_nodes.add(node_name)

    # Choose schema source
    if node_name in query_params and "relevant_schema" in query_params[node_name]:
        schema_used = "relevant_schema"
        schema_object_list = query_params[node_name]["relevant_schema"]
    else:
        schema_used = "GLOBAL object_list"
        schema_object_list = object_list

    # Schema analysis
    total_fields, total_edges = get_total_fields_edges_for_node(
        node_name,
        query_params,
        schema_object_list
    )

    # Sets
    all_fields_attempted, all_edges_attempted, all_ops_attempted = set(), set(), set()
    all_fields_success, all_edges_success, all_ops_success = set(), set(), set()

    for record in data:
        fields = record.get("fields", [])
        edges = record.get("edges", [])
        op = record.get("operation_name")

        filtered_fields = [f for f in fields if f in total_fields]
        filtered_edges = [e for e in edges if e in total_edges]

        all_fields_attempted.update(filtered_fields)
        all_edges_attempted.update(filtered_edges)
        if op:
            all_ops_attempted.add(op)

        if record.get("success"):
            filtered_fields_succ = [f for f in fields if f in total_fields]
            filtered_edges_succ = [e for e in edges if e in total_edges]
            all_fields_success.update(filtered_fields_succ)
            all_edges_success.update(filtered_edges_succ)
            if op:
                all_ops_success.add(op)

    # Metrics
    def calc_ratio(numerator, denominator):
        return (len(numerator & denominator) / len(denominator) * 100) if denominator else 0

    attempt_field_cov = calc_ratio(all_fields_attempted, total_fields)
    success_field_cov = calc_ratio(all_fields_success, total_fields)
    attempt_edge_cov = calc_ratio(all_edges_attempted, total_edges)
    success_edge_cov = calc_ratio(all_edges_success, total_edges)

    success_rate = (num_successes / total_requests * 100) if total_requests else 0

    field_quality_index = (success_field_cov * success_rate) / 100
    edge_quality_index = (success_edge_cov * success_rate) / 100
    composite_quality_score = (field_quality_index + edge_quality_index) / 2

    # Write to output
    out_lines.append(f"\n================= NODE: {node_name} =================")
    out_lines.append(f"Records total: {total_requests}")
    out_lines.append(f"✅ Successful requests: {num_successes}")
    out_lines.append(f"✅ Success Rate: {success_rate:.1f}%")
    out_lines.append(f"✅ Schema source used: {schema_used}")

    out_lines.append("\n✅ Attempted Coverage")
    out_lines.append(f"- Fields: {len(all_fields_attempted)}")
    out_lines.append(f"- Edges:  {len(all_edges_attempted)}")
    out_lines.append(f"- Operations: {len(all_ops_attempted)}")

    out_lines.append("\n✅ Successful Coverage")
    out_lines.append(f"- Fields: {len(all_fields_success)}")
    out_lines.append(f"- Edges:  {len(all_edges_success)}")
    out_lines.append(f"- Operations: {len(all_ops_success)}")

    out_lines.append("\n================ SCHEMA ANALYSIS ================")
    out_lines.append(f"Total possible fields in schema for '{node_name}': {len(total_fields)}")
    out_lines.append(f"Total possible edges in schema for '{node_name}': {len(total_edges)}")

    out_lines.append("\n✅ True Coverage against Schema")
    out_lines.append(f"- Attempted Field Coverage: {attempt_field_cov:.1f}%")
    out_lines.append(f"- Successful Field Coverage: {success_field_cov:.1f}%")
    out_lines.append(f"- Attempted Edge Coverage: {attempt_edge_cov:.1f}%")
    out_lines.append(f"- Successful Edge Coverage: {success_edge_cov:.1f}%")

    out_lines.append("\n================= QUALITY INDEX ==================")
    out_lines.append(f"- Field Coverage Quality Index: {field_quality_index:.1f}")
    out_lines.append(f"- Edge Coverage Quality Index: {edge_quality_index:.1f}")
    out_lines.append(f"- Composite Coverage Quality Score: {composite_quality_score:.1f}")
    out_lines.append("=" * 55 + "\n")

    # ✅ RETURN the counts for aggregation
    return len(total_fields), len(total_edges), len(all_fields_success), len(all_edges_success)

if __name__ == "__main__":
    all_summaries = []
    covered_nodes = set()
    total_nodes_attempted = 0

    # Initialize global totals for overall schema coverage
    total_all_possible_fields = 0
    total_all_success_fields = 0
    total_all_possible_edges = 0
    total_all_success_edges = 0

    # Go through all subfolders in DATA_DIR
    for entry in os.listdir(DATA_DIR):
        node_folder = os.path.join(DATA_DIR, entry)
        if os.path.isdir(node_folder):
            llama_file = os.path.join(node_folder, "llama_queries.json")
            if os.path.isfile(llama_file):
                total_nodes_attempted += 1

                # Call analyze_node and collect per-node coverage
                result = analyze_node(node_folder, all_summaries, covered_nodes)
                if result:
                    possible_fields, possible_edges, success_fields, success_edges = result
                    total_all_possible_fields += possible_fields
                    total_all_success_fields += success_fields
                    total_all_possible_edges += possible_edges
                    total_all_success_edges += success_edges

    # Add node coverage metric summary
    coverage_ratio = (len(covered_nodes) / total_nodes_attempted * 100) if total_nodes_attempted else 0
    all_summaries.append("\n================ OVERALL NODE COVERAGE ================")
    all_summaries.append(f"Total nodes attempted: {total_nodes_attempted}")
    all_summaries.append(f"Nodes successfully covered: {len(covered_nodes)}")
    all_summaries.append(f"✅ Node Coverage Ratio: {coverage_ratio:.1f}%")
    all_summaries.append("\n✅ Nodes covered:")
    for node in sorted(covered_nodes):
        all_summaries.append(f"- {node}")
    all_summaries.append("=" * 55 + "\n")

    # Add overall schema-level coverage summary
    if total_all_possible_fields:
        overall_success_field_coverage = (total_all_success_fields / total_all_possible_fields) * 100
    else:
        overall_success_field_coverage = 0

    if total_all_possible_edges:
        overall_success_edge_coverage = (total_all_success_edges / total_all_possible_edges) * 100
    else:
        overall_success_edge_coverage = 0

    all_summaries.append("\n================ OVERALL SCHEMA COVERAGE ================")
    all_summaries.append(f"✅ Total possible fields across all nodes: {total_all_possible_fields}")
    all_summaries.append(f"✅ Total successfully hit fields: {total_all_success_fields}")
    all_summaries.append(f"✅ Overall Successful Field Coverage: {overall_success_field_coverage:.1f}%")
    all_summaries.append("")
    all_summaries.append(f"✅ Total possible edges across all nodes: {total_all_possible_edges}")
    all_summaries.append(f"✅ Total successfully hit edges: {total_all_success_edges}")
    all_summaries.append(f"✅ Overall Successful Edge Coverage: {overall_success_edge_coverage:.1f}%")
    all_summaries.append("=" * 55 + "\n")

    # Write one report file
    with open(OUTPUT_REPORT, "w", encoding="utf-8") as f:
        for line in all_summaries:
            f.write(line + "\n")

    print(f"\n✅ All summaries written to {OUTPUT_REPORT}")
