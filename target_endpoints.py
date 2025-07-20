import re
import os 
import pandas as pd
from pathlib import Path
import yaml
import pandas as pd
from config import Config
import json
import ast

def extract_response_json_blocks(text):
    """
    Parse a text file containing multiple Payload/Response pairs.
    Handles both JSON and single-quote Python dict format.
    Returns a list of response JSON objects.
    """
    responses = []
    sections = text.split('------------------Payload:-------------------')

    for section in sections:
        if '------------------Response:-------------------' not in section:
            continue

        _, response_block = section.split('------------------Response:-------------------', 1)
        response_block = response_block.strip()

        if not response_block:
            continue

        # ✅ Try JSON first
        try:
            response_json = json.loads(response_block)
            responses.append(response_json)
            continue
        except json.JSONDecodeError:
            pass  # Fall through

        # ✅ Try parsing as Python literal
        try:
            parsed_python = ast.literal_eval(response_block)
            if isinstance(parsed_python, dict):
                responses.append(parsed_python)
            else:
                print("⚠️ Parsed but not a dict:", parsed_python)
        except Exception as e:
            print(f"⚠️ Could not parse as JSON or Python literal: {e}")
            print(response_block[:200], "...\n")

    return responses



def is_valid_response(response):
    """
    A response is valid if:
    - data is not null
    - errors field is empty or not present
    """
    if response.get("data") is None:
        return False
    if "errors" in response and response["errors"]:
        return False
    return True



import os
import json

def find200files(node_list, graphqler_output):
    """
    Go through endpoint_results folder.
    Check success/200 files that have *at least one* valid response with real data.
    """
    successnode = set()
    # base_path = Config.ENDPOINTS_RESULTS
    base_path = graphqler_output

    for folder_name in os.listdir(base_path):
        folder_path = os.path.join(base_path, folder_name)
        if not os.path.isdir(folder_path):
            continue

        success_path = os.path.join(folder_path, "success")
        success_file_200 = os.path.join(success_path, "200")

        if os.path.isdir(success_path) and os.path.isfile(success_file_200):
            if folder_name in node_list:
                try:
                    with open(success_file_200, "r", encoding="utf-8") as f:
                        text = f.read()

                    responses = extract_response_json_blocks(text)
                    if not responses:
                        print(f"❌ Excluded '{folder_name}': No valid JSON responses found in 200")
                        continue
                    # ✅ NEW RULE: include if ANY response is valid
                    if any(is_valid_response(r) for r in responses):
                        print(f"✅ Included '{folder_name}': At least one good response found")
                        successnode.add(folder_name)
                    else:
                        print(f"❌ Excluded '{folder_name}': All responses are errors or null data")
                except Exception as e:
                    print(f"⚠️ Error reading/parsing {success_file_200}: {e}")

    return successnode



def getnodefromcompiledfile():
    # Re-import required modules after code execution environment reset


    # Re-define file paths
    queries_path = "load_introspection/query_parameter_list.yml"
    mutations_path = "load_introspection/mutation_parameter_list.yml"

    # queries_path = Config.QUERY_FILE
    # mutations_path = Config.MUTATION_FILE

    # Load the YAML data
    with open(queries_path, 'r', encoding='utf-8') as f:
        queries_data = yaml.safe_load(f)

    with open(mutations_path, 'r', encoding='utf-8') as f:
        mutations_data = yaml.safe_load(f)

    # Extract node names
    query_nodes = list(queries_data.keys()) if isinstance(queries_data, dict) else []
    mutation_nodes = list(mutations_data.keys()) if isinstance(mutations_data, dict) else []

    # Combine into labeled list
    node_endpoints = [{"type": "query", "Node": node} for node in query_nodes] + \
                    [{"type": "mutation", "Node": node} for node in mutation_nodes]

    # Convert to DataFrame
    df_nodes = pd.DataFrame(node_endpoints)
    # print(df_nodes)
    return df_nodes
    # import ace_tools as tools; tools.display_dataframe_to_user(name="GraphQL Node Endpoints", dataframe=df_nodes)

## find those endpoint that not explored by graphqler:
# def find_target_endpoints():

#     df_node_compiled = getnodefromcompiledfile()
#     successnode = find200files(list(df_node_compiled['Node']))

#     print("\n \naccoding to list of endpoints from compiled file")
#     print("check if the success 200 file exist for specific endpoints")

#     df_node_compiled['success_200_file'] = '-'
#     # df_node_compiled['failure_200_file'] = '-'
#     df_node_compiled["success_200_file"] = df_node_compiled.Node.map(lambda x: "Yes" if x in successnode else "-")


#     print(df_node_compiled, "\ncount: ", len(df_node_compiled), " endpoints\n")
#     # target_endpoints = df_node_compiled.loc[df_node_compiled['success_200_file'] == '-']['Node']
#     target_endpoints = df_node_compiled['Node']
#     print(f"Targeting on these {len(target_endpoints)} endpoints: ")
#     print(list(target_endpoints))
#     return target_endpoints



def parse_table_file(filepath):
    result = {}

    with open(filepath, 'r') as f:
        lines = [line.strip() for line in f if line.strip()]

    # Filter only lines that look like table rows (with | separators)
    table_lines = [line for line in lines if '|' in line]

    # Extract header
    header_line = table_lines[0]
    header_parts = [part.strip() for part in header_line.split('|') if part.strip()]
    # Example: ['Node', 'Requests', 'Tokens', 'Succeed']

    # Process rows
    for row in table_lines[1:]:
        if row.startswith('+') or row.startswith('='):
            continue  # skip separator lines

        parts = [part.strip() for part in row.split('|') if part.strip()]
        if len(parts) != len(header_parts):
            continue  # skip malformed lines

        entry = {}
        node_name = parts[0]

        for i in range(1, len(header_parts)):
            header = header_parts[i]
            value = parts[i]

            # Try to convert
            if header.lower() == 'succeed':
                entry[header] = value.lower() == 'true'
            elif header.lower() in ('requests',):
                entry[header] = int(value.replace(',', ''))
            elif header.lower() in ('tokens',):
                entry[header] = float(value.replace(',', ''))
            else:
                entry[header] = value

        result[node_name] = entry

    return result


def evaluate_prediql_results(filepath, endpoint_file):
    df = getnodefromcompiledfile()
    successnodes = find200files(list(df['Node']), endpoint_file)

    print(df)
    df["success_200"] = df.Node.map(lambda x: "Yes" if x in successnodes else "-")
    df['Requests'] = '-'
    print(df)
    prediql_table = parse_table_file(filepath)
    for keys in prediql_table:
        print(keys)
        print(prediql_table[keys]['Requests'])
        # print(prediql_table[keys]['Tokens'])
        # print(prediql_table[keys]['Succeed'])
    # df_node_compiled['failure_200_file'] = '-'
        # df["Requests"] = df.Node.map(lambda x: prediql_table[keys]['Requests'] if x == keys else "-")
    df["Requests"] = df["Node"].apply(lambda x: prediql_table.get(x, {}).get('Requests', "-"))
    df["Tokens"] = df["Node"].apply(lambda x: prediql_table.get(x, {}).get('Tokens', 0))
    df["Succeed"] = df["Node"].apply(lambda x: prediql_table.get(x, {}).get('Succeed', "-"))
    df["Succeed"] = df["Succeed"].apply(lambda x: "-" if x is False else x)

    print(df)

    # Assuming your DataFrame is called df
    graphqler_success = (df["success_200"] == "Yes").sum()
    prediql_success = (df["Succeed"] == True).sum()
    total_endpoints = len(df)
    print(f"number of endpoints:{total_endpoints}")
    print(f"graphqler succeeds count:{graphqler_success}")
    print(f"prediql succeeds count:{prediql_success}")

    total_tokens = pd.to_numeric(df["Tokens"], errors="coerce").sum()
    print(f"total tokens sent to LLM:{total_tokens}")
    print(f"the estimated price for {Config.MODEL_NAME} is $0.0001 per 1k")
    token_price_per_1k = 0.0001
    print(f"Token cost: ${round(token_price_per_1k * total_tokens / 1000,2)}")


    total_requests = pd.to_numeric(df["Requests"], errors="coerce").sum()
    print(f"total requests sent to server:{total_requests}")

    print(f"average of requests:{total_requests/prediql_success}")

    print(f"\nPrediql Successfully explored {prediql_success} nodes:")
    total_tokens_true = pd.to_numeric(df.loc[df["Succeed"] == True, "Tokens"], errors="coerce").sum()
    print(f"total tokens per node: {total_tokens_true}")
    total_requests_true = pd.to_numeric(df.loc[df["Succeed"] == True, "Requests"], errors="coerce").sum()
    print(f"total requests per node: {total_requests_true}")
    print(f"average requests per node: {round(total_requests_true/prediql_success,2)}")
    print(f"average tokens sent per node: {round(total_tokens_true/prediql_success,2)}")


if __name__ == "__main__":
    #show the stats from graphqler
    # find_target_endpoints()
    # print(find_target_endpoints()[0])
    #show the stats from prediql
    evaluate_prediql_results("stats_table_allrounds.txt", "graphqler-output/endpoint_results")
    # df_node_compiled = getnodefromcompiledfile()
    # successnode = find200files(list(df_node_compiled['Node']))
    # print(successnode)

    #print success node list from graphqler 200 files, see the evaluation method is correct
    # print(find200files())

    # print(find200files())
    # print(getnodefromcompiledfile())
    # success_file_200 = "graphqler-output/endpoint_results/allConferences/success/200"
    # with open(success_file_200, "r", encoding="utf-8") as f:
    #     text = f.read()
    #     responses = extract_response_json_blocks(text)
    #     # if not responses:
    #     #     print(f"❌ Excluded '{folder_name}': No valid JSON responses found in 200")
    #     #     continue

    #     # ✅ NEW RULE: include if ANY response is valid
    #     if any(is_valid_response(r) for r in responses):
    #         print(f"✅ Included: At least one good response found")
    #     else:
    #         print(f"❌ Excluded: All responses are errors or null data")