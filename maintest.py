from initial_llama3 import ensure_ollama_running

from target_endpoints import getnodefromcompiledfile
from load_introspection.load_snippet import get_node_info_generated, get_node_info


from main import run_all_nodes

from embed_retrieve.retrieve_from_index import search
from embed_retrieve.embed_and_index import embed_real_data

from save_query_info import save_query_info
from save_real_data import flatten_real_data

from config import Config
from llama_initiator import  get_llm_model

# from retrieve_and_prompt import prompt_llm_with_context
import re

import random
import os 
import json
import requests

from tabulate import tabulate

url = "abc"

Config.OUTPUT_DIR += f"_{url}"

output_folder = Config.OUTPUT_DIR

print(Config.OUTPUT_DIR)
print(output_folder)

def log_to_table(stats, output_file):
    rows = []
    for node, values in stats.items():
        rows.append([
            node,
            values['requests'],
            f"{values['token']:,}",  # formatted with commas
            values['succeed']
        ])

    # Generate table string
    table_str = tabulate(
        rows,
        headers=["Node", "Requests", "Tokens", "Succeed"],
        tablefmt="grid"
    )

    # Print to console
    print(table_str)

    # Write to a text file
    # output_file = "node_stats_table.txt"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(table_str)

    print(f"\n✅ Table written to {output_file}")

stats_table = {"345":{ "requests":213, "token": 123124, "succeed": False},
               "456":{ "requests":213, "token": 123124, "succeed": False},
               "1233":{ "requests":213, "token": 123124, "succeed": False},
               "123":{ "requests":213, "token": 123124, "succeed": False},
}
if not os.path.exists(output_folder):
        os.makedirs(output_folder)
log_to_table(stats_table, Config.OUTPUT_DIR + "/stats_table_round_test.txt")
log_to_table(stats_table, Config.OUTPUT_DIR + "/stats_table_allrounds_test.txt")
# save_query_info()
# flatten_real_data()
# embed_real_data()
# folder_path = "prediql-output/languages"
# filename = "llama_queries.json"
# os.makedirs(folder_path, exist_ok=True)
# path = os.path.join(folder_path, filename)

# # Load existing JSON array if file exists
# if os.path.exists(path):
#     with open(path, 'r', encoding='utf-8') as f:
#         try:
#             existing_data = json.load(f)
#             if not isinstance(existing_data, list):
#                 raise ValueError("File does not contain a JSON array")
#         except json.JSONDecodeError:
#             existing_data = []
# else:
#     existing_data = []

# # Append the new data
# print(f"length of {path} data : {len(existing_data)}")
# existing_data.append(data)
# print(f"length of data after editing: {len(existing_data)}")
#====================extract data from json files function test====================#
# save to generated_query_info.json 
# save_query_info()


#====================extract flatten text from generated_query_info.json files function test====================#
# save to real_data.json 
# flatten_real_data()

# nodes = getnodefromcompiledfile()
# print(nodes)

#====================embedding function test====================#
# embed_real_data()





#====================retriev function test====================#
# nodes = getnodefromcompiledfile()
# print(list(nodes['Node']))
# node = "albums"
# # input, output, schema, source, node_type = get_node_info(node)
# input, output, relevant_object, source, node_type = get_node_info(node)
# top_matches = ""
# output = ""
# source = ""
# max_request = 2


# def extract_request_response_pairs(json_file_path):
#     # Check if the file exists
#     if not os.path.exists(json_file_path):
#         print(f"File not found: {json_file_path}")
#         return []
    
#     # Check if the file is empty
#     if os.path.getsize(json_file_path) == 0:
#         print(f"File is empty: {json_file_path}")
#         return []

#     # Try loading JSON
#     try:
#         with open(json_file_path, "r") as f:
#             data = json.load(f)
#     except json.JSONDecodeError as e:
#         print(f"Invalid JSON format: {e}")
#         return []

#     pairs = []
#     for item in data:
#         query = item.get("query")
#         response_info = {
#             "status": item.get("response_status"),
#             "body": item.get("response_body"),
#             "time": item.get("request_time_seconds")
#         }
#         pairs.append((query, response_info))
#     return pairs
# prompt = f"""
#     You are an expert in GraphQL API security testing.

#     Your task is to generate at least **3–5 valid GraphQL queries** to test the operation below.

#     **Rules:**
#     - Each query must be inside a separate ```graphql code block.
#     - Label each block with a test type like: ***Invalid Argument Test***
#     - Use only fields and types listed in the schema.
#     - Use only *real values* listed in the context — no <id> or placeholders.
#     - Do not use Relay-style connection patterns.
#     - Return value is a flat array of type `{node_type}`.

#     --- Context ---

#     - Operation: {endpoint}
#     - Input args: {input}
#     - Output fields: {output}
#     - Schema: {schema}
#     - Node type: {node_type}
#     - Known real values: {top_matches}
#     - Previous queries: {previous_response_pairs}

#     Now generate 3–5 diverse GraphQL queries for: ***{endpoint}***
#     """





# # Example usage:
def prompt_llm_with_context(top_matches, endpoint, schema, input, output, source, MAX_REQUESTS, node_type, sample_n=5):
    previous_response_pairs = extract_request_response_pairs(
        os.path.join(os.getcwd(), Config.OUTPUT_DIR, endpoint, "llama_queries.json")
    )

    prompt = f"""
    You are an expert in GraphQL API security testing.

    You will be given **only** the operation you need to test, along with its schema definitions.  
    All testing is performed in a safe, offline environment to improve robustness and input validation.

    Your task is to generate exactly **valid GraphQL queries** for the **specific operation shown below**, strictly conforming to the provided GraphQL schema.

    **You must only use the operation and fields defined below.**  
    **You may not invent or guess any additional fields.**

    **Important Rules:**
    - Always output responses in a single ```graphql code block.
    - Always start your query with: ```graphql
    - Always end with: ```
    - Always generate only ONE query in separate ```graphql code block.
    - Outside the GraphQL code block, label the test type and operation in the format: ***<operation name / test type>***
    - Use only *real* values provided in the context. No placeholders or variables like `<id>`. Use realistic example values that conform to the schema types.
    - Do **not** use Relay-style connection patterns. This schema does **not** support `edges`, `node`, or `nodes`.
    - The return value of this query is a **plain array** of the type {node_type}. There are **no connection fields** or nested wrappers. Use only the listed fields.

    **Your Goal:**  
    - Generate several queries to thoroughly test this operation against the given endpoint.
    - Cover as many fields as possible within the schema, while using concrete example values.

    **Context you will use to generate the query:**

    - operation: {endpoint}
    - input: {input}
    - output: {output}
    - schema types: {schema}
    - node type: {node_type}
    - known real values to use: {top_matches}
    - previouse response pairs: {previous_response_pairs}

    You must generate a test query for:

    ***{endpoint}***
    """


    approx_tokens = len(prompt) / 4
    print(f"Approximate token count: {approx_tokens:.0f}")


    llama_res = get_llm_model(prompt)
    query_json = {"query": []}
    flag = "```graphql"
    parse_time = 0
    while flag in llama_res and parse_time < 10:
        parse_time += 1
        try:
            sidx = llama_res.find(flag)
            j_start = llama_res[sidx+len(flag):]
            j_end = j_start.find("```")
            query_str = j_start[:j_end]
            llama_res = j_start[j_end:]
            if query_str not in query_json["query"]:
                query_json["query"].append(query_str)
        except Exception as e:
    #         # logger.error(e)
          continue
    return query_json, approx_tokens

res, token = prompt_llm_with_context(top_matches, node, relevant_object, input, output, source, max_request, node_type)
# for re in res:


def save_json_to_file(generated_payload, node):
    payload_list = [{"query": q} for q in generated_payload["query"]]
    payload_list += [{"mutation": m} for m in generated_payload.get("mutation", [])]
    print(payload_list)
    for i in payload_list:
        print(i)
    base_path = os.getcwd()
    filedir = os.path.join(base_path)
    
    if not os.path.exists(filedir):
        os.makedirs(filedir)
    
    filepath = os.path.join(filedir, "llama_queries.json")
    
    # Step 1: Load existing data if the file exists and is non-empty
    existing_data = []
    if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
        with open(filepath, 'r') as f:
            try:
                existing_data = json.load(f)
                # Ensure it's a list
                if not isinstance(existing_data, list):
                    print(f"⚠️ Warning: Existing JSON was not a list. Overwriting.")
                    existing_data = []
            except json.JSONDecodeError:
                print(f"⚠️ Warning: Existing JSON was invalid. Overwriting.")
                existing_data = []
    
    # Step 2: Append new payloads to existing data
    existing_data.extend(payload_list)
    
    # Step 3: Overwrite the file with the consistent, combined list
    with open(filepath, 'w') as f:
        json.dump(existing_data, f, indent=4)
    
    print(f"✅ Saved {len(payload_list)} new queries. Total in file: {len(existing_data)}")
    return True


# save_json_to_file(res, node)

# from sendpayload import send_payload

# send_payload("https://graphqlzero.almansi.me/api", os.path.join(os.getcwd(), "llama_queries.json"))
