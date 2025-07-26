import argparse
from retrieve_and_prompt import get_LLM_firstresposne, get_LLM_resposne, load_index_and_model, load_texts, retrieve_similar, prompt_llm_with_context, find_node_definition
# import retrieve_and_prompt
import os
import sys
import json
# from fuzzing import GraphQLFuzzer
import requests
from config import Config
# from fuzzing import GraphQLFuzzer

from sendpayload import send_payload
from initial_llama3 import ensure_ollama_running

from target_endpoints import  getnodefromcompiledfile

from parse_endpoint_results import ParseEndpointResults, loadjsonfile, embedding

from tabulate import tabulate
import shutil
import yaml

from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

import time
import random
from load_introspection.load_snippet import get_node_info

from embed_retrieve.retrieve_from_index import search
from embed_retrieve.embed_and_index import embed_real_data



from save_real_data import flatten_real_data

import subprocess

def main():
    parser = argparse.ArgumentParser(description="Please provide api URL")

    parser.add_argument("--url", type= str, help="GraphQL endpoint url")
    parser.add_argument("--requests", type= int, help="Number of requests per node per round")
    parser.add_argument("--rounds", type= int, help="Total number of rounds")

    # parser.add_argument("requests", type=int, help="Maximum number of requests to send to test the endpoint")

    args = parser.parse_args()

    url = args.url
    requests = args.requests
    rounds = args.rounds
    # requests = args.requests
    # nodes = ["episodesByIds", "charactersByIds", "locationsByIds"]
    
    # output_folder = Config.OUTPUT_DIR
    # Config.OUTPUT_DIR += f"_{url}"
    output_folder = Config.OUTPUT_DIR
    try:
        subprocess.run(['python3', 'load_introspection/save_instrospection.py', '--url', url], check=True)
        subprocess.run(['python3', 'load_introspection/load_introspection.py'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Subprocess failed with exit code {e.returncode}")
        sys.exit()
        # Optionally re-raise or exit


    # #==============remove folder=============
    if os.path.exists(output_folder):
        print(f"🗑️  Removing existing folder: {output_folder}")
        shutil.rmtree(output_folder)
    else:
        print(f"✅ No existing folder to remove: {output_folder}")
    #==============remove folder=============
    generated_query_info_file = "generated_query_info.json"
    real_data = "real_data.json"

    if os.path.exists(generated_query_info_file):
        os.remove(generated_query_info_file)
    else:
        print(f"No existing folder to remove: {generated_query_info_file}")
    if os.path.exists(real_data):
        os.remove(real_data)
    else:
        print(f"No existing folder to remove: {real_data}")
    # embedding_responses_from_graphqler()
    

    
    # nodes = find_target_endpoints()
    nodes = getnodefromcompiledfile()

    # nodes = ['film', 'node', 'person', 'species', 'vehicle']

    # url = "https://swapi-graphql.netlify.app/graphql"
    # url = "https://api.react-finland.fi/graphql"



    # index, model = load_index_and_model()
    # texts, records = load_texts()
    from save_query_info import save_query_info
    
    save_query_info()


    ensure_ollama_running("llama3")
    stats_allrounds = {}
    run_all_nodes(url, nodes['Node'], requests, rounds, stats_allrounds)
    # log_to_table(stats_allrounds, "prediql-output/stats_table_allrounds.txt")
    # log_to_table(stats_allrounds, Config.OUTPUT_DIR + "/stats_table_allrounds.txt")
    subprocess.run(['python3', 'reorganize_json_records.py'])
    subprocess.run(['python3', 'analysis_prediql.py'])



def run_all_nodes(url, nodes, max_requests, rounds, stats_allrounds):
    for i in range(1, rounds+1):
        all_stats = {}
        for node in nodes:
            result = process_node(url, node, max_requests * i)
        # for node in tqdm(nodes, desc="Processing nodes"):
        #     try:
        #         result = process_node(url, node, max_requests)
            all_stats.update(result)
        #     except Exception as e:
        #         print(f"❌ Error processing node: {e}")
        #     time.sleep(random.uniform(1.5, 3.0))  # stagger requests
        # log_to_table(all_stats, f"prediql-output/stats_table_round_{i}.txt")
        log_to_table(all_stats, Config.OUTPUT_DIR + f"/stats_table_round_{i}.txt")
        try:
            data_length = flatten_real_data()
            if data_length > 0:
                embed_real_data()
        except json.JSONDecodeError:
                print(f"⚠️ cannot process embedding")
        print(all_stats)
        write_to_all_rounds(stats_allrounds, all_stats)
        log_to_table(stats_allrounds, Config.OUTPUT_DIR + "/stats_table_allrounds.txt")
        

def write_to_all_rounds(overall_stats, round_stats):
    for node_name, round_data in round_stats.items():
        if node_name not in overall_stats:
            # Initialize if first time seeing this node
            overall_stats[node_name] = {
                "requests": 0,
                "token": 0.0,
                "succeed": False
            }

        # Add up requests and tokens
        overall_stats[node_name]["requests"] = round_data.get("requests", 0)
        overall_stats[node_name]["token"] += round_data.get("token", 0.0)

        # Logical OR for Succeed
        overall_stats[node_name]["succeed"] = (
            overall_stats[node_name]["succeed"] or round_data.get("succeed", False))



def process_node(url, node, max_request):

    input, output, relevant_object, source, node_type = get_node_info(node)
    stats = {}
    stats[node] = {}
    totaltoken = 0
    # max_requests = max_request
    requests = 0
    jsonfile_path = os.path.join(os.getcwd(), Config.OUTPUT_DIR, node, "llama_queries.json")

    # top_matches = retrieve_similar(node, model, index, texts)
    # schema = find_node_definition(node)
    # parameter = find_node_parameter(node)

    top_matches = ""
    # parameter = ""
    # schema = ""
    # objects = ""

    ##get top match from embeded file.
    query = f"input: {input}"
    try:
        records = search(query, top_k=5)
        top_matches = "\n".join(record["text"] for score, record in records)
    except: 
        print(f"something wrong with retriving")

    https200 = False
    # while https200 == False and requests < max_requests:

    while requests < max_request:

        second_res, token = prompt_llm_with_context(top_matches, node, relevant_object, input, output, source, max_request, node_type)
        # second_res, token = prompt_llm_with_context(top_matches, node, objects, schema, parameter, source)
        totaltoken += token
        save_json_to_file(second_res, node)
        https200_forthisrequest, requests = send_payload(url,jsonfile_path)
        if https200_forthisrequest:
            https200 = True
    stats[node]["requests"] = requests
    stats[node]['token'] = totaltoken
    stats[node]['succeed'] = https200
    print(stats)
    print(f"[{node}] Attempt {requests+1}/{max_request}")

    return stats

def embedding_responses_from_graphqler():
    pfr = ParseEndpointResults()
    payload_resp_pair = pfr.parse_result_to_json_with_status()
    natural_text = loadjsonfile()
    index_file_path = embedding(natural_text)

def save_json_to_file(generated_payload, node):
    payload_list = [{"query": q} for q in generated_payload["query"]]
    payload_list += [{"mutation": m} for m in generated_payload.get("mutation", [])]

    base_path = os.getcwd()
    filedir = os.path.join(base_path, Config.OUTPUT_DIR, node)
    
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

def find_node_parameter(node_name):

    query_parameter_path = os.path.join("graphqler-output", "extracted", "query_parameter_list.yml")
    mutation_parameter_path = os.path.join("graphqler-output", "extracted", "mutation_parameter_list.yml")
    filepaths = [query_parameter_path, mutation_parameter_path]
    for path in filepaths:
        if not os.path.exists(path):
            print(f"parameter file not found: {path}")
            continue

        with open(path, 'r') as f:
            try:
                data = yaml.safe_load(f)
            except yaml.YAMLError as e:
                print(f"⚠️ Error parsing YAML in {path}: {e}")
                continue

            if not data:
                continue

            for key, value in data.items():
                if key == node_name:
                    print(f"✅ Exact match on key in {path}: {key}")
                    return value

                # Check for internal 'name' field match
                if isinstance(value, dict):
                    internal_name = value.get("name")
                    if internal_name == node_name:
                        print(f"✅ Match on internal 'name' field in {path}: {internal_name}")
                        return value

    print(f"❌ Node '{node_name}' not found in any provided files.")
    return None



if __name__ == "__main__":
    main()