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


from collections import defaultdict, deque


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
        subprocess.run(['python', 'load_introspection/save_instrospection.py', '--url', url], check=True)
        subprocess.run(['python', 'load_introspection/load_introspection.py'], check=True)
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
    subprocess.run(['python', 'reorganize_json_records.py'])
    subprocess.run(['python', 'analysis_prediql.py'])



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



## thompson 
from collections import defaultdict
import random
import math
import numpy as np
from delta_coverage import compute_delta_coverage
BETA = defaultdict(lambda: {"alpha": 1.0, "beta": 1.0})  # key: (node, arm_name)
GAMMA = 1.0   # set <1.0 for discounting, e.g., 0.98

def pick_arm_thompson(node, arms):
    samples = []
    for arm in arms:
        key = (node, arm["name"])
        a, b = BETA[key]["alpha"], BETA[key]["beta"]
        theta = np.random.beta(a, b)
        samples.append((theta, arm))
    samples.sort(reverse=True, key=lambda x: x[0])
    return samples[0][1]

def update_bandit(node, arm_name, reward, gamma=GAMMA):
    key = (node, arm_name)
    # optional discounting for non-stationarity
    BETA[key]["alpha"] = gamma * BETA[key]["alpha"] + reward
    BETA[key]["beta"]  = gamma * BETA[key]["beta"]  + (1 - reward)









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
    input_args = f"{node}, input: {input}"
    # try:
    #     records = search(query, top_k=5)
    #     top_matches = "\n".join(record["text"] for score, record in records)
    # except: 
    #     print(f"something wrong with retriving")

    #arm manipulation
    ARM_STATS = defaultdict(lambda: {"succ": 0, "tot": 0})   # key: (node, arm_name)
    FAIL_STREAK = defaultdict(int)   
    covered = False
    ARMS = [
    {"name":"schema_min_known",   "include_schema":True,  "arg_mode":"known",   "depth":1, "top_k":3},
    {"name":"schema_min_real",    "include_schema":True,  "arg_mode":"real",    "depth":1, "top_k":3},
    {"name":"schema_mod_known",   "include_schema":True,  "arg_mode":"known",   "depth":2, "top_k":5},
    {"name":"noschema_min_known", "include_schema":False, "arg_mode":"known",   "depth":1, "top_k":3},
    {"name":"noschema_min_real",  "include_schema":False, "arg_mode":"real",    "depth":1, "top_k":0},
    {"name":"schema_min_nulls",   "include_schema":True,  "arg_mode":"nulls",   "depth":1, "top_k":3},
    {"name":"schema_deep_known",  "include_schema": True,  "arg_mode":"known",   "depth":3, "top_k":5},
    {"name":"schema_deep_real",   "include_schema": True,  "arg_mode":"real",    "depth":3, "top_k":5},
    ]

    max_k_needed = max([arm["top_k"] for arm in ARMS] + [5])

    try:
        # Single search to the max K; store the texts in order
        base_query = f"{node}, input: {input}"  # not input_args again
        pre_results = search(base_query, top_k=max_k_needed)
        pre_texts = ["{}".format(record["text"]) for score, record in pre_results]
    except Exception as e:
        print(f"⚠️ retrieve error for {node}: {e}")
        pre_texts = []
    # def build_top_matches(k: int) -> str:
    #     if not k: return ""
    #     try:
    #         records = search(f"{node}, input: {input_args}", top_k=k)
    #         return "\n".join(record["text"] for score, record in records)
    #     except Exception as e:
    #         print(f"⚠️ retrieve error for {node}: {e}")
    #         return ""
    #arm manipulation ends 

    def build_top_matches(k: int) -> str:
        if not k or not pre_texts:
            return ""
        k = min(k, len(pre_texts))
        return "\n".join(pre_texts[:k])


    https200 = False
    # while https200 == False and requests < max_requests:

    # while requests < max_request:
        
    #     second_res, token = prompt_llm_with_context(top_matches, node, relevant_object, input, output, source, max_request, node_type)
    #     # second_res, token = prompt_llm_with_context(top_matches, node, objects, schema, parameter, source)
    #     totaltoken += token
    #     save_json_to_file(second_res, node)
    #     https200_forthisrequest, requests = send_payload(url,jsonfile_path)
    #     if https200_forthisrequest:
    #         https200 = True
    # while (not covered) and (requests < max_request):
    # while (not covered):
    #     for arm in ARMS:
    #         if covered or requests >= max_request:
    #             break

    #         # top_k escalation heuristic (only for schema arms)
    #         k = arm["top_k"]
    #         if arm["include_schema"] and FAIL_STREAK[node] >= 2 and k < 5:
    #             k = 5  # one escalation

    #         top_matches = build_top_matches(k)
    #         schema_to_use = relevant_object if arm["include_schema"] else None

    #         # Build your prompt based on arg_mode/depth (you can pass these as extra flags if you extend prompt builder)
    #         second_res, token = prompt_llm_with_context(
    #             top_matches=top_matches,
    #             endpoint=node,
    #             schema=relevant_object if arm["include_schema"] else None,
    #             input=input_args,
    #             output=output,
    #             source=source,
    #             MAX_REQUESTS=max_request,
    #             node_type=node_type,
    #             include_schema=arm["include_schema"],
    #             arg_mode=arm["arg_mode"],     # "known" | "real" | "nulls"
    #             depth=arm["depth"],           # 1 or 2
    #             n_variants=1
    #         )
    #         totaltoken += token

    #         save_json_to_file(second_res, node)
    #         print(f"arm_name: {arm['name']}")
    #         ok_200, requests = send_payload(url, jsonfile_path, arm['name'])

    #         ARM_STATS[(node, arm["name"])]["tot"] += 1
    #         if ok_200:
    #             ARM_STATS[(node, arm["name"])]["succ"] += 1
    #             FAIL_STREAK[node] = 0
    #             covered = True
    #             break
    #         else:
    #             FAIL_STREAK[node] += 1
    #     break
    while (not covered) and (requests < max_request):
        arm = pick_arm_thompson(node, ARMS)

        # escalation tweak still allowed
        k = arm["top_k"]
        if arm["include_schema"] and FAIL_STREAK[node] >= 2 and k < 5:
            k = 5
        top_matches = build_top_matches(k)
        schema_to_use = relevant_object if arm["include_schema"] else None

        second_res, token = prompt_llm_with_context(
            top_matches=top_matches,
            endpoint=node,
            schema=schema_to_use,
            input=input_args,
            output=output,
            source=source,
            MAX_REQUESTS=max_request,
            node_type=node_type,
            include_schema=arm["include_schema"],
            arg_mode=arm["arg_mode"],
            depth=arm["depth"],
            n_variants=1
        )
        totaltoken += token
        save_json_to_file(second_res, node)
        ok_200, requests = send_payload(url, jsonfile_path, arm['name'])

        # Compute reward
        delta_cov = compute_delta_coverage(node)  # you implement; returns 0/1 first, later [0,1]
        reward = 1.0 if (ok_200 and delta_cov > 0) else 0.0

        update_bandit(node, arm['name'], reward)
        if reward > 0:
            FAIL_STREAK[node] = 0
            covered = True
        else:
            FAIL_STREAK[node] += 1

    stats[node]["requests"] = requests
    stats[node]['token'] = totaltoken
    stats[node]['succeed'] = ok_200
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