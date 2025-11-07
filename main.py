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
from datetime import datetime
from load_introspection.load_snippet import get_node_info

from embed_retrieve.retrieve_from_index import search
from embed_retrieve.embed_and_index import embed_real_data



from save_real_data import flatten_real_data

import subprocess

from simple_vulnerability_detector import SimpleVulnerabilityDetector
from dual_vulnerability_detector import DualVulnerabilityDetector

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
    index_dir = "embed_retrieve/faiss_index"
    if os.path.exists(index_dir):
        print(f"🗑️  Removing existing folder: {index_dir}")
        shutil.rmtree(index_dir)
    else:
        print(f"✅ No existing folder to remove: {index_dir}")
    generated_query_info_file = "generated_query_info.json"
    real_data = "real_data.json"
    errors = "errors.csv"

    if os.path.exists(generated_query_info_file):
        os.remove(generated_query_info_file)
    else:
        print(f"No existing folder to remove: {generated_query_info_file}")
    if os.path.exists(real_data):
        os.remove(real_data)
    else:
        print(f"No existing folder to remove: {real_data}")
    if os.path.exists(errors):
        os.remove(errors)
    else:
        print(f"No existing folder to remove: {errors}")
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
    
    # Generate vulnerability classification summary report
    generate_vulnerability_summary_report(stats_allrounds)
    
    subprocess.run(['python3', 'reorganize_json_records.py'])
    subprocess.run(['python3', 'analysis_prediql.py'])



def run_all_nodes(url, nodes, max_requests, rounds, stats_allrounds):
    # Track which nodes have succeeded in any round
    successful_nodes = set()
    
    for i in range(1, rounds+1):
        all_stats = {}
        for node in nodes:
            # Skip processing if this node has already succeeded in a previous round
            if node in successful_nodes:
                print(f"⏭️  Skipping {node} - already succeeded in a previous round")
                continue
                
            result = process_node(url, node, max_requests * i)
            all_stats.update(result)
            
            # Check if this node's basic call succeeded and add it to successful_nodes
            if result.get(node, {}).get('succeed', False):
                successful_nodes.add(node)
                print(f"✅ {node} succeeded in round {i} - will be skipped in future rounds")
        # for node in tqdm(nodes, desc="Processing nodes"):
        #     try:
        #         result = process_node(url, node, max_requests)
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
                "succeed": False,
                "basic_call_success": False,
                "negative_success": False,
                "vulnerability_detections": 0,
                "simple_detections": 0,
                "llm_detections": 0,
                "detector_agreement": 0.0,
                "consensus_breakdown": {},
                "simple_potential_detections": 0,
                "llm_potential_detections": 0,
                "potential_agreement": 0.0,
                "potential_consensus_breakdown": {},
                "confirmed_vulnerabilities": 0,
                "potential_vulnerabilities": 0,
                "vulnerability_categories": [],
                "high_severity_vulns": 0
            }

        # Add up requests and tokens
        overall_stats[node_name]["requests"] = round_data.get("requests", 0)
        overall_stats[node_name]["token"] += round_data.get("token", 0.0)

        # Logical OR for Succeed
        overall_stats[node_name]["succeed"] = (
            overall_stats[node_name]["succeed"] or round_data.get("succeed", False))
        
        # Logical OR for basic_call_success
        overall_stats[node_name]["basic_call_success"] = (
            overall_stats[node_name]["basic_call_success"] or round_data.get("basic_call_success", False))
        
        # Logical OR for negative_success
        overall_stats[node_name]["negative_success"] = (
            overall_stats[node_name]["negative_success"] or round_data.get("negative_success", False))
        
        # Add vulnerability metrics
        overall_stats[node_name]["vulnerability_detections"] += round_data.get("vulnerability_detections", 0)
        overall_stats[node_name]["simple_detections"] += round_data.get("simple_detections", 0)
        overall_stats[node_name]["llm_detections"] += round_data.get("llm_detections", 0)
        overall_stats[node_name]["simple_potential_detections"] += round_data.get("simple_potential_detections", 0)
        overall_stats[node_name]["llm_potential_detections"] += round_data.get("llm_potential_detections", 0)
        overall_stats[node_name]["potential_agreement"] = round_data.get("potential_agreement", 0.0)
        overall_stats[node_name]["potential_consensus_breakdown"] = round_data.get("potential_consensus_breakdown", {})
        overall_stats[node_name]["confirmed_vulnerabilities"] += round_data.get("confirmed_vulnerabilities", 0)
        overall_stats[node_name]["potential_vulnerabilities"] += round_data.get("potential_vulnerabilities", 0)
        overall_stats[node_name]["high_severity_vulns"] += round_data.get("high_severity_vulns", 0)
        
        # Update detector agreement (average)
        current_agreement = overall_stats[node_name]["detector_agreement"]
        round_agreement = round_data.get("detector_agreement", 0.0)
        if current_agreement == 0.0:
            overall_stats[node_name]["detector_agreement"] = round_agreement
        else:
            # Simple average for now
            overall_stats[node_name]["detector_agreement"] = (current_agreement + round_agreement) / 2
        
        # Merge consensus breakdown
        round_consensus = round_data.get("consensus_breakdown", {})
        existing_consensus = overall_stats[node_name]["consensus_breakdown"]
        for key, value in round_consensus.items():
            existing_consensus[key] = existing_consensus.get(key, 0) + value
        overall_stats[node_name]["consensus_breakdown"] = existing_consensus
        
        # Merge vulnerability categories (unique list)
        round_categories = round_data.get("vulnerability_categories", [])
        existing_categories = overall_stats[node_name]["vulnerability_categories"]
        overall_stats[node_name]["vulnerability_categories"] = list(set(existing_categories + round_categories))



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
    
    # Initialize dual vulnerability detector (both simple and LLM-based)
    vuln_detector = DualVulnerabilityDetector(url)

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
    basic_call_success = False  # Track specifically basic_call success
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
    while (not covered) and (requests < max_request) and (not https200):
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
        https200, requests, negative_success, newly_processed_responses = send_payload(url, jsonfile_path)

        print(f"max_request: {max_request}, requests: {requests}")
        
        # Check for basic_call success specifically
        if newly_processed_responses:
            for response in newly_processed_responses:
                if response.get('vulnerability_type') == 'basic_call':
                    # Check if this basic_call was successful
                    if response.get('success', False):
                        basic_call_success = True
                        print(f"✅ Basic call successful for {node}")
                        break
        
        # Run dual vulnerability detection only on newly processed responses and only when https200 is True
        try:
            # Use only newly processed response data from send_payload and only if we have HTTP 200
            if newly_processed_responses and https200:  # If there are newly processed responses AND we have HTTP 200
                all_comparison_results = []
                # Filter out basic_call responses
                filtered_responses = [r for r in newly_processed_responses if r.get('vulnerability_type') != 'basic_call']
                basic_call_count = len(newly_processed_responses) - len(filtered_responses)
                
                print(f"🔍 Running dual vulnerability detection on {len(filtered_responses)} newly processed responses (skipped {basic_call_count} basic_call responses) - HTTP 200 detected...")
                
                # Check only newly processed responses with both detectors (skip basic_call)
                for i, response in enumerate(newly_processed_responses, 1):
                    # Skip basic_call vulnerability types
                    if response.get('vulnerability_type') == 'basic_call':
                        print(f"   Skipping basic_call response {i}")
                        continue
                        
                    comparison_result = vuln_detector.detect_vulnerabilities(response, f"{node}_response_{i}")
                    if comparison_result:
                        all_comparison_results.append(comparison_result)
                        
                        # Print comparison summary
                        simple_count = comparison_result['simple_detector']['count']
                        llm_count = comparison_result['llm_detector']['count']
                        consensus = comparison_result['comparison']['consensus']
                        agreement = comparison_result['comparison']['agreement_score']
                        
                        # Potential detection summary
                        simple_vulnerable = comparison_result['simple_detector']['vulnerable_count']
                        simple_potential = comparison_result['simple_detector']['potential_count']
                        llm_vulnerable = comparison_result['llm_detector']['vulnerable_count']
                        llm_potential = comparison_result['llm_detector']['potential_count']
                        potential_consensus = comparison_result['comparison']['potential_analysis']['potential_consensus']
                        potential_agreement = comparison_result['comparison']['potential_analysis']['potential_agreement_score']
                        
                        print(f"   Response {i}: Simple={simple_count} (V:{simple_vulnerable}, P:{simple_potential}), LLM={llm_count} (V:{llm_vulnerable}, P:{llm_potential})")
                        print(f"     Consensus: {consensus} (Agreement: {agreement:.2f})")
                        print(f"     Potential: {potential_consensus} (Agreement: {potential_agreement:.2f})")
                        
                        # Show detailed results
                        if simple_count > 0:
                            print(f"     Simple Detector:")
                            for vuln in comparison_result['simple_detector']['results']:
                                print(f"       - {vuln['detection_name']} ({vuln['detection']}) - {vuln['category']}")
                        
                        if llm_count > 0:
                            print(f"     LLM Detector:")
                            for vuln in comparison_result['llm_detector']['results']:
                                print(f"       - {vuln['detection_name']} ({vuln['detection']}) - {vuln['category']}")
                                if 'confidence' in vuln:
                                    print(f"         Confidence: {vuln['confidence']:.2f}")
                
                if all_comparison_results:
                    print(f"🔍 Dual vulnerability detection completed for {node}: {len(all_comparison_results)} comparisons across {len(filtered_responses)} newly processed responses (skipped {basic_call_count} basic_call)")
                else:
                    print(f"✅ No vulnerabilities detected by either detector in {len(filtered_responses)} newly processed responses for {node} (skipped {basic_call_count} basic_call)")
            else:
                if newly_processed_responses and not https200:
                    print(f"⏭️ Skipping vulnerability detection for {node} - no HTTP 200 responses detected")
                elif not newly_processed_responses:
                    print(f"⏭️ Skipping vulnerability detection for {node} - no newly processed responses")
        except Exception as e:
            print(f"⚠️ Dual vulnerability detection failed for {node}: {e}")
        
        # Compute reward based on basic_call_success and delta coverage
        delta_cov = compute_delta_coverage(node)  # you implement; returns 0/1 first, later [0,1]
        reward = 1.0 if (https200 and delta_cov > 0) else 0.0

        update_bandit(node, arm['name'], reward)
        if reward > 0:
            FAIL_STREAK[node] = 0
            covered = True
        else:
            FAIL_STREAK[node] += 1

    stats[node]["requests"] = requests
    stats[node]['token'] = totaltoken
    stats[node]['succeed'] = https200
    stats[node]['basic_call_success'] = basic_call_success  # Track basic call success specifically
    stats[node]['negative_success'] = negative_success
    
    # Save dual vulnerability detection results for this node
    try:
        # Save comparison results to CSV
        comparison_csv_path = os.path.join(os.getcwd(), Config.OUTPUT_DIR, f"{node}_dual_detection_comparison.csv")
        vuln_detector.save_comparison_results_to_csv(comparison_csv_path)
        
        # Generate dual detector comparison report
        comparison_report_path = os.path.join(os.getcwd(), Config.OUTPUT_DIR, f"{node}_dual_detection_report.json")
        vuln_detector.generate_comparison_report(comparison_report_path)
        
        # Get summary stats from dual detector
        dual_summary = vuln_detector.get_summary_stats()
        if dual_summary:
            # Calculate combined statistics
            total_detections = dual_summary.get('simple_detections', 0) + dual_summary.get('llm_detections', 0)
            agreement_rate = dual_summary.get('agreement_rate', 0.0)
            consensus_breakdown = dual_summary.get('consensus_breakdown', {})
            
            stats[node]['vulnerability_detections'] = total_detections
            stats[node]['simple_detections'] = dual_summary.get('simple_detections', 0)
            stats[node]['llm_detections'] = dual_summary.get('llm_detections', 0)
            stats[node]['detector_agreement'] = agreement_rate
            stats[node]['consensus_breakdown'] = consensus_breakdown
            
            # Add potential detection statistics
            potential_analysis = dual_summary.get('potential_analysis', {})
            stats[node]['simple_potential_detections'] = potential_analysis.get('simple_potential_detections', 0)
            stats[node]['llm_potential_detections'] = potential_analysis.get('llm_potential_detections', 0)
            stats[node]['potential_agreement'] = potential_analysis.get('potential_agreement_rate', 0.0)
            stats[node]['potential_consensus_breakdown'] = potential_analysis.get('potential_consensus_breakdown', {})
            
            # Calculate confirmed vs potential (simplified)
            stats[node]['confirmed_vulnerabilities'] = dual_summary.get('simple_detections', 0)  # Simple detector as baseline
            stats[node]['potential_vulnerabilities'] = dual_summary.get('llm_detections', 0)  # LLM as potential
            
            # Combined categories from both detectors
            all_categories = set()
            for comparison in vuln_detector.comparison_results:
                all_categories.update(comparison['simple_detector']['categories'])
                all_categories.update(comparison['llm_detector']['categories'])
            stats[node]['vulnerability_categories'] = list(all_categories)
            
            # Count high severity vulnerabilities (from both detectors)
            high_severity_count = 0
            for comparison in vuln_detector.comparison_results:
                for vuln in comparison['simple_detector']['results']:
                    if vuln['detection'] == 'vulnerable':
                        high_severity_count += 1
                for vuln in comparison['llm_detector']['results']:
                    if vuln['detection'] == 'vulnerable':
                        high_severity_count += 1
            stats[node]['high_severity_vulns'] = high_severity_count
            
            print(f"🔍 Dual Detector Summary for {node}:")
            print(f"   Simple Detector: {dual_summary.get('simple_detections', 0)} detections")
            print(f"   LLM Detector: {dual_summary.get('llm_detections', 0)} detections")
            print(f"   Agreement Rate: {agreement_rate:.2f}")
            print(f"   Consensus: {consensus_breakdown}")
            print(f"   Categories: {', '.join(all_categories) if all_categories else 'None'}")
            print(f"   High Severity: {high_severity_count}")
            
            # Display potential detection summary
            potential_analysis = dual_summary.get('potential_analysis', {})
            if potential_analysis:
                print(f"   Potential Analysis:")
                print(f"     Simple Potential: {potential_analysis.get('simple_potential_detections', 0)}")
                print(f"     LLM Potential: {potential_analysis.get('llm_potential_detections', 0)}")
                print(f"     Potential Agreement: {potential_analysis.get('potential_agreement_rate', 0.0):.2f}")
                print(f"     Potential Consensus: {potential_analysis.get('potential_consensus_breakdown', {})}")
            
    except Exception as e:
        print(f"⚠️ Failed to save dual detector results for {node}: {e}")
        stats[node]['vulnerability_detections'] = 0
        stats[node]['simple_detections'] = 0
        stats[node]['llm_detections'] = 0
        stats[node]['detector_agreement'] = 0.0
        stats[node]['consensus_breakdown'] = {}
        stats[node]['confirmed_vulnerabilities'] = 0
        stats[node]['potential_vulnerabilities'] = 0
        stats[node]['vulnerability_categories'] = []
        stats[node]['high_severity_vulns'] = 0
    
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
        # Format categories as comma-separated string
        categories = ', '.join(values.get('vulnerability_categories', [])) if values.get('vulnerability_categories') else 'None'
        
        # Format consensus breakdown
        consensus = values.get('consensus_breakdown', {})
        consensus_str = ', '.join([f"{k}:{v}" for k, v in consensus.items()]) if consensus else 'None'
        
        rows.append([
            node,
            values['requests'],
            f"{values['token']:,}",  # formatted with commas
            values['succeed'],
            values.get('basic_call_success', False),
            values.get('negative_success', False),
            values.get('vulnerability_detections', 0),
            values.get('simple_detections', 0),
            values.get('llm_detections', 0),
            values.get('detector_agreement', 0.0),
            values.get('simple_potential_detections', 0),
            values.get('llm_potential_detections', 0),
            values.get('potential_agreement', 0.0),
            values.get('confirmed_vulnerabilities', 0),
            values.get('potential_vulnerabilities', 0),
            values.get('high_severity_vulns', 0),
            categories,
            consensus_str
        ])

    # Generate table string
    table_str = tabulate(
        rows,
        headers=["Node", "Requests", "Tokens", "Succeed", "Basic Call Success", "Negative Success", "Total Vulns", "Simple Det", "LLM Det", "Agreement", "Simple Pot", "LLM Pot", "Pot Agreement", "Confirmed", "Potential", "High Severity", "Categories", "Consensus"],
        tablefmt="grid"
    )

    # Print to console
    print(table_str)

    # Write to a text file
    # output_file = "node_stats_table.txt"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(table_str)

    print(f"\n✅ Table written to {output_file}")

def generate_vulnerability_summary_report(stats_allrounds, output_file=None):
    """Generate a comprehensive vulnerability classification summary report with dual detector analysis"""
    if not output_file:
        output_file = os.path.join(Config.OUTPUT_DIR, "dual_detector_vulnerability_summary_report.json")
    
    # Collect all vulnerability data
    total_vulnerabilities = 0
    total_simple_detections = 0
    total_llm_detections = 0
    total_simple_potential = 0
    total_llm_potential = 0
    total_confirmed = 0
    total_potential = 0
    total_high_severity = 0
    all_categories = set()
    detector_breakdown = {}
    agreement_rates = []
    potential_agreement_rates = []
    consensus_summary = {}
    potential_consensus_summary = {}
    
    for node, values in stats_allrounds.items():
        total_vulnerabilities += values.get('vulnerability_detections', 0)
        total_simple_detections += values.get('simple_detections', 0)
        total_llm_detections += values.get('llm_detections', 0)
        total_simple_potential += values.get('simple_potential_detections', 0)
        total_llm_potential += values.get('llm_potential_detections', 0)
        total_confirmed += values.get('confirmed_vulnerabilities', 0)
        total_potential += values.get('potential_vulnerabilities', 0)
        total_high_severity += values.get('high_severity_vulns', 0)
        
        # Track agreement rates
        agreement = values.get('detector_agreement', 0.0)
        if agreement > 0:
            agreement_rates.append(agreement)
        
        # Track potential agreement rates
        potential_agreement = values.get('potential_agreement', 0.0)
        if potential_agreement > 0:
            potential_agreement_rates.append(potential_agreement)
        
        # Track consensus breakdown
        consensus = values.get('consensus_breakdown', {})
        for consensus_type, count in consensus.items():
            consensus_summary[consensus_type] = consensus_summary.get(consensus_type, 0) + count
        
        # Track potential consensus breakdown
        potential_consensus = values.get('potential_consensus_breakdown', {})
        for consensus_type, count in potential_consensus.items():
            potential_consensus_summary[consensus_type] = potential_consensus_summary.get(consensus_type, 0) + count
        
        categories = values.get('vulnerability_categories', [])
        all_categories.update(categories)
    
    # Calculate average agreement rates
    avg_agreement = sum(agreement_rates) / len(agreement_rates) if agreement_rates else 0.0
    avg_potential_agreement = sum(potential_agreement_rates) / len(potential_agreement_rates) if potential_agreement_rates else 0.0
    
    # Create summary report
    summary_report = {
        'report_timestamp': datetime.utcnow().isoformat(),
        'overall_summary': {
            'total_nodes_tested': len(stats_allrounds),
            'total_vulnerability_detections': total_vulnerabilities,
            'simple_detector_detections': total_simple_detections,
            'llm_detector_detections': total_llm_detections,
            'simple_potential_detections': total_simple_potential,
            'llm_potential_detections': total_llm_potential,
            'total_confirmed_vulnerabilities': total_confirmed,
            'total_potential_vulnerabilities': total_potential,
            'total_high_severity_vulnerabilities': total_high_severity,
            'vulnerability_categories_found': list(all_categories),
            'detector_agreement_rate': avg_agreement,
            'potential_agreement_rate': avg_potential_agreement,
            'consensus_breakdown': consensus_summary,
            'potential_consensus_breakdown': potential_consensus_summary
        },
        'detector_comparison': {
            'simple_detector': {
                'total_detections': total_simple_detections,
                'potential_detections': total_simple_potential,
                'detection_rate': total_simple_detections / len(stats_allrounds) if stats_allrounds else 0,
                'potential_detection_rate': total_simple_potential / len(stats_allrounds) if stats_allrounds else 0,
                'description': 'Rule-based detector using predefined patterns'
            },
            'llm_detector': {
                'total_detections': total_llm_detections,
                'potential_detections': total_llm_potential,
                'detection_rate': total_llm_detections / len(stats_allrounds) if stats_allrounds else 0,
                'potential_detection_rate': total_llm_potential / len(stats_allrounds) if stats_allrounds else 0,
                'description': 'AI-powered detector using language model analysis'
            },
            'agreement_analysis': {
                'average_agreement': avg_agreement,
                'nodes_with_agreement': len(agreement_rates),
                'consensus_distribution': consensus_summary
            },
            'potential_agreement_analysis': {
                'average_potential_agreement': avg_potential_agreement,
                'nodes_with_potential_agreement': len(potential_agreement_rates),
                'potential_consensus_distribution': potential_consensus_summary
            }
        },
        'node_breakdown': stats_allrounds,
            'vulnerability_classification_info': {
                'categories': {
                    'Injection Attacks': 'VULNERABLE detection - Code injection vulnerabilities',
                    'Information Disclosure': 'POTENTIAL detection - API structure exposure',
                    'Access Control': 'VULNERABLE detection - Authorization bypass'
                },
                'detection_levels': {
                    'vulnerable': 'Confirmed vulnerability detected',
                    'potential': 'Potential vulnerability detected',
                    'safe': 'No vulnerability detected'
                }
            }
    }
    
    # Save report
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(summary_report, f, indent=2, ensure_ascii=False)
    
    print(f"✅ Vulnerability summary report saved to {output_file}")
    
    # Print summary to console
    print("\n" + "="*80)
    print("🔍 DUAL DETECTOR VULNERABILITY CLASSIFICATION SUMMARY")
    print("="*80)
    print(f"Total Nodes Tested: {len(stats_allrounds)}")
    print(f"Total Vulnerability Detections: {total_vulnerabilities}")
    print(f"  - Simple Detector: {total_simple_detections}")
    print(f"  - LLM Detector: {total_llm_detections}")
    print(f"Detector Agreement Rate: {avg_agreement:.2f}")
    print(f"Consensus Breakdown: {consensus_summary}")
    print(f"Confirmed Vulnerabilities: {total_confirmed}")
    print(f"Potential Vulnerabilities: {total_potential}")
    print(f"High Severity Vulnerabilities: {total_high_severity}")
    print(f"Categories Found: {', '.join(all_categories) if all_categories else 'None'}")
    print("="*80)
    
    return output_file

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