#!/usr/bin/env python3
"""
Script to analyze dual detection CSV files and generate an aggregated report per directory and consensus.
This script processes all dual_detection_comparison.csv files and generates statistics about vulnerabilities 
per directory and consensus type, with deduplication of nodes and unique detection combinations.
Only counts nodes_with_vulnerabilities once per unique detection name combination.
"""

import os
import csv
import json
import pandas as pd
from collections import defaultdict, Counter
import glob
from pathlib import Path

def normalize_detection_name(name):
    """Normalize detection names to merge similar ones and remove unwanted ones."""
    if not name:
        return None
    
    # Remove unknown detections
    if 'unknown' in name.lower():
        return None
    
    # Normalize the name
    normalized = name.strip()
    
    # Merge similar detection names (only within same category - LLM with LLM, non-LLM with non-LLM)
    normalization_map = {
        # LLM variations - merge only with other LLM
        'LLM: HTMLInjection': 'LLM: HTML Injection',
        'LLM: XSS_Injection': 'LLM: XSS Injection',
        'LLM: html_injection': 'LLM: HTML Injection',
        'LLM: xss_injection': 'LLM: XSS Injection',
        'LLM: sql_injection': 'LLM: SQL Injection',
        'LLM: Sql Injection': 'LLM: SQL Injection',
        'LLM: path_injection': 'LLM: Path Injection',
        'LLM: path injection': 'LLM: Path Injection',
        'LLM: os_command_injection': 'LLM: OS Command Injection',
        'LLM: ssrf_injection': 'LLM: SSRF Injection',
        'LLM: SSRF_INJECTION': 'LLM: SSRF Injection',
        'LLM: information_disclosure': 'LLM: Information Disclosure',
        'LLM: Information Disclosure (field_suggestions)': 'LLM: Information Disclosure',
        'LLM: Information Disclosure via GraphQL Schema': 'LLM: Information Disclosure',
        'LLM: Information Disclosure: field_suggestions': 'LLM: Information Disclosure',
        'LLM: field_suggestions': 'LLM: Field Suggestions',
        'LLM: fileds_suggestions': 'LLM: Field Suggestions',
        'LLM: introspection': 'LLM: GraphQL Introspection',
        'LLM: query_deny_bypass': 'LLM: Query Deny Bypass',
        'LLM: unknown': None,  # Remove unknown
        'LLM: ssrf_injection_with_link': 'LLM: SSRF Injection',
        # Merge LLM SSRF variations
        'LLM: SSRF': 'LLM: SSRF Injection',
        'LLM: SSRF (Server-Side Request Forgery)': 'LLM: SSRF Injection',
        # Merge LLM XSS variations
        'LLM: XSS': 'LLM: XSS Injection',
        'LLM: XSS (Cross-Site Scripting)': 'LLM: XSS Injection',
        'LLM: XSS (Cross-Site Scripting)/HTML Injection': 'LLM: XSS Injection',
        
        # Introspection-related variations - standardize to consistent names
        'LLM: GraphQL Introspection / Schema Information Disclosure': 'LLM: GraphQL Introspection',
        'LLM: GraphQL Schema Disclosure (Introspection-like error leakage)': 'LLM: GraphQL Introspection',
        'LLM: GraphQL introspection': 'LLM: GraphQL Introspection',
        'LLM: GraphQL schema information disclosure (introspection via error messages)': 'LLM: GraphQL Introspection',
        'LLM: GraphQL schema introspection / information disclosure': 'LLM: GraphQL Introspection',
        'LLM: Introspection (GraphQL schema exposure)': 'LLM: GraphQL Introspection',
        'LLM: Introspection / Schema disclosure': 'LLM: GraphQL Introspection',
        'LLM: Introspection (schema information disclosure)': 'LLM: GraphQL Introspection',
        'LLM: GraphQL Schema Information Disclosure (Introspection)': 'LLM: GraphQL Introspection',
        'LLM: GraphQL schema disclosure / introspection via error messages': 'LLM: GraphQL Introspection',
        # Consolidate all introspection types into GraphQL Introspection
        'LLM: Introspection': 'LLM: GraphQL Introspection',
        'LLM: Introspection Vulnerability': 'LLM: GraphQL Introspection',
        
        # Non-LLM variations - keep separate from LLM
        'Cross-Site Scripting (XSS) Injection': 'XSS Injection',
        'SQL Injection (SQLi) Injection': 'SQL Injection',
        'Server-Side Request Forgery (SSRF) Injection': 'SSRF Injection',
        'Path Injection': 'Path Injection',
        'HTML Injection': 'HTML Injection',
        'Field Suggestions Enabled': 'Field Suggestions'
    }
    
    # Apply normalization
    if normalized in normalization_map:
        return normalization_map[normalized]
    
    return normalized

def extract_detection_names_from_json(json_str):
    """Extract detection names from JSON string in llm_results column."""
    if not json_str or json_str.strip() == '[]':
        return []
    
    try:
        data = json.loads(json_str)
        if isinstance(data, list):
            names = [item.get('detection_name', '') for item in data if item.get('detection_name')]
            # Normalize and filter names
            normalized_names = [normalize_detection_name(name) for name in names]
            return [name for name in normalized_names if name is not None]
        return []
    except (json.JSONDecodeError, TypeError):
        return []

def extract_simple_detection_names(json_str):
    """Extract detection names from simple_results JSON string."""
    if not json_str or json_str.strip() == '[]':
        return []
    
    try:
        data = json.loads(json_str)
        if isinstance(data, list):
            names = [item.get('detection_name', '') for item in data if item.get('detection_name')]
            # Normalize and filter names
            normalized_names = [normalize_detection_name(name) for name in names]
            return [name for name in normalized_names if name is not None]
        return []
    except (json.JSONDecodeError, TypeError):
        return []

def process_csv_file(file_path):
    """Process a single CSV file and extract relevant data."""
    data = {
        'node_name': '',
        'total_vulnerabilities': 0,
        'consensus_stats': defaultdict(int),
        'detection_names': set(),
        'vulnerable_count': 0,
        'potential_count': 0,
        'safe_count': 0,
        'has_vulnerabilities': False
    }
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                # Extract node name from first row
                if not data['node_name']:
                    data['node_name'] = row.get('node_name', '').replace('_response_', '_')
                
                # Check if this row has vulnerabilities
                consensus = row.get('consensus', '')
                if consensus and consensus != 'no_vulnerabilities':
                    data['has_vulnerabilities'] = True
                    data['consensus_stats'][consensus] += 1
                    data['total_vulnerabilities'] += 1
                
                # Count vulnerable, potential, and safe
                try:
                    data['vulnerable_count'] += int(row.get('llm_vulnerable_count', 0))
                    data['potential_count'] += int(row.get('llm_potential_count', 0))
                    data['safe_count'] += int(row.get('llm_safe_count', 0))
                except (ValueError, TypeError):
                    pass
                
                # Extract detection names from llm_results
                llm_results = row.get('llm_results', '')
                if llm_results:
                    detection_names = extract_detection_names_from_json(llm_results)
                    data['detection_names'].update(detection_names)
                
                # Extract detection names from simple_results
                simple_results = row.get('simple_results', '')
                if simple_results:
                    simple_detection_names = extract_simple_detection_names(simple_results)
                    data['detection_names'].update(simple_detection_names)
    
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
    
    return data

def main():
    """Main function to process all CSV files and generate aggregated report."""
    base_dir = "/Users/sina/Documents/PrediQL-Results/gpt_all"
    
    # Find all dual detection CSV files
    csv_files = glob.glob(os.path.join(base_dir, "**", "*_dual_detection_comparison.csv"), recursive=True)
    
    print(f"Found {len(csv_files)} dual detection CSV files")
    
    # Group files by directory and consensus
    directory_consensus_data = defaultdict(lambda: defaultdict(list))
    
    for csv_file in csv_files:
        # Extract directory name (the parent of prediql-output)
        path_parts = Path(csv_file).parts
        if 'prediql-output' in path_parts:
            prediql_index = path_parts.index('prediql-output')
            directory_name = path_parts[prediql_index - 1]
        else:
            directory_name = 'unknown'
        
        print(f"Processing: {csv_file} -> {directory_name}")
        data = process_csv_file(csv_file)
        
        if data['node_name']:  # Only include if we found valid data
            # Convert set to list for JSON serialization
            data['detection_names'] = list(data['detection_names'])
            data['unique_detection_count'] = len(data['detection_names'])
            data['file_path'] = csv_file
            data['directory'] = directory_name
            
            # Group by consensus type within directory
            for consensus in data['consensus_stats'].keys():
                directory_consensus_data[directory_name][consensus].append(data)
    
    # Process each directory and consensus combination
    aggregated_data = []
    all_detection_names = set()
    
    for directory_name, consensus_data in directory_consensus_data.items():
        print(f"\nProcessing directory: {directory_name}")
        
        # Process each consensus type within the directory
        for consensus_type, nodes in consensus_data.items():
            print(f"  Processing consensus: {consensus_type} ({len(nodes)} nodes)")
            
            # Group nodes by node_name within this consensus
            node_groups = defaultdict(list)
            for node in nodes:
                node_groups[node['node_name']].append(node)
            
            # Track unique detection name combinations per node within this consensus
            node_detection_combinations = {}
            # Track unique vulnerability instances (node_name, detection_name) pairs
            unique_vulnerability_instances = set()
            
            # For each unique node, collect all detection name combinations
            for node_name, node_list in node_groups.items():
                # Get all unique detection name combinations for this node
                detection_combinations = set()
                for node in node_list:
                    if node['has_vulnerabilities'] and node['detection_names']:
                        # Create a sorted tuple of detection names as a unique identifier
                        detection_tuple = tuple(sorted(node['detection_names']))
                        detection_combinations.add(detection_tuple)
                        
                        # Add unique (node_name, detection_name) pairs
                        for detection_name in node['detection_names']:
                            unique_vulnerability_instances.add((node_name, detection_name))
                
                node_detection_combinations[node_name] = detection_combinations
            
            # Calculate stats for this directory-consensus combination
            consensus_stats = {
                'directory': directory_name,
                'consensus_type': consensus_type,
                'total_nodes': len(node_groups),
                'total_vulnerabilities': 0,
                'all_detection_names': set(),
                'vulnerable_count': 0,
                'potential_count': 0,
                'safe_count': 0,
                'nodes_with_vulnerabilities': 0,
                'unique_detection_combinations': 0,
                'unique_vulnerability_instances': 0  # New metric: unique (node_name, detection_name) pairs
            }
            
            # Count nodes with vulnerabilities and add individual records
            for node_name, node_list in node_groups.items():
                # Sort by has_vulnerabilities (True first), then by total_vulnerabilities
                best_node = sorted(node_list, key=lambda x: (not x['has_vulnerabilities'], -x['total_vulnerabilities']))[0]
                
                # Add to consensus stats
                consensus_stats['total_vulnerabilities'] += best_node['total_vulnerabilities']
                consensus_stats['vulnerable_count'] += best_node['vulnerable_count']
                consensus_stats['potential_count'] += best_node['potential_count']
                consensus_stats['safe_count'] += best_node['safe_count']
                consensus_stats['all_detection_names'].update(best_node['detection_names'])
                
                # Count unique detection combinations for this node
                unique_combinations = len(node_detection_combinations[node_name])
                if unique_combinations > 0:
                    consensus_stats['nodes_with_vulnerabilities'] += 1
                    consensus_stats['unique_detection_combinations'] += unique_combinations
                
                # Add individual node record for this consensus
                aggregated_data.append({
                    'directory': directory_name,
                    'consensus_type': consensus_type,
                    'node_name': node_name,
                    'vulnerability_count': best_node['total_vulnerabilities'],
                    'unique_detection_count': best_node['unique_detection_count'],
                    'vulnerable_count': best_node['vulnerable_count'],
                    'potential_count': best_node['potential_count'],
                    'safe_count': best_node['safe_count'],
                    'has_vulnerabilities': best_node['has_vulnerabilities'],
                    'unique_detection_combinations': unique_combinations,
                    'unique_vulnerability_instances': len([(node_name, det) for det in best_node['detection_names']]),
                    'detection_names': best_node['detection_names'],
                    'file_path': best_node['file_path']
                })
            
            # Set the total unique vulnerability instances for this consensus
            consensus_stats['unique_vulnerability_instances'] = len(unique_vulnerability_instances)
            
            # Convert set to list for JSON serialization
            consensus_stats['all_detection_names'] = list(consensus_stats['all_detection_names'])
            consensus_stats['unique_detection_count'] = len(consensus_stats['all_detection_names'])
            
            # Add consensus summary record
            aggregated_data.append({
                'directory': f"{directory_name}_{consensus_type}",
                'consensus_type': consensus_type,
                'node_name': 'TOTAL',
                'vulnerability_count': consensus_stats['total_vulnerabilities'],
                'unique_detection_count': consensus_stats['unique_detection_count'],
                'vulnerable_count': consensus_stats['vulnerable_count'],
                'potential_count': consensus_stats['potential_count'],
                'safe_count': consensus_stats['safe_count'],
                'has_vulnerabilities': consensus_stats['total_vulnerabilities'] > 0,
                'unique_detection_combinations': consensus_stats['unique_detection_combinations'],
                'unique_vulnerability_instances': consensus_stats['unique_vulnerability_instances'],
                'detection_names': consensus_stats['all_detection_names'],
                'file_path': 'AGGREGATED'
            })
            
            all_detection_names.update(consensus_stats['all_detection_names'])
    
    # Generate overall summary
    total_directories = len(directory_consensus_data)
    total_nodes = sum(len(set(node['node_name'] for nodes in consensus_data.values() for node in nodes)) for consensus_data in directory_consensus_data.values())
    total_vulnerabilities = sum(data['vulnerability_count'] for data in aggregated_data if data['node_name'] != 'TOTAL')
    total_unique_detections = len(all_detection_names)
    
    # Write detailed CSV report
    output_file = os.path.join(base_dir, "dual_detection_aggregated_report_v2.csv")
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        if aggregated_data:
            fieldnames = ['directory', 'consensus_type', 'node_name', 'vulnerability_count', 'unique_detection_count', 
                         'vulnerable_count', 'potential_count', 'safe_count', 'has_vulnerabilities', 
                         'unique_detection_combinations', 'unique_vulnerability_instances', 'detection_names', 'file_path']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(aggregated_data)
    
    # Print summary
    print("\n" + "="*80)
    print("DUAL DETECTION AGGREGATED ANALYSIS SUMMARY (V2)")
    print("="*80)
    print(f"Total directories analyzed: {total_directories}")
    print(f"Total unique nodes: {total_nodes}")
    print(f"Total vulnerabilities found: {total_vulnerabilities}")
    print(f"Total unique detection names: {total_unique_detections}")
    
    print(f"\nResults by directory and consensus:")
    for directory_name, consensus_data in directory_consensus_data.items():
        print(f"  {directory_name}:")
        for consensus_type, nodes in consensus_data.items():
            node_groups = defaultdict(list)
            for node in nodes:
                node_groups[node['node_name']].append(node)
            
            total_vulns = 0
            nodes_with_vulns = 0
            unique_combinations = 0
            
            for node_name, node_list in node_groups.items():
                best_node = sorted(node_list, key=lambda x: (not x['has_vulnerabilities'], -x['total_vulnerabilities']))[0]
                total_vulns += best_node['total_vulnerabilities']
                
                # Count unique detection combinations for this node
                detection_combinations = set()
                for node in node_list:
                    if node['has_vulnerabilities'] and node['detection_names']:
                        detection_tuple = tuple(sorted(node['detection_names']))
                        detection_combinations.add(detection_tuple)
                
                if len(detection_combinations) > 0:
                    nodes_with_vulns += 1
                    unique_combinations += len(detection_combinations)
            
            # Calculate unique vulnerability instances for this consensus
            unique_instances = set()
            for node_name, node_list in node_groups.items():
                best_node = sorted(node_list, key=lambda x: (not x['has_vulnerabilities'], -x['total_vulnerabilities']))[0]
                if best_node['has_vulnerabilities'] and best_node['detection_names']:
                    for detection_name in best_node['detection_names']:
                        unique_instances.add((node_name, detection_name))
            
            print(f"    {consensus_type}: {len(node_groups)} nodes, {nodes_with_vulns} with vulnerabilities, {unique_combinations} unique detection combinations, {len(unique_instances)} unique vulnerability instances, {total_vulns} total vulnerabilities")
    
    print(f"\nAll unique detection names found:")
    for name in sorted(all_detection_names):
        print(f"  - {name}")
    
    print(f"\nDetailed aggregated report saved to: {output_file}")
    
    # Create a summary JSON file as well
    summary_json = {
        'total_directories': total_directories,
        'total_nodes': total_nodes,
        'total_vulnerabilities': total_vulnerabilities,
        'total_unique_detections': total_unique_detections,
        'all_detection_names': sorted(list(all_detection_names)),
        'directory_summaries': {},
        'node_details': aggregated_data
    }
    
    # Add directory-consensus summaries
    for directory_name, consensus_data in directory_consensus_data.items():
        summary_json['directory_summaries'][directory_name] = {}
        
        for consensus_type, nodes in consensus_data.items():
            node_groups = defaultdict(list)
            for node in nodes:
                node_groups[node['node_name']].append(node)
            
            total_vulns = 0
            nodes_with_vulns = 0
            unique_combinations = 0
            all_detection_names_dir = set()
            
            for node_name, node_list in node_groups.items():
                best_node = sorted(node_list, key=lambda x: (not x['has_vulnerabilities'], -x['total_vulnerabilities']))[0]
                total_vulns += best_node['total_vulnerabilities']
                all_detection_names_dir.update(best_node['detection_names'])
                
                # Count unique detection combinations for this node
                detection_combinations = set()
                for node in node_list:
                    if node['has_vulnerabilities'] and node['detection_names']:
                        detection_tuple = tuple(sorted(node['detection_names']))
                        detection_combinations.add(detection_tuple)
                
                if len(detection_combinations) > 0:
                    nodes_with_vulns += 1
                    unique_combinations += len(detection_combinations)
            
            # Calculate unique vulnerability instances for JSON
            unique_instances_json = set()
            for node_name, node_list in node_groups.items():
                best_node = sorted(node_list, key=lambda x: (not x['has_vulnerabilities'], -x['total_vulnerabilities']))[0]
                if best_node['has_vulnerabilities'] and best_node['detection_names']:
                    for detection_name in best_node['detection_names']:
                        unique_instances_json.add((node_name, detection_name))
            
            summary_json['directory_summaries'][directory_name][consensus_type] = {
                'total_nodes': len(node_groups),
                'nodes_with_vulnerabilities': nodes_with_vulns,
                'unique_detection_combinations': unique_combinations,
                'unique_vulnerability_instances': len(unique_instances_json),
                'total_vulnerabilities': total_vulns,
                'unique_detection_count': len(all_detection_names_dir),
                'detection_names': sorted(list(all_detection_names_dir))
            }
    
    json_output_file = os.path.join(base_dir, "dual_detection_aggregated_summary_v2.json")
    with open(json_output_file, 'w', encoding='utf-8') as f:
        json.dump(summary_json, f, indent=2, ensure_ascii=False)
    
    print(f"Summary JSON saved to: {json_output_file}")

if __name__ == "__main__":
    main()
