import faiss
import numpy as np
import json
import re
from sentence_transformers import SentenceTransformer
from config import Config
# import openai  # or use local LLM interface like ollama
import os
from initial_llama3 import ensure_ollama_running
from llama_initiator import  get_llm_model
from parse_endpoint_results import getnodefromcompiledfile
from fix_endpoint_case import fix_endpoint_case
from datetime import datetime


import yaml
# def get_compiled_queries()):
#     compiled_results = self.qler_handler.get_compiled_results()
#     compiled_queries = compiled_results["queries"]
#     compiled_mutations = compiled_results["mutations"]
#     return compiled_queries, compiled_mutations

sets = []

def find_node_definition(node_name):
    """
    Search YAML files for a node definition matching node_name.
    Matches either:
      - the top-level key
      - the internal 'name' field in the value
    Returns the node definition (dict) if found, or None if not found.
    """
    queries_path = os.path.join("load_introspection",  "query_parameter_list.yml")
    mutations_path = os.path.join("load_introspection", "mutation_parameter_list.yml")
    file_paths = [queries_path, mutations_path]
    for path in file_paths:
        if not os.path.exists(path):
            print(f"Schema_File not found: {path}")
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


def extract_request_response_pairs(json_file_path):
    # Check if the file exists
    if not os.path.exists(json_file_path):
        print(f"File not found: {json_file_path}")
        return []
    
    # Check if the file is empty
    if os.path.getsize(json_file_path) == 0:
        print(f"File is empty: {json_file_path}")
        return []

    # Try loading JSON
    try:
        with open(json_file_path, "r") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON format: {e}")
        return []

    pairs = []
    for item in data:
        query = item.get("query")
        success = item.get("success", True)  # Default to True if not present
        
        if success:
            # For successful requests, only include the query
            pairs.append((query, None))
        else:
            # For failed requests, include query and error message
            response_body = item.get("response_body", {})
            if isinstance(response_body, dict):
                errors = response_body.get("errors", [])
                if errors and isinstance(errors, list) and len(errors) > 0:
                    # Remove extensions key from each error
                    cleaned_errors = []
                    for error in errors:
                        if isinstance(error, dict):
                            cleaned_error = {k: v for k, v in error.items() if k != "extensions"}
                            cleaned_errors.append(cleaned_error)
                        else:
                            cleaned_errors.append(error)
                    pairs.append((query, cleaned_errors))
    return pairs

# # Example usage:
# if __name__ == "__main__":
#     json_path = "llama_queries.json"  # replace with your path
#     pairs = extract_request_response_pairs(json_path)
#     for i, (request, response) in enumerate(pairs, 1):
#         print(f"--- Pair {i} ---")
#         print("Request:")
#         print(request.strip())
#         print("Response:")
#         print(json.dumps(response, indent=2))

def load_index_and_model():
    print("[INFO] Loading FAISS index and model...")
    index = faiss.read_index(Config.INDEX_FILE)
    with open(Config.MODEL_NAME_FILE, "r") as f:
        model_name = f.read().strip()
    model = SentenceTransformer(model_name)
    return index, model

def load_texts():
    with open(Config.JSON_FILE, "r", encoding="utf-8") as f:
        records = json.load(f)
    texts = [
        f"Query: {r['query']} | Response: {r['response']} | Status: {r.get('status', 'N/A')}"
        for r in records
    ]
    return texts, records

# def load_schema():
    

def retrieve_similar(node, model, index, texts, top_k=5):
    query_embedding = model.encode([node])
    distances, indices = index.search(np.array(query_embedding), top_k)
    results = [texts[i] for i in indices[0]]
    return results

# testtext = f"""You are an expert in GraphQL API analysis. 
#     The following are real queries, responses, and status codes from an endpoint.
#     Will be tested under an off-line and safe environment.
#     according to your analysis, generate new test payloads,
#     use fuzzing method to generate given parameters, do not use placeholders, instead, using real generated valid inputs.
#     all queries must look like real client requests.
#     - Generate realistic, production-like test values, not templates or variables."""

# prompt1 = """
#     You are an expert in GraphQL API testing.  
#     You will be given real queries, responses, and status codes from an endpoint.  
#     All testing will be performed in a safe, offline environment to improve robustness and input validation.  
#     All queries must strictly conform to the given GraphQL schema.
#     Always start the code block with: ```graphql and then the content of queries
#     Always end the code block with: ```
#     for test type name, put in format: ***<operation name/ test type>*** out side of graphql code block
#     please generate only ONE query in separate ```graphql code block.
#     Generate only ONE query each time.
#     you may start from simple request, and main idea is to covera all fields and edges in success request.
#     the total number of requests will be {MAX_REQUESTS}

#     Must not use placeholders or descriptive placeholders. 
#     always randomly generate actual, concrete values that conform to the schema type,
#     makes sure that I can copy it to send to the api.

#     Must not use edges or node in your payload generation.

#     you must use real fileds or data given: 
#     {top_matches}

#     previously generated and responses from the endpoint:
#     {previous_response_pairs}

#     the parameters input of this {source}:
#     {input}

#     the returns/output :
#     {output}

#     the relevant schema are:
#     {relevant_objects}

#     Node Type:
#     {node_type}

#     Based on this, create testing queries to explore the vulnerabilities of this node of the endpoint:
#     {endpoint}
#     """

#     





# prompt_llm_with_context(top_matches, node, relevant_object, input, output, source, max_requests, node_type)
def save_prompt_response_pair(endpoint, prompt, llm_response, query_json, approx_tokens):
    """
    Save the prompt and LLM response to a prompts folder for analysis and debugging.
    """
    # Create prompts directory if it doesn't exist
    prompts_dir = os.path.join(os.getcwd(), "prompts")
    if not os.path.exists(prompts_dir):
        os.makedirs(prompts_dir)
    
    # Create endpoint-specific subdirectory
    endpoint_dir = os.path.join(prompts_dir, endpoint)
    if not os.path.exists(endpoint_dir):
        os.makedirs(endpoint_dir)
    
    # Generate timestamp for unique filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"prompt_response_{timestamp}.json"
    filepath = os.path.join(endpoint_dir, filename)
    
    # Prepare data to save
    prompt_data = {
        "timestamp": timestamp,
        "endpoint": endpoint,
        "prompt": prompt,
        "llm_response": llm_response,
        "parsed_queries": query_json,
        "approx_tokens": approx_tokens,
        "request_time": datetime.now().isoformat()
    }
    
    # Save to file
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(prompt_data, f, indent=2, ensure_ascii=False)
        print(f"✅ Saved prompt-response pair to: {filepath}")
    except Exception as e:
        print(f"⚠️ Warning: Failed to save prompt-response pair: {e}")
    

# prompt_llm_with_context(top_matches, node, relevant_object, input, output, source, max_requests, node_type)
def prompt_llm_with_context(top_matches, endpoint, schema, input, output, source, MAX_REQUESTS, node_type, include_schema=True, arg_mode="known", depth=1, n_variants=1):
    previous_response_pairs = extract_request_response_pairs(os.path.join(os.getcwd(), Config.OUTPUT_DIR,endpoint, "llama_queries.json"))
    formatted_previous_pairs = []
    for query, error_msg in previous_response_pairs:
        pair_obj = {
            "query": query,
            "error": error_msg if error_msg else None
        }
        formatted_previous_pairs.append(pair_obj)
    
    previous_pairs_text = json.dumps(formatted_previous_pairs, indent=2) if formatted_previous_pairs else "[]"

    query_json = {"query": []}
    # context_block = "\n---\n".join(context_snippets)
#     prompt2 = f"""You are an expert in GraphQL API testing.  
# You will be given real queries, responses, and status codes from an endpoint.  
# All testing will be performed in a safe, offline environment to improve robustness and input validation.  
# All queries must strictly conform to the given GraphQL schema.
# #     Always start the code block with: ```graphql and then the content of queries
# #     Always end the code block with: ```
# #     please generate only ONE query in separate ```graphql code block.
# Generate only ONE query each time.
# you may start from simple request, and main idea is to covera all fields and edges in success request.
# Must not use placeholders or descriptive placeholders. 
# always randomly generate actual, concrete values that conform to the schema type,
# makes sure that I can copy it to send to the api.
# Must not use edges or node in your payload generation
# input: {input}
# putupt: {output}
# schemas: {schema}
# node type: {node_type}
# previouse response pairs: {previous_response_pairs}
# you shall use real fileds or data given: {top_matches}
# Based on this, you must create testing queries to explore the vulnerabilities of this node of the endpoint:***{endpoint}***"""
    header = f"""
    You are an expert in GraphQL API security testing.

    Goal: generate valid GraphQL queries for the operation shown, to get successful responses (HTTP 200) quickly while exploring robustness and testing for specific vulnerability types.

    
    CRITICAL REQUIREMENT: You MUST include at least one query for a basic call and EACH of the following vulnerability types:
    - SQL Injection
    - XSS Injection
    - SSRF Injection
    - OS Command Injection
    - Path Injection
    - HTML Injection
    - Query Deny Bypass (REQUIRES TWO QUERIES: non-aliased and aliased)
    - Introspection
    - Field Suggestions

    Strict Requirements:
    1) Queries must be syntactically valid GraphQL.
    2) No placeholders like <id>, "ID!", "value". Use realistic literals or known real values.
    3) You may attempt injected strings, nulls, overlong strings, and type mismatches where appropriate.
    4) You may output {n_variants} query(ies) but MUST cover all vulnerability types listed above.
    5) Do not use the words "edges" or "node".
    6) GraphQL is case-sensitive. Match the exact operation name: {endpoint}.
    7) If there are previous response pairs, use them to generate the query.
    8) For each vulnerability type, craft queries that specifically test for that vulnerability pattern.
    9) CRITICAL: Label each query with its vulnerability type using the format: ***<vulnerability_type>*** before each ```graphql block.
    10) SPECIAL CASE: For Query Deny Bypass, you MUST generate TWO queries:
        - First query: Non-aliased version (normal query structure)
        - Second query: Aliased version (using query aliases like "s: queryName")
        Both queries should test the same operation but with different structures to test access control bypass.
    """
    # ---- Schema / no-schema blocks
    if include_schema:
        schema_block = f"""
        SCHEMA (authoritative):
        - schema types: {schema}
        - output fields (if known): {output}
        Use only fields/args compatible with this schema.
        """
        fallback_block = ""
    else:
        schema_block = ""
        fallback_block = """
        Schema not provided: explore plausibly.
        - Prefer fields/args seen in prior successful responses or known real values.
        - Introduce at most 1–2 new fields per query.
        - Keep selection depth minimal to maximize validity.
        """

    # ---- Arg mode guidance
    if arg_mode == "known":
        arg_block = "Argument strategy: reuse known-good values from context and previous 200 responses."
    elif arg_mode == "real":
        arg_block = ("Argument strategy: synthesize realistic literals by type "
                     "(e.g., ISO dates, small integers, emails, UUIDv4), avoid placeholders.")
    elif arg_mode == "nulls":
        arg_block = ("Argument strategy: use null/empty for OPTIONAL inputs only; "
                     "never for non-null (!) fields.")
    else:
        arg_block = "Argument strategy: default."

    # ---- Depth constraint
    depth_block = f"Selection depth target: {depth}. Keep nested selections no deeper than {depth} levels."

    # ---- Context
    context = f"""
    Context:
    - operation: {endpoint}
    - input (declared): {input}
    - node type: {source}
    - known real values: {top_matches}
    - previous response pairs: {previous_response_pairs}

    {arg_block}
    {depth_block}
    """
    
    format_block = f"""
    Output format:
    Each query must be in its own fenced block with a vulnerability type label:
    Vulnerability Type Labels Are:
    - SQL_Injection
    - XSS_Injection
    - SSRF_Injection
    - OS_Command_Injection
    - Path_Injection
    - HTML_Injection
    - Query_Deny_Bypass_Non_Aliased
    - Query_Deny_Bypass_Aliased
    - Introspection
    - Field_Suggestions
    - Basic_Call

    ***<Vulnerability Type>***
    ```graphql
    <your query>
    ```
    
    Example:
    ***SQL_Injection***
    ```graphql
    query {{
      users(filter: "1' OR '1'='1") {{
        id
        name
      }}
    }}
    ```
    
    ***XSS_Injection***
    ```graphql
    query {{
      search(term: "<script>alert('xss')</script>") {{
        results
      }}
    }}
    ```
    """
    # prompt1 = f"""
    # You are an expert in GraphQL API security testing.

    # Your job is to **generate valid GraphQL queries** targeting the specific operation shown below, using the associated schema. The purpose of these queries is to **explore and test the robustness of the API implementation**, including detection of security vulnerabilities like:

    # - **SQL injection**
    # - **Field misuse or schema abuse**
    # - **Deep object traversal**
    # - **Unexpected type coercion**
    # - **Use of reserved fields or hidden introspection**

    # ---

    # **Strict Requirements:**

    # 1. All queries must be **syntactically valid** according to the GraphQL schema.
    # 2. You must **not use placeholders** such as `<id>`, `"ID!"`, or `"value"`.
    # - Instead, use:
    #     - *Known real values* from the context, or
    #     - *Generated realistic test values* based on the type (e.g., strings, dates, numbers).
    # 3. You **may explore security vectors**, such as:
    # - Injected strings: `" OR "1"="1"`
    # - Nulls, overlong strings, or unexpected nesting
    # - Type mismatches (e.g., numbers where strings are expected)
    # 4. LLM has the freedom to generate **either a single query or multiple queries**, based on what's most effective for testing the endpoint.
    # 5. Assume a secure, offline sandbox. You are free to test aggressively without risk.
    # 6. ***Must not use words such as: 'edges' or 'node' in your payload generation.***
    # 7. If the schema is not provided, you are free to explore the endpoint by making plausible assumptions about its structure and arguments, while still producing syntactically valid GraphQL queries and incorporating potential security test vectors.
    # ---

    # **Output Format:**

    # - Each query must be in its own code block like so:
    # ```graphql
    # <your query>
    # ```
    
    # Example:
    
    # Context you will use to generate the query:
    # operation: {endpoint}

    # input: {input}

    # node type: {node_type}

    # known real values to use: {top_matches}

    # previous response pairs: {previous_response_pairs}

    # Now, beaware that GraphQL is case-sensitive, generate one or more valid GraphQL queries to test, you must match the case given for query: {endpoint}


    # """

    # schemaprompt = f"""
    # #     output: {output}

    # # schema types: {schema}
    # """

    # prompt3  = f"""
    # You are an expert in GraphQL API security testing.

    # You will be given **only** the operation you need to test, along with its schema definitions.  
    # All testing is performed in a safe, offline environment to improve robustness and input validation.

    # Your task is to generate exactly **valid GraphQL queries** for the **specific operation shown below**, strictly conforming to the provided GraphQL schema.

    # **You must only use the operation and fields defined below.**  
    # **You may not invent or guess any additional fields.**

    # **Important Rules:**
    # - Always output responses in a single ```graphql code block.
    # - Always start your query with: ```graphql
    # - Always end with: ```
    # - Always generate only ONE query in separate ```graphql code block.
    # - Outside the GraphQL code block, label the test type and operation in the format: ***<operation name / test type>***
    # - Use only *real* values provided in the context. No placeholders or variables like `<id>`. Use realistic example values that conform to the schema types.
    # - Do **not** use Relay-style connection patterns. This schema does **not** support `edges`, `node`, or `nodes`.
    # - The return value of this query is a **plain array** of the type {node_type}. There are **no connection fields** or nested wrappers. Use only the listed fields.

    # **Your Goal:**  
    # - Generate several queries to thoroughly test this operation against the given endpoint.
    # - Cover as many fields as possible within the schema, while using concrete example values.

    # **Context you will use to generate the query:**

    # - operation: {endpoint}
    # - input: {input}
    # - output: {output}
    # - schema types: {schema}
    # - node type: {node_type}
    # - known real values to use: {top_matches}
    # - previouse response pairs: {previous_response_pairs}

    # You must generate a test query for:

    # ***{endpoint}***
    # """

    # prompt = f"""
    # You are an expert in GraphQL API security testing.

    # Your task is to generate at least **3–5 valid GraphQL queries** to test the operation below.

    # **Rules:**
    # - Each query must be inside a separate ```graphql code block.
    # - Label each block with a test type like: ***Invalid Argument Test***
    # - Use only fields and types listed in the schema.
    # - Use only *real values* listed in the context — no <id> or placeholders.
    # - Do not use Relay-style connection patterns.
    # - Return value is a flat array of type `{node_type}`.

    # --- Context ---

    # - Operation: {endpoint}
    # - Input args: {input}
    # - Output fields: {output}
    # - Schema: {schema}
    # - Node type: {node_type}
    # - Known real values: {top_matches}
    # - Previous queries: {previous_response_pairs}

    # Now generate 3–5 diverse GraphQL queries for: ***{endpoint}***
    # """

    prompt_arms = header + schema_block + fallback_block + context + format_block



    approx_tokens = len(prompt_arms) / 4
    print(f"Approximate token count: {approx_tokens:.0f}")


    try:
        llama_res = get_llm_model(prompt_arms)
    except Exception as e:
        print(f"⚠️ Error calling get_llm_model: {e}")
        return {"query": []}, 0
    
    query_json = {"query": []}
    flag = "```graphql"
    parse_time = 0
    
    # Handle case where get_llm_model returns None
    if llama_res is None:
        print("⚠️ Warning: get_llm_model returned None, skipping query parsing")
        return query_json, 0
    
    while flag in llama_res and parse_time < 12:
        parse_time += 1
        try:
            sidx = llama_res.find(flag)
            if sidx == -1:
                break
            
            # Look for vulnerability type label before the graphql block
            vulnerability_type = "unknown"
            # Updated pattern to match ***Vulnerability Type*** format
            label_pattern = r"\*\*\*([^*]+)\*\*\*"
            text_before_query = llama_res[:sidx]
            label_match = re.search(label_pattern, text_before_query)
            if label_match:
                vulnerability_type = label_match.group(1).strip().lower()
                # Normalize query deny bypass types
                if "query_deny_bypass_non_aliased" in vulnerability_type:
                    vulnerability_type = "query_deny_bypass_non_aliased"
                elif "query_deny_bypass_aliased" in vulnerability_type:
                    vulnerability_type = "query_deny_bypass_aliased"
                
            j_start = llama_res[sidx+len(flag):]
            j_end = j_start.find("```")
            if j_end == -1:
                break
                
            query_str = j_start[:j_end]
            llama_res = j_start[j_end:]
            
            # Safety check: if llama_res becomes empty or None, break
            if not llama_res:
                break

            query_str = fix_endpoint_case(query_str, endpoint)

            # Store query with vulnerability type
            query_entry = {
                "query": query_str,
                "vulnerability_type": vulnerability_type
            }
            
            # Check if this exact query already exists
            if not any(q["query"] == query_str for q in query_json["query"]):
                query_json["query"].append(query_entry)
        except Exception as e:
            print(e)
            continue
      
      
        
    # Save prompt and response to prompts folder
    save_prompt_response_pair(endpoint, prompt_arms, llama_res, query_json, approx_tokens)
    
    return query_json, approx_tokens

def get_LLM_firstresposne(node, objects):
    index, model = load_index_and_model()
    texts, records = load_texts()
    sets = node, model, index, texts

    ensure_ollama_running("llama3")


    top_matches = retrieve_similar(node, model, index, texts)
    # print("\n[INFO] Top Relevant Entries:\n")
    # for i, t in enumerate(top_matches, 1):
        # print(f"{i}. {t}\n")

    llm_output = prompt_llm_with_context(top_matches, node, objects)
    # print("\n[LLM Output]:\n")
    # print(llm_output)
    return llm_output

def get_LLM_resposne(node, objects):
    # index, model = load_index_and_model()
    # texts, records = load_texts()

    # ensure_ollama_running("llama3")


    top_matches = retrieve_similar(sets)
    # print("\n[INFO] Top Relevant Entries:\n")
    # for i, t in enumerate(top_matches, 1):
        # print(f"{i}. {t}\n")

    llm_output = prompt_llm_with_context(top_matches, node, objects)
    # print("\n[LLM Output]:\n")
    # print(llm_output)
    return llm_output
    


if __name__ == "__main__":
    endpoint, objects = getnodefromcompiledfile()
    node = "charactersByIds"
    for key in endpoint:
        print(endpoint[key])
    #     query_text = f"please generage graphql query to test the endpoint for this node: {endpoint[key]}"
    node = "episodesByIds"
    get_LLM_firstresposne(node, objects)

    # index, model = load_index_and_model()
    # texts, records = load_texts()

    # ensure_ollama_running("llama3")


    # top_matches = retrieve_similar(node, model, index, texts)
    # print("\n[INFO] Top Relevant Entries:\n")
    # for i, t in enumerate(top_matches, 1):
    #     print(f"{i}. {t}\n")

    # llm_output = prompt_llm_with_context(top_matches, node)
    # print("\n[LLM Output]:\n")
    # print(llm_output)
