import os
import re
import json
import yaml
import numpy as np
import faiss
from pathlib import Path
from sentence_transformers import SentenceTransformer
from config import Config

base_path = os.getcwd()

def getnodefromcompiledfile():
    queries_path = os.path.join("graphqler-output", "compiled", "compiled_queries.yml")
    mutations_path = os.path.join("graphqler-output", "compiled", "compiled_mutations.yml")
    objects_path = os.path.join("graphqler-output", "compiled", "compiled_objects.yml")

    with open(queries_path, 'r', encoding='utf-8') as f:
        queries_data = yaml.safe_load(f)

    with open(mutations_path, 'r', encoding='utf-8') as f:
        mutations_data = yaml.safe_load(f)

    with open(objects_path, "r", encoding='utf-8') as f:
        objects = yaml.safe_load(f)
    return {
        "query": list(queries_data.keys()) if isinstance(queries_data, dict) else [],
        "mutation": list(mutations_data.keys()) if isinstance(mutations_data, dict) else []
    }, objects

class ParseEndpointResults():
    def __init__(self, base_path=None):
        self.base_path = base_path or os.getcwd()
        self.end_path = os.path.join(self.base_path, "graphqler-output", "endpoint_results")
        if not os.path.isdir(self.end_path):
            raise FileNotFoundError("Path {} does not exist.".format(self.end_path))

    def get_file_path(self):
        self.nodes, objects = getnodefromcompiledfile()
        allnodes = self.nodes["query"] + self.nodes["mutation"]
        endpoints_file = []
        for root, dirs, files in os.walk(self.end_path):
            if "200" in files:
                if root.split("/")[-2] in allnodes:
                    endpoints_file.append(os.path.join(root, '200'))
        return endpoints_file


    def parse_result_to_json_with_status(self):
        max_len_respo_list = 200
        payload_resp_list = []
        endpoint_files = self.get_file_path()
        print(endpoint_files)
        for filepath in endpoint_files:
            endpoint = filepath.split("/")[-3]
            status = filepath.split("/")[-1]
            print(endpoint, status)
            if len(payload_resp_list) > max_len_respo_list:
                break
            try:
                with open(filepath, "r") as f:
                    contents = f.read()
            except Exception as e:
                print("Error reading file {}: {}".format(filepath, e))
                continue

            pair_pattern = (r"------------------Payload:-------------------\n(.*?)\n-+"
                            r"-----------------Response:-------------------\n(.*?)(?=\n-+|$)")
            pairs = re.findall(pair_pattern, contents, re.DOTALL)

            for payload, response_block in pairs:
                payload_clean = payload.strip()
                response_lines = response_block.strip().splitlines()

                response_text_lines = []
                for line in response_lines:
                    if not "status" in line.lower():
                        response_text_lines.append(line)

                response_clean = "\n".join(response_text_lines).strip()
                type = "query" if endpoint in self.nodes["query"] else "mutation"
                status_code = status

                if not any(p["query"] == payload_clean for p in payload_resp_list):
                    payload_resp_list.append({
                        "endpoint": endpoint,
                        "type": type,
                        "query": payload_clean,
                        "response": response_clean,
                        "status": status_code
                    })
                if len(payload_resp_list) > max_len_respo_list:
                    break

        os.makedirs(Config.OUTPUT_DIR, exist_ok=True)

        if os.path.exists(Config.JSON_FILE):
            os.remove(Config.JSON_FILE)

        with open(Config.JSON_FILE, "w", encoding="utf-8") as f:
            json.dump(payload_resp_list, f, indent=2)

        return Config.JSON_FILE

def loadjsonfile():
    with open(Config.JSON_FILE, "r", encoding="utf-8") as f:
        records = json.load(f)
    texts = [
        f"Query: {r['query']} | Response: {r['response']} | Status: {r.get('status', 'N/A')}"
        for r in records
    ]
    return texts

def into_naturallanguage(texts):
    if os.path.exists(Config.TEXT_FILE):
        os.remove(Config.TEXT_FILE)

    with open(Config.TEXT_FILE, "w", encoding="utf-8") as f:
        for line in texts:
            f.write(line + "\n")
    return texts

def embedding(texts):
    texts = into_naturallanguage(texts)
    model = SentenceTransformer(Config.MODEL_NAME)

    # Save the model name for future loading
    with open(Config.MODEL_NAME_FILE, "w") as f:
        f.write(Config.MODEL_NAME)

    embeddings = model.encode(texts, show_progress_bar=True)
    dimension = embeddings[0].shape[0]
    index = faiss.IndexFlatL2(dimension)
    index.add(np.array(embeddings))

    faiss.write_index(index, Config.INDEX_FILE)
    return Config.INDEX_FILE

if __name__ == "__main__":
    pfr = ParseEndpointResults()
    payload_resp_pair = pfr.parse_result_to_json_with_status()
    natural_text = loadjsonfile()
    index_file_path = embedding(natural_text)
