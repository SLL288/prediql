import os

# Define base path as current working directory
BASE_PATH = os.getcwd()

# Configuration paths
class Config:
   
    GRAHPQLER_OUTPUT = os.path.join(BASE_PATH, "graphqler-output")
    MUTATION_FILE = os.path.join(BASE_PATH, GRAHPQLER_OUTPUT,"compiled","compiled_mutations.yml")
    QUERY_FILE = os.path.join(BASE_PATH, GRAHPQLER_OUTPUT,"compiled","compiled_queries.yml")
    ENDPOINTS_RESULTS = os.path.join(BASE_PATH, GRAHPQLER_OUTPUT, "endpoint_results")

    OUTPUT_DIR = os.path.join(BASE_PATH, "prediql-output")
    JSON_FILE = os.path.join(OUTPUT_DIR, "parsed_endpoint_data.json")
    TEXT_FILE = os.path.join(OUTPUT_DIR, "parsed_endpoint_text_data.txt")
    INDEX_FILE = os.path.join(OUTPUT_DIR, "parsed_endpoint_embedded_index.faiss")
    MODEL_NAME_FILE = os.path.join(OUTPUT_DIR, "model_name.txt")
    MODEL_NAME = "all-MiniLM-L6-v2"