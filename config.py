import os
import re
from urllib.parse import urlparse

# Define base path as current working directory
BASE_PATH = os.getcwd()

# Configuration paths
class Config:
   
    GRAHPQLER_OUTPUT = os.path.join(BASE_PATH, "graphqler-output")
    MUTATION_FILE = os.path.join(BASE_PATH, GRAHPQLER_OUTPUT,"compiled","compiled_mutations.yml")
    QUERY_FILE = os.path.join(BASE_PATH, GRAHPQLER_OUTPUT,"compiled","compiled_queries.yml")
    ENDPOINTS_RESULTS = os.path.join(BASE_PATH, GRAHPQLER_OUTPUT, "endpoint_results")

    OUTPUT_DIR = os.path.join(BASE_PATH, "prediql-output")
    # Per-operation artifacts live under ``OUTPUT_DIR/nodes/<operation>/`` (not run root).
    RUN_NODES_SUBDIR = "nodes"
    JSON_FILE = os.path.join(OUTPUT_DIR, "parsed_endpoint_data.json")
    TEXT_FILE = os.path.join(OUTPUT_DIR, "parsed_endpoint_text_data.txt")
    INDEX_FILE = os.path.join(OUTPUT_DIR, "parsed_endpoint_embedded_index.faiss")
    MODEL_NAME_FILE = os.path.join(OUTPUT_DIR, "model_name.txt")

    # Populated by ``configure_run_artifacts`` / ``_sync_derived_paths_from_output_dir`` (introspection YAML + run JSON).
    RUN_LOAD_INTROSPECTION_DIR = os.path.join(BASE_PATH, "load_introspection")
    INTROSPECTION_RESULT_JSON = os.path.join(BASE_PATH, "introspection_result.json")
    EMBED_INDEX_DIR = os.path.join(BASE_PATH, "embed_retrieve", "faiss_index")
    GENERATED_QUERY_INFO_JSON = os.path.join(BASE_PATH, "generated_query_info.json")
    REAL_DATA_JSON = os.path.join(BASE_PATH, "real_data.json")
    ERRORS_CSV = os.path.join(BASE_PATH, "errors.csv")
    MODEL_NAME = "all-MiniLM-L6-v2"
    # Configuration

    """Debugging purposes"""
    DEBUG = False

    """For proxy"""
    PROXY = None  # Don't use this, this will be overriten by argparse

    """For any authentication tokens (GraphQL target); optional ``--graphql-api-key`` from CLI."""
    AUTHORIZATION = None

    """Bearer / Basic secret for the LLM HTTP client; optional ``--llm-api-key`` from CLI."""
    LLM_API_KEY = None

    """For the compiler / parser"""
    OUTPUT_DIRECTORY = "graphqler-output"
    SERIALIZED_DIR_NAME = "serialized"
    EXTRACTED_DIR_NAME = "extracted"
    COMPILED_DIR_NAME = "compiled"
    ENDPOINT_RESULTS_DIR_NAME = "endpoint_results"

    INTROSPECTION_RESULT_FILE_NAME = "introspection_result.json"
    CONFIG_FILE_NAME = "config.toml"

    """Pickle files -- mainly for cross-process communication"""
    OBJECTS_BUCKET_PICKLE_FILE_NAME = "objects_bucket.pkl"
    STATS_PICKLE_FILE_NAME = "stats.pkl"

    QUERY_PARAMETER_FILE_NAME = f"{EXTRACTED_DIR_NAME}/query_parameter_list.yml"
    MUTATION_PARAMETER_FILE_NAME = f"{EXTRACTED_DIR_NAME}/mutation_parameter_list.yml"
    OBJECT_LIST_FILE_NAME = f"{EXTRACTED_DIR_NAME}/object_list.yml"
    INPUT_OBJECT_LIST_FILE_NAME = f"{EXTRACTED_DIR_NAME}/input_object_list.yml"
    ENUM_LIST_FILE_NAME = f"{EXTRACTED_DIR_NAME}/enum_list.yml"
    UNION_LIST_FILE_NAME = f"{EXTRACTED_DIR_NAME}/union_list.yml"
    INTERFACE_LIST_FILE_NAME = f"{EXTRACTED_DIR_NAME}/interface_list.yml"

    COMPILED_OBJECTS_FILE_NAME = f"{COMPILED_DIR_NAME}/compiled_objects.yml"
    COMPILED_MUTATIONS_FILE_NAME = f"{COMPILED_DIR_NAME}/compiled_mutations.yml"
    COMPILED_QUERIES_FILE_NAME = f"{COMPILED_DIR_NAME}/compiled_queries.yml"

    """For clairvoyance"""
    WORDLIST_PATH = ""

    """For the resolver"""
    MAX_LEVENSHTEIN_THRESHOLD = 20  # A very high threshold, we could probably lower this, but this almost guarantees us to find a matching object name - ID

    """For the linker"""
    GRAPH_VISUALIZATION_OUTPUT = "dependency_graph.png"

    """General Graphql definitions: https://spec.graphql.org/October2021/"""
    BUILT_IN_TYPES = ["ID", "Int", "Float", "String", "Boolean"]
    BUILT_IN_TYPE_KINDS = ["SCALAR", "OBJECT", "INTERFACE", "UNION", "ENUM", "INPUT_OBJECT", "LIST", "NON_NULL"]

    """For materializers"""
    MAX_OBJECT_CYCLES = 5
    MAX_OUTPUT_SELECTOR_DEPTH = 5
    HARD_CUTOFF_DEPTH = 20
    MAX_INPUT_DEPTH = 20

    """For loggers"""
    FUZZER_LOG_FILE_PATH = "logs/fuzzer.log"
    COMPILER_LOG_FILE_PATH = "logs/compiler.log"
    DETECTOR_LOG_FILE_PATH = "logs/detector.log"
    IDOR_LOG_FILE_PATH = "logs/idor.log"

    """For stats"""
    STATS_FILE_NAME = "stats.txt"
    OBJECTS_BUCKET_TEXT_FILE_NAME = "objects_bucket.txt"
    UNIQUE_RESPONSES_FILE_NAME = "unique_responses.txt"

    """For plugins"""
    PLUGINS_PATH = f"{OUTPUT_DIRECTORY}/plugins"

    """For using GraphQLer in different modes"""
    USE_OBJECTS_BUCKET = True  # This mode is for when we want to use the objects bucket
    USE_DEPENDENCY_GRAPH = True  # This mode is for when we want to use DFS through the dependency graph
    NO_DATA_COUNT_AS_SUCCESS = False  # This mode is for when we want to count no data in the data object as a success or failure

    """For fuzzing"""
    ALLOW_DELETION_OF_OBJECTS = False  # This mode is for when we want to allow the deletion of objects from the objects bucket when coming across a DELETE mutation success
    MAX_FUZZING_ITERATIONS = 5
    MAX_TIME = 3600  # in seconds
    SKIP_MAXIMAL_PAYLOADS = False  # This mode is for when we want to skip the maximal payloads
    SKIP_DOS_ATTACKS = True  # This mode is for when we want to skip the DoS check
    SKIP_INJECTION_ATTACKS = False  # This mode is for when we want to skip the injection check
    SKIP_MISC_ATTACKS = False  # This mode is for when we want to skip the miscellaneous attacks

    """For each request"""
    REQUEST_TIMEOUT = 120  # in seconds
    TIME_BETWEEN_REQUESTS = 0.001  # in seconds

    """For custom skipping nodes"""
    SKIP_NODES = []

    """For custom headers"""
    CUSTOM_HEADERS = {}

    """Sub-schema for LLM prompts (large introspection graphs)"""
    SUBSCHEMA_ENABLED = True
    # If the legacy full graph has this many types or fewer, pass it through unchanged.
    SUBSCHEMA_FULL_THRESHOLD_TYPES = 45
    # Max graph hops from the operation return type through OBJECT/INTERFACE/UNION fields.
    # When 0, ``sub_schema_extractor`` derives distance from the arm selection depth instead.
    SUBSCHEMA_OUTPUT_GRAPH_MAX_DISTANCE = 0
    SUBSCHEMA_MAX_TYPES = 150
    SUBSCHEMA_MAX_JSON_CHARS = 120000

    """RNG seed for Thompson arm sampling (``np.random.Generator`` in ``main``)."""
    THOMPSON_SEED = 42

    """LLM chat ``temperature`` in HTTP JSON; default 0; override with ``--llm-temperature``."""
    LLM_TEMPERATURE = 0.0

    """LLM cost tables (USD). Fallback when model key is not found in ``LLM_MODEL_PRICING_PER_1M``."""
    LLM_COST_PRICING_REFERENCE = "OpenAI gpt-4o-mini public list ($/1M tokens)"
    LLM_USD_PER_MILLION_INPUT_TOKENS = 0.15
    LLM_USD_PER_MILLION_OUTPUT_TOKENS = 0.60
    # Per-model pricing map (USD per 1M tokens): model_key -> (input_rate, output_rate).
    # Matching is case-insensitive and prefix-aware (e.g., "gpt-4o-mini-2024-07-18" -> "gpt-4o-mini").
    # Keep local Ollama models at 0.0/0.0.
    LLM_MODEL_PRICING_PER_1M = {
        "gpt-4o-mini": (0.15, 0.60),
        "gpt-4o": (5.00, 15.00),
        "gpt-4.1-mini": (0.40, 1.60),
        "gpt-4.1": (2.00, 8.00),
        "claude-3-5-haiku": (0.80, 4.00),
        "claude-3-5-sonnet": (3.00, 15.00),
        "gemini-1.5-flash": (0.35, 1.05),
        "gemini-1.5-pro": (3.50, 10.50),
        "llama3": (0.0, 0.0),
        "llama3.1": (0.02, 0.05),
        "qwen": (0.0, 0.0),
        "deepseek": (0.0, 0.0),
    }

    """Primary LLM chat (Ollama-compatible ``/api/chat``). Cross-model Jaccard is offline-only (``prediql_jaccard.py``)."""
    PRIMARY_LLM_API_URL = ""  # empty → http://localhost:11434/api/chat
    PRIMARY_LLM_MODEL = "llama3"

    """Sequential pipeline: Stage 1 coverage-only LLM → Stage 2 HTTP replay → Stage 3 vuln fuzzing."""
    PIPELINE_SEQUENTIAL_ENABLED = True
    # Max LLM→send cycles in Stage 3 (each cycle may append many labeled queries).
    VULNERABILITY_PHASE_MAX_ROUNDS = 6

    """Ablation mode: prediql | prediql-base | prediql-aqg | prediql-scl."""
    MODE = "prediql"


def _slug_segment(s: str, max_len: int = 96) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"[^a-z0-9._-]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("._-")
    return (s[:max_len] if s else "unknown")


def slug_graphql_endpoint(url: str) -> str:
    """Filesystem-safe directory name from a GraphQL HTTP(S) URL."""
    p = urlparse((url or "").strip())
    host = (p.netloc or "host").replace(":", "_")
    path = (p.path or "").strip("/").replace("/", "_")
    base = f"{host}_{path}" if path else host
    return _slug_segment(base, 120)


def slug_llm_model(model: str) -> str:
    """Filesystem-safe directory name from an LLM model id (e.g. ``llama3.1:8b``)."""
    return _slug_segment((model or "model").replace(":", "_"), 80)


def run_nodes_root() -> str:
    """Absolute path ``OUTPUT_DIR/nodes/`` (per-operation folders live here)."""
    sub = getattr(Config, "RUN_NODES_SUBDIR", "nodes")
    return os.path.join(os.path.abspath(Config.OUTPUT_DIR), sub)


def run_node_dir(endpoint: str) -> str:
    """Absolute path ``OUTPUT_DIR/nodes/<endpoint>/`` (payloads, known_good, dual CSV, etc.)."""
    name = (endpoint or "").strip() or "_"
    return os.path.join(run_nodes_root(), name)


def _sync_derived_paths_from_output_dir() -> None:
    """Keep JSON / FAISS / introspection paths aligned with ``Config.OUTPUT_DIR``."""
    root = os.path.abspath(Config.OUTPUT_DIR)
    default_out = os.path.join(BASE_PATH, "prediql-output")
    if root == os.path.abspath(default_out):
        li = os.path.join(BASE_PATH, "load_introspection")
        intro_json = os.path.join(BASE_PATH, "introspection_result.json")
        embed_dir = os.path.join(BASE_PATH, "embed_retrieve", "faiss_index")
    else:
        li = os.path.join(root, "load_introspection")
        intro_json = os.path.join(root, "introspection_result.json")
        os.makedirs(li, exist_ok=True)
        embed_dir = os.path.join(root, "embed_retrieve", "faiss_index")
    Config.RUN_LOAD_INTROSPECTION_DIR = li
    Config.INTROSPECTION_RESULT_JSON = intro_json
    Config.EMBED_INDEX_DIR = embed_dir
    Config.GENERATED_QUERY_INFO_JSON = os.path.join(root, "generated_query_info.json")
    Config.REAL_DATA_JSON = os.path.join(root, "real_data.json")
    Config.ERRORS_CSV = os.path.join(root, "errors.csv")
    # Do not auto-create legacy ``prediql-output``; structured runs live under ``output/...``.
    if root != os.path.abspath(default_out):
        os.makedirs(root, exist_ok=True)
    os.makedirs(Config.EMBED_INDEX_DIR, exist_ok=True)
    Config.JSON_FILE = os.path.join(root, "parsed_endpoint_data.json")
    Config.TEXT_FILE = os.path.join(root, "parsed_endpoint_text_data.txt")
    Config.INDEX_FILE = os.path.join(root, "parsed_endpoint_embedded_index.faiss")
    Config.MODEL_NAME_FILE = os.path.join(root, "model_name.txt")
    os.makedirs(run_nodes_root(), exist_ok=True)


def configure_run_artifacts(graphql_url: str, primary_llm_model: str, mode: str = "prediql") -> None:
    """
    All run artifacts under ``output/<mode>/<endpoint-slug>/<model-slug>/`` (introspection JSON, YAML copies, node folders, etc.).
    Sets ``PREDIQL_OUTPUT_DIR`` so subprocess scripts pick up the same layout.
    """
    out_root = os.path.join(BASE_PATH, "output")
    mode_slug = _slug_segment(mode or "prediql", 40)
    u = slug_graphql_endpoint(graphql_url)
    m = slug_llm_model(primary_llm_model or "llama3")
    run_dir = os.path.join(out_root, mode_slug, u, m)
    os.makedirs(run_dir, exist_ok=True)
    os.makedirs(os.path.join(run_dir, getattr(Config, "RUN_NODES_SUBDIR", "nodes")), exist_ok=True)
    Config.OUTPUT_DIR = run_dir
    os.environ["PREDIQL_OUTPUT_DIR"] = run_dir
    _sync_derived_paths_from_output_dir()


# Child processes (e.g. analysis_prediql) inherit ``PREDIQL_OUTPUT_DIR`` from main.
_env_out = os.environ.get("PREDIQL_OUTPUT_DIR")
if _env_out:
    Config.OUTPUT_DIR = os.path.abspath(_env_out)
    _sync_derived_paths_from_output_dir()
