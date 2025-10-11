# PrediQL - GraphQL API Security Testing Framework

PrediQL is a GraphQL API security testing framework that leverages Large Language Models (LLMs) to generate comprehensive test queries for GraphQL endpoints. The tool focuses on exploring API vulnerabilities through intelligent query generation, coverage analysis, and automated security testing.

## Features

- **Automated GraphQL Schema Introspection**: Fetches and analyzes GraphQL schemas from any endpoint
- **LLM-Powered Query Generation**: Uses local LLMs (via Ollama) to generate diverse and comprehensive test queries
- **Security-Focused Testing**: Generates queries to test for SQL injection, field misuse, deep traversal, and other vulnerabilities  
- **Coverage Analysis**: Tracks field and operation coverage to ensure comprehensive testing
- **RAG-Enhanced Testing**: Uses embedding-based retrieval to incorporate real data examples into query generation
- **Multi-Round Testing**: Supports iterative testing rounds with progressive learning
- **Comprehensive Reporting**: Generates detailed coverage reports and success/failure analysis

## Architecture

The framework consists of several key components:

### Core Components
- **`main.py`**: Main entry point and orchestration logic
- **`retrieve_and_prompt.py`**: LLM integration and prompt management
- **`GraphQLPromptBuilder.py`**: Structured prompt generation for GraphQL operations
- **`sendpayload.py`**: HTTP request handling and GraphQL query execution
- **`analysis_prediql.py`**: Coverage analysis and reporting

### Schema Processing
- **`load_introspection/`**: GraphQL schema introspection and processing
  - `save_introspection.py`: Fetches schema from endpoints
  - `load_introspection.py`: Processes and structures schema data
  - `get_query_lists.py`: Extracts query/mutation operations

### Data Management
- **`embed_retrieve/`**: Vector embedding and retrieval system
  - `embed_and_index.py`: Creates embeddings from response data
  - `retrieve_from_index.py`: Retrieves similar examples for context

### Analysis & Reporting
- **`target_endpoints.py`**: Endpoint targeting and comparison utilities
- **`parse_endpoint_results.py`**: Result parsing and data extraction
- **`delta_coverage.py`**: Coverage delta analysis between test runs

## Installation

### Prerequisites
- Python 3.8+
- Ollama (for local LLM inference)
- GraphQL endpoint to test

### Setup
1. Clone the repository:
```bash
git clone https://github.com/SLL288/prediql.git
cd prediql
```

2. Install Python dependencies:
```bash
pip install requests graphql-core pyyaml sentence-transformers faiss-cpu tabulate tqdm
```

3. Install and setup Ollama:
```bash
# Install Ollama (see https://ollama.ai/)
ollama pull llama3  # or your preferred model
```

4. Configure the framework by editing `config.py` if needed.

## Usage

### Basic Usage
Test a GraphQL endpoint with default settings:
```bash
python main.py --url https://api.example.com/graphql --requests 10 --rounds 3
```

### Parameters
- `--url`: GraphQL endpoint URL (required)
- `--requests`: Number of requests per node per round (required)
- `--rounds`: Total number of testing rounds (required)

### Configuration

Key configuration options in `config.py`:
- Output directories
- LLM model selection  
- File paths for schema processing
- Analysis parameters
