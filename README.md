# PrediQL: Automated Testing of GraphQL APIs with LLMs

[![arXiv](https://img.shields.io/badge/arXiv-2510.10407-b31b1b.svg)](https://arxiv.org/abs/2510.10407)

**PrediQL** is the first retrieval-augmented, LLM-guided fuzzer for GraphQL APIs. It combines large language model reasoning with adaptive feedback loops to generate semantically valid and diverse queries for comprehensive security testing. PrediQL addresses the limitations of conventional GraphQL testing tools by leveraging intelligent query generation, coverage analysis, and context-aware vulnerability detection.

## Overview

GraphQL's flexible query model and nested data dependencies expose APIs to complex, context-dependent vulnerabilities that are difficult to uncover using conventional testing tools. Existing fuzzers either rely on random payload generation or rigid mutation heuristics, failing to adapt to the dynamic structures of GraphQL schemas and responses.

PrediQL transforms API security testing from reactive enumeration to intelligent exploration by:

- **Retrieval-Augmented Generation (RAG)**: Retrieves and reuses execution traces, schema fragments, and prior errors to enable self-correction and progressive learning
- **Adaptive Fuzzing Strategy**: Models the choice of fuzzing strategy as a multi-armed bandit problem, balancing exploration of new query structures with exploitation of past successes
- **Context-Aware Vulnerability Detection**: Uses LLM reasoning to analyze responses, interpreting data values, error messages, and status codes to identify security issues
- **Progressive Learning**: Enables self-correction and learning across test iterations

## Key Features

### Core Capabilities

- **Automated GraphQL Schema Introspection**: Automatically fetches and analyzes GraphQL schemas from any endpoint
- **LLM-Powered Query Generation**: Uses local LLMs (via Ollama) to generate diverse and semantically valid test queries
- **Retrieval-Augmented Testing (RAG)**: Incorporates real data examples into query generation through embedding-based retrieval
- **Multi-Armed Bandit Strategy**: Intelligently balances exploration of new query structures with exploitation of successful patterns
- **Adaptive Feedback Loops**: Learns from execution traces and progressively improves query generation

### Security Testing

- **Comprehensive Vulnerability Detection**: Identifies injection flaws, access-control bypasses, information disclosure, and other security issues
- **Context-Aware Analysis**: Uses LLM reasoning to interpret responses, error messages, and status codes
- **Dual Detection System**: Combines rule-based and LLM-based vulnerability detectors for comprehensive coverage
- **Deep Traversal Testing**: Explores nested data dependencies and complex query structures

### Coverage & Analysis

- **Field and Operation Coverage**: Tracks comprehensive coverage metrics to ensure thorough testing
- **Multi-Round Testing**: Supports iterative testing rounds with progressive learning
- **Delta Coverage Analysis**: Compares coverage between test runs to identify gaps
- **Comprehensive Reporting**: Generates detailed coverage reports, vulnerability summaries, and success/failure analysis

## Architecture

The framework consists of several key components organized into logical modules:

### Core Components

- **`main.py`**: Main entry point and orchestration logic, coordinates the testing workflow
- **`retrieve_and_prompt.py`**: LLM integration and prompt management, handles query generation
- **`GraphQLPromptBuilder.py`**: Structured prompt generation for GraphQL operations
- **`sendpayload.py`**: HTTP request handling and GraphQL query execution
- **`analysis_prediql.py`**: Coverage analysis and reporting

### Schema Processing

- **`load_introspection/`**: GraphQL schema introspection and processing
  - `save_instrospection.py`: Fetches schema from endpoints via introspection queries
  - `load_introspection.py`: Processes and structures schema data
  - `get_query_lists.py`: Extracts query/mutation operations and parameters
  - `load_snippet.py`: Loads schema snippets for context

### Data Management & Retrieval

- **`embed_retrieve/`**: Vector embedding and retrieval system for RAG
  - `embed_and_index.py`: Creates embeddings from response data and builds FAISS index
  - `retrieve_from_index.py`: Retrieves similar examples for context-aware query generation
- **`save_real_data.py`**: Processes and stores real API response data
- **`save_query_info.py`**: Manages query metadata and execution information

### Vulnerability Detection

- **`simple_vulnerability_detector.py`**: Rule-based vulnerability detection
- **`simple_llm_detector.py`**: LLM-based vulnerability detection
- **`dual_vulnerability_detector.py`**: Combines both detection methods for comprehensive analysis

### Analysis & Reporting

- **`target_endpoints.py`**: Endpoint targeting and comparison utilities
- **`parse_endpoint_results.py`**: Result parsing and data extraction
- **`delta_coverage.py`**: Coverage delta analysis between test runs
- **`negative_coverage.py`**: Analysis of negative test cases

### Utilities

- **`check_results_status.py`**: Checks which result directories are empty and need backfilling
- **`config.py`**: Centralized configuration management

## Installation

### Prerequisites

- **Python 3.8+**
- **Ollama** (for local LLM inference) - [Installation Guide](https://ollama.ai/)
- **GraphQL endpoint** to test

### Setup

1. **Clone the repository:**
```bash
git clone https://github.com/SLL288/prediql.git
cd prediql
```

2. **Install Python dependencies:**
```bash
pip install requests graphql-core pyyaml sentence-transformers faiss-cpu tabulate tqdm
```

3. **Install and setup Ollama:**
```bash
# Install Ollama (see https://ollama.ai/)
ollama pull llama3  # or your preferred model (llama3.1, deepseek-r1, gemini, etc.)
```

4. **Configure the framework** by editing `config.py` if needed:
   - Output directories
   - LLM model selection
   - File paths for schema processing
   - Analysis parameters

## Usage

### Basic Usage

Test a GraphQL endpoint with default settings:

```bash
python main.py --url https://api.example.com/graphql --requests 10 --rounds 3
```

### Command-Line Parameters

- **`--url`**: GraphQL endpoint URL (required)
- **`--requests`**: Number of requests per node per round (required)
- **`--rounds`**: Total number of testing rounds (required)

### Example Workflow

```bash
# Test a GraphQL API with 15 requests per node over 5 rounds
python main.py --url https://countries.trevorblades.com/graphql --requests 15 --rounds 5
```
## Configuration

Key configuration options in `config.py`:

- **Output directories**: Customize where results are stored
- **LLM model selection**: Configure which model to use
- **File paths**: Adjust paths for schema processing
- **Analysis parameters**: Tune coverage and analysis settings
- **Embedding model**: Configure the embedding model for RAG (default: `all-MiniLM-L6-v2`)

## Evaluation Results

Our evaluation across open-source and benchmark GraphQL APIs shows that PrediQL achieves significantly higher coverage and vulnerability discovery rates compared to state-of-the-art baselines. These results demonstrate that combining retrieval-augmented reasoning with adaptive fuzzing can transform API security testing.

## Citation

If you use PrediQL in your research, please cite our paper:

```bibtex
@article{liu2025prediql,
  title={PrediQL: Automated Testing of GraphQL APIs with LLMs},
  author={Liu, Shaolun and Marefat, Sina and Tsai, Omar and Chen, Yu and Deng, Zecheng and Wang, Jia and Tayebi, Mohammad A.},
  journal={arXiv preprint arXiv:2510.10407},
  year={2025},
  url={https://arxiv.org/abs/2510.10407}
}
```

**Paper**: [PrediQL: Automated Testing of GraphQL APIs with LLMs](https://arxiv.org/abs/2510.10407)  
**arXiv**: [2510.10407](https://arxiv.org/abs/2510.10407)

### Citation in Different Formats

**APA Style:**
```
Liu, S., Marefat, S., Tsai, O., Chen, Y., Deng, Z., Wang, J., & Tayebi, M. A. (2025). 
PrediQL: Automated Testing of GraphQL APIs with LLMs. arXiv preprint arXiv:2510.10407.
```

**IEEE Style:**
```
S. Liu et al., "PrediQL: Automated Testing of GraphQL APIs with LLMs," 
arXiv preprint arXiv:2510.10407, 2025.
```

**MLA Style:**
```
Liu, Shaolun, et al. "PrediQL: Automated Testing of GraphQL APIs with LLMs." 
arXiv preprint arXiv:2510.10407 (2025).
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

Please refer to the LICENSE file for details.

## Authors

- Shaolun Liu
- Sina Marefat
- Omar Tsai
- Yu Chen
- Zecheng Deng
- Jia Wang
- Mohammad A. Tayebi

## Acknowledgments

We gratefully acknowledge support from the research community and all contributors to this project.

## Related Work

PrediQL builds upon research in:
- GraphQL API security testing
- LLM-guided fuzzing
- Retrieval-augmented generation (RAG)
- Multi-armed bandit optimization
- Context-aware vulnerability detection

## Support

For questions, issues, or contributions, please open an issue on the GitHub repository.

---

**Note**: This tool is designed for security testing of GraphQL APIs. Always ensure you have proper authorization before testing any API endpoint.
