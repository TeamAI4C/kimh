# FindVuln – Automated Vulnerability Analysis & Patching Pipeline

**CodeQL (Static Analysis) → LLM (Agent + RAG) → Docker (Dynamic Verification via PoV)**

## Directory Structure

```
findVuln/
├── config/
│   └── settings.yaml              # All pipeline configuration
├── data/
│   ├── cve_corpus/                # JSON CVE entries for RAG ingestion
│   │   ├── CVE-2023-0001-example.json
│   │   └── CVE-2023-0002-example.json
│   └── vectordb/                  # ChromaDB persistence (auto-created)
├── src/
│   ├── rag/
│   │   └── ingest.py              # Corpus ingestion + VulnKnowledgeBase
│   ├── codeql/
│   │   ├── queries/
│   │   │   ├── uaf_dataflow.ql    # Use-After-Free path query
│   │   │   └── bof_dataflow.ql    # Buffer Overflow path query
│   │   └── wrapper.py             # CodeQL CLI wrapper + SARIF parser
│   ├── agent/
│   │   ├── prompts/
│   │   │   ├── system.txt         # System prompt (diff-only output)
│   │   │   ├── analysis_template.txt   # First-attempt template
│   │   │   └── feedback_template.txt   # Retry template with error log
│   │   └── agent.py               # PatchAgent (LangChain + diff extraction)
│   ├── sandbox/
│   │   ├── docker/
│   │   │   ├── Dockerfile         # ASAN-enabled Ubuntu build image
│   │   │   └── entrypoint.sh      # Compile → patch → run script
│   │   └── oracle.py              # SandboxOracle (Docker API driver)
│   └── orchestrator/
│       └── main.py                # Full pipeline + feedback loop
└── pyproject.toml
```

## Prerequisites

| Tool          | Version  | Purpose                                  |
|---------------|----------|------------------------------------------|
| Python        | ≥ 3.10   | Core runtime                             |
| gcc           | ≥ 11     | Compiling test targets with ASAN         |
| Docker        | ≥ 24     | Sandbox containers (Phase 4)             |
| CodeQL CLI    | ≥ 2.15   | Static analysis (Phase 2)                |
| API keys      | —        | `OPENAI_API_KEY` and/or `ANTHROPIC_API_KEY` |

## Setup

```bash
# 1. Install Python dependencies
pip install -e ".[dev]" --break-system-packages

# 2. Set API keys
export OPENAI_API_KEY="sk-..."        # for embeddings (Phase 1)
export ANTHROPIC_API_KEY="sk-ant-..." # for LLM agent (Phase 3)

# 3. Ingest the CVE corpus into ChromaDB
python -m src.phase1_rag.ingest

# 4. Build the Docker sandbox image
cd src/phase4_sandbox/docker && docker build -t findvuln-sandbox:latest . && cd -
```

## Running the Full Pipeline

```bash
python -m src.orchestrator.main \
    path/to/source_root \
    path/to/vulnerable_file.c \
    path/to/codeql_db \
    path/to/pov_input.txt
```

The orchestrator will: run CodeQL → query RAG → generate patch → verify in sandbox → retry on failure (up to 5 times).
