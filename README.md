# VulnExplain

VulnExplain is a repository-level multilingual vulnerability analysis and code intelligence system.
It pairs a fine-tuned GraphCodeBERT detector with AST-grounded vulnerability flows,
LLM-driven block-by-block explanations, diff-based automated remediation, and repository RAG.

### Documentation Index
- Quickstart & Execution: [docs/RUN.md](docs/RUN.md)
- Dataset Acquisition & Schemas: [docs/DATASETS.md](docs/DATASETS.md)
- Model Fine-Tuning Guide: [docs/TRAINING.md](docs/TRAINING.md)
- System Architecture & Pipeline: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Experimental Evaluation & Metrics: [docs/RESULTS.md](docs/RESULTS.md)

Supported Languages: C, C++, C#, Go, Java, JavaScript, Python.
Backend: FastAPI + Tree-Sitter + FAISS. Frontend: React + Vite.
