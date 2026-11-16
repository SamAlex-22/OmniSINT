# OmniSINT — Step-by-Step Implementation Tasks (`TASKS.md`)

This file breaks down the entire **OmniSINT** architecture into **10 sequential, self-contained tasks**. You can prompt the agent **one task at a time** (e.g., *"Execute Task 1 from TASKS.md"*), and after each task the agent will write the code, run unit tests, and update the Graphify context graph (`graphify-out/GRAPH_REPORT.md`).

---

## Status Overview

- [x] **Task 0:** Project Initialization, Package Skeleton, `AGENTS.md`, & Graphify AST Indexer (`scripts/update_code_graph.py`)
- [x] **Task 1:** Core Ontology & OSINT Pilot Chain-of-Custody Engine (`omnisint/core/models.py`, `omnisint/core/custody.py`)
- [x] **Task 2:** Async SQLite Case Store & TTL Response Cache (`omnisint/core/storage.py`)
- [x] **Task 3:** Mathematical Disambiguation Part 1 — Shannon Entropy, Handle Rarity & Multi-Modal Similarity (`omnisint/intelligence/entropy.py`, `omnisint/intelligence/similarity.py`, `omnisint/intelligence/temporal.py`)
- [ ] **Task 4:** Mathematical Disambiguation Part 2 — NetworkX Knowledge Graph, Louvain Persona Clustering & Hierarchy Tree (`omnisint/intelligence/graph_engine.py`)
- [ ] **Task 5:** Citation-Locked AI Analyst & Persona Dossier Synthesizer (`omnisint/intelligence/ai_analyst.py`)
- [ ] **Task 6:** Pluggable Collector Framework + Username & GitHub/PGP Collectors (`omnisint/collectors/base.py`, `username_collector.py`, `github_collector.py`)
- [ ] **Task 7:** Infrastructure, Threat Intel & Search Dork Collectors (`domain_ct_collector.py`, `threat_intel.py`, `search_dork_collector.py`)
- [ ] **Task 8:** Async Scan Orchestrator, Cross-Indicator Pivot Engine & STIX 2.1 / Markdown Exporters (`omnisint/core/orchestrator.py`, `omnisint/reporting/`)
- [ ] **Task 9:** FastAPI Backend, WebSocket Live Stream & Cytoscape.js Interactive Web GUI (`omnisint/api/`, `web/index.html`)
- [ ] **Task 10:** Typer CLI & Textual Interactive Terminal Dashboard (`omnisint/cli/main.py`, `omnisint/cli/tui.py`) + End-to-End Integration Suite

---

## Detailed Task Breakdown & Prompts

### Task 1: Core Ontology & OSINT Pilot Chain-of-Custody Engine
* **Goal:** Define strict Pydantic v2 models for cases, entities, observables, weighted relationship edges, and cryptographic evidence records. Build the OSINT Pilot-standard Chain of Custody service that computes SHA-256 hashes of raw OSINT responses and maintains an immutable audit trail.
* **Files to Create:**
  * `omnisint/core/models.py` (`EntityType`, `RelationType`, `EntityNode`, `RelationshipEdge`, `EvidenceItem`, `PersonaCluster`, `HierarchyTreeNode`, `Case`)
  * `omnisint/core/custody.py` (`CustodyLedger` with SHA-256 payload hashing, verification, and audit logging)
  * `tests/test_models_and_custody.py`
* **Prompt to Run:**
  > `"Implement Task 1 from TASKS.md: Core Ontology & OSINT Pilot Chain-of-Custody Engine, run tests, and update Graphify."`

---

### Task 2: Async SQLite Case Store & TTL Response Cache
* **Goal:** Build zero-configuration local persistence so investigations, nodes, edges, and SHA-256 evidence records are saved per Case, and collector HTTP responses are cached with configurable TTL to prevent burning API quotas.
* **Files to Create:**
  * `omnisint/core/storage.py` (`CaseStorage` managing cases, entities, edges, evidence items, and HTTP cache tables)
  * `tests/test_storage.py`
* **Prompt to Run:**
  > `"Implement Task 2 from TASKS.md: Async SQLite Case Store & TTL Response Cache, run tests, and update Graphify."`

---

### Task 3: Mathematical Disambiguation Part 1 — Shannon Entropy, Handle Rarity & Multi-Modal Similarity
* **Goal:** Build the mathematical scoring layer that solves the "same or similar name" problem before calling an LLM:
  1. **Shannon Entropy ($H$)** & handle uniqueness/collision scoring (penalizing common names like `john_smith` vs. rewarding high-entropy handles like `x7_krypton_99`).
  2. **String & Token Similarity:** Jaro-Winkler, normalized Levenshtein, and token-swap handle matching (`john_doe_sec` $\leftrightarrow$ `doejohnsec`).
  3. **Avatar & Temporal Correlation:** Perceptual hash (`dHash`/`pHash`) Hamming distance comparison and timezone/active-hour cosine similarity from commit/post timestamps.
* **Files to Create:**
  * `omnisint/intelligence/entropy.py`
  * `omnisint/intelligence/similarity.py`
  * `omnisint/intelligence/temporal.py`
  * `tests/test_entropy_and_similarity.py`
* **Prompt to Run:**
  > `"Implement Task 3 from TASKS.md: Shannon Entropy, Handle Rarity & Multi-Modal Similarity modules, run tests, and update Graphify."`

---

### Task 4: Mathematical Disambiguation Part 2 — NetworkX Knowledge Graph, Louvain Persona Clustering & Hierarchy Tree
* **Goal:** Build the graph intelligence engine that ingests discovered entities, automatically generates weighted similarity edges using Task 3's math, separates colliding namesakes into distinct **Persona Clusters** via community detection, and outputs a structured **Information Hierarchy Tree** (Root Persona $\rightarrow$ Accounts / Emails / Infrastructure / Organizations / Repositories) ready for UI rendering.
* **Files to Create:**
  * `omnisint/intelligence/graph_engine.py` (`KnowledgeGraphEngine`)
  * `tests/test_graph_engine.py`
* **Prompt to Run:**
  > `"Implement Task 4 from TASKS.md: NetworkX Knowledge Graph, Louvain Persona Clustering & Hierarchy Tree, run tests, and update Graphify."`

---

### Task 5: Citation-Locked AI Analyst & Persona Dossier Synthesizer
* **Goal:** Build the AI Entity Disambiguation Analyst that takes the mathematical Persona Clusters and Hierarchy Trees and produces an executive intelligence brief, Identity Confidence Matrix, and recommended pivot actions—strictly citing `evidence_id` and `node_id` values. Include support for Gemini, OpenAI, local Ollama, and a deterministic offline analytical synthesizer so it always works out-of-the-box.
* **Files to Create:**
  * `omnisint/intelligence/ai_analyst.py` (`AIAnalyst`)
  * `tests/test_ai_analyst.py`
* **Prompt to Run:**
  > `"Implement Task 5 from TASKS.md: Citation-Locked AI Analyst & Persona Dossier Synthesizer, run tests, and update Graphify."`

---

### Task 6: Pluggable Collector Framework + Username & GitHub/PGP Collectors
* **Goal:** Create the abstract `BaseCollector` & `CollectorRegistry` with automatic rate-limiting, caching, and Chain-of-Custody evidence generation. Implement:
  1. `UsernameCollector`: Sherlock-style multi-platform handle enumeration & bio/avatar extraction.
  2. `GitHubCollector`: Extracts profile metadata, repositories, commit author emails, and SSH/PGP keys (`github.com/<user>.keys`).
* **Files to Create:**
  * `omnisint/collectors/base.py`
  * `omnisint/collectors/username_collector.py`
  * `omnisint/collectors/github_collector.py`
  * `tests/test_identity_collectors.py`
* **Prompt to Run:**
  > `"Implement Task 6 from TASKS.md: Collector Framework, UsernameCollector, and GitHubCollector, run tests, and update Graphify."`

---

### Task 7: Infrastructure, Threat Intel & Search Dork Collectors
* **Goal:** Expand OmniSINT's coverage to SpiderFoot / VirusTotal / Google Dorking domains:
  1. `DomainCTCollector`: Certificate Transparency (`crt.sh`), RDAP/WHOIS, and passive DNS resolution.
  2. `ThreatIntelCollector`: VirusTotal domain/IP passive DNS & reputation indicators.
  3. `SearchDorkCollector`: Pluggable dork generator & Internet Archive Wayback Machine (`archive.org` CDX) + search API query engine.
* **Files to Create:**
  * `omnisint/collectors/domain_ct_collector.py`
  * `omnisint/collectors/threat_intel.py`
  * `omnisint/collectors/search_dork_collector.py`
  * `tests/test_infra_collectors.py`
* **Prompt to Run:**
  > `"Implement Task 7 from TASKS.md: DomainCTCollector, ThreatIntelCollector, and SearchDorkCollector, run tests, and update Graphify."`

---

### Task 8: Async Scan Orchestrator, Cross-Indicator Pivot Engine & STIX 2.1 / Markdown Exporters
* **Goal:** Connect collectors, storage, custody ledger, graph disambiguation, and AI analysis into a single `ScanOrchestrator` that supports **multi-hop pivoting** (clicking any node to expand the investigation) and exports findings into:
  1. **STIX 2.1 Bundles** (`omnisint/reporting/stix_exporter.py`)
  2. **Evidentiary Markdown Dossiers** (`omnisint/reporting/markdown_exporter.py`) with ASCII/Mermaid hierarchy trees and SHA-256 Chain of Custody tables.
* **Files to Create:**
  * `omnisint/core/orchestrator.py`
  * `omnisint/reporting/markdown_exporter.py`
  * `omnisint/reporting/stix_exporter.py`
  * `tests/test_orchestrator_and_reporting.py`
* **Prompt to Run:**
  > `"Implement Task 8 from TASKS.md: Scan Orchestrator, Pivot Engine, and STIX 2.1 / Markdown Exporters, run tests, and update Graphify."`

---

### Task 9: FastAPI Backend, WebSocket Live Stream & Cytoscape.js Interactive Web GUI
* **Goal:** Build the REST + WebSocket API (`omnisint/api/app.py`) and the interactive single-page **Web GUI** (`web/index.html`) featuring:
  * Interactive **Cytoscape.js** Knowledge Graph & **Hierarchy Tree** layout toggle
  * Persona Disambiguation Filter (view each separated namesake persona side-by-side)
  * Entropy & Confidence Score Inspector
  * One-click Node Pivot button & Chain-of-Custody Evidence Drawer
* **Files to Create:**
  * `omnisint/api/app.py`
  * `omnisint/api/routes/cases.py`
  * `web/index.html`
  * `tests/test_api.py`
* **Prompt to Run:**
  > `"Implement Task 9 from TASKS.md: FastAPI Backend and Cytoscape.js Web GUI, run tests, and update Graphify."`

---

### Task 10: Typer CLI & Textual Interactive Terminal Dashboard
* **Goal:** Build the complete terminal experience (`omnisint scan`, `omnisint case`, `omnisint pivot`, `omnisint report`, `omnisint serve`, and `omnisint tui`) using **Typer**, **Rich**, and **Textual**, plus a realistic end-to-end demo scenario showing OmniSINT separating multiple colliding targets with similar names into clean hierarchy trees.
* **Files to Create:**
  * `omnisint/cli/main.py`
  * `omnisint/cli/tui.py`
  * `tests/test_cli_e2e.py`
* **Prompt to Run:**
  > `"Implement Task 10 from TASKS.md: Typer CLI, Textual TUI, and End-to-End Verification, run tests, and update Graphify."`
