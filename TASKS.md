# OmniSINT — Master Architectural Blueprint & Step-by-Step Implementation Guide (`TASKS.md`)

Welcome to the **OmniSINT Master Task Guide**.

If you are new to this repository—whether you are a developer, a cybersecurity student, or an experienced OSINT investigator—this document explains **from first principles**:
1. **What OmniSINT is and the big picture of how all 10 tasks connect together**,
2. **Why every single task is needed** (with real-world cybersecurity examples),
3. **What exact classes, functions, schemas, and tests belong in each task**, and
4. **How to execute or verify each task step-by-step.**

---

## 1. The Big Picture: How All 10 Tasks Fit Together

Think of **OmniSINT** as building a complete, automated **Digital Detective & Forensic Lab** in 5 logical layers:

| Layer | Tasks | Plain-English Role in the Investigation |
| :--- | :--- | :--- |
| **Layer 1: The Forensic Vault & Filing Cabinet** | **Task 0, Task 1, Task 2** | Defines the vocabulary of an investigation (`EntityNode`, `RelationshipEdge`, `Case`), locks every raw piece of evidence with a tamper-proof **SHA-256 Chain of Custody**, and saves everything into a fast local **SQLite database** with a **TTL response cache** so we never waste API quotas. |
| **Layer 2: The Mathematical Brain (Solving "Same Name, Different Person")** | **Task 3, Task 4** | Before calling any AI, uses **Information Theory (Shannon Entropy)**, **Handle Rarity**, **Token-Swap Similarity**, **Perceptual Avatar Hashing (`dHash`)**, **Circadian Timezone Fingerprinting**, and **Conflict-Aware Louvain Graph Clustering** to separate unrelated people who share the same name into distinct **Persona Clusters** and build each persona's **Information Hierarchy Tree**. |
| **Layer 3: The Citation-Locked AI Analyst** | **Task 5** | Takes the mathematically resolved Persona Clusters and Hierarchy Trees and generates an **Executive Intelligence Brief** and **Identity Confidence Matrix** where *every single claim* must cite a verified `[node:<id>]` and `[evidence:<id>]`—with a built-in 100% offline synthesizer plus Gemini, OpenAI, and Ollama support. |
| **Layer 4: The Field Collectors, Pivot Engine & Dossier Exporters** | **Task 6, Task 7, Task 8** | Connects passive OSINT collectors (**Username enumeration**, **GitHub commits/PGP/SSH keys**, **Certificate Transparency `crt.sh` & Passive DNS**, **VirusTotal Threat Intel**, and **Search Engine / Wayback Dorking**) into an async **Multi-Hop Pivot Orchestrator**, and exports investigations to **Markdown Dossiers** and **STIX 2.1 Threat Intelligence Bundles**. |
| **Layer 5: The Analyst Interfaces (Web GUI, CLI & Terminal Dashboard)** | **Task 9, Task 10** | Provides dual interfaces for human analysts: a **FastAPI + WebSocket + Cytoscape.js Interactive Web GUI** (for visual graph exploration and one-click node pivoting) and a **Typer CLI + Textual TUI Terminal Dashboard**. |

---

## 2. Implementation Status Overview

- [x] **Task 0:** Project Initialization, Configuration, `AGENTS.md`, & Graphify AST Indexer (`scripts/update_code_graph.py`)
- [x] **Task 1:** Core Ontology & OSINT Pilot Chain-of-Custody Engine (`omnisint/core/models.py`, `omnisint/core/custody.py`)
- [x] **Task 2:** Async SQLite Case Store & TTL Response Cache (`omnisint/core/storage.py`)
- [x] **Task 3:** Mathematical Disambiguation Part 1 — Shannon Entropy, Handle Rarity & Multi-Modal Similarity (`omnisint/intelligence/entropy.py`, `omnisint/intelligence/similarity.py`, `omnisint/intelligence/temporal.py`)
- [x] **Task 4:** Mathematical Disambiguation Part 2 — NetworkX Knowledge Graph, Louvain Persona Clustering & Hierarchy Tree (`omnisint/intelligence/graph_engine.py`)
- [x] **Task 5:** Citation-Locked AI Analyst & Persona Dossier Synthesizer (`omnisint/intelligence/ai_analyst.py`)
- [x] **Task 6:** Pluggable Collector Framework + Username & GitHub/PGP Collectors (`omnisint/collectors/base.py`, `username_collector.py`, `github_collector.py`)
- [x] **Task 7:** Infrastructure, Threat Intel & Search Dork Collectors (`domain_ct_collector.py`, `threat_intel.py`, `search_dork_collector.py`)
- [x] **Task 8:** Async Scan Orchestrator, Cross-Indicator Pivot Engine & STIX 2.1 / Markdown Exporters (`omnisint/core/orchestrator.py`, `omnisint/reporting/`)
- [x] **Task 9:** FastAPI Backend, WebSocket Live Stream & Cytoscape.js Interactive Web GUI (`omnisint/api/`, `web/index.html`)
- [x] **Task 10:** Typer CLI & Textual Interactive Terminal Dashboard (`omnisint/cli/main.py`, `omnisint/cli/tui.py`) + End-to-End Integration Suite

---

## 3. Detailed Task-by-Task Specifications & Examples

---

### Task 0: Project Initialization, Package Skeleton, `AGENTS.md`, & Graphify AST Indexer
- **Status:** `[x] Completed`
- **Why This Task Exists:**
  Every enterprise Python platform needs a clean package structure, environment-variable configuration (`omnisint/config.py`), and an automated way to map all modules, classes, and functions (`scripts/update_code_graph.py`) so contributors and AI agents can understand the codebase architecture at a glance without reading thousands of lines of raw code.
- **Files Created:**
  - [AGENTS.md](file:///Users/alex/OmniSINT/AGENTS.md) — Engineering standards, module boundaries, and Graphify workflow.
  - [pyproject.toml](file:///Users/alex/OmniSINT/pyproject.toml) — Package metadata, dependencies, pytest, and ruff configuration.
  - [omnisint/config.py](file:///Users/alex/OmniSINT/omnisint/config.py) — `OmniSINTSettings` Pydantic v2 configuration loader.
  - [scripts/update_code_graph.py](file:///Users/alex/OmniSINT/scripts/update_code_graph.py) — Deterministic AST codebase parser that generates `graphify-out/GRAPH_REPORT.md` and `graphify-out/graph.json`.

---

### Task 1: Core Ontology & OSINT Pilot Chain-of-Custody Engine
- **Status:** `[x] Completed`
- **Why This Task Exists (With Example):**
  1. **Unified Graph Vocabulary:** Suppose you find a GitHub profile `alex_sec`, an email `alex@sec.io`, and a domain `alexsec.io`. Without a strict schema, every collector returns a different dictionary format. `models.py` standardizes everything into `EntityNode` vertices (17 `EntityType` values) and `RelationshipEdge` links (19 `RelationType` values), with a deterministic `canonical_key` (`<entity_type>:<platform>:<lowercase_value>`) so `"GitHub:Alex_Sec"` and `"github:alex_sec"` automatically deduplicate.
  2. **Tamper-Evident Chain of Custody:** In real cyber investigations, you must prove that raw API responses were not altered after collection. `CustodyLedger` (`custody.py`) canonicalizes every raw payload (`sort_keys=True`), computes its 64-character **SHA-256 hash**, and chains each `EvidenceItem` to the previous item's `chain_hash` (starting from `GENESIS_CHAIN_HASH = "0" * 64`). If anyone modifies a single byte of stored evidence later, `verify_chain()` catches the exact tampered item immediately.
- **Files Created:**
  - [omnisint/core/models.py](file:///Users/alex/OmniSINT/omnisint/core/models.py) (`EntityType`, `RelationType`, `CaseStatus`, `EvidenceItem`, `AuditLogEntry`, `EntityNode`, `RelationshipEdge`, `HierarchyTreeNode`, `PersonaCluster`, `CollectorResult`, `Case`)
  - [omnisint/core/custody.py](file:///Users/alex/OmniSINT/omnisint/core/custody.py) (`canonicalize_payload`, `compute_sha256`, `compute_chain_hash`, `CustodyLedger`)
  - [tests/test_models_and_custody.py](file:///Users/alex/OmniSINT/tests/test_models_and_custody.py)
- **Prompt Used:**
  > `"Implement Task 1 from TASKS.md: Core Ontology & OSINT Pilot Chain-of-Custody Engine, run tests, and update Graphify."`

---

### Task 2: Async SQLite Case Store & TTL Response Cache
- **Status:** `[x] Completed`
- **Why This Task Exists (With Example):**
  1. **Zero-Config Local Persistence:** Analysts need their cases, graphs, resolved personas, and SHA-256 custody ledgers saved to disk automatically without setting up external database servers. `CaseStorage` uses SQLite in WAL mode to persist 6 normalized tables (`cases`, `entities`, `edges`, `evidence_items`, `audit_log`, `http_cache`).
  2. **Cross-Collector Node Deduplication & ID Remapping:** If Collector A creates `EntityNode(id="temp-1", value="alex@sec.io")` and Collector B creates `EntityNode(id="temp-2", value="ALEX@sec.io")` with an edge pointing to `"temp-2"`, `CaseStorage.merge_collector_result()` merges `"temp-2"` into `"temp-1"` and automatically rewrites the edge to point to `"temp-1"`!
  3. **Quota-Saving HTTP Cache:** External OSINT APIs (like VirusTotal or GitHub) enforce strict rate limits. `CaseStorage` caches collector responses keyed by SHA-256 of `(collector_name, query_or_uri, params)` with configurable TTL expiration (`expires_at_utc`).
- **Files Created:**
  - [omnisint/core/storage.py](file:///Users/alex/OmniSINT/omnisint/core/storage.py) (`make_cache_key`, `CacheEntry`, `CaseStorage`)
  - [tests/test_storage.py](file:///Users/alex/OmniSINT/tests/test_storage.py)
- **Prompt Used:**
  > `"Implement Task 2 from TASKS.md: Async SQLite Case Store & TTL Response Cache, run tests, and update Graphify."`

---

### Task 3: Mathematical Disambiguation Part 1 — Shannon Entropy, Handle Rarity & Multi-Modal Similarity
- **Status:** `[x] Completed`
- **Why This Task Exists (With Example):**
  Traditional OSINT tools assume that if two accounts have a similar name, they belong to the same person—and if two handles look slightly different, they miss them completely. Task 3 builds the mathematical primitives to solve both problems:
  1. **Shannon Entropy & Handle Rarity (`entropy.py`):** Distinguishes common human names (`john_smith` $\rightarrow$ rarity `< 0.35`, high collision risk) from unique handles (`x7_krypton_99` $\rightarrow$ rarity `> 0.70`, low collision risk) using character-level Shannon entropy $H(X)$, unusual English bigram ratios, character-class diversity, and a curated dictionary of 150+ common names/generic words (`COMMON_NAME_TOKENS`).
  2. **Token-Swap, Lexical & Avatar Similarity (`similarity.py`):**
     - Matches reordered and delimiter-free concatenated handles: `token_swap_similarity("john_doe_sec", "doejohnsec") == 1.0`.
     - Normalizes leetspeak (`0→o, 1→i, 3→e, 4→a, 5→s, 7→t`).
     - Computes **64-bit Perceptual Avatar Difference Hashes (`dHash`)** across an $8 \times 9$ brightness grid and compares them via bit-level Hamming distance so identical profile pictures match (`>= 0.90`) even after platform resizing or JPEG recompression.
  3. **Circadian Timezone Fingerprinting (`temporal.py`):** Builds a 24-hour UTC activity histogram from commit/post timestamps, infers the operator's local UTC timezone (`UTC+05:30` vs `UTC-07:00`) from explicit offsets or the 7-hour biological sleep trough, and computes circularly smoothed cosine similarity.
- **Files Created:**
  - [omnisint/intelligence/entropy.py](file:///Users/alex/OmniSINT/omnisint/intelligence/entropy.py)
  - [omnisint/intelligence/similarity.py](file:///Users/alex/OmniSINT/omnisint/intelligence/similarity.py)
  - [omnisint/intelligence/temporal.py](file:///Users/alex/OmniSINT/omnisint/intelligence/temporal.py)
  - [tests/test_entropy_and_similarity.py](file:///Users/alex/OmniSINT/tests/test_entropy_and_similarity.py)
- **Prompt Used:**
  > `"Implement Task 3 from TASKS.md: Shannon Entropy, Handle Rarity & Multi-Modal Similarity modules, run tests, and update Graphify."`

---

### Task 4: Mathematical Disambiguation Part 2 — NetworkX Knowledge Graph, Louvain Persona Clustering & Hierarchy Tree
- **Status:** `[x] Completed`
- **Why This Task Exists (With Example):**
  Suppose an investigation into `alex_dev` discovers 14 entities: some belong to a security researcher in Bengaluru (`UTC+05:30`), and some belong to a cloud engineer in Seattle (`UTC-07:00`).
  `KnowledgeGraphEngine` (`graph_engine.py`) ingests all entities and edges, runs Task 3's pairwise math to synthesize weighted `SIMILAR_HANDLE`, `SAME_AVATAR`, `TEMPORAL_CORRELATION`, and `RESOLVED_SAME_PERSONA` edges, and records **Must-Not-Link Conflict Pairs** between accounts with incompatible timezones (`UTC+05:30` vs `UTC-07:00`), conflicting locations, or uncorroborated common handles (`john_smith`).
  It then executes **Two-Stage Conflict-Aware Louvain Community Detection + Multi-Hop Observable Propagation** to partition the graph into distinct `PersonaCluster`s and builds each persona's recursive 5-category **Information Hierarchy Tree** (`Root Persona` $\rightarrow$ `Accounts` / `Emails` / `Infrastructure` / `Organizations` / `Repositories`).
- **Files Created:**
  - [omnisint/intelligence/graph_engine.py](file:///Users/alex/OmniSINT/omnisint/intelligence/graph_engine.py) (`DisambiguationConfig`, `GraphDisambiguationReport`, `KnowledgeGraphEngine`, `compute_modularity`, `louvain_communities_deterministic`, `render_hierarchy_ascii`)
  - [tests/test_graph_engine.py](file:///Users/alex/OmniSINT/tests/test_graph_engine.py)
- **Prompt Used:**
  > `"Implement Task 4 from TASKS.md: NetworkX Knowledge Graph, Louvain Persona Clustering & Hierarchy Tree, run tests, and update Graphify."`

---

### Task 5: Citation-Locked AI Analyst & Persona Dossier Synthesizer
- **Status:** `[x] Completed`
- **Why This Task Exists (With Example):**
  Investigators need an executive intelligence brief and an **Identity Confidence Matrix** explaining *how confident* we are in each persona and *what to pivot on next*—but standard LLMs often hallucinate facts or invent fake citations.
  `AIAnalyst` (`ai_analyst.py`) solves this by:
  1. Building a structured `IdentityMatrixEntry` table (`HIGH` / `MEDIUM` / `LOW` confidence tiers, corroborating modalities, entropy, inferred timezone, and citations).
  2. Providing a **100% offline deterministic dossier synthesizer (`provider="deterministic"`)** so OmniSINT always produces rich Markdown intelligence briefs without needing any API key, while also supporting **Google Gemini (`gemini`)**, **OpenAI (`openai`)**, and local **Ollama (`ollama`)** with automatic offline fallback.
  3. Enforcing a **Citation Verification Guardrail (`audit_citations` & `sanitize_hallucinated_citations`)** that checks every `[node:<id>]` and `[evidence:<id>]` tag against the Case's actual database records and redacts any hallucinated IDs (`[REDACTED-UNVERIFIED-NODE:<id>]`).
- **Files Created:**
  - [omnisint/intelligence/ai_analyst.py](file:///Users/alex/OmniSINT/omnisint/intelligence/ai_analyst.py) (`IdentityMatrixEntry`, `CitationAuditResult`, `AIAnalysisReport`, `AIAnalyst`, `audit_citations`, `sanitize_hallucinated_citations`)
  - [tests/test_ai_analyst.py](file:///Users/alex/OmniSINT/tests/test_ai_analyst.py)
- **Prompt Used:**
  > `"Implement Task 5 from TASKS.md: Citation-Locked AI Analyst & Persona Dossier Synthesizer, run tests, and update Graphify."`

---

### Task 6: Pluggable Collector Framework + Username & GitHub/PGP Collectors
- **Status:** `[x] Completed`
- **Why This Task Exists (Plain-English Problem & Solution):**
  Now that our storage, cryptography, math, graph clustering, and AI analyst are ready, we need **passive OSINT collectors** to gather real-world identity data!
  - **Why `BaseCollector` & `CollectorRegistry` (`omnisint/collectors/base.py`):**
    Suppose you have 5 different collector plugins. Without a shared base class, every collector would have to re-implement:
    1. Checking the SQLite TTL cache before making a network request,
    2. Rate-limiting and exponential backoff (`429 Too Many Requests`),
    3. Computing the SHA-256 hash of the raw HTTP response and creating an `EvidenceItem`, and
    4. Handling network timeouts gracefully without crashing the whole scan.
    `BaseCollector` handles all of this automatically via `fetch_with_custody()`, while `CollectorRegistry` lets the orchestrator discover which collectors can handle a `USERNAME`, `EMAIL`, `DOMAIN`, or `IP_ADDRESS`.
  - **Why `UsernameCollector` (`username_collector.py`):**
    Given a handle like `krypton_sec_x7`, checks developer and social platforms (GitHub, GitLab, Reddit, Keybase, HackerNews, Dev.to), extracts display names, bios, locations, activity timestamps, and avatar perceptual hashes (`dHash`), and emits `SOCIAL_PROFILE` and `AVATAR_HASH` nodes.
  - **Why `GitHubCollector` (`github_collector.py`):**
    GitHub is one of the highest-value passive OSINT sources for developer and threat-actor attribution. Even when a user hides their email on their profile page:
    1. Their public events (`api.github.com/users/<user>/events/public`) and commit headers often expose their real commit author email (`alex.sec@proton.me`) and local timezone offset (`+05:30`),
    2. Their public SSH key endpoint (`github.com/<user>.keys`) and GPG key endpoint (`api.github.com/users/<user>/gpg_keys`) expose cryptographic key fingerprints (`SSH_KEY`, `PGP_KEY`) that uniquely identify the same person across GitLab, Keybase, or personal servers!
- **Concrete Example (Input $\rightarrow$ Output):**
  ```text
  Input Query:  username = "krypton_sec_x7"
  Collectors:   UsernameCollector + GitHubCollector
  Output Nodes:
    • [SOCIAL_PROFILE] GitHub:krypton_sec_x7 (location="Bengaluru, India", avatar_hash="8f3c3c1e1e0f0f00")
    • [SOCIAL_PROFILE] Reddit:krypton_sec_x7 (timestamps=["2026-05-04T15:10:00+05:30", ...])
    • [EMAIL]          krypton@proton.me     (extracted from GitHub PushEvent commit payload)
    • [SSH_KEY]        ssh-ed25519 AAAAC3Nza... (extracted from github.com/krypton_sec_x7.keys)
    • [REPOSITORY]     github.com/krypton_sec_x7/omnisint
  Output Custody:
    • 4+ EvidenceItem records with SHA-256 digests of the raw JSON/key responses
  ```
- **Files Created:**
  - [omnisint/collectors/base.py](file:///Users/alex/OmniSINT/omnisint/collectors/base.py) (`BaseCollector`, `CollectorConfig`, `CollectorRegistry`, `HttpResponseData`)
  - [omnisint/collectors/username_collector.py](file:///Users/alex/OmniSINT/omnisint/collectors/username_collector.py) (`UsernameCollector`, `PlatformSpec`)
  - [omnisint/collectors/github_collector.py](file:///Users/alex/OmniSINT/omnisint/collectors/github_collector.py) (`GitHubCollector`)
  - [tests/test_identity_collectors.py](file:///Users/alex/OmniSINT/tests/test_identity_collectors.py) (offline deterministic tests using mocked HTTP responses)
- **Prompt Used:**
  > `"Implement Task 6 from TASKS.md: Collector Framework, UsernameCollector, and GitHubCollector, run tests, and update Graphify."`

---

### Task 7: Infrastructure, Threat Intel & Search Dork Collectors
- **Status:** `[x] Completed`
- **Why This Task Exists (Plain-English Problem & Solution):**
  An investigation doesn't stop at social profiles—once you discover a target's personal domain (e.g., `alexsec.io`) or email domain, you need to map their **technical infrastructure, historical web footprint, and security reputation**:
  1. **`DomainCTCollector` (`domain_ct_collector.py`):**
     - **Why Certificate Transparency (`crt.sh`)?** Whenever anyone creates an SSL/TLS certificate (e.g., via Let's Encrypt or Cloudflare) for a hidden subdomain like `staging-vpn.alexsec.io`, Certificate Authorities are legally required to publish that certificate to public Certificate Transparency logs. By querying `crt.sh/?q=alexsec.io&output=json`, `DomainCTCollector` passively discovers subdomains without sending a single packet to the target's server!
     - Also queries **RDAP / WHOIS** registration records and passive DNS (`dns.google/resolve`) to emit `DOMAIN`, `SUBDOMAIN`, `CERTIFICATE`, `IP_ADDRESS`, `EMAIL`, and `ORGANIZATION` nodes.
  2. **`ThreatIntelCollector` (`threat_intel.py`):**
     - Queries **VirusTotal v3** (and deterministic passive posture fallback when no API key is configured) to inspect whether a discovered domain or IP address is associated with known malware, phishing, command-and-control (C2), or passive DNS resolutions, emitting `THREAT_INDICATOR` nodes (`FLAGGED_BY`) and `IP_ADDRESS` nodes (`RESOLVES_TO`).
  3. **`SearchDorkCollector` (`search_dork_collector.py`):**
     - Generates targeted OSINT search dorks (`generate_dork_queries()`) and queries the **Internet Archive Wayback Machine CDX API (`web.archive.org/cdx/search/cdx`)** + optional Google Custom Search Engine (CSE) to uncover historical URLs (`URL`, `MENTIONED_AT`) even after pages have been deleted from the live internet.
- **Concrete Example (Input $\rightarrow$ Output):**
  ```text
  Input Query:  domain = "alexsec.io"
  Collectors:   DomainCTCollector + ThreatIntelCollector + SearchDorkCollector
  Output Graph:
    [DOMAIN] alexsec.io
       ├── HAS_SUBDOMAIN ──> [SUBDOMAIN] api.alexsec.io ──> RESOLVES_TO ──> [IP_ADDRESS] 198.51.100.42
       ├── ISSUED_CERT   ──> [CERTIFICATE] CN=*.alexsec.io (Issuer: Let's Encrypt)
       ├── MENTIONED_AT  ──> [URL] https://web.archive.org/web/20250101/https://alexsec.io/about
       └── FLAGGED_BY    ──> [THREAT_INDICATOR] VT Reputation: Clean (0/90 detections)
  ```
- **Files Created:**
  - [omnisint/collectors/domain_ct_collector.py](file:///Users/alex/OmniSINT/omnisint/collectors/domain_ct_collector.py) (`DomainCTCollector`)
  - [omnisint/collectors/threat_intel.py](file:///Users/alex/OmniSINT/omnisint/collectors/threat_intel.py) (`ThreatIntelCollector`)
  - [omnisint/collectors/search_dork_collector.py](file:///Users/alex/OmniSINT/omnisint/collectors/search_dork_collector.py) (`SearchDorkCollector`, `generate_dork_queries`)
  - [tests/test_infra_collectors.py](file:///Users/alex/OmniSINT/tests/test_infra_collectors.py)
- **Prompt Used:**
  > `"Implement Task 7 from TASKS.md: DomainCTCollector, ThreatIntelCollector, and SearchDorkCollector, run tests, and update Graphify."`

---

### Task 8: Async Scan Orchestrator, Cross-Indicator Pivot Engine & STIX 2.1 / Markdown Exporters
- **Status:** `[x] Completed`
- **Why This Task Exists (Plain-English Problem & Solution):**
  1. **Automated Multi-Hop Pivoting (`ScanOrchestrator` in `omnisint/core/orchestrator.py`):**
     In real OSINT work, one clue leads to another:
     - **Hop 1:** You scan username `krypton_sec_x7`. `GitHubCollector` discovers email `krypton@alexsec.io` and personal website `alexsec.io`.
     - **Hop 2 (Automatic or Analyst-Triggered Pivot):** `ScanOrchestrator` inspects newly discovered nodes, extracts the domain `alexsec.io` from `krypton@alexsec.io`, and automatically runs `DomainCTCollector`, `ThreatIntelCollector`, and `SearchDorkCollector` on `alexsec.io`!
     - **Final Resolution:** Once all hops finish, `ScanOrchestrator` merges all results into `CaseStorage`, verifies the SHA-256 custody chain, runs `KnowledgeGraphEngine` to separate any colliding namesakes into `PersonaCluster`s, and invokes `AIAnalyst` to generate the citation-locked executive brief.
  2. **Industry-Standard Reporting Exporters (`omnisint/reporting/`):**
     - **`MarkdownExporter` (`markdown_exporter.py`):** Generates a complete investigative Markdown dossier containing the Case overview, optional Ed25519 signature, AI Executive Brief, Mermaid + ASCII Hierarchy Trees, and the complete **SHA-256 Chain of Custody Audit Table**.
     - **`STIXExporter` (`stix_exporter.py`):** Exports the entire resolved intelligence graph into an OASIS **STIX 2.1 JSON Bundle** (`type: "bundle"`, `identity`, `user-account`, `email-addr`, `domain-name`, `ipv4-addr`, `relationship`, `note`) so SOC teams can import OmniSINT findings directly into **OpenCTI, MISP, Splunk, or Microsoft Sentinel**.
- **Concrete Example (Sample STIX 2.1 Bundle Snippet):**
  ```json
  {
    "type": "bundle",
    "id": "bundle--771c6f74-3b14-4b26-abeb-551bcb142766",
    "objects": [
      {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--a1b2c3d4-...",
        "name": "Persona #1: krypton_sec_x7 (UTC+05:30, Bengaluru, India)",
        "identity_class": "individual",
        "confidence": 93
      }
    ]
  }
  ```
- **Files Created:**
  - [omnisint/core/orchestrator.py](file:///Users/alex/OmniSINT/omnisint/core/orchestrator.py) (`ScanOrchestrator`, `PivotRequest`, `ScanProgressEvent`, `infer_entity_type`)
  - [omnisint/reporting/markdown_exporter.py](file:///Users/alex/OmniSINT/omnisint/reporting/markdown_exporter.py) (`MarkdownExporter`)
  - [omnisint/reporting/stix_exporter.py](file:///Users/alex/OmniSINT/omnisint/reporting/stix_exporter.py) (`STIXExporter`)
  - [tests/test_orchestrator_and_reporting.py](file:///Users/alex/OmniSINT/tests/test_orchestrator_and_reporting.py)
- **Prompt Used:**
  > `"Implement Task 8 from TASKS.md: Scan Orchestrator, Pivot Engine, and STIX 2.1 / Markdown Exporters, run tests, and update Graphify."`

---

### Task 9: FastAPI Backend, WebSocket Live Stream & Cytoscape.js Interactive Web GUI
- **Status:** `[x] Completed`
- **Why This Task Exists (Plain-English Problem & Solution):**
  Visualizing a 50-node OSINT graph and comparing separated namesake personas side-by-side is fastest in an interactive visual dashboard.
  1. **FastAPI + WSGI REST & WebSocket Server (`omnisint/api/app.py`, `omnisint/api/routes/cases.py`):**
     - `POST /api/cases` & `GET /api/cases`: Create and list investigations.
     - `POST /api/cases/{case_id}/scan`: Trigger a multi-collector OSINT scan with real-time progress over `/ws/cases/{case_id}`.
     - `POST /api/cases/{case_id}/pivot`: Click any node in the UI to pivot and expand the graph from that entity.
     - `GET /api/cases/{case_id}/graph`: Return Cytoscape.js elements (`nodes`, `edges`, and compound `persona_cluster` boxes) + `HierarchyTreeNode` structures.
     - `GET /api/cases/{case_id}/custody`: Run live SHA-256 Chain-of-Custody verification and return the audit ledger.
     - `GET /api/cases/{case_id}/export/{format}`: Download Markdown dossier or STIX 2.1 JSON bundle.
  2. **Interactive Cytoscape.js Web GUI (`web/index.html`):**
     - **Knowledge Graph & Hierarchy Tree Layout Toggle:** Switch between force-directed network layout and top-down Information Hierarchy Tree layout with one click.
     - **Persona Disambiguation Filter Bar:** Isolate `Persona #1 (UTC+05:30)` vs `Persona #2 (UTC-07:00)` side-by-side.
     - **Entropy & Confidence Inspector + One-Click Pivot Drawer.**
     - **Cryptographic Chain-of-Custody Verification Badge & Evidence Viewer.**
- **Files Created:**
  - [omnisint/api/app.py](file:///Users/alex/OmniSINT/omnisint/api/app.py) (`create_app`, `get_default_app`)
  - [omnisint/api/routes/cases.py](file:///Users/alex/OmniSINT/omnisint/api/routes/cases.py) (`OmniSINTAPIService`, `ProgressBroadcaster`, `build_fastapi_router`)
  - [web/index.html](file:///Users/alex/OmniSINT/web/index.html)
  - [tests/test_api.py](file:///Users/alex/OmniSINT/tests/test_api.py)
- **Prompt Used:**
  > `"Implement Task 9 from TASKS.md: FastAPI Backend and Cytoscape.js Web GUI, run tests, and update Graphify."`

---

### Task 10: Typer CLI & Textual Interactive Terminal Dashboard + End-to-End Verification
- **Status:** `[x] Completed`
- **Why This Task Exists (Plain-English Problem & Solution):**
  Cybersecurity specialists and incident responders frequently work in terminal sessions over SSH where a browser isn't available. Task 10 provides a complete command-line interface (CLI) and an interactive terminal dashboard (TUI):
  1. **Click / Typer-Compatible CLI (`omnisint/cli/main.py`):**
     ```bash
     # Run the built-in offline colliding-namesake disambiguation demo
     omnisint demo --db demo.db --output-md dossier.md --output-stix bundle.stix.json

     # Run an investigation scan and display resolved Persona Hierarchy Trees
     omnisint scan krypton_sec_x7 --title "Incident #402 Attribution"

     # Inspect a case and cryptographically verify its SHA-256 Chain of Custody
     omnisint case list
     omnisint case show <case_id>
     omnisint case verify <case_id>

     # Pivot on a specific discovered node ID from the command line
     omnisint pivot <case_id> <node_id>

     # Export a citation-locked Markdown dossier or STIX 2.1 JSON bundle
     omnisint report <case_id> --format markdown --output dossier.md
     omnisint report <case_id> --format stix --output bundle.stix.json

     # Launch the interactive Textual/headless terminal dashboard or Web GUI
     omnisint tui <case_id>
     omnisint serve --port 8000
     ```
  2. **Interactive Terminal Dashboard (`omnisint/cli/tui.py`):**
     - `OmniSINTTUIDashboard` with live **Persona & Information Hierarchy Tree** view, **Identity Confidence Matrix** view, **SHA-256 Custody Ledger** view, and **Citation-Locked AI Brief** view (backed by `textual` when installed and deterministic snapshot rendering in headless shells).
  3. **End-to-End Integration Suite (`tests/test_cli_e2e.py`):**
     - Verifies `omnisint demo`, `case list`, `case show`, `case verify` (both intact and SQLite-tampered!), `report`, `tui --snapshot`, and `OmniSINTTUIDashboard` view switching.
- **Files Created:**
  - [omnisint/cli/main.py](file:///Users/alex/OmniSINT/omnisint/cli/main.py) (`app`, `run_cli`, `build_demo_collision_case`)
  - [omnisint/cli/tui.py](file:///Users/alex/OmniSINT/omnisint/cli/tui.py) (`OmniSINTTUIDashboard`, `launch_tui`)
  - [tests/test_cli_e2e.py](file:///Users/alex/OmniSINT/tests/test_cli_e2e.py)
- **Prompt Used:**
  > `"Implement Task 10 from TASKS.md: Typer CLI, Textual TUI, and End-to-End Verification, run tests, and update Graphify."`
