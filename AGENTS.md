# AGENTS.md — OmniSINT Engineering & Agent Guidelines

## 1. Project Overview & Mission
**OmniSINT** is an enterprise-grade, open-source OSINT Aggregation, Case Management, and AI Entity-Resolution Platform with dual interfaces (**Textual TUI/CLI** and **FastAPI + React/Cytoscape.js Web GUI**).

It combines:
1. **Multi-Source OSINT Collectors** (Sherlock-style username enumeration, passive DNS/CT logs, VirusTotal, GitHub/Git commit intelligence, search engine dorking APIs, metadata/EXIF & perceptual avatar hashing).
2. **OSINT Pilot-Class Case Management & Chain of Custody** (immutable evidence ledger with SHA-256 hashes, UTC acquisition timestamps, source attribution, and STIX 2.1 / Markdown dossier export).
3. **Mathematical & AI Entity Disambiguation Engine** (Shannon entropy scoring, handle rarity, Levenshtein/Jaro-Winkler similarity, temporal/timezone correlation, Louvain community detection, and citation-locked LLM synthesis).

---

## 2. Context Management with Graphify
To maintain high context efficiency across a large multi-module codebase without burning tokens on broad file reads:

### Graphify Workflow Rules for All Agents
- **Graph Location:** `graphify-out/` (`graph.json`, `GRAPH_REPORT.md`, `index.html`).
- **Before Broad Searches:** Always read `graphify-out/GRAPH_REPORT.md` first (when present) to identify architectural communities, core abstractions ("god nodes"), and module boundaries before running `grep` or reading raw files.
- **After Completing a Feature or Milestone:** Run `graphify update .` (or `python3 scripts/update_code_graph.py` fallback AST indexer) so the knowledge graph stays synchronized with the latest classes, FastAPI routes, collector plugins, and UI components.
- **Module Boundaries:** Keep collector plugins, core graph math, database models, API routers, and TUI/Web layers strictly decoupled so the AST call graph remains clean and acyclic.

---

## 3. Repository Architecture

```text
OmniSINT/
├── AGENTS.md                        # Agent instructions, architecture & conventions
├── pyproject.toml                   # Python packaging, dependencies, ruff, pytest config
├── scripts/
│   └── update_code_graph.py         # Deterministic AST & Graphify context-graph builder
├── graphify-out/                    # Auto-generated codebase knowledge graph & report
│   ├── GRAPH_REPORT.md
│   └── graph.json
├── omnisint/
│   ├── __init__.py
│   ├── config.py                    # Pydantic Settings (API keys, rate limits, LLM provider)
│   ├── core/
│   │   ├── models.py                # Unified Entity, Observable, Edge, Case, EvidenceItem schemas
│   │   ├── custody.py               # OSINT Pilot-style SHA-256 Chain of Custody & audit log
│   │   ├── storage.py               # Async SQLite + JSON graph persistence & caching (TTL)
│   │   └── orchestrator.py          # Async task execution, rate-limiting, & pivot engine
│   ├── intelligence/
│   │   ├── entropy.py               # Shannon entropy, n-gram rarity, handle collision probability
│   │   ├── similarity.py            # Jaro-Winkler, Levenshtein, token-swap, pHash avatar correlation
│   │   ├── temporal.py              # Timezone/active-hour fingerprinting from timestamps
│   │   ├── graph_engine.py          # NetworkX knowledge graph, Louvain persona clustering, hierarchy tree
│   │   └── ai_analyst.py            # Citation-enforced LLM entity disambiguation & dossier generator
│   ├── collectors/
│   │   ├── base.py                  # Abstract BaseCollector interface & Registry
│   │   ├── username_collector.py    # Async multi-platform username/profile discovery (Sherlock-compatible)
│   │   ├── domain_ct_collector.py   # Passive DNS, RDAP/WHOIS, crt.sh Certificate Transparency
│   │   ├── github_collector.py      # Public events, commit email extraction, SSH/PGP key correlation
│   │   ├── threat_intel.py          # VirusTotal & passive threat/infrastructure indicators
│   │   └── search_dork_collector.py # Pluggable search dorking (Google CSE / DuckDuckGo / Archive.org)
│   ├── reporting/
│   │   ├── markdown_exporter.py     # Investigative dossier with evidence hashes & hierarchy tree
│   │   └── stix_exporter.py         # Industry-standard STIX 2.1 bundle export
│   ├── api/
│   │   ├── app.py                   # FastAPI application + WebSocket live event stream
│   │   └── routes/                  # Cases, Scans, Graph, Pivot, Evidence, Reports endpoints
│   └── cli/
│       ├── main.py                  # Typer CLI entry point (`omnisint scan`, `omnisint case`, `omnisint tui`, `omnisint serve`)
│       └── tui.py                   # Textual interactive terminal dashboard
├── web/                             # Optional Single-File / Modular Web GUI (Cytoscape.js graph + Case UI)
│   └── index.html
└── tests/                           # Pytest suite (unit + async integration tests)
```

---

## 4. Engineering & Security Standards (Industry Grade)

1. **Strict Type Safety & Validation:**
   - Every function signature must include Python 3.11+ type annotations.
   - All data models, plugin inputs/outputs, and API payloads must use **Pydantic v2** schemas.
2. **Chain of Custody & Evidentiary Integrity (OSINT Pilot Standard):**
   - Every raw response or artifact collected by a plugin must generate an `EvidenceItem` containing:
     - `evidence_id` (UUIDv4)
     - `sha256_hash` of the raw payload
     - `collected_at_utc` (ISO-8601 UTC timestamp)
     - `collector_name` and `source_uri`
   - AI analysis claims **must** reference explicit `evidence_id` or `node_id` values—no unverified speculation.
3. **Passive-First & Ethical Guardrails:**
   - Collectors must respect configurable rate limits, exponential backoff, and local response caching.
   - No collector may perform active exploitation, authentication bypass, or CAPTCHA circumvention.
4. **Testing Requirement:**
   - Every new module in `core/`, `intelligence/`, or `collectors/` must have deterministic unit tests in `tests/` (mocking external HTTP calls where needed so tests run fast and offline).
