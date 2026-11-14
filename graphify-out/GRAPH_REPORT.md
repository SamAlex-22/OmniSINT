# OmniSINT — Graphify Codebase Knowledge Report

- **Generated (UTC):** `2026-11-14T19:24:38.556406+00:00`
- **Total AST Nodes:** `37`
- **Total Structural Edges:** `66`
- **Architectural Communities:** `10`

## 1. High-Centrality 'God Nodes' (Core Abstractions)
| Node ID | Degree (Connections) |
| :--- | :--- |
| `omnisint.core.models` | 22 |
| `omnisint.core.custody` | 11 |
| `scripts.update_code_graph` | 10 |
| `BaseModel` | 9 |
| `omnisint.config` | 7 |
| `tests.test_models_and_custody` | 6 |
| `__future__` | 5 |
| `typing` | 4 |
| `pydantic` | 3 |
| `StrEnum` | 3 |
| `pathlib` | 2 |
| `omnisint.config.OmniSINTSettings` | 2 |

## 2. Architectural Communities & Symbols
### Community: `api` (2 nodes)
- **`omnisint.api`** (`module` in `omnisint/api/__init__.py`) — FastAPI REST & WebSocket backend for OmniSINT.
- **`omnisint.api.routes`** (`module` in `omnisint/api/routes/__init__.py`) — API route modules for OmniSINT.

### Community: `cli` (1 nodes)
- **`omnisint.cli`** (`module` in `omnisint/cli/__init__.py`) — Typer CLI and Textual interactive TUI for OmniSINT.

### Community: `collectors` (1 nodes)
- **`omnisint.collectors`** (`module` in `omnisint/collectors/__init__.py`) — Pluggable passive OSINT collectors.

### Community: `config` (3 nodes)
- **`omnisint.config`** (`module` in `omnisint/config.py`) — Centralized Pydantic v2 configuration for OmniSINT.
- **`omnisint.config.OmniSINTSettings`** (`class` in `omnisint/config.py`) — Application-wide settings loaded from environment variables or defaults.
- **`omnisint.config.get_settings`** (`function` in `omnisint/config.py`) — Return a fresh settings instance.

### Community: `core` (20 nodes)
- **`omnisint.core`** (`module` in `omnisint/core/__init__.py`) — Core data models, chain-of-custody ledger, SQLite storage, and async orchestrator.
- **`omnisint.core.custody`** (`module` in `omnisint/core/custody.py`) — OSINT Pilot-grade Chain of Custody & SHA-256 Evidentiary Ledger for OmniSINT.
- **`omnisint.core.custody.canonicalize_payload`** (`function` in `omnisint/core/custody.py`) — Serialize any raw OSINT payload into deterministic canonical UTF-8 bytes.
- **`omnisint.core.custody.compute_sha256`** (`function` in `omnisint/core/custody.py`) — Compute hex-encoded SHA-256 digest of a canonicalized payload.
- **`omnisint.core.custody.compute_chain_hash`** (`function` in `omnisint/core/custody.py`) — Compute tamper-evident chained SHA-256 digest linking previous evidence record.
- **`omnisint.core.custody.CustodyLedger`** (`class` in `omnisint/core/custody.py`) — Manages cryptographic evidence acquisition, hash chaining, and audit trail for a Case.
- **`omnisint.core.models`** (`module` in `omnisint/core/models.py`) — Unified Pydantic v2 ontology for OmniSINT Entities, Edges, Cases, and Chain of Custody.
- **`omnisint.core.models.utc_now`** (`function` in `omnisint/core/models.py`) — Return current timezone-aware UTC datetime.
- **`omnisint.core.models.new_uuid`** (`function` in `omnisint/core/models.py`) — Return a fresh UUIDv4 string.
- **`omnisint.core.models.EntityType`** (`class` in `omnisint/core/models.py`) — Canonical OSINT entity and observable types.
- **`omnisint.core.models.RelationType`** (`class` in `omnisint/core/models.py`) — Canonical directed or undirected relationship types between entities.
- **`omnisint.core.models.CaseStatus`** (`class` in `omnisint/core/models.py`) — Investigative lifecycle status of a Case.
- **`omnisint.core.models.EvidenceItem`** (`class` in `omnisint/core/models.py`) — OSINT Pilot-grade immutable Chain of Custody record for a collected artifact.
- **`omnisint.core.models.AuditLogEntry`** (`class` in `omnisint/core/models.py`) — Chronological investigator or system action recorded in the Case custody trail.
- **`omnisint.core.models.EntityNode`** (`class` in `omnisint/core/models.py`) — A single vertex in the OmniSINT intelligence graph.
- **`omnisint.core.models.RelationshipEdge`** (`class` in `omnisint/core/models.py`) — Weighted, evidence-backed link between two EntityNodes.
- **`omnisint.core.models.HierarchyTreeNode`** (`class` in `omnisint/core/models.py`) — Recursive node representing the resolved target's Information Hierarchy Tree.
- **`omnisint.core.models.PersonaCluster`** (`class` in `omnisint/core/models.py`) — Disambiguated candidate identity cluster separating colliding namesakes.
- **`omnisint.core.models.CollectorResult`** (`class` in `omnisint/core/models.py`) — Standardized output returned by any OmniSINT Collector plugin.
- **`omnisint.core.models.Case`** (`class` in `omnisint/core/models.py`) — Top-level OSINT Pilot investigative container.

### Community: `intelligence` (1 nodes)
- **`omnisint.intelligence`** (`module` in `omnisint/intelligence/__init__.py`) — Mathematical and AI entity-resolution modules (entropy, similarity, temporal, graph, LLM).

### Community: `omnisint` (1 nodes)
- **`omnisint`** (`module` in `omnisint/__init__.py`) — OmniSINT — OSINT Aggregation, Case Management, and AI Entity-Resolution Platform.

### Community: `reporting` (1 nodes)
- **`omnisint.reporting`** (`module` in `omnisint/reporting/__init__.py`) — Investigative dossier and STIX 2.1 reporting exporters.

### Community: `scripts` (4 nodes)
- **`scripts.update_code_graph`** (`module` in `scripts/update_code_graph.py`) — Deterministic AST & Graphify Context Knowledge Graph Builder for OmniSINT.
- **`scripts.update_code_graph.extract_module_info`** (`function` in `scripts/update_code_graph.py`) — Parse a Python file into AST nodes (module, classes, functions) and structural edges.
- **`scripts.update_code_graph.build_graph`** (`function` in `scripts/update_code_graph.py`) — Scan workspace and build the structured codebase knowledge graph.
- **`scripts.update_code_graph.write_outputs`** (`function` in `scripts/update_code_graph.py`) — Write graph.json and human/agent-readable GRAPH_REPORT.md.

### Community: `tests` (3 nodes)
- **`tests`** (`module` in `tests/__init__.py`) — Pytest test suite for OmniSINT.
- **`tests.test_models_and_custody`** (`module` in `tests/test_models_and_custody.py`) — Unit tests for Task 1: Core Ontology & OSINT Pilot Chain-of-Custody Engine.
- **`tests.test_models_and_custody.TestModelsAndCustody`** (`class` in `tests/test_models_and_custody.py`) — Test suite for OmniSINT core models and cryptographic chain of custody.
