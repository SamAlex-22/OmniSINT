# OmniSINT — Project Milestones Log (`Milestone.md`)

This document tracks how and what was engineered across each completed milestone of the **OmniSINT** platform.

---

## Milestone 1 (Task 1): Core Ontology & OSINT Pilot Chain-of-Custody Engine
**Status:** Completed  
**Modules Created:**
- `omnisint/core/models.py`
- `omnisint/core/custody.py`
- `omnisint/core/__init__.py`
- `tests/test_models_and_custody.py`

### 1. What Was Built
1. **Unified Intelligence Ontology (`omnisint/core/models.py`):**
   - **`EntityType` & `RelationType` Enumerations:** Covers 17 OSINT entity types (`PERSON`, `USERNAME`, `SOCIAL_PROFILE`, `EMAIL`, `DOMAIN`, `SUBDOMAIN`, `IP_ADDRESS`, `REPOSITORY`, `ORGANIZATION`, `PGP_KEY`, `SSH_KEY`, `AVATAR_HASH`, `URL`, `PHONE`, `LOCATION`, `CERTIFICATE`, `THREAT_INDICATOR`) and 19 directed/undirected relationship types (including disambiguation edges `SIMILAR_HANDLE`, `SAME_AVATAR`, `TEMPORAL_CORRELATION`, and `RESOLVED_SAME_PERSONA`).
   - **`EntityNode`:** Pydantic v2 vertex schema storing `entropy_score`, `rarity_score`, `confidence`, `cluster_id`, `evidence_ids`, and a deterministic `canonical_key` property (`<entity_type>:<platform>:<lowercase_value>`) for cross-collector deduplication.
   - **`RelationshipEdge`:** Weighted edge schema with confidence scores, rationale strings, evidence citations, and a Pydantic field validator preventing self-referential loops.
   - **`HierarchyTreeNode` & `PersonaCluster`:** Recursive tree structure and disambiguated identity cluster models designed to separate colliding namesakes into distinct personas and represent their information hierarchy trees.
   - **`Case`, `EvidenceItem`, `AuditLogEntry`, & `CollectorResult`:** Top-level OSINT Pilot case container and plugin return contract.

2. **OSINT Pilot Chain-of-Custody Engine (`omnisint/core/custody.py`):**
   - **Deterministic Payload Canonicalization (`canonicalize_payload`, `compute_sha256`):** Normalizes raw JSON dicts, lists, strings, or bytes with sorted keys so identical payloads always yield the exact same 64-character SHA-256 hex digest.
   - **Cryptographic Hash Chaining (`compute_chain_hash`, `CustodyLedger`):** Every acquired `EvidenceItem` links to the previous item's `chain_hash` (starting from `GENESIS_CHAIN_HASH = "0" * 64`), creating an immutable, blockchain-style evidentiary ledger per case.
   - **Tamper Detection (`verify_item`, `verify_chain`):** Validates both individual payload SHA-256 hashes and the entire chronological hash chain, immediately pinpointing any modified payload or broken link.
   - **Automatic Audit Trail:** Every evidence acquisition automatically logs an `AuditLogEntry` with actor attribution, UTC timestamp, and hash metadata.

### 2. Verification & Graphify Sync
- **Unit Tests (`tests/test_models_and_custody.py`):** 5/5 tests passing (canonical deduplication keys, self-loop validation, hierarchy tree serialization, cryptographic hash chaining, and payload tamper detection).
- **Graphify Knowledge Graph (`graphify-out/GRAPH_REPORT.md`):** Updated via `python3 scripts/update_code_graph.py`.
