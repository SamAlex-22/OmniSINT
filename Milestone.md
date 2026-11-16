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
- **Unit Tests (`tests/test_models_and_custody.py`):** 6/6 tests passing (canonical deduplication keys, self-loop validation, hierarchy tree serialization, cryptographic hash chaining, payload tamper detection, and canonical JSON key ordering).
- **Graphify Knowledge Graph (`graphify-out/GRAPH_REPORT.md`):** Updated via `python3 scripts/update_code_graph.py`.

---

## Milestone 2 (Task 2): Async SQLite Case Store & TTL Response Cache
**Status:** Completed  
**Modules Created / Updated:**
- `omnisint/core/storage.py`
- `omnisint/core/__init__.py`
- `tests/test_storage.py`

### 1. What Was Built
1. **Zero-Config Async SQLite Persistence Engine (`CaseStorage` in `omnisint/core/storage.py`):**
   - **Normalized Relational + JSON Schema:** Manages 6 core SQLite tables (`cases`, `entities`, `edges`, `evidence_items`, `audit_log`, and `http_cache`) with WAL mode (`PRAGMA journal_mode = WAL`), foreign key cascading (`ON DELETE CASCADE`), and composite indexes.
   - **Full Case & Persona Graph Hydration (`create_case`, `save_case`, `get_case`, `list_cases`, `update_case_status`, `delete_case`):** Persists and hydrates complete `Case` containers—including nested `PersonaCluster` and recursive `HierarchyTreeNode` structures—across disk or `:memory:` SQLite databases.
   - **Canonical Entity & Edge Deduplication (`upsert_node`, `upsert_edge`):** Automatically deduplicates discovered `EntityNode` records within a case using `node.canonical_key` (`<entity_type>:<platform>:<lowercase_value>`), preserving the canonical `node_id` while merging `attributes`, `evidence_ids`, and retaining the maximum `confidence`, `entropy_score`, and `rarity_score`.
   - **Collector Result Ingestion & Node ID Remapping (`merge_collector_result`):** Ingests `CollectorResult` payloads from concurrent collectors, automatically remapping duplicate temporary `node_id` references on `RelationshipEdge` objects to the canonical persisted `node_id` and re-chaining new `EvidenceItem` records into the case's sequential hash chain.
   - **Type-Preserving Custody Serialization (`record_evidence`, `verify_case_custody`):** Tracks `payload_is_json` alongside `raw_payload_json` so both raw strings (including raw JSON text) and structured dictionaries round-trip through SQLite without altering their canonical SHA-256 or chain hashes.

2. **Deterministic TTL Collector Response Cache (`CacheEntry`, `make_cache_key`):**
   - **Canonical Request Hashing (`make_cache_key`):** Hashes `(collector_name, query_or_uri, canonical_params)` with SHA-256 to prevent redundant API calls and protect rate-limited OSINT quotas.
   - **TTL Enforcement & Eviction (`get_cached_response`, `set_cached_response`, `invalidate_cache`, `purge_expired_cache`):** Automatically checks `expires_at_utc` on lookup, evicts stale entries on-the-fly, and supports targeted invalidation by collector or cache key.

### 2. Verification & Graphify Sync
- **Unit Tests (`tests/test_storage.py`):** 4/4 async storage tests passing (10/10 total suite tests passing in `0.033s`), covering file-backed persistence, canonical node/edge deduplication, multi-collector result merging with cryptographic custody verification, and TTL cache expiration/invalidation.
- **Graphify Knowledge Graph (`graphify-out/GRAPH_REPORT.md`):** Updated via `python3 scripts/update_code_graph.py` (`43 nodes, 92 edges`).

---

## Milestone 3 (Task 3): Mathematical Disambiguation Part 1 — Shannon Entropy, Handle Rarity & Multi-Modal Similarity
**Status:** Completed  
**Modules Created / Updated:**
- `omnisint/intelligence/entropy.py`
- `omnisint/intelligence/similarity.py`
- `omnisint/intelligence/temporal.py`
- `omnisint/intelligence/__init__.py`
- `tests/test_entropy_and_similarity.py`

### 1. What Was Built
1. **Shannon Entropy, N-Gram Rarity & Handle Collision Scoring (`omnisint/intelligence/entropy.py`):**
   - **Tokenization & Email Normalization (`tokenize_handle`, `strip_email_domain`):** Splits handles across delimiters (`_`, `-`, `.`), camelCase transitions, and digit boundaries while stripping email domains.
   - **Information Theory Metrics (`shannon_entropy`, `information_bits`):** Computes character-level Shannon entropy $H(X)$ in bits/character and total information content $I(X) = |X| \cdot H(X)$.
   - **Rarity & Namesake Collision Probability (`compute_rarity_score`, `estimate_collision_probability`, `analyze_handle_entropy`, `enrich_node_entropy`):** Combines Shannon entropy, unusual bigram ratio (`COMMON_ENGLISH_BIGRAMS`), character-class diversity, and a curated high-collision human name/dictionary token filter (`COMMON_NAME_TOKENS`) to penalize common names (`john_smith` $\rightarrow$ rarity `< 0.35`, high collision risk) while rewarding unique handles (`x7_krypton_99` $\rightarrow$ rarity `> 0.70`, low collision risk).

2. **Multi-Modal Lexical, Token-Swap & Perceptual Avatar Similarity (`omnisint/intelligence/similarity.py`):**
   - **Edit & Prefix Similarity (`levenshtein_distance`, `normalized_levenshtein`, `jaro_similarity`, `jaro_winkler_similarity`, `normalize_leet`):** Evaluates lexical similarity and leetspeak substitutions (`0->o, 1->i, 3->e, 4->a, 5->s, 7->t`).
   - **Order-Invariant & Concatenated Token-Swap Matching (`token_swap_similarity`):** Combines Dice token overlap with greedy sub-token coverage and permutation edit distance to match both reordered handles (`john_doe_sec` $\leftrightarrow$ `sec_john_doe`) and delimiter-free concatenated handles (`john_doe_sec` $\leftrightarrow$ `doejohnsec` $= 1.0$).
   - **Perceptual Avatar Hashing (`compute_dhash_from_pixels`, `compute_dhash_from_bytes`, `hamming_distance_hex`, `avatar_hash_similarity`):** Generates 64-bit (16-hex-char) horizontal gradient difference hashes (`dHash`) from 8x9 pixel grids or raw avatar byte streams and computes normalized bit-level Hamming similarity.
   - **Rarity-Weighted Multi-Modal Evaluator (`compare_handles` -> `SimilarityResult`):** Synthesizes lexical, token-swap, leetspeak, handle rarity weight, and perceptual avatar similarity with an explicit rationale string.

3. **Circadian Active-Hour & Timezone Fingerprinting (`omnisint/intelligence/temporal.py`):**
   - **Circadian Profiling (`build_temporal_profile` -> `TemporalProfile`):** Builds a 24-bin UTC activity histogram, weekend cadence ratio, and infers the operator's timezone (`UTC+HH:MM`) either from explicit ISO-8601/Git commit offsets or by locating the 7-hour biological sleep trough.
   - **Temporal Correlation (`hourly_cosine_similarity`, `correlate_temporal_profiles`, `correlate_timestamps` -> `TemporalCorrelationResult`):** Computes raw and 3-hour circularly smoothed cosine similarity, circular timezone offset alignment, and weekday/weekend cadence similarity to separate colliding namesakes operating in different timezones.

### 2. Verification & Graphify Sync
- **Unit Tests (`tests/test_entropy_and_similarity.py`):** 5/5 tests passing (15/15 total suite tests passing in `0.033s`), covering Shannon entropy, common-name vs rare-handle scoring, `john_doe_sec` $\leftrightarrow$ `doejohnsec` token-swap matching, 64-bit `dHash` Hamming similarity, and `UTC+05:30` vs `UTC-07:00` temporal disambiguation.
- **Graphify Knowledge Graph (`graphify-out/GRAPH_REPORT.md`):** Updated via `python3 scripts/update_code_graph.py` (`81 nodes, 157 edges`).
