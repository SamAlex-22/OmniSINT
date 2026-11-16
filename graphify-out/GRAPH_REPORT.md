# OmniSINT — Graphify Codebase Knowledge Report

- **Generated (UTC):** `2026-11-16T20:21:30.897984+00:00`
- **Total AST Nodes:** `81`
- **Total Structural Edges:** `157`
- **Architectural Communities:** `10`

## 1. High-Centrality 'God Nodes' (Core Abstractions)
| Node ID | Degree (Connections) |
| :--- | :--- |
| `omnisint.core.models` | 26 |
| `omnisint.intelligence.similarity` | 20 |
| `omnisint.intelligence.entropy` | 19 |
| `omnisint.intelligence.temporal` | 18 |
| `omnisint.core.storage` | 16 |
| `BaseModel` | 14 |
| `omnisint.core.custody` | 13 |
| `__future__` | 11 |
| `scripts.update_code_graph` | 10 |
| `tests.test_storage` | 9 |
| `omnisint.config` | 8 |
| `typing` | 7 |

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

### Community: `core` (24 nodes)
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
- **`omnisint.core.storage`** (`module` in `omnisint/core/storage.py`) — Async SQLite Case Store & TTL Response Cache for OmniSINT.
- **`omnisint.core.storage.make_cache_key`** (`function` in `omnisint/core/storage.py`) — Generate a deterministic SHA-256 cache key for a collector request.
- **`omnisint.core.storage.CacheEntry`** (`class` in `omnisint/core/storage.py`) — Cached collector response record with TTL metadata and SHA-256 integrity hash.
- **`omnisint.core.storage.CaseStorage`** (`class` in `omnisint/core/storage.py`) — Async SQLite persistence engine for Cases, Graph Entities/Edges, Custody Ledger, and HTTP Cache.

### Community: `intelligence` (37 nodes)
- **`omnisint.intelligence`** (`module` in `omnisint/intelligence/__init__.py`) — Mathematical and AI entity-resolution modules (entropy, similarity, temporal, graph, LLM).
- **`omnisint.intelligence.entropy`** (`module` in `omnisint/intelligence/entropy.py`) — Shannon entropy, n-gram rarity, and handle collision probability scoring for OmniSINT.
- **`omnisint.intelligence.entropy.HandleEntropyMetrics`** (`class` in `omnisint/intelligence/entropy.py`) — Comprehensive information-theoretic and collision-risk metrics for an OSINT handle.
- **`omnisint.intelligence.entropy.strip_email_domain`** (`function` in `omnisint/intelligence/entropy.py`) — Return the local part if value is an email address, else the stripped string.
- **`omnisint.intelligence.entropy.tokenize_handle`** (`function` in `omnisint/intelligence/entropy.py`) — Split a handle into lowercase alphanumeric sub-tokens across delimiters, camelCase, and digits.
- **`omnisint.intelligence.entropy.shannon_entropy`** (`function` in `omnisint/intelligence/entropy.py`) — Compute Shannon entropy H(X) in bits per character for a string.
- **`omnisint.intelligence.entropy.information_bits`** (`function` in `omnisint/intelligence/entropy.py`) — Compute total Shannon information content I(X) = |X| * H(X) in bits.
- **`omnisint.intelligence.entropy._unusual_bigram_ratio`** (`function` in `omnisint/intelligence/entropy.py`) — Compute fraction of character bigrams that are NOT top-50 common English bigrams.
- **`omnisint.intelligence.entropy.compute_rarity_score`** (`function` in `omnisint/intelligence/entropy.py`) — Compute a normalized [0.0, 1.0] rarity score for a handle or username.
- **`omnisint.intelligence.entropy.estimate_collision_probability`** (`function` in `omnisint/intelligence/entropy.py`) — Estimate the probability [0.0, 1.0] that two accounts with this handle belong to different people.
- **`omnisint.intelligence.entropy.analyze_handle_entropy`** (`function` in `omnisint/intelligence/entropy.py`) — Perform full entropy, token, rarity, and collision-risk analysis on a handle.
- **`omnisint.intelligence.entropy.enrich_node_entropy`** (`function` in `omnisint/intelligence/entropy.py`) — Populate `entropy_score` and `rarity_score` on an EntityNode using its value.
- **`omnisint.intelligence.similarity`** (`module` in `omnisint/intelligence/similarity.py`) — Multi-modal similarity scoring: Jaro-Winkler, Levenshtein, token-swap, and perceptual avatar hashing.
- **`omnisint.intelligence.similarity.SimilarityResult`** (`class` in `omnisint/intelligence/similarity.py`) — Structured multi-modal similarity evaluation between two OSINT handles or profiles.
- **`omnisint.intelligence.similarity.normalize_leet`** (`function` in `omnisint/intelligence/similarity.py`) — Normalize common leetspeak substitutions into lowercase alphabetic characters.
- **`omnisint.intelligence.similarity.levenshtein_distance`** (`function` in `omnisint/intelligence/similarity.py`) — Compute exact Levenshtein edit distance between two strings.
- **`omnisint.intelligence.similarity.normalized_levenshtein`** (`function` in `omnisint/intelligence/similarity.py`) — Compute normalized Levenshtein similarity in [0.0, 1.0].
- **`omnisint.intelligence.similarity.jaro_similarity`** (`function` in `omnisint/intelligence/similarity.py`) — Compute Jaro string similarity in [0.0, 1.0].
- **`omnisint.intelligence.similarity.jaro_winkler_similarity`** (`function` in `omnisint/intelligence/similarity.py`) — Compute Jaro-Winkler similarity in [0.0, 1.0] with shared prefix boost.
- **`omnisint.intelligence.similarity._subtoken_coverage_score`** (`function` in `omnisint/intelligence/similarity.py`) — Evaluate how completely a list of tokens covers a delimiter-free concatenated handle.
- **`omnisint.intelligence.similarity.token_swap_similarity`** (`function` in `omnisint/intelligence/similarity.py`) — Compute order-invariant token & concatenated sub-token similarity between two handles.
- **`omnisint.intelligence.similarity.compute_dhash_from_pixels`** (`function` in `omnisint/intelligence/similarity.py`) — Compute a 64-bit horizontal difference hash (dHash, 16 hex chars) from an 8x9 grayscale grid.
- **`omnisint.intelligence.similarity.compute_dhash_from_bytes`** (`function` in `omnisint/intelligence/similarity.py`) — Compute a 64-bit perceptual difference hash (16 hex chars) from raw avatar bytes.
- **`omnisint.intelligence.similarity.hamming_distance_hex`** (`function` in `omnisint/intelligence/similarity.py`) — Compute bit-level Hamming distance between two equal-length hexadecimal perceptual hashes.
- **`omnisint.intelligence.similarity.avatar_hash_similarity`** (`function` in `omnisint/intelligence/similarity.py`) — Compute normalized [0.0, 1.0] perceptual avatar similarity from two hex dHash/pHash strings.
- **`omnisint.intelligence.similarity.compare_handles`** (`function` in `omnisint/intelligence/similarity.py`) — Compute rarity-weighted multi-modal similarity between two handles and optional avatar hashes.
- **`omnisint.intelligence.temporal`** (`module` in `omnisint/intelligence/temporal.py`) — Timezone inference and active-hour circadian fingerprinting from OSINT timestamps.
- **`omnisint.intelligence.temporal.TemporalProfile`** (`class` in `omnisint/intelligence/temporal.py`) — Circadian activity profile and inferred timezone derived from entity timestamps.
- **`omnisint.intelligence.temporal.TemporalCorrelationResult`** (`class` in `omnisint/intelligence/temporal.py`) — Comparison result between two entities' temporal activity fingerprints.
- **`omnisint.intelligence.temporal.format_utc_offset`** (`function` in `omnisint/intelligence/temporal.py`) — Format a floating-point hour offset (e.g. 5.5 or -4.0) as 'UTC+05:30' or 'UTC-04:00'.
- **`omnisint.intelligence.temporal.parse_timestamp`** (`function` in `omnisint/intelligence/temporal.py`) — Parse a datetime or ISO-8601 string into (utc_datetime, explicit_offset_hours_or_None).
- **`omnisint.intelligence.temporal._infer_offset_from_sleep_window`** (`function` in `omnisint/intelligence/temporal.py`) — Infer UTC offset in hours by locating the 7-hour minimum activity window (sleep trough).
- **`omnisint.intelligence.temporal.build_temporal_profile`** (`function` in `omnisint/intelligence/temporal.py`) — Construct a 24-hour UTC activity histogram and infer the operator's timezone.
- **`omnisint.intelligence.temporal.hourly_cosine_similarity`** (`function` in `omnisint/intelligence/temporal.py`) — Compute exact cosine similarity in [0.0, 1.0] between two 24-hour activity vectors.
- **`omnisint.intelligence.temporal._smooth_histogram`** (`function` in `omnisint/intelligence/temporal.py`) — Apply circular [0.25, 0.50, 0.25] 3-hour kernel smoothing to account for +/- 1h jitter.
- **`omnisint.intelligence.temporal.correlate_temporal_profiles`** (`function` in `omnisint/intelligence/temporal.py`) — Compare two TemporalProfiles across circadian rhythm, timezone offset, and weekend cadence.
- **`omnisint.intelligence.temporal.correlate_timestamps`** (`function` in `omnisint/intelligence/temporal.py`) — Build temporal profiles from two timestamp sequences and compute their correlation.

### Community: `omnisint` (1 nodes)
- **`omnisint`** (`module` in `omnisint/__init__.py`) — OmniSINT — OSINT Aggregation, Case Management, and AI Entity-Resolution Platform.

### Community: `reporting` (1 nodes)
- **`omnisint.reporting`** (`module` in `omnisint/reporting/__init__.py`) — Investigative dossier and STIX 2.1 reporting exporters.

### Community: `scripts` (4 nodes)
- **`scripts.update_code_graph`** (`module` in `scripts/update_code_graph.py`) — Deterministic AST & Graphify Context Knowledge Graph Builder for OmniSINT.
- **`scripts.update_code_graph.extract_module_info`** (`function` in `scripts/update_code_graph.py`) — Parse a Python file into AST nodes (module, classes, functions) and structural edges.
- **`scripts.update_code_graph.build_graph`** (`function` in `scripts/update_code_graph.py`) — Scan workspace and build the structured codebase knowledge graph.
- **`scripts.update_code_graph.write_outputs`** (`function` in `scripts/update_code_graph.py`) — Write graph.json and human/agent-readable GRAPH_REPORT.md.

### Community: `tests` (7 nodes)
- **`tests`** (`module` in `tests/__init__.py`) — Pytest test suite for OmniSINT.
- **`tests.test_entropy_and_similarity`** (`module` in `tests/test_entropy_and_similarity.py`) — Unit tests for Task 3: Shannon Entropy, Handle Rarity, Multi-Modal Similarity & Temporal Correlation.
- **`tests.test_entropy_and_similarity.TestEntropySimilarityAndTemporal`** (`class` in `tests/test_entropy_and_similarity.py`) — Test suite for mathematical entity disambiguation primitives (Task 3).
- **`tests.test_models_and_custody`** (`module` in `tests/test_models_and_custody.py`) — Unit tests for Task 1: Core Ontology & OSINT Pilot Chain-of-Custody Engine.
- **`tests.test_models_and_custody.TestModelsAndCustody`** (`class` in `tests/test_models_and_custody.py`) — Test suite for OmniSINT core models and cryptographic chain of custody.
- **`tests.test_storage`** (`module` in `tests/test_storage.py`) — Unit tests for Task 2: Async SQLite Case Store & TTL Response Cache.
- **`tests.test_storage.TestCaseStorage`** (`class` in `tests/test_storage.py`) — Test suite for async SQLite case persistence, graph deduplication, custody chain, and TTL cache.
