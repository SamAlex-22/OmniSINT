# OmniSINT — Graphify Codebase Knowledge Report

- **Generated (UTC):** `2026-11-23T10:24:51.103764+00:00`
- **Total AST Nodes:** `232`
- **Total Structural Edges:** `938`
- **Architectural Communities:** `11`

## 1. High-Centrality 'God Nodes' (Core Abstractions)
| Node ID | Degree (Connections) |
| :--- | :--- |
| `omnisint.core.models` | 49 |
| `omnisint.core.custody` | 39 |
| `omnisint.collectors.scrapling_collector` | 38 |
| `omnisint.cli.main` | 36 |
| `omnisint.core.storage.CaseStorage` | 33 |
| `omnisint.core.storage` | 31 |
| `omnisint.core.custody.CustodyLedger` | 30 |
| `omnisint.api.routes.cases` | 29 |
| `omnisint.intelligence.similarity` | 27 |
| `omnisint.collectors.base` | 27 |
| `omnisint.intelligence.graph_engine` | 26 |
| `omnisint.intelligence.ai_analyst` | 25 |

## 2. Architectural Communities & Symbols
### Community: `__main__` (1 nodes)
- **`omnisint.__main__`** (`module` in `omnisint/__main__.py`) — Module entrypoint allowing `python3 -m omnisint` execution without runpy warnings.

### Community: `api` (19 nodes)
- **`omnisint.api`** (`module` in `omnisint/api/__init__.py`) — FastAPI REST & WebSocket backend for OmniSINT.
- **`omnisint.api.app`** (`module` in `omnisint/api/app.py`) — FastAPI (or Flask WSGI fallback) web server and WebSocket live stream for OmniSINT.
- **`omnisint.api.app._run_coro_sync`** (`function` in `omnisint/api/app.py`) — Run an async coroutine cleanly from synchronous Flask handlers.
- **`omnisint.api.app.create_app`** (`function` in `omnisint/api/app.py`) — Create the OmniSINT ASGI (FastAPI) or WSGI (Flask fallback) web application.
- **`omnisint.api.app.get_default_app`** (`function` in `omnisint/api/app.py`) — Factory returning a default configured OmniSINT web application.
- **`omnisint.api.routes`** (`module` in `omnisint/api/routes/__init__.py`) — API route modules for OmniSINT.
- **`omnisint.api.routes.cases`** (`module` in `omnisint/api/routes/cases.py`) — REST & WebSocket Case, Scan, Graph, Pivot, Custody, Async Job & Reporting route handlers for OmniSINT.
- **`omnisint.api.routes.cases.CreateCaseRequest`** (`class` in `omnisint/api/routes/cases.py`) — Payload to create a new OSINT investigation Case.
- **`omnisint.api.routes.cases.ScanRequest`** (`class` in `omnisint/api/routes/cases.py`) — Payload to trigger a multi-collector OSINT scan inside a Case.
- **`omnisint.api.routes.cases.PivotNodeRequest`** (`class` in `omnisint/api/routes/cases.py`) — Payload to execute a one-click pivot on an existing EntityNode.
- **`omnisint.api.routes.cases.ScanJobStatus`** (`class` in `omnisint/api/routes/cases.py`) — Status tracker for non-blocking background scan or pivot jobs.
- **`omnisint.api.routes.cases.CustodyVerificationResponse`** (`class` in `omnisint/api/routes/cases.py`) — Cryptographic Chain of Custody verification response payload.
- **`omnisint.api.routes.cases.GraphPayloadResponse`** (`class` in `omnisint/api/routes/cases.py`) — Cytoscape.js elements + Persona Clusters + Hierarchy Trees for UI rendering.
- **`omnisint.api.routes.cases.ProgressBroadcaster`** (`class` in `omnisint/api/routes/cases.py`) — In-memory pub/sub hub streaming ScanProgressEvents to WebSocket subscribers.
- **`omnisint.api.routes.cases.JobManager`** (`class` in `omnisint/api/routes/cases.py`) — Tracks background scan and pivot tasks across both ASGI and WSGI runtimes.
- **`omnisint.api.routes.cases.verify_api_token`** (`function` in `omnisint/api/routes/cases.py`) — Return True if authentication is disabled or the supplied Bearer/X-API-Key token matches.
- **`omnisint.api.routes.cases.OmniSINTAPIService`** (`class` in `omnisint/api/routes/cases.py`) — Framework-agnostic async service layer backing FastAPI and Flask endpoints.
- **`omnisint.api.routes.cases.build_fastapi_router`** (`function` in `omnisint/api/routes/cases.py`) — Build a FastAPI APIRouter wired to `service` when FastAPI is installed.
- **`omnisint.api.routes.cases.json_dumps_safe`** (`function` in `omnisint/api/routes/cases.py`) — Serialize Pydantic models or JSON objects safely.

### Community: `cli` (21 nodes)
- **`omnisint.cli`** (`module` in `omnisint/cli/__init__.py`) — CLI and interactive terminal dashboard (TUI) for OmniSINT.
- **`omnisint.cli.main`** (`module` in `omnisint/cli/main.py`) — Command-line interface (`omnisint`) for scans, case custody verification, pivoting, TUI, and reporting.
- **`omnisint.cli.main.build_demo_collision_case`** (`function` in `omnisint/cli/main.py`) — Construct and analyze a realistic offline OSINT collision scenario separating distinct personas.
- **`omnisint.cli.main._resolve_db_path`** (`function` in `omnisint/cli/main.py`)
- **`omnisint.cli.main.app`** (`function` in `omnisint/cli/main.py`) — OmniSINT top-level CLI group.
- **`omnisint.cli.main.cmd_demo`** (`function` in `omnisint/cli/main.py`) — Run an offline colliding-namesake disambiguation demonstration.
- **`omnisint.cli.main._build_platform_specs`** (`function` in `omnisint/cli/main.py`) — Combine built-in JSON platform specs with optional Sherlock/WhatsMyName registries.
- **`omnisint.cli.main.cmd_scan`** (`function` in `omnisint/cli/main.py`) — Execute a multi-collector OSINT scan and resolve persona hierarchy trees.
- **`omnisint.cli.main.cmd_scrape`** (`function` in `omnisint/cli/main.py`) — Scrape a public URL or username profile via Scrapling and persist SHA-256 evidence.
- **`omnisint.cli.main.case_group`** (`function` in `omnisint/cli/main.py`) — Inspect and verify persisted investigation Cases.
- **`omnisint.cli.main.cmd_case_list`** (`function` in `omnisint/cli/main.py`) — List all Cases stored in SQLite.
- **`omnisint.cli.main.cmd_case_show`** (`function` in `omnisint/cli/main.py`) — Show details, hierarchy trees, and brief for CASE_ID.
- **`omnisint.cli.main.cmd_case_verify`** (`function` in `omnisint/cli/main.py`) — Cryptographically verify the SHA-256 Chain of Custody for CASE_ID.
- **`omnisint.cli.main.cmd_pivot`** (`function` in `omnisint/cli/main.py`) — Pivot on NODE_ID inside CASE_ID and re-resolve persona clusters.
- **`omnisint.cli.main.cmd_report`** (`function` in `omnisint/cli/main.py`) — Export CASE_ID as a Markdown investigative dossier or STIX 2.1 JSON bundle.
- **`omnisint.cli.main.cmd_tui`** (`function` in `omnisint/cli/main.py`) — Launch the interactive OmniSINT terminal dashboard.
- **`omnisint.cli.main.cmd_serve`** (`function` in `omnisint/cli/main.py`) — Start the OmniSINT Web GUI & REST API server.
- **`omnisint.cli.main.run_cli`** (`function` in `omnisint/cli/main.py`) — Invoke the OmniSINT CLI programmatically and return `(exit_code, output)`.
- **`omnisint.cli.tui`** (`module` in `omnisint/cli/tui.py`) — Textual interactive terminal dashboard (with deterministic headless snapshot fallback) for OmniSINT.
- **`omnisint.cli.tui.OmniSINTTUIDashboard`** (`class` in `omnisint/cli/tui.py`) — Stateful interactive terminal dashboard controller for OmniSINT Cases.
- **`omnisint.cli.tui.launch_tui`** (`function` in `omnisint/cli/tui.py`) — Launch the Textual TUI when available & interactive, or return rendered dashboard text.

### Community: `collectors` (47 nodes)
- **`omnisint.collectors`** (`module` in `omnisint/collectors/__init__.py`) — Pluggable passive OSINT collectors and registry.
- **`omnisint.collectors.create_default_registry`** (`function` in `omnisint/collectors/__init__.py`) — Create a CollectorRegistry pre-populated with all OmniSINT passive collectors.
- **`omnisint.collectors.base`** (`module` in `omnisint/collectors/base.py`) — Abstract BaseCollector, rate-limiting, caching, proxy routing, secret redaction, custody integration, and CollectorRegistry.
- **`omnisint.collectors.base.redact_sensitive_url`** (`function` in `omnisint/collectors/base.py`) — Mask sensitive query parameters (e.g. API keys/tokens) before storing URIs in custody or cache.
- **`omnisint.collectors.base.HttpResponseData`** (`class` in `omnisint/collectors/base.py`) — Normalized HTTP response returned by collector transports.
- **`omnisint.collectors.base.CollectorConfig`** (`class` in `omnisint/collectors/base.py`) — Runtime configuration for passive OSINT collectors.
- **`omnisint.collectors.base._default_urllib_get`** (`async_function` in `omnisint/collectors/base.py`) — Perform an async HTTP GET via httpx (when installed) or stdlib urllib in a worker thread.
- **`omnisint.collectors.base.BaseCollector`** (`class` in `omnisint/collectors/base.py`) — Abstract base class for all passive OmniSINT OSINT collectors.
- **`omnisint.collectors.base.CollectorRegistry`** (`class` in `omnisint/collectors/base.py`) — Registry for discovering and dispatching OmniSINT Collector plugins.
- **`omnisint.collectors.domain_ct_collector`** (`module` in `omnisint/collectors/domain_ct_collector.py`) — Passive Certificate Transparency (crt.sh), RDAP/WHOIS, and passive DNS collector.
- **`omnisint.collectors.domain_ct_collector.DomainCTCollector`** (`class` in `omnisint/collectors/domain_ct_collector.py`) — Collects Certificate Transparency logs (crt.sh), RDAP registration data, and passive DNS records.
- **`omnisint.collectors.github_collector`** (`module` in `omnisint/collectors/github_collector.py`) — Passive GitHub profile, repository, commit author email, and SSH/PGP key collector.
- **`omnisint.collectors.github_collector.GitHubCollector`** (`class` in `omnisint/collectors/github_collector.py`) — Collects GitHub profile metadata, repositories, commit emails/timestamps, and SSH/PGP keys.
- **`omnisint.collectors.scrapling_collector`** (`module` in `omnisint/collectors/scrapling_collector.py`) — Compliant Scrapling-powered public page & JS-rendered profile collector.
- **`omnisint.collectors.scrapling_collector.ScrapedPageData`** (`class` in `omnisint/collectors/scrapling_collector.py`) — Normalized HTTP or headless browser response captured by ScraplingCollector.
- **`omnisint.collectors.scrapling_collector.ExtractedProfileMetadata`** (`class` in `omnisint/collectors/scrapling_collector.py`) — Structured OSINT profile metadata parsed from public HTML.
- **`omnisint.collectors.scrapling_collector.detect_access_gate`** (`function` in `omnisint/collectors/scrapling_collector.py`) — Detect HTTP rate limits, auth walls, login redirects, and CAPTCHA gates without bypassing them.
- **`omnisint.collectors.scrapling_collector._StdlibMetaParser`** (`class` in `omnisint/collectors/scrapling_collector.py`) — Stdlib HTMLParser extracting title, meta tags, canonical link, JSON-LD blocks, and anchors.
- **`omnisint.collectors.scrapling_collector._extract_raw_html_fields`** (`function` in `omnisint/collectors/scrapling_collector.py`) — Parse raw HTML into `(title, meta_map, canonical_url, json_ld_raw, links)`.
- **`omnisint.collectors.scrapling_collector.extract_html_canonical_and_og_url`** (`function` in `omnisint/collectors/scrapling_collector.py`) — Return `(canonical_url, og_url)` from raw HTML for soft redirect detection.
- **`omnisint.collectors.scrapling_collector._infer_platform_from_url`** (`function` in `omnisint/collectors/scrapling_collector.py`) — Determine a normalized platform name from URL host or OpenGraph site_name.
- **`omnisint.collectors.scrapling_collector._parse_human_count`** (`function` in `omnisint/collectors/scrapling_collector.py`) — Convert numeric tokens like '1,234', '12.5K', or '1.2M' into integer counts.
- **`omnisint.collectors.scrapling_collector._extract_metric_count`** (`function` in `omnisint/collectors/scrapling_collector.py`) — Search candidate descriptions for social counts like Followers / Following / Posts.
- **`omnisint.collectors.scrapling_collector._clean_display_title`** (`function` in `omnisint/collectors/scrapling_collector.py`) — Strip common platform branding suffixes from `<title>` / `og:title` values.
- **`omnisint.collectors.scrapling_collector._dedupe_preserve_order`** (`function` in `omnisint/collectors/scrapling_collector.py`) — Deduplicate strings case-insensitively while preserving first-seen order.
- **`omnisint.collectors.scrapling_collector._flatten_json_ld_objects`** (`function` in `omnisint/collectors/scrapling_collector.py`) — Parse JSON-LD script blocks into a flat list of dictionary nodes.
- **`omnisint.collectors.scrapling_collector._extract_location_string`** (`function` in `omnisint/collectors/scrapling_collector.py`) — Convert schema.org `address` or `location` objects into a readable location string.
- **`omnisint.collectors.scrapling_collector._is_valid_external_url`** (`function` in `omnisint/collectors/scrapling_collector.py`) — Keep public http(s) URLs that are distinct from `page_url` and not auth/share noise.
- **`omnisint.collectors.scrapling_collector.parse_public_profile_html`** (`function` in `omnisint/collectors/scrapling_collector.py`) — Extract OpenGraph, Twitter Card, JSON-LD, links, @mentions, #hashtags, emails & counts from public HTML.
- **`omnisint.collectors.scrapling_collector._extract_scrapling_response`** (`function` in `omnisint/collectors/scrapling_collector.py`) — Normalize a Scrapling Response object into ScrapedPageData.
- **`omnisint.collectors.scrapling_collector._run_scrapling_static`** (`function` in `omnisint/collectors/scrapling_collector.py`)
- **`omnisint.collectors.scrapling_collector._run_scrapling_dynamic`** (`function` in `omnisint/collectors/scrapling_collector.py`)
- **`omnisint.collectors.scrapling_collector._extract_handle_from_url`** (`function` in `omnisint/collectors/scrapling_collector.py`) — Best-effort handle/slug extraction from the terminal path segment of a profile URL.
- **`omnisint.collectors.scrapling_collector.ScraplingCollector`** (`class` in `omnisint/collectors/scrapling_collector.py`) — Collects public profile & OpenGraph/JSON-LD metadata using Scrapling (or stdlib HTTP fallback).
- **`omnisint.collectors.search_dork_collector`** (`module` in `omnisint/collectors/search_dork_collector.py`) — Pluggable search dork generator, Wayback Machine CDX archive & Google CSE collector.
- **`omnisint.collectors.search_dork_collector.generate_dork_queries`** (`function` in `omnisint/collectors/search_dork_collector.py`) — Generate targeted passive OSINT search dork strings for a handle, email, or domain.
- **`omnisint.collectors.search_dork_collector.SearchDorkCollector`** (`class` in `omnisint/collectors/search_dork_collector.py`) — Queries Wayback Machine CDX archives and optional Google CSE for historical & dorked mentions.
- **`omnisint.collectors.threat_intel`** (`module` in `omnisint/collectors/threat_intel.py`) — Passive Threat Intelligence collector (VirusTotal v3 & passive DNS/reputation indicators).
- **`omnisint.collectors.threat_intel.ThreatIntelCollector`** (`class` in `omnisint/collectors/threat_intel.py`) — Collects VirusTotal reputation, threat indicators, and passive DNS infrastructure links.
- **`omnisint.collectors.username_collector`** (`module` in `omnisint/collectors/username_collector.py`) — Passive multi-platform username discovery & profile/avatar collector (Sherlock-compatible).
- **`omnisint.collectors.username_collector.PlatformSpec`** (`class` in `omnisint/collectors/username_collector.py`) — Definition of a passive platform check for UsernameCollector (WhatsMyName & Sherlock compatible).
- **`omnisint.collectors.username_collector._load_json_mapping`** (`function` in `omnisint/collectors/username_collector.py`) — Load a JSON dictionary from an in-memory dict, JSON string, or file path.
- **`omnisint.collectors.username_collector._format_handle_url`** (`function` in `omnisint/collectors/username_collector.py`) — Substitute `{handle}` or `{}` placeholders safely without failing on unrelated braces.
- **`omnisint.collectors.username_collector._url_matches_error_url`** (`function` in `omnisint/collectors/username_collector.py`) — Return True when a redirect/canonical URL matches a Sherlock `errorUrl` indicator.
- **`omnisint.collectors.username_collector.load_whatsmyname_specs`** (`function` in `omnisint/collectors/username_collector.py`) — Load PlatformSpec entries from a WhatsMyName JSON file path, JSON string, or parsed dictionary.
- **`omnisint.collectors.username_collector.load_sherlock_specs`** (`function` in `omnisint/collectors/username_collector.py`) — Load PlatformSpec entries from a Sherlock `data.json` path, JSON string, or parsed dictionary.
- **`omnisint.collectors.username_collector.UsernameCollector`** (`class` in `omnisint/collectors/username_collector.py`) — Sherlock-style async multi-platform username discovery, metadata, and avatar dHash collector.

### Community: `config` (3 nodes)
- **`omnisint.config`** (`module` in `omnisint/config.py`) — Centralized Pydantic v2 configuration for OmniSINT.
- **`omnisint.config.OmniSINTSettings`** (`class` in `omnisint/config.py`) — Application-wide settings loaded from environment variables or defaults.
- **`omnisint.config.get_settings`** (`function` in `omnisint/config.py`) — Return a fresh settings instance.

### Community: `core` (34 nodes)
- **`omnisint.core`** (`module` in `omnisint/core/__init__.py`) — Core data models, chain-of-custody ledger, SQLite storage, and async orchestrator.
- **`omnisint.core.custody`** (`module` in `omnisint/core/custody.py`) — SHA-256 chain-of-custody ledger for OmniSINT evidence.
- **`omnisint.core.custody.payload_kind`** (`function` in `omnisint/core/custody.py`) — Return the structural kind of a raw payload ("json", "text", or "bytes").
- **`omnisint.core.custody.canonicalize_payload`** (`function` in `omnisint/core/custody.py`) — Serialize a raw OSINT payload into deterministic canonical bytes.
- **`omnisint.core.custody.compute_sha256`** (`function` in `omnisint/core/custody.py`) — Compute hex-encoded SHA-256 digest of a canonicalized payload.
- **`omnisint.core.custody.compute_chain_hash`** (`function` in `omnisint/core/custody.py`) — Compute the tamper-evident chained SHA-256 digest for one evidence record.
- **`omnisint.core.custody.compute_item_chain_hash`** (`function` in `omnisint/core/custody.py`) — Recompute the chain hash for an EvidenceItem (optionally against a different predecessor).
- **`omnisint.core.custody.CustodyLedger`** (`class` in `omnisint/core/custody.py`) — Manages evidence acquisition, hash chaining, and the audit trail for a Case.
- **`omnisint.core.custody.CustodySigner`** (`class` in `omnisint/core/custody.py`) — Signs and verifies a CustodyLedger head state using Ed25519 (or HMAC-SHA256 fallback).
- **`omnisint.core.custody.RFC3161AnchorRecord`** (`class` in `omnisint/core/custody.py`) — Canonical SHA-256 imprint metadata prepared for RFC 3161 TSA timestamp anchoring.
- **`omnisint.core.custody.build_rfc3161_digest_request`** (`function` in `omnisint/core/custody.py`) — Build deterministic SHA-256 imprint metadata for anchoring a CustodyLedger head via RFC 3161.
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
- **`omnisint.core.orchestrator`** (`module` in `omnisint/core/orchestrator.py`) — Async scan orchestrator and multi-hop cross-indicator pivot engine for OmniSINT.
- **`omnisint.core.orchestrator.ScanProgressEvent`** (`class` in `omnisint/core/orchestrator.py`) — Real-time progress event emitted during scans and node pivots.
- **`omnisint.core.orchestrator.PivotRequest`** (`class` in `omnisint/core/orchestrator.py`) — Parameters for pivoting an investigation from an existing EntityNode.
- **`omnisint.core.orchestrator.infer_entity_type`** (`function` in `omnisint/core/orchestrator.py`) — Heuristically classify a raw OSINT seed string into a canonical EntityType.
- **`omnisint.core.orchestrator.ScanOrchestrator`** (`class` in `omnisint/core/orchestrator.py`) — Coordinates passive collectors, multi-hop pivots, storage persistence, graph clustering, and AI analysis.
- **`omnisint.core.storage`** (`module` in `omnisint/core/storage.py`) — Async SQLite Case Store & TTL Response Cache for OmniSINT.
- **`omnisint.core.storage.make_cache_key`** (`function` in `omnisint/core/storage.py`) — Generate a deterministic SHA-256 cache key for a collector request.
- **`omnisint.core.storage.CacheEntry`** (`class` in `omnisint/core/storage.py`) — Cached collector response record with TTL metadata and SHA-256 integrity hash.
- **`omnisint.core.storage.CaseStorage`** (`class` in `omnisint/core/storage.py`) — Async SQLite persistence engine for Cases, Graph Entities/Edges, Custody Ledger, and HTTP Cache.

### Community: `intelligence` (66 nodes)
- **`omnisint.intelligence`** (`module` in `omnisint/intelligence/__init__.py`) — Mathematical and AI entity-resolution modules (entropy, similarity, temporal, graph, LLM).
- **`omnisint.intelligence.ai_analyst`** (`module` in `omnisint/intelligence/ai_analyst.py`) — Citation-locked AI Entity Disambiguation Analyst & Persona Dossier Synthesizer for OmniSINT.
- **`omnisint.intelligence.ai_analyst.sanitize_untrusted_osint_text`** (`function` in `omnisint/intelligence/ai_analyst.py`) — Strip control characters and prompt-injection patterns from collected OSINT text.
- **`omnisint.intelligence.ai_analyst.IdentityMatrixEntry`** (`class` in `omnisint/intelligence/ai_analyst.py`) — Single row in the resolved Identity Confidence Matrix for a PersonaCluster.
- **`omnisint.intelligence.ai_analyst.CitationAuditResult`** (`class` in `omnisint/intelligence/ai_analyst.py`) — Verification audit of node_id and evidence_id citations in an AI intelligence brief.
- **`omnisint.intelligence.ai_analyst.AIAnalysisReport`** (`class` in `omnisint/intelligence/ai_analyst.py`) — Comprehensive citation-locked intelligence analysis report for a Case.
- **`omnisint.intelligence.ai_analyst.classify_confidence_tier`** (`function` in `omnisint/intelligence/ai_analyst.py`) — Classify a numeric [0.0, 1.0] confidence score into HIGH, MEDIUM, or LOW.
- **`omnisint.intelligence.ai_analyst.extract_citations`** (`function` in `omnisint/intelligence/ai_analyst.py`) — Extract all unique [node:<id>] and [evidence:<id>] references from an analytical text.
- **`omnisint.intelligence.ai_analyst.audit_citations`** (`function` in `omnisint/intelligence/ai_analyst.py`) — Verify that all cited node_ids and evidence_ids exist in the case and every persona is cited.
- **`omnisint.intelligence.ai_analyst.sanitize_hallucinated_citations`** (`function` in `omnisint/intelligence/ai_analyst.py`) — Replace any hallucinated [node:<id>] or [evidence:<id>] tags with explicit redaction markers.
- **`omnisint.intelligence.ai_analyst._default_http_post_json`** (`async_function` in `omnisint/intelligence/ai_analyst.py`) — Perform an async JSON POST request using standard library urllib inside a worker thread.
- **`omnisint.intelligence.ai_analyst.AIAnalyst`** (`class` in `omnisint/intelligence/ai_analyst.py`) — Citation-enforced AI Entity Disambiguation Analyst & Dossier Synthesizer.
- **`omnisint.intelligence.benchmark`** (`module` in `omnisint/intelligence/benchmark.py`) — Labelled entity-resolution benchmark harness for calibrating & measuring KnowledgeGraphEngine accuracy.
- **`omnisint.intelligence.benchmark.BenchmarkMetrics`** (`class` in `omnisint/intelligence/benchmark.py`) — Pairwise precision/recall/F1 and Adjusted Rand Index (ARI) clustering evaluation metrics.
- **`omnisint.intelligence.benchmark.BenchmarkCase`** (`class` in `omnisint/intelligence/benchmark.py`) — A single labelled multi-persona entity disambiguation test scenario.
- **`omnisint.intelligence.benchmark.BenchmarkCaseResult`** (`class` in `omnisint/intelligence/benchmark.py`) — Evaluation output for a single BenchmarkCase.
- **`omnisint.intelligence.benchmark.evaluate_clustering`** (`function` in `omnisint/intelligence/benchmark.py`) — Compute exact pairwise Precision, Recall, F1, and Adjusted Rand Index (ARI) in pure Python.
- **`omnisint.intelligence.benchmark._count_groups`** (`function` in `omnisint/intelligence/benchmark.py`)
- **`omnisint.intelligence.benchmark.default_benchmark_cases`** (`function` in `omnisint/intelligence/benchmark.py`) — Return a multi-scenario labelled benchmark suite covering edge cases and multinational namesakes.
- **`omnisint.intelligence.benchmark.run_disambiguation_benchmark`** (`function` in `omnisint/intelligence/benchmark.py`) — Run KnowledgeGraphEngine across labelled benchmark cases and compute aggregate accuracy metrics.
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
- **`omnisint.intelligence.graph_engine`** (`module` in `omnisint/intelligence/graph_engine.py`) — NetworkX knowledge graph, conflict-aware Louvain persona clustering, and hierarchy tree builder.
- **`omnisint.intelligence.graph_engine.DisambiguationConfig`** (`class` in `omnisint/intelligence/graph_engine.py`) — Configuration thresholds for mathematical entity disambiguation and Louvain clustering.
- **`omnisint.intelligence.graph_engine.GraphDisambiguationReport`** (`class` in `omnisint/intelligence/graph_engine.py`) — Summary report produced by KnowledgeGraphEngine persona disambiguation.
- **`omnisint.intelligence.graph_engine._FallbackWeightedGraph`** (`class` in `omnisint/intelligence/graph_engine.py`) — Pure-Python NetworkX-compatible weighted undirected graph for offline environments.
- **`omnisint.intelligence.graph_engine._parse_explicit_tz_offset`** (`function` in `omnisint/intelligence/graph_engine.py`) — Parse an explicit timezone string such as 'UTC+05:30', '+05:30', or 'UTC-07:00' into hours.
- **`omnisint.intelligence.graph_engine._extract_node_temporal_profile`** (`function` in `omnisint/intelligence/graph_engine.py`) — Extract or synthesize a TemporalProfile from an EntityNode's attributes.
- **`omnisint.intelligence.graph_engine.compute_modularity`** (`function` in `omnisint/intelligence/graph_engine.py`) — Compute Newman-Girvan weighted modularity Q in [-0.5, 1.0] for a graph partition.
- **`omnisint.intelligence.graph_engine.louvain_communities_deterministic`** (`function` in `omnisint/intelligence/graph_engine.py`) — Partition weighted graph nodes into communities via conflict-aware Louvain modularity optimization.
- **`omnisint.intelligence.graph_engine.KnowledgeGraphEngine`** (`class` in `omnisint/intelligence/graph_engine.py`) — Graph intelligence engine for entity deduplication, Louvain persona clustering, and hierarchy tree synthesis.
- **`omnisint.intelligence.graph_engine.render_hierarchy_ascii`** (`function` in `omnisint/intelligence/graph_engine.py`) — Render a HierarchyTreeNode into an investigative Unicode box-drawing hierarchy tree.
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

### Community: `reporting` (8 nodes)
- **`omnisint.reporting`** (`module` in `omnisint/reporting/__init__.py`) — Investigative dossier and STIX 2.1 reporting exporters.
- **`omnisint.reporting.markdown_exporter`** (`module` in `omnisint/reporting/markdown_exporter.py`) — Investigative Markdown dossier exporter with Hierarchy Trees & SHA-256 Chain of Custody tables.
- **`omnisint.reporting.markdown_exporter.redact_pii_text`** (`function` in `omnisint/reporting/markdown_exporter.py`) — Mask emails, IPv4 host octets, and phone numbers for PII-safe sharing.
- **`omnisint.reporting.markdown_exporter._hierarchy_tree_to_mermaid`** (`function` in `omnisint/reporting/markdown_exporter.py`) — Convert a PersonaCluster HierarchyTreeNode into a Mermaid flowchart TD diagram.
- **`omnisint.reporting.markdown_exporter.MarkdownExporter`** (`class` in `omnisint/reporting/markdown_exporter.py`) — Exports an OmniSINT Case into a complete, evidentiary Markdown investigative dossier.
- **`omnisint.reporting.stix_exporter`** (`module` in `omnisint/reporting/stix_exporter.py`) — OASIS STIX 2.1 Threat Intelligence bundle exporter for OmniSINT Cases.
- **`omnisint.reporting.stix_exporter._stix_id`** (`function` in `omnisint/reporting/stix_exporter.py`) — Generate a deterministic STIX 2.1 identifier `<stix_type>--<uuidv5>`.
- **`omnisint.reporting.stix_exporter.STIXExporter`** (`class` in `omnisint/reporting/stix_exporter.py`) — Exports a resolved OmniSINT Case into an OASIS STIX 2.1 JSON Bundle.

### Community: `scripts` (5 nodes)
- **`scripts.update_code_graph`** (`module` in `scripts/update_code_graph.py`) — Deterministic AST & Graphify Context Knowledge Graph Builder for OmniSINT.
- **`scripts.update_code_graph._resolve_call_target`** (`function` in `scripts/update_code_graph.py`) — Resolve simple function or imported symbol calls into candidate qualified IDs.
- **`scripts.update_code_graph.extract_module_info`** (`function` in `scripts/update_code_graph.py`) — Parse a Python file into AST nodes (module, classes, functions) and structural edges.
- **`scripts.update_code_graph.build_graph`** (`function` in `scripts/update_code_graph.py`) — Scan workspace and build the structured codebase knowledge graph.
- **`scripts.update_code_graph.write_outputs`** (`function` in `scripts/update_code_graph.py`) — Write graph.json and GRAPH_REPORT.md only when structural graph contents change.

### Community: `tests` (27 nodes)
- **`tests`** (`module` in `tests/__init__.py`) — Pytest test suite for OmniSINT.
- **`tests.test_ai_analyst`** (`module` in `tests/test_ai_analyst.py`) — Unit tests for Task 5: Citation-Locked AI Analyst & Persona Dossier Synthesizer.
- **`tests.test_ai_analyst.TestAIAnalyst`** (`class` in `tests/test_ai_analyst.py`) — Test suite for citation-locked AIAnalyst, Identity Confidence Matrix, and LLM providers.
- **`tests.test_api`** (`module` in `tests/test_api.py`) — Unit tests for Task 9: REST API & Cytoscape.js Web GUI endpoints.
- **`tests.test_api.TestOmniSINTAPI`** (`class` in `tests/test_api.py`) — Offline integration tests for the OmniSINT Web API and Cytoscape.js UI serving.
- **`tests.test_benchmark`** (`module` in `tests/test_benchmark.py`) — Unit tests for the labelled disambiguation benchmark harness.
- **`tests.test_benchmark.TestDisambiguationBenchmark`** (`class` in `tests/test_benchmark.py`) — Verify entity-resolution precision, recall, F1, and Adjusted Rand Index.
- **`tests.test_cli_e2e`** (`module` in `tests/test_cli_e2e.py`) — End-to-end integration tests for Task 10: CLI, TUI Dashboard, Custody Verification & Reporting.
- **`tests.test_cli_e2e.TestCLIEndToEnd`** (`class` in `tests/test_cli_e2e.py`) — End-to-end CLI and interactive TUI integration tests.
- **`tests.test_entropy_and_similarity`** (`module` in `tests/test_entropy_and_similarity.py`) — Unit tests for Task 3: Shannon Entropy, Handle Rarity, Multi-Modal Similarity & Temporal Correlation.
- **`tests.test_entropy_and_similarity.TestEntropySimilarityAndTemporal`** (`class` in `tests/test_entropy_and_similarity.py`) — Test suite for mathematical entity disambiguation primitives (Task 3).
- **`tests.test_graph_engine`** (`module` in `tests/test_graph_engine.py`) — Unit tests for Task 4: NetworkX Knowledge Graph, Louvain Persona Clustering & Hierarchy Tree.
- **`tests.test_graph_engine.TestKnowledgeGraphEngine`** (`class` in `tests/test_graph_engine.py`) — Test suite for KnowledgeGraphEngine disambiguation, Louvain clustering, and Hierarchy Tree.
- **`tests.test_identity_collectors`** (`module` in `tests/test_identity_collectors.py`) — Unit tests for Task 6: Pluggable Collector Framework, UsernameCollector & GitHubCollector.
- **`tests.test_identity_collectors.TestIdentityCollectors`** (`class` in `tests/test_identity_collectors.py`) — Offline deterministic tests for BaseCollector, CollectorRegistry, UsernameCollector, and GitHubCollector.
- **`tests.test_infra_collectors`** (`module` in `tests/test_infra_collectors.py`) — Unit tests for Task 7: DomainCTCollector, ThreatIntelCollector, and SearchDorkCollector.
- **`tests.test_infra_collectors.TestInfraCollectors`** (`class` in `tests/test_infra_collectors.py`) — Offline deterministic tests for DomainCTCollector, ThreatIntelCollector, and SearchDorkCollector.
- **`tests.test_live_smoke`** (`module` in `tests/test_live_smoke.py`) — Opt-in live-network smoke tests (skipped offline unless OMNISINT_LIVE_TESTS=1).
- **`tests.test_live_smoke.TestLiveCollectorSmoke`** (`class` in `tests/test_live_smoke.py`) — Real-network sanity checks against public GitHub and Google DoH APIs.
- **`tests.test_models_and_custody`** (`module` in `tests/test_models_and_custody.py`) — Unit tests for Task 1: Core Ontology & OSINT Pilot Chain-of-Custody Engine.
- **`tests.test_models_and_custody.TestModelsAndCustody`** (`class` in `tests/test_models_and_custody.py`) — Test suite for OmniSINT core models and cryptographic chain of custody.
- **`tests.test_orchestrator_and_reporting`** (`module` in `tests/test_orchestrator_and_reporting.py`) — Unit tests for Task 8: Async Scan Orchestrator, Pivot Engine, Markdown & STIX 2.1 Exporters.
- **`tests.test_orchestrator_and_reporting.TestOrchestratorAndReporting`** (`class` in `tests/test_orchestrator_and_reporting.py`) — End-to-end offline tests for ScanOrchestrator multi-hop pivoting and Markdown/STIX 2.1 export.
- **`tests.test_scrapling_and_sherlock`** (`module` in `tests/test_scrapling_and_sherlock.py`) — Offline deterministic tests for Sherlock data.json support and ScraplingCollector.
- **`tests.test_scrapling_and_sherlock.TestScraplingAndSherlock`** (`class` in `tests/test_scrapling_and_sherlock.py`) — Deterministic offline tests covering Sherlock data.json parsing and Scrapling integration.
- **`tests.test_storage`** (`module` in `tests/test_storage.py`) — Unit tests for Task 2: Async SQLite Case Store & TTL Response Cache.
- **`tests.test_storage.TestCaseStorage`** (`class` in `tests/test_storage.py`) — Test suite for async SQLite case persistence, graph deduplication, custody chain, and TTL cache.
