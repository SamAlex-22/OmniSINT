"""Async SQLite Case Store & TTL Response Cache for OmniSINT."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from omnisint.config import get_settings
from omnisint.core.custody import (
    GENESIS_CHAIN_HASH,
    CustodyLedger,
    canonicalize_payload,
    compute_chain_hash,
    compute_sha256,
)
from omnisint.core.models import (
    AuditLogEntry,
    Case,
    CaseStatus,
    CollectorResult,
    EntityNode,
    EntityType,
    EvidenceItem,
    PersonaCluster,
    RelationshipEdge,
    utc_now,
)


def make_cache_key(
    collector_name: str,
    query_or_uri: str,
    params: dict[str, Any] | None = None,
) -> str:
    """Generate a deterministic SHA-256 cache key for a collector request."""
    normalized_collector = collector_name.strip().lower()
    normalized_target = query_or_uri.strip()
    canonical_params = (
        json.dumps(params, sort_keys=True, separators=(",", ":"), default=str)
        if params
        else ""
    )
    material = f"{normalized_collector}|{normalized_target}|{canonical_params}"
    return compute_sha256(material)


class CacheEntry(BaseModel):
    """Cached collector response record with TTL metadata and SHA-256 integrity hash."""

    model_config = ConfigDict(extra="forbid")

    cache_key: str
    collector_name: str
    query_or_uri: str
    status_code: int = 200
    payload: str | dict[str, Any] | list[Any]
    sha256_hash: str = Field(..., min_length=64, max_length=64)
    created_at_utc: datetime = Field(default_factory=utc_now)
    expires_at_utc: datetime

    def is_expired(self, now: datetime | None = None) -> bool:
        """Return True if this cache entry has passed its UTC expiration timestamp."""
        reference = now or utc_now()
        return reference >= self.expires_at_utc


class CaseStorage:
    """Async SQLite persistence engine for Cases, Graph Entities/Edges, Custody Ledger, and HTTP Cache."""

    def __init__(
        self,
        db_path: str | Path | None = None,
        default_ttl_seconds: int | None = None,
    ) -> None:
        settings = get_settings()
        if db_path is None:
            self.db_path_str = str(settings.database_path)
        else:
            self.db_path_str = str(db_path)

        self.default_ttl_seconds = (
            settings.cache_ttl_seconds if default_ttl_seconds is None else default_ttl_seconds
        )
        self._conn: sqlite3.Connection | None = None
        self._lock = asyncio.Lock()
        self._initialized = False

    async def __aenter__(self) -> CaseStorage:
        """Enter async context manager and initialize database schema."""
        await self.initialize()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Close underlying SQLite connection on context exit."""
        await self.close()

    def _open_connection_sync(self) -> sqlite3.Connection:
        """Open and configure SQLite connection synchronously (executed inside worker thread)."""
        if self.db_path_str != ":memory:":
            db_file = Path(self.db_path_str)
            db_file.parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(self.db_path_str, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        if self.db_path_str != ":memory:":
            conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        return conn

    def _create_schema_sync(self, conn: sqlite3.Connection) -> None:
        """Create cases, entities, edges, evidence_items, audit_log, and http_cache tables."""
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                target_query TEXT NOT NULL,
                investigator TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL,
                personas_json TEXT NOT NULL DEFAULT '[]',
                ai_executive_brief TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS entities (
                node_id TEXT NOT NULL,
                case_id TEXT NOT NULL,
                canonical_key TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                value TEXT NOT NULL,
                label TEXT NOT NULL,
                platform TEXT,
                entropy_score REAL NOT NULL,
                rarity_score REAL NOT NULL,
                confidence REAL NOT NULL,
                cluster_id TEXT,
                attributes_json TEXT NOT NULL,
                evidence_ids_json TEXT NOT NULL,
                discovered_at_utc TEXT NOT NULL,
                PRIMARY KEY (case_id, node_id),
                FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_entities_case_canonical
                ON entities(case_id, canonical_key);
            CREATE INDEX IF NOT EXISTS idx_entities_case_type
                ON entities(case_id, entity_type);

            CREATE TABLE IF NOT EXISTS edges (
                edge_id TEXT NOT NULL,
                case_id TEXT NOT NULL,
                source_node_id TEXT NOT NULL,
                target_node_id TEXT NOT NULL,
                relation_type TEXT NOT NULL,
                weight REAL NOT NULL,
                confidence REAL NOT NULL,
                rationale TEXT NOT NULL,
                evidence_ids_json TEXT NOT NULL,
                attributes_json TEXT NOT NULL,
                created_at_utc TEXT NOT NULL,
                PRIMARY KEY (case_id, edge_id),
                FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_edges_case_pair
                ON edges(case_id, source_node_id, target_node_id, relation_type);

            CREATE TABLE IF NOT EXISTS evidence_items (
                evidence_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                seq_index INTEGER NOT NULL,
                collector_name TEXT NOT NULL,
                source_uri TEXT NOT NULL,
                sha256_hash TEXT NOT NULL,
                prev_chain_hash TEXT NOT NULL,
                chain_hash TEXT NOT NULL,
                collected_at_utc TEXT NOT NULL,
                raw_payload_json TEXT NOT NULL,
                payload_is_json INTEGER NOT NULL,
                mime_type TEXT NOT NULL,
                notes TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_evidence_case_seq
                ON evidence_items(case_id, seq_index);

            CREATE TABLE IF NOT EXISTS audit_log (
                entry_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                seq_index INTEGER NOT NULL,
                timestamp_utc TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                details_json TEXT NOT NULL,
                evidence_id TEXT,
                FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_audit_case_seq
                ON audit_log(case_id, seq_index);

            CREATE TABLE IF NOT EXISTS http_cache (
                cache_key TEXT PRIMARY KEY,
                collector_name TEXT NOT NULL,
                query_or_uri TEXT NOT NULL,
                status_code INTEGER NOT NULL DEFAULT 200,
                payload_json TEXT NOT NULL,
                payload_is_json INTEGER NOT NULL,
                sha256_hash TEXT NOT NULL,
                created_at_utc TEXT NOT NULL,
                expires_at_utc TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_http_cache_expires
                ON http_cache(expires_at_utc);
            CREATE INDEX IF NOT EXISTS idx_http_cache_collector
                ON http_cache(collector_name);
            """
        )
        conn.commit()

    async def initialize(self) -> None:
        """Initialize the SQLite connection and create all required tables."""
        async with self._lock:
            if self._initialized and self._conn is not None:
                return
            conn = await asyncio.to_thread(self._open_connection_sync)
            await asyncio.to_thread(self._create_schema_sync, conn)
            self._conn = conn
            self._initialized = True

    async def _ensure_conn(self) -> sqlite3.Connection:
        """Ensure the database is initialized and return the active connection."""
        if not self._initialized or self._conn is None:
            await self.initialize()
        assert self._conn is not None
        return self._conn

    async def close(self) -> None:
        """Close the active SQLite connection safely."""
        async with self._lock:
            if self._conn is not None:
                conn = self._conn
                self._conn = None
                self._initialized = False
                await asyncio.to_thread(conn.close)

    # -------------------------------------------------------------------------
    # Serialization Helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def _encode_payload(payload: str | dict[str, Any] | list[Any]) -> tuple[str, int]:
        """Serialize payload into text and record whether it was structured JSON (1) or raw str (0)."""
        if isinstance(payload, str):
            return payload, 0
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str), 1

    @staticmethod
    def _decode_payload(raw_text: str, is_json: int) -> str | dict[str, Any] | list[Any]:
        """Deserialize payload back to its exact original type (str vs dict/list)."""
        if is_json:
            loaded: dict[str, Any] | list[Any] = json.loads(raw_text)
            return loaded
        return raw_text

    @staticmethod
    def _row_to_node(row: sqlite3.Row) -> EntityNode:
        """Convert a SQLite entities row into an EntityNode."""
        return EntityNode(
            node_id=row["node_id"],
            entity_type=EntityType(row["entity_type"]),
            value=row["value"],
            label=row["label"],
            platform=row["platform"],
            entropy_score=float(row["entropy_score"]),
            rarity_score=float(row["rarity_score"]),
            confidence=float(row["confidence"]),
            cluster_id=row["cluster_id"],
            attributes=json.loads(row["attributes_json"]),
            evidence_ids=json.loads(row["evidence_ids_json"]),
            discovered_at_utc=datetime.fromisoformat(row["discovered_at_utc"]),
        )

    @staticmethod
    def _row_to_edge(row: sqlite3.Row) -> RelationshipEdge:
        """Convert a SQLite edges row into a RelationshipEdge."""
        return RelationshipEdge(
            edge_id=row["edge_id"],
            source_node_id=row["source_node_id"],
            target_node_id=row["target_node_id"],
            relation_type=row["relation_type"],
            weight=float(row["weight"]),
            confidence=float(row["confidence"]),
            rationale=row["rationale"],
            evidence_ids=json.loads(row["evidence_ids_json"]),
            attributes=json.loads(row["attributes_json"]),
            created_at_utc=datetime.fromisoformat(row["created_at_utc"]),
        )

    @classmethod
    def _row_to_evidence(cls, row: sqlite3.Row) -> EvidenceItem:
        """Convert a SQLite evidence_items row into an EvidenceItem."""
        decoded_payload = cls._decode_payload(row["raw_payload_json"], int(row["payload_is_json"]))
        if isinstance(decoded_payload, list):
            # EvidenceItem.raw_payload is str | dict[str, Any]; wrap or preserve string if list
            raw_payload: str | dict[str, Any] = {"items": decoded_payload}
        else:
            raw_payload = decoded_payload
        return EvidenceItem(
            evidence_id=row["evidence_id"],
            case_id=row["case_id"],
            collector_name=row["collector_name"],
            source_uri=row["source_uri"],
            sha256_hash=row["sha256_hash"],
            prev_chain_hash=row["prev_chain_hash"],
            chain_hash=row["chain_hash"],
            collected_at_utc=datetime.fromisoformat(row["collected_at_utc"]),
            raw_payload=raw_payload,
            mime_type=row["mime_type"],
            notes=row["notes"],
        )

    @staticmethod
    def _row_to_audit(row: sqlite3.Row) -> AuditLogEntry:
        """Convert a SQLite audit_log row into an AuditLogEntry."""
        return AuditLogEntry(
            entry_id=row["entry_id"],
            case_id=row["case_id"],
            timestamp_utc=datetime.fromisoformat(row["timestamp_utc"]),
            actor=row["actor"],
            action=row["action"],
            details=json.loads(row["details_json"]),
            evidence_id=row["evidence_id"],
        )

    # -------------------------------------------------------------------------
    # Case Lifecycle & Graph Persistence
    # -------------------------------------------------------------------------

    async def create_case(
        self,
        title: str,
        target_query: str,
        investigator: str = "lead-analyst",
        description: str = "",
    ) -> Case:
        """Create a new Case with an initial CASE_CREATED audit entry and persist it."""
        case = Case(
            title=title,
            target_query=target_query,
            investigator=investigator,
            description=description,
        )
        initial_audit = AuditLogEntry(
            case_id=case.case_id,
            actor=investigator,
            action="CASE_CREATED",
            details={"title": title, "target_query": target_query},
        )
        case.audit_log.append(initial_audit)
        return await self.save_case(case)

    def _save_case_sync(self, conn: sqlite3.Connection, case: Case) -> None:
        """Synchronously persist a full Case and all child collections in one transaction."""
        personas_json = json.dumps(
            [p.model_dump(mode="json") for p in case.personas],
            separators=(",", ":"),
        )
        with conn:
            conn.execute(
                """
                INSERT INTO cases (
                    case_id, title, target_query, investigator, description,
                    status, created_at_utc, updated_at_utc, personas_json, ai_executive_brief
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(case_id) DO UPDATE SET
                    title = excluded.title,
                    target_query = excluded.target_query,
                    investigator = excluded.investigator,
                    description = excluded.description,
                    status = excluded.status,
                    updated_at_utc = excluded.updated_at_utc,
                    personas_json = excluded.personas_json,
                    ai_executive_brief = excluded.ai_executive_brief;
                """,
                (
                    case.case_id,
                    case.title,
                    case.target_query,
                    case.investigator,
                    case.description,
                    case.status.value,
                    case.created_at_utc.isoformat(),
                    case.updated_at_utc.isoformat(),
                    personas_json,
                    case.ai_executive_brief,
                ),
            )

            # Synchronize nodes, edges, evidence items, and audit log
            conn.execute("DELETE FROM entities WHERE case_id = ?;", (case.case_id,))
            for node in case.nodes:
                conn.execute(
                    """
                    INSERT INTO entities (
                        node_id, case_id, canonical_key, entity_type, value, label,
                        platform, entropy_score, rarity_score, confidence, cluster_id,
                        attributes_json, evidence_ids_json, discovered_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        node.node_id,
                        case.case_id,
                        node.canonical_key,
                        node.entity_type.value,
                        node.value,
                        node.label,
                        node.platform,
                        node.entropy_score,
                        node.rarity_score,
                        node.confidence,
                        node.cluster_id,
                        json.dumps(node.attributes, sort_keys=True),
                        json.dumps(node.evidence_ids),
                        node.discovered_at_utc.isoformat(),
                    ),
                )

            conn.execute("DELETE FROM edges WHERE case_id = ?;", (case.case_id,))
            for edge in case.edges:
                conn.execute(
                    """
                    INSERT INTO edges (
                        edge_id, case_id, source_node_id, target_node_id, relation_type,
                        weight, confidence, rationale, evidence_ids_json, attributes_json,
                        created_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        edge.edge_id,
                        case.case_id,
                        edge.source_node_id,
                        edge.target_node_id,
                        edge.relation_type.value,
                        edge.weight,
                        edge.confidence,
                        edge.rationale,
                        json.dumps(edge.evidence_ids),
                        json.dumps(edge.attributes, sort_keys=True),
                        edge.created_at_utc.isoformat(),
                    ),
                )

            conn.execute("DELETE FROM evidence_items WHERE case_id = ?;", (case.case_id,))
            for seq_idx, item in enumerate(case.evidence_ledger):
                raw_text, is_json = self._encode_payload(item.raw_payload)
                conn.execute(
                    """
                    INSERT INTO evidence_items (
                        evidence_id, case_id, seq_index, collector_name, source_uri,
                        sha256_hash, prev_chain_hash, chain_hash, collected_at_utc,
                        raw_payload_json, payload_is_json, mime_type, notes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        item.evidence_id,
                        case.case_id,
                        seq_idx,
                        item.collector_name,
                        item.source_uri,
                        item.sha256_hash,
                        item.prev_chain_hash,
                        item.chain_hash,
                        item.collected_at_utc.isoformat(),
                        raw_text,
                        is_json,
                        item.mime_type,
                        item.notes,
                    ),
                )

            conn.execute("DELETE FROM audit_log WHERE case_id = ?;", (case.case_id,))
            for seq_idx, entry in enumerate(case.audit_log):
                conn.execute(
                    """
                    INSERT INTO audit_log (
                        entry_id, case_id, seq_index, timestamp_utc, actor,
                        action, details_json, evidence_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        entry.entry_id,
                        case.case_id,
                        seq_idx,
                        entry.timestamp_utc.isoformat(),
                        entry.actor,
                        entry.action,
                        json.dumps(entry.details, sort_keys=True, default=str),
                        entry.evidence_id,
                    ),
                )

    async def save_case(self, case: Case) -> Case:
        """Persist or update a complete Case and its graph/custody collections in SQLite."""
        conn = await self._ensure_conn()
        case.updated_at_utc = utc_now()
        async with self._lock:
            await asyncio.to_thread(self._save_case_sync, conn, case)
        return case

    def _get_case_sync(self, conn: sqlite3.Connection, case_id: str) -> Case | None:
        """Synchronously hydrate a full Case from SQLite tables."""
        row = conn.execute("SELECT * FROM cases WHERE case_id = ?;", (case_id,)).fetchone()
        if row is None:
            return None

        node_rows = conn.execute(
            "SELECT * FROM entities WHERE case_id = ? ORDER BY discovered_at_utc ASC;",
            (case_id,),
        ).fetchall()
        edge_rows = conn.execute(
            "SELECT * FROM edges WHERE case_id = ? ORDER BY created_at_utc ASC;",
            (case_id,),
        ).fetchall()
        ev_rows = conn.execute(
            "SELECT * FROM evidence_items WHERE case_id = ? ORDER BY seq_index ASC;",
            (case_id,),
        ).fetchall()
        audit_rows = conn.execute(
            "SELECT * FROM audit_log WHERE case_id = ? ORDER BY seq_index ASC;",
            (case_id,),
        ).fetchall()

        personas_raw = json.loads(row["personas_json"])
        personas = [PersonaCluster.model_validate(p) for p in personas_raw]

        return Case(
            case_id=row["case_id"],
            title=row["title"],
            target_query=row["target_query"],
            investigator=row["investigator"],
            description=row["description"],
            status=CaseStatus(row["status"]),
            created_at_utc=datetime.fromisoformat(row["created_at_utc"]),
            updated_at_utc=datetime.fromisoformat(row["updated_at_utc"]),
            nodes=[self._row_to_node(r) for r in node_rows],
            edges=[self._row_to_edge(r) for r in edge_rows],
            personas=personas,
            evidence_ledger=[self._row_to_evidence(r) for r in ev_rows],
            audit_log=[self._row_to_audit(r) for r in audit_rows],
            ai_executive_brief=row["ai_executive_brief"],
        )

    async def get_case(self, case_id: str) -> Case | None:
        """Retrieve and hydrate a Case by its case_id, or return None if not found."""
        conn = await self._ensure_conn()
        async with self._lock:
            return await asyncio.to_thread(self._get_case_sync, conn, case_id)

    def _list_cases_sync(
        self,
        conn: sqlite3.Connection,
        status: CaseStatus | None = None,
    ) -> list[Case]:
        """Synchronously list and hydrate all cases matching optional status filter."""
        if status is not None:
            rows = conn.execute(
                "SELECT case_id FROM cases WHERE status = ? ORDER BY updated_at_utc DESC;",
                (status.value,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT case_id FROM cases ORDER BY updated_at_utc DESC;"
            ).fetchall()

        cases: list[Case] = []
        for r in rows:
            hydrated = self._get_case_sync(conn, r["case_id"])
            if hydrated is not None:
                cases.append(hydrated)
        return cases

    async def list_cases(self, status: CaseStatus | None = None) -> list[Case]:
        """Return all stored Cases ordered by most recently updated."""
        conn = await self._ensure_conn()
        async with self._lock:
            return await asyncio.to_thread(self._list_cases_sync, conn, status)

    async def update_case_status(
        self,
        case_id: str,
        status: CaseStatus,
        actor: str = "omnisint-system",
    ) -> Case | None:
        """Update a Case's lifecycle status and append an audit log entry."""
        case = await self.get_case(case_id)
        if case is None:
            return None
        old_status = case.status
        case.status = status
        case.audit_log.append(
            AuditLogEntry(
                case_id=case_id,
                actor=actor,
                action="CASE_STATUS_UPDATED",
                details={"old_status": old_status.value, "new_status": status.value},
            )
        )
        return await self.save_case(case)

    def _delete_case_sync(self, conn: sqlite3.Connection, case_id: str) -> bool:
        """Synchronously delete a case and cascade to all child records."""
        with conn:
            cursor = conn.execute("DELETE FROM cases WHERE case_id = ?;", (case_id,))
            return cursor.rowcount > 0

    async def delete_case(self, case_id: str) -> bool:
        """Delete a Case and all associated graph entities, edges, evidence, and audit entries."""
        conn = await self._ensure_conn()
        async with self._lock:
            return await asyncio.to_thread(self._delete_case_sync, conn, case_id)

    # -------------------------------------------------------------------------
    # Granular Graph Node & Edge Operations (with Canonical Deduplication)
    # -------------------------------------------------------------------------

    def _upsert_node_sync(
        self,
        conn: sqlite3.Connection,
        case_id: str,
        node: EntityNode,
    ) -> EntityNode:
        """Upsert an EntityNode into a Case, deduplicating by canonical_key or node_id."""
        existing_row = conn.execute(
            """
            SELECT * FROM entities
            WHERE case_id = ? AND (canonical_key = ? OR node_id = ?)
            LIMIT 1;
            """,
            (case_id, node.canonical_key, node.node_id),
        ).fetchone()

        if existing_row is not None:
            existing = self._row_to_node(existing_row)
            merged_attrs = {**existing.attributes, **node.attributes}
            merged_ev_ids = list(dict.fromkeys([*existing.evidence_ids, *node.evidence_ids]))
            merged_node = EntityNode(
                node_id=existing.node_id,
                entity_type=existing.entity_type,
                value=existing.value,
                label=node.label or existing.label,
                platform=existing.platform or node.platform,
                entropy_score=max(existing.entropy_score, node.entropy_score),
                rarity_score=max(existing.rarity_score, node.rarity_score),
                confidence=max(existing.confidence, node.confidence),
                cluster_id=node.cluster_id or existing.cluster_id,
                attributes=merged_attrs,
                evidence_ids=merged_ev_ids,
                discovered_at_utc=existing.discovered_at_utc,
            )
            with conn:
                conn.execute(
                    """
                    UPDATE entities SET
                        label = ?,
                        platform = ?,
                        entropy_score = ?,
                        rarity_score = ?,
                        confidence = ?,
                        cluster_id = ?,
                        attributes_json = ?,
                        evidence_ids_json = ?
                    WHERE case_id = ? AND node_id = ?;
                    """,
                    (
                        merged_node.label,
                        merged_node.platform,
                        merged_node.entropy_score,
                        merged_node.rarity_score,
                        merged_node.confidence,
                        merged_node.cluster_id,
                        json.dumps(merged_node.attributes, sort_keys=True),
                        json.dumps(merged_node.evidence_ids),
                        case_id,
                        merged_node.node_id,
                    ),
                )
                conn.execute(
                    "UPDATE cases SET updated_at_utc = ? WHERE case_id = ?;",
                    (utc_now().isoformat(), case_id),
                )
            return merged_node

        with conn:
            conn.execute(
                """
                INSERT INTO entities (
                    node_id, case_id, canonical_key, entity_type, value, label,
                    platform, entropy_score, rarity_score, confidence, cluster_id,
                    attributes_json, evidence_ids_json, discovered_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    node.node_id,
                    case_id,
                    node.canonical_key,
                    node.entity_type.value,
                    node.value,
                    node.label,
                    node.platform,
                    node.entropy_score,
                    node.rarity_score,
                    node.confidence,
                    node.cluster_id,
                    json.dumps(node.attributes, sort_keys=True),
                    json.dumps(node.evidence_ids),
                    node.discovered_at_utc.isoformat(),
                ),
            )
            conn.execute(
                "UPDATE cases SET updated_at_utc = ? WHERE case_id = ?;",
                (utc_now().isoformat(), case_id),
            )
        return node

    async def upsert_node(self, case_id: str, node: EntityNode) -> EntityNode:
        """Insert or deduplicate an EntityNode within a Case by canonical_key."""
        conn = await self._ensure_conn()
        async with self._lock:
            return await asyncio.to_thread(self._upsert_node_sync, conn, case_id, node)

    def _upsert_edge_sync(
        self,
        conn: sqlite3.Connection,
        case_id: str,
        edge: RelationshipEdge,
    ) -> RelationshipEdge:
        """Upsert a RelationshipEdge within a Case, deduplicating by (source, target, relation_type)."""
        existing_row = conn.execute(
            """
            SELECT * FROM edges
            WHERE case_id = ? AND (
                edge_id = ?
                OR (source_node_id = ? AND target_node_id = ? AND relation_type = ?)
            )
            LIMIT 1;
            """,
            (
                case_id,
                edge.edge_id,
                edge.source_node_id,
                edge.target_node_id,
                edge.relation_type.value,
            ),
        ).fetchone()

        if existing_row is not None:
            existing = self._row_to_edge(existing_row)
            merged_ev_ids = list(dict.fromkeys([*existing.evidence_ids, *edge.evidence_ids]))
            merged_attrs = {**existing.attributes, **edge.attributes}
            merged_edge = RelationshipEdge(
                edge_id=existing.edge_id,
                source_node_id=existing.source_node_id,
                target_node_id=existing.target_node_id,
                relation_type=existing.relation_type,
                weight=max(existing.weight, edge.weight),
                confidence=max(existing.confidence, edge.confidence),
                rationale=edge.rationale or existing.rationale,
                evidence_ids=merged_ev_ids,
                attributes=merged_attrs,
                created_at_utc=existing.created_at_utc,
            )
            with conn:
                conn.execute(
                    """
                    UPDATE edges SET
                        weight = ?,
                        confidence = ?,
                        rationale = ?,
                        evidence_ids_json = ?,
                        attributes_json = ?
                    WHERE case_id = ? AND edge_id = ?;
                    """,
                    (
                        merged_edge.weight,
                        merged_edge.confidence,
                        merged_edge.rationale,
                        json.dumps(merged_edge.evidence_ids),
                        json.dumps(merged_edge.attributes, sort_keys=True),
                        case_id,
                        merged_edge.edge_id,
                    ),
                )
                conn.execute(
                    "UPDATE cases SET updated_at_utc = ? WHERE case_id = ?;",
                    (utc_now().isoformat(), case_id),
                )
            return merged_edge

        with conn:
            conn.execute(
                """
                INSERT INTO edges (
                    edge_id, case_id, source_node_id, target_node_id, relation_type,
                    weight, confidence, rationale, evidence_ids_json, attributes_json,
                    created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    edge.edge_id,
                    case_id,
                    edge.source_node_id,
                    edge.target_node_id,
                    edge.relation_type.value,
                    edge.weight,
                    edge.confidence,
                    edge.rationale,
                    json.dumps(edge.evidence_ids),
                    json.dumps(edge.attributes, sort_keys=True),
                    edge.created_at_utc.isoformat(),
                ),
            )
            conn.execute(
                "UPDATE cases SET updated_at_utc = ? WHERE case_id = ?;",
                (utc_now().isoformat(), case_id),
            )
        return edge

    async def upsert_edge(self, case_id: str, edge: RelationshipEdge) -> RelationshipEdge:
        """Insert or merge a RelationshipEdge within a Case."""
        conn = await self._ensure_conn()
        async with self._lock:
            return await asyncio.to_thread(self._upsert_edge_sync, conn, case_id, edge)

    def _get_case_nodes_sync(
        self,
        conn: sqlite3.Connection,
        case_id: str,
        entity_type: EntityType | None = None,
    ) -> list[EntityNode]:
        """Synchronously fetch entities for a case, optionally filtered by EntityType."""
        if entity_type is not None:
            rows = conn.execute(
                """
                SELECT * FROM entities
                WHERE case_id = ? AND entity_type = ?
                ORDER BY discovered_at_utc ASC;
                """,
                (case_id, entity_type.value),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM entities WHERE case_id = ? ORDER BY discovered_at_utc ASC;",
                (case_id,),
            ).fetchall()
        return [self._row_to_node(r) for r in rows]

    async def get_case_nodes(
        self,
        case_id: str,
        entity_type: EntityType | None = None,
    ) -> list[EntityNode]:
        """Return all EntityNodes for a Case, optionally filtered by EntityType."""
        conn = await self._ensure_conn()
        async with self._lock:
            return await asyncio.to_thread(self._get_case_nodes_sync, conn, case_id, entity_type)

    def _get_case_edges_sync(
        self,
        conn: sqlite3.Connection,
        case_id: str,
        node_id: str | None = None,
    ) -> list[RelationshipEdge]:
        """Synchronously fetch edges for a case, optionally filtered by incident node_id."""
        if node_id is not None:
            rows = conn.execute(
                """
                SELECT * FROM edges
                WHERE case_id = ? AND (source_node_id = ? OR target_node_id = ?)
                ORDER BY created_at_utc ASC;
                """,
                (case_id, node_id, node_id),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM edges WHERE case_id = ? ORDER BY created_at_utc ASC;",
                (case_id,),
            ).fetchall()
        return [self._row_to_edge(r) for r in rows]

    async def get_case_edges(
        self,
        case_id: str,
        node_id: str | None = None,
    ) -> list[RelationshipEdge]:
        """Return all RelationshipEdges for a Case, optionally filtered by incident node_id."""
        conn = await self._ensure_conn()
        async with self._lock:
            return await asyncio.to_thread(self._get_case_edges_sync, conn, case_id, node_id)

    # -------------------------------------------------------------------------
    # Evidence Chain of Custody & Collector Result Ingestion
    # -------------------------------------------------------------------------

    def _get_custody_ledger_sync(self, conn: sqlite3.Connection, case_id: str) -> CustodyLedger:
        """Synchronously load CustodyLedger for a case."""
        ev_rows = conn.execute(
            "SELECT * FROM evidence_items WHERE case_id = ? ORDER BY seq_index ASC;",
            (case_id,),
        ).fetchall()
        audit_rows = conn.execute(
            "SELECT * FROM audit_log WHERE case_id = ? ORDER BY seq_index ASC;",
            (case_id,),
        ).fetchall()
        return CustodyLedger(
            case_id=case_id,
            existing_evidence=[self._row_to_evidence(r) for r in ev_rows],
            existing_audit_log=[self._row_to_audit(r) for r in audit_rows],
        )

    async def get_custody_ledger(self, case_id: str) -> CustodyLedger:
        """Load the cryptographic CustodyLedger for a Case from SQLite."""
        conn = await self._ensure_conn()
        async with self._lock:
            return await asyncio.to_thread(self._get_custody_ledger_sync, conn, case_id)

    def _record_evidence_sync(
        self,
        conn: sqlite3.Connection,
        case_id: str,
        collector_name: str,
        source_uri: str,
        raw_payload: str | dict[str, Any],
        mime_type: str,
        notes: str,
        actor: str,
    ) -> EvidenceItem:
        """Synchronously record a new evidence item onto the case's hash chain and persist it."""
        ledger = self._get_custody_ledger_sync(conn, case_id)
        ev_seq = len(ledger.evidence_items)
        audit_seq = len(ledger.audit_log)

        item = ledger.record_evidence(
            collector_name=collector_name,
            source_uri=source_uri,
            raw_payload=raw_payload,
            mime_type=mime_type,
            notes=notes,
            actor=actor,
        )
        latest_audit = ledger.audit_log[-1]
        raw_text, is_json = self._encode_payload(item.raw_payload)

        with conn:
            conn.execute(
                """
                INSERT INTO evidence_items (
                    evidence_id, case_id, seq_index, collector_name, source_uri,
                    sha256_hash, prev_chain_hash, chain_hash, collected_at_utc,
                    raw_payload_json, payload_is_json, mime_type, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    item.evidence_id,
                    case_id,
                    ev_seq,
                    item.collector_name,
                    item.source_uri,
                    item.sha256_hash,
                    item.prev_chain_hash,
                    item.chain_hash,
                    item.collected_at_utc.isoformat(),
                    raw_text,
                    is_json,
                    item.mime_type,
                    item.notes,
                ),
            )
            conn.execute(
                """
                INSERT INTO audit_log (
                    entry_id, case_id, seq_index, timestamp_utc, actor,
                    action, details_json, evidence_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    latest_audit.entry_id,
                    case_id,
                    audit_seq,
                    latest_audit.timestamp_utc.isoformat(),
                    latest_audit.actor,
                    latest_audit.action,
                    json.dumps(latest_audit.details, sort_keys=True, default=str),
                    latest_audit.evidence_id,
                ),
            )
            conn.execute(
                "UPDATE cases SET updated_at_utc = ? WHERE case_id = ?;",
                (utc_now().isoformat(), case_id),
            )
        return item

    async def record_evidence(
        self,
        case_id: str,
        collector_name: str,
        source_uri: str,
        raw_payload: str | dict[str, Any],
        mime_type: str = "application/json",
        notes: str = "",
        actor: str = "omnisint-collector",
    ) -> EvidenceItem:
        """Hash a raw OSINT artifact, chain it to the Case's custody ledger, and persist it."""
        conn = await self._ensure_conn()
        async with self._lock:
            return await asyncio.to_thread(
                self._record_evidence_sync,
                conn,
                case_id,
                collector_name,
                source_uri,
                raw_payload,
                mime_type,
                notes,
                actor,
            )

    async def verify_case_custody(self, case_id: str) -> tuple[bool, list[str]]:
        """Verify the SHA-256 payload hashes and chronological chain hashes for a Case."""
        ledger = await self.get_custody_ledger(case_id)
        return ledger.verify_chain()

    def _merge_collector_result_sync(
        self,
        conn: sqlite3.Connection,
        case_id: str,
        result: CollectorResult,
    ) -> Case:
        """Synchronously merge a CollectorResult into a Case, remapping deduplicated node IDs."""
        # 1. Append evidence items to the case custody chain, preserving evidence_id
        ledger = self._get_custody_ledger_sync(conn, case_id)
        ev_seq = len(ledger.evidence_items)
        audit_seq = len(ledger.audit_log)
        head_hash = ledger.head_chain_hash or GENESIS_CHAIN_HASH

        existing_ev_ids = {e.evidence_id for e in ledger.evidence_items}
        for item in result.evidence_items:
            if item.evidence_id in existing_ev_ids:
                continue
            payload_hash = compute_sha256(item.raw_payload)
            chained_hash = compute_chain_hash(
                prev_chain_hash=head_hash,
                payload_sha256=payload_hash,
                collector_name=item.collector_name,
                source_uri=item.source_uri,
                collected_at_iso=item.collected_at_utc.isoformat(),
            )
            chained_item = EvidenceItem(
                evidence_id=item.evidence_id,
                case_id=case_id,
                collector_name=item.collector_name,
                source_uri=item.source_uri,
                sha256_hash=payload_hash,
                prev_chain_hash=head_hash,
                chain_hash=chained_hash,
                collected_at_utc=item.collected_at_utc,
                raw_payload=item.raw_payload,
                mime_type=item.mime_type,
                notes=item.notes,
            )
            raw_text, is_json = self._encode_payload(chained_item.raw_payload)
            audit_entry = AuditLogEntry(
                case_id=case_id,
                actor=result.collector_name,
                action="EVIDENCE_ACQUIRED",
                evidence_id=chained_item.evidence_id,
                details={
                    "collector_name": chained_item.collector_name,
                    "source_uri": chained_item.source_uri,
                    "sha256_hash": chained_item.sha256_hash,
                    "chain_hash": chained_item.chain_hash,
                },
            )
            with conn:
                conn.execute(
                    """
                    INSERT INTO evidence_items (
                        evidence_id, case_id, seq_index, collector_name, source_uri,
                        sha256_hash, prev_chain_hash, chain_hash, collected_at_utc,
                        raw_payload_json, payload_is_json, mime_type, notes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        chained_item.evidence_id,
                        case_id,
                        ev_seq,
                        chained_item.collector_name,
                        chained_item.source_uri,
                        chained_item.sha256_hash,
                        chained_item.prev_chain_hash,
                        chained_item.chain_hash,
                        chained_item.collected_at_utc.isoformat(),
                        raw_text,
                        is_json,
                        chained_item.mime_type,
                        chained_item.notes,
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO audit_log (
                        entry_id, case_id, seq_index, timestamp_utc, actor,
                        action, details_json, evidence_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        audit_entry.entry_id,
                        case_id,
                        audit_seq,
                        audit_entry.timestamp_utc.isoformat(),
                        audit_entry.actor,
                        audit_entry.action,
                        json.dumps(audit_entry.details, sort_keys=True, default=str),
                        audit_entry.evidence_id,
                    ),
                )
            head_hash = chained_hash
            ev_seq += 1
            audit_seq += 1
            existing_ev_ids.add(chained_item.evidence_id)

        # 2. Upsert nodes and track original_node_id -> canonical persisted node_id
        node_id_map: dict[str, str] = {}
        for node in result.nodes:
            persisted_node = self._upsert_node_sync(conn, case_id, node)
            node_id_map[node.node_id] = persisted_node.node_id

        # 3. Upsert edges with remapped source/target node IDs
        for edge in result.edges:
            mapped_source = node_id_map.get(edge.source_node_id, edge.source_node_id)
            mapped_target = node_id_map.get(edge.target_node_id, edge.target_node_id)
            if mapped_source == mapped_target:
                continue
            remapped_edge = RelationshipEdge(
                edge_id=edge.edge_id,
                source_node_id=mapped_source,
                target_node_id=mapped_target,
                relation_type=edge.relation_type,
                weight=edge.weight,
                confidence=edge.confidence,
                rationale=edge.rationale,
                evidence_ids=edge.evidence_ids,
                attributes=edge.attributes,
                created_at_utc=edge.created_at_utc,
            )
            self._upsert_edge_sync(conn, case_id, remapped_edge)

        hydrated = self._get_case_sync(conn, case_id)
        if hydrated is None:
            raise KeyError(f"Case '{case_id}' does not exist in storage")
        return hydrated

    async def merge_collector_result(self, case_id: str, result: CollectorResult) -> Case:
        """Merge a CollectorResult (evidence, nodes, edges) into an existing Case."""
        conn = await self._ensure_conn()
        async with self._lock:
            return await asyncio.to_thread(self._merge_collector_result_sync, conn, case_id, result)

    # -------------------------------------------------------------------------
    # TTL Response Cache for OSINT Collectors
    # -------------------------------------------------------------------------

    def _get_cached_response_sync(
        self,
        conn: sqlite3.Connection,
        cache_key: str,
    ) -> CacheEntry | None:
        """Synchronously fetch a cached response and evict it if expired."""
        row = conn.execute(
            "SELECT * FROM http_cache WHERE cache_key = ?;",
            (cache_key,),
        ).fetchone()
        if row is None:
            return None

        entry = CacheEntry(
            cache_key=row["cache_key"],
            collector_name=row["collector_name"],
            query_or_uri=row["query_or_uri"],
            status_code=int(row["status_code"]),
            payload=self._decode_payload(row["payload_json"], int(row["payload_is_json"])),
            sha256_hash=row["sha256_hash"],
            created_at_utc=datetime.fromisoformat(row["created_at_utc"]),
            expires_at_utc=datetime.fromisoformat(row["expires_at_utc"]),
        )
        if entry.is_expired():
            with conn:
                conn.execute("DELETE FROM http_cache WHERE cache_key = ?;", (cache_key,))
            return None
        return entry

    async def get_cached_response(
        self,
        collector_name: str,
        query_or_uri: str,
        params: dict[str, Any] | None = None,
    ) -> CacheEntry | None:
        """Look up a non-expired cached collector response by (collector_name, query_or_uri, params)."""
        conn = await self._ensure_conn()
        cache_key = make_cache_key(collector_name, query_or_uri, params)
        async with self._lock:
            return await asyncio.to_thread(self._get_cached_response_sync, conn, cache_key)

    def _set_cached_response_sync(
        self,
        conn: sqlite3.Connection,
        entry: CacheEntry,
    ) -> None:
        """Synchronously insert or replace an HTTP cache record."""
        raw_text, is_json = self._encode_payload(entry.payload)
        with conn:
            conn.execute(
                """
                INSERT INTO http_cache (
                    cache_key, collector_name, query_or_uri, status_code,
                    payload_json, payload_is_json, sha256_hash,
                    created_at_utc, expires_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    status_code = excluded.status_code,
                    payload_json = excluded.payload_json,
                    payload_is_json = excluded.payload_is_json,
                    sha256_hash = excluded.sha256_hash,
                    created_at_utc = excluded.created_at_utc,
                    expires_at_utc = excluded.expires_at_utc;
                """,
                (
                    entry.cache_key,
                    entry.collector_name,
                    entry.query_or_uri,
                    entry.status_code,
                    raw_text,
                    is_json,
                    entry.sha256_hash,
                    entry.created_at_utc.isoformat(),
                    entry.expires_at_utc.isoformat(),
                ),
            )

    async def set_cached_response(
        self,
        collector_name: str,
        query_or_uri: str,
        payload: str | dict[str, Any] | list[Any],
        ttl_seconds: int | None = None,
        params: dict[str, Any] | None = None,
        status_code: int = 200,
    ) -> CacheEntry:
        """Store a collector response in the SQLite TTL cache with its SHA-256 hash."""
        conn = await self._ensure_conn()
        effective_ttl = self.default_ttl_seconds if ttl_seconds is None else max(0, ttl_seconds)
        now = utc_now()
        expires = now + timedelta(seconds=effective_ttl)
        cache_key = make_cache_key(collector_name, query_or_uri, params)
        payload_sha256 = compute_sha256(canonicalize_payload(payload))

        entry = CacheEntry(
            cache_key=cache_key,
            collector_name=collector_name,
            query_or_uri=query_or_uri,
            status_code=status_code,
            payload=payload,
            sha256_hash=payload_sha256,
            created_at_utc=now,
            expires_at_utc=expires,
        )
        if effective_ttl > 0:
            async with self._lock:
                await asyncio.to_thread(self._set_cached_response_sync, conn, entry)
        return entry

    def _invalidate_cache_sync(
        self,
        conn: sqlite3.Connection,
        collector_name: str | None = None,
        cache_key: str | None = None,
    ) -> int:
        """Synchronously delete matching cache records and return count removed."""
        with conn:
            if cache_key is not None:
                cur = conn.execute("DELETE FROM http_cache WHERE cache_key = ?;", (cache_key,))
            elif collector_name is not None:
                cur = conn.execute(
                    "DELETE FROM http_cache WHERE collector_name = ?;",
                    (collector_name,),
                )
            else:
                cur = conn.execute("DELETE FROM http_cache;")
            return cur.rowcount

    async def invalidate_cache(
        self,
        collector_name: str | None = None,
        cache_key: str | None = None,
    ) -> int:
        """Invalidate cached responses by cache_key, collector_name, or clear all cache entries."""
        conn = await self._ensure_conn()
        async with self._lock:
            return await asyncio.to_thread(
                self._invalidate_cache_sync,
                conn,
                collector_name,
                cache_key,
            )

    def _purge_expired_cache_sync(self, conn: sqlite3.Connection) -> int:
        """Synchronously remove all expired HTTP cache rows."""
        now_iso = utc_now().isoformat()
        with conn:
            cur = conn.execute(
                "DELETE FROM http_cache WHERE expires_at_utc <= ?;",
                (now_iso,),
            )
            return cur.rowcount

    async def purge_expired_cache(self) -> int:
        """Purge all expired entries from the HTTP cache table and return removed row count."""
        conn = await self._ensure_conn()
        async with self._lock:
            return await asyncio.to_thread(self._purge_expired_cache_sync, conn)
