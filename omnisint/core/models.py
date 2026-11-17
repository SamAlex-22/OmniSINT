"""Unified Pydantic v2 ontology for OmniSINT Entities, Edges, Cases, and Chain of Custody."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


def utc_now() -> datetime:
    """Return current timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    """Return a fresh UUIDv4 string."""
    return str(uuid4())


class EntityType(StrEnum):
    """Canonical OSINT entity and observable types."""

    PERSON = "person"
    USERNAME = "username"
    SOCIAL_PROFILE = "social_profile"
    EMAIL = "email"
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    REPOSITORY = "repository"
    ORGANIZATION = "organization"
    PGP_KEY = "pgp_key"
    SSH_KEY = "ssh_key"
    AVATAR_HASH = "avatar_hash"
    URL = "url"
    PHONE = "phone"
    LOCATION = "location"
    CERTIFICATE = "certificate"
    THREAT_INDICATOR = "threat_indicator"


class RelationType(StrEnum):
    """Canonical directed or undirected relationship types between entities."""

    HAS_HANDLE = "HAS_HANDLE"
    HAS_PROFILE = "HAS_PROFILE"
    HAS_EMAIL = "HAS_EMAIL"
    OWNS_DOMAIN = "OWNS_DOMAIN"
    HAS_SUBDOMAIN = "HAS_SUBDOMAIN"
    RESOLVES_TO = "RESOLVES_TO"
    ISSUED_CERT = "ISSUED_CERT"
    COMMITTED_TO = "COMMITTED_TO"
    OWNS_REPO = "OWNS_REPO"
    USES_KEY = "USES_KEY"
    HAS_AVATAR = "HAS_AVATAR"
    MEMBER_OF = "MEMBER_OF"
    LOCATED_IN = "LOCATED_IN"
    MENTIONED_AT = "MENTIONED_AT"
    SIMILAR_HANDLE = "SIMILAR_HANDLE"
    SAME_AVATAR = "SAME_AVATAR"
    TEMPORAL_CORRELATION = "TEMPORAL_CORRELATION"
    RESOLVED_SAME_PERSONA = "RESOLVED_SAME_PERSONA"
    FLAGGED_BY = "FLAGGED_BY"


class CaseStatus(StrEnum):
    """Investigative lifecycle status of a Case."""

    OPEN = "open"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class EvidenceItem(BaseModel):
    """OSINT Pilot-grade immutable Chain of Custody record for a collected artifact."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(default_factory=new_uuid)
    case_id: str
    collector_name: str
    source_uri: str
    sha256_hash: str = Field(..., min_length=64, max_length=64)
    prev_chain_hash: str = Field(default="0" * 64, min_length=64, max_length=64)
    chain_hash: str = Field(..., min_length=64, max_length=64)
    collected_at_utc: datetime = Field(default_factory=utc_now)
    raw_payload: str | dict[str, Any] | list[Any]
    mime_type: str = "application/json"
    notes: str = ""


class AuditLogEntry(BaseModel):
    """Chronological investigator or system action recorded in the Case custody trail."""

    model_config = ConfigDict(extra="forbid")

    entry_id: str = Field(default_factory=new_uuid)
    case_id: str
    timestamp_utc: datetime = Field(default_factory=utc_now)
    actor: str = "omnisint-system"
    action: str
    details: dict[str, Any] = Field(default_factory=dict)
    evidence_id: str | None = None


class EntityNode(BaseModel):
    """A single vertex in the OmniSINT intelligence graph."""

    model_config = ConfigDict(extra="forbid")

    node_id: str = Field(default_factory=new_uuid)
    entity_type: EntityType
    value: str = Field(..., min_length=1)
    label: str = ""
    platform: str | None = None
    entropy_score: float = Field(default=0.0, ge=0.0)
    rarity_score: float = Field(default=0.5, ge=0.0, le=1.0)
    confidence: float = Field(default=0.75, ge=0.0, le=1.0)
    cluster_id: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    evidence_ids: list[str] = Field(default_factory=list)
    discovered_at_utc: datetime = Field(default_factory=utc_now)

    def model_post_init(self, __context: Any) -> None:
        """Populate default label when omitted."""
        if not self.label:
            prefix = f"{self.platform}:" if self.platform else ""
            self.label = f"{prefix}{self.value}"

    @property
    def canonical_key(self) -> str:
        """Deterministic deduplication key for entity nodes within a case."""
        plat = (self.platform or "").strip().lower()
        val = self.value.strip().lower()
        return f"{self.entity_type.value}:{plat}:{val}"


class RelationshipEdge(BaseModel):
    """Weighted, evidence-backed link between two EntityNodes."""

    model_config = ConfigDict(extra="forbid")

    edge_id: str = Field(default_factory=new_uuid)
    source_node_id: str
    target_node_id: str
    relation_type: RelationType
    weight: float = Field(default=0.75, ge=0.0, le=1.0)
    confidence: float = Field(default=0.75, ge=0.0, le=1.0)
    rationale: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)
    created_at_utc: datetime = Field(default_factory=utc_now)

    @field_validator("target_node_id")
    @classmethod
    def prevent_self_loop(cls, v: str, info: Any) -> str:
        """Disallow self-referential edges."""
        source = info.data.get("source_node_id")
        if source and source == v:
            raise ValueError("source_node_id and target_node_id cannot be identical")
        return v


class HierarchyTreeNode(BaseModel):
    """Recursive node representing the resolved target's Information Hierarchy Tree."""

    model_config = ConfigDict(extra="forbid")

    node_id: str
    label: str
    category: str
    entity_type: EntityType | str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    entropy_score: float = Field(default=0.0, ge=0.0)
    evidence_ids: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    children: list[HierarchyTreeNode] = Field(default_factory=list)


class PersonaCluster(BaseModel):
    """Disambiguated candidate identity cluster separating colliding namesakes."""

    model_config = ConfigDict(extra="forbid")

    cluster_id: str = Field(default_factory=new_uuid)
    persona_label: str
    primary_handle: str
    confidence_score: float = Field(default=0.5, ge=0.0, le=1.0)
    avg_handle_entropy: float = Field(default=0.0, ge=0.0)
    inferred_timezone: str | None = None
    summary: str = ""
    node_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    disambiguation_reasons: list[str] = Field(default_factory=list)
    recommended_pivots: list[str] = Field(default_factory=list)
    hierarchy_tree: HierarchyTreeNode | None = None


class CollectorResult(BaseModel):
    """Standardized output returned by any OmniSINT Collector plugin."""

    model_config = ConfigDict(extra="forbid")

    collector_name: str
    query: str
    nodes: list[EntityNode] = Field(default_factory=list)
    edges: list[RelationshipEdge] = Field(default_factory=list)
    evidence_items: list[EvidenceItem] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class Case(BaseModel):
    """Top-level OSINT Pilot investigative container."""

    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(default_factory=new_uuid)
    title: str
    target_query: str
    investigator: str = "lead-analyst"
    description: str = ""
    status: CaseStatus = CaseStatus.OPEN
    created_at_utc: datetime = Field(default_factory=utc_now)
    updated_at_utc: datetime = Field(default_factory=utc_now)
    nodes: list[EntityNode] = Field(default_factory=list)
    edges: list[RelationshipEdge] = Field(default_factory=list)
    personas: list[PersonaCluster] = Field(default_factory=list)
    evidence_ledger: list[EvidenceItem] = Field(default_factory=list)
    audit_log: list[AuditLogEntry] = Field(default_factory=list)
    ai_executive_brief: str = ""
