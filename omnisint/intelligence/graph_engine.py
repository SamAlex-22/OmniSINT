"""NetworkX knowledge graph, conflict-aware Louvain persona clustering, and hierarchy tree builder."""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any, Iterable, Sequence

from pydantic import BaseModel, ConfigDict, Field

from omnisint.core.models import (
    Case,
    EntityNode,
    EntityType,
    HierarchyTreeNode,
    PersonaCluster,
    RelationshipEdge,
    RelationType,
    new_uuid,
)
from omnisint.intelligence.entropy import (
    analyze_handle_entropy,
    compute_rarity_score,
    enrich_node_entropy,
    strip_email_domain,
)
from omnisint.intelligence.similarity import (
    SimilarityResult,
    avatar_hash_similarity,
    compare_handles,
)
from omnisint.intelligence.temporal import (
    TemporalCorrelationResult,
    TemporalProfile,
    build_temporal_profile,
    correlate_temporal_profiles,
    format_utc_offset,
)

try:
    import networkx as nx  # type: ignore[import-untyped]

    HAS_NETWORKX = True
except ImportError:  # pragma: no cover
    nx = None
    HAS_NETWORKX = False


# Canonical top-level categories in the Information Hierarchy Tree
CATEGORY_ORDER: tuple[str, ...] = (
    "Accounts",
    "Emails",
    "Infrastructure",
    "Organizations",
    "Repositories",
)

ENTITY_CATEGORY_MAP: dict[EntityType, str] = {
    EntityType.PERSON: "Accounts",
    EntityType.USERNAME: "Accounts",
    EntityType.SOCIAL_PROFILE: "Accounts",
    EntityType.AVATAR_HASH: "Accounts",
    EntityType.EMAIL: "Emails",
    EntityType.PHONE: "Emails",
    EntityType.PGP_KEY: "Emails",
    EntityType.SSH_KEY: "Emails",
    EntityType.DOMAIN: "Infrastructure",
    EntityType.SUBDOMAIN: "Infrastructure",
    EntityType.IP_ADDRESS: "Infrastructure",
    EntityType.CERTIFICATE: "Infrastructure",
    EntityType.URL: "Infrastructure",
    EntityType.THREAT_INDICATOR: "Infrastructure",
    EntityType.ORGANIZATION: "Organizations",
    EntityType.LOCATION: "Organizations",
    EntityType.REPOSITORY: "Repositories",
}

IDENTITY_ANCHOR_TYPES: frozenset[EntityType] = frozenset(
    {
        EntityType.PERSON,
        EntityType.USERNAME,
        EntityType.SOCIAL_PROFILE,
    }
)

HARD_SELECTOR_TYPES: frozenset[EntityType] = frozenset(
    {
        EntityType.EMAIL,
        EntityType.PGP_KEY,
        EntityType.SSH_KEY,
        EntityType.AVATAR_HASH,
        EntityType.PHONE,
    }
)


class DisambiguationConfig(BaseModel):
    """Configuration thresholds for mathematical entity disambiguation and Louvain clustering."""

    model_config = ConfigDict(extra="forbid")

    handle_similarity_threshold: float = Field(default=0.72, ge=0.0, le=1.0)
    common_handle_similarity_threshold: float = Field(default=0.88, ge=0.0, le=1.0)
    common_handle_rarity_cutoff: float = Field(default=0.40, ge=0.0, le=1.0)
    avatar_similarity_threshold: float = Field(default=0.85, ge=0.0, le=1.0)
    temporal_correlation_threshold: float = Field(default=0.70, ge=0.0, le=1.0)
    temporal_conflict_threshold: float = Field(default=0.35, ge=0.0, le=1.0)
    min_cluster_edge_weight: float = Field(default=0.50, ge=0.0, le=1.0)
    louvain_resolution: float = Field(default=1.0, gt=0.0)


class GraphDisambiguationReport(BaseModel):
    """Summary report produced by KnowledgeGraphEngine persona disambiguation."""

    model_config = ConfigDict(extra="forbid")

    total_nodes: int = Field(..., ge=0)
    total_edges: int = Field(..., ge=0)
    synthesized_edges_count: int = Field(..., ge=0)
    modularity_score: float = 0.0
    personas: list[PersonaCluster] = Field(default_factory=list)
    conflicts_detected: list[str] = Field(default_factory=list)


class _FallbackWeightedGraph:
    """Pure-Python NetworkX-compatible weighted undirected graph for offline environments."""

    def __init__(self) -> None:
        self._nodes: dict[str, dict[str, Any]] = {}
        self._adj: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)

    def clear(self) -> None:
        """Remove all nodes and edges from the graph."""
        self._nodes.clear()
        self._adj.clear()

    def add_node(self, node_for_adding: str, **attr: Any) -> None:
        """Add or update a single vertex with attributes."""
        if node_for_adding not in self._nodes:
            self._nodes[node_for_adding] = {}
        self._nodes[node_for_adding].update(attr)
        self._adj.setdefault(node_for_adding, {})

    def add_edge(self, u_of_edge: str, v_of_edge: str, **attr: Any) -> None:
        """Add or update an undirected weighted edge between u and v."""
        if u_of_edge == v_of_edge:
            return
        self.add_node(u_of_edge)
        self.add_node(v_of_edge)
        existing = self._adj[u_of_edge].get(v_of_edge, {})
        merged = dict(existing)
        merged.update(attr)
        self._adj[u_of_edge][v_of_edge] = merged
        self._adj[v_of_edge][u_of_edge] = merged

    def has_node(self, n: str) -> bool:
        """Return True if the graph contains node n."""
        return n in self._nodes

    def has_edge(self, u: str, v: str) -> bool:
        """Return True if an edge exists between u and v."""
        return v in self._adj.get(u, {})

    def get_edge_data(self, u: str, v: str, default: Any = None) -> dict[str, Any] | Any:
        """Return attribute dictionary for edge (u, v)."""
        return self._adj.get(u, {}).get(v, default)

    def neighbors(self, n: str) -> list[str]:
        """Return adjacent node IDs for node n."""
        return list(self._adj.get(n, {}).keys())

    def number_of_nodes(self) -> int:
        """Return total vertex count."""
        return len(self._nodes)

    def number_of_edges(self) -> int:
        """Return total undirected edge count."""
        return sum(len(nbrs) for nbrs in self._adj.values()) // 2

    def nodes(self, data: bool = False) -> list[Any]:
        """Return node IDs or (node_id, attr_dict) tuples."""
        if data:
            return [(nid, dict(attrs)) for nid, attrs in self._nodes.items()]
        return list(self._nodes.keys())

    def edges(self, data: bool = False) -> list[Any]:
        """Return undirected edges as (u, v) or (u, v, attr_dict) tuples."""
        result: list[Any] = []
        seen: set[tuple[str, str]] = set()
        for u in sorted(self._adj.keys()):
            for v in sorted(self._adj[u].keys()):
                pair = (u, v) if u <= v else (v, u)
                if pair in seen:
                    continue
                seen.add(pair)
                if data:
                    result.append((u, v, dict(self._adj[u][v])))
                else:
                    result.append((u, v))
        return result

    def degree(self, n: str, weight: str | None = None) -> float | int:
        """Return unweighted or weighted degree of node n."""
        nbrs = self._adj.get(n, {})
        if weight is None:
            return len(nbrs)
        return sum(float(edata.get(weight, 1.0)) for edata in nbrs.values())


def _parse_explicit_tz_offset(tz_str: str) -> float | None:
    """Parse an explicit timezone string such as 'UTC+05:30', '+05:30', or 'UTC-07:00' into hours."""
    cleaned = tz_str.strip().upper()
    if cleaned.startswith("UTC"):
        cleaned = cleaned[3:].strip()
    elif cleaned.startswith("GMT"):
        cleaned = cleaned[3:].strip()

    if not cleaned or cleaned == "Z":
        return 0.0

    sign = 1.0
    if cleaned.startswith("+"):
        cleaned = cleaned[1:]
    elif cleaned.startswith("-"):
        sign = -1.0
        cleaned = cleaned[1:]

    try:
        if ":" in cleaned:
            parts = cleaned.split(":", 1)
            hours = float(parts[0])
            minutes = float(parts[1]) / 60.0
            return sign * (hours + minutes)
        return sign * float(cleaned)
    except ValueError:
        return None


def _extract_node_temporal_profile(node: EntityNode) -> TemporalProfile | None:
    """Extract or synthesize a TemporalProfile from an EntityNode's attributes."""
    for key in ("timestamps", "commit_timestamps", "activity_timestamps", "post_timestamps"):
        raw_list = node.attributes.get(key)
        if isinstance(raw_list, Sequence) and not isinstance(raw_list, (str, bytes)) and len(raw_list) > 0:
            return build_temporal_profile([str(ts) for ts in raw_list])

    for tz_key in ("timezone", "inferred_timezone", "utc_offset"):
        raw_tz = node.attributes.get(tz_key)
        if isinstance(raw_tz, (int, float)):
            offset_hrs = float(raw_tz)
        elif isinstance(raw_tz, str) and raw_tz.strip():
            parsed = _parse_explicit_tz_offset(raw_tz)
            if parsed is None:
                continue
            offset_hrs = parsed
        else:
            continue

        # Synthesize a canonical afternoon circadian profile (13:00-17:00 local time)
        hist = [0.0] * 24
        peak_utc: list[int] = []
        weights = (0.15, 0.25, 0.30, 0.20, 0.10)
        for idx, local_hr in enumerate(range(13, 18)):
            utc_hr = int(round(local_hr - offset_hrs)) % 24
            hist[utc_hr] = round(hist[utc_hr] + weights[idx], 4)
            peak_utc.append(utc_hr)

        quiet_utc = [int(round(local_hr - offset_hrs)) % 24 for local_hr in range(1, 7)]
        return TemporalProfile(
            sample_count=5,
            hourly_histogram_utc=hist,
            inferred_utc_offset_hours=offset_hrs,
            inferred_timezone=format_utc_offset(offset_hrs),
            peak_active_hours_utc=peak_utc[:3],
            quiet_hours_utc=quiet_utc,
            weekend_ratio=0.2,
        )

    return None


def compute_modularity(
    nodes: Sequence[str],
    adjacency: dict[str, dict[str, float]],
    communities: Sequence[ set[str] | Sequence[str] ],
    resolution: float = 1.0,
) -> float:
    """Compute Newman-Girvan weighted modularity Q in [-0.5, 1.0] for a graph partition."""
    if not nodes or not communities:
        return 0.0

    degrees: dict[str, float] = {
        u: sum(adjacency.get(u, {}).values()) for u in nodes
    }
    two_m = sum(degrees.values())
    if two_m <= 1e-9:
        return 0.0

    q = 0.0
    for comm in communities:
        comm_set = set(comm)
        sigma_in = 0.0
        sigma_tot = 0.0
        for u in comm_set:
            sigma_tot += degrees.get(u, 0.0)
            for v, w in adjacency.get(u, {}).items():
                if v in comm_set:
                    sigma_in += w
        q += (sigma_in / two_m) - resolution * ((sigma_tot / two_m) ** 2)

    return round(max(-1.0, min(1.0, q)), 4)


def louvain_communities_deterministic(
    nodes: Sequence[str],
    adjacency: dict[str, dict[str, float]],
    conflict_pairs: set[tuple[str, str]] | None = None,
    resolution: float = 1.0,
) -> list[list[str]]:
    """Partition weighted graph nodes into communities via conflict-aware Louvain modularity optimization.

    Implements Blondel et al. (2008) local modularity maximization while respecting must-not-link
    conflict constraints (e.g., colliding namesakes operating in incompatible timezones or locations).
    """
    ordered_nodes = sorted(set(nodes))
    if not ordered_nodes:
        return []
    if len(ordered_nodes) == 1:
        return [[ordered_nodes[0]]]

    conflicts: dict[str, set[str]] = defaultdict(set)
    if conflict_pairs:
        for u, v in conflict_pairs:
            conflicts[u].add(v)
            conflicts[v].add(u)

    # Filter adjacency to ordered_nodes and compute node strengths k_i
    adj: dict[str, dict[str, float]] = {u: {} for u in ordered_nodes}
    for u in ordered_nodes:
        for v, w in adjacency.get(u, {}).items():
            if v in adj and u != v and w > 0.0 and v not in conflicts[u]:
                adj[u][v] = float(w)

    degrees: dict[str, float] = {u: sum(adj[u].values()) for u in ordered_nodes}
    two_m = sum(degrees.values())

    # If no positive edges exist, every node is its own singleton community
    if two_m <= 1e-9:
        return [[u] for u in ordered_nodes]

    # Initialize each node in its own community
    node_to_comm: dict[str, int] = {u: idx for idx, u in enumerate(ordered_nodes)}
    comm_members: dict[int, set[str]] = {idx: {u} for idx, u in enumerate(ordered_nodes)}
    comm_tot: dict[int, float] = {idx: degrees[u] for idx, u in enumerate(ordered_nodes)}

    improved = True
    max_passes = 25
    pass_num = 0

    while improved and pass_num < max_passes:
        improved = False
        pass_num += 1

        for u in ordered_nodes:
            current_comm = node_to_comm[u]
            k_u = degrees[u]
            if k_u <= 0.0:
                continue

            # Compute edge weights from u to neighboring communities
            comm_weights: dict[int, float] = defaultdict(float)
            for nbr, w in adj[u].items():
                comm_weights[node_to_comm[nbr]] += w

            # Remove u temporarily from its current community
            comm_members[current_comm].remove(u)
            comm_tot[current_comm] -= k_u
            k_u_in_current = comm_weights.get(current_comm, 0.0)

            best_comm = current_comm
            # Baseline gain of returning to current_comm
            best_gain = k_u_in_current - resolution * (comm_tot[current_comm] * k_u) / two_m

            # Evaluate candidate neighboring communities in deterministic order
            for target_comm in sorted(comm_weights.keys()):
                if target_comm == current_comm:
                    continue

                # Must-not-link check: forbid joining target_comm if any member conflicts with u
                if conflicts[u] and (conflicts[u] & comm_members[target_comm]):
                    continue

                k_u_in = comm_weights[target_comm]
                gain = k_u_in - resolution * (comm_tot[target_comm] * k_u) / two_m
                if gain > best_gain + 1e-9:
                    best_gain = gain
                    best_comm = target_comm

            # Place u into best_comm
            comm_members[best_comm].add(u)
            comm_tot[best_comm] += k_u
            node_to_comm[u] = best_comm
            if best_comm != current_comm:
                improved = True

    # Second-stage refinement: merge connected communities when modularity gain >= 0 and no conflicts exist
    active_comms = [cid for cid, members in sorted(comm_members.items()) if members]
    merged_any = True
    while merged_any and len(active_comms) > 1:
        merged_any = False
        for i, cid_a in enumerate(list(active_comms)):
            if not comm_members[cid_a]:
                continue
            for cid_b in list(active_comms[i + 1 :]):
                if not comm_members[cid_b]:
                    continue

                # Check conflict constraints between community A and community B
                has_conflict = any(
                    bool(conflicts[u] & comm_members[cid_b]) for u in comm_members[cid_a]
                )
                if has_conflict:
                    continue

                # Sum cross-community edge weight e_ab
                w_ab = sum(
                    w
                    for u in comm_members[cid_a]
                    for v, w in adj[u].items()
                    if v in comm_members[cid_b]
                )
                if w_ab <= 0.0:
                    continue

                # Modularity change from merging cid_a and cid_b:
                # delta_Q = (2 * w_ab / 2m) - 2 * resolution * (Sigma_tot_A * Sigma_tot_B) / (2m)^2
                # Also allow merging connected identity components when strong corroborating link exists (w_ab >= 0.75)
                delta_q = (w_ab / two_m) - resolution * (
                    (comm_tot[cid_a] * comm_tot[cid_b]) / (two_m * two_m)
                )
                if delta_q > -1e-6 or w_ab >= 0.75:
                    comm_members[cid_a].update(comm_members[cid_b])
                    comm_tot[cid_a] += comm_tot[cid_b]
                    for member in comm_members[cid_b]:
                        node_to_comm[member] = cid_a
                    comm_members[cid_b].clear()
                    comm_tot[cid_b] = 0.0
                    merged_any = True

        active_comms = [cid for cid, members in sorted(comm_members.items()) if members]

    clusters = [sorted(comm_members[cid]) for cid in active_comms if comm_members[cid]]
    clusters.sort(key=lambda c: (-len(c), c[0]))
    return clusters


class KnowledgeGraphEngine:
    """Graph intelligence engine for entity deduplication, Louvain persona clustering, and hierarchy tree synthesis."""

    def __init__(self, config: DisambiguationConfig | None = None) -> None:
        self.config = config or DisambiguationConfig()
        self._nodes: dict[str, EntityNode] = {}
        self._canonical_index: dict[str, str] = {}
        self._node_id_remap: dict[str, str] = {}
        self._edges: dict[str, RelationshipEdge] = {}
        self._edge_triple_index: dict[tuple[str, str, RelationType], str] = {}
        self._conflict_pairs: set[tuple[str, str]] = set()
        self._conflict_reasons: dict[tuple[str, str], str] = {}
        self._graph: Any = nx.Graph() if HAS_NETWORKX else _FallbackWeightedGraph()

    @property
    def graph(self) -> Any:
        """Return the underlying NetworkX (or NetworkX-compatible) weighted graph."""
        return self._graph

    @property
    def nodes(self) -> list[EntityNode]:
        """Return all deduplicated EntityNodes sorted by discovery timestamp and node_id."""
        return [self._nodes[nid] for nid in sorted(self._nodes.keys())]

    @property
    def edges(self) -> list[RelationshipEdge]:
        """Return all deduplicated RelationshipEdges sorted by edge_id."""
        return [self._edges[eid] for eid in sorted(self._edges.keys())]

    @classmethod
    def from_case(
        cls,
        case: Case,
        config: DisambiguationConfig | None = None,
    ) -> KnowledgeGraphEngine:
        """Construct a KnowledgeGraphEngine populated with a Case's nodes and edges."""
        engine = cls(config=config)
        engine.ingest_nodes_and_edges(case.nodes, case.edges)
        return engine

    def clear(self) -> None:
        """Reset all nodes, edges, conflicts, and underlying graph state."""
        self._nodes.clear()
        self._canonical_index.clear()
        self._node_id_remap.clear()
        self._edges.clear()
        self._edge_triple_index.clear()
        self._conflict_pairs.clear()
        self._conflict_reasons.clear()
        self._graph.clear()

    def get_node(self, node_id: str) -> EntityNode | None:
        """Lookup an EntityNode by its node_id (automatically resolving remapped IDs)."""
        canonical_id = self._node_id_remap.get(node_id, node_id)
        return self._nodes.get(canonical_id)

    def add_node(self, node: EntityNode) -> EntityNode:
        """Add or merge an EntityNode into the knowledge graph with automatic entropy enrichment."""
        working = node.model_copy(deep=True)
        if working.entropy_score == 0.0 and working.entity_type in (
            EntityType.PERSON,
            EntityType.USERNAME,
            EntityType.SOCIAL_PROFILE,
            EntityType.EMAIL,
        ):
            handle_val = str(working.attributes.get("username") or working.value)
            metrics = analyze_handle_entropy(handle_val)
            working.entropy_score = metrics.shannon_entropy
            working.rarity_score = metrics.rarity_score
        elif working.entropy_score == 0.0:
            enrich_node_entropy(working)

        ckey = working.canonical_key
        existing_id = self._canonical_index.get(ckey)
        if existing_id is None and working.node_id in self._nodes:
            existing_id = working.node_id

        if existing_id is not None and existing_id in self._nodes:
            existing = self._nodes[existing_id]
            self._node_id_remap[working.node_id] = existing.node_id
            merged_attrs = dict(existing.attributes)
            merged_attrs.update(working.attributes)
            existing.attributes = merged_attrs
            existing.evidence_ids = sorted(set(existing.evidence_ids) | set(working.evidence_ids))
            existing.confidence = max(existing.confidence, working.confidence)
            existing.entropy_score = max(existing.entropy_score, working.entropy_score)
            existing.rarity_score = max(existing.rarity_score, working.rarity_score)
            if working.cluster_id and not existing.cluster_id:
                existing.cluster_id = working.cluster_id
            self._sync_graph_node(existing)
            return existing

        self._nodes[working.node_id] = working
        self._canonical_index[ckey] = working.node_id
        self._node_id_remap[working.node_id] = working.node_id
        self._sync_graph_node(working)
        return working

    def add_edge(self, edge: RelationshipEdge) -> RelationshipEdge | None:
        """Add or merge a weighted RelationshipEdge into the knowledge graph."""
        src_id = self._node_id_remap.get(edge.source_node_id, edge.source_node_id)
        tgt_id = self._node_id_remap.get(edge.target_node_id, edge.target_node_id)
        if src_id == tgt_id:
            return None
        if src_id not in self._nodes or tgt_id not in self._nodes:
            return None

        triple = (src_id, tgt_id, edge.relation_type)
        reverse_triple = (tgt_id, src_id, edge.relation_type)
        symmetric_relations = {
            RelationType.SIMILAR_HANDLE,
            RelationType.SAME_AVATAR,
            RelationType.TEMPORAL_CORRELATION,
            RelationType.RESOLVED_SAME_PERSONA,
        }

        existing_eid = self._edge_triple_index.get(triple)
        if existing_eid is None and edge.relation_type in symmetric_relations:
            existing_eid = self._edge_triple_index.get(reverse_triple)

        if existing_eid is not None and existing_eid in self._edges:
            existing = self._edges[existing_eid]
            existing.weight = round(max(existing.weight, edge.weight), 4)
            existing.confidence = round(max(existing.confidence, edge.confidence), 4)
            existing.evidence_ids = sorted(set(existing.evidence_ids) | set(edge.evidence_ids))
            merged_attrs = dict(existing.attributes)
            merged_attrs.update(edge.attributes)
            existing.attributes = merged_attrs
            if edge.rationale and edge.rationale not in existing.rationale:
                existing.rationale = (
                    f"{existing.rationale}; {edge.rationale}"
                    if existing.rationale
                    else edge.rationale
                )
            self._sync_graph_edge(existing)
            return existing

        working = edge.model_copy(
            update={"source_node_id": src_id, "target_node_id": tgt_id},
            deep=True,
        )
        self._edges[working.edge_id] = working
        self._edge_triple_index[triple] = working.edge_id
        self._sync_graph_edge(working)
        return working

    def ingest_nodes_and_edges(
        self,
        nodes: Iterable[EntityNode],
        edges: Iterable[RelationshipEdge] = (),
    ) -> None:
        """Ingest batches of EntityNodes and RelationshipEdges into the engine."""
        for node in nodes:
            self.add_node(node)
        for edge in edges:
            self.add_edge(edge)

    def _sync_graph_node(self, node: EntityNode) -> None:
        """Synchronize an EntityNode with the underlying NetworkX graph."""
        self._graph.add_node(
            node.node_id,
            label=node.label,
            entity_type=node.entity_type.value,
            value=node.value,
            platform=node.platform,
            entropy_score=node.entropy_score,
            rarity_score=node.rarity_score,
            confidence=node.confidence,
            cluster_id=node.cluster_id,
        )

    def _sync_graph_edge(self, edge: RelationshipEdge) -> None:
        """Synchronize a RelationshipEdge with the underlying NetworkX graph."""
        u, v = edge.source_node_id, edge.target_node_id
        effective_weight = round(0.6 * edge.weight + 0.4 * edge.confidence, 4)
        existing_data = self._graph.get_edge_data(u, v) if self._graph.has_edge(u, v) else None
        if existing_data:
            best_weight = max(float(existing_data.get("weight", 0.0)), effective_weight)
            rel_types = set(existing_data.get("relation_types", []))
            rel_types.add(edge.relation_type.value)
            self._graph.add_edge(
                u,
                v,
                edge_id=edge.edge_id,
                relation_type=edge.relation_type.value,
                relation_types=sorted(rel_types),
                weight=best_weight,
                confidence=max(float(existing_data.get("confidence", 0.0)), edge.confidence),
            )
        else:
            self._graph.add_edge(
                u,
                v,
                edge_id=edge.edge_id,
                relation_type=edge.relation_type.value,
                relation_types=[edge.relation_type.value],
                weight=effective_weight,
                confidence=edge.confidence,
            )

    def _extract_avatar_hash(self, node: EntityNode) -> str | None:
        """Return a hex perceptual hash from node attributes or adjacent AVATAR_HASH nodes."""
        for attr_key in ("avatar_hash", "dhash", "phash", "avatar_dhash"):
            val = node.attributes.get(attr_key)
            if isinstance(val, str) and len(val.strip()) >= 8:
                return val.strip()

        for edge in self._edges.values():
            other_id: str | None = None
            if edge.source_node_id == node.node_id:
                other_id = edge.target_node_id
            elif edge.target_node_id == node.node_id:
                other_id = edge.source_node_id
            if other_id:
                other_node = self._nodes.get(other_id)
                if other_node and other_node.entity_type == EntityType.AVATAR_HASH:
                    return other_node.value.strip()
        return None

    def _extract_handle_string(self, node: EntityNode) -> str:
        """Return the primary handle or username string for an identity node."""
        for key in ("username", "handle", "login"):
            raw = node.attributes.get(key)
            if isinstance(raw, str) and raw.strip():
                return strip_email_domain(raw.strip())
        return strip_email_domain(node.value)

    def _record_conflict(self, node_a: EntityNode, node_b: EntityNode, reason: str) -> None:
        """Record a must-not-link conflict constraint between two identity nodes."""
        u, v = (
            (node_a.node_id, node_b.node_id)
            if node_a.node_id <= node_b.node_id
            else (node_b.node_id, node_a.node_id)
        )
        self._conflict_pairs.add((u, v))
        self._conflict_reasons[(u, v)] = (
            f"Separated {node_a.label} [{node_a.node_id}] and {node_b.label} [{node_b.node_id}]: {reason}"
        )

    def _has_shared_hard_selector(self, node_a: EntityNode, node_b: EntityNode) -> tuple[bool, str]:
        """Check whether two identity nodes share an explicit email, key, domain, or graph neighbor selector."""
        # 1. Check direct attribute matches (email, pgp_fingerprint, ssh_key, website/domain)
        for attr_key in ("email", "commit_email", "pgp_key", "ssh_key", "domain", "website"):
            val_a = node_a.attributes.get(attr_key)
            val_b = node_b.attributes.get(attr_key)
            if (
                isinstance(val_a, str)
                and isinstance(val_b, str)
                and val_a.strip()
                and val_a.strip().lower() == val_b.strip().lower()
            ):
                return True, f"shared {attr_key} '{val_a.strip()}'"

        # 2. Check shared high-specificity neighbor nodes in the graph
        neighbors_a: set[str] = set()
        neighbors_b: set[str] = set()
        for edge in self._edges.values():
            if edge.relation_type == RelationType.SIMILAR_HANDLE:
                continue
            if edge.source_node_id == node_a.node_id:
                neighbors_a.add(edge.target_node_id)
            elif edge.target_node_id == node_a.node_id:
                neighbors_a.add(edge.source_node_id)

            if edge.source_node_id == node_b.node_id:
                neighbors_b.add(edge.target_node_id)
            elif edge.target_node_id == node_b.node_id:
                neighbors_b.add(edge.source_node_id)

        shared_ids = neighbors_a & neighbors_b
        for shared_id in sorted(shared_ids):
            shared_node = self._nodes.get(shared_id)
            if shared_node and shared_node.entity_type in (
                HARD_SELECTOR_TYPES | {EntityType.REPOSITORY, EntityType.DOMAIN}
            ):
                return True, f"shared {shared_node.entity_type.value} {shared_node.label} [{shared_node.node_id}]"

        return False, ""

    def _check_location_conflict(self, node_a: EntityNode, node_b: EntityNode) -> str | None:
        """Return conflict explanation if two nodes specify incompatible physical locations."""
        loc_a = str(node_a.attributes.get("location") or "").strip()
        loc_b = str(node_b.attributes.get("location") or "").strip()
        if not loc_a or not loc_b:
            return None

        tokens_a = {t.strip().lower() for t in loc_a.replace(",", " ").split() if len(t.strip()) >= 2}
        tokens_b = {t.strip().lower() for t in loc_b.replace(",", " ").split() if len(t.strip()) >= 2}
        if tokens_a and tokens_b and not (tokens_a & tokens_b):
            return f"conflicting declared locations ('{loc_a}' vs '{loc_b}')"
        return None

    def synthesize_similarity_edges(self) -> list[RelationshipEdge]:
        """Evaluate pairwise mathematical similarity and synthesize disambiguation edges."""
        synthesized: list[RelationshipEdge] = []
        identity_nodes = [
            n
            for n in self.nodes
            if n.entity_type in IDENTITY_ANCHOR_TYPES
        ]

        # Precompute temporal profiles and avatar hashes for candidate nodes
        temporal_profiles: dict[str, TemporalProfile] = {}
        avatar_hashes: dict[str, str] = {}
        for node in identity_nodes:
            t_prof = _extract_node_temporal_profile(node)
            if t_prof is not None and t_prof.sample_count > 0:
                temporal_profiles[node.node_id] = t_prof
            av_hash = self._extract_avatar_hash(node)
            if av_hash:
                avatar_hashes[node.node_id] = av_hash

        # Also compare standalone AVATAR_HASH nodes in the graph
        avatar_nodes = [n for n in self.nodes if n.entity_type == EntityType.AVATAR_HASH]
        for i, av_a in enumerate(avatar_nodes):
            for av_b in avatar_nodes[i + 1 :]:
                try:
                    av_sim = avatar_hash_similarity(av_a.value, av_b.value)
                except ValueError:
                    continue
                if av_sim >= self.config.avatar_similarity_threshold:
                    edge = self.add_edge(
                        RelationshipEdge(
                            source_node_id=av_a.node_id,
                            target_node_id=av_b.node_id,
                            relation_type=RelationType.SAME_AVATAR,
                            weight=av_sim,
                            confidence=av_sim,
                            rationale=f"Perceptual avatar dHash similarity={av_sim:.2f}",
                            evidence_ids=sorted(set(av_a.evidence_ids) | set(av_b.evidence_ids)),
                        )
                    )
                    if edge:
                        synthesized.append(edge)

        # Pairwise comparison across identity/handle nodes
        for i, node_a in enumerate(identity_nodes):
            handle_a = self._extract_handle_string(node_a)
            for node_b in identity_nodes[i + 1 :]:
                handle_b = self._extract_handle_string(node_b)
                combined_evidence = sorted(set(node_a.evidence_ids) | set(node_b.evidence_ids))

                av_hash_a = avatar_hashes.get(node_a.node_id)
                av_hash_b = avatar_hashes.get(node_b.node_id)
                sim_res: SimilarityResult = compare_handles(
                    handle_a,
                    handle_b,
                    avatar_hash_1=av_hash_a,
                    avatar_hash_2=av_hash_b,
                )

                # Evaluate temporal correlation if both nodes have temporal profiles
                temp_corr: TemporalCorrelationResult | None = None
                if node_a.node_id in temporal_profiles and node_b.node_id in temporal_profiles:
                    temp_corr = correlate_temporal_profiles(
                        temporal_profiles[node_a.node_id],
                        temporal_profiles[node_b.node_id],
                    )

                has_hard_selector, selector_reason = self._has_shared_hard_selector(node_a, node_b)
                loc_conflict = self._check_location_conflict(node_a, node_b)

                # Check for strong temporal/timezone conflict (e.g., UTC+05:30 vs UTC-07:00)
                has_temporal_conflict = bool(
                    temp_corr is not None
                    and (
                        temp_corr.composite_temporal_score < self.config.temporal_conflict_threshold
                        or temp_corr.timezone_alignment_score <= 0.50
                    )
                )

                # Check for divergent avatar on low-rarity handles
                has_avatar_conflict = bool(
                    sim_res.avatar_similarity is not None
                    and sim_res.avatar_similarity < 0.45
                )

                is_common_handle_pair = (
                    sim_res.rarity_weight < self.config.common_handle_rarity_cutoff
                )

                # Namesake Separation Rule:
                # 1. If two handles have incompatible circadian/timezone profiles and no shared hard selector,
                #    mark them as a conflict pair and do not link them.
                if has_temporal_conflict and not has_hard_selector:
                    assert temp_corr is not None
                    conflict_msg = (
                        f"divergent circadian/timezone profiles ({temp_corr.inferred_timezone_a} vs "
                        f"{temp_corr.inferred_timezone_b}, score={temp_corr.composite_temporal_score:.2f})"
                    )
                    if loc_conflict:
                        conflict_msg = f"{conflict_msg}; {loc_conflict}"
                    self._record_conflict(node_a, node_b, conflict_msg)
                    continue

                # 2. If two common/high-collision handles have conflicting locations or divergent avatars
                #    without a shared hard selector, separate them as distinct namesakes.
                if is_common_handle_pair and not has_hard_selector:
                    if loc_conflict:
                        self._record_conflict(
                            node_a,
                            node_b,
                            f"high-collision handle '{handle_a}' (rarity={sim_res.rarity_weight:.2f}) with {loc_conflict}",
                        )
                        continue
                    if has_avatar_conflict:
                        self._record_conflict(
                            node_a,
                            node_b,
                            f"high-collision handle '{handle_a}' with divergent avatar dHash ({sim_res.avatar_similarity:.2f})",
                        )
                        continue

                # Emit SAME_AVATAR edge when perceptual hashes align
                if (
                    sim_res.avatar_similarity is not None
                    and sim_res.avatar_similarity >= self.config.avatar_similarity_threshold
                ):
                    av_edge = self.add_edge(
                        RelationshipEdge(
                            source_node_id=node_a.node_id,
                            target_node_id=node_b.node_id,
                            relation_type=RelationType.SAME_AVATAR,
                            weight=sim_res.avatar_similarity,
                            confidence=sim_res.avatar_similarity,
                            rationale=f"Matching perceptual avatar dHash (similarity={sim_res.avatar_similarity:.2f})",
                            evidence_ids=combined_evidence,
                        )
                    )
                    if av_edge:
                        synthesized.append(av_edge)

                # Emit TEMPORAL_CORRELATION edge when circadian profiles align
                if (
                    temp_corr is not None
                    and temp_corr.composite_temporal_score >= self.config.temporal_correlation_threshold
                    and (
                        sim_res.composite_score >= 0.55
                        or has_hard_selector
                        or (
                            sim_res.avatar_similarity is not None
                            and sim_res.avatar_similarity >= self.config.avatar_similarity_threshold
                        )
                    )
                ):
                    t_edge = self.add_edge(
                        RelationshipEdge(
                            source_node_id=node_a.node_id,
                            target_node_id=node_b.node_id,
                            relation_type=RelationType.TEMPORAL_CORRELATION,
                            weight=temp_corr.composite_temporal_score,
                            confidence=temp_corr.composite_temporal_score,
                            rationale=temp_corr.rationale,
                            evidence_ids=combined_evidence,
                        )
                    )
                    if t_edge:
                        synthesized.append(t_edge)

                # Emit RESOLVED_SAME_PERSONA if corroborated by a hard selector
                if has_hard_selector:
                    res_edge = self.add_edge(
                        RelationshipEdge(
                            source_node_id=node_a.node_id,
                            target_node_id=node_b.node_id,
                            relation_type=RelationType.RESOLVED_SAME_PERSONA,
                            weight=0.95,
                            confidence=0.95,
                            rationale=f"Corroborated by {selector_reason}",
                            evidence_ids=combined_evidence,
                        )
                    )
                    if res_edge:
                        synthesized.append(res_edge)

                # Emit SIMILAR_HANDLE edge if handle similarity meets rarity-adjusted criteria
                has_corroboration = bool(
                    has_hard_selector
                    or (
                        sim_res.avatar_similarity is not None
                        and sim_res.avatar_similarity >= self.config.avatar_similarity_threshold
                    )
                    or (
                        temp_corr is not None
                        and temp_corr.composite_temporal_score >= self.config.temporal_correlation_threshold
                    )
                )

                # Common names ("john_smith") require corroboration (avatar, temporal, or shared selector)
                # across different platforms to avoid false-positive namesake merges.
                if is_common_handle_pair and not has_corroboration:
                    if handle_a.lower() == handle_b.lower():
                        self._record_conflict(
                            node_a,
                            node_b,
                            f"uncorroborated identical common handle '{handle_a}' (rarity={sim_res.rarity_weight:.2f} < "
                            f"{self.config.common_handle_rarity_cutoff:.2f})",
                        )
                    continue

                effective_threshold = (
                    self.config.handle_similarity_threshold
                    if not is_common_handle_pair or has_corroboration
                    else self.config.common_handle_similarity_threshold
                )

                effective_score = sim_res.composite_score
                if has_corroboration and sim_res.composite_score >= 0.60:
                    effective_score = min(1.0, round(sim_res.composite_score + 0.12, 4))

                if effective_score >= effective_threshold:
                    sim_edge = self.add_edge(
                        RelationshipEdge(
                            source_node_id=node_a.node_id,
                            target_node_id=node_b.node_id,
                            relation_type=RelationType.SIMILAR_HANDLE,
                            weight=effective_score,
                            confidence=effective_score,
                            rationale=sim_res.rationale,
                            evidence_ids=combined_evidence,
                            attributes={
                                "jaro_winkler": sim_res.jaro_winkler,
                                "levenshtein": sim_res.levenshtein,
                                "token_swap": sim_res.token_swap,
                                "rarity_weight": sim_res.rarity_weight,
                            },
                        )
                    )
                    if sim_edge:
                        synthesized.append(sim_edge)

        return synthesized

    def _build_clustering_adjacency(self) -> dict[str, dict[str, float]]:
        """Construct undirected weighted adjacency matrix for community detection."""
        adj: dict[str, dict[str, float]] = {nid: defaultdict(float) for nid in self._nodes}

        # Direct edges above min_cluster_edge_weight
        for edge in self._edges.values():
            u, v = edge.source_node_id, edge.target_node_id
            pair = (u, v) if u <= v else (v, u)
            if pair in self._conflict_pairs:
                continue

            eff_w = round(0.6 * edge.weight + 0.4 * edge.confidence, 4)
            if eff_w < self.config.min_cluster_edge_weight:
                continue

            if eff_w > adj[u].get(v, 0.0):
                adj[u][v] = eff_w
                adj[v][u] = eff_w

        # Induce direct identity-to-identity affinity across shared high-specificity selectors
        # (e.g. two accounts connected to the same EMAIL, PGP_KEY, SSH_KEY, AVATAR_HASH, or REPOSITORY)
        selector_types = HARD_SELECTOR_TYPES | {EntityType.REPOSITORY, EntityType.DOMAIN}
        for sel_node in self._nodes.values():
            if sel_node.entity_type not in selector_types:
                continue
            connected_identities = [
                nbr_id
                for nbr_id in adj.get(sel_node.node_id, {})
                if self._nodes[nbr_id].entity_type in IDENTITY_ANCHOR_TYPES
            ]
            for i, id_a in enumerate(connected_identities):
                for id_b in connected_identities[i + 1 :]:
                    pair = (id_a, id_b) if id_a <= id_b else (id_b, id_a)
                    if pair in self._conflict_pairs:
                        continue
                    induced_w = 0.90
                    if induced_w > adj[id_a].get(id_b, 0.0):
                        adj[id_a][id_b] = induced_w
                        adj[id_b][id_a] = induced_w

        return {k: dict(v) for k, v in adj.items()}

    def detect_persona_clusters(self) -> tuple[list[PersonaCluster], float]:
        """Partition the knowledge graph into disambiguated PersonaClusters and build HierarchyTrees."""
        if not self._nodes:
            return [], 0.0

        full_adj = self._build_clustering_adjacency()
        identity_ids = [
            nid
            for nid, node in sorted(self._nodes.items())
            if node.entity_type in IDENTITY_ANCHOR_TYPES
        ]

        if identity_ids:
            # Stage 1: Conflict-aware Louvain community detection on the Identity Core
            identity_adj: dict[str, dict[str, float]] = {
                u: {v: w for v, w in full_adj.get(u, {}).items() if v in identity_ids}
                for u in identity_ids
            }
            identity_communities = louvain_communities_deterministic(
                nodes=identity_ids,
                adjacency=identity_adj,
                conflict_pairs=self._conflict_pairs,
                resolution=self.config.louvain_resolution,
            )

            # Map each identity node to its community index
            comm_groups: list[set[str]] = [set(comm) for comm in identity_communities]
            node_to_group: dict[str, int] = {}
            for idx, group in enumerate(comm_groups):
                for nid in group:
                    node_to_group[nid] = idx

            # Stage 2: Multi-hop weighted propagation to attach non-identity observables
            # (Emails, Repos, Domains, Subdomains, IPs, Keys, Avatars, Orgs) to their owning PersonaCluster
            unassigned = [nid for nid in sorted(self._nodes.keys()) if nid not in node_to_group]
            for obs_id in unassigned:
                best_group: int | None = None
                best_score = -1.0

                # BFS from obs_id over full_adj tracking path product weight
                visited: dict[str, float] = {obs_id: 1.0}
                queue: deque[tuple[str, float]] = deque([(obs_id, 1.0)])
                while queue:
                    curr_id, curr_score = queue.popleft()
                    if curr_id in node_to_group and curr_id != obs_id:
                        grp = node_to_group[curr_id]
                        if curr_score > best_score:
                            best_score = curr_score
                            best_group = grp
                        continue

                    for nbr_id, edge_w in full_adj.get(curr_id, {}).items():
                        next_score = round(curr_score * edge_w, 4)
                        if next_score > visited.get(nbr_id, 0.0) and next_score >= 0.15:
                            visited[nbr_id] = next_score
                            queue.append((nbr_id, next_score))

                if best_group is not None:
                    comm_groups[best_group].add(obs_id)
                    node_to_group[obs_id] = best_group

            # Any remaining disconnected infrastructure/observable nodes form their own Louvain clusters
            still_unassigned = [nid for nid in sorted(self._nodes.keys()) if nid not in node_to_group]
            if still_unassigned:
                rem_adj = {
                    u: {v: w for v, w in full_adj.get(u, {}).items() if v in still_unassigned}
                    for u in still_unassigned
                }
                rem_comms = louvain_communities_deterministic(
                    nodes=still_unassigned,
                    adjacency=rem_adj,
                    conflict_pairs=self._conflict_pairs,
                    resolution=self.config.louvain_resolution,
                )
                for r_comm in rem_comms:
                    comm_groups.append(set(r_comm))

            raw_communities = [sorted(g) for g in comm_groups if g]
        else:
            # Infrastructure-only graph without identity nodes
            raw_communities = louvain_communities_deterministic(
                nodes=list(self._nodes.keys()),
                adjacency=full_adj,
                conflict_pairs=self._conflict_pairs,
                resolution=self.config.louvain_resolution,
            )

        modularity_q = compute_modularity(
            nodes=list(self._nodes.keys()),
            adjacency=full_adj,
            communities=raw_communities,
            resolution=self.config.louvain_resolution,
        )

        # Sort communities deterministically: largest identity-bearing clusters first
        def _cluster_sort_key(member_ids: list[str]) -> tuple[int, int, float, str]:
            has_identity = any(
                self._nodes[nid].entity_type in IDENTITY_ANCHOR_TYPES for nid in member_ids
            )
            max_rarity = max((self._nodes[nid].rarity_score for nid in member_ids), default=0.0)
            return (1 if has_identity else 0, len(member_ids), round(max_rarity, 3), member_ids[0])

        raw_communities.sort(key=_cluster_sort_key, reverse=True)

        personas: list[PersonaCluster] = []
        for idx, member_ids in enumerate(raw_communities, start=1):
            cluster_id = f"persona-cluster-{idx:02d}"
            member_set = set(member_ids)
            member_nodes = [self._nodes[nid] for nid in member_ids]

            for m_node in member_nodes:
                m_node.cluster_id = cluster_id
                self._sync_graph_node(m_node)

            internal_edges = [
                e
                for e in self._edges.values()
                if e.source_node_id in member_set and e.target_node_id in member_set
            ]

            persona = self._construct_persona_cluster(
                index=idx,
                cluster_id=cluster_id,
                member_nodes=member_nodes,
                internal_edges=internal_edges,
            )
            personas.append(persona)

        return personas, modularity_q

    def _select_primary_node(self, member_nodes: Sequence[EntityNode]) -> EntityNode:
        """Select the anchor EntityNode that best represents a PersonaCluster."""
        priority_order = {
            EntityType.PERSON: 5,
            EntityType.USERNAME: 4,
            EntityType.SOCIAL_PROFILE: 4,
            EntityType.EMAIL: 3,
            EntityType.DOMAIN: 2,
            EntityType.ORGANIZATION: 2,
        }
        return max(
            member_nodes,
            key=lambda n: (
                priority_order.get(n.entity_type, 1),
                round(n.rarity_score, 4),
                round(n.confidence, 4),
                -len(n.value),
            ),
        )

    def _infer_cluster_timezone(self, member_nodes: Sequence[EntityNode]) -> str | None:
        """Infer the dominant UTC timezone for a PersonaCluster from member timestamps or attributes."""
        all_timestamps: list[str] = []
        explicit_tzs: list[str] = []

        for node in member_nodes:
            for ts_key in ("timestamps", "commit_timestamps", "activity_timestamps", "post_timestamps"):
                raw_ts = node.attributes.get(ts_key)
                if isinstance(raw_ts, Sequence) and not isinstance(raw_ts, (str, bytes)):
                    all_timestamps.extend(str(t) for t in raw_ts)
            for tz_key in ("timezone", "inferred_timezone"):
                raw_tz = node.attributes.get(tz_key)
                if isinstance(raw_tz, str) and raw_tz.strip():
                    parsed = _parse_explicit_tz_offset(raw_tz)
                    if parsed is not None:
                        explicit_tzs.append(format_utc_offset(parsed))

        if all_timestamps:
            prof = build_temporal_profile(all_timestamps)
            return prof.inferred_timezone
        if explicit_tzs:
            return explicit_tzs[0]
        return None

    def _construct_persona_cluster(
        self,
        index: int,
        cluster_id: str,
        member_nodes: Sequence[EntityNode],
        internal_edges: Sequence[RelationshipEdge],
    ) -> PersonaCluster:
        """Build a fully populated PersonaCluster with disambiguation reasons, pivots, and HierarchyTree."""
        primary_node = self._select_primary_node(member_nodes)
        primary_handle = self._extract_handle_string(primary_node)
        inferred_tz = self._infer_cluster_timezone(member_nodes)

        # Compute average Shannon entropy across identity/handle/email nodes in the cluster
        identity_members = [
            n
            for n in member_nodes
            if n.entity_type in IDENTITY_ANCHOR_TYPES | {EntityType.EMAIL}
        ]
        target_for_entropy = identity_members if identity_members else list(member_nodes)
        avg_entropy = round(
            sum(n.entropy_score for n in target_for_entropy) / max(1, len(target_for_entropy)),
            4,
        )
        avg_rarity = round(
            sum(n.rarity_score for n in target_for_entropy) / max(1, len(target_for_entropy)),
            4,
        )

        # Compute cluster confidence score combining node confidence, edge confidence, and multi-modal corroboration
        avg_node_conf = sum(n.confidence for n in member_nodes) / max(1, len(member_nodes))
        if internal_edges:
            avg_edge_conf = sum(e.confidence for e in internal_edges) / len(internal_edges)
            corroboration_bonus = min(0.12, 0.03 * len(internal_edges))
            confidence_score = min(
                0.99,
                round(0.45 * avg_node_conf + 0.40 * avg_edge_conf + 0.15 * avg_rarity + corroboration_bonus, 4),
            )
        else:
            confidence_score = round(0.75 * avg_node_conf + 0.25 * avg_rarity, 4)

        # Collect all evidence IDs across nodes and internal edges
        evidence_ids = sorted(
            {ev_id for n in member_nodes for ev_id in n.evidence_ids}
            | {ev_id for e in internal_edges for ev_id in e.evidence_ids}
        )

        # Disambiguated persona label (include timezone and/or location when available)
        qualifiers: list[str] = []
        if inferred_tz:
            qualifiers.append(inferred_tz)
        for node in member_nodes:
            loc = node.attributes.get("location")
            if isinstance(loc, str) and loc.strip():
                qualifiers.append(loc.strip())
                break
        qualifier_str = f" ({', '.join(qualifiers)})" if qualifiers else ""
        persona_label = f"Persona #{index}: {primary_handle}{qualifier_str}"

        # Construct citation-backed disambiguation reasons
        reasons: list[str] = [
            f"Anchored by primary entity {primary_node.label} [{primary_node.node_id}] "
            f"(entropy={primary_node.entropy_score:.2f} bits, rarity={primary_node.rarity_score:.2f})."
        ]
        for edge in internal_edges:
            if edge.relation_type in (
                RelationType.SIMILAR_HANDLE,
                RelationType.SAME_AVATAR,
                RelationType.TEMPORAL_CORRELATION,
                RelationType.RESOLVED_SAME_PERSONA,
            ):
                src_node = self._nodes.get(edge.source_node_id)
                tgt_node = self._nodes.get(edge.target_node_id)
                if src_node and tgt_node:
                    ev_cite = f" (evidence: {', '.join(edge.evidence_ids)})" if edge.evidence_ids else ""
                    reasons.append(
                        f"[{edge.relation_type.value}] {src_node.label} [{src_node.node_id}] <-> "
                        f"{tgt_node.label} [{tgt_node.node_id}] (confidence={edge.confidence:.2f}: "
                        f"{edge.rationale}){ev_cite}"
                    )

        # Include conflict explanations where any member of this cluster was separated from a colliding namesake
        member_id_set = {n.node_id for n in member_nodes}
        for (u, v), conflict_reason in sorted(self._conflict_reasons.items()):
            if u in member_id_set or v in member_id_set:
                reasons.append(conflict_reason)

        # Generate intelligent next-step OSINT pivot recommendations
        pivots = self._recommend_pivots(member_nodes, avg_rarity, inferred_tz)

        # Build the recursive Information Hierarchy Tree
        hierarchy_tree = self.build_hierarchy_tree(
            cluster_id=cluster_id,
            persona_label=persona_label,
            primary_handle=primary_handle,
            member_nodes=member_nodes,
            internal_edges=internal_edges,
            confidence_score=confidence_score,
            avg_entropy=avg_entropy,
            inferred_timezone=inferred_tz,
            evidence_ids=evidence_ids,
        )

        summary = (
            f"{persona_label} comprising {len(member_nodes)} entities and "
            f"{len(internal_edges)} corroborating links (confidence={confidence_score:.2f}, "
            f"avg_entropy={avg_entropy:.2f} bits)."
        )

        return PersonaCluster(
            cluster_id=cluster_id,
            persona_label=persona_label,
            primary_handle=primary_handle,
            confidence_score=confidence_score,
            avg_handle_entropy=avg_entropy,
            inferred_timezone=inferred_tz,
            summary=summary,
            node_ids=[n.node_id for n in member_nodes],
            evidence_ids=evidence_ids,
            disambiguation_reasons=reasons,
            recommended_pivots=pivots,
            hierarchy_tree=hierarchy_tree,
        )

    def _recommend_pivots(
        self,
        member_nodes: Sequence[EntityNode],
        avg_rarity: float,
        inferred_timezone: str | None,
    ) -> list[str]:
        """Generate context-aware investigative pivot actions for a PersonaCluster."""
        pivots: list[str] = []
        types_present = {n.entity_type for n in member_nodes}

        for node in member_nodes:
            if node.entity_type == EntityType.EMAIL:
                pivots.append(
                    f"Pivot on email '{node.value}' [{node.node_id}] via Git commit history, PGP keyservers, and domain WHOIS/RDAP."
                )
            elif node.entity_type == EntityType.DOMAIN:
                pivots.append(
                    f"Pivot on domain '{node.value}' [{node.node_id}] via crt.sh Certificate Transparency and passive DNS."
                )
            elif node.entity_type in (EntityType.PGP_KEY, EntityType.SSH_KEY):
                pivots.append(
                    f"Cross-correlate cryptographic key '{node.value}' [{node.node_id}] across GitHub/GitLab key endpoints."
                )

        if EntityType.EMAIL not in types_present:
            pivots.append(
                "Extract commit author emails or public bio contact selectors to anchor handle identity with a hard selector."
            )
        if avg_rarity < self.config.common_handle_rarity_cutoff:
            pivots.append(
                "High-collision handle detected: acquire profile avatars (dHash) and activity timestamps to prevent namesake contamination."
            )
        if inferred_timezone is None:
            pivots.append(
                "Collect commit or post timestamps to establish circadian active-hour fingerprint and UTC offset."
            )

        return pivots[:5]

    def build_hierarchy_tree(
        self,
        cluster_id: str,
        persona_label: str,
        primary_handle: str,
        member_nodes: Sequence[EntityNode],
        internal_edges: Sequence[RelationshipEdge],
        confidence_score: float,
        avg_entropy: float,
        inferred_timezone: str | None = None,
        evidence_ids: list[str] | None = None,
    ) -> HierarchyTreeNode:
        """Construct the recursive Information Hierarchy Tree for a resolved PersonaCluster.

        Structure:
            Root Persona
            ├── Accounts (PERSON, USERNAME, SOCIAL_PROFILE -> nested AVATAR_HASH)
            ├── Emails (EMAIL, PHONE, PGP_KEY, SSH_KEY)
            ├── Infrastructure (DOMAIN -> nested SUBDOMAIN -> nested IP_ADDRESS / CERTIFICATE / URL)
            ├── Organizations (ORGANIZATION, LOCATION)
            └── Repositories (REPOSITORY)
        """
        member_by_id: dict[str, EntityNode] = {n.node_id: n for n in member_nodes}
        grouped: dict[str, list[EntityNode]] = defaultdict(list)
        for node in member_nodes:
            cat = ENTITY_CATEGORY_MAP.get(node.entity_type, "Accounts")
            grouped[cat].append(node)

        # Identify parent->child nesting relationships within categories (e.g., DOMAIN -> SUBDOMAIN -> IP_ADDRESS,
        # and SOCIAL_PROFILE/USERNAME -> AVATAR_HASH)
        nested_children_map: dict[str, list[EntityNode]] = defaultdict(list)
        nested_child_ids: set[str] = set()

        for edge in internal_edges:
            src = member_by_id.get(edge.source_node_id)
            tgt = member_by_id.get(edge.target_node_id)
            if not src or not tgt:
                continue

            # Account -> Avatar nesting
            if (
                src.entity_type in (EntityType.SOCIAL_PROFILE, EntityType.USERNAME, EntityType.PERSON)
                and tgt.entity_type == EntityType.AVATAR_HASH
                and tgt.node_id not in nested_child_ids
            ):
                nested_children_map[src.node_id].append(tgt)
                nested_child_ids.add(tgt.node_id)
            elif (
                tgt.entity_type in (EntityType.SOCIAL_PROFILE, EntityType.USERNAME, EntityType.PERSON)
                and src.entity_type == EntityType.AVATAR_HASH
                and src.node_id not in nested_child_ids
            ):
                nested_children_map[tgt.node_id].append(src)
                nested_child_ids.add(src.node_id)

            # Domain -> Subdomain / Certificate / IP nesting
            elif (
                src.entity_type == EntityType.DOMAIN
                and tgt.entity_type in (EntityType.SUBDOMAIN, EntityType.CERTIFICATE, EntityType.IP_ADDRESS)
                and tgt.node_id not in nested_child_ids
            ):
                nested_children_map[src.node_id].append(tgt)
                nested_child_ids.add(tgt.node_id)
            elif (
                src.entity_type == EntityType.SUBDOMAIN
                and tgt.entity_type in (EntityType.IP_ADDRESS, EntityType.CERTIFICATE)
                and tgt.node_id not in nested_child_ids
            ):
                nested_children_map[src.node_id].append(tgt)
                nested_child_ids.add(tgt.node_id)

        def _to_tree_node(entity: EntityNode, category_name: str, visited: set[str]) -> HierarchyTreeNode:
            visited.add(entity.node_id)
            child_entities = [
                ch for ch in nested_children_map.get(entity.node_id, []) if ch.node_id not in visited
            ]
            child_tree_nodes = [
                _to_tree_node(ch, category_name, visited)
                for ch in sorted(child_entities, key=lambda x: (x.entity_type.value, x.label))
            ]
            meta = dict(entity.attributes)
            if entity.platform:
                meta["platform"] = entity.platform
            meta["rarity_score"] = entity.rarity_score
            meta["value"] = entity.value

            return HierarchyTreeNode(
                node_id=entity.node_id,
                label=entity.label,
                category=category_name,
                entity_type=entity.entity_type,
                confidence=entity.confidence,
                entropy_score=entity.entropy_score,
                evidence_ids=list(entity.evidence_ids),
                metadata=meta,
                children=child_tree_nodes,
            )

        category_branches: list[HierarchyTreeNode] = []
        for category_name in CATEGORY_ORDER:
            cat_entities = grouped.get(category_name, [])
            if not cat_entities:
                continue

            visited_in_cat: set[str] = set()
            top_entities = [e for e in cat_entities if e.node_id not in nested_child_ids]
            if not top_entities:
                top_entities = list(cat_entities)

            leaf_nodes = [
                _to_tree_node(ent, category_name, visited_in_cat)
                for ent in sorted(
                    top_entities,
                    key=lambda x: (-x.confidence, -x.rarity_score, x.label),
                )
            ]
            # Catch any unvisited entities in this category
            for ent in cat_entities:
                if ent.node_id not in visited_in_cat:
                    leaf_nodes.append(_to_tree_node(ent, category_name, visited_in_cat))

            cat_conf = round(
                sum(n.confidence for n in cat_entities) / max(1, len(cat_entities)),
                4,
            )
            cat_entropy = round(
                sum(n.entropy_score for n in cat_entities) / max(1, len(cat_entities)),
                4,
            )
            cat_evidence = sorted({ev for n in cat_entities for ev in n.evidence_ids})

            category_branches.append(
                HierarchyTreeNode(
                    node_id=f"cat:{cluster_id}:{category_name.lower()}",
                    label=f"{category_name} ({len(cat_entities)})",
                    category=category_name,
                    entity_type=category_name.lower(),
                    confidence=cat_conf,
                    entropy_score=cat_entropy,
                    evidence_ids=cat_evidence,
                    metadata={"count": len(cat_entities)},
                    children=leaf_nodes,
                )
            )

        return HierarchyTreeNode(
            node_id=f"root:{cluster_id}",
            label=persona_label,
            category="Root Persona",
            entity_type=EntityType.PERSON,
            confidence=confidence_score,
            entropy_score=avg_entropy,
            evidence_ids=evidence_ids or [],
            metadata={
                "cluster_id": cluster_id,
                "primary_handle": primary_handle,
                "inferred_timezone": inferred_timezone,
                "total_entities": len(member_nodes),
            },
            children=category_branches,
        )

    def resolve_personas(self, synthesize_edges: bool = True) -> GraphDisambiguationReport:
        """Run full mathematical similarity edge synthesis, Louvain clustering, and hierarchy tree generation."""
        synthesized: list[RelationshipEdge] = []
        if synthesize_edges:
            synthesized = self.synthesize_similarity_edges()

        personas, modularity_q = self.detect_persona_clusters()
        conflicts = [
            self._conflict_reasons[pair]
            for pair in sorted(self._conflict_reasons.keys())
        ]

        return GraphDisambiguationReport(
            total_nodes=len(self._nodes),
            total_edges=len(self._edges),
            synthesized_edges_count=len(synthesized),
            modularity_score=modularity_q,
            personas=personas,
            conflicts_detected=conflicts,
        )

    def apply_to_case(self, case: Case, synthesize_edges: bool = True) -> GraphDisambiguationReport:
        """Ingest a Case, resolve personas, and update case.nodes, case.edges, and case.personas in-place."""
        self.clear()
        self.ingest_nodes_and_edges(case.nodes, case.edges)
        report = self.resolve_personas(synthesize_edges=synthesize_edges)
        case.nodes = self.nodes
        case.edges = self.edges
        case.personas = report.personas
        return report

    def to_cytoscape_elements(
        self,
        personas: Sequence[PersonaCluster] | None = None,
    ) -> dict[str, list[dict[str, Any]]]:
        """Export graph nodes, edges, and optional persona cluster compounds for Cytoscape.js rendering."""
        cy_nodes: list[dict[str, Any]] = []
        cy_edges: list[dict[str, Any]] = []

        if personas:
            for p in personas:
                cy_nodes.append(
                    {
                        "data": {
                            "id": p.cluster_id,
                            "label": p.persona_label,
                            "type": "persona_cluster",
                            "confidence": p.confidence_score,
                            "inferred_timezone": p.inferred_timezone,
                        }
                    }
                )

        for node in self.nodes:
            cy_nodes.append(
                {
                    "data": {
                        "id": node.node_id,
                        "label": node.label,
                        "value": node.value,
                        "entity_type": node.entity_type.value,
                        "category": ENTITY_CATEGORY_MAP.get(node.entity_type, "Accounts"),
                        "platform": node.platform,
                        "entropy_score": node.entropy_score,
                        "rarity_score": node.rarity_score,
                        "confidence": node.confidence,
                        "parent": node.cluster_id,
                        "evidence_ids": node.evidence_ids,
                    }
                }
            )

        for edge in self.edges:
            cy_edges.append(
                {
                    "data": {
                        "id": edge.edge_id,
                        "source": edge.source_node_id,
                        "target": edge.target_node_id,
                        "relation_type": edge.relation_type.value,
                        "weight": edge.weight,
                        "confidence": edge.confidence,
                        "rationale": edge.rationale,
                        "evidence_ids": edge.evidence_ids,
                    }
                }
            )

        return {"nodes": cy_nodes, "edges": cy_edges}


def render_hierarchy_ascii(tree: HierarchyTreeNode) -> str:
    """Render a HierarchyTreeNode into an investigative Unicode box-drawing hierarchy tree."""
    lines: list[str] = [
        f"{tree.label} [conf={tree.confidence:.2f}, H={tree.entropy_score:.2f}]"
    ]

    def _walk(children: Sequence[HierarchyTreeNode], prefix: str) -> None:
        total = len(children)
        for idx, child in enumerate(children):
            is_last = idx == total - 1
            connector = "└── " if is_last else "├── "
            if str(child.node_id).startswith("cat:"):
                lines.append(f"{prefix}{connector}{child.label}")
            else:
                ev_str = f" (ev:{len(child.evidence_ids)})" if child.evidence_ids else ""
                lines.append(
                    f"{prefix}{connector}[{child.entity_type}] {child.label} "
                    f"(id={child.node_id}, conf={child.confidence:.2f}){ev_str}"
                )
            next_prefix = prefix + ("    " if is_last else "│   ")
            if child.children:
                _walk(child.children, next_prefix)

    _walk(tree.children, "")
    return "\n".join(lines)
