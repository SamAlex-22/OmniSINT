"""Async scan orchestrator and multi-hop cross-indicator pivot engine for OmniSINT."""

from __future__ import annotations

import asyncio
import ipaddress
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Sequence

from pydantic import BaseModel, ConfigDict, Field

from omnisint.core.custody import CustodyLedger
from omnisint.core.models import (
    AuditLogEntry,
    Case,
    CaseStatus,
    CollectorResult,
    EntityNode,
    EntityType,
    utc_now,
)
from omnisint.core.storage import CaseStorage
from omnisint.intelligence.ai_analyst import AIAnalysisReport, AIAnalyst
from omnisint.intelligence.graph_engine import KnowledgeGraphEngine

if TYPE_CHECKING:  # pragma: no cover
    from omnisint.collectors.base import CollectorRegistry


class ScanProgressEvent(BaseModel):
    """Real-time progress event emitted during scans and node pivots."""

    model_config = ConfigDict(extra="forbid")

    case_id: str
    stage: str
    collector_name: str | None = None
    query: str
    message: str
    nodes_discovered: int = 0
    edges_discovered: int = 0
    timestamp_utc: str = Field(default_factory=lambda: utc_now().isoformat())


class PivotRequest(BaseModel):
    """Parameters for pivoting an investigation from an existing EntityNode."""

    model_config = ConfigDict(extra="forbid")

    case_id: str
    node_id: str
    collector_names: list[str] | None = None
    run_disambiguation: bool = True
    run_ai_analysis: bool = True


ProgressCallback = Callable[[ScanProgressEvent], Awaitable[None] | None]


def infer_entity_type(query: str) -> EntityType:
    """Heuristically classify a raw OSINT seed string into a canonical EntityType."""
    cleaned = query.strip()
    if not cleaned:
        return EntityType.USERNAME
    try:
        ipaddress.ip_address(cleaned)
        return EntityType.IP_ADDRESS
    except ValueError:
        pass

    lower = cleaned.lower()
    if lower.startswith(("http://", "https://")):
        return EntityType.URL
    if "@" in cleaned and not cleaned.startswith("@"):
        return EntityType.EMAIL
    if "." in cleaned and " " not in cleaned and not cleaned.startswith("@"):
        return EntityType.DOMAIN
    if " " in cleaned and not cleaned.startswith("@"):
        return EntityType.PERSON
    return EntityType.USERNAME


class ScanOrchestrator:
    """Coordinates passive collectors, multi-hop pivots, storage persistence, graph clustering, and AI analysis."""

    def __init__(
        self,
        storage: CaseStorage,
        registry: CollectorRegistry | None = None,
        graph_engine: KnowledgeGraphEngine | None = None,
        ai_analyst: AIAnalyst | None = None,
        progress_callback: ProgressCallback | None = None,
    ) -> None:
        self.storage = storage
        if registry is not None:
            self.registry = registry
        else:
            from omnisint.collectors import create_default_registry

            self.registry = create_default_registry()
        self.graph_engine = graph_engine or KnowledgeGraphEngine()
        self.ai_analyst = ai_analyst or AIAnalyst()
        self.progress_callback = progress_callback

    async def _emit_progress(self, event: ScanProgressEvent) -> None:
        """Deliver a progress event to an optional sync or async callback."""
        if self.progress_callback is None:
            return
        res = self.progress_callback(event)
        if asyncio.iscoroutine(res):
            await res

    def _select_collectors(
        self,
        entity_type: EntityType,
        collector_names: Sequence[str] | None = None,
    ) -> list[Any]:
        """Select matching collectors for `entity_type`, optionally filtered by name."""
        if collector_names:
            selected = []
            for cname in collector_names:
                c = self.registry.get(cname)
                if c is not None:
                    selected.append(c)
            return selected

        if entity_type in (EntityType.SOCIAL_PROFILE, EntityType.PERSON):
            by_type = {c.name: c for c in self.registry.get_for_entity_type(entity_type)}
            for c in self.registry.get_for_entity_type(EntityType.USERNAME):
                if entity_type == EntityType.PERSON and c.name == "scrapling_collector":
                    continue
                by_type.setdefault(c.name, c)
            return [by_type[k] for k in sorted(by_type.keys())]

        return self.registry.get_for_entity_type(entity_type)

    async def _execute_collectors_for_query(
        self,
        case_id: str,
        query: str,
        entity_type: EntityType,
        collector_names: Sequence[str] | None = None,
    ) -> list[CollectorResult]:
        """Run matching collectors concurrently for `(query, entity_type)` and return their results."""
        collectors = self._select_collectors(entity_type, collector_names=collector_names)
        if not collectors:
            return []

        async def _run_one(collector: Any) -> CollectorResult:
            await self._emit_progress(
                ScanProgressEvent(
                    case_id=case_id,
                    stage="collector_started",
                    collector_name=collector.name,
                    query=query,
                    message=f"Running {collector.name} on '{query}' ({entity_type.value})",
                )
            )
            # Each collector runs against its own local ledger; CaseStorage re-chains on merge
            local_ledger = CustodyLedger(case_id=case_id)
            result = await collector.collect(
                query=query,
                case_id=case_id,
                ledger=local_ledger,
                storage=self.storage,
            )
            await self._emit_progress(
                ScanProgressEvent(
                    case_id=case_id,
                    stage="collector_finished",
                    collector_name=collector.name,
                    query=query,
                    message=f"{collector.name} finished '{query}'",
                    nodes_discovered=len(result.nodes),
                    edges_discovered=len(result.edges),
                )
            )
            return result

        return list(await asyncio.gather(*(_run_one(c) for c in collectors)))

    async def _finalize_intelligence(
        self,
        case_id: str,
        run_disambiguation: bool = True,
        run_ai_analysis: bool = True,
    ) -> tuple[Case, AIAnalysisReport | None]:
        """Run KnowledgeGraphEngine + AIAnalyst on persisted Case and update status."""
        case = await self.storage.get_case(case_id)
        if case is None:
            raise KeyError(f"Case '{case_id}' not found")

        if run_disambiguation and case.nodes:
            await self._emit_progress(
                ScanProgressEvent(
                    case_id=case_id,
                    stage="disambiguation",
                    query=case.target_query,
                    message="Running Louvain persona clustering & hierarchy tree synthesis",
                    nodes_discovered=len(case.nodes),
                    edges_discovered=len(case.edges),
                )
            )
            self.graph_engine.apply_to_case(case)

        ai_report: AIAnalysisReport | None = None
        if run_ai_analysis and case.nodes:
            await self._emit_progress(
                ScanProgressEvent(
                    case_id=case_id,
                    stage="ai_analysis",
                    query=case.target_query,
                    message=f"Generating citation-locked brief via {self.ai_analyst.provider}",
                )
            )
            ai_report = await self.ai_analyst.analyze_case(
                case,
                run_graph_disambiguation=False,
            )

        case.status = CaseStatus.COMPLETED
        saved_case = await self.storage.save_case(case)
        await self._emit_progress(
            ScanProgressEvent(
                case_id=case_id,
                stage="completed",
                query=saved_case.target_query,
                message=f"Case finalized with {len(saved_case.personas)} persona(s)",
                nodes_discovered=len(saved_case.nodes),
                edges_discovered=len(saved_case.edges),
            )
        )
        return saved_case, ai_report

    async def run_scan(
        self,
        query: str,
        case_id: str | None = None,
        title: str | None = None,
        entity_type: EntityType | None = None,
        max_hops: int = 2,
        collector_names: Sequence[str] | None = None,
        run_ai_analysis: bool = True,
    ) -> tuple[Case, AIAnalysisReport | None]:
        """Execute an end-to-end async OSINT scan with optional multi-hop cross-indicator pivoting."""
        cleaned = query.strip()
        seed_type = entity_type or infer_entity_type(cleaned)

        if case_id:
            case = await self.storage.get_case(case_id)
            if case is None:
                raise KeyError(f"Case '{case_id}' not found")
        else:
            case = await self.storage.create_case(
                title=title or f"OSINT Investigation: {cleaned}",
                target_query=cleaned,
            )

        await self.storage.update_case_status(case.case_id, CaseStatus.ANALYZING)

        pivoted_keys: set[tuple[EntityType, str]] = {
            (seed_type, cleaned.lower()),
            (EntityType.USERNAME, cleaned.lstrip("@").lower()),
        }
        frontier: list[tuple[str, EntityType]] = [(cleaned, seed_type)]

        for hop in range(1, max(1, max_hops) + 1):
            if not frontier:
                break

            hop_results: list[CollectorResult] = []
            for target_val, target_type in frontier:
                # Apply caller-specified collector_names only on hop 1
                hop_filter = collector_names if hop == 1 else None
                res_list = await self._execute_collectors_for_query(
                    case_id=case.case_id,
                    query=target_val,
                    entity_type=target_type,
                    collector_names=hop_filter,
                )
                hop_results.extend(res_list)

            for res in hop_results:
                await self.storage.merge_collector_result(case.case_id, res)

            if hop >= max_hops:
                break

            # Build next-hop pivot frontier from newly discovered domains, IPs, emails & usernames
            refreshed = await self.storage.get_case(case.case_id)
            if refreshed is None:
                break

            next_frontier: list[tuple[str, EntityType]] = []
            for node in refreshed.nodes:
                if node.entity_type in (EntityType.DOMAIN, EntityType.IP_ADDRESS):
                    key = (node.entity_type, node.value.strip().lower())
                    if key not in pivoted_keys:
                        pivoted_keys.add(key)
                        next_frontier.append((node.value.strip(), node.entity_type))
                elif node.entity_type == EntityType.EMAIL and "@" in node.value:
                    dom_part = node.value.split("@", 1)[1].strip().lower()
                    if dom_part and "." in dom_part:
                        key = (EntityType.DOMAIN, dom_part)
                        if key not in pivoted_keys:
                            pivoted_keys.add(key)
                            next_frontier.append((dom_part, EntityType.DOMAIN))
                elif node.entity_type == EntityType.USERNAME:
                    uname = node.value.strip().lstrip("@")
                    if uname and " " not in uname:
                        key = (EntityType.USERNAME, uname.lower())
                        if key not in pivoted_keys:
                            pivoted_keys.add(key)
                            next_frontier.append((uname, EntityType.USERNAME))
                elif (
                    node.entity_type == EntityType.SOCIAL_PROFILE
                    and (node.platform or "").strip().lower() == "github"
                ):
                    uname = node.value.strip().lstrip("@")
                    if uname and " " not in uname:
                        key = (EntityType.USERNAME, uname.lower())
                        if key not in pivoted_keys:
                            pivoted_keys.add(key)
                            next_frontier.append((uname, EntityType.USERNAME))
            frontier = next_frontier[:10]

        return await self._finalize_intelligence(
            case_id=case.case_id,
            run_disambiguation=True,
            run_ai_analysis=run_ai_analysis,
        )

    async def pivot_on_node(
        self,
        case_id: str,
        node_id: str,
        collector_names: Sequence[str] | None = None,
        run_disambiguation: bool = True,
        run_ai_analysis: bool = True,
    ) -> tuple[Case, AIAnalysisReport | None]:
        """Pivot on an existing EntityNode in a Case, merge new intelligence, and re-resolve personas."""
        case = await self.storage.get_case(case_id)
        if case is None:
            raise KeyError(f"Case '{case_id}' not found")

        target_node: EntityNode | None = next((n for n in case.nodes if n.node_id == node_id), None)
        if target_node is None:
            raise KeyError(f"Node '{node_id}' not found in Case '{case_id}'")

        await self.storage.update_case_status(case_id, CaseStatus.ANALYZING)

        case.audit_log.append(
            AuditLogEntry(
                case_id=case_id,
                actor="omnisint-orchestrator",
                action="PIVOT_EXECUTED",
                details={
                    "node_id": target_node.node_id,
                    "entity_type": target_node.entity_type.value,
                    "value": target_node.value,
                },
            )
        )
        await self.storage.save_case(case)

        results = await self._execute_collectors_for_query(
            case_id=case_id,
            query=target_node.value,
            entity_type=target_node.entity_type,
            collector_names=collector_names,
        )
        for res in results:
            await self.storage.merge_collector_result(case_id, res)

        return await self._finalize_intelligence(
            case_id=case_id,
            run_disambiguation=run_disambiguation,
            run_ai_analysis=run_ai_analysis,
        )
