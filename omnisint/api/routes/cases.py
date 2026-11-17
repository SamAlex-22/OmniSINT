"""REST & WebSocket Case, Scan, Graph, Pivot, Custody & Reporting route handlers for OmniSINT."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from omnisint.core.custody import CustodyLedger
from omnisint.core.models import Case, EntityType
from omnisint.core.orchestrator import ScanOrchestrator, ScanProgressEvent
from omnisint.core.storage import CaseStorage
from omnisint.intelligence.graph_engine import KnowledgeGraphEngine
from omnisint.reporting import MarkdownExporter, STIXExporter

try:
    from fastapi import APIRouter, HTTPException, Response, WebSocket, WebSocketDisconnect  # type: ignore[import-untyped]

    HAS_FASTAPI = True
except ImportError:  # pragma: no cover
    APIRouter = None
    HTTPException = None
    Response = None
    WebSocket = None
    WebSocketDisconnect = None
    HAS_FASTAPI = False


class CreateCaseRequest(BaseModel):
    """Payload to create a new OSINT investigation Case."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=1)
    target_query: str = Field(..., min_length=1)
    investigator: str = "lead-analyst"
    description: str = ""


class ScanRequest(BaseModel):
    """Payload to trigger a multi-collector OSINT scan inside a Case."""

    model_config = ConfigDict(extra="forbid")

    query: str | None = None
    entity_type: EntityType | None = None
    max_hops: int = Field(default=2, ge=1, le=4)
    collector_names: list[str] | None = None
    run_ai_analysis: bool = True


class PivotNodeRequest(BaseModel):
    """Payload to execute a one-click pivot on an existing EntityNode."""

    model_config = ConfigDict(extra="forbid")

    node_id: str = Field(..., min_length=1)
    collector_names: list[str] | None = None
    run_disambiguation: bool = True
    run_ai_analysis: bool = True


class CustodyVerificationResponse(BaseModel):
    """Cryptographic Chain of Custody verification response payload."""

    model_config = ConfigDict(extra="forbid")

    case_id: str
    is_valid: bool
    item_count: int
    head_chain_hash: str
    violations: list[str] = Field(default_factory=list)
    evidence_items: list[dict[str, Any]] = Field(default_factory=list)
    audit_log: list[dict[str, Any]] = Field(default_factory=list)


class GraphPayloadResponse(BaseModel):
    """Cytoscape.js elements + Persona Clusters + Hierarchy Trees for UI rendering."""

    model_config = ConfigDict(extra="forbid")

    case_id: str
    elements: dict[str, list[dict[str, Any]]]
    personas: list[dict[str, Any]]
    ai_executive_brief: str = ""


class ProgressBroadcaster:
    """In-memory pub/sub hub streaming ScanProgressEvents to WebSocket subscribers."""

    def __init__(self) -> None:
        self._subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = {}

    def subscribe(self, case_id: str) -> asyncio.Queue[dict[str, Any]]:
        """Subscribe a listener queue to live progress events for `case_id`."""
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._subscribers.setdefault(case_id, set()).add(queue)
        return queue

    def unsubscribe(self, case_id: str, queue: asyncio.Queue[dict[str, Any]]) -> None:
        """Remove a subscriber queue."""
        listeners = self._subscribers.get(case_id)
        if listeners:
            listeners.discard(queue)
            if not listeners:
                self._subscribers.pop(case_id, None)

    async def publish(self, event: ScanProgressEvent) -> None:
        """Broadcast a ScanProgressEvent to all listeners subscribed to `event.case_id`."""
        payload = event.model_dump(mode="json")
        for queue in list(self._subscribers.get(event.case_id, ())):
            await queue.put(payload)


class OmniSINTAPIService:
    """Framework-agnostic async service layer backing FastAPI and Flask endpoints."""

    def __init__(
        self,
        storage: CaseStorage | None = None,
        orchestrator: ScanOrchestrator | None = None,
        broadcaster: ProgressBroadcaster | None = None,
    ) -> None:
        self.storage = storage or CaseStorage()
        self.broadcaster = broadcaster or ProgressBroadcaster()
        if orchestrator is not None:
            self.orchestrator = orchestrator
        else:
            self.orchestrator = ScanOrchestrator(
                storage=self.storage,
                progress_callback=self.broadcaster.publish,
            )

    async def ensure_ready(self) -> None:
        """Ensure CaseStorage SQLite schema is initialized."""
        await self.storage.initialize()

    async def list_cases(self) -> list[dict[str, Any]]:
        """Return summary dictionaries for all persisted Cases."""
        await self.ensure_ready()
        cases = await self.storage.list_cases()
        return [
            {
                "case_id": c.case_id,
                "title": c.title,
                "target_query": c.target_query,
                "investigator": c.investigator,
                "status": c.status.value,
                "created_at_utc": c.created_at_utc.isoformat(),
                "updated_at_utc": c.updated_at_utc.isoformat(),
                "node_count": len(c.nodes),
                "edge_count": len(c.edges),
                "persona_count": len(c.personas),
                "evidence_count": len(c.evidence_ledger),
            }
            for c in cases
        ]

    async def create_case(self, req: CreateCaseRequest) -> Case:
        """Create and persist a new Case."""
        await self.ensure_ready()
        return await self.storage.create_case(
            title=req.title,
            target_query=req.target_query,
            investigator=req.investigator,
            description=req.description,
        )

    async def get_case(self, case_id: str) -> Case:
        """Retrieve a full Case or raise KeyError if missing."""
        await self.ensure_ready()
        case = await self.storage.get_case(case_id)
        if case is None:
            raise KeyError(f"Case '{case_id}' not found")
        return case

    async def run_scan(self, case_id: str, req: ScanRequest) -> dict[str, Any]:
        """Run a multi-collector scan inside an existing Case."""
        case = await self.get_case(case_id)
        target = (req.query or case.target_query).strip()
        updated_case, report = await self.orchestrator.run_scan(
            query=target,
            case_id=case_id,
            entity_type=req.entity_type,
            max_hops=req.max_hops,
            collector_names=req.collector_names,
            run_ai_analysis=req.run_ai_analysis,
        )
        return {
            "case_id": updated_case.case_id,
            "status": updated_case.status.value,
            "node_count": len(updated_case.nodes),
            "edge_count": len(updated_case.edges),
            "persona_count": len(updated_case.personas),
            "evidence_count": len(updated_case.evidence_ledger),
            "citation_valid": report.citation_audit.is_valid if report else True,
        }

    async def pivot_node(self, case_id: str, req: PivotNodeRequest) -> dict[str, Any]:
        """Execute a pivot on `req.node_id` inside `case_id`."""
        await self.ensure_ready()
        updated_case, report = await self.orchestrator.pivot_on_node(
            case_id=case_id,
            node_id=req.node_id,
            collector_names=req.collector_names,
            run_disambiguation=req.run_disambiguation,
            run_ai_analysis=req.run_ai_analysis,
        )
        return {
            "case_id": updated_case.case_id,
            "pivoted_node_id": req.node_id,
            "status": updated_case.status.value,
            "node_count": len(updated_case.nodes),
            "edge_count": len(updated_case.edges),
            "persona_count": len(updated_case.personas),
            "citation_valid": report.citation_audit.is_valid if report else True,
        }

    async def get_graph_payload(self, case_id: str) -> GraphPayloadResponse:
        """Build Cytoscape.js graph elements and PersonaCluster hierarchy trees for `case_id`."""
        case = await self.get_case(case_id)
        engine = KnowledgeGraphEngine.from_case(case)
        elements = engine.to_cytoscape_elements(personas=case.personas)
        return GraphPayloadResponse(
            case_id=case.case_id,
            elements=elements,
            personas=[p.model_dump(mode="json") for p in case.personas],
            ai_executive_brief=case.ai_executive_brief,
        )

    async def verify_custody(self, case_id: str) -> CustodyVerificationResponse:
        """Verify SHA-256 Chain of Custody for `case_id` and return ledger metadata."""
        case = await self.get_case(case_id)
        ledger = CustodyLedger(
            case_id=case.case_id,
            existing_evidence=case.evidence_ledger,
            existing_audit_log=case.audit_log,
        )
        is_valid, violations = ledger.verify_chain()
        ev_summaries = [
            {
                "evidence_id": ev.evidence_id,
                "collector_name": ev.collector_name,
                "source_uri": ev.source_uri,
                "sha256_hash": ev.sha256_hash,
                "prev_chain_hash": ev.prev_chain_hash,
                "chain_hash": ev.chain_hash,
                "collected_at_utc": ev.collected_at_utc.isoformat(),
                "mime_type": ev.mime_type,
                "notes": ev.notes,
            }
            for ev in case.evidence_ledger
        ]
        audit_summaries = [entry.model_dump(mode="json") for entry in case.audit_log]
        return CustodyVerificationResponse(
            case_id=case.case_id,
            is_valid=is_valid,
            item_count=len(case.evidence_ledger),
            head_chain_hash=ledger.head_chain_hash,
            violations=violations,
            evidence_items=ev_summaries,
            audit_log=audit_summaries,
        )

    async def export_report(self, case_id: str, fmt: str) -> tuple[str, str]:
        """Export a Case as Markdown or STIX 2.1 JSON; returns `(content, media_type)`."""
        case = await self.get_case(case_id)
        norm = fmt.strip().lower()
        if norm in ("md", "markdown"):
            return MarkdownExporter().export(case, verify_custody=True), "text/markdown; charset=utf-8"
        if norm in ("stix", "stix2", "json"):
            return STIXExporter().export_json(case), "application/stix+json; charset=utf-8"
        raise ValueError(f"Unsupported export format '{fmt}' (expected 'markdown' or 'stix')")


def build_fastapi_router(service: OmniSINTAPIService) -> Any:  # pragma: no cover
    """Build a FastAPI APIRouter wired to `service` when FastAPI is installed."""
    if not HAS_FASTAPI or APIRouter is None or HTTPException is None or Response is None:
        raise RuntimeError("FastAPI is not installed in this environment")

    router = APIRouter(prefix="/api", tags=["omnisint"])

    @router.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "omnisint"}

    @router.get("/cases")
    async def list_cases() -> list[dict[str, Any]]:
        return await service.list_cases()

    @router.post("/cases", status_code=201)
    async def create_case(payload: CreateCaseRequest) -> dict[str, Any]:
        case = await service.create_case(payload)
        return case.model_dump(mode="json")

    @router.get("/cases/{case_id}")
    async def get_case(case_id: str) -> dict[str, Any]:
        try:
            case = await service.get_case(case_id)
            return case.model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @router.post("/cases/{case_id}/scan")
    async def scan_case(case_id: str, payload: ScanRequest) -> dict[str, Any]:
        try:
            return await service.run_scan(case_id, payload)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @router.post("/cases/{case_id}/pivot")
    async def pivot_case_node(case_id: str, payload: PivotNodeRequest) -> dict[str, Any]:
        try:
            return await service.pivot_node(case_id, payload)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @router.get("/cases/{case_id}/graph")
    async def get_case_graph(case_id: str) -> dict[str, Any]:
        try:
            res = await service.get_graph_payload(case_id)
            return res.model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @router.get("/cases/{case_id}/custody")
    async def get_case_custody(case_id: str) -> dict[str, Any]:
        try:
            res = await service.verify_custody(case_id)
            return res.model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @router.get("/cases/{case_id}/export/{fmt}")
    async def export_case(case_id: str, fmt: str) -> Any:
        try:
            content, media_type = await service.export_report(case_id, fmt)
            return Response(content=content, media_type=media_type)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    return router


def json_dumps_safe(data: Any) -> str:
    """Serialize Pydantic models or JSON objects safely."""
    return json.dumps(data, default=str)
