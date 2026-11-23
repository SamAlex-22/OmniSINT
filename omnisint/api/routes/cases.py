"""REST & WebSocket Case, Scan, Graph, Pivot, Custody, Async Job & Reporting route handlers for OmniSINT."""

from __future__ import annotations

import asyncio
import concurrent.futures
import hmac
import json
import threading
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from omnisint.collectors import create_default_registry
from omnisint.config import get_settings
from omnisint.core.custody import CustodyLedger
from omnisint.core.models import Case, EntityType, new_uuid, utc_now
from omnisint.core.orchestrator import ScanOrchestrator, ScanProgressEvent
from omnisint.core.storage import CaseStorage
from omnisint.intelligence.graph_engine import KnowledgeGraphEngine
from omnisint.reporting import MarkdownExporter, STIXExporter

try:
    from fastapi import APIRouter, HTTPException, Request, Response  # type: ignore[import-untyped]

    HAS_FASTAPI = True
except ImportError:  # pragma: no cover
    APIRouter = None
    HTTPException = None
    Request = None
    Response = None
    HAS_FASTAPI = False


class CreateCaseRequest(BaseModel):
    """Payload to create a new OSINT investigation Case."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=1)
    target_query: str = Field(..., min_length=1)
    investigator: str = "lead-analyst"
    description: str = ""
    legal_basis: str = "authorized-defensive-research"
    retention_days: int | None = Field(default=None, ge=1)


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


class ScanJobStatus(BaseModel):
    """Status tracker for non-blocking background scan or pivot jobs."""

    model_config = ConfigDict(extra="forbid")

    job_id: str = Field(default_factory=new_uuid)
    case_id: str
    job_type: Literal["scan", "pivot"]
    status: Literal["queued", "running", "completed", "failed"] = "queued"
    created_at_utc: str = Field(default_factory=lambda: utc_now().isoformat())
    completed_at_utc: str | None = None
    result: dict[str, Any] | None = None
    error: str | None = None


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


class JobManager:
    """Tracks background scan and pivot tasks across both ASGI and WSGI runtimes."""

    def __init__(self) -> None:
        self._jobs: dict[str, ScanJobStatus] = {}
        self._lock = threading.Lock()
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)

    def create_job(self, case_id: str, job_type: Literal["scan", "pivot"]) -> ScanJobStatus:
        """Create and register a queued background job."""
        job = ScanJobStatus(case_id=case_id, job_type=job_type)
        with self._lock:
            self._jobs[job.job_id] = job
        return job

    def get_job(self, job_id: str) -> ScanJobStatus | None:
        """Retrieve a job status record by ID."""
        with self._lock:
            job = self._jobs.get(job_id)
            return job.model_copy(deep=True) if job else None

    def launch_coro(self, job: ScanJobStatus, coro_factory: Any) -> None:
        """Execute `coro_factory()` asynchronously and record job completion/error."""

        async def _runner() -> None:
            with self._lock:
                job.status = "running"
            try:
                res = await coro_factory()
                with self._lock:
                    job.status = "completed"
                    job.result = res
                    job.completed_at_utc = utc_now().isoformat()
            except Exception as exc:
                with self._lock:
                    job.status = "failed"
                    job.error = f"{type(exc).__name__}: {exc}"
                    job.completed_at_utc = utc_now().isoformat()

        try:
            loop = asyncio.get_running_loop()
            loop.create_task(_runner())
        except RuntimeError:
            self._executor.submit(lambda: asyncio.run(_runner()))


def verify_api_token(provided_header_auth: str | None, provided_api_key: str | None, expected_token: str | None) -> bool:
    """Return True if authentication is disabled or the supplied Bearer/X-API-Key token matches."""
    if not expected_token:
        return True
    candidate: str | None = None
    if provided_header_auth and provided_header_auth.lower().startswith("bearer "):
        candidate = provided_header_auth[7:].strip()
    elif provided_api_key:
        candidate = provided_api_key.strip()
    if not candidate:
        return False
    return hmac.compare_digest(candidate, expected_token)


class OmniSINTAPIService:
    """Framework-agnostic async service layer backing FastAPI and Flask endpoints."""

    def __init__(
        self,
        storage: CaseStorage | None = None,
        orchestrator: ScanOrchestrator | None = None,
        broadcaster: ProgressBroadcaster | None = None,
        api_auth_token: str | None = None,
    ) -> None:
        self.storage = storage or CaseStorage()
        self.broadcaster = broadcaster or ProgressBroadcaster()
        self.jobs = JobManager()
        self.api_auth_token = (
            api_auth_token if api_auth_token is not None else get_settings().api_auth_token
        )
        if orchestrator is not None:
            self.orchestrator = orchestrator
        else:
            self.orchestrator = ScanOrchestrator(
                storage=self.storage,
                registry=create_default_registry(include_scrapling=True),
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
                "legal_basis": c.legal_basis,
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
            legal_basis=req.legal_basis,
            retention_days=req.retention_days,
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

    def submit_scan_job(self, case_id: str, req: ScanRequest) -> ScanJobStatus:
        """Queue a non-blocking background scan job and return its ScanJobStatus."""
        job = self.jobs.create_job(case_id=case_id, job_type="scan")
        self.jobs.launch_coro(job, lambda: self.run_scan(case_id, req))
        return job

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

    def submit_pivot_job(self, case_id: str, req: PivotNodeRequest) -> ScanJobStatus:
        """Queue a non-blocking background pivot job and return its ScanJobStatus."""
        job = self.jobs.create_job(case_id=case_id, job_type="pivot")
        self.jobs.launch_coro(job, lambda: self.pivot_node(case_id, req))
        return job

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

    async def export_report(
        self,
        case_id: str,
        fmt: str,
        redact_pii: bool = False,
    ) -> tuple[str, str]:
        """Export a Case as Markdown or STIX 2.1 JSON; returns `(content, media_type)`."""
        case = await self.get_case(case_id)
        norm = fmt.strip().lower()
        if norm in ("md", "markdown"):
            return (
                MarkdownExporter().export(case, verify_custody=True, redact_pii=redact_pii),
                "text/markdown; charset=utf-8",
            )
        if norm in ("stix", "stix2", "json"):
            return STIXExporter().export_json(case), "application/stix+json; charset=utf-8"
        raise ValueError(f"Unsupported export format '{fmt}' (expected 'markdown' or 'stix')")


def build_fastapi_router(service: OmniSINTAPIService) -> Any:  # pragma: no cover
    """Build a FastAPI APIRouter wired to `service` when FastAPI is installed."""
    if not HAS_FASTAPI or APIRouter is None or HTTPException is None or Response is None:
        raise RuntimeError("FastAPI is not installed in this environment")

    router = APIRouter(prefix="/api", tags=["omnisint"])

    def _require_auth(request: Any) -> None:
        ok = verify_api_token(
            request.headers.get("authorization"),
            request.headers.get("x-api-key"),
            service.api_auth_token,
        )
        if not ok:
            raise HTTPException(status_code=401, detail="Unauthorized")

    @router.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "omnisint"}

    @router.get("/cases")
    async def list_cases(request: Any) -> list[dict[str, Any]]:
        _require_auth(request)
        return await service.list_cases()

    @router.post("/cases", status_code=201)
    async def create_case(payload: CreateCaseRequest, request: Any) -> dict[str, Any]:
        _require_auth(request)
        case = await service.create_case(payload)
        return case.model_dump(mode="json")

    @router.get("/cases/{case_id}")
    async def get_case(case_id: str, request: Any) -> dict[str, Any]:
        _require_auth(request)
        try:
            case = await service.get_case(case_id)
            return case.model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @router.post("/cases/{case_id}/scan")
    async def scan_case(
        case_id: str,
        payload: ScanRequest,
        request: Any,
        async_mode: bool = False,
    ) -> Any:
        _require_auth(request)
        try:
            await service.get_case(case_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        if async_mode or request.query_params.get("async") == "true":
            job = service.submit_scan_job(case_id, payload)
            return Response(
                content=json_dumps_safe(job.model_dump(mode="json")),
                status_code=202,
                media_type="application/json",
            )
        return await service.run_scan(case_id, payload)

    @router.post("/cases/{case_id}/pivot")
    async def pivot_case_node(case_id: str, payload: PivotNodeRequest, request: Any) -> Any:
        _require_auth(request)
        try:
            await service.get_case(case_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        if request.query_params.get("async") == "true":
            job = service.submit_pivot_job(case_id, payload)
            return Response(
                content=json_dumps_safe(job.model_dump(mode="json")),
                status_code=202,
                media_type="application/json",
            )
        return await service.pivot_node(case_id, payload)

    @router.get("/jobs/{job_id}")
    async def get_job_status(job_id: str, request: Any) -> dict[str, Any]:
        _require_auth(request)
        job = service.jobs.get_job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found")
        return job.model_dump(mode="json")

    @router.get("/cases/{case_id}/graph")
    async def get_case_graph(case_id: str, request: Any) -> dict[str, Any]:
        _require_auth(request)
        try:
            res = await service.get_graph_payload(case_id)
            return res.model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @router.get("/cases/{case_id}/custody")
    async def get_case_custody(case_id: str, request: Any) -> dict[str, Any]:
        _require_auth(request)
        try:
            res = await service.verify_custody(case_id)
            return res.model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @router.get("/cases/{case_id}/export/{fmt}")
    async def export_case(case_id: str, fmt: str, request: Any, redact_pii: bool = False) -> Any:
        _require_auth(request)
        try:
            content, media_type = await service.export_report(case_id, fmt, redact_pii=redact_pii)
            return Response(content=content, media_type=media_type)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    return router


def json_dumps_safe(data: Any) -> str:
    """Serialize Pydantic models or JSON objects safely."""
    return json.dumps(data, default=str)
