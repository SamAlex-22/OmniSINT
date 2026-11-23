"""FastAPI (or Flask WSGI fallback) web server and WebSocket live stream for OmniSINT."""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from omnisint.api.routes.cases import (
    HAS_FASTAPI,
    CreateCaseRequest,
    OmniSINTAPIService,
    PivotNodeRequest,
    ScanRequest,
    build_fastapi_router,
    verify_api_token,
)
from omnisint.core.orchestrator import ScanOrchestrator
from omnisint.core.storage import CaseStorage

DEFAULT_WEB_DIR = Path(__file__).resolve().parent.parent.parent / "web"

if HAS_FASTAPI:  # pragma: no cover
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect  # type: ignore[import-untyped]
    from fastapi.responses import HTMLResponse  # type: ignore[import-untyped]
else:
    FastAPI = None
    WebSocket = None
    WebSocketDisconnect = None
    HTMLResponse = None

try:
    from flask import Flask, Response as FlaskResponse, jsonify, request
except ImportError:  # pragma: no cover
    Flask = None
    FlaskResponse = None
    jsonify = None
    request = None


_BG_LOOP: asyncio.AbstractEventLoop | None = None
_BG_LOOP_LOCK = threading.Lock()


def _get_bg_loop() -> asyncio.AbstractEventLoop:
    """Return a single persistent background event loop shared by synchronous Flask handlers."""
    global _BG_LOOP
    with _BG_LOOP_LOCK:
        if _BG_LOOP is not None and _BG_LOOP.is_running():
            return _BG_LOOP
        loop = asyncio.new_event_loop()
        ready = threading.Event()

        def _loop_runner() -> None:
            asyncio.set_event_loop(loop)
            ready.set()
            loop.run_forever()

        thread = threading.Thread(
            target=_loop_runner,
            name="omnisint-wsgi-loop",
            daemon=True,
        )
        thread.start()
        ready.wait()
        _BG_LOOP = loop
        return loop


def _run_coro_sync(coro: Any) -> Any:
    """Run an async coroutine cleanly from synchronous Flask handlers."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        loop = _get_bg_loop()
        return asyncio.run_coroutine_threadsafe(coro, loop).result()

    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def create_app(
    storage: CaseStorage | None = None,
    orchestrator: ScanOrchestrator | None = None,
    web_dir: Path | None = None,
    api_auth_token: str | None = None,
) -> Any:
    """Create the OmniSINT ASGI (FastAPI) or WSGI (Flask fallback) web application."""
    resolved_web_dir = web_dir or DEFAULT_WEB_DIR
    index_path = resolved_web_dir / "index.html"
    service = OmniSINTAPIService(
        storage=storage,
        orchestrator=orchestrator,
        api_auth_token=api_auth_token,
    )

    if HAS_FASTAPI and FastAPI is not None and HTMLResponse is not None:  # pragma: no cover
        app = FastAPI(title="OmniSINT API & Web GUI", version="0.1.0")
        app.include_router(build_fastapi_router(service))
        app.state.omnisint_service = service

        @app.get("/", response_class=HTMLResponse)
        async def serve_index() -> str:
            if index_path.exists():
                return index_path.read_text(encoding="utf-8")
            return "<h1>OmniSINT Web GUI not found</h1>"

        @app.websocket("/ws/cases/{case_id}")
        async def ws_case_events(websocket: Any, case_id: str) -> None:
            await websocket.accept()
            queue = service.broadcaster.subscribe(case_id)
            try:
                while True:
                    event_payload = await queue.get()
                    await websocket.send_json(event_payload)
            except WebSocketDisconnect:
                service.broadcaster.unsubscribe(case_id, queue)

        return app

    if Flask is None or jsonify is None or FlaskResponse is None or request is None:  # pragma: no cover
        raise RuntimeError("Neither FastAPI nor Flask is installed")

    flask_app = Flask(__name__)
    flask_app.extensions["omnisint_service"] = service

    @flask_app.before_request
    def _enforce_optional_api_auth() -> tuple[Any, int] | None:
        if request.path.startswith("/api/") and request.path != "/api/health":
            ok = verify_api_token(
                request.headers.get("Authorization"),
                request.headers.get("X-API-Key"),
                service.api_auth_token,
            )
            if not ok:
                return jsonify({"detail": "Unauthorized"}), 401
        return None

    @flask_app.errorhandler(Exception)
    def _handle_flask_exception(exc: Exception) -> Any:
        from werkzeug.exceptions import HTTPException as WerkzeugHTTPException

        if isinstance(exc, WerkzeugHTTPException):
            if request.path.startswith("/api/"):
                return jsonify({"detail": exc.description or str(exc)}), exc.code or 500
            return exc
        return jsonify({"detail": f"{type(exc).__name__}: {exc}"}), 500

    @flask_app.get("/")
    def serve_index() -> FlaskResponse:
        html = index_path.read_text(encoding="utf-8") if index_path.exists() else "<h1>OmniSINT</h1>"
        return FlaskResponse(html, status=200, mimetype="text/html")

    @flask_app.get("/api/health")
    def health() -> tuple[Any, int]:
        return jsonify({"status": "ok", "service": "omnisint"}), 200

    @flask_app.get("/api/cases")
    def list_cases() -> tuple[Any, int]:
        items = _run_coro_sync(service.list_cases())
        return jsonify(items), 200

    @flask_app.post("/api/cases")
    def create_case() -> tuple[Any, int]:
        data = request.get_json(silent=True) or {}
        try:
            req = CreateCaseRequest.model_validate(data)
        except ValidationError as exc:
            return jsonify({"detail": exc.errors()}), 422
        case = _run_coro_sync(service.create_case(req))
        return jsonify(case.model_dump(mode="json")), 201

    @flask_app.get("/api/cases/<case_id>")
    def get_case(case_id: str) -> tuple[Any, int]:
        try:
            case = _run_coro_sync(service.get_case(case_id))
            return jsonify(case.model_dump(mode="json")), 200
        except KeyError as exc:
            return jsonify({"detail": str(exc)}), 404

    @flask_app.post("/api/cases/<case_id>/scan")
    def scan_case(case_id: str) -> tuple[Any, int]:
        data = request.get_json(silent=True) or {}
        try:
            req = ScanRequest.model_validate(data)
        except ValidationError as exc:
            return jsonify({"detail": exc.errors()}), 422
        try:
            _run_coro_sync(service.get_case(case_id))
        except KeyError as exc:
            return jsonify({"detail": str(exc)}), 404
        if request.args.get("async", "").lower() == "true":
            job = service.submit_scan_job(case_id, req)
            return jsonify(job.model_dump(mode="json")), 202
        res = _run_coro_sync(service.run_scan(case_id, req))
        return jsonify(res), 200

    @flask_app.post("/api/cases/<case_id>/pivot")
    def pivot_case_node(case_id: str) -> tuple[Any, int]:
        data = request.get_json(silent=True) or {}
        try:
            req = PivotNodeRequest.model_validate(data)
        except ValidationError as exc:
            return jsonify({"detail": exc.errors()}), 422
        try:
            _run_coro_sync(service.get_case(case_id))
        except KeyError as exc:
            return jsonify({"detail": str(exc)}), 404
        if request.args.get("async", "").lower() == "true":
            job = service.submit_pivot_job(case_id, req)
            return jsonify(job.model_dump(mode="json")), 202
        res = _run_coro_sync(service.pivot_node(case_id, req))
        return jsonify(res), 200

    @flask_app.get("/api/jobs/<job_id>")
    def get_job_status(job_id: str) -> tuple[Any, int]:
        job = service.jobs.get_job(job_id)
        if job is None:
            return jsonify({"detail": f"Job '{job_id}' not found"}), 404
        return jsonify(job.model_dump(mode="json")), 200

    @flask_app.get("/api/cases/<case_id>/graph")
    def get_case_graph(case_id: str) -> tuple[Any, int]:
        try:
            res = _run_coro_sync(service.get_graph_payload(case_id))
            return jsonify(res.model_dump(mode="json")), 200
        except KeyError as exc:
            return jsonify({"detail": str(exc)}), 404

    @flask_app.get("/api/cases/<case_id>/custody")
    def get_case_custody(case_id: str) -> tuple[Any, int]:
        try:
            res = _run_coro_sync(service.verify_custody(case_id))
            return jsonify(res.model_dump(mode="json")), 200
        except KeyError as exc:
            return jsonify({"detail": str(exc)}), 404

    @flask_app.get("/api/cases/<case_id>/export/<fmt>")
    def export_case(case_id: str, fmt: str) -> FlaskResponse | tuple[Any, int]:
        redact_pii = request.args.get("redact_pii", "").lower() == "true"
        try:
            content, media_type = _run_coro_sync(
                service.export_report(case_id, fmt, redact_pii=redact_pii)
            )
            ext = "md" if fmt.strip().lower() in ("md", "markdown") else "stix.json"
            safe_id = "".join(ch for ch in case_id if ch.isalnum() or ch in ("-", "_")) or "case"
            return FlaskResponse(
                content,
                status=200,
                content_type=media_type,
                headers={"Content-Disposition": f'attachment; filename="omnisint-{safe_id}.{ext}"'},
            )
        except KeyError as exc:
            return jsonify({"detail": str(exc)}), 404
        except ValueError as exc:
            return jsonify({"detail": str(exc)}), 400

    return flask_app


def get_default_app() -> Any:
    """Factory returning a default configured OmniSINT web application."""
    return create_app()
