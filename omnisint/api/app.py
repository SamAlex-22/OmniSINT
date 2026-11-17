"""FastAPI (or Flask WSGI fallback) web server and WebSocket live stream for OmniSINT."""

from __future__ import annotations

import asyncio
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


def _run_coro_sync(coro: Any) -> Any:
    """Run an async coroutine cleanly from synchronous Flask handlers."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    # If invoked inside an existing event loop thread, execute on a fresh loop in a thread
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def create_app(
    storage: CaseStorage | None = None,
    orchestrator: ScanOrchestrator | None = None,
    web_dir: Path | None = None,
) -> Any:
    """Create the OmniSINT ASGI (FastAPI) or WSGI (Flask fallback) web application."""
    resolved_web_dir = web_dir or DEFAULT_WEB_DIR
    index_path = resolved_web_dir / "index.html"
    service = OmniSINTAPIService(storage=storage, orchestrator=orchestrator)

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
            res = _run_coro_sync(service.run_scan(case_id, req))
            return jsonify(res), 200
        except KeyError as exc:
            return jsonify({"detail": str(exc)}), 404

    @flask_app.post("/api/cases/<case_id>/pivot")
    def pivot_case_node(case_id: str) -> tuple[Any, int]:
        data = request.get_json(silent=True) or {}
        try:
            req = PivotNodeRequest.model_validate(data)
        except ValidationError as exc:
            return jsonify({"detail": exc.errors()}), 422
        try:
            res = _run_coro_sync(service.pivot_node(case_id, req))
            return jsonify(res), 200
        except KeyError as exc:
            return jsonify({"detail": str(exc)}), 404

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
        try:
            content, media_type = _run_coro_sync(service.export_report(case_id, fmt))
            return FlaskResponse(content, status=200, mimetype=media_type)
        except KeyError as exc:
            return jsonify({"detail": str(exc)}), 404
        except ValueError as exc:
            return jsonify({"detail": str(exc)}), 400

    return flask_app


def get_default_app() -> Any:
    """Factory returning a default configured OmniSINT web application."""
    return create_app()
