"""Abstract BaseCollector, rate-limiting, caching, custody integration, and CollectorRegistry."""

from __future__ import annotations

import asyncio
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from typing import Any, Awaitable, Callable

from pydantic import BaseModel, ConfigDict, Field

from omnisint.config import OmniSINTSettings, get_settings
from omnisint.core.custody import CustodyLedger
from omnisint.core.models import CollectorResult, EntityType, EvidenceItem
from omnisint.core.storage import CaseStorage

try:
    import httpx  # type: ignore[import-untyped]

    HAS_HTTPX = True
except ImportError:  # pragma: no cover
    httpx = None
    HAS_HTTPX = False


class HttpResponseData(BaseModel):
    """Normalized HTTP response returned by collector transports."""

    model_config = ConfigDict(extra="forbid")

    status_code: int
    body: str | dict[str, Any] | list[Any]
    headers: dict[str, str] = Field(default_factory=dict)


HttpGetTransportCallable = Callable[
    [str, dict[str, str] | None, dict[str, Any] | None, float],
    Awaitable[HttpResponseData | tuple[int, Any] | dict[str, Any] | list[Any] | str],
]


class CollectorConfig(BaseModel):
    """Runtime configuration for passive OSINT collectors."""

    model_config = ConfigDict(extra="forbid")

    timeout_seconds: float = Field(default=15.0, gt=0.0)
    max_retries: int = Field(default=2, ge=0, le=5)
    backoff_base_seconds: float = Field(default=0.25, ge=0.0)
    rate_limit_per_second: float = Field(default=5.0, gt=0.0)
    use_cache: bool = True
    cache_ttl_seconds: int = Field(default=86400, ge=0)
    max_concurrency: int = Field(default=5, ge=1, le=50)
    user_agent: str = "OmniSINT/0.1.0 (+https://github.com/SamAlex-22/OmniSINT; Passive-OSINT)"


async def _default_urllib_get(
    url: str,
    headers: dict[str, str] | None,
    params: dict[str, Any] | None,
    timeout: float,
) -> HttpResponseData:
    """Perform an async HTTP GET via httpx (when installed) or stdlib urllib in a worker thread."""
    final_url = url
    if params:
        query_str = urllib.parse.urlencode({k: str(v) for k, v in params.items()})
        sep = "&" if "?" in url else "?"
        final_url = f"{url}{sep}{query_str}"

    if HAS_HTTPX and httpx is not None:  # pragma: no cover
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(final_url, headers=headers or {})
            raw_text = resp.text
            parsed_body: str | dict[str, Any] | list[Any] = raw_text
            ctype = resp.headers.get("content-type", "").lower()
            if "json" in ctype or raw_text.lstrip().startswith(("{", "[")):
                try:
                    parsed_body = json.loads(raw_text)
                except ValueError:
                    parsed_body = raw_text
            return HttpResponseData(
                status_code=resp.status_code,
                body=parsed_body,
                headers={k.lower(): v for k, v in resp.headers.items()},
            )

    def _sync_get() -> HttpResponseData:
        req = urllib.request.Request(final_url, headers=headers or {}, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                raw_bytes = resp.read()
                raw_text = raw_bytes.decode("utf-8", errors="replace")
                ctype = str(resp.headers.get("Content-Type", "")).lower()
                parsed_body: str | dict[str, Any] | list[Any] = raw_text
                if "json" in ctype or raw_text.lstrip().startswith(("{", "[")):
                    try:
                        parsed_body = json.loads(raw_text)
                    except ValueError:
                        parsed_body = raw_text
                return HttpResponseData(
                    status_code=int(getattr(resp, "status", 200)),
                    body=parsed_body,
                    headers={k.lower(): v for k, v in resp.headers.items()},
                )
        except urllib.error.HTTPError as err:
            raw_err = err.read().decode("utf-8", errors="replace")
            return HttpResponseData(
                status_code=int(err.code),
                body=raw_err,
                headers={k.lower(): v for k, v in err.headers.items()} if err.headers else {},
            )

    return await asyncio.to_thread(_sync_get)


class BaseCollector(ABC):
    """Abstract base class for all passive OmniSINT OSINT collectors."""

    name: str = "base_collector"
    description: str = "Abstract OmniSINT passive collector"
    supported_types: tuple[EntityType, ...] = ()

    def __init__(
        self,
        config: CollectorConfig | None = None,
        settings: OmniSINTSettings | None = None,
        http_transport: HttpGetTransportCallable | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.config = config or CollectorConfig(
            timeout_seconds=self.settings.http_timeout_seconds,
            cache_ttl_seconds=self.settings.cache_ttl_seconds,
            max_concurrency=self.settings.max_concurrent_requests,
            user_agent=self.settings.user_agent,
        )
        self._http_transport: HttpGetTransportCallable = http_transport or _default_urllib_get
        self._rate_lock = asyncio.Lock()
        self._last_request_ts: float = 0.0

    def supports(self, entity_type: EntityType) -> bool:
        """Return True if this collector can pivot on or collect for `entity_type`."""
        return entity_type in self.supported_types

    async def _respect_rate_limit(self) -> None:
        """Enforce minimum inter-request spacing based on `rate_limit_per_second`."""
        min_interval = 1.0 / self.config.rate_limit_per_second
        async with self._rate_lock:
            now = time.monotonic()
            elapsed = now - self._last_request_ts
            if elapsed < min_interval:
                await asyncio.sleep(min_interval - elapsed)
            self._last_request_ts = time.monotonic()

    @staticmethod
    def _normalize_transport_output(
        raw: HttpResponseData | tuple[int, Any] | dict[str, Any] | list[Any] | str,
    ) -> HttpResponseData:
        """Normalize custom transport return shapes into HttpResponseData."""
        if isinstance(raw, HttpResponseData):
            return raw
        if isinstance(raw, tuple) and len(raw) == 2:
            return HttpResponseData(status_code=int(raw[0]), body=raw[1])
        return HttpResponseData(status_code=200, body=raw)

    async def fetch_with_custody(
        self,
        url: str,
        case_id: str,
        ledger: CustodyLedger | None = None,
        storage: CaseStorage | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        notes: str = "",
        record_on_non_200: bool = False,
    ) -> tuple[int, str | dict[str, Any] | list[Any], EvidenceItem | None, bool]:
        """Fetch an external OSINT resource with TTL caching, rate-limiting, backoff, and custody hashing."""
        if storage is not None and self.config.use_cache:
            cached = await storage.get_cached_response(self.name, url, params=params)
            if cached is not None:
                ev_item: EvidenceItem | None = None
                if cached.status_code == 200 or record_on_non_200:
                    ev_item = self._record_custody_item(
                        case_id=case_id,
                        ledger=ledger,
                        source_uri=url,
                        payload=cached.payload,
                        notes=f"{notes} [cache-hit]".strip(),
                    )
                return cached.status_code, cached.payload, ev_item, True

        req_headers = {"User-Agent": self.config.user_agent, "Accept": "application/json"}
        if headers:
            req_headers.update(headers)

        last_exc: Exception | None = None
        response: HttpResponseData | None = None

        for attempt in range(self.config.max_retries + 1):
            await self._respect_rate_limit()
            try:
                raw_out = await self._http_transport(
                    url,
                    req_headers,
                    params,
                    self.config.timeout_seconds,
                )
                response = self._normalize_transport_output(raw_out)
                if response.status_code in (429, 500, 502, 503, 504) and attempt < self.config.max_retries:
                    await asyncio.sleep(self.config.backoff_base_seconds * (2**attempt))
                    continue
                break
            except Exception as exc:
                last_exc = exc
                if attempt < self.config.max_retries:
                    await asyncio.sleep(self.config.backoff_base_seconds * (2**attempt))
                    continue
                raise

        if response is None:  # pragma: no cover
            if last_exc is not None:
                raise last_exc
            raise RuntimeError(f"Collector {self.name} received no response for {url}")

        if (
            storage is not None
            and self.config.use_cache
            and response.status_code == 200
        ):
            await storage.set_cached_response(
                collector_name=self.name,
                query_or_uri=url,
                payload=response.body,
                status_code=response.status_code,
                params=params,
                ttl_seconds=self.config.cache_ttl_seconds,
            )

        evidence_item: EvidenceItem | None = None
        if response.status_code == 200 or record_on_non_200:
            mime = (
                "application/json"
                if isinstance(response.body, (dict, list))
                else response.headers.get("content-type", "text/plain").split(";")[0]
            )
            evidence_item = self._record_custody_item(
                case_id=case_id,
                ledger=ledger,
                source_uri=url,
                payload=response.body,
                mime_type=mime,
                notes=notes,
            )

        return response.status_code, response.body, evidence_item, False

    def _record_custody_item(
        self,
        case_id: str,
        ledger: CustodyLedger | None,
        source_uri: str,
        payload: str | dict[str, Any] | list[Any],
        mime_type: str = "application/json",
        notes: str = "",
    ) -> EvidenceItem:
        """Record an EvidenceItem onto the provided CustodyLedger or a local ledger."""
        active_ledger = ledger if ledger is not None else CustodyLedger(case_id=case_id)
        return active_ledger.record_evidence(
            collector_name=self.name,
            source_uri=source_uri,
            raw_payload=payload,
            mime_type=mime_type,
            notes=notes,
            actor=self.name,
        )

    @abstractmethod
    async def collect(
        self,
        query: str,
        case_id: str,
        ledger: CustodyLedger | None = None,
        storage: CaseStorage | None = None,
    ) -> CollectorResult:
        """Execute passive collection for `query` and return a standardized CollectorResult."""


class CollectorRegistry:
    """Registry for discovering and dispatching OmniSINT Collector plugins."""

    def __init__(self) -> None:
        self._collectors: dict[str, BaseCollector] = {}

    def register(self, collector: BaseCollector) -> None:
        """Register a collector instance by its unique `name`."""
        self._collectors[collector.name] = collector

    def unregister(self, name: str) -> None:
        """Remove a collector from the registry if present."""
        self._collectors.pop(name, None)

    def get(self, name: str) -> BaseCollector | None:
        """Return a registered collector by name."""
        return self._collectors.get(name)

    def list_collectors(self) -> list[BaseCollector]:
        """Return all registered collectors sorted by name."""
        return [self._collectors[k] for k in sorted(self._collectors.keys())]

    def get_for_entity_type(self, entity_type: EntityType) -> list[BaseCollector]:
        """Return all registered collectors capable of handling `entity_type`."""
        return [
            c
            for c in self.list_collectors()
            if c.supports(entity_type)
        ]
