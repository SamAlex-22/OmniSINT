"""Abstract BaseCollector, rate-limiting, caching, proxy routing, secret redaction, custody integration, and CollectorRegistry."""

from __future__ import annotations

import asyncio
import json
import threading
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

_SENSITIVE_QUERY_KEYS: frozenset[str] = frozenset(
    {"key", "api_key", "apikey", "token", "access_token", "secret", "auth"}
)


def redact_sensitive_url(url: str) -> str:
    """Mask sensitive query parameters (e.g. API keys/tokens) before storing URIs in custody or cache."""
    parsed = urllib.parse.urlsplit(url)
    if not parsed.query:
        return url
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    redacted_pairs: list[tuple[str, str]] = []
    changed = False
    for k, v in pairs:
        if k.strip().lower() in _SENSITIVE_QUERY_KEYS and v:
            redacted_pairs.append((k, "REDACTED"))
            changed = True
        else:
            redacted_pairs.append((k, v))
    if not changed:
        return url
    new_query = urllib.parse.urlencode(redacted_pairs)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))


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
    http_proxy: str | None = None


async def _default_urllib_get(
    url: str,
    headers: dict[str, str] | None,
    params: dict[str, Any] | None,
    timeout: float,
    proxy_url: str | None = None,
) -> HttpResponseData:
    """Perform an async HTTP GET via httpx (when installed) or stdlib urllib in a worker thread."""
    final_url = url
    if params:
        query_str = urllib.parse.urlencode({k: str(v) for k, v in params.items()})
        sep = "&" if "?" in url else "?"
        final_url = f"{url}{sep}{query_str}"

    if HAS_HTTPX and httpx is not None:  # pragma: no cover
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, proxy=proxy_url) as client:
            resp = await client.get(final_url, headers=headers or {})
            raw_text = resp.text
            parsed_body: str | dict[str, Any] | list[Any] = raw_text
            ctype = resp.headers.get("content-type", "").lower()
            if "json" in ctype or raw_text.lstrip().startswith(("{", "[")):
                try:
                    parsed_body = json.loads(raw_text)
                except ValueError:
                    parsed_body = raw_text
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            resp_headers.setdefault("x-final-url", str(resp.url))
            return HttpResponseData(
                status_code=resp.status_code,
                body=parsed_body,
                headers=resp_headers,
            )

    def _sync_get() -> HttpResponseData:
        req = urllib.request.Request(final_url, headers=headers or {}, method="GET")
        opener = (
            urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
            )
            if proxy_url
            else urllib.request.build_opener()
        )
        try:
            with opener.open(req, timeout=timeout) as resp:  # noqa: S310
                raw_bytes = resp.read()
                raw_text = raw_bytes.decode("utf-8", errors="replace")
                ctype = str(resp.headers.get("Content-Type", "")).lower()
                parsed_body: str | dict[str, Any] | list[Any] = raw_text
                if "json" in ctype or raw_text.lstrip().startswith(("{", "[")):
                    try:
                        parsed_body = json.loads(raw_text)
                    except ValueError:
                        parsed_body = raw_text
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                resp_headers.setdefault("x-final-url", str(resp.geturl()))
                return HttpResponseData(
                    status_code=int(getattr(resp, "status", 200)),
                    body=parsed_body,
                    headers=resp_headers,
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
            http_proxy=self.settings.http_proxy,
        )
        self._has_custom_transport = http_transport is not None
        if http_transport is not None:
            self._http_transport: HttpGetTransportCallable = http_transport
        else:
            proxy_url = self.config.http_proxy

            async def _proxied_default_get(
                url: str,
                headers: dict[str, str] | None,
                params: dict[str, Any] | None,
                timeout: float,
            ) -> HttpResponseData:
                return await _default_urllib_get(url, headers, params, timeout, proxy_url=proxy_url)

            self._http_transport = _proxied_default_get
        self._rate_lock = threading.Lock()
        self._last_request_ts: float = 0.0

    def supports(self, entity_type: EntityType) -> bool:
        """Return True if this collector can pivot on or collect for `entity_type`."""
        return entity_type in self.supported_types

    async def _respect_rate_limit(self) -> None:
        """Enforce minimum inter-request spacing based on `rate_limit_per_second`."""
        min_interval = 1.0 / self.config.rate_limit_per_second
        with self._rate_lock:
            now = time.monotonic()
            next_allowed = max(
                now,
                self._last_request_ts + min_interval if self._last_request_ts > 0.0 else now,
            )
            wait_seconds = max(0.0, next_allowed - now)
            self._last_request_ts = next_allowed
        if wait_seconds > 0.0:
            await asyncio.sleep(wait_seconds)

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
        """Fetch an external OSINT resource with TTL caching, rate-limiting, secret redaction, and custody hashing."""
        status_code, payload, ev_item, from_cache, _ = await self._fetch_with_custody_full(
            url=url,
            case_id=case_id,
            ledger=ledger,
            storage=storage,
            params=params,
            headers=headers,
            notes=notes,
            record_on_non_200=record_on_non_200,
        )
        return status_code, payload, ev_item, from_cache

    async def _fetch_with_custody_full(
        self,
        url: str,
        case_id: str,
        ledger: CustodyLedger | None = None,
        storage: CaseStorage | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        notes: str = "",
        record_on_non_200: bool = False,
    ) -> tuple[int, str | dict[str, Any] | list[Any], EvidenceItem | None, bool, dict[str, str]]:
        """Internal variant of `fetch_with_custody` that also returns normalized HTTP response headers."""
        sanitized_url = redact_sensitive_url(url)

        if storage is not None and self.config.use_cache:
            cached = await storage.get_cached_response(self.name, sanitized_url, params=params)
            if cached is not None:
                ev_item: EvidenceItem | None = None
                if cached.status_code == 200 or record_on_non_200:
                    ev_item = self._record_custody_item(
                        case_id=case_id,
                        ledger=ledger,
                        source_uri=sanitized_url,
                        payload=cached.payload,
                        notes=f"{notes} [cache-hit]".strip(),
                    )
                return cached.status_code, cached.payload, ev_item, True, {}

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
            raise RuntimeError(f"Collector {self.name} received no response for {sanitized_url}")

        if (
            storage is not None
            and self.config.use_cache
            and response.status_code == 200
        ):
            await storage.set_cached_response(
                collector_name=self.name,
                query_or_uri=sanitized_url,
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
                source_uri=sanitized_url,
                payload=response.body,
                mime_type=mime,
                notes=notes,
            )

        return response.status_code, response.body, evidence_item, False, dict(response.headers)

    async def fetch_bytes(self, url: str, max_bytes: int = 2_000_000) -> bytes | None:
        """Download raw bytes (e.g. avatar images) safely up to `max_bytes`."""
        cleaned_url = url.strip()
        if not cleaned_url:
            return None

        if self._has_custom_transport:
            await self._respect_rate_limit()
            try:
                raw_out = await self._http_transport(
                    cleaned_url,
                    {"User-Agent": self.config.user_agent, "Accept": "image/*,*/*"},
                    None,
                    self.config.timeout_seconds,
                )
            except Exception:
                return None
            if isinstance(raw_out, bytes):
                return raw_out[:max_bytes]
            resp = self._normalize_transport_output(raw_out)
            if resp.status_code != 200:
                return None
            if isinstance(resp.body, dict) and isinstance(resp.body.get("bytes_hex"), str):
                try:
                    return bytes.fromhex(resp.body["bytes_hex"])[:max_bytes]
                except ValueError:
                    return None
            if isinstance(resp.body, str) and resp.body:
                return resp.body.encode("latin-1", errors="replace")[:max_bytes]
            return None

        def _sync_fetch_bytes() -> bytes | None:
            req = urllib.request.Request(
                cleaned_url,
                headers={"User-Agent": self.config.user_agent, "Accept": "image/*,*/*"},
                method="GET",
            )
            proxy_url = self.config.http_proxy
            opener = (
                urllib.request.build_opener(
                    urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
                )
                if proxy_url
                else urllib.request.build_opener()
            )
            try:
                with opener.open(req, timeout=self.config.timeout_seconds) as resp:  # noqa: S310
                    if int(getattr(resp, "status", 200)) != 200:
                        return None
                    data = resp.read(max_bytes + 1)
                    if len(data) > max_bytes:
                        return data[:max_bytes]
                    return data
            except Exception:
                return None

        await self._respect_rate_limit()
        return await asyncio.to_thread(_sync_fetch_bytes)

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
