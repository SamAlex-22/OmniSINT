"""Compliant Scrapling-powered public page & JS-rendered profile collector.

Strictly adheres to OmniSINT passive OSINT guardrails:
- Escalates only from static HTTP (`scrapling.fetchers.Fetcher` / stdlib HTTP)
  to headless browser rendering (`scrapling.fetchers.DynamicFetcher`) for public
  JavaScript-rendered pages.
- Parses DOM metadata cleanly via `scrapling.parser.Selector` (or stdlib HTMLParser fallback).
- NEVER imports or uses stealth bypasses (`StealthyFetcher`, `solve_cloudflare`) and
  immediately aborts cleanly when encountering login walls, HTTP 401/403/429 gates,
  Cloudflare challenges, or CAPTCHAs.
"""

from __future__ import annotations

import asyncio
import json
import re
import urllib.parse
from collections.abc import Awaitable, Callable
from html.parser import HTMLParser
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from omnisint.collectors.base import (
    BaseCollector,
    CollectorConfig,
    HttpGetTransportCallable,
    redact_sensitive_url,
)
from omnisint.config import OmniSINTSettings
from omnisint.core.custody import CustodyLedger
from omnisint.core.models import (
    CollectorResult,
    EntityNode,
    EntityType,
    EvidenceItem,
    RelationshipEdge,
    RelationType,
)
from omnisint.core.storage import CaseStorage
from omnisint.intelligence.entropy import analyze_handle_entropy
from omnisint.intelligence.similarity import compute_dhash_from_bytes

try:
    from scrapling.fetchers import Fetcher  # type: ignore[import-untyped]

    HAS_SCRAPLING_FETCHERS = True
except ImportError:  # pragma: no cover
    Fetcher = None
    HAS_SCRAPLING_FETCHERS = False

try:
    from scrapling.fetchers import DynamicFetcher  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover
    DynamicFetcher = None

try:
    from playwright.async_api import async_playwright  # type: ignore[import-untyped]

    HAS_PLAYWRIGHT = True
except ImportError:  # pragma: no cover
    async_playwright = None
    HAS_PLAYWRIGHT = False

try:
    from scrapling.parser import Selector  # type: ignore[import-untyped]

    HAS_SCRAPLING_SELECTOR = True
except ImportError:  # pragma: no cover
    Selector = None
    HAS_SCRAPLING_SELECTOR = False


DEFAULT_PROFILE_URL_TEMPLATES: dict[str, str] = {
    "Instagram": "https://www.instagram.com/{handle}/",
    "GitHub": "https://github.com/{handle}",
    "Reddit": "https://www.reddit.com/user/{handle}/",
}

_PLATFORM_HOST_MAP: dict[str, str] = {
    "instagram.com": "Instagram",
    "github.com": "GitHub",
    "reddit.com": "Reddit",
    "x.com": "Twitter",
    "twitter.com": "Twitter",
    "linkedin.com": "LinkedIn",
    "tiktok.com": "TikTok",
    "youtube.com": "YouTube",
    "gitlab.com": "GitLab",
    "bsky.app": "Bluesky",
    "keybase.io": "Keybase",
    "dev.to": "DevTo",
}

_LOGIN_URL_MARKERS: tuple[str, ...] = (
    "/accounts/login",
    "/login?",
    "/signin",
    "/authwall",
)

_CAPTCHA_HTML_MARKERS: tuple[str, ...] = (
    "g-recaptcha",
    "h-captcha",
    "cf-turnstile",
    "verify you are human",
    "attention required! | cloudflare",
    "cdn-cgi/challenge-platform",
    "datadome",
    "perimeterx",
)

_LOGIN_HTML_MARKERS: tuple[str, ...] = (
    "log in to instagram",
    "sign in to continue",
    "authwall",
)

_NOISE_LINK_MARKERS: tuple[str, ...] = (
    "/accounts/login",
    "/accounts/emailsignup",
    "/login",
    "/signup",
    "/register",
    "/privacy",
    "/terms",
    "sharer.php",
    "intent/tweet",
)

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_MENTION_RE = re.compile(r"(?<![A-Za-z0-9_.+-])@([A-Za-z0-9_](?:[A-Za-z0-9_.]*[A-Za-z0-9_])?)")
_HASHTAG_RE = re.compile(r"(?<![A-Za-z0-9_])#([A-Za-z0-9_]{2,50})")
_MULTIPLIER_MAP: dict[str, float] = {"": 1.0, "k": 1_000.0, "m": 1_000_000.0, "b": 1_000_000_000.0}


class ScrapedPageData(BaseModel):
    """Normalized HTTP or headless browser response captured by ScraplingCollector."""

    model_config = ConfigDict(extra="forbid")

    url: str
    final_url: str
    status_code: int
    html: str
    fetcher_used: str
    blocked_reason: str | None = None


class ExtractedProfileMetadata(BaseModel):
    """Structured OSINT profile metadata parsed from public HTML."""

    model_config = ConfigDict(extra="forbid")

    url: str
    platform: str = "Web"
    title: str = ""
    display_name: str = ""
    bio: str = ""
    avatar_url: str = ""
    external_links: list[str] = Field(default_factory=list)
    mentions: list[str] = Field(default_factory=list)
    hashtags: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    locations: list[str] = Field(default_factory=list)
    follower_count: int | None = None
    following_count: int | None = None
    post_count: int | None = None
    json_ld_types: list[str] = Field(default_factory=list)


PageFetcherCallable = Callable[[str, bool], Awaitable[ScrapedPageData]]


def detect_access_gate(status_code: int, html: str, final_url: str = "") -> str | None:
    """Detect HTTP rate limits, auth walls, login redirects, and CAPTCHA gates without bypassing them."""
    if status_code == 429:
        return "http_429_rate_limited"
    if status_code == 401:
        return "http_401_unauthorized"
    if status_code == 403:
        return "http_403_forbidden"

    lower_url = final_url.strip().lower()
    if any(marker in lower_url for marker in _LOGIN_URL_MARKERS) or lower_url.rstrip("/").endswith("/login"):
        return "login_wall"

    lower_html = (html or "").lower()
    if any(marker in lower_html for marker in _CAPTCHA_HTML_MARKERS):
        return "captcha_or_antibot_gate"
    if any(marker in lower_html for marker in _LOGIN_HTML_MARKERS):
        return "login_wall"

    return None


class _StdlibMetaParser(HTMLParser):
    """Stdlib HTMLParser extracting title, meta tags, canonical link, JSON-LD blocks, and anchors."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self._in_title = False
        self._in_ld_json = False
        self._ld_parts: list[str] = []
        self.meta: dict[str, str] = {}
        self.canonical_url: str = ""
        self.json_ld_raw: list[str] = []
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_lower = tag.lower()
        attr_map = {k.lower(): (v or "") for k, v in attrs if k}
        if tag_lower == "title":
            self._in_title = True
        elif tag_lower == "meta":
            key = (attr_map.get("property") or attr_map.get("name") or "").strip().lower()
            content = attr_map.get("content", "").strip()
            if key and content:
                self.meta.setdefault(key, content)
        elif tag_lower == "link":
            rel_tokens = attr_map.get("rel", "").lower().split()
            href = attr_map.get("href", "").strip()
            if "canonical" in rel_tokens and href and not self.canonical_url:
                self.canonical_url = href
        elif tag_lower == "script":
            stype = attr_map.get("type", "").lower()
            if "ld+json" in stype:
                self._in_ld_json = True
                self._ld_parts = []
        elif tag_lower == "a":
            href = attr_map.get("href", "").strip()
            if href:
                self.links.append(href)

    def handle_endtag(self, tag: str) -> None:
        tag_lower = tag.lower()
        if tag_lower == "title":
            self._in_title = False
        elif tag_lower == "script" and self._in_ld_json:
            self._in_ld_json = False
            joined = "".join(self._ld_parts).strip()
            if joined:
                self.json_ld_raw.append(joined)
            self._ld_parts = []

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)
        elif self._in_ld_json:
            self._ld_parts.append(data)


def _extract_raw_html_fields(
    html: str,
    use_scrapling_selector: bool = True,
) -> tuple[str, dict[str, str], str, list[str], list[str]]:
    """Parse raw HTML into `(title, meta_map, canonical_url, json_ld_raw, links)`."""
    if use_scrapling_selector and HAS_SCRAPLING_SELECTOR and Selector is not None:  # pragma: no cover
        sel = Selector(html)
        title = str(sel.css("title::text").get() or "").strip()
        meta: dict[str, str] = {}
        for m in sel.css("meta"):
            attrs = getattr(m, "attrib", {}) or {}
            key = str(attrs.get("property") or attrs.get("name") or "").strip().lower()
            val = str(attrs.get("content") or "").strip()
            if key and val and key not in meta:
                meta[key] = val
        canonical = str(sel.css("link[rel='canonical']::attr(href)").get() or "").strip()
        ld_raw: list[str] = []
        for s in sel.css("script[type='application/ld+json']"):
            raw_txt = str(s.css("::text").get() or getattr(s, "text", "") or "").strip()
            if raw_txt:
                ld_raw.append(raw_txt)
        links = [str(u).strip() for u in sel.css("a::attr(href)").getall() if str(u).strip()]
        return title, meta, canonical, ld_raw, links

    parser = _StdlibMetaParser()
    parser.feed(html or "")
    parser.close()
    title = "".join(parser.title_parts).strip()
    return title, parser.meta, parser.canonical_url, parser.json_ld_raw, parser.links


def extract_html_canonical_and_og_url(
    html: str,
    use_scrapling_selector: bool = True,
) -> tuple[str, str]:
    """Return `(canonical_url, og_url)` from raw HTML for soft redirect detection."""
    _, meta, canonical, _, _ = _extract_raw_html_fields(
        html,
        use_scrapling_selector=use_scrapling_selector,
    )
    return canonical, meta.get("og:url", "")


def _infer_platform_from_url(url: str, og_site_name: str = "") -> str:
    """Determine a normalized platform name from URL host or OpenGraph site_name."""
    host = urllib.parse.urlsplit(url).netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    for domain_suffix, label in _PLATFORM_HOST_MAP.items():
        if host == domain_suffix or host.endswith(f".{domain_suffix}"):
            return label
    if "mastodon" in host:
        return "Mastodon"
    return og_site_name.strip() or "Web"


def _parse_human_count(raw_token: str) -> int | None:
    """Convert numeric tokens like '1,234', '12.5K', or '1.2M' into integer counts."""
    cleaned = raw_token.strip().replace(",", "")
    match = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([KkMmBb]?)", cleaned)
    if not match:
        return None
    base = float(match.group(1))
    mult = _MULTIPLIER_MAP.get(match.group(2).lower(), 1.0)
    return int(round(base * mult))


def _extract_metric_count(text_blobs: list[str], metric_pattern: str) -> int | None:
    """Search candidate descriptions for social counts like Followers / Following / Posts."""
    regex = re.compile(rf"([\d,.]+\s*[KkMmBb]?)\s+{metric_pattern}\b", re.IGNORECASE)
    for blob in text_blobs:
        m = regex.search(blob)
        if m:
            parsed = _parse_human_count(m.group(1))
            if parsed is not None:
                return parsed
    return None


def _clean_display_title(raw_title: str) -> str:
    """Strip common platform branding suffixes from `<title>` / `og:title` values."""
    cleaned = raw_title.strip()
    for sep in (" • Instagram photos and videos", " · GitHub", " - YouTube"):
        if cleaned.endswith(sep):
            cleaned = cleaned[: -len(sep)].strip()
    return cleaned


def _dedupe_preserve_order(items: list[str], limit: int | None = None) -> list[str]:
    """Deduplicate strings case-insensitively while preserving first-seen order."""
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        stripped = item.strip()
        key = stripped.lower()
        if not stripped or key in seen:
            continue
        seen.add(key)
        out.append(stripped)
        if limit is not None and len(out) >= limit:
            break
    return out


def _flatten_json_ld_objects(raw_blocks: list[str]) -> list[dict[str, Any]]:
    """Parse JSON-LD script blocks into a flat list of dictionary nodes."""
    objects: list[dict[str, Any]] = []

    def _collect_node(obj: Any) -> None:
        if isinstance(obj, list):
            for entry in obj:
                _collect_node(entry)
        elif isinstance(obj, dict):
            objects.append(obj)
            if isinstance(obj.get("@graph"), list):
                _collect_node(obj["@graph"])
            if isinstance(obj.get("mainEntity"), (dict, list)):
                _collect_node(obj["mainEntity"])

    for raw in raw_blocks:
        try:
            parsed = json.loads(raw)
        except ValueError:
            continue
        _collect_node(parsed)
    return objects


def _extract_location_string(value: Any) -> str:
    """Convert schema.org `address` or `location` objects into a readable location string."""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        if isinstance(value.get("name"), str) and value["name"].strip():
            return value["name"].strip()
        parts: list[str] = []
        for field in ("addressLocality", "addressRegion", "addressCountry"):
            val = value.get(field)
            if isinstance(val, str) and val.strip():
                parts.append(val.strip())
            elif isinstance(val, dict) and isinstance(val.get("name"), str) and val["name"].strip():
                parts.append(val["name"].strip())
        return ", ".join(parts)
    return ""


def _is_valid_external_url(candidate: str, page_url: str) -> bool:
    """Keep public http(s) URLs that are distinct from `page_url` and not auth/share noise."""
    parsed = urllib.parse.urlsplit(candidate.strip())
    if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
        return False
    lower = candidate.strip().lower()
    if lower.rstrip("/") == page_url.strip().rstrip("/").lower():
        return False
    return not any(noise in lower for noise in _NOISE_LINK_MARKERS)


def parse_public_profile_html(
    html: str,
    url: str,
    use_scrapling_selector: bool = True,
) -> ExtractedProfileMetadata:
    """Extract OpenGraph, Twitter Card, JSON-LD, links, @mentions, #hashtags, emails & counts from public HTML."""
    title, meta, _, ld_raw, links = _extract_raw_html_fields(
        html,
        use_scrapling_selector=use_scrapling_selector,
    )
    platform = _infer_platform_from_url(url, meta.get("og:site_name", ""))
    og_title = meta.get("og:title") or meta.get("twitter:title") or title
    og_desc = meta.get("og:description") or meta.get("description") or meta.get("twitter:description") or ""
    og_img = meta.get("og:image") or meta.get("twitter:image") or meta.get("twitter:image:src") or ""

    ld_types: list[str] = []
    ld_name = ""
    ld_desc = ""
    ld_img = ""
    ld_links: list[str] = []
    emails: list[str] = []
    locations: list[str] = []
    alt_names: list[str] = []

    for obj in _flatten_json_ld_objects(ld_raw):
        raw_type = obj.get("@type")
        if isinstance(raw_type, str) and raw_type.strip():
            ld_types.append(raw_type.strip())
        elif isinstance(raw_type, list):
            ld_types.extend(str(t).strip() for t in raw_type if str(t).strip())

        if not ld_name and isinstance(obj.get("name"), str):
            ld_name = obj["name"].strip()
        if not ld_desc and isinstance(obj.get("description"), str):
            ld_desc = obj["description"].strip()

        alt = obj.get("alternateName")
        if isinstance(alt, str) and alt.strip():
            alt_names.append(alt.strip())

        if not ld_img:
            img_val = obj.get("image")
            if isinstance(img_val, str):
                ld_img = img_val.strip()
            elif isinstance(img_val, dict) and isinstance(img_val.get("url"), str):
                ld_img = img_val["url"].strip()
            elif isinstance(img_val, list) and img_val:
                first_img = img_val[0]
                if isinstance(first_img, str):
                    ld_img = first_img.strip()
                elif isinstance(first_img, dict) and isinstance(first_img.get("url"), str):
                    ld_img = first_img["url"].strip()

        email_val = obj.get("email")
        if isinstance(email_val, str) and email_val.strip():
            cleaned_email = email_val.strip().removeprefix("mailto:")
            if _EMAIL_RE.fullmatch(cleaned_email):
                emails.append(cleaned_email)

        same_as = obj.get("sameAs")
        if isinstance(same_as, str):
            ld_links.append(same_as.strip())
        elif isinstance(same_as, list):
            ld_links.extend(str(x).strip() for x in same_as if isinstance(x, str))
        if isinstance(obj.get("url"), str):
            ld_links.append(obj["url"].strip())

        for loc_key in ("address", "homeLocation", "workLocation", "location"):
            if loc_key in obj:
                loc_str = _extract_location_string(obj[loc_key])
                if loc_str:
                    locations.append(loc_str)

    for meta_loc_key in ("profile:location", "og:locality", "geo.placename"):
        if meta.get(meta_loc_key):
            locations.append(meta[meta_loc_key])

    for href in links:
        if href.lower().startswith("mailto:"):
            addr = href[7:].split("?", 1)[0].strip()
            if _EMAIL_RE.fullmatch(addr):
                emails.append(addr)

    bio = ld_desc or og_desc
    display_name = ld_name or _clean_display_title(og_title) or title
    avatar_url = ld_img or og_img

    candidate_links = [
        href for href in (ld_links + links) if _is_valid_external_url(href, url)
    ]
    external_links = _dedupe_preserve_order(candidate_links, limit=10)

    text_blobs = [bio, og_desc, og_title, title] + alt_names
    combined_text = "\n".join(b for b in text_blobs if b)

    raw_mentions = [f"@{m}" for m in _MENTION_RE.findall(combined_text)]
    for alt in alt_names:
        norm_alt = alt.lstrip("@")
        if re.fullmatch(r"[A-Za-z0-9_.]{2,39}", norm_alt):
            raw_mentions.append(f"@{norm_alt}")
    mentions = _dedupe_preserve_order(raw_mentions)

    hashtags = _dedupe_preserve_order([f"#{h}" for h in _HASHTAG_RE.findall(combined_text)])
    emails.extend(_EMAIL_RE.findall(combined_text))

    return ExtractedProfileMetadata(
        url=url,
        platform=platform,
        title=title or og_title,
        display_name=display_name,
        bio=bio,
        avatar_url=avatar_url,
        external_links=external_links,
        mentions=mentions,
        hashtags=hashtags,
        emails=_dedupe_preserve_order([e.lower() for e in emails]),
        locations=_dedupe_preserve_order(locations),
        follower_count=_extract_metric_count(text_blobs, r"followers?"),
        following_count=_extract_metric_count(text_blobs, r"following"),
        post_count=_extract_metric_count(text_blobs, r"posts?"),
        json_ld_types=_dedupe_preserve_order(ld_types),
    )


def _extract_scrapling_response(
    page: Any,
    requested_url: str,
    fetcher_used: str,
) -> ScrapedPageData:
    """Normalize a Scrapling Response object into ScrapedPageData."""
    status_code = int(getattr(page, "status", None) or getattr(page, "status_code", 200))
    final_url = str(getattr(page, "url", requested_url) or requested_url)
    raw_html = getattr(page, "html_content", None)
    if raw_html is None:
        raw_body = getattr(page, "body", None)
        if isinstance(raw_body, (bytes, bytearray)):
            raw_html = raw_body.decode("utf-8", errors="replace")
        elif raw_body is not None:
            raw_html = str(raw_body)
        else:
            raw_html = str(getattr(page, "text", None) or page or "")
    html_str = str(raw_html)
    return ScrapedPageData(
        url=requested_url,
        final_url=final_url,
        status_code=status_code,
        html=html_str,
        fetcher_used=fetcher_used,
        blocked_reason=detect_access_gate(status_code, html_str, final_url),
    )


def _run_scrapling_static(url: str, timeout_seconds: float) -> ScrapedPageData:  # pragma: no cover
    assert Fetcher is not None
    page = Fetcher.get(url, timeout=int(max(1.0, timeout_seconds)))
    return _extract_scrapling_response(page, url, "scrapling_fetcher")


def _run_scrapling_dynamic(url: str, timeout_seconds: float) -> ScrapedPageData:  # pragma: no cover
    assert DynamicFetcher is not None
    page = DynamicFetcher.fetch(
        url,
        headless=True,
        timeout=int(max(1000.0, timeout_seconds * 1000.0)),
    )
    return _extract_scrapling_response(page, url, "scrapling_dynamic")


async def _run_playwright_dynamic(
    url: str,
    timeout_seconds: float,
    user_agent: str,
) -> ScrapedPageData:  # pragma: no cover
    assert async_playwright is not None
    timeout_ms = int(max(1000.0, timeout_seconds * 1000.0))
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        try:
            page = await browser.new_page(user_agent=user_agent)
            resp = await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            status_code = int(resp.status) if resp is not None else 200
            final_url = str(page.url or url)
            html_str = await page.content()
        finally:
            await browser.close()
    return ScrapedPageData(
        url=url,
        final_url=final_url,
        status_code=status_code,
        html=html_str,
        fetcher_used="scrapling_dynamic",
        blocked_reason=detect_access_gate(status_code, html_str, final_url),
    )


def _extract_handle_from_url(url: str) -> str:
    """Best-effort handle/slug extraction from the terminal path segment of a profile URL."""
    path = urllib.parse.urlsplit(url).path.strip("/")
    if not path:
        return ""
    segments = [seg for seg in path.split("/") if seg]
    return segments[-1].lstrip("@") if segments else ""


class ScraplingCollector(BaseCollector):
    """Collects public profile & OpenGraph/JSON-LD metadata using Scrapling (or stdlib HTTP fallback)."""

    name = "scrapling_collector"
    description = (
        "Scrapes public social profiles & JS-rendered web pages via Scrapling Fetcher/"
        "DynamicFetcher and Selector, halting cleanly on auth walls or CAPTCHAs."
    )
    supported_types = (EntityType.URL, EntityType.USERNAME, EntityType.SOCIAL_PROFILE)

    def __init__(
        self,
        use_dynamic_browser: bool = False,
        profile_url_templates: dict[str, str] | None = None,
        page_fetcher: PageFetcherCallable | None = None,
        fetch_avatars: bool = True,
        max_avatar_bytes: int = 2_000_000,
        config: CollectorConfig | None = None,
        settings: OmniSINTSettings | None = None,
        http_transport: HttpGetTransportCallable | None = None,
    ) -> None:
        super().__init__(config=config, settings=settings, http_transport=http_transport)
        self.use_dynamic_browser = use_dynamic_browser
        self.profile_url_templates = dict(profile_url_templates or DEFAULT_PROFILE_URL_TEMPLATES)
        self._page_fetcher = page_fetcher
        self.fetch_avatars = fetch_avatars
        self.max_avatar_bytes = max_avatar_bytes

    async def _fetch_page(self, url: str) -> ScrapedPageData:
        """Fetch public HTML via custom fetcher, Scrapling Fetcher/DynamicFetcher, or stdlib HTTP."""
        if self._page_fetcher is not None:
            page = await self._page_fetcher(url, self.use_dynamic_browser)
            detected = page.blocked_reason or detect_access_gate(
                page.status_code,
                page.html,
                page.final_url,
            )
            if detected and page.blocked_reason != detected:
                return page.model_copy(update={"blocked_reason": detected})
            return page

        if self.use_dynamic_browser and not self._has_custom_transport:  # pragma: no cover
            if DynamicFetcher is not None:
                await self._respect_rate_limit()
                return await asyncio.to_thread(_run_scrapling_dynamic, url, self.config.timeout_seconds)
            if HAS_PLAYWRIGHT and async_playwright is not None:
                await self._respect_rate_limit()
                try:
                    return await _run_playwright_dynamic(
                        url,
                        self.config.timeout_seconds,
                        self.config.user_agent,
                    )
                except Exception:
                    if HAS_SCRAPLING_FETCHERS and Fetcher is not None:
                        return await asyncio.to_thread(
                            _run_scrapling_static,
                            url,
                            self.config.timeout_seconds,
                        )

        if HAS_SCRAPLING_FETCHERS and Fetcher is not None and not self._has_custom_transport:  # pragma: no cover
            await self._respect_rate_limit()
            return await asyncio.to_thread(_run_scrapling_static, url, self.config.timeout_seconds)

        await self._respect_rate_limit()
        raw_out = await self._http_transport(
            url,
            {"User-Agent": self.config.user_agent, "Accept": "text/html,application/xhtml+xml,*/*"},
            None,
            self.config.timeout_seconds,
        )
        resp = self._normalize_transport_output(raw_out)
        html_str = resp.body if isinstance(resp.body, str) else json.dumps(resp.body)
        final_url = resp.headers.get("x-final-url") or resp.headers.get("location") or url
        return ScrapedPageData(
            url=url,
            final_url=final_url,
            status_code=resp.status_code,
            html=html_str,
            fetcher_used="stdlib_http",
            blocked_reason=detect_access_gate(resp.status_code, html_str, final_url),
        )

    async def collect(
        self,
        query: str,
        case_id: str,
        ledger: CustodyLedger | None = None,
        storage: CaseStorage | None = None,
    ) -> CollectorResult:
        """Scrape public URL(s) or profile templates for `query` and emit evidence-backed graph entities."""
        raw_query = query.strip()
        active_ledger = ledger if ledger is not None else CustodyLedger(case_id=case_id)
        if not raw_query:
            return CollectorResult(
                collector_name=self.name,
                query=query,
                errors=["Scrapling query cannot be empty"],
            )

        is_url_query = raw_query.lower().startswith(("http://", "https://"))
        nodes: list[EntityNode] = []
        edges: list[RelationshipEdge] = []
        evidence_items: list[EvidenceItem] = []
        errors: list[str] = []
        child_node_cache: dict[tuple[EntityType, str], EntityNode] = {}

        if is_url_query:
            clean_query = raw_query
            root_node: EntityNode | None = None
            targets: list[tuple[str, str]] = [(_infer_platform_from_url(clean_query), clean_query)]
        else:
            clean_query = raw_query.lstrip("@")
            metrics = analyze_handle_entropy(clean_query)
            root_node = EntityNode(
                entity_type=EntityType.USERNAME,
                value=clean_query,
                entropy_score=metrics.shannon_entropy,
                rarity_score=metrics.rarity_score,
                confidence=0.90,
            )
            nodes.append(root_node)
            targets = [
                (platform, tmpl.replace("{}", "{handle}").replace("{handle}", clean_query))
                for platform, tmpl in self.profile_url_templates.items()
            ]

        def _get_or_create_child(
            entity_type: EntityType,
            value: str,
            ev_id: str,
            confidence: float = 0.85,
            attributes: dict[str, Any] | None = None,
        ) -> EntityNode:
            key = (entity_type, value.strip().lower())
            existing = child_node_cache.get(key)
            if existing is not None:
                if ev_id not in existing.evidence_ids:
                    existing.evidence_ids.append(ev_id)
                return existing
            node = EntityNode(
                entity_type=entity_type,
                value=value.strip(),
                confidence=confidence,
                attributes=attributes or {},
                evidence_ids=[ev_id],
            )
            child_node_cache[key] = node
            nodes.append(node)
            return node

        semaphore = asyncio.Semaphore(self.config.max_concurrency)

        async def _process_target(target_platform: str, target_url: str) -> None:
            sanitized_target = redact_sensitive_url(target_url)
            async with semaphore:
                try:
                    page = await self._fetch_page(target_url)
                except Exception as exc:
                    errors.append(f"{sanitized_target}: {type(exc).__name__}: {exc}")
                    return

                label = sanitized_target if is_url_query else target_platform
                if page.blocked_reason:
                    errors.append(
                        f"{label}: access gated ({page.blocked_reason}) — skipped without bypass"
                    )
                    return

                if page.status_code != 200 or not page.html.strip():
                    return

                sanitized_final = redact_sensitive_url(page.final_url or target_url)
                meta = parse_public_profile_html(page.html, sanitized_final)
                platform_label = meta.platform if is_url_query else (target_platform or meta.platform)

                ev_item = active_ledger.record_evidence(
                    collector_name=self.name,
                    source_uri=sanitized_final,
                    raw_payload={
                        "url": sanitized_target,
                        "final_url": sanitized_final,
                        "status_code": page.status_code,
                        "fetcher_used": page.fetcher_used,
                        "metadata": meta.model_dump(),
                        "html_excerpt": page.html[:4000],
                    },
                    mime_type="application/json",
                    notes=f"Public HTML metadata extracted from {sanitized_final} via {page.fetcher_used}",
                    actor=self.name,
                )
                evidence_items.append(ev_item)

                av_hash: str | None = None
                if self.fetch_avatars and meta.avatar_url:
                    raw_av_bytes = await self.fetch_bytes(
                        meta.avatar_url,
                        max_bytes=self.max_avatar_bytes,
                    )
                    if raw_av_bytes:
                        av_hash = compute_dhash_from_bytes(raw_av_bytes)

                primary_attrs: dict[str, Any] = {
                    "url": sanitized_final,
                    "fetcher_used": page.fetcher_used,
                    "title": meta.title,
                    "display_name": meta.display_name,
                    "bio": meta.bio,
                    "mentions": list(meta.mentions),
                    "hashtags": list(meta.hashtags),
                    "json_ld_types": list(meta.json_ld_types),
                }
                if meta.avatar_url:
                    primary_attrs["avatar_url"] = meta.avatar_url
                if av_hash:
                    primary_attrs["avatar_hash"] = av_hash
                if meta.follower_count is not None:
                    primary_attrs["follower_count"] = meta.follower_count
                if meta.following_count is not None:
                    primary_attrs["following_count"] = meta.following_count
                if meta.post_count is not None:
                    primary_attrs["post_count"] = meta.post_count
                if meta.locations:
                    primary_attrs["location"] = meta.locations[0]

                is_profile_like = (
                    not is_url_query
                    or platform_label != "Web"
                    or "Person" in meta.json_ld_types
                    or "ProfilePage" in meta.json_ld_types
                    or meta.follower_count is not None
                )

                if is_profile_like:
                    handle_val = (
                        _extract_handle_from_url(sanitized_final) or meta.display_name or sanitized_final
                        if is_url_query
                        else clean_query
                    )
                    prof_metrics = analyze_handle_entropy(handle_val)
                    primary_node = EntityNode(
                        entity_type=EntityType.SOCIAL_PROFILE,
                        value=handle_val,
                        label=meta.display_name or handle_val,
                        platform=platform_label,
                        entropy_score=prof_metrics.shannon_entropy,
                        rarity_score=prof_metrics.rarity_score,
                        confidence=0.88,
                        attributes=primary_attrs,
                        evidence_ids=[ev_item.evidence_id],
                    )
                else:
                    primary_node = EntityNode(
                        entity_type=EntityType.URL,
                        value=sanitized_final,
                        label=meta.title or sanitized_final,
                        confidence=0.88,
                        attributes=primary_attrs,
                        evidence_ids=[ev_item.evidence_id],
                    )
                nodes.append(primary_node)

                if root_node is not None:
                    if ev_item.evidence_id not in root_node.evidence_ids:
                        root_node.evidence_ids.append(ev_item.evidence_id)
                    edges.append(
                        RelationshipEdge(
                            source_node_id=root_node.node_id,
                            target_node_id=primary_node.node_id,
                            relation_type=RelationType.HAS_PROFILE,
                            weight=0.90,
                            confidence=0.88,
                            rationale=f"Public {platform_label} profile metadata captured for '{clean_query}'",
                            evidence_ids=[ev_item.evidence_id],
                        )
                    )

                if av_hash:
                    av_node = _get_or_create_child(
                        entity_type=EntityType.AVATAR_HASH,
                        value=av_hash,
                        ev_id=ev_item.evidence_id,
                        confidence=0.92,
                        attributes={"source_platform": platform_label, "avatar_url": meta.avatar_url},
                    )
                    edges.append(
                        RelationshipEdge(
                            source_node_id=primary_node.node_id,
                            target_node_id=av_node.node_id,
                            relation_type=RelationType.HAS_AVATAR,
                            weight=0.92,
                            confidence=0.92,
                            rationale=f"Perceptual avatar dHash extracted from {platform_label}",
                            evidence_ids=[ev_item.evidence_id],
                        )
                    )

                for ext_url in meta.external_links[:10]:
                    url_node = _get_or_create_child(
                        entity_type=EntityType.URL,
                        value=redact_sensitive_url(ext_url),
                        ev_id=ev_item.evidence_id,
                        confidence=0.82,
                    )
                    edges.append(
                        RelationshipEdge(
                            source_node_id=primary_node.node_id,
                            target_node_id=url_node.node_id,
                            relation_type=RelationType.MENTIONED_AT,
                            weight=0.80,
                            confidence=0.82,
                            rationale=f"External link advertised on {platform_label} page",
                            evidence_ids=[ev_item.evidence_id],
                        )
                    )

                for email_addr in meta.emails:
                    email_node = _get_or_create_child(
                        entity_type=EntityType.EMAIL,
                        value=email_addr,
                        ev_id=ev_item.evidence_id,
                        confidence=0.88,
                    )
                    edges.append(
                        RelationshipEdge(
                            source_node_id=primary_node.node_id,
                            target_node_id=email_node.node_id,
                            relation_type=RelationType.HAS_EMAIL,
                            weight=0.88,
                            confidence=0.88,
                            rationale=f"Public email extracted from {platform_label} metadata",
                            evidence_ids=[ev_item.evidence_id],
                        )
                    )

                for loc_str in meta.locations:
                    loc_node = _get_or_create_child(
                        entity_type=EntityType.LOCATION,
                        value=loc_str,
                        ev_id=ev_item.evidence_id,
                        confidence=0.80,
                    )
                    edges.append(
                        RelationshipEdge(
                            source_node_id=primary_node.node_id,
                            target_node_id=loc_node.node_id,
                            relation_type=RelationType.LOCATED_IN,
                            weight=0.80,
                            confidence=0.80,
                            rationale=f"Public location extracted from {platform_label} metadata",
                            evidence_ids=[ev_item.evidence_id],
                        )
                    )

        await asyncio.gather(*(_process_target(p, u) for p, u in targets))

        return CollectorResult(
            collector_name=self.name,
            query=clean_query,
            nodes=nodes,
            edges=edges,
            evidence_items=evidence_items,
            errors=errors,
        )
