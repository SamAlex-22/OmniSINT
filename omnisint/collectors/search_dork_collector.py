"""Pluggable search dork generator, no-key web search, Wayback CDX archive & Google CSE collector."""

from __future__ import annotations

import html as html_lib
import re
import urllib.parse
from html.parser import HTMLParser
from typing import Any

from omnisint.collectors.base import BaseCollector, CollectorConfig, HttpGetTransportCallable
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


_NON_PROFILE_SEGMENTS: frozenset[str] = frozenset(
    {
        "accounts",
        "account",
        "auth",
        "oauth",
        "login",
        "signin",
        "signup",
        "register",
        "explore",
        "search",
        "p",
        "reel",
        "reels",
        "stories",
        "direct",
        "posts",
        "company",
        "jobs",
        "pulse",
        "watch",
        "channel",
        "intent",
        "share",
        "sharer.php",
        "settings",
        "about",
        "privacy",
        "terms",
        "help",
        "topics",
        "tags",
        "tag",
        "hashtag",
        "directory",
        "pub",
        "learning",
        "school",
    }
)

_SEARCH_INTERNAL_HOSTS: tuple[str, ...] = (
    "duckduckgo.com",
    "yahoo.com",
    "bing.com",
    "google.com",
    "gstatic.com",
    "w3.org",
    "schema.org",
)

_YAHOO_RU_RE = re.compile(r"/RU=([^/]+)(?:/|$)")


def generate_dork_queries(target: str, entity_type: EntityType | None = None) -> list[str]:
    """Generate targeted passive OSINT search dork strings for a person name, handle, email, or domain."""
    cleaned = target.strip()
    if entity_type == EntityType.DOMAIN or (
        "." in cleaned and "@" not in cleaned and " " not in cleaned
    ):
        return [
            f"site:{cleaned} ext:pdf OR ext:docx OR ext:txt",
            f"site:{cleaned} inurl:admin OR inurl:login OR inurl:api",
            f'"{cleaned}" site:github.com OR site:gitlab.com',
            f'"{cleaned}" site:pastebin.com OR site:gist.github.com',
        ]
    if entity_type == EntityType.EMAIL or "@" in cleaned:
        return [
            f'"{cleaned}"',
            f'"{cleaned}" site:github.com OR site:gist.github.com',
            f'"{cleaned}" site:pastebin.com OR site:reddit.com',
        ]
    return [
        f'"{cleaned}" (site:linkedin.com/in/ OR site:instagram.com OR site:x.com OR site:github.com)',
        f'"{cleaned}" (site:medium.com OR site:youtube.com OR site:linktr.ee OR site:reddit.com)',
        f'"{cleaned}" site:github.com OR site:gitlab.com',
        f'"{cleaned}" site:pastebin.com OR site:gist.github.com',
    ]


def classify_social_profile_url(
    url: str,
    title: str = "",
    snippet: str = "",
) -> tuple[str, str] | None:
    """Classify a discovered URL into `(platform, handle)` for recognized social/code profiles."""
    _ = (title, snippet)
    parsed = urllib.parse.urlsplit(url.strip())
    if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
        return None

    host = parsed.netloc.lower().split(":", 1)[0]
    for prefix in ("www.", "m.", "mobile."):
        if host.startswith(prefix):
            host = host[len(prefix) :]

    segs = [urllib.parse.unquote(seg.strip()) for seg in parsed.path.split("/") if seg.strip()]

    def _valid_handle(candidate: str) -> str | None:
        cleaned = candidate.strip().lstrip("@")
        lower = cleaned.lower()
        if (
            len(cleaned) < 2
            or lower in _NON_PROFILE_SEGMENTS
            or lower.endswith((".php", ".html", ".htm", ".json", ".xml"))
        ):
            return None
        return cleaned

    if host == "linkedin.com" or host.endswith(".linkedin.com"):
        if len(segs) >= 2 and segs[0].lower() == "in":
            h = _valid_handle(segs[1])
            return ("LinkedIn", h) if h else None
        return None

    if host == "instagram.com":
        if segs:
            h = _valid_handle(segs[0])
            return ("Instagram", h) if h else None
        return None

    if host in ("x.com", "twitter.com"):
        if segs and segs[0].lower() != "i":
            h = _valid_handle(segs[0])
            return ("Twitter", h) if h else None
        return None

    if host == "github.com":
        gh_reserved = _NON_PROFILE_SEGMENTS | {
            "orgs",
            "features",
            "marketplace",
            "sponsors",
            "trending",
            "collections",
            "events",
            "pricing",
            "enterprise",
            "solutions",
            "blog",
        }
        if segs and segs[0].lower() not in gh_reserved:
            if len(segs) >= 2 and segs[1].lower() in ("blob", "tree", "issues", "pull", "commit"):
                return None
            h = _valid_handle(segs[0])
            return ("GitHub", h) if h else None
        return None

    if host == "gitlab.com":
        gl_reserved = _NON_PROFILE_SEGMENTS | {"explore", "users", "groups", "-"}
        if segs and segs[0].lower() not in gl_reserved:
            h = _valid_handle(segs[0])
            return ("GitLab", h) if h else None
        return None

    if host == "reddit.com":
        if len(segs) >= 2 and segs[0].lower() in ("user", "u"):
            h = _valid_handle(segs[1])
            return ("Reddit", h) if h else None
        return None

    if host == "medium.com":
        if segs and segs[0].startswith("@"):
            h = _valid_handle(segs[0])
            return ("Medium", h) if h else None
        return None

    if host.endswith(".medium.com") and host != "medium.com":
        sub = _valid_handle(host[: -len(".medium.com")])
        return ("Medium", sub) if sub else None

    if host == "youtube.com":
        if segs and segs[0].startswith("@"):
            h = _valid_handle(segs[0])
            return ("YouTube", h) if h else None
        if len(segs) >= 2 and segs[0].lower() in ("c", "user"):
            h = _valid_handle(segs[1])
            return ("YouTube", h) if h else None
        return None

    if host == "tiktok.com":
        if segs and segs[0].startswith("@"):
            h = _valid_handle(segs[0])
            return ("TikTok", h) if h else None
        return None

    if host == "facebook.com":
        fb_reserved = _NON_PROFILE_SEGMENTS | {
            "groups",
            "pages",
            "events",
            "marketplace",
            "gaming",
            "photo",
            "profile.php",
        }
        if segs and segs[0].lower() not in fb_reserved:
            h = _valid_handle(segs[0])
            return ("Facebook", h) if h else None
        return None

    if host == "pinterest.com":
        if segs and segs[0].lower() not in (_NON_PROFILE_SEGMENTS | {"pin", "ideas"}):
            h = _valid_handle(segs[0])
            return ("Pinterest", h) if h else None
        return None

    if host == "linktr.ee":
        if segs:
            h = _valid_handle(segs[0])
            return ("Linktree", h) if h else None
        return None

    if host == "kaggle.com":
        kaggle_reserved = _NON_PROFILE_SEGMENTS | {
            "datasets",
            "competitions",
            "code",
            "models",
            "learn",
            "discussions",
        }
        if segs and segs[0].lower() not in kaggle_reserved:
            h = _valid_handle(segs[0])
            return ("Kaggle", h) if h else None
        return None

    if host == "huggingface.co":
        hf_reserved = _NON_PROFILE_SEGMENTS | {
            "models",
            "datasets",
            "spaces",
            "docs",
            "blog",
            "papers",
            "tasks",
        }
        if segs and segs[0].lower() not in hf_reserved:
            h = _valid_handle(segs[0])
            return ("HuggingFace", h) if h else None
        return None

    if host == "leetcode.com":
        if len(segs) >= 2 and segs[0].lower() == "u":
            h = _valid_handle(segs[1])
            return ("LeetCode", h) if h else None
        lc_reserved = _NON_PROFILE_SEGMENTS | {
            "problems",
            "contest",
            "explore",
            "discuss",
            "interview",
        }
        if len(segs) == 1 and segs[0].lower() not in lc_reserved:
            h = _valid_handle(segs[0])
            return ("LeetCode", h) if h else None
        return None

    if host in ("t.me", "telegram.me"):
        tg_reserved = _NON_PROFILE_SEGMENTS | {"s", "joinchat", "addstickers"}
        if segs and segs[0].lower() not in tg_reserved:
            h = _valid_handle(segs[0])
            return ("Telegram", h) if h else None
        return None

    return None


class _SearchEngineHtmlParser(HTMLParser):
    """Lightweight HTML parser extracting `<a href>` links and inner text for search results."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._in_a = False
        self._cur_href = ""
        self._cur_classes = ""
        self._cur_text: list[str] = []
        self.anchors: list[tuple[str, str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            attr_map = {k.lower(): (v or "") for k, v in attrs if k}
            href = attr_map.get("href", "").strip()
            if href:
                self._in_a = True
                self._cur_href = href
                self._cur_classes = attr_map.get("class", "").lower()
                self._cur_text = []

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._in_a:
            self._in_a = False
            title = " ".join("".join(self._cur_text).split())
            self.anchors.append((self._cur_href, title, self._cur_classes))
            self._cur_href = ""
            self._cur_classes = ""
            self._cur_text = []

    def handle_data(self, data: str) -> None:
        if self._in_a:
            self._cur_text.append(data)


def _unwrap_search_redirect(raw_href: str) -> str:
    """Decode DuckDuckGo `uddg=` and Yahoo `/RU=` redirect wrappers into clean target URLs."""
    href = html_lib.unescape(raw_href.strip())
    if href.startswith("//"):
        href = f"https:{href}"

    parsed = urllib.parse.urlsplit(href)
    if "uddg=" in parsed.query:
        qs = urllib.parse.parse_qs(parsed.query)
        if qs.get("uddg"):
            return qs["uddg"][0].strip()

    yahoo_match = _YAHOO_RU_RE.search(href)
    if yahoo_match:
        return urllib.parse.unquote(yahoo_match.group(1)).strip()

    return href


def parse_search_engine_html(html: str) -> list[dict[str, str]]:
    """Extract deduplicated organic search hits from DuckDuckGo or Yahoo Search HTML."""
    parser = _SearchEngineHtmlParser()
    parser.feed(html or "")
    parser.close()

    results: list[dict[str, str]] = []
    seen_urls: set[str] = set()
    snippet_by_url: dict[str, str] = {}

    for raw_href, text, classes in parser.anchors:
        target = _unwrap_search_redirect(raw_href)
        parsed = urllib.parse.urlsplit(target)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
            continue
        host = parsed.netloc.lower().split(":", 1)[0]
        if any(host == ih or host.endswith(f".{ih}") for ih in _SEARCH_INTERNAL_HOSTS):
            continue

        if "result__snippet" in classes and target in snippet_by_url and not snippet_by_url[target]:
            snippet_by_url[target] = text
            continue

        norm = target.rstrip("/")
        if norm in seen_urls:
            if "result__snippet" in classes and not snippet_by_url.get(norm) and text:
                snippet_by_url[norm] = text
            continue
        seen_urls.add(norm)
        snippet_by_url[norm] = "" if "result__snippet" not in classes else text
        results.append({"url": target, "title": text, "snippet": ""})

    for item in results:
        norm = item["url"].rstrip("/")
        if snippet_by_url.get(norm):
            item["snippet"] = snippet_by_url[norm]
    return results


class SearchDorkCollector(BaseCollector):
    """Queries GitHub User Search, no-key web search dorks, Wayback CDX & Google CSE."""

    name = "search_dork_collector"
    description = (
        "Discovers public social profiles (LinkedIn, Instagram, X, GitHub) via no-key "
        "search dorks, GitHub user search, Wayback CDX archives & Google CSE."
    )
    supported_types = (
        EntityType.DOMAIN,
        EntityType.USERNAME,
        EntityType.EMAIL,
        EntityType.PERSON,
    )

    def __init__(
        self,
        config: CollectorConfig | None = None,
        settings: OmniSINTSettings | None = None,
        http_transport: HttpGetTransportCallable | None = None,
    ) -> None:
        super().__init__(config=config, settings=settings, http_transport=http_transport)
        self._has_custom_transport = http_transport is not None

    async def collect(
        self,
        query: str,
        case_id: str,
        ledger: CustodyLedger | None = None,
        storage: CaseStorage | None = None,
    ) -> CollectorResult:
        """Collect historical Wayback CDX snapshots, GitHub matches, and web search dork hits."""
        cleaned = query.strip()
        active_ledger = ledger if ledger is not None else CustodyLedger(case_id=case_id)
        if not cleaned:
            return CollectorResult(
                collector_name=self.name,
                query=query,
                errors=["SearchDork query cannot be empty"],
            )

        is_email = "@" in cleaned
        is_domain = "." in cleaned and not is_email and " " not in cleaned
        is_person = " " in cleaned and not is_email and not is_domain
        root_type = (
            EntityType.EMAIL
            if is_email
            else (
                EntityType.DOMAIN
                if is_domain
                else (EntityType.PERSON if is_person else EntityType.USERNAME)
            )
        )
        metrics = analyze_handle_entropy(cleaned)
        root_node = EntityNode(
            entity_type=root_type,
            value=cleaned,
            entropy_score=metrics.shannon_entropy,
            rarity_score=metrics.rarity_score,
            confidence=0.90,
            attributes={"dork_queries": generate_dork_queries(cleaned, root_type)},
        )

        nodes: list[EntityNode] = [root_node]
        edges: list[RelationshipEdge] = []
        evidence_items: list[EvidenceItem] = []
        errors: list[str] = []
        urls_seen: set[str] = set()
        profile_keys_seen: set[tuple[str, str]] = set()
        username_keys_seen: set[str] = (
            {cleaned.lstrip("@").lower()} if root_type == EntityType.USERNAME else set()
        )

        def _record_search_hit(
            link: str,
            title: str,
            snippet: str,
            dork: str,
            ev_item: EvidenceItem,
            via: str,
        ) -> None:
            classified = classify_social_profile_url(link, title=title, snippet=snippet)
            if classified is not None:
                plat, handle = classified
                pkey = (plat.lower(), handle.lower())
                if pkey in profile_keys_seen:
                    return
                profile_keys_seen.add(pkey)
                urls_seen.add(link)
                prof_metrics = analyze_handle_entropy(handle)
                prof_node = EntityNode(
                    entity_type=EntityType.SOCIAL_PROFILE,
                    value=handle,
                    platform=plat,
                    entropy_score=prof_metrics.shannon_entropy,
                    rarity_score=prof_metrics.rarity_score,
                    confidence=0.84,
                    attributes={
                        "url": link,
                        "title": title,
                        "snippet": snippet,
                        "dork_query": dork,
                        "discovered_via": via,
                    },
                    evidence_ids=[ev_item.evidence_id],
                )
                nodes.append(prof_node)
                edges.append(
                    RelationshipEdge(
                        source_node_id=root_node.node_id,
                        target_node_id=prof_node.node_id,
                        relation_type=RelationType.HAS_PROFILE,
                        weight=0.85,
                        confidence=0.84,
                        rationale=f"Discovered {plat} profile '{handle}' via {via}",
                        evidence_ids=[ev_item.evidence_id],
                    )
                )
                return

            if link in urls_seen:
                return
            urls_seen.add(link)
            url_node = EntityNode(
                entity_type=EntityType.URL,
                value=link,
                platform=via,
                confidence=0.80,
                attributes={"title": title, "snippet": snippet, "dork_query": dork},
                evidence_ids=[ev_item.evidence_id],
            )
            nodes.append(url_node)
            edges.append(
                RelationshipEdge(
                    source_node_id=root_node.node_id,
                    target_node_id=url_node.node_id,
                    relation_type=RelationType.MENTIONED_AT,
                    weight=0.80,
                    confidence=0.80,
                    rationale=f"Matched search dork: {dork}",
                    evidence_ids=[ev_item.evidence_id],
                )
            )

        # 1. Wayback Machine CDX archive lookup for domain queries
        if is_domain:
            cdx_url = (
                f"https://web.archive.org/cdx/search/cdx?"
                f"url={urllib.parse.quote(cleaned)}/*&output=json&limit=25&collapse=urlkey"
            )
            try:
                status, cdx_payload, ev_cdx, _ = await self.fetch_with_custody(
                    url=cdx_url,
                    case_id=case_id,
                    ledger=active_ledger,
                    storage=storage,
                    notes=f"Internet Archive Wayback CDX lookup for '{cleaned}'",
                )
                if status == 200 and ev_cdx is not None and isinstance(cdx_payload, list) and len(cdx_payload) > 1:
                    evidence_items.append(ev_cdx)
                    if ev_cdx.evidence_id not in root_node.evidence_ids:
                        root_node.evidence_ids.append(ev_cdx.evidence_id)

                    headers_row = cdx_payload[0]
                    orig_idx = (
                        headers_row.index("original")
                        if isinstance(headers_row, list) and "original" in headers_row
                        else 2
                    )
                    ts_idx = (
                        headers_row.index("timestamp")
                        if isinstance(headers_row, list) and "timestamp" in headers_row
                        else 1
                    )

                    for row in cdx_payload[1:20]:
                        if not isinstance(row, list) or len(row) <= orig_idx:
                            continue
                        orig_url = str(row[orig_idx]).strip()
                        snap_ts = str(row[ts_idx]).strip() if len(row) > ts_idx else ""
                        if not orig_url or orig_url in urls_seen:
                            continue
                        urls_seen.add(orig_url)
                        archive_url = (
                            f"https://web.archive.org/web/{snap_ts}/{orig_url}"
                            if snap_ts
                            else orig_url
                        )
                        url_node = EntityNode(
                            entity_type=EntityType.URL,
                            value=orig_url,
                            platform="WaybackMachine",
                            confidence=0.88,
                            attributes={"archive_url": archive_url, "snapshot_timestamp": snap_ts},
                            evidence_ids=[ev_cdx.evidence_id],
                        )
                        nodes.append(url_node)
                        edges.append(
                            RelationshipEdge(
                                source_node_id=root_node.node_id,
                                target_node_id=url_node.node_id,
                                relation_type=RelationType.MENTIONED_AT,
                                weight=0.88,
                                confidence=0.88,
                                rationale=f"Archived URL snapshot captured via Wayback Machine ({snap_ts or 'CDX'})",
                                evidence_ids=[ev_cdx.evidence_id],
                            )
                        )
            except Exception as exc:
                errors.append(f"Wayback CDX lookup failed: {type(exc).__name__}: {exc}")

        # 2. No-key GitHub User Search API + DuckDuckGo/Yahoo web search dorking for handles & names
        if not is_domain and not is_email:
            gh_search_url = (
                f"https://api.github.com/search/users?q={urllib.parse.quote(cleaned)}&per_page=5"
            )
            gh_headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
            if self.settings.github_token:
                gh_headers["Authorization"] = f"Bearer {self.settings.github_token}"
            try:
                gh_status, gh_payload, ev_gh, _ = await self.fetch_with_custody(
                    url=gh_search_url,
                    case_id=case_id,
                    ledger=active_ledger,
                    storage=storage,
                    headers=gh_headers,
                    notes=f"GitHub public user search for '{cleaned}'",
                )
                if (
                    gh_status == 200
                    and ev_gh is not None
                    and isinstance(gh_payload, dict)
                    and isinstance(gh_payload.get("items"), list)
                ):
                    items_list = [it for it in gh_payload["items"][:5] if isinstance(it, dict) and it.get("login")]
                    if items_list:
                        evidence_items.append(ev_gh)
                        if ev_gh.evidence_id not in root_node.evidence_ids:
                            root_node.evidence_ids.append(ev_gh.evidence_id)
                    for item in items_list:
                        login = str(item["login"]).strip()
                        html_url = str(item.get("html_url") or f"https://github.com/{login}").strip()
                        pkey = ("github", login.lower())
                        if pkey not in profile_keys_seen:
                            profile_keys_seen.add(pkey)
                            urls_seen.add(html_url)
                            prof_metrics = analyze_handle_entropy(login)
                            prof_node = EntityNode(
                                entity_type=EntityType.SOCIAL_PROFILE,
                                value=login,
                                platform="GitHub",
                                entropy_score=prof_metrics.shannon_entropy,
                                rarity_score=prof_metrics.rarity_score,
                                confidence=0.86,
                                attributes={
                                    "url": html_url,
                                    "avatar_url": item.get("avatar_url") or "",
                                    "score": item.get("score"),
                                    "discovered_via": "github_user_search",
                                },
                                evidence_ids=[ev_gh.evidence_id],
                            )
                            nodes.append(prof_node)
                            edges.append(
                                RelationshipEdge(
                                    source_node_id=root_node.node_id,
                                    target_node_id=prof_node.node_id,
                                    relation_type=RelationType.HAS_PROFILE,
                                    weight=0.86,
                                    confidence=0.86,
                                    rationale=f"Matched GitHub user '{login}' via public user search",
                                    evidence_ids=[ev_gh.evidence_id],
                                )
                            )
                        if login.lower() not in username_keys_seen:
                            username_keys_seen.add(login.lower())
                            uname_metrics = analyze_handle_entropy(login)
                            uname_node = EntityNode(
                                entity_type=EntityType.USERNAME,
                                value=login,
                                entropy_score=uname_metrics.shannon_entropy,
                                rarity_score=uname_metrics.rarity_score,
                                confidence=0.84,
                                attributes={
                                    "discovered_via": "github_user_search",
                                    "source_url": html_url,
                                },
                                evidence_ids=[ev_gh.evidence_id],
                            )
                            nodes.append(uname_node)
                            edges.append(
                                RelationshipEdge(
                                    source_node_id=root_node.node_id,
                                    target_node_id=uname_node.node_id,
                                    relation_type=RelationType.HAS_HANDLE,
                                    weight=0.84,
                                    confidence=0.84,
                                    rationale=f"Derived GitHub handle '{login}' for '{cleaned}'",
                                    evidence_ids=[ev_gh.evidence_id],
                                )
                            )
            except Exception as exc:
                errors.append(f"GitHub user search failed: {type(exc).__name__}: {exc}")

            # Public DuckDuckGo HTML search with Yahoo HTML fallback
            dorks = generate_dork_queries(cleaned, root_type)
            html_headers = {
                "Accept": "text/html,application/xhtml+xml,*/*",
                "Accept-Language": "en-US,en;q=0.9",
            }
            for dork in dorks[:2]:
                parsed_hits: list[dict[str, str]] = []
                active_ev: EvidenceItem | None = None
                ddg_url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(dork)}"
                try:
                    d_status, d_body, ev_ddg, _ = await self.fetch_with_custody(
                        url=ddg_url,
                        case_id=case_id,
                        ledger=active_ledger,
                        storage=storage,
                        headers=html_headers,
                        notes=f"DuckDuckGo HTML search dork: {dork}",
                    )
                    if d_status == 200 and ev_ddg is not None and isinstance(d_body, str):
                        parsed_hits = parse_search_engine_html(d_body)
                        if parsed_hits:
                            active_ev = ev_ddg
                except Exception as exc:
                    errors.append(f"DuckDuckGo search failed: {type(exc).__name__}: {exc}")

                if not parsed_hits:
                    yahoo_url = f"https://search.yahoo.com/search?p={urllib.parse.quote(dork)}"
                    try:
                        y_status, y_body, ev_yahoo, _ = await self.fetch_with_custody(
                            url=yahoo_url,
                            case_id=case_id,
                            ledger=active_ledger,
                            storage=storage,
                            headers=html_headers,
                            notes=f"Yahoo HTML search fallback dork: {dork}",
                        )
                        if y_status == 200 and ev_yahoo is not None and isinstance(y_body, str):
                            parsed_hits = parse_search_engine_html(y_body)
                            if parsed_hits:
                                active_ev = ev_yahoo
                    except Exception as exc:
                        errors.append(f"Yahoo search fallback failed: {type(exc).__name__}: {exc}")

                if parsed_hits and active_ev is not None:
                    evidence_items.append(active_ev)
                    if active_ev.evidence_id not in root_node.evidence_ids:
                        root_node.evidence_ids.append(active_ev.evidence_id)
                    for hit in parsed_hits[:10]:
                        _record_search_hit(
                            link=hit["url"],
                            title=hit.get("title", ""),
                            snippet=hit.get("snippet", ""),
                            dork=dork,
                            ev_item=active_ev,
                            via="search_dork",
                        )

        # 3. Optional Google Custom Search Engine (CSE) dork execution
        cse_key = self.settings.google_cse_api_key
        cse_cx = self.settings.google_cse_cx
        if (cse_key and cse_cx) or (self._has_custom_transport and not is_domain):
            dorks = generate_dork_queries(cleaned, root_type)
            for dork in dorks[:2]:
                cse_url = (
                    "https://www.googleapis.com/customsearch/v1"
                    f"?key={urllib.parse.quote(cse_key or 'mock-key')}"
                    f"&cx={urllib.parse.quote(cse_cx or 'mock-cx')}"
                    f"&q={urllib.parse.quote(dork)}"
                )
                try:
                    c_status, c_payload, ev_cse, _ = await self.fetch_with_custody(
                        url=cse_url,
                        case_id=case_id,
                        ledger=active_ledger,
                        storage=storage,
                        notes=f"Search dork query: {dork}",
                    )
                    if c_status == 200 and ev_cse is not None and isinstance(c_payload, dict):
                        items = c_payload.get("items") or []
                        if items:
                            evidence_items.append(ev_cse)
                            if ev_cse.evidence_id not in root_node.evidence_ids:
                                root_node.evidence_ids.append(ev_cse.evidence_id)
                        for item in items:
                            if not isinstance(item, dict) or not item.get("link"):
                                continue
                            _record_search_hit(
                                link=str(item["link"]).strip(),
                                title=str(item.get("title") or ""),
                                snippet=str(item.get("snippet") or ""),
                                dork=dork,
                                ev_item=ev_cse,
                                via="SearchDork",
                            )
                except Exception as exc:
                    errors.append(f"Search CSE dork failed: {type(exc).__name__}: {exc}")

        return CollectorResult(
            collector_name=self.name,
            query=cleaned,
            nodes=nodes,
            edges=edges,
            evidence_items=evidence_items,
            errors=errors,
        )
