"""Pluggable search dork generator, Wayback Machine CDX archive & Google CSE collector."""

from __future__ import annotations

import urllib.parse
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


def generate_dork_queries(target: str, entity_type: EntityType | None = None) -> list[str]:
    """Generate targeted passive OSINT search dork strings for a handle, email, or domain."""
    cleaned = target.strip()
    if entity_type == EntityType.DOMAIN or ("." in cleaned and "@" not in cleaned and " " not in cleaned):
        return [
            f'site:{cleaned} ext:pdf OR ext:docx OR ext:txt',
            f'site:{cleaned} inurl:admin OR inurl:login OR inurl:api',
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
        f'"{cleaned}" site:github.com OR site:gitlab.com',
        f'"{cleaned}" site:reddit.com OR site:news.ycombinator.com',
        f'"{cleaned}" site:pastebin.com OR site:gist.github.com',
    ]


class SearchDorkCollector(BaseCollector):
    """Queries Wayback Machine CDX archives and optional Google CSE for historical & dorked mentions."""

    name = "search_dork_collector"
    description = "Discovers archived URLs (Wayback CDX) and search engine dork hits."
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
        """Collect historical Wayback CDX snapshots and search dork URLs for `query`."""
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
        root_type = (
            EntityType.EMAIL
            if is_email
            else (EntityType.DOMAIN if is_domain else EntityType.USERNAME)
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
                    orig_idx = headers_row.index("original") if isinstance(headers_row, list) and "original" in headers_row else 2
                    ts_idx = headers_row.index("timestamp") if isinstance(headers_row, list) and "timestamp" in headers_row else 1

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

        # 2. Optional Google Custom Search Engine (CSE) dork execution
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
                            link = str(item["link"]).strip()
                            if link in urls_seen:
                                continue
                            urls_seen.add(link)
                            url_node = EntityNode(
                                entity_type=EntityType.URL,
                                value=link,
                                platform="SearchDork",
                                confidence=0.80,
                                attributes={
                                    "title": item.get("title") or "",
                                    "snippet": item.get("snippet") or "",
                                    "dork_query": dork,
                                },
                                evidence_ids=[ev_cse.evidence_id],
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
                                    evidence_ids=[ev_cse.evidence_id],
                                )
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
