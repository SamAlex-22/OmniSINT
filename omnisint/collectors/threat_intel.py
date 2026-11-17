"""Passive Threat Intelligence collector (VirusTotal v3 & passive DNS/reputation indicators)."""

from __future__ import annotations

import ipaddress
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


class ThreatIntelCollector(BaseCollector):
    """Collects VirusTotal reputation, threat indicators, and passive DNS infrastructure links."""

    name = "threat_intel"
    description = "Queries VirusTotal v3 API for domain/IP reputation, passive DNS, and threat indicators."
    supported_types = (EntityType.DOMAIN, EntityType.IP_ADDRESS)

    def __init__(
        self,
        config: CollectorConfig | None = None,
        settings: OmniSINTSettings | None = None,
        http_transport: HttpGetTransportCallable | None = None,
    ) -> None:
        super().__init__(config=config, settings=settings, http_transport=http_transport)
        self._has_custom_transport = http_transport is not None

    @staticmethod
    def _is_ip_address(value: str) -> bool:
        try:
            ipaddress.ip_address(value.strip())
            return True
        except ValueError:
            return False

    async def collect(
        self,
        query: str,
        case_id: str,
        ledger: CustodyLedger | None = None,
        storage: CaseStorage | None = None,
    ) -> CollectorResult:
        """Query VirusTotal v3 (or deterministic passive indicator fallback) for a domain or IP."""
        target = query.strip().lower()
        active_ledger = ledger if ledger is not None else CustodyLedger(case_id=case_id)
        if not target:
            return CollectorResult(
                collector_name=self.name,
                query=query,
                errors=["ThreatIntel query cannot be empty"],
            )

        is_ip = self._is_ip_address(target)
        root_type = EntityType.IP_ADDRESS if is_ip else EntityType.DOMAIN
        root_node = EntityNode(
            entity_type=root_type,
            value=target,
            confidence=0.95,
        )

        nodes: list[EntityNode] = [root_node]
        edges: list[RelationshipEdge] = []
        evidence_items: list[EvidenceItem] = []
        errors: list[str] = []

        vt_key = self.settings.virustotal_api_key
        if not vt_key and not self._has_custom_transport:
            # Offline deterministic posture indicator without making an unauthenticated VT call
            passive_payload = {
                "target": target,
                "entity_type": root_type.value,
                "mode": "offline_passive_posture",
                "note": "OMNISINT_VIRUSTOTAL_API_KEY not set; live VirusTotal v3 lookup skipped.",
            }
            ev_item = self._record_custody_item(
                case_id=case_id,
                ledger=active_ledger,
                source_uri=f"omnisint://passive-posture/{target}",
                payload=passive_payload,
                notes="Passive threat-intel posture note (no VT API key configured)",
            )
            evidence_items.append(ev_item)
            root_node.evidence_ids.append(ev_item.evidence_id)
            return CollectorResult(
                collector_name=self.name,
                query=target,
                nodes=nodes,
                edges=edges,
                evidence_items=evidence_items,
                errors=errors,
            )

        endpoint = (
            f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
            if is_ip
            else f"https://www.virustotal.com/api/v3/domains/{target}"
        )
        headers = {"x-apikey": vt_key or "mock-transport"}

        try:
            status, payload, ev_vt, _ = await self.fetch_with_custody(
                url=endpoint,
                case_id=case_id,
                ledger=active_ledger,
                storage=storage,
                headers=headers,
                notes=f"VirusTotal v3 reputation lookup for '{target}'",
            )
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                query=target,
                nodes=nodes,
                evidence_items=evidence_items,
                errors=[f"VirusTotal lookup failed: {type(exc).__name__}: {exc}"],
            )

        if status != 200 or ev_vt is None or not isinstance(payload, dict):
            return CollectorResult(
                collector_name=self.name,
                query=target,
                nodes=nodes,
                evidence_items=evidence_items,
                errors=[f"VirusTotal returned status={status} for '{target}'"],
            )

        evidence_items.append(ev_vt)
        root_node.evidence_ids.append(ev_vt.evidence_id)

        data = payload.get("data") or {}
        attrs: dict[str, Any] = data.get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        total_engines = max(1, malicious + suspicious + harmless + int(stats.get("undetected", 0)))
        reputation = int(attrs.get("reputation", 0))
        categories = attrs.get("categories") or {}

        verdict = (
            "MALICIOUS"
            if malicious > 0
            else ("SUSPICIOUS" if suspicious > 0 else "CLEAN")
        )
        indicator_label = (
            f"VT {verdict}: {malicious}/{total_engines} malicious, "
            f"{suspicious} suspicious (rep={reputation})"
        )
        indicator_node = EntityNode(
            entity_type=EntityType.THREAT_INDICATOR,
            value=f"virustotal:{target}:{verdict.lower()}",
            label=indicator_label,
            platform="VirusTotal",
            confidence=0.92,
            attributes={
                "verdict": verdict,
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "reputation": reputation,
                "categories": categories,
            },
            evidence_ids=[ev_vt.evidence_id],
        )
        nodes.append(indicator_node)
        edges.append(
            RelationshipEdge(
                source_node_id=root_node.node_id,
                target_node_id=indicator_node.node_id,
                relation_type=RelationType.FLAGGED_BY,
                weight=0.92,
                confidence=0.92,
                rationale=indicator_label,
                evidence_ids=[ev_vt.evidence_id],
            )
        )

        # Extract passive DNS A records from VirusTotal domain attributes
        if not is_ip:
            for rec in attrs.get("last_dns_records") or []:
                if not isinstance(rec, dict):
                    continue
                if str(rec.get("type", "")).upper() == "A" and rec.get("value"):
                    ip_val = str(rec["value"]).strip()
                    if self._is_ip_address(ip_val):
                        ip_node = EntityNode(
                            entity_type=EntityType.IP_ADDRESS,
                            value=ip_val,
                            platform="VirusTotal",
                            confidence=0.88,
                            evidence_ids=[ev_vt.evidence_id],
                        )
                        nodes.append(ip_node)
                        edges.append(
                            RelationshipEdge(
                                source_node_id=root_node.node_id,
                                target_node_id=ip_node.node_id,
                                relation_type=RelationType.RESOLVES_TO,
                                weight=0.88,
                                confidence=0.88,
                                rationale=f"Passive DNS A record reported by VirusTotal for '{target}'",
                                evidence_ids=[ev_vt.evidence_id],
                            )
                        )

        return CollectorResult(
            collector_name=self.name,
            query=target,
            nodes=nodes,
            edges=edges,
            evidence_items=evidence_items,
            errors=errors,
        )
