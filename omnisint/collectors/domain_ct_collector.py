"""Passive Certificate Transparency (crt.sh), RDAP/WHOIS, and passive DNS collector."""

from __future__ import annotations

import ipaddress
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

_FREE_EMAIL_DOMAINS: frozenset[str] = frozenset(
    {
        "gmail.com",
        "yahoo.com",
        "outlook.com",
        "hotmail.com",
        "proton.me",
        "protonmail.com",
        "icloud.com",
        "users.noreply.github.com",
    }
)


class DomainCTCollector(BaseCollector):
    """Collects Certificate Transparency logs (crt.sh), RDAP registration data, and passive DNS records."""

    name = "domain_ct_collector"
    description = "Queries crt.sh CT logs, RDAP domain metadata, and DNS-over-HTTPS records passively."
    supported_types = (EntityType.DOMAIN, EntityType.SUBDOMAIN, EntityType.EMAIL)

    def __init__(
        self,
        config: CollectorConfig | None = None,
        settings: OmniSINTSettings | None = None,
        http_transport: HttpGetTransportCallable | None = None,
    ) -> None:
        super().__init__(config=config, settings=settings, http_transport=http_transport)

    @staticmethod
    def _normalize_domain(query: str) -> tuple[str, bool]:
        """Extract normalized domain name; returns (domain, is_free_mail_provider)."""
        cleaned = query.strip().lower()
        if "@" in cleaned:
            domain_part = cleaned.split("@", 1)[1].strip()
            return domain_part, domain_part in _FREE_EMAIL_DOMAINS
        if "://" in cleaned:
            parsed = urllib.parse.urlparse(cleaned)
            cleaned = (parsed.netloc or "").split(":")[0]
        return cleaned.strip("."), False

    @staticmethod
    def _extract_rdap_entities(rdap_payload: dict[str, Any]) -> tuple[list[str], list[str]]:
        """Extract registrant organization names and email addresses from an RDAP JSON response."""
        orgs: list[str] = []
        emails: list[str] = []

        def _walk_entities(entities: Any) -> None:
            if not isinstance(entities, list):
                return
            for ent in entities:
                if not isinstance(ent, dict):
                    continue
                vcard = ent.get("vcardArray")
                if isinstance(vcard, list) and len(vcard) >= 2 and isinstance(vcard[1], list):
                    for prop in vcard[1]:
                        if not isinstance(prop, list) or len(prop) < 4:
                            continue
                        prop_name = str(prop[0]).lower()
                        prop_val = str(prop[3]).strip()
                        if not prop_val:
                            continue
                        if prop_name in ("fn", "org") and prop_val not in orgs:
                            orgs.append(prop_val)
                        elif prop_name == "email" and "@" in prop_val:
                            addr = prop_val.lower()
                            if addr not in emails:
                                emails.append(addr)
                if ent.get("entities"):
                    _walk_entities(ent.get("entities"))

        _walk_entities(rdap_payload.get("entities"))
        return orgs, emails

    async def collect(
        self,
        query: str,
        case_id: str,
        ledger: CustodyLedger | None = None,
        storage: CaseStorage | None = None,
    ) -> CollectorResult:
        """Query crt.sh, RDAP, and passive DNS for a domain (or custom email domain)."""
        domain, is_free_mail = self._normalize_domain(query)
        active_ledger = ledger if ledger is not None else CustodyLedger(case_id=case_id)
        if not domain or "." not in domain:
            return CollectorResult(
                collector_name=self.name,
                query=query,
                errors=[f"Invalid domain query: '{query}'"],
            )
        if is_free_mail:
            return CollectorResult(
                collector_name=self.name,
                query=domain,
                errors=[],
            )

        domain_node = EntityNode(
            entity_type=EntityType.DOMAIN,
            value=domain,
            confidence=0.95,
        )
        nodes: list[EntityNode] = [domain_node]
        edges: list[RelationshipEdge] = []
        evidence_items: list[EvidenceItem] = []
        errors: list[str] = []

        subdomains_by_name: dict[str, EntityNode] = {}
        ips_by_addr: dict[str, EntityNode] = {}
        certs_seen: set[str] = set()

        # 1. Certificate Transparency via crt.sh
        crt_url = f"https://crt.sh/?q={urllib.parse.quote(domain)}&output=json"
        try:
            status, crt_payload, ev_crt, _ = await self.fetch_with_custody(
                url=crt_url,
                case_id=case_id,
                ledger=active_ledger,
                storage=storage,
                notes=f"Certificate Transparency lookup (crt.sh) for '{domain}'",
            )
            if status == 200 and ev_crt is not None and isinstance(crt_payload, list):
                evidence_items.append(ev_crt)
                if ev_crt.evidence_id not in domain_node.evidence_ids:
                    domain_node.evidence_ids.append(ev_crt.evidence_id)

                for entry in crt_payload[:50]:
                    if not isinstance(entry, dict):
                        continue
                    issuer = str(entry.get("issuer_name") or "").strip()
                    common_name = str(entry.get("common_name") or "").strip().lower()
                    name_value = str(entry.get("name_value") or "").strip().lower()
                    serial_or_id = str(entry.get("id") or entry.get("serial_number") or common_name)

                    cert_label = f"{common_name or domain} ({serial_or_id})"
                    if cert_label not in certs_seen and (common_name or issuer):
                        certs_seen.add(cert_label)
                        cert_node = EntityNode(
                            entity_type=EntityType.CERTIFICATE,
                            value=cert_label,
                            confidence=0.92,
                            attributes={
                                "common_name": common_name,
                                "issuer_name": issuer,
                                "not_before": entry.get("not_before"),
                                "not_after": entry.get("not_after"),
                            },
                            evidence_ids=[ev_crt.evidence_id],
                        )
                        nodes.append(cert_node)
                        edges.append(
                            RelationshipEdge(
                                source_node_id=domain_node.node_id,
                                target_node_id=cert_node.node_id,
                                relation_type=RelationType.ISSUED_CERT,
                                weight=0.92,
                                confidence=0.92,
                                rationale=f"CT log certificate observed via crt.sh (issuer={issuer or 'unknown'})",
                                evidence_ids=[ev_crt.evidence_id],
                            )
                        )

                    raw_names = [common_name] + name_value.splitlines()
                    for raw_name in raw_names:
                        sub = raw_name.strip().lstrip("*.")
                        if (
                            sub
                            and sub != domain
                            and sub.endswith(f".{domain}")
                            and sub not in subdomains_by_name
                        ):
                            sub_node = EntityNode(
                                entity_type=EntityType.SUBDOMAIN,
                                value=sub,
                                confidence=0.90,
                                evidence_ids=[ev_crt.evidence_id],
                            )
                            subdomains_by_name[sub] = sub_node
                            nodes.append(sub_node)
                            edges.append(
                                RelationshipEdge(
                                    source_node_id=domain_node.node_id,
                                    target_node_id=sub_node.node_id,
                                    relation_type=RelationType.HAS_SUBDOMAIN,
                                    weight=0.90,
                                    confidence=0.90,
                                    rationale=f"Subdomain '{sub}' discovered in crt.sh Certificate Transparency log",
                                    evidence_ids=[ev_crt.evidence_id],
                                )
                            )
        except Exception as exc:
            errors.append(f"crt.sh lookup failed: {type(exc).__name__}: {exc}")

        # 2. RDAP / WHOIS Domain Registration Lookup
        rdap_url = f"https://rdap.org/domain/{urllib.parse.quote(domain)}"
        try:
            r_status, r_payload, ev_rdap, _ = await self.fetch_with_custody(
                url=rdap_url,
                case_id=case_id,
                ledger=active_ledger,
                storage=storage,
                notes=f"RDAP WHOIS registration lookup for '{domain}'",
            )
            if r_status == 200 and ev_rdap is not None and isinstance(r_payload, dict):
                evidence_items.append(ev_rdap)
                if ev_rdap.evidence_id not in domain_node.evidence_ids:
                    domain_node.evidence_ids.append(ev_rdap.evidence_id)

                orgs, emails = self._extract_rdap_entities(r_payload)
                for org_name in orgs:
                    org_node = EntityNode(
                        entity_type=EntityType.ORGANIZATION,
                        value=org_name,
                        confidence=0.88,
                        evidence_ids=[ev_rdap.evidence_id],
                    )
                    nodes.append(org_node)
                    edges.append(
                        RelationshipEdge(
                            source_node_id=org_node.node_id,
                            target_node_id=domain_node.node_id,
                            relation_type=RelationType.OWNS_DOMAIN,
                            weight=0.88,
                            confidence=0.88,
                            rationale=f"RDAP registrant/registrar entity for '{domain}'",
                            evidence_ids=[ev_rdap.evidence_id],
                        )
                    )

                for addr in emails:
                    em_metrics = analyze_handle_entropy(addr)
                    em_node = EntityNode(
                        entity_type=EntityType.EMAIL,
                        value=addr,
                        entropy_score=em_metrics.shannon_entropy,
                        rarity_score=em_metrics.rarity_score,
                        confidence=0.86,
                        evidence_ids=[ev_rdap.evidence_id],
                    )
                    nodes.append(em_node)
                    edges.append(
                        RelationshipEdge(
                            source_node_id=domain_node.node_id,
                            target_node_id=em_node.node_id,
                            relation_type=RelationType.HAS_EMAIL,
                            weight=0.86,
                            confidence=0.86,
                            rationale=f"Contact/abuse email listed in RDAP record for '{domain}'",
                            evidence_ids=[ev_rdap.evidence_id],
                        )
                    )
        except Exception as exc:
            errors.append(f"RDAP lookup failed: {type(exc).__name__}: {exc}")

        # 3. Passive DNS Resolution via DNS-over-HTTPS
        hosts_to_resolve = [domain] + sorted(subdomains_by_name.keys())[:10]
        for host in hosts_to_resolve:
            doh_url = f"https://dns.google/resolve?name={urllib.parse.quote(host)}&type=A"
            try:
                d_status, d_payload, ev_dns, _ = await self.fetch_with_custody(
                    url=doh_url,
                    case_id=case_id,
                    ledger=active_ledger,
                    storage=storage,
                    notes=f"Passive DNS A-record lookup for '{host}'",
                )
                if d_status != 200 or ev_dns is None or not isinstance(d_payload, dict):
                    continue
                answers = d_payload.get("Answer") or []
                if not isinstance(answers, list) or not answers:
                    continue
                evidence_items.append(ev_dns)
                parent_node = domain_node if host == domain else subdomains_by_name[host]
                if ev_dns.evidence_id not in parent_node.evidence_ids:
                    parent_node.evidence_ids.append(ev_dns.evidence_id)

                for ans in answers:
                    if not isinstance(ans, dict):
                        continue
                    ip_str = str(ans.get("data") or "").strip()
                    try:
                        ipaddress.ip_address(ip_str)
                    except ValueError:
                        continue
                    if ip_str not in ips_by_addr:
                        ip_node = EntityNode(
                            entity_type=EntityType.IP_ADDRESS,
                            value=ip_str,
                            confidence=0.92,
                            evidence_ids=[ev_dns.evidence_id],
                        )
                        ips_by_addr[ip_str] = ip_node
                        nodes.append(ip_node)
                    else:
                        ip_node = ips_by_addr[ip_str]
                        if ev_dns.evidence_id not in ip_node.evidence_ids:
                            ip_node.evidence_ids.append(ev_dns.evidence_id)

                    edges.append(
                        RelationshipEdge(
                            source_node_id=parent_node.node_id,
                            target_node_id=ip_node.node_id,
                            relation_type=RelationType.RESOLVES_TO,
                            weight=0.92,
                            confidence=0.92,
                            rationale=f"DNS A record resolves '{host}' -> {ip_str}",
                            evidence_ids=[ev_dns.evidence_id],
                        )
                    )
            except Exception as exc:
                errors.append(f"DNS resolve failed for '{host}': {type(exc).__name__}: {exc}")

        return CollectorResult(
            collector_name=self.name,
            query=domain,
            nodes=nodes,
            edges=edges,
            evidence_items=evidence_items,
            errors=errors,
        )
