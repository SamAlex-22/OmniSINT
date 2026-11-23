"""OASIS STIX 2.1 Threat Intelligence bundle exporter for OmniSINT Cases."""

from __future__ import annotations

import ipaddress
import json
import uuid
from typing import Any

from omnisint.core.custody import CustodyLedger
from omnisint.core.models import Case, EntityNode, EntityType, PersonaCluster, RelationshipEdge

# Deterministic UUIDv5 namespace for OmniSINT STIX 2.1 object identifiers
OMNISINT_STIX_NAMESPACE = uuid.UUID("a3f1e890-771c-4b26-abeb-551bcb142766")


def _stix_id(stix_type: str, seed: str) -> str:
    """Generate a deterministic STIX 2.1 identifier `<stix_type>--<uuidv5>`."""
    return f"{stix_type}--{uuid.uuid5(OMNISINT_STIX_NAMESPACE, f'{stix_type}:{seed}')}"


class STIXExporter:
    """Exports a resolved OmniSINT Case into an OASIS STIX 2.1 JSON Bundle."""

    @staticmethod
    def _node_to_stix_object(node: EntityNode) -> dict[str, Any]:
        """Map an EntityNode into a STIX 2.1 SCO or SDO dictionary."""
        etype = node.entity_type
        custom_ext = {
            "x_omnisint_node_id": node.node_id,
            "x_omnisint_confidence": node.confidence,
            "x_omnisint_entropy": node.entropy_score,
            "x_omnisint_rarity": node.rarity_score,
            "x_omnisint_evidence_ids": list(node.evidence_ids),
        }

        if etype in (EntityType.USERNAME, EntityType.SOCIAL_PROFILE):
            obj: dict[str, Any] = {
                "type": "user-account",
                "spec_version": "2.1",
                "id": _stix_id("user-account", node.node_id),
                "user_id": node.value,
                "account_login": node.value,
                **custom_ext,
            }
            if node.platform:
                obj["account_type"] = node.platform.lower()
            return obj

        if etype == EntityType.EMAIL:
            return {
                "type": "email-addr",
                "spec_version": "2.1",
                "id": _stix_id("email-addr", node.node_id),
                "value": node.value,
                **custom_ext,
            }

        if etype in (EntityType.DOMAIN, EntityType.SUBDOMAIN):
            return {
                "type": "domain-name",
                "spec_version": "2.1",
                "id": _stix_id("domain-name", node.node_id),
                "value": node.value,
                **custom_ext,
            }

        if etype == EntityType.IP_ADDRESS:
            stix_ip_type = "ipv4-addr"
            try:
                if ipaddress.ip_address(node.value).version == 6:
                    stix_ip_type = "ipv6-addr"
            except ValueError:
                pass
            return {
                "type": stix_ip_type,
                "spec_version": "2.1",
                "id": _stix_id(stix_ip_type, node.node_id),
                "value": node.value,
                **custom_ext,
            }

        if etype == EntityType.URL:
            return {
                "type": "url",
                "spec_version": "2.1",
                "id": _stix_id("url", node.node_id),
                "value": node.value,
                **custom_ext,
            }

        if etype == EntityType.CERTIFICATE:
            return {
                "type": "x509-certificate",
                "spec_version": "2.1",
                "id": _stix_id("x509-certificate", node.node_id),
                "subject": node.attributes.get("common_name") or node.value,
                "issuer": node.attributes.get("issuer_name") or "Unknown",
                **custom_ext,
            }

        if etype in (EntityType.ORGANIZATION, EntityType.PERSON):
            return {
                "type": "identity",
                "spec_version": "2.1",
                "id": _stix_id("identity", node.node_id),
                "name": node.label,
                "identity_class": "organization" if etype == EntityType.ORGANIZATION else "individual",
                **custom_ext,
            }

        if etype == EntityType.LOCATION:
            return {
                "type": "location",
                "spec_version": "2.1",
                "id": _stix_id("location", node.node_id),
                "name": node.value,
                **custom_ext,
            }

        if etype == EntityType.THREAT_INDICATOR:
            raw_val = node.value
            parts = raw_val.split(":")
            target_observable = parts[1] if len(parts) >= 3 else raw_val
            try:
                ip_obj = ipaddress.ip_address(target_observable)
                stix_obs = "ipv6-addr" if ip_obj.version == 6 else "ipv4-addr"
                pattern = f"[{stix_obs}:value = '{target_observable}']"
            except ValueError:
                if "." in target_observable and " " not in target_observable:
                    pattern = f"[domain-name:value = '{target_observable}']"
                else:
                    pattern = f"[x-omnisint-indicator:value = '{raw_val}']"
            return {
                "type": "indicator",
                "spec_version": "2.1",
                "id": _stix_id("indicator", node.node_id),
                "name": node.label,
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": node.discovered_at_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "confidence": int(round(node.confidence * 100)),
                **custom_ext,
            }

        # Repositories, PGP/SSH keys, Avatar hashes, Phones -> STIX infrastructure or observed artifact
        return {
            "type": "infrastructure",
            "spec_version": "2.1",
            "id": _stix_id("infrastructure", node.node_id),
            "name": node.label,
            "description": f"{etype.value}: {node.value}",
            **custom_ext,
        }

    @staticmethod
    def _persona_to_stix_identity(persona: PersonaCluster) -> dict[str, Any]:
        """Map a resolved PersonaCluster into a STIX 2.1 Identity SDO."""
        return {
            "type": "identity",
            "spec_version": "2.1",
            "id": _stix_id("identity", persona.cluster_id),
            "name": persona.persona_label,
            "description": persona.summary,
            "identity_class": "individual",
            "confidence": int(round(persona.confidence_score * 100)),
            "x_omnisint_cluster_id": persona.cluster_id,
            "x_omnisint_primary_handle": persona.primary_handle,
            "x_omnisint_avg_handle_entropy": persona.avg_handle_entropy,
            "x_omnisint_inferred_timezone": persona.inferred_timezone,
            "x_omnisint_evidence_ids": list(persona.evidence_ids),
        }

    @staticmethod
    def _edge_to_stix_relationship(
        edge: RelationshipEdge,
        stix_id_by_node_id: dict[str, str],
    ) -> dict[str, Any] | None:
        """Map a RelationshipEdge into a STIX 2.1 Relationship SRO."""
        src_ref = stix_id_by_node_id.get(edge.source_node_id)
        tgt_ref = stix_id_by_node_id.get(edge.target_node_id)
        if not src_ref or not tgt_ref:
            return None

        return {
            "type": "relationship",
            "spec_version": "2.1",
            "id": _stix_id("relationship", edge.edge_id),
            "relationship_type": edge.relation_type.value.lower().replace("_", "-"),
            "source_ref": src_ref,
            "target_ref": tgt_ref,
            "description": edge.rationale,
            "confidence": int(round(edge.confidence * 100)),
            "x_omnisint_weight": edge.weight,
            "x_omnisint_evidence_ids": list(edge.evidence_ids),
        }

    def export_bundle(self, case: Case) -> dict[str, Any]:
        """Export a Case as a STIX 2.1 Bundle dictionary."""
        objects: list[dict[str, Any]] = []
        stix_id_by_node_id: dict[str, str] = {}

        # 1. Convert EntityNodes
        for node in case.nodes:
            stix_obj = self._node_to_stix_object(node)
            stix_id_by_node_id[node.node_id] = stix_obj["id"]
            objects.append(stix_obj)

        # 2. Convert PersonaClusters & emit attributed-to links to member nodes
        for persona in case.personas:
            p_obj = self._persona_to_stix_identity(persona)
            objects.append(p_obj)
            for nid in persona.node_ids:
                member_ref = stix_id_by_node_id.get(nid)
                if member_ref:
                    objects.append(
                        {
                            "type": "relationship",
                            "spec_version": "2.1",
                            "id": _stix_id("relationship", f"{persona.cluster_id}:{nid}"),
                            "relationship_type": "attributed-to",
                            "source_ref": member_ref,
                            "target_ref": p_obj["id"],
                            "confidence": int(round(persona.confidence_score * 100)),
                        }
                    )

        # 3. Convert RelationshipEdges
        for edge in case.edges:
            rel_obj = self._edge_to_stix_relationship(edge, stix_id_by_node_id)
            if rel_obj is not None:
                objects.append(rel_obj)

        # 4. Attach Case Executive Brief & SHA-256 Custody Ledger Note
        ledger = CustodyLedger(
            case_id=case.case_id,
            existing_evidence=case.evidence_ledger,
            existing_audit_log=case.audit_log,
        )
        custody_valid, _ = ledger.verify_chain()
        object_refs = [obj["id"] for obj in objects]
        if object_refs:
            objects.append(
                {
                    "type": "note",
                    "spec_version": "2.1",
                    "id": _stix_id("note", case.case_id),
                    "abstract": f"OmniSINT Case '{case.title}' (Custody={custody_valid})",
                    "content": case.ai_executive_brief or case.description or case.title,
                    "object_refs": object_refs,
                    "x_omnisint_case_id": case.case_id,
                    "x_omnisint_custody_head_hash": ledger.head_chain_hash,
                    "x_omnisint_custody_valid": custody_valid,
                    "x_omnisint_evidence_count": len(case.evidence_ledger),
                }
            )

        return {
            "type": "bundle",
            "id": _stix_id("bundle", case.case_id),
            "objects": objects,
        }

    def export_json(self, case: Case, indent: int = 2) -> str:
        """Serialize a Case's STIX 2.1 Bundle to formatted JSON."""
        return json.dumps(self.export_bundle(case), indent=indent)
