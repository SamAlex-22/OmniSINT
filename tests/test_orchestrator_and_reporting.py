"""Unit tests for Task 8: Async Scan Orchestrator, Pivot Engine, Markdown & STIX 2.1 Exporters."""

from __future__ import annotations

import json
import unittest
from typing import Any

from omnisint.collectors import (
    CollectorConfig,
    HttpResponseData,
    create_default_registry,
)
from omnisint.config import OmniSINTSettings
from omnisint.core.custody import CustodySigner
from omnisint.core.models import CaseStatus, EntityType
from omnisint.core.orchestrator import (
    ScanOrchestrator,
    ScanProgressEvent,
    infer_entity_type,
)
from omnisint.core.storage import CaseStorage
from omnisint.reporting import MarkdownExporter, STIXExporter


class TestOrchestratorAndReporting(unittest.IsolatedAsyncioTestCase):
    """End-to-end offline tests for ScanOrchestrator multi-hop pivoting and Markdown/STIX 2.1 export."""

    async def test_multi_hop_scan_orchestrator_pivots_and_exporters(self) -> None:
        async def _mock_http(
            url: str,
            headers: dict[str, str] | None,
            params: dict[str, Any] | None,
            timeout: float,
        ) -> HttpResponseData:
            if url == "https://api.github.com/users/krypton_sec_x7":
                return HttpResponseData(
                    status_code=200,
                    body={
                        "login": "krypton_sec_x7",
                        "name": "Alex K.",
                        "blog": "https://alexsec.io",
                        "location": "Bengaluru, India",
                        "avatar_hash": "8f3c3c1e1e0f0f00",
                        "created_at": "2024-01-10T10:00:00Z",
                    },
                )
            if url == "https://api.github.com/users/krypton_sec_x7/repos":
                return HttpResponseData(
                    status_code=200,
                    body=[{"full_name": "krypton_sec_x7/omnisint", "language": "Python"}],
                )
            if url == "https://api.github.com/users/krypton_sec_x7/events/public":
                return HttpResponseData(
                    status_code=200,
                    body=[
                        {
                            "type": "PushEvent",
                            "created_at": "2026-05-05T15:30:00+05:30",
                            "repo": {"name": "krypton_sec_x7/omnisint"},
                            "payload": {
                                "commits": [
                                    {
                                        "timestamp": "2026-05-05T15:28:00+05:30",
                                        "author": {"email": "krypton@alexsec.io"},
                                    }
                                ]
                            },
                        }
                    ],
                )
            if url == "https://github.com/krypton_sec_x7.keys":
                return HttpResponseData(
                    status_code=200,
                    body="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOmniSINTUnitTestKey\n",
                )
            if "crt.sh" in url and "alexsec.io" in url:
                return HttpResponseData(
                    status_code=200,
                    body=[
                        {
                            "id": 99,
                            "common_name": "api.alexsec.io",
                            "name_value": "api.alexsec.io",
                            "issuer_name": "Let's Encrypt",
                        }
                    ],
                )
            if "dns.google/resolve" in url and "alexsec.io" in url:
                return HttpResponseData(
                    status_code=200,
                    body={"Answer": [{"type": 1, "data": "203.0.113.10"}]},
                )
            if "virustotal.com/api/v3/domains/alexsec.io" in url:
                return HttpResponseData(
                    status_code=200,
                    body={
                        "data": {
                            "attributes": {
                                "reputation": 10,
                                "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 88},
                            }
                        }
                    },
                )
            if "web.archive.org/cdx/search/cdx" in url and "alexsec.io" in url:
                return HttpResponseData(
                    status_code=200,
                    body=[
                        ["urlkey", "timestamp", "original"],
                        ["io,alexsec)/", "20260101000000", "https://alexsec.io/"],
                    ],
                )
            return HttpResponseData(status_code=404, body={})

        self.assertEqual(infer_entity_type("krypton_sec_x7"), EntityType.USERNAME)
        self.assertEqual(infer_entity_type("krypton@alexsec.io"), EntityType.EMAIL)
        self.assertEqual(infer_entity_type("alexsec.io"), EntityType.DOMAIN)
        self.assertEqual(infer_entity_type("203.0.113.10"), EntityType.IP_ADDRESS)

        events: list[ScanProgressEvent] = []

        async def _on_progress(ev: ScanProgressEvent) -> None:
            events.append(ev)

        settings = OmniSINTSettings(virustotal_api_key="vt-key")
        registry = create_default_registry(
            config=CollectorConfig(rate_limit_per_second=100.0),
            settings=settings,
            http_transport=_mock_http,
        )

        async with CaseStorage(":memory:") as storage:
            orchestrator = ScanOrchestrator(
                storage=storage,
                registry=registry,
                progress_callback=_on_progress,
            )
            case, report = await orchestrator.run_scan(
                query="krypton_sec_x7",
                title="Multi-Hop Pivot Investigation",
                max_hops=2,
            )

            self.assertEqual(case.status, CaseStatus.COMPLETED)
            self.assertIsNotNone(report)
            assert report is not None
            self.assertTrue(report.citation_audit.is_valid)
            self.assertGreaterEqual(len(case.personas), 1)

            # Verify Hop 1 (GitHub/Username) AND Hop 2 (DomainCT/ThreatIntel/Wayback on alexsec.io) ran
            node_types = {n.entity_type for n in case.nodes}
            self.assertIn(EntityType.SOCIAL_PROFILE, node_types)
            self.assertIn(EntityType.EMAIL, node_types)
            self.assertIn(EntityType.DOMAIN, node_types)
            self.assertIn(EntityType.SUBDOMAIN, node_types)
            self.assertIn(EntityType.IP_ADDRESS, node_types)
            self.assertIn(EntityType.THREAT_INDICATOR, node_types)

            # Verify cryptographic custody integrity in SQLite
            custody_ok, violations = await storage.verify_case_custody(case.case_id)
            self.assertTrue(custody_ok, f"Unexpected custody violations: {violations}")
            self.assertTrue(any(ev.stage == "completed" for ev in events))

            # Explicit manual pivot on the IP node
            ip_node = next(n for n in case.nodes if n.entity_type == EntityType.IP_ADDRESS)
            pivoted_case, _ = await orchestrator.pivot_on_node(
                case_id=case.case_id,
                node_id=ip_node.node_id,
            )
            self.assertTrue(any(a.action == "PIVOT_EXECUTED" for a in pivoted_case.audit_log))

            # Export Markdown dossier with Ed25519 custody signature + PII redaction mode
            signer = CustodySigner()
            md = MarkdownExporter().export(pivoted_case, verify_custody=True, signer=signer)
            self.assertIn("VERIFIED (INTACT)", md)
            self.assertIn("```mermaid", md)
            self.assertIn("SHA-256 Chain of Custody Evidence Ledger", md)
            self.assertIn(signer.public_key_hex, md)

            md_redacted = MarkdownExporter().export(pivoted_case, verify_custody=True, redact_pii=True)
            self.assertNotIn("krypton@alexsec.io", md_redacted)
            self.assertIn("k***@alexsec.io", md_redacted)
            self.assertNotIn("203.0.113.10", md_redacted)
            self.assertIn("203.0.xxx.xxx", md_redacted)

            # Export OASIS STIX 2.1 JSON Bundle (with valid observable STIX indicator pattern)
            stix_json = STIXExporter().export_json(pivoted_case)
            bundle = json.loads(stix_json)
            self.assertEqual(bundle["type"], "bundle")
            obj_types = {obj["type"] for obj in bundle["objects"]}
            self.assertIn("identity", obj_types)
            self.assertIn("user-account", obj_types)
            self.assertIn("domain-name", obj_types)
            self.assertIn("ipv4-addr", obj_types)
            self.assertIn("relationship", obj_types)
            self.assertIn("note", obj_types)
            indicators = [obj for obj in bundle["objects"] if obj["type"] == "indicator"]
            self.assertEqual(indicators[0]["pattern"], "[domain-name:value = 'alexsec.io']")


if __name__ == "__main__":
    unittest.main()
