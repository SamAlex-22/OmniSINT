"""Unit tests for Task 7: DomainCTCollector, ThreatIntelCollector, and SearchDorkCollector."""

from __future__ import annotations

import unittest
from typing import Any

from omnisint.collectors import (
    CollectorConfig,
    DomainCTCollector,
    HttpResponseData,
    SearchDorkCollector,
    ThreatIntelCollector,
    create_default_registry,
    generate_dork_queries,
)
from omnisint.config import OmniSINTSettings
from omnisint.core.custody import CustodyLedger
from omnisint.core.models import EntityType, RelationType


class TestInfraCollectors(unittest.IsolatedAsyncioTestCase):
    """Offline deterministic tests for DomainCTCollector, ThreatIntelCollector, and SearchDorkCollector."""

    async def test_domain_ct_collector_extracts_subdomains_certs_rdap_and_dns(self) -> None:
        async def _mock_get(
            url: str,
            headers: dict[str, str] | None,
            params: dict[str, Any] | None,
            timeout: float,
        ) -> HttpResponseData:
            if "crt.sh" in url:
                return HttpResponseData(
                    status_code=200,
                    body=[
                        {
                            "id": 1001,
                            "common_name": "*.alexsec.io",
                            "name_value": "*.alexsec.io\napi.alexsec.io\nvpn.alexsec.io",
                            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
                        }
                    ],
                )
            if "rdap.org/domain/alexsec.io" in url:
                return HttpResponseData(
                    status_code=200,
                    body={
                        "ldhName": "alexsec.io",
                        "entities": [
                            {
                                "roles": ["registrant"],
                                "vcardArray": [
                                    "vcard",
                                    [
                                        ["fn", {}, "text", "OmniSINT Security Lab"],
                                        ["email", {}, "text", "hostmaster@alexsec.io"],
                                    ],
                                ],
                            }
                        ],
                    },
                )
            if "dns.google/resolve" in url:
                if "name=alexsec.io" in url:
                    return HttpResponseData(
                        status_code=200,
                        body={"Answer": [{"type": 1, "data": "203.0.113.10"}]},
                    )
                if "name=api.alexsec.io" in url:
                    return HttpResponseData(
                        status_code=200,
                        body={"Answer": [{"type": 1, "data": "203.0.113.11"}]},
                    )
            return HttpResponseData(status_code=404, body={})

        ledger = CustodyLedger(case_id="case-domain-01")
        collector = DomainCTCollector(
            config=CollectorConfig(rate_limit_per_second=100.0),
            http_transport=_mock_get,
        )
        result = await collector.collect("alexsec.io", case_id="case-domain-01", ledger=ledger)

        self.assertEqual(result.errors, [])
        subdomains = {n.value for n in result.nodes if n.entity_type == EntityType.SUBDOMAIN}
        ips = {n.value for n in result.nodes if n.entity_type == EntityType.IP_ADDRESS}
        orgs = {n.value for n in result.nodes if n.entity_type == EntityType.ORGANIZATION}
        emails = {n.value for n in result.nodes if n.entity_type == EntityType.EMAIL}

        self.assertEqual(subdomains, {"api.alexsec.io", "vpn.alexsec.io"})
        self.assertEqual(ips, {"203.0.113.10", "203.0.113.11"})
        self.assertEqual(orgs, {"OmniSINT Security Lab"})
        self.assertEqual(emails, {"hostmaster@alexsec.io"})
        self.assertTrue(any(n.entity_type == EntityType.CERTIFICATE for n in result.nodes))
        self.assertTrue(ledger.verify_chain()[0])

    async def test_threat_intel_collector_virustotal_and_offline_fallback(self) -> None:
        async def _mock_vt(
            url: str,
            headers: dict[str, str] | None,
            params: dict[str, Any] | None,
            timeout: float,
        ) -> HttpResponseData:
            return HttpResponseData(
                status_code=200,
                body={
                    "data": {
                        "attributes": {
                            "reputation": -15,
                            "last_analysis_stats": {
                                "malicious": 3,
                                "suspicious": 1,
                                "harmless": 80,
                                "undetected": 6,
                            },
                            "last_dns_records": [
                                {"type": "A", "value": "198.51.100.42"},
                            ],
                        }
                    }
                },
            )

        ledger = CustodyLedger(case_id="case-vt-01")
        settings = OmniSINTSettings(virustotal_api_key="test-vt-key")
        vt_collector = ThreatIntelCollector(
            config=CollectorConfig(rate_limit_per_second=100.0),
            settings=settings,
            http_transport=_mock_vt,
        )
        res = await vt_collector.collect("suspicious-c2.example", case_id="case-vt-01", ledger=ledger)

        self.assertEqual(res.errors, [])
        indicators = [n for n in res.nodes if n.entity_type == EntityType.THREAT_INDICATOR]
        self.assertEqual(len(indicators), 1)
        self.assertEqual(indicators[0].attributes["verdict"], "MALICIOUS")
        self.assertEqual(indicators[0].attributes["malicious"], 3)
        self.assertTrue(any(n.value == "198.51.100.42" for n in res.nodes))
        self.assertTrue(any(e.relation_type == RelationType.FLAGGED_BY for e in res.edges))
        self.assertTrue(ledger.verify_chain()[0])

        # Without VT API key and without custom transport -> offline passive posture record
        offline_vt = ThreatIntelCollector(settings=OmniSINTSettings(virustotal_api_key=None))
        offline_res = await offline_vt.collect("alexsec.io", case_id="case-vt-off")
        self.assertEqual(offline_res.errors, [])
        self.assertEqual(len(offline_res.evidence_items), 1)

    async def test_search_dork_collector_wayback_and_cse(self) -> None:
        async def _mock_search(
            url: str,
            headers: dict[str, str] | None,
            params: dict[str, Any] | None,
            timeout: float,
        ) -> HttpResponseData:
            if "web.archive.org/cdx/search/cdx" in url:
                return HttpResponseData(
                    status_code=200,
                    body=[
                        ["urlkey", "timestamp", "original"],
                        ["io,alexsec)/about", "20250101120000", "https://alexsec.io/about"],
                        ["io,alexsec)/keys.asc", "20250115100000", "https://alexsec.io/keys.asc"],
                    ],
                )
            if "customsearch/v1" in url:
                return HttpResponseData(
                    status_code=200,
                    body={
                        "items": [
                            {
                                "link": "https://gist.github.com/krypton_sec/12345",
                                "title": "PGP key backup",
                                "snippet": "krypton_sec PGP public block",
                            }
                        ]
                    },
                )
            return HttpResponseData(status_code=404, body={})

        dorks = generate_dork_queries("alexsec.io", EntityType.DOMAIN)
        self.assertGreaterEqual(len(dorks), 3)

        ledger = CustodyLedger(case_id="case-dork-01")
        collector = SearchDorkCollector(
            config=CollectorConfig(rate_limit_per_second=100.0),
            settings=OmniSINTSettings(google_cse_api_key="k", google_cse_cx="cx"),
            http_transport=_mock_search,
        )
        res_domain = await collector.collect("alexsec.io", case_id="case-dork-01", ledger=ledger)
        urls = {n.value for n in res_domain.nodes if n.entity_type == EntityType.URL}
        self.assertIn("https://alexsec.io/about", urls)
        self.assertIn("https://alexsec.io/keys.asc", urls)
        self.assertIn("https://gist.github.com/krypton_sec/12345", urls)
        self.assertTrue(ledger.verify_chain()[0])

        # Verify default registry contains all 5 collectors
        registry = create_default_registry()
        self.assertEqual(len(registry.list_collectors()), 5)


if __name__ == "__main__":
    unittest.main()
