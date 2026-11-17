"""Unit tests for Task 9: REST API & Cytoscape.js Web GUI endpoints."""

from __future__ import annotations

import asyncio
import json
import unittest
from typing import Any

from omnisint.api import create_app
from omnisint.collectors import CollectorConfig, HttpResponseData, create_default_registry
from omnisint.core.orchestrator import ScanOrchestrator
from omnisint.core.storage import CaseStorage


class TestOmniSINTAPI(unittest.TestCase):
    """Offline integration tests for the OmniSINT Web API and Cytoscape.js UI serving."""

    def test_api_case_scan_graph_pivot_custody_and_exports(self) -> None:
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
                    },
                )
            if "crt.sh" in url and "alexsec.io" in url:
                return HttpResponseData(
                    status_code=200,
                    body=[{"id": 1, "common_name": "api.alexsec.io", "name_value": "api.alexsec.io"}],
                )
            return HttpResponseData(status_code=404, body={})

        storage = CaseStorage(":memory:")
        asyncio.run(storage.initialize())
        registry = create_default_registry(
            config=CollectorConfig(rate_limit_per_second=100.0),
            http_transport=_mock_http,
        )
        orchestrator = ScanOrchestrator(storage=storage, registry=registry)
        app = create_app(storage=storage, orchestrator=orchestrator)

        try:
            client = app.test_client()

            # 1. Health & Web GUI HTML
            health = client.get("/api/health")
            self.assertEqual(health.status_code, 200)
            self.assertEqual(health.get_json()["status"], "ok")

            index_res = client.get("/")
            self.assertEqual(index_res.status_code, 200)
            self.assertIn("OmniSINT", index_res.get_data(as_text=True))
            self.assertIn("cytoscape", index_res.get_data(as_text=True))

            # 2. Create Case
            create_res = client.post(
                "/api/cases",
                json={"title": "Web GUI Case", "target_query": "krypton_sec_x7"},
            )
            self.assertEqual(create_res.status_code, 201)
            case_id = create_res.get_json()["case_id"]

            # 3. Run Scan via API
            scan_res = client.post(
                f"/api/cases/{case_id}/scan",
                json={"query": "krypton_sec_x7", "max_hops": 2, "run_ai_analysis": True},
            )
            self.assertEqual(scan_res.status_code, 200)
            scan_data = scan_res.get_json()
            self.assertGreaterEqual(scan_data["node_count"], 2)
            self.assertTrue(scan_data["citation_valid"])

            # 4. Graph endpoint returns Cytoscape elements + Hierarchy Tree
            graph_res = client.get(f"/api/cases/{case_id}/graph")
            self.assertEqual(graph_res.status_code, 200)
            graph_data = graph_res.get_json()
            self.assertGreaterEqual(len(graph_data["elements"]["nodes"]), 2)
            self.assertGreaterEqual(len(graph_data["personas"]), 1)

            # 5. Custody endpoint verifies intact SHA-256 chain
            custody_res = client.get(f"/api/cases/{case_id}/custody")
            self.assertEqual(custody_res.status_code, 200)
            custody_data = custody_res.get_json()
            self.assertTrue(custody_data["is_valid"])
            self.assertGreaterEqual(custody_data["item_count"], 1)

            # 6. One-click Node Pivot endpoint
            target_node_id = graph_data["personas"][0]["node_ids"][0]
            pivot_res = client.post(
                f"/api/cases/{case_id}/pivot",
                json={"node_id": target_node_id},
            )
            self.assertEqual(pivot_res.status_code, 200)

            # 7. Export Markdown & STIX 2.1 endpoints
            md_res = client.get(f"/api/cases/{case_id}/export/markdown")
            self.assertEqual(md_res.status_code, 200)
            self.assertIn("VERIFIED (INTACT)", md_res.get_data(as_text=True))

            stix_res = client.get(f"/api/cases/{case_id}/export/stix")
            self.assertEqual(stix_res.status_code, 200)
            bundle = json.loads(stix_res.get_data(as_text=True))
            self.assertEqual(bundle["type"], "bundle")

            # 8. 404 handling for missing case
            missing_res = client.get("/api/cases/nonexistent-case")
            self.assertEqual(missing_res.status_code, 404)
        finally:
            asyncio.run(storage.close())


if __name__ == "__main__":
    unittest.main()
