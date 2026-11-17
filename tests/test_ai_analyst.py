"""Unit tests for Task 5: Citation-Locked AI Analyst & Persona Dossier Synthesizer."""

from __future__ import annotations

import unittest
from typing import Any

from omnisint.core.custody import CustodyLedger
from omnisint.core.models import (
    Case,
    EntityNode,
    EntityType,
    RelationshipEdge,
    RelationType,
)
from omnisint.intelligence.ai_analyst import (
    AIAnalyst,
    audit_citations,
    extract_citations,
    sanitize_hallucinated_citations,
)
from omnisint.intelligence.similarity import compute_dhash_from_pixels


class TestAIAnalyst(unittest.IsolatedAsyncioTestCase):
    """Test suite for citation-locked AIAnalyst, Identity Confidence Matrix, and LLM providers."""

    def _build_disambiguation_case(self) -> Case:
        ledger = CustodyLedger(case_id="case-ai-001")
        ev_a1 = ledger.record_evidence(
            collector_name="github_collector",
            source_uri="https://api.github.com/users/krypton_sec_x7",
            raw_payload={"login": "krypton_sec_x7", "location": "Bengaluru, India"},
        )
        ev_a2 = ledger.record_evidence(
            collector_name="username_collector",
            source_uri="https://x.com/x7kryptonsec",
            raw_payload={"handle": "x7kryptonsec", "location": "Bengaluru, India"},
        )
        ev_b1 = ledger.record_evidence(
            collector_name="username_collector",
            source_uri="https://gitlab.com/krypton_sec",
            raw_payload={"handle": "krypton_sec", "location": "Seattle, USA"},
        )

        grid = [[(r * 20 + c * 10) % 255 for c in range(9)] for r in range(8)]
        dhash_a = compute_dhash_from_pixels(grid)

        nodes = [
            EntityNode(
                node_id="n-gh-a",
                entity_type=EntityType.SOCIAL_PROFILE,
                value="krypton_sec_x7",
                platform="GitHub",
                evidence_ids=[ev_a1.evidence_id],
                attributes={
                    "location": "Bengaluru, India",
                    "avatar_hash": dhash_a,
                    "timestamps": [
                        "2026-05-04T14:15:00+05:30",
                        "2026-05-05T15:30:00+05:30",
                        "2026-05-06T16:10:00+05:30",
                    ],
                },
            ),
            EntityNode(
                node_id="n-tw-a",
                entity_type=EntityType.SOCIAL_PROFILE,
                value="x7kryptonsec",
                platform="Twitter",
                evidence_ids=[ev_a2.evidence_id],
                attributes={
                    "location": "Bengaluru, India",
                    "avatar_hash": dhash_a,
                    "timestamps": [
                        "2026-05-07T14:45:00+05:30",
                        "2026-05-08T15:20:00+05:30",
                        "2026-05-09T16:05:00+05:30",
                    ],
                },
            ),
            EntityNode(
                node_id="n-email-a",
                entity_type=EntityType.EMAIL,
                value="krypton@proton.me",
                evidence_ids=[ev_a1.evidence_id],
            ),
            EntityNode(
                node_id="n-repo-a",
                entity_type=EntityType.REPOSITORY,
                value="github.com/krypton_sec_x7/omnisint",
                evidence_ids=[ev_a1.evidence_id],
            ),
            EntityNode(
                node_id="n-gl-b",
                entity_type=EntityType.SOCIAL_PROFILE,
                value="krypton_sec",
                platform="GitLab",
                evidence_ids=[ev_b1.evidence_id],
                attributes={
                    "location": "Seattle, USA",
                    "timestamps": [
                        "2026-05-04T14:10:00-07:00",
                        "2026-05-05T15:20:00-07:00",
                        "2026-05-06T16:05:00-07:00",
                    ],
                },
            ),
        ]

        edges = [
            RelationshipEdge(
                source_node_id="n-gh-a",
                target_node_id="n-email-a",
                relation_type=RelationType.HAS_EMAIL,
                weight=0.95,
                confidence=0.95,
                evidence_ids=[ev_a1.evidence_id],
            ),
            RelationshipEdge(
                source_node_id="n-gh-a",
                target_node_id="n-repo-a",
                relation_type=RelationType.OWNS_REPO,
                weight=0.95,
                confidence=0.95,
                evidence_ids=[ev_a1.evidence_id],
            ),
        ]

        return Case(
            case_id="case-ai-001",
            title="Krypton Persona Disambiguation",
            target_query="krypton_sec",
            nodes=nodes,
            edges=edges,
            evidence_ledger=ledger.evidence_items,
            audit_log=ledger.audit_log,
        )

    def test_deterministic_ai_analyst_produces_citation_locked_brief_and_matrix(self) -> None:
        case = self._build_disambiguation_case()
        analyst = AIAnalyst(provider="deterministic")
        report = analyst.analyze_case_sync(case)

        self.assertEqual(report.provider_used, "deterministic")
        self.assertEqual(len(report.identity_matrix), 2)
        self.assertTrue(report.citation_audit.is_valid)
        self.assertEqual(report.citation_audit.hallucinated_node_ids, [])
        self.assertEqual(report.citation_audit.hallucinated_evidence_ids, [])
        self.assertEqual(report.citation_audit.uncited_persona_clusters, [])

        # Primary cluster (Bengaluru UTC+05:30) should be HIGH confidence with multiple modalities
        primary_row = report.identity_matrix[0]
        self.assertEqual(primary_row.confidence_tier, "HIGH")
        self.assertEqual(primary_row.inferred_timezone, "UTC+05:30")
        self.assertIn("Perceptual Avatar Match (dHash)", primary_row.corroborating_modalities)
        self.assertIn("Hard Contact Selector (Email)", primary_row.corroborating_modalities)

        # Colliding namesake (Seattle UTC-07:00) should be separated into cluster 2
        secondary_row = report.identity_matrix[1]
        self.assertEqual(secondary_row.inferred_timezone, "UTC-07:00")
        self.assertEqual(secondary_row.node_ids, ["n-gl-b"])

        # Executive brief must be populated on Case and contain explicit [node:...] and [evidence:...] tags
        self.assertEqual(case.ai_executive_brief, report.executive_brief)
        self.assertIn("[node:n-gh-a]", report.executive_brief)
        self.assertIn("[node:n-gl-b]", report.executive_brief)
        for ev in case.evidence_ledger:
            self.assertIn(f"[evidence:{ev.evidence_id}]", report.executive_brief)

    async def test_citation_audit_detects_and_sanitizes_hallucinated_ids(self) -> None:
        case = self._build_disambiguation_case()
        valid_nodes = {n.node_id for n in case.nodes}
        valid_evs = {ev.evidence_id for ev in case.evidence_ledger}

        hallucinated_text = (
            "Analysis shows [node:n-gh-a] is linked to [node:ghost-node-999] "
            "via [evidence:fake-ev-123] and [evidence:"
            + case.evidence_ledger[0].evidence_id
            + "]."
        )
        audit = audit_citations(hallucinated_text, valid_nodes, valid_evs)
        self.assertFalse(audit.is_valid)
        self.assertEqual(audit.hallucinated_node_ids, ["ghost-node-999"])
        self.assertEqual(audit.hallucinated_evidence_ids, ["fake-ev-123"])

        sanitized = sanitize_hallucinated_citations(hallucinated_text, valid_nodes, valid_evs)
        self.assertIn("[REDACTED-UNVERIFIED-NODE:ghost-node-999]", sanitized)
        self.assertIn("[REDACTED-UNVERIFIED-EVIDENCE:fake-ev-123]", sanitized)
        self.assertIn("[node:n-gh-a]", sanitized)

        # Verify AIAnalyst automatically sanitizes hallucinated LLM output and appends verified appendix
        async def _hallucinating_transport(
            url: str,
            payload: dict[str, Any],
            headers: dict[str, str],
            timeout: float,
        ) -> dict[str, Any]:
            return {
                "choices": [
                    {
                        "message": {
                            "content": "Target [node:n-gh-a] also owns [node:hallucinated-99] per [evidence:fake-ev-00]."
                        }
                    }
                ]
            }

        analyst = AIAnalyst(
            provider="openai",
            model="gpt-4o-mini",
            api_key="test-key",
            http_transport=_hallucinating_transport,
        )
        report = await analyst.analyze_case(case)
        self.assertTrue(report.citation_audit.is_valid)
        self.assertIn("[REDACTED-UNVERIFIED-NODE:hallucinated-99]", report.executive_brief)
        self.assertIn("Verified Evidentiary Appendix", report.executive_brief)

    async def test_gemini_openai_and_ollama_providers_with_mock_transport(self) -> None:
        case = self._build_disambiguation_case()
        ev_ids = [ev.evidence_id for ev in case.evidence_ledger]
        valid_llm_markdown = (
            f"# Verified Brief\n"
            f"- Persona 1: [node:n-gh-a] [node:n-tw-a] [evidence:{ev_ids[0]}] [evidence:{ev_ids[1]}]\n"
            f"- Persona 2: [node:n-gl-b] [evidence:{ev_ids[2]}]\n"
        )

        captured_urls: list[str] = []

        async def _mock_transport(
            url: str,
            payload: dict[str, Any],
            headers: dict[str, str],
            timeout: float,
        ) -> dict[str, Any]:
            captured_urls.append(url)
            if "generativelanguage.googleapis.com" in url:
                return {"candidates": [{"content": {"parts": [{"text": valid_llm_markdown}]}}]}
            if "api.openai.com" in url:
                return {"choices": [{"message": {"content": valid_llm_markdown}}]}
            if "/api/generate" in url:
                return {"response": valid_llm_markdown}
            raise RuntimeError("Unknown endpoint")

        # 1. Gemini provider
        gemini_analyst = AIAnalyst(
            provider="gemini",
            model="gemini-2.5-flash",
            api_key="gm-key",
            http_transport=_mock_transport,
        )
        gm_report = await gemini_analyst.analyze_case(case)
        self.assertEqual(gm_report.provider_used, "gemini")
        self.assertTrue(gm_report.citation_audit.is_valid)
        self.assertEqual(gm_report.executive_brief, valid_llm_markdown.strip())

        # 2. Ollama provider
        ollama_analyst = AIAnalyst(
            provider="ollama",
            model="llama3.1:8b",
            ollama_base_url="http://localhost:11434",
            http_transport=_mock_transport,
        )
        ol_report = await ollama_analyst.analyze_case(case)
        self.assertEqual(ol_report.provider_used, "ollama")
        self.assertTrue(ol_report.citation_audit.is_valid)

        # 3. Missing API key fallback to deterministic synthesizer
        fallback_analyst = AIAnalyst(provider="gemini", api_key=None)
        fb_report = await fallback_analyst.analyze_case(case)
        self.assertEqual(fb_report.provider_used, "gemini->deterministic(fallback)")
        self.assertTrue(fb_report.citation_audit.is_valid)

        nodes_cited, evs_cited = extract_citations(fb_report.executive_brief)
        self.assertGreaterEqual(len(nodes_cited), 5)
        self.assertEqual(len(evs_cited), 3)


if __name__ == "__main__":
    unittest.main()
