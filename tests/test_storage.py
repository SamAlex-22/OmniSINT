"""Unit tests for Task 2: Async SQLite Case Store & TTL Response Cache."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from omnisint.core.custody import CustodyLedger
from omnisint.core.models import (
    CaseStatus,
    CollectorResult,
    EntityNode,
    EntityType,
    HierarchyTreeNode,
    PersonaCluster,
    RelationshipEdge,
    RelationType,
)
from omnisint.core.storage import CaseStorage, make_cache_key


class TestCaseStorage(unittest.IsolatedAsyncioTestCase):
    """Test suite for async SQLite case persistence, graph deduplication, custody chain, and TTL cache."""

    async def test_case_lifecycle_and_file_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_file = Path(tmpdir) / "test_omnisint.db"

            async with CaseStorage(db_path=db_file) as store:
                created = await store.create_case(
                    title="Operation Shadow Handle",
                    target_query="alex_sec",
                    investigator="analyst-01",
                    description="Investigating colliding handles across GitHub and domains",
                )
                self.assertEqual(created.status, CaseStatus.OPEN)
                self.assertEqual(len(created.audit_log), 1)
                self.assertEqual(created.audit_log[0].action, "CASE_CREATED")

                # Add persona with HierarchyTreeNode and executive brief
                tree = HierarchyTreeNode(
                    node_id="n-root",
                    label="Persona #1: Alex Sec",
                    category="Root Persona",
                    entity_type=EntityType.PERSON,
                )
                created.personas.append(
                    PersonaCluster(
                        persona_label="Alex Sec (AppSec)",
                        primary_handle="alex_sec",
                        confidence_score=0.94,
                        avg_handle_entropy=3.41,
                        hierarchy_tree=tree,
                    )
                )
                created.ai_executive_brief = "Target resolved with high confidence [node_id=n-root]."
                await store.save_case(created)
                await store.update_case_status(created.case_id, CaseStatus.COMPLETED)

            # Re-open from disk to verify durable persistence
            async with CaseStorage(db_path=db_file) as store2:
                loaded = await store2.get_case(created.case_id)
                self.assertIsNotNone(loaded)
                assert loaded is not None
                self.assertEqual(loaded.title, "Operation Shadow Handle")
                self.assertEqual(loaded.status, CaseStatus.COMPLETED)
                self.assertEqual(len(loaded.personas), 1)
                self.assertIsNotNone(loaded.personas[0].hierarchy_tree)
                self.assertIn("n-root", loaded.ai_executive_brief)
                self.assertEqual(len(loaded.audit_log), 2)

                completed_cases = await store2.list_cases(status=CaseStatus.COMPLETED)
                self.assertEqual(len(completed_cases), 1)

                deleted = await store2.delete_case(created.case_id)
                self.assertTrue(deleted)
                self.assertIsNone(await store2.get_case(created.case_id))

    async def test_node_and_edge_canonical_deduplication(self) -> None:
        async with CaseStorage(db_path=":memory:") as store:
            case = await store.create_case(title="Dedup Test", target_query="alex_sec")

            node_v1 = EntityNode(
                node_id="node-gh-1",
                entity_type=EntityType.SOCIAL_PROFILE,
                value="Alex_Sec",
                platform="GitHub",
                entropy_score=3.1,
                rarity_score=0.70,
                confidence=0.75,
                attributes={"bio": "Security Engineer"},
                evidence_ids=["ev-1"],
            )
            node_v2 = EntityNode(
                node_id="node-gh-duplicate-id",
                entity_type=EntityType.SOCIAL_PROFILE,
                value="alex_sec",
                platform="github",
                entropy_score=3.4,
                rarity_score=0.85,
                confidence=0.92,
                attributes={"followers": 140},
                evidence_ids=["ev-2"],
            )

            persisted_1 = await store.upsert_node(case.case_id, node_v1)
            persisted_2 = await store.upsert_node(case.case_id, node_v2)

            # Must preserve original canonical node_id and merge attributes + evidence_ids
            self.assertEqual(persisted_1.node_id, "node-gh-1")
            self.assertEqual(persisted_2.node_id, "node-gh-1")
            self.assertEqual(persisted_2.confidence, 0.92)
            self.assertEqual(persisted_2.entropy_score, 3.4)
            self.assertEqual(persisted_2.attributes["bio"], "Security Engineer")
            self.assertEqual(persisted_2.attributes["followers"], 140)
            self.assertEqual(persisted_2.evidence_ids, ["ev-1", "ev-2"])

            all_nodes = await store.get_case_nodes(case.case_id)
            self.assertEqual(len(all_nodes), 1)

            repo_node = await store.upsert_node(
                case.case_id,
                EntityNode(
                    node_id="node-repo-1",
                    entity_type=EntityType.REPOSITORY,
                    value="alex_sec/omnisint",
                    platform="github",
                ),
            )

            edge_1 = RelationshipEdge(
                source_node_id=persisted_1.node_id,
                target_node_id=repo_node.node_id,
                relation_type=RelationType.OWNS_REPO,
                weight=0.75,
                confidence=0.80,
                evidence_ids=["ev-1"],
            )
            edge_2 = RelationshipEdge(
                source_node_id=persisted_1.node_id,
                target_node_id=repo_node.node_id,
                relation_type=RelationType.OWNS_REPO,
                weight=0.95,
                confidence=0.95,
                rationale="Verified repository owner in GitHub API",
                evidence_ids=["ev-2"],
            )
            await store.upsert_edge(case.case_id, edge_1)
            merged_edge = await store.upsert_edge(case.case_id, edge_2)

            self.assertEqual(merged_edge.weight, 0.95)
            self.assertEqual(merged_edge.evidence_ids, ["ev-1", "ev-2"])
            edges = await store.get_case_edges(case.case_id, node_id=persisted_1.node_id)
            self.assertEqual(len(edges), 1)

    async def test_evidence_custody_chain_roundtrip_and_merge_collector_result(self) -> None:
        async with CaseStorage(db_path=":memory:") as store:
            case = await store.create_case(title="Custody Test", target_query="alexsec.io")

            ev1 = await store.record_evidence(
                case_id=case.case_id,
                collector_name="domain_ct_collector",
                source_uri="https://crt.sh/?q=alexsec.io&output=json",
                raw_payload='[{"common_name":"vpn.alexsec.io"}]',
                notes="Raw JSON string payload from crt.sh",
            )
            ev2 = await store.record_evidence(
                case_id=case.case_id,
                collector_name="github_collector",
                source_uri="https://api.github.com/users/alex_sec",
                raw_payload={"login": "alex_sec", "blog": "https://alexsec.io"},
                notes="Structured dict payload from GitHub API",
            )
            self.assertEqual(ev2.prev_chain_hash, ev1.chain_hash)

            # Now simulate two collectors returning CollectorResults with overlapping nodes
            temp_ledger = CustodyLedger(case_id=case.case_id)
            collector_ev = temp_ledger.record_evidence(
                collector_name="threat_intel",
                source_uri="https://www.virustotal.com/api/v3/domains/alexsec.io",
                raw_payload={"harmless": 70, "malicious": 0},
            )

            domain_node_a = EntityNode(
                node_id="temp-domain-id-1",
                entity_type=EntityType.DOMAIN,
                value="alexsec.io",
                evidence_ids=[ev1.evidence_id],
            )
            await store.upsert_node(case.case_id, domain_node_a)

            # Second collector uses a different temporary node_id for the same domain
            domain_node_b = EntityNode(
                node_id="temp-domain-id-2",
                entity_type=EntityType.DOMAIN,
                value="ALEXSEC.IO",
                evidence_ids=[collector_ev.evidence_id],
            )
            ip_node = EntityNode(
                node_id="node-ip-1",
                entity_type=EntityType.IP_ADDRESS,
                value="93.184.216.34",
                evidence_ids=[collector_ev.evidence_id],
            )
            dns_edge = RelationshipEdge(
                source_node_id="temp-domain-id-2",
                target_node_id="node-ip-1",
                relation_type=RelationType.RESOLVES_TO,
                evidence_ids=[collector_ev.evidence_id],
            )

            result = CollectorResult(
                collector_name="threat_intel",
                query="alexsec.io",
                nodes=[domain_node_b, ip_node],
                edges=[dns_edge],
                evidence_items=[collector_ev],
            )

            updated_case = await store.merge_collector_result(case.case_id, result)
            self.assertEqual(len(updated_case.nodes), 2)
            self.assertEqual(len(updated_case.edges), 1)
            # Edge source_node_id must have been remapped to the canonical first domain node ID
            self.assertEqual(updated_case.edges[0].source_node_id, "temp-domain-id-1")
            self.assertEqual(updated_case.edges[0].target_node_id, "node-ip-1")

            # Verify entire 3-item cryptographic chain of custody after SQLite round-trip
            is_valid, violations = await store.verify_case_custody(case.case_id)
            self.assertTrue(is_valid, f"Custody violations: {violations}")
            self.assertEqual(violations, [])
            self.assertEqual(len(updated_case.evidence_ledger), 3)

    async def test_ttl_response_cache_hit_expiry_and_invalidation(self) -> None:
        async with CaseStorage(db_path=":memory:", default_ttl_seconds=3600) as store:
            key1 = make_cache_key("github_collector", "https://api.github.com/users/alex", {"page": 1})
            key2 = make_cache_key("github_collector", "https://api.github.com/users/alex", {"page": 2})
            self.assertNotEqual(key1, key2)

            await store.set_cached_response(
                collector_name="github_collector",
                query_or_uri="https://api.github.com/users/alex",
                payload={"login": "alex", "id": 42},
                params={"page": 1},
                ttl_seconds=3600,
            )

            cached = await store.get_cached_response(
                collector_name="github_collector",
                query_or_uri="https://api.github.com/users/alex",
                params={"page": 1},
            )
            self.assertIsNotNone(cached)
            assert cached is not None
            self.assertEqual(cached.payload, {"login": "alex", "id": 42})
            self.assertFalse(cached.is_expired())

            # Simulate an already-expired cache row directly in SQLite
            past_time = datetime.now(timezone.utc) - timedelta(seconds=120)
            assert store._conn is not None
            store._conn.execute(
                "UPDATE http_cache SET expires_at_utc = ? WHERE cache_key = ?;",
                (past_time.isoformat(), cached.cache_key),
            )
            store._conn.commit()

            expired_lookup = await store.get_cached_response(
                collector_name="github_collector",
                query_or_uri="https://api.github.com/users/alex",
                params={"page": 1},
            )
            self.assertIsNone(expired_lookup)

            # Populate two new cache entries and test invalidation
            await store.set_cached_response(
                collector_name="username_collector",
                query_or_uri="https://reddit.com/user/alex/about.json",
                payload={"data": {"name": "alex"}},
            )
            removed_count = await store.invalidate_cache(collector_name="username_collector")
            self.assertEqual(removed_count, 1)


if __name__ == "__main__":
    unittest.main()
