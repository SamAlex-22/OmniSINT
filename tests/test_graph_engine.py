"""Unit tests for Task 4: NetworkX Knowledge Graph, Louvain Persona Clustering & Hierarchy Tree."""

from __future__ import annotations

import unittest

from omnisint.core.models import (
    Case,
    EntityNode,
    EntityType,
    RelationshipEdge,
    RelationType,
)
from omnisint.intelligence.graph_engine import (
    KnowledgeGraphEngine,
    render_hierarchy_ascii,
)
from omnisint.intelligence.similarity import compute_dhash_from_pixels


class TestKnowledgeGraphEngine(unittest.TestCase):
    """Test suite for KnowledgeGraphEngine disambiguation, Louvain clustering, and Hierarchy Tree."""

    def test_node_deduplication_and_entropy_enrichment(self) -> None:
        engine = KnowledgeGraphEngine()

        n1 = EntityNode(
            node_id="temp-id-1",
            entity_type=EntityType.SOCIAL_PROFILE,
            value="x7_krypton_99",
            platform="GitHub",
            confidence=0.70,
            evidence_ids=["ev-1"],
            attributes={"bio": "Security researcher"},
        )
        n2 = EntityNode(
            node_id="temp-id-2",
            entity_type=EntityType.SOCIAL_PROFILE,
            value="X7_Krypton_99",
            platform="github",
            confidence=0.92,
            evidence_ids=["ev-2"],
            attributes={"followers": 420},
        )
        repo = EntityNode(
            node_id="repo-1",
            entity_type=EntityType.REPOSITORY,
            value="github.com/x7_krypton_99/omnisint",
            evidence_ids=["ev-2"],
        )

        canon_n1 = engine.add_node(n1)
        canon_n2 = engine.add_node(n2)
        engine.add_node(repo)

        # Duplicate canonical_key should merge into temp-id-1 and remap temp-id-2 -> temp-id-1
        self.assertEqual(canon_n1.node_id, "temp-id-1")
        self.assertEqual(canon_n2.node_id, "temp-id-1")
        self.assertEqual(len(engine.nodes), 2)
        self.assertGreater(canon_n1.entropy_score, 2.5)
        self.assertGreater(canon_n1.rarity_score, 0.70)
        self.assertEqual(canon_n1.confidence, 0.92)
        self.assertEqual(canon_n1.evidence_ids, ["ev-1", "ev-2"])
        self.assertEqual(canon_n1.attributes["bio"], "Security researcher")
        self.assertEqual(canon_n1.attributes["followers"], 420)

        # Adding an edge referencing remapped temp-id-2 should automatically point to temp-id-1
        edge = engine.add_edge(
            RelationshipEdge(
                source_node_id="temp-id-2",
                target_node_id="repo-1",
                relation_type=RelationType.OWNS_REPO,
                weight=0.95,
                confidence=0.95,
                evidence_ids=["ev-2"],
            )
        )
        assert edge is not None
        self.assertEqual(edge.source_node_id, "temp-id-1")
        self.assertEqual(edge.target_node_id, "repo-1")
        self.assertEqual(engine.graph.number_of_nodes(), 2)
        self.assertEqual(engine.graph.number_of_edges(), 1)

    def test_similarity_edge_synthesis_for_rare_and_corroborated_handles(self) -> None:
        engine = KnowledgeGraphEngine()

        grid_a = [[(row * 20 + col * 10) % 255 for col in range(9)] for row in range(8)]
        grid_b = [list(row) for row in grid_a]
        grid_b[0][0] = 250
        dhash_a = compute_dhash_from_pixels(grid_a)
        dhash_b = compute_dhash_from_pixels(grid_b)

        ts_a = [
            "2026-05-04T14:15:00+05:30",
            "2026-05-05T15:30:00+05:30",
            "2026-05-06T16:10:00+05:30",
            "2026-05-07T14:45:00+05:30",
        ]
        ts_b = [
            "2026-05-11T14:50:00+05:30",
            "2026-05-12T15:10:00+05:30",
            "2026-05-13T16:40:00+05:30",
            "2026-05-14T17:05:00+05:30",
        ]

        gh_node = EntityNode(
            node_id="n-gh",
            entity_type=EntityType.SOCIAL_PROFILE,
            value="krypton_sec_x7",
            platform="GitHub",
            evidence_ids=["ev-gh"],
            attributes={"avatar_hash": dhash_a, "timestamps": ts_a},
        )
        tw_node = EntityNode(
            node_id="n-tw",
            entity_type=EntityType.SOCIAL_PROFILE,
            value="x7kryptonsec",
            platform="Twitter",
            evidence_ids=["ev-tw"],
            attributes={"avatar_hash": dhash_b, "timestamps": ts_b},
        )

        engine.ingest_nodes_and_edges([gh_node, tw_node])
        synthesized = engine.synthesize_similarity_edges()
        rel_types = {e.relation_type for e in synthesized}

        self.assertIn(RelationType.SIMILAR_HANDLE, rel_types)
        self.assertIn(RelationType.SAME_AVATAR, rel_types)
        self.assertIn(RelationType.TEMPORAL_CORRELATION, rel_types)

        for edge in synthesized:
            self.assertEqual(edge.evidence_ids, ["ev-gh", "ev-tw"])
            self.assertGreaterEqual(edge.confidence, 0.80)

    def test_colliding_namesake_separation_into_distinct_persona_clusters(self) -> None:
        engine = KnowledgeGraphEngine()

        # Avatar dHashes for Persona A (India) vs Persona B (Seattle)
        grid_india = [[(row * 25 + col * 12) % 255 for col in range(9)] for row in range(8)]
        dhash_india_1 = compute_dhash_from_pixels(grid_india)
        grid_india_2 = [list(r) for r in grid_india]
        grid_india_2[0][0] = 240
        dhash_india_2 = compute_dhash_from_pixels(grid_india_2)

        # --- Persona A: alex_dev in Bengaluru, India (UTC+05:30) ---
        ts_india_gh = [
            "2026-05-04T14:15:00+05:30",
            "2026-05-05T15:30:00+05:30",
            "2026-05-06T16:10:00+05:30",
            "2026-05-07T14:45:00+05:30",
        ]
        ts_india_tw = [
            "2026-05-11T14:50:00+05:30",
            "2026-05-12T15:10:00+05:30",
            "2026-05-13T16:40:00+05:30",
            "2026-05-14T15:25:00+05:30",
        ]

        a_gh = EntityNode(
            node_id="a-github",
            entity_type=EntityType.SOCIAL_PROFILE,
            value="alex_dev",
            platform="GitHub",
            evidence_ids=["ev-a1"],
            attributes={
                "location": "Bengaluru, India",
                "avatar_hash": dhash_india_1,
                "timestamps": ts_india_gh,
            },
        )
        a_tw = EntityNode(
            node_id="a-twitter",
            entity_type=EntityType.SOCIAL_PROFILE,
            value="dev_alex_sec",
            platform="Twitter",
            evidence_ids=["ev-a2"],
            attributes={
                "location": "Bengaluru, India",
                "avatar_hash": dhash_india_2,
                "timestamps": ts_india_tw,
            },
        )
        a_avatar = EntityNode(
            node_id="a-avatar",
            entity_type=EntityType.AVATAR_HASH,
            value=dhash_india_1,
            evidence_ids=["ev-a1"],
        )
        a_email = EntityNode(
            node_id="a-email",
            entity_type=EntityType.EMAIL,
            value="alex.sec@proton.me",
            evidence_ids=["ev-a1"],
        )
        a_pgp = EntityNode(
            node_id="a-pgp",
            entity_type=EntityType.PGP_KEY,
            value="0x99AABBCC11223344",
            evidence_ids=["ev-a1"],
        )
        a_repo = EntityNode(
            node_id="a-repo",
            entity_type=EntityType.REPOSITORY,
            value="github.com/alex_dev/omnisint",
            evidence_ids=["ev-a1"],
        )
        a_domain = EntityNode(
            node_id="a-domain",
            entity_type=EntityType.DOMAIN,
            value="alexsec.in",
            evidence_ids=["ev-a3"],
        )
        a_sub = EntityNode(
            node_id="a-subdomain",
            entity_type=EntityType.SUBDOMAIN,
            value="api.alexsec.in",
            evidence_ids=["ev-a3"],
        )
        a_ip = EntityNode(
            node_id="a-ip",
            entity_type=EntityType.IP_ADDRESS,
            value="203.0.113.10",
            evidence_ids=["ev-a3"],
        )

        # --- Persona B: colliding namesake alex_dev in Seattle, USA (UTC-07:00) ---
        ts_us_gl = [
            "2026-05-04T14:10:00-07:00",
            "2026-05-05T15:20:00-07:00",
            "2026-05-06T16:05:00-07:00",
            "2026-05-07T15:40:00-07:00",
        ]
        ts_us_rd = [
            "2026-05-08T14:30:00-07:00",
            "2026-05-09T15:10:00-07:00",
            "2026-05-10T16:25:00-07:00",
            "2026-05-11T15:50:00-07:00",
        ]

        b_gl = EntityNode(
            node_id="b-gitlab",
            entity_type=EntityType.SOCIAL_PROFILE,
            value="alex_dev",
            platform="GitLab",
            evidence_ids=["ev-b1"],
            attributes={
                "location": "Seattle, USA",
                "timestamps": ts_us_gl,
                "email": "alex@seattle-cloud.io",
            },
        )
        b_rd = EntityNode(
            node_id="b-reddit",
            entity_type=EntityType.SOCIAL_PROFILE,
            value="alex_dev",
            platform="Reddit",
            evidence_ids=["ev-b2"],
            attributes={
                "location": "Seattle, USA",
                "timestamps": ts_us_rd,
                "email": "alex@seattle-cloud.io",
            },
        )
        b_email = EntityNode(
            node_id="b-email",
            entity_type=EntityType.EMAIL,
            value="alex@seattle-cloud.io",
            evidence_ids=["ev-b1"],
        )
        b_org = EntityNode(
            node_id="b-org",
            entity_type=EntityType.ORGANIZATION,
            value="PacificCloud Inc",
            evidence_ids=["ev-b1"],
        )
        b_repo = EntityNode(
            node_id="b-repo",
            entity_type=EntityType.REPOSITORY,
            value="gitlab.com/alex_dev/k8s-tools",
            evidence_ids=["ev-b1"],
        )

        structural_edges = [
            RelationshipEdge(
                source_node_id="a-github",
                target_node_id="a-avatar",
                relation_type=RelationType.HAS_AVATAR,
                weight=0.95,
                confidence=0.95,
                evidence_ids=["ev-a1"],
            ),
            RelationshipEdge(
                source_node_id="a-github",
                target_node_id="a-email",
                relation_type=RelationType.HAS_EMAIL,
                weight=0.95,
                confidence=0.95,
                evidence_ids=["ev-a1"],
            ),
            RelationshipEdge(
                source_node_id="a-github",
                target_node_id="a-pgp",
                relation_type=RelationType.USES_KEY,
                weight=0.95,
                confidence=0.95,
                evidence_ids=["ev-a1"],
            ),
            RelationshipEdge(
                source_node_id="a-github",
                target_node_id="a-repo",
                relation_type=RelationType.OWNS_REPO,
                weight=0.95,
                confidence=0.95,
                evidence_ids=["ev-a1"],
            ),
            RelationshipEdge(
                source_node_id="a-github",
                target_node_id="a-domain",
                relation_type=RelationType.OWNS_DOMAIN,
                weight=0.90,
                confidence=0.90,
                evidence_ids=["ev-a3"],
            ),
            RelationshipEdge(
                source_node_id="a-domain",
                target_node_id="a-subdomain",
                relation_type=RelationType.HAS_SUBDOMAIN,
                weight=0.95,
                confidence=0.95,
                evidence_ids=["ev-a3"],
            ),
            RelationshipEdge(
                source_node_id="a-subdomain",
                target_node_id="a-ip",
                relation_type=RelationType.RESOLVES_TO,
                weight=0.95,
                confidence=0.95,
                evidence_ids=["ev-a3"],
            ),
            RelationshipEdge(
                source_node_id="b-gitlab",
                target_node_id="b-email",
                relation_type=RelationType.HAS_EMAIL,
                weight=0.95,
                confidence=0.95,
                evidence_ids=["ev-b1"],
            ),
            RelationshipEdge(
                source_node_id="b-gitlab",
                target_node_id="b-org",
                relation_type=RelationType.MEMBER_OF,
                weight=0.90,
                confidence=0.90,
                evidence_ids=["ev-b1"],
            ),
            RelationshipEdge(
                source_node_id="b-gitlab",
                target_node_id="b-repo",
                relation_type=RelationType.OWNS_REPO,
                weight=0.95,
                confidence=0.95,
                evidence_ids=["ev-b1"],
            ),
        ]

        engine.ingest_nodes_and_edges(
            [
                a_gh,
                a_tw,
                a_avatar,
                a_email,
                a_pgp,
                a_repo,
                a_domain,
                a_sub,
                a_ip,
                b_gl,
                b_rd,
                b_email,
                b_org,
                b_repo,
            ],
            structural_edges,
        )

        report = engine.resolve_personas()

        # Must cleanly separate into exactly 2 PersonaClusters
        self.assertEqual(len(report.personas), 2)
        self.assertGreater(len(report.conflicts_detected), 0)
        self.assertGreater(report.modularity_score, 0.25)

        cluster_1, cluster_2 = report.personas[0], report.personas[1]
        expected_a_ids = {
            "a-github",
            "a-twitter",
            "a-avatar",
            "a-email",
            "a-pgp",
            "a-repo",
            "a-domain",
            "a-subdomain",
            "a-ip",
        }
        expected_b_ids = {
            "b-gitlab",
            "b-reddit",
            "b-email",
            "b-org",
            "b-repo",
        }

        self.assertEqual(set(cluster_1.node_ids), expected_a_ids)
        self.assertEqual(set(cluster_2.node_ids), expected_b_ids)
        self.assertEqual(cluster_1.inferred_timezone, "UTC+05:30")
        self.assertEqual(cluster_2.inferred_timezone, "UTC-07:00")
        self.assertEqual(cluster_1.evidence_ids, ["ev-a1", "ev-a2", "ev-a3"])
        self.assertEqual(cluster_2.evidence_ids, ["ev-b1", "ev-b2"])

        # Verify hierarchy tree categories and nested infrastructure/avatar hierarchy
        assert cluster_1.hierarchy_tree is not None
        tree_1 = cluster_1.hierarchy_tree
        self.assertEqual(tree_1.category, "Root Persona")
        cat_names_1 = [ch.category for ch in tree_1.children]
        self.assertEqual(cat_names_1, ["Accounts", "Emails", "Infrastructure", "Repositories"])

        # Verify nested Infrastructure: a-domain -> a-subdomain -> a-ip
        infra_branch = next(ch for ch in tree_1.children if ch.category == "Infrastructure")
        self.assertEqual(len(infra_branch.children), 1)
        domain_tree_node = infra_branch.children[0]
        self.assertEqual(domain_tree_node.node_id, "a-domain")
        self.assertEqual(len(domain_tree_node.children), 1)
        sub_tree_node = domain_tree_node.children[0]
        self.assertEqual(sub_tree_node.node_id, "a-subdomain")
        self.assertEqual(len(sub_tree_node.children), 1)
        self.assertEqual(sub_tree_node.children[0].node_id, "a-ip")

        # Verify ASCII rendering & Cytoscape export
        ascii_output = render_hierarchy_ascii(tree_1)
        self.assertIn("Accounts", ascii_output)
        self.assertIn("Infrastructure", ascii_output)
        self.assertIn("api.alexsec.in", ascii_output)
        self.assertIn("203.0.113.10", ascii_output)

        cy_elements = engine.to_cytoscape_elements(personas=report.personas)
        self.assertEqual(len(cy_elements["nodes"]), 14 + 2)  # 14 entity nodes + 2 persona compound nodes
        self.assertGreaterEqual(len(cy_elements["edges"]), len(structural_edges))

    def test_apply_to_case_updates_nodes_edges_and_personas(self) -> None:
        case = Case(
            title="Disambiguation Case Test",
            target_query="krypton_sec",
            nodes=[
                EntityNode(
                    node_id="n-1",
                    entity_type=EntityType.USERNAME,
                    value="krypton_sec_x7",
                    platform="GitHub",
                    evidence_ids=["ev-1"],
                ),
                EntityNode(
                    node_id="n-2",
                    entity_type=EntityType.USERNAME,
                    value="x7kryptonsec",
                    platform="Keybase",
                    evidence_ids=["ev-2"],
                ),
            ],
        )

        engine = KnowledgeGraphEngine()
        report = engine.apply_to_case(case)

        self.assertEqual(len(report.personas), 1)
        self.assertEqual(len(case.personas), 1)
        self.assertGreaterEqual(len(case.edges), 1)
        self.assertEqual(case.nodes[0].cluster_id, "persona-cluster-01")
        self.assertEqual(case.nodes[1].cluster_id, "persona-cluster-01")

    def test_uncorroborated_common_names_separate_without_false_positive_merge(self) -> None:
        engine = KnowledgeGraphEngine()
        js_github = EntityNode(
            node_id="js-1",
            entity_type=EntityType.SOCIAL_PROFILE,
            value="john_smith",
            platform="GitHub",
            evidence_ids=["ev-js1"],
        )
        js_reddit = EntityNode(
            node_id="js-2",
            entity_type=EntityType.SOCIAL_PROFILE,
            value="john_smith",
            platform="Reddit",
            evidence_ids=["ev-js2"],
        )
        engine.ingest_nodes_and_edges([js_github, js_reddit])
        report = engine.resolve_personas()

        # High-collision handle "john_smith" without corroboration must stay separated
        self.assertEqual(len(report.personas), 2)
        self.assertEqual(len(report.conflicts_detected), 1)
        self.assertIn("uncorroborated identical common handle", report.conflicts_detected[0])

    def test_location_alias_normalization_avoids_false_conflict(self) -> None:
        engine = KnowledgeGraphEngine()
        n1 = EntityNode(
            node_id="n-loc-1",
            entity_type=EntityType.SOCIAL_PROFILE,
            value="rahul_sharma",
            platform="GitHub",
            attributes={"location": "Bangalore"},
        )
        n2 = EntityNode(
            node_id="n-loc-2",
            entity_type=EntityType.SOCIAL_PROFILE,
            value="rahul_sharma",
            platform="Twitter",
            attributes={"location": "Bengaluru, India"},
        )
        self.assertIsNone(engine._check_location_conflict(n1, n2))


if __name__ == "__main__":
    unittest.main()
